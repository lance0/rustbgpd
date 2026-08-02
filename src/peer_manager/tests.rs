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

fn blocked_snapshot_query_handle(
    peer: IpAddr,
    release: oneshot::Receiver<()>,
    observed: mpsc::UnboundedSender<&'static str>,
) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;

    let (commands, mut receiver) = mpsc::channel(1);
    commands
        .try_send(PeerCommand::Start)
        .expect("pre-fill the session command channel");
    let task = tokio::spawn(async move {
        let _ = release.await;
        assert!(matches!(receiver.recv().await, Some(PeerCommand::Start)));
        while let Some(command) = receiver.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    let _ = observed.send("state");
                    let _ = reply.send(policy_test_peer_state(peer, SessionState::Established));
                }
                PeerCommand::QueryWarmCheckpointState { reply } => {
                    let _ = observed.send("warm");
                    let _ = reply.send(eligible_warm_checkpoint_state());
                }
                PeerCommand::Shutdown | PeerCommand::Stop { .. } | PeerCommand::CollisionDump => {
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(commands, task)
}

async fn assert_canceled_list_peers_releases_driver(use_readiness_lane: bool) {
    use rustbgpd_api::peer_types::PeerManagerReadinessQuery;

    let (tx, rx) = mpsc::channel(1);
    let (readiness_tx, readiness_rx) = mpsc::channel(1);
    let (rib_tx, _rib_rx) = mpsc::channel(8);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    )
    .with_readiness_queries(readiness_rx);
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let (release, release_rx) = oneshot::channel();
    let (observed, mut observations) = mpsc::unbounded_channel();
    insert_test_managed_peer(
        &mut manager,
        peer,
        blocked_snapshot_query_handle(peer, release_rx, observed),
        false,
    );
    let actor = tokio::spawn(manager.run());

    let (canceled_reply, canceled_response) = oneshot::channel();
    if use_readiness_lane {
        readiness_tx
            .send(PeerManagerReadinessQuery::ListPeers {
                reply: canceled_reply,
            })
            .await
            .unwrap();
    } else {
        tx.send(PeerManagerCommand::ListPeers {
            reply: canceled_reply,
        })
        .await
        .unwrap();
    }
    // The bounded peer-manager/readiness channel accepting another item proves
    // the actor consumed the snapshot request. Its one session query is then
    // synchronously spawned and parked behind the deliberately full channel.
    while if use_readiness_lane {
        readiness_tx.capacity() == 0
    } else {
        tx.capacity() == 0
    } {
        tokio::task::yield_now().await;
    }
    tokio::task::yield_now().await;

    let later_tx = tx.clone();
    let later_command = tokio::spawn(async move { subscribe_session_events(&later_tx).await });
    tokio::task::yield_now().await;
    assert!(
        !later_command.is_finished(),
        "later manager command waits behind the live snapshot"
    );
    drop(canceled_response);
    for _ in 0..10 {
        tokio::task::yield_now().await;
        if later_command.is_finished() {
            break;
        }
    }
    assert!(
        later_command.is_finished(),
        "canceling the snapshot releases the manager without advancing time"
    );
    drop(later_command.await.unwrap());

    release.send(()).unwrap();
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert!(
        observations.try_recv().is_err(),
        "the canceled driver must not admit a late QueryState"
    );

    let (reply, response) = oneshot::channel();
    if use_readiness_lane {
        readiness_tx
            .send(PeerManagerReadinessQuery::ListPeers { reply })
            .await
            .unwrap();
    } else {
        tx.send(PeerManagerCommand::ListPeers { reply })
            .await
            .unwrap();
    }
    let peers = response.await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(observations.recv().await, Some("state"));
    assert!(observations.try_recv().is_err());

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    actor.await.unwrap();
}

/// Load-bearing ordinary-lane proof: detaching the spawned `QueryState` driver
/// leaves it queued after aggregate cancellation, so freeing the slot observes
/// a late first query and the exact-one assertion fails.
#[tokio::test(start_paused = true)]
async fn canceled_ordinary_list_peers_aborts_blocked_session_driver() {
    assert_canceled_list_peers_releases_driver(false).await;
}

/// Load-bearing readiness-lane proof: bypassing the shared complete-only
/// answer path or detaching its driver admits a late `QueryState` after the
/// health caller is gone.
#[tokio::test(start_paused = true)]
async fn canceled_readiness_list_peers_aborts_blocked_session_driver() {
    assert_canceled_list_peers_releases_driver(true).await;
}

/// Load-bearing warm-capture proof: detaching `QueryWarmCheckpointState` leaves
/// it queued after cancellation, so freeing the slot observes a late warm
/// query before the next all-or-nothing capture.
#[tokio::test(start_paused = true)]
async fn canceled_warm_checkpoint_aborts_blocked_session_driver() {
    let (tx, rx) = mpsc::channel(1);
    let (rib_tx, _rib_rx) = mpsc::channel(8);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let (release, release_rx) = oneshot::channel();
    let (observed, mut observations) = mpsc::unbounded_channel();
    insert_test_managed_peer(
        &mut manager,
        peer,
        blocked_snapshot_query_handle(peer, release_rx, observed),
        false,
    );
    let actor = tokio::spawn(manager.run());

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryWarmCheckpointCapture { reply })
        .await
        .unwrap();
    while tx.capacity() == 0 {
        tokio::task::yield_now().await;
    }
    tokio::task::yield_now().await;
    let later_tx = tx.clone();
    let later_command = tokio::spawn(async move { subscribe_session_events(&later_tx).await });
    tokio::task::yield_now().await;
    assert!(!later_command.is_finished());
    drop(response);
    for _ in 0..10 {
        tokio::task::yield_now().await;
        if later_command.is_finished() {
            break;
        }
    }
    assert!(later_command.is_finished());
    drop(later_command.await.unwrap());

    release.send(()).unwrap();
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert!(observations.try_recv().is_err());

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryWarmCheckpointCapture { reply })
        .await
        .unwrap();
    let capture = response.await.unwrap().unwrap();
    assert_eq!(capture.sessions.len(), 1);
    assert_eq!(observations.recv().await, Some("warm"));
    assert!(observations.try_recv().is_err());

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    actor.await.unwrap();
}

enum HeldSnapshotReply {
    State(IpAddr, oneshot::Sender<PeerSessionState>),
    Warm(IpAddr, oneshot::Sender<WarmCheckpointSessionState>),
}

impl HeldSnapshotReply {
    fn peer(&self) -> IpAddr {
        match self {
            Self::State(peer, _) | Self::Warm(peer, _) => *peer,
        }
    }

    fn is_closed(&self) -> bool {
        match self {
            Self::State(_, reply) => reply.is_closed(),
            Self::Warm(_, reply) => reply.is_closed(),
        }
    }
}

fn held_snapshot_query_handle(
    peer: IpAddr,
    warm: bool,
    admitted: mpsc::UnboundedSender<HeldSnapshotReply>,
) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;

    let (commands, mut receiver) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        while let Some(command) = receiver.recv().await {
            match command {
                PeerCommand::QueryState { reply } if !warm => {
                    let _ = admitted.send(HeldSnapshotReply::State(peer, reply));
                    break;
                }
                PeerCommand::QueryWarmCheckpointState { reply } if warm => {
                    let _ = admitted.send(HeldSnapshotReply::Warm(peer, reply));
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(commands, task)
}

fn blocked_cohort_query_handle(
    release: oneshot::Receiver<()>,
    settled: mpsc::UnboundedSender<bool>,
) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;

    let (commands, mut receiver) = mpsc::channel(1);
    commands
        .try_send(PeerCommand::Start)
        .expect("pre-fill cohort command channel");
    let task = tokio::spawn(async move {
        let _ = release.await;
        assert!(matches!(receiver.recv().await, Some(PeerCommand::Start)));
        let admitted = receiver.recv().await.is_some_and(|command| {
            matches!(
                command,
                PeerCommand::QueryState { .. } | PeerCommand::QueryWarmCheckpointState { .. }
            )
        });
        let _ = settled.send(admitted);
        Ok(())
    });
    PeerHandle::from_parts(commands, task)
}

async fn assert_canceled_snapshot_cohort_aborts_every_driver(warm: bool) {
    const PEERS: usize = 32;
    const ADMITTED: usize = 7;

    let mut manager = test_peer_manager();
    let (admitted, mut admitted_rx) = mpsc::unbounded_channel();
    let (settled, mut settled_rx) = mpsc::unbounded_channel();
    let mut releases = Vec::new();
    for index in 1..=PEERS {
        let peer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, u8::try_from(index).unwrap()));
        let handle = if index <= ADMITTED {
            held_snapshot_query_handle(peer, warm, admitted.clone())
        } else {
            let (release, release_rx) = oneshot::channel();
            releases.push(release);
            blocked_cohort_query_handle(release_rx, settled.clone())
        };
        insert_test_managed_peer(&mut manager, peer, handle, false);
    }
    drop(admitted);
    drop(settled);

    let collector = tokio::spawn(async move {
        if warm {
            let _ = manager.query_warm_checkpoint_capture().await;
        } else {
            let _ = manager.list_peers().await;
        }
    });
    let mut admitted_replies = Vec::with_capacity(ADMITTED);
    for _ in 0..ADMITTED {
        admitted_replies.push(admitted_rx.recv().await.unwrap());
    }
    let admitted_peers: BTreeSet<_> = admitted_replies
        .iter()
        .map(HeldSnapshotReply::peer)
        .collect();
    assert_eq!(admitted_peers.len(), ADMITTED);

    collector.abort();
    assert!(collector.await.unwrap_err().is_cancelled());
    assert!(
        admitted_replies.iter().all(HeldSnapshotReply::is_closed),
        "every admitted session reply receiver closes synchronously"
    );

    for release in releases {
        release.send(()).unwrap();
    }
    for _ in ADMITTED..PEERS {
        assert_eq!(
            settled_rx.recv().await,
            Some(false),
            "a driver waiting for a remaining session slot must not be admitted"
        );
    }
    assert!(settled_rx.try_recv().is_err());
}

/// Load-bearing high-cardinality `QueryState` proof: plain `JoinHandles` detach
/// when the collector is canceled, so all 25 blocked drivers become admitted
/// after their slots are freed and the exact-empty assertion fails.
#[tokio::test(start_paused = true)]
async fn canceled_list_peers_cohort_aborts_admitted_and_blocked_drivers() {
    assert_canceled_snapshot_cohort_aborts_every_driver(false).await;
}

/// Load-bearing high-cardinality warm proof: plain `JoinHandles` detach when the
/// capture is canceled, so blocked `QueryWarmCheckpointState` drivers enter the
/// session channels and admitted reply senders stay open.
#[tokio::test(start_paused = true)]
async fn canceled_warm_checkpoint_cohort_aborts_admitted_and_blocked_drivers() {
    assert_canceled_snapshot_cohort_aborts_every_driver(true).await;
}

#[tokio::test]
async fn canceled_ordinary_list_peers_skips_session_queries() {
    let (tx, rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(8);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut manager,
        peer,
        fake_peer_handle(peer, SessionState::Established, None, counters.clone()),
        false,
    );
    let stale_peer: IpAddr = "192.0.2.2".parse().unwrap();
    let (stale_commands, stale_receiver) = mpsc::channel(1);
    let stale_task = tokio::spawn(async move {
        drop(stale_receiver);
        Ok::<(), rustbgpd_transport::TransportError>(())
    });
    insert_test_managed_peer(
        &mut manager,
        stale_peer,
        PeerHandle::from_parts(stale_commands, stale_task),
        false,
    );
    let actor = tokio::spawn(manager.run());
    tokio::task::yield_now().await;

    let (reply, receiver) = oneshot::channel();
    drop(receiver);
    tx.send(PeerManagerCommand::ListPeers { reply })
        .await
        .unwrap();

    let (reply, receiver) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply })
        .await
        .unwrap();
    let peers = receiver.await.unwrap();
    assert_eq!(peers.len(), 2);
    assert!(
        peers.iter().any(|row| row.address == peer && !row.stale),
        "live row remains fresh"
    );
    assert!(
        peers
            .iter()
            .any(|row| row.address == stale_peer && row.stale),
        "unanswered row keeps the existing stale fallback"
    );
    assert_eq!(counters.query_state.load(Ordering::SeqCst), 1);

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    actor.await.unwrap();
}

#[tokio::test]
async fn canceled_plan_drops_rib_snapshot_and_actor_answers_later_command() {
    let config = load_test_config(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"
"#,
    );
    let candidate = toml::to_string_pretty(&config).unwrap();
    let (tx, rx) = mpsc::channel(8);
    let (rib_tx, mut rib_rx) = mpsc::channel(8);
    let manager = PeerManager::new_with_config(
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
    );
    let actor = tokio::spawn(manager.run());

    let (plan_reply, plan_receiver) = oneshot::channel();
    tx.send(PeerManagerCommand::PlanConfigTransaction {
        candidate_toml: candidate,
        expected_runtime_snapshot_token: None,
        reply: plan_reply,
    })
    .await
    .unwrap();
    let RibUpdate::QueryUpdateGroupSnapshot { mut reply } = rib_rx.recv().await.unwrap() else {
        panic!("plan did not request its RIB snapshot");
    };
    drop(plan_receiver);
    tokio::time::timeout(Duration::from_secs(1), reply.closed())
        .await
        .expect("abandoned plan kept its RIB snapshot receiver alive");

    let (policies_reply, policies_receiver) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPolicies {
        reply: policies_reply,
    })
    .await
    .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(1), policies_receiver)
        .await
        .expect("actor remained blocked on the abandoned RIB snapshot")
        .unwrap();

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    actor.await.unwrap();
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
                        target_local_role: None,
                        interpret_rfc1997: true,
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
                            target_local_role: None,
                            interpret_rfc1997: true,
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

#[tokio::test]
async fn transaction_plan_rejects_full_snapshot_family_with_external_policy_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let rpol_path = dir.path().join("edge.rpol");
    let dataset_path = dir.path().join("customers.list");
    std::fs::write(
        &rpol_path,
        r"
dataset asn-set customers

policy edge-in {
    term customer { if route.origin-as in customers { accept } }
    term rest { reject }
}
",
    )
    .unwrap();
    std::fs::write(&dataset_path, "64500\n").unwrap();
    let config = load_test_config(&format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[policy]
rpol_files = [{rpol_path:?}]

[policy.datasets.customers]
path = {dataset_path:?}

[[neighbors]]
address = "192.0.2.1"
remote_asn = 65002
description = "before"
import_policy_chain = ["edge-in"]
"#,
        rpol_path = rpol_path.display().to_string(),
        dataset_path = dataset_path.display().to_string()
    ));
    let live_dataset = std::sync::Arc::clone(
        config
            .policy
            .dataset_bindings
            .get("customers")
            .expect("live dataset binding"),
    );
    let live_status = live_dataset.status();
    std::fs::write(&dataset_path, "64500\n64999\n").unwrap();
    let mut candidate = config.clone();
    candidate.neighbors[0].description = Some("after".to_string());
    let candidate = toml::to_string_pretty(&candidate).unwrap();
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

    let plan = mgr.plan_config_transaction(&candidate, None).await.unwrap();

    assert_eq!(
        plan.status,
        rustbgpd_api::peer_types::RuntimeConfigTransactionStatus::Rejected
    );
    assert_eq!(plan.supported_sections, vec!["[[neighbors]] modify"]);
    assert_eq!(plan.unsupported_sections.len(), 1);
    assert!(plan.unsupported_sections[0].contains("external inputs"));
    assert_eq!(
        mgr.current_config.neighbors[0].description.as_deref(),
        Some("before")
    );
    assert_eq!(live_dataset.status(), live_status);
    assert_eq!(live_dataset.pin().data.records(), 1);
    responder.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "keeps the external dataset, real peer snapshot, and both planner verdicts in one load-bearing scenario"
)]
async fn independent_external_reparse_noop_and_pure_fib_have_zero_update_group_impact() {
    let dir = tempfile::tempdir().unwrap();
    let rpol_path = dir.path().join("catalog.rpol");
    let dataset_path = dir.path().join("customers.list");
    std::fs::write(
        &rpol_path,
        r"
dataset asn-set customers

policy dataset-export {
    term customer { if route.origin-as in customers { accept } }
    term rest { reject }
}
",
    )
    .unwrap();
    std::fs::write(&dataset_path, "64500\n").unwrap();
    let mut current = load_test_config(&format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[policy]
rpol_files = [{rpol_path:?}]

[policy.datasets.customers]
path = {dataset_path:?}

[[neighbors]]
address = "192.0.2.1"
remote_asn = 65002
export_policy_chain = ["dataset-export"]
"#,
        rpol_path = rpol_path.display().to_string(),
        dataset_path = dataset_path.display().to_string()
    ));
    current.fib_tables.push(crate::config::FibTableConfig {
        name: "edge".to_string(),
        table_id: 1000,
        metric: 200,
        families: vec!["ipv4_unicast".to_string()],
        allowed_peer_groups: Vec::new(),
        allowed_neighbors: Vec::new(),
        max_routes: None,
        maximum_paths: None,
        maximum_paths_ebgp: None,
        maximum_paths_ibgp: None,
    });
    let noop_candidate = toml::to_string_pretty(&current).unwrap();
    let mut fib_candidate = current.clone();
    fib_candidate.fib_tables[0].metric = 201;
    let fib_candidate = toml::to_string_pretty(&fib_candidate).unwrap();
    let resolved = current.resolved_neighbors().unwrap();
    let neighbor = &resolved[0];
    let policy = neighbor
        .export_policy
        .as_ref()
        .expect("export chain resolved");
    assert!(policy.references_dataset("customers"));
    let live_input = rustbgpd_rib::UpdateGroupClassifierInput {
        policy_fingerprint: Some(format!("{policy:?}")),
        policy_provenance: Some(policy.groupability_provenance().to_string()),
        policy_requires_peer_context: policy.requires_peer_context(),
        target_is_ebgp: true,
        target_is_rr_client: neighbor.transport_config.route_reflector_client,
        target_local_role: neighbor
            .transport_config
            .peer
            .local_role
            .map(rustbgpd_wire::BgpRole::to_u8),
        sendable_families: vec![(1, 1)],
        llgr_families: Vec::new(),
        add_path_send: false,
        per_client_best: neighbor.transport_config.per_client_best,
        interpret_rfc1997: neighbor.transport_config.interpret_rfc1997,
        orr_vantage: neighbor.transport_config.orr_vantage,
        orf_installed: false,
    };
    let live_classification = rustbgpd_rib::classify_update_group(live_input.clone());
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
        current,
    );
    let responder = tokio::spawn(async move {
        for _ in 0..2 {
            let Some(RibUpdate::QueryUpdateGroupSnapshot { reply }) = rib_rx.recv().await else {
                panic!("plan snapshot query missing");
            };
            reply
                .send(rustbgpd_rib::UpdateGroupSnapshot {
                    peers: vec![rustbgpd_rib::UpdateGroupPeerSnapshot {
                        peer: "192.0.2.1".parse().unwrap(),
                        input: live_input.clone(),
                        classification: live_classification.clone(),
                        runtime_membership: "group:0".to_string(),
                    }],
                })
                .unwrap();
        }
    });

    let noop = mgr
        .plan_config_transaction(&noop_candidate, None)
        .await
        .unwrap();
    let fib = mgr
        .plan_config_transaction(&fib_candidate, None)
        .await
        .unwrap();

    assert_eq!(
        noop.status,
        rustbgpd_api::peer_types::RuntimeConfigTransactionStatus::Noop
    );
    assert!(noop.supported_sections.is_empty());
    assert!(noop.unsupported_sections.is_empty());
    assert_eq!(noop.update_group_impact.entries.len(), 1);
    assert_eq!(noop.update_group_impact.entries[0].transition, "no_op");
    assert!(!noop.update_group_impact.entries[0].local_resync);
    assert_eq!(noop.update_group_impact.rollup.affected_peers, 0);
    assert_eq!(noop.update_group_impact.rollup.affected_families, 0);
    assert_eq!(noop.update_group_impact.rollup.local_resyncs, 0);
    assert_eq!(noop.update_group_impact.rollup.no_op, 1);
    assert_eq!(
        fib.status,
        rustbgpd_api::peer_types::RuntimeConfigTransactionStatus::Committable
    );
    assert_eq!(fib.supported_sections, vec!["[[fib_tables]]"]);
    assert!(fib.unsupported_sections.is_empty());
    assert_eq!(fib.update_group_impact.entries.len(), 1);
    assert_eq!(fib.update_group_impact.entries[0].transition, "no_op");
    assert!(!fib.update_group_impact.entries[0].local_resync);
    assert_eq!(fib.update_group_impact.rollup.affected_peers, 0);
    assert_eq!(fib.update_group_impact.rollup.affected_families, 0);
    assert_eq!(fib.update_group_impact.rollup.local_resyncs, 0);
    assert_eq!(fib.update_group_impact.rollup.no_op, 1);
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

    let config = Config {
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
            ebgp_requires_policy: false,
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

/// Load-bearing producer-path proof: dropping the field at either
/// `ResolvedNeighbor` -> `PeerManagerConfig` or `PeerManagerConfig` -> `ManagedPeer`
/// makes the final assertion `None` while parsing/inheritance still passes.
#[tokio::test]
async fn inherited_max_prefix_restart_reaches_managed_peer() {
    let config = load_test_config(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

[peer_groups.ix-members]
max_prefix_restart_seconds = 30

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "ix-members"
"#,
    );
    let resolved = config.resolved_neighbors().unwrap().pop().unwrap();
    let peer_config = PeerManager::peer_manager_config_from_resolved(resolved, false);
    assert_eq!(peer_config.max_prefix_restart_seconds, Some(30));

    let mut mgr = test_peer_manager();
    let peer = key(peer_config.address);
    mgr.add_peer(peer_config, false).await.unwrap();
    assert_eq!(
        mgr.peers[&peer].max_prefix_restart_seconds,
        Some(30),
        "manager must own the fully resolved restart policy"
    );
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
    mgr.current_config.dynamic_neighbors[0].tcp_ao = Some(test_tcp_ao().into());

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
fn runtime_dynamic_add_rejects_static_tcp_ao_neighbor_coverage() {
    let mut mgr = dynamic_test_manager();
    let mut neighbor = config_neighbor("10.20.30.40".parse().unwrap(), 65002);
    neighbor.tcp_ao = Some(test_tcp_ao().into());
    mgr.current_config.neighbors.push(neighbor);

    let err = mgr
        .add_dynamic_range("10.0.0.0/8".into(), "ix-members".into(), 0, None)
        .expect_err("runtime range must not introduce plaintext over static TCP-AO");
    assert!(err.to_string().contains("static TCP-AO neighbor"), "{err}");
    assert!(
        mgr.dynamic_ranges
            .iter()
            .all(|range| range.addr != "10.0.0.0".parse::<IpAddr>().unwrap()),
        "rejected range must not mutate runtime state"
    );
}

#[tokio::test]
async fn dynamic_tcp_ao_snapshot_reports_protected_from_explicit_range_keyring() {
    let (tx, rx) = mpsc::channel(16);
    let (_internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mut config = make_dynamic_manager_config();
    config.dynamic_neighbors[0].tcp_ao = Some(test_tcp_ao().into());
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

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let connect = TcpStream::connect(listener.local_addr().unwrap());
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(connect, accept);
    let client = client.unwrap();
    let (server, remote_addr) = accepted.unwrap();
    tx.send(PeerManagerCommand::AcceptInbound {
        stream: server,
        peer_addr: remote_addr,
        tcp_ao_info: Some(rustbgpd_transport::TcpAoInfoSnapshot {
            has_current_key: true,
            has_rnext_key: true,
            ao_required: false,
            accept_icmps: false,
            current_key: 1,
            rnext_key: 1,
            pkt_good: 1,
            pkt_bad: 0,
            pkt_key_not_found: 0,
            pkt_ao_required: 0,
            pkt_dropped_icmp: 0,
            keys: vec![rustbgpd_transport::TcpAoKeyState {
                peer: "127.0.0.0".parse().unwrap(),
                prefix_len: 8,
                send_id: 1,
                recv_id: 1,
                algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
                is_current: true,
                is_rnext: true,
                preferred: false,
                deprecated: false,
                vrf_ifindex: None,
                pkt_good: 1,
                pkt_bad: 0,
            }],
        }),
        tcp_ao_generation: Some(rustbgpd_transport::TcpAoRotationGeneration::STARTUP),
    })
    .await
    .unwrap();

    let (list_tx, list_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply: list_tx })
        .await
        .unwrap();
    let peers = list_rx.await.unwrap();
    assert_eq!(peers.len(), 1);
    assert!(peers[0].is_dynamic);
    assert_eq!(peers[0].authentication, "tcp_ao");

    drop(client);
    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
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
#[expect(
    clippy::too_many_lines,
    reason = "transaction fence test covers both reject and restore paths"
)]
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
        tcp_ao_info: None,
        tcp_ao_generation: None,
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
        tcp_ao_info: None,
        tcp_ao_generation: None,
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

    let candidate = tier_authorized_uds_test_config(
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
    );
    let diff = mgr.diff_runtime_config(&candidate).unwrap();

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

fn chainless_policy_query_handle() -> PeerHandle {
    let (commands, mut command_rx) = mpsc::channel(4);
    let task = tokio::spawn(async move {
        while let Some(command) = command_rx.recv().await {
            match command {
                rustbgpd_transport::PeerCommand::QueryImportPolicyTermHits { reply } => {
                    let _ = reply.send(None);
                }
                rustbgpd_transport::PeerCommand::Shutdown => break,
                other => panic!("unexpected peer command: {other:?}"),
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(commands, task)
}

fn gone_policy_query_handle() -> PeerHandle {
    let (commands, command_rx) = mpsc::channel(1);
    drop(command_rx);
    PeerHandle::from_parts(commands, tokio::spawn(async { Ok(()) }))
}

type ControlledPolicyAdmission = (
    IpAddr,
    oneshot::Sender<Option<rustbgpd_transport::ImportPolicyTermHits>>,
);

fn controlled_policy_query_handle(
    address: IpAddr,
    admitted: mpsc::UnboundedSender<ControlledPolicyAdmission>,
) -> PeerHandle {
    let (commands, mut command_rx) = mpsc::channel(4);
    let task = tokio::spawn(async move {
        while let Some(command) = command_rx.recv().await {
            match command {
                rustbgpd_transport::PeerCommand::QueryImportPolicyTermHits { reply } => {
                    let _ = admitted.send((address, reply));
                }
                rustbgpd_transport::PeerCommand::Shutdown => break,
                other => panic!("unexpected peer command: {other:?}"),
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(commands, task)
}

fn disappearing_policy_query_handle(
    admitted: oneshot::Sender<()>,
    disappear: oneshot::Receiver<()>,
) -> PeerHandle {
    let (commands, mut command_rx) = mpsc::channel(4);
    let task = tokio::spawn(async move {
        let Some(command) = command_rx.recv().await else {
            return Ok(());
        };
        match command {
            rustbgpd_transport::PeerCommand::QueryImportPolicyTermHits { reply } => {
                let _ = admitted.send(());
                let _ = disappear.await;
                drop(reply);
                Ok(())
            }
            rustbgpd_transport::PeerCommand::Shutdown => Ok(()),
            other => panic!("unexpected peer command: {other:?}"),
        }
    });
    PeerHandle::from_parts(commands, task)
}

fn controlled_policy_snapshot(address: IpAddr) -> rustbgpd_transport::ImportPolicyTermHits {
    let generation = match address {
        IpAddr::V4(address) => u64::from(address.octets()[3]),
        IpAddr::V6(_) => 0,
    };
    rustbgpd_transport::ImportPolicyTermHits {
        generation,
        evals: generation,
        eval_errors: 0,
        last_error: None,
        terms: Vec::new(),
    }
}

async fn receive_controlled_policy_admissions(
    admitted: &mut mpsc::UnboundedReceiver<ControlledPolicyAdmission>,
    count: usize,
) -> Vec<ControlledPolicyAdmission> {
    tokio::time::timeout(Duration::from_millis(1), async {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(admitted.recv().await.expect("controlled session task"));
        }
        out
    })
    .await
    .expect("expected policy queries were not admitted")
}

/// LAN-661 red proof: validating against static config rejects the accepted
/// dynamic peer; replacing the typed forwarding result with the old `Option`
/// path makes its stalled task return `SessionGone`; silently omitting a
/// timed-out term-hit query makes the second timeout assertion return
/// `Reply([])`. Each production break fails its corresponding assertion.
#[tokio::test(start_paused = true)]
async fn policy_query_timeout_does_not_masquerade_as_missing_session() {
    let (tx, rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let configured = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    insert_test_managed_peer(
        &mut manager,
        configured,
        stalled_policy_query_handle(),
        false,
    );
    manager.peers.get_mut(&key(configured)).unwrap().is_dynamic = true;
    let manager_task = tokio::spawn(manager.run());

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::HasPeerAddress {
        address: configured,
        reply,
    })
    .await
    .unwrap();
    assert!(
        response.await.unwrap(),
        "runtime validation must include an accepted dynamic peer"
    );

    let prefix = rustbgpd_wire::Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
        Ipv4Addr::new(198, 51, 100, 0),
        24,
    ));
    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::ExplainImportPolicy {
        address: configured,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        prefix,
        path_id: None,
        reply,
    })
    .await
    .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(EXPLAIN_QUERY_TIMEOUT).await;
    assert!(matches!(
        response.await.unwrap(),
        SessionQueryOutcome::TimedOut
    ));

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: Some(configured),
        deadline: tokio::time::Instant::now() + EXPLAIN_QUERY_TIMEOUT,
        reply,
    })
    .await
    .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(EXPLAIN_QUERY_TIMEOUT).await;
    assert!(
        matches!(response.await.unwrap(), SessionQueryOutcome::TimedOut),
        "a stalled term-hit query must fail the snapshot instead of being omitted"
    );

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::ExplainImportPolicy {
        address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        prefix,
        path_id: None,
        reply,
    })
    .await
    .unwrap();
    assert!(matches!(
        response.await.unwrap(),
        SessionQueryOutcome::SessionGone
    ));

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

/// LAN-661 red proof: changing the production `Reply(None)` arm to
/// `SessionGone` (or treating it as a row) makes this healthy, answered
/// chainless query fail instead of returning a successful empty snapshot.
#[tokio::test]
async fn import_policy_stats_omit_an_answered_chainless_peer() {
    let (tx, rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    insert_test_managed_peer(&mut manager, peer, chainless_policy_query_handle(), false);
    let manager_task = tokio::spawn(manager.run());

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: Some(peer),
        deadline: tokio::time::Instant::now() + EXPLAIN_QUERY_TIMEOUT,
        reply,
    })
    .await
    .unwrap();
    let outcome = response.await.unwrap();
    assert!(
        matches!(&outcome, SessionQueryOutcome::Reply(rows) if rows.is_empty()),
        "a healthy session without an import chain must answer with no row, got {outcome:?}"
    );

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

/// LAN-661: more stalled sessions than the collector's concurrency cap still
/// consume one aggregate deadline. The actor must remain available while the
/// detached collector waits, so an unrelated address query answers promptly.
#[tokio::test(start_paused = true)]
async fn import_policy_stats_over_concurrency_cap_use_one_deadline_without_blocking_actor() {
    let (tx, rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let peer_count = IMPORT_POLICY_QUERY_CONCURRENCY + 1;
    for host in 1..=peer_count {
        let address = IpAddr::V4(Ipv4Addr::new(198, 51, 100, u8::try_from(host).unwrap()));
        insert_test_managed_peer(&mut manager, address, stalled_policy_query_handle(), false);
    }
    let manager_task = tokio::spawn(manager.run());
    let started = tokio::time::Instant::now();
    let deadline = started + EXPLAIN_QUERY_TIMEOUT;

    let (reply, mut response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: None,
        deadline,
        reply,
    })
    .await
    .unwrap();
    tokio::task::yield_now().await;

    let (reply, has_peer) = oneshot::channel();
    tx.send(PeerManagerCommand::HasPeerAddress {
        address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        reply,
    })
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(1), has_peer)
            .await
            .expect("peer manager actor must not wait for fleet collection")
            .unwrap()
    );
    assert!(
        matches!(
            response.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "stalled sessions must not fabricate an early partial snapshot"
    );

    tokio::time::advance(deadline - tokio::time::Instant::now()).await;
    assert!(matches!(
        response.await.unwrap(),
        SessionQueryOutcome::TimedOut
    ));
    assert_eq!(
        tokio::time::Instant::now() - started,
        EXPLAIN_QUERY_TIMEOUT,
        "N > concurrency cap must still finish at the one fleet deadline"
    );

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

/// LAN-661: bounded unordered collection admits exactly 64 queries, lets
/// later-ready members of that wave open slots for the remainder, and
/// completes every row under the original absolute deadline.
#[tokio::test(start_paused = true)]
async fn import_policy_stats_concurrency_gate_is_64_and_makes_unordered_two_wave_progress() {
    const EXPECTED_CONCURRENCY: usize = 64;

    assert_eq!(
        IMPORT_POLICY_QUERY_CONCURRENCY, EXPECTED_CONCURRENCY,
        "the fleet collector's documented concurrency cap must remain 64"
    );
    let (tx, rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let (admitted_tx, mut admitted_rx) = mpsc::unbounded_channel();
    let peer_count = EXPECTED_CONCURRENCY + 8;
    let mut expected_addresses = Vec::with_capacity(peer_count);
    for host in 1..=peer_count {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, u8::try_from(host).unwrap()));
        expected_addresses.push(address);
        insert_test_managed_peer(
            &mut manager,
            address,
            controlled_policy_query_handle(address, admitted_tx.clone()),
            false,
        );
    }
    // Production snapshots this same HashMap iteration order. Holding its
    // first target makes the unordered proof deterministic: ordered buffering
    // cannot yield any later completion to open a second-wave slot.
    let first_target = manager
        .peers
        .keys()
        .next()
        .expect("controlled fleet is non-empty")
        .address;
    let manager_task = tokio::spawn(manager.run());

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: None,
        deadline: tokio::time::Instant::now() + EXPLAIN_QUERY_TIMEOUT,
        reply,
    })
    .await
    .unwrap();

    let mut first_wave =
        receive_controlled_policy_admissions(&mut admitted_rx, EXPECTED_CONCURRENCY).await;
    assert!(
        matches!(
            admitted_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ),
        "the collector must admit exactly 64 initial queries, not a 65th"
    );

    let first_target_index = first_wave
        .iter()
        .position(|(address, _)| *address == first_target)
        .expect("the source-order first target must be in the initial wave");
    let held_first_target = first_wave.swap_remove(first_target_index);
    // Keep the source-order first future pending while eight later futures
    // complete. Only unordered buffering can use them to open eight slots.
    for (address, reply) in first_wave.drain(..8) {
        reply
            .send(Some(controlled_policy_snapshot(address)))
            .unwrap();
    }
    // Give the single-threaded test runtime ample scheduling turns, then use
    // nonblocking receives. An ordered buffer must fail here promptly rather
    // than hanging the regression proof behind the fleet deadline.
    for _ in 0..(EXPECTED_CONCURRENCY * 4) {
        tokio::task::yield_now().await;
    }
    let second_wave: Vec<_> = (0..8)
        .map(|_| {
            admitted_rx
                .try_recv()
                .expect("later-ready replies must open second-wave slots without source ordering")
        })
        .collect();
    assert!(
        matches!(
            admitted_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ),
        "only the eight newly available slots may admit the remainder"
    );

    for (address, reply) in std::iter::once(held_first_target)
        .chain(first_wave)
        .chain(second_wave)
    {
        reply
            .send(Some(controlled_policy_snapshot(address)))
            .unwrap();
    }
    let SessionQueryOutcome::Reply(rows) = response.await.unwrap() else {
        panic!("all controlled sessions answered before the deadline");
    };
    let actual_addresses: Vec<_> = rows.into_iter().map(|(address, _)| address).collect();
    expected_addresses.sort_unstable();
    assert_eq!(
        actual_addresses, expected_addresses,
        "the complete fleet snapshot must be sorted by peer address"
    );

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

/// LAN-661: dropping the RPC reply before dispatch prevents session queries;
/// dropping it with 64 in-flight queries cancels all of their reply futures
/// promptly instead of retaining the fleet until the deadline.
#[tokio::test(start_paused = true)]
async fn import_policy_stats_caller_drop_cancels_snapshot_and_in_flight_queries() {
    let (tx, rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let (admitted_tx, mut admitted_rx) = mpsc::unbounded_channel();
    for host in 1..=(IMPORT_POLICY_QUERY_CONCURRENCY + 1) {
        let address = IpAddr::V4(Ipv4Addr::new(198, 18, 0, u8::try_from(host).unwrap()));
        insert_test_managed_peer(
            &mut manager,
            address,
            controlled_policy_query_handle(address, admitted_tx.clone()),
            false,
        );
    }

    // Queue a request whose receiver is already gone before the actor starts.
    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: None,
        deadline: tokio::time::Instant::now() + EXPLAIN_QUERY_TIMEOUT,
        reply,
    })
    .await
    .unwrap();
    drop(response);
    let manager_task = tokio::spawn(manager.run());
    let (reply, barrier) = oneshot::channel();
    tx.send(PeerManagerCommand::HasPeerAddress {
        address: IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
        reply,
    })
    .await
    .unwrap();
    assert!(barrier.await.unwrap());
    assert!(
        matches!(
            admitted_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ),
        "a pre-cancelled request must not query the fleet"
    );

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: None,
        deadline: tokio::time::Instant::now() + EXPLAIN_QUERY_TIMEOUT,
        reply,
    })
    .await
    .unwrap();
    let mut admissions =
        receive_controlled_policy_admissions(&mut admitted_rx, IMPORT_POLICY_QUERY_CONCURRENCY)
            .await;
    drop(response);
    tokio::time::timeout(Duration::from_millis(1), async {
        for (_, reply) in &mut admissions {
            reply.closed().await;
        }
    })
    .await
    .expect("caller cancellation must drop every in-flight reply receiver");
    assert!(
        matches!(
            admitted_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ),
        "caller cancellation must not admit the remaining target"
    );

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

/// LAN-661: one successful fleet row followed by a stalled session fails the
/// complete snapshot at the shared deadline; the successful row is not
/// returned as a partial response.
#[tokio::test(start_paused = true)]
async fn import_policy_stats_mixed_success_and_timeout_is_atomic() {
    let (tx, rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let (admitted_tx, mut admitted_rx) = mpsc::unbounded_channel();
    for host in 1..=2 {
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, host));
        insert_test_managed_peer(
            &mut manager,
            address,
            controlled_policy_query_handle(address, admitted_tx.clone()),
            false,
        );
    }
    let manager_task = tokio::spawn(manager.run());
    let deadline = tokio::time::Instant::now() + EXPLAIN_QUERY_TIMEOUT;

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: None,
        deadline,
        reply,
    })
    .await
    .unwrap();
    let mut admissions = receive_controlled_policy_admissions(&mut admitted_rx, 2).await;
    let (address, success) = admissions.pop().unwrap();
    success
        .send(Some(controlled_policy_snapshot(address)))
        .unwrap();
    let mut stalled = admissions.pop().unwrap().1;

    tokio::time::advance(deadline - tokio::time::Instant::now()).await;
    assert!(matches!(
        response.await.unwrap(),
        SessionQueryOutcome::TimedOut
    ));
    stalled.closed().await;

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

/// LAN-661: an all-peers query remains atomic when one session disappears
/// after its command was admitted. A completed sibling row cannot turn that
/// `SessionGone` into partial success.
#[tokio::test(start_paused = true)]
async fn import_policy_stats_all_peers_session_gone_after_admission_is_atomic() {
    let (tx, rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let (admitted_tx, mut admitted_rx) = mpsc::unbounded_channel();
    let successful_peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    insert_test_managed_peer(
        &mut manager,
        successful_peer,
        controlled_policy_query_handle(successful_peer, admitted_tx),
        false,
    );
    let disappearing_peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let (gone_admitted, gone_admission) = oneshot::channel();
    let (disappear, disappear_signal) = oneshot::channel();
    insert_test_managed_peer(
        &mut manager,
        disappearing_peer,
        disappearing_policy_query_handle(gone_admitted, disappear_signal),
        false,
    );
    let manager_task = tokio::spawn(manager.run());

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: None,
        deadline: tokio::time::Instant::now() + EXPLAIN_QUERY_TIMEOUT,
        reply,
    })
    .await
    .unwrap();
    let mut admissions = receive_controlled_policy_admissions(&mut admitted_rx, 1).await;
    gone_admission.await.unwrap();
    let (address, success) = admissions.pop().unwrap();
    success
        .send(Some(controlled_policy_snapshot(address)))
        .unwrap();
    disappear.send(()).unwrap();

    assert!(matches!(
        response.await.unwrap(),
        SessionQueryOutcome::SessionGone
    ));

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

/// LAN-661: a selected managed peer whose command channel is closed is
/// truthfully distinct from both an empty chain and aggregate timeout.
#[tokio::test(start_paused = true)]
async fn import_policy_stats_selected_session_gone_is_truthful() {
    let (tx, rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    insert_test_managed_peer(&mut manager, peer, gone_policy_query_handle(), false);
    let manager_task = tokio::spawn(manager.run());

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: Some(peer),
        deadline: tokio::time::Instant::now() + EXPLAIN_QUERY_TIMEOUT,
        reply,
    })
    .await
    .unwrap();
    assert!(matches!(
        response.await.unwrap(),
        SessionQueryOutcome::SessionGone
    ));

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

/// LAN-661: the actor must reject an expired fleet deadline before resolving
/// a selected peer or observing its already-closed session channel.
#[tokio::test(start_paused = true)]
async fn import_policy_stats_expired_deadline_precedes_resolution_and_selected_session_gone() {
    let (tx, rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    insert_test_managed_peer(&mut manager, peer, gone_policy_query_handle(), false);
    let manager_task = tokio::spawn(manager.run());

    let (reply, missing_response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99))),
        deadline: tokio::time::Instant::now(),
        reply,
    })
    .await
    .unwrap();
    assert!(
        matches!(
            missing_response.await.unwrap(),
            SessionQueryOutcome::TimedOut
        ),
        "deadline rejection must happen before selected-peer resolution"
    );

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: Some(peer),
        deadline: tokio::time::Instant::now(),
        reply,
    })
    .await
    .unwrap();
    assert!(matches!(
        response.await.unwrap(),
        SessionQueryOutcome::TimedOut
    ));

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
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

async fn assert_session_state_query_count(counter: &AtomicUsize, expected: usize) {
    for _ in 0..3 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        expected,
        "expired readiness requests must not query every session"
    );
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

#[tokio::test(start_paused = true)]
async fn manager_shutdown_bounds_many_stalled_peers_by_concurrent_waves() {
    let (tx, rx) = mpsc::channel(1);
    let (rib_tx, _rib_rx) = mpsc::channel(1);
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
    let peer_count = PEER_SHUTDOWN_CONCURRENCY + 1;
    let dropped = Arc::new(AtomicU32::new(0));

    for index in 0..peer_count {
        let host = u8::try_from(index + 1).expect("test peer count fits one IPv4 /24");
        let addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, host));
        let primary = stalled_shutdown_peer_handle(dropped.clone()).await;
        insert_test_managed_peer(&mut mgr, addr, primary, false);
        let pending = stalled_shutdown_peer_handle(dropped.clone()).await;
        mgr.peers.get_mut(&key(addr)).unwrap().pending_inbound = Some(PendingInbound {
            handle: pending,
            session_id: (index + peer_count + 1) as u64,
        });
    }

    let started = tokio::time::Instant::now();
    let manager = tokio::spawn(mgr.run());
    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager.await.unwrap();
    let elapsed = started.elapsed();

    assert!(
        elapsed <= PEER_LIFECYCLE_COMMAND_TIMEOUT * 5,
        "bounded cross-peer shutdown should take two pending+primary waves, took {elapsed:?}"
    );
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        u32::try_from(peer_count * 2).expect("test handle count fits u32"),
        "every timed-out pending and primary task must be aborted and reaped"
    );
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

fn warm_checkpoint_peer_handle(response: Option<WarmCheckpointSessionState>) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        let mut held_replies = Vec::new();
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::QueryWarmCheckpointState { reply } => {
                    if let Some(state) = response.clone() {
                        let _ = reply.send(state);
                    } else {
                        held_replies.push(reply);
                    }
                }
                PeerCommand::Shutdown | PeerCommand::Stop { .. } => break,
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

#[tokio::test]
async fn warm_checkpoint_capture_uses_live_actor_config_identity() {
    let mut mgr = test_peer_manager();
    let startup = mgr.current_config.effective_redacted_toml().unwrap();
    mgr.current_config.global.honor_blackhole = true;
    let addr: IpAddr = "10.0.0.2".parse().unwrap();
    let mut neighbor = config_neighbor(addr, 65002);
    neighbor.gr_restart_time = Some(17);
    mgr.current_config.neighbors.push(neighbor);

    let capture = mgr.query_warm_checkpoint_capture().await.unwrap();
    assert_ne!(capture.effective_config_toml, startup);
    assert!(
        capture
            .effective_config_toml
            .contains("honor_blackhole = true")
    );
    assert_eq!(capture.restart_time_secs, Some(17));
}

#[tokio::test]
async fn warm_checkpoint_rejects_sighup_desired_live_global_identity_drift() {
    let mut mgr = test_peer_manager();

    // SIGHUP accepts restart-required global fields into the desired runtime
    // snapshot, but the listener/session actors retain their boot identity.
    mgr.current_config.global.asn = 65123;
    let error = mgr.query_warm_checkpoint_capture().await.unwrap_err();
    assert!(error.contains("restart-required local identity"), "{error}");
    assert!(error.contains("65123/10.0.0.1"), "{error}");
    assert!(error.contains("65001/10.0.0.1"), "{error}");

    mgr.current_config.global.asn = 65001;
    mgr.current_config.global.router_id = "192.0.2.99".to_string();
    let error = mgr.query_warm_checkpoint_capture().await.unwrap_err();
    assert!(error.contains("restart-required local identity"), "{error}");
    assert!(error.contains("65001/192.0.2.99"), "{error}");
    assert!(error.contains("65001/10.0.0.1"), "{error}");
}

#[tokio::test]
async fn warm_checkpoint_session_query_returns_current_negotiated_identity() {
    let mut mgr = test_peer_manager();
    let addr: IpAddr = "10.0.0.2".parse().unwrap();
    insert_test_managed_peer(
        &mut mgr,
        addr,
        warm_checkpoint_peer_handle(Some(eligible_warm_checkpoint_state())),
        false,
    );
    let mut neighbor = config_neighbor(addr, 65002);
    neighbor.graceful_restart = Some(true);
    neighbor.gr_restart_time = Some(120);
    mgr.current_config.neighbors.push(neighbor);

    let capture = mgr.query_warm_checkpoint_capture().await.unwrap();
    assert_eq!(capture.local_asn, 65001);
    assert_eq!(capture.local_router_id, Ipv4Addr::new(10, 0, 0, 1));
    assert!(capture.effective_config_toml.contains("asn = 65001"));
    assert_eq!(capture.restart_time_secs, Some(120));
    let sessions = capture.sessions;
    assert_eq!(sessions.len(), 1);
    let session = &sessions[0];
    assert_eq!(session.peer, key(addr));
    assert_eq!(session.session_id, 1);
    assert_eq!(session.peer_asn, 65002);
    assert_eq!(session.peer_router_id, Ipv4Addr::new(10, 0, 0, 2));
    assert_eq!(
        session.add_path_receive_families,
        vec![(Afi::Ipv4, Safi::Unicast)]
    );
    assert_eq!(
        session.canonical_import_policy,
        b"rustbgpd/policy-chain/warm-checkpoint/v1/implicit-permit\n"
    );
}

#[tokio::test]
async fn warm_checkpoint_session_query_rejects_pending_collision() {
    let mut mgr = test_peer_manager();
    let addr: IpAddr = "10.0.0.2".parse().unwrap();
    insert_test_managed_peer(
        &mut mgr,
        addr,
        warm_checkpoint_peer_handle(Some(eligible_warm_checkpoint_state())),
        false,
    );
    attach_test_pending_inbound(
        &mut mgr,
        addr,
        warm_checkpoint_peer_handle(Some(eligible_warm_checkpoint_state())),
        2,
    );

    let error = mgr.query_warm_checkpoint_capture().await.unwrap_err();
    assert!(error.contains("unresolved collision candidate"), "{error}");
}

#[tokio::test(start_paused = true)]
async fn warm_checkpoint_session_query_timeout_rejects_complete_snapshot() {
    let mut mgr = test_peer_manager();
    let addr: IpAddr = "10.0.0.2".parse().unwrap();
    insert_test_managed_peer(&mut mgr, addr, warm_checkpoint_peer_handle(None), false);

    let error = mgr.query_warm_checkpoint_capture().await.unwrap_err();
    assert!(error.contains("bounded checkpoint query"), "{error}");
}

#[tokio::test]
async fn warm_checkpoint_session_query_skips_unusable_gr_sessions() {
    let mut mgr = test_peer_manager();
    let no_family_addr: IpAddr = "10.0.0.2".parse().unwrap();
    let zero_restart_addr: IpAddr = "10.0.0.3".parse().unwrap();
    let mut no_family = eligible_warm_checkpoint_state();
    no_family.peer_gr_families.clear();
    let mut zero_restart = eligible_warm_checkpoint_state();
    zero_restart.peer_gr_restart_time = 0;
    insert_test_managed_peer(
        &mut mgr,
        no_family_addr,
        warm_checkpoint_peer_handle(Some(no_family)),
        false,
    );
    insert_test_managed_peer(
        &mut mgr,
        zero_restart_addr,
        warm_checkpoint_peer_handle(Some(zero_restart)),
        false,
    );

    assert!(
        mgr.query_warm_checkpoint_capture()
            .await
            .unwrap()
            .sessions
            .is_empty()
    );
}

#[tokio::test]
async fn unavailable_session_authentication_uses_durable_managed_protection() {
    // Mutation-red for min_hold_time: deleting snapshot propagation yields
    // None instead of the configured 30.
    let mut mgr = test_peer_manager();
    let addr: IpAddr = "10.0.0.44".parse().unwrap();
    let handle = fake_peer_handle(
        addr,
        SessionState::Idle,
        None,
        Arc::new(FakePeerCounters::default()),
    );
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let peer_key = key(addr);

    {
        let managed = mgr.peers.get_mut(&peer_key).unwrap();
        managed.is_dynamic = true;
        managed.tcp_ao_protected = true;
        managed.transport_config.peer.min_hold_time = Some(30);
        assert!(managed.transport_config.tcp_ao.is_none());
        let info = super::snapshot::build_peer_info(&peer_key, managed, None, false);
        assert_eq!(info.authentication, "tcp_ao");
        assert_eq!(info.min_hold_time, Some(30));
        assert!(info.tcp_ao_info.is_none());
        assert!(info.stale);

        managed.is_dynamic = false;
        managed.tcp_ao_protected = true;
        assert_eq!(
            super::snapshot::build_peer_info(&peer_key, managed, None, false).authentication,
            "tcp_ao"
        );

        managed.tcp_ao_protected = false;
        assert_eq!(
            super::snapshot::build_peer_info(&peer_key, managed, None, false).authentication,
            "plaintext"
        );

        managed.transport_config.md5_password = Some("test-password".into());
        assert_eq!(
            super::snapshot::build_peer_info(&peer_key, managed, None, false).authentication,
            "md5"
        );
    }

    let managed = mgr.peers.remove(&peer_key).unwrap();
    managed.handle.shutdown().await.unwrap().unwrap();
}

/// Load-bearing: sourcing this from unavailable session state, or omitting the
/// `ManagedPeer` copy, makes the asserted true intent disappear.
#[tokio::test]
async fn unavailable_session_preserves_graceful_shutdown_advertise_intent() {
    let mut mgr = test_peer_manager();
    let addr: IpAddr = "10.0.0.45".parse().unwrap();
    let handle = fake_peer_handle(
        addr,
        SessionState::Idle,
        None,
        Arc::new(FakePeerCounters::default()),
    );
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let peer_key = key(addr);
    let managed = mgr.peers.get_mut(&peer_key).unwrap();
    managed.advertise_graceful_shutdown = true;

    let info = super::snapshot::build_peer_info(&peer_key, managed, None, false);
    assert!(info.graceful_shutdown_advertise_intent);
    assert!(info.stale);

    let managed = mgr.peers.remove(&peer_key).unwrap();
    managed.handle.shutdown().await.unwrap().unwrap();
}

fn effective_posture(
    info: &rustbgpd_api::peer_types::PeerInfo,
) -> (bool, bool, bool, Option<IpAddr>) {
    (
        info.next_hop_ownership_strict_peer,
        info.interpret_rfc1997,
        info.rs_control_communities,
        info.orr_vantage,
    )
}

const EFFECTIVE_POSTURE_TOML: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[peer_groups.inherited_rs]
route_server_client = true
next_hop_ownership = "strict_peer"
interpret_rfc1997 = true
rs_control_communities = false
[peer_groups.rr_clients]
route_reflector_client = true
orr_vantage = "192.0.2.7"
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
route_server_client = true
[[neighbors]]
address = "10.0.0.4"
remote_asn = 65004
route_server_client = true
next_hop_ownership = "strict_peer"
interpret_rfc1997 = true
rs_control_communities = false
[[neighbors]]
address = "10.0.0.5"
remote_asn = 65005
peer_group = "inherited_rs"
[[neighbors]]
address = "10.0.0.6"
remote_asn = 65001
peer_group = "rr_clients"
[[dynamic_neighbors]]
prefix = "127.0.0.0/8"
peer_group = "inherited_rs"
remote_asn = 0
"#;

/// Load-bearing snapshot proof across the supported resolution shapes:
/// deleting any `ManagedPeer.transport_config` posture assignment makes at
/// least one exact tuple fall back to the `PeerInfo` fixture defaults.
#[tokio::test]
async fn effective_posture_snapshot_reports_resolved_static_values() {
    let config = load_test_config(EFFECTIVE_POSTURE_TOML);
    let mut mgr = test_peer_manager();
    for (index, resolved) in config.resolved_neighbors().unwrap().into_iter().enumerate() {
        mgr.install_established_policy_test_peer(resolved, index as u64 + 1);
    }

    let snapshot = |address: &str| {
        let peer = key(address.parse().unwrap());
        super::snapshot::build_peer_info(&peer, mgr.peers.get(&peer).unwrap(), None, false)
    };
    let cases = [
        ("10.0.0.2", (false, true, false, None), "plain eBGP"),
        ("10.0.0.3", (false, false, true, None), "RS defaults"),
        ("10.0.0.4", (true, true, false, None), "neighbor override"),
        ("10.0.0.5", (true, true, false, None), "group inheritance"),
        (
            "10.0.0.6",
            (false, true, false, Some("192.0.2.7".parse().unwrap())),
            "ORR inheritance",
        ),
    ];
    for (address, expected, shape) in cases {
        assert_eq!(effective_posture(&snapshot(address)), expected, "{shape}");
    }

    for (_, managed) in mgr.peers.drain() {
        managed.handle.shutdown().await.unwrap().unwrap();
    }
}

/// Load-bearing accepted-dynamic parity proof: dropping resolved posture while
/// retaining the live inbound child makes its snapshot differ from the static
/// member inheriting the same peer group.
#[tokio::test]
async fn effective_posture_snapshot_keeps_dynamic_inheritance_at_static_parity() {
    let config = load_test_config(EFFECTIVE_POSTURE_TOML);
    let static_rs = config
        .resolved_neighbors()
        .unwrap()
        .into_iter()
        .find(|peer| {
            peer.transport_config.remote_addr.ip() == "10.0.0.5".parse::<IpAddr>().unwrap()
        })
        .unwrap();
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mut mgr = PeerManager::new_with_config(
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
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();
    mgr.handle_inbound(server_stream, sock(remote_addr.ip()), None, None)
        .await;
    mgr.install_established_policy_test_peer(static_rs, 99);

    let snapshot = |address: &str| {
        let peer = key(address.parse().unwrap());
        super::snapshot::build_peer_info(&peer, mgr.peers.get(&peer).unwrap(), None, false)
    };
    let static_rs = snapshot("10.0.0.5");
    let dynamic_rs = snapshot(&remote_addr.ip().to_string());
    assert_eq!(
        effective_posture(&static_rs),
        effective_posture(&dynamic_rs)
    );
    assert!(!static_rs.is_dynamic && dynamic_rs.is_dynamic);

    drop(client_stream);
    for (_, managed) in mgr.peers.drain() {
        managed.handle.shutdown().await.unwrap().unwrap();
    }
}

/// Load-bearing: sourcing live counts from config or deriving stale headroom
/// from zero placeholders makes at least one exact snapshot assertion fail.
#[tokio::test]
async fn max_prefix_snapshot_uses_live_accounting_and_withholds_stale_headroom() {
    let mut mgr = test_peer_manager();
    let addr: IpAddr = "10.0.0.46".parse().unwrap();
    let handle = fake_peer_handle(
        addr,
        SessionState::Idle,
        None,
        Arc::new(FakePeerCounters::default()),
    );
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let peer_key = key(addr);
    let managed = mgr.peers.get_mut(&peer_key).unwrap();
    managed.max_prefixes = Some(30);
    managed.transport_config.max_prefixes_ipv4 = Some(20);
    managed.transport_config.max_prefixes_ipv6 = Some(10);

    let mut state = policy_test_peer_state(addr, SessionState::Established);
    state.prefix_count = 11;
    state.max_prefix.prefix_count_ipv4 = 7;
    state.max_prefix.prefix_count_ipv6 = 3;
    state.max_prefix.max_prefixes = Some(25);
    state.max_prefix.max_prefixes_ipv4 = Some(15);
    state.max_prefix.max_prefixes_ipv6 = None;
    state.max_prefix.headroom = Some(14);
    state.max_prefix.headroom_ipv4 = Some(8);

    let live = super::snapshot::build_peer_info(&peer_key, managed, Some(&state), false);
    assert_eq!(
        (
            live.prefix_count,
            live.prefix_count_ipv4,
            live.prefix_count_ipv6
        ),
        (11, 7, 3)
    );
    assert_eq!(live.max_prefixes_effective, Some(25));
    assert_eq!(live.max_prefixes_ipv4_effective, Some(15));
    assert_eq!(live.max_prefixes_ipv6_effective, None);
    assert_eq!(live.max_prefix_headroom, Some(14));
    assert_eq!(live.max_prefix_headroom_ipv4, Some(8));
    assert_eq!(live.max_prefix_headroom_ipv6, None);

    let stale_info = super::snapshot::build_peer_info(&peer_key, managed, None, false);
    assert_eq!(stale_info.max_prefixes_effective, Some(30));
    assert_eq!(stale_info.max_prefixes_ipv4_effective, Some(20));
    assert_eq!(stale_info.max_prefixes_ipv6_effective, Some(10));
    assert_eq!(
        (
            stale_info.max_prefix_headroom,
            stale_info.max_prefix_headroom_ipv4,
            stale_info.max_prefix_headroom_ipv6,
        ),
        (None, None, None)
    );

    let managed = mgr.peers.remove(&peer_key).unwrap();
    managed.handle.shutdown().await.unwrap().unwrap();
}

/// Load-bearing proof: copying configured families or the `OpenConfirm` identity
/// fields when the actor snapshot is absent makes the stale assertion fail;
/// dropping the live actor projection makes the exact live assertion fail.
#[tokio::test]
async fn negotiated_snapshot_uses_only_fresh_established_actor_state() {
    let mut mgr = test_peer_manager();
    let addr: IpAddr = "10.0.0.47".parse().unwrap();
    let handle = fake_peer_handle(
        addr,
        SessionState::Idle,
        None,
        Arc::new(FakePeerCounters::default()),
    );
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let peer_key = key(addr);
    let managed = mgr.peers.get_mut(&peer_key).unwrap();
    managed.transport_config.peer.families = vec![(Afi::Ipv4, Safi::Unicast)];

    let mut state = policy_test_peer_state(addr, SessionState::Established);
    state.negotiated_hold_time = Some(90);
    state.four_octet_as = Some(true);
    state.remote_router_id = Some(Ipv4Addr::new(198, 51, 100, 1));
    state.negotiated_session = Some(rustbgpd_transport::NegotiatedSessionState {
        hold_time: 33,
        remote_router_id: Ipv4Addr::new(192, 0, 2, 7),
        four_octet_as: false,
        families: vec![(Afi::Ipv6, Safi::Unicast)],
        peer_route_refresh: true,
        peer_enhanced_route_refresh: true,
        peer_extended_message: true,
        outbound_max_message_bytes: rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN,
        graceful_restart: None,
    });

    let live = super::snapshot::build_peer_info(&peer_key, managed, Some(&state), false);
    assert_eq!(live.negotiated_session, state.negotiated_session);

    let stale_info = super::snapshot::build_peer_info(&peer_key, managed, None, false);
    assert!(stale_info.stale);
    assert!(stale_info.negotiated_session.is_none());

    state.fsm_state = SessionState::Idle;
    state.negotiated_session = None;
    let fresh_down = super::snapshot::build_peer_info(&peer_key, managed, Some(&state), false);
    assert!(!fresh_down.stale);
    assert!(fresh_down.negotiated_session.is_none());

    let managed = mgr.peers.remove(&peer_key).unwrap();
    managed.handle.shutdown().await.unwrap().unwrap();
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

/// Load-bearing timed-restart proof: removing the run-loop sleep, using
/// `>=` one second early, extending on a duplicate terminal notice, or leaving
/// the latch armed after success makes one of the exact count/deadline/status
/// assertions fail.
#[tokio::test(start_paused = true)]
async fn max_prefix_restart_fires_at_exact_first_deadline_once() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(16);
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
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 70));
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        addr,
        fake_peer_handle(addr, SessionState::Idle, None, counters.clone()),
        false,
    );
    let managed = mgr.peers.get_mut(&key(addr)).unwrap();
    managed.enabled = false;
    managed.max_prefix_restart_seconds = Some(30);
    assert!(mgr.install_max_prefix_latch(
        key(addr),
        1,
        "max-prefix limit exceeded: 501 accepted, bound 500".to_string(),
        Some(30),
    ));

    tokio::time::advance(Duration::from_secs(10)).await;
    let info = mgr.get_peer_info(&key(addr)).await.unwrap();
    assert_eq!(info.max_prefix_action, "restart");
    assert_eq!(info.max_prefix_restart_seconds, Some(30));
    assert_eq!(info.max_prefix_restart_remaining_millis, Some(20_000));
    assert!(!mgr.install_max_prefix_latch(
        key(addr),
        2,
        "duplicate terminal notice".to_string(),
        Some(30),
    ));

    let task = tokio::spawn(mgr.run());
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(19)).await;
    tokio::task::yield_now().await;
    assert_eq!(counters.start.load(Ordering::SeqCst), 0);

    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(counters.start.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    assert_eq!(counters.start.load(Ordering::SeqCst), 1);

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply })
        .await
        .unwrap();
    let peers = response.await.unwrap();
    assert!(peers[0].enabled);
    assert_eq!(peers[0].max_prefix_action, "restart");
    assert_eq!(peers[0].max_prefix_restart_remaining_millis, None);
    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    task.await.unwrap();
}

/// Load-bearing re-arm proof: after the first automatic restart, a second
/// terminal max-prefix notification must create one fresh hold-down. Failing
/// to remove the consumed latch suppresses the second incident; reusing its
/// deadline fires early; retaining either deadline adds extra Start attempts.
#[tokio::test(start_paused = true)]
async fn post_restart_second_breach_gets_one_fresh_hold_down() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 74));
    let counters = Arc::new(FakePeerCounters::default());
    let handle = max_prefix_on_command_peer_handle(
        addr,
        1,
        rustbgpd_transport::SessionRole::Primary,
        MaxPrefixTrigger::StartTwice,
        mgr.session_notify_tx.clone(),
        counters.clone(),
    );
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    mgr.peers
        .get_mut(&key(addr))
        .unwrap()
        .max_prefix_restart_seconds = Some(30);

    mgr.peers[&key(addr)].handle.start().await.unwrap();
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    mgr.drain_ready_session_notifications().await;
    assert_eq!(counters.start.load(Ordering::SeqCst), 1);
    let first_generation = mgr.max_prefix_latches[&key(addr)].generation;

    tokio::time::advance(Duration::from_secs(30)).await;
    mgr.handle_due_max_prefix_restarts().await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    mgr.drain_ready_session_notifications().await;
    assert_eq!(counters.start.load(Ordering::SeqCst), 2);
    let second = &mgr.max_prefix_latches[&key(addr)];
    assert_ne!(second.generation, first_generation);
    assert_eq!(
        second.deadline.unwrap() - tokio::time::Instant::now(),
        Duration::from_secs(30),
        "the second incident must own a full fresh hold-down"
    );

    tokio::time::advance(Duration::from_secs(29)).await;
    mgr.handle_due_max_prefix_restarts().await;
    assert_eq!(counters.start.load(Ordering::SeqCst), 2);
    tokio::time::advance(Duration::from_secs(1)).await;
    mgr.handle_due_max_prefix_restarts().await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    mgr.drain_ready_session_notifications().await;
    assert_eq!(counters.start.load(Ordering::SeqCst), 3);
    assert!(!mgr.max_prefix_latches.contains_key(&key(addr)));
    tokio::time::advance(Duration::from_secs(31)).await;
    mgr.handle_due_max_prefix_restarts().await;
    assert_eq!(counters.start.load(Ordering::SeqCst), 3);
}

/// Load-bearing explicit-disable race proof: removing the pre-await deadline
/// invalidation lets the due handler send Start after the operator's Stop.
#[tokio::test(start_paused = true)]
async fn explicit_disable_consumes_pending_max_prefix_restart() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 71));
    let counters = Arc::new(FakePeerCounters::default());
    let handle = max_prefix_on_command_peer_handle(
        addr,
        1,
        rustbgpd_transport::SessionRole::Primary,
        MaxPrefixTrigger::CollisionDump,
        mgr.session_notify_tx.clone(),
        counters.clone(),
    );
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let managed = mgr.peers.get_mut(&key(addr)).unwrap();
    managed.enabled = false;
    managed.max_prefix_restart_seconds = Some(30);
    mgr.install_max_prefix_latch(key(addr), 1, "max-prefix".to_string(), Some(30));

    mgr.disable_peer(key(addr), None).await.unwrap();
    assert!(
        mgr.max_prefix_latches
            .get(&key(addr))
            .is_some_and(|latch| latch.deadline.is_none())
    );
    tokio::time::advance(Duration::from_secs(31)).await;
    mgr.handle_due_max_prefix_restarts().await;
    tokio::task::yield_now().await;
    assert_eq!(counters.stop.load(Ordering::SeqCst), 1);
    assert_eq!(counters.start.load(Ordering::SeqCst), 0);
    assert!(!mgr.peers.get(&key(addr)).unwrap().enabled);
}

/// Load-bearing dynamic-range fence: deleting the accepting range must remove
/// remaining-time visibility immediately. Omitting delete-time invalidation
/// leaves the old deadline armed and this assertion red.
#[tokio::test(start_paused = true)]
async fn dynamic_range_removal_invalidates_max_prefix_restart() {
    let mut mgr = dynamic_test_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 72));
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_dynamic_managed_peer(
        &mut mgr,
        addr,
        72,
        fake_peer_handle(addr, SessionState::Idle, None, counters.clone()),
        false,
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        8,
        "ix-members",
    );
    mgr.peers
        .get_mut(&key(addr))
        .unwrap()
        .max_prefix_restart_seconds = Some(30);
    mgr.install_max_prefix_latch(key(addr), 72, "max-prefix".to_string(), Some(30));

    mgr.delete_dynamic_range("127.0.0.0/8").unwrap();
    let latch = mgr.max_prefix_latches.get(&key(addr)).unwrap();
    assert!(latch.deadline.is_none());
    let info = mgr.get_peer_info(&key(addr)).await.unwrap();
    assert_eq!(info.max_prefix_action, "shutdown");
    assert_eq!(info.max_prefix_restart_remaining_millis, None);
    tokio::time::advance(Duration::from_secs(31)).await;
    mgr.handle_due_max_prefix_restarts().await;
    assert_eq!(counters.start.load(Ordering::SeqCst), 0);
}

/// Load-bearing single-attempt proof: retaining the deadline after a failed
/// Start turns the feature into an unbounded retry loop; clearing the latch
/// entirely weakens fail-closed recovery. Omitting failure replacement leaves
/// the stale breach text instead of the exact recovery action.
#[tokio::test(start_paused = true)]
async fn failed_max_prefix_restart_becomes_indefinite_shutdown() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 73));
    let (commands, receiver) = mpsc::channel(1);
    drop(receiver);
    let task = tokio::spawn(async { Ok(()) });
    insert_test_managed_peer(
        &mut mgr,
        addr,
        PeerHandle::from_parts(commands, task),
        false,
    );
    let managed = mgr.peers.get_mut(&key(addr)).unwrap();
    managed.enabled = false;
    managed.max_prefix_restart_seconds = Some(1);
    mgr.install_max_prefix_latch(key(addr), 1, "max-prefix".to_string(), Some(1));

    tokio::time::advance(Duration::from_secs(1)).await;
    mgr.handle_due_max_prefix_restarts().await;
    let managed = mgr.peers.get(&key(addr)).unwrap();
    assert!(!managed.enabled);
    let latch = mgr.max_prefix_latches.get(&key(addr)).unwrap();
    assert!(latch.deadline.is_none());
    assert_eq!(
        latch.error,
        "automatic max-prefix restart failed: session task exited; peer remains disabled; run 'rbgp neighbor 10.0.0.73 enable' to retry"
    );
    let info = mgr.get_peer_info(&key(addr)).await.unwrap();
    assert_eq!(info.max_prefix_action, "shutdown");
    assert_eq!(info.max_prefix_restart_remaining_millis, None);
    tokio::time::advance(Duration::from_secs(10)).await;
    mgr.handle_due_max_prefix_restarts().await;
    assert!(mgr.max_prefix_latches[&key(addr)].deadline.is_none());
}

fn full_max_prefix_restart_channel(release_after: Option<Duration>) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;

    let (commands, mut receiver) = mpsc::channel(1);
    commands
        .try_send(PeerCommand::Start)
        .expect("pre-fill the automatic-restart command channel");
    let task = tokio::spawn(async move {
        if let Some(delay) = release_after {
            tokio::time::sleep(delay).await;
            let _ = receiver.recv().await;
        }
        std::future::pending::<Result<(), rustbgpd_transport::TransportError>>().await
    });
    PeerHandle::from_parts(commands, task)
}

/// Load-bearing aggregate-restart proof:
/// - sequential per-peer waits make the handler exceed the exact 500 ms bound;
/// - bypassing `await_with_readiness` leaves the queued snapshot unanswered at 100 ms;
/// - applying futures in completion order publishes the high peer before the low peer;
/// - retaining the breach text instead of the delivery failure breaks the exact recovery error.
#[tokio::test(start_paused = true)]
async fn due_max_prefix_restarts_share_one_readiness_serving_deadline() {
    use rustbgpd_api::peer_types::PeerManagerReadinessQuery;

    let low = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 80));
    let middle = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 81));
    let high = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 82));
    let (_commands_tx, commands_rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let (readiness_tx, readiness_rx) = mpsc::channel(1);
    let mut mgr = PeerManager::new(
        commands_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    )
    .with_readiness_queries(readiness_rx);
    for (address, release_after) in [
        (low, Some(Duration::from_millis(300))),
        (middle, None),
        (high, Some(Duration::from_millis(100))),
    ] {
        insert_test_managed_peer(
            &mut mgr,
            address,
            full_max_prefix_restart_channel(release_after),
            false,
        );
        let managed = mgr.peers.get_mut(&key(address)).unwrap();
        managed.enabled = false;
        managed.max_prefix_restart_seconds = Some(1);
        assert!(mgr.install_max_prefix_latch(
            key(address),
            1,
            format!("stale max-prefix breach for {address}"),
            Some(0),
        ));
    }

    let mut events = mgr.session_events_tx.subscribe();
    let (readiness_reply, readiness_response) = oneshot::channel();
    readiness_tx
        .send(PeerManagerReadinessQuery::ListPeers {
            reply: readiness_reply,
        })
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    let readiness = tokio::spawn(async move {
        let peers = readiness_response.await.unwrap();
        (tokio::time::Instant::now(), peers)
    });
    let handler = tokio::spawn(async move {
        mgr.handle_due_max_prefix_restarts().await;
        mgr
    });
    tokio::task::yield_now().await;

    // Check between the snapshot's 100 ms per-session bound and the 200 ms
    // readiness contract, avoiding an assertion on the timeout timer's edge.
    tokio::time::advance(Duration::from_millis(150)).await;
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert!(readiness.is_finished());
    let (readiness_at, peers) = readiness.await.unwrap();
    assert_eq!(peers.len(), 3);
    assert!(readiness_at - started < Duration::from_millis(200));

    tokio::time::advance(Duration::from_millis(150)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(199)).await;
    tokio::task::yield_now().await;
    assert!(!handler.is_finished());
    tokio::time::advance(Duration::from_millis(1)).await;
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert!(handler.is_finished());
    let mgr = handler.await.unwrap();
    assert_eq!(
        tokio::time::Instant::now() - started,
        Duration::from_millis(500)
    );

    let enabled: Vec<IpAddr> = std::iter::from_fn(|| events.try_recv().ok())
        .filter_map(|event| match event {
            SessionEvent::Lifecycle(event)
                if event.event_type == SessionLifecycleEventType::PeerEnabled =>
            {
                Some(event.peer)
            }
            _ => None,
        })
        .collect();
    assert_eq!(enabled, vec![low, high]);
    assert!(mgr.peers[&key(low)].enabled);
    assert!(!mgr.peers[&key(middle)].enabled);
    assert!(mgr.peers[&key(high)].enabled);
    assert_eq!(mgr.max_prefix_latches[&key(middle)].deadline, None);
    assert_eq!(
        mgr.max_prefix_latches[&key(middle)].error,
        "automatic max-prefix restart failed: start timed out after 500ms; peer remains disabled; run 'rbgp neighbor 10.0.0.81 enable' to retry"
    );
}

fn straddling_restart_channel(starts: Arc<AtomicU32>) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;

    let (commands, mut receiver) = mpsc::channel(1);
    commands
        .try_send(PeerCommand::CollisionDump)
        .expect("pre-fill the straddling command channel");
    let task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(550)).await;
        let _ = receiver.recv().await;
        while let Some(command) = receiver.recv().await {
            if matches!(command, PeerCommand::Start) {
                starts.fetch_add(1, Ordering::SeqCst);
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(commands, task)
}

/// Load-bearing expired-deadline proof: replacing the biased deadline-first
/// select with `timeout_at` lets the newly writable send win when the second
/// readiness snapshot returns after the deadline, enabling the peer and
/// incrementing `starts` at 550 ms.
#[tokio::test(start_paused = true)]
async fn readiness_straddle_cannot_accept_a_late_max_prefix_start() {
    use rustbgpd_api::peer_types::PeerManagerReadinessQuery;

    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 83));
    let starts = Arc::new(AtomicU32::new(0));
    let (readiness_tx, readiness_rx) = mpsc::channel(2);
    let mut mgr = test_peer_manager().with_readiness_queries(readiness_rx);
    insert_test_managed_peer(
        &mut mgr,
        address,
        straddling_restart_channel(starts.clone()),
        false,
    );
    let managed = mgr.peers.get_mut(&key(address)).unwrap();
    managed.enabled = false;
    managed.max_prefix_restart_seconds = Some(1);
    mgr.install_max_prefix_latch(key(address), 1, "stale breach".to_string(), Some(0));

    let started = tokio::time::Instant::now();
    let handler = tokio::spawn(async move {
        mgr.handle_due_max_prefix_restarts().await;
        mgr
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(450)).await;
    let (second_reply, second_response) = oneshot::channel();
    readiness_tx
        .send(PeerManagerReadinessQuery::ListPeers {
            reply: second_reply,
        })
        .await
        .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(100)).await;
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    second_response.await.unwrap();
    let mgr = handler.await.unwrap();

    assert_eq!(
        tokio::time::Instant::now() - started,
        Duration::from_millis(550)
    );
    assert_eq!(starts.load(Ordering::SeqCst), 0);
    assert!(!mgr.peers[&key(address)].enabled);
    assert!(
        mgr.max_prefix_latches[&key(address)]
            .error
            .contains("start timed out after 500ms")
    );
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

/// Load-bearing full-reconfigure proof: removing the pre-delete invalidation
/// lets an old incident's timer restart the replacement peer after 30 seconds.
#[tokio::test(start_paused = true)]
async fn reconfigure_peer_preserves_disabled_state_and_cancels_old_restart() {
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
    let mut initial = make_config(addr, 65002);
    initial.max_prefix_restart_seconds = Some(30);
    mgr.add_peer(initial, false).await.unwrap();
    mgr.disable_peer(key(addr), None).await.unwrap();
    mgr.install_max_prefix_latch(
        key(addr),
        0,
        "max-prefix limit exceeded: 501 accepted, bound 500".to_string(),
        Some(30),
    );
    let original_generation = mgr.max_prefix_latches[&key(addr)].generation;

    let mut replacement = make_config(addr, 65002);
    replacement.hold_time = Some(45);
    replacement.max_prefix_restart_seconds = Some(30);
    let previous = mgr.reconfigure_peer(replacement).await.unwrap();

    assert_eq!(previous.hold_time, Some(90));
    let managed = mgr.peers.get(&key(addr)).expect("reconfigured peer");
    assert_eq!(managed.hold_time, Some(45));
    assert!(!managed.enabled);
    assert!(
        mgr.max_prefix_latches.contains_key(&key(addr)),
        "reconfigure's non-reap delete/re-add must preserve the latch"
    );
    let latch = &mgr.max_prefix_latches[&key(addr)];
    assert!(
        latch.deadline.is_none(),
        "replacement must cancel the old timer"
    );
    assert_ne!(
        latch.generation, original_generation,
        "replacement must fence the old latch generation"
    );
    tokio::time::advance(Duration::from_secs(31)).await;
    mgr.handle_due_max_prefix_restarts().await;
    assert!(!mgr.peers[&key(addr)].enabled);
    assert!(mgr.max_prefix_latches.contains_key(&key(addr)));
}

/// Load-bearing reconcile recovery proof: if a changed peer's re-add failed,
/// the next reconcile classifies it as Added. Removing the centralized latch
/// check in `add_peer_with_admin_state` starts it despite the retained shutdown.
#[tokio::test]
async fn classified_add_honors_retained_max_prefix_latch() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 22));
    mgr.install_max_prefix_latch(
        key(addr),
        0,
        "max-prefix limit exceeded: 501 accepted, bound 500".to_string(),
        None,
    );

    mgr.add_peer(make_config(addr, 65002), false).await.unwrap();

    assert!(
        !mgr.peers.get(&key(addr)).unwrap().enabled,
        "a retained latch must keep a later classified Add disabled"
    );
    mgr.delete_peer(key(addr), false).await.unwrap();
    assert!(
        !mgr.max_prefix_latches.contains_key(&key(addr)),
        "authoritative peer deletion must clear the retained latch"
    );
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
async fn hot_update_peer_forwards_and_records_gr_peer_restart_cap() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
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
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 82));
    let (handle, mut seen_rx) = recording_runtime_config_handle();
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let session_id = mgr.peers[&key(addr)].session_id;

    let mut updated = make_config(addr, 65002);
    updated.gr_peer_restart_time_max = 300;
    mgr.hot_update_peer(updated).await.unwrap();

    // Load-bearing end-to-end proof for the manager seam:
    // - removing the comparison sends no command;
    // - forwarding the old/default cap observes 4095 instead of 300;
    // - removing the manager-side copy leaves the stored value at 4095.
    assert_eq!(seen_rx.try_recv().unwrap(), 300);
    assert!(seen_rx.try_recv().is_err(), "cap-only edit sent twice");
    let managed = &mgr.peers[&key(addr)];
    assert_eq!(managed.session_id, session_id);
    assert_eq!(managed.transport_config.gr_peer_restart_time_max, 300);
}

/// Load-bearing hot-update boundary proof: an unrelated accepted edit keeps
/// the exact armed incident, while a successful restart-duration change
/// reschedules it to now + new under a fresh generation. Removing the
/// conditional re-arm leaves the old deadline and makes the rescheduling
/// assertions red; making it unconditional makes the identity assertions red.
#[tokio::test(start_paused = true)]
async fn hot_update_peer_rearms_restart_when_duration_changes() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
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
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 75));
    let mut initial = make_config(addr, 65002);
    initial.max_prefix_restart_seconds = Some(30);
    mgr.add_peer(initial, false).await.unwrap();
    mgr.disable_peer(key(addr), None).await.unwrap();

    mgr.install_max_prefix_latch(key(addr), 1, "original".to_string(), Some(30));
    let original_generation = mgr.max_prefix_latches[&key(addr)].generation;
    let original_deadline = mgr.max_prefix_latches[&key(addr)].deadline;
    let mut description_edit = make_config(addr, 65002);
    description_edit.max_prefix_restart_seconds = Some(30);
    description_edit.description = "updated".to_string();
    mgr.hot_update_peer(description_edit).await.unwrap();
    assert_eq!(
        mgr.max_prefix_latches[&key(addr)].generation,
        original_generation
    );
    assert_eq!(
        mgr.max_prefix_latches[&key(addr)].deadline,
        original_deadline
    );

    tokio::time::advance(Duration::from_secs(10)).await;
    let mut duration_edit = make_config(addr, 65002);
    duration_edit.max_prefix_restart_seconds = Some(60);
    duration_edit.description = "updated".to_string();
    mgr.hot_update_peer(duration_edit).await.unwrap();
    let latch = &mgr.max_prefix_latches[&key(addr)];
    assert_ne!(latch.generation, original_generation);
    assert_eq!(
        latch.deadline.unwrap() - tokio::time::Instant::now(),
        Duration::from_mins(1),
        "an accepted duration edit must reschedule the countdown to now + new"
    );
    assert_eq!(
        mgr.next_max_prefix_restart_deadline, latch.deadline,
        "the cached earliest wake must track the rescheduled deadline"
    );
}

/// Load-bearing fence proof for the re-arm: after a duration edit the
/// superseded deadline can never fire — past it (but before the new one) no
/// Start is issued; past the new one the single attempt fires exactly once
/// and is not repeated.
#[tokio::test(start_paused = true)]
async fn rearmed_restart_ignores_superseded_deadline_and_fires_once() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 78));
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        addr,
        fake_peer_handle(addr, SessionState::Idle, None, counters.clone()),
        false,
    );
    let managed = mgr.peers.get_mut(&key(addr)).unwrap();
    managed.enabled = false;
    managed.max_prefix_restart_seconds = Some(30);
    mgr.install_max_prefix_latch(key(addr), 1, "max-prefix".to_string(), Some(30));

    tokio::time::advance(Duration::from_secs(10)).await;
    let mut edit = make_config(addr, 65002);
    edit.max_prefix_restart_seconds = Some(60);
    mgr.hot_update_peer(edit).await.unwrap();

    // Past the superseded t+30 deadline but before the re-armed t+70 one.
    tokio::time::advance(Duration::from_secs(40)).await;
    mgr.handle_due_max_prefix_restarts().await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(counters.start.load(Ordering::SeqCst), 0);
    assert!(!mgr.peers[&key(addr)].enabled);

    tokio::time::advance(Duration::from_secs(20)).await;
    mgr.handle_due_max_prefix_restarts().await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(counters.start.load(Ordering::SeqCst), 1);
    assert!(mgr.peers[&key(addr)].enabled);
    assert!(!mgr.max_prefix_latches.contains_key(&key(addr)));

    tokio::time::advance(Duration::from_mins(2)).await;
    mgr.handle_due_max_prefix_restarts().await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(counters.start.load(Ordering::SeqCst), 1);
}

/// Load-bearing exactly-once proof: once the single automatic attempt is
/// consumed (here by a failed Start), a later duration edit must not grant a
/// second one — the peer stays latched until an explicit enable.
#[tokio::test(start_paused = true)]
async fn duration_edit_does_not_rearm_consumed_restart_attempt() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 79));
    let (commands, receiver) = mpsc::channel(1);
    drop(receiver);
    let task = tokio::spawn(async { Ok(()) });
    insert_test_managed_peer(
        &mut mgr,
        addr,
        PeerHandle::from_parts(commands, task),
        false,
    );
    let managed = mgr.peers.get_mut(&key(addr)).unwrap();
    managed.enabled = false;
    managed.max_prefix_restart_seconds = Some(1);
    mgr.install_max_prefix_latch(key(addr), 1, "max-prefix".to_string(), Some(1));

    tokio::time::advance(Duration::from_secs(1)).await;
    mgr.handle_due_max_prefix_restarts().await;
    assert!(mgr.max_prefix_latches[&key(addr)].deadline.is_none());

    let mut edit = make_config(addr, 65002);
    edit.max_prefix_restart_seconds = Some(60);
    mgr.hot_update_peer(edit).await.unwrap();
    assert!(
        mgr.max_prefix_latches[&key(addr)].deadline.is_none(),
        "a consumed attempt must not be re-armed by a duration edit"
    );
    tokio::time::advance(Duration::from_mins(2)).await;
    mgr.handle_due_max_prefix_restarts().await;
    assert!(!mgr.peers[&key(addr)].enabled);
}

/// Removing the restart duration during an armed hold-down cancels the
/// countdown; the peer stays fail-closed latched until an explicit enable.
#[tokio::test(start_paused = true)]
async fn removing_restart_duration_cancels_armed_countdown() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 84));
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        addr,
        fake_peer_handle(addr, SessionState::Idle, None, counters.clone()),
        false,
    );
    let managed = mgr.peers.get_mut(&key(addr)).unwrap();
    managed.enabled = false;
    managed.max_prefix_restart_seconds = Some(30);
    mgr.install_max_prefix_latch(key(addr), 1, "max-prefix".to_string(), Some(30));

    let edit = make_config(addr, 65002);
    mgr.hot_update_peer(edit).await.unwrap();
    assert!(mgr.max_prefix_latches[&key(addr)].deadline.is_none());
    tokio::time::advance(Duration::from_secs(31)).await;
    mgr.handle_due_max_prefix_restarts().await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(counters.start.load(Ordering::SeqCst), 0);
    assert!(!mgr.peers[&key(addr)].enabled);
}

/// Adding a restart duration to an already indefinitely-latched peer must not
/// retroactively arm a countdown — that peer may be intentionally held down;
/// explicit enable remains the recovery path.
#[tokio::test(start_paused = true)]
async fn adding_restart_duration_does_not_arm_indefinite_latch() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 85));
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        addr,
        fake_peer_handle(addr, SessionState::Idle, None, counters.clone()),
        false,
    );
    mgr.peers.get_mut(&key(addr)).unwrap().enabled = false;
    mgr.install_max_prefix_latch(key(addr), 1, "max-prefix".to_string(), None);

    let mut edit = make_config(addr, 65002);
    edit.max_prefix_restart_seconds = Some(30);
    mgr.hot_update_peer(edit).await.unwrap();
    assert!(mgr.max_prefix_latches[&key(addr)].deadline.is_none());
    tokio::time::advance(Duration::from_mins(1)).await;
    mgr.handle_due_max_prefix_restarts().await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(counters.start.load(Ordering::SeqCst), 0);
    assert!(!mgr.peers[&key(addr)].enabled);
}

/// Load-bearing rejected-replacement proof: moving countdown invalidation
/// ahead of the fallible RIB refresh cancels the armed timer even though the
/// export-knob replacement returns `Err`, making both identity assertions red.
#[tokio::test(start_paused = true)]
async fn rejected_hot_update_preserves_old_restart_countdown() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, rib_rx) = mpsc::channel(1);
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
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 77));
    let mut initial = make_config(addr, 65002);
    initial.max_prefix_restart_seconds = Some(30);
    mgr.add_peer(initial, false).await.unwrap();
    mgr.disable_peer(key(addr), None).await.unwrap();
    mgr.install_max_prefix_latch(key(addr), 1, "original".to_string(), Some(30));
    let original_generation = mgr.max_prefix_latches[&key(addr)].generation;
    let original_deadline = mgr.max_prefix_latches[&key(addr)].deadline;
    drop(rib_rx);

    let mut rejected = make_config(addr, 65002);
    rejected.max_prefix_restart_seconds = Some(60);
    rejected.local_ipv6_nexthop = Some("2001:db8::1".parse().unwrap());
    assert!(mgr.hot_update_peer(rejected).await.is_err());
    assert_eq!(
        mgr.max_prefix_latches[&key(addr)].generation,
        original_generation
    );
    assert_eq!(
        mgr.max_prefix_latches[&key(addr)].deadline,
        original_deadline
    );
    assert_eq!(mgr.peers[&key(addr)].max_prefix_restart_seconds, Some(30));
}

#[tokio::test]
async fn hot_update_peer_refreshes_outbound_for_export_affecting_knobs() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    // Mirror the gshut-toggle precedent: record every forced outbound
    // refresh the RIB would receive, then reply so the apply completes.
    let (seen_tx, mut seen_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::RefreshPeerOutbound { peer, reply } = update {
                seen_tx.send(peer).await.unwrap();
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

    // `local_ipv6_nexthop` decides the exact-export preflight's
    // `MissingIpv6NextHop` suppression: remediating it must re-probe
    // the peer's suppressed routes without waiting for unrelated churn.
    let mut updated = make_config(addr, 65002);
    updated.local_ipv6_nexthop = Some("2001:db8::1".parse().unwrap());
    mgr.hot_update_peer(updated).await.unwrap();
    assert_eq!(
        seen_rx
            .try_recv()
            .expect("hot-applying local_ipv6_nexthop must force an outbound refresh"),
        addr
    );

    // `remove_private_as` changes already-advertised AS_PATHs.
    let mut updated = make_config(addr, 65002);
    updated.local_ipv6_nexthop = Some("2001:db8::1".parse().unwrap());
    updated.remove_private_as = rustbgpd_transport::RemovePrivateAs::All;
    mgr.hot_update_peer(updated).await.unwrap();
    assert_eq!(
        seen_rx
            .try_recv()
            .expect("hot-applying remove_private_as must force an outbound refresh"),
        addr
    );
}

#[tokio::test]
async fn hot_update_peer_skips_outbound_refresh_when_export_knobs_unchanged() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
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

    // Export-inert knob changes and a full no-op must not replay the
    // peer's outbound table.
    let mut updated = make_config(addr, 65002);
    updated.description = "hot-updated".to_string();
    updated.max_prefixes = Some(500);
    updated.gr_stale_routes_time = 300;
    mgr.hot_update_peer(updated.clone()).await.unwrap();
    mgr.hot_update_peer(updated).await.unwrap();

    while let Ok(update) = rib_rx.try_recv() {
        assert!(
            !matches!(update, RibUpdate::RefreshPeerOutbound { .. }),
            "an export-inert hot apply must not force an outbound refresh"
        );
    }
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
    replacement.tcp_ao = Some(
        rustbgpd_transport::TcpAoConfig {
            key: "secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        }
        .into(),
    );

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

/// Load-bearing dynamic lifecycle proof: removing the latch cleanup from the
/// authoritative rollback reap leaves a stale error keyed to the address, so a
/// future dynamic accept at that address can inherit state from a dead peer.
/// Removing the rollback capacity refresh leaves the process-global used gauge
/// pinned at one after the same authoritative reap.
#[tokio::test]
async fn rollback_reap_clears_dynamic_max_prefix_latch() {
    let mut mgr = dynamic_test_manager();
    mgr.dynamic_ranges.clear();
    let peer_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 43));
    insert_test_dynamic_managed_peer(
        &mut mgr,
        peer_addr,
        89,
        fake_peer_handle(
            peer_addr,
            SessionState::Idle,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
        false,
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        8,
        "ix-members",
    );
    mgr.install_max_prefix_latch(
        key(peer_addr),
        0,
        "max-prefix limit exceeded: 501 accepted, bound 500".to_string(),
        None,
    );
    assert_dynamic_neighbor_capacity(&mgr.metrics, 1.0, 100.0, 99.0, 0.0);

    assert_eq!(
        mgr.reap_dynamic_peers_not_allowed_by_current_ranges().await,
        1
    );
    assert!(!mgr.peers.contains_key(&key(peer_addr)));
    assert!(
        !mgr.max_prefix_latches.contains_key(&key(peer_addr)),
        "authoritative dynamic removal must reap its manager-owned latch"
    );
    assert_dynamic_neighbor_capacity(&mgr.metrics, 0.0, 100.0, 100.0, 0.0);
}

/// Load-bearing transaction-bounce proof: removing the pre-filter policy sync
/// leaves the matching disabled dynamic peer on `None` instead of 30 seconds.
#[tokio::test]
async fn bounce_dynamic_peers_signals_only_matching_enabled_dynamic_sessions() {
    let mut mgr = dynamic_test_manager();
    mgr.current_config
        .peer_groups
        .get_mut("ix-members")
        .unwrap()
        .max_prefix_restart_seconds = std::num::NonZeroU32::new(30);

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
    assert_eq!(
        mgr.peers[&key(disabled_addr)].max_prefix_restart_seconds,
        Some(30)
    );

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
    // Mutation-red for min_hold_time: deleting DTO/config/runtime projection
    // breaks the exact managed-peer or API readback assertion below.
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
                min_hold_time: Some(30),
                hold_time: Some(45),
                send_hold_time: None,
                max_prefixes: None,
                max_prefix_restart_seconds: None,
                md5_password: None,
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
    assert_eq!(managed.transport_config.peer.min_hold_time, Some(30));
    assert_eq!(
        crate::policy_admin::named_peer_group_from_config(&mgr.current_config, "edge")
            .unwrap()
            .min_hold_time,
        Some(30)
    );
    assert!(!managed.enabled);
}

fn edge_group_definition(hold_time: Option<u16>) -> rustbgpd_api::peer_types::PeerGroupDefinition {
    rustbgpd_api::peer_types::PeerGroupDefinition {
        min_hold_time: None,
        hold_time,
        send_hold_time: None,
        max_prefixes: None,
        max_prefix_restart_seconds: None,
        md5_password: None,
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

#[tokio::test]
async fn targeted_required_family_edit_revalidates_dynamic_consumers() {
    // Load-bearing: skipping whole-config validation in SetPeerGroup commits
    // IPv6 as required even though the existing IPv4 dynamic range defaults
    // to IPv4 only. The static IPv6 member proves the group is referenced by
    // both consumer shapes without itself making the edit invalid.
    let config = load_test_config(&format!(
        "{}\n[[dynamic_neighbors]]\nprefix = \"192.0.2.0/24\"\npeer_group = \"edge\"\n",
        EDGE_GROUP_TOML
            .replace("10.0.0.2", "2001:db8::2")
            .replace("10.0.0.3", "2001:db8::3")
            .replace("10.0.0.4", "2001:db8::4")
    ));
    let prior = config.clone();
    let mut mgr = peer_group_reshape_manager(config);
    let mut definition = edge_group_definition(Some(90));
    definition.required_families = vec!["ipv6_unicast".to_string()];
    let err = mgr
        .apply_peer_group_change(
            rustbgpd_api::peer_types::ConfigEvent::SetPeerGroup {
                name: "edge".to_string(),
                definition,
                ack: None,
            },
            vec!["2001:db8::2".parse().unwrap()],
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("required family"), "{err}");
    assert_eq!(mgr.current_config, prior);
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

// ── peer-group edits partitioned by `ConfigFieldImpact` ───────────────

fn edge_group_max_prefixes_event(
    hold_time: u16,
    max_prefixes: u32,
) -> rustbgpd_api::peer_types::ConfigEvent {
    let mut definition = edge_group_definition(Some(hold_time));
    definition.max_prefixes = Some(max_prefixes);
    rustbgpd_api::peer_types::ConfigEvent::SetPeerGroup {
        name: "edge".to_string(),
        definition,
        ack: None,
    }
}

async fn edge_group_manager_with_members() -> PeerManager {
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
    mgr
}

/// Load-bearing: a peer-group edit whose every changed field is
/// reload-matrix `live` must apply to the inheriting members in place.
/// Both halves fail without the impact partition — before it,
/// `apply_peer_group_change` reshaped for *any* group change, so every
/// member's session id changed (a `peer deleted` + re-add on the wire)
/// even though the identical neighbor-level edit hot-applies.
#[tokio::test]
async fn peer_group_hot_field_edit_applies_in_place_without_session_reset() {
    let mut mgr = edge_group_manager_with_members().await;
    let addresses = [
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
    ];
    let before: Vec<_> = addresses
        .iter()
        .map(|addr| {
            let managed = mgr.peers.get(&key(*addr)).expect("managed peer");
            assert_eq!(managed.transport_config.max_prefixes, None);
            (*addr, managed.session_id)
        })
        .collect();

    mgr.apply_peer_group_change(edge_group_max_prefixes_event(90, 5_000), addresses.to_vec())
        .await
        .unwrap();

    for (addr, session_id) in before {
        let managed = mgr.peers.get(&key(addr)).expect("hot-applied member");
        assert_eq!(
            managed.session_id, session_id,
            "a pure-hot peer-group edit must not tear down {addr}'s session"
        );
        // Skipping the reshape is only correct if the member's *effective*
        // state actually moved; a path that updated the stored group
        // definition alone would leave both of these stale.
        assert_eq!(
            managed.max_prefixes,
            Some(5_000),
            "{addr} must inherit the new group maximum"
        );
        assert_eq!(managed.transport_config.max_prefixes, Some(5_000));
    }
    assert_eq!(
        mgr.current_config
            .peer_groups
            .get("edge")
            .expect("group definition")
            .max_prefixes,
        Some(5_000)
    );
}

/// The other half of the partition: a change set that mixes a hot field
/// with a session-reset one keeps the ADR-0081 reshape path, because the
/// session-reset field can only take effect on a renegotiated session.
#[tokio::test]
async fn peer_group_mixed_impact_edit_still_reshapes_members() {
    let mut mgr = edge_group_manager_with_members().await;
    let addresses = [
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
    ];
    let before: Vec<_> = addresses
        .iter()
        .map(|addr| (*addr, mgr.peers.get(&key(*addr)).expect("peer").session_id))
        .collect();

    // `hold_time` is OPEN-negotiated (session reset) and `max_prefixes` is
    // hot; a mixed set must not take the in-place path.
    mgr.apply_peer_group_change(edge_group_max_prefixes_event(45, 5_000), addresses.to_vec())
        .await
        .unwrap();

    for (addr, session_id) in before {
        let managed = mgr.peers.get(&key(addr)).expect("reshaped member");
        assert_ne!(
            managed.session_id, session_id,
            "a mixed-impact peer-group edit must still reshape {addr}"
        );
        assert_eq!(managed.hold_time, Some(45));
        assert_eq!(managed.max_prefixes, Some(5_000));
    }
}

/// ADR-0081 for the in-place path: a mid-cohort failure restores the
/// members applied before it from their captured live priors, and
/// `current_config` — so also the stored group definition — never
/// advances.
#[tokio::test]
async fn peer_group_hot_apply_mid_cohort_failure_restores_prior_members() {
    let mut mgr = edge_group_manager_with_members().await;
    let a1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let a2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)); // its hot apply fails
    let a3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    mgr.inject_hot_update_failures.insert(key(a2), 0);
    let sessions: Vec<_> = [a1, a2, a3]
        .into_iter()
        .map(|addr| (addr, mgr.peers.get(&key(addr)).expect("peer").session_id))
        .collect();

    let Err(error) = mgr
        .apply_peer_group_change(edge_group_max_prefixes_event(90, 5_000), vec![a1, a2, a3])
        .await
    else {
        panic!("mid-cohort hot-apply failure must surface as Err");
    };
    assert!(
        matches!(error, CatalogMutationError::Internal(_)),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(message.contains("prior peers restored"), "{message}");
    assert!(message.contains("10.0.0.3"), "{message}");

    for (addr, session_id) in sessions {
        let managed = mgr.peers.get(&key(addr)).expect("member");
        assert_eq!(
            managed.max_prefixes, None,
            "{addr} must be back on (or never moved off) its prior value"
        );
        assert_eq!(managed.transport_config.max_prefixes, None);
        assert_eq!(
            managed.session_id, session_id,
            "rollback of an in-place apply must not bounce {addr} either"
        );
    }
    assert!(
        mgr.current_config
            .peer_groups
            .get("edge")
            .expect("group definition")
            .max_prefixes
            .is_none(),
        "a failed hot apply must leave the group definition unchanged"
    );
}

/// Dynamic inheritors are part of the hot cohort: ADR-0081 decision 4
/// defers *reshaping* an accepted dynamic peer, but a hot knob swap needs
/// no reconnect, so the new inherited value reaches the live session
/// without a bounce.
#[tokio::test]
async fn peer_group_hot_field_edit_reaches_live_dynamic_members() {
    let mut mgr = dynamic_test_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 91));
    let (handle, mut applied_caps) = recording_runtime_config_handle();
    insert_test_dynamic_managed_peer(
        &mut mgr,
        addr,
        91,
        handle,
        true,
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        8,
        "ix-members",
    );
    let session_id = mgr.peers[&key(addr)].session_id;
    let cap_before = mgr.peers[&key(addr)]
        .transport_config
        .gr_peer_restart_time_max;
    assert_ne!(cap_before, 1_800);

    let mut definition = crate::policy_admin::config_peer_group_to_api(
        &mgr.current_config.peer_groups["ix-members"],
    );
    definition.gr_peer_restart_time_max = Some(1_800);
    mgr.apply_peer_group_change(
        rustbgpd_api::peer_types::ConfigEvent::SetPeerGroup {
            name: "ix-members".to_string(),
            definition,
            ack: None,
        },
        Vec::new(),
    )
    .await
    .unwrap();

    assert_eq!(
        applied_caps.try_recv(),
        Ok(1_800),
        "the live dynamic session must receive the new inherited cap"
    );
    let managed = &mgr.peers[&key(addr)];
    assert_eq!(managed.transport_config.gr_peer_restart_time_max, 1_800);
    assert_eq!(
        managed.session_id, session_id,
        "a hot peer-group edit must not bounce the dynamic member"
    );
    assert!(managed.is_dynamic);
}

#[tokio::test]
async fn required_family_group_reconcile_waits_for_dynamic_reconnect() {
    // Load-bearing: this shared SIGHUP/targeted-group reconcile primitive must
    // not reconfigure an accepted dynamic peer in place, while the committed
    // group must advance what its next connection resolves.
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
    assert!(
        mgr.peers[&key(addr)]
            .transport_config
            .peer
            .required_families
            .is_empty()
    );

    let mut definition =
        crate::policy_admin::config_peer_group_to_api(&mgr.current_config.peer_groups["edge"]);
    definition.required_families = vec!["ipv4_unicast".to_string()];
    mgr.apply_peer_group_change(
        rustbgpd_api::peer_types::ConfigEvent::SetPeerGroup {
            name: "edge".to_string(),
            definition,
            ack: None,
        },
        vec![addr],
    )
    .await
    .unwrap();

    assert_eq!(counters.shutdown.load(Ordering::SeqCst), 0);
    assert!(
        mgr.peers[&key(addr)]
            .transport_config
            .peer
            .required_families
            .is_empty(),
        "accepted dynamic session must retain its running OPEN contract"
    );
    let reconnect = mgr
        .current_config
        .resolve_dynamic_neighbor(
            addr,
            65002,
            "reconnect",
            &mgr.current_config.peer_groups["edge"],
            "edge",
            false,
        )
        .unwrap();
    assert_eq!(
        reconnect.transport_config.peer.required_families,
        vec![(Afi::Ipv4, Safi::Unicast)]
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

/// Load-bearing ownership/lifecycle proof:
///
/// - matching by immutable `SessionRole` rejects a promoted candidate's latch;
/// - failing to Stop the current owner can leave a rearmed session live;
/// - dynamic `BackToIdle` auto-removal drops the disabled/latch state;
/// - consulting only the session's stale `last_error` hides the manager-owned
///   max-prefix cause; and
/// - failing to clear on explicit enable leaves the peer permanently latched.
#[tokio::test]
async fn promoted_dynamic_max_prefix_latch_survives_idle_until_explicit_enable() {
    use rustbgpd_transport::PeerCommand;

    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 32));
    let counters = Arc::new(FakePeerCounters::default());
    let task_counters = counters.clone();
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        while let Some(command) = session_rx.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Idle,
                        peer_ip: addr,
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
                        last_error: "stale TCP connect error".to_string(),
                        tcp_ao_info: None,
                        tcp_ao_protected: false,
                        slow_peer: false,
                    });
                }
                PeerCommand::Stop { .. } => {
                    task_counters.stop.fetch_add(1, Ordering::SeqCst);
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    insert_test_managed_peer_with_asn(
        &mut mgr,
        addr,
        65002,
        PeerHandle::from_parts(session_tx, task),
        false,
    );
    let managed = mgr.peers.get_mut(&key(addr)).unwrap();
    managed.is_dynamic = true;
    mgr.dynamic_peer_count = 1;

    mgr.handle_session_notification(SessionNotification::MaxPrefixExceeded {
        session_id: 1,
        // Promoted inbound tasks retain this spawn role even though session_id
        // 1 is now the primary owner in ManagedPeer.
        role: rustbgpd_transport::SessionRole::InboundCandidate,
        peer_addr: addr,
        count: 501,
        bound: 500,
        family: Some((Afi::Ipv4, Safi::Unicast)),
    })
    .await;
    assert!(!mgr.peers.get(&key(addr)).unwrap().enabled);
    wait_counter(&counters.stop, 1).await;
    assert_eq!(counters.stop.load(Ordering::SeqCst), 1);

    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id: 1,
        role: rustbgpd_transport::SessionRole::InboundCandidate,
        peer_addr: addr,
    })
    .await;
    assert!(mgr.peers.contains_key(&key(addr)));
    assert_eq!(mgr.dynamic_peer_count, 1);
    let info = mgr.get_peer_info(&key(addr)).await.unwrap();
    assert_eq!(
        info.last_error,
        "max-prefix limit exceeded for Ipv4/Unicast: 501 accepted, bound 500"
    );
    assert_eq!(
        mgr.list_peers().await[0].last_error,
        "max-prefix limit exceeded for Ipv4/Unicast: 501 accepted, bound 500",
        "list and targeted snapshots must both prefer the manager-owned latch"
    );

    mgr.enable_peer(key(addr)).await.unwrap();
    assert!(mgr.peers.get(&key(addr)).unwrap().enabled);
    assert!(!mgr.max_prefix_latches.contains_key(&key(addr)));
    assert_eq!(
        mgr.get_peer_info(&key(addr)).await.unwrap().last_error,
        "stale TCP connect error",
        "explicit enable must remove the manager-owned override"
    );
}

/// Removing the session-id ownership check lets a delayed latch from a
/// superseded generation disable the replacement session.
#[tokio::test]
async fn stale_max_prefix_generation_cannot_latch_replacement() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 33));
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
    mgr.session_index.insert(99, key(addr));

    mgr.handle_session_notification(SessionNotification::MaxPrefixExceeded {
        session_id: 99,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr: addr,
        count: 501,
        bound: 500,
        family: None,
    })
    .await;

    assert!(mgr.peers.get(&key(addr)).unwrap().enabled);
    assert!(!mgr.max_prefix_latches.contains_key(&key(addr)));
}

/// Removing the pending-candidate drain lets `BackToIdle` promote a sibling
/// connection immediately after the primary exceeded max-prefix.
#[tokio::test]
async fn primary_max_prefix_breach_drains_pending_collision_candidate() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 34));
    let primary = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        addr,
        fake_peer_handle(addr, SessionState::Established, None, primary.clone()),
        false,
    );
    let candidate = Arc::new(FakePeerCounters::default());
    mgr.peers.get_mut(&key(addr)).unwrap().pending_inbound = Some(PendingInbound {
        handle: fake_peer_handle(addr, SessionState::OpenConfirm, None, candidate.clone()),
        session_id: 2,
    });
    mgr.register_session(2, &key(addr));

    mgr.handle_session_notification(SessionNotification::MaxPrefixExceeded {
        session_id: 1,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr: addr,
        count: 501,
        bound: 500,
        family: None,
    })
    .await;

    let managed = mgr.peers.get(&key(addr)).unwrap();
    assert!(!managed.enabled);
    assert!(managed.pending_inbound.is_none());
    assert_eq!(primary.stop.load(Ordering::SeqCst), 1);
    assert_eq!(candidate.shutdown.load(Ordering::SeqCst), 1);
    assert!(mgr.peer_key_for_session(2).is_none());
}

/// `MaxPrefixExceeded` and `BackToIdle` share one FIFO lossless channel. Removing
/// that ordering (or handling `BackToIdle` first) auto-removes this dynamic peer
/// or promotes its candidate before the shutdown latch is installed.
#[tokio::test]
async fn peer_presence_retained_max_prefix_emits_no_removed() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 37));
    insert_test_managed_peer(
        &mut mgr,
        addr,
        fake_peer_handle(
            addr,
            SessionState::Idle,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
        false,
    );
    let candidate = Arc::new(FakePeerCounters::default());
    let managed = mgr.peers.get_mut(&key(addr)).unwrap();
    managed.is_dynamic = true;
    managed.pending_inbound = Some(PendingInbound {
        handle: fake_peer_handle(addr, SessionState::OpenConfirm, None, candidate.clone()),
        session_id: 2,
    });
    mgr.register_session(2, &key(addr));
    mgr.dynamic_peer_count = 1;
    mgr.session_notify_tx
        .send(SessionNotification::MaxPrefixExceeded {
            session_id: 1,
            role: rustbgpd_transport::SessionRole::Primary,
            peer_addr: addr,
            count: 501,
            bound: 500,
            family: None,
        })
        .unwrap();
    mgr.session_notify_tx
        .send(SessionNotification::BackToIdle {
            session_id: 1,
            role: rustbgpd_transport::SessionRole::Primary,
            peer_addr: addr,
        })
        .unwrap();

    mgr.drain_ready_session_notifications().await;

    let managed = mgr
        .peers
        .get(&key(addr))
        .expect("latched dynamic peer retained");
    assert!(!managed.enabled);
    assert!(managed.pending_inbound.is_none());
    assert_eq!(mgr.dynamic_peer_count, 1);
    assert!(mgr.max_prefix_latches.contains_key(&key(addr)));
    assert_eq!(candidate.shutdown.load(Ordering::SeqCst), 1);
    let removed = query_session_event_history(
        &mgr,
        Some(addr),
        [SessionLifecycleEventType::PeerRemoved]
            .into_iter()
            .collect(),
        0,
    )
    .await;
    assert!(removed.is_empty());
}

/// A candidate-owned breach is fail-closed for the whole peer. Removing the
/// unconditional current-primary Stop leaves the sibling Established; removing the
/// candidate drain leaves the breaching sibling registered.
#[tokio::test]
async fn pending_candidate_max_prefix_breach_stops_primary_and_drains_candidate() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 35));
    let primary = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        addr,
        fake_peer_handle(addr, SessionState::Established, None, primary.clone()),
        false,
    );
    let candidate = Arc::new(FakePeerCounters::default());
    mgr.peers.get_mut(&key(addr)).unwrap().pending_inbound = Some(PendingInbound {
        handle: fake_peer_handle(addr, SessionState::OpenConfirm, None, candidate.clone()),
        session_id: 2,
    });
    mgr.register_session(2, &key(addr));

    mgr.handle_session_notification(SessionNotification::MaxPrefixExceeded {
        session_id: 2,
        role: rustbgpd_transport::SessionRole::InboundCandidate,
        peer_addr: addr,
        count: 501,
        bound: 500,
        family: Some((Afi::Ipv4, Safi::Unicast)),
    })
    .await;

    let managed = mgr.peers.get(&key(addr)).unwrap();
    assert!(!managed.enabled);
    assert!(managed.pending_inbound.is_none());
    assert_eq!(primary.stop.load(Ordering::SeqCst), 1);
    assert_eq!(candidate.shutdown.load(Ordering::SeqCst), 1);
    assert!(mgr.peer_key_for_session(2).is_none());
}

/// Load-bearing cross-lane proof: `EnablePeer` starts the session first and
/// that Start triggers the terminal signal. Removing the unconditional primary
/// Stop leaves the peer reported disabled but still live after Start.
#[tokio::test]
async fn max_prefix_after_enable_start_stops_and_latches_primary() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
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
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 38));
    let counters = Arc::new(FakePeerCounters::default());
    let notify_tx = mgr.session_notify_tx.clone();
    insert_test_managed_peer(
        &mut mgr,
        addr,
        max_prefix_on_command_peer_handle(
            addr,
            1,
            rustbgpd_transport::SessionRole::Primary,
            MaxPrefixTrigger::Start,
            notify_tx,
            counters.clone(),
        ),
        false,
    );
    let manager = tokio::spawn(mgr.run());

    let (reply, result) = oneshot::channel();
    tx.send(PeerManagerCommand::EnablePeer {
        peer: key(addr),
        reply,
    })
    .await
    .unwrap();
    result.await.unwrap().unwrap();
    wait_counter(&counters.start, 1).await;
    wait_counter(&counters.stop, 1).await;

    let (reply, result) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply })
        .await
        .unwrap();
    let peers = result.await.unwrap();
    assert_eq!(peers.len(), 1);
    assert!(peers[0].last_error.contains("max-prefix limit exceeded"));

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager.await.unwrap();
}

/// Load-bearing retirement proof: the old actor emits max-prefix only while
/// processing reconcile's Shutdown. Removing the retirement tombstone or the
/// latch-aware re-add starts the replacement enabled and loses the cause.
#[tokio::test]
async fn reconcile_preserves_max_prefix_emitted_during_old_actor_shutdown() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 39));
    let counters = Arc::new(FakePeerCounters::default());
    let notify_tx = mgr.session_notify_tx.clone();
    insert_test_managed_peer(
        &mut mgr,
        addr,
        max_prefix_on_command_peer_handle(
            addr,
            1,
            rustbgpd_transport::SessionRole::Primary,
            MaxPrefixTrigger::Shutdown,
            notify_tx,
            counters.clone(),
        ),
        false,
    );
    mgr.next_session_id = 2;
    let mut changed = make_config(addr, 65002);
    changed.description = "replacement".to_string();

    let result = mgr
        .reconcile_peers(Vec::new(), Vec::new(), vec![changed])
        .await;

    assert!(result.failures.is_empty(), "{:?}", result.failures);
    assert_eq!(counters.shutdown.load(Ordering::SeqCst), 1);
    let managed = mgr.peers.get(&key(addr)).expect("replacement peer");
    assert_ne!(managed.session_id, 1);
    assert!(!managed.enabled);
    assert!(mgr.max_prefix_latches.contains_key(&key(addr)));
    assert!(mgr.retiring_sessions.is_empty());
    assert!(mgr.peer_key_for_session(1).is_none());
}

/// Load-bearing local-wins proof: `OpenReceived` is handled first and the
/// losing candidate emits max-prefix only while consuming `CollisionDump`.
/// Unregister-before-join discards that terminal signal and leaves the primary.
#[tokio::test]
async fn local_wins_collision_preserves_candidate_terminal_breach() {
    let mut mgr = test_peer_manager();
    mgr.router_id = Ipv4Addr::new(10, 0, 0, 10);
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 40));
    let primary = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        addr,
        fake_peer_handle(addr, SessionState::OpenConfirm, None, primary.clone()),
        false,
    );
    let candidate = Arc::new(FakePeerCounters::default());
    let notify_tx = mgr.session_notify_tx.clone();
    attach_test_pending_inbound(
        &mut mgr,
        addr,
        max_prefix_on_command_peer_handle(
            addr,
            2,
            rustbgpd_transport::SessionRole::InboundCandidate,
            MaxPrefixTrigger::CollisionDump,
            notify_tx,
            candidate.clone(),
        ),
        2,
    );
    mgr.session_notify_tx
        .send(SessionNotification::OpenReceived {
            session_id: 2,
            role: rustbgpd_transport::SessionRole::InboundCandidate,
            peer_addr: addr,
            remote_router_id: Ipv4Addr::new(10, 0, 0, 2),
            peer_asn: 65002,
        })
        .unwrap();

    mgr.drain_ready_session_notifications().await;
    wait_counter(&primary.stop, 1).await;

    let managed = mgr.peers.get(&key(addr)).unwrap();
    assert!(!managed.enabled);
    assert!(managed.pending_inbound.is_none());
    assert_eq!(managed.session_id, 1);
    assert_eq!(candidate.collision_dump.load(Ordering::SeqCst), 1);
    assert_eq!(primary.stop.load(Ordering::SeqCst), 1);
    assert!(mgr.max_prefix_latches.contains_key(&key(addr)));
    assert!(mgr.retiring_sessions.is_empty());
    assert!(mgr.peer_key_for_session(2).is_none());
}

/// Load-bearing remote-wins proof: after candidate promotion, the retiring old
/// primary emits max-prefix while consuming `CollisionDump`. Removing its
/// tombstone leaves the promoted candidate live and enabled.
#[tokio::test]
async fn remote_wins_collision_preserves_old_primary_terminal_breach() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 41));
    let primary = Arc::new(FakePeerCounters::default());
    let notify_tx = mgr.session_notify_tx.clone();
    insert_test_managed_peer(
        &mut mgr,
        addr,
        max_prefix_on_command_peer_handle(
            addr,
            1,
            rustbgpd_transport::SessionRole::Primary,
            MaxPrefixTrigger::CollisionDump,
            notify_tx,
            primary.clone(),
        ),
        false,
    );
    let candidate = Arc::new(FakePeerCounters::default());
    attach_test_pending_inbound(
        &mut mgr,
        addr,
        fake_peer_handle(
            addr,
            SessionState::OpenConfirm,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            candidate.clone(),
        ),
        2,
    );
    mgr.session_notify_tx
        .send(SessionNotification::OpenReceived {
            session_id: 2,
            role: rustbgpd_transport::SessionRole::InboundCandidate,
            peer_addr: addr,
            remote_router_id: Ipv4Addr::new(10, 0, 0, 2),
            peer_asn: 65002,
        })
        .unwrap();

    mgr.drain_ready_session_notifications().await;
    wait_counter(&candidate.stop, 1).await;

    let managed = mgr.peers.get(&key(addr)).unwrap();
    assert!(!managed.enabled);
    assert!(managed.pending_inbound.is_none());
    assert_eq!(managed.session_id, 2);
    assert_eq!(primary.collision_dump.load(Ordering::SeqCst), 1);
    assert_eq!(candidate.stop.load(Ordering::SeqCst), 1);
    assert!(mgr.max_prefix_latches.contains_key(&key(addr)));
    assert!(mgr.retiring_sessions.is_empty());
    assert!(mgr.peer_key_for_session(1).is_none());
    assert_eq!(mgr.peer_key_for_session(2), Some(key(addr)));
    assert_eq!(
        peer_identity_gauge(&mgr.metrics, "bgp_peer_admin_enabled", "10.0.0.41", ""),
        Some(0.0)
    );
}

/// Load-bearing Idle replacement proof: the old primary emits max-prefix only
/// from Shutdown. Removing retirement ownership starts the new inbound actor
/// and loses the terminal latch.
#[tokio::test]
async fn inbound_replace_preserves_old_primary_terminal_breach() {
    let mut mgr = test_peer_manager();
    mgr.next_session_id = 2;
    let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let old = Arc::new(FakePeerCounters::default());
    let notify_tx = mgr.session_notify_tx.clone();
    insert_test_managed_peer(
        &mut mgr,
        addr,
        max_prefix_on_command_peer_handle(
            addr,
            1,
            rustbgpd_transport::SessionRole::Primary,
            MaxPrefixTrigger::Shutdown,
            notify_tx,
            old.clone(),
        ),
        false,
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (stream, _) = listener.accept().await.unwrap();
    let client = client.await.unwrap();

    mgr.replace_with_inbound(
        key(addr),
        stream,
        None,
        rustbgpd_transport::TcpAoRotationGeneration::STARTUP,
    )
    .await;

    assert_eq!(old.shutdown.load(Ordering::SeqCst), 1);
    let managed = mgr.peers.get(&key(addr)).unwrap();
    assert_eq!(managed.session_id, 2);
    assert!(!managed.enabled);
    assert!(mgr.max_prefix_latches.contains_key(&key(addr)));
    assert!(mgr.retiring_sessions.is_empty());
    assert!(mgr.peer_key_for_session(1).is_none());
    assert_eq!(mgr.peer_key_for_session(2), Some(key(addr)));

    drop(client);
    let managed = mgr.peers.remove(&key(addr)).unwrap();
    managed.handle.shutdown().await.unwrap().unwrap();
}

/// Load-bearing dynamic-retirement proof: the actor emits max-prefix only from
/// Shutdown after an older `BackToIdle` was queued. Removing the retirement
/// barrier auto-removes the peer and leaves no explicit-Enable recovery target;
/// decrementing or refreshing the slot on the retained branch loses its
/// process-global capacity ownership.
#[tokio::test]
async fn dynamic_back_to_idle_retains_recovery_target_for_late_terminal_breach() {
    let mut mgr = test_peer_manager();
    mgr.next_session_id = 2;
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42));
    let old = Arc::new(FakePeerCounters::default());
    let notify_tx = mgr.session_notify_tx.clone();
    insert_test_managed_peer(
        &mut mgr,
        addr,
        max_prefix_on_command_peer_handle(
            addr,
            1,
            rustbgpd_transport::SessionRole::Primary,
            MaxPrefixTrigger::Shutdown,
            notify_tx,
            old.clone(),
        ),
        false,
    );
    mgr.peers.get_mut(&key(addr)).unwrap().is_dynamic = true;
    mgr.dynamic_peer_count = 1;
    mgr.refresh_dynamic_neighbor_capacity_metrics();
    assert_dynamic_neighbor_capacity(&mgr.metrics, 1.0, 100.0, 99.0, 0.0);
    mgr.session_notify_tx
        .send(SessionNotification::BackToIdle {
            session_id: 1,
            role: rustbgpd_transport::SessionRole::Primary,
            peer_addr: addr,
        })
        .unwrap();

    mgr.drain_ready_session_notifications().await;

    assert_eq!(old.shutdown.load(Ordering::SeqCst), 1);
    let managed = mgr.peers.get(&key(addr)).expect("disabled recovery target");
    assert_eq!(managed.session_id, 2);
    assert!(managed.is_dynamic);
    assert!(!managed.enabled);
    assert_eq!(mgr.dynamic_peer_count, 1);
    assert!(mgr.max_prefix_latches.contains_key(&key(addr)));
    assert!(mgr.retiring_sessions.is_empty());
    assert!(mgr.peer_key_for_session(1).is_none());
    assert_eq!(mgr.peer_key_for_session(2), Some(key(addr)));
    assert_dynamic_neighbor_capacity(&mgr.metrics, 1.0, 100.0, 99.0, 0.0);

    mgr.enable_peer(key(addr)).await.unwrap();
    assert!(mgr.peers.get(&key(addr)).unwrap().enabled);
    assert!(!mgr.max_prefix_latches.contains_key(&key(addr)));
    let managed = mgr.peers.remove(&key(addr)).unwrap();
    managed.handle.shutdown().await.unwrap().unwrap();
}

/// Load-bearing fail-closed recovery proof: a wedged, full primary command
/// channel makes Stop time out. Removing abort/rebuild leaves the stale generation owned,
/// omits `PeerDown`, and makes explicit Enable fail with `SessionExited`.
#[tokio::test(start_paused = true)]
async fn pending_breach_rebuilds_unstoppable_primary_for_explicit_recovery() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(1);
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx.clone(),
        None,
    );
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 36));
    let aborted = Arc::new(AtomicU32::new(0));
    let cancel_notify = Arc::new(Notify::new());
    insert_test_managed_peer(
        &mut mgr,
        addr,
        stalled_shutdown_peer_handle_with_notify(aborted.clone(), Some(cancel_notify.clone()))
            .await,
        false,
    );
    let candidate = Arc::new(FakePeerCounters::default());
    mgr.peers.get_mut(&key(addr)).unwrap().pending_inbound = Some(PendingInbound {
        handle: fake_peer_handle(addr, SessionState::OpenConfirm, None, candidate.clone()),
        session_id: 2,
    });
    mgr.register_session(2, &key(addr));
    mgr.next_session_id = 3;

    rib_tx
        .send(RibUpdate::PeerDown {
            peer: addr,
            session_id: 999,
        })
        .await
        .unwrap();
    let cancel_observed = aborted.clone();
    let drain_after_cancel = tokio::spawn(async move {
        cancel_notify.notified().await;
        assert_eq!(
            cancel_observed.load(Ordering::SeqCst),
            1,
            "RIB capacity must remain blocked until actor cancellation completes"
        );
        let _seed = rib_rx.recv().await.expect("seeded RIB update");
        rib_rx.recv().await.expect("old-generation RIB fence")
    });

    tokio::time::timeout(
        PEER_LIFECYCLE_COMMAND_TIMEOUT * 3,
        mgr.handle_session_notification(SessionNotification::MaxPrefixExceeded {
            session_id: 2,
            role: rustbgpd_transport::SessionRole::InboundCandidate,
            peer_addr: addr,
            count: 501,
            bound: 500,
            family: None,
        }),
    )
    .await
    .expect("cancellation must precede the capacity-blocked RIB fence");

    let RibUpdate::PeerDown { peer, session_id } = drain_after_cancel.await.unwrap() else {
        panic!("aborted primary must be fenced in the RIB");
    };
    assert_eq!(peer, addr);
    assert_eq!(session_id, 1);
    let managed = mgr.peers.get(&key(addr)).unwrap();
    assert_eq!(managed.session_id, 3);
    assert!(!managed.enabled);
    assert!(managed.pending_inbound.is_none());
    assert!(mgr.peer_key_for_session(1).is_none());
    assert_eq!(mgr.peer_key_for_session(3), Some(key(addr)));
    assert_eq!(candidate.shutdown.load(Ordering::SeqCst), 1);
    mgr.enable_peer(key(addr)).await.unwrap();
    assert!(mgr.peers.get(&key(addr)).unwrap().enabled);
    assert!(!mgr.max_prefix_latches.contains_key(&key(addr)));
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

/// Load-bearing: omitting the bounded cause from notification-history
/// projection removes the exact suffix while changing the canonical BGP
/// description or shutdown reason breaks the remaining field assertions.
#[tokio::test]
async fn notification_event_reason_includes_bounded_failure_cause() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut events = mgr.session_events_tx.subscribe();
    mgr.publish_notification_event(rustbgpd_transport::SessionNotificationEvent {
        session_id: 1,
        peer_addr: addr,
        role: rustbgpd_transport::SessionRole::Primary,
        direction: rustbgpd_transport::SessionNotificationDirection::Sent,
        code: rustbgpd_wire::notification::NotificationCode::Cease.as_u8(),
        subcode: rustbgpd_wire::notification::cease_subcode::OUT_OF_RESOURCES,
        description: "Out of Resources".to_string(),
        shutdown_reason: None,
        failure_cause: Some(rustbgpd_transport::handle::SessionFailureCause::OutboundSaturation),
    });

    let rustbgpd_api::peer_types::SessionEvent::Notification(event) = events.try_recv().unwrap()
    else {
        panic!("expected notification event");
    };
    assert_eq!(
        event.reason,
        "BGP NOTIFICATION sent for peer 10.0.0.2: 6/8 (Out of Resources); transport failure: outbound writer queue saturated"
    );
    assert_eq!(event.code, 6);
    assert_eq!(event.subcode, 8);
    assert_eq!(event.description, "Out of Resources");
    assert_eq!(event.shutdown_reason, None);
}

/// Successful configured-peer installs publish their current admin event only
/// after installation; failed duplicate adds must not fabricate one.
#[tokio::test]
async fn peer_presence_add_and_readd_publish_current_admin_state_without_failed_add_noise() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let metrics = mgr.metrics.clone();
    let admin_types = [
        SessionLifecycleEventType::PeerEnabled,
        SessionLifecycleEventType::PeerDisabled,
    ]
    .into_iter()
    .collect();

    mgr.add_peer(make_config(addr, 65002), false).await.unwrap();
    assert_eq!(
        peer_identity_gauge(&metrics, "bgp_peer_admin_enabled", "10.0.0.2", ""),
        Some(1.0)
    );
    assert_eq!(
        peer_identity_gauge(&metrics, "bgp_peer_session_established", "10.0.0.2", ""),
        Some(0.0)
    );
    assert!(mgr.add_peer(make_config(addr, 65002), false).await.is_err());
    mgr.disable_peer(key(addr), None).await.unwrap();
    mgr.delete_peer(key(addr), false).await.unwrap();
    mgr.add_peer(make_config(addr, 65002), false).await.unwrap();
    mgr.delete_peer(key(addr), false).await.unwrap();
    mgr.add_peer_with_admin_state(make_config(addr, 65002), false, false)
        .await
        .unwrap();

    let events = query_session_event_history(&mgr, Some(addr), admin_types, 0).await;
    assert_eq!(
        events
            .iter()
            .map(|event| event.event_type)
            .collect::<Vec<_>>(),
        vec![
            SessionLifecycleEventType::PeerEnabled,
            SessionLifecycleEventType::PeerDisabled,
            SessionLifecycleEventType::PeerEnabled,
            SessionLifecycleEventType::PeerDisabled,
        ]
    );
    assert!(!mgr.list_peers().await[0].enabled);

    let presence_types = [
        SessionLifecycleEventType::PeerAdded,
        SessionLifecycleEventType::PeerRemoved,
    ]
    .into_iter()
    .collect();
    let presence = query_session_event_history(&mgr, Some(addr), presence_types, 0).await;
    assert_eq!(
        presence
            .iter()
            .map(|event| (event.event_type, event.reason.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (SessionLifecycleEventType::PeerAdded, "peer 10.0.0.2 added"),
            (
                SessionLifecycleEventType::PeerRemoved,
                "peer 10.0.0.2 removed"
            ),
            (SessionLifecycleEventType::PeerAdded, "peer 10.0.0.2 added"),
            (
                SessionLifecycleEventType::PeerRemoved,
                "peer 10.0.0.2 removed"
            ),
        ]
    );
    assert_eq!(presence[0].old_state, None);
    assert_eq!(presence[0].new_state, Some(SessionState::Idle));
    assert_eq!(presence[1].old_state, None);
    assert_eq!(presence[1].new_state, None);
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

fn blocked_truth_observing_start_handle(
    metrics: BgpMetrics,
    peer: PeerKey,
) -> (PeerHandle, Arc<Notify>, oneshot::Receiver<()>) {
    let (commands, mut command_rx) = mpsc::channel(1);
    commands.try_send(PeerCommand::Start).unwrap();
    let gate = Arc::new(Notify::new());
    let task_gate = gate.clone();
    let (observed_tx, observed_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        task_gate.notified().await;
        let _filler = command_rx.recv().await;
        assert!(matches!(command_rx.recv().await, Some(PeerCommand::Start)));
        let label = rustbgpd_telemetry::peer_label(peer.address);
        let interface = peer.interface.as_deref().unwrap_or("");
        assert_eq!(
            peer_identity_gauge(&metrics, "bgp_peer_admin_enabled", &label, interface),
            Some(1.0)
        );
        assert_eq!(
            peer_identity_gauge(&metrics, "bgp_peer_session_established", &label, interface),
            Some(0.0)
        );
        metrics.set_peer_session_established(&label, interface, true);
        let _ = observed_tx.send(());
        while let Some(command) = command_rx.recv().await {
            if matches!(command, PeerCommand::Shutdown) {
                break;
            }
        }
        Ok(())
    });
    (PeerHandle::from_parts(commands, task), gate, observed_rx)
}

async fn assert_new_peer_start_truth_is_seeded(peer: PeerKey) {
    let mgr = test_peer_manager();
    let metrics = mgr.metrics.clone();
    let label = rustbgpd_telemetry::peer_label(peer.address);
    let interface = peer.interface.as_deref().unwrap_or("");
    let (handle, gate, observed) =
        blocked_truth_observing_start_handle(metrics.clone(), peer.clone());
    let provision = mgr.provision_new_peer_session(&peer, true, true, handle, "test start");
    tokio::pin!(provision);
    tokio::select! {
        biased;
        _ = &mut provision => panic!("Start unexpectedly advanced through a full channel"),
        () = tokio::task::yield_now() => {}
    }
    assert_eq!(
        peer_identity_gauge(&metrics, "bgp_peer_admin_enabled", &label, interface),
        Some(1.0)
    );
    assert_eq!(
        peer_identity_gauge(&metrics, "bgp_peer_session_established", &label, interface),
        Some(0.0)
    );
    gate.notify_one();
    let handle = provision.await.unwrap();
    observed.await.unwrap();
    assert_eq!(
        peer_identity_gauge(&metrics, "bgp_peer_session_established", &label, interface),
        Some(1.0),
        "ownership preparation must never overwrite a post-Start state"
    );
    handle.shutdown().await.unwrap().unwrap();
}

#[tokio::test]
async fn new_peer_provisioning_seeds_truth_before_start_and_never_post_zeros() {
    assert_new_peer_start_truth_is_seeded(key("192.0.2.10".parse().unwrap())).await;
}

#[test]
fn static_add_routes_start_through_truth_provisioning_before_install() {
    let source = include_str!("lifecycle.rs");
    let body = source
        .split_once("pub(super) async fn add_peer_with_admin_state")
        .unwrap()
        .1
        .split_once("pub(super) async fn reconfigure_peer")
        .unwrap()
        .0;
    assert_eq!(body.matches(".provision_new_peer_session(").count(), 1);
    assert!(
        body.find(".provision_new_peer_session(").unwrap()
            < body.find("self.peers.insert(").unwrap()
    );
    assert!(!body.contains("seed_peer_truth_metrics"));
}

#[test]
fn fresh_dynamic_accept_routes_start_through_truth_provisioning_before_install() {
    let source = include_str!("inbound.rs");
    let body = source
        .split_once("pub(super) async fn handle_inbound")
        .unwrap()
        .1
        .split_once("pub(super) async fn resolve_collision")
        .unwrap()
        .0;
    assert_eq!(body.matches(".provision_new_peer_session(").count(), 1);
    assert!(
        body.find(".provision_new_peer_session(").unwrap()
            < body.find("self.peers.insert(").unwrap()
    );
    assert!(!body.contains("seed_peer_truth_metrics"));
}

#[tokio::test(start_paused = true)]
async fn failed_start_exact_reaps_provisional_truth_and_preserves_scoped_sibling() {
    let mgr = test_peer_manager();
    let metrics = mgr.metrics.clone();
    let address = "fe80::1".parse().unwrap();
    let failed = scoped_key(address, "eth0");
    let dropped = Arc::new(AtomicU32::new(0));
    mgr.seed_peer_truth_metrics(&scoped_key(address, "eth1"), false);

    assert!(
        mgr.provision_new_peer_session(
            &failed,
            true,
            true,
            stalled_shutdown_peer_handle(dropped.clone()).await,
            "test failed start"
        )
        .await
        .is_err()
    );
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        1,
        "failed provisioning must quiesce the provisional actor before returning"
    );
    for family in ["bgp_peer_admin_enabled", "bgp_peer_session_established"] {
        assert_eq!(
            peer_identity_gauge(&metrics, family, "fe80::1", "eth0"),
            None
        );
        assert_eq!(
            peer_identity_gauge(&metrics, family, "fe80::1", "eth1"),
            Some(0.0)
        );
    }

    let source = include_str!("lifecycle.rs");
    let body = source
        .split_once("pub(super) async fn provision_new_peer_session")
        .unwrap()
        .1
        .split_once("pub(super) async fn sync_owned_session_metrics")
        .unwrap()
        .0;
    assert_eq!(body.matches(".shutdown_handle_bounded(").count(), 1);
    assert_eq!(body.matches(".reap_peer_identity_series(").count(), 1);
    assert!(
        body.find(".shutdown_handle_bounded(").unwrap()
            < body.find(".reap_peer_identity_series(").unwrap(),
        "failed provisioning must quiesce the actor before reaping its identity series"
    );
}

/// Seed per-peer series across the emitters that own them — session,
/// RIB, BFD — all under the one canonical bare-address `peer` label.
fn seed_peer_metric_series(metrics: &BgpMetrics, peer_label: &str) {
    metrics.initialize_exact_export_rejection_series(peer_label, ["ipv4_unicast"]);
    metrics.initialize_update_malformed_series(peer_label);
    metrics.record_state_transition(peer_label, "idle", "connect");
    metrics.record_state_transition(peer_label, "open_confirm", "established");
    metrics.set_peer_admin_enabled(peer_label, "", true);
    metrics.set_peer_session_established(peer_label, "", true);
    metrics.record_message_sent(peer_label, "keepalive");
    metrics.set_rib_prefixes(peer_label, "ipv4_unicast", 42);
    metrics.record_bfd_state(peer_label, true, false);
    // ADR-0112: peer creation materializes both directional gauges so a
    // healthy peer has a 0 series to alert on rather than an absent one. The
    // direct-insert test helpers bypass that path, so seed them here to keep
    // the reap accounting comparable to production.
    metrics.set_rfc8212_missing_policy(peer_label, false, false);
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
    seed_peer_metric_series(&metrics_view, "10.0.0.2");
    metrics_view.record_fib_route_installed(); // process-global counter
    assert!(peer_metric_series_count(&metrics_view, "10.0.0.2") > 0);

    mgr.delete_peer(key(peer_addr), false).await.unwrap();

    // One reap clears every emitter; process-global counters are untouched.
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

#[tokio::test(start_paused = true)]
async fn peer_presence_rollback_reap_after_shutdown_preserves_scoped_sibling() {
    let mut mgr = dynamic_test_manager();
    mgr.dynamic_ranges.clear();
    let metrics = mgr.metrics.clone();
    let address = "fe80::1".parse().unwrap();
    let stale = scoped_key(address, "eth0");
    let sibling = scoped_key(address, "eth1");
    let dropped = Arc::new(AtomicU32::new(0));
    insert_test_dynamic_managed_peer(
        &mut mgr,
        address,
        89,
        stalled_shutdown_peer_handle(dropped.clone()).await,
        true,
        "2001:db8::".parse().unwrap(),
        64,
        "ix-members",
    );
    let managed = mgr.peers.remove(&key(address)).unwrap();
    mgr.unregister_session(89);
    mgr.peers.insert(stale.clone(), managed);
    mgr.register_session(89, &stale);
    mgr.seed_peer_truth_metrics(&stale, true);

    let mut sibling_config = make_config(address, 65002);
    sibling_config.interface = Some("eth1".to_string());
    sibling_config.scope_id = Some(2);
    mgr.add_peer_with_admin_state(sibling_config, false, false)
        .await
        .unwrap();

    assert_eq!(
        mgr.reap_dynamic_peers_not_allowed_by_current_ranges().await,
        1
    );
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    let removed = query_session_event_history(
        &mgr,
        Some(address),
        [SessionLifecycleEventType::PeerRemoved]
            .into_iter()
            .collect(),
        0,
    )
    .await;
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].peer_label.as_deref(), Some("fe80::1%eth0"));
    assert_eq!(
        peer_identity_gauge(&metrics, "bgp_peer_session_established", "fe80::1", "eth0"),
        None
    );
    assert_eq!(
        peer_identity_gauge(&metrics, "bgp_peer_admin_enabled", "fe80::1", "eth0"),
        None
    );
    assert_eq!(
        peer_identity_gauge(&metrics, "bgp_peer_admin_enabled", "fe80::1", "eth1"),
        Some(0.0)
    );
    assert_eq!(
        peer_identity_gauge(&metrics, "bgp_peer_session_established", "fe80::1", "eth1"),
        Some(0.0)
    );
    assert!(mgr.peers.contains_key(&sibling));
    mgr.delete_peer(sibling, false).await.unwrap();
}

#[tokio::test]
async fn peer_presence_scoped_siblings_remove_exactly_and_reap_bare_address_last() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
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
    let address = "fe80::1".parse().unwrap();
    let first = scoped_key(address, "eth0");
    let last = scoped_key(address, "eth1");
    for (interface, scope_id) in [("eth0", 1), ("eth1", 2)] {
        let mut config = make_config(address, 65002);
        config.interface = Some(interface.to_string());
        config.scope_id = Some(scope_id);
        mgr.add_peer_with_admin_state(config, false, false)
            .await
            .unwrap();
    }

    mgr.delete_peer(first, false).await.unwrap();
    assert!(
        rib_rx.try_recv().is_err(),
        "surviving sibling owns bare address"
    );
    mgr.delete_peer(last, false).await.unwrap();
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::PeerDeleted { peer }) if peer == address
    ));
    let removed = query_session_event_history(
        &mgr,
        Some(address),
        [SessionLifecycleEventType::PeerRemoved]
            .into_iter()
            .collect(),
        0,
    )
    .await;
    assert_eq!(
        removed
            .iter()
            .map(|event| event.peer_label.as_deref())
            .collect::<Vec<_>>(),
        vec![Some("fe80::1%eth0"), Some("fe80::1%eth1")]
    );
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
    seed_peer_metric_series(&metrics_view, "10.0.0.2");
    metrics_view.record_state_transition("10.0.0.2", "established", "idle");
    let before = peer_metric_series_count(&metrics_view, "10.0.0.2");

    // A static peer's session flap (BackToIdle) must keep its history.
    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id: 1,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr,
    })
    .await;

    assert!(mgr.peers.contains_key(&key(peer_addr)));
    assert_eq!(peer_metric_series_count(&metrics_view, "10.0.0.2"), before);
    assert!(rib_rx.try_recv().is_err(), "no PeerDeleted on a flap");
}

#[tokio::test]
async fn peer_presence_reconfigure_keeps_admin_event_but_stays_presence_silent() {
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
    seed_peer_metric_series(&metrics_view, "10.0.0.2");
    let before = peer_metric_series_count(&metrics_view, "10.0.0.2");

    // Reconfigure routes through the same delete primitive, but the
    // peer continues to exist — its series and history must survive.
    let mut new_config = make_config(peer_addr, 65002);
    new_config.description = "reshaped".to_string();
    mgr.reconfigure_peer(new_config).await.unwrap();

    assert!(mgr.peers.contains_key(&key(peer_addr)));
    assert_eq!(peer_metric_series_count(&metrics_view, "10.0.0.2"), before);
    assert!(
        rib_rx.try_recv().is_err(),
        "no PeerDeleted on a reconfigure"
    );
    let presence = query_session_event_history(
        &mgr,
        Some(peer_addr),
        [
            SessionLifecycleEventType::PeerAdded,
            SessionLifecycleEventType::PeerRemoved,
        ]
        .into_iter()
        .collect(),
        0,
    )
    .await;
    assert!(presence.is_empty(), "reconfigure must be presence-silent");
    let admin = query_session_event_history(
        &mgr,
        Some(peer_addr),
        [SessionLifecycleEventType::PeerEnabled]
            .into_iter()
            .collect(),
        0,
    )
    .await;
    assert_eq!(admin.len(), 1, "reconfigure keeps its incarnation fence");
}

#[test]
fn peer_presence_source_ordering_contracts() {
    let lifecycle = include_str!("lifecycle.rs");
    let public_add = lifecycle
        .split_once("pub(super) async fn add_peer(")
        .unwrap()
        .1
        .split_once("pub(super) async fn runtime_create_peer")
        .unwrap()
        .0;
    assert!(public_add.contains("add_peer_impl(config, sync_config_snapshot, true, true)"));
    let internal_add = lifecycle
        .split_once("pub(super) async fn add_peer_with_admin_state(")
        .unwrap()
        .1
        .split_once("async fn add_peer_impl")
        .unwrap()
        .0;
    assert!(internal_add.contains("add_peer_impl(config, sync_config_snapshot, enabled, false)"));

    let reap = lifecycle
        .split_once("reap_deleted_peer_metric_series_for_key")
        .unwrap()
        .1;
    assert!(reap.find("PeerRemoved").unwrap() < reap.find("peer_keys_for_address").unwrap());
    let deletion = lifecycle
        .split_once("pub(super) async fn delete_peer_checked")
        .unwrap()
        .1
        .split_once("pub(super) async fn reap_deleted_peer_metric_series_for_key")
        .unwrap()
        .0;
    assert!(
        deletion.rfind("quiesce_retiring_session").unwrap()
            < deletion
                .find("reap_deleted_peer_metric_series_for_key")
                .unwrap()
    );
    assert!(!deletion.contains("PeerRemoved"));

    let publisher = include_str!("events.rs")
        .split_once("pub(super) fn publish_session_event")
        .unwrap()
        .1
        .split_once("pub(super) fn publish_lifecycle_event")
        .unwrap()
        .0;
    assert!(publisher.find("push_back").unwrap() < publisher.find("try_send_envelope").unwrap());
    assert!(
        publisher.find("try_send_envelope").unwrap()
            < publisher.find("session_events_tx.send").unwrap()
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
    seed_peer_metric_series(&metrics_view, "10.0.0.2");

    // Auto-removal on idle is a full deletion for a dynamic peer.
    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id: 1,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr,
    })
    .await;

    assert!(mgr.peers.is_empty());
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
    config.tcp_ao = Some(
        rustbgpd_transport::TcpAoConfig {
            key: "secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        }
        .into(),
    );

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
    let tcp_ao: rustbgpd_transport::TcpAoKeyring = rustbgpd_transport::TcpAoConfig {
        key: "secret".into(),
        send_id: 1,
        recv_id: 1,
        algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
        preferred: false,
        deprecated: false,
    }
    .into();
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
fn build_transport_config_threads_reject_retention_settings() {
    // LAN-472: both [policy.reject_retention] knobs must propagate from
    // the daemon config snapshot into the per-session TransportConfig —
    // same threading hazard as the [policy.explain] siblings above.
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
    mgr.current_config.policy.reject_retention.enabled = false;
    mgr.current_config.policy.reject_retention.capacity = 64;

    let config = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
    let transport = mgr.build_transport_config(&config);
    assert!(
        !transport.reject_retention_enabled,
        "enabled must propagate"
    );
    assert_eq!(
        transport.reject_retention_capacity, 64,
        "capacity must propagate"
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
#[allow(
    clippy::too_many_lines,
    reason = "the inventory test keeps every transport field in one exact assertion"
)]
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
        min_hold_time: Some(30),
        address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        interface: Some("test-if".to_string()),
        scope_id: Some(7),
        remote_asn: 65002,
        description: "sentinel-description".to_string(),
        peer_group: Some("rr-clients".to_string()),
        hold_time: Some(240),
        send_hold_time: Some(600),
        slow_peer_threshold_pct: 77,
        slow_peer_duration: 120,
        slow_peer_isolation: true,
        max_prefixes: Some(1000),
        max_prefixes_ipv4: None,
        max_prefixes_ipv6: None,
        max_prefix_restart_seconds: Some(30),
        md5_password: Some("hunter2".into()),
        tcp_ao: Some(
            rustbgpd_transport::TcpAoConfig {
                key: "ao-secret".into(),
                send_id: 11,
                recv_id: 22,
                algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
                preferred: true,
                deprecated: false,
            }
            .into(),
        ),
        ttl_security: true,
        families: vec![(Afi::Ipv6, Safi::Unicast)],
        required_families: vec![(Afi::Ipv6, Safi::Unicast)],
        graceful_restart: true,
        gr_restart_time: 300,
        gr_peer_restart_time_max: 301,
        gr_stale_routes_time: 720,
        llgr_stale_time: 3600,
        gr_restart_eligible: false,
        local_ipv6_nexthop: Some("2001:db8::1".parse().unwrap()),
        route_reflector_client: true,
        orr_vantage: Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
        route_server_client: true,
        per_client_best: true,
        next_hop_ownership_strict_peer: true,
        interpret_rfc1997: false,
        rs_control_communities: true,
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
        max_prefixes_ipv4,
        max_prefixes_ipv6,
        max_prefix_restart_seconds: _max_prefix_restart_seconds,
        md5_password,
        tcp_ao,
        ttl_security,
        families,
        required_families,
        graceful_restart,
        gr_restart_time,
        gr_peer_restart_time_max,
        gr_stale_routes_time,
        llgr_stale_time,
        gr_restart_eligible,
        local_ipv6_nexthop,
        route_reflector_client,
        orr_vantage,
        route_server_client,
        per_client_best,
        next_hop_ownership_strict_peer,
        slow_peer_threshold_pct,
        slow_peer_duration,
        slow_peer_isolation,
        interpret_rfc1997,
        rs_control_communities,
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
        min_hold_time,
    } = &config;

    let t = mgr.build_transport_config(&config);

    assert_eq!(t.remote_addr.ip(), *address, "address");
    assert_eq!(t.peer_interface, *interface, "interface");
    assert_eq!(t.peer_scope_id, *scope_id, "scope_id");
    assert_eq!(t.peer.remote_asn, *remote_asn, "remote_asn");
    assert_eq!(t.peer_group, *peer_group, "peer_group");
    assert_eq!(t.peer.hold_time, hold_time.unwrap(), "hold_time");
    assert_eq!(t.peer.min_hold_time, *min_hold_time, "min_hold_time");
    assert_eq!(t.max_prefixes_ipv4, *max_prefixes_ipv4, "max_prefixes_ipv4");
    assert_eq!(t.max_prefixes_ipv6, *max_prefixes_ipv6, "max_prefixes_ipv6");
    assert_eq!(
        t.peer.send_hold_time,
        send_hold_time.unwrap(),
        "send_hold_time"
    );
    assert_eq!(t.max_prefixes, *max_prefixes, "max_prefixes");
    assert_eq!(
        t.md5_password.as_ref().map(std::convert::AsRef::as_ref),
        md5_password.as_ref().map(std::convert::AsRef::as_ref),
        "md5_password"
    );
    assert_eq!(t.tcp_ao, *tcp_ao, "tcp_ao");
    assert_eq!(t.ttl_security, *ttl_security, "ttl_security");
    assert_eq!(t.peer.families, *families, "families");
    assert_eq!(
        t.peer.required_families, *required_families,
        "required_families"
    );
    assert_eq!(
        t.peer.graceful_restart, *graceful_restart,
        "graceful_restart"
    );
    assert_eq!(t.peer.gr_restart_time, *gr_restart_time, "gr_restart_time");
    assert_eq!(
        t.gr_peer_restart_time_max, *gr_peer_restart_time_max,
        "gr_peer_restart_time_max"
    );
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
    // ADR-0107: same #702 threading class — the fixture value (true)
    // differs from the TransportConfig::new default (false), so a
    // dropped assignment fails here rather than shipping silently.
    assert_eq!(
        t.next_hop_ownership_strict_peer, *next_hop_ownership_strict_peer,
        "next_hop_ownership_strict_peer"
    );
    assert_eq!(
        t.slow_peer_threshold_pct, *slow_peer_threshold_pct,
        "slow_peer_threshold_pct"
    );
    assert_eq!(
        t.slow_peer_duration, *slow_peer_duration,
        "slow_peer_duration"
    );
    assert_eq!(
        t.slow_peer_isolation, *slow_peer_isolation,
        "slow_peer_isolation"
    );
    // Same class of pin for the RFC 1997 egress knob: the fixture value
    // (false) differs from the TransportConfig::new default (true), so a
    // dropped assignment fails here rather than shipping silently.
    assert_eq!(t.interpret_rfc1997, *interpret_rfc1997, "interpret_rfc1997");
    // RFC 7947 control communities: fixture value (true) differs from the
    // TransportConfig::new default (false) — a dropped assignment fails
    // here rather than shipping silently.
    assert_eq!(
        t.rs_control_communities, *rs_control_communities,
        "rs_control_communities"
    );
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

/// Read one policy-freshness metric from the gathered exposition:
/// the unlabeled family value, or the child whose `dataset` label
/// matches. `None` when the family/series is absent.
#[expect(
    clippy::cast_possible_truncation,
    reason = "unix-seconds gauges and small test counters fit i64"
)]
fn policy_metric_value(metrics: &BgpMetrics, family: &str, dataset: Option<&str>) -> Option<i64> {
    metrics
        .registry()
        .gather()
        .iter()
        .find(|f| f.name() == family)?
        .get_metric()
        .iter()
        .find(|m| match dataset {
            Some(dataset) => m
                .get_label()
                .iter()
                .any(|l| l.name() == "dataset" && l.value() == dataset),
            None => true,
        })
        .map(|m| {
            // Counter families follow the `_total` naming convention;
            // everything read here otherwise is a gauge.
            if family.ends_with("_total") {
                m.get_counter().value() as i64
            } else {
                m.get_gauge().value() as i64
            }
        })
}

/// Block until the wall clock has advanced past `after` (unix
/// seconds), so a subsequent timestamp stamp is distinguishable
/// from one taken at `after`.
async fn wait_for_unix_second_after(after: i64) {
    loop {
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_secs(),
        )
        .expect("unix seconds fit i64");
        if now > after {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// ADR-0110 load-bearing staleness assertion: a rejected rpol sync
/// keeps the old generation live AND freezes
/// `bgp_policy_generation_loaded_timestamp_seconds` — the timestamp
/// must NOT advance on a failed swap, otherwise `time() - <gauge>`
/// alerting can never see a stuck pipeline. A subsequent successful
/// sync advances it.
#[tokio::test]
async fn rejected_rpol_sync_freezes_policy_generation_timestamp() {
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

    const FAMILY: &str = "bgp_policy_generation_loaded_timestamp_seconds";
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
    // Initial load: constructing the manager stamped the generation.
    let initial = policy_metric_value(&mgr.metrics, FAMILY, None).expect("stamped at construction");
    assert!(initial > 0);

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

    // Let the wall clock tick so a (buggy) stamp on the failed swap
    // below would be distinguishable from the construction stamp.
    wait_for_unix_second_after(initial).await;

    // Candidate registry renames the policy, so the static peer's
    // chain no longer resolves: the sync is rejected — and the
    // timestamp must stay frozen at the last ACCEPTED apply.
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
    assert_eq!(
        policy_metric_value(&mgr.metrics, FAMILY, None),
        Some(initial),
        "a rejected swap must not advance the loaded timestamp"
    );

    // A successful sync IS an accept: the timestamp advances.
    mgr.sync_rpol_policies(
        vec!["policies/core.rpol".to_string()],
        registry(
            "edge-in",
            "policy edge-in { term all { set local-pref 250; accept } }",
        ),
        rustbgpd_policy::datasets::DatasetBindings::default(),
    )
    .await
    .expect("sync succeeds");
    let advanced = policy_metric_value(&mgr.metrics, FAMILY, None).expect("still present");
    assert!(
        advanced > initial,
        "successful swap must stamp a newer time"
    );

    drop(mgr);
    rib_drainer.await.unwrap();
}

/// ADR-0110: `RefreshDatasetDependents` stamps
/// `bgp_policy_dataset_loaded_timestamp_seconds{dataset}` for each
/// swapped dataset, while a failed refresh only increments the
/// failure counter — it never creates/advances the loaded timestamp.
#[tokio::test]
async fn dataset_refresh_stamps_swapped_and_freezes_failed() {
    const LOADED: &str = "bgp_policy_dataset_loaded_timestamp_seconds";
    const FAILURES: &str = "bgp_policy_dataset_refresh_errors_total";
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
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
    mgr.refresh_dataset_dependents(
        &["customers".to_string()],
        &[("bogons".to_string(), "unreadable".to_string())],
    )
    .await
    .expect("refresh fan-out with no peers succeeds");

    let stamped =
        policy_metric_value(&mgr.metrics, LOADED, Some("customers")).expect("swapped stamped");
    assert!(stamped > 0);
    assert_eq!(
        policy_metric_value(&mgr.metrics, LOADED, Some("bogons")),
        None,
        "a failed refresh must not create a loaded-timestamp series"
    );
    assert_eq!(
        policy_metric_value(&mgr.metrics, FAILURES, Some("bogons")),
        Some(1)
    );
}

/// ADR-0110 reap discipline: a dataset removed from config on a
/// successful rpol sync drops BOTH its per-dataset series (loaded
/// timestamp and failure counter); a dataset introduced by the sync
/// gets its initial stamp.
#[tokio::test]
async fn rpol_sync_reaps_removed_dataset_series() {
    use rustbgpd_policy::datasets::{DatasetBindings, DatasetData, DatasetHandle, DatasetKind};
    use rustbgpd_policy::rpol::RpolPolicySet;
    use rustbgpd_policy::sets::AsnSet;

    const LOADED: &str = "bgp_policy_dataset_loaded_timestamp_seconds";
    const FAILURES: &str = "bgp_policy_dataset_refresh_errors_total";
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
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

    // Sync #1 introduces the dataset: its series appears.
    let mut bindings = DatasetBindings::default();
    bindings.insert(std::sync::Arc::new(DatasetHandle::new(
        "customers",
        DatasetKind::Asn,
        DatasetData::Asn(AsnSet::new(std::iter::once(64500))),
    )));
    mgr.sync_rpol_policies(Vec::new(), RpolPolicySet::default(), bindings)
        .await
        .expect("sync with a new dataset succeeds");
    assert!(policy_metric_value(&mgr.metrics, LOADED, Some("customers")).is_some());
    mgr.metrics.record_policy_dataset_refresh_error("customers");
    assert_eq!(
        policy_metric_value(&mgr.metrics, FAILURES, Some("customers")),
        Some(1)
    );

    // Sync #2 removes it from config: both series are reaped.
    mgr.sync_rpol_policies(
        Vec::new(),
        RpolPolicySet::default(),
        DatasetBindings::default(),
    )
    .await
    .expect("sync removing the dataset succeeds");
    assert_eq!(
        policy_metric_value(&mgr.metrics, LOADED, Some("customers")),
        None,
        "removed dataset must not keep advertising freshness"
    );
    assert_eq!(
        policy_metric_value(&mgr.metrics, FAILURES, Some("customers")),
        None
    );
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

/// Load-bearing dynamic inheritance proof: dropping the post-commit sync in
/// `apply_peer_group_change` leaves an accepted dynamic peer on the duration
/// it inherited at accept time. The None -> 30 assertion and the 30 -> 60
/// countdown rescheduling each fail independently without that sync.
#[tokio::test(start_paused = true)]
async fn set_peer_group_restart_policy_updates_live_dynamic_peer() {
    let mut mgr = dynamic_test_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 76));
    insert_test_dynamic_managed_peer(
        &mut mgr,
        addr,
        76,
        fake_peer_handle(
            addr,
            SessionState::Idle,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
        false,
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        8,
        "ix-members",
    );
    assert_eq!(mgr.peers[&key(addr)].max_prefix_restart_seconds, None);

    let mut group = crate::policy_admin::config_peer_group_to_api(
        &mgr.current_config.peer_groups["ix-members"],
    );
    group.max_prefix_restart_seconds = Some(30);
    mgr.apply_peer_group_change(
        rustbgpd_api::peer_types::ConfigEvent::SetPeerGroup {
            name: "ix-members".to_string(),
            definition: group,
            ack: None,
        },
        Vec::new(),
    )
    .await
    .unwrap();
    assert_eq!(mgr.peers[&key(addr)].max_prefix_restart_seconds, Some(30));

    mgr.install_max_prefix_latch(key(addr), 76, "first policy".to_string(), Some(30));
    tokio::time::advance(Duration::from_secs(10)).await;
    let mut group = crate::policy_admin::config_peer_group_to_api(
        &mgr.current_config.peer_groups["ix-members"],
    );
    group.max_prefix_restart_seconds = Some(60);
    mgr.apply_peer_group_change(
        rustbgpd_api::peer_types::ConfigEvent::SetPeerGroup {
            name: "ix-members".to_string(),
            definition: group,
            ack: None,
        },
        Vec::new(),
    )
    .await
    .unwrap();
    assert_eq!(mgr.peers[&key(addr)].max_prefix_restart_seconds, Some(60));
    assert_eq!(
        mgr.max_prefix_latches[&key(addr)].deadline.unwrap() - tokio::time::Instant::now(),
        Duration::from_mins(1),
        "a group duration edit must reschedule the armed countdown to now + new"
    );
}

/// Load-bearing reload-sweep re-arm proof: a config swap that edits a group's
/// restart duration reschedules a still-matched dynamic member's armed
/// countdown to now + new and syncs the managed copy so the due-time policy
/// check passes — the superseded deadline never fires, the re-armed one fires
/// exactly once.
#[tokio::test(start_paused = true)]
async fn reconcile_sweep_rearms_dynamic_peer_on_group_duration_edit() {
    let mut mgr = dynamic_test_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 78));
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_dynamic_managed_peer(
        &mut mgr,
        addr,
        78,
        fake_peer_handle(addr, SessionState::Idle, None, counters.clone()),
        false,
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        8,
        "ix-members",
    );
    mgr.current_config
        .peer_groups
        .get_mut("ix-members")
        .unwrap()
        .max_prefix_restart_seconds = std::num::NonZeroU32::new(30);
    mgr.peers
        .get_mut(&key(addr))
        .unwrap()
        .max_prefix_restart_seconds = Some(30);
    mgr.install_max_prefix_latch(key(addr), 78, "max-prefix".to_string(), Some(30));

    tokio::time::advance(Duration::from_secs(10)).await;
    mgr.current_config
        .peer_groups
        .get_mut("ix-members")
        .unwrap()
        .max_prefix_restart_seconds = std::num::NonZeroU32::new(60);
    mgr.reconcile_stale_dynamic_max_prefix_restarts();
    assert_eq!(
        mgr.max_prefix_latches[&key(addr)].deadline.unwrap() - tokio::time::Instant::now(),
        Duration::from_mins(1)
    );
    assert_eq!(mgr.peers[&key(addr)].max_prefix_restart_seconds, Some(60));

    // Past the superseded t+30 deadline but before the re-armed t+70 one.
    tokio::time::advance(Duration::from_secs(25)).await;
    mgr.handle_due_max_prefix_restarts().await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(counters.start.load(Ordering::SeqCst), 0);
    assert!(!mgr.peers[&key(addr)].enabled);

    tokio::time::advance(Duration::from_secs(35)).await;
    mgr.handle_due_max_prefix_restarts().await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(counters.start.load(Ordering::SeqCst), 1);
    assert!(mgr.peers[&key(addr)].enabled);
    assert!(!mgr.max_prefix_latches.contains_key(&key(addr)));
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
            max_prefix_restart_seconds: None,
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: false,
            rfc8212_external: false,
            tcp_ao_protected: false,
            accepted_dynamic_range: None,
            pending_refresh: true,
            pending_export_apply: false,
            tcp_ao_rotation: TcpAoRotationStatus::default(),
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

/// Session model for an ambiguous import apply: it installs every supplied
/// chain, drops the first reply after mutation, and acknowledges subsequent
/// installs. Rollback must therefore reassert the prior chain before refresh.
fn import_ack_loss_policy_handle(
    peer_addr: IpAddr,
    live_import: Arc<Mutex<Option<rustbgpd_policy::PolicyChain>>>,
    import_installs: Arc<AtomicUsize>,
    refreshes: Arc<AtomicUsize>,
) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let first_import = Arc::new(AtomicBool::new(true));
    let task = tokio::spawn(async move {
        while let Some(command) = session_rx.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    let _ =
                        reply.send(policy_test_peer_state(peer_addr, SessionState::Established));
                }
                PeerCommand::UpdateImportPolicy { policy, reply } => {
                    *live_import.lock().unwrap() = policy;
                    import_installs.fetch_add(1, Ordering::SeqCst);
                    if first_import.swap(false, Ordering::SeqCst) {
                        drop(reply);
                    } else {
                        let _ = reply.send(Ok(()));
                    }
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    refreshes.fetch_add(1, Ordering::SeqCst);
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

/// A policy-acking peer with a controllable first and subsequent state-query
/// result. `None` drops the reply and keeps the observation explicitly unknown.
fn sequenced_policy_state_handle(
    peer_addr: IpAddr,
    first_state: Option<SessionState>,
    subsequent_state: Option<SessionState>,
) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let state_queries = Arc::new(AtomicU32::new(0));
    let state_queries_in_task = Arc::clone(&state_queries);
    let task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::QueryState { reply } => {
                    let first = state_queries_in_task.fetch_add(1, Ordering::SeqCst) == 0;
                    let Some(state) = (if first { first_state } else { subsequent_state }) else {
                        drop(reply);
                        continue;
                    };
                    let _ = reply.send(PeerSessionState {
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
                        flap_count: 1,
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

#[derive(Clone, Copy)]
enum NonEstablishedRollbackRibOutcome {
    Registered,
    NotFound,
    UnknownStateNotFound,
    Internal,
}

#[allow(
    clippy::too_many_lines,
    reason = "the rollback helper keeps all peer and RIB outcome assertions together"
)]
async fn assert_non_established_rollback_rib_outcome(
    rollback_outcome: NonEstablishedRollbackRibOutcome,
) {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
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
    let flapping = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let failing = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    insert_test_managed_peer(
        &mut mgr,
        flapping,
        sequenced_policy_state_handle(
            flapping,
            Some(SessionState::Established),
            (!matches!(
                rollback_outcome,
                NonEstablishedRollbackRibOutcome::UnknownStateNotFound
            ))
            .then_some(SessionState::Idle),
        ),
        false,
    );
    insert_test_managed_peer(
        &mut mgr,
        failing,
        acking_policy_handle(failing, SessionState::Established),
        false,
    );

    let prior_import = validation_policy_chain(ImportValidationDependency::Rpki);
    let prior_export = validation_policy_chain(ImportValidationDependency::Aspa);
    for peer in [flapping, failing] {
        let managed = mgr.peers.get_mut(&key(peer)).unwrap();
        managed.import_policy = Some(prior_import.clone());
        managed.export_policy = Some(prior_export.clone());
    }
    let next = deny_policy_chain();
    let expected_next = format!("{:?}", Some(next.clone()));
    let expected_prior = format!("{:?}", Some(prior_export.clone()));
    let rib_driver = tokio::spawn(async move {
        let RibUpdate::ReplacePeerExportPolicy {
            peer,
            export_policy,
            reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected flapping peer forward RIB replacement");
        };
        assert_eq!(peer, flapping);
        assert_eq!(format!("{export_policy:?}"), expected_next);
        reply.send(Ok(())).unwrap();

        let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected failing peer forward RIB replacement");
        };
        assert_eq!(peer, failing);
        reply
            .send(Err(rustbgpd_rib::RibCommandError::internal(
                "force transaction rollback",
            )))
            .unwrap();

        let RibUpdate::ReplacePeerExportPolicy {
            peer,
            export_policy,
            reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected failing peer rollback RIB replacement");
        };
        assert_eq!(peer, failing);
        assert_eq!(format!("{export_policy:?}"), expected_prior);
        reply.send(Ok(())).unwrap();

        let RibUpdate::ReplacePeerExportPolicy {
            peer,
            export_policy,
            reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("non-Established rollback must still attempt the RIB replacement");
        };
        assert_eq!(peer, flapping);
        assert_eq!(format!("{export_policy:?}"), expected_prior);
        let reply_result = match rollback_outcome {
            NonEstablishedRollbackRibOutcome::Registered => Ok(()),
            NonEstablishedRollbackRibOutcome::NotFound => Err(
                rustbgpd_rib::RibCommandError::not_found("peer already absent during rollback"),
            ),
            NonEstablishedRollbackRibOutcome::UnknownStateNotFound => Err(
                rustbgpd_rib::RibCommandError::not_found("peer absent after unknown state query"),
            ),
            NonEstablishedRollbackRibOutcome::Internal => Err(
                rustbgpd_rib::RibCommandError::internal("rollback RIB transport failed"),
            ),
        };
        reply.send(reply_result).unwrap();
    });

    // Distinct export targets keep this snapshot off the LAN-462
    // import-tolerant cohort (no repeated export pair) and on the per-peer
    // authoritative transaction whose rollback this regression pins.
    let result = mgr
        .apply_resolved_policy_snapshot(
            [flapping, failing]
                .into_iter()
                .enumerate()
                .map(|(index, address)| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: Some(next.clone()),
                    export_policy: Some(if index == 0 {
                        next.clone()
                    } else {
                        distinct_deny_policy_chain(1)
                    }),
                })
                .collect(),
        )
        .await;
    let error = result.expect_err("the second peer's forward RIB failure must abort the apply");
    rib_driver.await.unwrap();

    let managed = mgr.peers.get(&key(flapping)).unwrap();
    assert_eq!(
        format!("{:?}", managed.import_policy),
        format!("{:?}", Some(prior_import)),
        "rollback must restore the flapping peer's session import policy"
    );
    assert_eq!(
        format!("{:?}", managed.export_policy),
        format!("{:?}", Some(prior_export)),
        "rollback must restore the flapping peer's session export policy"
    );
    assert!(
        managed.pending_refresh,
        "the non-Established rollback must defer its import refresh"
    );
    match rollback_outcome {
        NonEstablishedRollbackRibOutcome::Registered
        | NonEstablishedRollbackRibOutcome::NotFound => {
            assert!(
                error.contains("already-applied peers restored")
                    && !error.contains("restoring already-applied peers also failed"),
                "a completed restore or typed absence must not manufacture a compound failure: {error}"
            );
            assert!(
                !managed.pending_export_apply,
                "a restored registered object or typed absence leaves no stale RIB export work"
            );
        }
        NonEstablishedRollbackRibOutcome::UnknownStateNotFound
        | NonEstablishedRollbackRibOutcome::Internal => {
            assert!(
                error.contains("restoring already-applied peers also failed")
                    && (error.contains("rollback RIB transport failed")
                        || error.contains("peer absent after unknown state query")),
                "an ambiguous rollback RIB failure must compose into the transaction error: {error}"
            );
            assert!(
                managed.pending_export_apply,
                "an ambiguous rollback RIB failure must retain authoritative export intent"
            );
        }
    }

    mgr.delete_peer(key(flapping), false).await.unwrap();
    mgr.delete_peer(key(failing), false).await.unwrap();
}

#[tokio::test]
async fn non_established_rollback_restores_registered_rib_entry() {
    assert_non_established_rollback_rib_outcome(NonEstablishedRollbackRibOutcome::Registered).await;
}

#[tokio::test]
async fn non_established_rollback_accepts_typed_rib_absence() {
    assert_non_established_rollback_rib_outcome(NonEstablishedRollbackRibOutcome::NotFound).await;
}

#[tokio::test]
async fn unknown_state_rollback_treats_typed_rib_absence_as_fatal() {
    assert_non_established_rollback_rib_outcome(
        NonEstablishedRollbackRibOutcome::UnknownStateNotFound,
    )
    .await;
}

#[tokio::test]
async fn non_established_rollback_internal_rib_failure_is_composed_and_rearmed() {
    assert_non_established_rollback_rib_outcome(NonEstablishedRollbackRibOutcome::Internal).await;
}

#[tokio::test]
async fn ordinary_export_apply_unknown_state_rearms_until_established_retry() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
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
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    insert_test_managed_peer(
        &mut mgr,
        peer,
        sequenced_policy_state_handle(peer, None, Some(SessionState::Established)),
        false,
    );
    let next = deny_policy_chain();

    mgr.update_runtime_policies(peer, None, Some(next.clone()))
        .await
        .expect("an unknown state keeps ordinary forward compatibility");
    assert!(
        mgr.peers.get(&key(peer)).unwrap().pending_export_apply,
        "an unknown state must retain fresh export intent because the peer may actually be Established"
    );
    assert!(
        matches!(rib_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "the unknown-state call must not blindly address an unconfirmed RIB registration"
    );

    let retry = mgr.update_runtime_policies(peer, None, Some(next));
    let drive_rib = async {
        let RibUpdate::ReplacePeerExportPolicy {
            peer: actual,
            reply,
            ..
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected the Established retry to reach the RIB");
        };
        assert_eq!(actual, peer);
        reply.send(Ok(())).unwrap();
    };
    let (result, ()) = tokio::join!(retry, drive_rib);
    result.expect("the Established retry must consume the retained RIB intent");
    assert!(
        !mgr.peers.get(&key(peer)).unwrap().pending_export_apply,
        "a successful authoritative retry must clear export intent"
    );

    mgr.delete_peer(key(peer), false).await.unwrap();
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
    let candidate_toml = tier_authorized_uds_test_config(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix]
import_policy_chain = ["deny-import"]

[policy.definitions.deny-import]
default_action = "deny"

[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "ix"
remote_asn = 65030
"#,
    );
    let candidate = crate::config::Config::load_toml_with_diagnostics(
        &candidate_toml,
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

#[allow(
    clippy::too_many_lines,
    reason = "the regression drives both updates through one complete pending-refresh receipt"
)]
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
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: Some(90),
                        four_octet_as: Some(true),
                        remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
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
                        uptime_secs: u64::from(state == SessionState::Established),
                        last_error: String::new(),
                        tcp_ao_info: None,
                        tcp_ao_protected: false,
                        slow_peer: false,
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
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: Some(90),
                        four_octet_as: Some(true),
                        remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
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
#[allow(
    clippy::too_many_lines,
    reason = "the fanout regression keeps affected and unaffected peer assertions together"
)]
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
            match update {
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    if peer == a {
                        replaces_a.fetch_add(1, Ordering::SeqCst);
                    } else {
                        replaces_b.fetch_add(1, Ordering::SeqCst);
                    }
                    let _ = reply.send(Ok(()));
                }
                // LAN-462: the initial uniform install rides the batched
                // import-tolerant cohort — one member replacement per peer.
                RibUpdate::ReplacePeerExportPolicies {
                    replacements,
                    reply,
                } => {
                    for replacement in replacements {
                        if replacement.peer == a {
                            replaces_a.fetch_add(1, Ordering::SeqCst);
                        } else {
                            replaces_b.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                _ => {}
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

#[tokio::test]
async fn export_only_snapshot_uses_one_batched_rib_commit_and_preserves_priors() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 30, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 30, 0, 2)),
    ];
    let installs = Arc::new(AtomicUsize::new(0));
    let batches = Arc::new(AtomicUsize::new(0));
    let singles = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let batch_count = Arc::clone(&batches);
    let single_count = Arc::clone(&singles);
    let rib_task = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies {
                    replacements,
                    reply,
                } => {
                    assert_eq!(replacements.len(), peers.len());
                    batch_count.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPolicy { reply, .. } => {
                    single_count.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
    });

    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    for peer in peers {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&installs), None),
            false,
        );
    }
    let next = deny_policy_chain();
    let priors = manager
        .apply_resolved_policy_snapshot(
            peers
                .iter()
                .map(|&address| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: None,
                    export_policy: Some(next.clone()),
                })
                .collect(),
        )
        .await
        .unwrap();

    assert_eq!(installs.load(Ordering::SeqCst), peers.len());
    assert_eq!(batches.load(Ordering::SeqCst), 1);
    assert_eq!(singles.load(Ordering::SeqCst), 0);
    assert_eq!(priors.len(), peers.len());
    assert!(priors.iter().all(|prior| prior.export_policy.is_none()));
    assert!(peers.iter().all(|peer| {
        manager
            .peers
            .get(&key(*peer))
            .is_some_and(|managed| managed.export_policy == Some(next.clone()))
    }));

    for peer in peers {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    rib_task.await.unwrap();
}

#[tokio::test]
async fn export_only_snapshot_skips_probe_without_repeated_policy_pair() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 35, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 35, 0, 2)),
    ];
    let (rib_tx, _rib_rx) = mpsc::channel(1);
    let (_command_tx, command_rx) = mpsc::channel(1);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let mut query_counts = Vec::new();
    for peer in peers {
        let (handle, _entered, _release, queries) = stalled_export_policy_test_session(peer);
        query_counts.push(queries);
        insert_test_managed_peer(&mut manager, peer, handle, false);
    }

    let targets = [
        ResolvedPeerPolicy {
            address: peers[0],
            interface: None,
            import_policy: None,
            export_policy: Some(deny_policy_chain()),
        },
        ResolvedPeerPolicy {
            address: peers[1],
            interface: None,
            import_policy: None,
            export_policy: Some(validation_policy_chain(ImportValidationDependency::Rpki)),
        },
    ];
    let selected = manager.export_only_policy_cohort_mask(&targets).await;

    assert_eq!(selected, vec![false, false]);
    assert!(
        query_counts
            .iter()
            .all(|queries| queries.load(Ordering::SeqCst) == 0)
    );

    drop(manager);
}

/// Load-bearing LAN-521 regression: restoring first-viable anchoring selects
/// the leading two-peer pair, making the six-peer batch, single order, and
/// cohort-first prior order below go red.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the actor regression keeps fleet partitioning, RIB dialogue, and prior order in one fixture"
)]
async fn export_only_snapshot_selects_largest_local_policy_pair() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = (1..=10)
        .map(|last| IpAddr::V4(Ipv4Addr::new(10, 36, 1, last)))
        .collect::<Vec<_>>();
    let small = &peers[0..2];
    let large = &peers[2..8];
    let ninth = peers[8];
    let tenth = peers[9];
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
    let rib_task = tokio::spawn(async move {
        let mut batches = Vec::new();
        let mut singles = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies {
                    replacements,
                    reply,
                } => {
                    batches.push(
                        replacements
                            .into_iter()
                            .map(|replacement| replacement.peer)
                            .collect::<Vec<_>>(),
                    );
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    singles.push(peer);
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
        (batches, singles)
    });
    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let installs = Arc::new(AtomicUsize::new(0));
    for &peer in &peers {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&installs), None),
            false,
        );
    }

    let pair_two_chain = distinct_deny_policy_chain(0);
    let pair_six_chain = distinct_deny_policy_chain(1);
    let ninth_chain = distinct_deny_policy_chain(2);
    let tenth_chain = distinct_deny_policy_chain(3);
    let targets = peers
        .iter()
        .copied()
        .map(|address| ResolvedPeerPolicy {
            address,
            interface: None,
            import_policy: None,
            export_policy: Some(if small.contains(&address) {
                pair_two_chain.clone()
            } else if large.contains(&address) {
                pair_six_chain.clone()
            } else if address == ninth {
                ninth_chain.clone()
            } else {
                tenth_chain.clone()
            }),
        })
        .collect::<Vec<_>>();
    let priors = manager
        .apply_resolved_policy_snapshot(targets)
        .await
        .expect("largest-pair snapshot must commit");
    assert_eq!(
        priors.iter().map(|prior| prior.address).collect::<Vec<_>>(),
        large
            .iter()
            .chain(small)
            .copied()
            .chain([ninth, tenth])
            .collect::<Vec<_>>(),
        "apply order remains winning cohort then caller-ordered remainder"
    );
    assert_eq!(installs.load(Ordering::SeqCst), peers.len());

    for &peer in &peers {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    let (batches, singles) = rib_task.await.unwrap();
    assert_eq!(batches, vec![large.to_vec()]);
    assert_eq!(
        singles,
        small
            .iter()
            .copied()
            .chain([ninth, tenth])
            .collect::<Vec<_>>()
    );
}

/// Load-bearing LAN-521 regression: replacing the canonical tie-break with
/// first-seen selection makes the two permutations disagree; querying beyond
/// the winning pair makes one of the losing-pair zero counters go red.
#[tokio::test]
async fn export_only_cohort_tie_break_is_stable_and_queries_only_winner() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let a1 = IpAddr::V4(Ipv4Addr::new(10, 36, 2, 1));
    let b1 = IpAddr::V4(Ipv4Addr::new(10, 36, 2, 2));
    let b2 = IpAddr::V4(Ipv4Addr::new(10, 36, 2, 3));
    let a2 = IpAddr::V4(Ipv4Addr::new(10, 36, 2, 4));
    let all = [a1, b1, b2, a2];
    let permutations = [[a1, b1, b2, a2], [b2, a2, a1, b1]];
    let winner_policy = distinct_deny_policy_chain(4);
    let loser_policy = distinct_deny_policy_chain(5);

    for order in permutations {
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let (_command_tx, command_rx) = mpsc::channel(1);
        let mut manager = PeerManager::new(
            command_rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            BgpMetrics::new(),
            rib_tx,
            None,
        );
        let installs = Arc::new(AtomicUsize::new(0));
        let mut queries = Vec::new();
        for &peer in &all {
            let (handle, peer_queries) = established_export_policy_test_session_with_queries(
                peer,
                Arc::clone(&installs),
                None,
            );
            insert_test_managed_peer(&mut manager, peer, handle, false);
            queries.push((peer, peer_queries));
        }
        let targets = order
            .iter()
            .copied()
            .map(|address| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: None,
                export_policy: Some(if [a1, a2].contains(&address) {
                    winner_policy.clone()
                } else {
                    loser_policy.clone()
                }),
            })
            .collect::<Vec<_>>();
        let mask = manager.export_only_policy_cohort_mask(&targets).await;
        let selected = order
            .iter()
            .zip(&mask)
            .filter_map(|(&peer, &selected)| selected.then_some(peer))
            .collect::<Vec<_>>();
        let remainder = order
            .iter()
            .zip(mask)
            .filter_map(|(&peer, selected)| (!selected).then_some(peer))
            .collect::<Vec<_>>();
        for (peer, count) in &queries {
            assert_eq!(
                count.load(Ordering::SeqCst),
                usize::from([a1, a2].contains(peer)),
                "only the canonical winning pair may receive state queries"
            );
        }
        assert_eq!(
            selected,
            order
                .iter()
                .copied()
                .filter(|peer| [a1, a2].contains(peer))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            remainder,
            order
                .iter()
                .copied()
                .filter(|peer| [b1, b2].contains(peer))
                .collect::<Vec<_>>()
        );
        drop(manager);
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the mixed-fleet regression pins cohort selection, reconnect fallback, and prior-token ordering together"
)]
async fn export_only_snapshot_partitions_first_eligible_cohort_and_stable_remainder() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let unchanged = IpAddr::V4(Ipv4Addr::new(10, 36, 0, 1));
    let reconnecting = IpAddr::V4(Ipv4Addr::new(10, 36, 0, 2));
    let first = IpAddr::V4(Ipv4Addr::new(10, 36, 0, 3));
    let import_changing = IpAddr::V4(Ipv4Addr::new(10, 36, 0, 4));
    let second = IpAddr::V4(Ipv4Addr::new(10, 36, 0, 5));
    let different_chain = IpAddr::V4(Ipv4Addr::new(10, 36, 0, 6));
    let all_peers = [
        unchanged,
        reconnecting,
        first,
        import_changing,
        second,
        different_chain,
    ];
    let cohort_installs = Arc::new(AtomicUsize::new(0));
    let different_installs = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
    let rib_task = tokio::spawn(async move {
        let mut batches = Vec::new();
        let mut singles = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies {
                    replacements,
                    reply,
                } => {
                    batches.push(
                        replacements
                            .into_iter()
                            .map(|replacement| replacement.peer)
                            .collect::<Vec<_>>(),
                    );
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    singles.push(peer);
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
        (batches, singles)
    });

    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    insert_test_managed_peer(
        &mut manager,
        unchanged,
        acking_policy_handle(unchanged, SessionState::Established),
        false,
    );
    insert_test_managed_peer(
        &mut manager,
        reconnecting,
        acking_policy_handle(reconnecting, SessionState::Active),
        false,
    );
    for peer in [first, second] {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&cohort_installs), None),
            false,
        );
    }
    insert_test_managed_peer(
        &mut manager,
        import_changing,
        acking_policy_handle(import_changing, SessionState::Established),
        false,
    );
    insert_test_managed_peer(
        &mut manager,
        different_chain,
        established_export_policy_test_session(
            different_chain,
            Arc::clone(&different_installs),
            None,
        ),
        false,
    );

    let shared_next = deny_policy_chain();
    let other_next = validation_policy_chain(ImportValidationDependency::Aspa);
    let import_next = validation_policy_chain(ImportValidationDependency::Rpki);
    let targets = vec![
        ResolvedPeerPolicy {
            address: unchanged,
            interface: None,
            import_policy: None,
            export_policy: None,
        },
        ResolvedPeerPolicy {
            address: reconnecting,
            interface: None,
            import_policy: None,
            export_policy: Some(shared_next.clone()),
        },
        ResolvedPeerPolicy {
            address: first,
            interface: None,
            import_policy: None,
            export_policy: Some(shared_next.clone()),
        },
        ResolvedPeerPolicy {
            address: import_changing,
            interface: None,
            import_policy: Some(import_next.clone()),
            export_policy: None,
        },
        ResolvedPeerPolicy {
            address: second,
            interface: None,
            import_policy: None,
            export_policy: Some(shared_next.clone()),
        },
        ResolvedPeerPolicy {
            address: different_chain,
            interface: None,
            import_policy: None,
            export_policy: Some(other_next.clone()),
        },
    ];
    let priors = manager
        .apply_resolved_policy_snapshot(targets)
        .await
        .expect("mixed policy snapshot must commit");

    assert_eq!(
        priors.iter().map(|prior| prior.address).collect::<Vec<_>>(),
        vec![
            first,
            second,
            unchanged,
            reconnecting,
            import_changing,
            different_chain,
        ],
        "rollback tokens follow actual apply order: cohort, then stable remainder"
    );
    assert_eq!(cohort_installs.load(Ordering::SeqCst), 2);
    assert_eq!(different_installs.load(Ordering::SeqCst), 1);
    assert_eq!(
        manager.peers.get(&key(reconnecting)).unwrap().export_policy,
        Some(shared_next),
        "a reconnecting peer remains authoritative and keeps the desired session policy for PeerUp"
    );
    assert_eq!(
        manager
            .peers
            .get(&key(import_changing))
            .unwrap()
            .import_policy,
        Some(import_next)
    );
    assert_eq!(
        manager
            .peers
            .get(&key(different_chain))
            .unwrap()
            .export_policy,
        Some(other_next)
    );

    for peer in all_peers {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    let (batches, singles) = rib_task.await.unwrap();
    assert_eq!(batches, vec![vec![first, second]]);
    assert_eq!(singles, vec![different_chain]);
}

#[tokio::test]
async fn export_only_snapshot_duplicate_key_disables_partitioning_wholesale() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let first = IpAddr::V4(Ipv4Addr::new(10, 37, 0, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 37, 0, 2));
    let peers = [first, second];
    let attempts = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let rib_task = tokio::spawn(async move {
        let mut batches = 0usize;
        let mut singles = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    batches += 1;
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    singles.push(peer);
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
        (batches, singles)
    });
    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    for peer in peers {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&attempts), None),
            false,
        );
    }
    let next = deny_policy_chain();
    let priors = manager
        .apply_resolved_policy_snapshot(
            [first, second, first]
                .into_iter()
                .map(|address| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: None,
                    export_policy: Some(next.clone()),
                })
                .collect(),
        )
        .await
        .expect("duplicate targets retain the pre-existing authoritative behavior");
    assert_eq!(
        priors.iter().map(|prior| prior.address).collect::<Vec<_>>(),
        vec![first, second, first]
    );

    for peer in peers {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    let (batches, singles) = rib_task.await.unwrap();
    assert_eq!(batches, 0, "duplicate keys disable batching wholesale");
    assert_eq!(singles, vec![first, second]);
}

#[tokio::test]
async fn export_only_snapshot_cohort_failure_leaves_remainder_untouched() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let first = IpAddr::V4(Ipv4Addr::new(10, 38, 0, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 38, 0, 2));
    let remainder = IpAddr::V4(Ipv4Addr::new(10, 38, 0, 3));
    let cohort_attempts = Arc::new(AtomicUsize::new(0));
    let remainder_attempts = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let rib_task = tokio::spawn(async move {
        let mut singles = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    let _ = reply.send(Err("injected cohort failure".to_string()));
                }
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    singles.push(peer);
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
        singles
    });
    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    for peer in [first, second] {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&cohort_attempts), None),
            false,
        );
    }
    insert_test_managed_peer(
        &mut manager,
        remainder,
        established_export_policy_test_session(remainder, Arc::clone(&remainder_attempts), None),
        false,
    );
    let shared_next = deny_policy_chain();
    let other_next = validation_policy_chain(ImportValidationDependency::Aspa);
    let result = manager
        .apply_resolved_policy_snapshot(vec![
            ResolvedPeerPolicy {
                address: first,
                interface: None,
                import_policy: None,
                export_policy: Some(shared_next.clone()),
            },
            ResolvedPeerPolicy {
                address: second,
                interface: None,
                import_policy: None,
                export_policy: Some(shared_next),
            },
            ResolvedPeerPolicy {
                address: remainder,
                interface: None,
                import_policy: None,
                export_policy: Some(other_next),
            },
        ])
        .await;
    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.contains("injected cohort failure"))
    );
    assert_eq!(cohort_attempts.load(Ordering::SeqCst), 4);
    assert_eq!(
        remainder_attempts.load(Ordering::SeqCst),
        0,
        "cohort failure must leave the authoritative remainder untouched"
    );
    assert!(
        manager
            .peers
            .get(&key(remainder))
            .unwrap()
            .export_policy
            .is_none()
    );

    for peer in [first, second, remainder] {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    assert_eq!(rib_task.await.unwrap(), vec![second, first]);
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the cross-phase rollback regression pins failing remainder restoration before committed cohort unwind"
)]
async fn export_only_snapshot_remainder_failure_restores_remainder_then_cohort() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let first = IpAddr::V4(Ipv4Addr::new(10, 39, 0, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 39, 0, 2));
    let remainder_first = IpAddr::V4(Ipv4Addr::new(10, 39, 0, 3));
    let remainder_failing = IpAddr::V4(Ipv4Addr::new(10, 39, 0, 4));
    let cohort_attempts = Arc::new(AtomicUsize::new(0));
    let remainder_first_attempts = Arc::new(AtomicUsize::new(0));
    let remainder_failing_attempts = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
    let rib_task = tokio::spawn(async move {
        let mut singles = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    singles.push(peer);
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
        singles
    });
    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    for peer in [first, second] {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&cohort_attempts), None),
            false,
        );
    }
    insert_test_managed_peer(
        &mut manager,
        remainder_first,
        established_export_policy_test_session(
            remainder_first,
            Arc::clone(&remainder_first_attempts),
            None,
        ),
        false,
    );
    insert_test_managed_peer(
        &mut manager,
        remainder_failing,
        established_export_policy_test_session(
            remainder_failing,
            Arc::clone(&remainder_failing_attempts),
            Some(1),
        ),
        false,
    );
    let shared_next = deny_policy_chain();
    let other_next = validation_policy_chain(ImportValidationDependency::Aspa);
    let result = manager
        .apply_resolved_policy_snapshot(
            [
                (first, shared_next.clone()),
                (second, shared_next),
                (remainder_first, other_next.clone()),
                (remainder_failing, other_next),
            ]
            .into_iter()
            .map(|(address, export_policy)| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: None,
                export_policy: Some(export_policy),
            })
            .collect(),
        )
        .await;
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("failed to apply authoritative policy remainder")
                && error.contains("committed cohort restored")
        }),
        "remainder failure must compose its self-heal with cohort rollback: {result:?}"
    );
    for peer in [first, second, remainder_first, remainder_failing] {
        assert!(
            manager
                .peers
                .get(&key(peer))
                .unwrap()
                .export_policy
                .is_none(),
            "{peer} must finish on its prior export policy"
        );
    }
    assert_eq!(cohort_attempts.load(Ordering::SeqCst), 4);
    assert_eq!(remainder_first_attempts.load(Ordering::SeqCst), 2);
    assert_eq!(remainder_failing_attempts.load(Ordering::SeqCst), 2);

    for peer in [first, second, remainder_first, remainder_failing] {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    assert_eq!(
        rib_task.await.unwrap(),
        vec![
            remainder_first,
            remainder_failing,
            remainder_first,
            second,
            first,
        ],
        "authoritative self-heal completes newest-first before cohort rollback"
    );
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "the cross-partition deadline proof must hold both rollback partitions at once"
)]
async fn policy_rollback_rib_wait_has_one_cross_partition_deadline() {
    use rustbgpd_api::peer_types::{PeerManagerReadinessQuery, ResolvedPeerPolicy};

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 39, 2, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 39, 2, 2)),
        IpAddr::V4(Ipv4Addr::new(10, 39, 2, 3)),
        IpAddr::V4(Ipv4Addr::new(10, 39, 2, 4)),
    ];
    let attempts = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (_command_tx, command_rx) = mpsc::channel(16);
    let (readiness_tx, readiness_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    )
    .with_readiness_queries(readiness_rx);
    for peer in peers {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&attempts), None),
            false,
        );
    }

    let cohort_policy = deny_policy_chain();
    let remainder_policy = validation_policy_chain(ImportValidationDependency::Aspa);
    let started = tokio::time::Instant::now();
    let apply = manager.apply_resolved_policy_snapshot(
        peers
            .into_iter()
            .zip([
                cohort_policy.clone(),
                cohort_policy,
                remainder_policy.clone(),
                remainder_policy,
            ])
            .map(|(address, export_policy)| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: None,
                export_policy: Some(export_policy),
            })
            .collect(),
    );
    let drive_rib = async {
        skip_destination_prestage(&mut rib_rx).await;
        let RibUpdate::ReplacePeerExportPolicies { reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected cohort commit");
        };
        reply
            .send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed))
            .unwrap();

        for (index, expected_peer) in peers[2..].iter().copied().enumerate() {
            let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected remainder forward command");
            };
            assert_eq!(peer, expected_peer);
            if index == 0 {
                reply.send(Ok(())).unwrap();
            } else {
                reply
                    .send(Err(rustbgpd_rib::RibCommandError::internal(
                        "force cross-partition rollback",
                    )))
                    .unwrap();
            }
        }

        let mut late_replies = Vec::new();
        for expected_peer in peers[2..].iter().rev() {
            let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected remainder rollback command");
            };
            assert_eq!(peer, *expected_peer);
            late_replies.push(reply);
        }

        let (readiness_reply, readiness_response) = oneshot::channel();
        readiness_tx
            .send(PeerManagerReadinessQuery::ListPeers {
                reply: readiness_reply,
            })
            .await
            .unwrap();
        // LOAD-BEARING: awaiting the registered aggregate without the
        // read-only readiness lane makes this deadline expire.
        assert_eq!(
            tokio::time::timeout(
                rustbgpd_api::health_probe::CORE_READINESS_DEADLINE,
                readiness_response,
            )
            .await
            .expect("readiness must remain live during rollback RIB congestion")
            .unwrap()
            .len(),
            peers.len()
        );

        tokio::time::advance(RIB_REPLY_TIMEOUT + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        for expected_peer in peers[..2].iter().rev() {
            let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected cohort rollback command");
            };
            assert_eq!(peer, *expected_peer);
            late_replies.push(reply);
        }
        late_replies
    };
    let (result, late_replies) = tokio::join!(apply, drive_rib);

    // LOAD-BEARING: constructing a fresh five-second timeout for the cohort
    // unwind makes elapsed time ten seconds and this assertion goes red.
    assert!(
        tokio::time::Instant::now().duration_since(started)
            < RIB_REPLY_TIMEOUT + Duration::from_secs(1),
        "all rollback partitions must share the first rollback RIB deadline"
    );
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("force cross-partition rollback")
                && error.matches("shared 5s deadline").count() == 2
        }),
        "both timed-out partitions must report the shared deadline: {result:?}"
    );
    for reply in late_replies {
        assert!(
            reply.send(Ok(())).is_ok(),
            "the exact timed-out RIB future must remain detached for late repair"
        );
    }
    for peer in peers {
        let peer_state = manager.peers.get(&key(peer)).unwrap();
        assert!(peer_state.pending_export_apply);
    }
}

#[tokio::test(start_paused = true)]
async fn policy_rollback_rib_deadline_starts_after_session_restores() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    const PEER_COUNT: u8 = 13;
    const ROLLBACK_EXPORT_DELAY: Duration = Duration::from_millis(450);

    let peers = (1..=PEER_COUNT)
        .map(|last| IpAddr::V4(Ipv4Addr::new(10, 39, 5, last)))
        .collect::<Vec<_>>();
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx.clone(),
        None,
    );
    for (index, peer) in peers.iter().copied().enumerate() {
        insert_test_managed_peer(
            &mut manager,
            peer,
            rollback_ordering_policy_session(
                peer,
                rib_tx.clone(),
                index + 1 == peers.len(),
                Some(ROLLBACK_EXPORT_DELAY),
            ),
            false,
        );
    }

    let started = tokio::time::Instant::now();
    let apply = manager.apply_resolved_policy_snapshot(
        peers
            .iter()
            .copied()
            .map(|address| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: None,
                export_policy: Some(deny_policy_chain()),
            })
            .collect(),
    );
    let drive_rib = async {
        skip_destination_prestage(&mut rib_rx).await;
        let mut replies = Vec::new();
        for expected_peer in peers[..peers.len() - 1].iter().rev() {
            let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected rollback RIB restore");
            };
            assert_eq!(peer, *expected_peer);
            replies.push(reply);
        }
        assert!(
            tokio::time::Instant::now().duration_since(started) > RIB_REPLY_TIMEOUT,
            "successful session restores must consume more than the RIB-only deadline"
        );

        tokio::time::advance(
            RIB_REPLY_TIMEOUT
                .checked_sub(Duration::from_millis(1))
                .expect("RIB reply timeout exceeds one millisecond"),
        )
        .await;
        tokio::task::yield_now().await;
        for reply in replies {
            reply.send(Ok(())).unwrap();
        }
    };
    let (result, ()) = tokio::join!(apply, drive_rib);

    // LOAD-BEARING: moving `budget.deadline()` to the start of
    // `restore_resolved_policies` makes this red because the successful session
    // restores consume that prematurely anchored RIB-only wait budget.
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("injected final session failure")
                && error.contains("already-applied peers restored")
        }),
        "rollback RIB waiting must receive a fresh deadline after session restores: {result:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn timed_out_policy_rollback_rearms_import_and_export_retry_intent() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 39, 3, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 39, 3, 2)),
    ];
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
    let (_command_tx, command_rx) = mpsc::channel(8);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    for peer in peers {
        insert_test_managed_peer(
            &mut manager,
            peer,
            acking_policy_handle(peer, SessionState::Established),
            false,
        );
    }
    let next = deny_policy_chain();
    // Distinct export targets keep this snapshot off the LAN-462
    // import-tolerant cohort (no repeated export pair) and on the per-peer
    // authoritative transaction whose rollback this regression pins.
    let apply = manager.apply_resolved_policy_snapshot(
        peers
            .iter()
            .copied()
            .enumerate()
            .map(|(index, address)| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: Some(next.clone()),
                export_policy: Some(distinct_deny_policy_chain(index)),
            })
            .collect(),
    );
    let drive_rib = async {
        for (index, expected_peer) in peers.iter().copied().enumerate() {
            let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected forward RIB command");
            };
            assert_eq!(peer, expected_peer);
            if index == 0 {
                reply.send(Ok(())).unwrap();
            } else {
                reply
                    .send(Err(rustbgpd_rib::RibCommandError::internal(
                        "force rollback timeout",
                    )))
                    .unwrap();
            }
        }
        let mut held = Vec::new();
        for expected_peer in peers.iter().rev() {
            let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected rollback RIB command");
            };
            assert_eq!(peer, *expected_peer);
            held.push(reply);
        }
        tokio::time::advance(RIB_REPLY_TIMEOUT + Duration::from_millis(1)).await;
        held
    };
    let (result, held) = tokio::join!(apply, drive_rib);
    assert!(result.is_err());

    for peer in peers {
        let peer_state = manager.peers.get(&key(peer)).unwrap();
        // LOAD-BEARING: clearing rollback refresh state before a timed-out RIB
        // aggregate without rearming it makes pending_refresh false here.
        assert!(peer_state.pending_refresh);
        assert!(peer_state.pending_export_apply);
    }
    for reply in held {
        assert!(reply.send(Ok(())).is_ok());
    }
}

#[tokio::test]
async fn policy_rollback_skips_refresh_when_rib_restore_cannot_register() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 39, 4, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 39, 4, 2)),
    ];
    let counters = [
        Arc::new(FakePeerCounters::default()),
        Arc::new(FakePeerCounters::default()),
    ];
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
    let (_command_tx, command_rx) = mpsc::channel(8);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    for (peer, counter) in peers.iter().copied().zip(&counters) {
        insert_test_managed_peer(
            &mut manager,
            peer,
            acking_counted_policy_handle(peer, Arc::clone(counter)),
            false,
        );
    }

    let next = deny_policy_chain();
    // Distinct export targets keep this snapshot off the LAN-462
    // import-tolerant cohort (no repeated export pair) and on the per-peer
    // authoritative transaction whose rollback this regression pins.
    let apply = manager.apply_resolved_policy_snapshot(
        peers
            .iter()
            .copied()
            .enumerate()
            .map(|(index, address)| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: Some(next.clone()),
                export_policy: Some(distinct_deny_policy_chain(index)),
            })
            .collect(),
    );
    let close_rib_before_rollback = async {
        let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected first forward RIB command");
        };
        assert_eq!(peer, peers[0]);
        reply.send(Ok(())).unwrap();

        let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected second forward RIB command");
        };
        assert_eq!(peer, peers[1]);
        reply
            .send(Err(rustbgpd_rib::RibCommandError::internal(
                "force rollback after one completed peer",
            )))
            .unwrap();
        drop(rib_rx);
    };
    let (result, ()) = tokio::join!(apply, close_rib_before_rollback);

    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.contains("force rollback after one completed peer")),
        "the injected second-peer failure must drive rollback: {result:?}"
    );
    // LOAD-BEARING: removing the immediate-registration-failure refresh gate
    // sends a second Route Refresh to peer 1 even though its RIB restore was
    // never queued, making this exact count red. Peer 2 failed before its
    // forward refresh, so it must remain at zero as well.
    assert_eq!(counters[0].route_refresh.load(Ordering::SeqCst), 1);
    assert_eq!(counters[1].route_refresh.load(Ordering::SeqCst), 0);
    for peer in peers {
        let peer_state = manager.peers.get(&key(peer)).unwrap();
        assert!(peer_state.pending_refresh);
        assert!(peer_state.pending_export_apply);
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the mutation-sensitive cross-phase regression keeps the ambiguous session state and exact rollback order in one proof"
)]
async fn export_only_snapshot_reasserts_prior_import_after_remainder_ack_loss() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let first = IpAddr::V4(Ipv4Addr::new(10, 39, 1, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 39, 1, 2));
    let remainder = IpAddr::V4(Ipv4Addr::new(10, 39, 1, 3));
    let cohort_installs = Arc::new(AtomicUsize::new(0));
    let live_import = Arc::new(Mutex::new(None));
    let import_installs = Arc::new(AtomicUsize::new(0));
    let refreshes = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let rib_task = tokio::spawn(async move {
        let mut batches = Vec::new();
        let mut singles = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies {
                    replacements,
                    reply,
                } => {
                    batches.push(
                        replacements
                            .into_iter()
                            .map(|replacement| replacement.peer)
                            .collect::<Vec<_>>(),
                    );
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    singles.push(peer);
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
        (batches, singles)
    });
    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    for peer in [first, second] {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&cohort_installs), None),
            false,
        );
    }
    insert_test_managed_peer(
        &mut manager,
        remainder,
        import_ack_loss_policy_handle(
            remainder,
            Arc::clone(&live_import),
            Arc::clone(&import_installs),
            Arc::clone(&refreshes),
        ),
        false,
    );

    let shared_export = deny_policy_chain();
    let changed_import = validation_policy_chain(ImportValidationDependency::Rpki);
    let result = manager
        .apply_resolved_policy_snapshot(vec![
            ResolvedPeerPolicy {
                address: first,
                interface: None,
                import_policy: None,
                export_policy: Some(shared_export.clone()),
            },
            ResolvedPeerPolicy {
                address: second,
                interface: None,
                import_policy: None,
                export_policy: Some(shared_export),
            },
            ResolvedPeerPolicy {
                address: remainder,
                interface: None,
                import_policy: Some(changed_import),
                export_policy: None,
            },
        ])
        .await;
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("failed to apply authoritative policy remainder")
                && error.contains("committed cohort restored")
        }),
        "the ambiguous remainder failure must unwind both phases: {result:?}"
    );
    // LOAD-BEARING: treating the ambiguous forward import command as complete
    // suppresses its rollback reassertion; the live chain and install count
    // below then remain on the changed policy and make this test red.
    assert_eq!(
        *live_import.lock().unwrap(),
        None,
        "rollback must reassert the prior import chain after the forward command mutated then lost its reply"
    );
    assert_eq!(
        import_installs.load(Ordering::SeqCst),
        2,
        "the session must observe the ambiguous forward install and the explicit prior reassert"
    );
    assert_eq!(
        refreshes.load(Ordering::SeqCst),
        1,
        "the rollback refresh must run only after the prior chain is reasserted"
    );
    let remainder_state = manager.peers.get(&key(remainder)).unwrap();
    assert!(remainder_state.import_policy.is_none());
    assert!(!remainder_state.pending_refresh);
    assert_eq!(cohort_installs.load(Ordering::SeqCst), 4);

    for peer in [first, second, remainder] {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    let (batches, singles) = rib_task.await.unwrap();
    assert_eq!(batches, vec![vec![first, second]]);
    assert_eq!(singles, vec![second, first]);
}

/// Session model for the LAN-462 import-tolerant cohort tests: acks import,
/// export, refresh, and state queries while counting each, tracks the live
/// import chain, and optionally fails one export attempt.
#[derive(Default)]
struct CohortSessionCounters {
    import_installs: AtomicUsize,
    export_installs: AtomicUsize,
    refreshes: AtomicUsize,
    live_import: Mutex<Option<rustbgpd_policy::PolicyChain>>,
}

fn import_tolerant_cohort_test_session(
    addr: IpAddr,
    counters: Arc<CohortSessionCounters>,
    fail_export_on_attempt: Option<usize>,
) -> PeerHandle {
    import_tolerant_cohort_test_session_with_states(addr, counters, fail_export_on_attempt, None)
}

/// Like `import_tolerant_cohort_test_session`, but the session answers
/// Established only for the first `established_queries` state queries and
/// Connect afterwards (`None` = always Established), so tests can model a
/// session that drops out of Established mid-transaction.
fn import_tolerant_cohort_test_session_with_states(
    addr: IpAddr,
    counters: Arc<CohortSessionCounters>,
    fail_export_on_attempt: Option<usize>,
    established_queries: Option<usize>,
) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(16);
    let task = tokio::spawn(async move {
        let mut state_queries = 0usize;
        while let Some(command) = session_rx.recv().await {
            match command {
                PeerCommand::UpdateImportPolicy { policy, reply } => {
                    counters.import_installs.fetch_add(1, Ordering::SeqCst);
                    *counters.live_import.lock().unwrap() = policy;
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let attempt = counters.export_installs.fetch_add(1, Ordering::SeqCst) + 1;
                    let result = if fail_export_on_attempt == Some(attempt) {
                        Err(rustbgpd_transport::PeerCommandError::CommandFailed(
                            "injected export-policy apply failure".to_string(),
                        ))
                    } else {
                        Ok(())
                    };
                    let _ = reply.send(result);
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    counters.refreshes.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::QueryState { reply } => {
                    state_queries += 1;
                    let state = if established_queries.is_some_and(|limit| state_queries > limit) {
                        SessionState::Connect
                    } else {
                        SessionState::Established
                    };
                    let _ = reply.send(policy_test_peer_state(addr, state));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(session_tx, task)
}

/// LAN-462: a reload that moves import AND export chains must still engage the
/// batched cohort (previously the import delta disqualified every member and
/// the whole fleet fell onto the per-peer authoritative path), and each
/// import-moving member's Route Refresh must fire exactly once, only after the
/// cohort RIB commit acknowledges. Import-unchanged members get no refresh.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the regression pins partition engagement, deferred-refresh ordering, and the unchanged-member exemption together"
)]
async fn import_tolerant_cohort_defers_refresh_past_committed_batch() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let first = IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 42, 0, 2));
    let export_only = IpAddr::V4(Ipv4Addr::new(10, 42, 0, 3));
    let peers = [first, second, export_only];
    let counters: Vec<Arc<CohortSessionCounters>> = peers
        .iter()
        .map(|_| Arc::new(CohortSessionCounters::default()))
        .collect();
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    for (peer, counter) in peers.iter().zip(&counters) {
        insert_test_managed_peer(
            &mut manager,
            *peer,
            import_tolerant_cohort_test_session(*peer, Arc::clone(counter), None),
            false,
        );
    }

    let shared_export = deny_policy_chain();
    let changed_import = validation_policy_chain(ImportValidationDependency::Rpki);
    let targets = vec![
        ResolvedPeerPolicy {
            address: first,
            interface: None,
            import_policy: Some(changed_import.clone()),
            export_policy: Some(shared_export.clone()),
        },
        ResolvedPeerPolicy {
            address: second,
            interface: None,
            import_policy: Some(changed_import.clone()),
            export_policy: Some(shared_export.clone()),
        },
        ResolvedPeerPolicy {
            address: export_only,
            interface: None,
            import_policy: None,
            export_policy: Some(shared_export.clone()),
        },
    ];
    let apply = manager.apply_resolved_policy_snapshot(targets);
    let refresh_watch = counters.clone();
    let drive_rib = async {
        skip_destination_prestage(&mut rib_rx).await;
        let RibUpdate::ReplacePeerExportPolicies {
            replacements,
            reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected cohort RIB command");
        };
        assert_eq!(
            replacements.len(),
            peers.len(),
            "the partition must cover the whole fleet despite import deltas"
        );
        assert!(
            refresh_watch
                .iter()
                .all(|counter| counter.refreshes.load(Ordering::SeqCst) == 0),
            "no Route Refresh may fire before the cohort RIB commit acknowledges"
        );
        reply
            .send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed))
            .unwrap();
    };
    let (result, ()) = tokio::join!(apply, drive_rib);
    let priors = result.expect("import+export cohort snapshot must commit");

    assert_eq!(priors.len(), peers.len());
    assert!(
        matches!(rib_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "no per-peer authoritative RIB command may run after the committed batch"
    );
    for (peer, counter) in peers.iter().zip(&counters) {
        let expected_refreshes = usize::from(*peer != export_only);
        assert_eq!(
            counter.refreshes.load(Ordering::SeqCst),
            expected_refreshes,
            "deferred refresh fires exactly once per import-moving member ({peer})"
        );
        assert_eq!(
            counter.import_installs.load(Ordering::SeqCst),
            expected_refreshes,
            "import hot-apply runs only for import-moving members ({peer})"
        );
        assert_eq!(counter.export_installs.load(Ordering::SeqCst), 1);
        let peer_state = manager.peers.get(&key(*peer)).unwrap();
        assert_eq!(peer_state.export_policy, Some(shared_export.clone()));
        assert!(!peer_state.pending_refresh);
        assert!(!peer_state.pending_export_apply);
    }
    assert_eq!(
        manager.peers.get(&key(first)).unwrap().import_policy,
        Some(changed_import.clone())
    );
    assert_eq!(
        manager.peers.get(&key(second)).unwrap().import_policy,
        Some(changed_import)
    );
    assert_eq!(
        manager.peers.get(&key(export_only)).unwrap().import_policy,
        None
    );

    for peer in peers {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
}

/// LAN-462: when the RIB batch hands the cohort back for the per-peer
/// authoritative RIB seam (`RequiresAuthoritativePerPeerApply`), the deferred
/// refresh still fires exactly once per member — after the handoff completes —
/// with no double refresh from the handoff itself.
#[tokio::test]
async fn import_tolerant_cohort_handoff_fires_deferred_refresh_once() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 43, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 43, 0, 2)),
    ];
    let counters: Vec<Arc<CohortSessionCounters>> = peers
        .iter()
        .map(|_| Arc::new(CohortSessionCounters::default()))
        .collect();
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    for (peer, counter) in peers.iter().zip(&counters) {
        insert_test_managed_peer(
            &mut manager,
            *peer,
            import_tolerant_cohort_test_session(*peer, Arc::clone(counter), None),
            false,
        );
    }

    let shared_export = deny_policy_chain();
    let changed_import = validation_policy_chain(ImportValidationDependency::Rpki);
    let apply = manager.apply_resolved_policy_snapshot(
        peers
            .iter()
            .map(|&address| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: Some(changed_import.clone()),
                export_policy: Some(shared_export.clone()),
            })
            .collect(),
    );
    let refresh_watch = counters.clone();
    let drive_rib = async {
        skip_destination_prestage(&mut rib_rx).await;
        let RibUpdate::ReplacePeerExportPolicies { reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected cohort RIB command");
        };
        reply
            .send(Ok(
                rustbgpd_rib::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply,
            ))
            .unwrap();
        for expected_peer in peers {
            let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected ordinary per-peer RIB command");
            };
            assert_eq!(peer, expected_peer);
            assert!(
                refresh_watch
                    .iter()
                    .all(|counter| counter.refreshes.load(Ordering::SeqCst) == 0),
                "no Route Refresh may fire before the authoritative handoff completes"
            );
            reply.send(Ok(())).unwrap();
        }
    };
    let (result, ()) = tokio::join!(apply, drive_rib);
    result.expect("handoff cohort snapshot must commit");

    for counter in &counters {
        assert_eq!(
            counter.refreshes.load(Ordering::SeqCst),
            1,
            "the deferred refresh fires exactly once per member — no handoff double refresh"
        );
        assert_eq!(counter.import_installs.load(Ordering::SeqCst), 1);
        assert_eq!(counter.export_installs.load(Ordering::SeqCst), 1);
    }
    for peer in peers {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
}

/// LAN-462: a cohort RIB commit failure must restore BOTH chains — the import
/// delta hot-applied during setup and the export chain — and fire no forward
/// refresh (only the rollback's post-reassert refresh), leaving no pending
/// retry intent behind after a clean restore.
#[tokio::test]
async fn import_tolerant_cohort_rib_failure_restores_both_chains() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 44, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 44, 0, 2)),
    ];
    let counters: Vec<Arc<CohortSessionCounters>> = peers
        .iter()
        .map(|_| Arc::new(CohortSessionCounters::default()))
        .collect();
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let rib_task = tokio::spawn(async move {
        let mut singles = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    let _ = reply.send(Err("injected cohort failure".to_string()));
                }
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    singles.push(peer);
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
        singles
    });
    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    for (peer, counter) in peers.iter().zip(&counters) {
        insert_test_managed_peer(
            &mut manager,
            *peer,
            import_tolerant_cohort_test_session(*peer, Arc::clone(counter), None),
            false,
        );
    }

    let shared_export = deny_policy_chain();
    let changed_import = validation_policy_chain(ImportValidationDependency::Rpki);
    let result = manager
        .apply_resolved_policy_snapshot(
            peers
                .iter()
                .map(|&address| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: Some(changed_import.clone()),
                    export_policy: Some(shared_export.clone()),
                })
                .collect(),
        )
        .await;
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("failed to update export policy cohort: injected cohort failure")
                && error.contains("already-applied peers restored")
        }),
        "the RIB failure must surface with a successful rollback: {result:?}"
    );

    for (peer, counter) in peers.iter().zip(&counters) {
        assert_eq!(
            counter.import_installs.load(Ordering::SeqCst),
            2,
            "the session must observe the forward install and the rollback reassert ({peer})"
        );
        assert_eq!(
            *counter.live_import.lock().unwrap(),
            None,
            "the rollback must reassert the prior import chain ({peer})"
        );
        assert_eq!(counter.export_installs.load(Ordering::SeqCst), 2);
        assert_eq!(
            counter.refreshes.load(Ordering::SeqCst),
            1,
            "the rollback refresh runs only after the prior chain is reasserted ({peer})"
        );
        let peer_state = manager.peers.get(&key(*peer)).unwrap();
        assert_eq!(peer_state.import_policy, None);
        assert_eq!(peer_state.export_policy, None);
        assert!(!peer_state.pending_refresh);
        assert!(!peer_state.pending_export_apply);
    }

    for peer in peers {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    let singles = rib_task.await.unwrap();
    assert_eq!(
        singles,
        vec![peers[1], peers[0]],
        "rollback RIB restores run newest-first"
    );
}

/// LAN-462/LAN-464: an export hot-apply failure on a member whose import
/// delta was already acknowledged must reassert that member's prior import
/// chain directly (its bookkeeping had advanced) AND fire a Route Refresh to
/// reconcile routes the session accepted under the new chain during the
/// window, while the previously captured members restore through the
/// ordinary rollback — and the failing member still gets no RIB
/// compensation, matching the export-only discipline.
#[tokio::test]
async fn import_tolerant_cohort_export_failure_reasserts_failing_member_import() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let first = IpAddr::V4(Ipv4Addr::new(10, 45, 0, 1));
    let failing = IpAddr::V4(Ipv4Addr::new(10, 45, 0, 2));
    let first_counters = Arc::new(CohortSessionCounters::default());
    let failing_counters = Arc::new(CohortSessionCounters::default());
    let rib_single_restores = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let restores = Arc::clone(&rib_single_restores);
    let _rib_task = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicy { reply, .. } => {
                    restores.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::ReplacePeerExportPolicies { .. } => {
                    panic!("the RIB batch must not run after a session-side cohort failure");
                }
                _ => {}
            }
        }
    });
    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    insert_test_managed_peer(
        &mut manager,
        first,
        import_tolerant_cohort_test_session(first, Arc::clone(&first_counters), None),
        false,
    );
    insert_test_managed_peer(
        &mut manager,
        failing,
        import_tolerant_cohort_test_session(failing, Arc::clone(&failing_counters), Some(1)),
        false,
    );

    let shared_export = deny_policy_chain();
    let changed_import = validation_policy_chain(ImportValidationDependency::Rpki);
    let result = manager
        .apply_resolved_policy_snapshot(
            [first, failing]
                .into_iter()
                .map(|address| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: Some(changed_import.clone()),
                    export_policy: Some(shared_export.clone()),
                })
                .collect(),
        )
        .await;
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains(&format!(
                "failed to apply resolved policy to {failing}: export:"
            )) && error.contains("already-applied peers restored")
        }),
        "the export failure must surface with a successful rollback: {result:?}"
    );

    // The failing member: forward import install + direct prior reassert, a
    // post-reassert refresh for the acked-import window, no RIB compensation.
    assert_eq!(failing_counters.import_installs.load(Ordering::SeqCst), 2);
    assert_eq!(
        *failing_counters.live_import.lock().unwrap(),
        None,
        "the failing member's prior import chain must be reasserted"
    );
    assert_eq!(failing_counters.export_installs.load(Ordering::SeqCst), 2);
    assert_eq!(
        failing_counters.refreshes.load(Ordering::SeqCst),
        1,
        "the repair must fire a refresh for routes accepted under the new import chain during the window"
    );
    // The captured member restores through the ordinary rollback: reassert,
    // RIB restore, then the conservative post-reassert refresh.
    assert_eq!(first_counters.import_installs.load(Ordering::SeqCst), 2);
    assert_eq!(*first_counters.live_import.lock().unwrap(), None);
    assert_eq!(first_counters.export_installs.load(Ordering::SeqCst), 2);
    assert_eq!(first_counters.refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(
        rib_single_restores.load(Ordering::SeqCst),
        1,
        "no RIB compensation may be planned for the member whose forward apply failed"
    );
    for peer in [first, failing] {
        let peer_state = manager.peers.get(&key(peer)).unwrap();
        assert_eq!(peer_state.import_policy, None);
        assert_eq!(peer_state.export_policy, None);
        assert!(!peer_state.pending_refresh);
        assert!(!peer_state.pending_export_apply);
    }

    for peer in [first, failing] {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
}

/// LAN-464 companion: when the failing member is no longer Established at
/// repair time, the acked-import-window reconciliation cannot refresh
/// immediately — it must arm `pending_refresh` instead so the retry pipeline
/// fires it once the session is reachable again.
#[tokio::test]
async fn cohort_export_failure_repair_arms_pending_refresh_when_not_established() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let first = IpAddr::V4(Ipv4Addr::new(10, 46, 0, 1));
    let failing = IpAddr::V4(Ipv4Addr::new(10, 46, 0, 2));
    let first_counters = Arc::new(CohortSessionCounters::default());
    let failing_counters = Arc::new(CohortSessionCounters::default());
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let _rib_task = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    insert_test_managed_peer(
        &mut manager,
        first,
        import_tolerant_cohort_test_session(first, Arc::clone(&first_counters), None),
        false,
    );
    // Established for the cohort-selection state query only: by the time the
    // repair checks the session again it reports Connect.
    insert_test_managed_peer(
        &mut manager,
        failing,
        import_tolerant_cohort_test_session_with_states(
            failing,
            Arc::clone(&failing_counters),
            Some(1),
            Some(1),
        ),
        false,
    );

    let shared_export = deny_policy_chain();
    let changed_import = validation_policy_chain(ImportValidationDependency::Rpki);
    let result = manager
        .apply_resolved_policy_snapshot(
            [first, failing]
                .into_iter()
                .map(|address| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: Some(changed_import.clone()),
                    export_policy: Some(shared_export.clone()),
                })
                .collect(),
        )
        .await;
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains(&format!(
                "failed to apply resolved policy to {failing}: export:"
            ))
        }),
        "the export failure must surface: {result:?}"
    );

    // The failing member: prior import chain reasserted, no immediate
    // refresh (not Established), retry intent armed instead.
    assert_eq!(failing_counters.import_installs.load(Ordering::SeqCst), 2);
    assert_eq!(*failing_counters.live_import.lock().unwrap(), None);
    assert_eq!(failing_counters.refreshes.load(Ordering::SeqCst), 0);
    let failing_state = manager.peers.get(&key(failing)).unwrap();
    assert!(
        failing_state.pending_refresh,
        "a non-Established failing member must carry the refresh intent as pending_refresh"
    );
    // The captured member still restores through the ordinary rollback.
    assert_eq!(first_counters.refreshes.load(Ordering::SeqCst), 1);
    assert!(!manager.peers.get(&key(first)).unwrap().pending_refresh);

    for peer in [first, failing] {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
}

#[tokio::test]
async fn export_only_snapshot_handoff_applies_one_rib_peer_at_a_time() {
    use rustbgpd_api::peer_types::{PeerManagerReadinessQuery, ResolvedPeerPolicy};

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 35, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 35, 0, 2)),
    ];
    let installs = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (_command_tx, command_rx) = mpsc::channel(16);
    let (readiness_tx, readiness_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    )
    .with_readiness_queries(readiness_rx);
    for peer in peers {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&installs), None),
            false,
        );
    }
    let next = deny_policy_chain();
    let apply = manager.apply_resolved_policy_snapshot(
        peers
            .iter()
            .map(|&address| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: None,
                export_policy: Some(next.clone()),
            })
            .collect(),
    );
    let drive_rib = async {
        skip_destination_prestage(&mut rib_rx).await;
        let RibUpdate::ReplacePeerExportPolicies { reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected cohort RIB command");
        };
        reply
            .send(Ok(
                rustbgpd_rib::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply,
            ))
            .unwrap();

        for (index, expected_peer) in peers.into_iter().enumerate() {
            let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected ordinary per-peer RIB command");
            };
            assert_eq!(peer, expected_peer);
            assert!(
                matches!(rib_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
                "the next peer must not be queued before peer {index} replies"
            );
            let (readiness_reply, readiness_response) = oneshot::channel();
            readiness_tx
                .send(PeerManagerReadinessQuery::ListPeers {
                    reply: readiness_reply,
                })
                .await
                .unwrap();
            let infos = tokio::time::timeout(
                rustbgpd_api::health_probe::CORE_READINESS_DEADLINE,
                readiness_response,
            )
            .await
            .expect("readiness must remain live while an ordinary RIB reply is held")
            .unwrap();
            assert_eq!(infos.len(), peers.len());
            reply.send(Ok(())).unwrap();
        }
    };
    let (result, ()) = tokio::join!(apply, drive_rib);

    let priors = result.unwrap();
    assert_eq!(priors.len(), peers.len());
    assert_eq!(
        installs.load(Ordering::SeqCst),
        peers.len(),
        "the handoff must not hot-apply session policy a second time"
    );
    assert!(peers.iter().all(|peer| {
        manager
            .peers
            .get(&key(*peer))
            .is_some_and(|peer_state| peer_state.export_policy == Some(next.clone()))
    }));
    for peer in peers {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the handoff fixture scripts the full prestage + cohort + per-peer dialogue"
)]
async fn export_only_snapshot_handoff_skips_missing_peer_and_continues_without_rollback() {
    use rustbgpd_api::peer_types::{PeerManagerReadinessQuery, ResolvedPeerPolicy};

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 35, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 35, 1, 2)),
    ];
    let installs = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (_command_tx, command_rx) = mpsc::channel(16);
    let (readiness_tx, readiness_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    )
    .with_readiness_queries(readiness_rx);
    for peer in peers {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&installs), None),
            false,
        );
    }
    let next = deny_policy_chain();
    let apply = manager.apply_resolved_policy_snapshot(
        peers
            .iter()
            .map(|&address| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: None,
                export_policy: Some(next.clone()),
            })
            .collect(),
    );
    let drive_rib = async {
        skip_destination_prestage(&mut rib_rx).await;
        let RibUpdate::ReplacePeerExportPolicies { reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected cohort RIB command");
        };
        reply
            .send(Ok(
                rustbgpd_rib::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply,
            ))
            .unwrap();

        let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected first ordinary per-peer RIB command");
        };
        assert_eq!(peer, peers[0]);
        reply
            .send(Err(rustbgpd_rib::RibCommandError::not_found(
                "peer disappeared after cohort handoff",
            )))
            .unwrap();

        let (readiness_reply, readiness_response) = oneshot::channel();
        readiness_tx
            .send(PeerManagerReadinessQuery::ListPeers {
                reply: readiness_reply,
            })
            .await
            .unwrap();
        let infos = readiness_response.await.unwrap();
        assert_eq!(infos.len(), peers.len());

        let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected second ordinary per-peer RIB command");
        };
        assert_eq!(peer, peers[1]);
        reply.send(Ok(())).unwrap();
        tokio::task::yield_now().await;
        assert!(matches!(
            rib_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    };
    let (result, ()) = tokio::join!(apply, drive_rib);

    assert!(
        result.is_ok(),
        "NotFound handoff race must be benign: {result:?}"
    );
    assert_eq!(
        installs.load(Ordering::SeqCst),
        peers.len(),
        "handoff must neither duplicate the forward session apply nor roll it back"
    );
    assert!(peers.iter().all(|peer| {
        manager
            .peers
            .get(&key(*peer))
            .is_some_and(|managed| managed.export_policy == Some(next.clone()))
    }));
    for peer in peers {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the handoff failure regression keeps forward ordering and complete reverse rollback together"
)]
async fn export_only_snapshot_handoff_failure_restores_every_peer_newest_first() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 36, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 36, 0, 2)),
    ];
    let installs = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let rib_task = tokio::spawn(async move {
        skip_destination_prestage(&mut rib_rx).await;
        let RibUpdate::ReplacePeerExportPolicies { reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected cohort RIB command");
        };
        reply
            .send(Ok(
                rustbgpd_rib::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply,
            ))
            .unwrap();

        let mut order = Vec::new();
        for expected_peer in peers {
            let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected forward ordinary RIB command");
            };
            assert_eq!(peer, expected_peer);
            order.push(peer);
            if peer == peers[1] {
                reply
                    .send(Err(rustbgpd_rib::RibCommandError::internal(
                        "synthetic second-peer failure",
                    )))
                    .unwrap();
            } else {
                reply.send(Ok(())).unwrap();
            }
        }
        for expected_peer in peers.into_iter().rev() {
            let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected rollback ordinary RIB command");
            };
            assert_eq!(peer, expected_peer);
            order.push(peer);
            reply.send(Ok(())).unwrap();
        }
        order
    });

    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    for peer in peers {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&installs), None),
            false,
        );
    }
    let next = deny_policy_chain();
    let result = manager
        .apply_resolved_policy_snapshot(
            peers
                .iter()
                .map(|&address| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: None,
                    export_policy: Some(next.clone()),
                })
                .collect(),
        )
        .await;
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("synthetic second-peer failure")
                && error.contains("already-applied peers restored")
        }),
        "a later handoff failure must surface after a complete rollback: {result:?}"
    );
    assert_eq!(
        installs.load(Ordering::SeqCst),
        peers.len() * 2,
        "handoff must avoid a second forward session apply and restore every session once"
    );
    assert_eq!(
        rib_task.await.unwrap(),
        vec![peers[0], peers[1], peers[1], peers[0]]
    );
    for peer in peers {
        let peer_state = manager.peers.get(&key(peer)).unwrap();
        assert!(peer_state.export_policy.is_none());
        assert!(!peer_state.pending_export_apply);
        assert!(!peer_state.pending_refresh);
        manager.delete_peer(key(peer), false).await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "the timeout regression keeps the late forward reply and ordered rollback in one paused-time proof"
)]
async fn export_only_snapshot_handoff_timeout_restores_after_the_owned_forward_command() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 37, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 37, 0, 2)),
    ];
    let installs = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    for peer in peers {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&installs), None),
            false,
        );
    }
    let next = deny_policy_chain();
    let apply = manager.apply_resolved_policy_snapshot(
        peers
            .iter()
            .map(|&address| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: None,
                export_policy: Some(next.clone()),
            })
            .collect(),
    );
    let drive_rib = async {
        skip_destination_prestage(&mut rib_rx).await;
        let RibUpdate::ReplacePeerExportPolicies { reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected cohort RIB command");
        };
        reply
            .send(Ok(
                rustbgpd_rib::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply,
            ))
            .unwrap();

        let RibUpdate::ReplacePeerExportPolicy {
            peer: forward_peer,
            export_policy: forward_policy,
            reply: late_forward_reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected first ordinary forward command");
        };
        assert_eq!(forward_peer, peers[0]);
        assert_eq!(forward_policy, Some(next.clone()));
        assert!(matches!(
            rib_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        tokio::task::yield_now().await;
        tokio::time::advance(RIB_REPLY_TIMEOUT + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;

        assert!(
            late_forward_reply.send(Ok(())).is_err(),
            "the timed-out forward receiver must be gone before the RIB actor advances to rollback"
        );
        let mut rollback_order = Vec::new();
        for expected_peer in peers.into_iter().rev() {
            let RibUpdate::ReplacePeerExportPolicy {
                peer,
                export_policy,
                reply,
            } = rib_rx.recv().await.unwrap()
            else {
                panic!("expected ordinary rollback command");
            };
            assert_eq!(peer, expected_peer);
            assert!(export_policy.is_none());
            rollback_order.push(peer);
            reply.send(Ok(())).unwrap();
        }
        rollback_order
    };
    let (result, rollback_order) = tokio::join!(apply, drive_rib);

    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("did not reply within")
                && error.contains("already-applied peers restored")
        }),
        "a timed-out handoff must fail only after complete rollback: {result:?}"
    );
    assert_eq!(rollback_order, vec![peers[1], peers[0]]);
    assert_eq!(installs.load(Ordering::SeqCst), peers.len() * 2);
    for peer in peers {
        let peer_state = manager.peers.get(&key(peer)).unwrap();
        assert!(peer_state.export_policy.is_none());
        assert!(!peer_state.pending_export_apply);
        assert!(!peer_state.pending_refresh);
        manager.delete_peer(key(peer), false).await.unwrap();
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the bounded-channel proof keeps registration, refresh, and later lifecycle ordering together"
)]
async fn policy_rollback_registers_every_rib_restore_before_refresh_and_lifecycle_work() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    const PEER_COUNT: u8 = 160;
    let peers = (1..=PEER_COUNT)
        .map(|last| IpAddr::V4(Ipv4Addr::new(10, 40, 0, last)))
        .collect::<Vec<_>>();
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(1);
    let lifecycle_tx = rib_tx.clone();
    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx.clone(),
        None,
    );
    for (index, peer) in peers.iter().copied().enumerate() {
        insert_test_managed_peer(
            &mut manager,
            peer,
            rollback_ordering_policy_session(peer, rib_tx.clone(), index + 1 == peers.len(), None),
            false,
        );
    }

    let next = deny_policy_chain();
    // Distinct export targets keep this snapshot off the LAN-462
    // import-tolerant cohort (no repeated export pair) and on the per-peer
    // authoritative transaction whose rollback ordering this proof pins.
    let apply = manager.apply_resolved_policy_snapshot(
        peers
            .iter()
            .copied()
            .enumerate()
            .map(|(index, address)| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: Some(next.clone()),
                export_policy: Some(distinct_deny_policy_chain(index)),
            })
            .collect(),
    );
    let drive_rib = async {
        for expected_peer in peers.iter().take(peers.len() - 1) {
            let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected forward RIB restore");
            };
            assert_eq!(peer, *expected_peer);
            reply.send(Ok(())).unwrap();
        }

        let mut lifecycle_task = None;
        let mut restores = Vec::new();
        let mut refresh_markers = 0;
        let mut saw_delete = false;
        let mut saw_recreate = false;
        while restores.len() < peers.len()
            || refresh_markers < peers.len() - 1
            || !saw_delete
            || !saw_recreate
        {
            match rib_rx.recv().await.unwrap() {
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    if restores.is_empty() {
                        let later_tx = lifecycle_tx.clone();
                        let recreated = peers[0];
                        lifecycle_task = Some(tokio::spawn(async move {
                            later_tx
                                .send(RibUpdate::PeerDeleted { peer: recreated })
                                .await
                                .unwrap();
                            let (outbound_tx, _outbound_rx) = mpsc::channel(1);
                            later_tx
                                .send(RibUpdate::PeerUp {
                                    peer: recreated,
                                    session_id: 99,
                                    peer_asn: 65002,
                                    peer_router_id: Ipv4Addr::new(192, 0, 2, 1),
                                    outbound_tx,
                                    export_policy: None,
                                    sendable_families: vec![(Afi::Ipv4, Safi::Unicast)],
                                    is_ebgp: true,
                                    route_reflector_client: false,
                                    orr_vantage: None,
                                    per_client_best: false,
                                    interpret_rfc1997: true,
                                    add_path_send_families: Vec::new(),
                                    add_path_send_max: 0,
                                    negotiated_orf_recv: Vec::new(),
                                    negotiated_llgr_families: Vec::new(),
                                })
                                .await
                                .unwrap();
                        }));
                    }
                    assert_eq!(peer, peers[peers.len() - 1 - restores.len()]);
                    restores.push(peer);
                    reply.send(Ok(())).unwrap();
                }
                RibUpdate::QueryLocRibCount { reply } => {
                    // LOAD-BEARING: moving Route Refresh ahead of aggregate
                    // registration lets this marker overtake a restore.
                    assert_eq!(restores.len(), peers.len());
                    refresh_markers += 1;
                    reply.send(0).unwrap();
                }
                RibUpdate::PeerDeleted { peer } => {
                    // LOAD-BEARING: removing reverse-order pre-registration
                    // lets this later delete overtake an unregistered restore.
                    assert_eq!(restores.len(), peers.len());
                    assert_eq!(peer, peers[0]);
                    saw_delete = true;
                }
                RibUpdate::PeerUp {
                    peer, session_id, ..
                } => {
                    assert!(saw_delete);
                    assert_eq!(restores.len(), peers.len());
                    assert_eq!(peer, peers[0]);
                    assert_eq!(session_id, 99);
                    saw_recreate = true;
                }
                _ => panic!("unexpected RIB command in rollback ordering proof"),
            }
        }
        lifecycle_task.unwrap().await.unwrap();
    };
    let (result, ()) = tokio::join!(apply, drive_rib);

    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.contains("injected final session failure")),
        "the forced final failure must drive a complete rollback: {result:?}"
    );
}

#[tokio::test]
async fn policy_rollback_registered_rib_futures_survive_caller_cancellation() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = (1..=8)
        .map(|last| IpAddr::V4(Ipv4Addr::new(10, 41, 0, last)))
        .collect::<Vec<_>>();
    let attempts = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(1);
    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    for (index, peer) in peers.iter().copied().enumerate() {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(
                peer,
                Arc::clone(&attempts),
                (index + 1 == peers.len()).then_some(peers.len()),
            ),
            false,
        );
    }
    let task_peers = peers.clone();
    let apply_task = tokio::spawn(async move {
        manager
            .apply_resolved_policy_snapshot(
                task_peers
                    .iter()
                    .copied()
                    .map(|address| ResolvedPeerPolicy {
                        address,
                        interface: None,
                        import_policy: None,
                        export_policy: Some(deny_policy_chain()),
                    })
                    .collect(),
            )
            .await
    });

    skip_destination_prestage(&mut rib_rx).await;
    let RibUpdate::ReplacePeerExportPolicy {
        peer: first_restore,
        reply,
        ..
    } = rib_rx.recv().await.unwrap()
    else {
        panic!("expected the first registered rollback restore");
    };
    assert_eq!(first_restore, peers[peers.len() - 2]);
    apply_task.abort();
    assert!(apply_task.await.unwrap_err().is_cancelled());
    reply.send(Ok(())).unwrap();

    let mut restored = vec![first_restore];
    while restored.len() < peers.len() - 1 {
        let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected detached rollback restore");
        };
        restored.push(peer);
        reply.send(Ok(())).unwrap();
    }
    // LOAD-BEARING: awaiting rollback futures directly in the caller drops
    // this suffix on cancellation, closing the channel before all peers arrive.
    assert_eq!(
        restored,
        peers[..peers.len() - 1]
            .iter()
            .rev()
            .copied()
            .collect::<Vec<_>>()
    );
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "the readiness regression keeps direct-lane and complete core-probe assertions in one held transaction"
)]
async fn export_only_snapshot_services_readiness_without_admitting_mutations() {
    use rustbgpd_api::peer_types::{PeerManagerReadinessQuery, ResolvedPeerPolicy};

    let peers = (1..=16)
        .map(|last| IpAddr::V4(Ipv4Addr::new(10, 33, 0, last)))
        .collect::<Vec<_>>();
    let attempts = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (command_tx, command_rx) = mpsc::channel(16);
    let (readiness_tx, readiness_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    )
    .with_readiness_queries(readiness_rx);
    for peer in peers.iter().copied() {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&attempts), None),
            false,
        );
    }
    let manager_task = tokio::spawn(manager.run());

    let (apply_reply, mut apply_response) = oneshot::channel();
    command_tx
        .send(PeerManagerCommand::ApplyResolvedPolicySnapshot {
            targets: peers
                .iter()
                .copied()
                .map(|address| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: None,
                    export_policy: Some(deny_policy_chain()),
                })
                .collect(),
            reply: apply_reply,
        })
        .await
        .unwrap();
    skip_destination_prestage(&mut rib_rx).await;
    let RibUpdate::ReplacePeerExportPolicies {
        reply: rib_reply, ..
    } = rib_rx.recv().await.unwrap()
    else {
        panic!("expected cohort RIB command");
    };

    let (mutation_reply, mut mutation_response) = oneshot::channel();
    command_tx
        .send(PeerManagerCommand::SyncExplainConfig {
            enabled: false,
            cache_size: 17,
            reject_retention_enabled: true,
            reject_retention_capacity: 1024,
            reply: mutation_reply,
        })
        .await
        .unwrap();

    for _ in 0..8 {
        let (readiness_reply, readiness_response) = oneshot::channel();
        readiness_tx
            .send(PeerManagerReadinessQuery::ListPeers {
                reply: readiness_reply,
            })
            .await
            .unwrap();
        let infos = tokio::time::timeout(
            rustbgpd_api::health_probe::CORE_READINESS_DEADLINE,
            readiness_response,
        )
        .await
        .expect("live readiness must stay inside the unchanged 200ms deadline")
        .unwrap();
        assert_eq!(infos.len(), peers.len());
    }
    let (health_rib_tx, mut health_rib_rx) = mpsc::channel(1);
    let probe =
        rustbgpd_api::health_probe::CoreReadinessProbe::new(command_tx.clone(), health_rib_tx)
            .with_peer_manager_readiness(readiness_tx.clone());
    let (health, ()) = tokio::join!(probe.snapshot(), async {
        let RibUpdate::QueryLocRibCount { reply } =
            health_rib_rx.recv().await.expect("core RIB query")
        else {
            panic!("core readiness must use the read-only RIB count query");
        };
        reply.send(17).unwrap();
    });
    assert_eq!(
        health
            .expect("complete core readiness must beat its unchanged deadline")
            .total_routes,
        17
    );
    assert!(
        matches!(
            mutation_response.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ),
        "ordinary mutation lane must stay blocked behind the policy transaction"
    );
    assert!(
        matches!(
            apply_response.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ),
        "readiness must not fabricate cohort completion"
    );

    // The successfully enqueued RIB transaction owns its reply. Advancing
    // beyond the ordinary per-peer five-second deadline must not start a
    // competing rollback while the forward RIB commit can still complete.
    tokio::time::advance(RIB_REPLY_TIMEOUT + Duration::from_secs(1)).await;
    for _ in 0..3 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        peers.len(),
        "no session rollback may race an owned forward RIB transaction"
    );
    assert!(
        matches!(rib_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "the prior timeout would enqueue a per-peer rollback while the forward reply remained owned"
    );
    assert!(matches!(
        mutation_response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        apply_response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    let (late_readiness_reply, late_readiness_response) = oneshot::channel();
    readiness_tx
        .send(PeerManagerReadinessQuery::ListPeers {
            reply: late_readiness_reply,
        })
        .await
        .unwrap();
    let late_infos = tokio::time::timeout(
        rustbgpd_api::health_probe::CORE_READINESS_DEADLINE,
        late_readiness_response,
    )
    .await
    .expect("readiness must remain live beyond the former five-second cohort timeout")
    .unwrap();
    assert_eq!(late_infos.len(), peers.len());
    assert_eq!(attempts.load(Ordering::SeqCst), peers.len());

    rib_reply
        .send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed))
        .unwrap();
    apply_response.await.unwrap().unwrap();
    mutation_response.await.unwrap();
    command_tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "the readiness regression keeps cancellation and live probing in one held transaction"
)]
async fn export_only_snapshot_services_readiness_during_stalled_session_apply() {
    use rustbgpd_api::peer_types::{PeerManagerReadinessQuery, ResolvedPeerPolicy};

    let stalled = IpAddr::V4(Ipv4Addr::new(10, 34, 0, 1));
    let responsive = IpAddr::V4(Ipv4Addr::new(10, 34, 0, 2));
    let attempts = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (command_tx, command_rx) = mpsc::channel(16);
    let (readiness_tx, readiness_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    )
    .with_readiness_queries(readiness_rx);
    let (stalled_handle, entered, release, state_queries) =
        stalled_export_policy_test_session(stalled);
    insert_test_managed_peer(&mut manager, stalled, stalled_handle, false);
    insert_test_managed_peer(
        &mut manager,
        responsive,
        established_export_policy_test_session(responsive, attempts, None),
        false,
    );
    let manager_task = tokio::spawn(manager.run());

    let (apply_reply, mut apply_response) = oneshot::channel();
    command_tx
        .send(PeerManagerCommand::ApplyResolvedPolicySnapshot {
            targets: [stalled, responsive]
                .into_iter()
                .map(|address| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: None,
                    export_policy: Some(deny_policy_chain()),
                })
                .collect(),
            reply: apply_reply,
        })
        .await
        .unwrap();
    skip_destination_prestage(&mut rib_rx).await;
    entered.await.unwrap();
    state_queries.store(0, Ordering::SeqCst);
    tokio::time::advance(std::time::Duration::from_millis(250)).await;
    tokio::task::yield_now().await;
    assert!(matches!(
        apply_response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    let (cancelled_reply, cancelled_response) = oneshot::channel();
    drop(cancelled_response);
    readiness_tx
        .send(PeerManagerReadinessQuery::ListPeers {
            reply: cancelled_reply,
        })
        .await
        .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_millis(100)).await;
    tokio::task::yield_now().await;

    let (readiness_reply, readiness_response) = oneshot::channel();
    readiness_tx
        .send(PeerManagerReadinessQuery::ListPeers {
            reply: readiness_reply,
        })
        .await
        .unwrap();
    let infos = tokio::time::timeout(
        rustbgpd_api::health_probe::CORE_READINESS_DEADLINE,
        readiness_response,
    )
    .await
    .expect("readiness must beat the unchanged 200ms deadline")
    .unwrap();
    assert_eq!(infos.len(), 2);
    assert!(
        infos
            .iter()
            .find(|info| info.address == stalled)
            .is_some_and(|info| info.stale),
        "the independently stalled session must be reported as stale, not fabricated healthy"
    );
    assert!(
        infos
            .iter()
            .find(|info| info.address == responsive)
            .is_some_and(|info| !info.stale)
    );

    release.notify_one();
    let RibUpdate::ReplacePeerExportPolicies {
        reply: rib_reply, ..
    } = rib_rx.recv().await.unwrap()
    else {
        panic!("expected cohort RIB command after the stalled session resumes");
    };
    rib_reply
        .send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed))
        .unwrap();
    apply_response.await.unwrap().unwrap();
    assert_session_state_query_count(&state_queries, 1).await;
    command_tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

#[tokio::test]
async fn export_only_snapshot_restores_newest_first_after_session_failure() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let first = IpAddr::V4(Ipv4Addr::new(10, 31, 0, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 31, 0, 2));
    let first_attempts = Arc::new(AtomicUsize::new(0));
    let second_attempts = Arc::new(AtomicUsize::new(0));
    let rib_single_restores = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let restores = Arc::clone(&rib_single_restores);
    let rib_task = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicy { reply, .. } => {
                    restores.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::ReplacePeerExportPolicies { .. } => {
                    panic!("the RIB batch must not run after a session-side cohort failure");
                }
                _ => {}
            }
        }
    });

    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    insert_test_managed_peer(
        &mut manager,
        first,
        established_export_policy_test_session(first, Arc::clone(&first_attempts), None),
        false,
    );
    insert_test_managed_peer(
        &mut manager,
        second,
        established_export_policy_test_session(second, Arc::clone(&second_attempts), Some(1)),
        false,
    );
    let next = deny_policy_chain();
    let result = manager
        .apply_resolved_policy_snapshot(
            [first, second]
                .into_iter()
                .map(|address| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: None,
                    export_policy: Some(next.clone()),
                })
                .collect(),
        )
        .await;
    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.contains("already-applied peers restored")),
        "cohort failure must surface with an explicit successful rollback: {result:?}"
    );
    assert_eq!(first_attempts.load(Ordering::SeqCst), 2);
    assert_eq!(
        second_attempts.load(Ordering::SeqCst),
        2,
        "the failing session must have its prior chain reasserted too"
    );
    // LOAD-BEARING: planning RIB compensation for the session whose forward
    // command failed increases this to two and makes the assertion red.
    assert_eq!(rib_single_restores.load(Ordering::SeqCst), 1);
    for peer in [first, second] {
        let peer_state = manager.peers.get(&key(peer)).unwrap();
        assert!(peer_state.export_policy.is_none());
        assert!(!peer_state.pending_export_apply);
        assert!(!peer_state.pending_refresh);
    }

    for peer in [first, second] {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    rib_task.await.unwrap();
}

#[tokio::test]
async fn export_only_snapshot_restores_newest_first_after_rib_batch_failure() {
    use rustbgpd_api::peer_types::{PeerManagerReadinessQuery, ResolvedPeerPolicy};

    let first = IpAddr::V4(Ipv4Addr::new(10, 32, 0, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 32, 0, 2));
    let attempts = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (batch_seen_tx, batch_seen_rx) = oneshot::channel();
    let release_batch = Arc::new(tokio::sync::Notify::new());
    let task_release = Arc::clone(&release_batch);
    let rib_task = tokio::spawn(async move {
        let mut restore_order = Vec::new();
        let mut batch_seen_tx = Some(batch_seen_tx);
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    if let Some(batch_seen) = batch_seen_tx.take() {
                        let _ = batch_seen.send(());
                    }
                    task_release.notified().await;
                    drop(reply);
                }
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    restore_order.push(peer);
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
        restore_order
    });

    let (_command_tx, command_rx) = mpsc::channel(16);
    let (readiness_tx, readiness_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    )
    .with_readiness_queries(readiness_rx);
    for peer in [first, second] {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&attempts), None),
            false,
        );
    }
    let next = deny_policy_chain();
    let apply = manager.apply_resolved_policy_snapshot(
        [first, second]
            .into_iter()
            .map(|address| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: None,
                export_policy: Some(next.clone()),
            })
            .collect(),
    );
    let readiness = async {
        batch_seen_rx.await.unwrap();
        let (reply, response) = oneshot::channel();
        readiness_tx
            .send(PeerManagerReadinessQuery::ListPeers { reply })
            .await
            .unwrap();
        let infos = response.await.unwrap();
        assert_eq!(infos.len(), 2);
        release_batch.notify_one();
    };
    let (result, ()) = tokio::join!(apply, readiness);
    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.contains("RIB manager dropped cohort reply")
                && error.contains("already-applied peers restored")),
        "a dropped owned RIB reply must restore every session and RIB policy: {result:?}"
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 4);
    for peer in [first, second] {
        let peer_state = manager.peers.get(&key(peer)).unwrap();
        assert!(peer_state.export_policy.is_none());
        assert!(!peer_state.pending_export_apply);
        assert!(!peer_state.pending_refresh);
    }

    for peer in [first, second] {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    assert_eq!(rib_task.await.unwrap(), vec![second, first]);
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

#[allow(
    clippy::too_many_lines,
    reason = "the timeout regression keeps its full transaction and recovery receipt together"
)]
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
                }
                _ => {}
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(session_tx, session_task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let rib_attempts = Arc::new(AtomicU32::new(0));
    let rib_attempts_in_task = Arc::clone(&rib_attempts);
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                if rib_attempts_in_task.fetch_add(1, Ordering::SeqCst) == 0 {
                    // First attempt wedges; the content-equal retry succeeds.
                    held.push(reply);
                } else {
                    let _ = reply.send(Ok(()));
                }
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
    assert!(
        mgr.peers.get(&key(addr)).unwrap().pending_export_apply,
        "RIB reply timeout must retain export intent for a content-equal retry"
    );

    mgr.update_runtime_policies(addr, None, Some(deny_policy_chain()))
        .await
        .expect("content-equal retry must revisit the RIB after the timeout");
    assert_eq!(rib_attempts.load(Ordering::SeqCst), 2);
    assert!(!mgr.peers.get(&key(addr)).unwrap().pending_export_apply);
}

/// Load-bearing error classification proof: removing the managed-peer check
/// emits a RIB command and turns an operator typo into `FAILED_PRECONDITION`;
/// changing the forwarded address or collapsing the typed RIB error makes the
/// exact-target/unavailable assertions red.
#[tokio::test]
async fn refresh_outbound_forwards_exact_peer_and_classifies_failures() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(4);
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
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
    let peer = key(address);

    let unknown = mgr.refresh_outbound(peer.clone()).await.unwrap_err();
    assert!(matches!(
        unknown,
        rustbgpd_api::peer_types::OutboundRefreshError::PeerNotFound(ref key) if key == &peer
    ));
    assert!(
        rib_rx.try_recv().is_err(),
        "an unknown peer must be rejected before the RIB"
    );

    insert_test_managed_peer(&mut mgr, address, closed_peer_handle(), false);
    let success = mgr.refresh_outbound(peer.clone());
    let respond = async {
        let RibUpdate::RefreshPeerOutbound {
            peer: target,
            reply,
        } = rib_rx.recv().await.expect("refresh command")
        else {
            panic!("expected outbound refresh");
        };
        assert_eq!(target, address);
        let _ = reply.send(Ok(()));
    };
    let (result, ()) = tokio::join!(success, respond);
    result.unwrap();

    let unavailable = mgr.refresh_outbound(peer.clone());
    let respond = async {
        let RibUpdate::RefreshPeerOutbound { reply, .. } =
            rib_rx.recv().await.expect("refresh command")
        else {
            panic!("expected outbound refresh");
        };
        let _ = reply.send(Err(rustbgpd_rib::RibCommandError::not_found(
            "peer not registered",
        )));
    };
    let (unavailable, ()) = tokio::join!(unavailable, respond);
    let unavailable = unavailable.unwrap_err();
    assert!(matches!(
        unavailable,
        rustbgpd_api::peer_types::OutboundRefreshError::PeerUnavailable(ref key)
            if key == &peer
    ));
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

#[allow(
    clippy::too_many_lines,
    reason = "the hot-apply regression keeps all eBGP and iBGP peer assertions together"
)]
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
                            max_prefix: MaxPrefixState::default(),
                            negotiated_hold_time: Some(90),
                            four_octet_as: Some(true),
                            remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
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
#[allow(
    clippy::too_many_lines,
    reason = "the failure regression keeps the rejected import and no-refresh receipt together"
)]
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
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: Some(90),
                        four_octet_as: Some(true),
                        remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
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
#[allow(
    clippy::too_many_lines,
    reason = "the idle-peer failure regression keeps pending-refresh state and wire assertions together"
)]
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
#[allow(
    clippy::too_many_lines,
    reason = "the export failure regression keeps bookkeeping and wire assertions together"
)]
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
#[allow(
    clippy::too_many_lines,
    reason = "the retry regression keeps import, export failure, and refresh receipt together"
)]
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
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: Some(90),
                        four_octet_as: Some(true),
                        remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
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
/// Fix: every RIB failure re-arms `pending_export_apply`, while
/// import-side intent independently re-arms `pending_refresh`. A
/// content-equal retry must therefore revisit the RIB, then refresh
/// Adj-RIB-In and clear both intents after success.
#[allow(
    clippy::too_many_lines,
    reason = "the RIB failure regression keeps transaction and retry state together"
)]
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
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: Some(90),
                        four_octet_as: Some(true),
                        remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
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
    // RIB drainer that rejects the first ReplacePeerExportPolicy and
    // accepts the content-equal retry.
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let rib_attempts = Arc::new(AtomicU32::new(0));
    let rib_attempts_in_task = Arc::clone(&rib_attempts);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                if rib_attempts_in_task.fetch_add(1, Ordering::SeqCst) == 0 {
                    let _ = reply.send(Err(rustbgpd_rib::RibCommandError::internal(
                        "simulated RIB failure",
                    )));
                } else {
                    let _ = reply.send(Ok(()));
                }
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

    let chain = PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Deny,
    }]);

    // Both sides changed; both session-side applies succeed
    // (advancing bookkeeping); RIB step fails; before fix this
    // would return Err with no `pending_refresh` set, leaving
    // the next retry to silently skip Route Refresh.
    let result = mgr
        .update_runtime_policies(task_addr, Some(chain.clone()), Some(chain.clone()))
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
        managed.pending_export_apply,
        "pending_export_apply must re-arm on every RIB error so a content-equal retry reaches the RIB"
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

    mgr.update_runtime_policies(task_addr, Some(chain.clone()), Some(chain))
        .await
        .expect("content-equal retry must revisit and successfully update the RIB");
    assert_eq!(
        rib_attempts.load(Ordering::SeqCst),
        2,
        "the retained export intent must drive exactly one retry"
    );
    assert_eq!(
        route_refresh_calls.load(Ordering::SeqCst),
        1,
        "the independently retained import intent must refresh after the RIB retry succeeds"
    );
    let managed = mgr.peers.get(&key(task_addr)).expect("peer present");
    assert!(!managed.pending_export_apply);
    assert!(!managed.pending_refresh);

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
#[allow(
    clippy::too_many_lines,
    reason = "the stale-query regression keeps fencing and retry assertions together"
)]
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

#[allow(
    clippy::too_many_lines,
    reason = "the active-open regression keeps both candidate paths and fencing assertions together"
)]
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

    mgr.handle_inbound(server_stream, remote_addr, None, None)
        .await;
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
            peer_asn,
            ..
        } => {
            assert_eq!(*role, rustbgpd_transport::SessionRole::InboundCandidate);
            assert_eq!(*remote_router_id, Ipv4Addr::new(10, 0, 0, 2));
            assert_eq!(*peer_asn, 65002);
        }
        other @ (SessionNotification::BackToIdle { .. }
        | SessionNotification::StateChanged { .. }
        | SessionNotification::MaxPrefixExceeded { .. }) => {
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

/// Load-bearing cross-channel ordering proof: removing the pre-accept drain
/// allows this already-queued latch to lose to `AcceptInbound`, which queries the
/// old `OpenSent` session and spawns a live collision candidate.
#[tokio::test]
async fn queued_max_prefix_latch_fences_inbound_before_collision_handling() {
    let mut mgr = test_peer_manager();
    let peer_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        peer_addr,
        fake_peer_handle(peer_addr, SessionState::OpenSent, None, counters.clone()),
        false,
    );
    mgr.session_notify_tx
        .send(SessionNotification::MaxPrefixExceeded {
            session_id: 1,
            role: rustbgpd_transport::SessionRole::Primary,
            peer_addr,
            count: 501,
            bound: 500,
            family: None,
        })
        .unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let mut client_stream = client.await.unwrap();
    mgr.accept_inbound(server_stream, remote_addr, None, None)
        .await;

    let managed = mgr.peers.get(&key(peer_addr)).unwrap();
    assert_eq!(managed.session_id, 1);
    assert!(!managed.enabled);
    assert!(managed.pending_inbound.is_none());
    assert_eq!(
        counters.query_state.load(Ordering::SeqCst),
        0,
        "queued lossless latch must run before collision state query"
    );
    let mut byte = [0_u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), client_stream.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0,
        "disabled peer must drop the passive socket"
    );
}

/// Load-bearing query-race proof: the fake session queues `MaxPrefixExceeded`
/// before replying Idle. Removing the post-query drain/recheck replaces that
/// breached generation with the inbound socket before the manager sees it.
#[tokio::test]
async fn max_prefix_latch_arriving_during_idle_query_blocks_inbound_replace() {
    use rustbgpd_transport::PeerCommand;

    let mut mgr = test_peer_manager();
    let peer_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let notify_tx = mgr.session_notify_tx.clone();
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        while let Some(command) = session_rx.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    notify_tx
                        .send(SessionNotification::MaxPrefixExceeded {
                            session_id: 1,
                            role: rustbgpd_transport::SessionRole::Primary,
                            peer_addr,
                            count: 501,
                            bound: 500,
                            family: Some((Afi::Ipv4, Safi::Unicast)),
                        })
                        .unwrap();
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
        PeerHandle::from_parts(session_tx, task),
        false,
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let mut client_stream = client.await.unwrap();
    mgr.handle_inbound(server_stream, remote_addr, None, None)
        .await;

    let managed = mgr.peers.get(&key(peer_addr)).unwrap();
    assert_eq!(managed.session_id, 1);
    assert!(!managed.enabled);
    assert!(managed.pending_inbound.is_none());
    assert!(mgr.max_prefix_latches.contains_key(&key(peer_addr)));
    let mut byte = [0_u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), client_stream.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0,
        "latched peer must drop the racing passive socket"
    );
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

    mgr.handle_inbound(server_stream, remote_addr, None, None)
        .await;

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

    mgr.handle_inbound(server_stream, remote_addr, None, None)
        .await;

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
        peer_asn: 65002,
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
async fn collision_equal_router_ids_larger_remote_as_promotes_dynamic_inbound() {
    // Mutation-red: deleting the AS tie-break, reversing it, or consulting the
    // configured wildcard ASN 0 leaves the primary session in place.
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
        0,
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
        peer_asn: 4_200_000_001,
    })
    .await;

    wait_counter(&primary.collision_dump, 1).await;
    assert_eq!(primary.collision_dump.load(Ordering::SeqCst), 1);
    assert_eq!(pending.collision_dump.load(Ordering::SeqCst), 0);
    assert!(
        mgr.peers
            .get(&key(peer_addr))
            .is_some_and(|m| m.pending_inbound.is_none() && m.session_id == 2),
        "the larger remote four-octet AS must preserve its inbound connection; \
         using ManagedPeer.remote_asn would read the dynamic wildcard 0 and fail"
    );
}

#[tokio::test]
async fn collision_equal_router_ids_larger_local_four_octet_as_drops_inbound() {
    // Mutation-red: reversing the AS comparison promotes the pending inbound
    // connection even though the larger local AS initiated the primary.
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        4_200_000_001,
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
        0,
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
        peer_asn: 65002,
    })
    .await;

    wait_counter(&pending.collision_dump, 1).await;
    assert_eq!(primary.collision_dump.load(Ordering::SeqCst), 0);
    assert_eq!(pending.collision_dump.load(Ordering::SeqCst), 1);
    assert!(
        mgr.peers
            .get(&key(peer_addr))
            .is_some_and(|m| m.pending_inbound.is_none() && m.session_id == 1),
        "the larger local four-octet AS must preserve its outbound connection"
    );
}

#[tokio::test]
async fn collision_equal_router_id_and_as_drops_inbound_defensively() {
    // Mutation-red: treating an impossible equal identity as remote-wins
    // replaces the primary session instead of failing closed.
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
        0,
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
        peer_asn: 65001,
    })
    .await;

    wait_counter(&pending.collision_dump, 1).await;
    assert_eq!(primary.collision_dump.load(Ordering::SeqCst), 0);
    assert_eq!(pending.collision_dump.load(Ordering::SeqCst), 1);
    assert!(
        mgr.peers
            .get(&key(peer_addr))
            .is_some_and(|m| m.pending_inbound.is_none() && m.session_id == 1),
        "equal AS and router ID is invalid iBGP identity and must not promote inbound"
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
    assert_eq!(
        pending.activate_max_prefix_metrics.load(Ordering::SeqCst),
        1,
        "BackToIdle promotion must transfer capacity-metric ownership"
    );
    assert!(
        mgr.peers
            .get(&key(peer_addr))
            .is_some_and(|m| m.pending_inbound.is_none() && m.session_id == 2),
        "pending inbound candidate should be promoted when the primary idles"
    );
}

fn max_prefix_capacity_gauge(
    metrics: &BgpMetrics,
    family: &str,
    peer: &str,
    scope: &str,
) -> Option<f64> {
    metrics
        .registry()
        .gather()
        .into_iter()
        .find(|metric_family| metric_family.name() == family)
        .and_then(|metric_family| {
            metric_family.get_metric().iter().find_map(|metric| {
                let has_peer = metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "peer" && label.value() == peer);
                let has_scope = metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "scope" && label.value() == scope);
                (has_peer && has_scope).then(|| metric.get_gauge().value())
            })
        })
}

/// Load-bearing production ordering proof: deleting `PeerManager`'s activation
/// leaves the gauge absent after primary termination; moving activation before
/// `quiesce_retiring_session` makes the primary's final reap erase the exact
/// candidate value and sets `activated_before_termination`.
#[tokio::test]
async fn production_collision_promotion_transfers_capacity_after_primary_termination() {
    use rustbgpd_transport::PeerCommand;

    let mut mgr = test_peer_manager();
    let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let peer_label = sock(peer_addr).to_string();
    let terminated = Arc::new(AtomicBool::new(false));
    let activated_before_termination = Arc::new(AtomicBool::new(false));
    let activation_count = Arc::new(AtomicU32::new(0));

    mgr.metrics
        .set_max_prefix_capacity(&peer_label, "aggregate", 2, Some(10));
    let (primary_tx, mut primary_rx) = mpsc::channel::<PeerCommand>(8);
    let primary_metrics = mgr.metrics.clone();
    let primary_peer_label = peer_label.clone();
    let primary_terminated = terminated.clone();
    let primary_task = tokio::spawn(async move {
        while let Some(command) = primary_rx.recv().await {
            if matches!(command, PeerCommand::Shutdown) {
                primary_metrics.reap_max_prefix_capacity(&primary_peer_label);
                primary_terminated.store(true, Ordering::SeqCst);
                break;
            }
        }
        Ok(())
    });
    insert_test_managed_peer(
        &mut mgr,
        peer_addr,
        PeerHandle::from_parts(primary_tx, primary_task),
        false,
    );

    let (candidate_tx, mut candidate_rx) = mpsc::channel::<PeerCommand>(8);
    let candidate_metrics = mgr.metrics.clone();
    let candidate_peer_label = peer_label.clone();
    let candidate_terminated = terminated.clone();
    let candidate_early = activated_before_termination.clone();
    let candidate_activations = activation_count.clone();
    let candidate_task = tokio::spawn(async move {
        while let Some(command) = candidate_rx.recv().await {
            match command {
                PeerCommand::ActivateMaxPrefixMetrics { reply } => {
                    if !candidate_terminated.load(Ordering::SeqCst) {
                        candidate_early.store(true, Ordering::SeqCst);
                    }
                    candidate_metrics.set_max_prefix_capacity(
                        &candidate_peer_label,
                        "aggregate",
                        1,
                        Some(10),
                    );
                    candidate_activations.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(());
                }
                PeerCommand::Shutdown => {
                    candidate_metrics.reap_max_prefix_capacity(&candidate_peer_label);
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    });
    attach_test_pending_inbound(
        &mut mgr,
        peer_addr,
        PeerHandle::from_parts(candidate_tx, candidate_task),
        2,
    );

    assert_eq!(
        max_prefix_capacity_gauge(
            &mgr.metrics,
            "bgp_max_prefix_usage",
            &peer_label,
            "aggregate"
        ),
        Some(2.0),
        "inactive candidate must not overwrite the primary"
    );

    mgr.resolve_collision(key(peer_addr), Ipv4Addr::new(10, 0, 0, 2), 65002)
        .await;

    assert!(terminated.load(Ordering::SeqCst));
    assert!(!activated_before_termination.load(Ordering::SeqCst));
    assert_eq!(activation_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        max_prefix_capacity_gauge(
            &mgr.metrics,
            "bgp_max_prefix_usage",
            &peer_label,
            "aggregate"
        ),
        Some(1.0)
    );
    assert!(
        mgr.peers
            .get(&key(peer_addr))
            .is_some_and(|managed| managed.session_id == 2 && managed.pending_inbound.is_none())
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
        peer_asn: 65002,
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

/// Load-bearing capacity telemetry proof: removing the constructor seed, the
/// successful-accept refresh, or the ordinary `BackToIdle` removal refresh
/// breaks the exact 0 → 1 → 0 process-global gauge sequence.
#[tokio::test]
async fn peer_presence_dynamic_inbound_added_then_back_to_idle_removed_fifo() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let metrics_view = metrics.clone();
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
    assert_dynamic_neighbor_capacity(&metrics_view, 0.0, 100.0, 100.0, 0.0);

    mgr.tcp_ao_rotation = TcpAoRotationStatus {
        desired: rustbgpd_transport::TcpAoRotationGeneration::STARTUP
            .next()
            .unwrap(),
        applied: rustbgpd_transport::TcpAoRotationGeneration::STARTUP,
        phase: rustbgpd_transport::TcpAoRotationPhase::Selecting,
        last_error: None,
    };

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();
    let peer_addr = remote_addr.ip();

    mgr.handle_inbound(server_stream, sock(peer_addr), None, None)
        .await;

    assert_eq!(
        mgr.dynamic_peer_count, 1,
        "dynamic peer count should increment"
    );
    assert_dynamic_neighbor_capacity(&metrics_view, 1.0, 100.0, 99.0, 0.0);
    let info = mgr.get_peer_info(&key(peer_addr)).await.unwrap();
    assert!(info.is_dynamic, "peer should be marked dynamic");
    assert_eq!(info.peer_group.as_deref(), Some("ix-members"));
    assert_eq!(info.description, "ix-auto");
    assert_eq!(
        mgr.peers[&key(peer_addr)].tcp_ao_rotation,
        TcpAoRotationStatus::default(),
        "plaintext dynamic accepts must not inherit an unrelated TCP-AO rollout"
    );

    let peers = mgr.list_peers().await;
    assert_eq!(peers.len(), 1);
    assert!(peers[0].is_dynamic);

    mgr.publish_state_lifecycle_event(
        &key(peer_addr),
        rustbgpd_transport::SessionRole::Primary,
        SessionState::Idle,
        SessionState::Connect,
    );

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
    assert_dynamic_neighbor_capacity(&metrics_view, 0.0, 100.0, 100.0, 0.0);
    let presence = query_session_event_history(&mgr, Some(peer_addr), BTreeSet::new(), 0).await;
    assert_eq!(
        presence
            .iter()
            .map(|event| event.event_type)
            .collect::<Vec<_>>(),
        vec![
            SessionLifecycleEventType::PeerAdded,
            SessionLifecycleEventType::StateChanged,
            SessionLifecycleEventType::PeerRemoved,
        ]
    );

    drop(client_stream);
}

/// Load-bearing saturated-drop proof: removing the rejection increment leaves
/// the counter at zero; mutating capacity or installing the rejected peer
/// breaks the unchanged gauge and peer-table assertions.
#[tokio::test]
async fn saturated_dynamic_neighbor_accept_counts_rejection_without_consuming_capacity() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let metrics_view = metrics.clone();
    let mut config = make_dynamic_manager_config();
    config.global.dynamic_neighbor_limit = Some(1);
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
    let (first_stream, first_addr) = listener.accept().await.unwrap();
    let first_client = client.await.unwrap();
    mgr.handle_inbound(first_stream, first_addr, None, None)
        .await;
    assert_dynamic_neighbor_capacity(&metrics_view, 1.0, 1.0, 0.0, 0.0);

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (rejected_stream, _) = listener.accept().await.unwrap();
    let rejected_client = client.await.unwrap();
    let rejected_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    mgr.handle_inbound(rejected_stream, sock(rejected_addr), None, None)
        .await;

    assert_dynamic_neighbor_capacity(&metrics_view, 1.0, 1.0, 0.0, 1.0);
    assert_eq!(
        inbound_drop_metric(&metrics_view, "dynamic_limit"),
        Some(1.0),
        "slot saturation must also count under the bounded drop-reason vocabulary"
    );
    assert_eq!(mgr.dynamic_peer_count, 1);
    assert_eq!(mgr.peers.len(), 1);
    assert!(!mgr.peers.contains_key(&key(rejected_addr)));
    drop(first_client);
    drop(rejected_client);
}

async fn localhost_inbound_stream() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, _) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();
    (server_stream, client_stream)
}

/// Load-bearing unconfigured-source accounting proof (ADR-0120): the
/// pre-existing unmatched-source drop must count under the bounded
/// drop-reason vocabulary even with the limiter disabled (the default).
#[tokio::test]
async fn unmatched_inbound_source_counts_unconfigured_drop() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let metrics_view = metrics.clone();
    let mut config = make_dynamic_manager_config();
    config.dynamic_neighbors.clear();
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

    let (server_stream, client_stream) = localhost_inbound_stream().await;
    mgr.handle_inbound(
        server_stream,
        sock(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
        None,
        None,
    )
    .await;

    assert!(mgr.peers.is_empty());
    assert_eq!(
        inbound_drop_metric(&metrics_view, "unconfigured"),
        Some(1.0)
    );
    drop(client_stream);
}

/// ADR-0120 default-off invariant: without `[inbound_admission]`, rapid
/// re-accept churn from one dynamic source behaves exactly as before —
/// every cycle is admitted and nothing is rate-limited.
#[tokio::test]
async fn inbound_admission_disabled_by_default_admits_rapid_dynamic_reaccepts() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let metrics_view = metrics.clone();
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

    let churny = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9));
    let mut client_streams = Vec::new();
    for cycle in 0..3 {
        let (server_stream, client_stream) = localhost_inbound_stream().await;
        client_streams.push(client_stream);
        mgr.handle_inbound(server_stream, sock(churny), None, None)
            .await;
        assert!(
            mgr.peers.contains_key(&key(churny)),
            "cycle {cycle}: default config must admit every re-accept"
        );
        let session_id = mgr.peers.get(&key(churny)).unwrap().session_id;
        mgr.handle_session_notification(SessionNotification::BackToIdle {
            session_id,
            role: rustbgpd_transport::SessionRole::Primary,
            peer_addr: churny,
        })
        .await;
        assert!(
            mgr.peers.is_empty(),
            "cycle {cycle}: peer should be removed"
        );
    }
    assert_eq!(inbound_drop_metric(&metrics_view, "rate_limited"), None);
    drop(client_streams);
}

/// Load-bearing ADR-0120 enforcement proof: with `[inbound_admission]`
/// enabled at burst 1, a dynamic source's re-accept inside the same v4
/// aggregate is dropped before session spawn and counted, while a static
/// neighbor inside the very same aggregate is exempt by admission path.
#[tokio::test]
async fn enabled_inbound_admission_rate_limits_dynamic_source_but_exempts_static_neighbor() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let metrics_view = metrics.clone();
    let mut config = make_dynamic_manager_config();
    config.inbound_admission = crate::config::InboundAdmissionConfig {
        enabled: true,
        rate_per_minute: 1,
        burst: 1,
        v4_aggregation_len: 24,
        v6_aggregation_len: 64,
        table_capacity: 64,
    };
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

    // First accept consumes the aggregate's whole burst.
    let first_source = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9));
    let (server_stream, first_client) = localhost_inbound_stream().await;
    mgr.handle_inbound(server_stream, sock(first_source), None, None)
        .await;
    assert!(
        mgr.peers.contains_key(&key(first_source)),
        "the first accept within burst must be admitted"
    );
    let session_id = mgr.peers.get(&key(first_source)).unwrap().session_id;
    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr: first_source,
    })
    .await;
    assert!(mgr.peers.is_empty());

    // A different host inside the same /24 aggregate shares the empty
    // bucket: dropped before session spawn, counted, logged.
    let second_source = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10));
    let (server_stream, second_client) = localhost_inbound_stream().await;
    mgr.handle_inbound(server_stream, sock(second_source), None, None)
        .await;
    assert!(
        mgr.peers.is_empty(),
        "an over-rate source aggregate must not spawn a session"
    );
    assert_eq!(
        inbound_drop_metric(&metrics_view, "rate_limited"),
        Some(1.0)
    );
    assert_dynamic_neighbor_capacity(&metrics_view, 0.0, 100.0, 100.0, 0.0);

    // A statically configured neighbor inside the very same exhausted
    // aggregate is exempt: its inbound takes the static path and never
    // consults the limiter.
    let static_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 20));
    insert_test_managed_peer_with_asn(
        &mut mgr,
        static_addr,
        65002,
        acking_policy_handle(static_addr, SessionState::Established),
        false,
    );
    let (server_stream, static_client) = localhost_inbound_stream().await;
    mgr.handle_inbound(server_stream, sock(static_addr), None, None)
        .await;
    assert!(
        mgr.peers.contains_key(&key(static_addr)),
        "static neighbor must survive its inbound untouched"
    );
    assert_eq!(
        inbound_drop_metric(&metrics_view, "rate_limited"),
        Some(1.0),
        "the static path must not consult the ADR-0120 limiter"
    );

    drop(first_client);
    drop(second_client);
    drop(static_client);
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
            prefix: "127.0.0.9/16".to_string(),
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

    mgr.handle_inbound(server_stream, sock(peer_addr), None, None)
        .await;

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

    mgr.delete_dynamic_range("127.0.0.9/24").unwrap();
    let current_match = mgr
        .match_dynamic_range(peer_addr)
        .expect("covering /16 remains in the live matcher");
    assert_eq!(current_match.prefix_len, 16);
    assert_eq!(current_match.peer_group, "ix-members");

    let managed = mgr.peers.get(&key(peer_addr)).unwrap();
    let snapshot = super::snapshot::build_peer_info(&key(peer_addr), managed, None, false);
    assert_eq!(
        snapshot.accepted_dynamic_range,
        Some(DynamicRangeTarget {
            addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
            prefix_len: 24,
            peer_group: "narrow-members".to_string(),
        }),
        "snapshot provenance stays pinned to the accepted /24 after the live matcher falls back to /16"
    );

    drop(client_stream);
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "fresh-start regression keeps dynamic config, accepted metadata, manager retention, and session preflight together"
)]
async fn fresh_dynamic_tcp_ao_inbound_seeds_selected_owner_keyring_for_manager_and_session() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mut config = make_dynamic_manager_config();
    let current = test_tcp_ao();
    let successor = crate::config::TcpAoConfig {
        key: "fresh-start-successor".to_string(),
        send_id: 2,
        recv_id: 2,
        algorithm: "hmac(sha256)".to_string(),
        preferred: false,
        deprecated: false,
    };
    config.dynamic_neighbors[0].tcp_ao = Some(crate::config::TcpAoKeyringConfig(vec![
        current.clone(),
        successor,
    ]));
    let mut manager = PeerManager::new_with_config(
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
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let connect = TcpStream::connect(listener.local_addr().unwrap());
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(connect, accept);
    let client = client.unwrap();
    let (server, remote_addr) = accepted.unwrap();
    let peer_addr = remote_addr.ip();
    let owner_peer: IpAddr = "127.0.0.0".parse().unwrap();
    let key_state = |send_id, is_selected| rustbgpd_transport::TcpAoKeyState {
        peer: owner_peer,
        prefix_len: 8,
        send_id,
        recv_id: send_id,
        algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
        is_current: is_selected,
        is_rnext: is_selected,
        preferred: false,
        deprecated: false,
        vrf_ifindex: None,
        pkt_good: u64::from(is_selected),
        pkt_bad: 0,
    };
    manager
        .handle_inbound(
            server,
            sock(peer_addr),
            Some(rustbgpd_transport::TcpAoInfoSnapshot {
                has_current_key: true,
                has_rnext_key: true,
                ao_required: false,
                accept_icmps: false,
                current_key: 1,
                rnext_key: 1,
                pkt_good: 1,
                pkt_bad: 0,
                pkt_key_not_found: 0,
                pkt_ao_required: 0,
                pkt_dropped_icmp: 0,
                keys: vec![key_state(1, true), key_state(2, false)],
            }),
            Some(rustbgpd_transport::TcpAoRotationGeneration::STARTUP),
        )
        .await;

    let peer_key = key(peer_addr);
    let dynamic_peer = manager
        .peers
        .get(&peer_key)
        .expect("fresh protected dynamic peer must be created");
    let current_keyring = dynamic_peer
        .transport_config
        .tcp_ao
        .clone()
        .expect("ManagedPeer must retain the explicit direct-range keyring");
    assert_eq!(current_keyring.0.len(), 2);
    let commands = dynamic_peer.handle.commands_sender();
    let mut desired_keyring = current_keyring.clone();
    desired_keyring.0[0].deprecated = true;
    desired_keyring.0[1].preferred = true;
    let selected_owner = rustbgpd_transport::listener::TcpAoSelectedOwner {
        owner: rustbgpd_transport::TcpAoListenerOwnerKind::Dynamic,
        peer: owner_peer,
        prefix_len: 8,
    };
    let desired = rustbgpd_transport::TcpAoSessionSelection {
        generation: rustbgpd_transport::TcpAoRotationGeneration::new(2).unwrap(),
        active_keyring: Some(desired_keyring.clone()),
        accepted_owners: vec![rustbgpd_transport::TcpAoRotationOwner {
            owner: rustbgpd_transport::TcpAoListenerOwnerKind::Dynamic,
            peer: owner_peer,
            prefix_len: 8,
            keyring: desired_keyring,
        }]
        .into(),
        accepted_selected_owner: Some(selected_owner),
    };
    let (reply, response) = oneshot::channel();
    commands
        .send(rustbgpd_transport::PeerCommand::PreflightTcpAoSelection { desired, reply })
        .await
        .unwrap();
    let error = tokio::time::timeout(Duration::from_secs(1), response)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err()
        .to_string();
    // The test stream is deliberately plaintext, so low-level kernel
    // preflight fails. Reaching that boundary proves PeerSession received the
    // same selected-owner keyring; without seeding it fails earlier with
    // "lacks its current selected-owner keyring".
    assert!(
        error.contains("failed to preflight exact TCP-AO selection inventory"),
        "PeerSession did not retain the fresh-start direct-range keyring: {error}"
    );
    assert!(!error.contains("lacks its current selected-owner keyring"));

    manager.peers[&peer_key].handle.abort_for_transport_safety();
    drop(client);
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "queued-accept regression keeps stale config, staged listener metadata, and manager rotation truth together"
)]
async fn queued_dynamic_selection_accept_reconciles_metadata_and_rotation_status() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mut config = make_dynamic_manager_config();
    config.dynamic_neighbors[0].tcp_ao = Some(crate::config::TcpAoKeyringConfig(vec![
        test_tcp_ao(),
        crate::config::TcpAoConfig {
            key: "queued-selection-successor".to_string(),
            send_id: 2,
            recv_id: 2,
            algorithm: "hmac(sha256)".to_string(),
            preferred: false,
            deprecated: false,
        },
    ]));
    let mut manager = PeerManager::new_with_config(
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
    );

    // Model an accept queued by the listener after its desired-generation
    // selection snapshot was staged but before PeerManager installed the new
    // config snapshot. The direct-owner secrets and key identities still come
    // exclusively from the old current config; only redacted selection
    // metadata is reconciled from the already-validated accepted socket.
    let desired_generation = rustbgpd_transport::TcpAoRotationGeneration::STARTUP
        .next()
        .unwrap();
    let selection_status = TcpAoRotationStatus {
        desired: desired_generation,
        applied: rustbgpd_transport::TcpAoRotationGeneration::STARTUP,
        phase: rustbgpd_transport::TcpAoRotationPhase::Selecting,
        last_error: None,
    };
    manager.tcp_ao_rotation = selection_status.clone();
    let mut expected_keyring = manager.dynamic_ranges[0].tcp_ao.clone().unwrap();
    expected_keyring.0[1].preferred = true;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let connect = TcpStream::connect(listener.local_addr().unwrap());
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(connect, accept);
    let client = client.unwrap();
    let (server, remote_addr) = accepted.unwrap();
    let peer_addr = remote_addr.ip();
    let owner_peer: IpAddr = "127.0.0.0".parse().unwrap();
    let key_state =
        |peer, prefix_len, send_id, preferred, is_selected| rustbgpd_transport::TcpAoKeyState {
            peer,
            prefix_len,
            send_id,
            recv_id: send_id,
            algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
            is_current: is_selected,
            is_rnext: is_selected,
            preferred,
            deprecated: false,
            vrf_ifindex: None,
            pkt_good: u64::from(is_selected),
            pkt_bad: 0,
        };
    manager
        .handle_inbound(
            server,
            sock(peer_addr),
            Some(rustbgpd_transport::TcpAoInfoSnapshot {
                has_current_key: true,
                has_rnext_key: true,
                ao_required: false,
                accept_icmps: false,
                current_key: 2,
                rnext_key: 2,
                pkt_good: 1,
                pkt_bad: 0,
                pkt_key_not_found: 0,
                pkt_ao_required: 0,
                pkt_dropped_icmp: 0,
                keys: vec![
                    // A covering owner with the same key identity must not
                    // influence the explicit /8 owner's local metadata.
                    key_state("0.0.0.0".parse().unwrap(), 0, 2, false, false),
                    key_state(owner_peer, 8, 1, false, false),
                    key_state(owner_peer, 8, 2, true, true),
                ],
            }),
            Some(desired_generation),
        )
        .await;

    let peer_key = key(peer_addr);
    let accepted_peer = manager
        .peers
        .get(&peer_key)
        .expect("queued desired-generation dynamic peer must be created");
    assert_eq!(
        accepted_peer.transport_config.tcp_ao.as_ref(),
        Some(&expected_keyring),
        "accepted selection metadata must update the configured direct-owner keyring without replacing its secrets"
    );
    assert_eq!(
        accepted_peer.tcp_ao_rotation, selection_status,
        "a desired-generation accept must retain the in-progress global rotation truth"
    );

    accepted_peer.handle.abort_for_transport_safety();
    drop(client);
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
    mgr.handle_inbound(server_stream, sock(link_local), None, None)
        .await;

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

    mgr.handle_inbound(server_stream, sock(peer_addr), None, None)
        .await;
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

    mgr.handle_inbound(server2, sock(peer_addr2), None, None)
        .await;

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

    mgr.handle_inbound(server_stream, sock(peer_addr), None, None)
        .await;
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

    mgr.handle_inbound(server2, sock(peer_addr2), None, None)
        .await;

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
    cfg.tcp_ao = Some(
        rustbgpd_transport::TcpAoConfig {
            key: "secret".into(),
            send_id: 1,
            recv_id: 2,
            algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        }
        .into(),
    );

    let transport = mgr.build_transport_config(&cfg);

    let tcp_ao = transport.tcp_ao.as_ref().expect("tcp_ao carried");
    let tcp_ao = &tcp_ao.0[0];
    assert_eq!(tcp_ao.key.as_ref(), "secret");
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
        peer_identity_gauge(&mgr.metrics, "bgp_peer_admin_enabled", "10.0.0.2", ""),
        Some(1.0)
    );
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

    mgr.handle_inbound(server_stream, sock(peer), None, None)
        .await;

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

    mgr.handle_inbound(server_stream, sock(peer), None, None)
        .await;

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

/// Load-bearing BFD retirement proof: the pending actor emits max-prefix only
/// while consuming BFD Down's Shutdown. Removing the retirement barrier loses
/// the latch; restarting an administratively disabled peer on BFD Up bypasses
/// the explicit-Enable contract.
#[tokio::test]
async fn bfd_pending_terminal_breach_blocks_later_automatic_restart() {
    let peer: IpAddr = "10.0.0.43".parse().unwrap();
    let primary = Arc::new(BfdCouplingCounters::default());
    let (mut mgr, _rx) = coupled_mgr(peer, false, fake_bfd_peer_handle(primary.clone()));
    let pending = Arc::new(FakePeerCounters::default());
    let notify_tx = mgr.session_notify_tx.clone();
    attach_test_pending_inbound(
        &mut mgr,
        peer,
        max_prefix_on_command_peer_handle(
            peer,
            2,
            rustbgpd_transport::SessionRole::InboundCandidate,
            MaxPrefixTrigger::Shutdown,
            notify_tx,
            pending.clone(),
        ),
        2,
    );

    mgr.handle_bfd_state_change(down(peer)).await;

    assert_eq!(pending.shutdown.load(Ordering::SeqCst), 1);
    let managed = mgr.peers.get(&key(peer)).unwrap();
    assert!(!managed.enabled);
    assert!(managed.pending_inbound.is_none());
    assert!(mgr.max_prefix_latches.contains_key(&key(peer)));
    assert!(mgr.retiring_sessions.is_empty());
    assert!(mgr.peer_key_for_session(2).is_none());
    let starts_before_up = primary.start.load(Ordering::SeqCst);

    mgr.handle_bfd_state_change(up(peer)).await;
    for _ in 0..3 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        primary.start.load(Ordering::SeqCst),
        starts_before_up,
        "BFD Up must not restart an administratively disabled max-prefix peer"
    );
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

/// ADR-0112: a child accepted by an accept-any (`remote_asn = 0`) dynamic
/// range keeps its reserved deny when live chains are re-resolved — even in
/// the worst case, where OPEN replaced the sentinel with the local ASN.
///
/// `sync_rpol_policies` changes no policy content here, so the reserved deny
/// is the only chain that can arrive. Resolving this peer from
/// `managed.remote_asn` instead of its pinned classification reads it as iBGP,
/// leaves both directions permit-all, and makes this red.
#[tokio::test]
async fn rfc8212_pinned_dynamic_child_keeps_deny_across_chain_reresolution() {
    use rustbgpd_policy::rpol::RpolPolicySet;

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
    let mut config = make_dynamic_manager_config();
    config.global.ebgp_requires_policy = true;
    mgr.current_config = config;

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let counters = Arc::new(FakePeerCounters::default());
    let handle = acking_counted_policy_handle(addr, counters.clone());
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let managed = mgr.peers.get_mut(&key(addr)).unwrap();
    managed.is_dynamic = true;
    managed.peer_group = Some("ix-members".to_string());
    // What the accept path produced: `remote_asn = 0` classified external.
    managed.rfc8212_external = true;
    // What OPEN then did to `remote_asn` — worst case, the local ASN.
    managed.remote_asn = 65001;
    managed.import_policy = None;
    managed.export_policy = None;

    mgr.sync_rpol_policies(
        Vec::new(),
        RpolPolicySet::default(),
        rustbgpd_policy::datasets::DatasetBindings::default(),
    )
    .await
    .expect("registry sync succeeds");

    let managed = mgr.peers.get(&key(addr)).expect("peer still present");
    for (direction, chain) in [
        (
            crate::config::RFC8212_MISSING_IMPORT_POLICY,
            managed.import_policy.as_ref(),
        ),
        (
            crate::config::RFC8212_MISSING_EXPORT_POLICY,
            managed.export_policy.as_ref(),
        ),
    ] {
        let chain = chain.unwrap_or_else(|| panic!("{direction} must be installed"));
        assert_eq!(
            chain
                .policies
                .iter()
                .map(|member| member.name.as_deref())
                .collect::<Vec<_>>(),
            vec![Some(direction)]
        );
    }

    drop(mgr);
    rib_drainer.await.unwrap();
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
    config.global.ebgp_requires_policy = true;
    // The running config says every neighbor inherits an explicit operator
    // chain. Nothing in the status derivation may consult it.
    config.policy.import_chain = vec!["operator-import".to_string()];
    config.policy.export_chain = vec!["operator-export".to_string()];
    mgr.current_config = config;
    (mgr, rib_rx)
}

/// ADR-0112 step 5: the directional status is a read of the chain the peer has
/// **installed**, never a re-resolution of the running config.
///
/// The state under test is the one a failed or not-yet-applied live edit
/// leaves behind: `current_config` already names explicit operator chains in
/// both directions while the peer still runs the reserved deny on import. A
/// surface that answered from `Config` would report `present` over a live
/// deny — the one answer ADR-0112 must never produce. Deriving the verdict
/// from anything other than `ManagedPeer`'s installed chains makes the import
/// assertion red.
#[tokio::test]
async fn rfc8212_status_reads_the_installed_chain_not_the_running_config() {
    let (mut mgr, _rib_rx) = rfc8212_status_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let counters = Arc::new(FakePeerCounters::default());
    let handle = acking_counted_policy_handle(addr, counters);
    insert_test_managed_peer(&mut mgr, addr, handle, false);

    {
        let managed = mgr.peers.get_mut(&key(addr)).unwrap();
        managed.rfc8212_external = true;
        managed.import_policy = Some(crate::config::reserved_rfc8212_deny_chain(
            crate::config::RFC8212_MISSING_IMPORT_POLICY,
        ));
        // An ordinary operator chain that happens to deny everything: the
        // export direction has deliberate policy, so it is PRESENT.
        managed.export_policy = Some(deny_policy_chain());
    }

    let managed = mgr.peers.get(&key(addr)).unwrap();
    let info = super::snapshot::build_peer_info(&key(addr), managed, None, true);
    assert_eq!(
        info.rfc8212_import_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::Missing,
        "the reserved deny is installed on import; the running config's explicit \
         chain is not evidence about this peer"
    );
    assert_eq!(
        info.rfc8212_export_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::Present,
        "an operator deny-all is deliberate policy — RFC 8212 wants a decision, \
         not a particular filtering strategy"
    );

    // The gauges share the derivation, so they cannot disagree with the row.
    mgr.refresh_rfc8212_policy_metrics(&key(addr));
    assert_eq!(
        mgr.metrics.rfc8212_missing_import_policy(&addr.to_string()),
        1
    );
    assert_eq!(
        mgr.metrics.rfc8212_missing_export_policy(&addr.to_string()),
        0
    );
}

/// ADR-0112 step 5: enforcement off, or an internal session, reports
/// `NOT_REQUIRED` — never `PRESENT`, which would claim a requirement was met
/// that was never applied. Treating `enforced` as unconditionally true makes
/// both halves red.
#[tokio::test]
async fn rfc8212_status_is_not_required_when_disabled_or_internal() {
    let (mut mgr, _rib_rx) = rfc8212_status_manager();
    let external = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let internal = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));
    for addr in [external, internal] {
        let counters = Arc::new(FakePeerCounters::default());
        let handle = acking_counted_policy_handle(addr, counters);
        insert_test_managed_peer(&mut mgr, addr, handle, false);
        let managed = mgr.peers.get_mut(&key(addr)).unwrap();
        managed.import_policy = None;
        managed.export_policy = None;
    }
    mgr.peers.get_mut(&key(external)).unwrap().rfc8212_external = true;
    mgr.peers.get_mut(&key(internal)).unwrap().rfc8212_external = false;

    // Enforcement disabled process-wide: the external peer is exempt too.
    let managed = mgr.peers.get(&key(external)).unwrap();
    let info = super::snapshot::build_peer_info(&key(external), managed, None, false);
    assert_eq!(
        info.rfc8212_import_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::NotRequired
    );
    assert_eq!(
        info.rfc8212_export_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::NotRequired
    );

    // Enforcement on, but the session is iBGP.
    let managed = mgr.peers.get(&key(internal)).unwrap();
    let info = super::snapshot::build_peer_info(&key(internal), managed, None, true);
    assert_eq!(
        info.rfc8212_import_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::NotRequired
    );
    assert_eq!(
        info.rfc8212_export_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::NotRequired
    );

    mgr.refresh_rfc8212_policy_metrics(&key(external));
    mgr.refresh_rfc8212_policy_metrics(&key(internal));
    for addr in [external, internal] {
        assert_eq!(
            mgr.metrics.rfc8212_missing_import_policy(&addr.to_string()),
            0
        );
        assert_eq!(
            mgr.metrics.rfc8212_missing_export_policy(&addr.to_string()),
            0
        );
    }
}

/// ADR-0112 step 5: a live policy edit moves the gauges with the chains it
/// installs, one direction at a time. Refreshing only at peer creation, or
/// only on the direction the caller changed, leaves a latched gauge and makes
/// this red.
#[tokio::test]
async fn rfc8212_gauges_track_a_live_policy_edit_in_both_directions() {
    let (mut mgr, mut rib_rx) = rfc8212_status_manager();
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let counters = Arc::new(FakePeerCounters::default());
    let handle = acking_counted_policy_handle(addr, counters);
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    {
        let managed = mgr.peers.get_mut(&key(addr)).unwrap();
        managed.rfc8212_external = true;
        managed.import_policy = Some(crate::config::reserved_rfc8212_deny_chain(
            crate::config::RFC8212_MISSING_IMPORT_POLICY,
        ));
        managed.export_policy = Some(crate::config::reserved_rfc8212_deny_chain(
            crate::config::RFC8212_MISSING_EXPORT_POLICY,
        ));
    }
    mgr.refresh_rfc8212_policy_metrics(&key(addr));
    assert_eq!(
        mgr.metrics.rfc8212_missing_import_policy(&addr.to_string()),
        1
    );
    assert_eq!(
        mgr.metrics.rfc8212_missing_export_policy(&addr.to_string()),
        1
    );

    // Operator adds an explicit import policy; export keeps the reserved deny,
    // exactly as resolution would hand both chains to this call.
    mgr.update_runtime_policies(
        addr,
        Some(deny_policy_chain()),
        Some(crate::config::reserved_rfc8212_deny_chain(
            crate::config::RFC8212_MISSING_EXPORT_POLICY,
        )),
    )
    .await
    .expect("live import edit applies");

    assert_eq!(
        mgr.metrics.rfc8212_missing_import_policy(&addr.to_string()),
        0,
        "the import gauge must follow the chain the session acknowledged"
    );
    assert_eq!(
        mgr.metrics.rfc8212_missing_export_policy(&addr.to_string()),
        1,
        "the untouched export direction stays denied"
    );
    let managed = mgr.peers.get(&key(addr)).unwrap();
    let info = super::snapshot::build_peer_info(&key(addr), managed, None, true);
    assert_eq!(
        info.rfc8212_import_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::Present
    );
    assert_eq!(
        info.rfc8212_export_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::Missing
    );

    drop(mgr);
    rib_drainer.await.unwrap();
}

/// ADR-0112 step 5: a governed direction with no chain at all is unreachable
/// through resolution, and must never be rounded up to PRESENT.
///
/// `evaluate_chain(None, ..)` is permit-all, so reporting "explicit policy
/// present" for an absent chain would state the requirement was met on the
/// one shape that lets every route through unfiltered. Answering PRESENT for
/// any enforced direction — rather than only for one that actually carries a
/// chain — makes this red.
#[tokio::test]
async fn rfc8212_status_never_calls_a_governed_absent_chain_present() {
    let (mut mgr, _rib_rx) = rfc8212_status_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let counters = Arc::new(FakePeerCounters::default());
    let handle = acking_counted_policy_handle(addr, counters);
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    {
        let managed = mgr.peers.get_mut(&key(addr)).unwrap();
        managed.rfc8212_external = true;
        managed.import_policy = None;
        managed.export_policy = None;
    }

    let managed = mgr.peers.get(&key(addr)).unwrap();
    let info = super::snapshot::build_peer_info(&key(addr), managed, None, true);
    assert_eq!(
        info.rfc8212_import_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::Unknown
    );
    assert_eq!(
        info.rfc8212_export_policy,
        rustbgpd_api::peer_types::Rfc8212PolicyStatus::Unknown
    );
}

// ---------------------------------------------------------------------------
// A rejected mutation leaves no observable trace.
//
// `FAILED_PRECONDITION` from a mutating RPC means the request did nothing.
// These drive the real pipeline end to end — peer-manager actor, gRPC neighbor
// service, config bridge, config persister — against a config directory the
// process cannot write, which is the persistence failure an operator actually
// hits on a read-only or root-owned config mount.
// ---------------------------------------------------------------------------

/// A session task that answers `QueryState` with a fixed, non-zero identity.
///
/// A torn-down-and-recreated session cannot reproduce these values: rebuilding
/// the peer installs a real session task reporting a zeroed uptime and zeroed
/// counters, so a teardown stays visible in the peer list even when the peer
/// address comes back.
fn persistence_probe_handle(peer_addr: IpAddr) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Established,
                        peer_ip: peer_addr,
                        peer_asn: Some(65002),
                        prefix_count: 17,
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: Some(90),
                        four_octet_as: Some(true),
                        remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
                        negotiated_session: None,
                        local_role: None,
                        remote_role: None,
                        role_negotiated: false,
                        peer_paths_limits: Vec::new(),
                        effective_add_path_send_limits: Vec::new(),
                        updates_received: 4_242,
                        updates_sent: 1_337,
                        notifications_received: 0,
                        notifications_sent: 0,
                        messages_received: 9_001,
                        messages_sent: 8_128,
                        otc_routes_blocked: 0,
                        import_policy_routes_permitted: 0,
                        import_policy_routes_denied: 0,
                        flap_count: 3,
                        uptime_secs: 86_400,
                        last_error: String::new(),
                        tcp_ao_info: None,
                        tcp_ao_protected: false,
                        slow_peer: false,
                    });
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

/// The session identity and counters an operator watches: every one of these
/// changes when a session is torn down and rebuilt, and none of them changes
/// while it is left alone.
fn observable_session(
    info: &rustbgpd_api::peer_types::PeerInfo,
) -> (SessionState, u64, u64, u64, u64, u64, u64, usize, bool) {
    (
        info.state,
        info.updates_received,
        info.updates_sent,
        info.messages_received,
        info.messages_sent,
        info.flap_count,
        info.uptime_secs,
        info.prefix_count,
        info.stale,
    )
}

/// Peer-manager actor, config bridge, config persister, and neighbor service —
/// all real — wired to a config file inside a temp directory.
struct PersistenceRig {
    dir: tempfile::TempDir,
    config_path: std::path::PathBuf,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    rib_rx: mpsc::Receiver<RibUpdate>,
    service: rustbgpd_api::NeighborService,
}

impl PersistenceRig {
    /// The peer that exists both on disk and as a live Established session.
    const PEER: &'static str = "10.0.0.2";
    /// A second configured neighbor, so deleting `PEER` is a targeted removal
    /// rather than emptying the file.
    const OTHER_PEER: &'static str = "10.0.0.4";

    /// Not `async`: everything here is either synchronous or a `tokio::spawn`,
    /// which only needs the caller's runtime, so the rig is fully wired the
    /// moment this returns.
    #[expect(
        clippy::too_many_lines,
        reason = "the integration rig setup is intentionally centralized"
    )]
    fn start() -> Self {
        let dir = tempfile::tempdir().expect("temp config dir");
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            crate::test_support::tier_authorized_uds_test_config(
                r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.ix-members]
families = ["ipv4_unicast", "ipv6_unicast"]
route_server_client = true
per_client_best = true
ttl_security = true
graceful_restart = false
role = "route_server"
strict_role = true

[peer_groups.ix-members.add_path]
receive = true
send = true
send_max = 4
receive_max = 8

[peer_groups.rr-clients]
families = ["ipv6_unicast"]
route_reflector_client = true
graceful_restart = false

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90

[[neighbors]]
address = "10.0.0.4"
remote_asn = 65004
hold_time = 90
"#,
            ),
        )
        .expect("seed config file");
        let config = Config::load_with_diagnostics(config_path.to_str().unwrap())
            .expect("seed config parses");
        assert_tier_authorized_test_config(&config);

        // Real persister writing to the real path, behind the real bridge.
        let (mutation_tx, mutation_rx) = mpsc::channel(8);
        tokio::spawn(
            crate::config_persister::ConfigPersister::new(
                mutation_rx,
                config_path.clone(),
                config.clone(),
                None,
            )
            .run(),
        );
        let (event_tx, event_rx) = mpsc::channel::<ConfigEvent>(8);
        let (_replace_tx, replace_rx) = mpsc::unbounded_channel::<Box<Config>>();
        let actor_config = config.clone();
        tokio::spawn(crate::reload::run_config_bridge(
            event_rx,
            replace_rx,
            mutation_tx,
            config,
        ));

        // Real peer-manager actor holding one Established session.
        let (peer_mgr_tx, peer_mgr_rx) = mpsc::channel(16);
        let (rib_tx, rib_rx) = mpsc::channel(64);
        let mut mgr = PeerManager::new(
            peer_mgr_rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            BgpMetrics::new(),
            rib_tx.clone(),
            None,
        );
        mgr.current_config = actor_config;
        let peer_addr: IpAddr = Self::PEER.parse().unwrap();
        insert_test_managed_peer_with_asn(
            &mut mgr,
            peer_addr,
            65002,
            persistence_probe_handle(peer_addr),
            false,
        );
        tokio::spawn(mgr.run());

        let service = rustbgpd_api::NeighborService::with_runtime_config_lock(
            65001,
            rustbgpd_api::server::AccessMode::ReadWrite,
            peer_mgr_tx.clone(),
            rib_tx,
            Some(event_tx),
            Arc::new(tokio::sync::Mutex::new(())),
            None,
        );

        Self {
            dir,
            config_path,
            peer_mgr_tx,
            rib_rx,
            service,
        }
    }

    async fn list_peers(&self) -> Vec<rustbgpd_api::peer_types::PeerInfo> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::ListPeers { reply: reply_tx })
            .await
            .expect("peer-manager actor alive");
        tokio::time::timeout(Duration::from_secs(5), reply_rx)
            .await
            .expect("peer-manager actor answered ListPeers")
            .expect("peer-manager actor kept the reply channel")
    }

    async fn peer(&self, address: &str) -> Option<rustbgpd_api::peer_types::PeerInfo> {
        let wanted: IpAddr = address.parse().unwrap();
        self.list_peers()
            .await
            .into_iter()
            .find(|info| info.address == wanted)
    }

    fn config_bytes(&self) -> Vec<u8> {
        std::fs::read(&self.config_path).expect("config file readable")
    }

    fn staged_temp_path(&self) -> std::path::PathBuf {
        self.dir.path().join("config.toml.tmp")
    }

    /// Take write permission away from the config *directory* so the real
    /// staging write fails with `EACCES`.
    ///
    /// Returns `false` when the mode bits do not bind — uid 0 ignores them —
    /// so the caller skips instead of asserting a failure the kernel will not
    /// produce. Probing with an actual write is the honest check: the whole
    /// premise is that writing fails, so ask the filesystem rather than
    /// guessing from the effective uid.
    fn seal_config_dir(&self) -> bool {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(self.dir.path(), std::fs::Permissions::from_mode(0o500))
            .expect("seal config dir");
        let probe = self.dir.path().join("write-probe");
        if std::fs::write(&probe, b"probe").is_ok() {
            std::fs::remove_file(&probe).ok();
            self.unseal_config_dir();
            return false;
        }
        true
    }

    /// Restore write permission so the temp directory can be cleaned up.
    fn unseal_config_dir(&self) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(self.dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("unseal config dir");
    }

    /// Nothing peer-deleting reached the RIB.
    fn assert_no_rib_peer_deletion(&mut self, peer: IpAddr) {
        while let Ok(update) = self.rib_rx.try_recv() {
            assert!(
                !matches!(update, RibUpdate::PeerDeleted { peer: deleted } if deleted == peer),
                "a rejected mutation must not reap the peer's RIB state"
            );
        }
    }

    async fn delete_neighbor(&self, address: &str) -> Result<(), tonic::Status> {
        use rustbgpd_api::proto::neighbor_service_server::NeighborService as _;

        tokio::time::timeout(
            Duration::from_secs(10),
            self.service.delete_neighbor(tonic::Request::new(
                rustbgpd_api::proto::DeleteNeighborRequest {
                    address: address.to_string(),
                    interface: String::new(),
                },
            )),
        )
        .await
        .expect("delete_neighbor must answer, not hang")
        .map(|_| ())
    }

    async fn add_neighbor(&self, address: &str, remote_asn: u32) -> Result<(), tonic::Status> {
        use rustbgpd_api::proto::neighbor_service_server::NeighborService as _;

        tokio::time::timeout(
            Duration::from_secs(10),
            self.service.add_neighbor(tonic::Request::new(
                rustbgpd_api::proto::AddNeighborRequest {
                    config: Some(rustbgpd_api::proto::NeighborConfig {
                        address: address.to_string(),
                        remote_asn,
                        hold_time: 90,
                        ..Default::default()
                    }),
                    intent: None,
                },
            )),
        )
        .await
        .expect("add_neighbor must answer, not hang")
        .map(|_| ())
    }

    #[expect(
        clippy::default_trait_access,
        reason = "the API crate does not re-export prost_types::FieldMask"
    )]
    async fn add_presence_neighbor(
        &self,
        config: rustbgpd_api::proto::NeighborConfig,
        paths: &[&str],
    ) -> Result<(), tonic::Status> {
        use rustbgpd_api::proto::neighbor_service_server::NeighborService as _;

        let mut intent = rustbgpd_api::proto::NeighborCreateIntent {
            config: Some(config),
            override_mask: Some(Default::default()),
        };
        intent.override_mask.as_mut().unwrap().paths =
            paths.iter().map(|path| (*path).to_string()).collect();
        tokio::time::timeout(
            Duration::from_secs(10),
            self.service.add_neighbor(tonic::Request::new(
                rustbgpd_api::proto::AddNeighborRequest {
                    config: None,
                    intent: Some(intent),
                },
            )),
        )
        .await
        .expect("presence-aware add must answer, not hang")
        .map(|_| ())
    }

    async fn session_history(&self) -> Vec<rustbgpd_api::peer_types::SessionLifecycleEvent> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::QuerySessionEventHistory {
                peer: None,
                event_types: BTreeSet::new(),
                limit: 0,
                reply: reply_tx,
            })
            .await
            .unwrap();
        reply_rx.await.unwrap()
    }

    async fn runtime_config(&self) -> Config {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.peer_mgr_tx
            .send(PeerManagerCommand::RuntimeConfigSnapshot { reply: reply_tx })
            .await
            .unwrap();
        let snapshot = reply_rx.await.unwrap().unwrap();
        Config::load_toml_with_diagnostics(&snapshot.toml, "actor runtime snapshot").unwrap()
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario verifies raw, resolved, persisted, actor, and reload parity"
)]
async fn presence_create_preserves_raw_inheritance_over_disk_actor_and_reload() {
    const INHERITED: &str = "10.0.0.9";
    const MASKED: &str = "10.0.0.10";
    const IPV6_DEFAULT: &str = "2001:db8::9";
    const RR_CLIENT: &str = "10.0.0.14";
    let rig = PersistenceRig::start();
    assert!(
        Config::load_with_diagnostics(rig.config_path.to_str().unwrap())
            .unwrap()
            .peer_groups
            .contains_key("ix-members")
    );
    assert!(
        rig.runtime_config()
            .await
            .peer_groups
            .contains_key("ix-members")
    );

    rig.add_presence_neighbor(
        rustbgpd_api::proto::NeighborConfig {
            address: INHERITED.into(),
            remote_asn: 65009,
            peer_group: "ix-members".into(),
            ..Default::default()
        },
        &[],
    )
    .await
    .unwrap();
    let inherited = rig.peer(INHERITED).await.unwrap();
    assert_eq!(
        inherited.families,
        vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)]
    );
    assert!(inherited.route_server_client && inherited.per_client_best);
    assert_eq!(
        inherited.local_role,
        Some(rustbgpd_wire::BgpRole::RouteServer)
    );
    assert!(inherited.strict_role && inherited.add_path_receive && inherited.add_path_send);
    assert_eq!(inherited.add_path_send_max, 4);
    assert_eq!(inherited.paths_limit_receive_max, 8);

    rig.add_presence_neighbor(
        rustbgpd_api::proto::NeighborConfig {
            address: MASKED.into(),
            remote_asn: 65010,
            peer_group: "ix-members".into(),
            families: vec!["ipv6_unicast".into()],
            ..Default::default()
        },
        &[
            "families",
            "route_server_client",
            "per_client_best",
            "strict_role",
            "add_path_receive",
            "add_path_send",
            "add_path_send_max",
            "paths_limit_receive_max",
        ],
    )
    .await
    .unwrap();
    let masked = rig.peer(MASKED).await.unwrap();
    assert_eq!(masked.families, vec![(Afi::Ipv6, Safi::Unicast)]);
    assert!(!masked.route_server_client && !masked.per_client_best && !masked.strict_role);
    assert!(!masked.add_path_receive && !masked.add_path_send);

    rig.add_presence_neighbor(
        rustbgpd_api::proto::NeighborConfig {
            address: IPV6_DEFAULT.into(),
            remote_asn: 65011,
            ..Default::default()
        },
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        rig.peer(IPV6_DEFAULT).await.unwrap().families,
        vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)],
        "presence-aware IPv6 omission must reach the resolver, not legacy IPv4 materialization"
    );
    rig.add_presence_neighbor(
        rustbgpd_api::proto::NeighborConfig {
            address: RR_CLIENT.into(),
            remote_asn: 65001,
            peer_group: "rr-clients".into(),
            ..Default::default()
        },
        &[],
    )
    .await
    .unwrap();
    let rr = rig.peer(RR_CLIENT).await.unwrap();
    assert!(rr.route_reflector_client);
    assert_eq!(rr.families, vec![(Afi::Ipv6, Safi::Unicast)]);

    let disk = Config::load_with_diagnostics(rig.config_path.to_str().unwrap()).unwrap();
    let actor = rig.runtime_config().await;
    for snapshot in [&disk, &actor] {
        let raw = snapshot
            .neighbors
            .iter()
            .find(|neighbor| neighbor.address == INHERITED)
            .unwrap();
        assert!(raw.families.is_empty());
        assert_eq!(raw.route_server_client, None);
        assert_eq!(raw.per_client_best, None);
        assert_eq!(raw.ttl_security, None);
        assert_eq!(raw.graceful_restart, None);
        assert_eq!(raw.role, None);
        assert_eq!(raw.strict_role, None);
        assert_eq!(raw.add_path, None);
        let effective = snapshot.resolve_neighbor(raw).unwrap();
        assert!(effective.transport_config.ttl_security);
        assert!(!effective.transport_config.peer.graceful_restart);

        let raw = snapshot
            .neighbors
            .iter()
            .find(|neighbor| neighbor.address == MASKED)
            .unwrap();
        assert_eq!(raw.families, vec!["ipv6_unicast"]);
        assert_eq!(raw.route_server_client, Some(false));
        assert_eq!(raw.per_client_best, Some(false));
        assert_eq!(raw.strict_role, Some(false));
        let add_path = raw.add_path.as_ref().unwrap();
        assert!(!add_path.receive && !add_path.send);
        let effective = snapshot.resolve_neighbor(raw).unwrap();
        assert!(!effective.transport_config.peer.add_path_receive);
        assert!(!effective.transport_config.peer.add_path_send);

        let raw = snapshot
            .neighbors
            .iter()
            .find(|neighbor| neighbor.address == RR_CLIENT)
            .unwrap();
        assert!(raw.families.is_empty());
        assert_eq!(raw.route_reflector_client, None);
        assert_eq!(raw.graceful_restart, None);
        let effective = snapshot.resolve_neighbor(raw).unwrap();
        assert!(effective.transport_config.route_reflector_client);
        assert_eq!(
            effective.transport_config.cluster_id,
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert!(!effective.transport_config.peer.graceful_restart);
    }
}

#[tokio::test]
async fn presence_create_rejections_leave_no_disk_history_or_live_half_state() {
    let rig = PersistenceRig::start();
    let config_before = rig.config_bytes();
    let history_before = rig.session_history().await;

    let actor_error = rig
        .add_presence_neighbor(
            rustbgpd_api::proto::NeighborConfig {
                address: PersistenceRig::PEER.into(),
                remote_asn: 65002,
                ..Default::default()
            },
            &[],
        )
        .await
        .unwrap_err();
    assert_eq!(actor_error.code(), tonic::Code::AlreadyExists);
    assert_eq!(rig.config_bytes(), config_before);
    assert_eq!(rig.session_history().await, history_before);
    assert!(rig.peer(PersistenceRig::PEER).await.is_some());

    let effective_error = rig
        .add_presence_neighbor(
            rustbgpd_api::proto::NeighborConfig {
                address: "10.0.0.12".into(),
                remote_asn: 65012,
                peer_group: "ix-members".into(),
                ..Default::default()
            },
            &["route_server_client"],
        )
        .await
        .unwrap_err();
    assert_eq!(effective_error.code(), tonic::Code::InvalidArgument);
    assert!(
        effective_error.message().contains("per_client_best"),
        "{effective_error}"
    );
    assert!(rig.peer("10.0.0.12").await.is_none());
    assert_eq!(rig.config_bytes(), config_before);
    assert_eq!(rig.session_history().await, history_before);

    if !rig.seal_config_dir() {
        return;
    }
    let persistence_error = rig
        .add_presence_neighbor(
            rustbgpd_api::proto::NeighborConfig {
                address: "10.0.0.13".into(),
                remote_asn: 65013,
                peer_group: "ix-members".into(),
                ..Default::default()
            },
            &[],
        )
        .await
        .unwrap_err();
    assert_eq!(
        persistence_error.code(),
        tonic::Code::FailedPrecondition,
        "{persistence_error}"
    );
    assert!(rig.peer("10.0.0.13").await.is_none());
    assert_eq!(rig.config_bytes(), config_before);
    assert_eq!(rig.session_history().await, history_before);
    rig.unseal_config_dir();
    assert!(!rig.staged_temp_path().exists());
}

#[test]
fn presence_create_policy_event_keeps_the_legacy_neighbor_sentinel() {
    let raw = rustbgpd_api::peer_types::PresenceAwareNeighborCreate {
        address: "10.0.0.9".parse().unwrap(),
        interface: None,
        remote_asn: 65009,
        description: None,
        peer_group: None,
        hold_time: None,
        min_hold_time: None,
        send_hold_time: None,
        max_prefixes: None,
        max_prefix_restart_seconds: None,
        remove_private_as: None,
        local_role: None,
        families: None,
        required_families: None,
        route_server_client: None,
        per_client_best: None,
        strict_role: None,
        add_path: None,
    };
    let event = ConfigEvent::PresenceAwareNeighborAdded {
        spec: rustbgpd_api::peer_types::NeighborCreateSpec::PresenceAware(Box::new(raw)),
        ack: None,
    };
    assert_eq!(
        PeerManager::policy_event_details(&event),
        ("change", "neighbor", String::new(), None)
    );
}

/// A `DeleteNeighbor` that cannot persist must return without touching the
/// session. Applying first and compensating afterwards cannot satisfy this:
/// the re-added peer is a *new* session with a new identity, a zeroed uptime,
/// zeroed counters, and a fresh metric series, and the teardown never reaches
/// the operator's flap count.
#[tokio::test]
async fn neighbor_delete_persistence_failure_leaves_the_session_untouched() {
    let mut rig = PersistenceRig::start();
    let peer_addr: IpAddr = PersistenceRig::PEER.parse().unwrap();

    let before = rig
        .peer(PersistenceRig::PEER)
        .await
        .expect("peer is present before the rejected delete");
    assert_eq!(before.state, SessionState::Established);
    assert!(
        before.updates_received > 0 && before.updates_sent > 0,
        "the probe session must carry counters a rebuilt session could not reproduce"
    );
    let before_observable = observable_session(&before);
    let config_before = rig.config_bytes();

    if !rig.seal_config_dir() {
        return;
    }

    let error = rig
        .delete_neighbor(PersistenceRig::PEER)
        .await
        .expect_err("an unwritable config directory must reject the delete");
    assert_eq!(error.code(), tonic::Code::FailedPrecondition, "{error}");
    assert!(
        error.message().contains("config persistence failed"),
        "{}",
        error.message()
    );

    let after = rig
        .peer(PersistenceRig::PEER)
        .await
        .expect("the rejected delete must leave the peer in the list");
    assert_eq!(
        observable_session(&after),
        before_observable,
        "the session must be untouched, not restored: a rebuilt session reports a \
         zeroed uptime and zeroed counters"
    );
    assert_eq!(after.remote_asn, before.remote_asn);
    assert_eq!(after.description, before.description);

    rig.assert_no_rib_peer_deletion(peer_addr);

    assert_eq!(
        rig.config_bytes(),
        config_before,
        "the config file must be byte-for-byte unchanged"
    );
    let staged = rig.staged_temp_path();
    rig.unseal_config_dir();
    assert!(
        !staged.exists(),
        "no staged temp file may be left behind: {}",
        staged.display()
    );
}

/// An `AddNeighbor` that cannot persist must create nothing at all — not a
/// peer that is created and then deleted again, and not a config file edit.
#[tokio::test]
async fn neighbor_add_persistence_failure_creates_no_session() {
    const NEW_PEER: &str = "10.0.0.9";

    let rig = PersistenceRig::start();
    let existing_before = observable_session(
        &rig.peer(PersistenceRig::PEER)
            .await
            .expect("pre-existing peer is present"),
    );
    let config_before = rig.config_bytes();

    if !rig.seal_config_dir() {
        return;
    }

    let error = rig
        .add_neighbor(NEW_PEER, 65009)
        .await
        .expect_err("an unwritable config directory must reject the add");
    assert_eq!(error.code(), tonic::Code::FailedPrecondition, "{error}");
    assert!(
        error.message().contains("config persistence failed"),
        "{}",
        error.message()
    );

    assert!(
        rig.peer(NEW_PEER).await.is_none(),
        "the rejected add must never create the peer — not even briefly"
    );
    assert_eq!(
        observable_session(
            &rig.peer(PersistenceRig::PEER)
                .await
                .expect("pre-existing peer survives an unrelated rejected add")
        ),
        existing_before,
        "an unrelated peer must not be disturbed by a rejected add"
    );

    assert_eq!(
        rig.config_bytes(),
        config_before,
        "the config file must be byte-for-byte unchanged"
    );
    let staged = rig.staged_temp_path();
    rig.unseal_config_dir();
    assert!(
        !staged.exists(),
        "no staged temp file may be left behind: {}",
        staged.display()
    );
}

/// The success path still works: staging before applying must not turn a
/// writable config into a no-op.
#[tokio::test]
async fn neighbor_delete_persists_and_applies_when_the_config_is_writable() {
    let rig = PersistenceRig::start();
    assert!(rig.peer(PersistenceRig::PEER).await.is_some());

    rig.delete_neighbor(PersistenceRig::PEER)
        .await
        .expect("a writable config directory must accept the delete");

    assert!(
        rig.peer(PersistenceRig::PEER).await.is_none(),
        "the accepted delete must remove the session"
    );
    let persisted = String::from_utf8(rig.config_bytes()).expect("config is UTF-8");
    assert!(
        !persisted.contains(PersistenceRig::PEER),
        "the accepted delete must remove the neighbor from disk: {persisted}"
    );
    assert!(
        persisted.contains(PersistenceRig::OTHER_PEER),
        "the accepted delete must not disturb the other neighbor: {persisted}"
    );
    assert!(
        !rig.staged_temp_path().exists(),
        "the staged temp file must be renamed into place, not left behind"
    );
}

/// A whole-peer Route Refresh is bounded by what the session negotiated: a
/// configured family the peer never accepted has no `AdjRibIn` to re-evaluate,
/// so it is skipped rather than failing the refresh. An explicitly requested
/// family still errors.
///
/// Load-bearing: dropping the `refresh_all` guard in `soft_reset_in` makes the
/// first case red; dropping the whole arm makes it red the other way, because
/// every policy edit on an asymmetric session would fail.
#[tokio::test]
async fn soft_reset_in_skips_configured_families_the_peer_never_negotiated() {
    use rustbgpd_transport::{PeerCommand, PeerCommandError};

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let refreshed = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&refreshed);
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                // IPv4 unicast negotiated, IPv6 unicast configured but not.
                PeerCommand::SendRouteRefresh { afi, safi, reply } => {
                    if (afi, safi) == (Afi::Ipv4, Safi::Unicast) {
                        counted.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    } else {
                        let _ =
                            reply.send(Err(PeerCommandError::FamilyNotNegotiated { afi, safi }));
                    }
                }
                PeerCommand::Shutdown | PeerCommand::Stop { .. } => break,
                _ => {}
            }
        }
        Ok(())
    });

    let mut mgr = test_peer_manager();
    insert_test_managed_peer(
        &mut mgr,
        addr,
        PeerHandle::from_parts(session_tx, task),
        false,
    );
    mgr.peers
        .get_mut(&key(addr))
        .unwrap()
        .transport_config
        .peer
        .families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];

    mgr.soft_reset_in(key(addr), Vec::new())
        .await
        .expect("an un-negotiated configured family must not fail the whole refresh");
    assert_eq!(
        refreshed.load(Ordering::SeqCst),
        1,
        "the negotiated family must still be refreshed"
    );

    mgr.soft_reset_in(key(addr), vec![(Afi::Ipv6, Safi::Unicast)])
        .await
        .expect_err("an explicitly named un-negotiated family still errors");

    let managed = mgr.peers.remove(&key(addr)).unwrap();
    managed.handle.shutdown().await.unwrap().unwrap();
}

/// A forward apply that fails *at the Route Refresh step* may already have
/// delivered one family's request: `soft_reset_in` queues families
/// sequentially, so IPv4 can be accepted before IPv6 fails, and a timeout is
/// ambiguous either way. Adj-RIB-In may therefore already sit on the candidate
/// policy. When the rollback's own refresh then fails, that is real unfinished
/// convergence debt and `pending_refresh` must stay armed.
///
/// Load-bearing: this is the case `forward_completed = false` used to swallow.
/// With the pre-fix `BestEffortRestorePrior { pending_refresh: false }`
/// selection, the rollback clears the flag and the final assertion fails.
///
/// Its discriminator is
/// `rfc8212_import_presence_edit_fails_when_the_peer_flaps_after_preflight`,
/// which asserts the opposite for a forward that never reached the refresh
/// step at all. Neither test means anything without the other.
#[tokio::test]
async fn rollback_arms_retry_when_a_partially_delivered_refresh_cannot_be_undone() {
    use rustbgpd_transport::{PeerCommand, PeerCommandError};

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11));
    let ipv4_refreshes = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&ipv4_refreshes);
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::QueryState { reply } => {
                    let mut state = policy_test_peer_state(addr, SessionState::Established);
                    state.negotiated_session = Some(test_negotiated_session(true));
                    let _ = reply.send(state);
                }
                // Both families negotiated. IPv4's request is accepted and
                // queued; IPv6's send fails. Deliberately NOT
                // `FamilyNotNegotiated`, which a whole-peer refresh skips.
                PeerCommand::SendRouteRefresh { afi, safi, reply } => {
                    if (afi, safi) == (Afi::Ipv4, Safi::Unicast) {
                        counted.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    } else {
                        let _ = reply
                            .send(Err(PeerCommandError::SendFailed("link wedged".to_string())));
                    }
                }
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown | PeerCommand::Stop { .. } => break,
                _ => {}
            }
        }
        Ok(())
    });

    let (mut mgr, rib_rx) = rfc8212_status_manager();
    let rib = spawn_rfc8212_rib_stub(rib_rx, 0);
    insert_test_managed_peer(
        &mut mgr,
        addr,
        PeerHandle::from_parts(session_tx, task),
        false,
    );
    {
        let managed = mgr.peers.get_mut(&key(addr)).unwrap();
        managed.transport_config.peer.families =
            vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
        managed.import_policy = Some(deny_policy_chain());
        managed.export_policy = Some(distinct_deny_policy_chain(3));
    }

    // Export is unchanged, so no RIB replacement runs and the rollback is
    // purely the import chain plus its refresh.
    let error = mgr
        .apply_resolved_policy_snapshot(vec![rustbgpd_api::peer_types::ResolvedPeerPolicy {
            address: addr,
            interface: None,
            import_policy: Some(distinct_deny_policy_chain(5)),
            export_policy: Some(distinct_deny_policy_chain(3)),
        }])
        .await
        .expect_err("a failed Route Refresh fails the forward apply");
    assert!(
        error.contains("already-applied peers restored"),
        "the forward failure must have rolled back: {error}"
    );
    assert!(
        ipv4_refreshes.load(Ordering::SeqCst) >= 1,
        "the IPv4 request must have been accepted before IPv6 failed — otherwise \
         this test proves nothing about a partially delivered refresh"
    );

    let managed = mgr.peers.get(&key(addr)).unwrap();
    assert_eq!(
        managed.import_policy,
        Some(deny_policy_chain()),
        "rollback must restore the prior import chain"
    );
    assert!(
        managed.pending_refresh,
        "a partially delivered forward refresh whose rollback refresh also failed \
         leaves real convergence debt; retry intent must stay armed"
    );

    let managed = mgr.peers.remove(&key(addr)).unwrap();
    managed.handle.shutdown().await.unwrap().unwrap();
    drop(mgr);
    rib.await.unwrap();
}

// ---------------------------------------------------------------------------
// ADR-0112 step 4 — live policy-presence transitions
// ---------------------------------------------------------------------------

fn rfc8212_missing_import() -> PolicyChain {
    crate::config::reserved_rfc8212_deny_chain(crate::config::RFC8212_MISSING_IMPORT_POLICY)
}

fn rfc8212_missing_export() -> PolicyChain {
    crate::config::reserved_rfc8212_deny_chain(crate::config::RFC8212_MISSING_EXPORT_POLICY)
}

/// A stub session whose reported FSM state and Route Refresh capability are
/// scripted, and which refuses `SendRouteRefresh` exactly when it reports the
/// capability absent — the two answers a real session keeps consistent.
///
/// `established_for` bounds how many `QueryState` answers report Established
/// before the session starts reporting `Idle`, which is how a flap between the
/// snapshot preflight and the per-peer apply is reproduced deterministically.
fn scripted_policy_handle(
    peer_addr: IpAddr,
    route_refresh: bool,
    established_for: usize,
    refreshes: Arc<AtomicUsize>,
) -> PeerHandle {
    use rustbgpd_transport::{PeerCommand, PeerCommandError};
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        let mut queries = 0usize;
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::QueryState { reply } => {
                    queries += 1;
                    let state = if queries <= established_for {
                        SessionState::Established
                    } else {
                        SessionState::Idle
                    };
                    let mut snapshot = policy_test_peer_state(peer_addr, state);
                    snapshot.negotiated_session = (state == SessionState::Established)
                        .then(|| test_negotiated_session(route_refresh));
                    let _ = reply.send(snapshot);
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    if route_refresh {
                        refreshes.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    } else {
                        let _ = reply.send(Err(PeerCommandError::RouteRefreshUnsupported));
                    }
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

fn rfc8212_target(
    addr: IpAddr,
    import: Option<PolicyChain>,
) -> rustbgpd_api::peer_types::ResolvedPeerPolicy {
    rustbgpd_api::peer_types::ResolvedPeerPolicy {
        address: addr,
        interface: None,
        import_policy: import,
        export_policy: Some(rfc8212_missing_export()),
    }
}

fn install_rfc8212_peer(
    mgr: &mut PeerManager,
    addr: IpAddr,
    handle: PeerHandle,
    import: Option<PolicyChain>,
) {
    insert_test_managed_peer(mgr, addr, handle, false);
    let managed = mgr.peers.get_mut(&key(addr)).unwrap();
    managed.rfc8212_external = true;
    managed.import_policy = import;
    managed.export_policy = Some(rfc8212_missing_export());
}

/// ADR-0112 step 4: an Established peer that never negotiated Route Refresh
/// cannot converge an import policy-presence change, so the edit is rejected
/// with clear/reconnect guidance and its chains stay exactly where they were.
///
/// Load-bearing: dropping the capability check in
/// `qualify_rfc8212_import_transition` lets the apply proceed and the assertion
/// on the retained prior chain fails — the peer would be left running the new
/// import chain over an `AdjRibIn` still full of routes the old verdict
/// accepted.
#[tokio::test]
async fn rfc8212_import_presence_edit_rejects_a_peer_without_route_refresh() {
    let (mut mgr, rib_rx) = rfc8212_status_manager();
    let rib = spawn_rfc8212_rib_stub(rib_rx, 0);
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let refreshes = Arc::new(AtomicUsize::new(0));
    let handle = scripted_policy_handle(addr, false, usize::MAX, Arc::clone(&refreshes));
    install_rfc8212_peer(&mut mgr, addr, handle, Some(rfc8212_missing_import()));

    let error = mgr
        .apply_resolved_policy_snapshot(vec![rfc8212_target(addr, Some(deny_policy_chain()))])
        .await
        .expect_err("a peer without Route Refresh must not take a presence transition");
    assert!(
        error.contains("did not negotiate Route Refresh"),
        "the error must name the missing capability: {error}"
    );
    assert!(
        error.contains("clear the session"),
        "the error must be actionable: {error}"
    );
    assert!(
        error.contains("no peer was modified"),
        "the rejection must state that nothing was mutated: {error}"
    );

    let managed = mgr.peers.get(&key(addr)).unwrap();
    assert_eq!(
        managed.import_policy,
        Some(rfc8212_missing_import()),
        "the prior reserved deny must remain authoritative"
    );
    assert!(
        !managed.pending_refresh && !managed.pending_export_apply,
        "a rejection before mutation must not arm retry intent"
    );
    assert_eq!(
        refreshes.load(Ordering::SeqCst),
        0,
        "no Route Refresh may be attempted for a rejected transition"
    );

    drop(mgr);
    rib.await.unwrap();
}

/// ADR-0112 step 4: one incapable peer rejects the whole multi-peer edit before
/// any peer is mutated.
///
/// Load-bearing: moving the preflight from `apply_resolved_policy_snapshot`
/// into the per-peer apply lets the capable peer commit first, and the
/// assertion that its chains are untouched fails.
#[tokio::test]
async fn rfc8212_import_presence_preflight_rejects_the_whole_edit_before_mutation() {
    let (mut mgr, rib_rx) = rfc8212_status_manager();
    let rib = spawn_rfc8212_rib_stub(rib_rx, 0);
    let capable = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let incapable = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));
    let capable_refreshes = Arc::new(AtomicUsize::new(0));
    install_rfc8212_peer(
        &mut mgr,
        capable,
        scripted_policy_handle(capable, true, usize::MAX, Arc::clone(&capable_refreshes)),
        Some(rfc8212_missing_import()),
    );
    install_rfc8212_peer(
        &mut mgr,
        incapable,
        scripted_policy_handle(incapable, false, usize::MAX, Arc::new(AtomicUsize::new(0))),
        Some(rfc8212_missing_import()),
    );

    let error = mgr
        .apply_resolved_policy_snapshot(vec![
            rfc8212_target(capable, Some(deny_policy_chain())),
            rfc8212_target(incapable, Some(deny_policy_chain())),
        ])
        .await
        .expect_err("one incapable peer rejects the edit");
    assert!(
        error.contains(&incapable.to_string()),
        "the rejection must name the incapable peer: {error}"
    );

    for addr in [capable, incapable] {
        let managed = mgr.peers.get(&key(addr)).unwrap();
        assert_eq!(
            managed.import_policy,
            Some(rfc8212_missing_import()),
            "{addr} must keep its prior chain when the edit is rejected whole"
        );
    }
    assert_eq!(
        capable_refreshes.load(Ordering::SeqCst),
        0,
        "the capable peer must not be refreshed for an edit that never committed"
    );

    drop(mgr);
    rib.await.unwrap();
}

/// ADR-0112 step 4: a capable Established peer converges the transition —
/// chains advance and every negotiated family is asked to re-advertise.
#[tokio::test]
async fn rfc8212_import_presence_edit_commits_and_refreshes_a_capable_peer() {
    let (mut mgr, rib_rx) = rfc8212_status_manager();
    let rib = spawn_rfc8212_rib_stub(rib_rx, 0);
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let refreshes = Arc::new(AtomicUsize::new(0));
    let handle = scripted_policy_handle(addr, true, usize::MAX, Arc::clone(&refreshes));
    install_rfc8212_peer(&mut mgr, addr, handle, Some(rfc8212_missing_import()));

    mgr.apply_resolved_policy_snapshot(vec![rfc8212_target(addr, Some(deny_policy_chain()))])
        .await
        .expect("a Route Refresh capable peer takes the transition");

    let managed = mgr.peers.get(&key(addr)).unwrap();
    assert_eq!(managed.import_policy, Some(deny_policy_chain()));
    assert!(
        refreshes.load(Ordering::SeqCst) >= 1,
        "the committed transition must have queued a Route Refresh"
    );
    assert!(
        !managed.pending_refresh,
        "a delivered refresh must not leave retry intent armed"
    );

    drop(mgr);
    rib.await.unwrap();
}

/// ADR-0112 step 4: a down peer whose routes GR or LLGR still retains defers
/// the transition, and takes it once nothing is retained.
///
/// Load-bearing: answering from session-local state instead of the RIB (or
/// skipping the query for a non-Established peer) makes the retained case
/// commit, and the first assertion fails.
#[tokio::test]
async fn rfc8212_import_presence_edit_defers_while_gr_llgr_state_is_retained() {
    for (retained, expect_commit) in [(3usize, false), (0usize, true)] {
        let (mut mgr, rib_rx) = rfc8212_status_manager();
        let rib = spawn_rfc8212_rib_stub(rib_rx, retained);
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let handle = scripted_policy_handle(addr, true, 0, Arc::new(AtomicUsize::new(0)));
        install_rfc8212_peer(&mut mgr, addr, handle, Some(rfc8212_missing_import()));

        let outcome = mgr
            .apply_resolved_policy_snapshot(vec![rfc8212_target(addr, Some(deny_policy_chain()))])
            .await;
        let managed = mgr.peers.get(&key(addr)).unwrap();
        if expect_commit {
            outcome.expect("a down peer with nothing retained may take the transition");
            assert_eq!(managed.import_policy, Some(deny_policy_chain()));
        } else {
            let error = outcome.expect_err("retained stale state must defer the transition");
            assert!(
                error.contains("stale route"),
                "the error must name the retained state: {error}"
            );
            assert_eq!(
                managed.import_policy,
                Some(rfc8212_missing_import()),
                "the prior verdict stays paired with the routes retained under it"
            );
        }

        drop(mgr);
        rib.await.unwrap();
    }
}

/// ADR-0112 step 4: a peer that qualifies at preflight and flaps before its
/// Route Refresh can be delivered fails the edit rather than committing the
/// desired verdict over an undelivered refresh.
///
/// Load-bearing: letting the non-Established branch arm `pending_refresh` and
/// return `Ok` for a presence transition makes the error assertion fail and
/// leaves the new chain installed with no convergence behind it.
#[tokio::test]
async fn rfc8212_import_presence_edit_fails_when_the_peer_flaps_after_preflight() {
    let (mut mgr, rib_rx) = rfc8212_status_manager();
    let rib = spawn_rfc8212_rib_stub(rib_rx, 0);
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let refreshes = Arc::new(AtomicUsize::new(0));
    // Established for the snapshot preflight and the per-peer requalification,
    // Idle by the time the apply queries state for the refresh decision.
    let handle = scripted_policy_handle(addr, true, 2, Arc::clone(&refreshes));
    install_rfc8212_peer(&mut mgr, addr, handle, Some(rfc8212_missing_import()));

    let error = mgr
        .apply_resolved_policy_snapshot(vec![rfc8212_target(addr, Some(deny_policy_chain()))])
        .await
        .expect_err("a flap before the refresh must fail the edit");
    assert!(
        error.contains("Route Refresh"),
        "the error must name the undelivered refresh: {error}"
    );
    assert_eq!(
        refreshes.load(Ordering::SeqCst),
        0,
        "no refresh was delivered, so none may be reported"
    );
    let managed = mgr.peers.get(&key(addr)).unwrap();
    assert_eq!(
        managed.import_policy,
        Some(rfc8212_missing_import()),
        "rollback must restore the prior chain"
    );
    // Retry intent for a fully unwound forward is the captured prior, not an
    // armed flag. This forward bailed *before* any Route Refresh was attempted
    // — the peer stopped reporting Established — so `AdjRibIn` provably never
    // left the prior policy and the rollback is exact. `pending_refresh` means
    // unfinished convergence debt, not a rejected desired change; arming it
    // here would make an unrelated later edit refresh the restored policy. The
    // operator's intent survives structurally because `current_config` never
    // advanced: the next reload re-derives the same delta and requalifies.
    //
    // Discriminator: `rollback_arms_retry_when_a_partially_delivered_refresh_cannot_be_undone`
    // asserts the opposite for a forward that failed *at* the refresh step,
    // where one family may already have converged. Neither assertion means
    // anything without the other.
    assert!(
        !managed.pending_refresh && !managed.pending_export_apply,
        "a fully restored peer must not carry a spurious retry"
    );

    drop(mgr);
    rib.await.unwrap();
}

/// ADR-0112 step 4: the batched export cohort defers its members' Route
/// Refresh past the RIB commit, so a member whose RFC 8212 import verdict moves
/// is never selected into it.
///
/// Load-bearing: removing the disqualification from
/// `local_export_only_policy_pair` selects both peers and the presence
/// transition's refresh — its entire convergence — rides the deferred path.
#[tokio::test]
async fn rfc8212_import_presence_transition_is_excluded_from_the_export_cohort() {
    let (mut mgr, rib_rx) = rfc8212_status_manager();
    let rib = spawn_rfc8212_rib_stub(rib_rx, 0);
    let plain = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let transitioning = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));
    install_rfc8212_peer(
        &mut mgr,
        plain,
        scripted_policy_handle(plain, true, usize::MAX, Arc::new(AtomicUsize::new(0))),
        Some(deny_policy_chain()),
    );
    install_rfc8212_peer(
        &mut mgr,
        transitioning,
        scripted_policy_handle(
            transitioning,
            true,
            usize::MAX,
            Arc::new(AtomicUsize::new(0)),
        ),
        Some(rfc8212_missing_import()),
    );

    // Identical export moves, so cohort identity is satisfied for both and only
    // the import-presence rule can separate them.
    let targets = vec![
        rustbgpd_api::peer_types::ResolvedPeerPolicy {
            address: plain,
            interface: None,
            import_policy: Some(deny_policy_chain()),
            export_policy: Some(distinct_deny_policy_chain(3)),
        },
        rustbgpd_api::peer_types::ResolvedPeerPolicy {
            address: transitioning,
            interface: None,
            import_policy: Some(deny_policy_chain()),
            export_policy: Some(distinct_deny_policy_chain(3)),
        },
    ];
    let mask = mgr.export_only_policy_cohort_mask(&targets).await;
    assert_eq!(
        mask,
        vec![false, false],
        "a presence transition disqualifies its cohort, dropping the pair below two members"
    );

    drop(mgr);
    rib.await.unwrap();
}

/// ADR-0112 step 4 scoping: an ordinary import edit between two explicit chains
/// is not a policy-presence transition, so it keeps the pre-existing path — the
/// new gate must not start rejecting every policy edit on a peer that happens
/// to lack Route Refresh.
#[tokio::test]
async fn rfc8212_gate_ignores_an_ordinary_import_edit() {
    let (mut mgr, rib_rx) = rfc8212_status_manager();
    let rib = spawn_rfc8212_rib_stub(rib_rx, 0);
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let handle = scripted_policy_handle(addr, false, usize::MAX, Arc::new(AtomicUsize::new(0)));
    install_rfc8212_peer(&mut mgr, addr, handle, Some(deny_policy_chain()));

    let error = mgr
        .apply_resolved_policy_snapshot(vec![rfc8212_target(
            addr,
            Some(distinct_deny_policy_chain(3)),
        )])
        .await
        .expect_err("the stub session still rejects the ordinary refresh it cannot send");
    assert!(
        !error.contains("policy-presence"),
        "the presence gate must not claim an ordinary chain edit: {error}"
    );

    drop(mgr);
    rib.await.unwrap();
}
