//! Session-wait rounds use one deadline and let ready peers finish independently.

use super::*;
use rustbgpd_api::peer_types::PeerManagerReadinessQuery;

pub(super) const ROUND_WINDOW: Duration = Duration::from_millis(500);

/// Real TCP setup runs with the clock unfrozen. Re-align to the runtime's
/// original millisecond ticks before measuring the exact round budget.
pub(super) async fn pause_round_clock(origin: tokio::time::Instant) {
    tokio::time::pause();
    let fraction = origin.elapsed().subsec_nanos() % 1_000_000;
    if fraction != 0 {
        tokio::time::advance(Duration::from_nanos(u64::from(1_000_000 - fraction))).await;
    }
}

/// Establish an actual session. The admitted `PeerUp`, then the actor's state
/// response, prove it owns a RIB epoch before a test fills the mailbox.
pub(super) async fn established_round_session(
    config: TransportConfig,
    session_id: u64,
    rib_tx: mpsc::Sender<RibUpdate>,
    rib_rx: &mut mpsc::Receiver<RibUpdate>,
    notify: rustbgpd_transport::SessionNotificationSender,
) -> (PeerHandle, TcpStream) {
    let (server, mut client) = super::inbound_admission::localhost_inbound_stream().await;
    let handle = PeerHandle::spawn_inbound_with_identity(
        config,
        BgpMetrics::new(),
        rib_tx,
        None,
        None,
        server,
        Some(notify),
        None,
        None,
        None,
        false,
        rustbgpd_transport::SessionIdentity::primary(session_id),
    );
    handle
        .start_inbound_timeout(0, Duration::from_secs(1))
        .await
        .unwrap();
    let mut buffer = BytesMut::new();
    assert!(matches!(
        tokio::time::timeout(
            Duration::from_secs(5),
            super::collision::read_bgp_message(&mut client, &mut buffer)
        )
        .await
        .expect("the started inbound session sends OPEN"),
        Message::Open(_)
    ));
    let mut open = super::collision::mock_open(Ipv4Addr::new(10, 0, 0, 2));
    open.capabilities.push(Capability::MultiProtocol {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
    });
    super::collision::send_bgp_message(&mut client, &Message::Open(open)).await;
    super::collision::send_bgp_message(&mut client, &Message::Keepalive).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(rib_rx.recv().await.expect("RIB lane stays open during establishment"), RibUpdate::PeerUp { session_id: id, .. } if id == session_id) {
                break;
            }
        }
    })
    .await
    .expect("the real session registers its Established epoch");
    assert_eq!(
        handle.query_state().await.unwrap().fsm_state,
        SessionState::Established
    );
    (handle, client)
}

pub(super) fn fill_round_rib(
    sender: &mpsc::Sender<RibUpdate>,
    receiver: &mut mpsc::Receiver<RibUpdate>,
) {
    while receiver.try_recv().is_ok() {}
    while sender
        .try_send(RibUpdate::ReleasePeer {
            peer: rustbgpd_rib::PeerId::UNASSIGNED,
        })
        .is_ok()
    {}
    assert_eq!(sender.capacity(), 0);
}

/// Capture the actual transition without running its manager handler.
pub(super) async fn receive_round_idle(
    receiver: &mut rustbgpd_transport::SessionNotificationReceiver,
    session_id: u64,
) -> SessionNotification {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let notification = receiver.recv().await.expect("session notice lane stays open");
            if matches!(notification, SessionNotification::BackToIdle { session_id: id, .. } if id == session_id) {
                break notification;
            }
        }
    })
    .await
    .expect("the actual session reports BackToIdle")
}

pub(super) async fn round_ping(
    sender: &mpsc::Sender<PeerManagerReadinessQuery>,
) -> oneshot::Receiver<()> {
    let (reply, response) = oneshot::channel();
    sender
        .send(PeerManagerReadinessQuery::Ping { reply })
        .await
        .unwrap();
    response
}

/// Poll each runnable task without advancing paused time. Readiness and the
/// healthy peer's completion are explicit receipts checked after this poll set.
pub(super) async fn poll_round_tasks() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

struct NotificationRoundFixture {
    manager: PeerManager,
    readiness: mpsc::Sender<PeerManagerReadinessQuery>,
    rib_rx: mpsc::Receiver<RibUpdate>,
    held_commands: Vec<mpsc::Sender<PeerCommand>>,
    healthy_commands: mpsc::Sender<PeerCommand>,
    pending_commands: Option<mpsc::Sender<PeerCommand>>,
}

impl NotificationRoundFixture {
    fn retiring_commands(&self) -> Vec<mpsc::Sender<PeerCommand>> {
        self.held_commands
            .iter()
            .cloned()
            .chain(std::iter::once(self.healthy_commands.clone()))
            .chain(self.pending_commands.iter().cloned())
            .collect()
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the fixture owns real session establishment, parked teardown, and independent healthy control together"
)]
async fn notification_round_fixture(held: usize, pending: bool) -> NotificationRoundFixture {
    let (commands, command_rx) = mpsc::channel(8);
    drop(commands);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let (readiness, readiness_rx) = mpsc::channel(4);
    let mut mgr = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx.clone(),
        None,
    )
    .with_readiness_queries(readiness_rx);
    let mut clients = Vec::new();
    let mut held_commands = Vec::new();
    for index in 0..held {
        let address = IpAddr::V4(Ipv4Addr::new(127, 0, 0, u8::try_from(index + 11).unwrap()));
        let id = u64::try_from(index + 1).unwrap();
        let config = mgr.build_transport_config(&make_config(address, 65002));
        let (handle, client) = established_round_session(
            config,
            id,
            rib_tx.clone(),
            &mut rib_rx,
            mgr.session_notify_tx.clone(),
        )
        .await;
        held_commands.push(handle.commands_sender());
        insert_test_dynamic_managed_peer(
            &mut mgr,
            address,
            id,
            handle,
            true,
            "127.0.0.0".parse().unwrap(),
            8,
            "round",
        );
        clients.push(client);
    }
    fill_round_rib(&rib_tx, &mut rib_rx);
    let mut idle = Vec::new();
    for (index, client) in clients.into_iter().enumerate() {
        drop(client);
        idle.push(
            receive_round_idle(
                &mut mgr.session_notify_rx,
                u64::try_from(index + 1).unwrap(),
            )
            .await,
        );
    }
    let mut pending_commands = None;
    if pending {
        let handle = super::command_fan_out::wedged_session();
        pending_commands = Some(handle.commands_sender());
        let peer = key("127.0.0.11".parse().unwrap());
        mgr.peers.get_mut(&peer).unwrap().pending_inbound = Some(PendingInbound {
            recovery_reset: None,
            handle,
            session_id: 99,
        });
        mgr.register_session(99, &peer);
    }
    let address = "127.0.0.100".parse().unwrap();
    let handle = PeerHandle::spawn(
        mgr.build_transport_config(&make_config(address, 65002)),
        BgpMetrics::new(),
        rib_tx,
        None,
        None,
        None,
        None,
        None,
        false,
    );
    let healthy_commands = handle.commands_sender();
    insert_test_dynamic_managed_peer(
        &mut mgr,
        address,
        100,
        handle,
        true,
        "127.0.0.0".parse().unwrap(),
        8,
        "round",
    );
    for notification in idle {
        mgr.session_notify_tx.send(notification).unwrap();
    }
    // A healthy Idle actor with no open RIB epoch is the independent control.
    mgr.session_notify_tx
        .send(SessionNotification::BackToIdle {
            session_id: 100,
            role: rustbgpd_transport::SessionRole::Primary,
            peer_addr: address,
        })
        .unwrap();
    NotificationRoundFixture {
        manager: mgr,
        readiness,
        rib_rx,
        held_commands,
        healthy_commands,
        pending_commands,
    }
}

async fn finish_notification_round(
    task: tokio::task::JoinHandle<PeerManager>,
    mut rib_rx: mpsc::Receiver<RibUpdate>,
    expected_ends: usize,
    commands: Vec<mpsc::Sender<PeerCommand>>,
) {
    let mgr = task.await.unwrap();
    assert_eq!(mgr.dynamic_peer_count, 0);
    assert!(mgr.peers.is_empty());
    assert!(
        commands.iter().all(mpsc::Sender::is_closed),
        "every primary, pending candidate and healthy actor ends before the RIB drains"
    );
    let mut ended = BTreeSet::new();
    tokio::time::timeout(Duration::from_secs(1), async {
        while ended.len() != expected_ends {
            let message = tokio::time::timeout(Duration::from_secs(1), rib_rx.recv())
                .await
                .unwrap()
                .unwrap();
            if let RibUpdate::LateSessionEnd(end) = message
                && let RibUpdate::PeerDown { session_id, .. } = *end
            {
                ended.insert(session_id);
            }
        }
    })
    .await
    .expect("every retired primary hands off its held end");
    assert_eq!(ended, (1..=u64::try_from(expected_ends).unwrap()).collect());
}

#[tokio::test(start_paused = true)]
async fn notification_round_serves_readiness_during_real_parked_retirement() {
    let clock_origin = tokio::time::Instant::now();
    tokio::time::resume();
    let fixture = notification_round_fixture(1, false).await;
    let commands = fixture.retiring_commands();
    let mut mgr = fixture.manager;
    pause_round_clock(clock_origin).await;
    let ping = round_ping(&fixture.readiness).await;
    let task = tokio::spawn(async move {
        mgr.drain_ready_session_notifications(None).await;
        mgr
    });
    tokio::time::timeout(Duration::from_millis(200), ping)
        .await
        .expect("notification retirement must serve readiness before its unchanged 200 ms deadline")
        .unwrap();
    finish_notification_round(task, fixture.rib_rx, 1, commands).await;
}

#[tokio::test(start_paused = true)]
async fn notification_round_finalizes_healthy_peer_before_held_peers() {
    let clock_origin = tokio::time::Instant::now();
    tokio::time::resume();
    let fixture = notification_round_fixture(2, false).await;
    let commands = fixture.retiring_commands();
    let mut mgr = fixture.manager;
    let metrics = mgr.metrics.clone();
    pause_round_clock(clock_origin).await;
    let started = tokio::time::Instant::now();
    let task = tokio::spawn(async move {
        mgr.drain_ready_session_notifications(None).await;
        mgr
    });
    poll_round_tasks().await;
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert!(
        fixture.healthy_commands.is_closed(),
        "the healthy actor has joined"
    );
    assert!(
        fixture
            .held_commands
            .iter()
            .all(|commands| !commands.is_closed()),
        "both held actors remain owned until their deadline"
    );
    assert_eq!(
        process_global_metric(&metrics, "bgp_dynamic_neighbor_slots_used"),
        Some(2.0),
        "the healthy peer finishes bookkeeping before either held peer's deadline"
    );
    finish_notification_round(task, fixture.rib_rx, 2, commands).await;
}

#[tokio::test(start_paused = true)]
async fn notification_round_shares_one_deadline_across_peers_and_retirement_phases() {
    let clock_origin = tokio::time::Instant::now();
    tokio::time::resume();
    let fixture = notification_round_fixture(2, true).await;
    let commands = fixture.retiring_commands();
    let mut mgr = fixture.manager;
    pause_round_clock(clock_origin).await;
    let started = tokio::time::Instant::now();
    let task = tokio::spawn(async move {
        mgr.drain_ready_session_notifications(None).await;
        mgr
    });
    poll_round_tasks().await;
    tokio::time::advance(ROUND_WINDOW).await;
    poll_round_tasks().await;
    assert!(
        task.is_finished(),
        "pending candidate, primary, and every peer share the original 500 ms round"
    );
    assert_eq!(started.elapsed(), ROUND_WINDOW);
    finish_notification_round(task, fixture.rib_rx, 2, commands).await;
}

fn attach_round_candidate(
    mgr: &mut PeerManager,
    address: IpAddr,
) -> (Arc<FakePeerCounters>, Arc<FakePeerCounters>) {
    let primary = Arc::new(FakePeerCounters::default());
    let candidate = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer_with_asn(
        mgr,
        address,
        65002,
        fake_peer_handle(address, SessionState::Idle, None, primary.clone()),
        false,
    );
    attach_test_pending_inbound(
        mgr,
        address,
        fake_peer_handle(
            address,
            SessionState::OpenConfirm,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            candidate.clone(),
        ),
        202,
    );
    (primary, candidate)
}

pub(super) fn round_breach(session_id: u64, peer_addr: IpAddr) -> SessionNotification {
    SessionNotification::MaxPrefixExceeded {
        session_id,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr,
        count: 501,
        bound: 500,
        family: None,
        received: false,
        path_limit: false,
    }
}

#[tokio::test(start_paused = true)]
async fn queued_primary_breach_remains_visible_during_candidate_open_resolution() {
    tokio::time::resume();
    let mut mgr = test_peer_manager();
    let address = "10.0.0.41".parse().unwrap();
    let (_, candidate) = attach_round_candidate(&mut mgr, address);
    let primary_id = mgr.peers[&key(address)].session_id();
    // The primary has already fallen to Idle after its cap breach; its
    // terminal notice follows a previously queued candidate OPEN.
    for notice in [
        SessionNotification::OpenReceived {
            session_id: 202,
            role: rustbgpd_transport::SessionRole::InboundCandidate,
            peer_addr: address,
            remote_router_id: Ipv4Addr::new(10, 0, 0, 2),
            peer_asn: 65002,
        },
        round_breach(primary_id, address),
        SessionNotification::BackToIdle {
            session_id: primary_id,
            role: rustbgpd_transport::SessionRole::Primary,
            peer_addr: address,
        },
    ] {
        mgr.session_notify_tx.send(notice).unwrap();
    }
    mgr.drain_ready_session_notifications(None).await;
    assert!(mgr.max_prefix_latches.contains_key(&key(address)));
    assert!(!mgr.peers[&key(address)].enabled);
    assert!(mgr.peers[&key(address)].pending_inbound.is_none());
    assert_eq!(
        candidate.activate_max_prefix_metrics.load(Ordering::SeqCst),
        0
    );
    assert!(mgr.peer_key_for_session(202).is_none());
    assert!(mgr.retiring_sessions.is_empty());
}

#[tokio::test(start_paused = true)]
async fn queued_candidate_idle_prevents_its_promotion_during_open_resolution() {
    tokio::time::resume();
    let mut mgr = test_peer_manager();
    let address = "10.0.0.42".parse().unwrap();
    let (_, candidate) = attach_round_candidate(&mut mgr, address);
    mgr.session_notify_tx
        .send(SessionNotification::OpenReceived {
            session_id: 202,
            role: rustbgpd_transport::SessionRole::InboundCandidate,
            peer_addr: address,
            remote_router_id: Ipv4Addr::new(10, 0, 0, 2),
            peer_asn: 65002,
        })
        .unwrap();
    mgr.session_notify_tx
        .send(SessionNotification::BackToIdle {
            session_id: 202,
            role: rustbgpd_transport::SessionRole::InboundCandidate,
            peer_addr: address,
        })
        .unwrap();
    mgr.drain_ready_session_notifications(None).await;
    assert_eq!(
        candidate.activate_max_prefix_metrics.load(Ordering::SeqCst),
        0
    );
    assert!(mgr.peers[&key(address)].pending_inbound.is_none());
    assert!(mgr.peer_key_for_session(202).is_none());
}

#[tokio::test(start_paused = true)]
async fn held_dynamic_retirement_does_not_expire_a_later_collision_inspection() {
    let clock_origin = tokio::time::Instant::now();
    tokio::time::resume();
    let fixture = notification_round_fixture(1, false).await;
    let mut mgr = fixture.manager;
    let address = "10.0.0.43".parse().unwrap();
    let (primary, candidate) = attach_round_candidate(&mut mgr, address);
    let primary_id = mgr.peers[&key(address)].session_id();
    mgr.session_notify_tx
        .send(SessionNotification::BackToIdle {
            session_id: primary_id,
            role: rustbgpd_transport::SessionRole::Primary,
            peer_addr: address,
        })
        .unwrap();
    pause_round_clock(clock_origin).await;
    mgr.drain_ready_session_notifications(None).await;
    assert_eq!(primary.shutdown.load(Ordering::SeqCst), 1);
    assert_eq!(
        candidate.activate_max_prefix_metrics.load(Ordering::SeqCst),
        1
    );
    assert_eq!(mgr.peers[&key(address)].session_id(), 202);
    assert!(mgr.peers[&key(address)].pending_inbound.is_none());
}

#[tokio::test(start_paused = true)]
async fn failed_stop_with_full_rib_does_not_hold_other_retirements() {
    let clock_origin = tokio::time::Instant::now();
    tokio::time::resume();
    let fixture = notification_round_fixture(2, false).await;
    let commands = fixture.retiring_commands();
    let mut mgr = fixture.manager;
    let address = "10.0.0.44".parse().unwrap();
    let handle = super::command_fan_out::wedged_session();
    let failed_commands = handle.commands_sender();
    insert_test_managed_peer(&mut mgr, address, handle, false);
    let old_id = mgr.peers[&key(address)].session_id();
    mgr.session_notify_tx
        .send(round_breach(old_id, address))
        .unwrap();
    let metrics = mgr.metrics.clone();
    pause_round_clock(clock_origin).await;
    let started = tokio::time::Instant::now();
    let task = tokio::spawn(async move {
        mgr.drain_ready_session_notifications(None).await;
        mgr
    });
    poll_round_tasks().await;
    assert!(fixture.healthy_commands.is_closed());
    assert_eq!(
        process_global_metric(&metrics, "bgp_dynamic_neighbor_slots_used"),
        Some(2.0)
    );
    tokio::time::advance(ROUND_WINDOW).await;
    poll_round_tasks().await;
    assert!(
        task.is_finished(),
        "full RIB must not fence completion of the round"
    );
    assert_eq!(started.elapsed(), ROUND_WINDOW);
    let mut mgr = task.await.unwrap();
    assert!(commands.iter().all(mpsc::Sender::is_closed));
    assert!(failed_commands.is_closed());
    assert!(!mgr.peers[&key(address)].enabled);
    assert_ne!(mgr.peers[&key(address)].session_id(), old_id);
    assert!(mgr.peer_key_for_session(old_id).is_none());
    assert!(mgr.retiring_sessions.is_empty());
    assert!(mgr.deferred_rib.queue.iter().any(|(_, update)| matches!(
        update, RibUpdate::LateSessionEnd(end)
            if matches!(end.as_ref(), RibUpdate::PeerDown { session_id, .. } if *session_id == old_id)
    )), "the delayed fence retains exact old ownership without a mailbox wait");
    // A later explicit enable remains possible while the old fence is queued.
    mgr.enable_peer(key(address)).await.unwrap();
    assert!(mgr.peers[&key(address)].enabled);
}

#[tokio::test]
async fn notification_replacement_uses_the_settled_owner_for_cleanup_and_supersession() {
    for final_owner in [Some(41), Some(42), None] {
        let (_commands, receiver) = mpsc::channel(1);
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let mut mgr = PeerManager::new(
            receiver,
            65001,
            Ipv4Addr::LOCALHOST,
            None,
            None,
            BgpMetrics::new(),
            rib_tx,
            None,
        );
        let address = "10.0.0.45".parse().unwrap();
        insert_test_managed_peer(
            &mut mgr,
            address,
            fake_peer_handle(address, SessionState::Idle, None, Arc::default()),
            false,
        );
        let (old, old_id, managed) = mgr.peers.remove(&key(address)).unwrap().into_parts();
        old.abort_for_transport_safety_and_wait().await;
        mgr.retiring_sessions.insert(old_id, key(address));
        fill_round_rib(&mgr.rib_tx, &mut rib_rx);
        mgr.next_session_id = old_id + 1;
        mgr.finish_notification_replacement(&key(address), old_id, managed, final_owner);
        let managed = &mgr.peers[&key(address)];
        assert!(
            !managed.enabled,
            "no new PeerUp is required to finish retirement"
        );
        assert_eq!(
            managed
                .handle()
                .rib_registration_owner(managed.session_id()),
            final_owner
        );
        // An inherited owner is fenced after the retired session's own id,
        // under which it may have staged context it never registered.
        let ended: Vec<u64> = mgr
            .deferred_rib
            .queue
            .iter()
            .map(|(_, update)| match update {
                RibUpdate::LateSessionEnd(end) => match end.as_ref() {
                    RibUpdate::PeerDown { session_id, .. } => *session_id,
                    _ => panic!("only session ends are deferred"),
                },
                _ => panic!("a full mailbox defers every end as a late one"),
            })
            .collect();
        let expected: Vec<u64> = match final_owner {
            Some(owner) if owner != old_id => vec![old_id, owner],
            _ => vec![old_id],
        };
        assert_eq!(ended, expected);
        assert!(mgr.peer_key_for_session(old_id).is_none());
        assert!(mgr.retiring_sessions.is_empty());
    }
}

pub(super) fn gated_round_shutdown(
    on_exit: Option<(
        rustbgpd_transport::SessionNotificationSender,
        SessionNotification,
    )>,
) -> (PeerHandle, oneshot::Receiver<()>, oneshot::Sender<()>) {
    let (commands, mut receiver) = mpsc::channel(8);
    let (entered, receipt) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let task = tokio::spawn(async move {
        assert!(matches!(receiver.recv().await, Some(PeerCommand::Shutdown)));
        entered.send(()).unwrap();
        released.await.unwrap();
        if let Some((notices, notice)) = on_exit {
            notices.send(notice).unwrap();
        }
        Ok(())
    });
    (PeerHandle::from_parts(commands, task), receipt, release)
}

fn insert_round_dynamic(mgr: &mut PeerManager, address: IpAddr, id: u64, handle: PeerHandle) {
    insert_test_dynamic_managed_peer(
        mgr,
        address,
        id,
        handle,
        true,
        "127.0.0.0".parse().unwrap(),
        8,
        "round",
    );
}

fn round_idle(session_id: u64, peer_addr: IpAddr) -> SessionNotification {
    SessionNotification::BackToIdle {
        session_id,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr,
    }
}

#[tokio::test(start_paused = true)]
async fn newly_deferred_retirements_form_one_independent_next_cohort() {
    let mut mgr = test_peer_manager();
    let (a, mut a_entered, release_a) = gated_round_shutdown(None);
    let addresses: [IpAddr; 3] = [
        "127.0.0.21".parse().unwrap(),
        "127.0.0.22".parse().unwrap(),
        "127.0.0.23".parse().unwrap(),
    ];
    let b = super::command_fan_out::wedged_session();
    let b_commands = b.commands_sender();
    let c = fake_peer_handle(addresses[2], SessionState::Idle, None, Arc::default());
    let c_commands = c.commands_sender();
    for ((address, id), handle) in addresses.into_iter().zip([1, 2, 3]).zip([a, b, c]) {
        insert_round_dynamic(&mut mgr, address, id, handle);
    }
    let notices = mgr.session_notify_tx.clone();
    notices.send(round_idle(1, addresses[0])).unwrap();
    let metrics = mgr.metrics.clone();
    let started = tokio::time::Instant::now();
    let task = tokio::spawn(async move {
        mgr.drain_ready_session_notifications(None).await;
        mgr
    });
    poll_round_tasks().await;
    a_entered
        .try_recv()
        .expect("cohort A is captured and owns its shutdown");
    notices.send(round_idle(2, addresses[1])).unwrap();
    notices.send(round_idle(3, addresses[2])).unwrap();
    release_a.send(()).unwrap();
    poll_round_tasks().await;
    assert!(
        c_commands.is_closed(),
        "healthy C joins while newly deferred B remains held"
    );
    assert!(!b_commands.is_closed());
    assert_eq!(
        process_global_metric(&metrics, "bgp_dynamic_neighbor_slots_used"),
        Some(1.0),
        "both A and C complete their owner bookkeeping"
    );
    assert_eq!(started.elapsed(), Duration::ZERO);
    tokio::time::advance(ROUND_WINDOW).await;
    poll_round_tasks().await;
    assert!(task.is_finished());
    let mgr = task.await.unwrap();
    assert_eq!(mgr.dynamic_peer_count, 0);
    assert!(mgr.retiring_sessions.is_empty());
}

#[tokio::test(start_paused = true)]
async fn late_primary_breach_during_candidate_join_does_not_hold_healthy_bookkeeping() {
    let mut mgr = test_peer_manager();
    let address: IpAddr = "10.0.0.46".parse().unwrap();
    let primary = super::command_fan_out::wedged_session();
    let primary_commands = primary.commands_sender();
    insert_test_managed_peer(&mut mgr, address, primary, false);
    let primary_id = mgr.peers[&key(address)].session_id();
    let (candidate, mut candidate_entered, release_candidate) = gated_round_shutdown(Some((
        mgr.session_notify_tx.clone(),
        round_breach(primary_id, address),
    )));
    attach_test_pending_inbound(&mut mgr, address, candidate, 2);
    let healthy_address: IpAddr = "127.0.0.24".parse().unwrap();
    let (healthy, mut healthy_entered, release_healthy) = gated_round_shutdown(None);
    let healthy_commands = healthy.commands_sender();
    insert_round_dynamic(&mut mgr, healthy_address, 100, healthy);
    mgr.next_session_id = 201;
    mgr.session_notify_tx.send(round_idle(2, address)).unwrap();
    mgr.session_notify_tx
        .send(round_idle(100, healthy_address))
        .unwrap();
    let metrics = mgr.metrics.clone();
    let started = tokio::time::Instant::now();
    let task = tokio::spawn(async move {
        mgr.drain_ready_session_notifications(None).await;
        mgr
    });
    poll_round_tasks().await;
    candidate_entered
        .try_recv()
        .expect("candidate shutdown dispatched");
    healthy_entered
        .try_recv()
        .expect("healthy shutdown dispatched");
    release_candidate.send(()).unwrap();
    poll_round_tasks().await;
    assert_eq!(
        peer_identity_gauge(&metrics, "bgp_max_prefix_latched", "10.0.0.46", ""),
        Some(1.0),
        "the late primary notice applies before the candidate's ID is forgotten"
    );
    release_healthy.send(()).unwrap();
    poll_round_tasks().await;
    assert!(healthy_commands.is_closed());
    assert!(!primary_commands.is_closed());
    assert_eq!(
        process_global_metric(&metrics, "bgp_dynamic_neighbor_slots_used"),
        Some(0.0),
        "healthy bookkeeping does not wait inside the primary's new retirement"
    );
    assert_eq!(started.elapsed(), Duration::ZERO);
    tokio::time::advance(ROUND_WINDOW).await;
    poll_round_tasks().await;
    assert!(task.is_finished());
    let mgr = task.await.unwrap();
    assert!(mgr.max_prefix_latches.contains_key(&key(address)));
    assert!(!mgr.peers[&key(address)].enabled);
    assert!(mgr.retiring_sessions.is_empty());
}

/// A collision candidate that reports `notice` as it takes over the peer's
/// max-prefix metrics: the last command of its promotion, after the old
/// primary's retirement drain.
fn candidate_reporting_on_activation(
    address: IpAddr,
    notices: rustbgpd_transport::SessionNotificationSender,
    notice: SessionNotification,
) -> PeerHandle {
    let (commands, mut receiver) = mpsc::channel(8);
    let task = tokio::spawn(async move {
        let mut notice = Some(notice);
        while let Some(command) = receiver.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(policy_test_peer_state(address, SessionState::OpenConfirm));
                }
                PeerCommand::ClaimCollisionPromotion { reply } => {
                    let _ = reply.send(true);
                }
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. }
                | PeerCommand::UpdateGracefulShutdown { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::UpdateRuntimeConfig { reply, .. } => {
                    let _ = reply.send(Ok(false));
                }
                PeerCommand::ActivateMaxPrefixMetrics { reply, .. } => {
                    if let Some(notice) = notice.take() {
                        notices.send(notice).unwrap();
                    }
                    let _ = reply.send(());
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(commands, task)
}

/// An inbound accept drains the session notices first so a queued max-prefix
/// latch is applied before the connection is admitted. That needs the channel
/// empty when the drain returns: a notice queued while an earlier one was
/// being handled, after that handler's last look at the channel, is handled
/// by the same drain.
#[tokio::test]
async fn depth_zero_drain_applies_a_notice_queued_while_an_earlier_one_was_handled() {
    let mut mgr = test_peer_manager();
    let address: IpAddr = "10.0.0.47".parse().unwrap();
    insert_test_managed_peer_with_asn(
        &mut mgr,
        address,
        65002,
        fake_peer_handle(address, SessionState::Idle, None, Arc::default()),
        false,
    );
    let primary_id = mgr.peers[&key(address)].session_id();
    let candidate = candidate_reporting_on_activation(
        address,
        mgr.session_notify_tx.clone(),
        round_breach(202, address),
    );
    attach_test_pending_inbound(&mut mgr, address, candidate, 202);
    mgr.session_notify_tx
        .send(round_idle(primary_id, address))
        .unwrap();

    mgr.drain_ready_session_notifications(None).await;

    assert_eq!(
        mgr.peers[&key(address)].session_id(),
        202,
        "the candidate was promoted"
    );
    assert!(
        mgr.max_prefix_latches.contains_key(&key(address)),
        "the breach it reported during the promotion is latched before the drain returns"
    );
    assert!(!mgr.peers[&key(address)].enabled);
    assert_eq!(mgr.session_notify_rx.ready_count(), 0);
}
