use super::*;

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
