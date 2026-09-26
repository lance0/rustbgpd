use super::*;

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

#[expect(
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
                        rejected_routes_retained: 0,
                        policy_reject_counts: None,
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
                        reconnect_in_secs: 0,
                        notification_idle_failures: 0,
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

    let notification = tokio::time::timeout(Duration::from_secs(2), mgr.session_notify_rx.recv())
        .await
        .expect("candidate should notify OpenReceived")
        .expect("notification channel should stay open");
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
        | SessionNotification::MaxPrefixExceeded { .. }
        | SessionNotification::MaxPrefixWarning { .. }) => {
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
        let state = managed.handle().query_state().await.expect("query state");
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
            received: false,
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
    assert_eq!(managed.session_id(), 1);
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
                            received: false,
                        })
                        .unwrap();
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Idle,
                        peer_ip: peer_addr,
                        peer_asn: Some(65002),
                        prefix_count: 0,
                        rejected_routes_retained: 0,
                        policy_reject_counts: None,
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
                        reconnect_in_secs: 0,
                        notification_idle_failures: 0,
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
    assert_eq!(managed.session_id(), 1);
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
        managed.session_id(),
        1,
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
        managed.session_id(),
        1,
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
            .is_some_and(|m| m.pending_inbound.is_none() && m.session_id() == 1),
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
            .is_some_and(|m| m.pending_inbound.is_none() && m.session_id() == 2),
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
            .is_some_and(|m| m.pending_inbound.is_none() && m.session_id() == 1),
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
            .is_some_and(|m| m.pending_inbound.is_none() && m.session_id() == 1),
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
            .is_some_and(|m| m.pending_inbound.is_none() && m.session_id() == 2),
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
                PeerCommand::ActivateMaxPrefixMetrics { reply, .. } => {
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
            .is_some_and(|managed| managed.session_id() == 2 && managed.pending_inbound.is_none())
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
            .is_some_and(|m| m.pending_inbound.is_some() && m.session_id() == 1),
        "stale notifications must not drop or promote live sessions"
    );
}

#[tokio::test]
async fn stale_max_prefix_warnings_are_not_published() {
    let mut mgr = test_peer_manager();
    let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        peer_addr,
        fake_peer_handle(peer_addr, SessionState::Established, None, counters),
        false,
    );
    let mut live_events = mgr.session_events_tx.subscribe();
    mgr.register_session(99, &key(peer_addr));

    for session_id in [99, 100] {
        mgr.handle_session_notification(SessionNotification::MaxPrefixWarning {
            session_id,
            role: rustbgpd_transport::SessionRole::Primary,
            peer_addr,
            scope: "ipv4_unicast",
            usage: 80,
            bound: 100,
            percent: 80,
        })
        .await;
    }

    assert!(live_events.try_recv().is_err());
    assert!(
        query_session_event_history(
            &mgr,
            Some(peer_addr),
            [SessionLifecycleEventType::MaxPrefixWarning]
                .into_iter()
                .collect(),
            0,
        )
        .await
        .is_empty()
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
        mpsc::channel(1).1,
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

    let session_id = mgr.peers.get(&key(peer_addr)).unwrap().session_id();
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
        mpsc::channel(1).1,
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

/// RFC 4271 §6.8: "a connection collision cannot be detected with connections
/// that are in Idle, Connect, or Active states." A candidate that has received
/// the peer's OPEN while the primary has no connection is the only live
/// connection, so it is promoted even when the local identifier is higher.
/// Dropping it instead livelocks against a peer that keeps connecting in.
async fn assert_candidate_promoted_over_connectionless_primary(primary_state: SessionState) {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 10),
        None,
        None,
        BgpMetrics::new(),
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
        fake_peer_handle(peer_addr, primary_state, None, primary.clone()),
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

    // Resolution joins the retired primary before returning, so the counters
    // are final here.
    assert_eq!(
        pending.collision_dump.load(Ordering::SeqCst),
        0,
        "{primary_state:?} primary: the only live connection must not be dumped"
    );
    assert_eq!(
        primary.shutdown.load(Ordering::SeqCst),
        1,
        "{primary_state:?} primary and its connect attempt must be stopped and joined"
    );
    assert_eq!(
        primary.collision_dump.load(Ordering::SeqCst),
        0,
        "{primary_state:?} primary has no connection to send Cease 6/7 on"
    );
    assert_eq!(
        pending.activate_max_prefix_metrics.load(Ordering::SeqCst),
        1,
        "promotion must transfer metric ownership"
    );
    assert!(
        mgr.peers
            .get(&key(peer_addr))
            .is_some_and(|m| m.pending_inbound.is_none() && m.session_id() == 2),
        "{primary_state:?} primary: the candidate must become the primary"
    );
    assert_eq!(
        mgr.peer_key_for_session(1),
        None,
        "retired primary unregistered"
    );

    // Late signals from the retired primary (its outbound connect completing
    // and reading an OPEN, or its Idle transition) must not start a second
    // collision round against the promoted session.
    mgr.handle_session_notification(SessionNotification::OpenReceived {
        session_id: 1,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr,
        remote_router_id: Ipv4Addr::new(10, 0, 0, 2),
        peer_asn: 65002,
    })
    .await;
    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id: 1,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr,
    })
    .await;
    assert_eq!(pending.collision_dump.load(Ordering::SeqCst), 0);
    assert_eq!(pending.shutdown.load(Ordering::SeqCst), 0);
    assert!(
        mgr.peers
            .get(&key(peer_addr))
            .is_some_and(|m| m.pending_inbound.is_none() && m.session_id() == 2),
        "stale signals from the retired primary must not touch the promoted session"
    );
}

#[tokio::test]
async fn collision_primary_active_promotes_inbound_despite_higher_local_id() {
    assert_candidate_promoted_over_connectionless_primary(SessionState::Active).await;
}

#[tokio::test]
async fn collision_primary_connect_promotes_inbound_despite_higher_local_id() {
    assert_candidate_promoted_over_connectionless_primary(SessionState::Connect).await;
}

#[tokio::test]
async fn collision_primary_idle_promotes_inbound_despite_higher_local_id() {
    // Reachable when the primary has dropped to Idle but its BackToIdle
    // notification is still queued behind the candidate's OpenReceived.
    assert_candidate_promoted_over_connectionless_primary(SessionState::Idle).await;
}

#[tokio::test]
async fn collision_primary_established_keeps_primary_even_when_remote_id_higher() {
    // RFC 4271 §6.8: a collision with an Established connection closes the
    // newly created one, whatever the identifiers say.
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
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

    assert_eq!(pending.collision_dump.load(Ordering::SeqCst), 1);
    assert_eq!(primary.collision_dump.load(Ordering::SeqCst), 0);
    assert_eq!(primary.shutdown.load(Ordering::SeqCst), 0);
    assert!(
        mgr.peers
            .get(&key(peer_addr))
            .is_some_and(|m| m.pending_inbound.is_none() && m.session_id() == 1),
        "an Established primary must survive a late candidate OPEN"
    );
}

/// Accept a real inbound connection for `peer_addr` (loopback) and return the
/// remote end after the manager has started it as a live collision candidate.
async fn accept_real_candidate(mgr: &mut PeerManager, peer_addr: IpAddr) -> TcpStream {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();
    mgr.handle_inbound(server_stream, remote_addr, None, None)
        .await;
    assert!(
        mgr.peers
            .get(&key(peer_addr))
            .is_some_and(|m| m.pending_inbound.is_some()),
        "inbound socket should become a live collision candidate"
    );
    client_stream
}

async fn next_candidate_open_received(mgr: &mut PeerManager) -> SessionNotification {
    let notification = tokio::time::timeout(Duration::from_secs(2), mgr.session_notify_rx.recv())
        .await
        .expect("candidate should notify OpenReceived")
        .expect("notification channel should stay open");
    assert!(
        matches!(
            notification,
            SessionNotification::OpenReceived {
                role: rustbgpd_transport::SessionRole::InboundCandidate,
                ..
            }
        ),
        "expected candidate OpenReceived, got {notification:?}"
    );
    notification
}

/// Send the peer's OPEN and its KEEPALIVE together, as a peer that already
/// has our OPEN does, and wait until the candidate has reported the OPEN.
async fn candidate_open_exchange(
    mgr: &mut PeerManager,
    client: &mut TcpStream,
    buf: &mut BytesMut,
) -> SessionNotification {
    let msg = tokio::time::timeout(Duration::from_secs(2), read_bgp_message(client, buf))
        .await
        .expect("candidate must send OPEN");
    assert!(matches!(msg, Message::Open(_)));
    let mut bytes = encode_message(&Message::Open(mock_open(Ipv4Addr::new(10, 0, 0, 2)))).unwrap();
    bytes.extend(encode_message(&Message::Keepalive).unwrap());
    client.write_all(&bytes).await.unwrap();
    next_candidate_open_received(mgr).await
}

async fn pending_candidate_state(mgr: &PeerManager, peer_addr: IpAddr) -> SessionState {
    mgr.peers[&key(peer_addr)]
        .pending_inbound
        .as_ref()
        .expect("candidate still pending")
        .handle
        .query_state()
        .await
        .unwrap()
        .fsm_state
}

/// The M81 interleaving end to end: the primary sits in Active with no
/// connection and the peer connects in. The candidate holds in `OpenConfirm`
/// until the manager resolves its OPEN, then promotion completes the
/// handshake. With a higher local identifier the candidate must still be kept.
#[tokio::test]
async fn inbound_candidate_held_while_primary_active_is_promoted() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 255, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let peer_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    // The helper-inserted primary is session 1; keep the candidate distinct.
    let _ = mgr.allocate_session_id();
    let primary = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        fake_peer_handle(peer_addr, SessionState::Active, None, primary.clone()),
        false,
    );

    let mut client = accept_real_candidate(&mut mgr, peer_addr).await;
    let mut buf = BytesMut::with_capacity(4096);
    let notification = candidate_open_exchange(&mut mgr, &mut client, &mut buf).await;
    assert_eq!(
        pending_candidate_state(&mgr, peer_addr).await,
        SessionState::OpenConfirm,
        "the candidate must wait for the verdict despite the peer KEEPALIVE"
    );

    mgr.handle_session_notification(notification).await;

    assert_eq!(primary.shutdown.load(Ordering::SeqCst), 1);
    let msg = tokio::time::timeout(
        Duration::from_secs(2),
        read_bgp_message(&mut client, &mut buf),
    )
    .await
    .expect("promotion must release the held KEEPALIVE");
    assert!(matches!(msg, Message::Keepalive));
    let managed = &mgr.peers[&key(peer_addr)];
    assert!(managed.pending_inbound.is_none() && managed.session_id() != 1);
    assert_eq!(
        managed.handle().query_state().await.unwrap().fsm_state,
        SessionState::Established,
        "the promoted inbound session consumes the buffered KEEPALIVE"
    );
}

/// A true simultaneous open that the local identifier wins: the candidate has
/// the peer's OPEN and KEEPALIVE, the primary is in `OpenConfirm`. The
/// candidate is never Established, never registers with the RIB, and is
/// closed with Cease 6/7 before it ever sends a KEEPALIVE.
#[tokio::test]
async fn collision_loser_is_closed_from_open_confirm_without_keepalive() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 255, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let peer_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let _ = mgr.allocate_session_id();
    let primary = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        fake_peer_handle(peer_addr, SessionState::OpenSent, None, primary.clone()),
        false,
    );
    let mut client = accept_real_candidate(&mut mgr, peer_addr).await;
    // The primary's own connection reaches OpenConfirm before the verdict.
    let session_id = mgr.peers[&key(peer_addr)].session_id();
    let (accept_handle, _) = mgr
        .peers
        .replace_handle(
            &key(peer_addr),
            fake_peer_handle(
                peer_addr,
                SessionState::OpenConfirm,
                Some(Ipv4Addr::new(10, 0, 0, 2)),
                primary.clone(),
            ),
            session_id,
        )
        .unwrap();
    let _ = accept_handle.shutdown().await;

    let mut buf = BytesMut::with_capacity(4096);
    let notification = candidate_open_exchange(&mut mgr, &mut client, &mut buf).await;
    assert_eq!(
        pending_candidate_state(&mgr, peer_addr).await,
        SessionState::OpenConfirm
    );

    mgr.handle_session_notification(notification).await;

    assert_eq!(primary.collision_dump.load(Ordering::SeqCst), 0);
    assert!(
        mgr.peers
            .get(&key(peer_addr))
            .is_some_and(|m| m.pending_inbound.is_none() && m.session_id() == 1),
        "the OpenConfirm primary with the higher local identifier must win"
    );
    let msg = tokio::time::timeout(
        Duration::from_secs(2),
        read_bgp_message(&mut client, &mut buf),
    )
    .await
    .expect("the loser must be closed");
    let Message::Notification(notification) = msg else {
        panic!("the loser sent {msg:?} before its Cease; the peer saw a KEEPALIVE");
    };
    assert_eq!(
        notification.code,
        rustbgpd_wire::notification::NotificationCode::Cease
    );
    assert_eq!(
        notification.subcode,
        rustbgpd_wire::notification::cease_subcode::CONNECTION_COLLISION_RESOLUTION
    );
    while let Ok(update) = rib_rx.try_recv() {
        assert!(
            !matches!(update, rustbgpd_rib::RibUpdate::PeerUp { .. }),
            "the collision loser must never register with the RIB"
        );
    }
}

/// The resolution rule reads the primary's state when the OPEN arrives, not
/// the state seen when the connection was accepted: a primary that was Active
/// at accept time but has since reached `OpenConfirm` on its own connection is a
/// real collision, and the higher local identifier keeps it.
#[tokio::test]
async fn collision_rule_uses_primary_state_at_resolution_not_accept() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 255, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let peer_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let _ = mgr.allocate_session_id();
    let accept_time = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        fake_peer_handle(peer_addr, SessionState::Active, None, accept_time.clone()),
        false,
    );
    let mut client = accept_real_candidate(&mut mgr, peer_addr).await;
    assert_eq!(accept_time.query_state.load(Ordering::SeqCst), 1);

    // The primary's own outbound connection completes its OPEN exchange
    // before the candidate's OPEN arrives.
    let resolution_time = Arc::new(FakePeerCounters::default());
    let session_id = mgr.peers[&key(peer_addr)].session_id();
    let (accept_handle, _) = mgr
        .peers
        .replace_handle(
            &key(peer_addr),
            fake_peer_handle(
                peer_addr,
                SessionState::OpenConfirm,
                Some(Ipv4Addr::new(10, 0, 0, 2)),
                resolution_time.clone(),
            ),
            session_id,
        )
        .unwrap();
    let _ = accept_handle.shutdown().await;

    let mut buf = BytesMut::with_capacity(4096);
    let msg = tokio::time::timeout(
        Duration::from_secs(2),
        read_bgp_message(&mut client, &mut buf),
    )
    .await
    .expect("candidate must send OPEN");
    assert!(matches!(msg, Message::Open(_)));
    send_bgp_message(
        &mut client,
        &Message::Open(mock_open(Ipv4Addr::new(10, 0, 0, 2))),
    )
    .await;
    let notification = next_candidate_open_received(&mut mgr).await;
    mgr.handle_session_notification(notification).await;

    assert_eq!(resolution_time.collision_dump.load(Ordering::SeqCst), 0);
    assert!(
        mgr.peers
            .get(&key(peer_addr))
            .is_some_and(|m| m.pending_inbound.is_none() && m.session_id() == 1),
        "an OpenConfirm primary with the higher local identifier must win"
    );
    loop {
        let msg = tokio::time::timeout(
            Duration::from_secs(2),
            read_bgp_message(&mut client, &mut buf),
        )
        .await
        .expect("dropped candidate must send a NOTIFICATION");
        if let Message::Notification(notification) = msg {
            assert_eq!(
                notification.code,
                rustbgpd_wire::notification::NotificationCode::Cease
            );
            assert_eq!(
                notification.subcode,
                rustbgpd_wire::notification::cease_subcode::CONNECTION_COLLISION_RESOLUTION
            );
            break;
        }
    }
}

/// A candidate whose collision verdict times out while `PeerManager` is busy
/// elsewhere falls to Idle and queues `BackToIdle` behind its own, still
/// unprocessed `OpenReceived`. When the manager resumes, that stale report must
/// not promote the dead candidate over the primary: the primary would be
/// retired and a closed session left in its place.
#[tokio::test]
async fn stale_open_received_after_verdict_timeout_does_not_promote_candidate() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 255, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let peer_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let _ = mgr.allocate_session_id();
    let primary = Arc::new(FakePeerCounters::default());
    // An Active primary has no connection, so a live candidate would be
    // promoted by the no-primary-connection rule.
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        fake_peer_handle(peer_addr, SessionState::Active, None, primary.clone()),
        false,
    );
    let mut client = accept_real_candidate(&mut mgr, peer_addr).await;
    let mut buf = BytesMut::with_capacity(4096);
    let stale = candidate_open_exchange(&mut mgr, &mut client, &mut buf).await;

    // The manager is blocked: `stale` is held while the candidate's verdict
    // timer (10 s in the transport) expires on the paused clock.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    // Handshake: the candidate has closed from OpenConfirm. Its Idle
    // transition, and so its `BackToIdle`, ran in the same batch as this
    // NOTIFICATION, before the writer task could send it.
    loop {
        if let Message::Notification(notification) = read_bgp_message(&mut client, &mut buf).await {
            assert_eq!(
                notification.code,
                rustbgpd_wire::notification::NotificationCode::HoldTimerExpired
            );
            break;
        }
    }

    mgr.handle_session_notification(stale).await;

    assert_eq!(
        primary.shutdown.load(Ordering::SeqCst),
        0,
        "the primary must not be retired for a dead candidate"
    );
    let managed = &mgr.peers[&key(peer_addr)];
    assert!(
        managed.pending_inbound.is_none(),
        "the dead candidate is dropped"
    );
    assert_eq!(managed.session_id(), 1, "the primary keeps ownership");
}

/// A startup burst queues one collision OPEN per peer while each primary is
/// still in `Active`. Every promotion drains the queue before it transfers
/// ownership; that drain must not resolve the other peers' collisions inside
/// itself, or nesting grows with the burst and overflows the worker stack.
/// Mutation-red: handling every peer's notification inside a nested drain
/// aborts this test with a stack overflow.
#[test]
fn collision_promotion_burst_does_not_nest_one_level_per_peer() {
    const PEERS: u8 = 128;
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(async {
                    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
                    let (rib_tx, _rib_rx) = mpsc::channel(1024);
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
                    let addrs: Vec<IpAddr> = (1..=PEERS)
                        .map(|i| IpAddr::V4(Ipv4Addr::new(10, 1, 0, i)))
                        .collect();
                    for (&peer_addr, candidate) in addrs.iter().zip(1001_u64..) {
                        let counters = Arc::new(FakePeerCounters::default());
                        insert_test_managed_peer_with_asn(
                            &mut mgr,
                            peer_addr,
                            65002,
                            fake_peer_handle(
                                peer_addr,
                                SessionState::Active,
                                None,
                                counters.clone(),
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
                                counters,
                            ),
                            candidate,
                        );
                        mgr.session_notify_tx
                            .send(SessionNotification::OpenReceived {
                                session_id: candidate,
                                role: rustbgpd_transport::SessionRole::InboundCandidate,
                                peer_addr,
                                remote_router_id: Ipv4Addr::new(10, 0, 0, 2),
                                peer_asn: 65002,
                            })
                            .expect("notification queued");
                    }

                    mgr.drain_ready_session_notifications(Some(&key(addrs[0])))
                        .await;

                    for (peer_addr, candidate) in addrs.iter().zip(1001_u64..) {
                        assert!(
                            mgr.peers.get(&key(*peer_addr)).is_some_and(|m| {
                                m.pending_inbound.is_none() && m.session_id() == candidate
                            }),
                            "every queued candidate must be promoted: {peer_addr}"
                        );
                    }
                    assert!(mgr.deferred_session_notifications.is_empty());
                });
        })
        .expect("spawn burst thread")
        .join()
        .expect("burst thread");
}

/// Link-local neighbors on different interfaces share an address. A fence
/// for one must not handle the other's notification: the owner is resolved
/// through the session, not the address.
/// Mutation-red: matching nested drains on `peer_addr` promotes eth1's
/// candidate inside eth0's fence.
#[tokio::test]
async fn nested_drain_defers_same_address_peer_on_another_interface() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
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
    let addr: IpAddr = "fe80::2".parse().unwrap();
    let (eth0, eth1) = (scoped_key(addr, "eth0"), scoped_key(addr, "eth1"));
    for (peer_key, candidate) in [(&eth0, 11), (&eth1, 12)] {
        insert_active_peer_with_candidate(&mut mgr, peer_key, candidate);
    }
    queue_candidate_open(&mgr, 12, addr);

    // Inside a handler, fencing eth0.
    mgr.session_notification_depth = 1;
    mgr.drain_ready_session_notifications(Some(&eth0)).await;
    assert!(
        mgr.peers[&eth1].pending_inbound.is_some(),
        "eth0's fence must not resolve eth1's collision"
    );
    assert_eq!(mgr.deferred_session_notifications.len(), 1);
    assert_eq!(
        mgr.deferred_session_notification_counts.get(&eth1),
        Some(&1)
    );

    // The fence for eth1 takes its deferred notice back, after the lifecycle
    // events queued before it, as a notice taken from the channel would be.
    queue_state_changed(&mgr, 11, addr);
    mgr.drain_ready_session_notifications(Some(&eth1)).await;
    assert!(
        mgr.session_lifecycle_rx.is_empty(),
        "a deferred notice is handled after the ready lifecycle events"
    );
    assert!(mgr.deferred_session_notifications.is_empty());
    assert!(mgr.deferred_session_notification_counts.is_empty());
    assert!(
        mgr.peers[&eth1].pending_inbound.is_none() && mgr.peers[&eth1].session_id() == 12,
        "eth1's own fence handles its notification"
    );
    mgr.session_notification_depth = 0;

    // The outermost handler drains ready lifecycle events before each
    // deferred notice too. MaxPrefixWarning from an unknown session returns
    // without draining anything itself.
    let (eth2, eth3) = (scoped_key(addr, "eth2"), scoped_key(addr, "eth3"));
    for (peer_key, candidate) in [(&eth2, 21), (&eth3, 22)] {
        insert_active_peer_with_candidate(&mut mgr, peer_key, candidate);
    }
    mgr.session_notification_depth = 1;
    queue_candidate_open(&mgr, 22, addr);
    mgr.drain_ready_session_notifications(Some(&eth2)).await;
    assert_eq!(mgr.deferred_session_notifications.len(), 1);
    mgr.session_notification_depth = 0;
    queue_state_changed(&mgr, 21, addr);
    mgr.handle_session_notification(SessionNotification::MaxPrefixWarning {
        session_id: 999,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr: addr,
        scope: "aggregate",
        usage: 1,
        bound: 2,
        percent: 50,
    })
    .await;
    assert!(mgr.deferred_session_notifications.is_empty());
    assert!(
        mgr.peers[&eth3].pending_inbound.is_none() && mgr.peers[&eth3].session_id() == 22,
        "the outermost handler handles the deferred notice"
    );
    assert!(
        mgr.session_lifecycle_rx.is_empty(),
        "the outermost handler drains lifecycle events before a deferred notice"
    );
}

fn queue_state_changed(mgr: &PeerManager, session_id: u64, peer_addr: IpAddr) {
    mgr.session_lifecycle_tx
        .try_send(
            rustbgpd_transport::SessionLifecycleNotification::StateChanged {
                session_id,
                role: rustbgpd_transport::SessionRole::Primary,
                peer_addr,
                peer_asn: None,
                old: SessionState::Idle,
                new: SessionState::Connect,
            },
        )
        .unwrap();
}

fn insert_active_peer_with_candidate(mgr: &mut PeerManager, peer_key: &PeerKey, candidate: u64) {
    let addr = peer_key.address;
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer_for_key(
        mgr,
        peer_key,
        65002,
        fake_peer_handle(addr, SessionState::Active, None, counters.clone()),
        false,
    );
    mgr.peers.get_mut(peer_key).unwrap().pending_inbound = Some(PendingInbound {
        handle: fake_peer_handle(
            addr,
            SessionState::OpenConfirm,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            counters,
        ),
        session_id: candidate,
    });
    mgr.register_session(candidate, peer_key);
}

fn queue_candidate_open(mgr: &PeerManager, session_id: u64, peer_addr: IpAddr) {
    mgr.session_notify_tx
        .send(SessionNotification::OpenReceived {
            session_id,
            role: rustbgpd_transport::SessionRole::InboundCandidate,
            peer_addr,
            remote_router_id: Ipv4Addr::new(10, 0, 0, 2),
            peer_asn: 65002,
        })
        .unwrap();
}
