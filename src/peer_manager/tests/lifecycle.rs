use super::*;

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
