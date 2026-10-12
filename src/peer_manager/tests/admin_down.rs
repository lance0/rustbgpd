use super::*;

/// Session stub that records every `Stop` reason and counts `Start`, and keeps
/// running across both so a down/up cycle stays observable.
fn recording_admin_handle() -> (
    PeerHandle,
    Arc<AtomicU32>,
    mpsc::UnboundedReceiver<Option<bytes::Bytes>>,
) {
    use rustbgpd_transport::PeerCommand;

    let starts = Arc::new(AtomicU32::new(0));
    let (stop_tx, stop_rx) = mpsc::unbounded_channel();
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let task_starts = starts.clone();
    let task = tokio::spawn(async move {
        while let Some(command) = session_rx.recv().await {
            match command {
                PeerCommand::Start => {
                    task_starts.fetch_add(1, Ordering::SeqCst);
                }
                PeerCommand::Stop { reason } => {
                    let _ = stop_tx.send(reason);
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    (PeerHandle::from_parts(session_tx, task), starts, stop_rx)
}

/// Barrier: the stub drops a `QueryState` reply only after every earlier
/// command, so once the query returns, earlier stops and starts are recorded.
async fn settle(mgr: &PeerManager, addr: IpAddr) {
    let _ = mgr.get_peer_info(&key(addr)).await;
}

/// The peer's live config as a forward reload target, not a rollback prior.
fn forward_config(mgr: &PeerManager, addr: IpAddr) -> PeerManagerNeighborConfig {
    let mut config = PeerManager::removed_peer_config(&key(addr), &mgr.peers[&key(addr)]);
    config.restore_admin_enabled = None;
    config
}

/// Regression: a daemon (re)started with `admin_down` set never offers that
/// peer an OPEN. The configured-peer startup batch adds it disabled: its
/// session is never started (so it stays Idle and never connects), the admin
/// gauge reads 0, and an inbound connection is closed before any OPEN.
#[tokio::test]
async fn configured_admin_down_peer_boots_disabled_and_never_sends_open() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut config = make_config(addr, 65002);
    config.admin_down = Some("quarantined".to_string());

    mgr.add_configured_peers(vec![config]).await.unwrap();

    let info = mgr
        .get_peer_info(&key(addr))
        .await
        .expect("peer stays listed");
    assert!(
        !info.enabled,
        "config admin_down must add the peer disabled"
    );
    // Start is sent before the add returns and the session task handles
    // commands in order, so a started session would already report Connect.
    assert_eq!(info.state, SessionState::Idle, "no connection attempt");
    assert_eq!(
        peer_identity_gauge(&mgr.metrics, "bgp_peer_admin_enabled", "127.0.0.1", ""),
        Some(0.0)
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let mut client_stream = client.await.unwrap();
    mgr.handle_inbound(server_stream, remote_addr, None, None)
        .await;

    let mut buf = [0_u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(2), client_stream.read(&mut buf))
        .await
        .expect("refused inbound socket must close promptly");
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "admin-down peer must not answer an inbound connection: {read:?}"
    );
    assert!(!mgr.peers[&key(addr)].enabled);
}

/// Reload edges on the in-place path reuse the operator disable/enable
/// paths, and an unchanged key keeps the runtime toggle.
#[tokio::test]
async fn config_admin_down_hot_edges_disable_enable_and_keep_runtime_toggle() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (handle, starts, mut stops) = recording_admin_handle();
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let current = forward_config(&mgr, addr);
    let mut down = current.clone();
    down.admin_down = Some("maintenance".to_string());

    // Setting the key sends Cease/Administrative Shutdown with the reason.
    mgr.hot_update_peer_in_place(down.clone()).await.unwrap();
    settle(&mgr, addr).await;
    assert_eq!(
        stops.try_recv().unwrap(),
        Some(rustbgpd_wire::notification::encode_shutdown_communication(
            "maintenance"
        ))
    );
    assert!(!mgr.peers[&key(addr)].enabled);
    assert_eq!(
        peer_identity_gauge(&mgr.metrics, "bgp_peer_admin_enabled", "10.0.0.2", ""),
        Some(0.0)
    );

    // Clearing it enables the peer.
    mgr.hot_update_peer_in_place(current.clone()).await.unwrap();
    settle(&mgr, addr).await;
    assert!(mgr.peers[&key(addr)].enabled);
    assert_eq!(starts.load(Ordering::SeqCst), 1);

    // A runtime enable of a config-down peer survives a reload that keeps
    // the key: only a change to `admin_down` overrides the toggle.
    mgr.hot_update_peer_in_place(down.clone()).await.unwrap();
    assert!(!mgr.peers[&key(addr)].enabled);
    settle(&mgr, addr).await;
    assert!(stops.try_recv().unwrap().is_some());
    mgr.enable_peer(key(addr)).await.unwrap();
    settle(&mgr, addr).await;
    assert_eq!(starts.load(Ordering::SeqCst), 2);
    let mut unchanged_key = down.clone();
    unchanged_key.description = "renamed".to_string();
    mgr.hot_update_peer_in_place(unchanged_key).await.unwrap();
    settle(&mgr, addr).await;
    assert!(mgr.peers[&key(addr)].enabled);
    assert_eq!(mgr.peers[&key(addr)].description, "renamed");
    assert!(
        stops.try_recv().is_err(),
        "unchanged key must not stop the peer"
    );

    // A reason-only edit is bookkeeping; the peer keeps its runtime state.
    let mut new_reason = down;
    new_reason.admin_down = Some("extended".to_string());
    mgr.hot_update_peer_in_place(new_reason).await.unwrap();
    settle(&mgr, addr).await;
    assert!(mgr.peers[&key(addr)].enabled);
    assert_eq!(
        mgr.peers[&key(addr)].admin_down.as_deref(),
        Some("extended")
    );
    assert!(stops.try_recv().is_err());
    assert_eq!(starts.load(Ordering::SeqCst), 2);
}

/// The session-replacing reload path applies the same rule: the key decides
/// the re-added admin state only when it changed.
#[tokio::test]
async fn config_admin_down_replacement_follows_key_changes_only() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut config = make_config(addr, 65002);
    config.admin_down = Some(String::new());
    mgr.add_configured_peers(vec![config.clone()])
        .await
        .unwrap();
    assert!(!mgr.peers[&key(addr)].enabled);

    // Runtime enable, then a session-reset edit that keeps the key.
    mgr.enable_peer(key(addr)).await.unwrap();
    config.hold_time = Some(30);
    mgr.reconfigure_peer(config.clone()).await.unwrap();
    assert!(
        mgr.peers[&key(addr)].enabled,
        "unchanged key keeps runtime enable"
    );

    // Runtime disable, then clear the key in a session-reset edit: enabled.
    mgr.disable_peer(key(addr), None).await.unwrap();
    config.admin_down = None;
    config.hold_time = Some(45);
    mgr.reconfigure_peer(config.clone()).await.unwrap();
    assert!(
        mgr.peers[&key(addr)].enabled,
        "cleared key enables the peer"
    );

    // Set it again together with another session-reset edit: disabled.
    config.admin_down = Some("bye".to_string());
    config.hold_time = Some(60);
    mgr.reconfigure_peer(config).await.unwrap();
    assert!(!mgr.peers[&key(addr)].enabled, "set key disables the peer");
    assert_eq!(mgr.peers[&key(addr)].admin_down.as_deref(), Some("bye"));
}

/// A replacement that also sets the key closes the Established session with
/// the configured shutdown communication, like the in-place disable.
#[tokio::test]
async fn config_admin_down_replacement_sends_the_configured_reason() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let (handle, starts, mut stops) = recording_admin_handle();
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let mut next = forward_config(&mgr, addr);
    next.admin_down = Some("abuse review".to_string());
    next.hold_time = Some(30);

    mgr.reconfigure_peer(next).await.unwrap();

    assert_eq!(
        stops.recv().await.expect("old session receives Stop"),
        Some(rustbgpd_wire::notification::encode_shutdown_communication(
            "abuse review"
        ))
    );
    let managed = &mgr.peers[&key(addr)];
    assert!(!managed.enabled);
    assert_eq!(managed.hold_time, Some(30));
    assert_eq!(starts.load(Ordering::SeqCst), 0);
}

/// The sequential reload route rebuilds through `reconcile_peers`. A rebuild
/// that also sets the key (here with a GTSM change, which keeps a candidate
/// on that route) closes the session with the configured reason too.
#[tokio::test]
async fn sequential_rebuild_that_sets_admin_down_sends_the_configured_reason() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let (handle, starts, mut stops) = recording_admin_handle();
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let mut next = forward_config(&mgr, addr);
    next.admin_down = Some("gtsm rollout".to_string());
    next.ttl_security_hops = std::num::NonZeroU8::new(1);

    let outcome = mgr
        .reconcile_peers(Vec::new(), Vec::new(), vec![next])
        .await;

    assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
    assert_eq!(
        stops.recv().await.expect("old session receives Stop"),
        Some(rustbgpd_wire::notification::encode_shutdown_communication(
            "gtsm rollout"
        ))
    );
    let managed = &mgr.peers[&key(addr)];
    assert!(!managed.enabled);
    assert_eq!(
        managed.transport_config.ttl_security_hops,
        std::num::NonZeroU8::new(1)
    );
    assert_eq!(starts.load(Ordering::SeqCst), 0);
}

/// The reconfigure restore path tears the replacement down before re-adding
/// the prior. When the prior was configured down and the replacement is
/// enabled, that teardown carries the prior's configured reason.
#[tokio::test]
async fn reconfigure_restore_that_takes_the_peer_down_sends_the_prior_reason() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));
    let (handle, starts, mut stops) = recording_admin_handle();
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let mut previous = forward_config(&mgr, addr);
    previous.admin_down = Some("restored quarantine".to_string());

    mgr.restore_reconfigured_peer(key(addr), previous, false, false, None)
        .await
        .unwrap();

    assert_eq!(
        stops
            .recv()
            .await
            .expect("replacement session receives Stop"),
        Some(rustbgpd_wire::notification::encode_shutdown_communication(
            "restored quarantine"
        ))
    );
    let managed = &mgr.peers[&key(addr)];
    assert!(!managed.enabled);
    assert_eq!(managed.admin_down.as_deref(), Some("restored quarantine"));
    assert_eq!(starts.load(Ordering::SeqCst), 0);
}
