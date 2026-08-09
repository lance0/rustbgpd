use super::*;

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
