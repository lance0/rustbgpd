use super::*;

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
    let source = include_str!("../lifecycle.rs");
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
    let source = include_str!("../inbound.rs");
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

    let source = include_str!("../lifecycle.rs");
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
    let lifecycle = include_str!("../lifecycle.rs");
    let public_add = lifecycle
        .split_once("pub(super) async fn add_peer(")
        .unwrap()
        .1
        .split_once("pub(super) async fn runtime_create_peer")
        .unwrap()
        .0;
    let public_add = public_add.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(public_add.contains("add_peer_impl(config, sync_config_snapshot, true, true)"));
    let internal_add = lifecycle
        .split_once("pub(super) async fn add_peer_with_admin_state(")
        .unwrap()
        .1
        .split_once("async fn add_peer_impl")
        .unwrap()
        .0;
    let internal_add = internal_add
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
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

    let publisher = include_str!("../events.rs")
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
