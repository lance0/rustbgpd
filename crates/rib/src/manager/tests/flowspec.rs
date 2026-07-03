use super::*;

#[tokio::test]
async fn send_initial_table_includes_flowspec_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let fs_route = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
    let fs_rule = fs_route.rule.clone();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![fs_route],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_flowspec_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert!(update.withdraw.is_empty());
    assert_eq!(update.flowspec_announce.len(), 1);
    assert_eq!(update.flowspec_announce[0].rule, fs_rule);
    assert!(update.flowspec_withdraw.is_empty());

    let eor = out_rx.recv().await.unwrap();
    assert_eq!(eor.end_of_rib, ipv4_flowspec_sendable());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_refresh_flowspec_re_advertises_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let fs_route = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
    let fs_rule = fs_route.rule.clone();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![fs_route],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_flowspec_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    // Drain the initial dump and its EoR before triggering route refresh.
    let _ = out_rx.recv().await.unwrap();
    let _ = out_rx.recv().await.unwrap();

    tx.send(RibUpdate::RouteRefreshRequest {
        session_id: 0,
        peer: target,
        afi: Afi::Ipv4,
        safi: Safi::FlowSpec,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert!(update.withdraw.is_empty());
    assert_eq!(update.flowspec_announce.len(), 1);
    assert_eq!(update.flowspec_announce[0].rule, fs_rule);
    assert!(update.flowspec_withdraw.is_empty());
    assert_eq!(update.end_of_rib, vec![(Afi::Ipv4, Safi::FlowSpec)]);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn dirty_resync_retries_flowspec_updates() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(1);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_flowspec_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    // The initial EoR occupies the single slot, so the next FlowSpec
    // update will fail to enqueue and mark the peer dirty.
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let fs_route = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
    let fs_rule = fs_route.rule.clone();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![fs_route],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Drain the initial EoR to make room for the timer-driven resync.
    let initial = out_rx.recv().await.unwrap();
    assert_eq!(initial.end_of_rib, ipv4_flowspec_sendable());

    tokio::time::advance(Duration::from_secs(2)).await;

    let resync = out_rx.recv().await.unwrap();
    assert!(resync.announce.is_empty());
    assert!(resync.withdraw.is_empty());
    assert_eq!(resync.flowspec_announce.len(), 1);
    assert_eq!(resync.flowspec_announce[0].rule, fs_rule);
    assert!(resync.flowspec_withdraw.is_empty());

    drop(tx);
    handle.await.unwrap();
}

// --- Graceful Restart tests ---

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "covers the stale demotion, RFC 4724 §4.1 re-advertise-before-EoR, and best-path flip-back in one scenario"
)]
async fn gr_flowspec_eor_recomputes_and_redistributes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_flowspec_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let source_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let source_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let mut route_a = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
    route_a.attributes.push(PathAttribute::LocalPref(200));
    let mut route_b = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 2));
    route_b.attributes.push(PathAttribute::LocalPref(100));
    let rule = route_a.rule.clone();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source_a,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![route_a.clone()],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let initial = out_rx.recv().await.unwrap();
    assert_eq!(initial.flowspec_announce.len(), 1);
    assert_eq!(initial.flowspec_announce[0].peer, source_a);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source_b,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![route_b],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let best_before = query_flowspec_routes(&tx).await;
    assert_eq!(best_before.len(), 1);
    assert_eq!(best_before[0].peer, source_a);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source_a,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::FlowSpec)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let stale_switch = out_rx.recv().await.unwrap();
    assert_eq!(stale_switch.flowspec_announce.len(), 1);
    assert_eq!(stale_switch.flowspec_announce[0].peer, source_b);

    let best_during_gr = query_flowspec_routes(&tx).await;
    assert_eq!(best_during_gr.len(), 1);
    assert_eq!(best_during_gr[0].peer, source_b);

    // RFC 4724 §4.1: a route still marked stale at End-of-RIB is removed,
    // so source_a must re-advertise its rule for it to survive (and win
    // the best-path back from source_b).
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source_a,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![route_a],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source_a,
        afi: Afi::Ipv4,
        safi: Safi::FlowSpec,
    })
    .await
    .unwrap();

    let eor_switch = out_rx.recv().await.unwrap();
    assert_eq!(eor_switch.flowspec_announce.len(), 1);
    assert_eq!(eor_switch.flowspec_announce[0].peer, source_a);
    assert_eq!(eor_switch.flowspec_announce[0].rule, rule);

    let best_after_eor = query_flowspec_routes(&tx).await;
    assert_eq!(best_after_eor.len(), 1);
    assert_eq!(best_after_eor[0].peer, source_a);

    drop(tx);
    handle.await.unwrap();
}

/// A `FlowSpec` rule distinct from the shared `make_flowspec_route` fixture
/// rule, so one source peer can hold two Adj-RIB-In entries.
fn make_flowspec_route_alt(peer: Ipv4Addr) -> FlowSpecRoute {
    let mut route = make_flowspec_route(peer);
    route.rule.components = vec![rustbgpd_wire::FlowSpecComponent::DestinationPrefix(
        rustbgpd_wire::FlowSpecPrefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24)),
    )];
    route
}

/// A second GR entry while `FlowSpec` routes are still stale deletes them
/// (RFC 4724 §4.1: no retention across consecutive restarts).
#[tokio::test]
async fn flowspec_gr_consecutive_restart_deletes_stale_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1))],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let gr_entry = || RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::FlowSpec)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    };
    tx.send(gr_entry()).await.unwrap();
    let stale = query_flowspec_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    tx.send(gr_entry()).await.unwrap();
    assert!(
        query_flowspec_routes(&tx).await.is_empty(),
        "a rule still stale at the next restart must be deleted, not re-marked"
    );

    drop(tx);
    handle.await.unwrap();
}

/// RFC 4724 §4.1: a `FlowSpec` rule still marked stale at End-of-RIB was
/// not re-advertised during the restart window and must be removed; the
/// re-advertised rule survives with its stale flag cleared.
#[tokio::test]
async fn flowspec_gr_eor_sweeps_non_readvertised() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
    let dropped = make_flowspec_route_alt(Ipv4Addr::new(10, 0, 0, 1));
    let kept_rule = kept.rule.clone();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![kept.clone(), dropped],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::FlowSpec)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();
    let stale = query_flowspec_routes(&tx).await;
    assert_eq!(stale.len(), 2);
    assert!(stale.iter().all(|r| r.is_stale));

    // Only `kept` is re-advertised before End-of-RIB.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![kept],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::FlowSpec,
    })
    .await
    .unwrap();

    let after_eor = query_flowspec_routes(&tx).await;
    assert_eq!(
        after_eor.len(),
        1,
        "the non-readvertised stale FlowSpec rule must be removed at End-of-RIB"
    );
    assert_eq!(after_eor[0].rule, kept_rule);
    assert!(!after_eor[0].is_stale, "EoR must clear the stale flag");

    drop(tx);
    handle.await.unwrap();
}

/// RFC 4724 §4.1 via RFC 9494 §4.2: a `FlowSpec` rule still LLGR-stale at
/// End-of-RIB was not re-advertised during the LLGR window and must be
/// removed; the re-advertised rule survives with flags cleared.
#[tokio::test]
async fn flowspec_llgr_eor_sweeps_non_readvertised() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
    let dropped = make_flowspec_route_alt(Ipv4Addr::new(10, 0, 0, 1));
    let kept_rule = kept.rule.clone();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![kept.clone(), dropped],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::Ipv4, Safi::FlowSpec)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::FlowSpec,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 3600,
    })
    .await
    .unwrap();
    let stale = query_flowspec_routes(&tx).await;
    assert!(stale.iter().all(|r| r.is_stale));

    // Advance past GR timer → LLGR phase
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let promoted = query_flowspec_routes(&tx).await;
    assert!(promoted.iter().all(|r| r.is_llgr_stale));

    // Only `kept` is re-advertised before End-of-RIB.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![kept],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::FlowSpec,
    })
    .await
    .unwrap();

    let after_eor = query_flowspec_routes(&tx).await;
    assert_eq!(
        after_eor.len(),
        1,
        "the non-readvertised LLGR-stale FlowSpec rule must be removed at End-of-RIB"
    );
    assert_eq!(after_eor[0].rule, kept_rule);
    assert!(!after_eor[0].is_llgr_stale, "EoR must clear the LLGR flag");
    assert!(!after_eor[0].is_stale);

    drop(tx);
    handle.await.unwrap();
}
