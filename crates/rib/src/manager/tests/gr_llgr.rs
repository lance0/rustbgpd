use super::*;

#[tokio::test]
async fn gr_marks_stale_and_demotes_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
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

    // Source sends a route
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);

    // Source enters graceful restart
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Route should still be in Loc-RIB (stale but present)
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert!(best[0].is_stale, "route should be marked stale");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn gr_eor_clears_stale() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let dropped_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

    // Source sends two routes
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![
            make_route(kept_prefix, Ipv4Addr::new(10, 0, 0, 1)),
            make_route(dropped_prefix, Ipv4Addr::new(10, 0, 0, 1)),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Source enters graceful restart
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Verify stale
    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 2);
    assert!(best.iter().all(|r| r.is_stale));

    // Only `kept_prefix` is re-advertised before End-of-RIB.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(kept_prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
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
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    // RFC 4724 §4.1: a route still marked stale at End-of-RIB was not
    // re-advertised during the restart window and must be removed; the
    // re-advertised route survives with its stale flag cleared.
    let best = query_best_routes(&tx).await;
    assert_eq!(
        best.len(),
        1,
        "the non-readvertised stale route must be removed at End-of-RIB"
    );
    assert_eq!(best[0].prefix, Prefix::V4(kept_prefix));
    assert!(
        !best[0].is_stale,
        "route should no longer be stale after EoR"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A second GR entry while unicast routes are still stale deletes them
/// (RFC 4724 §4.1: no retention across consecutive restarts).
#[tokio::test]
async fn gr_consecutive_restart_deletes_stale_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
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
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    };
    tx.send(gr_entry()).await.unwrap();
    let stale = query_best_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    tx.send(gr_entry()).await.unwrap();
    assert!(
        query_best_routes(&tx).await.is_empty(),
        "a route still stale at the next restart must be deleted, not re-marked"
    );

    drop(tx);
    handle.await.unwrap();
}

/// The RFC 4724 §4.1 End-of-RIB sweep is family-scoped: an (IPv4, Unicast)
/// `EoR` removes only non-readvertised IPv4 stale routes — an IPv6 unicast
/// route from the same peer stays stale, awaiting its own `EoR`.
#[tokio::test]
async fn gr_eor_sweep_scopes_to_family() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source: IpAddr = "10.0.0.1".parse().unwrap();
    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);
    let mut v6_route = make_v6_route(v6_prefix, "2001:db8::1".parse().unwrap());
    v6_route.peer = source;
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1)), v6_route],
        withdrawn: vec![],
        flowspec_announced: vec![],
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
        gr_families: vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();
    let stale = query_best_routes(&tx).await;
    assert_eq!(stale.len(), 2);
    assert!(stale.iter().all(|r| r.is_stale));

    // IPv4 EoR without re-advertisement: the v4 route is removed
    // (RFC 4724 §4.1), the v6 route is untouched and still stale.
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1, "only the IPv6 route survives the IPv4 EoR");
    assert_eq!(best[0].prefix, Prefix::V6(v6_prefix));
    assert!(
        best[0].is_stale,
        "the IPv6 route still awaits its own End-of-RIB"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn gr_timer_sweeps_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Source sends a route
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Source enters graceful restart with short timer
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 5,
        stale_routes_time: 10,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Route is stale but still in Loc-RIB
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert!(best[0].is_stale);

    // Advance past the GR timer (min(5, 10) = 5 seconds)
    tokio::time::advance(Duration::from_secs(6)).await;
    // Yield to let the manager process the expired GR timer
    tokio::task::yield_now().await;

    // Route should have been swept
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert!(best.is_empty(), "stale routes should be swept after timer");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn gr_peer_up_defers_stale_to_eor() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Source sends a route
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Source enters graceful restart
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Verify route is stale
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert!(best[0].is_stale);

    // Source re-establishes — route should STILL be stale
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
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

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert!(best[0].is_stale, "route should still be stale after PeerUp");

    // Re-advertise before End-of-RIB: RFC 4724 §4.1 removes any route
    // still marked stale when the EoR arrives, so only a re-advertised
    // route survives GR completion.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // End-of-RIB clears stale and completes GR
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert!(
        !best[0].is_stale,
        "route should be non-stale after End-of-RIB"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn gr_peer_up_timer_expires_sweeps_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Source sends a route
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Source enters GR with short restart_time
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 5,
        stale_routes_time: 10,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Advance past restart_time but before stale_routes_time
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    // Source re-establishes — timer resets to stale_routes_time (10s)
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
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

    // Route still stale (no EoR yet)
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert!(best[0].is_stale);

    // Advance past stale_routes_time — timer should sweep
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert!(best.is_empty(), "stale routes should be swept after timer");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn gr_peer_down_aborts_gr() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Source sends a route
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Source enters graceful restart
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Source goes fully down during GR — aborts GR, clears all routes
    tx.send(RibUpdate::PeerDown {
        peer: source,
        session_id: 0,
    })
    .await
    .unwrap();

    // Routes should be gone
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert!(best.is_empty(), "routes cleared after PeerDown aborts GR");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn gr_withdraws_non_gr_family_routes() {
    use rustbgpd_wire::Ipv6Prefix;

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source: IpAddr = "10.0.0.1".parse().unwrap();
    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

    // Source sends both IPv4 and IPv6 routes
    let v6_route = Route {
        prefix: Prefix::V6(v6_prefix),
        next_hop: "2001:db8::1".parse().unwrap(),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: source,
        attributes: Arc::new(vec![]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1)), v6_route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Verify both routes present
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 2);

    // GR with only IPv4 in GR capability — IPv6 should be withdrawn
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // IPv4 route should be stale, IPv6 route should be gone
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1, "only IPv4 route should remain");
    assert!(
        matches!(best[0].prefix, Prefix::V4(_)),
        "remaining route should be IPv4"
    );
    assert!(best[0].is_stale, "IPv4 route should be stale");

    drop(tx);
    handle.await.unwrap();
}

// --- LLGR (RFC 9494) tests ---

#[tokio::test]
async fn llgr_gr_timer_promotes_to_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Source sends a route
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Source enters GR with LLGR enabled
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 5,
        stale_routes_time: 10,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 7200,
    })
    .await
    .unwrap();

    // Route should be GR-stale
    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert!(best[0].is_stale);
    assert!(!best[0].is_llgr_stale);

    // Advance past GR timer — should promote to LLGR-stale
    tokio::time::advance(Duration::from_secs(6)).await;
    tokio::task::yield_now().await;

    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1, "route should still be present during LLGR");
    assert!(!best[0].is_stale, "GR-stale flag should be cleared");
    assert!(best[0].is_llgr_stale, "route should be LLGR-stale");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn llgr_timer_sweeps_llgr_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // GR with LLGR, short timers for testing
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: false,
            stale_time: 10,
        }],
        llgr_stale_time: 10,
    })
    .await
    .unwrap();

    // Ensure manager processes PeerGracefulRestart before advancing time
    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert!(best[0].is_stale);

    // Advance past GR timer → promotes to LLGR
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert!(best[0].is_llgr_stale);

    // Advance past LLGR timer → sweeps routes
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;

    let best = query_best_routes(&tx).await;
    assert!(best.is_empty(), "LLGR-stale routes should be swept");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn llgr_eor_clears_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let dropped_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![
            make_route(kept_prefix, Ipv4Addr::new(10, 0, 0, 1)),
            make_route(dropped_prefix, Ipv4Addr::new(10, 0, 0, 1)),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
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
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 3600,
    })
    .await
    .unwrap();

    // Ensure manager processes PeerGracefulRestart
    let best = query_best_routes(&tx).await;
    assert!(best.iter().all(|r| r.is_stale));

    // Advance past GR timer → LLGR phase
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    let best = query_best_routes(&tx).await;
    assert!(best.iter().all(|r| r.is_llgr_stale));

    // Peer re-establishes during LLGR
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
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

    // Only `kept_prefix` is re-advertised before End-of-RIB.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(kept_prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
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
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    // RFC 4724 §4.1 via RFC 9494 §4.2: a route still LLGR-stale at
    // End-of-RIB was not re-advertised during the LLGR window and must be
    // removed; the re-advertised route survives with flags cleared.
    let best = query_best_routes(&tx).await;
    assert_eq!(
        best.len(),
        1,
        "the non-readvertised LLGR-stale route must be removed at End-of-RIB"
    );
    assert_eq!(best[0].prefix, Prefix::V4(kept_prefix));
    assert!(
        !best[0].is_llgr_stale,
        "LLGR-stale should be cleared by EoR"
    );
    assert!(!best[0].is_stale, "GR-stale should also be cleared");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn llgr_peer_down_aborts_llgr() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
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
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 3600,
    })
    .await
    .unwrap();

    // Ensure manager processes PeerGracefulRestart
    let best = query_best_routes(&tx).await;
    assert!(best[0].is_stale);

    // Advance past GR timer → LLGR phase
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    let best = query_best_routes(&tx).await;
    assert!(best[0].is_llgr_stale);

    // PeerDown during LLGR — should clear everything
    tx.send(RibUpdate::PeerDown {
        peer: source,
        session_id: 0,
    })
    .await
    .unwrap();

    let best = query_best_routes(&tx).await;
    assert!(
        best.is_empty(),
        "routes should be cleared on PeerDown during LLGR"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn llgr_without_peer_capability_falls_through_to_sweep() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // GR without LLGR capability — timer expiry should purge
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 3600, // local config, but peer doesn't support
    })
    .await
    .unwrap();

    // Ensure manager processes PeerGracefulRestart
    let best = query_best_routes(&tx).await;
    assert!(best[0].is_stale);

    // Advance past GR timer — should purge (no LLGR promotion)
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    let best = query_best_routes(&tx).await;
    assert!(
        best.is_empty(),
        "routes should be purged when peer lacks LLGR"
    );

    drop(tx);
    handle.await.unwrap();
}

// --- GR/LLGR expiry session-hygiene tests ---
//
// Direct-manager style: these assert internal per-peer map state across
// the retention-expiry sweeps, which the channel-driven tests above
// cannot observe.

/// `PeerUp` with the boilerplate defaulted; returns the outbound receiver
/// so the channel stays open for the initial dump + `EoR`.
fn establish_peer(manager: &mut RibManager, peer: IpAddr) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, out_rx) = mpsc::channel(16);
    manager.handle_update(RibUpdate::PeerUp {
        session_id: 0,
        peer,
        peer_asn: 65001,
        peer_router_id: Ipv4Addr::new(1, 1, 1, 1),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    });
    out_rx
}

#[tokio::test]
async fn stale_peer_policy_context_from_superseded_session_is_discarded() {
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    let _out_rx = establish_peer(&mut manager, peer);

    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer,
        session_id: 0,
        peer_group: Some("active".to_string()),
    });
    assert_eq!(
        manager.peer_group.get(&peer).map(String::as_str),
        Some("active")
    );

    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer,
        session_id: 7,
        peer_group: Some("stale".to_string()),
    });
    assert_eq!(
        manager.peer_group.get(&peer).map(String::as_str),
        Some("active"),
        "stale policy context from a superseded session must not overwrite the active registration"
    );

    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer,
        session_id: 0,
        peer_group: None,
    });
    assert!(
        !manager.peer_group.contains_key(&peer),
        "matching session id must still be able to clear policy context"
    );
}

#[tokio::test]
async fn llgr_reestablish_uses_captured_stale_routes_time() {
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // GR with LLGR and a non-default stale_routes_time.
    manager.handle_update(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer,
        restart_time: 2,
        stale_routes_time: 77,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 3600,
    });

    // GR deadline expires → promotion to the LLGR stale phase.
    manager.sweep_gr_stale(peer);
    assert!(manager.llgr_peers.contains_key(&peer));

    // Peer re-establishes during LLGR: the re-armed GR deadline must use
    // the stale_routes_time captured at GR entry, not the 360 s default.
    let _out_rx = establish_peer(&mut manager, peer);
    assert_eq!(
        manager.gr_stale_routes_time.get(&peer),
        Some(&77),
        "re-establishment during LLGR must honor the captured stale_routes_time"
    );
}

#[tokio::test]
async fn llgr_expiry_sweep_drops_llgr_peer_config() {
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    manager.handle_update(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: false,
            stale_time: 10,
        }],
        llgr_stale_time: 10,
    });

    manager.sweep_gr_stale(peer);
    assert!(
        manager.llgr_peer_config.contains_key(&peer),
        "LLGR config must survive GR→LLGR promotion (handle_peer_up reads it)"
    );

    // LLGR expires with the peer still gone — the config must not leak.
    manager.sweep_llgr_stale(peer);
    assert!(
        !manager.llgr_peer_config.contains_key(&peer),
        "LLGR expiry must drop the per-peer LLGR config"
    );
}

#[tokio::test]
async fn gr_expiry_without_reestablish_releases_peer_state() {
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    let _out_rx = establish_peer(&mut manager, peer);
    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer,
        session_id: 0,
        peer_group: Some("edge".to_string()),
    });
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    drain_route_chunks(&mut manager);
    assert!(manager.ribs.contains_key(&peer));

    // GR flap without LLGR; the peer never re-establishes, so when the
    // retention expires nothing references its per-peer state anymore.
    manager.handle_update(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });
    manager.sweep_gr_stale(peer);

    assert!(
        !manager.ribs.contains_key(&peer),
        "GR expiry without re-establishment must release the Adj-RIB-In shell"
    );
    assert!(
        !manager.peer_asn.contains_key(&peer),
        "GR expiry without re-establishment must release peer_asn"
    );
    assert!(
        !manager.peer_bgp_id.contains_key(&peer),
        "GR expiry without re-establishment must release peer_bgp_id"
    );
    assert!(
        !manager.peer_group.contains_key(&peer),
        "GR expiry without re-establishment must release peer_group"
    );
}

#[tokio::test]
async fn llgr_expiry_without_reestablish_releases_peer_state() {
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    let _out_rx = establish_peer(&mut manager, peer);
    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer,
        session_id: 0,
        peer_group: Some("edge".to_string()),
    });
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    drain_route_chunks(&mut manager);

    manager.handle_update(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: false,
            stale_time: 10,
        }],
        llgr_stale_time: 10,
    });
    manager.sweep_gr_stale(peer);
    assert!(manager.ribs.contains_key(&peer), "LLGR retains the rib");

    // LLGR expires with the peer still gone.
    manager.sweep_llgr_stale(peer);

    assert!(
        !manager.ribs.contains_key(&peer),
        "LLGR expiry without re-establishment must release the Adj-RIB-In shell"
    );
    assert!(
        !manager.peer_asn.contains_key(&peer),
        "LLGR expiry without re-establishment must release peer_asn"
    );
    assert!(
        !manager.peer_bgp_id.contains_key(&peer),
        "LLGR expiry without re-establishment must release peer_bgp_id"
    );
    assert!(
        !manager.peer_group.contains_key(&peer),
        "LLGR expiry without re-establishment must release peer_group"
    );
}

#[tokio::test]
async fn gr_expiry_sweep_spares_reestablished_peer_awaiting_eor() {
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    let _out_rx = establish_peer(&mut manager, peer);
    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer,
        session_id: 0,
        peer_group: Some("edge".to_string()),
    });
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    drain_route_chunks(&mut manager);

    manager.handle_update(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });

    // Peer re-establishes during GR, but its End-of-RIB is late: the
    // stale-time sweep fires while the session is up. Stale routes go,
    // the live session's state must not.
    let _out_rx2 = establish_peer(&mut manager, peer);
    manager.sweep_gr_stale(peer);

    assert_eq!(
        manager
            .ribs
            .get(&peer)
            .map(crate::adj_rib_in::AdjRibIn::len),
        Some(0),
        "stale routes are swept but the Adj-RIB-In entry survives"
    );
    assert!(
        manager.peer_asn.contains_key(&peer),
        "identity must survive a sweep that fires before a late EoR"
    );
    assert!(manager.peer_bgp_id.contains_key(&peer));
    assert!(manager.peer_group.contains_key(&peer));
    assert!(
        manager.outbound_peers.contains_key(&peer),
        "outbound registration must survive a sweep that fires before a late EoR"
    );
}

// --- Route Reflector tests ---
