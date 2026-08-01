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
        per_client_best: false,
        interpret_rfc1997: true,
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
        per_client_best: false,
        interpret_rfc1997: true,
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
        per_client_best: false,
        interpret_rfc1997: true,
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
#[expect(
    clippy::too_many_lines,
    reason = "one scenario walks promotion, retention, and EoR sweep end to end"
)]
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
        per_client_best: false,
        interpret_rfc1997: true,
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
        per_client_best: false,
        interpret_rfc1997: true,
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
    manager.sweep_llgr_stale(peer, &[(Afi::Ipv4, Safi::Unicast)]);
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
    manager.sweep_llgr_stale(peer, &[(Afi::Ipv4, Safi::Unicast)]);

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

fn establish_ibgp_peer(
    manager: &mut RibManager,
    peer: IpAddr,
    session_id: u64,
    route_reflector_client: bool,
    negotiated_llgr_families: Vec<(Afi, Safi)>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, outbound_rx) = mpsc::channel(16);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client,
        orr_vantage: None,
        add_path_send_families: Vec::new(),
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families,
    });
    outbound_rx
}

fn make_rr_ibgp_route(prefix: Ipv4Prefix, source: Ipv4Addr) -> Route {
    let mut route = make_route(prefix, source);
    route.origin_type = crate::route::RouteOrigin::Ibgp;
    route
}

async fn drain_unicast_initial_dump(
    outbound_rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
) -> Vec<Route> {
    let mut announced = Vec::new();
    loop {
        let update = outbound_rx.recv().await.expect("initial dump stays open");
        assert!(
            update.withdraw.is_empty(),
            "an initial dump must not withdraw unicast routes"
        );
        announced.extend(update.announce.iter().cloned());
        if update.end_of_rib.contains(&(Afi::Ipv4, Safi::Unicast)) {
            return announced;
        }
    }
}

#[tokio::test]
async fn grouped_late_join_reflects_gr_retained_rr_client_route() {
    let (_tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 254));
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);

    let mut source_rx = establish_ibgp_peer(&mut manager, source, 11, true, Vec::new());
    drain_eor(&mut source_rx).await;
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 11,
        peer: source,
        announced: vec![make_rr_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
    });
    drain_route_chunks(&mut manager);

    manager.handle_update(RibUpdate::PeerGracefulRestart {
        session_id: 11,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: Vec::new(),
        llgr_stale_time: 0,
    });

    let mut target_rx = establish_ibgp_peer(&mut manager, target, 21, false, Vec::new());
    assert!(
        manager.grouped_member_of(target).is_some(),
        "late join must exercise the grouped initial-dump path"
    );
    let initial = drain_unicast_initial_dump(&mut target_rx).await;
    assert!(
        initial
            .iter()
            .any(|route| route.prefix == Prefix::V4(prefix) && route.is_stale),
        "a non-client must receive an RR-client source's GR-retained route before EoR"
    );

    manager.sweep_gr_stale(source);
    assert!(
        !manager.peer_is_rr_client.contains_key(&source),
        "terminal GR expiry must remove the retained source classification"
    );
}

#[tokio::test]
async fn ungrouped_llgr_promotion_keeps_rr_client_route_advertised() {
    let (_tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 254));
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    manager.test_force_ungrouped = true;
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let family = (Afi::Ipv4, Safi::Unicast);

    let mut source_rx = establish_ibgp_peer(&mut manager, source, 31, true, vec![family]);
    drain_eor(&mut source_rx).await;
    let mut target_rx = establish_ibgp_peer(&mut manager, target, 41, false, vec![family]);
    drain_eor(&mut target_rx).await;
    assert!(manager.grouped_member_of(target).is_none());

    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 31,
        peer: source,
        announced: vec![make_rr_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
    });
    drain_route_chunks(&mut manager);
    let initial = target_rx
        .try_recv()
        .expect("target receives reflected route");
    assert!(
        initial
            .announce
            .iter()
            .any(|route| route.prefix == Prefix::V4(prefix))
    );
    assert!(initial.withdraw.is_empty());

    manager.handle_update(RibUpdate::PeerGracefulRestart {
        session_id: 31,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![family],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: family.0,
            safi: family.1,
            forwarding_preserved: false,
            stale_time: 600,
        }],
        llgr_stale_time: 600,
    });
    while let Ok(update) = target_rx.try_recv() {
        assert!(
            !update.withdraw.contains(&(Prefix::V4(prefix), 0)),
            "GR entry must not withdraw the reflected route"
        );
    }

    manager.sweep_gr_stale(source);
    while let Ok(update) = target_rx.try_recv() {
        assert!(
            !update.withdraw.contains(&(Prefix::V4(prefix), 0)),
            "LLGR promotion must not reclassify the retained client route as split-horizon"
        );
    }
    assert!(
        manager.adj_ribs_out[&target]
            .get(&Prefix::V4(prefix), 0)
            .is_some(),
        "the ungrouped target must retain the reflected prefix after LLGR promotion"
    );
    assert_eq!(manager.peer_is_rr_client.get(&source), Some(&true));

    manager.sweep_llgr_stale(source, &[family]);
    assert!(
        !manager.peer_is_rr_client.contains_key(&source),
        "terminal LLGR expiry must remove the retained source classification"
    );
}

#[tokio::test]
async fn rr_client_role_is_overwritten_when_source_reestablishes_as_nonclient() {
    let (_tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 254));
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    let mut first_rx = establish_ibgp_peer(&mut manager, source, 51, true, Vec::new());
    drain_eor(&mut first_rx).await;
    manager.handle_update(RibUpdate::PeerGracefulRestart {
        session_id: 51,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: Vec::new(),
        llgr_stale_time: 0,
    });
    assert_eq!(manager.peer_is_rr_client.get(&source), Some(&true));

    let mut replacement_rx = establish_ibgp_peer(&mut manager, source, 52, false, Vec::new());
    drain_eor(&mut replacement_rx).await;
    assert_eq!(
        manager.peer_is_rr_client.get(&source),
        Some(&false),
        "new-session registration must overwrite the retained GR role"
    );
}

// --- Per-family LLGR lifecycle (LAN-282) + LLGR export coupling (LAN-191) ---

/// Re-establish `peer` through the run loop as an iBGP RR client with the
/// given sendable families.
async fn channel_peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    sendable: Vec<(Afi, Safi)>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: sendable,
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    out_rx
}

async fn send_eor(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr, afi: Afi, safi: Safi) {
    tx.send(RibUpdate::EndOfRib {
        peer,
        session_id: 0,
        afi,
        safi,
    })
    .await
    .unwrap();
}

/// RFC 9494 §4.3: the stale time is per AFI/SAFI. Two families with
/// different peer-advertised stale times must be swept on their OWN
/// deadlines — the shorter one first, the longer one retained until its
/// own timer expires (the old peer-wide min purged both at the shorter).
#[tokio::test]
async fn llgr_mixed_stale_times_sweep_per_family() {
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
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    // GR with per-family LLGR stale times: unicast 10 s, VPN 60 s.
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 2,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv4, Safi::MplsVpn)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![
            rustbgpd_wire::LlgrFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                forwarding_preserved: false,
                stale_time: 10,
            },
            rustbgpd_wire::LlgrFamily {
                afi: Afi::Ipv4,
                safi: Safi::MplsVpn,
                forwarding_preserved: false,
                stale_time: 60,
            },
        ],
        llgr_stale_time: 3600,
    })
    .await
    .unwrap();
    assert!(query_best_routes(&tx).await[0].is_stale);

    // Past the GR timer: both families promote to LLGR-stale.
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(query_best_routes(&tx).await[0].is_llgr_stale);
    assert!(query_vpn_routes(&tx).await[0].is_llgr_stale);

    // Past the unicast stale time only: unicast swept, VPN retained.
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;
    assert!(
        query_best_routes(&tx).await.is_empty(),
        "shorter-stale-time family must be swept on its own deadline"
    );
    let vpn = query_vpn_routes(&tx).await;
    assert_eq!(
        vpn.len(),
        1,
        "longer-stale-time family must survive the shorter family's sweep"
    );
    assert!(vpn[0].is_llgr_stale);

    // Past the VPN stale time: the remaining family is swept.
    tokio::time::advance(Duration::from_secs(50)).await;
    tokio::task::yield_now().await;
    assert!(query_vpn_routes(&tx).await.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// RFC 9494: the ORIGINAL Long-Lived Stale Time bounds total retention.
/// A peer that re-establishes during LLGR and goes down again must not
/// restart the timer — the surviving deadline is re-used, and the
/// LLGR-stale routes are retained (not purged) across the second reset.
#[tokio::test]
async fn llgr_reconnect_and_second_down_preserve_original_deadline() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let family = vec![(Afi::Ipv4, Safi::Unicast)];
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

    // GR down with a 20 s LLST; promotion happens ~t=3, deadline ~t=23.
    tx.send(gr_with_llgr(source, 2, family.clone(), family.clone(), 20))
        .await
        .unwrap();
    assert!(query_best_routes(&tx).await[0].is_stale);
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(query_best_routes(&tx).await[0].is_llgr_stale);

    // ~t=13: re-establish during LLGR, then drop again WITHOUT refreshing.
    // A restarted timer would push the sweep out to ~t=33.
    tokio::time::advance(Duration::from_secs(10)).await;
    tokio::task::yield_now().await;
    let _out_rx = channel_peer_up(&tx, source, ipv4_sendable()).await;
    tx.send(gr_with_llgr(source, 100, family.clone(), family, 20))
        .await
        .unwrap();

    // The LLGR-stale route survives the second reset (RFC 9494 retention —
    // the old purge-on-second-reset would have deleted it here)...
    let best = query_best_routes(&tx).await;
    assert_eq!(
        best.len(),
        1,
        "LLGR-stale route must be retained across consecutive resets"
    );
    assert!(best[0].is_llgr_stale);
    assert!(!best[0].is_stale, "must not be demoted back to GR-stale");

    // ...but only until the ORIGINAL deadline (~t=23): at ~t=25 it is gone,
    // long before both the restarted-timer horizon (~t=33) and the second
    // session's GR window (~t=113).
    tokio::time::advance(Duration::from_secs(12)).await;
    tokio::task::yield_now().await;
    assert!(
        query_best_routes(&tx).await.is_empty(),
        "original LLST must bound total retention through reconnects"
    );

    drop(tx);
    handle.await.unwrap();
}

/// LLGR→GR re-establishment carries the `LLGR_STALE` state: routes stay
/// LLGR-stale (flag + community) through the new session until End-of-RIB,
/// which retires both the staleness and the family's surviving original
/// deadline — a refreshed table must NOT be swept at the old LLST horizon.
#[tokio::test]
async fn llgr_reestablish_carries_llgr_stale_until_eor() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let family = vec![(Afi::Ipv4, Safi::Unicast)];
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

    tx.send(gr_with_llgr(source, 2, family.clone(), family, 60))
        .await
        .unwrap();
    assert!(query_best_routes(&tx).await[0].is_stale);
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    // Re-establish during LLGR: the unrefreshed route keeps its LLGR-stale
    // flag and community while the session waits for End-of-RIB.
    let _out_rx = channel_peer_up(&tx, source, ipv4_sendable()).await;
    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert!(
        best[0].is_llgr_stale,
        "LLGR_STALE state must carry through re-establishment until EoR"
    );
    assert!(
        best[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
    );

    // The peer re-advertises the route and completes with End-of-RIB.
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
    send_eor(&tx, source, Afi::Ipv4, Safi::Unicast).await;
    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert!(!best[0].is_stale && !best[0].is_llgr_stale);
    assert!(
        !best[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "locally injected LLGR_STALE community must be stripped after EoR"
    );

    // Past the original 60 s LLST: the refreshed route must survive — EoR
    // retired the family's deadline.
    tokio::time::advance(Duration::from_secs(70)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        query_best_routes(&tx).await.len(),
        1,
        "EoR must retire the surviving original deadline for the family"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Reconnect-before-expiry across every LLGR-capable family on one peer
/// (unicast, VPN, labeled, EVPN, RTC): promotion marks all five families
/// LLGR-stale; the peer re-establishes, re-advertises everything, and
/// sends per-family End-of-RIB — every route survives past the original
/// LLST fresh.
#[expect(
    clippy::too_many_lines,
    reason = "announce + assert across five address families"
)]
#[tokio::test]
async fn llgr_reconnect_before_expiry_across_families() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let src_v4 = Ipv4Addr::new(10, 0, 0, 1);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let families = vec![
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv4, Safi::MplsVpn),
        (Afi::Ipv4, Safi::LabeledUnicast),
        (Afi::L2Vpn, Safi::Evpn),
        (Afi::Ipv4, Safi::RtConstrain),
    ];

    let announce_all = |tx: mpsc::Sender<RibUpdate>| async move {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: source,
            announced: vec![make_route(prefix, src_v4)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![make_evpn_imet(src_v4, 100)],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
        tx.send(RibUpdate::VpnRoutesReceived {
            session_id: 0,
            peer: source,
            announced: vec![make_vpn_rib_route(src_v4, 31, 100, 100)],
            withdrawn: vec![],
        })
        .await
        .unwrap();
        tx.send(RibUpdate::LabeledRoutesReceived {
            session_id: 0,
            peer: source,
            announced: vec![make_labeled_rib_route(src_v4, 41, 100, 100)],
            withdrawn: vec![],
        })
        .await
        .unwrap();
        tx.send(RibUpdate::RtcRoutesReceived {
            session_id: 0,
            peer: source,
            announced: vec![make_rtc_rib_route(src_v4, 7, 100)],
            withdrawn: vec![],
        })
        .await
        .unwrap();
    };
    announce_all(tx.clone()).await;

    tx.send(gr_with_llgr(
        source,
        2,
        families.clone(),
        families.clone(),
        30,
    ))
    .await
    .unwrap();
    // Sync: the GR entry must be processed before time advances.
    assert!(query_best_routes(&tx).await[0].is_stale);
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    assert!(query_best_routes(&tx).await[0].is_llgr_stale);
    assert!(query_vpn_routes(&tx).await[0].is_llgr_stale);
    assert!(query_labeled_routes(&tx).await[0].is_llgr_stale);
    assert!(query_evpn_routes(&tx).await[0].is_llgr_stale);
    assert!(query_rtc_routes(&tx).await[0].is_llgr_stale);

    // Re-establish before expiry, re-advertise everything, EoR per family.
    let _out_rx = channel_peer_up(&tx, source, families.clone()).await;
    announce_all(tx.clone()).await;
    for &(afi, safi) in &families {
        send_eor(&tx, source, afi, safi).await;
    }

    // Past the original 30 s LLST: every family survived, fresh.
    tokio::time::advance(Duration::from_secs(35)).await;
    tokio::task::yield_now().await;
    let best = query_best_routes(&tx).await;
    assert_eq!(
        best.len(),
        1,
        "unicast must survive reconnect-before-expiry"
    );
    assert!(!best[0].is_stale && !best[0].is_llgr_stale);
    let vpn = query_vpn_routes(&tx).await;
    assert_eq!(vpn.len(), 1, "VPN must survive reconnect-before-expiry");
    assert!(!vpn[0].is_stale && !vpn[0].is_llgr_stale);
    let labeled = query_labeled_routes(&tx).await;
    assert_eq!(
        labeled.len(),
        1,
        "labeled must survive reconnect-before-expiry"
    );
    assert!(!labeled[0].is_stale && !labeled[0].is_llgr_stale);
    let evpn = query_evpn_routes(&tx).await;
    assert_eq!(evpn.len(), 1, "EVPN must survive reconnect-before-expiry");
    assert!(!evpn[0].is_stale && !evpn[0].is_llgr_stale);
    // The RTC-capable re-establishment also self-originates the default
    // wildcard RTC NLRI — pick out the peer's own route.
    let rtc = query_rtc_routes(&tx).await;
    let peer_rtc: Vec<_> = rtc.iter().filter(|r| r.peer == source).collect();
    assert_eq!(
        peer_rtc.len(),
        1,
        "RTC must survive reconnect-before-expiry"
    );
    assert!(!peer_rtc[0].is_stale && !peer_rtc[0].is_llgr_stale);

    drop(tx);
    handle.await.unwrap();
}

/// LAN-191: EVPN GR-stale routes deliberately continue to be exported
/// during the GR window (RFC 4724 permits advertising stale paths) — the
/// operational tradeoff is documented at the EVPN staging gate. A GR entry
/// must not withdraw the already-advertised EVPN route from other peers.
#[tokio::test]
async fn evpn_gr_stale_routes_keep_exporting_during_gr_window() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // eBGP target: iBGP targets would be split-horizon-suppressed without
    // an RR cluster-id, and GR-stale export is not eBGP-gated (only
    // LLGR-stale toward a non-LLGR eBGP peer is).
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = llgr_gate_peer_up(&tx, target, evpn_sendable(), true, vec![], None).await;
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.evpn_announce.len(), 1);

    // Source enters GR covering EVPN (no LLGR).
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let evpn = query_evpn_routes(&tx).await;
    assert_eq!(evpn.len(), 1);
    assert!(evpn[0].is_stale, "route must be GR-stale during the window");

    // The stale route stays exported: no withdraw toward the target.
    while let Ok(update) = out_rx.try_recv() {
        assert!(
            !update.evpn_withdraw.contains(&key),
            "GR-stale EVPN route must keep exporting during the GR window"
        );
    }

    drop(tx);
    handle.await.unwrap();
}
