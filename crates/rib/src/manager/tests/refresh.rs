use super::*;

#[tokio::test]
async fn route_refresh_bgpls_re_advertises_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 34, 100);
    let key = route.key();

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: bgpls_sendable(),
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

    let _initial = out_rx.recv().await.unwrap();
    let _eor = out_rx.recv().await.unwrap();

    tx.send(RibUpdate::RouteRefreshRequest {
        session_id: 0,
        peer: target,
        afi: Afi::BgpLs,
        safi: Safi::BgpLs,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert!(update.withdraw.is_empty());
    assert_eq!(update.bgpls_announce.len(), 1);
    assert_eq!(update.bgpls_announce[0].key(), key);
    assert!(update.bgpls_withdraw.is_empty());
    assert_eq!(update.end_of_rib, vec![(Afi::BgpLs, Safi::BgpLs)]);
    assert_eq!(
        update.refresh_markers,
        vec![
            (
                Afi::BgpLs,
                Safi::BgpLs,
                rustbgpd_wire::RouteRefreshSubtype::BoRR
            ),
            (
                Afi::BgpLs,
                Safi::BgpLs,
                rustbgpd_wire::RouteRefreshSubtype::EoRR
            ),
        ]
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_replacement_preserves_refreshed_route() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route.clone()],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap();
    tokio::task::yield_now().await;

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].prefix, Prefix::V4(prefix));

    let received = query_received_routes(&tx, peer).await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].prefix, Prefix::V4(prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_eorr_sweeps_unreplaced_route() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let route1 = make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1));
    let route2 = make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1));

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route1.clone(), route2],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap();
    assert_refresh_metrics(&metrics, "10.0.0.1", "ipv4_unicast", 1.0, 2.0);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route1],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap();
    assert_refresh_metrics(&metrics, "10.0.0.1", "ipv4_unicast", 1.0, 1.0);

    tx.send(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].prefix, Prefix::V4(prefix1));

    let received = query_received_routes(&tx, peer).await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].prefix, Prefix::V4(prefix1));
    assert_refresh_metrics(&metrics, "10.0.0.1", "ipv4_unicast", 0.0, 0.0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_duplicate_borr_rebuilds_snapshot_safely() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route.clone()],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    for _ in 0..2 {
        tx.send(RibUpdate::BeginRouteRefresh {
            session_id: 0,
            peer,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();
    }

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].prefix, Prefix::V4(prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_eorr_without_active_state_is_ignored() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].prefix, Prefix::V4(prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_timeout_sweeps_unreplaced_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let route1 = make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1));
    let route2 = make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1));

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route1.clone(), route2],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await.unwrap();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route1],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tokio::time::advance(ERR_REFRESH_TIMEOUT + Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].prefix, Prefix::V4(prefix1));

    let received = query_received_routes(&tx, peer).await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].prefix, Prefix::V4(prefix1));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_timeout_is_family_isolated() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let v6_prefix = Ipv6Prefix::new(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0), 64);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![
            make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1)),
            make_v6_route(v6_prefix, Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1)),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await.unwrap();

    tokio::time::advance(ERR_REFRESH_TIMEOUT + Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].prefix, Prefix::V6(v6_prefix));

    let received = query_received_routes(&tx, peer).await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].prefix, Prefix::V6(v6_prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_bgpls_eorr_sweeps_unreplaced_route() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    let route1 = make_bgpls_route(peer_addr, 21, 100);
    let route2 = make_bgpls_route(peer_addr, 22, 100);
    let key1 = route1.key();

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route1.clone(), route2],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::BgpLs,
        safi: Safi::BgpLs,
    })
    .await
    .unwrap();
    let before_refresh = query_bgpls_routes(&tx).await;
    assert_eq!(before_refresh.len(), 2);
    assert_refresh_metrics(&metrics, "10.0.0.1", "bgpls", 1.0, 2.0);

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route1],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let during_refresh = query_bgpls_routes(&tx).await;
    assert_eq!(during_refresh.len(), 2);
    assert_refresh_metrics(&metrics, "10.0.0.1", "bgpls", 1.0, 1.0);

    tx.send(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::BgpLs,
        safi: Safi::BgpLs,
    })
    .await
    .unwrap();

    let after_refresh = query_bgpls_routes(&tx).await;
    assert_eq!(after_refresh.len(), 1);
    assert_eq!(after_refresh[0].key(), key1);
    assert_refresh_metrics(&metrics, "10.0.0.1", "bgpls", 0.0, 0.0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_bgpls_withdraw_clears_stale_marker() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    let route = make_bgpls_route(peer_addr, 23, 100);
    let key = route.key();

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::BgpLs,
        safi: Safi::BgpLs,
    })
    .await
    .unwrap();
    let before_withdraw = query_bgpls_routes(&tx).await;
    assert_eq!(before_withdraw.len(), 1);
    assert_refresh_metrics(&metrics, "10.0.0.1", "bgpls", 1.0, 1.0);

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![key],
    })
    .await
    .unwrap();
    let after_withdraw = query_bgpls_routes(&tx).await;
    assert!(after_withdraw.is_empty());
    assert_refresh_metrics(&metrics, "10.0.0.1", "bgpls", 1.0, 0.0);

    tx.send(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::BgpLs,
        safi: Safi::BgpLs,
    })
    .await
    .unwrap();

    let after_refresh = query_bgpls_routes(&tx).await;
    assert!(after_refresh.is_empty());
    assert_refresh_metrics(&metrics, "10.0.0.1", "bgpls", 0.0, 0.0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_vpn_eorr_sweeps_unreplaced_route() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    let route1 = make_vpn_rib_route(peer_addr, 21, 100, 100);
    let route2 = make_vpn_rib_route(peer_addr, 22, 100, 100);
    let key1 = route1.key();

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route1.clone(), route2],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();
    let before_refresh = query_vpn_routes(&tx).await;
    assert_eq!(before_refresh.len(), 2);
    assert_refresh_metrics(&metrics, "10.0.0.1", "l3vpn_ipv4_unicast", 1.0, 2.0);

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route1],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let during_refresh = query_vpn_routes(&tx).await;
    assert_eq!(during_refresh.len(), 2);
    assert_refresh_metrics(&metrics, "10.0.0.1", "l3vpn_ipv4_unicast", 1.0, 1.0);

    tx.send(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();

    let after_refresh = query_vpn_routes(&tx).await;
    assert_eq!(after_refresh.len(), 1);
    assert_eq!(after_refresh[0].key(), key1);
    assert_refresh_metrics(&metrics, "10.0.0.1", "l3vpn_ipv4_unicast", 0.0, 0.0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_vpn_withdraw_clears_stale_marker() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    let route = make_vpn_rib_route(peer_addr, 23, 100, 100);
    let key = route.key();

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();
    let before_withdraw = query_vpn_routes(&tx).await;
    assert_eq!(before_withdraw.len(), 1);
    assert_refresh_metrics(&metrics, "10.0.0.1", "l3vpn_ipv4_unicast", 1.0, 1.0);

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![key],
    })
    .await
    .unwrap();
    let after_withdraw = query_vpn_routes(&tx).await;
    assert!(after_withdraw.is_empty());
    assert_refresh_metrics(&metrics, "10.0.0.1", "l3vpn_ipv4_unicast", 1.0, 0.0);

    tx.send(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();

    let after_refresh = query_vpn_routes(&tx).await;
    assert!(after_refresh.is_empty());
    assert_refresh_metrics(&metrics, "10.0.0.1", "l3vpn_ipv4_unicast", 0.0, 0.0);

    drop(tx);
    handle.await.unwrap();
}

/// The `EoRR` sweep of an unrefreshed VPN route must flow through the Loc-RIB
/// recompute and surface as a reflected withdrawal to other eligible peers,
/// not just vanish from the sweeping peer's Adj-RIB-In.
#[tokio::test]
async fn enhanced_route_refresh_vpn_eorr_reflects_withdrawal_to_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vpn_sendable(),
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

    let source_addr = Ipv4Addr::new(10, 0, 0, 1);
    let source = IpAddr::V4(source_addr);
    let survivor = make_vpn_rib_route(source_addr, 24, 100, 100);
    let omitted = make_vpn_rib_route(source_addr, 25, 100, 100);
    let omitted_key = omitted.key();

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![survivor.clone(), omitted],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announce = out_rx.recv().await.unwrap();
    assert_eq!(announce.vpn_announce.len(), 2);

    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();
    // Reannounce only the survivor; the omitted route stays stale.
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![survivor],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();

    let swept = out_rx.recv().await.unwrap();
    assert!(swept.vpn_announce.is_empty());
    assert_eq!(swept.vpn_withdraw, vec![omitted_key]);

    drop(tx);
    handle.await.unwrap();
}
