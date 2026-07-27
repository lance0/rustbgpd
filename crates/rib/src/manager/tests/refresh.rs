use super::*;

fn assert_route_refresh_actor_samples(metrics: &BgpMetrics, begin: u64, eorr: u64, timeout: u64) {
    assert_eq!(
        histogram_sample_counts_by_label(
            metrics,
            "bgp_rib_route_refresh_actor_duration_seconds",
            "operation",
        ),
        BTreeMap::from([
            ("begin".to_owned(), begin),
            ("eorr".to_owned(), eorr),
            ("timeout".to_owned(), timeout),
        ])
    );
}

#[test]
fn route_refresh_actor_duration_counts_only_accepted_active_refresh_work() {
    // Destructive breaks: each assertion follows one marker, so omitting a
    // legitimate observation or moving one across the session/active gate
    // changes that marker's own delta and cannot be hidden by a later sample.
    let (_tx, rx) = mpsc::channel(8);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (outbound_tx, _outbound_rx) = mpsc::channel(8);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 2,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
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

    let begin = || RibUpdate::BeginRouteRefresh {
        session_id: 2,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    };
    let eorr = || RibUpdate::EndRouteRefresh {
        session_id: 2,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    };

    // Normal accepted BoRR/EoRR records one snapshot and one complete finisher.
    manager.handle_update(begin());
    assert_route_refresh_actor_samples(&metrics, 1, 0, 0);
    manager.handle_update(eorr());
    assert_route_refresh_actor_samples(&metrics, 1, 1, 0);

    // A timeout is an active finisher and gets its distinct operation label.
    manager.handle_update(begin());
    assert_route_refresh_actor_samples(&metrics, 2, 1, 0);
    manager.handle_update(RibUpdate::RouteRefreshTimeout {
        session_id: 2,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    });
    assert_route_refresh_actor_samples(&metrics, 2, 1, 1);

    // A duplicate BoRR rebuilds the snapshot, so both accepted snapshots count.
    manager.handle_update(begin());
    assert_route_refresh_actor_samples(&metrics, 3, 1, 1);
    manager.handle_update(begin());
    assert_route_refresh_actor_samples(&metrics, 4, 1, 1);
    manager.handle_update(eorr());
    assert_route_refresh_actor_samples(&metrics, 4, 2, 1);

    // Inactive finishers have no synchronous actor work to observe.
    manager.handle_update(eorr());
    assert_route_refresh_actor_samples(&metrics, 4, 2, 1);
    manager.handle_update(RibUpdate::RouteRefreshTimeout {
        session_id: 2,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    });
    assert_route_refresh_actor_samples(&metrics, 4, 2, 1);

    // A superseded session's markers must be discarded before observation.
    manager.handle_update(RibUpdate::BeginRouteRefresh {
        session_id: 1,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    });
    assert_route_refresh_actor_samples(&metrics, 4, 2, 1);
    manager.handle_update(RibUpdate::EndRouteRefresh {
        session_id: 1,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    });
    assert_route_refresh_actor_samples(&metrics, 4, 2, 1);
    manager.handle_update(RibUpdate::RouteRefreshTimeout {
        session_id: 1,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    });
    assert_route_refresh_actor_samples(&metrics, 4, 2, 1);
}

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
        per_client_best: false,
        interpret_rfc1997: true,
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
        per_client_best: false,
        interpret_rfc1997: true,
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

/// LAN-187: an enhanced-refresh window completing while the peer is inside
/// its GR window (re-established, End-of-RIB pending) must not purge the
/// GR-stale routes RFC 4724 §4.1 retains until End-of-RIB — the restarting
/// peer's replay is not authoritative while it is still converging.
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end GR + refresh-window walk: down, re-establish, BoRR..EoRR, End-of-RIB"
)]
#[tokio::test]
async fn eorr_preserves_gr_stale_routes_awaiting_eor() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let retained_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![
            make_route(kept_prefix, Ipv4Addr::new(10, 0, 0, 1)),
            make_route(retained_prefix, Ipv4Addr::new(10, 0, 0, 1)),
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
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Peer re-establishes — still awaiting End-of-RIB, routes GR-stale.
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

    // A refresh window opens mid-GR: GR-stale routes are owned by the GR
    // machinery and must not enter the refresh snapshot.
    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer: source,
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
    assert_refresh_metrics(&metrics, "10.0.0.1", "ipv4_unicast", 1.0, 0.0);

    // Only `kept_prefix` is re-advertised inside the window.
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
    tx.send(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    // EoRR must NOT purge the GR-stale route: End-of-RIB (or the GR
    // timer) resolves it, not the refresh sweep.
    let mut received = query_received_routes(&tx, source).await;
    received.sort_by_key(|r| r.prefix.to_string());
    assert_eq!(
        received.len(),
        2,
        "GR-stale route must survive the EoRR sweep until End-of-RIB"
    );
    assert!(!received[0].is_stale, "re-advertised route is fresh");
    assert!(
        received[1].is_stale,
        "non-readvertised route stays GR-stale after EoRR"
    );

    // End-of-RIB then performs the RFC 4724 §4.1 removal as usual.
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let received = query_received_routes(&tx, source).await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].prefix, Prefix::V4(kept_prefix));
    assert!(!received[0].is_stale);

    drop(tx);
    handle.await.unwrap();
}

/// LAN-187 (LLGR arm): a route promoted to LLGR-stale (RFC 9494) whose peer
/// re-established during the LLGR phase must equally survive an `EoRR` sweep
/// — RFC 9494 §4.2 retains it until re-advertisement, End-of-RIB, or the
/// LLGR timer.
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end LLGR + refresh-window walk: down, GR expiry, re-establish, BoRR..EoRR, End-of-RIB"
)]
#[tokio::test]
async fn eorr_preserves_llgr_stale_routes_awaiting_eor() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let retained_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![
            make_route(kept_prefix, Ipv4Addr::new(10, 0, 0, 1)),
            make_route(retained_prefix, Ipv4Addr::new(10, 0, 0, 1)),
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
        stale_routes_time: 3600,
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
    let best = query_best_routes(&tx).await;
    assert!(best.iter().all(|r| r.is_stale));

    // GR timer expires → LLGR promotion.
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let best = query_best_routes(&tx).await;
    assert!(best.iter().all(|r| r.is_llgr_stale));

    // Peer re-establishes during LLGR (moves back to the GR wait-for-EoR
    // phase, routes keep their LLGR-stale flag).
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

    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
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
    tx.send(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    let mut received = query_received_routes(&tx, source).await;
    received.sort_by_key(|r| r.prefix.to_string());
    assert_eq!(
        received.len(),
        2,
        "LLGR-stale route must survive the EoRR sweep until End-of-RIB"
    );
    assert!(!received[0].is_llgr_stale, "re-advertised route is fresh");
    assert!(
        received[1].is_llgr_stale,
        "non-readvertised route stays LLGR-stale after EoRR"
    );

    // End-of-RIB then removes it (RFC 4724 §4.1 via RFC 9494 §4.2).
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let received = query_received_routes(&tx, source).await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].prefix, Prefix::V4(kept_prefix));
    assert!(!received[0].is_llgr_stale);

    drop(tx);
    handle.await.unwrap();
}
