use super::*;
use crate::test_support::peer_v4;

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
    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
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

    let source = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
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

    let target = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
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
        queued: Arc::default(),
        session_id: 0,
        peer: target,
        afi: Afi::BgpLs,
        safi: Safi::BgpLs,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert_eq!(update.withdraw.len(), 0);
    assert_eq!(update.bgpls_announce.len(), 1);
    assert_eq!(update.bgpls_announce[0].key(), key);
    assert_eq!(update.bgpls_withdraw.len(), 0);
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

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
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
        validated_with: None,
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
        validated_with: None,
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

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
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
        validated_with: None,
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
        validated_with: None,
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

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
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
        validated_with: None,
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
        validated_with: None,
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

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
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
        validated_with: None,
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

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
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
        validated_with: None,
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
        validated_with: None,
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

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
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
        validated_with: None,
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
    let peer = peer_v4(peer_addr);
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
    assert_refresh_metrics(&metrics, "10.0.0.1", "linkstate", 1.0, 2.0);

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
    assert_refresh_metrics(&metrics, "10.0.0.1", "linkstate", 1.0, 1.0);

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
    assert_refresh_metrics(&metrics, "10.0.0.1", "linkstate", 0.0, 0.0);

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
    let peer = peer_v4(peer_addr);
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
    assert_refresh_metrics(&metrics, "10.0.0.1", "linkstate", 1.0, 1.0);

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
    assert_refresh_metrics(&metrics, "10.0.0.1", "linkstate", 1.0, 0.0);

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
    assert_refresh_metrics(&metrics, "10.0.0.1", "linkstate", 0.0, 0.0);

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
    let peer = peer_v4(peer_addr);
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
    let peer = peer_v4(peer_addr);
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

    let target = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
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
    let source = peer_v4(source_addr);
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

    let source = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
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
        validated_with: None,
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
        validated_with: None,
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

    let source = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
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
        validated_with: None,
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
        validated_with: None,
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

#[test]
fn peer_down_mid_refresh_zeroes_refresh_gauges() {
    // A session that ends while an enhanced route refresh is in progress
    // must leave `bgp_route_refresh_in_progress` and
    // `bgp_route_refresh_stale_entries` at zero; nothing else runs for
    // the peer until it re-establishes.
    let (_tx, rx) = mpsc::channel(8);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
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

    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 2,
        peer,
        announced: vec![
            make_route(
                Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24),
                Ipv4Addr::new(10, 0, 0, 1),
            ),
            make_route(
                Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
                Ipv4Addr::new(10, 0, 0, 1),
            ),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);

    manager.handle_update(RibUpdate::BeginRouteRefresh {
        session_id: 2,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    });
    assert_refresh_metrics(&metrics, "10.0.0.1", "ipv4_unicast", 1.0, 2.0);

    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 2,
    });
    assert_refresh_metrics(&metrics, "10.0.0.1", "ipv4_unicast", 0.0, 0.0);
}

/// The RIB releases a request's coalescing flag when it dequeues it, before
/// the replay, so the session queues a fresh request for any refresh that
/// arrives afterwards. Stale-session requests release it too; otherwise a
/// flag could stay set with nothing queued to clear it.
#[test]
fn route_refresh_request_releases_its_queued_flag_on_dequeue() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let (outbound_tx, mut outbound_rx) = mpsc::channel(8);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
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
    while outbound_rx.try_recv().is_ok() {}

    for (session_id, replays) in [(0, 1), (1, 0)] {
        let queued = Arc::new(std::sync::atomic::AtomicBool::new(true));
        manager.handle_update(RibUpdate::RouteRefreshRequest {
            peer,
            session_id,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            queued: Arc::clone(&queued),
        });
        assert!(
            !queued.load(std::sync::atomic::Ordering::Acquire),
            "session {session_id}: dequeue must release the flag"
        );
        let mut eors = 0;
        while let Ok(update) = outbound_rx.try_recv() {
            eors += usize::from(update.end_of_rib.contains(&(Afi::Ipv4, Safi::Unicast)));
        }
        assert_eq!(eors, replays, "session {session_id}");
    }
}

/// One family's route, its announcement and withdrawal from `source`, and
/// the receiver's view of an envelope (`Debug` keys, announced and withdrawn).
struct OwedFamily {
    sendable: Vec<(Afi, Safi)>,
    family: (Afi, Safi),
    update: Box<dyn Fn(bool) -> RibUpdate>,
    key: String,
    view: fn(&OutboundRouteUpdate) -> (Vec<String>, Vec<String>),
}

fn debug_keys<K: std::fmt::Debug>(keys: impl Iterator<Item = K>) -> Vec<String> {
    keys.map(|key| format!("{key:?}")).collect()
}

#[expect(
    clippy::too_many_lines,
    reason = "one fixture row per family keeps the five shapes side by side"
)]
fn owed_families(source: Ipv4Addr) -> Vec<OwedFamily> {
    let peer = peer_v4(source);
    let flowspec = crate::test_support::make_flowspec_route(source);
    let bgpls = make_bgpls_route(source, 0x31, 100);
    let vpn = make_vpn_rib_route(source, 31, 1031, 100);
    let labeled = make_labeled_rib_route(source, 32, 1032, 100);
    let rtc = make_rtc_rib_route(source, 33, 100);
    vec![
        OwedFamily {
            sendable: ipv4_flowspec_sendable(),
            family: (Afi::Ipv4, Safi::FlowSpec),
            key: format!("{:?}", flowspec.selection_key()),
            update: Box::new(move |announce| RibUpdate::RoutesReceived {
                peer,
                session_id: 0,
                announced: vec![],
                withdrawn: vec![],
                flowspec_announced: if announce {
                    vec![flowspec.clone()]
                } else {
                    vec![]
                },
                flowspec_withdrawn: if announce {
                    vec![]
                } else {
                    vec![flowspec.selection_key()]
                },
                evpn_announced: vec![],
                evpn_withdrawn: vec![],
                validated_with: None,
            }),
            view: |update| {
                (
                    debug_keys(
                        update
                            .flowspec_announce
                            .iter()
                            .map(FlowSpecRoute::selection_key),
                    ),
                    debug_keys(update.flowspec_withdraw.iter()),
                )
            },
        },
        OwedFamily {
            sendable: bgpls_sendable(),
            family: (Afi::BgpLs, Safi::BgpLs),
            key: format!("{:?}", bgpls.key()),
            update: Box::new(move |announce| RibUpdate::BgpLsRoutesReceived {
                peer,
                session_id: 0,
                announced: if announce {
                    vec![bgpls.clone()]
                } else {
                    vec![]
                },
                withdrawn: if announce { vec![] } else { vec![bgpls.key()] },
            }),
            view: |update| {
                (
                    debug_keys(update.bgpls_announce.iter().map(BgpLsRibRoute::key)),
                    debug_keys(update.bgpls_withdraw.iter()),
                )
            },
        },
        OwedFamily {
            sendable: vpn_sendable(),
            family: (Afi::Ipv4, Safi::MplsVpn),
            key: format!("{:?}", vpn.key()),
            update: Box::new(move |announce| RibUpdate::VpnRoutesReceived {
                peer,
                session_id: 0,
                announced: if announce { vec![vpn.clone()] } else { vec![] },
                withdrawn: if announce { vec![] } else { vec![vpn.key()] },
            }),
            view: |update| {
                (
                    debug_keys(update.vpn_announce.iter().map(VpnRibRoute::key)),
                    debug_keys(update.vpn_withdraw.iter()),
                )
            },
        },
        OwedFamily {
            sendable: labeled_sendable(),
            family: (Afi::Ipv4, Safi::LabeledUnicast),
            key: format!("{:?}", labeled.key()),
            update: Box::new(move |announce| RibUpdate::LabeledRoutesReceived {
                peer,
                session_id: 0,
                announced: if announce {
                    vec![labeled.clone()]
                } else {
                    vec![]
                },
                withdrawn: if announce {
                    vec![]
                } else {
                    vec![labeled.key()]
                },
            }),
            view: |update| {
                (
                    debug_keys(
                        update
                            .labeled_announce
                            .iter()
                            .map(crate::route::LabeledRibRoute::key),
                    ),
                    debug_keys(update.labeled_withdraw.iter()),
                )
            },
        },
        OwedFamily {
            sendable: rtc_sendable(),
            family: (Afi::Ipv4, Safi::RtConstrain),
            key: format!("{:?}", rtc.key()),
            update: Box::new(move |announce| RibUpdate::RtcRoutesReceived {
                peer,
                session_id: 0,
                announced: if announce { vec![rtc.clone()] } else { vec![] },
                withdrawn: if announce { vec![] } else { vec![rtc.key()] },
            }),
            view: |update| {
                (
                    debug_keys(
                        update
                            .rtc_announce
                            .iter()
                            .map(crate::route::RtcRibRoute::key),
                    ),
                    debug_keys(update.rtc_withdraw.iter()),
                )
            },
        },
    ]
}

/// For each family whose refresh answer is staged against an empty view
/// (`FlowSpec`, BGP-LS, VPN, labeled unicast, RT-Constrain): a receiver whose
/// channel is full when a route is withdrawn goes dirty owing that
/// withdrawal, drains, and refreshes the family before the resync tick. The
/// answer must withdraw the route inside `BoRR`/`EoRR`, and the resync must
/// not withdraw it again. Red proof: without the answer's sweep for a
/// family, its answer omits the withdrawal and the resync sends it after
/// the `EoRR`.
#[test]
fn refresh_answer_settles_owed_withdrawals_of_every_family() {
    let source = Ipv4Addr::new(192, 0, 2, 70);
    for case in owed_families(source) {
        let (_tx, rx) = mpsc::channel(4);
        let mut manager = RibManager::new(
            rx,
            dummy_query_rx(),
            None,
            Some(Ipv4Addr::new(192, 0, 2, 254)),
            BgpMetrics::new(),
        );
        let receiver = peer_v4(Ipv4Addr::new(192, 0, 2, 71));
        let (outbound_tx, mut receiver_rx) = mpsc::channel(1);
        manager.handle_update(RibUpdate::PeerUp {
            per_client_best: false,
            interpret_rfc1997: true,
            session_id: 0,
            peer: receiver,
            peer_asn: 65_000,
            peer_router_id: Ipv4Addr::new(192, 0, 2, 71),
            outbound_tx,
            export_policy: None,
            sendable_families: case.sendable.clone(),
            is_ebgp: false,
            route_reflector_client: true,
            orr_vantage: None,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: vec![],
            negotiated_llgr_families: vec![],
        });
        while receiver_rx.try_recv().is_ok() {}
        let views = |rx: &mut mpsc::Receiver<OutboundRouteUpdate>| {
            let mut announced = Vec::new();
            let mut withdrawn = Vec::new();
            while let Ok(update) = rx.try_recv() {
                let (a, w) = (case.view)(&update);
                announced.extend(a);
                withdrawn.extend(w);
            }
            (announced, withdrawn)
        };

        manager.handle_update((case.update)(true));
        while manager.process_next_route_chunk() {}
        assert!(manager.outbound_channel_full(receiver), "{:?}", case.family);
        manager.handle_update((case.update)(false));
        while manager.process_next_route_chunk() {}
        assert!(manager.dirty_peers.contains(&receiver), "{:?}", case.family);
        let (announced, _) = views(&mut receiver_rx);
        assert_eq!(announced, vec![case.key.clone()], "{:?}", case.family);

        manager.handle_update(RibUpdate::RouteRefreshRequest {
            queued: Arc::default(),
            peer: receiver,
            session_id: 0,
            afi: case.family.0,
            safi: case.family.1,
        });
        let (_, answer) = views(&mut receiver_rx);
        assert_eq!(answer, vec![case.key.clone()], "{:?}", case.family);
        manager.resync_dirty_peers_bounded();
        let (_, resync) = views(&mut receiver_rx);
        assert!(resync.is_empty(), "{:?}: {resync:?}", case.family);
        assert!(!manager.dirty_peers.contains(&receiver));
    }
}
