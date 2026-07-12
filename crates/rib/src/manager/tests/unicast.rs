use super::*;

fn drain_unicast_state(
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
) -> HashMap<(Prefix, u32), Route> {
    let mut state = HashMap::new();
    while let Ok(update) = rx.try_recv() {
        for route in update.announce.iter() {
            state.insert((route.prefix, route.path_id), route.clone());
        }
        for withdrawn in update.withdraw {
            state.remove(&withdrawn);
        }
    }
    state
}

#[test]
fn paths_limit_is_applied_per_unicast_family_and_rejects_stale_session() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    manager.outbound_session_ids.insert(peer, 7);
    manager.peer_add_path_send_max.insert(peer, 8);
    manager.peer_add_path_send_families.insert(
        peer,
        vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)],
    );

    manager.handle_update(RibUpdate::PeerAddPathLimits {
        peer,
        session_id: 6,
        limits: vec![((Afi::Ipv4, Safi::Unicast), 1)],
    });
    assert!(!manager.peer_add_path_send_limits.contains_key(&peer));

    manager.handle_update(RibUpdate::PeerAddPathLimits {
        peer,
        session_id: 7,
        limits: vec![
            ((Afi::Ipv4, Safi::Unicast), 2),
            ((Afi::Ipv6, Safi::Unicast), 5),
        ],
    });
    assert_eq!(
        manager.add_path_send_max_for_prefix(
            peer,
            &Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24))
        ),
        2
    );
    assert_eq!(
        manager.add_path_send_max_for_prefix(
            peer,
            &Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32))
        ),
        5
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end dual-stack scenario covers initial dump, churn, withdrawal re-ranking, and refresh replay"
)]
async fn paths_limit_drives_dual_stack_initial_churn_withdraw_and_refresh() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let v4 = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let v6 = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);
    let mut v4_routes = Vec::new();
    let mut v6_routes = Vec::new();
    for host in 1..=3 {
        let v4_route = make_route(v4, Ipv4Addr::new(10, 0, 0, host));
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: v4_route.peer,
            announced: vec![v4_route.clone()],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
        v4_routes.push(v4_route);

        let v6_route = make_v6_route(v6, format!("2001:db8::{host}").parse().unwrap());
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: v6_route.peer,
            announced: vec![v6_route.clone()],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
        v6_routes.push(v6_route);
    }
    let (sync_tx, sync_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: sync_tx })
        .await
        .unwrap();
    assert_eq!(sync_rx.await.unwrap(), 2);

    let target: IpAddr = "192.0.2.9".parse().unwrap();
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        session_id: 7,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        add_path_send_families: vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)],
        add_path_send_max: 1,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::PeerAddPathLimits {
        peer: target,
        session_id: 7,
        limits: vec![
            ((Afi::Ipv4, Safi::Unicast), 1),
            ((Afi::Ipv6, Safi::Unicast), 2),
        ],
    })
    .await
    .unwrap();
    let (sync_tx, sync_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: sync_tx })
        .await
        .unwrap();
    let _ = sync_rx.await.unwrap();
    let initial = drain_unicast_state(&mut out_rx);
    assert_eq!(
        initial.keys().filter(|(p, _)| *p == Prefix::V4(v4)).count(),
        1
    );
    assert_eq!(
        initial.keys().filter(|(p, _)| *p == Prefix::V6(v6)).count(),
        2
    );

    for route in [v4_routes.remove(0), v6_routes.remove(0)] {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: route.peer,
            announced: vec![],
            withdrawn: vec![(route.prefix, route.path_id)],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }
    let (sync_tx, sync_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: sync_tx })
        .await
        .unwrap();
    let _ = sync_rx.await.unwrap();
    let reranked = drain_unicast_state(&mut out_rx);
    assert_eq!(
        reranked
            .keys()
            .filter(|(p, _)| *p == Prefix::V4(v4))
            .count(),
        1
    );
    assert_eq!(
        reranked
            .keys()
            .filter(|(p, _)| *p == Prefix::V6(v6))
            .count(),
        2
    );

    for (afi, safi) in [(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)] {
        tx.send(RibUpdate::RouteRefreshRequest {
            peer: target,
            session_id: 7,
            afi,
            safi,
        })
        .await
        .unwrap();
    }
    let (sync_tx, sync_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: sync_tx })
        .await
        .unwrap();
    let _ = sync_rx.await.unwrap();
    let refreshed = drain_unicast_state(&mut out_rx);
    assert_eq!(
        refreshed
            .keys()
            .filter(|(p, _)| *p == Prefix::V4(v4))
            .count(),
        1
    );
    assert_eq!(
        refreshed
            .keys()
            .filter(|(p, _)| *p == Prefix::V6(v6))
            .count(),
        2
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn routes_received_and_queried() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
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

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: Some(peer),
        reply: reply_tx,
    })
    .await
    .unwrap();

    let routes = reply_rx.await.unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].prefix, Prefix::V4(prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn closed_query_channel_does_not_block_primary_channel() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();

    let count = tokio::time::timeout(Duration::from_secs(1), reply_rx)
        .await
        .expect("query should not stall when query channel is closed")
        .unwrap();
    assert_eq!(count, 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn large_routes_received_batch_preserves_final_state() {
    let (tx, rx) = mpsc::channel(64);
    let (_query_tx, query_rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, query_rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let next_hop = Ipv4Addr::new(10, 0, 0, 1);
    let routes: Vec<Route> = (0..2500).map(|i| make_indexed_route(i, next_hop)).collect();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: routes,
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

    let count = tokio::time::timeout(Duration::from_secs(2), reply_rx)
        .await
        .expect("large chunked batch should still converge")
        .unwrap();
    assert_eq!(count, 2500);

    drop(tx);
    handle.await.unwrap();
}

/// PR3: a multi-chunk initial-load flood (>1024 routes in one batch)
/// distributes to each peer as ONE coalesced `OutboundRouteUpdate`, not one
/// per 1024-route chunk. `recompute_best` still runs per chunk (see
/// `query_channel_observes_partial_progress_during_large_batch`), so only
/// outbound distribution is deferred to batch-end. Asserts both the
/// coalescing (single outbound message) and correctness (every route is
/// advertised).
#[tokio::test]
async fn multi_chunk_flood_coalesces_into_one_outbound_batch() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Register an outbound observer peer first and drain its initial EoR.
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

    // Flood 2500 routes (3 chunks at the 1024 chunk size) from a source peer.
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let next_hop = Ipv4Addr::new(10, 0, 0, 1);
    let route_count = 2500_u32;
    let routes: Vec<Route> = (0..route_count)
        .map(|i| make_indexed_route(i, next_hop))
        .collect();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: routes,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Collect outbound updates until every route is advertised, counting how
    // many distinct OutboundRouteUpdate messages it took.
    let mut announced = 0usize;
    let mut messages = 0usize;
    while announced < route_count as usize {
        let update = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("outbound update should arrive")
            .expect("outbound channel open");
        messages += 1;
        announced += update.announce.len();
    }
    assert_eq!(
        announced, route_count as usize,
        "every flooded route must be advertised"
    );
    assert_eq!(
        messages, 1,
        "a multi-chunk flood must coalesce into one outbound batch, got {messages}"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn query_channel_observes_partial_progress_during_large_batch() {
    let (tx, rx) = mpsc::channel(64);
    let (query_tx, query_rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, query_rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let next_hop = Ipv4Addr::new(10, 0, 0, 1);
    let route_count = 20_000_u32;
    let routes: Vec<Route> = (0..route_count)
        .map(|i| make_indexed_route(i, next_hop))
        .collect();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: routes,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tokio::task::yield_now().await;

    let (reply_tx, reply_rx) = oneshot::channel();
    query_tx
        .send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();

    let count = tokio::time::timeout(Duration::from_secs(2), reply_rx)
        .await
        .expect("priority query should respond during chunked processing")
        .unwrap();
    assert!(count > 0, "query should observe some inserted routes");
    assert!(
        count < route_count as usize,
        "query should be serviced before the full batch completes"
    );

    drop(tx);
    drop(query_tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn peer_down_clears_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
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

    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: Some(peer),
        reply: reply_tx,
    })
    .await
    .unwrap();

    let routes = reply_rx.await.unwrap();
    assert!(routes.is_empty());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn withdrawal_removes_route() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![
            make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1)),
            make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1)),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix1), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: Some(peer),
        reply: reply_tx,
    })
    .await
    .unwrap();

    let routes = reply_rx.await.unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].prefix, Prefix::V4(prefix2));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn query_all_peers() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24),
            Ipv4Addr::new(10, 0, 0, 1),
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer2,
        announced: vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24),
            Ipv4Addr::new(10, 0, 0, 2),
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: None,
        reply: reply_tx,
    })
    .await
    .unwrap();

    let routes = reply_rx.await.unwrap();
    assert_eq!(routes.len(), 2);

    drop(tx);
    handle.await.unwrap();
}

// --- Loc-RIB integration tests ---

#[tokio::test]
async fn best_routes_returns_winner() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

    // Peer1: local_pref 100
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Peer2: local_pref 200 — should win
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer2,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();

    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer2);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn peer_down_promotes_second_best() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer2,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Peer2 goes down — peer1 should be promoted
    tx.send(RibUpdate::PeerDown {
        peer: peer2,
        session_id: 0,
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();

    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer1);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn withdrawal_updates_best() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer2,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Peer2 withdraws the prefix
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer2,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();

    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer1);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn different_best_per_prefix() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix_a = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let prefix_b = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

    // Peer1 wins prefix_a (higher LP), peer2 wins prefix_b (higher LP)
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![
            make_route_with_lp(prefix_a, Ipv4Addr::new(1, 0, 0, 1), 200),
            make_route_with_lp(prefix_b, Ipv4Addr::new(1, 0, 0, 1), 100),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer2,
        announced: vec![
            make_route_with_lp(prefix_a, Ipv4Addr::new(1, 0, 0, 2), 100),
            make_route_with_lp(prefix_b, Ipv4Addr::new(1, 0, 0, 2), 200),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();

    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 2);

    let best_a = best
        .iter()
        .find(|r| r.prefix == Prefix::V4(prefix_a))
        .unwrap();
    let best_b = best
        .iter()
        .find(|r| r.prefix == Prefix::V4(prefix_b))
        .unwrap();
    assert_eq!(best_a.peer, peer1);
    assert_eq!(best_b.peer, peer2);

    drop(tx);
    handle.await.unwrap();
}

// --- M3 outbound distribution tests ---

#[tokio::test]
async fn peer_up_triggers_initial_table_dump() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Inject a route from source
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

    // Register target for outbound
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
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

    // Should receive initial table dump
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));
    assert!(update.withdraw.is_empty());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_change_distributes_to_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

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

    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn single_best_send_normalizes_path_id_to_zero() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

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

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
    route.path_id = 42;

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: route.peer,
        announced: vec![route],
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
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));
    assert_eq!(update.announce[0].path_id, 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn split_horizon_prevents_echo() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer,
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

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    // The route is FROM this peer — should not be sent back
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Force a query to serialize the event loop
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    // Channel should be empty (no outbound update sent)
    assert!(out_rx.try_recv().is_err());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn query_peer_groups_returns_current_policy_context() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::SetPeerPolicyContext {
        peer,
        session_id: 0,
        peer_group: Some("transit".to_string()),
    })
    .await
    .unwrap();
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryPeerGroups { reply: reply_tx })
        .await
        .unwrap();

    let groups = reply_rx.await.unwrap();
    assert_eq!(groups.get(&peer).map(String::as_str), Some("transit"));

    drop(tx);
    handle.await.unwrap();
}

/// Like [`make_route`] but with iBGP origin (iBGP-learned route).
fn make_ibgp_route(prefix: Ipv4Prefix, next_hop: Ipv4Addr) -> Route {
    Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(next_hop),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(next_hop),
        attributes: Arc::new(vec![]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

#[tokio::test]
async fn ibgp_route_not_sent_to_ibgp_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Source: iBGP peer
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Target: iBGP peer (is_ebgp: false)
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
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
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

    // iBGP-learned route should NOT be sent to iBGP peer
    assert!(out_rx.try_recv().is_err());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn ibgp_route_sent_to_ebgp_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Source: iBGP peer
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Target: eBGP peer (is_ebgp: true)
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

    // Initial dump includes the route (iBGP→eBGP is allowed)
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

    // Then EoR
    drain_eor(&mut out_rx).await;

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn ebgp_route_sent_to_ibgp_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Source: eBGP peer
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

    // Target: iBGP peer (is_ebgp: false)
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
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    // Initial dump includes the route (eBGP→iBGP is allowed)
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

    // Then EoR
    drain_eor(&mut out_rx).await;

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn ibgp_split_horizon_withdraw_on_best_change() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Setup: eBGP source announces route, iBGP target receives it
    let ebgp_source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let ibgp_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Register iBGP target peer
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: ibgp_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
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

    // eBGP route → should be advertised to iBGP peer
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: ebgp_source,
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

    // Now the eBGP source goes down, replaced by iBGP source
    tx.send(RibUpdate::PeerDown {
        peer: ebgp_source,
        session_id: 0,
    })
    .await
    .unwrap();

    // Withdraw should be sent to iBGP target
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.withdraw.len(), 1);

    // iBGP source announces the same prefix
    let ibgp_source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: ibgp_source,
        announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 3))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Force serialization
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    // iBGP-learned route should NOT be sent to iBGP peer
    assert!(out_rx.try_recv().is_err());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn local_route_sent_to_ibgp_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Register iBGP target peer first
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
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
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

    // Inject a local route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: LOCAL_PEER,
        attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::InjectRoute {
        route,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let _ = reply_rx.await;

    // Local route SHOULD be sent to iBGP peer (unlike iBGP-learned routes)
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn local_route_in_initial_table_to_ibgp_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Inject a local route first
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: LOCAL_PEER,
        attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::InjectRoute {
        route,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let _ = reply_rx.await;

    // Register iBGP target peer — should receive local route in initial dump
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
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    // Initial dump should include the local route
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

    // Then EoR
    drain_eor(&mut out_rx).await;

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn peer_down_cleans_up_outbound() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (out_tx, _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer,
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

    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    })
    .await
    .unwrap();

    // Query advertised routes — should be empty after PeerDown
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer,
        reply: reply_tx,
    })
    .await
    .unwrap();

    let routes = reply_rx.await.unwrap();
    assert!(routes.is_empty());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn inject_route_enters_loc_rib_and_distributes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
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

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: LOCAL_PEER,
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
        ]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::InjectRoute {
        route,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    // Should be in Loc-RIB
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].prefix, Prefix::V4(prefix));

    // Should have been distributed
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn withdraw_injected_removes_and_distributes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
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

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: LOCAL_PEER,
        attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::InjectRoute {
        route,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let _ = reply_rx.await;

    // Consume the inject announcement
    let _ = out_rx.recv().await;

    // Now withdraw
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::WithdrawInjected {
        prefix: Prefix::V4(prefix),
        path_id: 0,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    // Should receive withdrawal
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.withdraw.len(), 1);
    assert_eq!(update.withdraw[0], (Prefix::V4(prefix), 0));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn distribute_changes_filters_unsendable_families() {
    use rustbgpd_wire::Ipv6Prefix;

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);

    // Register peer with IPv4-only sendable families
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
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

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

    let v4_route = make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1));
    let v6_route = Route {
        prefix: Prefix::V6(v6_prefix),
        next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
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

    // Send both IPv4 and IPv6 routes
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![v4_route, v6_route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Should only receive IPv4 route
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(v4_prefix));
    assert!(update.withdraw.is_empty());

    // Adj-RIB-Out should only contain IPv4
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let advertised = reply_rx.await.unwrap();
    assert_eq!(advertised.len(), 1);
    assert_eq!(advertised[0].prefix, Prefix::V4(v4_prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn send_initial_table_filters_unsendable_families() {
    use rustbgpd_wire::Ipv6Prefix;

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

    let v4_route = make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1));
    let v6_route = Route {
        prefix: Prefix::V6(v6_prefix),
        next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
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

    // Pre-populate Loc-RIB with both IPv4 and IPv6 routes
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![v4_route, v6_route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Register peer with IPv4-only sendable families — initial dump
    // should filter out the IPv6 route
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

    // Initial table dump should only contain IPv4
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(v4_prefix));
    assert!(update.withdraw.is_empty());

    // Adj-RIB-Out should only contain IPv4
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let advertised = reply_rx.await.unwrap();
    assert_eq!(advertised.len(), 1);
    assert_eq!(advertised[0].prefix, Prefix::V4(v4_prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn dual_stack_peer_receives_both_families() {
    use rustbgpd_wire::Ipv6Prefix;

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

    let v4_route = make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1));
    let v6_route = Route {
        prefix: Prefix::V6(v6_prefix),
        next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
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

    // Pre-populate Loc-RIB
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![v4_route, v6_route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Register peer with dual-stack sendable families
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
        sendable_families: dual_stack_sendable(),
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

    // Should receive both routes in initial dump
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 2);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rr_client_route_reflected_to_all_ibgp() {
    // When RR receives a route from a client, it should reflect to all
    // iBGP peers (both clients and non-clients), except the source.
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 1));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let client_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let nonclient_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

    // Register source as iBGP client
    let (out_tx_src, _) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx_src,
        export_policy: None,
        sendable_families: ipv4_sendable(),
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

    // Register client target
    let (client_tx, mut client_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: client_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: client_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
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
    drain_eor(&mut client_rx).await;

    // Register non-client target
    let (nonclient_tx, mut nonclient_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: nonclient_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: nonclient_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut nonclient_rx).await;

    // Source client sends a route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 4))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Both targets should receive the reflected route
    let client_update = client_rx.recv().await.unwrap();
    assert!(
        !client_update.announce.is_empty(),
        "client should receive reflected route"
    );

    let nonclient_update = nonclient_rx.recv().await.unwrap();
    assert!(
        !nonclient_update.announce.is_empty(),
        "non-client should receive route reflected from client"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rr_nonclient_route_reflected_to_clients_only() {
    // Route from non-client → reflect to clients only (not non-clients).
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 1));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)); // non-client
    let client_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let nonclient_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));

    // Register source as non-client
    let (out_tx_src, _) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx_src,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    // Register client target
    let (client_tx, mut client_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: client_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: client_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
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
    drain_eor(&mut client_rx).await;

    // Register non-client target
    let (nonclient_tx, mut nonclient_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: nonclient_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: nonclient_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut nonclient_rx).await;

    // Source sends a route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 2))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Client should get the route
    let update_c = client_rx.recv().await.unwrap();
    assert!(
        !update_c.announce.is_empty(),
        "client should receive non-client route"
    );

    // Non-client should NOT get the route (suppressed by RR)
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        nonclient_rx.try_recv().is_err(),
        "non-client should not receive non-client route"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn non_rr_ibgp_split_horizon_unchanged() {
    // Without cluster_id (no RR), standard split-horizon applies
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

    // Register target first (Loc-RIB empty, clean EoR)
    let (out_tx, mut out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
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

    // Source sends iBGP route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 2))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // iBGP route should be suppressed (standard split-horizon)
    assert!(
        out_rx.try_recv().is_err(),
        "iBGP route should be suppressed without RR"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rr_ebgp_route_to_all_ibgp() {
    // eBGP-learned routes should go to all iBGP peers regardless of RR role
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 1));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)); // iBGP non-client

    // Register target first (Loc-RIB empty, clean EoR)
    let (out_tx, mut out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
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

    // eBGP source sends a route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 5))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(
        !update.announce.is_empty(),
        "eBGP route should reach iBGP non-client"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rr_local_route_to_all_ibgp() {
    // Local routes should pass to all iBGP peers even with RR
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 1));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

    // Register target first (Loc-RIB empty, clean EoR)
    let (out_tx, mut out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
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

    // Inject local route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: LOCAL_PEER,
        attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    let (reply_tx, _) = oneshot::channel();
    tx.send(RibUpdate::InjectRoute {
        route,
        reply: reply_tx,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(
        !update.announce.is_empty(),
        "local route should reach iBGP non-client via RR"
    );

    drop(tx);
    handle.await.unwrap();
}

// --- RPKI integration tests ---
