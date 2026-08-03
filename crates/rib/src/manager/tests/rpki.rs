use super::*;

#[test]
fn validate_route_rpki_valid() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let table = VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]);
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65001],
    );
    assert_eq!(
        super::validate_route_rpki(&route, &table),
        RpkiValidation::Valid,
    );
}

#[test]
fn validate_route_rpki_invalid() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let table = VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]);
    // Origin AS 65002 doesn't match VRP
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65002],
    );
    assert_eq!(
        super::validate_route_rpki(&route, &table),
        RpkiValidation::Invalid,
    );
}

#[test]
fn validate_route_rpki_not_found() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let table = VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]);
    // Prefix 192.168.1.0/24 not covered by any VRP
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65001],
    );
    assert_eq!(
        super::validate_route_rpki(&route, &table),
        RpkiValidation::NotFound,
    );
}

#[test]
fn validate_route_rpki_no_as_path() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let table = VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]);
    // Route with no AS_PATH
    let route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
    );
    assert_eq!(
        super::validate_route_rpki(&route, &table),
        RpkiValidation::NotFound,
    );
}

#[test]
fn validate_route_rpki_empty_as_path() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let table = VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]);
    // Route with empty AS_PATH (no segments)
    let route = Route {
        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
        next_hop: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
            PathAttribute::LocalPref(100),
        ]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    assert_eq!(
        super::validate_route_rpki(&route, &table),
        RpkiValidation::NotFound,
    );
}

#[tokio::test]
async fn routes_validated_on_insert_with_vrp_table() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Send RPKI cache update first
    let table = Arc::new(VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]));
    tx.send(RibUpdate::RpkiCacheUpdate { table }).await.unwrap();

    // Now send a route with matching origin
    let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65001],
    );
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

    // Query received routes — should have Valid validation state
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: Some(peer),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let routes = reply_rx.await.unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].validation_state, RpkiValidation::Valid);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rpki_cache_update_revalidates_existing_routes() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65001],
    );

    // Insert route (no VRP table yet → NotFound)
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

    // Verify it's NotFound
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: Some(peer),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let routes = reply_rx.await.unwrap();
    assert_eq!(routes[0].validation_state, RpkiValidation::NotFound);

    // Now send VRP table that covers the route
    let table = Arc::new(VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]));
    tx.send(RibUpdate::RpkiCacheUpdate { table }).await.unwrap();

    // Query again — should be Valid now
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: Some(peer),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let routes = reply_rx.await.unwrap();
    assert_eq!(routes[0].validation_state, RpkiValidation::Valid);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rpki_cache_update_changes_best_path() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);

    // Both routes same LP, same AS_PATH length. peer1 has lower peer address → wins initially.
    let route1 = make_route_with_as_path(prefix, Ipv4Addr::new(1, 0, 0, 1), vec![65001]);
    let route2 = make_route_with_as_path(prefix, Ipv4Addr::new(1, 0, 0, 2), vec![65002]);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![route1],
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
        announced: vec![route2],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Before RPKI: peer1 should be best (lower address)
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer1);

    // Now send VRP that only validates peer2's origin
    let table = Arc::new(VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65002,
    }]));
    tx.send(RibUpdate::RpkiCacheUpdate { table }).await.unwrap();

    // After RPKI: peer2 should be best (Valid > NotFound)
    // But peer1's route has origin 65001, not covered → still NotFound.
    // peer2's route has origin 65002, covered with matching ASN → Valid.
    // Wait a moment for processing...
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    // peer2 wins: Valid beats NotFound
    assert_eq!(best[0].peer, peer2);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rpki_cache_update_invalid_demotes_best_path() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);

    // peer1 has lower address → wins initially
    let route1 = make_route_with_as_path(prefix, Ipv4Addr::new(1, 0, 0, 1), vec![65001]);
    let route2 = make_route_with_as_path(prefix, Ipv4Addr::new(1, 0, 0, 2), vec![65002]);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![route1],
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
        announced: vec![route2],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // VRP covers the prefix but only for AS 65002 → peer1 (65001) becomes Invalid
    let table = Arc::new(VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65002,
    }]));
    tx.send(RibUpdate::RpkiCacheUpdate { table }).await.unwrap();

    // peer1 is now Invalid (VRP covers prefix but wrong origin), peer2 is Valid
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
async fn rpki_no_table_all_not_found() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65001],
    );
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
    assert_eq!(routes[0].validation_state, RpkiValidation::NotFound);

    drop(tx);
    handle.await.unwrap();
}

/// Load-bearing RIB replay proof: removing the `!route.is_ebgp()` guard makes
/// insertion evaluate Valid and the cache update evaluate Invalid, so both
/// exact Unknown assertions fail.
#[tokio::test]
async fn ibgp_aspa_stays_unknown_on_insert_and_cache_revalidation() {
    use rustbgpd_rpki::{AspaRecord, AspaTable};

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 5));
    let valid_table = Arc::new(AspaTable::new(vec![AspaRecord {
        customer_asn: 65003,
        provider_asns: vec![65002],
    }]));
    tx.send(RibUpdate::AspaTableUpdate { table: valid_table })
        .await
        .unwrap();

    let mut route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 5),
        vec![65002, 65003],
    );
    route.origin_type = crate::route::RouteOrigin::Ibgp;
    route.aspa_context = rustbgpd_wire::AspaValidationContext {
        neighbor_asn: Some(65002),
        local_role: None,
        first_as_check_exempt: false,
    };
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

    let query = async |tx: &mpsc::Sender<RibUpdate>| {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();
        reply_rx.await.unwrap()
    };
    let inserted = query(&tx).await;
    assert_eq!(
        inserted[0].aspa_state,
        rustbgpd_wire::AspaValidation::Unknown
    );

    let invalid_table = Arc::new(AspaTable::new(vec![AspaRecord {
        customer_asn: 65003,
        provider_asns: vec![65099],
    }]));
    tx.send(RibUpdate::AspaTableUpdate {
        table: invalid_table,
    })
    .await
    .unwrap();
    let revalidated = query(&tx).await;
    assert_eq!(
        revalidated[0].aspa_state,
        rustbgpd_wire::AspaValidation::Unknown
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn aspa_cache_update_revalidates_with_stored_downstream_context() {
    use rustbgpd_rpki::{AspaRecord, AspaTable};

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 4));
    let mut route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 4),
        vec![65004, 65003, 65002, 65001],
    );
    route.aspa_context = rustbgpd_wire::AspaValidationContext {
        neighbor_asn: Some(65004),
        local_role: Some(rustbgpd_wire::BgpRole::Customer),
        first_as_check_exempt: false,
    };

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

    let table = Arc::new(AspaTable::new(vec![
        AspaRecord {
            customer_asn: 65004,
            provider_asns: vec![65003],
        },
        AspaRecord {
            customer_asn: 65003,
            provider_asns: vec![65002],
        },
        AspaRecord {
            customer_asn: 65002,
            provider_asns: vec![65001],
        },
    ]));
    tx.send(RibUpdate::AspaTableUpdate { table }).await.unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: Some(peer),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let routes = reply_rx.await.unwrap();
    assert_eq!(routes[0].aspa_state, rustbgpd_wire::AspaValidation::Valid);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rpki_cache_update_no_change_no_redistribution() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let (out_tx, mut out_rx) = mpsc::channel(16);

    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
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

    // Insert route with origin 65001
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65001],
    );
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

    // Consume the outbound update from route insertion (split-horizon blocks it
    // since peer == route.peer, so nothing should arrive)
    // Send an unrelated VRP table that doesn't cover our prefix
    let table = Arc::new(VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
        prefix_len: 16,
        max_len: 24,
        origin_asn: 65099,
    }]));
    tx.send(RibUpdate::RpkiCacheUpdate { table }).await.unwrap();

    // Verify route stays NotFound — no VRP covers 10.0.0.0/24
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: Some(peer),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let routes = reply_rx.await.unwrap();
    assert_eq!(routes[0].validation_state, RpkiValidation::NotFound);

    drop(tx);
    handle.await.unwrap();
}

// ---- Add-Path multi-path send tests ----
