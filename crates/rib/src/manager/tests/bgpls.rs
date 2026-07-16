use super::*;

fn with_bgpls_no_advertise(mut route: crate::route::BgpLsRibRoute) -> crate::route::BgpLsRibRoute {
    Arc::make_mut(&mut route.attributes).push(PathAttribute::Communities(vec![
        rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
    ]));
    route
}

fn bgpls_no_advertise_policy(next_hop: IpAddr, add: bool) -> rustbgpd_policy::PolicyChain {
    rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
        entries: vec![rustbgpd_policy::PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: rustbgpd_policy::PolicyAction::Permit,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: Some(next_hop),
            modifications: rustbgpd_policy::RouteModifications {
                communities_add: add
                    .then_some(rustbgpd_wire::COMMUNITY_NO_ADVERTISE)
                    .into_iter()
                    .collect(),
                communities_remove: (!add)
                    .then_some(rustbgpd_wire::COMMUNITY_NO_ADVERTISE)
                    .into_iter()
                    .collect(),
                ..rustbgpd_policy::RouteModifications::default()
            },
        }],
        default_action: rustbgpd_policy::PolicyAction::Permit,
    }])
}

fn make_bgpls_policy_route(
    family: crate::route::BgpLsFamily,
    peer: Ipv4Addr,
) -> crate::route::BgpLsRibRoute {
    let mut route = make_bgpls_route(peer, 42, 100);
    route.family = family;
    if family == crate::route::BgpLsFamily::LinkStateVpn {
        route.nlri = rustbgpd_wire::bgpls::decode_bgpls_vpn_nlri(&[
            0xfd, 0xe8, 0, 11, // 8-byte RD + 3-byte opaque payload
            0, 0, 0xfd, 0xe8, 0, 0, 0, 42, 0xaa, 0xbb, 0x2a,
        ])
        .expect("fixture BGP-LS VPN NLRI decodes")
        .pop()
        .expect("fixture contains one BGP-LS VPN NLRI");
    }
    route
}

#[tokio::test]
async fn bgpls_routes_received_recompute_and_withdraw() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let first_advertiser = Ipv4Addr::new(10, 0, 0, 1);
    let better_advertiser = Ipv4Addr::new(10, 0, 0, 2);
    let first_peer = IpAddr::V4(first_advertiser);
    let better_peer = IpAddr::V4(better_advertiser);
    let route_a = make_bgpls_route(first_advertiser, 7, 100);
    let route_b = make_bgpls_route(better_advertiser, 7, 200);
    let key: BgpLsRouteKey = route_a.key();
    assert_eq!(route_b.key(), key);

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: first_peer,
        announced: vec![route_a],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let best_after_first = query_bgpls_routes(&tx).await;
    assert_eq!(best_after_first.len(), 1);
    assert_eq!(best_after_first[0].peer, first_peer);

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: better_peer,
        announced: vec![route_b],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let best_after_second = query_bgpls_routes(&tx).await;
    assert_eq!(best_after_second.len(), 1);
    assert_eq!(best_after_second[0].peer, better_peer);

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: better_peer,
        announced: vec![],
        withdrawn: vec![key.clone()],
    })
    .await
    .unwrap();

    let best_after_withdraw_b = query_bgpls_routes(&tx).await;
    assert_eq!(best_after_withdraw_b.len(), 1);
    assert_eq!(best_after_withdraw_b[0].peer, first_peer);

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: first_peer,
        announced: vec![],
        withdrawn: vec![key],
    })
    .await
    .unwrap();

    let best_after_withdraw_a = query_bgpls_routes(&tx).await;
    assert!(best_after_withdraw_a.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// The topology query builds from every peer's Adj-RIB-In union — NOT the
/// Loc-RIB best-only view. Two peers advertise disjoint links; the
/// snapshot must contain both.
#[tokio::test]
async fn query_topology_reflects_adj_rib_in_across_multiple_peers() {
    use crate::orr::fixtures::{A, B, X, Y, link_route};

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = Ipv4Addr::new(10, 0, 0, 1);
    let peer2 = Ipv4Addr::new(10, 0, 0, 2);
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer1),
        announced: vec![link_route(peer1, A, X, Some(1), &[])],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer2),
        announced: vec![link_route(peer2, B, Y, Some(1), &[])],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let snapshot = query_orr_topology(&tx).await;
    assert_eq!(
        snapshot.nodes.len(),
        4,
        "endpoints from both peers interned"
    );
    assert_eq!(
        snapshot.links.len(),
        2,
        "disjoint links from both peers kept"
    );
    assert!(snapshot.prefixes.is_empty());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn bgpls_routes_received_reflects_and_withdraws_to_eligible_peer() {
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
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100);
    let key = route.key();

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route.clone()],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert!(update.withdraw.is_empty());
    assert_eq!(update.bgpls_announce.len(), 1);
    assert_eq!(update.bgpls_announce[0].key(), key);
    assert!(update.bgpls_withdraw.is_empty());

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![key.clone()],
    })
    .await
    .unwrap();

    let withdraw = out_rx.recv().await.unwrap();
    assert!(withdraw.bgpls_announce.is_empty());
    assert_eq!(withdraw.bgpls_withdraw, vec![key]);

    drop(tx);
    handle.await.unwrap();
}

/// Both BGP-LS SAFIs enforce RFC 1997 before and after export policy,
/// withdraw the exact prior Adj-RIB-Out identity, and recover when the source
/// or policy scope is removed.
///
/// Break-to-red: deleting the pre-policy guard lets the removal policy export
/// the source-scoped route; deleting the post-policy guard retains the route
/// when policy adds `NO_ADVERTISE`; deleting either existing-state withdrawal
/// leaves the exact SAFI-specific key advertised; sticky suppression prevents
/// the two recovery announcements.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one ordered state-machine regression covers both BGP-LS SAFIs"
)]
async fn bgpls_no_advertise_withdraws_exact_prior_and_recovers_for_both_safis() {
    #[expect(
        clippy::too_many_lines,
        reason = "the per-SAFI sequence proves suppression, withdrawal, and recovery"
    )]
    async fn exercise(family: crate::route::BgpLsFamily) {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());
        let source = Ipv4Addr::new(198, 51, 100, 11);
        let source_ip = IpAddr::V4(source);
        let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 31));
        let (out_tx, mut out_rx) = mpsc::channel(16);
        tx.send(RibUpdate::PeerUp {
            per_client_best: false,
            interpret_rfc1997: true,
            session_id: 0,
            peer: target,
            peer_asn: 65100,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx: out_tx,
            export_policy: Some(bgpls_no_advertise_policy(source_ip, false)),
            sendable_families: vec![family.to_afi_safi()],
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

        let route = make_bgpls_policy_route(family, source);
        let key = route.key();
        tx.send(RibUpdate::BgpLsRoutesReceived {
            session_id: 0,
            peer: source_ip,
            announced: vec![route.clone()],
            withdrawn: vec![],
        })
        .await
        .unwrap();
        let _ = query_bgpls_routes(&tx).await;
        let initial = out_rx
            .try_recv()
            .expect("plain BGP-LS route must be announced");
        assert_eq!(initial.bgpls_announce.len(), 1);
        assert_eq!(initial.bgpls_announce[0].key(), key);

        tx.send(RibUpdate::BgpLsRoutesReceived {
            session_id: 0,
            peer: source_ip,
            announced: vec![with_bgpls_no_advertise(route.clone())],
            withdrawn: vec![],
        })
        .await
        .unwrap();
        let _ = query_bgpls_routes(&tx).await;
        let source_scoped = out_rx
            .try_recv()
            .expect("source NO_ADVERTISE must withdraw the prior BGP-LS route");
        assert!(source_scoped.bgpls_announce.is_empty());
        assert_eq!(source_scoped.bgpls_withdraw, vec![key.clone()]);

        tx.send(RibUpdate::BgpLsRoutesReceived {
            session_id: 0,
            peer: source_ip,
            announced: vec![route],
            withdrawn: vec![],
        })
        .await
        .unwrap();
        let _ = query_bgpls_routes(&tx).await;
        let source_recovered = out_rx.try_recv().expect("plain BGP-LS route must recover");
        assert_eq!(source_recovered.bgpls_announce.len(), 1);
        assert!(source_recovered.bgpls_withdraw.is_empty());

        let (reply, response) = oneshot::channel();
        tx.send(RibUpdate::ReplacePeerExportPolicy {
            peer: target,
            export_policy: Some(bgpls_no_advertise_policy(source_ip, true)),
            reply,
        })
        .await
        .unwrap();
        response.await.unwrap().unwrap();
        let _ = query_bgpls_routes(&tx).await;
        let policy_scoped = out_rx
            .try_recv()
            .expect("policy-added NO_ADVERTISE must withdraw BGP-LS");
        assert!(policy_scoped.bgpls_announce.is_empty());
        assert_eq!(policy_scoped.bgpls_withdraw, vec![key]);

        let (reply, response) = oneshot::channel();
        tx.send(RibUpdate::ReplacePeerExportPolicy {
            peer: target,
            export_policy: Some(bgpls_no_advertise_policy(source_ip, false)),
            reply,
        })
        .await
        .unwrap();
        response.await.unwrap().unwrap();
        let _ = query_bgpls_routes(&tx).await;
        let policy_recovered = out_rx
            .try_recv()
            .expect("removing policy-added NO_ADVERTISE must re-announce BGP-LS");
        assert_eq!(policy_recovered.bgpls_announce.len(), 1);
        assert!(policy_recovered.bgpls_withdraw.is_empty());
        assert!(out_rx.try_recv().is_err());

        drop(tx);
        handle.await.unwrap();
    }

    exercise(crate::route::BgpLsFamily::LinkState).await;
    exercise(crate::route::BgpLsFamily::LinkStateVpn).await;
}

#[tokio::test]
async fn bgpls_export_policy_does_not_match_dummy_default_prefix() {
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
        export_policy: Some(deny_default_prefix_chain()),
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
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 36, 100);
    let key = route.key();

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert_eq!(
        update.bgpls_announce.len(),
        1,
        "BGP-LS topology NLRIs are prefixless and must not match 0.0.0.0/0 policy"
    );
    assert_eq!(update.bgpls_announce[0].key(), key);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn bgpls_routes_received_does_not_reflect_back_to_source_peer() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (source_out_tx, mut source_out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_out_tx,
        export_policy: None,
        sendable_families: bgpls_sendable(),
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
    drain_eor(&mut source_out_rx).await;

    let (other_out_tx, mut other_out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: other,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: other_out_tx,
        export_policy: None,
        sendable_families: bgpls_sendable(),
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
    drain_eor(&mut other_out_rx).await;

    let route = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 32, 100);
    let key = route.key();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let reflected = other_out_rx.recv().await.unwrap();
    assert_eq!(reflected.bgpls_announce.len(), 1);
    assert_eq!(reflected.bgpls_announce[0].key(), key);

    let source_self_echo =
        tokio::time::timeout(Duration::from_millis(50), source_out_rx.recv()).await;
    assert!(
        source_self_echo.is_err(),
        "BGP-LS routes must not be reflected back to the source peer"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn bgpls_routes_received_does_not_reflect_to_unsendable_peer() {
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

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        announced: vec![make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 32, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let no_update = tokio::time::timeout(Duration::from_millis(50), out_rx.recv()).await;
    assert!(
        no_update.is_err(),
        "peer without BGP-LS in sendable_families must not receive reflected routes"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn dirty_resync_includes_bgpls_routes_after_channel_full() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (out_tx, mut out_rx) = mpsc::channel(1);
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
    drain_eor(&mut out_rx).await;

    let route1 = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 34, 100);
    let key1 = route1.key();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route1],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let route2 = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 35, 100);
    let key2 = route2.key();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route2],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let first = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("first BGP-LS announce must arrive")
        .expect("channel open");
    assert_eq!(first.bgpls_announce.len(), 1);
    assert_eq!(first.bgpls_announce[0].key(), key1);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut saw_key2 = false;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), out_rx.recv()).await {
            Ok(Some(update)) => {
                if update
                    .bgpls_announce
                    .iter()
                    .any(|route| route.key() == key2)
                {
                    saw_key2 = true;
                    break;
                }
            }
            Ok(None) => panic!("outbound channel closed unexpectedly"),
            Err(_) => {}
        }
    }
    assert!(
        saw_key2,
        "dirty resync must eventually deliver the second BGP-LS announce to the target peer"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn send_initial_table_includes_bgpls_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 33, 100);
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

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert_eq!(update.bgpls_announce.len(), 1);
    assert_eq!(update.bgpls_announce[0].key(), key);
    assert!(update.bgpls_withdraw.is_empty());

    let eor = out_rx.recv().await.unwrap();
    assert_eq!(eor.end_of_rib, bgpls_sendable());

    drop(tx);
    handle.await.unwrap();
}

/// A peer going down must drop its BGP-LS routes from the Loc-RIB the same way
/// unicast/FlowSpec/EVPN do — otherwise the entries strand until process
/// restart and `QueryBgpLsRoutes`/`ListBgpLsRoutes` keep reporting a dead
/// peer's routes as live. Two peers advertise the same key so we can assert the
/// Loc-RIB *falls back* to the surviving peer on the first teardown, then
/// *empties* on the second.
#[tokio::test]
async fn bgpls_peer_down_clears_or_falls_back_loc_rib() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let best_advertiser = Ipv4Addr::new(10, 0, 0, 1);
    let alternate_advertiser = Ipv4Addr::new(10, 0, 0, 2);
    let best_peer = IpAddr::V4(best_advertiser);
    let alternate_peer = IpAddr::V4(alternate_advertiser);

    // Same opaque key (same NLRI payload suffix), different LOCAL_PREF so the
    // tie-break has a defined winner: peer A (200) beats peer B (100).
    let route_a = make_bgpls_route(best_advertiser, 9, 200);
    let route_b = make_bgpls_route(alternate_advertiser, 9, 100);
    let key: BgpLsRouteKey = route_a.key();
    assert_eq!(route_b.key(), key);

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: best_peer,
        announced: vec![route_a],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: alternate_peer,
        announced: vec![route_b],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let best_before = query_bgpls_routes(&tx).await;
    assert_eq!(best_before.len(), 1);
    assert_eq!(
        best_before[0].peer, best_peer,
        "higher LOCAL_PREF peer should win before teardown"
    );

    // Tear down the winner — the Loc-RIB must fall back to the surviving peer.
    tx.send(RibUpdate::PeerDown {
        peer: best_peer,
        session_id: 0,
    })
    .await
    .unwrap();

    let after_winner_down = query_bgpls_routes(&tx).await;
    assert_eq!(
        after_winner_down.len(),
        1,
        "Loc-RIB must fall back to the surviving peer, not strand the dead peer's route"
    );
    assert_eq!(
        after_winner_down[0].peer, alternate_peer,
        "surviving peer's route should be selected after the winner goes down"
    );

    // Tear down the last advertiser — the key must leave the Loc-RIB entirely.
    tx.send(RibUpdate::PeerDown {
        peer: alternate_peer,
        session_id: 0,
    })
    .await
    .unwrap();

    let after_last_down = query_bgpls_routes(&tx).await;
    assert!(
        after_last_down.is_empty(),
        "Loc-RIB must be empty once no peer advertises the BGP-LS key"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A peer entering GR with (`BgpLs`, `BgpLs`) in its capability keeps its
/// BGP-LS objects as stale (RFC 4724 helper retention). Staleness demotes
/// the tiebreak rank, so a fresh route from another peer takes over the
/// Loc-RIB; when every advertiser is stale, the normal tiebreak order
/// re-applies among the stale candidates and the key stays visible.
#[tokio::test]
async fn bgpls_gr_marks_stale_and_demotes_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let best_advertiser = Ipv4Addr::new(10, 0, 0, 1);
    let alternate_advertiser = Ipv4Addr::new(10, 0, 0, 2);
    let best_peer = IpAddr::V4(best_advertiser);
    let alternate_peer = IpAddr::V4(alternate_advertiser);

    let route_a = make_bgpls_route(best_advertiser, 10, 200);
    let route_b = make_bgpls_route(alternate_advertiser, 10, 100);
    assert_eq!(route_a.key(), route_b.key());

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: best_peer,
        announced: vec![route_a],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: alternate_peer,
        announced: vec![route_b],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let best_before = query_bgpls_routes(&tx).await;
    assert_eq!(best_before.len(), 1);
    assert_eq!(best_before[0].peer, best_peer);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: best_peer,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::BgpLs, Safi::BgpLs)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let after_winner_gr = query_bgpls_routes(&tx).await;
    assert_eq!(after_winner_gr.len(), 1);
    assert_eq!(
        after_winner_gr[0].peer, alternate_peer,
        "stale demotion must hand the Loc-RIB to the fresh alternate route"
    );
    assert!(!after_winner_gr[0].is_stale);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: alternate_peer,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::BgpLs, Safi::BgpLs)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let after_last_gr = query_bgpls_routes(&tx).await;
    assert_eq!(
        after_last_gr.len(),
        1,
        "GR must retain the stale BGP-LS route instead of dropping the key"
    );
    assert_eq!(
        after_last_gr[0].peer, best_peer,
        "with both candidates stale the normal tiebreak (higher LOCAL_PREF) re-applies"
    );
    assert!(after_last_gr[0].is_stale);

    drop(tx);
    handle.await.unwrap();
}

/// A peer whose GR capability does NOT list (`BgpLs`, `BgpLs`) must have its
/// BGP-LS routes withdrawn on GR entry — RFC 4724 retains only families in
/// the advertised capability.
#[tokio::test]
async fn bgpls_gr_family_not_in_capability_is_withdrawn() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let advertiser = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(advertiser);
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_bgpls_route(advertiser, 10, 200)],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    assert_eq!(query_bgpls_routes(&tx).await.len(), 1);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    assert!(
        query_bgpls_routes(&tx).await.is_empty(),
        "BGP-LS absent from the GR capability must be withdrawn, not retained stale"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Re-advertisement during the restart window replaces the stale route;
/// End-of-RIB clears the survivors' stale flags and removes what was not
/// re-advertised (RFC 4724 §4.1).
#[tokio::test]
async fn bgpls_gr_eor_clears_stale() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let advertiser = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(advertiser);
    let kept = make_bgpls_route(advertiser, 10, 200);
    let dropped = make_bgpls_route(advertiser, 20, 200);
    let kept_key = kept.key();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![kept.clone(), dropped],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::BgpLs, Safi::BgpLs)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();
    let stale = query_bgpls_routes(&tx).await;
    assert_eq!(stale.len(), 2);
    assert!(stale.iter().all(|r| r.is_stale));

    // Only `kept` is re-advertised before End-of-RIB.
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![kept],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer,
        afi: Afi::BgpLs,
        safi: Safi::BgpLs,
    })
    .await
    .unwrap();

    let after_eor = query_bgpls_routes(&tx).await;
    assert_eq!(
        after_eor.len(),
        1,
        "the non-readvertised stale route must be removed at End-of-RIB"
    );
    assert_eq!(after_eor[0].key(), kept_key);
    assert!(!after_eor[0].is_stale, "EoR must clear the stale flag");

    drop(tx);
    handle.await.unwrap();
}

/// GR timer expiry without LLGR purges the stale BGP-LS routes.
#[tokio::test]
async fn bgpls_gr_timer_sweeps_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let advertiser = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(advertiser);
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_bgpls_route(advertiser, 10, 200)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::BgpLs, Safi::BgpLs)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();
    let stale = query_bgpls_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    assert!(
        query_bgpls_routes(&tx).await.is_empty(),
        "GR timer expiry must sweep stale BGP-LS routes"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A second GR entry while routes are still stale (consecutive restart
/// without a refresh in between) deletes them instead of re-marking
/// (RFC 4724 §4.1), and the deletion propagates to the Loc-RIB.
#[tokio::test]
async fn bgpls_gr_consecutive_restart_deletes_stale_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let advertiser = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(advertiser);
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_bgpls_route(advertiser, 10, 200)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let gr_entry = |session_id| RibUpdate::PeerGracefulRestart {
        session_id,
        peer,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::BgpLs, Safi::BgpLs)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    };
    tx.send(gr_entry(0)).await.unwrap();
    let stale = query_bgpls_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    // The peer comes back and restarts again without re-advertising.
    tx.send(gr_entry(0)).await.unwrap();
    assert!(
        query_bgpls_routes(&tx).await.is_empty(),
        "a route still stale at the next restart must be deleted, not re-marked"
    );

    drop(tx);
    handle.await.unwrap();
}
