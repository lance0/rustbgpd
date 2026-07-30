use super::*;
use crate::best_path::BestPathReason;

/// Helper: build an IPv6 route with specific peer, AS path, and
/// `LOCAL_PREF` for dual-stack Add-Path tests.
fn make_multipath_route_v6(
    prefix: Ipv6Prefix,
    peer: Ipv4Addr,
    next_hop: Ipv6Addr,
    asns: Vec<u32>,
    local_pref: u32,
) -> Route {
    Route {
        prefix: Prefix::V6(prefix),
        next_hop: IpAddr::V6(next_hop),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(peer),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(asns)],
            }),
            PathAttribute::LocalPref(local_pref),
        ]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
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
async fn multipath_send_advertises_multiple_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Inject two routes for the same prefix from different peers
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 1),
            vec![65001],
            200,
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
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![65002],
            100,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Register multi-path target (send_max=5)
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
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 5,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    // Initial dump should contain both routes
    let update = out_rx.recv().await.unwrap();
    assert_eq!(
        update.announce.len(),
        2,
        "multi-path peer should receive 2 routes"
    );
    // path_ids should be 1-indexed rank
    let mut path_ids: Vec<u32> = update.announce.iter().map(|r| r.path_id).collect();
    path_ids.sort_unstable();
    assert_eq!(path_ids, vec![1, 2]);
    // Higher LOCAL_PREF route should be path_id 1 (best)
    let best = update.announce.iter().find(|r| r.path_id == 1).unwrap();
    assert_eq!(best.next_hop, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

    drop(tx);
    handle.await.unwrap();
}

#[expect(
    clippy::too_many_lines,
    reason = "one live session proves initial rank, payload replacement, explain, and withdrawal compaction"
)]
#[tokio::test]
async fn same_peer_add_path_rank_is_stable_across_order_and_replacement() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 7, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 7, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);

    let mut path_7 = make_multipath_route(prefix, Ipv4Addr::new(10, 0, 7, 1), vec![65001], 100);
    path_7.path_id = 7;
    path_7.next_hop = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    let mut path_9 = path_7.clone();
    path_9.path_id = 9;
    path_9.next_hop = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![path_9.clone(), path_7.clone()],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

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
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 2,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    })
    .await
    .unwrap();

    let initial = out_rx.recv().await.unwrap();
    assert_eq!(initial.announce.len(), 2);
    assert_eq!(
        initial
            .announce
            .iter()
            .find(|route| route.path_id == 1)
            .unwrap()
            .next_hop,
        path_7.next_hop,
        "reverse insertion order must not assign rank 1 to path 9"
    );
    drain_eor(&mut out_rx).await;

    let explain = query_explain_best_path_for_peer(&tx, Prefix::V4(prefix), target)
        .await
        .unwrap();
    assert_eq!(explain.best.as_ref().unwrap().path_id, 7);
    assert_eq!(explain.best_reason, Some(BestPathReason::LowerPathId));
    assert_eq!(explain.best_reason_detail, "path_id 7 < 9");
    assert_eq!(
        explain.candidates[0].vs_best_reason,
        BestPathReason::LowerPathId
    );
    assert_eq!(explain.candidates[0].vs_best_detail, "path_id 9 > 7");
    assert_eq!(explain.candidates[0].advertised_path_id, 2);

    path_7.next_hop = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![path_7.clone()],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;
    let replacement = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("replacement update must arrive")
        .expect("outbound channel must stay open");
    assert_eq!(replacement.announce.len(), 1);
    assert_eq!(replacement.announce[0].path_id, 1);
    assert_eq!(replacement.announce[0].next_hop, path_7.next_hop);
    assert!(replacement.withdraw.is_empty());
    assert!(
        matches!(out_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "replacement must produce one exact outbound update"
    );

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix), 7)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;
    let reranked = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("rerank update must arrive")
        .expect("outbound channel must stay open");
    assert_eq!(reranked.announce.len(), 1);
    assert_eq!(reranked.announce[0].path_id, 1);
    assert_eq!(reranked.announce[0].next_hop, path_9.next_hop);
    assert_eq!(reranked.withdraw, vec![(Prefix::V4(prefix), 2)]);
    assert!(
        matches!(out_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "withdrawal must produce one exact rerank update"
    );

    drop(tx);
    handle.await.unwrap();
}

/// `NO_ADVERTISE` removes one Add-Path candidate before ranking and
/// export policy. The remaining sibling compacts to rank/path-id 1;
/// the old rank 2 is withdrawn even when policy would remove the
/// well-known community and permit the scoped route.
#[expect(
    clippy::too_many_lines,
    reason = "one scenario proves live and explain rank parity before and after policy"
)]
#[tokio::test]
async fn no_advertise_candidate_is_removed_before_add_path_rank_compaction() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let source_a = Ipv4Addr::new(10, 0, 1, 1);
    let source_b = Ipv4Addr::new(10, 0, 1, 2);
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 3));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);

    for (source, local_pref) in [(source_a, 200), (source_b, 100)] {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: IpAddr::V4(source),
            announced: vec![make_multipath_route(
                prefix,
                source,
                vec![u32::from(source.octets()[3]) + 65000],
                local_pref,
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: Some(super::unicast::no_advertise_removal_chain(false)),
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 2,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    })
    .await
    .unwrap();
    let initial = out_rx.recv().await.unwrap();
    assert_eq!(initial.announce.len(), 2);
    assert_eq!(
        initial
            .announce
            .iter()
            .find(|route| route.path_id == 1)
            .unwrap()
            .peer,
        IpAddr::V4(source_a)
    );
    drain_eor(&mut out_rx).await;

    let scoped =
        super::unicast::with_no_advertise(make_multipath_route(prefix, source_a, vec![65001], 200));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source_a),
        announced: vec![scoped],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;

    let update = out_rx
        .try_recv()
        .expect("rank compaction emitted after query synchronization");
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].peer, IpAddr::V4(source_b));
    assert_eq!(update.announce[0].path_id, 1);
    assert_eq!(update.withdraw, vec![(Prefix::V4(prefix), 2)]);
    assert!(
        out_rx.try_recv().is_err(),
        "one compact delta is sufficient"
    );

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply,
    })
    .await
    .unwrap();
    let advertised = response.await.unwrap();
    assert_eq!(advertised.len(), 1);
    assert_eq!(advertised[0].peer, IpAddr::V4(source_b));
    assert_eq!(advertised[0].path_id, 1);

    let explain = query_explain_best_path_for_peer(&tx, Prefix::V4(prefix), target)
        .await
        .expect("known Add-Path peer");
    let sibling = explain
        .candidates
        .iter()
        .find(|candidate| candidate.route.peer == IpAddr::V4(source_b))
        .expect("runner-up is present in best-path explain");
    assert_eq!(
        sibling.advertised_path_id, 1,
        "ExplainBestPath applies pre-policy NO_ADVERTISE before rank assignment"
    );

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: target,
        export_policy: Some(super::unicast::no_advertise_addition_chain(false)),
        reply,
    })
    .await
    .unwrap();
    assert_eq!(response.await.unwrap(), Ok(()));
    let _ = query_best_routes(&tx).await;

    let update = out_rx
        .try_recv()
        .expect("policy-added NO_ADVERTISE withdraws the remaining rank");
    assert!(update.announce.is_empty());
    assert_eq!(update.withdraw, vec![(Prefix::V4(prefix), 1)]);
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply,
    })
    .await
    .unwrap();
    assert!(response.await.unwrap().is_empty());

    let explain = query_explain_best_path_for_peer(&tx, Prefix::V4(prefix), target)
        .await
        .expect("known Add-Path peer");
    let sibling = explain
        .candidates
        .iter()
        .find(|candidate| candidate.route.peer == IpAddr::V4(source_b))
        .expect("runner-up is present in best-path explain");
    assert_eq!(
        sibling.advertised_path_id, 0,
        "ExplainBestPath skips post-policy NO_ADVERTISE before rank assignment"
    );

    // Post-policy NO_ADVERTISE suppression must surface through live
    // policy-filtered observability, not only export explain.
    let history = query_route_event_history(&tx, Some(target), Some(Afi::Ipv4), None, 10).await;
    let policy_filtered = history
        .iter()
        .filter(|event| event.event_type == RouteEventType::PolicyFiltered)
        .collect::<Vec<_>>();
    assert_eq!(
        policy_filtered.len(),
        1,
        "policy-added NO_ADVERTISE emits one policy-filtered event"
    );
    assert_eq!(policy_filtered[0].peer, Some(IpAddr::V4(source_b)));
    assert_eq!(policy_filtered[0].target_peer, Some(target));
    assert_eq!(policy_filtered[0].prefix, Prefix::V4(prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_send_respects_send_max() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let peer3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Inject 3 routes
    for (peer, peer_addr, asn, lp) in [
        (peer1, Ipv4Addr::new(10, 0, 0, 1), 65001, 200),
        (peer2, Ipv4Addr::new(10, 0, 0, 2), 65002, 150),
        (peer3, Ipv4Addr::new(10, 0, 0, 3), 65003, 100),
    ] {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer,
            announced: vec![make_multipath_route(prefix, peer_addr, vec![asn], lp)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

    // Register target with send_max=2
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
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 2,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert_eq!(
        update.announce.len(),
        2,
        "send_max=2 should limit to 2 routes"
    );
    // Should be the top 2 by LOCAL_PREF (200 and 150)
    let next_hops: Vec<IpAddr> = update.announce.iter().map(|r| r.next_hop).collect();
    assert!(next_hops.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(next_hops.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_send_split_horizon() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Inject route from peer1 and target (target's own route)
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 1),
            vec![65001],
            200,
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
        peer: target,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![65002],
            100,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Register multi-path target
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
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 5,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert_eq!(
        update.announce.len(),
        1,
        "split-horizon should exclude target's own route"
    );
    assert_eq!(
        update.announce[0].next_hop,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_withdrawal_on_candidate_removal() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Register multi-path target first
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
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 5,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Inject 2 routes
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 1),
            vec![65001],
            200,
        )],
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

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer2,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![65002],
            100,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    // Should now have an announcement for the second path
    assert!(!update.announce.is_empty());

    // Now withdraw peer2's route
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
    let update = out_rx.recv().await.unwrap();
    // Should have a withdrawal for the removed path
    assert!(
        !update.withdraw.is_empty(),
        "removing a candidate should produce a withdrawal"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn single_best_peer_unaffected_by_multipath_config() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Inject 2 routes
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 1),
            vec![65001],
            200,
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
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![65002],
            100,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Register single-best target (send_max=0)
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

    let update = out_rx.recv().await.unwrap();
    assert_eq!(
        update.announce.len(),
        1,
        "single-best peer should get only 1 route"
    );
    assert_eq!(
        update.announce[0].path_id, 0,
        "single-best peer should get path_id=0"
    );
    assert_eq!(
        update.announce[0].next_hop,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        "single-best peer should get the best route"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_peer_down_cleans_up_state() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // Register multi-path target
    let (out_tx, _out_rx) = mpsc::channel(64);
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
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 5,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    // Peer goes down
    tx.send(RibUpdate::PeerDown {
        peer: target,
        session_id: 0,
    })
    .await
    .unwrap();

    // Re-register as single-best (send_max=0) — should work fine,
    // state was properly cleaned up
    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![65001],
            100,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reconnect_tx, mut reconnect_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: reconnect_tx,
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

    let update = reconnect_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].path_id, 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_send_incremental_route_addition() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Register multi-path target
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
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 5,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Add first route
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 1),
            vec![65001],
            200,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1, "first route announced");
    assert_eq!(update.announce[0].path_id, 1);

    // Add second route — should get an incremental update
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer2,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![65002],
            100,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    // The new route should be announced (path_id 2)
    let new_announcements: Vec<_> = update
        .announce
        .iter()
        .filter(|r| r.next_hop == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        .collect();
    assert!(
        !new_announcements.is_empty(),
        "second route should be announced incrementally"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_send_mixed_peers_single_and_multi() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let source2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let multi_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let single_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Inject 2 routes
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source1,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 1),
            vec![65001],
            200,
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
        peer: source2,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![65002],
            100,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Register multi-path target
    let (multi_tx, mut multi_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: multi_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: multi_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 5,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    // Register single-best target
    let (single_tx, mut single_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: single_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: single_tx,
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

    // Multi-path target gets 2 routes
    let multi_update = multi_rx.recv().await.unwrap();
    assert_eq!(multi_update.announce.len(), 2);

    // Single-best target gets 1 route
    let single_update = single_rx.recv().await.unwrap();
    assert_eq!(single_update.announce.len(), 1);
    assert_eq!(single_update.announce[0].path_id, 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_send_ipv6_advertises_multiple_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48);

    let mk = |peer_addr: Ipv4Addr, asn: u32, local_pref: u32| Route {
        prefix: Prefix::V6(prefix),
        next_hop: "2001:db8::1".parse().unwrap(),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(peer_addr),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![asn])],
            }),
            PathAttribute::LocalPref(local_pref),
        ]),
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
        peer: peer1,
        announced: vec![mk(Ipv4Addr::new(10, 0, 0, 1), 65001, 200)],
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
        announced: vec![mk(Ipv4Addr::new(10, 0, 0, 2), 65002, 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

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
        sendable_families: vec![(Afi::Ipv6, Safi::Unicast)],
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![(Afi::Ipv6, Safi::Unicast)],
        add_path_send_max: 5,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert_eq!(
        update.announce.len(),
        2,
        "IPv6 multi-path peer should receive both routes"
    );
    let mut path_ids: Vec<u32> = update.announce.iter().map(|r| r.path_id).collect();
    path_ids.sort_unstable();
    assert_eq!(path_ids, vec![1, 2]);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_send_partial_negotiation_ipv4_only() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix4 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let prefix6 = Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![
            make_multipath_route(prefix4, Ipv4Addr::new(10, 0, 0, 1), vec![65001], 200),
            make_multipath_route_v6(
                prefix6,
                Ipv4Addr::new(10, 0, 0, 1),
                "2001:db8::1".parse().unwrap(),
                vec![65001],
                200,
            ),
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
            make_multipath_route(prefix4, Ipv4Addr::new(10, 0, 0, 2), vec![65002], 100),
            make_multipath_route_v6(
                prefix6,
                Ipv4Addr::new(10, 0, 0, 2),
                "2001:db8::2".parse().unwrap(),
                vec![65002],
                100,
            ),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

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
        sendable_families: dual_stack_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![(Afi::Ipv4, Safi::Unicast)],
        add_path_send_max: 5,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    let v4_routes: Vec<_> = update
        .announce
        .iter()
        .filter(|r| r.prefix == Prefix::V4(prefix4))
        .collect();
    let v6_routes: Vec<_> = update
        .announce
        .iter()
        .filter(|r| r.prefix == Prefix::V6(prefix6))
        .collect();
    assert_eq!(v4_routes.len(), 2, "IPv4 should use multi-path send");
    assert_eq!(v6_routes.len(), 1, "IPv6 should fall back to single-best");
    let mut v4_path_ids: Vec<u32> = v4_routes.iter().map(|r| r.path_id).collect();
    v4_path_ids.sort_unstable();
    assert_eq!(v4_path_ids, vec![1, 2]);
    assert_eq!(v6_routes[0].path_id, 0);
    drain_eor(&mut out_rx).await;

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_send_partial_negotiation_ipv6_only() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix4 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let prefix6 = Ipv6Prefix::new("2001:db8:2::".parse().unwrap(), 48);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![
            make_multipath_route(prefix4, Ipv4Addr::new(10, 0, 0, 1), vec![65001], 200),
            make_multipath_route_v6(
                prefix6,
                Ipv4Addr::new(10, 0, 0, 1),
                "2001:db8::1".parse().unwrap(),
                vec![65001],
                200,
            ),
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
            make_multipath_route(prefix4, Ipv4Addr::new(10, 0, 0, 2), vec![65002], 100),
            make_multipath_route_v6(
                prefix6,
                Ipv4Addr::new(10, 0, 0, 2),
                "2001:db8::2".parse().unwrap(),
                vec![65002],
                100,
            ),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

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
        sendable_families: dual_stack_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![(Afi::Ipv6, Safi::Unicast)],
        add_path_send_max: 5,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    let v4_routes: Vec<_> = update
        .announce
        .iter()
        .filter(|r| r.prefix == Prefix::V4(prefix4))
        .collect();
    let v6_routes: Vec<_> = update
        .announce
        .iter()
        .filter(|r| r.prefix == Prefix::V6(prefix6))
        .collect();
    assert_eq!(v4_routes.len(), 1, "IPv4 should fall back to single-best");
    assert_eq!(v6_routes.len(), 2, "IPv6 should use multi-path send");
    assert_eq!(v4_routes[0].path_id, 0);
    let mut v6_path_ids: Vec<u32> = v6_routes.iter().map(|r| r.path_id).collect();
    v6_path_ids.sort_unstable();
    assert_eq!(v6_path_ids, vec![1, 2]);
    drain_eor(&mut out_rx).await;

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "large end-to-end test covering many route-refresh edge cases"
)]
async fn route_refresh_partial_negotiation_respects_family_mode() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix4 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 10, 0), 24);
    let prefix6 = Ipv6Prefix::new("2001:db8:10::".parse().unwrap(), 48);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![
            make_multipath_route(prefix4, Ipv4Addr::new(10, 0, 0, 1), vec![65001], 200),
            make_multipath_route_v6(
                prefix6,
                Ipv4Addr::new(10, 0, 0, 1),
                "2001:db8::1".parse().unwrap(),
                vec![65001],
                200,
            ),
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
            make_multipath_route(prefix4, Ipv4Addr::new(10, 0, 0, 2), vec![65002], 100),
            make_multipath_route_v6(
                prefix6,
                Ipv4Addr::new(10, 0, 0, 2),
                "2001:db8::2".parse().unwrap(),
                vec![65002],
                100,
            ),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

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
        sendable_families: dual_stack_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![(Afi::Ipv4, Safi::Unicast)],
        add_path_send_max: 5,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    let _ = out_rx.recv().await.unwrap();
    drain_eor(&mut out_rx).await;

    tx.send(RibUpdate::RouteRefreshRequest {
        session_id: 0,
        peer: target,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    let v4_routes: Vec<_> = update
        .announce
        .iter()
        .filter(|r| r.prefix == Prefix::V4(prefix4))
        .collect();
    assert_eq!(v4_routes.len(), 2, "IPv4 refresh should be multi-path");
    let mut v4_path_ids: Vec<u32> = v4_routes.iter().map(|r| r.path_id).collect();
    v4_path_ids.sort_unstable();
    assert_eq!(v4_path_ids, vec![1, 2]);
    assert_eq!(update.end_of_rib, vec![(Afi::Ipv4, Safi::Unicast)]);

    tx.send(RibUpdate::RouteRefreshRequest {
        session_id: 0,
        peer: target,
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    let v6_routes: Vec<_> = update
        .announce
        .iter()
        .filter(|r| r.prefix == Prefix::V6(prefix6))
        .collect();
    assert_eq!(v6_routes.len(), 1, "IPv6 refresh should be single-best");
    assert_eq!(v6_routes[0].path_id, 0);
    assert_eq!(update.end_of_rib, vec![(Afi::Ipv6, Safi::Unicast)]);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_send_max_one_uses_path_id_one() {
    // send_max=1 should behave like single-best but with path_id=1 (not 0).
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 1),
            vec![65001],
            200,
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
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![65002],
            100,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

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
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 1,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1, "send_max=1 sends only one route");
    assert_eq!(
        update.announce[0].path_id, 1,
        "multi-path peer uses path_id=1 not 0"
    );
    assert_eq!(
        update.announce[0].next_hop,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        "should be the best route"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "multipath policy-filter scenario keeps both peers and assertions together"
)]
async fn multipath_policy_filtered_events_for_denied_candidates() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

    // Deny all prefixes in 192.168.0.0/16
    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 16);
    let export_policy = PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: Some(Prefix::V4(denied_prefix)),
            ge: None,
            le: Some(32),
            action: PolicyAction::Deny,
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
            match_next_hop: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }]);

    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(
        rx,
        dummy_query_rx(),
        Some(export_policy),
        None,
        metrics.clone(),
    );
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Register multi-path target
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
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 5,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Inject 2 routes for the denied prefix
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 1),
            vec![65001],
            200,
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
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![65002],
            100,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Force serialization — query to ensure all RoutesReceived processed
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    // No outbound updates should have been sent (all denied)
    assert!(
        out_rx.try_recv().is_err(),
        "all candidates denied by export policy — nothing sent"
    );
    let history = query_route_event_history(&tx, Some(target), Some(Afi::Ipv4), None, 10).await;
    let policy_filtered = history
        .iter()
        .filter(|event| event.event_type == RouteEventType::PolicyFiltered)
        .collect::<Vec<_>>();
    assert_eq!(policy_filtered.len(), 2);
    assert!(policy_filtered.iter().all(|event| {
        event.target_peer == Some(target)
            && event.prefix == Prefix::V4(prefix)
            && event.reason == "policy_denied"
    }));
    assert!(
        (policy_metric_value(&metrics, "10.0.0.3", "inline", "export", "deny") - 3.0).abs()
            < f64::EPSILON
    );
    let stats = query_neighbor_policy_stats(&tx, target).await;
    assert_eq!(stats.export_policy_routes_permitted, 0);
    assert_eq!(stats.export_policy_routes_denied, 3);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn fib_install_candidates_groups_equal_cost_ecmp() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));
    // Two equal-cost eBGP paths (empty attrs ⇒ same LP/AS/origin/MED/class).
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
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
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 2))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let cands = query_fib_install_candidates(&tx, 2).await;
    assert_eq!(cands.len(), 1);
    let c = &cands[0];
    let nhs: Vec<IpAddr> = c.next_hops.iter().map(|n| n.next_hop).collect();
    assert_eq!(nhs.len(), 2, "both equal-cost next-hops installed");
    // best (lower peer addr tiebreak) is index 0
    assert_eq!(c.next_hops[0].next_hop, c.best.next_hop);
    assert!(nhs.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(nhs.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn fib_install_candidates_preserve_link_local_next_hop_scope() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let scope = NextHopScope {
        interface: Arc::from("eth1"),
        ifindex: 7,
    };
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V6("fe80::1".parse().unwrap()),
        link_local_next_hop: Some("fe80::1".parse().unwrap()),
        next_hop_scope: Some(Box::new(scope.clone())),
        peer: IpAddr::V6("fe80::2".parse().unwrap()),
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

    let cands = query_fib_install_candidates(&tx, 1).await;
    assert_eq!(cands.len(), 1);
    assert_eq!(cands[0].best.next_hop_scope.as_deref(), Some(&scope));
    assert_eq!(cands[0].next_hops[0].next_hop_scope, Some(scope));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn fib_install_candidates_keep_same_link_local_on_distinct_ifindexes() {
    // ADR-0069: two equal-cost routes whose next-hop is the same fe80::/10
    // address but reached over different interfaces are distinct forwarding
    // next-hops. The ECMP dedup keys on (next-hop, ifindex), so both must
    // install as ECMP rather than collapsing to one path on the bare address.
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let shared_nh = IpAddr::V6("fe80::1".parse().unwrap());
    let make_scoped = |ifname: &'static str, ifindex: u32, peer: &str| Route {
        prefix: Prefix::V4(prefix),
        next_hop: shared_nh,
        link_local_next_hop: Some("fe80::1".parse().unwrap()),
        next_hop_scope: Some(Box::new(NextHopScope {
            interface: Arc::from(ifname),
            ifindex,
        })),
        peer: IpAddr::V6(peer.parse().unwrap()),
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
    for route in [
        make_scoped("eth1", 7, "fe80::2"),
        make_scoped("eth2", 9, "fe80::3"),
    ] {
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
    }

    let cands = query_fib_install_candidates(&tx, 2).await;
    assert_eq!(cands.len(), 1, "one prefix");
    let mut ifindexes: Vec<u32> = cands[0]
        .next_hops
        .iter()
        .filter_map(|nh| nh.next_hop_scope.as_ref().map(|scope| scope.ifindex))
        .collect();
    ifindexes.sort_unstable();
    assert_eq!(
        ifindexes,
        vec![7, 9],
        "same fe80:: next-hop on two ifindexes must install as two ECMP paths"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn fib_install_candidates_multipath_relax_groups_different_as_paths() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = Ipv4Addr::new(1, 0, 0, 1);
    let peer2 = Ipv4Addr::new(1, 0, 0, 2);
    // Same AS_PATH *length* (2), different ASNs: strict refuses to group, relax
    // (ADR-0066 multipath-relax) groups them as ECMP.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer1),
        announced: vec![make_route_with_as_path(prefix, peer1, vec![65001, 65010])],
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
        peer: IpAddr::V4(peer2),
        announced: vec![make_route_with_as_path(prefix, peer2, vec![65001, 65020])],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Strict: exact AS_PATH required → only the best installs (1 next-hop).
    let strict = query_fib_install_candidates_relax(&tx, 2, false).await;
    assert_eq!(strict.len(), 1);
    assert_eq!(
        strict[0].next_hops.len(),
        1,
        "strict mode: different AS_PATHs do not group"
    );

    // Relax: equal-length AS_PATHs co-install (2 next-hops).
    let relaxed = query_fib_install_candidates_relax(&tx, 2, true).await;
    assert_eq!(relaxed.len(), 1);
    assert_eq!(
        relaxed[0].next_hops.len(),
        2,
        "multipath-relax: equal-length AS_PATHs group as ECMP"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Attach a Link Bandwidth Extended Community (bytes/second) to a route.
fn make_route_with_link_bw(
    prefix: Ipv4Prefix,
    peer: Ipv4Addr,
    asns: Vec<u32>,
    bw: Option<f32>,
) -> Route {
    let mut route = make_route_with_as_path(prefix, peer, asns);
    if let Some(bw) = bw {
        Arc::make_mut(&mut route.attributes).push(PathAttribute::ExtendedCommunities(vec![
            ExtendedCommunity::link_bandwidth(65001, bw),
        ]));
    }
    route
}

#[tokio::test]
async fn fib_install_candidates_weighted_proportional_to_link_bandwidth() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = Ipv4Addr::new(1, 0, 0, 1); // best (lowest peer), 40G
    let peer2 = Ipv4Addr::new(1, 0, 0, 2); // sibling, 10G
    for (peer, bw) in [(peer1, 40e9), (peer2, 10e9)] {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: IpAddr::V4(peer),
            announced: vec![make_route_with_link_bw(
                prefix,
                peer,
                vec![65001, 65010],
                Some(bw),
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

    // Weighting on: 40G best maps to 256, the 10G sibling to 64 (ratio 1:4).
    let weighted = query_fib_install_candidates_weighted(&tx, 2, true).await;
    assert_eq!(weighted.len(), 1);
    let nhs = &weighted[0].next_hops;
    assert_eq!(nhs.len(), 2);
    assert_eq!(nhs[0].next_hop, IpAddr::V4(peer1));
    assert_eq!(nhs[0].weight, 256);
    assert_eq!(nhs[1].next_hop, IpAddr::V4(peer2));
    assert_eq!(nhs[1].weight, 64);

    // Weighting off: same group, every next-hop equal-cost (weight 1).
    let equal = query_fib_install_candidates_weighted(&tx, 2, false).await;
    assert!(equal[0].next_hops.iter().all(|nh| nh.weight == 1));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn fib_install_candidates_weighted_all_or_nothing_on_missing_bandwidth() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = Ipv4Addr::new(1, 0, 0, 1);
    let peer2 = Ipv4Addr::new(1, 0, 0, 2);
    // peer1 carries a Link Bandwidth community; peer2 does not.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer1),
        announced: vec![make_route_with_link_bw(
            prefix,
            peer1,
            vec![65001, 65010],
            Some(40e9),
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
        peer: IpAddr::V4(peer2),
        announced: vec![make_route_with_link_bw(
            prefix,
            peer2,
            vec![65001, 65010],
            None,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // A single path missing the community ⇒ the whole prefix stays equal-cost.
    let weighted = query_fib_install_candidates_weighted(&tx, 2, true).await;
    assert_eq!(weighted[0].next_hops.len(), 2);
    assert!(
        weighted[0].next_hops.iter().all(|nh| nh.weight == 1),
        "all-or-nothing: one missing bandwidth disables weighting for the group"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn fib_install_candidates_respects_max_paths() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    for (peer, nh) in [
        (
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            Ipv4Addr::new(10, 0, 0, 1),
        ),
        (
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2)),
            Ipv4Addr::new(10, 0, 0, 2),
        ),
    ] {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer,
            announced: vec![make_route(prefix, nh)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

    // max_paths=1 ⇒ single best next-hop only (today's behavior).
    let cands = query_fib_install_candidates(&tx, 1).await;
    assert_eq!(cands.len(), 1);
    assert_eq!(cands[0].next_hops.len(), 1);
    assert_eq!(cands[0].next_hops[0].next_hop, cands[0].best.next_hop);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn fib_install_candidates_dedupes_same_next_hop_before_cap() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let shared_nh = Ipv4Addr::new(10, 0, 0, 9);
    // Two peers advertising the SAME next-hop ⇒ collapses to one ECMP member.
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));
    let mut r1 = make_route(prefix, shared_nh);
    r1.peer = peer1;
    let mut r2 = make_route(prefix, shared_nh);
    r2.peer = peer2;
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![r1],
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
        announced: vec![r2],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let cands = query_fib_install_candidates(&tx, 2).await;
    assert_eq!(cands.len(), 1);
    assert_eq!(
        cands[0].next_hops.len(),
        1,
        "same next-hop deduped before cap"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn fib_install_candidates_excludes_non_equal_cost() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    // peer2 has higher LOCAL_PREF ⇒ it is the sole best; peer1 is not equal-cost.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
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
        peer: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2)),
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let cands = query_fib_install_candidates(&tx, 4).await;
    assert_eq!(cands.len(), 1);
    assert_eq!(
        cands[0].next_hops.len(),
        1,
        "lower-LP path is not co-installed"
    );
    assert_eq!(cands[0].best.peer, IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2)));

    drop(tx);
    handle.await.unwrap();
}

// ── Outbound Route Filtering (ORF) — RFC 5291/5292 ──────────────────────
