use super::*;
use crate::PeerId;
use crate::test_support::peer_v4;

#[tokio::test]
async fn warm_mrt_snapshot_rejects_session_generation_change_at_rib_fence() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let peer_router_id = Ipv4Addr::new(192, 0, 2, 1);
    let (out_tx, _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        supersedes: None,
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 42,
        peer,
        peer_asn: 65002,
        peer_router_id,
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

    let error = query_warm_mrt_snapshot(
        &tx,
        vec![crate::update::WarmMrtSnapshotView {
            peer,
            session_id: 41,
            peer_asn: 65002,
            peer_router_id,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            add_path_receive: false,
        }],
    )
    .await
    .unwrap_err();
    assert!(error.contains("changed active session"), "{error}");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn warm_mrt_snapshot_excludes_routes_for_family_outside_exact_view() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let peer_router_id = Ipv4Addr::new(192, 0, 2, 1);
    let (out_tx, _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        supersedes: None,
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 42,
        peer,
        peer_asn: 65002,
        peer_router_id,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)],
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

    let v4 = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let mut v6 = make_v6_route(
        Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32),
        "2001:db8::1".parse().unwrap(),
    );
    set_peer(&mut v6, peer);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 42,
        peer,
        announced: vec![make_route(v4, Ipv4Addr::new(10, 0, 0, 1)), v6],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let snapshot = query_warm_mrt_snapshot(
        &tx,
        vec![crate::update::WarmMrtSnapshotView {
            peer,
            session_id: 42,
            peer_asn: 65002,
            peer_router_id,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            add_path_receive: false,
        }],
    )
    .await
    .unwrap();
    assert_eq!(snapshot.routes.len(), 1);
    assert_eq!(snapshot.routes[0].prefix, Prefix::V4(v4));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn cancelled_warm_mrt_snapshot_fails_fast_without_wedging_actor() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(true));

    let error = query_warm_mrt_snapshot_with_budget(
        &tx,
        Vec::new(),
        crate::update::WarmMrtSnapshotBudget {
            deadline: std::time::Instant::now() + Duration::from_secs(30),
            cancelled,
            max_materialized_bytes: 512 * 1024 * 1024,
        },
    )
    .await
    .unwrap_err();
    assert!(error.contains("cancelled"), "{error}");

    // A following actor query must still complete; cancellation is scoped to
    // the abandoned checkpoint and cannot wedge the single-threaded actor.
    let snapshot = query_mrt_snapshot(&tx).await;
    assert!(snapshot.routes.is_empty());
    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn warm_mrt_snapshot_rejects_materialization_before_route_clone() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let peer_router_id = Ipv4Addr::new(192, 0, 2, 1);
    let (out_tx, _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        supersedes: None,
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 42,
        peer,
        peer_asn: 65002,
        peer_router_id,
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
    tx.send(RibUpdate::RoutesReceived {
        session_id: 42,
        peer,
        announced: vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
            Ipv4Addr::new(10, 0, 0, 1),
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let error = query_warm_mrt_snapshot_with_budget(
        &tx,
        vec![crate::update::WarmMrtSnapshotView {
            peer,
            session_id: 42,
            peer_asn: 65002,
            peer_router_id,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            add_path_receive: false,
        }],
        crate::update::WarmMrtSnapshotBudget {
            deadline: std::time::Instant::now() + Duration::from_secs(30),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            max_materialized_bytes: 0,
        },
    )
    .await
    .unwrap_err();
    assert!(error.contains("materialized bytes"), "{error}");

    let snapshot = query_mrt_snapshot(&tx).await;
    assert_eq!(snapshot.routes.len(), 1, "actor remained responsive");
    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn mrt_snapshot_uses_adj_rib_in_routes_without_loc_rib_duplication() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(registering_peer_up(peer, 0)).await.unwrap();
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let snapshot = query_mrt_snapshot(&tx).await;
    assert_eq!(
        snapshot.routes.len(),
        1,
        "MRT snapshot should include only Adj-RIB-In routes (no Loc-RIB duplication)"
    );
    assert_eq!(snapshot.routes[0].prefix, Prefix::V4(prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn mrt_peer_metadata_retained_during_gr() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        supersedes: None,
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer,
        peer_asn: 65001,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
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

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
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

    let snapshot = query_mrt_snapshot(&tx).await;
    let meta = snapshot
        .peers
        .iter()
        .find(|entry| entry.peer_addr == peer.addr())
        .expect("peer metadata should remain available during GR");
    assert_eq!(meta.peer_asn, 65001);
    assert_eq!(meta.peer_bgp_id, Ipv4Addr::new(10, 0, 0, 1));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn explain_best_path_returns_candidates_without_winner() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer_a = Ipv4Addr::new(1, 0, 0, 1);
    let peer_b = Ipv4Addr::new(1, 0, 0, 2);

    // Route from peer_a has higher LOCAL_PREF → should be best.
    let route_a = make_route_with_lp(prefix, peer_a, 200);
    let route_b = make_route_with_lp(prefix, peer_b, 100);

    tx.send(registering_peer_up(peer_v4(peer_a), 0))
        .await
        .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(peer_a),
        announced: vec![route_a],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    tx.send(registering_peer_up(peer_v4(peer_b), 0))
        .await
        .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(peer_b),
        announced: vec![route_b],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    // Give the RIB manager time to process.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let explain = query_explain_best_path(&tx, Prefix::V4(prefix)).await;

    // Best route should be from peer_a (higher LP).
    assert!(explain.best.is_some());
    let best = explain.best.unwrap();
    assert_eq!(best.peer, peer_v4(peer_a));

    // Candidates should NOT include the winner.
    assert_eq!(explain.candidates.len(), 1);
    let loser = &explain.candidates[0];
    assert_eq!(loser.route.peer, peer_v4(peer_b));
    assert_eq!(
        loser.vs_best_reason,
        crate::best_path::BestPathReason::HigherLocalPref
    );
    assert_eq!(loser.vs_best_ordering, std::cmp::Ordering::Greater);
    assert_eq!(loser.vs_best_detail, "local_pref 100 < 200");
    assert_eq!(
        loser.multipath,
        crate::best_path::MultipathEligibility::None
    );

    // Winner attribution: with one competitor, that competitor is the
    // runner-up — the winner's decisive step is the same ladder step,
    // rendered winner-side.
    assert_eq!(
        explain.best_reason,
        Some(crate::best_path::BestPathReason::HigherLocalPref)
    );
    assert_eq!(explain.best_reason_detail, "local_pref 200 > 100");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn lookup_best_path_is_atomic_and_falls_back_after_withdrawal() {
    let (tx, rx) = mpsc::channel(64);
    let handle =
        tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new()).run());
    let default = Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0);
    let farther = Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 16);
    let closer = Ipv4Prefix::new(Ipv4Addr::new(10, 1, 2, 0), 24);
    let query = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 2, 128), 25));
    let [default_peer, winner_peer, alternative_peer, closer_peer] =
        [1, 2, 3, 4].map(|last| Ipv4Addr::new(192, 0, 2, last));

    for (peer, route) in [
        (default_peer, make_route_with_lp(default, default_peer, 100)),
        (winner_peer, make_route_with_lp(farther, winner_peer, 200)),
        (
            alternative_peer,
            make_route_with_lp(farther, alternative_peer, 100),
        ),
        (closer_peer, make_route_with_lp(closer, closer_peer, 150)),
    ] {
        tx.send(registering_peer_up(peer_v4(peer), 0))
            .await
            .unwrap();
        tx.send(super::lifecycle::test_routes_received(
            peer_v4(peer),
            vec![route],
        ))
        .await
        .unwrap();
    }

    let exact = query_lookup_best_path(&tx, Prefix::V4(closer))
        .await
        .unwrap();
    assert_eq!(exact.prefix, Prefix::V4(closer));
    assert_eq!(exact.best.as_ref().unwrap().peer, peer_v4(closer_peer));

    let closest = query_lookup_best_path(&tx, query).await.unwrap();
    assert_eq!(closest.prefix, Prefix::V4(closer));
    assert!(
        closest.candidates.is_empty(),
        "farther-prefix candidates must not leak into the matched prefix"
    );

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(closer_peer),
        announced: vec![],
        withdrawn: vec![(Prefix::V4(closer), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    let fallback = query_lookup_best_path(&tx, query).await.unwrap();
    assert_eq!(fallback.prefix, Prefix::V4(farther));
    assert_eq!(fallback.best.as_ref().unwrap().peer, peer_v4(winner_peer));
    assert_eq!(fallback.candidates.len(), 1);
    assert_eq!(fallback.candidates[0].route.peer, peer_v4(alternative_peer));
    assert!(fallback.peer.is_none());
    assert_eq!(fallback.add_path_send_max, 0);

    for peer in [winner_peer, alternative_peer] {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: peer_v4(peer),
            announced: vec![],
            withdrawn: vec![(Prefix::V4(farther), 0)],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        })
        .await
        .unwrap();
    }
    assert_eq!(
        query_lookup_best_path(&tx, query).await.unwrap().prefix,
        Prefix::V4(default)
    );
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(default_peer),
        announced: vec![],
        withdrawn: vec![(Prefix::V4(default), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    assert!(query_lookup_best_path(&tx, query).await.is_none());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn explain_best_path_no_candidates() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    let explain = query_explain_best_path(&tx, prefix).await;

    assert!(explain.best.is_none());
    assert!(explain.candidates.is_empty());
    assert!(explain.peer.is_none());
    assert_eq!(explain.add_path_send_max, 0);
    assert!(explain.best_reason.is_none());
    assert_eq!(explain.best_reason_detail.len(), 0);

    drop(tx);
    handle.await.unwrap();
}

/// Single-path prefix: the winner is trivial — no runner-up exists, so
/// there is no decisive step to report (`best_reason = None`; the API
/// layer renders that as "`only_path`").
#[tokio::test]
async fn explain_best_path_single_path_has_no_best_reason() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer = Ipv4Addr::new(1, 0, 0, 1);

    tx.send(registering_peer_up(peer_v4(peer), 0))
        .await
        .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(peer),
        announced: vec![make_route_with_lp(prefix, peer, 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let explain = query_explain_best_path(&tx, Prefix::V4(prefix)).await;
    assert_eq!(explain.best.as_ref().map(|r| r.peer), Some(peer_v4(peer)));
    assert!(explain.candidates.is_empty());
    assert!(explain.best_reason.is_none());
    assert_eq!(explain.best_reason_detail.len(), 0);

    drop(tx);
    handle.await.unwrap();
}

/// Tiebreaker attribution across a multi-step elimination matrix: each
/// loser reports the step that eliminated it (with compared values),
/// the winner reports the step that beat the *runner-up* (the deepest-
/// surviving competitor), and the multipath cut is classified per
/// candidate. Also pins explain-vs-comparator agreement: the route the
/// explain calls best must be the `best_path_cmp` minimum.
#[tokio::test]
async fn explain_best_path_attributes_each_loss_and_the_winning_step() {
    use crate::best_path::{BestPathReason, MultipathEligibility, best_path_cmp};

    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let winner_peer = Ipv4Addr::new(1, 0, 0, 1);
    let sibling_peer = Ipv4Addr::new(1, 0, 0, 2); // exact AS_PATH twin → ECMP-eligible, runner-up
    let relax_peer = Ipv4Addr::new(1, 0, 0, 4); // same AS_PATH length, different ASN
    let aspath_peer = Ipv4Addr::new(1, 0, 0, 5); // longer AS_PATH
    let lp_peer = Ipv4Addr::new(1, 0, 0, 6); // lower LOCAL_PREF

    let routes = [
        (winner_peer, vec![65001], 200),
        (sibling_peer, vec![65001], 200),
        (relax_peer, vec![65009], 200),
        (aspath_peer, vec![65001, 65002], 200),
        (lp_peer, vec![65001], 100),
    ];
    // Parallel sessions from one neighbor router: every candidate carries
    // the same BGP Identifier, so RFC 4271 §9.1.2.2 step (f) ties and the
    // peer address separates the twins.
    let shared_router_id = winner_peer;
    let all: Vec<Route> = routes
        .iter()
        .map(|(peer, asns, lp)| {
            let mut route = make_multipath_route(prefix, *peer, asns.clone(), *lp);
            route.peer_router_id = shared_router_id;
            route
        })
        .collect();
    for route in &all {
        tx.send(registering_peer_up(route.peer, 0)).await.unwrap();
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: route.peer,
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
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    let explain = query_explain_best_path(&tx, Prefix::V4(prefix)).await;

    // Agreement: explain's winner == the comparator's minimum over the
    // same input set.
    let expected_best = all.iter().min_by(|a, b| best_path_cmp(a, b)).unwrap();
    let best = explain.best.as_ref().expect("best route");
    assert_eq!(best.peer, expected_best.peer);
    assert_eq!(best.peer, peer_v4(winner_peer));

    // Winner attribution: the runner-up is the ECMP sibling (ties every
    // attribute step, loses on peer address), so the winning step is
    // the final tiebreaker.
    assert_eq!(explain.best_reason, Some(BestPathReason::LowerPeerAddress));
    assert_eq!(explain.best_reason_detail, "peer 1.0.0.1 < 1.0.0.2");

    // Each loser: the step that eliminated it + compared values +
    // multipath-cut classification.
    let by_peer = |peer: Ipv4Addr| {
        explain
            .candidates
            .iter()
            .find(|c| c.route.peer == peer_v4(peer))
            .unwrap_or_else(|| panic!("candidate {peer} missing"))
    };

    let sibling = by_peer(sibling_peer);
    assert_eq!(sibling.vs_best_reason, BestPathReason::LowerPeerAddress);
    assert_eq!(sibling.vs_best_detail, "peer 1.0.0.2 > 1.0.0.1");
    assert_eq!(sibling.multipath, MultipathEligibility::Eligible);

    let relax = by_peer(relax_peer);
    assert_eq!(relax.vs_best_reason, BestPathReason::LowerPeerAddress);
    assert_eq!(relax.vs_best_detail, "peer 1.0.0.4 > 1.0.0.1");
    assert_eq!(relax.multipath, MultipathEligibility::RelaxOnly);

    let aspath = by_peer(aspath_peer);
    assert_eq!(aspath.vs_best_reason, BestPathReason::ShorterAsPath);
    assert_eq!(aspath.vs_best_detail, "as_path_len 2 > 1");
    assert_eq!(aspath.multipath, MultipathEligibility::None);

    let lp = by_peer(lp_peer);
    assert_eq!(lp.vs_best_reason, BestPathReason::HigherLocalPref);
    assert_eq!(lp.vs_best_detail, "local_pref 100 < 200");
    assert_eq!(lp.multipath, MultipathEligibility::None);

    drop(tx);
    handle.await.unwrap();
}

/// RFC 4271 §9.1.2.2 step (f) through the manager: between two otherwise
/// equal paths the lower advertising BGP Identifier wins even though the
/// other peer has the lower address, and explain attributes the decision
/// to `lower_bgp_identifier` on both the winner and the loser.
#[tokio::test]
async fn explain_best_path_lower_bgp_identifier_beats_peer_address() {
    use crate::best_path::BestPathReason;

    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);
    let low_id_peer = Ipv4Addr::new(1, 0, 0, 2);
    let low_addr_peer = Ipv4Addr::new(1, 0, 0, 1);
    let mut low_id = make_multipath_route(prefix, low_id_peer, vec![65001], 200);
    low_id.peer_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let mut low_addr = make_multipath_route(prefix, low_addr_peer, vec![65001], 200);
    low_addr.peer_router_id = Ipv4Addr::new(2, 2, 2, 2);
    for route in [&low_id, &low_addr] {
        tx.send(registering_peer_up(route.peer, 0)).await.unwrap();
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: route.peer,
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
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    let explain = query_explain_best_path(&tx, Prefix::V4(prefix)).await;
    let best = explain.best.as_ref().expect("best route");
    assert_eq!(best.peer, peer_v4(low_id_peer));
    assert_eq!(
        explain.best_reason,
        Some(BestPathReason::LowerBgpIdentifier)
    );
    assert_eq!(
        explain.best_reason_detail,
        "bgp_identifier 1.1.1.1 < 2.2.2.2"
    );
    let loser = explain
        .candidates
        .iter()
        .find(|c| c.route.peer == peer_v4(low_addr_peer))
        .expect("losing candidate");
    assert_eq!(loser.vs_best_reason, BestPathReason::LowerBgpIdentifier);
    assert_eq!(loser.vs_best_detail, "bgp_identifier 2.2.2.2 > 1.1.1.1");

    drop(tx);
    handle.await.unwrap();
}

/// Add-Path explain: a peer with `send_max=2` and 3 candidate routes
/// should see exactly 2 candidates with non-zero `advertised_path_id`
/// (ranks 1 + 2 by best-path order), and the third one with a zero
/// `advertised_path_id` (it would be dropped past the limit).
#[tokio::test]
async fn explain_best_path_for_addpath_peer_marks_top_n_with_path_id() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let peer1 = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let peer3 = peer_v4(Ipv4Addr::new(10, 0, 0, 3));
    let target = peer_v4(Ipv4Addr::new(10, 0, 0, 4));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    for (peer, peer_addr, asn, lp) in [
        (peer1, Ipv4Addr::new(10, 0, 0, 1), 65001, 200),
        (peer2, Ipv4Addr::new(10, 0, 0, 2), 65002, 150),
        (peer3, Ipv4Addr::new(10, 0, 0, 3), 65003, 100),
    ] {
        tx.send(registering_peer_up(peer, 0)).await.unwrap();
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer,
            announced: vec![make_multipath_route(prefix, peer_addr, vec![asn], lp)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        })
        .await
        .unwrap();
    }

    let (out_tx, _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        supersedes: None,
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

    tokio::time::sleep(Duration::from_millis(50)).await;

    let explain = query_explain_best_path_for_peer(&tx, Prefix::V4(prefix), target)
        .await
        .expect("known peer");

    assert_eq!(explain.peer, Some(target));
    assert_eq!(explain.add_path_send_max, 2);
    assert!(explain.best.is_some(), "best should be peer1 (LP=200)");
    let best = explain.best.as_ref().unwrap();
    assert_eq!(best.peer, peer1);

    // Candidates exclude the winner; that's the existing contract.
    // The remaining two are peer2 (advertised at rank 2) and peer3
    // (filtered, beyond send_max).
    assert_eq!(explain.candidates.len(), 2);
    let by_peer: std::collections::HashMap<PeerId, &crate::update::BestPathCandidate> = explain
        .candidates
        .iter()
        .map(|c| (c.route.peer, c))
        .collect();

    let cand_peer2 = by_peer.get(&peer2).expect("peer2 is a candidate");
    assert_eq!(
        cand_peer2.advertised_path_id, 2,
        "peer2 (LP=150) should be advertised at rank 2"
    );

    let cand_peer3 = by_peer.get(&peer3).expect("peer3 is a candidate");
    assert_eq!(
        cand_peer3.advertised_path_id, 0,
        "peer3 (LP=100) should be filtered (beyond send_max)"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Regression: when the target peer is itself the source of the
/// Loc-RIB best (split-horizon excludes it from the export-filtered
/// set), single-best send mode (`send_max=0`) must not fall back to
/// the next-best candidate. `distribute_single_best_prefix` would
/// advertise nothing in this case; explain must reflect the same
/// answer or it lies to the operator.
#[tokio::test]
async fn explain_best_path_single_best_does_not_fall_back_when_winner_is_target() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let peer_winner = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let peer_runner_up = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    let (out_tx, _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        supersedes: None,
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: peer_winner, // <-- target IS the winner
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
    tx.send(registering_peer_up(peer_runner_up, 0))
        .await
        .unwrap();

    // peer_winner has the higher LP and *is* the target peer.
    // Under split-horizon, peer_winner cannot receive its own route
    // back — so single-best advertises nothing.
    for (peer, addr, asn, lp) in [
        (peer_winner, Ipv4Addr::new(10, 0, 0, 1), 65001, 200),
        (peer_runner_up, Ipv4Addr::new(10, 0, 0, 2), 65002, 100),
    ] {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer,
            announced: vec![make_multipath_route(prefix, addr, vec![asn], lp)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        })
        .await
        .unwrap();
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    let explain = query_explain_best_path_for_peer(&tx, Prefix::V4(prefix), peer_winner)
        .await
        .expect("known peer");
    assert_eq!(explain.add_path_send_max, 0);
    // No candidate may have a non-zero advertised_path_id. Before
    // the fix, peer_runner_up would have been promoted to rank 1.
    for cand in &explain.candidates {
        assert_eq!(
            cand.advertised_path_id, 0,
            "single-best must not fall back; cand={:?}",
            cand.route.peer
        );
    }

    drop(tx);
    handle.await.unwrap();
}

/// Add-Path explain: a peer with `send_max=0` (single-best mode)
/// only advertises the global best, even when more candidates exist.
#[tokio::test]
async fn explain_best_path_for_single_best_peer_marks_only_winner_path_id_zero() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = peer_v4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    for (peer, addr, asn, lp) in [
        (peer1, Ipv4Addr::new(10, 0, 0, 1), 65001, 200),
        (peer2, Ipv4Addr::new(10, 0, 0, 2), 65002, 100),
    ] {
        tx.send(registering_peer_up(PeerId::from_addr(peer), 0))
            .await
            .unwrap();
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: PeerId::from_addr(peer),
            announced: vec![make_multipath_route(prefix, addr, vec![asn], lp)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        })
        .await
        .unwrap();
    }

    let (out_tx, _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        supersedes: None,
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

    tokio::time::sleep(Duration::from_millis(50)).await;

    let explain = query_explain_best_path_for_peer(&tx, Prefix::V4(prefix), target)
        .await
        .expect("known peer");

    assert_eq!(explain.peer, Some(target));
    assert_eq!(explain.add_path_send_max, 0);
    // Best = peer1 (LP=200). The losing candidate is peer2; under
    // single-best send mode it would not be advertised even with
    // a higher rank, so its advertised_path_id is 0.
    assert!(explain.best.is_some());
    assert_eq!(explain.candidates.len(), 1);
    assert_eq!(explain.candidates[0].advertised_path_id, 0);

    drop(tx);
    handle.await.unwrap();
}

/// Regression: when the prefix's AFI/SAFI isn't in the peer's
/// `add_path_send_families`, the response's `add_path_send_max`
/// must reflect 0 — not the bare config knob — to match what
/// distribution would actually do.
#[tokio::test]
async fn explain_best_path_effective_send_max_zero_on_family_mismatch() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = peer_v4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    for (peer, addr, asn, lp) in [
        (peer1, Ipv4Addr::new(10, 0, 0, 1), 65001, 200),
        (peer2, Ipv4Addr::new(10, 0, 0, 2), 65002, 100),
    ] {
        tx.send(registering_peer_up(PeerId::from_addr(peer), 0))
            .await
            .unwrap();
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: PeerId::from_addr(peer),
            announced: vec![make_multipath_route(prefix, addr, vec![asn], lp)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        })
        .await
        .unwrap();
    }

    // Peer registered with sendable_families = IPv4 unicast, but
    // add_path_send_families = IPv6 unicast. Asking about an IPv4
    // prefix → effective send_max should be 0.
    let (out_tx, _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        supersedes: None,
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
        add_path_send_families: vec![(Afi::Ipv6, Safi::Unicast)],
        add_path_send_max: 4,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let explain = query_explain_best_path_for_peer(&tx, Prefix::V4(prefix), target)
        .await
        .expect("known peer");

    assert_eq!(
        explain.add_path_send_max, 0,
        "effective send_max should be 0 when the prefix's family isn't in add_path_send_families"
    );
    for cand in &explain.candidates {
        assert_eq!(cand.advertised_path_id, 0);
    }

    drop(tx);
    handle.await.unwrap();
}

/// Add-Path explain: an unknown peer returns `None` (not Found at the
/// gRPC layer) rather than silently giving the global view.
#[tokio::test]
async fn explain_best_path_for_unknown_peer_returns_none() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let unknown = peer_v4(Ipv4Addr::new(10, 99, 99, 99));

    let result = query_explain_best_path_for_peer(&tx, Prefix::V4(prefix), unknown).await;
    assert!(result.is_none(), "unknown peer should yield None");

    drop(tx);
    handle.await.unwrap();
}

/// Global-view explain (no peer scope) preserves the v0.7.0 shape
/// even after the Add-Path extensions.
#[tokio::test]
async fn explain_best_path_global_view_unchanged() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer_a = Ipv4Addr::new(1, 0, 0, 1);
    let peer_b = Ipv4Addr::new(1, 0, 0, 2);

    tx.send(registering_peer_up(peer_v4(peer_a), 0))
        .await
        .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(peer_a),
        announced: vec![make_route_with_lp(prefix, peer_a, 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    tx.send(registering_peer_up(peer_v4(peer_b), 0))
        .await
        .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(peer_b),
        announced: vec![make_route_with_lp(prefix, peer_b, 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let explain = query_explain_best_path(&tx, Prefix::V4(prefix)).await;
    assert!(explain.peer.is_none());
    assert_eq!(explain.add_path_send_max, 0);
    // Every candidate has advertised_path_id == 0 in global view.
    for cand in &explain.candidates {
        assert_eq!(cand.advertised_path_id, 0);
    }

    drop(tx);
    handle.await.unwrap();
}

#[test]
fn mrt_snapshot_captures_unregistered_route_sources_before_rebind() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let old: IpAddr = "fe80::a".parse().unwrap();
    let peer = PeerId::allocate(crate::PeerEndpoint::new(old, Some("swp1")));
    let mut route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24),
        Ipv4Addr::new(198, 51, 100, 1),
    );
    route.peer = peer;
    // Seed the snapshot's fallback case directly; session ingress requires PeerUp.
    let mut rib = AdjRibIn::new(peer);
    rib.insert(route);
    manager.ribs.insert(peer, rib);
    assert!(!manager.peer_asn.contains_key(&peer));

    let (snapshot, _) = drain_mrt_snapshot(&mut manager, |_, _| {});
    assert_eq!(snapshot.routes.len(), 1);
    assert_eq!(snapshot.peers.len(), 1);
    assert_eq!(snapshot.peers[0].peer_asn, 0);
    assert_eq!(snapshot.peers[0].peer_addr, old);
    assert_eq!(snapshot.peers[0].interface.as_deref(), Some("swp1"));

    manager.handle_update(RibUpdate::RebindPeer {
        peer,
        endpoint: crate::PeerEndpoint::new("fe80::b".parse().unwrap(), Some("swp1")),
    });
    assert_eq!(peer.addr(), "fe80::b".parse::<IpAddr>().unwrap());
    assert_eq!(snapshot.peers[0].peer_addr, old);
    assert!(peer.release());
}

/// Run one chunked MRT snapshot to completion, calling `between` after each
/// turn but the last with the number of turns so far. Returns the gathered
/// snapshot and the rows each turn copied.
fn drain_mrt_snapshot(
    manager: &mut RibManager,
    mut between: impl FnMut(&mut RibManager, usize),
) -> (crate::update::MrtSnapshotData, Vec<usize>) {
    let mut snapshot = crate::update::MrtSnapshotAssembler::default();
    let mut turns = Vec::new();
    let mut cursor = None;
    loop {
        let (reply, mut response) = oneshot::channel();
        manager.handle_update(RibUpdate::QueryMrtSnapshotChunk { cursor, reply });
        let chunk = response.try_recv().unwrap().unwrap();
        turns.push(chunk.routes.len() + chunk.evpn_routes.len());
        cursor = snapshot.push(chunk);
        if cursor.is_none() {
            return (snapshot.finish(), turns);
        }
        between(manager, turns.len());
    }
}

fn mrt_test_manager() -> RibManager {
    RibManager::new(
        mpsc::channel(1).1,
        dummy_query_rx(),
        None,
        None,
        BgpMetrics::new(),
    )
}

fn mrt_test_peer(index: u8) -> PeerId {
    peer_v4(Ipv4Addr::new(10, 77, 0, index))
}

fn mrt_test_prefix(n: u32) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(0x0b00_0000 + (n << 8)), 24))
}

/// Unicast route `n` of `peer`; `version` is carried in the next hop.
fn mrt_test_route(peer: PeerId, n: u32, version: u8) -> Route {
    let Prefix::V4(prefix) = mrt_test_prefix(n) else {
        unreachable!()
    };
    let mut route = make_route(prefix, Ipv4Addr::new(198, 51, 100, version));
    route.peer = peer;
    route
}

/// EVPN route `tag` of `peer`; `version` is carried in the next hop.
fn mrt_test_evpn(peer: PeerId, tag: u32, version: u8) -> EvpnRibRoute {
    let mut route = make_evpn_imet(Ipv4Addr::new(10, 77, 0, 1), tag);
    route.peer = peer;
    route.next_hop = IpAddr::V4(Ipv4Addr::new(198, 51, 100, version));
    route
}

fn seed_mrt_rib(manager: &mut RibManager, peer: PeerId, prefixes: u32, evpn: u32) {
    let rib = manager
        .ribs
        .entry(peer)
        .or_insert_with(|| AdjRibIn::new(peer));
    for n in 0..prefixes {
        rib.insert(mrt_test_route(peer, n, 0));
    }
    for tag in 0..evpn {
        rib.insert_evpn(mrt_test_evpn(peer, tag, 0));
    }
}

/// Regression: the rows one RIB turn copies for an MRT snapshot do not grow
/// with the unicast table. The one-turn snapshot this replaces copied every
/// row in a single turn (20,000 and 80,000 here).
#[test]
fn mrt_snapshot_unicast_turn_is_flat_in_table_size() {
    const PEERS: u8 = 5;
    let budget = crate::update::MRT_SNAPSHOT_CHUNK_ROWS;
    let mut longest = Vec::new();
    for prefixes in [4_000u32, 16_000] {
        let mut manager = mrt_test_manager();
        for index in 1..=PEERS {
            seed_mrt_rib(&mut manager, mrt_test_peer(index), prefixes, 0);
        }
        let (snapshot, turns) = drain_mrt_snapshot(&mut manager, |_, _| {});
        let rows = prefixes as usize * usize::from(PEERS);
        assert_eq!(snapshot.routes.len(), rows);
        let max = turns.iter().copied().max().unwrap();
        println!(
            "mrt snapshot unicast: rows={rows} turns={} longest_turn_rows={max}",
            turns.len()
        );
        // A turn ends on a prefix boundary: at most one prefix past the budget.
        assert!(max < budget + usize::from(PEERS), "{max}");
        longest.push(max);
    }
    assert_eq!(longest[0], longest[1], "longest turn grew with the table");
}

/// Growing the table never grows one actor turn, including sparse slots.
#[test]
fn mrt_snapshot_evpn_turn_is_flat_in_table_size() {
    let budget = crate::update::MRT_SNAPSHOT_CHUNK_ROWS;
    for routes in [10_000u32, 40_000, 160_000] {
        let mut manager = mrt_test_manager();
        let peer = mrt_test_peer(1);
        seed_mrt_rib(&mut manager, peer, 0, routes);
        for index in 2..=9 {
            seed_mrt_rib(&mut manager, mrt_test_peer(index), 0, 1_000);
        }
        let mut slots = Vec::new();
        crate::manager::queries::mrt_chunks_built::take_slots();
        let (snapshot, turns) = drain_mrt_snapshot(&mut manager, |_, _| {
            slots.push(crate::manager::queries::mrt_chunks_built::take_slots());
        });
        slots.push(crate::manager::queries::mrt_chunks_built::take_slots());
        assert_eq!(snapshot.evpn_routes.len(), routes as usize + 8_000);
        assert_eq!(snapshot.peers.len(), 9, "retained EVPN sources are listed");
        assert_eq!(slots.iter().sum::<usize>(), routes as usize + 8_000);
        let max = slots.iter().copied().max().unwrap();
        println!(
            "mrt snapshot evpn: one_peer_rows={routes} turns={} longest_turn_slots={max}",
            turns.len()
        );
        assert_eq!(max, budget);
        assert!(turns.into_iter().all(|rows| rows <= budget));
    }
}

#[test]
fn mrt_snapshot_evpn_sparse_slots_are_bounded_work() {
    const SLOTS: u32 = 10_000;
    let mut manager = mrt_test_manager();
    let peer = mrt_test_peer(1);
    seed_mrt_rib(&mut manager, peer, 0, SLOTS);
    let rib = manager.ribs.get_mut(&peer).unwrap();
    for tag in 0..SLOTS - 1 {
        assert!(rib.withdraw_evpn(&mrt_test_evpn(peer, tag, 0).key()));
    }
    let mut slots = Vec::new();
    crate::manager::queries::mrt_chunks_built::take_slots();
    let (snapshot, turns) = drain_mrt_snapshot(&mut manager, |_, _| {
        slots.push(crate::manager::queries::mrt_chunks_built::take_slots());
    });
    slots.push(crate::manager::queries::mrt_chunks_built::take_slots());
    assert_eq!(snapshot.evpn_routes.len(), 1);
    assert_eq!(turns, [0, 0, 0, 1]);
    assert_eq!(slots, [0, 4096, 4096, 1808]);
}

/// The consistency a chunked snapshot promises while the table changes
/// between its turns, over several mutation orders:
/// - a route stored and unchanged for the whole dump is copied exactly once;
/// - no unicast identity is copied twice; changed EVPN rows may recur after
///   slot reuse, but every copied route is in a form it actually had;
/// - one prefix is read from every neighbor in the same turn;
/// - every copied route names a peer from the initial roster; a departing
///   peer retains its entry and late joiners are excluded.
#[expect(
    clippy::too_many_lines,
    reason = "one scenario keeps its mutations and assertions together"
)]
#[test]
fn mrt_snapshot_under_churn_keeps_its_consistency_model() {
    const PREFIXES: u32 = 6_000;
    const EVPN: u32 = 40_000;
    const PIVOT: u32 = 3_001;
    let stable = |n: u32| n < PREFIXES && n.is_multiple_of(3);

    for seed in 0..8u64 {
        let mut manager = mrt_test_manager();
        let stayers = [mrt_test_peer(1), mrt_test_peer(2), mrt_test_peer(3)];
        let leaver = mrt_test_peer(4);
        let joiner = mrt_test_peer(5);
        for peer in stayers.into_iter().chain([leaver]) {
            seed_mrt_rib(&mut manager, peer, PREFIXES, 0);
            manager.peer_asn.insert(peer, 65_001);
        }
        seed_mrt_rib(&mut manager, stayers[0], 0, EVPN);
        seed_mrt_rib(&mut manager, stayers[1], 0, 100);

        // Every next-hop version a route identity ever had.
        let mut unicast_versions: HashMap<(PeerId, Prefix), HashSet<u8>> = HashMap::new();
        let mut evpn_versions: HashMap<u32, HashSet<u8>> = HashMap::new();
        let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let mut next = move |bound: u32| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            u32::try_from((state >> 33) % u64::from(bound)).unwrap()
        };

        let (snapshot, turns) = drain_mrt_snapshot(&mut manager, |manager, turn| {
            let version = u8::try_from(turn % 200).unwrap() + 1;
            if turn == 1 {
                // Not yet reached by a prefix-ordered walk on any neighbor.
                for peer in stayers {
                    manager
                        .ribs
                        .get_mut(&peer)
                        .unwrap()
                        .insert(mrt_test_route(peer, PIVOT, 250));
                }
            }
            if turn == 2 {
                manager.ribs.remove(&leaver);
                manager.peer_asn.remove(&leaver);
                // Rows behind and ahead of the cursor, under a new session.
                seed_mrt_rib(manager, joiner, PREFIXES, 0);
                manager.peer_asn.insert(joiner, 65_005);
            }
            for _ in 0..300 {
                let peer = stayers[next(3) as usize];
                // Inserts behind and ahead of the cursor, and new prefixes.
                let n = next(PREFIXES + 500);
                if stable(n) || n == PIVOT {
                    continue;
                }
                let rib = manager.ribs.get_mut(&peer).unwrap();
                if next(2) == 0 {
                    rib.withdraw(&mrt_test_prefix(n), 0);
                } else {
                    rib.insert(mrt_test_route(peer, n, version));
                    unicast_versions
                        .entry((peer, mrt_test_prefix(n)))
                        .or_default()
                        .insert(version);
                }
            }
            let rib = manager.ribs.get_mut(&stayers[0]).unwrap();
            for _ in 0..300 {
                let tag = next(EVPN + 500);
                if tag < EVPN && tag.is_multiple_of(2) {
                    continue;
                }
                if next(2) == 0 {
                    rib.withdraw_evpn(&mrt_test_evpn(stayers[0], tag, 0).key());
                } else {
                    rib.insert_evpn(mrt_test_evpn(stayers[0], tag, version));
                    evpn_versions.entry(tag).or_default().insert(version);
                }
            }
        });
        assert!(turns.len() > 12, "seed {seed}: {} turns", turns.len());

        let version_of = |next_hop: IpAddr| match next_hop {
            IpAddr::V4(addr) => addr.octets()[3],
            IpAddr::V6(_) => unreachable!(),
        };
        let mut seen = HashSet::new();
        let mut stable_seen = 0usize;
        let mut pivot = Vec::new();
        for route in &snapshot.routes {
            assert!(
                seen.insert((route.peer, route.prefix, route.path_id)),
                "seed {seed}: {} copied twice for one neighbor",
                route.prefix
            );
            let version = version_of(route.next_hop);
            let had = version == 0
                || version == 250
                || unicast_versions
                    .get(&(route.peer, route.prefix))
                    .is_some_and(|versions| versions.contains(&version));
            assert!(had, "seed {seed}: {} in a form it never had", route.prefix);
            if route.prefix == mrt_test_prefix(PIVOT) && stayers.contains(&route.peer) {
                pivot.push(version);
            }
            let Prefix::V4(prefix) = route.prefix else {
                unreachable!()
            };
            let n = (u32::from(prefix.addr) - 0x0b00_0000) >> 8;
            if stable(n) && stayers.contains(&route.peer) {
                assert_eq!(version, 0);
                stable_seen += 1;
            }
        }
        assert_eq!(
            stable_seen,
            stayers.len() * (PREFIXES as usize).div_ceil(3),
            "seed {seed}: an unchanged unicast route is missing"
        );
        // The pivot changed on every neighbor between two turns, ahead of
        // the walk: the dump shows one instant of it.
        assert_eq!(pivot, [250, 250, 250], "seed {seed}");

        let mut evpn_stable = HashSet::new();
        let mut evpn_stable_seen = 0usize;
        for route in &snapshot.evpn_routes {
            if route.peer != stayers[0] {
                continue;
            }
            let rustbgpd_wire::EvpnRoute::Imet(imet) = &route.route else {
                unreachable!()
            };
            let tag = imet.ethernet_tag.0;
            let version = version_of(route.next_hop);
            let had = version == 0
                || evpn_versions
                    .get(&tag)
                    .is_some_and(|versions| versions.contains(&version));
            assert!(had, "seed {seed}: EVPN tag {tag} in a form it never had");
            if tag < EVPN && tag.is_multiple_of(2) {
                assert!(
                    evpn_stable.insert(route.key()),
                    "unchanged route copied twice"
                );
                assert_eq!(version, 0);
                evpn_stable_seen += 1;
            }
        }
        assert_eq!(
            evpn_stable_seen,
            (EVPN / 2) as usize,
            "seed {seed}: an unchanged EVPN route is missing"
        );

        // The peer table: one entry per neighbor, covering every route.
        let mut listed = HashMap::new();
        for entry in &snapshot.peers {
            assert!(
                listed.insert(entry.peer, entry.peer_asn).is_none(),
                "seed {seed}: a neighbor is listed twice"
            );
        }
        for peer in snapshot
            .routes
            .iter()
            .map(|route| route.peer)
            .chain(snapshot.evpn_routes.iter().map(|route| route.peer))
        {
            assert!(listed.contains_key(&peer), "seed {seed}: unlisted source");
        }
        let rows_of = |peer| snapshot.routes.iter().filter(|r| r.peer == peer).count();
        // The neighbor that left keeps the rows read before it left, under
        // the session it had then.
        assert!(rows_of(leaver) > 0 && rows_of(leaver) < PREFIXES as usize);
        assert_eq!(listed[&leaver], 65_001);
        assert_eq!(rows_of(joiner), 0, "late joiner is excluded");
        assert!(!listed.contains_key(&joiner));
    }
}

/// [`drain_mrt_snapshot`] with a caller-chosen row budget, straight through
/// the chunk builder, so a small table still takes many turns.
fn drain_mrt_snapshot_with_budget(
    manager: &mut RibManager,
    budget: usize,
    mut between: impl FnMut(&mut RibManager, usize),
) -> (crate::update::MrtSnapshotData, Vec<usize>) {
    let mut snapshot = crate::update::MrtSnapshotAssembler::default();
    let mut turns = Vec::new();
    let mut cursor = None;
    loop {
        let chunk = manager.mrt_snapshot_chunk(cursor, budget).unwrap();
        turns.push(chunk.routes.len() + chunk.evpn_routes.len());
        assert!(turns.len() < 10_000, "the walk does not advance");
        cursor = snapshot.push(chunk);
        if cursor.is_none() {
            return (snapshot.finish(), turns);
        }
        between(manager, turns.len());
    }
}

/// The fixed cost of a unicast turn is one prefix-index seek per neighbor,
/// whatever the table holds: a many-neighbor shape reports it next to the
/// rows, which stay within one prefix of the budget.
#[test]
fn mrt_snapshot_unicast_turn_at_many_peers() {
    const PEERS: u16 = 800;
    const PREFIXES: u32 = 30;
    let budget = crate::update::MRT_SNAPSHOT_CHUNK_ROWS;
    let mut manager = mrt_test_manager();
    for index in 0..PEERS {
        let [high, low] = index.to_be_bytes();
        let peer = peer_v4(Ipv4Addr::new(10, 78, high, low));
        seed_mrt_rib(&mut manager, peer, PREFIXES, 0);
    }
    let (snapshot, turns) = drain_mrt_snapshot(&mut manager, |_, _| {});
    assert_eq!(
        snapshot.routes.len(),
        usize::from(PEERS) * PREFIXES as usize
    );
    let max = turns.iter().copied().max().unwrap();
    println!(
        "mrt snapshot unicast: peers={PEERS} rows={} turns={} longest_turn_rows={max} seeks_per_turn={}",
        snapshot.routes.len(),
        turns.len(),
        manager.ribs.len()
    );
    assert!(max < budget + usize::from(PEERS), "{max}");
}

/// The prefix-ordered walk resumes correctly when the cursor is a prefix
/// most neighbors do not hold (a covering /8 or /16 over their /24s), across
/// both address families, and keeps every Add-Path path of a prefix.
#[test]
fn mrt_snapshot_walks_nested_prefixes_and_add_path() {
    let mut manager = mrt_test_manager();
    let peers = [mrt_test_peer(21), mrt_test_peer(22), mrt_test_peer(23)];
    let v4 =
        |a: u8, b: u8, c: u8, len: u8| Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(a, b, c, 0), len));
    let v6 = |text: &str, len: u8| {
        Prefix::V6(rustbgpd_wire::Ipv6Prefix::new(text.parse().unwrap(), len))
    };
    let held: [Vec<Prefix>; 3] = [
        vec![
            v4(10, 0, 0, 8),
            v4(10, 1, 0, 16),
            v4(10, 1, 1, 24),
            v6("2001:db8::", 32),
            v6("2001:db8:1:1::", 64),
        ],
        vec![
            v4(10, 1, 0, 16),
            v4(10, 1, 1, 24),
            v4(10, 2, 0, 16),
            v6("2001:db8:1::", 48),
        ],
        vec![
            v4(10, 1, 1, 24),
            v4(11, 0, 0, 8),
            v6("2001:db8:1:1::", 64),
            v6("2001:db9::", 32),
        ],
    ];
    let mut expected = HashSet::new();
    for (peer, prefixes) in peers.into_iter().zip(&held) {
        let rib = manager
            .ribs
            .entry(peer)
            .or_insert_with(|| AdjRibIn::new(peer));
        for &prefix in prefixes {
            // The shared /24 carries three Add-Path paths on every neighbor.
            let paths = if prefix == v4(10, 1, 1, 24) {
                1..4
            } else {
                0..1
            };
            for path_id in paths {
                let mut route = mrt_test_route(peer, 0, 0);
                route.prefix = prefix;
                route.path_id = path_id;
                rib.insert(route);
                expected.insert((peer, prefix, path_id));
            }
        }
    }

    // Budget 1: every turn stops after one prefix, so every prefix is a cursor.
    let (snapshot, turns) = drain_mrt_snapshot_with_budget(&mut manager, 1, |_, _| {});
    assert_eq!(
        snapshot.routes.len(),
        expected.len(),
        "a route copied twice"
    );
    let copied: HashSet<_> = snapshot
        .routes
        .iter()
        .map(|route| (route.peer, route.prefix, route.path_id))
        .collect();
    assert_eq!(copied, expected);
    // Nine distinct prefixes, one per turn, then the EVPN turn.
    assert_eq!(turns.len(), 10);
    assert_eq!(
        turns.iter().copied().max(),
        Some(9),
        "the Add-Path prefix is one turn"
    );
}

/// One prefix is one instant: a turn whose budget runs out inside a prefix
/// still reads that prefix from every neighbor before it stops.
#[test]
fn mrt_snapshot_reads_one_prefix_from_every_peer_in_one_turn() {
    let mut manager = mrt_test_manager();
    let peers = [mrt_test_peer(31), mrt_test_peer(32), mrt_test_peer(33)];
    for peer in peers {
        seed_mrt_rib(&mut manager, peer, 6, 0);
    }
    // Budget 4 over 3 neighbors: the first turn reaches the budget one row
    // into prefix 1 and must finish it; prefix 2 belongs to the next turn.
    let (snapshot, turns) = drain_mrt_snapshot_with_budget(&mut manager, 4, |manager, turn| {
        if turn == 1 {
            for peer in peers {
                let rib = manager.ribs.get_mut(&peer).unwrap();
                rib.insert(mrt_test_route(peer, 1, 9));
                rib.insert(mrt_test_route(peer, 2, 9));
            }
        }
    });
    assert_eq!(turns[0], 6, "the first turn ends on a prefix boundary");
    let versions = |n: u32| -> Vec<IpAddr> {
        snapshot
            .routes
            .iter()
            .filter(|route| route.prefix == mrt_test_prefix(n))
            .map(|route| route.next_hop)
            .collect()
    };
    let old = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0));
    let new = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
    assert_eq!(
        versions(1),
        [old; 3],
        "prefix 1 was read whole before the change"
    );
    assert_eq!(
        versions(2),
        [new; 3],
        "prefix 2 was read whole after the change"
    );
}

/// A chunk query whose caller is already gone copies nothing.
#[test]
fn canceled_mrt_snapshot_chunk_copies_no_rows() {
    let mut manager = mrt_test_manager();
    seed_mrt_rib(&mut manager, mrt_test_peer(41), 3, 0);
    crate::manager::queries::mrt_chunks_built::take();

    let (reply, receiver) = oneshot::channel();
    drop(receiver);
    manager.handle_update(RibUpdate::QueryMrtSnapshotChunk {
        cursor: None,
        reply,
    });
    assert_eq!(crate::manager::queries::mrt_chunks_built::take(), 0);

    let (reply, mut receiver) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryMrtSnapshotChunk {
        cursor: None,
        reply,
    });
    assert_eq!(receiver.try_recv().unwrap().unwrap().routes.len(), 3);
    assert_eq!(crate::manager::queries::mrt_chunks_built::take(), 1);
}

/// Splitting the key index cannot move an unchanged body past the cursor.
/// Appended routes beyond the initial slot bounds are excluded.
#[test]
fn mrt_snapshot_evpn_table_that_splits_mid_walk_is_read_once() {
    const BEFORE: u32 = 10_000;
    const AFTER: u32 = 20_000;
    let mut manager = mrt_test_manager();
    let mut peers = [mrt_test_peer(51), mrt_test_peer(52)];
    peers.sort_unstable();
    for peer in peers {
        seed_mrt_rib(&mut manager, peer, 0, BEFORE);
        assert_eq!(manager.ribs[&peer].evpn_index_shards(), 1);
    }
    let mut grown = false;
    let (snapshot, turns) = drain_mrt_snapshot(&mut manager, |manager, turn| {
        // Split the first table while its slot walk is in progress.
        if turn == 2 {
            grown = true;
            for peer in peers {
                let rib = manager.ribs.get_mut(&peer).unwrap();
                for tag in BEFORE..AFTER {
                    rib.insert_evpn(mrt_test_evpn(peer, tag, 0));
                }
                assert!(rib.evpn_index_shards() > 1, "the table split");
            }
        }
    });
    assert!(grown);
    assert_eq!(turns[1], crate::update::MRT_SNAPSHOT_CHUNK_ROWS);
    let mut seen = HashSet::new();
    for route in &snapshot.evpn_routes {
        assert!(
            seen.insert((route.peer, route.key())),
            "an EVPN route copied twice"
        );
    }
    let rows_of = |peer| {
        snapshot
            .evpn_routes
            .iter()
            .filter(|route| route.peer == peer)
            .count()
    };
    assert_eq!(rows_of(peers[0]), BEFORE as usize);
    assert_eq!(rows_of(peers[1]), BEFORE as usize);
}

/// A neighbor is listed once, with the identity of the first chunk that
/// read its routes: one that rebinds or restarts mid-dump keeps that entry
/// for the routes read afterward.
#[test]
fn mrt_snapshot_lists_a_neighbor_with_its_first_identity() {
    let peer = mrt_test_peer(61);
    let entry = |peer_asn| crate::update::MrtPeerEntry {
        peer_asn,
        ..crate::update::MrtPeerEntry::capture(peer, 0, Ipv4Addr::UNSPECIFIED)
    };
    let mut snapshot = crate::update::MrtSnapshotAssembler::default();
    for peer_asn in [65_001, 65_002] {
        snapshot.push(crate::update::MrtSnapshotChunk {
            peers: vec![entry(peer_asn)],
            routes: vec![mrt_test_route(peer, peer_asn, 0)],
            ..Default::default()
        });
    }
    let snapshot = snapshot.finish();
    assert_eq!(snapshot.routes.len(), 2);
    assert_eq!(snapshot.peers.len(), 1);
    assert_eq!(snapshot.peers[0].peer_asn, 65_001);
}

#[test]
fn mrt_snapshot_rejects_evpn_table_reset_or_replacement() {
    for replace in [false, true] {
        let mut manager = mrt_test_manager();
        let peer = mrt_test_peer(71);
        seed_mrt_rib(&mut manager, peer, 0, 6);
        let first = manager.mrt_snapshot_chunk(None, 2).unwrap();
        let second = manager.mrt_snapshot_chunk(first.next, 2).unwrap();
        assert_eq!(second.evpn_routes.len(), 2);
        if replace {
            manager.ribs.insert(peer, AdjRibIn::new(peer));
        } else {
            manager.ribs.get_mut(&peer).unwrap().clear();
        }
        // Relearn in reverse order so unchanged-looking keys occupy other slots.
        for tag in (0..6).rev() {
            manager
                .ribs
                .get_mut(&peer)
                .unwrap()
                .insert_evpn(mrt_test_evpn(peer, tag, 0));
        }
        let error = manager.mrt_snapshot_chunk(second.next, 2).unwrap_err();
        assert!(error.contains("EVPN table was reset"), "{error}");
    }
}

#[test]
fn mrt_snapshot_freezes_roster_before_any_later_prefix() {
    let mut manager = mrt_test_manager();
    let address: IpAddr = "fe80::100".parse().unwrap();
    let peer = PeerId::allocate(crate::PeerEndpoint::new(address, Some("swp100")));
    let idle = mrt_test_peer(72);
    let late = mrt_test_peer(73);
    let empty_source = mrt_test_peer(74);
    manager
        .ribs
        .insert(empty_source, AdjRibIn::new(empty_source));
    seed_mrt_rib(&mut manager, peer, 3, 0);
    manager.peer_asn.insert(peer, 65_100);
    manager
        .peer_bgp_id
        .insert(peer, Ipv4Addr::new(192, 0, 2, 100));
    manager.peer_asn.insert(idle, 65_101);
    let first = manager.mrt_snapshot_chunk(None, 1).unwrap();
    assert_eq!(first.peers.len(), 2, "idle sessions are captured too");
    let entry = first.peers.iter().find(|entry| entry.peer == peer).unwrap();
    assert_eq!(entry.peer_addr, address);
    assert_eq!(entry.peer_asn, 65_100);
    assert_eq!(entry.interface.as_deref(), Some("swp100"));
    manager.handle_update(RibUpdate::RebindPeer {
        peer,
        endpoint: crate::PeerEndpoint::new("fe80::101".parse().unwrap(), Some("swp100")),
    });
    // Rebind tears down the old table; later unicast prefixes may come from
    // the new session, under the peer metadata frozen at the first query.
    seed_mrt_rib(&mut manager, peer, 3, 3);
    manager.peer_asn.insert(peer, 65_200);
    manager
        .peer_bgp_id
        .insert(peer, Ipv4Addr::new(192, 0, 2, 200));
    seed_mrt_rib(&mut manager, late, 3, 3);
    manager.peer_asn.insert(late, 65_300);
    let mut snapshot = crate::update::MrtSnapshotAssembler::default();
    let mut cursor = snapshot.push(first);
    while cursor.is_some() {
        let chunk = manager.mrt_snapshot_chunk(cursor, 1).unwrap();
        assert!(chunk.peers.is_empty(), "roster is emitted only once");
        cursor = snapshot.push(chunk);
    }
    let snapshot = snapshot.finish();
    assert_eq!(snapshot.routes.len(), 3);
    assert!(
        snapshot.evpn_routes.is_empty(),
        "EVPN added after capture is excluded"
    );
    assert!(snapshot.routes.iter().all(|route| route.peer == peer));
    assert!(snapshot.evpn_routes.iter().all(|route| route.peer == peer));
    let entry = snapshot
        .peers
        .iter()
        .find(|entry| entry.peer == peer)
        .unwrap();
    assert_eq!(entry.peer_addr, address);
    assert_eq!(entry.peer_asn, 65_100);
    assert_eq!(entry.peer_bgp_id, Ipv4Addr::new(192, 0, 2, 100));
    assert!(peer.release());
}

fn mrt_unicast_chunk_row_limit() -> usize {
    crate::MRT_SNAPSHOT_CHUNK_BYTES
        / (std::mem::size_of::<Route>() + std::mem::size_of::<crate::NextHopScope>())
}

#[test]
fn mrt_snapshot_rejects_oversized_prefix_before_cloning() {
    let mut manager = mrt_test_manager();
    let peers = [mrt_test_peer(81), mrt_test_peer(82)];
    for path_id in 0..=u32::try_from(mrt_unicast_chunk_row_limit()).unwrap() {
        let peer = peers[path_id as usize % peers.len()];
        let rib = manager
            .ribs
            .entry(peer)
            .or_insert_with(|| AdjRibIn::new(peer));
        let mut route = mrt_test_route(peer, 0, 0);
        route.path_id = path_id;
        rib.insert(route);
    }
    crate::manager::queries::mrt_chunks_built::take_rows();
    let error = manager.mrt_snapshot_chunk(None, 4096).unwrap_err();
    assert!(
        error.contains("exceeds the 8388608-byte chunk cap"),
        "{error}"
    );
    assert_eq!(crate::manager::queries::mrt_chunks_built::take_rows(), 0);
}

#[test]
fn mrt_snapshot_byte_cap_keeps_whole_prefixes() {
    let mut manager = mrt_test_manager();
    let peer = mrt_test_peer(83);
    let rib = manager
        .ribs
        .entry(peer)
        .or_insert_with(|| AdjRibIn::new(peer));
    let row_limit = mrt_unicast_chunk_row_limit();
    for prefix in 0..2 {
        let mut route = mrt_test_route(peer, prefix, 0);
        for path_id in 0..u32::try_from(row_limit).unwrap() {
            route.path_id = path_id;
            rib.insert(route.clone());
        }
    }
    // A large test-only row budget lets the byte limit be the stopping reason.
    let first = manager.mrt_snapshot_chunk(None, usize::MAX).unwrap();
    assert_eq!(first.routes.len(), row_limit);
    assert!(
        first
            .routes
            .iter()
            .all(|route| route.prefix == mrt_test_prefix(0))
    );
    assert!(first.routes.capacity() <= row_limit);
    let second = manager.mrt_snapshot_chunk(first.next, usize::MAX).unwrap();
    assert_eq!(second.routes.len(), row_limit);
    assert!(
        second
            .routes
            .iter()
            .all(|route| route.prefix == mrt_test_prefix(1))
    );
    assert!(second.routes.capacity() <= row_limit);
    let last = manager.mrt_snapshot_chunk(second.next, usize::MAX).unwrap();
    assert!(last.next.is_none());
}

#[test]
fn mrt_evpn_slab_preserves_sparse_retention_checkpoints() {
    const SLOTS: u32 = 100;
    let mut manager = mrt_test_manager();
    let peer = mrt_test_peer(84);
    seed_mrt_rib(&mut manager, peer, 0, SLOTS);
    let mut rib = manager.ribs.remove(&peer).unwrap();
    for tag in 0..SLOTS - 1 {
        assert!(rib.withdraw_evpn(&mrt_test_evpn(peer, tag, 0).key()));
    }
    let family = (Afi::L2Vpn, Safi::Evpn);
    let mut checkpoints = 0;
    assert_eq!(
        rib.mark_stale_evpn_with_checkpoint(family, &mut || checkpoints += 1),
        Vec::new(),
    );
    assert!(checkpoints >= 2 * SLOTS);
    assert_eq!(rib.gr_stale_family_len(family), 1);

    checkpoints = 0;
    assert_eq!(
        rib.promote_to_llgr_stale_evpn_with_checkpoint(
            family,
            &mut crate::AttrInternTable::new(),
            &mut || checkpoints += 1,
        )
        .len(),
        1
    );
    assert!(checkpoints >= 2 * SLOTS);
    assert_eq!(rib.gr_stale_family_len(family), 0);
    assert_eq!(rib.retained_family_len(family, true), 1);

    checkpoints = 0;
    rib.clear_stale_evpn_with_checkpoint(family, true, &mut || checkpoints += 1);
    assert!(checkpoints >= SLOTS);
    assert_eq!(rib.retained_family_len(family, true), 0);

    rib.mark_stale_evpn(family);
    checkpoints = 0;
    assert_eq!(
        rib.sweep_stale_family_evpn_with_checkpoint(family, false, &mut || checkpoints += 1,)
            .len(),
        1
    );
    assert!(checkpoints >= SLOTS);
    assert_eq!(rib.evpn_len(), 0);

    checkpoints = 0;
    rib.retire_with(&mut || checkpoints += 1);
    assert!(
        checkpoints >= 2 * SLOTS,
        "retirement must visit vacant slots too"
    );
}
