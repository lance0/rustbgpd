use super::*;

#[tokio::test]
async fn warm_mrt_snapshot_rejects_session_generation_change_at_rib_fence() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer_router_id = Ipv4Addr::new(192, 0, 2, 1);
    let (out_tx, _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
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

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer_router_id = Ipv4Addr::new(192, 0, 2, 1);
    let (out_tx, _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
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
    v6.peer = peer;
    tx.send(RibUpdate::RoutesReceived {
        session_id: 42,
        peer,
        announced: vec![make_route(v4, Ipv4Addr::new(10, 0, 0, 1)), v6],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer_router_id = Ipv4Addr::new(192, 0, 2, 1);
    let (out_tx, _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
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

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
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
        .find(|entry| entry.peer_addr == peer)
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

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer_a),
        announced: vec![route_a],
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
        peer: IpAddr::V4(peer_b),
        announced: vec![route_b],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Give the RIB manager time to process.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let explain = query_explain_best_path(&tx, Prefix::V4(prefix)).await;

    // Best route should be from peer_a (higher LP).
    assert!(explain.best.is_some());
    let best = explain.best.unwrap();
    assert_eq!(best.peer, IpAddr::V4(peer_a));

    // Candidates should NOT include the winner.
    assert_eq!(explain.candidates.len(), 1);
    let loser = &explain.candidates[0];
    assert_eq!(loser.route.peer, IpAddr::V4(peer_b));
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
    assert!(explain.best_reason_detail.is_empty());

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
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer),
        announced: vec![make_route_with_lp(prefix, peer, 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let explain = query_explain_best_path(&tx, Prefix::V4(prefix)).await;
    assert_eq!(
        explain.best.as_ref().map(|r| r.peer),
        Some(IpAddr::V4(peer))
    );
    assert!(explain.candidates.is_empty());
    assert!(explain.best_reason.is_none());
    assert!(explain.best_reason_detail.is_empty());

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
    let all: Vec<Route> = routes
        .iter()
        .map(|(peer, asns, lp)| make_multipath_route(prefix, *peer, asns.clone(), *lp))
        .collect();
    for route in &all {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: route.peer,
            announced: vec![route.clone()],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
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
    assert_eq!(best.peer, IpAddr::V4(winner_peer));

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
            .find(|c| c.route.peer == IpAddr::V4(peer))
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

/// Add-Path explain: a peer with `send_max=2` and 3 candidate routes
/// should see exactly 2 candidates with non-zero `advertised_path_id`
/// (ranks 1 + 2 by best-path order), and the third one with a zero
/// `advertised_path_id` (it would be dropped past the limit).
#[tokio::test]
async fn explain_best_path_for_addpath_peer_marks_top_n_with_path_id() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let peer3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

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

    let (out_tx, _out_rx) = mpsc::channel(64);
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
    let by_peer: std::collections::HashMap<IpAddr, &crate::update::BestPathCandidate> = explain
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

    let peer_winner = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer_runner_up = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

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
        })
        .await
        .unwrap();
    }

    let (out_tx, _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
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
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    for (peer, addr, asn, lp) in [
        (peer1, Ipv4Addr::new(10, 0, 0, 1), 65001, 200),
        (peer2, Ipv4Addr::new(10, 0, 0, 2), 65002, 100),
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
        })
        .await
        .unwrap();
    }

    let (out_tx, _out_rx) = mpsc::channel(64);
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
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    for (peer, addr, asn, lp) in [
        (peer1, Ipv4Addr::new(10, 0, 0, 1), 65001, 200),
        (peer2, Ipv4Addr::new(10, 0, 0, 2), 65002, 100),
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
        })
        .await
        .unwrap();
    }

    // Peer registered with sendable_families = IPv4 unicast, but
    // add_path_send_families = IPv6 unicast. Asking about an IPv4
    // prefix → effective send_max should be 0.
    let (out_tx, _out_rx) = mpsc::channel(64);
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
    let unknown = IpAddr::V4(Ipv4Addr::new(10, 99, 99, 99));

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

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer_a),
        announced: vec![make_route_with_lp(prefix, peer_a, 200)],
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
        peer: IpAddr::V4(peer_b),
        announced: vec![make_route_with_lp(prefix, peer_b, 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
