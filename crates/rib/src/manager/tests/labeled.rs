use super::*;

fn with_labeled_no_advertise(
    mut route: crate::route::LabeledRibRoute,
) -> crate::route::LabeledRibRoute {
    let attributes = Arc::make_mut(&mut route.attributes);
    if let Some(PathAttribute::Communities(communities)) = attributes
        .iter_mut()
        .find(|attribute| matches!(attribute, PathAttribute::Communities(_)))
    {
        if !communities.contains(&rustbgpd_wire::COMMUNITY_NO_ADVERTISE) {
            communities.push(rustbgpd_wire::COMMUNITY_NO_ADVERTISE);
        }
    } else {
        attributes.push(PathAttribute::Communities(vec![
            rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
        ]));
    }
    route
}

fn labeled_route_at(
    peer: Ipv4Addr,
    prefix: Prefix,
    next_hop: IpAddr,
    local_pref: u32,
) -> crate::route::LabeledRibRoute {
    let mut route = make_labeled_rib_route(peer, 42, 4093, local_pref);
    route.nlri.prefix = prefix;
    route.next_hop = next_hop;
    route
}

fn add_no_advertise_for_next_hop(next_hop: IpAddr) -> rustbgpd_policy::PolicyChain {
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
                communities_add: vec![rustbgpd_wire::COMMUNITY_NO_ADVERTISE],
                ..rustbgpd_policy::RouteModifications::default()
            },
        }],
        default_action: rustbgpd_policy::PolicyAction::Permit,
    }])
}

fn drain_labeled_delta(
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    state: &mut HashMap<crate::route::LabeledRibRouteKey, crate::route::LabeledRibRoute>,
) -> (
    Vec<crate::route::LabeledRibRoute>,
    Vec<crate::route::LabeledRibRouteKey>,
) {
    let mut announced = Vec::new();
    let mut withdrawn = Vec::new();
    while let Ok(update) = rx.try_recv() {
        for route in update.labeled_announce {
            state.insert(route.key(), route.clone());
            announced.push(route);
        }
        for key in update.labeled_withdraw {
            state.remove(&key);
            withdrawn.push(key);
        }
    }
    (announced, withdrawn)
}

// --- Receive / reflect / withdraw (the SAFI 4 mirror of tests/vpn.rs) ---

/// A resolved ORR client selects the vantage-closest labeled winner while a
/// plain client keeps the Loc-RIB winner. Source- and policy-produced
/// `NO_ADVERTISE` withdraw that selected winner without falling back, for both
/// labeled IPv4 and IPv6, and clearing the restriction restores it.
///
/// Break-to-red: deleting either single-best guard advertises the scoped Y
/// winner; moving the source guard into ORR candidate filtering announces X;
/// deleting `withdraw_existing` loses the exact path-0 withdrawals and leaves
/// the state non-empty or prevents the identical winner from recovering.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one stateful scenario pins dual-AFI plain/ORR winner suppression, zero fallback, exact withdrawal, and recovery"
)]
async fn labeled_no_advertise_suppresses_resolved_orr_winner_without_plain_churn() {
    use crate::orr::fixtures::{A, B, X, Y};

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 255, 0, 1)),
        BgpMetrics::new(),
    );
    let handle = tokio::spawn(manager.run());
    let feed = Ipv4Addr::new(10, 9, 9, 9);
    feed_square_topology(&tx, feed).await;

    let next_hop_x = IpAddr::V4(Ipv4Addr::new(10, 0, X, A));
    let next_hop_y = IpAddr::V4(Ipv4Addr::new(10, 0, Y, A));
    let vantage_b = IpAddr::V4(Ipv4Addr::new(10, 0, B, X));
    let source_x = Ipv4Addr::new(192, 0, 2, 1);
    let source_y = Ipv4Addr::new(192, 0, 2, 2);
    let families = vec![
        (Afi::Ipv4, Safi::LabeledUnicast),
        (Afi::Ipv6, Safi::LabeledUnicast),
    ];
    let plain = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 30));
    let orr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 31));
    let mut receivers = Vec::new();
    for (peer, vantage) in [(plain, None), (orr, Some(vantage_b))] {
        let (out_tx, mut out_rx) = mpsc::channel(32);
        tx.send(RibUpdate::PeerUp {
            per_client_best: false,
            interpret_rfc1997: true,
            session_id: 0,
            peer,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx: out_tx,
            export_policy: Some(super::unicast::no_advertise_removal_chain(false)),
            sendable_families: families.clone(),
            is_ebgp: false,
            route_reflector_client: true,
            orr_vantage: vantage,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
            negotiated_llgr_families: Vec::new(),
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;
        receivers.push((peer, out_rx, HashMap::new()));
    }
    let status = query_orr_status(&tx).await;
    assert!(
        status
            .vantages
            .iter()
            .any(|entry| entry.vantage == vantage_b && entry.resolved),
        "the ORR differential requires a resolved vantage"
    );

    let v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24));
    let v6 = Prefix::V6(Ipv6Prefix::new("2001:db8:442::".parse().unwrap(), 64));
    let routes_x = vec![
        labeled_route_at(source_x, v4, next_hop_x, 100),
        labeled_route_at(source_x, v6, next_hop_x, 100),
    ];
    let routes_y = vec![
        labeled_route_at(source_y, v4, next_hop_y, 100),
        labeled_route_at(source_y, v6, next_hop_y, 100),
    ];
    let expected_keys: HashSet<_> = routes_x
        .iter()
        .map(crate::route::LabeledRibRoute::key)
        .collect();
    for (peer, routes) in [(source_x, routes_x.clone()), (source_y, routes_y.clone())] {
        tx.send(RibUpdate::LabeledRoutesReceived {
            session_id: 0,
            peer: IpAddr::V4(peer),
            announced: routes,
            withdrawn: vec![],
        })
        .await
        .unwrap();
    }
    let _ = query_labeled_routes(&tx).await;
    for (peer, out_rx, state) in &mut receivers {
        let (announced, withdrawn) = drain_labeled_delta(out_rx, state);
        assert!(!announced.is_empty(), "baseline must stage real output");
        assert!(withdrawn.is_empty());
        assert_eq!(state.keys().copied().collect::<HashSet<_>>(), expected_keys);
        let expected_source = if *peer == plain { source_x } else { source_y };
        assert!(
            state
                .values()
                .all(|route| route.peer == IpAddr::V4(expected_source))
        );
    }

    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source_y),
        announced: routes_y
            .iter()
            .cloned()
            .map(with_labeled_no_advertise)
            .collect(),
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_labeled_routes(&tx).await;
    let (_, plain_rx, plain_state) = &mut receivers[0];
    let (announced, withdrawn) = drain_labeled_delta(plain_rx, plain_state);
    assert!(announced.is_empty() && withdrawn.is_empty());
    assert_eq!(plain_state.len(), 2);
    let (_, orr_rx, orr_state) = &mut receivers[1];
    let (announced, withdrawn) = drain_labeled_delta(orr_rx, orr_state);
    assert!(announced.is_empty(), "ORR must not fall back to X");
    assert_eq!(withdrawn.len(), 2);
    assert_eq!(withdrawn.into_iter().collect::<HashSet<_>>(), expected_keys);
    assert!(
        orr_state.is_empty(),
        "withdrawals clear the stateful oracle"
    );

    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source_y),
        announced: routes_y.clone(),
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_labeled_routes(&tx).await;
    let (announced, withdrawn) = drain_labeled_delta(orr_rx, orr_state);
    assert_eq!(announced.len(), 2);
    assert!(withdrawn.is_empty());
    assert!(
        orr_state
            .values()
            .all(|route| route.peer == IpAddr::V4(source_y))
    );

    for (peer, _, _) in &receivers {
        let (reply, response) = oneshot::channel();
        tx.send(RibUpdate::ReplacePeerExportPolicy {
            peer: *peer,
            export_policy: Some(add_no_advertise_for_next_hop(next_hop_y)),
            reply,
        })
        .await
        .unwrap();
        response.await.unwrap().unwrap();
    }
    let _ = query_labeled_routes(&tx).await;
    let (_, plain_rx, plain_state) = &mut receivers[0];
    let (announced, withdrawn) = drain_labeled_delta(plain_rx, plain_state);
    assert!(announced.is_empty() && withdrawn.is_empty());
    assert!(
        plain_state
            .values()
            .all(|route| route.peer == IpAddr::V4(source_x))
    );
    let (_, orr_rx, orr_state) = &mut receivers[1];
    let (announced, withdrawn) = drain_labeled_delta(orr_rx, orr_state);
    assert!(
        announced.is_empty(),
        "policy-scoped ORR winner has no fallback"
    );
    assert_eq!(withdrawn.len(), 2);
    assert_eq!(withdrawn.into_iter().collect::<HashSet<_>>(), expected_keys);
    assert!(orr_state.is_empty());

    for (peer, _, _) in &receivers {
        let (reply, response) = oneshot::channel();
        tx.send(RibUpdate::ReplacePeerExportPolicy {
            peer: *peer,
            export_policy: Some(super::unicast::no_advertise_removal_chain(false)),
            reply,
        })
        .await
        .unwrap();
        response.await.unwrap().unwrap();
    }
    let _ = query_labeled_routes(&tx).await;
    let (_, plain_rx, plain_state) = &mut receivers[0];
    let (announced, withdrawn) = drain_labeled_delta(plain_rx, plain_state);
    assert!(announced.is_empty() && withdrawn.is_empty());
    let (_, orr_rx, orr_state) = &mut receivers[1];
    let (announced, withdrawn) = drain_labeled_delta(orr_rx, orr_state);
    assert_eq!(announced.len(), 2);
    assert!(withdrawn.is_empty());
    assert_eq!(
        orr_state.keys().copied().collect::<HashSet<_>>(),
        expected_keys
    );

    drop(tx);
    handle.await.unwrap();
}

/// Labeled Add-Path removes scoped candidates before assigning outbound ranks,
/// compacts surviving ranks, withdraws stale ranks, and restores the full set.
///
/// Break-to-red: deleting either Add-Path guard, moving it after the rank
/// increment, or deleting stale-rank cleanup changes the raw rank-1 announce,
/// loses the exact rank-2/rank-1 withdrawal, or prevents full recovery.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one stateful scenario proves source and policy suppression, compact ranks, exact stale cleanup, and recovery"
)]
async fn labeled_add_path_no_advertise_compacts_and_withdraws_ranks() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 40));
    let (out_tx, mut out_rx) = mpsc::channel(32);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: target,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: Some(super::unicast::no_advertise_removal_chain(false)),
        sendable_families: labeled_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: labeled_sendable(),
        add_path_send_max: 2,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let best = make_labeled_rib_route(Ipv4Addr::new(192, 0, 2, 11), 43, 100, 200);
    let second = make_labeled_rib_route(Ipv4Addr::new(192, 0, 2, 12), 43, 200, 100);
    let prefix = best.nlri.key();
    for route in [&best, &second] {
        tx.send(RibUpdate::LabeledRoutesReceived {
            session_id: 0,
            peer: route.peer,
            announced: vec![route.clone()],
            withdrawn: vec![],
        })
        .await
        .unwrap();
    }
    let _ = query_labeled_routes(&tx).await;
    let mut state = HashMap::new();
    let (announced, withdrawn) = drain_labeled_delta(&mut out_rx, &mut state);
    assert!(!announced.is_empty(), "baseline must begin non-empty");
    assert!(withdrawn.is_empty());
    assert_eq!(state.len(), 2);
    assert_eq!(
        state[&crate::route::LabeledRibRouteKey { prefix, path_id: 1 }].peer,
        best.peer
    );
    assert_eq!(
        state[&crate::route::LabeledRibRouteKey { prefix, path_id: 2 }].peer,
        second.peer
    );

    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: best.peer,
        announced: vec![with_labeled_no_advertise(best.clone())],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_labeled_routes(&tx).await;
    let (announced, withdrawn) = drain_labeled_delta(&mut out_rx, &mut state);
    assert_eq!(announced.len(), 1);
    assert_eq!((announced[0].path_id, announced[0].peer), (1, second.peer));
    assert_eq!(
        withdrawn,
        vec![crate::route::LabeledRibRouteKey { prefix, path_id: 2 }]
    );
    assert_eq!(state.len(), 1);

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: target,
        export_policy: Some(super::unicast::no_advertise_addition_chain(false)),
        reply,
    })
    .await
    .unwrap();
    response.await.unwrap().unwrap();
    let _ = query_labeled_routes(&tx).await;
    let (announced, withdrawn) = drain_labeled_delta(&mut out_rx, &mut state);
    assert!(announced.is_empty());
    assert_eq!(
        withdrawn,
        vec![crate::route::LabeledRibRouteKey { prefix, path_id: 1 }]
    );
    assert!(state.is_empty());

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: target,
        export_policy: Some(super::unicast::no_advertise_removal_chain(false)),
        reply,
    })
    .await
    .unwrap();
    response.await.unwrap().unwrap();
    let _ = query_labeled_routes(&tx).await;
    let (announced, withdrawn) = drain_labeled_delta(&mut out_rx, &mut state);
    assert_eq!(announced.len(), 1);
    assert_eq!((announced[0].path_id, announced[0].peer), (1, second.peer));
    assert!(withdrawn.is_empty());

    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: best.peer,
        announced: vec![best.clone()],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_labeled_routes(&tx).await;
    let (announced, withdrawn) = drain_labeled_delta(&mut out_rx, &mut state);
    assert_eq!(announced.len(), 2);
    assert!(withdrawn.is_empty());
    assert_eq!(state.len(), 2);
    assert_eq!(
        state[&crate::route::LabeledRibRouteKey { prefix, path_id: 1 }].peer,
        best.peer
    );
    assert_eq!(
        state[&crate::route::LabeledRibRouteKey { prefix, path_id: 2 }].peer,
        second.peer
    );

    drop(tx);
    handle.await.unwrap();
}

/// A received labeled route must be reflected to an eligible (eBGP-export)
/// peer, and a withdrawal must be staged with the prefix + path-id key.
#[tokio::test]
async fn labeled_routes_received_reflects_and_withdraws_to_eligible_peer() {
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
        sendable_families: labeled_sendable(),
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
    let route = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100);
    let key = route.key();

    tx.send(RibUpdate::LabeledRoutesReceived {
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
    assert_eq!(update.labeled_announce.len(), 1);
    assert_eq!(update.labeled_announce[0].key(), key);
    assert_eq!(
        update.labeled_announce[0].nlri, route.nlri,
        "label stack must pass through reflection verbatim"
    );
    assert_eq!(update.labeled_announce[0].next_hop, route.next_hop);
    assert!(update.labeled_withdraw.is_empty());

    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![key],
    })
    .await
    .unwrap();

    let withdraw = out_rx.recv().await.unwrap();
    assert!(withdraw.labeled_announce.is_empty());
    assert_eq!(withdraw.labeled_withdraw, vec![key]);

    drop(tx);
    handle.await.unwrap();
}

/// RFC 4456 eligibility on labeled reflection: a non-client iBGP route is
/// reflected to RR clients, suppressed toward other non-clients, and never
/// echoed back to the source.
#[tokio::test]
async fn labeled_rr_reflects_non_client_route_to_clients_only() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let non_client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

    let mut rxs = Vec::new();
    for (peer, is_client) in [(source, false), (client, true), (non_client, false)] {
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            per_client_best: false,
            interpret_rfc1997: true,
            session_id: 0,
            peer,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: labeled_sendable(),
            is_ebgp: false,
            route_reflector_client: is_client,
            orr_vantage: None,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
            negotiated_llgr_families: Vec::new(),
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;
        rxs.push(out_rx);
    }
    let mut non_client_rx = rxs.pop().unwrap();
    let mut client_rx = rxs.pop().unwrap();
    let mut source_rx = rxs.pop().unwrap();

    let route = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 32, 100, 100);
    let key = route.key();
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let reflected = client_rx.recv().await.unwrap();
    assert_eq!(reflected.labeled_announce.len(), 1);
    assert_eq!(reflected.labeled_announce[0].key(), key);

    let non_client_echo =
        tokio::time::timeout(Duration::from_millis(50), non_client_rx.recv()).await;
    assert!(
        non_client_echo.is_err(),
        "non-client iBGP route must not be reflected to another non-client"
    );
    let source_echo = tokio::time::timeout(Duration::from_millis(50), source_rx.recv()).await;
    assert!(
        source_echo.is_err(),
        "labeled routes must not be reflected back to the source peer"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A same-peer relabel (same prefix key, new MPLS label stack) must be
/// re-advertised: the label is route data and `labeled_routes_equal` must
/// catch the `nlri` change.
#[tokio::test]
async fn labeled_same_peer_relabel_triggers_re_advertise() {
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
        sendable_families: labeled_sendable(),
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
    let route = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 33, 100, 100);
    let relabeled = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 33, 200, 100);
    assert_eq!(
        route.key(),
        relabeled.key(),
        "label must not change the key"
    );

    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.labeled_announce.len(), 1);
    assert_eq!(first.labeled_announce[0].nlri.labels[0].label, 100);

    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![relabeled],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let second = out_rx.recv().await.unwrap();
    assert_eq!(
        second.labeled_announce.len(),
        1,
        "same-peer relabel must re-advertise"
    );
    assert_eq!(second.labeled_announce[0].nlri.labels[0].label, 200);

    drop(tx);
    handle.await.unwrap();
}

/// A dirty-resync (here: an export-policy replace, which forces a full
/// restage against the real Adj-RIB-Out) must not re-send a labeled route
/// whose staged form is unchanged.
#[tokio::test]
async fn labeled_dirty_resync_equality_skip_does_not_resend_unchanged_route() {
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
        sendable_families: labeled_sendable(),
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
    let route = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 34, 100, 100);
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.labeled_announce.len(), 1);

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: target,
        export_policy: None,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap().unwrap();

    let resend = tokio::time::timeout(Duration::from_millis(50), out_rx.recv()).await;
    assert!(
        resend.is_err(),
        "unchanged labeled route must be skipped by the dirty-resync equality check"
    );

    drop(tx);
    handle.await.unwrap();
}

// --- Add-Path (RFC 7911) ---

/// RFC 7911 labeled receive: distinct path IDs for the same prefix are
/// distinct Adj-RIB-In entries, and a withdraw keyed by path ID removes
/// only that one — the surviving path takes over the Loc-RIB best.
#[tokio::test]
async fn labeled_addpath_ingest_distinct_path_ids_stored_and_withdrawn_independently() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let mut path_1 = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 200);
    path_1.path_id = 1;
    let mut path_2 = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100);
    path_2.path_id = 2;
    assert_eq!(path_1.nlri.key(), path_2.nlri.key());
    assert_ne!(path_1.key(), path_2.key());

    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![path_1.clone(), path_2.clone()],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let best = query_labeled_routes(&tx).await;
    assert_eq!(best.len(), 1, "one Loc-RIB best per prefix identity");
    assert_eq!(
        best[0].path_id, 1,
        "the higher-LOCAL_PREF received path wins"
    );

    // Withdraw ONLY path 1 — path 2 must survive and take over.
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![path_1.key()],
    })
    .await
    .unwrap();
    let best = query_labeled_routes(&tx).await;
    assert_eq!(best.len(), 1, "path 2 must survive a path-1-only withdraw");
    assert_eq!(best[0].path_id, 2);

    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![path_2.key()],
    })
    .await
    .unwrap();
    assert!(query_labeled_routes(&tx).await.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// RFC 7911 labeled send: an Add-Path-send target receives up to `send_max`
/// candidates per prefix with outbound path IDs 1..=N ranked by the labeled
/// tiebreak, a non-Add-Path target keeps single-best (`path_id = 0`), and
/// a source withdraw shrinks the staged set by outbound path ID.
#[expect(
    clippy::too_many_lines,
    reason = "one scenario: Add-Path target, single-best target, and a source withdraw over the same staged set"
)]
#[tokio::test]
async fn labeled_addpath_send_stages_top_n_and_single_best_unchanged() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let addpath_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (addpath_out_tx, mut addpath_out) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: addpath_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: addpath_out_tx,
        export_policy: None,
        sendable_families: labeled_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![(Afi::Ipv4, Safi::LabeledUnicast)],
        add_path_send_max: 3,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut addpath_out).await;
    tx.send(RibUpdate::PeerAddPathLimits {
        peer: addpath_target,
        session_id: 0,
        limits: vec![((Afi::Ipv4, Safi::LabeledUnicast), 2)],
    })
    .await
    .unwrap();
    drain_eor(&mut addpath_out).await;

    let plain_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let (plain_out_tx, mut plain_out) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: plain_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: plain_out_tx,
        export_policy: None,
        sendable_families: labeled_sendable(),
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
    drain_eor(&mut plain_out).await;

    // Same prefix from three sources, ranked by LOCAL_PREF: 300 > 200 > 100.
    let best = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 11), 31, 100, 300);
    let second = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 12), 31, 200, 200);
    let third = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 13), 31, 300, 100);
    let prefix = best.nlri.key();
    for route in [&best, &second, &third] {
        tx.send(RibUpdate::LabeledRoutesReceived {
            session_id: 0,
            peer: route.peer,
            announced: vec![route.clone()],
            withdrawn: vec![],
        })
        .await
        .unwrap();
    }
    let _ = query_labeled_routes(&tx).await; // sync point

    let staged = drain_final_labeled(&mut addpath_out);
    assert_eq!(
        staged.len(),
        2,
        "family-local limit=2 overrides scalar send_max=3"
    );
    let rank_1 = staged
        .get(&crate::route::LabeledRibRouteKey { prefix, path_id: 1 })
        .expect("outbound path_id 1 staged");
    let rank_2 = staged
        .get(&crate::route::LabeledRibRouteKey { prefix, path_id: 2 })
        .expect("outbound path_id 2 staged");
    assert_eq!(rank_1.next_hop, best.next_hop, "rank 1 = best by tiebreak");
    assert_eq!(rank_2.next_hop, second.next_hop, "rank 2 = runner-up");

    tx.send(RibUpdate::RouteRefreshRequest {
        session_id: 0,
        peer: addpath_target,
        afi: Afi::Ipv4,
        safi: Safi::LabeledUnicast,
    })
    .await
    .unwrap();
    let _ = query_labeled_routes(&tx).await;
    let refreshed = drain_final_labeled(&mut addpath_out);
    assert_eq!(
        refreshed.len(),
        2,
        "route refresh preserves the family-local labeled cap"
    );

    let plain_staged = drain_final_labeled(&mut plain_out);
    assert_eq!(plain_staged.len(), 1, "non-Add-Path peer stays single-best");
    let single = plain_staged
        .get(&crate::route::LabeledRibRouteKey { prefix, path_id: 0 })
        .expect("single-best staged at path_id 0");
    assert_eq!(single.next_hop, best.next_hop);

    // The best source withdraws: the staged top-2 becomes {second, third}
    // re-ranked as path IDs 1..2; the diff withdraws by outbound path ID.
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: best.peer,
        announced: vec![],
        withdrawn: vec![best.key()],
    })
    .await
    .unwrap();
    let _ = query_labeled_routes(&tx).await; // sync point

    let staged = drain_final_labeled(&mut addpath_out);
    let rank_1 = staged
        .get(&crate::route::LabeledRibRouteKey { prefix, path_id: 1 })
        .expect("outbound path_id 1 restaged after withdraw");
    let rank_2 = staged
        .get(&crate::route::LabeledRibRouteKey { prefix, path_id: 2 })
        .expect("outbound path_id 2 restaged after withdraw");
    assert_eq!(rank_1.next_hop, second.next_hop);
    assert_eq!(rank_2.next_hop, third.next_hop);

    drop(tx);
    handle.await.unwrap();
}

// --- Initial dump / EoR / route refresh ---

/// A peer that comes up after the labeled table converged must receive the
/// full table in its initial dump, followed by the SAFI-4 `EoR`.
#[tokio::test]
async fn send_initial_table_includes_labeled_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 35, 100, 100);
    let key = route.key();

    tx.send(RibUpdate::LabeledRoutesReceived {
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
        sendable_families: labeled_sendable(),
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
    assert_eq!(update.labeled_announce.len(), 1);
    assert_eq!(update.labeled_announce[0].key(), key);
    assert!(update.labeled_withdraw.is_empty());

    let eor = out_rx.recv().await.unwrap();
    assert_eq!(eor.end_of_rib, labeled_sendable());

    drop(tx);
    handle.await.unwrap();
}

/// A plain ROUTE-REFRESH request for (IPv4, `LabeledUnicast`) must replay
/// the staged labeled routes between the BoRR/EoRR markers.
#[tokio::test]
async fn route_refresh_labeled_re_advertises_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 36, 100, 100);
    let key = route.key();

    tx.send(RibUpdate::LabeledRoutesReceived {
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
        sendable_families: labeled_sendable(),
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
        afi: Afi::Ipv4,
        safi: Safi::LabeledUnicast,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert!(update.withdraw.is_empty());
    assert_eq!(update.labeled_announce.len(), 1);
    assert_eq!(update.labeled_announce[0].key(), key);
    assert!(update.labeled_withdraw.is_empty());
    assert_eq!(update.end_of_rib, vec![(Afi::Ipv4, Safi::LabeledUnicast)]);
    assert_eq!(
        update.refresh_markers,
        vec![
            (
                Afi::Ipv4,
                Safi::LabeledUnicast,
                rustbgpd_wire::RouteRefreshSubtype::BoRR
            ),
            (
                Afi::Ipv4,
                Safi::LabeledUnicast,
                rustbgpd_wire::RouteRefreshSubtype::EoRR
            ),
        ]
    );

    drop(tx);
    handle.await.unwrap();
}

/// RFC 7313 `BoRR` snapshots the peer's labeled Adj-RIB-In as stale;
/// peer-down during the window must clear every piece of that state.
#[test]
fn labeled_peer_down_during_refresh_clears_stale_state() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);

    manager.handle_labeled_routes_received(
        peer,
        vec![make_labeled_rib_route(peer_addr, 26, 100, 100)],
        vec![],
    );
    manager.handle_update(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::LabeledUnicast,
    });
    assert!(
        manager
            .refresh_stale_labeled
            .get(&peer)
            .is_some_and(|stale| stale.len() == 1),
        "BoRR must snapshot the peer's Adj-RIB-In labeled keys as stale"
    );

    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    });
    assert!(
        !manager.refresh_stale_labeled.contains_key(&peer),
        "peer-down during an active refresh must clear the labeled stale snapshot"
    );
    assert!(!manager.refresh_in_progress.contains_key(&peer));
    assert!(
        manager
            .refresh_stale_counts
            .keys()
            .all(|(stale_peer, _, _)| *stale_peer != peer),
        "peer-down must drop the peer's refresh-stale counters"
    );
}

// --- Graceful restart (RFC 4724) ---

/// A peer entering GR with (IPv4, `LabeledUnicast`) in its capability keeps
/// its labeled routes as stale. Staleness demotes the tiebreak rank, so a
/// fresh route from another peer takes over; with every candidate stale the
/// normal tiebreak re-applies and the key stays reflected.
#[tokio::test]
async fn labeled_gr_marks_stale_and_demotes_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let best_advertiser = Ipv4Addr::new(10, 0, 0, 1);
    let alternate_advertiser = Ipv4Addr::new(10, 0, 0, 3);
    let best_peer = IpAddr::V4(best_advertiser);
    let alternate_peer = IpAddr::V4(alternate_advertiser);

    // Same prefix (octet) from both peers ⇒ same RIB key.
    let route_a = make_labeled_rib_route(best_advertiser, 31, 100, 200);
    let route_b = make_labeled_rib_route(alternate_advertiser, 31, 200, 100);
    assert_eq!(route_a.key(), route_b.key());
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: best_peer,
        announced: vec![route_a],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: alternate_peer,
        announced: vec![route_b],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let best_before = query_labeled_routes(&tx).await;
    assert_eq!(best_before.len(), 1);
    assert_eq!(best_before[0].peer, best_peer);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: best_peer,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::LabeledUnicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let after_winner_gr = query_labeled_routes(&tx).await;
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
        gr_families: vec![(Afi::Ipv4, Safi::LabeledUnicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let after_last_gr = query_labeled_routes(&tx).await;
    assert_eq!(
        after_last_gr.len(),
        1,
        "GR must retain the stale labeled route instead of dropping the key"
    );
    assert_eq!(
        after_last_gr[0].peer, best_peer,
        "with both candidates stale the normal tiebreak (higher LOCAL_PREF) re-applies"
    );
    assert!(after_last_gr[0].is_stale);

    drop(tx);
    handle.await.unwrap();
}

/// A peer whose GR capability does NOT list (IPv4, `LabeledUnicast`) must
/// have its labeled routes withdrawn on GR entry and the withdrawal staged
/// downstream.
#[tokio::test]
async fn labeled_gr_family_not_in_capability_is_withdrawn() {
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
        sendable_families: labeled_sendable(),
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
    let route = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100);
    let key = route.key();
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.labeled_announce.len(), 1);

    // GR capability carries only unicast: labeled is withdrawn, not retained.
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

    let withdraw = out_rx.recv().await.unwrap();
    assert_eq!(
        withdraw.labeled_withdraw,
        vec![key],
        "GR entry must withdraw labeled routes absent from the capability"
    );
    assert!(
        query_labeled_routes(&tx).await.is_empty(),
        "labeled absent from the GR capability must not be retained stale"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Re-advertisement during the restart window replaces the stale labeled
/// route; End-of-RIB clears the survivor's stale flag and removes (and
/// withdraws downstream) what was not re-advertised (RFC 4724 §4.1).
#[tokio::test]
async fn labeled_gr_eor_clears_stale() {
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
        sendable_families: labeled_sendable(),
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
    let kept = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 60, 100, 100);
    let dropped = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 61, 100, 100);
    let kept_key = kept.key();
    let dropped_key = dropped.key();
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept.clone(), dropped],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.labeled_announce.len(), 2);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::LabeledUnicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();
    let stale = query_labeled_routes(&tx).await;
    assert_eq!(stale.len(), 2);
    assert!(stale.iter().all(|r| r.is_stale));

    // Only `kept` is re-advertised before End-of-RIB.
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::LabeledUnicast,
    })
    .await
    .unwrap();

    let after_eor = query_labeled_routes(&tx).await;
    assert_eq!(
        after_eor.len(),
        1,
        "the non-readvertised stale labeled route must be removed at End-of-RIB"
    );
    assert_eq!(after_eor[0].key(), kept_key);
    assert!(!after_eor[0].is_stale, "EoR must clear the stale flag");

    // The removal must be withdrawn downstream.
    loop {
        let update = out_rx.recv().await.unwrap();
        if update.labeled_withdraw.is_empty() {
            continue;
        }
        assert_eq!(update.labeled_withdraw, vec![dropped_key]);
        break;
    }

    drop(tx);
    handle.await.unwrap();
}

/// GR timer expiry without LLGR purges the stale labeled routes.
#[tokio::test]
async fn labeled_gr_timer_sweeps_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_labeled_rib_route(
            Ipv4Addr::new(10, 0, 0, 1),
            31,
            100,
            100,
        )],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::Ipv4, Safi::LabeledUnicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();
    let stale = query_labeled_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    assert!(
        query_labeled_routes(&tx).await.is_empty(),
        "GR timer expiry must sweep stale labeled routes"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A second GR entry while labeled routes are still stale deletes them
/// (RFC 4724 §4.1: no retention across consecutive restarts).
#[tokio::test]
async fn labeled_gr_consecutive_restart_deletes_stale_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_labeled_rib_route(
            Ipv4Addr::new(10, 0, 0, 1),
            31,
            100,
            100,
        )],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let gr_entry = || RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::LabeledUnicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    };
    tx.send(gr_entry()).await.unwrap();
    let stale = query_labeled_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    tx.send(gr_entry()).await.unwrap();
    assert!(
        query_labeled_routes(&tx).await.is_empty(),
        "a route still stale at the next restart must be deleted, not re-marked"
    );

    drop(tx);
    handle.await.unwrap();
}

// --- LLGR (RFC 9494) ---

/// GR-timer expiry with LLGR negotiated promotes GR-stale labeled routes to
/// LLGR-stale: flag flip, locally-injected `LLGR_STALE` community, and a
/// DEEPER tiebreak demotion — an LLGR-stale candidate loses to a GR-stale
/// one regardless of `LOCAL_PREF` (RFC 9494 §4.3).
#[tokio::test]
async fn labeled_llgr_gr_timer_promotes_to_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    // Same key from both peers; A wins the LOCAL_PREF tiebreak.
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: peer_a,
        announced: vec![make_labeled_rib_route(
            Ipv4Addr::new(10, 0, 0, 1),
            31,
            100,
            200,
        )],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: peer_b,
        announced: vec![make_labeled_rib_route(
            Ipv4Addr::new(10, 0, 0, 3),
            31,
            100,
            100,
        )],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::Ipv4, Safi::LabeledUnicast)];
    tx.send(gr_with_llgr(
        peer_a,
        2,
        family.clone(),
        family.clone(),
        3600,
    ))
    .await
    .unwrap();
    tx.send(gr_with_llgr(peer_b, 10, family.clone(), family, 3600))
        .await
        .unwrap();

    let best = query_labeled_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_a, "both GR-stale: LOCAL_PREF tiebreak");
    assert!(best[0].is_stale);
    assert!(!best[0].is_llgr_stale);

    // Past A's GR timer only: A is promoted to LLGR-stale and now ranks
    // BELOW B's GR-stale route despite the higher LOCAL_PREF.
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let best = query_labeled_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_b, "GR-stale must outrank LLGR-stale");
    assert!(best[0].is_stale);

    // Past B's GR timer too: both LLGR-stale, the LOCAL_PREF tiebreak
    // re-applies and the promoted route carries the injected community.
    tokio::time::advance(Duration::from_secs(8)).await;
    tokio::task::yield_now().await;
    let best = query_labeled_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_a);
    assert!(!best[0].is_stale);
    assert!(best[0].is_llgr_stale);
    assert!(
        best[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "promoted labeled route must carry LLGR_STALE community"
    );

    drop(tx);
    handle.await.unwrap();
}

/// LLGR timer expiry sweeps the LLGR-stale labeled routes.
#[tokio::test]
async fn labeled_llgr_timer_sweeps_llgr_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_labeled_rib_route(
            Ipv4Addr::new(10, 0, 0, 1),
            31,
            100,
            100,
        )],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::Ipv4, Safi::LabeledUnicast)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 4))
        .await
        .unwrap();
    assert!(query_labeled_routes(&tx).await[0].is_stale);

    // Past the GR timer: promoted, still present.
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let promoted = query_labeled_routes(&tx).await;
    assert_eq!(promoted.len(), 1);
    assert!(promoted[0].is_llgr_stale);

    // Past the LLGR stale time: swept.
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::task::yield_now().await;
    assert!(
        query_labeled_routes(&tx).await.is_empty(),
        "LLGR timer expiry must sweep LLGR-stale labeled routes"
    );

    drop(tx);
    handle.await.unwrap();
}

/// End-of-RIB during the LLGR phase sweeps what was not re-advertised and
/// clears the LLGR flag on the survivor (RFC 9494 §4.2 via RFC 4724 §4.1).
#[tokio::test]
async fn labeled_llgr_eor_clears_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 60, 100, 100);
    let dropped = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 61, 100, 100);
    let kept_key = kept.key();
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept.clone(), dropped],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::Ipv4, Safi::LabeledUnicast)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    let _ = query_labeled_routes(&tx).await;
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(
        query_labeled_routes(&tx)
            .await
            .iter()
            .all(|r| r.is_llgr_stale)
    );

    // Peer re-establishes during LLGR: re-advertises only `kept`, then EoR.
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::LabeledUnicast,
    })
    .await
    .unwrap();

    let after_eor = query_labeled_routes(&tx).await;
    assert_eq!(
        after_eor.len(),
        1,
        "the non-readvertised LLGR-stale labeled route must be swept at EoR"
    );
    assert_eq!(after_eor[0].key(), kept_key);
    assert!(!after_eor[0].is_llgr_stale, "EoR must clear the LLGR flag");
    assert!(
        !after_eor[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "the locally-injected LLGR_STALE community must be cleared with the flag"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A labeled route carrying `NO_LLGR` is removed at promotion instead of
/// entering the LLGR stale phase (RFC 9494 §4.3).
#[tokio::test]
async fn labeled_llgr_no_llgr_community_drops_route_on_promotion() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let mut route = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100);
    route.attributes = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::Communities(vec![rustbgpd_wire::COMMUNITY_NO_LLGR]),
    ]);
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::Ipv4, Safi::LabeledUnicast)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    assert_eq!(query_labeled_routes(&tx).await.len(), 1);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(
        query_labeled_routes(&tx).await.is_empty(),
        "a NO_LLGR labeled route must be removed at promotion, not retained"
    );

    drop(tx);
    handle.await.unwrap();
}

// --- RFC 9494 §4.4 export gate ---

/// An LLGR-stale labeled route is withdrawn from a non-LLGR eBGP peer at
/// promotion.
#[tokio::test]
async fn labeled_llgr_stale_suppressed_toward_ebgp_peer_without_llgr() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = llgr_gate_peer_up(&tx, target, labeled_sendable(), true, vec![], None).await;
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100);
    let key = route.key();
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.labeled_announce.len(), 1);

    let family = vec![(Afi::Ipv4, Safi::LabeledUnicast)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    assert!(query_labeled_routes(&tx).await[0].is_stale);
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(query_labeled_routes(&tx).await[0].is_llgr_stale);

    let mut withdrawn = false;
    while let Ok(update) = out_rx.try_recv() {
        assert!(
            !update.labeled_announce.iter().any(|route| route
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)),
            "LLGR-stale labeled route must not be announced to a non-LLGR eBGP peer"
        );
        if update.labeled_withdraw.contains(&key) {
            withdrawn = true;
        }
    }
    assert!(
        withdrawn,
        "previously advertised labeled route must be withdrawn from the non-LLGR eBGP peer"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Toward an LLGR-capable eBGP peer: unchanged — the promoted route
/// re-announces with the community riding (RFC 9494 §4.6 form is applied by
/// transport at encode time; the manager keeps announcing).
#[tokio::test]
async fn labeled_llgr_stale_unchanged_toward_llgr_capable_ebgp_peer() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = llgr_gate_peer_up(
        &tx,
        target,
        labeled_sendable(),
        true,
        vec![(Afi::Ipv4, Safi::LabeledUnicast)],
        None,
    )
    .await;
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100);
    let key = route.key();
    tx.send(RibUpdate::LabeledRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    assert_eq!(out_rx.recv().await.unwrap().labeled_announce.len(), 1);

    let family = vec![(Afi::Ipv4, Safi::LabeledUnicast)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    assert!(query_labeled_routes(&tx).await[0].is_stale);
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(query_labeled_routes(&tx).await[0].is_llgr_stale);

    let mut reannounced = false;
    while let Ok(update) = out_rx.try_recv() {
        assert!(
            !update.labeled_withdraw.contains(&key),
            "LLGR-stale labeled route must not be withdrawn from an LLGR-capable peer"
        );
        if update.labeled_announce.iter().any(|route| {
            route.key().prefix == key.prefix
                && route
                    .communities()
                    .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
        }) {
            reannounced = true;
        }
    }
    assert!(reannounced, "community must ride to the LLGR-capable peer");

    drop(tx);
    handle.await.unwrap();
}

/// RFC 9494 §4.4 in the labeled Add-Path branch: each staged candidate is
/// gated individually — the LLGR-stale path loses its Add-Path rank toward
/// a non-LLGR eBGP peer while the fresh path keeps flowing.
#[tokio::test]
async fn labeled_addpath_llgr_stale_candidates_gated_individually() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = llgr_gate_peer_up(
        &tx,
        target,
        labeled_sendable(),
        true,
        vec![],
        Some(((Afi::Ipv4, Safi::LabeledUnicast), 4)),
    )
    .await;
    drain_eor(&mut out_rx).await;

    // Same prefix identity from two sources; A wins on LOCAL_PREF.
    let source_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let source_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let route_a = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 200);
    let route_b = make_labeled_rib_route(Ipv4Addr::new(10, 0, 0, 3), 31, 100, 100);
    let prefix = route_a.nlri.key();
    for (peer, route) in [(source_a, route_a), (source_b, route_b)] {
        tx.send(RibUpdate::LabeledRoutesReceived {
            session_id: 0,
            peer,
            announced: vec![route],
            withdrawn: vec![],
        })
        .await
        .unwrap();
    }
    // Both paths staged with Add-Path ranks 1..=2 before the LLGR phase.
    assert_eq!(query_labeled_routes(&tx).await.len(), 1);
    let mut ranks_seen: HashSet<u32> = HashSet::new();
    while let Ok(update) = out_rx.try_recv() {
        for route in &update.labeled_announce {
            ranks_seen.insert(route.path_id);
        }
    }
    assert!(
        ranks_seen.contains(&1) && ranks_seen.contains(&2),
        "both candidates staged pre-LLGR, got ranks {ranks_seen:?}"
    );

    // B restarts and its path is promoted to LLGR-stale.
    let family = vec![(Afi::Ipv4, Safi::LabeledUnicast)];
    tx.send(gr_with_llgr(source_b, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    let _ = query_labeled_routes(&tx).await;
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let _ = query_labeled_routes(&tx).await;

    let mut rank2_withdrawn = false;
    while let Ok(update) = out_rx.try_recv() {
        assert!(
            !update.labeled_announce.iter().any(|route| route
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)),
            "the LLGR-stale candidate must not occupy an Add-Path rank"
        );
        if update
            .labeled_withdraw
            .contains(&crate::route::LabeledRibRouteKey { prefix, path_id: 2 })
        {
            rank2_withdrawn = true;
        }
    }
    assert!(
        rank2_withdrawn,
        "the LLGR-stale candidate's former rank must be withdrawn"
    );

    drop(tx);
    handle.await.unwrap();
}

// --- Max-prefix accounting parity is covered at the transport layer
// (`known_labeled` joins `known_prefix_count`); the manager-side ingest
// counters are family-generic and exercised by the tests above. ---
