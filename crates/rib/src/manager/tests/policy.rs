use super::*;

#[tokio::test]
async fn export_policy_counter_records_single_best_permit() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);

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

    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
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
    assert_eq!(update.announce.len(), 1);

    assert!(
        (policy_metric_value(&metrics, "10.0.0.2", "inline", "export", "permit") - 1.0).abs()
            < f64::EPSILON
    );
    let stats = query_neighbor_policy_stats(&tx, target).await;
    assert_eq!(stats.export_policy_routes_permitted, 1);
    assert_eq!(stats.export_policy_routes_denied, 0);

    // Peer-down clears per-peer state including the export policy
    // counters. Without this cleanup the HashMap grows unbounded across
    // peer add/delete churn — see handle_peer_down in peer_lifecycle.rs.
    // The counter resets here matches the import-side per-session
    // contract: both directions zero on the next session.
    tx.send(RibUpdate::PeerDown {
        peer: target,
        session_id: 0,
    })
    .await
    .unwrap();
    let stats_after = query_neighbor_policy_stats(&tx, target).await;
    assert_eq!(
        stats_after.export_policy_routes_permitted, 0,
        "PeerDown must clear export_policy_stats; saw {stats_after:?}"
    );
    assert_eq!(stats_after.export_policy_routes_denied, 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn graceful_restart_clears_export_policy_stats() {
    // Mirror of the PeerDown cleanup assertion. A GR-driven session
    // teardown reuses the outbound peer state slot on reconnect, so the
    // export policy aggregates must reset alongside the rest of the
    // per-peer state cleared in handle_peer_graceful_restart. Without
    // this, `rbgp neighbor show` shows import counters at 0
    // (reset on SessionDown in transport/session/fsm.rs) but export
    // counters carrying forward — a directional asymmetry that
    // confuses operators.
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);

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

    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
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
    let _ = out_rx.recv().await.unwrap();

    let stats = query_neighbor_policy_stats(&tx, target).await;
    assert_eq!(stats.export_policy_routes_permitted, 1);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: target,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let stats_after = query_neighbor_policy_stats(&tx, target).await;
    assert_eq!(
        stats_after.export_policy_routes_permitted, 0,
        "PeerGracefulRestart must clear export_policy_stats; saw {stats_after:?}"
    );
    assert_eq!(stats_after.export_policy_routes_denied, 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn explain_advertised_route_does_not_increment_export_policy_counter() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);

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

    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
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
    let _ = out_rx.recv().await.unwrap();

    let before = policy_metric_value(&metrics, "10.0.0.2", "inline", "export", "permit");
    let explain = query_explain_advertised_route(&tx, target, Prefix::V4(prefix)).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Advertise);
    let after = policy_metric_value(&metrics, "10.0.0.2", "inline", "export", "permit");
    assert!((after - before).abs() < f64::EPSILON);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn export_policy_blocks_denied() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
    let export_policy = PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: Some(Prefix::V4(denied_prefix)),
            ge: None,
            le: None,
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

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
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
    // This route matches the deny entry
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(denied_prefix, Ipv4Addr::new(10, 0, 0, 1))],
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

    // Should NOT have received the denied route
    assert!(out_rx.try_recv().is_err());
    assert!(
        (policy_metric_value(&metrics, "10.0.0.2", "inline", "export", "deny") - 1.0).abs()
            < f64::EPSILON
    );
    let stats = query_neighbor_policy_stats(&tx, target).await;
    assert_eq!(stats.export_policy_routes_permitted, 0);
    assert_eq!(stats.export_policy_routes_denied, 1);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn query_advertised_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
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

    // Wait for distribution
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
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
async fn per_peer_export_policy() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
    let allowed_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Peer1 gets a deny policy on 10.0.0.0/8, peer2 has no per-peer policy
    let peer1_export = Some(PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: Some(Prefix::V4(denied_prefix)),
            ge: None,
            le: None,
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
    }]));

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

    let (send_filtered, mut recv_filtered) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: peer1,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: send_filtered,
        export_policy: peer1_export,
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
    drain_eor(&mut recv_filtered).await;

    let (send_unfiltered, mut recv_unfiltered) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: peer2,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: send_unfiltered,
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
    drain_eor(&mut recv_unfiltered).await;

    // Source peer sends both prefixes
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![
            make_route(denied_prefix, Ipv4Addr::new(10, 0, 0, 1)),
            make_route(allowed_prefix, Ipv4Addr::new(10, 0, 0, 1)),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Peer1: should get only the allowed prefix (denied_prefix blocked)
    let filtered = recv_filtered.recv().await.unwrap();
    assert_eq!(filtered.announce.len(), 1);
    assert_eq!(filtered.announce[0].prefix, Prefix::V4(allowed_prefix));

    // Peer2: should get both (no per-peer policy, no global policy)
    let unfiltered = recv_unfiltered.recv().await.unwrap();
    assert_eq!(unfiltered.announce.len(), 2);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "scenario test keeps policy setup, stimulus, and assertions together"
)]
async fn replace_peer_export_policy_resyncs_outbound_state_and_emits_policy_filtered_event() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
    let deny_chain = Some(PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: Some(Prefix::V4(denied_prefix)),
            ge: None,
            le: None,
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
    }]));

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
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(denied_prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let initial = out_rx.recv().await.unwrap();
    assert_eq!(initial.announce.len(), 1);
    assert!(initial.withdraw.is_empty());

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: target,
        export_policy: deny_chain.clone(),
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert_eq!(reply_rx.await.unwrap(), Ok(()));

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert_eq!(update.withdraw, vec![(Prefix::V4(denied_prefix), 0)]);

    let history = query_route_event_history(
        &tx,
        Some(target),
        Some(Afi::Ipv4),
        Some(Prefix::V4(denied_prefix)),
        10,
    )
    .await;
    let policy_filtered = history
        .iter()
        .filter(|event| event.event_type == RouteEventType::PolicyFiltered)
        .collect::<Vec<_>>();
    assert_eq!(policy_filtered.len(), 1);
    assert_eq!(policy_filtered[0].peer, Some(source));
    assert_eq!(policy_filtered[0].target_peer, Some(target));
    assert_eq!(policy_filtered[0].reason, "policy_denied");

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: target,
        export_policy: deny_chain,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert_eq!(reply_rx.await.unwrap(), Ok(()));
    let history = query_route_event_history(
        &tx,
        Some(target),
        Some(Afi::Ipv4),
        Some(Prefix::V4(denied_prefix)),
        10,
    )
    .await;
    assert_eq!(
        history
            .iter()
            .filter(|event| event.event_type == RouteEventType::PolicyFiltered)
            .count(),
        1,
        "unchanged policy denial should not emit duplicate route events"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn export_policy_match_next_hop_filters_route() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

    let export_policy = Some(PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
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
            match_next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }]));

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
        export_policy,
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

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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

    assert!(
        out_rx.try_recv().is_err(),
        "export policy should filter the route by next-hop"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn explain_advertised_route_reports_no_best_route() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(8);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65002,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
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

    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    let explain = query_explain_advertised_route(&tx, target, prefix).await;
    assert_eq!(
        explain.decision,
        crate::update::ExplainDecision::NoBestRoute
    );
    assert_eq!(explain.reasons[0].code, "no_best_route");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn explain_advertised_route_reports_policy_deny_without_mutation() {
    let (tx, rx) = mpsc::channel(64);
    let deny_policy = rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
        default_action: rustbgpd_policy::PolicyAction::Deny,
        entries: vec![],
    }]);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(8);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65002,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: Some(deny_policy),
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

    let route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
        Ipv4Addr::new(10, 0, 0, 1),
    );
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    let explain = query_explain_advertised_route(&tx, target, prefix).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Deny);
    assert_eq!(explain.reasons[0].code, "policy_denied");

    let advertised = {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        reply_rx.await.unwrap()
    };
    assert!(advertised.is_empty());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn export_as_path_regex_still_filters_through_distribution() {
    // Pins the lazy-AS_PATH-string gate on the RIB distribution path: an export
    // policy that denies on a `match_as_path` regex must still filter a matching
    // route (the gate has to render the string and run the regex) while permitting
    // a non-matching one. A broken gate that skipped the string when needed would
    // run the regex against "" and wrongly permit the matching route.
    use rustbgpd_policy::{
        AsPathRegex, Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications,
    };
    use rustbgpd_wire::{AsPath, AsPathSegment, PathAttribute};

    let deny_65200 = PolicyStatement {
        prefix: None,
        ge: None,
        le: None,
        action: PolicyAction::Deny,
        match_community: vec![],
        match_as_path: Some(AsPathRegex::new("_65200_").unwrap()),
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
    };
    let export_policy = PolicyChain::new(vec![Policy {
        entries: vec![deny_65200],
        default_action: PolicyAction::Permit,
    }]);

    let with_as_path = |prefix: Ipv4Prefix, asns: Vec<u32>| Route {
        attributes: Arc::new(vec![PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(asns)],
        })]),
        ..make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))
    };
    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let permitted_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let denied = with_as_path(denied_prefix, vec![65100, 65200]);
    let permitted = with_as_path(permitted_prefix, vec![65100, 65300]);

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(8);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65002,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: Some(export_policy),
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

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![denied, permitted],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let advertised = {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        reply_rx.await.unwrap()
    };
    let prefixes: Vec<_> = advertised.iter().map(|r| r.prefix).collect();

    assert!(
        prefixes.contains(&Prefix::V4(permitted_prefix)),
        "AS_PATH not matching the deny regex must be advertised; saw {prefixes:?}"
    );
    assert!(
        !prefixes.contains(&Prefix::V4(denied_prefix)),
        "AS_PATH matching the deny regex must be filtered (string rendered + regex \
         applied through the gated export path); saw {prefixes:?}"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn explain_advertised_route_reports_modifications() {
    let (tx, rx) = mpsc::channel(64);
    let export_policy = rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
        default_action: rustbgpd_policy::PolicyAction::Permit,
        entries: vec![rustbgpd_policy::PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: rustbgpd_policy::RouteModifications {
                set_local_pref: Some(200),
                ..rustbgpd_policy::RouteModifications::default()
            },
            action: rustbgpd_policy::PolicyAction::Permit,
        }],
    }]);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(8);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65002,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: Some(export_policy),
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

    let route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
        Ipv4Addr::new(10, 0, 0, 1),
    );
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    let explain = query_explain_advertised_route(&tx, target, prefix).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Advertise);
    assert_eq!(explain.route_peer, Some(source));
    assert_eq!(
        explain.route_type,
        Some(rustbgpd_policy::RouteType::External)
    );
    assert_eq!(explain.modifications.set_local_pref, Some(200));
    assert_eq!(explain.reasons[0].code, "ebgp_route");
    assert_eq!(explain.reasons[1].code, "policy_permitted");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn explain_advertised_route_reports_ipv6_next_hop_override() {
    let (tx, rx) = mpsc::channel(64);
    let export_policy = rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
        default_action: rustbgpd_policy::PolicyAction::Permit,
        entries: vec![rustbgpd_policy::PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: rustbgpd_policy::RouteModifications {
                set_next_hop: Some(rustbgpd_policy::NextHopAction::Specific(IpAddr::V6(
                    "2001:db8::42".parse().unwrap(),
                ))),
                ..rustbgpd_policy::RouteModifications::default()
            },
            action: rustbgpd_policy::PolicyAction::Permit,
        }],
    }]);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(8);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65002,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: Some(export_policy),
        sendable_families: vec![(Afi::Ipv6, Safi::Unicast)],
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

    let prefix = Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 64);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_v6_route(prefix, "2001:db8::1".parse().unwrap())],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let explain = query_explain_advertised_route(&tx, target, Prefix::V6(prefix)).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Advertise);
    assert_eq!(
        explain.next_hop,
        Some(IpAddr::V6("2001:db8::42".parse().unwrap()))
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn peer_down_cleans_up_export_policy() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (out_tx, _out_rx) = mpsc::channel(64);
    let policy = Some(PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))),
            ge: None,
            le: None,
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
    }]));

    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: policy,
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

    // Query to confirm loop processed PeerDown
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
