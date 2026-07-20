use super::*;

#[tokio::test]
async fn send_initial_table_includes_flowspec_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let fs_route = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
    let fs_rule = fs_route.rule.clone();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![fs_route],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        sendable_families: ipv4_flowspec_sendable(),
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
    assert!(update.withdraw.is_empty());
    assert_eq!(update.flowspec_announce.len(), 1);
    assert_eq!(update.flowspec_announce[0].rule, fs_rule);
    assert!(update.flowspec_withdraw.is_empty());

    let eor = out_rx.recv().await.unwrap();
    assert_eq!(eor.end_of_rib, ipv4_flowspec_sendable());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_refresh_flowspec_re_advertises_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let fs_route = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
    let fs_rule = fs_route.rule.clone();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![fs_route],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        sendable_families: ipv4_flowspec_sendable(),
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

    // Drain the initial dump and its EoR before triggering route refresh.
    let _ = out_rx.recv().await.unwrap();
    let _ = out_rx.recv().await.unwrap();

    tx.send(RibUpdate::RouteRefreshRequest {
        session_id: 0,
        peer: target,
        afi: Afi::Ipv4,
        safi: Safi::FlowSpec,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert!(update.withdraw.is_empty());
    assert_eq!(update.flowspec_announce.len(), 1);
    assert_eq!(update.flowspec_announce[0].rule, fs_rule);
    assert!(update.flowspec_withdraw.is_empty());
    assert_eq!(update.end_of_rib, vec![(Afi::Ipv4, Safi::FlowSpec)]);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn dirty_resync_retries_flowspec_updates() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

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
        sendable_families: ipv4_flowspec_sendable(),
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

    // The initial EoR occupies the single slot, so the next FlowSpec
    // update will fail to enqueue and mark the peer dirty.
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let fs_route = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
    let fs_rule = fs_route.rule.clone();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![fs_route],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Drain the initial EoR to make room for the timer-driven resync.
    let initial = out_rx.recv().await.unwrap();
    assert_eq!(initial.end_of_rib, ipv4_flowspec_sendable());

    tokio::time::advance(Duration::from_secs(2)).await;

    let resync = out_rx.recv().await.unwrap();
    assert!(resync.announce.is_empty());
    assert!(resync.withdraw.is_empty());
    assert_eq!(resync.flowspec_announce.len(), 1);
    assert_eq!(resync.flowspec_announce[0].rule, fs_rule);
    assert!(resync.flowspec_withdraw.is_empty());

    drop(tx);
    handle.await.unwrap();
}

// --- Graceful Restart tests ---

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "covers the stale demotion, RFC 4724 §4.1 re-advertise-before-EoR, and best-path flip-back in one scenario"
)]
async fn gr_flowspec_eor_recomputes_and_redistributes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100));
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
        sendable_families: ipv4_flowspec_sendable(),
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

    let source_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let source_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let mut route_a = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
    route_a.attributes.push(PathAttribute::LocalPref(200));
    let mut route_b = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 2));
    route_b.attributes.push(PathAttribute::LocalPref(100));
    let rule = route_a.rule.clone();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source_a,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![route_a.clone()],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let initial = out_rx.recv().await.unwrap();
    assert_eq!(initial.flowspec_announce.len(), 1);
    assert_eq!(initial.flowspec_announce[0].peer, source_a);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source_b,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![route_b],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let best_before = query_flowspec_routes(&tx).await;
    assert_eq!(best_before.len(), 1);
    assert_eq!(best_before[0].peer, source_a);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source_a,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::FlowSpec)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let stale_switch = out_rx.recv().await.unwrap();
    assert_eq!(stale_switch.flowspec_announce.len(), 1);
    assert_eq!(stale_switch.flowspec_announce[0].peer, source_b);

    let best_during_gr = query_flowspec_routes(&tx).await;
    assert_eq!(best_during_gr.len(), 1);
    assert_eq!(best_during_gr[0].peer, source_b);

    // RFC 4724 §4.1: a route still marked stale at End-of-RIB is removed,
    // so source_a must re-advertise its rule for it to survive (and win
    // the best-path back from source_b).
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source_a,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![route_a],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source_a,
        afi: Afi::Ipv4,
        safi: Safi::FlowSpec,
    })
    .await
    .unwrap();

    let eor_switch = out_rx.recv().await.unwrap();
    assert_eq!(eor_switch.flowspec_announce.len(), 1);
    assert_eq!(eor_switch.flowspec_announce[0].peer, source_a);
    assert_eq!(eor_switch.flowspec_announce[0].rule, rule);

    let best_after_eor = query_flowspec_routes(&tx).await;
    assert_eq!(best_after_eor.len(), 1);
    assert_eq!(best_after_eor[0].peer, source_a);

    drop(tx);
    handle.await.unwrap();
}

/// A legal `FlowSpec` route with no destination-prefix component
/// (IP-protocol match only), for the given address family.
fn make_destless_flowspec_route(afi: Afi, peer: Ipv4Addr, protocol: u8) -> FlowSpecRoute {
    let mut route = make_flowspec_route(peer);
    route.afi = afi;
    route.rule.components = vec![rustbgpd_wire::FlowSpecComponent::IpProtocol(vec![
        rustbgpd_wire::NumericMatch {
            end_of_list: true,
            and_bit: false,
            lt: false,
            gt: false,
            eq: true,
            value: u64::from(protocol),
        },
    ])];
    route
}

#[tokio::test]
async fn destinationless_v4_v6_rules_coexist_and_withdraw_independently() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let target: IpAddr = "192.0.2.2".parse().unwrap();
    let (out_tx, mut out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv4, Safi::FlowSpec), (Afi::Ipv6, Safi::FlowSpec)],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let source: IpAddr = "198.51.100.1".parse().unwrap();
    let v4 = make_destless_flowspec_route(Afi::Ipv4, "198.51.100.1".parse().unwrap(), 6);
    let v6 = make_destless_flowspec_route(Afi::Ipv6, "198.51.100.1".parse().unwrap(), 6);
    assert_eq!(v4.rule, v6.rule, "fixture must differ only by AFI");
    let v4_key = v4.selection_key();
    let v6_key = v6.selection_key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![v4, v6],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(
        announced
            .flowspec_announce
            .iter()
            .map(FlowSpecRoute::selection_key)
            .collect::<HashSet<_>>(),
        HashSet::from([v4_key.clone(), v6_key.clone()])
    );
    assert_eq!(query_flowspec_routes(&tx).await.len(), 2);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![v6_key.clone()],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let withdrawn = out_rx.recv().await.unwrap();
    assert_eq!(withdrawn.flowspec_withdraw, vec![v6_key]);
    let remaining = query_flowspec_routes(&tx).await;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].selection_key(), v4_key);

    drop(tx);
    handle.await.unwrap();
}

/// LAN-291: a destination-less `FlowSpec` rule must be `prefix = None` in
/// the export policy context — a fabricated `0.0.0.0/0` would spuriously
/// match prefix-based deny terms and suppress the rule.
#[tokio::test]
async fn flowspec_export_prefix_term_does_not_match_destination_less_rules() {
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
        export_policy: Some(deny_prefixes_chain(&[
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0)),
            Prefix::V6(Ipv6Prefix::new(Ipv6Addr::UNSPECIFIED, 0)),
        ])),
        sendable_families: vec![(Afi::Ipv4, Safi::FlowSpec), (Afi::Ipv6, Safi::FlowSpec)],
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
    let v4_route = make_destless_flowspec_route(Afi::Ipv4, Ipv4Addr::new(10, 0, 0, 1), 6);
    let v6_route = make_destless_flowspec_route(Afi::Ipv6, Ipv4Addr::new(10, 0, 0, 1), 17);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![v4_route.clone(), v6_route.clone()],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    let announced: BTreeSet<_> = update
        .flowspec_announce
        .iter()
        .map(|r| r.rule.clone())
        .collect();
    assert_eq!(
        announced,
        BTreeSet::from([v4_route.rule, v6_route.rule]),
        "destination-less FlowSpec rules are prefixless and must not match \
         default-prefix deny terms"
    );
    assert!(update.flowspec_withdraw.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// LAN-291 companion: a `FlowSpec` rule that DOES carry a destination
/// prefix still evaluates it against prefix-based export terms.
#[tokio::test]
async fn flowspec_export_prefix_term_still_matches_real_destination_prefix() {
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
        // Denies the fixture rule's real destination prefix.
        export_policy: Some(deny_prefixes_chain(&[Prefix::V4(Ipv4Prefix::new(
            Ipv4Addr::new(192, 0, 2, 0),
            24,
        ))])),
        sendable_families: ipv4_flowspec_sendable(),
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
    // Destination 192.0.2.0/24 — must be denied by the export term.
    let denied = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
    // Destination-less — must pass through to the default Permit.
    let permitted = make_destless_flowspec_route(Afi::Ipv4, Ipv4Addr::new(10, 0, 0, 1), 6);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![denied, permitted.clone()],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert_eq!(
        update.flowspec_announce.len(),
        1,
        "the rule whose real destination prefix matches the deny term must \
         be suppressed"
    );
    assert_eq!(update.flowspec_announce[0].rule, permitted.rule);
    assert!(update.flowspec_withdraw.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// A `FlowSpec` rule distinct from the shared `make_flowspec_route` fixture
/// rule, so one source peer can hold two Adj-RIB-In entries.
fn make_flowspec_route_alt(peer: Ipv4Addr) -> FlowSpecRoute {
    let mut route = make_flowspec_route(peer);
    route.rule.components = vec![rustbgpd_wire::FlowSpecComponent::DestinationPrefix(
        rustbgpd_wire::FlowSpecPrefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24)),
    )];
    route
}

/// A second GR entry while `FlowSpec` routes are still stale deletes them
/// (RFC 4724 §4.1: no retention across consecutive restarts).
#[tokio::test]
async fn flowspec_gr_consecutive_restart_deletes_stale_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1))],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let gr_entry = || RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::FlowSpec)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    };
    tx.send(gr_entry()).await.unwrap();
    let stale = query_flowspec_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    tx.send(gr_entry()).await.unwrap();
    assert!(
        query_flowspec_routes(&tx).await.is_empty(),
        "a rule still stale at the next restart must be deleted, not re-marked"
    );

    drop(tx);
    handle.await.unwrap();
}

/// RFC 4724 §4.1: a `FlowSpec` rule still marked stale at End-of-RIB was
/// not re-advertised during the restart window and must be removed; the
/// re-advertised rule survives with its stale flag cleared.
#[tokio::test]
async fn flowspec_gr_eor_sweeps_non_readvertised() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
    let dropped = make_flowspec_route_alt(Ipv4Addr::new(10, 0, 0, 1));
    let kept_rule = kept.rule.clone();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![kept.clone(), dropped],
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
        gr_families: vec![(Afi::Ipv4, Safi::FlowSpec)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();
    let stale = query_flowspec_routes(&tx).await;
    assert_eq!(stale.len(), 2);
    assert!(stale.iter().all(|r| r.is_stale));

    // Only `kept` is re-advertised before End-of-RIB.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![kept],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::FlowSpec,
    })
    .await
    .unwrap();

    let after_eor = query_flowspec_routes(&tx).await;
    assert_eq!(
        after_eor.len(),
        1,
        "the non-readvertised stale FlowSpec rule must be removed at End-of-RIB"
    );
    assert_eq!(after_eor[0].rule, kept_rule);
    assert!(!after_eor[0].is_stale, "EoR must clear the stale flag");

    drop(tx);
    handle.await.unwrap();
}

/// RFC 4724 §4.1 via RFC 9494 §4.2: a `FlowSpec` rule still LLGR-stale at
/// End-of-RIB was not re-advertised during the LLGR window and must be
/// removed; the re-advertised rule survives with flags cleared.
#[tokio::test]
async fn flowspec_llgr_eor_sweeps_non_readvertised() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
    let dropped = make_flowspec_route_alt(Ipv4Addr::new(10, 0, 0, 1));
    let kept_rule = kept.rule.clone();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![kept.clone(), dropped],
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
        stale_routes_time: 5,
        gr_families: vec![(Afi::Ipv4, Safi::FlowSpec)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::FlowSpec,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 3600,
    })
    .await
    .unwrap();
    let stale = query_flowspec_routes(&tx).await;
    assert!(stale.iter().all(|r| r.is_stale));

    // Advance past GR timer → LLGR phase
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let promoted = query_flowspec_routes(&tx).await;
    assert!(promoted.iter().all(|r| r.is_llgr_stale));

    // Only `kept` is re-advertised before End-of-RIB.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![kept],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::FlowSpec,
    })
    .await
    .unwrap();

    let after_eor = query_flowspec_routes(&tx).await;
    assert_eq!(
        after_eor.len(),
        1,
        "the non-readvertised LLGR-stale FlowSpec rule must be removed at End-of-RIB"
    );
    assert_eq!(after_eor[0].rule, kept_rule);
    assert!(!after_eor[0].is_llgr_stale, "EoR must clear the LLGR flag");
    assert!(!after_eor[0].is_stale);

    drop(tx);
    handle.await.unwrap();
}

fn with_flowspec_communities(mut route: FlowSpecRoute, communities: Vec<u32>) -> FlowSpecRoute {
    route
        .attributes
        .retain(|attr| !matches!(attr, PathAttribute::Communities(_)));
    route
        .attributes
        .push(PathAttribute::Communities(communities));
    route
}

fn flowspec_policy_statement(
    marker: u32,
    modifications: rustbgpd_policy::RouteModifications,
) -> rustbgpd_policy::PolicyStatement {
    rustbgpd_policy::PolicyStatement {
        prefix: None,
        ge: None,
        le: None,
        action: rustbgpd_policy::PolicyAction::Permit,
        match_community: vec![rustbgpd_policy::CommunityMatch::Standard { value: marker }],
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
        modifications,
    }
}

async fn replace_flowspec_routes(
    tx: &mpsc::Sender<RibUpdate>,
    source: IpAddr,
    routes: Vec<FlowSpecRoute>,
) {
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: routes,
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_flowspec_routes(tx).await;
}

/// Source `NO_ADVERTISE` outranks a policy that removes it. Suppression stays
/// silent until an exact prior `(AFI, rule)` advertisement must be withdrawn.
///
/// Break-to-red: deleting the source guard announces the first route; removing
/// the Adj-RIB-Out membership check emits a first-seen withdrawal; using only
/// rule identity withdraws the same-looking IPv6 route; wrong-rule or broadened
/// withdrawal churns the sibling; sticky suppression blocks recovery.
#[tokio::test]
async fn flowspec_source_no_advertise_precedes_removal_policy() {
    let mut removal = rustbgpd_policy::RouteModifications::default();
    removal
        .communities_remove
        .push(rustbgpd_wire::COMMUNITY_NO_ADVERTISE);
    let policy = rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
        entries: vec![flowspec_policy_statement(
            rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
            removal,
        )],
        default_action: rustbgpd_policy::PolicyAction::Permit,
    }]);
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let source_addr = Ipv4Addr::new(198, 51, 100, 41);
    let source = IpAddr::V4(source_addr);
    let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 41));
    let (out_tx, mut out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: target,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: Some(policy),
        sendable_families: vec![(Afi::Ipv4, Safi::FlowSpec), (Afi::Ipv6, Safi::FlowSpec)],
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

    let victim = make_destless_flowspec_route(Afi::Ipv4, source_addr, 6);
    let victim_key = victim.selection_key();
    let first_scoped =
        with_flowspec_communities(victim.clone(), vec![rustbgpd_wire::COMMUNITY_NO_ADVERTISE]);
    replace_flowspec_routes(&tx, source, vec![first_scoped.clone()]).await;
    assert!(
        out_rx.try_recv().is_err(),
        "first-seen scoped rule is silent"
    );

    let mut changed_scoped = first_scoped;
    changed_scoped.attributes.push(PathAttribute::Med(41));
    replace_flowspec_routes(&tx, source, vec![changed_scoped]).await;
    assert!(
        out_rx.try_recv().is_err(),
        "changed-attribute scoped rule remains silent"
    );

    let sibling = make_destless_flowspec_route(Afi::Ipv4, source_addr, 17);
    let sibling_key = sibling.selection_key();
    let mut other_afi = victim.clone();
    other_afi.afi = Afi::Ipv6;
    let other_afi_key = other_afi.selection_key();
    replace_flowspec_routes(&tx, source, vec![victim.clone(), sibling, other_afi]).await;
    let plain = out_rx.try_recv().expect("plain rules advertise");
    assert_eq!(plain.flowspec_announce.len(), 3);
    assert!(plain.flowspec_withdraw.is_empty());
    for key in [&victim_key, &sibling_key, &other_afi_key] {
        assert!(
            plain
                .flowspec_announce
                .iter()
                .any(|route| route.selection_key() == *key)
        );
    }

    let scoped_replacement =
        with_flowspec_communities(victim.clone(), vec![rustbgpd_wire::COMMUNITY_NO_ADVERTISE]);
    replace_flowspec_routes(&tx, source, vec![scoped_replacement]).await;
    let withdrawn = out_rx
        .try_recv()
        .expect("source restriction withdraws exact prior rule");
    assert!(withdrawn.flowspec_announce.is_empty());
    assert_eq!(withdrawn.flowspec_withdraw, vec![victim_key.clone()]);

    let recovered = with_flowspec_communities(victim, vec![(65000u32 << 16) | 0x01BD]);
    replace_flowspec_routes(&tx, source, vec![recovered]).await;
    let recovery = out_rx.try_recv().expect("plain rule recovers");
    assert_eq!(recovery.flowspec_announce.len(), 1);
    assert_eq!(recovery.flowspec_announce[0].selection_key(), victim_key);
    assert!(recovery.flowspec_withdraw.is_empty());
    assert!(
        out_rx.try_recv().is_err(),
        "sibling and IPv6 rule do not churn"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Export modifications apply to `FlowSpec` except `set_next_hop`, and a
/// policy-added `NO_ADVERTISE` suppresses or withdraws only the exact prior.
///
/// Break-to-red: deleting modification application loses every rewritten
/// attribute; deleting the post-policy guard announces scoped rules; removing
/// the membership check emits a first-seen withdrawal; passing `set_next_hop`
/// to the shared helper inserts legacy `NEXT_HOP`; wrong/broad withdrawal churns
/// the sibling; sticky suppression blocks both recovery announcements.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one actor sequence proves modification, suppression, withdrawal, and recovery semantics"
)]
async fn flowspec_policy_modifications_suppress_and_recover_without_next_hop() {
    let suppress_marker = (65000u32 << 16) | 0x01BD;
    let permit_marker = (65000u32 << 16) | 0x01BE;
    let added_standard = (65000u32 << 16) | 0x01BF;
    let added_large = rustbgpd_wire::LargeCommunity::new(65000, 4, 45);
    let modifications = rustbgpd_policy::RouteModifications {
        set_local_pref: Some(275),
        set_med: Some(44),
        set_next_hop: Some(rustbgpd_policy::NextHopAction::Specific(IpAddr::V4(
            Ipv4Addr::new(203, 0, 113, 44),
        ))),
        communities_add: vec![added_standard],
        large_communities_add: vec![added_large],
        as_path_prepend: Some((64512, 2)),
        ..rustbgpd_policy::RouteModifications::default()
    };
    let mut suppress_modifications = modifications.clone();
    suppress_modifications
        .communities_add
        .push(rustbgpd_wire::COMMUNITY_NO_ADVERTISE);
    let policy = rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
        entries: vec![
            flowspec_policy_statement(suppress_marker, suppress_modifications),
            flowspec_policy_statement(permit_marker, modifications),
        ],
        default_action: rustbgpd_policy::PolicyAction::Permit,
    }]);

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let source_addr = Ipv4Addr::new(198, 51, 100, 42);
    let source = IpAddr::V4(source_addr);
    let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42));
    let (out_tx, mut out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: target,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: Some(policy),
        sendable_families: ipv4_flowspec_sendable(),
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

    let mut victim = make_flowspec_route(source_addr);
    victim.attributes.push(PathAttribute::AsPath(AsPath {
        segments: vec![AsPathSegment::AsSequence(vec![65001])],
    }));
    let victim_key = victim.selection_key();
    let sibling = make_flowspec_route_alt(source_addr);
    let sibling_key = sibling.selection_key();
    let scoped = with_flowspec_communities(victim.clone(), vec![suppress_marker]);
    replace_flowspec_routes(&tx, source, vec![scoped.clone(), sibling]).await;
    let first = out_rx.try_recv().expect("unscoped sibling advertises");
    assert_eq!(first.flowspec_announce.len(), 1);
    assert_eq!(first.flowspec_announce[0].selection_key(), sibling_key);
    assert!(first.flowspec_withdraw.is_empty());

    let mut changed_scoped = scoped;
    changed_scoped
        .attributes
        .push(PathAttribute::LocalPref(999));
    replace_flowspec_routes(&tx, source, vec![changed_scoped]).await;
    assert!(
        out_rx.try_recv().is_err(),
        "changed-attribute policy-scoped rule remains silent"
    );

    let assert_modified = |route: &FlowSpecRoute| {
        assert_eq!(route.local_pref_attr(), Some(275));
        assert_eq!(route.med_attr(), Some(44));
        assert!(route.communities().contains(&added_standard));
        assert!(route.large_communities().contains(&added_large));
        assert_eq!(
            route.as_path().unwrap().segments,
            vec![AsPathSegment::AsSequence(vec![64512, 64512, 65001])]
        );
        assert!(
            route
                .attributes
                .iter()
                .all(|attr| !matches!(attr, PathAttribute::NextHop(_))),
            "FlowSpec must not acquire legacy NEXT_HOP"
        );
    };

    let permitted = with_flowspec_communities(victim.clone(), vec![permit_marker]);
    replace_flowspec_routes(&tx, source, vec![permitted]).await;
    let recovery = out_rx.try_recv().expect("permitted rule recovers");
    assert_eq!(recovery.flowspec_announce.len(), 1);
    assert_eq!(recovery.flowspec_announce[0].selection_key(), victim_key);
    assert_modified(&recovery.flowspec_announce[0]);

    let rescoped = with_flowspec_communities(victim.clone(), vec![suppress_marker]);
    replace_flowspec_routes(&tx, source, vec![rescoped.clone()]).await;
    let withdrawn = out_rx
        .try_recv()
        .expect("post-policy restriction withdraws exact prior rule");
    assert!(withdrawn.flowspec_announce.is_empty());
    assert_eq!(withdrawn.flowspec_withdraw, vec![victim_key.clone()]);

    let mut changed_again = rescoped;
    changed_again.attributes.push(PathAttribute::Med(999));
    replace_flowspec_routes(&tx, source, vec![changed_again]).await;
    assert!(
        out_rx.try_recv().is_err(),
        "repeated suppression stays silent"
    );

    let recovered_again = with_flowspec_communities(victim, vec![permit_marker]);
    replace_flowspec_routes(&tx, source, vec![recovered_again]).await;
    let final_recovery = out_rx.try_recv().expect("rule recovers again");
    assert_eq!(final_recovery.flowspec_announce.len(), 1);
    assert_eq!(
        final_recovery.flowspec_announce[0].selection_key(),
        victim_key
    );
    assert_modified(&final_recovery.flowspec_announce[0]);
    assert!(final_recovery.flowspec_withdraw.is_empty());
    assert!(out_rx.try_recv().is_err(), "sibling rule does not churn");

    drop(tx);
    handle.await.unwrap();
}
