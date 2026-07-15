use super::*;

fn with_vpn_no_advertise(mut route: VpnRibRoute) -> VpnRibRoute {
    Arc::make_mut(&mut route.attributes).push(PathAttribute::Communities(vec![
        rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
    ]));
    route
}

fn make_vpn_v6_rib_route(peer: Ipv4Addr, local_pref: u32) -> VpnRibRoute {
    VpnRibRoute {
        nlri: VpnNlri {
            labels: vec![MplsLabelEntry::try_new(300, 0, true).unwrap()],
            route_distinguisher: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 2]),
            prefix: VpnPrefix::v6("2001:db8:442::".parse().unwrap(), 64).unwrap(),
        },
        next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
        link_local_next_hop: None,
        peer: IpAddr::V4(peer),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::LocalPref(local_pref),
        ]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: peer,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    }
}

fn drain_vpn_delta(
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
) -> (Vec<VpnRibRoute>, Vec<crate::route::VpnRibRouteKey>) {
    let mut announced = Vec::new();
    let mut withdrawn = Vec::new();
    while let Ok(update) = rx.try_recv() {
        announced.extend(update.vpn_announce);
        withdrawn.extend(update.vpn_withdraw);
    }
    (announced, withdrawn)
}

async fn query_vpn_group_label(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr) -> String {
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::QueryPeerUpdateGroup { peer, reply })
        .await
        .unwrap();
    response.await.unwrap()
}

async fn query_vpn_advertised(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr) -> Vec<(String, IpAddr)> {
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::TestQueryVpnAdvertised { peer, reply })
        .await
        .unwrap();
    response.await.unwrap()
}

/// A peer entering GR with (IPv4, `MplsVpn`) in its capability keeps its VPN
/// routes as stale. Staleness demotes the tiebreak rank, so a fresh route
/// from another peer takes over; with every candidate stale the normal
/// tiebreak re-applies and the key stays reflected.
#[tokio::test]
async fn vpn_gr_marks_stale_and_demotes_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let best_advertiser = Ipv4Addr::new(10, 0, 0, 1);
    let alternate_advertiser = Ipv4Addr::new(10, 0, 0, 3);
    let best_peer = IpAddr::V4(best_advertiser);
    let alternate_peer = IpAddr::V4(alternate_advertiser);

    // Same RD + prefix (octet) from both peers ⇒ same RIB key.
    let route_a = make_vpn_rib_route(best_advertiser, 31, 100, 200);
    let route_b = make_vpn_rib_route(alternate_advertiser, 31, 200, 100);
    assert_eq!(route_a.key(), route_b.key());
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: best_peer,
        announced: vec![route_a],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: alternate_peer,
        announced: vec![route_b],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let best_before = query_vpn_routes(&tx).await;
    assert_eq!(best_before.len(), 1);
    assert_eq!(best_before[0].peer, best_peer);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: best_peer,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::MplsVpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let after_winner_gr = query_vpn_routes(&tx).await;
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
        gr_families: vec![(Afi::Ipv4, Safi::MplsVpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let after_last_gr = query_vpn_routes(&tx).await;
    assert_eq!(
        after_last_gr.len(),
        1,
        "GR must retain the stale VPN route instead of dropping the key"
    );
    assert_eq!(
        after_last_gr[0].peer, best_peer,
        "with both candidates stale the normal tiebreak (higher LOCAL_PREF) re-applies"
    );
    assert!(after_last_gr[0].is_stale);

    drop(tx);
    handle.await.unwrap();
}

/// A peer whose GR capability does NOT list (IPv4, `MplsVpn`) must have its
/// VPN routes withdrawn on GR entry and the withdrawal staged downstream.
#[tokio::test]
async fn vpn_gr_family_not_in_capability_is_withdrawn() {
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

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100);
    let key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.vpn_announce.len(), 1);

    // GR capability carries only unicast: VPN is withdrawn, not retained.
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
        withdraw.vpn_withdraw,
        vec![key],
        "GR entry must withdraw VPN routes absent from the capability"
    );
    assert!(
        query_vpn_routes(&tx).await.is_empty(),
        "VPN absent from the GR capability must not be retained stale"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Re-advertisement during the restart window replaces the stale VPN route;
/// End-of-RIB clears the survivor's stale flag and removes (and withdraws
/// downstream) what was not re-advertised (RFC 4724 §4.1).
#[tokio::test]
async fn vpn_gr_eor_clears_stale() {
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

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 60, 100, 100);
    let dropped = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 61, 100, 100);
    let kept_key = kept.key();
    let dropped_key = dropped.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept.clone(), dropped],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.vpn_announce.len(), 2);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::MplsVpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();
    let stale = query_vpn_routes(&tx).await;
    assert_eq!(stale.len(), 2);
    assert!(stale.iter().all(|r| r.is_stale));

    // Only `kept` is re-advertised before End-of-RIB.
    tx.send(RibUpdate::VpnRoutesReceived {
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
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();

    let after_eor = query_vpn_routes(&tx).await;
    assert_eq!(
        after_eor.len(),
        1,
        "the non-readvertised stale VPN route must be removed at End-of-RIB"
    );
    assert_eq!(after_eor[0].key(), kept_key);
    assert!(!after_eor[0].is_stale, "EoR must clear the stale flag");

    // The removal must be withdrawn downstream.
    loop {
        let update = out_rx.recv().await.unwrap();
        if update.vpn_withdraw.is_empty() {
            continue;
        }
        assert_eq!(update.vpn_withdraw, vec![dropped_key.clone()]);
        break;
    }

    drop(tx);
    handle.await.unwrap();
}

/// GR timer expiry without LLGR purges the stale VPN routes.
#[tokio::test]
async fn vpn_gr_timer_sweeps_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::Ipv4, Safi::MplsVpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();
    let stale = query_vpn_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    assert!(
        query_vpn_routes(&tx).await.is_empty(),
        "GR timer expiry must sweep stale VPN routes"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A second GR entry while VPN routes are still stale deletes them
/// (RFC 4724 §4.1: no retention across consecutive restarts).
#[tokio::test]
async fn vpn_gr_consecutive_restart_deletes_stale_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let gr_entry = || RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::MplsVpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    };
    tx.send(gr_entry()).await.unwrap();
    let stale = query_vpn_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    tx.send(gr_entry()).await.unwrap();
    assert!(
        query_vpn_routes(&tx).await.is_empty(),
        "a route still stale at the next restart must be deleted, not re-marked"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Grouped and private VPN targets enforce RFC 1997 before and after export
/// policy for both `VPNv4` and `VPNv6`, withdraw prior state, and recover when the
/// restriction is removed.
///
/// Break-to-red: removing either single-best guard in `stage_vpn_routes`, or
/// retaining the guard while deleting its `withdraw_existing`, makes the
/// corresponding source/policy phase advertise or retain both exact keys.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario pins both VPN families across grouped/private source and policy transitions"
)]
async fn vpn_no_advertise_withdraws_grouped_and_private_single_best() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let grouped_a: IpAddr = "192.0.2.30".parse().unwrap();
    let grouped_b: IpAddr = "192.0.2.31".parse().unwrap();
    let private: IpAddr = "192.0.2.32".parse().unwrap();
    let families = vec![(Afi::Ipv4, Safi::MplsVpn), (Afi::Ipv6, Safi::MplsVpn)];
    let mut receivers = Vec::new();

    for (peer, peer_context) in [(grouped_a, false), (grouped_b, false), (private, true)] {
        let (out_tx, mut out_rx) = mpsc::channel(16);
        tx.send(RibUpdate::PeerUp {
            per_client_best: false,
            session_id: 0,
            peer,
            peer_asn: 65100,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx: out_tx,
            export_policy: Some(super::unicast::no_advertise_removal_chain(peer_context)),
            sendable_families: families.clone(),
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
        receivers.push((peer, out_rx));
    }

    let group = query_vpn_group_label(&tx, grouped_a).await;
    assert!(group.starts_with("group:"));
    assert_eq!(query_vpn_group_label(&tx, grouped_b).await, group);
    assert_eq!(
        query_vpn_group_label(&tx, private).await,
        "policy_peer_context"
    );

    let source = Ipv4Addr::new(198, 51, 100, 10);
    let v4 = make_vpn_rib_route(source, 42, 200, 200);
    let v6 = make_vpn_v6_rib_route(source, 200);
    let expected_keys: HashSet<_> = [v4.key(), v6.key()].into_iter().collect();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![v4.clone(), v6.clone()],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_vpn_routes(&tx).await;
    for (_, out_rx) in &mut receivers {
        let (announced, withdrawn) = drain_vpn_delta(out_rx);
        assert_eq!(announced.len(), 2);
        assert!(withdrawn.is_empty());
    }

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![
            with_vpn_no_advertise(v4.clone()),
            with_vpn_no_advertise(v6.clone()),
        ],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_vpn_routes(&tx).await;
    for (peer, out_rx) in &mut receivers {
        let (announced, withdrawn) = drain_vpn_delta(out_rx);
        assert!(announced.is_empty());
        assert_eq!(withdrawn.len(), 2, "each VPN identity withdraws once");
        assert_eq!(withdrawn.into_iter().collect::<HashSet<_>>(), expected_keys);
        assert!(query_vpn_advertised(&tx, *peer).await.is_empty());
    }
    for route in [&v4, &v6] {
        let grouped_explain = query_explain_advertised_vpn_route(
            &tx,
            grouped_a,
            route.inner_prefix(),
            route.nlri.route_distinguisher,
        )
        .await;
        let private_explain = query_explain_advertised_vpn_route(
            &tx,
            private,
            route.inner_prefix(),
            route.nlri.route_distinguisher,
        )
        .await;
        assert!(grouped_explain.update_group_id.is_some());
        assert!(private_explain.update_group_id.is_none());
        assert_eq!(
            grouped_explain.decision,
            crate::update::ExplainDecision::Deny
        );
        assert_eq!(private_explain.decision, grouped_explain.decision);
        assert_eq!(
            grouped_explain
                .gates
                .last()
                .map(|gate| (gate.gate, gate.code)),
            Some(("no_advertise", "no_advertise_suppressed"))
        );
        assert_eq!(
            private_explain
                .gates
                .last()
                .map(|gate| (gate.gate, gate.code)),
            grouped_explain
                .gates
                .last()
                .map(|gate| (gate.gate, gate.code))
        );
        assert!(grouped_explain.modifications.communities_remove.is_empty());
    }

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![v4.clone(), v6.clone()],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_vpn_routes(&tx).await;
    for (_, out_rx) in &mut receivers {
        let (announced, withdrawn) = drain_vpn_delta(out_rx);
        assert_eq!(announced.len(), 2);
        assert!(withdrawn.is_empty());
    }

    for (peer, _) in &receivers {
        let (reply, response) = oneshot::channel();
        tx.send(RibUpdate::ReplacePeerExportPolicy {
            peer: *peer,
            export_policy: Some(super::unicast::no_advertise_addition_chain(
                *peer == private,
            )),
            reply,
        })
        .await
        .unwrap();
        response.await.unwrap().unwrap();
    }
    let _ = query_vpn_routes(&tx).await;
    for (peer, out_rx) in &mut receivers {
        let (announced, withdrawn) = drain_vpn_delta(out_rx);
        assert!(announced.is_empty());
        assert_eq!(withdrawn.len(), 2, "each VPN identity withdraws once");
        assert_eq!(withdrawn.into_iter().collect::<HashSet<_>>(), expected_keys);
        assert!(query_vpn_advertised(&tx, *peer).await.is_empty());
    }
    for route in [&v4, &v6] {
        let grouped_explain = query_explain_advertised_vpn_route(
            &tx,
            grouped_a,
            route.inner_prefix(),
            route.nlri.route_distinguisher,
        )
        .await;
        let private_explain = query_explain_advertised_vpn_route(
            &tx,
            private,
            route.inner_prefix(),
            route.nlri.route_distinguisher,
        )
        .await;
        assert!(grouped_explain.update_group_id.is_some());
        assert!(private_explain.update_group_id.is_none());
        assert_eq!(
            grouped_explain.decision,
            crate::update::ExplainDecision::Deny
        );
        assert_eq!(private_explain.decision, grouped_explain.decision);
        assert_eq!(
            grouped_explain
                .gates
                .last()
                .map(|gate| (gate.gate, gate.code)),
            Some(("no_advertise", "no_advertise_policy_suppressed"))
        );
        assert_eq!(
            private_explain
                .gates
                .last()
                .map(|gate| (gate.gate, gate.code)),
            grouped_explain
                .gates
                .last()
                .map(|gate| (gate.gate, gate.code))
        );
        assert!(
            grouped_explain
                .modifications
                .communities_add
                .contains(&rustbgpd_wire::COMMUNITY_NO_ADVERTISE)
        );
    }

    for (peer, _) in &receivers {
        let (reply, response) = oneshot::channel();
        tx.send(RibUpdate::ReplacePeerExportPolicy {
            peer: *peer,
            export_policy: Some(super::unicast::no_advertise_removal_chain(*peer == private)),
            reply,
        })
        .await
        .unwrap();
        response.await.unwrap().unwrap();
    }
    let _ = query_vpn_routes(&tx).await;
    for (_, out_rx) in &mut receivers {
        let (announced, withdrawn) = drain_vpn_delta(out_rx);
        assert_eq!(announced.len(), 2);
        assert!(withdrawn.is_empty());
    }

    drop(tx);
    handle.await.unwrap();
}

/// VPN Add-Path removes source- and policy-scoped candidates before assigning
/// outbound ranks, compacts survivors, and withdraws stale ranks.
///
/// Break-to-red: deleting either Add-Path guard, or moving it after the rank
/// increment, leaves the scoped best/rank hole or retains a policy-scoped rank.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario proves source suppression, policy suppression, rank compaction, stale cleanup, and recovery"
)]
async fn vpn_add_path_no_advertise_compacts_and_withdraws_ranks() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let target: IpAddr = "192.0.2.40".parse().unwrap();
    let (out_tx, mut out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: target,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: Some(super::unicast::no_advertise_removal_chain(false)),
        sendable_families: vpn_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vpn_sendable(),
        add_path_send_max: 2,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;
    assert_eq!(query_vpn_group_label(&tx, target).await, "add_path_send");

    let best = make_vpn_rib_route(Ipv4Addr::new(198, 51, 100, 11), 43, 100, 200);
    let second = make_vpn_rib_route(Ipv4Addr::new(198, 51, 100, 12), 43, 200, 100);
    let nlri_key = best.nlri.key();
    for route in [&best, &second] {
        tx.send(RibUpdate::VpnRoutesReceived {
            session_id: 0,
            peer: route.peer,
            announced: vec![route.clone()],
            withdrawn: vec![],
        })
        .await
        .unwrap();
    }
    let _ = query_vpn_routes(&tx).await;
    let initial = drain_final_vpn(&mut out_rx);
    assert_eq!(initial.len(), 2);
    assert_eq!(
        initial[&crate::route::VpnRibRouteKey {
            nlri_key,
            path_id: 1
        }]
            .peer,
        best.peer
    );
    assert_eq!(
        initial[&crate::route::VpnRibRouteKey {
            nlri_key,
            path_id: 2
        }]
            .peer,
        second.peer
    );

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: best.peer,
        announced: vec![with_vpn_no_advertise(best.clone())],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_vpn_routes(&tx).await;
    let (announced, withdrawn) = drain_vpn_delta(&mut out_rx);
    assert_eq!(announced.len(), 1);
    assert_eq!(announced[0].path_id, 1);
    assert_eq!(announced[0].peer, second.peer);
    assert_eq!(
        withdrawn,
        vec![crate::route::VpnRibRouteKey {
            nlri_key,
            path_id: 2
        }]
    );

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: target,
        export_policy: Some(super::unicast::no_advertise_addition_chain(false)),
        reply,
    })
    .await
    .unwrap();
    response.await.unwrap().unwrap();
    let _ = query_vpn_routes(&tx).await;
    let (announced, withdrawn) = drain_vpn_delta(&mut out_rx);
    assert!(announced.is_empty());
    assert_eq!(
        withdrawn,
        vec![crate::route::VpnRibRouteKey {
            nlri_key,
            path_id: 1
        }]
    );
    assert!(query_vpn_advertised(&tx, target).await.is_empty());

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: target,
        export_policy: Some(super::unicast::no_advertise_removal_chain(false)),
        reply,
    })
    .await
    .unwrap();
    response.await.unwrap().unwrap();
    let _ = query_vpn_routes(&tx).await;
    let recovered = drain_final_vpn(&mut out_rx);
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[&crate::route::VpnRibRouteKey {
            nlri_key,
            path_id: 1
        }]
            .peer,
        second.peer
    );

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: best.peer,
        announced: vec![best.clone()],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_vpn_routes(&tx).await;
    let recovered = drain_final_vpn(&mut out_rx);
    assert_eq!(recovered.len(), 2);
    assert_eq!(
        recovered[&crate::route::VpnRibRouteKey {
            nlri_key,
            path_id: 1
        }]
            .peer,
        best.peer
    );
    assert_eq!(
        recovered[&crate::route::VpnRibRouteKey {
            nlri_key,
            path_id: 2
        }]
            .peer,
        second.peer
    );

    drop(tx);
    handle.await.unwrap();
}

/// A received VPN route must be reflected to an eligible (eBGP-export) peer,
/// and a withdrawal must be staged with the RD + prefix key.
#[tokio::test]
async fn vpn_routes_received_reflects_and_withdraws_to_eligible_peer() {
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

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100);
    let key = route.key();

    tx.send(RibUpdate::VpnRoutesReceived {
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
    assert_eq!(update.vpn_announce.len(), 1);
    assert_eq!(update.vpn_announce[0].key(), key);
    assert_eq!(
        update.vpn_announce[0].nlri, route.nlri,
        "RD + label stack must pass through reflection verbatim"
    );
    assert_eq!(update.vpn_announce[0].next_hop, route.next_hop);
    assert!(update.vpn_withdraw.is_empty());

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![key.clone()],
    })
    .await
    .unwrap();

    let withdraw = out_rx.recv().await.unwrap();
    assert!(withdraw.vpn_announce.is_empty());
    assert_eq!(withdraw.vpn_withdraw, vec![key]);

    drop(tx);
    handle.await.unwrap();
}

/// RFC 7911 VPN receive: distinct path IDs for the same RD+prefix are
/// distinct Adj-RIB-In entries, and a withdraw keyed by path ID removes
/// only that one — the surviving path takes over the Loc-RIB best.
#[tokio::test]
async fn vpn_addpath_ingest_distinct_path_ids_stored_and_withdrawn_independently() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let mut path_1 = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 200);
    path_1.path_id = 1;
    let mut path_2 = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100);
    path_2.path_id = 2;
    assert_eq!(path_1.nlri.key(), path_2.nlri.key());
    assert_ne!(path_1.key(), path_2.key());

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![path_1.clone(), path_2.clone()],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let best = query_vpn_routes(&tx).await;
    assert_eq!(best.len(), 1, "one Loc-RIB best per RD+prefix identity");
    assert_eq!(
        best[0].path_id, 1,
        "the higher-LOCAL_PREF received path wins"
    );

    // Withdraw ONLY path 1 — path 2 must survive and take over.
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![path_1.key()],
    })
    .await
    .unwrap();
    let best = query_vpn_routes(&tx).await;
    assert_eq!(best.len(), 1, "path 2 must survive a path-1-only withdraw");
    assert_eq!(best[0].path_id, 2);

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![path_2.key()],
    })
    .await
    .unwrap();
    assert!(query_vpn_routes(&tx).await.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// RFC 7911 VPN send: an Add-Path-send target receives up to `send_max`
/// candidates per RD+prefix with outbound path IDs 1..=N ranked by the VPN
/// tiebreak, a non-Add-Path target keeps single-best (`path_id = 0`), and
/// a source withdraw shrinks the staged set by outbound path ID.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "covers Add-Path top-N, single-best parity, and withdraw re-ranking in one scenario"
)]
async fn vpn_addpath_send_stages_top_n_and_single_best_unchanged() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let addpath_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (addpath_out_tx, mut addpath_out) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: addpath_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: addpath_out_tx,
        export_policy: None,
        sendable_families: vpn_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![(Afi::Ipv4, Safi::MplsVpn)],
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
        limits: vec![((Afi::Ipv4, Safi::MplsVpn), 2)],
    })
    .await
    .unwrap();
    drain_eor(&mut addpath_out).await;

    let plain_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let (plain_out_tx, mut plain_out) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer: plain_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: plain_out_tx,
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
    drain_eor(&mut plain_out).await;

    // Same RD+prefix from three sources, ranked by LOCAL_PREF: 300 > 200 > 100.
    let best = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 11), 31, 100, 300);
    let second = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 12), 31, 200, 200);
    let third = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 13), 31, 300, 100);
    let nlri_key = best.nlri.key();
    for route in [&best, &second, &third] {
        tx.send(RibUpdate::VpnRoutesReceived {
            session_id: 0,
            peer: route.peer,
            announced: vec![route.clone()],
            withdrawn: vec![],
        })
        .await
        .unwrap();
    }
    let _ = query_vpn_routes(&tx).await; // sync point

    let staged = drain_final_vpn(&mut addpath_out);
    assert_eq!(
        staged.len(),
        2,
        "family-local limit=2 overrides scalar send_max=3"
    );
    let rank_1 = staged
        .get(&crate::route::VpnRibRouteKey {
            nlri_key,
            path_id: 1,
        })
        .expect("outbound path_id 1 staged");
    let rank_2 = staged
        .get(&crate::route::VpnRibRouteKey {
            nlri_key,
            path_id: 2,
        })
        .expect("outbound path_id 2 staged");
    assert_eq!(rank_1.next_hop, best.next_hop, "rank 1 = best by tiebreak");
    assert_eq!(rank_2.next_hop, second.next_hop, "rank 2 = runner-up");

    tx.send(RibUpdate::RouteRefreshRequest {
        session_id: 0,
        peer: addpath_target,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();
    let _ = query_vpn_routes(&tx).await;
    let refreshed = drain_final_vpn(&mut addpath_out);
    assert_eq!(
        refreshed.len(),
        2,
        "route refresh preserves the family-local VPN cap"
    );

    let plain_staged = drain_final_vpn(&mut plain_out);
    assert_eq!(plain_staged.len(), 1, "non-Add-Path peer stays single-best");
    let single = plain_staged
        .get(&crate::route::VpnRibRouteKey {
            nlri_key,
            path_id: 0,
        })
        .expect("single-best staged at path_id 0");
    assert_eq!(single.next_hop, best.next_hop);

    // The best source withdraws: the staged top-2 becomes {second, third}
    // re-ranked as path IDs 1..2; the diff withdraws by outbound path ID.
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: best.peer,
        announced: vec![],
        withdrawn: vec![best.key()],
    })
    .await
    .unwrap();
    let _ = query_vpn_routes(&tx).await; // sync point

    let staged = drain_final_vpn(&mut addpath_out);
    // drain_final_vpn folds over the earlier state: ranks 1..2 re-announced.
    let rank_1 = staged
        .get(&crate::route::VpnRibRouteKey {
            nlri_key,
            path_id: 1,
        })
        .expect("outbound path_id 1 restaged after withdraw");
    let rank_2 = staged
        .get(&crate::route::VpnRibRouteKey {
            nlri_key,
            path_id: 2,
        })
        .expect("outbound path_id 2 restaged after withdraw");
    assert_eq!(rank_1.next_hop, second.next_hop);
    assert_eq!(rank_2.next_hop, third.next_hop);

    drop(tx);
    handle.await.unwrap();
}

/// RFC 4456 eligibility on VPN reflection: a non-client iBGP route is
/// reflected to RR clients, suppressed toward other non-clients, and never
/// echoed back to the source.
#[tokio::test]
async fn vpn_rr_reflects_non_client_route_to_clients_only() {
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
            session_id: 0,
            peer,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: vpn_sendable(),
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

    let route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 32, 100, 100);
    let key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let reflected = client_rx.recv().await.unwrap();
    assert_eq!(reflected.vpn_announce.len(), 1);
    assert_eq!(reflected.vpn_announce[0].key(), key);

    let non_client_echo =
        tokio::time::timeout(Duration::from_millis(50), non_client_rx.recv()).await;
    assert!(
        non_client_echo.is_err(),
        "non-client iBGP route must not be reflected to another non-client"
    );
    let source_echo = tokio::time::timeout(Duration::from_millis(50), source_rx.recv()).await;
    assert!(
        source_echo.is_err(),
        "VPN routes must not be reflected back to the source peer"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A same-peer relabel (same RD + prefix key, new MPLS label stack) must be
/// re-advertised: the label is route data with no analog in the BGP-LS
/// template, and `vpn_routes_equal` must catch the `nlri` change.
#[tokio::test]
async fn vpn_same_peer_relabel_triggers_re_advertise() {
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

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 33, 100, 100);
    let relabeled = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 33, 200, 100);
    assert_eq!(
        route.key(),
        relabeled.key(),
        "label must not change the key"
    );

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.vpn_announce.len(), 1);
    assert_eq!(first.vpn_announce[0].nlri.labels[0].label, 100);

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![relabeled],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let second = out_rx.recv().await.unwrap();
    assert_eq!(
        second.vpn_announce.len(),
        1,
        "same-peer relabel must re-advertise"
    );
    assert_eq!(second.vpn_announce[0].nlri.labels[0].label, 200);

    drop(tx);
    handle.await.unwrap();
}

/// A dirty-resync (here: an export-policy replace, which forces a full
/// restage against the real Adj-RIB-Out) must not re-send a VPN route whose
/// staged form is unchanged.
#[tokio::test]
async fn vpn_dirty_resync_equality_skip_does_not_resend_unchanged_route() {
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

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 34, 100, 100);
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.vpn_announce.len(), 1);

    // Policy replace marks the peer dirty and runs a full resync; the staged
    // route equals the committed Adj-RIB-Out entry, so nothing is re-sent.
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
        "unchanged VPN route must be skipped by the dirty-resync equality check"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A peer that comes up after the VPN table converged must receive the full
/// table in its initial dump, followed by the SAFI-128 `EoR`.
#[tokio::test]
async fn send_initial_table_includes_vpn_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 35, 100, 100);
    let key = route.key();

    tx.send(RibUpdate::VpnRoutesReceived {
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

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert_eq!(update.vpn_announce.len(), 1);
    assert_eq!(update.vpn_announce[0].key(), key);
    assert!(update.vpn_withdraw.is_empty());

    let eor = out_rx.recv().await.unwrap();
    assert_eq!(eor.end_of_rib, vpn_sendable());

    drop(tx);
    handle.await.unwrap();
}

/// A plain ROUTE-REFRESH request for (IPv4, `MplsVpn`) must replay the staged
/// VPN routes between the BoRR/EoRR markers.
#[tokio::test]
async fn route_refresh_vpn_re_advertises_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 36, 100, 100);
    let key = route.key();

    tx.send(RibUpdate::VpnRoutesReceived {
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

    let _initial = out_rx.recv().await.unwrap();
    let _eor = out_rx.recv().await.unwrap();

    tx.send(RibUpdate::RouteRefreshRequest {
        session_id: 0,
        peer: target,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert!(update.withdraw.is_empty());
    assert_eq!(update.vpn_announce.len(), 1);
    assert_eq!(update.vpn_announce[0].key(), key);
    assert!(update.vpn_withdraw.is_empty());
    assert_eq!(update.end_of_rib, vec![(Afi::Ipv4, Safi::MplsVpn)]);
    assert_eq!(
        update.refresh_markers,
        vec![
            (
                Afi::Ipv4,
                Safi::MplsVpn,
                rustbgpd_wire::RouteRefreshSubtype::BoRR
            ),
            (
                Afi::Ipv4,
                Safi::MplsVpn,
                rustbgpd_wire::RouteRefreshSubtype::EoRR
            ),
        ]
    );

    drop(tx);
    handle.await.unwrap();
}

#[test]
fn vpn_peer_down_during_refresh_clears_stale_state() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);

    manager.handle_vpn_routes_received(
        peer,
        vec![make_vpn_rib_route(peer_addr, 26, 100, 100)],
        vec![],
    );
    manager.handle_update(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    });
    assert!(
        manager
            .refresh_stale_vpn
            .get(&peer)
            .is_some_and(|stale| stale.len() == 1),
        "BoRR must snapshot the peer's Adj-RIB-In VPN keys as stale"
    );

    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    });
    assert!(
        !manager.refresh_stale_vpn.contains_key(&peer),
        "peer-down during an active refresh must clear the VPN stale snapshot"
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

// --- RFC 9107 VPN-ORR: per-vantage best selection for SAFI 128 ---
