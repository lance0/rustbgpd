use super::*;
use crate::attr_set::AttrSet;

#[test]
fn smet_obeys_family_export_policy_and_rr_client_gates() {
    for (family, deny, client, exported) in [
        (true, false, true, true),
        (false, false, true, false),
        (true, true, true, false),
        (true, false, false, false),
    ] {
        let (_tx, rx) = mpsc::channel(4);
        let mut manager = RibManager::new(
            rx,
            dummy_query_rx(),
            None,
            Some("192.0.2.254".parse().unwrap()),
            BgpMetrics::new(),
        );
        let (outbound_tx, mut out) = mpsc::channel(4);
        manager.handle_update(RibUpdate::PeerUp {
            per_client_best: false,
            interpret_rfc1997: true,
            session_id: 0,
            peer: "192.0.2.30".parse().unwrap(),
            peer_asn: 65000,
            peer_router_id: "192.0.2.30".parse().unwrap(),
            outbound_tx,
            export_policy: deny.then(|| {
                rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
                    entries: vec![],
                    default_action: rustbgpd_policy::PolicyAction::Deny,
                }])
            }),
            sendable_families: if family { evpn_sendable() } else { vec![] },
            is_ebgp: false,
            route_reflector_client: client,
            orr_vantage: None,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: vec![],
            negotiated_llgr_families: vec![],
        });
        while out.try_recv().is_ok() {}
        let mut route = make_evpn_smet("192.0.2.10".parse().unwrap(), 0xf2);
        route.origin_type = crate::route::RouteOrigin::Ibgp;
        manager.ribs.insert(route.peer, AdjRibIn::new(route.peer));
        manager.process_evpn_announce_chunk(route.peer, vec![route.clone()]);
        assert!(manager.loc_rib.get_evpn(&route.key()).is_some());
        let announcements: Vec<_> = std::iter::from_fn(|| out.try_recv().ok())
            .flat_map(|update| update.evpn_announce)
            .collect();
        assert_eq!(
            announcements.len(),
            usize::from(exported),
            "family={family} deny={deny} client={client}"
        );
        if exported {
            assert_eq!(announcements[0].route, route.route);
        }
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one lifecycle pins flags-only replacement, fallback, distinct originators, events, and dataplane exclusion"
)]
fn smet_flags_replace_selected_payload_fallback_and_originators_stay_distinct() {
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some("192.0.2.254".parse().unwrap()),
        BgpMetrics::new(),
    );
    let mut live = manager.evpn_events_tx.subscribe();
    let target: IpAddr = "192.0.2.30".parse().unwrap();
    let (outbound_tx, mut out) = mpsc::channel(16);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: "192.0.2.30".parse().unwrap(),
        outbound_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    while out.try_recv().is_ok() {}
    let mut winner = make_evpn_smet("192.0.2.10".parse().unwrap(), 0xf2);
    AttrSet::edit(&mut winner.attributes, |attrs| {
        attrs.push(PathAttribute::LocalPref(200));
    });
    let fallback = make_evpn_smet("192.0.2.11".parse().unwrap(), 0x02);
    for route in [&winner, &fallback] {
        manager.ribs.insert(route.peer, AdjRibIn::new(route.peer));
        manager.process_evpn_announce_chunk(route.peer, vec![route.clone()]);
    }
    let key = winner.key();
    assert_eq!(manager.loc_rib.get_evpn(&key).unwrap().peer, winner.peer);
    let initial = out.try_recv().unwrap();
    assert_eq!(initial.evpn_announce[0].route, winner.route);
    assert!(out.try_recv().is_err());
    assert_eq!(live.try_recv().unwrap().event_type, RouteEventType::Added);
    assert!(live.try_recv().is_err());
    let original = winner.clone();
    let EvpnRoute::Smet(smet) = &mut winner.route else {
        unreachable!()
    };
    smet.flags = 0xfa;
    manager.process_evpn_announce_chunk(winner.peer, vec![winner.clone()]);
    assert_eq!(winner.key(), key);
    assert_eq!(manager.ribs[&winner.peer].evpn_len(), 1);
    assert_eq!(manager.loc_rib.get_evpn(&key).unwrap().route, winner.route);
    let changed = out.try_recv().unwrap();
    assert_eq!(changed.evpn_announce.len(), 1);
    assert_eq!(changed.evpn_announce[0].route, winner.route);
    assert_eq!(changed.evpn_withdraw.len(), 0);
    let event = live.try_recv().unwrap();
    assert_eq!(event.event_type, RouteEventType::BestChanged);
    assert_eq!(event.key, key);
    assert_eq!(event.best.as_ref().unwrap().route, winner.route);
    assert_eq!(event.previous_best.as_ref().unwrap().route, original.route);
    assert_eq!(
        manager
            .evpn_route_event_history
            .back()
            .unwrap()
            .best
            .as_ref()
            .unwrap()
            .route,
        winner.route
    );

    let mut other_originator = winner.clone();
    let EvpnRoute::Smet(smet) = &mut other_originator.route else {
        unreachable!()
    };
    smet.originator_ip = "2001:db8::99".parse().unwrap();
    manager.process_evpn_announce_chunk(winner.peer, vec![other_originator.clone()]);
    assert_eq!(manager.loc_rib.iter_evpn().count(), 2);
    assert_eq!(
        out.try_recv().unwrap().evpn_announce[0].key(),
        other_originator.key()
    );

    manager.process_evpn_withdraw_chunk(winner.peer, vec![key]);
    assert_eq!(
        manager.loc_rib.get_evpn(&key).unwrap().route,
        fallback.route
    );
    let changed = out.try_recv().unwrap();
    assert_eq!(changed.evpn_announce[0].peer, fallback.peer);
    assert_eq!(changed.evpn_announce[0].route, fallback.route);
    manager.process_evpn_withdraw_chunk(fallback.peer, vec![key]);
    assert!(manager.loc_rib.get_evpn(&key).is_none());
    assert_eq!(out.try_recv().unwrap().evpn_withdraw, vec![key]);
    assert!(manager.loc_rib.get_evpn(&other_originator.key()).is_some());
    let (reply, mut received) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryEvpnDataplaneRoutes {
        known_generation: None,
        reply,
    });
    assert_eq!(received.try_recv().unwrap().routes.unwrap().len(), 0);
    assert_eq!(manager.evpn_dataplane_generation, 0);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one lifecycle compares retained, selected, advertised, and dataplane consumer views"
)]
fn srv6_evpn_eligibility_filters_selection_exports_and_consumer_queries() {
    use crate::srv6::tests::service_attribute;

    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let target: IpAddr = "192.0.2.30".parse().unwrap();
    let (outbound_tx, mut out) = mpsc::channel(16);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: target,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    while out.try_recv().is_ok() {}
    let sid = "2001:db8:111:1::".parse().unwrap();
    let valid = service_attribute(6, sid, 23, Some([40, 24, 16, 0, 0, 0]));
    let mut fallback = make_evpn_macip(
        Ipv4Addr::new(192, 0, 2, 10),
        [0, 1, 2, 3, 4, 5],
        Some(1),
        false,
    );
    fallback.next_hop = "2001:db8::10".parse().unwrap();
    AttrSet::edit(&mut fallback.attributes, |attrs| attrs.push(valid.clone()));
    let mut invalid = make_evpn_macip(
        Ipv4Addr::new(192, 0, 2, 11),
        [0, 1, 2, 3, 4, 5],
        Some(100),
        true,
    );
    invalid.next_hop = "2001:db8::11".parse().unwrap();
    AttrSet::edit(&mut invalid.attributes, |attrs| {
        attrs.push(service_attribute(6, sid, 23, Some([100, 24, 16, 0, 0, 0])));
    });
    let announce = |manager: &mut RibManager, route: &EvpnRibRoute| {
        manager.enqueue_routes_received(
            route.peer,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![route.clone()],
            vec![],
            None,
        );
        drain_route_chunks(manager);
    };
    let query = |manager: &mut RibManager, expected: Option<IpAddr>| {
        let (reply, mut response) = oneshot::channel();
        manager.handle_update(RibUpdate::QueryEvpnRoutes {
            filter: None,
            reply,
        });
        let routes = response.try_recv().unwrap();
        assert_eq!(
            routes.iter().map(|r| r.peer).collect::<Vec<_>>(),
            expected.into_iter().collect::<Vec<_>>()
        );
        let (reply, mut response) = oneshot::channel();
        manager.handle_update(RibUpdate::QueryEvpnDataplaneRoutes {
            known_generation: None,
            reply,
        });
        let routes = response.try_recv().unwrap().routes.unwrap();
        assert_eq!(
            routes.iter().map(|r| r.peer).collect::<Vec<_>>(),
            expected.into_iter().collect::<Vec<_>>()
        );
    };
    announce(&mut manager, &fallback);
    while out.try_recv().is_ok() {}
    announce(&mut manager, &invalid);
    assert_eq!(
        manager.loc_rib.get_evpn(&fallback.key()).unwrap().peer,
        fallback.peer
    );
    query(&mut manager, Some(fallback.peer));
    assert_eq!(
        manager.ribs[&invalid.peer]
            .get_evpn(&invalid.key())
            .unwrap()
            .attributes,
        invalid.attributes
    );
    let explain = manager.explain_evpn_route(invalid.key(), Some(invalid.peer), Some(target), None);
    assert_eq!(explain.reason, Some(crate::BestPathReason::Srv6SidInvalid));
    assert_eq!(explain.received.unwrap().attributes, invalid.attributes);
    assert_eq!(explain.selection_best.unwrap().peer, fallback.peer);
    while let Ok(update) = out.try_recv() {
        assert!(update.evpn_announce.is_empty());
        assert_eq!(update.evpn_withdraw.len(), 0);
    }
    manager.enqueue_routes_received(
        fallback.peer,
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![fallback.key()],
        None,
    );
    drain_route_chunks(&mut manager);
    query(&mut manager, None);
    let mut withdrawn = Vec::new();
    while let Ok(update) = out.try_recv() {
        assert!(update.evpn_announce.is_empty());
        withdrawn.extend(update.evpn_withdraw);
    }
    assert_eq!(withdrawn, vec![fallback.key()]);
    let explain = manager.explain_evpn_route(invalid.key(), None, Some(target), None);
    assert!(explain.best.is_none());
    assert_eq!(explain.candidate_count, 1);
    assert_eq!(explain.reason, Some(crate::BestPathReason::Srv6SidInvalid));
    assert!(
        explain
            .export
            .unwrap()
            .gates
            .iter()
            .any(|gate| gate.code == "srv6_sid_invalid")
    );
    AttrSet::edit(&mut invalid.attributes, |attrs| {
        *attrs.last_mut().unwrap() = valid;
    });
    announce(&mut manager, &invalid);
    query(&mut manager, Some(invalid.peer));
    let mut announced = Vec::new();
    while let Ok(update) = out.try_recv() {
        announced.extend(update.evpn_announce);
    }
    assert_eq!(announced.len(), 1);
    assert_eq!(announced[0].attributes, invalid.attributes);
}

fn with_evpn_community(mut route: EvpnRibRoute, community: u32) -> EvpnRibRoute {
    AttrSet::edit(&mut route.attributes, |attrs| {
        attrs.push(PathAttribute::Communities(vec![community]));
    });
    route
}

fn evpn_no_advertise_policy(
    matched_community: u32,
    add: bool,
    remove: bool,
) -> rustbgpd_policy::PolicyChain {
    rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
        entries: vec![rustbgpd_policy::PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: rustbgpd_policy::PolicyAction::Permit,
            match_community: vec![rustbgpd_policy::CommunityMatch::Standard {
                value: matched_community,
            }],
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
            modifications: rustbgpd_policy::RouteModifications {
                communities_add: add
                    .then_some(rustbgpd_wire::COMMUNITY_NO_ADVERTISE)
                    .into_iter()
                    .collect(),
                communities_remove: remove
                    .then_some(rustbgpd_wire::COMMUNITY_NO_ADVERTISE)
                    .into_iter()
                    .collect(),
                ..rustbgpd_policy::RouteModifications::default()
            },
        }],
        default_action: rustbgpd_policy::PolicyAction::Permit,
    }])
}

fn evpn_no_export_policy(
    matched_community: u32,
    add: bool,
    remove: bool,
) -> rustbgpd_policy::PolicyChain {
    rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
        entries: vec![rustbgpd_policy::PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: rustbgpd_policy::PolicyAction::Permit,
            match_community: vec![rustbgpd_policy::CommunityMatch::Standard {
                value: matched_community,
            }],
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
            modifications: rustbgpd_policy::RouteModifications {
                communities_add: add
                    .then_some(rustbgpd_wire::COMMUNITY_NO_EXPORT)
                    .into_iter()
                    .collect(),
                communities_remove: remove
                    .then_some(rustbgpd_wire::COMMUNITY_NO_EXPORT)
                    .into_iter()
                    .collect(),
                ..rustbgpd_policy::RouteModifications::default()
            },
        }],
        default_action: rustbgpd_policy::PolicyAction::Permit,
    }])
}

async fn evpn_export_peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    is_ebgp: bool,
    interpret_rfc1997: bool,
    export_policy: Option<rustbgpd_policy::PolicyChain>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, mut out_rx) = mpsc::channel(32);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997,
        session_id: 0,
        peer,
        peer_asn: if is_ebgp { 65100 } else { 65000 },
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy,
        sendable_families: evpn_sendable(),
        is_ebgp,
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
    out_rx
}

/// Regression: EVPN routes learned from a peer that goes down must be
/// withdrawn from remaining peers. Before this fix, `handle_peer_down` removed
/// the dead peer's Adj-RIB-In but never called `recompute_and_distribute_evpn`,
/// leaving the Loc-RIB advertising stale MAC/IP reachability.
#[tokio::test]
async fn peer_down_withdraws_evpn_routes_from_remaining_peers() {
    let (tx, rx) = mpsc::channel(64);
    // Cluster-ID is required for iBGP→iBGP reflection (RFC 4456); without it,
    // should_suppress_ibgp_inner falls back to standard split-horizon.
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Register target as RR client for L2VPN/EVPN (iBGP, same AS).
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
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
    drain_eor(&mut out_rx).await;

    // Register source as an RR client too — the RibManager needs an outbound
    // entry for the source or it skips reflection evaluation entirely; the
    // source's own announces will round-trip to itself but split-horizon
    // suppresses them at the stage step.
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
        sendable_families: evpn_sendable(),
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

    // Source advertises a Type 3 IMET route.
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet_key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    // Target receives the reflected EVPN announce.
    let announce = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("target should receive EVPN announce within 2s")
        .expect("outbound channel open");
    assert_eq!(announce.evpn_announce.len(), 1);
    assert_eq!(announce.evpn_announce[0].key(), imet_key);
    assert!(
        announce.evpn_withdraw.is_empty(),
        "announce phase should have no withdrawals"
    );

    // Source goes down.
    tx.send(RibUpdate::PeerDown {
        peer: source,
        session_id: 0,
    })
    .await
    .unwrap();

    // Target should receive a withdrawal for that EVPN key.
    let withdraw = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("target should receive EVPN withdrawal within 2s")
        .expect("outbound channel still open");
    assert!(
        withdraw.evpn_announce.is_empty(),
        "peer-down should not produce announces"
    );
    assert_eq!(
        withdraw.evpn_withdraw,
        vec![imet_key],
        "target must see the withdrawal for the dead peer's EVPN route"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Regression: an RR must not reflect an EVPN route back to the peer
/// that originated it (source-peer split horizon). Prior to the fix the
/// distribution path went `loc_rib.get_evpn()` → RR suppression check →
/// stage for all peers including the source. FRR dropped the
/// self-reflection via `ORIGINATOR_ID`, but RFC 4456 hygiene says we
/// shouldn't emit it in the first place.
#[tokio::test]
async fn evpn_is_not_reflected_back_to_source_peer() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Source is an RR client.
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
        sendable_families: evpn_sendable(),
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

    // A second RR client so reflection has somewhere to go.
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
        sendable_families: evpn_sendable(),
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

    // Source advertises a Type 3 IMET.
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet_key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    // The "other" client must receive a reflected announce.
    let other_announce = tokio::time::timeout(Duration::from_secs(2), other_out_rx.recv())
        .await
        .expect("other peer should receive reflection within 2s")
        .expect("outbound channel still open");
    assert_eq!(other_announce.evpn_announce.len(), 1);
    assert_eq!(other_announce.evpn_announce[0].key(), imet_key);

    // The source must NOT receive its own route back. A short wait is
    // enough — if the bug exists, the bad announce fires on the same
    // distribute_changes as the reflection to "other".
    match tokio::time::timeout(Duration::from_millis(300), source_out_rx.recv()).await {
        Err(_) => {
            // Timeout — correct behavior. Source saw nothing.
        }
        Ok(Some(msg)) => {
            assert!(
                msg.evpn_announce.is_empty(),
                "source peer must not receive its own EVPN route back (got {:?})",
                msg.evpn_announce,
            );
        }
        Ok(None) => panic!("source outbound channel closed unexpectedly"),
    }

    drop(tx);
    handle.await.unwrap();
}

/// Regression: when an EVPN update fails to send (outbound channel full),
/// the peer is marked dirty; a later `distribute_changes` must resync EVPN
/// routes, not only unicast / `FlowSpec`. Before this fix, dirty resync
/// rebuilt unicast prefixes + `FlowSpec` rules but never gathered EVPN keys
/// or staged EVPN routes, so EVPN deltas could be silently dropped.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "full channel-full → dirty-resync flow in one scenario"
)]
async fn dirty_resync_includes_evpn_routes_after_channel_full() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Target's outbound channel is size 1 — after the EoR, one more slot.
    // We'll fill it, then the EVPN announce will fail and mark target dirty.
    let (out_tx, mut out_rx) = mpsc::channel(1);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
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
    drain_eor(&mut out_rx).await;

    // Source as RR client so reflection isn't suppressed.
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
        sendable_families: evpn_sendable(),
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

    // Fill the target's outbound channel by NOT draining — send two EVPN
    // announces in a row. The first lands in the channel (queue size 1);
    // the second fails `try_send` and marks target dirty.
    let imet1 = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet1_key = imet1.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet1],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    // Give the RibManager a tick to process and fill the channel.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Second EVPN route arrives; target's channel is full → target goes dirty.
    let imet2 = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 200);
    let imet2_key = imet2.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet2],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    // Drain the first queued update to make room, then drain anything the
    // resync timer delivers.
    let first = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("first EVPN announce must arrive")
        .expect("channel open");
    assert_eq!(first.evpn_announce.len(), 1);
    assert_eq!(first.evpn_announce[0].key(), imet1_key);

    // Collect EVPN announces until we see imet2_key — the dirty-resync path
    // must eventually deliver it. Time out after 10s (resync timer is faster).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut saw_imet2 = false;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), out_rx.recv()).await {
            Ok(Some(update)) => {
                if update.evpn_announce.iter().any(|r| r.key() == imet2_key) {
                    saw_imet2 = true;
                    break;
                }
            }
            Ok(None) => panic!("outbound channel closed unexpectedly"),
            Err(_) => {}
        }
    }
    assert!(
        saw_imet2,
        "dirty resync must eventually deliver the second EVPN announce (imet2) to the target peer"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A Type 2 or Type 5 route from 10.0.0.1, distinguished by `n`.
fn churn_route(n: u8, type5: bool) -> EvpnRibRoute {
    let mut route = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let rd = RouteDistinguisher([0, 1, 10, 0, 0, 1, 0, 1]);
    route.route = if type5 {
        EvpnRoute::IpPrefix(rustbgpd_wire::EvpnIpPrefixRoute {
            rd,
            esi: EthernetSegmentIdentifier([0; 10]),
            ethernet_tag: EthernetTagId(0),
            prefix: rustbgpd_wire::EvpnIpPrefixValue::V4(Ipv4Prefix::new(
                Ipv4Addr::new(100, 64, 0, n),
                32,
            )),
            gateway: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            label: MplsLabel::new(50_000),
        })
    } else {
        EvpnRoute::MacIp(EvpnMacIp {
            rd,
            esi: EthernetSegmentIdentifier([0; 10]),
            ethernet_tag: EthernetTagId(0),
            mac: MacAddress([2, 0, 0, 0, 0, n]),
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 9, 0, n))),
            label1: MplsLabel::new(10_100),
            label2: None,
        })
    };
    route
}

/// Apply outbound updates to a client view until it equals `expected`
/// (keys and route content) or `wait` passes; returns the final view.
async fn drain_view(
    out_rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    view: &mut BTreeMap<rustbgpd_wire::EvpnRouteKey, EvpnRoute>,
    expected: &BTreeMap<rustbgpd_wire::EvpnRouteKey, EvpnRoute>,
    wait: Duration,
    stop_when_exact: bool,
) {
    let deadline = tokio::time::Instant::now() + wait;
    while tokio::time::Instant::now() < deadline {
        if stop_when_exact && view == expected {
            return;
        }
        match tokio::time::timeout_at(deadline, out_rx.recv()).await {
            Ok(Some(update)) => {
                for key in &update.evpn_withdraw {
                    view.remove(key);
                }
                for route in &update.evpn_announce {
                    view.insert(route.route.key(), route.route.clone());
                }
            }
            Ok(None) => panic!("outbound channel closed unexpectedly"),
            Err(_) => return,
        }
    }
}

/// A deferred EVPN update (outbound channel full) must recover through the
/// dirty resync without losing an announcement or a withdrawal: after
/// Type 2/5 churn that includes withdrawals of already-sent routes and an
/// announce-then-withdraw inside the deferral window, the client's view is
/// exactly the current table, and stays so across further resync ticks.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "setup, saturated churn and the exact-view drain in one scenario"
)]
async fn deferred_evpn_churn_recovers_exact_announces_and_withdrawals() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let mut outputs = Vec::new();
    for (peer, router_id, capacity) in [(target, 2, 1), (source, 1, 64)] {
        let (out_tx, mut out_rx) = mpsc::channel(capacity);
        tx.send(RibUpdate::PeerUp {
            per_client_best: false,
            interpret_rfc1997: true,
            session_id: 0,
            peer,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::new(10, 0, 0, router_id),
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: evpn_sendable(),
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
        drain_eor(&mut out_rx).await;
        outputs.push(out_rx);
    }
    let mut out_rx = outputs.remove(0);
    let _source_out = outputs.remove(0);

    let send = |announce: Vec<EvpnRibRoute>, withdraw: Vec<EvpnRibRoute>| {
        let tx = tx.clone();
        async move {
            tx.send(RibUpdate::RoutesReceived {
                session_id: 0,
                peer: source,
                announced: vec![],
                withdrawn: vec![],
                flowspec_announced: vec![],
                flowspec_withdrawn: vec![],
                evpn_announced: announce,
                evpn_withdrawn: withdraw.iter().map(|r| r.route.key()).collect(),
                validated_with: None,
            })
            .await
            .unwrap();
            // Let the manager distribute each change on its own.
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    let table = |routes: &[(u8, bool)]| {
        routes
            .iter()
            .map(|&(n, t5)| {
                let route = churn_route(n, t5).route;
                (route.key(), route)
            })
            .collect::<BTreeMap<_, _>>()
    };

    // Initial table, delivered normally.
    let mut view = BTreeMap::new();
    send(
        vec![
            churn_route(1, false),
            churn_route(2, false),
            churn_route(1, true),
        ],
        vec![],
    )
    .await;
    let initial = table(&[(1, false), (2, false), (1, true)]);
    drain_view(
        &mut out_rx,
        &mut view,
        &initial,
        Duration::from_secs(10),
        true,
    )
    .await;
    assert_eq!(view, initial, "initial table must arrive exactly");

    // Churn without draining: the first change fills the one-slot channel
    // and every later one is deferred.
    send(vec![churn_route(3, false)], vec![churn_route(1, false)]).await;
    send(vec![churn_route(2, true)], vec![churn_route(1, true)]).await;
    send(vec![churn_route(4, false)], vec![]).await;
    send(vec![], vec![churn_route(4, false)]).await;
    send(vec![churn_route(5, false)], vec![churn_route(2, false)]).await;
    assert_eq!(
        out_rx.len(),
        1,
        "the channel must be saturated, so later changes were deferred"
    );

    let current = table(&[(3, false), (5, false), (2, true)]);
    drain_view(
        &mut out_rx,
        &mut view,
        &current,
        Duration::from_secs(10),
        true,
    )
    .await;
    assert_eq!(
        view, current,
        "deferred churn must recover to the exact table"
    );
    // Further resync ticks must not resurrect a withdrawn route.
    drain_view(
        &mut out_rx,
        &mut view,
        &current,
        Duration::from_millis(2500),
        false,
    )
    .await;
    assert_eq!(view, current, "the view must stay exact after recovery");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_gr_marks_stale_and_demotes_routes() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    // Source enters graceful restart
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 1, "EVPN route should remain in Loc-RIB");
    assert!(best[0].is_stale, "EVPN route should be marked stale");
    assert!(!best[0].is_llgr_stale);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_gr_eor_clears_stale() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let dropped = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 200);
    let kept_key = kept.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![kept.clone(), dropped],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 2);
    assert!(best.iter().all(|r| r.is_stale));

    // Only `kept` is re-advertised before End-of-RIB.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![kept],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::L2Vpn,
        safi: Safi::Evpn,
    })
    .await
    .unwrap();

    // RFC 4724 §4.1: an EVPN route still marked stale at End-of-RIB was
    // not re-advertised during the restart window and must be removed;
    // the re-advertised route survives with its stale flag cleared.
    let best = query_evpn_routes(&tx).await;
    assert_eq!(
        best.len(),
        1,
        "the non-readvertised stale EVPN route must be removed at End-of-RIB"
    );
    assert_eq!(best[0].key(), kept_key);
    assert!(!best[0].is_stale, "EoR should clear stale flag");

    drop(tx);
    handle.await.unwrap();
}

/// A second GR entry while EVPN routes are still stale deletes them
/// (RFC 4724 §4.1: no retention across consecutive restarts).
#[tokio::test]
async fn evpn_gr_consecutive_restart_deletes_stale_routes() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100)],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let gr_entry = || RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    };
    tx.send(gr_entry()).await.unwrap();
    let stale = query_evpn_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    tx.send(gr_entry()).await.unwrap();
    assert!(
        query_evpn_routes(&tx).await.is_empty(),
        "a route still stale at the next restart must be deleted, not re-marked"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_gr_timer_sweeps_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    // GR without LLGR — stale routes should be purged on timer expiry.
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert!(best[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    let best = query_evpn_routes(&tx).await;
    assert!(
        best.is_empty(),
        "GR timer expiry must sweep stale EVPN routes"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_llgr_gr_timer_promotes_to_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 5,
        stale_routes_time: 10,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 7200,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert!(best[0].is_stale);
    assert!(!best[0].is_llgr_stale);

    // Advance past GR timer — promotes to LLGR-stale
    tokio::time::advance(Duration::from_secs(6)).await;
    tokio::task::yield_now().await;

    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 1, "EVPN route retained during LLGR");
    assert!(!best[0].is_stale);
    assert!(best[0].is_llgr_stale);
    // LLGR_STALE community injected locally
    assert!(
        best[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "promoted EVPN route must carry LLGR_STALE community"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_llgr_timer_sweeps_llgr_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            forwarding_preserved: false,
            stale_time: 10,
        }],
        llgr_stale_time: 10,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert!(best[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let best = query_evpn_routes(&tx).await;
    assert!(best[0].is_llgr_stale);

    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;

    let best = query_evpn_routes(&tx).await;
    assert!(
        best.is_empty(),
        "LLGR timer expiry must sweep LLGR-stale EVPN routes"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_llgr_eor_clears_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let dropped = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 200);
    let kept_key = kept.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![kept.clone(), dropped],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 3600,
    })
    .await
    .unwrap();

    // Force the manager to process PeerGracefulRestart before advancing time
    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 2);
    assert!(best.iter().all(|r| r.is_stale));

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let best = query_evpn_routes(&tx).await;
    assert!(best.iter().all(|r| r.is_llgr_stale));
    assert!(best.iter().all(|r| {
        r.communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
    }));

    // Only `kept` is re-advertised before End-of-RIB. EoR during the LLGR
    // phase removes what was not re-advertised (RFC 4724 §4.1 via RFC 9494
    // §4.2) and clears is_llgr_stale + strips the locally-injected
    // LLGR_STALE community on the retained route.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![kept],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::L2Vpn,
        safi: Safi::Evpn,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert_eq!(
        best.len(),
        1,
        "the non-readvertised LLGR-stale EVPN route must be removed at End-of-RIB"
    );
    assert_eq!(best[0].key(), kept_key);
    assert!(!best[0].is_llgr_stale, "LLGR-stale flag must be cleared");
    assert!(
        !best[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "locally-injected LLGR_STALE community must be stripped"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_gr_no_llgr_community_drops_route_on_promotion() {
    use rustbgpd_wire::{EthernetTagId, EvpnImet, EvpnRoute, RouteDistinguisher};

    tokio::time::pause();

    // Build an EVPN route carrying COMMUNITY_NO_LLGR so it must be dropped
    // when the GR timer expires rather than promoted to LLGR-stale.
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = EvpnRoute::Imet(EvpnImet {
        rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 100]),
        ethernet_tag: EthernetTagId(100),
        originator_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    });
    let imet = EvpnRibRoute {
        route,
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        link_local_next_hop: None,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        attributes: AttrSet::new(vec![PathAttribute::Communities(vec![
            rustbgpd_wire::COMMUNITY_NO_LLGR,
        ])]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        is_stale: false,
        is_llgr_stale: false,
    };
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 3600,
    })
    .await
    .unwrap();

    // Force the manager to process PeerGracefulRestart before advancing time
    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert!(best[0].is_stale);

    // Advance past GR timer — NO_LLGR route must be removed, not promoted.
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let best = query_evpn_routes(&tx).await;
    assert!(
        best.is_empty(),
        "NO_LLGR EVPN route must be dropped on GR timer expiry"
    );

    drop(tx);
    handle.await.unwrap();
}

// --- Typed-family LLGR two-phase lifecycle (RFC 9494): VPN, BGP-LS, RTC ---

/// Gate 6: controller-driven EVPN injection. `InjectEvpn` places a
/// `RouteOrigin::Local` EVPN route into the RR's Loc-RIB and reflects
/// it to peers negotiating L2VPN/EVPN — same shape as `InjectFlowSpec`.
#[tokio::test]
async fn inject_evpn_reflects_to_peer() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
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
    drain_eor(&mut out_rx).await;

    // Construct an EVPN Type 3 IMET anchored on a synthetic local
    // originator (0.0.0.0, matches LOCAL_PEER in the manager).
    let mut imet = make_evpn_imet(Ipv4Addr::UNSPECIFIED, 100);
    imet.origin_type = crate::route::RouteOrigin::Local;
    let injected_key = imet.key();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::InjectEvpn {
        route: imet,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx
        .await
        .expect("inject reply")
        .expect("inject must succeed");

    // Peer must see the reflected local route as an announce.
    let msg = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("peer should receive the injected route within 2s")
        .expect("outbound channel open");
    assert_eq!(msg.evpn_announce.len(), 1);
    assert_eq!(msg.evpn_announce[0].key(), injected_key);

    // Withdraw through the same channel; peer must see the retraction.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::WithdrawEvpn {
        key: injected_key,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx
        .await
        .expect("withdraw reply")
        .expect("withdraw must succeed");

    let msg = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("peer should receive withdraw within 2s")
        .expect("outbound channel open");
    assert!(msg.evpn_announce.is_empty());
    assert_eq!(msg.evpn_withdraw, vec![injected_key]);

    drop(tx);
    handle.await.unwrap();
}

fn with_evpn_cluster_list(mut route: EvpnRibRoute, ids: &[Ipv4Addr]) -> EvpnRibRoute {
    AttrSet::edit(&mut route.attributes, |attrs| {
        attrs.push(PathAttribute::ClusterList(ids.to_vec()));
    });
    route
}

async fn evpn_rr_client_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: Ipv4Addr,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: IpAddr::V4(peer),
        peer_asn: 65000,
        peer_router_id: peer,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
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
    drain_eor(&mut out_rx).await;
    out_rx
}

async fn evpn_routes_received(tx: &mpsc::Sender<RibUpdate>, peer: Ipv4Addr, route: EvpnRibRoute) {
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![route],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
}

async fn next_evpn_announce_next_hop(
    out_rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    what: &str,
) -> IpAddr {
    let msg = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .unwrap_or_else(|_| panic!("{what}: expected an EVPN announce within 2s"))
        .expect("outbound channel open");
    assert_eq!(
        msg.evpn_announce.len(),
        1,
        "{what}: {:?}",
        msg.evpn_announce
    );
    msg.evpn_announce[0].next_hop
}

/// A locally injected EVPN route has no BGP Identifier, so the identifier
/// step ranks it ahead of a received route for the same key — even one
/// with a shorter `CLUSTER_LIST` — and the reflector's other client
/// switches to the injected route.
#[tokio::test]
async fn inject_evpn_local_route_ranks_first_at_identifier_step() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = Ipv4Addr::new(10, 0, 0, 1);
    let client = Ipv4Addr::new(10, 0, 0, 2);
    let _source_rx = evpn_rr_client_up(&tx, source).await;
    let mut client_rx = evpn_rr_client_up(&tx, client).await;

    // Same key from a client, no CLUSTER_LIST.
    let mac = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x07];
    let received = make_evpn_macip(source, mac, None, false);
    let key = received.key();
    evpn_routes_received(&tx, source, received).await;
    assert_eq!(
        next_evpn_announce_next_hop(&mut client_rx, "received route").await,
        IpAddr::V4(source)
    );

    let mut local = make_evpn_macip(Ipv4Addr::UNSPECIFIED, mac, None, false);
    local.origin_type = crate::route::RouteOrigin::Local;
    let local = with_evpn_cluster_list(local, &[Ipv4Addr::new(10, 0, 0, 200)]);
    assert_eq!(local.key(), key);
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::InjectEvpn {
        route: local,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx
        .await
        .expect("inject reply")
        .expect("inject succeeds");
    assert_eq!(
        next_evpn_announce_next_hop(&mut client_rx, "injected route replaces received").await,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    );

    drop(tx);
    handle.await.unwrap();
}

/// Between two received EVPN routes for one key, the lower advertising
/// BGP Identifier decides before `CLUSTER_LIST` length, so the reflector
/// switches its clients to the route from the lower identifier even
/// though it carries the longer list.
#[tokio::test]
async fn evpn_lower_identifier_reflected_over_shorter_cluster_list() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let low_id = Ipv4Addr::new(10, 0, 0, 1);
    let high_id = Ipv4Addr::new(10, 0, 0, 2);
    let client = Ipv4Addr::new(10, 0, 0, 3);
    let _low_rx = evpn_rr_client_up(&tx, low_id).await;
    let _high_rx = evpn_rr_client_up(&tx, high_id).await;
    let mut client_rx = evpn_rr_client_up(&tx, client).await;

    let mac = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x08];
    let short_list = with_evpn_cluster_list(
        make_evpn_macip(high_id, mac, None, false),
        &[Ipv4Addr::new(10, 0, 0, 200)],
    );
    let long_list = with_evpn_cluster_list(
        make_evpn_macip(low_id, mac, None, false),
        &[Ipv4Addr::new(10, 0, 0, 200), Ipv4Addr::new(10, 0, 0, 201)],
    );
    assert_eq!(short_list.key(), long_list.key());

    evpn_routes_received(&tx, high_id, short_list).await;
    assert_eq!(
        next_evpn_announce_next_hop(&mut client_rx, "first route").await,
        IpAddr::V4(high_id)
    );

    evpn_routes_received(&tx, low_id, long_list).await;
    assert_eq!(
        next_evpn_announce_next_hop(&mut client_rx, "lower identifier becomes best").await,
        IpAddr::V4(low_id)
    );

    drop(tx);
    handle.await.unwrap();
}

/// RFC 8214 §4: a single-homed VPWS per-EVI Ethernet A-D route carries
/// ESI 0. Decoded from the wire, it is reflected to another client with
/// byte-identical NLRI, and its withdrawal follows.
#[tokio::test]
async fn zero_esi_vpws_ead_per_evi_reflects_byte_identically() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = Ipv4Addr::new(10, 0, 0, 1);
    let client = Ipv4Addr::new(10, 0, 0, 2);
    let _source_rx = evpn_rr_client_up(&tx, source).await;
    let mut client_rx = evpn_rr_client_up(&tx, client).await;

    let mut wire = vec![1, 25, 0, 0, 0xFD, 0xE8, 0, 0, 0, 100]; // RD 65000:100
    wire.extend([0; 10]); // ESI 0: single-homed
    wire.extend([0, 0, 0, 100]); // VPWS service instance 100
    wire.extend([0, 0x06, 0x41]); // label 100, bottom of stack
    let mut routes = rustbgpd_wire::decode_evpn_nlri(&wire).unwrap();
    assert!(matches!(routes[..], [EvpnRoute::EadPerEvi(_)]));
    let mut received = make_evpn_macip(source, [0; 6], None, false);
    received.route = routes.remove(0);
    let key = received.key();
    evpn_routes_received(&tx, source, received).await;

    let msg = tokio::time::timeout(Duration::from_secs(2), client_rx.recv())
        .await
        .expect("client should receive the reflection within 2s")
        .expect("outbound channel open");
    assert_eq!(msg.evpn_announce.len(), 1);
    let mut reflected = Vec::new();
    rustbgpd_wire::encode_evpn_nlri(&[msg.evpn_announce[0].route.clone()], &mut reflected).unwrap();
    assert_eq!(reflected, wire);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![key],
        validated_with: None,
    })
    .await
    .unwrap();
    let msg = tokio::time::timeout(Duration::from_secs(2), client_rx.recv())
        .await
        .expect("client should receive the withdrawal within 2s")
        .expect("outbound channel open");
    assert!(msg.evpn_announce.is_empty());
    assert_eq!(msg.evpn_withdraw, vec![key]);

    drop(tx);
    handle.await.unwrap();
}

/// RFC 9135 §9.1.1 / RFC 7432 §7.2: a Type 2 with MAC Address Length 0 is
/// treat-as-withdraw, and its key is not the 48-bit route's. Applying the
/// revised parser's treat-as-withdraw keys for an UPDATE carrying it next
/// to a valid sibling withdraws only the sibling from a reflection client;
/// the peer's 48-bit route for the same MAC is still reflected state.
#[tokio::test]
async fn zero_length_mac_type2_withdraws_only_its_siblings_from_clients() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = Ipv4Addr::new(10, 0, 0, 1);
    let client = Ipv4Addr::new(10, 0, 0, 2);
    let _source_rx = evpn_rr_client_up(&tx, source).await;
    let mut client_rx = evpn_rr_client_up(&tx, client).await;
    let mac = make_evpn_macip(source, [0, 0x11, 0x22, 0x33, 0x44, 0x55], None, false);
    let sibling = make_evpn_macip(source, [0, 0x11, 0x22, 0x33, 0x44, 0x66], None, false);
    for route in [&mac, &sibling] {
        evpn_routes_received(&tx, source, route.clone()).await;
        let msg = tokio::time::timeout(Duration::from_secs(2), client_rx.recv())
            .await
            .expect("client should receive the reflection within 2s")
            .expect("outbound channel open");
        assert_eq!(msg.evpn_announce.len(), 1);
    }

    let mut nlri = Vec::new();
    rustbgpd_wire::encode_evpn_nlri(&[mac.route.clone(), sibling.route.clone()], &mut nlri)
        .unwrap();
    assert_eq!(nlri[24], 48);
    nlri[24] = 0; // first route: MAC Address Length 0
    let mut value = vec![0, 25, 70, 4, 10, 0, 0, 1, 0];
    value.extend(nlri);
    let mut attributes = vec![0x40, 1, 1, 0, 0x40, 2, 0, 0x90, 14];
    attributes.extend(u16::try_from(value.len()).unwrap().to_be_bytes());
    attributes.extend(value);
    let parsed = rustbgpd_wire::UpdateMessage {
        withdrawn_routes: bytes::Bytes::new(),
        path_attributes: bytes::Bytes::from(attributes),
        nlri: bytes::Bytes::new(),
    }
    .parse_revised(true, true, false, &[])
    .expect("zero-length MAC must not be session-reset");
    assert_eq!(parsed.malformed.len(), 1);
    let withdrawn: Vec<_> = parsed
        .update
        .attributes
        .iter()
        .filter_map(|attr| match attr {
            PathAttribute::MpReachNlri(mp) => Some(mp.evpn_announced.iter().map(EvpnRoute::key)),
            _ => None,
        })
        .flatten()
        .collect();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: withdrawn,
        validated_with: None,
    })
    .await
    .unwrap();
    let msg = tokio::time::timeout(Duration::from_secs(2), client_rx.recv())
        .await
        .expect("client should receive the withdrawal within 2s")
        .expect("outbound channel open");
    assert!(msg.evpn_announce.is_empty());
    assert_eq!(msg.evpn_withdraw, vec![sibling.key()]);

    // The 48-bit route was never withdrawn: withdrawing it now reaches the
    // client.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![mac.key()],
        validated_with: None,
    })
    .await
    .unwrap();
    let msg = tokio::time::timeout(Duration::from_secs(2), client_rx.recv())
        .await
        .expect("client should receive the 48-bit withdrawal within 2s")
        .expect("outbound channel open");
    assert_eq!(msg.evpn_withdraw, vec![mac.key()]);

    drop(tx);
    handle.await.unwrap();
}

/// Withdrawing an unknown EVPN key surfaces a user-visible error
/// (controller got a bad route identifier).
#[tokio::test]
async fn withdraw_evpn_unknown_key_returns_error() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let fake_key = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 999).key();
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::WithdrawEvpn {
        key: fake_key,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let result = reply_rx.await.expect("withdraw reply");
    assert!(result.is_err(), "unknown key must return an error");

    drop(tx);
    handle.await.unwrap();
}

/// Regression: a peer that joins AFTER the EVPN Loc-RIB has been
/// populated must receive the existing routes in its initial dump.
/// Prior to the fix, `send_initial_table` never called
/// `stage_evpn_routes` and hardcoded `evpn_announce: vec![]`, so a
/// late-joining VTEP saw an EVPN End-of-RIB with zero routes and
/// cleared any stale state — operating with no EVPN reachability for
/// the existing fabric until unrelated RIB churn forced redistribution.
/// The M30-M33 harnesses miss this because they bring up peers before
/// any EVPN advertisements; production VTEPs reconnect into a
/// converged fabric all the time.
#[tokio::test]
async fn late_joining_peer_receives_existing_evpn_routes_in_initial_dump() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let early = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (early_out_tx, mut early_out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: early,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: early_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
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
    drain_eor(&mut early_out_rx).await;

    // Early peer advertises a Type 3 IMET — this populates the RR's
    // EVPN Loc-RIB before the late peer connects.
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet_key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: early,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    // Drain side-effects so the early peer's reflection (if any) is
    // processed before we register the late peer.
    let _ = query_evpn_routes(&tx).await;

    // Now a late-joining peer connects to the same RR.
    let late = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (late_out_tx, mut late_out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: late,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: late_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
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

    // First message to the late peer must be the initial dump carrying
    // the existing EVPN route. Without the fix this is just an empty
    // EoR and the route is silently absent.
    let msg = tokio::time::timeout(Duration::from_secs(2), late_out_rx.recv())
        .await
        .expect("late peer should receive an outbound update within 2s")
        .expect("outbound channel open");

    assert_eq!(
        msg.evpn_announce.len(),
        1,
        "late-joining peer must see the existing EVPN route in initial dump"
    );
    assert_eq!(msg.evpn_announce[0].key(), imet_key);

    drop(tx);
    handle.await.unwrap();
}

/// Regression: RFC 7313 Enhanced Route Refresh on the L2VPN/EVPN family
/// must remove re-advertised keys from the per-peer stale set, otherwise
/// `EoRR` sweeps every reflected EVPN route off the RIB. The unicast and
/// `FlowSpec` chunks already do this; the EVPN chunks were missing the
/// hook entirely.
#[tokio::test]
async fn enhanced_route_refresh_evpn_replacement_preserves_route() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // Stage 1: peer advertises one EVPN Type 3 IMET route.
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet_key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet.clone()],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    // Stage 2: peer initiates ERR for L2VPN/EVPN. The manager snapshots
    // imet_key into refresh_stale_evpn[peer] at this point.
    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::L2Vpn,
        safi: Safi::Evpn,
    })
    .await
    .unwrap();

    // Quiesce the manager so the BoRR snapshot lands before the
    // re-advertisement races it.
    let _drain = query_evpn_routes(&tx).await;

    // Stage 3: peer re-advertises the same key — must remove it from
    // the stale set. Without the fix this is a no-op on the stale set.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    // Stage 4: peer ends the refresh window. EoRR sweeps anything left
    // in the stale set; with the fix that set is empty, so the route
    // survives. Without the fix, the route gets withdrawn here.
    tx.send(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::L2Vpn,
        safi: Safi::Evpn,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 1, "refreshed EVPN route must survive EoRR");
    assert_eq!(best[0].key(), imet_key);

    drop(tx);
    handle.await.unwrap();
}

/// EVPN honors source-route `NO_EXPORT` only for eBGP peers that enable RFC
/// 1997 interpretation. The source gate precedes policy, while a policy-added
/// community remains part of the delivered route.
///
/// Break-to-red: deleting or moving the EVPN source predicate after policy
/// fails to emit the exact withdrawal after the removal policy strips the
/// community, leaving the prior Adj-RIB-Out entry stale; checking every peer
/// suppresses the transparent and iBGP announcements; checking the post-policy
/// route suppresses the policy-added announcement.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one actor sequence pins honor, transparent, iBGP, policy, and exact-withdrawal semantics"
)]
async fn evpn_no_export_honors_neighbor_mode_and_source_precedence() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let honor: IpAddr = "192.0.2.110".parse().unwrap();
    let transparent: IpAddr = "192.0.2.111".parse().unwrap();
    let internal: IpAddr = "192.0.2.112".parse().unwrap();
    let policy_adder: IpAddr = "192.0.2.113".parse().unwrap();
    let marker = (65000u32 << 16) | 0x01D2;

    let mut honor_rx = evpn_export_peer_up(
        &tx,
        honor,
        true,
        true,
        Some(evpn_no_export_policy(
            rustbgpd_wire::COMMUNITY_NO_EXPORT,
            false,
            true,
        )),
    )
    .await;
    let mut transparent_rx = evpn_export_peer_up(&tx, transparent, true, false, None).await;
    let mut internal_rx = evpn_export_peer_up(&tx, internal, false, true, None).await;
    let mut adder_rx = evpn_export_peer_up(
        &tx,
        policy_adder,
        true,
        true,
        Some(evpn_no_export_policy(marker, true, false)),
    )
    .await;

    let source_addr = Ipv4Addr::new(198, 51, 100, 110);
    let source = IpAddr::V4(source_addr);
    let mut policy_added_route = with_evpn_community(make_evpn_imet(source_addr, 510), marker);
    policy_added_route.origin_type = crate::route::RouteOrigin::Ebgp;
    let added_key = policy_added_route.key();
    let mut primary = make_evpn_imet(source_addr, 520);
    primary.origin_type = crate::route::RouteOrigin::Ebgp;
    let primary_key = primary.key();
    let mut sibling = make_evpn_imet(source_addr, 530);
    sibling.origin_type = crate::route::RouteOrigin::Ebgp;
    let sibling_key = sibling.key();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![policy_added_route, primary.clone(), sibling],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    let _ = query_evpn_routes(&tx).await;

    for out_rx in [&mut honor_rx, &mut transparent_rx, &mut internal_rx] {
        let update = out_rx.try_recv().expect("plain EVPN routes advertise");
        assert_eq!(update.evpn_announce.len(), 3);
        assert_eq!(update.evpn_withdraw.len(), 0);
    }
    let added_update = adder_rx
        .try_recv()
        .expect("policy-added NO_EXPORT EVPN route is delivered");
    let added_route = added_update
        .evpn_announce
        .iter()
        .find(|route| route.key() == added_key)
        .expect("marker route is present in the policy-modified update");
    assert!(
        added_route
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_NO_EXPORT),
        "policy-added NO_EXPORT must remain on the delivered EVPN route"
    );

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![with_evpn_community(
            primary,
            rustbgpd_wire::COMMUNITY_NO_EXPORT,
        )],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    let _ = query_evpn_routes(&tx).await;

    let honor_update = honor_rx
        .try_recv()
        .expect("honor-mode eBGP peer receives exact withdrawal");
    assert!(honor_update.evpn_announce.is_empty());
    assert_eq!(honor_update.evpn_withdraw, vec![primary_key]);
    for out_rx in [&mut transparent_rx, &mut internal_rx] {
        let update = out_rx
            .try_recv()
            .expect("transparent and iBGP peers retain the tagged route");
        assert_eq!(update.evpn_announce.len(), 1);
        assert_eq!(update.evpn_announce[0].key(), primary_key);
        assert_eq!(update.evpn_withdraw.len(), 0);
    }
    assert!(honor_rx.try_recv().is_err(), "sibling must not churn");
    assert_ne!(primary_key, sibling_key, "fixture keys must be distinct");

    drop(tx);
    handle.await.unwrap();
}

/// Source `NO_ADVERTISE` is enforced before export policy, withdraws only the
/// exact prior EVPN key, and recovers without disturbing a sibling route.
///
/// Break-to-red: deleting the pre-policy guard lets the targeted removal policy
/// export the first-seen scoped route; removing the existing-state membership
/// check emits a withdrawal for that unknown route; omitting or broadening the
/// withdrawal fails the exact-key and sibling assertions; sticky suppression
/// prevents the recovery announcement.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one ordered actor scenario proves source precedence, silence, exact withdrawal, and recovery"
)]
async fn evpn_source_no_advertise_cannot_be_removed_by_export_policy() {
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
        export_policy: Some(evpn_no_advertise_policy(
            rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
            false,
            true,
        )),
        sendable_families: evpn_sendable(),
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

    let first_seen = with_evpn_community(
        make_evpn_imet(source, 99),
        rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
    );
    for attempt in 0..2 {
        let mut scoped = first_seen.clone();
        if attempt > 0 {
            AttrSet::edit(&mut scoped.attributes, |attrs| {
                attrs.push(PathAttribute::Med(attempt));
            });
        }
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: source_ip,
            announced: vec![],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![scoped],
            evpn_withdrawn: vec![],
            validated_with: None,
        })
        .await
        .unwrap();
        let _ = query_evpn_routes(&tx).await;
        assert!(
            out_rx.try_recv().is_err(),
            "first-seen and repeated source-scoped EVPN routes stay silent"
        );
    }

    let primary = make_evpn_imet(source, 100);
    let sibling = make_evpn_imet(source, 200);
    let primary_key = primary.key();
    let sibling_key = sibling.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source_ip,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![primary.clone(), sibling],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    let _ = query_evpn_routes(&tx).await;
    let initial = out_rx.try_recv().expect("plain EVPN routes must advertise");
    assert_eq!(initial.evpn_announce.len(), 2);
    assert!(
        initial
            .evpn_announce
            .iter()
            .any(|route| route.key() == primary_key)
    );
    assert!(
        initial
            .evpn_announce
            .iter()
            .any(|route| route.key() == sibling_key)
    );

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source_ip,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![with_evpn_community(
            primary.clone(),
            rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
        )],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    let _ = query_evpn_routes(&tx).await;
    let scoped = out_rx
        .try_recv()
        .expect("source NO_ADVERTISE must withdraw the prior EVPN route");
    assert!(scoped.evpn_announce.is_empty());
    assert_eq!(scoped.evpn_withdraw, vec![primary_key]);

    let recovered_primary = with_evpn_community(primary, (65000u32 << 16) | 0x01BD);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source_ip,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![recovered_primary],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    let _ = query_evpn_routes(&tx).await;
    let recovered = out_rx
        .try_recv()
        .expect("removing source NO_ADVERTISE must re-announce EVPN");
    assert_eq!(recovered.evpn_announce.len(), 1);
    assert_eq!(recovered.evpn_announce[0].key(), primary_key);
    assert_eq!(recovered.evpn_withdraw.len(), 0);
    assert!(
        out_rx.try_recv().is_err(),
        "sibling EVPN route must not churn"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Policy-added `NO_ADVERTISE` suppresses first-seen EVPN routes, withdraws
/// only an exact prior advertisement, and recovers when policy scope is removed.
///
/// Break-to-red: deleting the post-policy guard announces the scoped route;
/// removing the existing-state membership check emits a first-seen withdrawal;
/// omitting or broadening the withdrawal fails the exact-key and sibling
/// assertions; sticky suppression prevents either recovery announcement.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one ordered actor scenario proves policy-added suppression, silence, exact withdrawal, and recovery"
)]
async fn evpn_policy_added_no_advertise_withdraws_exact_prior() {
    let marker = (65000u32 << 16) | 0x01BC;
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let source = Ipv4Addr::new(198, 51, 100, 12);
    let source_ip = IpAddr::V4(source);
    let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 32));
    let (out_tx, mut out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: target,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: Some(evpn_no_advertise_policy(marker, true, false)),
        sendable_families: evpn_sendable(),
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

    let primary = with_evpn_community(make_evpn_imet(source, 300), marker);
    let sibling = make_evpn_imet(source, 400);
    let primary_key = primary.key();
    let sibling_key = sibling.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source_ip,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![primary.clone(), sibling],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    let _ = query_evpn_routes(&tx).await;
    let first_seen = out_rx
        .try_recv()
        .expect("unscoped EVPN sibling must advertise");
    assert_eq!(first_seen.evpn_announce.len(), 1);
    assert_eq!(first_seen.evpn_announce[0].key(), sibling_key);
    assert_eq!(first_seen.evpn_withdraw.len(), 0);

    let mut repeated = primary.clone();
    AttrSet::edit(&mut repeated.attributes, |attrs| {
        attrs.push(PathAttribute::Med(50));
    });
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source_ip,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![repeated],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    let _ = query_evpn_routes(&tx).await;
    assert!(
        out_rx.try_recv().is_err(),
        "repeated policy-scoped EVPN route stays silent"
    );

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: target,
        export_policy: Some(evpn_no_advertise_policy(marker, false, false)),
        reply,
    })
    .await
    .unwrap();
    response.await.unwrap().unwrap();
    let _ = query_evpn_routes(&tx).await;
    let recovered = out_rx
        .try_recv()
        .expect("removing policy-added NO_ADVERTISE must announce EVPN");
    assert_eq!(recovered.evpn_announce.len(), 1);
    assert_eq!(recovered.evpn_announce[0].key(), primary_key);
    assert_eq!(recovered.evpn_withdraw.len(), 0);

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: target,
        export_policy: Some(evpn_no_advertise_policy(marker, true, false)),
        reply,
    })
    .await
    .unwrap();
    response.await.unwrap().unwrap();
    let _ = query_evpn_routes(&tx).await;
    let scoped = out_rx
        .try_recv()
        .expect("policy-added NO_ADVERTISE must withdraw prior EVPN");
    assert!(scoped.evpn_announce.is_empty());
    assert_eq!(scoped.evpn_withdraw, vec![primary_key]);

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: target,
        export_policy: Some(evpn_no_advertise_policy(marker, false, false)),
        reply,
    })
    .await
    .unwrap();
    response.await.unwrap().unwrap();
    let _ = query_evpn_routes(&tx).await;
    let recovered_again = out_rx
        .try_recv()
        .expect("EVPN must recover after repeated policy scope");
    assert_eq!(recovered_again.evpn_announce.len(), 1);
    assert_eq!(recovered_again.evpn_announce[0].key(), primary_key);
    assert_eq!(recovered_again.evpn_withdraw.len(), 0);
    assert!(
        out_rx.try_recv().is_err(),
        "sibling EVPN route must not churn"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Regression: EVPN export-policy `RouteModifications` (community add,
/// `LocalPref` override, etc.) must be applied to the announced route.
/// Before the fix, `evaluate_chain`'s result was checked for Permit/Deny
/// but `result.modifications` was discarded, so RT/community/`LocalPref`
/// rewrite policy silently had no effect on EVPN exports.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "EVPN export-policy regression keeps route setup and modification assertions together"
)]
async fn evpn_export_policy_applies_modifications() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

    // Permit-all with a community-add side effect.
    let added_community: u32 = (65000u32 << 16) | 0x3E7;
    let mut mods = RouteModifications::default();
    mods.communities_add.push(added_community);
    let export_policy = PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Permit,
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
            modifications: mods,
        }],
        default_action: PolicyAction::Permit,
    }]);

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(
        rx,
        dummy_query_rx(),
        Some(export_policy),
        cluster_id,
        BgpMetrics::new(),
    );
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
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
    drain_eor(&mut out_rx).await;

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
        sendable_families: evpn_sendable(),
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

    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let announce = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("target should receive EVPN announce within 2s")
        .expect("outbound channel open");
    assert_eq!(announce.evpn_announce.len(), 1);

    let attrs = announce.evpn_announce[0].attributes.as_ref();
    let comms_attr = attrs
        .iter()
        .find_map(|a| {
            if let PathAttribute::Communities(c) = a {
                Some(c)
            } else {
                None
            }
        })
        .expect("export policy must add Communities attribute when modifications include communities_add");
    assert!(
        comms_attr.contains(&added_community),
        "added community {added_community:#x} must appear on the reflected EVPN route"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the route batch literal carries every supported family as one transaction"
)]
async fn partial_pmsi_survives_type3_imet_distribution_and_wire_encoding() {
    let (tx, rx) = mpsc::channel(32);
    let manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 100)),
        BgpMetrics::new(),
    );
    let handle = tokio::spawn(manager.run());
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: target,
        peer_asn: 65_000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
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
    drain_eor(&mut out_rx).await;

    let (source_tx, mut source_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: source,
        peer_asn: 65_000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
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
    drain_eor(&mut source_rx).await;

    let mut imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    imet.attributes = AttrSet::new(vec![PathAttribute::PmsiTunnelPartial(
        rustbgpd_wire::PmsiTunnel::for_evpn_ingress_replication(100, source),
    )]);
    let imet_key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    let _ = query_evpn_routes(&tx).await;

    let update = out_rx.try_recv().expect("Type 3 IMET is distributed");
    let advertised = update
        .evpn_announce
        .first()
        .expect("one Type 3 IMET announced");
    assert_eq!(advertised.key(), imet_key);
    assert!(
        advertised
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, PathAttribute::PmsiTunnelPartial(_)))
    );
    let mut wire = Vec::new();
    rustbgpd_wire::attribute::encode_path_attributes(
        &advertised.attributes,
        &mut wire,
        true,
        false,
    )
    .unwrap();
    let pmsi_frame = [0xe0, 22, 9, 0, 6, 0, 0, 100, 10, 0, 0, 1];
    assert!(
        wire.windows(pmsi_frame.len())
            .any(|window| window == pmsi_frame)
    );

    drop(tx);
    handle.await.unwrap();
}

/// Regression: `PendingRoutesReceived::has_more()` previously omitted
/// the EVPN iterators, so a `RoutesReceived` carrying more than
/// `ROUTES_RECEIVED_CHUNK_SIZE` EVPN routes had everything past the
/// first chunk silently dropped at distribution.rs's `if has_more()
/// push_front` re-enqueue site. This test drains a 2-chunk-sized batch
/// of EVPN announces and verifies every route appears in the chunk
/// stream.
#[test]
fn pending_routes_received_drains_full_evpn_announce_batch() {
    let total = ROUTES_RECEIVED_CHUNK_SIZE * 2 + 7;
    let peer = Ipv4Addr::new(192, 0, 2, 1);
    let evpn_announced: Vec<EvpnRibRoute> = (0..u32::try_from(total).unwrap())
        .map(|tag| make_evpn_imet(peer, tag))
        .collect();

    let mut pending = PendingRoutesReceived::new(
        IpAddr::V4(peer),
        vec![],
        vec![],
        vec![],
        vec![],
        evpn_announced,
        vec![],
        None,
    );

    let mut drained: usize = 0;
    let mut last_was_evpn = false;
    while let Some(chunk) = pending.next_chunk() {
        match chunk {
            PendingRouteChunk::EvpnAnnounced(routes) => {
                drained += routes.len();
                last_was_evpn = true;
            }
            PendingRouteChunk::EvpnWithdrawn(routes) => {
                drained += routes.len();
                last_was_evpn = true;
            }
            _ => last_was_evpn = false,
        }
    }
    assert!(last_was_evpn, "final chunk must be EVPN");
    assert_eq!(
        drained, total,
        "every EVPN route must be drained; has_more() must keep the batch alive"
    );
    assert!(
        !pending.has_more(),
        "after full drain, has_more() must report false"
    );
}

/// Regression: same drain check for EVPN withdrawals, since they also
/// flow through the `evpn_withdrawn` iterator and `has_more()`.
#[test]
fn pending_routes_received_drains_full_evpn_withdraw_batch() {
    let total = ROUTES_RECEIVED_CHUNK_SIZE + 1;
    let peer = Ipv4Addr::new(192, 0, 2, 2);
    let withdrawn: Vec<rustbgpd_wire::EvpnRouteKey> = (0..u32::try_from(total).unwrap())
        .map(|tag| make_evpn_imet(peer, tag).key())
        .collect();

    let mut pending = PendingRoutesReceived::new(
        IpAddr::V4(peer),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        withdrawn,
        None,
    );

    let mut drained: usize = 0;
    while let Some(chunk) = pending.next_chunk() {
        if let PendingRouteChunk::EvpnWithdrawn(keys) = chunk {
            drained += keys.len();
        }
    }
    assert_eq!(drained, total);
    assert!(!pending.has_more());
}

// --- EVPN route event streaming tests (Gate 7c) ---

/// Build a Type 2 (`MacIp`) `EvpnRibRoute` carrying an optional MAC
/// Mobility extended community. Tests use this to simulate received
/// routes with varying mobility sequences.
pub(super) fn make_evpn_macip(
    peer: Ipv4Addr,
    mac: [u8; 6],
    mobility_seq: Option<u32>,
    sticky: bool,
) -> EvpnRibRoute {
    let route = EvpnRoute::MacIp(EvpnMacIp {
        rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 100]),
        esi: EthernetSegmentIdentifier::ZERO,
        ethernet_tag: EthernetTagId(100),
        mac: MacAddress::new(mac),
        ip: None,
        label1: MplsLabel::new(100),
        label2: None,
    });

    let mut attrs: Vec<PathAttribute> = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::NextHop(peer),
    ];
    if let Some(seq) = mobility_seq {
        attrs.push(PathAttribute::ExtendedCommunities(vec![
            ExtendedCommunity::mac_mobility(sticky, seq),
        ]));
    }

    EvpnRibRoute {
        route,
        next_hop: IpAddr::V4(peer),
        link_local_next_hop: None,
        peer: IpAddr::V4(peer),
        attributes: AttrSet::new(attrs),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: peer,
        is_stale: false,
        is_llgr_stale: false,
    }
}

async fn subscribe_evpn_events(
    tx: &mpsc::Sender<RibUpdate>,
) -> tokio::sync::broadcast::Receiver<Arc<crate::event::EvpnRouteEvent>> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::SubscribeEvpnRouteEvents { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap()
}

#[derive(Default)]
struct SharedEvpnCapture(std::sync::Mutex<Option<Arc<crate::event::EvpnRouteEvent>>>);

impl crate::event_sink::RibEventSink for SharedEvpnCapture {
    fn publish_route_event(&self, _event: &Arc<crate::event::RouteEvent>) {}

    fn publish_evpn_event(&self, event: &Arc<crate::event::EvpnRouteEvent>) {
        *self.0.lock().unwrap() = Some(Arc::clone(event));
    }
}

#[test]
fn evpn_history_and_live_broadcast_share_arc() {
    let (_tx, rx) = mpsc::channel(1);
    let capture = Arc::new(SharedEvpnCapture::default());
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_event_sink(capture.clone());
    let mut live = manager.evpn_events_tx.subscribe();
    let route = make_evpn_macip(
        Ipv4Addr::new(10, 0, 0, 1),
        [0x02, 0, 0, 0, 0, 1],
        None,
        false,
    );
    manager.publish_evpn_route_event(crate::event::EvpnRouteEvent {
        event_type: RouteEventType::Added,
        key: route.key(),
        peer: Some(route.peer),
        previous_peer: None,
        best: Some(route),
        previous_best: None,
        timestamp: "1".to_string(),
    });

    let broadcast = live.try_recv().unwrap();
    let captured = capture.0.lock().unwrap().take().unwrap();
    assert!(Arc::ptr_eq(
        manager.evpn_route_event_history.back().unwrap(),
        &broadcast
    ));
    assert!(Arc::ptr_eq(&captured, &broadcast));

    let (reply, result) = oneshot::channel();
    manager.handle_query_evpn_route_event_history(None, None, None, &BTreeSet::new(), 0, reply);
    let mut owned = result.blocking_recv().unwrap();
    owned[0].timestamp = "caller mutation".to_string();
    assert_eq!(
        manager.evpn_route_event_history.back().unwrap().timestamp,
        "1"
    );
}

async fn query_evpn_event_history(
    tx: &mpsc::Sender<RibUpdate>,
    peer: Option<IpAddr>,
    route_type: Option<u8>,
    rd: Option<RouteDistinguisher>,
    event_types: BTreeSet<RouteEventType>,
    limit: usize,
) -> Vec<crate::event::EvpnRouteEvent> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryEvpnRouteEventHistory {
        peer,
        route_type,
        rd,
        event_types,
        limit,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap()
}

#[tokio::test]
async fn evpn_route_event_added_on_new_best() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mut events_rx = subscribe_evpn_events(&tx).await;

    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    let route = make_evpn_macip(
        peer_addr,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        Some(0),
        false,
    );
    let key = route.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![route],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let event = tokio::time::timeout(Duration::from_secs(2), events_rx.recv())
        .await
        .expect("EVPN broadcast should deliver event within 2s")
        .expect("broadcast not closed");
    assert_eq!(event.event_type, crate::event::RouteEventType::Added);
    assert_eq!(event.key, key);
    assert_eq!(event.peer, Some(peer));
    assert!(event.previous_peer.is_none());
    assert!(event.best.is_some(), "Added must carry a best path");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_event_history_records_events_without_subscriber() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    let route = make_evpn_macip(
        peer_addr,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x77],
        Some(0),
        false,
    );
    let key = route.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![route],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let history = query_evpn_event_history(&tx, None, Some(2), None, BTreeSet::new(), 10).await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].event_type, RouteEventType::Added);
    assert_eq!(history[0].key, key);
    assert_eq!(history[0].peer, Some(peer));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_event_history_filters_peer_rd_type_and_limit() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mac = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x02];
    let peer1_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer2_addr = Ipv4Addr::new(10, 0, 0, 2);
    let peer1 = IpAddr::V4(peer1_addr);
    let peer2 = IpAddr::V4(peer2_addr);
    let route1 = make_evpn_macip(peer1_addr, mac, Some(0), false);
    let rd = crate::event::evpn_key_rd(&route1.key()).expect("MAC/IP key carries an RD");

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![route1],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer2,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![make_evpn_macip(peer2_addr, mac, Some(1), false)],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let mut event_types = BTreeSet::new();
    event_types.insert(RouteEventType::BestChanged);
    let history =
        query_evpn_event_history(&tx, Some(peer1), Some(2), Some(rd), event_types, 1).await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].event_type, RouteEventType::BestChanged);
    assert_eq!(history[0].peer, Some(peer2));
    assert_eq!(history[0].previous_peer, Some(peer1));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_event_history_capacity_evicts_oldest_event() {
    let (tx, rx) = mpsc::channel(256);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    for index in 0..=EVPN_ROUTE_EVENT_HISTORY_CAPACITY {
        let index_bytes = u32::try_from(index)
            .expect("test history capacity fits in u32")
            .to_be_bytes();
        let mac = [
            0x02,
            0x00,
            0x00,
            index_bytes[1],
            index_bytes[2],
            index_bytes[3],
        ];
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer,
            announced: vec![],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![make_evpn_macip(peer_addr, mac, Some(0), false)],
            evpn_withdrawn: vec![],
            validated_with: None,
        })
        .await
        .unwrap();
    }

    let history = query_evpn_event_history(&tx, None, Some(2), None, BTreeSet::new(), 0).await;
    assert_eq!(history.len(), EVPN_ROUTE_EVENT_HISTORY_CAPACITY);
    assert_eq!(history[0].key.route_type(), 2);
    let rustbgpd_wire::EvpnRouteKey::MacIp { mac: first_mac, .. } = history[0].key else {
        panic!("expected Type 2 key");
    };
    assert_eq!(first_mac.octets(), [0x02, 0x00, 0x00, 0, 0, 1]);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_route_event_best_changed_on_higher_mobility() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mac = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01];
    let original_peer = Ipv4Addr::new(10, 0, 0, 1);
    let new_peer = Ipv4Addr::new(10, 0, 0, 2);

    // First peer originates with seq=0.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(original_peer),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![make_evpn_macip(original_peer, mac, Some(0), false)],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    // Subscribe after the initial Added event so the next event we
    // observe is the contended best-path move.
    let mut events_rx = subscribe_evpn_events(&tx).await;

    // Second peer originates the same MAC with a higher mobility seq.
    // Best-path tiebreak (RFC 7432 §15.1) prefers the higher seq.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(new_peer),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![make_evpn_macip(new_peer, mac, Some(1), false)],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let event = tokio::time::timeout(Duration::from_secs(2), events_rx.recv())
        .await
        .expect("EVPN broadcast should deliver event within 2s")
        .expect("broadcast not closed");
    assert_eq!(event.event_type, crate::event::RouteEventType::BestChanged);
    assert_eq!(event.peer, Some(IpAddr::V4(new_peer)));
    assert_eq!(event.previous_peer, Some(IpAddr::V4(original_peer)));
    let best = event
        .best
        .as_ref()
        .expect("BestChanged must carry a best path");
    assert_eq!(best.peer, IpAddr::V4(new_peer));
    let prior = event
        .previous_best
        .as_ref()
        .expect("BestChanged must carry the prior best path");
    assert_eq!(prior.peer, IpAddr::V4(original_peer));

    drop(tx);
    handle.await.unwrap();
}

/// A locally originated MAC+IP route re-injected under the same key
/// with a higher MAC Mobility sequence (the RFC 9721 §5.1/§6.2
/// local-move cascade) is a best-path change for that key, not a
/// silent replace: subscribers see `BestChanged` carrying the new
/// sequence, with the local originator on both sides.
#[tokio::test]
async fn evpn_route_event_best_changed_on_local_mac_ip_reinject_with_higher_mobility() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mac = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x09];
    let local_macip = |seq| {
        let mut route = make_evpn_macip(Ipv4Addr::UNSPECIFIED, mac, Some(seq), false);
        route.origin_type = crate::route::RouteOrigin::Local;
        if let EvpnRoute::MacIp(ref mut macip) = route.route {
            macip.ip = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
        }
        route
    };
    let inject = |route: EvpnRibRoute| {
        let tx = tx.clone();
        async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(RibUpdate::InjectEvpn {
                route,
                reply: reply_tx,
            })
            .await
            .unwrap();
            reply_rx
                .await
                .expect("inject reply")
                .expect("inject succeeds");
        }
    };

    let first = local_macip(0);
    let key = first.key();
    inject(first).await;

    // Subscribe after the initial Added so the next event is the
    // re-inject.
    let mut events_rx = subscribe_evpn_events(&tx).await;

    let second = local_macip(1);
    assert_eq!(second.key(), key, "re-inject must reuse the same key");
    let expected_attrs = second.attributes.clone();
    inject(second).await;

    let event = tokio::time::timeout(Duration::from_secs(2), events_rx.recv())
        .await
        .expect("EVPN broadcast should deliver event within 2s")
        .expect("broadcast not closed");
    assert_eq!(event.event_type, crate::event::RouteEventType::BestChanged);
    assert_eq!(event.key, key);
    assert_eq!(event.peer, Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    assert_eq!(event.previous_peer, Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    let best = event
        .best
        .as_ref()
        .expect("BestChanged must carry a best path");
    assert_eq!(
        best.attributes, expected_attrs,
        "new best must carry the bumped MAC Mobility sequence"
    );
    let prior = event
        .previous_best
        .as_ref()
        .expect("BestChanged must carry the prior best path");
    assert_ne!(prior.attributes, expected_attrs);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_route_event_withdrawn_on_last_removed() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer_addr = Ipv4Addr::new(10, 0, 0, 3);
    let peer = IpAddr::V4(peer_addr);
    let route = make_evpn_macip(
        peer_addr,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x66],
        Some(0),
        false,
    );
    let key = route.key();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![route],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let mut events_rx = subscribe_evpn_events(&tx).await;

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![key],
        validated_with: None,
    })
    .await
    .unwrap();

    let event = tokio::time::timeout(Duration::from_secs(2), events_rx.recv())
        .await
        .expect("EVPN broadcast should deliver event within 2s")
        .expect("broadcast not closed");
    assert_eq!(event.event_type, crate::event::RouteEventType::Withdrawn);
    assert_eq!(event.key, key);
    assert!(event.peer.is_none());
    assert_eq!(event.previous_peer, Some(peer));
    assert!(event.best.is_none(), "Withdrawn must not carry a best");
    let prior = event
        .previous_best
        .as_ref()
        .expect("Withdrawn must carry the prior best so consumers recover VNI");
    assert_eq!(prior.peer, peer);

    drop(tx);
    handle.await.unwrap();
}

async fn evpn_sessions_synced(tx: &mpsc::Sender<RibUpdate>) -> bool {
    let (reply, rx) = tokio::sync::oneshot::channel();
    tx.send(RibUpdate::QueryEvpnSessionsSynced { reply })
        .await
        .unwrap();
    rx.await.unwrap()
}

/// `PeerUp` without waiting for the initial End-of-RIB, which selection
/// deferral withholds; the outbound channel stays open and drained.
async fn session_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: Ipv4Addr,
    session_id: u64,
    sendable_families: Vec<(Afi, Safi)>,
) {
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id,
        peer: IpAddr::V4(peer),
        peer_asn: 65000,
        peer_router_id: peer,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families,
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
    tokio::spawn(async move { while out_rx.recv().await.is_some() {} });
}

async fn evpn_eor(tx: &mpsc::Sender<RibUpdate>, peer: Ipv4Addr, session_id: u64) {
    tx.send(RibUpdate::EndOfRib {
        session_id,
        peer: IpAddr::V4(peer),
        afi: Afi::L2Vpn,
        safi: Safi::Evpn,
    })
    .await
    .unwrap();
}

/// GR selection deferral leaves EVPN Loc-RIB unchanged, so remote Type 4
/// routes are unreadable; synced up sessions must not open the boot gate.
#[tokio::test]
async fn evpn_sessions_synced_waits_for_selection_deferral_release() {
    let a = Ipv4Addr::new(10, 0, 0, 1);
    let b = Ipv4Addr::new(10, 0, 0, 2);
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(crate::SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: [a, b]
                .into_iter()
                .map(|peer| crate::SelectionDeferralWaiterConfig {
                    peer: IpAddr::V4(peer),
                    families: evpn_sendable(),
                })
                .collect(),
        });
    let handle = tokio::spawn(manager.run());
    let gr_up = |peer: Ipv4Addr| {
        let tx = tx.clone();
        async move {
            tx.send(RibUpdate::SetPeerGracefulRestartContext {
                peer: IpAddr::V4(peer),
                session_id: 1,
                peer_restart_state: false,
                peer_gr_families: evpn_sendable(),
                peer_enhanced_refresh: true,
                peer_llgr_families: Vec::new(),
                local_llgr_stale_time: 0,
            })
            .await
            .unwrap();
            session_up(&tx, peer, 1, evpn_sendable()).await;
        }
    };

    gr_up(a).await;
    evpn_eor(&tx, a, 1).await;
    assert!(
        !evpn_sessions_synced(&tx).await,
        "deferral still waits for b"
    );
    gr_up(b).await;
    evpn_eor(&tx, b, 1).await;
    assert!(evpn_sessions_synced(&tx).await);

    drop(tx);
    handle.await.unwrap();
}

/// Only established EVPN sessions count, and only their current session's
/// End-of-RIB.
#[tokio::test]
async fn evpn_sessions_synced_ignores_non_evpn_sessions_and_stale_end_of_rib() {
    let a = Ipv4Addr::new(10, 0, 0, 1);
    let unicast = Ipv4Addr::new(10, 0, 0, 2);
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    session_up(&tx, unicast, 1, vec![(Afi::Ipv4, Safi::Unicast)]).await;
    assert!(
        !evpn_sessions_synced(&tx).await,
        "a non-EVPN session is not an EVPN session"
    );
    session_up(&tx, a, 2, evpn_sendable()).await;
    evpn_eor(&tx, a, 1).await;
    assert!(
        !evpn_sessions_synced(&tx).await,
        "a stale session's End-of-RIB is ignored"
    );
    evpn_eor(&tx, a, 2).await;
    assert!(
        evpn_sessions_synced(&tx).await,
        "the unsynced non-EVPN session does not hold the gate"
    );

    drop(tx);
    handle.await.unwrap();
}

// --- FIB install-candidate view (multipath/ECMP) ---

/// RFC 9785 §4.3 boot gate: synced only once every established EVPN
/// session has sent the EVPN End-of-RIB; other families' markers do not count.
#[tokio::test]
async fn evpn_sessions_synced_tracks_evpn_end_of_rib_per_session() {
    async fn synced(tx: &mpsc::Sender<RibUpdate>) -> bool {
        let (reply, rx) = tokio::sync::oneshot::channel();
        tx.send(RibUpdate::QueryEvpnSessionsSynced { reply })
            .await
            .unwrap();
        rx.await.unwrap()
    }
    async fn eor(tx: &mpsc::Sender<RibUpdate>, peer: Ipv4Addr, afi: Afi, safi: Safi) {
        tx.send(RibUpdate::EndOfRib {
            session_id: 0,
            peer: IpAddr::V4(peer),
            afi,
            safi,
        })
        .await
        .unwrap();
    }
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let a = Ipv4Addr::new(10, 0, 0, 1);
    let b = Ipv4Addr::new(10, 0, 0, 2);

    assert!(!synced(&tx).await, "no established EVPN session");
    let _a_out = evpn_rr_client_up(&tx, a).await;
    assert!(!synced(&tx).await);
    eor(&tx, a, Afi::L2Vpn, Safi::Evpn).await;
    assert!(synced(&tx).await);
    let _b_out = evpn_rr_client_up(&tx, b).await;
    assert!(!synced(&tx).await, "a new EVPN session reopens the gate");
    eor(&tx, b, Afi::Ipv4, Safi::Unicast).await;
    assert!(!synced(&tx).await, "only the EVPN marker counts");
    eor(&tx, b, Afi::L2Vpn, Safi::Evpn).await;
    assert!(synced(&tx).await);
    tx.send(RibUpdate::PeerDown {
        peer: IpAddr::V4(b),
        session_id: 0,
    })
    .await
    .unwrap();
    let _b_out = evpn_rr_client_up(&tx, b).await;
    assert!(!synced(&tx).await, "a reconnect must resend End-of-RIB");

    drop(tx);
    handle.await.unwrap();
}

/// A collision-window replacement discards the peer's Adj-RIB-In, so neither
/// the superseded record nor a failover back to it may vouch for EVPN routes
/// that the replayed feed has not yet re-delivered with End-of-RIB.
#[tokio::test]
async fn evpn_sessions_synced_resets_on_collision_replacement_and_failover() {
    async fn synced(tx: &mpsc::Sender<RibUpdate>) -> bool {
        let (reply, rx) = tokio::sync::oneshot::channel();
        tx.send(RibUpdate::QueryEvpnSessionsSynced { reply })
            .await
            .unwrap();
        rx.await.unwrap()
    }
    async fn up(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr, session_id: u64) {
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            per_client_best: false,
            interpret_rfc1997: true,
            session_id,
            peer,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: evpn_sendable(),
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
        drain_eor(&mut out_rx).await;
        // Keep the outbound channel open so failover finds a live sender.
        tokio::spawn(async move { while out_rx.recv().await.is_some() {} });
    }
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    up(&tx, peer, 1).await;
    tx.send(RibUpdate::EndOfRib {
        session_id: 1,
        peer,
        afi: Afi::L2Vpn,
        safi: Safi::Evpn,
    })
    .await
    .unwrap();
    assert!(synced(&tx).await);
    up(&tx, peer, 2).await;
    assert!(
        !synced(&tx).await,
        "the replacement session has not sent End-of-RIB"
    );
    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 2,
    })
    .await
    .unwrap();
    assert!(
        !synced(&tx).await,
        "failover back to session 1 replays a discarded Adj-RIB-In"
    );

    drop(tx);
    handle.await.unwrap();
}
