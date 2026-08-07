use super::*;
use rustbgpd_policy::{
    NeighborSetMatch, Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications,
};

fn no_advertise_chain(peer_context: bool, add: bool) -> PolicyChain {
    let statement = PolicyStatement {
        prefix: None,
        ge: None,
        le: None,
        action: PolicyAction::Permit,
        match_community: vec![],
        match_as_path: None,
        match_neighbor_set: peer_context.then_some(NeighborSetMatch {
            addresses: vec![],
            remote_asns: vec![65100],
            peer_groups: vec![],
        }),
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
        modifications: RouteModifications {
            communities_add: add
                .then_some(rustbgpd_wire::COMMUNITY_NO_ADVERTISE)
                .into_iter()
                .collect(),
            communities_remove: (!add)
                .then_some(rustbgpd_wire::COMMUNITY_NO_ADVERTISE)
                .into_iter()
                .collect(),
            ..RouteModifications::default()
        },
    };
    PolicyChain::new(vec![Policy {
        entries: vec![statement],
        default_action: PolicyAction::Deny,
    }])
}

pub(super) fn no_advertise_removal_chain(peer_context: bool) -> PolicyChain {
    no_advertise_chain(peer_context, false)
}

pub(super) fn no_advertise_addition_chain(peer_context: bool) -> PolicyChain {
    no_advertise_chain(peer_context, true)
}

pub(super) fn with_no_advertise(mut route: Route) -> Route {
    Arc::make_mut(&mut route.attributes).push(PathAttribute::Communities(vec![
        rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
    ]));
    route
}

fn with_otc(mut route: Route, asn: u32) -> Route {
    Arc::make_mut(&mut route.attributes).push(PathAttribute::OnlyToCustomer(asn));
    route
}

fn drain_unicast_state(
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
) -> HashMap<(Prefix, u32), Route> {
    let mut state = HashMap::new();
    while let Ok(update) = rx.try_recv() {
        for route in update.announce.iter() {
            state.insert((route.prefix, route.path_id), route.clone());
        }
        for withdrawn in update.withdraw {
            state.remove(&withdrawn);
        }
    }
    state
}

async fn seed_three_dual_stack_candidates(
    tx: &mpsc::Sender<RibUpdate>,
) -> (Ipv4Prefix, Ipv6Prefix) {
    fn received(route: Route) -> RibUpdate {
        RibUpdate::RoutesReceived {
            session_id: 0,
            peer: route.peer,
            announced: vec![route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        }
    }

    let v4 = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let v6 = Ipv6Prefix::new("2001:db8:700::".parse().unwrap(), 48);
    for host in 1..=3 {
        let v4_route = make_route(v4, Ipv4Addr::new(10, 0, 0, host));
        tx.send(received(v4_route)).await.unwrap();
        let v6_route = make_v6_route(v6, format!("2001:db8:700::{host}").parse().unwrap());
        tx.send(received(v6_route)).await.unwrap();
    }
    let (reply, result) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply })
        .await
        .unwrap();
    assert_eq!(result.await.unwrap(), 2);
    (v4, v6)
}

fn dual_stack_add_path_peer_up(
    peer: IpAddr,
    session_id: u64,
    outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
) -> RibUpdate {
    RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: dual_stack_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: dual_stack_sendable(),
        add_path_send_max: 1,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    }
}

async fn receive_dual_stack_dump(
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
) -> HashMap<(Prefix, u32), Route> {
    let mut state = HashMap::new();
    let mut eor = HashSet::new();
    while eor.len() < 2 {
        let update = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("deferred initial dump should complete")
            .expect("outbound channel should stay open");
        for route in update.announce.iter() {
            state.insert((route.prefix, route.path_id), route.clone());
        }
        for withdrawn in update.withdraw {
            state.remove(&withdrawn);
        }
        eor.extend(update.end_of_rib);
    }
    state
}

fn path_count(state: &HashMap<(Prefix, u32), Route>, prefix: Prefix) -> usize {
    state
        .keys()
        .filter(|(candidate, _)| *candidate == prefix)
        .count()
}

/// Restoring the `outbound_session_ids`-only acceptance guard makes the IPv6
/// assertion red: the deferred first dump falls back to the scalar limit.
#[tokio::test]
async fn deferred_registration_stages_current_session_paths_limit() {
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.initial_dump_defer_min_routes = 0;
    let handle = tokio::spawn(manager.run());
    let (v4, v6) = seed_three_dual_stack_candidates(&tx).await;
    let peer: IpAddr = "192.0.2.70".parse().unwrap();
    let (out_tx, mut out_rx) = mpsc::channel(32);

    tx.try_send(dual_stack_add_path_peer_up(peer, 7, out_tx))
        .unwrap();
    tx.try_send(RibUpdate::PeerAddPathLimits {
        peer,
        session_id: 7,
        limits: vec![
            ((Afi::Ipv4, Safi::Unicast), 1),
            ((Afi::Ipv6, Safi::Unicast), 2),
        ],
    })
    .unwrap();

    let initial = receive_dual_stack_dump(&mut out_rx).await;
    assert_eq!(path_count(&initial, Prefix::V4(v4)), 1);
    assert_eq!(path_count(&initial, Prefix::V6(v6)), 2);
    assert!(out_rx.try_recv().is_err(), "the first dump must run once");
    drop(tx);
    handle.await.unwrap();
}

/// Weakening newest-record ownership to ignore session identity makes the
/// IPv6 assertions red: a superseded session stages its limit into the winner.
#[tokio::test]
async fn deferred_registration_rejects_superseded_session_paths_limit() {
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.initial_dump_defer_min_routes = 0;
    let handle = tokio::spawn(manager.run());
    let (v4, v6) = seed_three_dual_stack_candidates(&tx).await;
    let peer: IpAddr = "192.0.2.71".parse().unwrap();
    let (old_tx, mut old_rx) = mpsc::channel(32);
    let (new_tx, mut new_rx) = mpsc::channel(32);

    tx.try_send(dual_stack_add_path_peer_up(peer, 7, old_tx))
        .unwrap();
    tx.try_send(dual_stack_add_path_peer_up(peer, 8, new_tx))
        .unwrap();
    tx.try_send(RibUpdate::PeerAddPathLimits {
        peer,
        session_id: 8,
        limits: vec![
            ((Afi::Ipv4, Safi::Unicast), 1),
            ((Afi::Ipv6, Safi::Unicast), 1),
        ],
    })
    .unwrap();
    tx.try_send(RibUpdate::PeerAddPathLimits {
        peer,
        session_id: 7,
        limits: vec![((Afi::Ipv6, Safi::Unicast), 2)],
    })
    .unwrap();

    let initial = receive_dual_stack_dump(&mut new_rx).await;
    assert_eq!(path_count(&initial, Prefix::V4(v4)), 1);
    assert_eq!(path_count(&initial, Prefix::V6(v6)), 1);
    assert!(
        old_rx.try_recv().is_err(),
        "superseded session emitted a dump"
    );

    for (afi, safi) in dual_stack_sendable() {
        tx.send(RibUpdate::RouteRefreshRequest {
            peer,
            session_id: 8,
            afi,
            safi,
        })
        .await
        .unwrap();
    }
    let refreshed = receive_dual_stack_dump(&mut new_rx).await;
    assert_eq!(path_count(&refreshed, Prefix::V4(v4)), 1);
    assert_eq!(path_count(&refreshed, Prefix::V6(v6)), 1);
    drop(tx);
    handle.await.unwrap();
}

/// Operator-triggered outbound refresh is a one-peer replay of the exact
/// currently exportable inventory. Removing the force insertion makes the
/// target announcement assertion time out (ordinary equality suppression wins);
/// broadening the target makes the sibling-empty assertion red; replaying
/// withdrawn, source-split, RFC 1997-rejected, or unsendable routes makes the
/// exact-prefix assertion red.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture proves typed rejection, exact peer scope, and every retained export gate"
)]
async fn refresh_peer_outbound_replays_only_the_target_exportable_inventory() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let target: IpAddr = "192.0.2.30".parse().unwrap();
    let sibling: IpAddr = "192.0.2.31".parse().unwrap();
    let sibling_deny = PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }]);
    let mut receivers = Vec::new();

    let (reply, result) = oneshot::channel();
    tx.send(RibUpdate::RefreshPeerOutbound {
        peer: target,
        reply,
    })
    .await
    .unwrap();
    assert!(
        matches!(
            result.await.unwrap(),
            Err(crate::RibCommandError::NotFound(_))
        ),
        "an unregistered peer must retain the typed not-found class"
    );

    for peer in [target, sibling] {
        let (out_tx, mut out_rx) = mpsc::channel(16);
        tx.send(RibUpdate::PeerUp {
            peer,
            session_id: 7,
            peer_asn: 65100,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx: out_tx,
            export_policy: (peer == sibling).then(|| sibling_deny.clone()),
            sendable_families: dual_stack_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            orr_vantage: None,
            per_client_best: false,
            interpret_rfc1997: true,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: vec![],
            negotiated_llgr_families: vec![],
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;
        receivers.push((peer, out_rx));
    }

    let source = Ipv4Addr::new(198, 51, 100, 10);
    let kept_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let withdrawn_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 114, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![
            make_route(kept_prefix, source),
            make_route(withdrawn_prefix, source),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![],
        withdrawn: vec![(Prefix::V4(withdrawn_prefix), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // A target-sourced route is present in the Loc-RIB but split-horizon
    // excluded for that target. A NO_ADVERTISE route and a VPN route that
    // neither peer negotiated are likewise never part of its exportable view.
    let target_source = match target {
        IpAddr::V4(address) => address,
        IpAddr::V6(_) => unreachable!("fixture is IPv4"),
    };
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: target,
        announced: vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(203, 0, 115, 0), 24),
            target_source,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let rejected = with_no_advertise(make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 116, 0), 24),
        source,
    ));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![rejected],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let v6 = Ipv6Prefix::new("2001:db8:676::".parse().unwrap(), 64);
    let v6_route = make_v6_route(v6, "2001:db8:676::1".parse().unwrap());
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: v6_route.peer,
        announced: vec![v6_route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(source),
        announced: vec![make_vpn_rib_route(source, 117, 16, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;
    for (_, out_rx) in &mut receivers {
        while out_rx.try_recv().is_ok() {}
    }

    let (reply, result) = oneshot::channel();
    tx.send(RibUpdate::RefreshPeerOutbound {
        peer: target,
        reply,
    })
    .await
    .unwrap();
    assert_eq!(result.await.unwrap(), Ok(()));

    let (_, target_rx) = receivers
        .iter_mut()
        .find(|(peer, _)| *peer == target)
        .unwrap();
    let refreshed = tokio::time::timeout(Duration::from_millis(100), target_rx.recv())
        .await
        .expect("force refresh must enqueue the target's retained exportable route")
        .expect("target outbound channel stays open");
    assert_eq!(
        refreshed
            .announce
            .iter()
            .map(|route| route.prefix)
            .collect::<HashSet<_>>(),
        HashSet::from([Prefix::V4(kept_prefix), Prefix::V6(v6)])
    );
    assert!(refreshed.vpn_announce.is_empty());
    assert!(refreshed.withdraw.is_empty());

    let (_, sibling_rx) = receivers
        .iter_mut()
        .find(|(peer, _)| *peer == sibling)
        .unwrap();
    assert!(
        sibling_rx.try_recv().is_err(),
        "a one-peer refresh must not emit to a sibling"
    );

    // Force the denied sibling after the target-only empty-input pass. If
    // that pass erased the sibling's retained denial inventory, this
    // re-evaluation publishes a duplicate PolicyFiltered transition.
    let (reply, result) = oneshot::channel();
    tx.send(RibUpdate::RefreshPeerOutbound {
        peer: sibling,
        reply,
    })
    .await
    .unwrap();
    assert_eq!(result.await.unwrap(), Ok(()));
    let sibling_history = query_route_event_history(
        &tx,
        Some(sibling),
        Some(Afi::Ipv4),
        Some(Prefix::V4(kept_prefix)),
        10,
    )
    .await;
    assert_eq!(
        sibling_history
            .iter()
            .filter(|event| event.event_type == RouteEventType::PolicyFiltered)
            .count(),
        1,
        "refreshing another peer must preserve this sibling's denial inventory"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A grouped and a genuinely private single-best target must both apply
/// RFC 1997 before a permit policy that removes `NO_ADVERTISE`. Replacing
/// an advertised route with the scoped form withdraws it, clears logical
/// advertised state, and explains the same pre-policy stop on both paths.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario proves grouped/private staging, policy order, withdrawal, state, and explain parity"
)]
async fn no_advertise_precedes_policy_for_grouped_and_private_single_best() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let grouped_a: IpAddr = "192.0.2.30".parse().unwrap();
    let grouped_b: IpAddr = "192.0.2.31".parse().unwrap();
    let private: IpAddr = "192.0.2.32".parse().unwrap();
    let mut receivers = Vec::new();

    for (peer, peer_context) in [(grouped_a, false), (grouped_b, false), (private, true)] {
        let (out_tx, mut out_rx) = mpsc::channel(16);
        tx.send(RibUpdate::PeerUp {
            peer,
            session_id: 0,
            peer_asn: 65100,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx: out_tx,
            export_policy: Some(no_advertise_removal_chain(peer_context)),
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            orr_vantage: None,
            per_client_best: false,
            interpret_rfc1997: true,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: vec![],
            negotiated_llgr_families: vec![],
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;
        receivers.push((peer, out_rx));
    }

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 115, 0), 24);
    let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    let plain = make_route(prefix, Ipv4Addr::new(198, 51, 100, 10));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![plain.clone()],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;
    for (_, out_rx) in &mut receivers {
        let update = out_rx.try_recv().expect("plain route announced after sync");
        assert_eq!(update.announce.len(), 1);
        assert!(update.withdraw.is_empty());
    }

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![with_no_advertise(plain.clone())],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;
    for (peer, out_rx) in &mut receivers {
        let update = out_rx
            .try_recv()
            .expect("NO_ADVERTISE replacement withdrawn after sync");
        assert!(
            update.announce.is_empty(),
            "{peer} must not receive the route"
        );
        assert_eq!(update.withdraw, vec![(Prefix::V4(prefix), 0)]);

        let (reply, response) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes { peer: *peer, reply })
            .await
            .unwrap();
        assert!(response.await.unwrap().is_empty());

        let explain = query_explain_advertised_route(&tx, *peer, Prefix::V4(prefix)).await;
        assert_eq!(explain.decision, crate::update::ExplainDecision::Deny);
        assert_eq!(
            explain.update_group_id.is_some(),
            *peer != private,
            "group membership must distinguish shared from private staging"
        );
        let stop = explain
            .gates
            .iter()
            .find(|step| step.verdict == crate::update::ExportGateVerdict::Stop)
            .unwrap();
        assert_eq!(
            (stop.gate, stop.code),
            ("no_advertise", "no_advertise_suppressed")
        );
        assert!(
            explain.modifications.communities_remove.is_empty(),
            "the pre-policy stop must occur before the configured removal"
        );
    }

    // Restore a plain source route under the removal policy, then replace
    // each target's policy with one that adds NO_ADVERTISE. The post-policy
    // guard must withdraw the route on both staging shapes.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![plain],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;
    for (_, out_rx) in &mut receivers {
        let update = out_rx
            .try_recv()
            .expect("plain replacement announced after query synchronization");
        assert_eq!(update.announce.len(), 1);
    }

    for (peer, _) in &receivers {
        let (reply, response) = oneshot::channel();
        tx.send(RibUpdate::ReplacePeerExportPolicy {
            peer: *peer,
            export_policy: Some(no_advertise_addition_chain(*peer == private)),
            reply,
        })
        .await
        .unwrap();
        assert_eq!(response.await.unwrap(), Ok(()));
    }
    let _ = query_best_routes(&tx).await;

    for (peer, out_rx) in &mut receivers {
        let mut saw_withdraw = false;
        while let Ok(update) = out_rx.try_recv() {
            assert!(
                update.announce.is_empty(),
                "policy-added NO_ADVERTISE must not be announced to {peer}"
            );
            saw_withdraw |= update.withdraw.contains(&(Prefix::V4(prefix), 0));
        }
        assert!(saw_withdraw, "policy replacement must withdraw from {peer}");

        let (reply, response) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes { peer: *peer, reply })
            .await
            .unwrap();
        assert!(response.await.unwrap().is_empty());

        let explain = query_explain_advertised_route(&tx, *peer, Prefix::V4(prefix)).await;
        assert_eq!(explain.decision, crate::update::ExplainDecision::Deny);
        assert_eq!(
            explain.update_group_id.is_some(),
            *peer != private,
            "replacement keeps grouped/private staging distinction"
        );
        assert_eq!(
            explain.gates.last().map(|step| (step.gate, step.code)),
            Some(("no_advertise", "no_advertise_policy_suppressed"))
        );
        assert!(
            explain
                .modifications
                .communities_add
                .contains(&rustbgpd_wire::COMMUNITY_NO_ADVERTISE),
            "explain shows the policy modification that triggered suppression"
        );
    }

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end scenario proves grouped/private OTC commit, withdrawal, explain, and cleanup parity"
)]
async fn otc_is_rejected_before_grouped_and_private_adj_rib_out_commit() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let grouped: IpAddr = "192.0.2.10".parse().unwrap();
    let private: IpAddr = "192.0.2.11".parse().unwrap();
    let mut receivers = Vec::new();

    for (peer, per_client_best) in [(grouped, false), (private, true)] {
        tx.send(RibUpdate::SetPeerExportContext {
            peer,
            session_id: 7,
            local_role: Some(rustbgpd_wire::BgpRole::Customer),
        })
        .await
        .unwrap();
        let (out_tx, mut out_rx) = mpsc::channel(16);
        tx.send(RibUpdate::PeerUp {
            peer,
            session_id: 7,
            peer_asn: 65100,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx: out_tx,
            export_policy: None,
            // The private peer must stay on the per-peer path: since the
            // ADR-0126 classifier flip a unicast-only per-client-best
            // session groups, so the private side negotiates VPNv4 too —
            // the residual `per_client_best` fallback — which leaves its
            // IPv4-unicast OTC flow under test unchanged.
            sendable_families: if per_client_best {
                vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv4, Safi::MplsVpn)]
            } else {
                ipv4_sendable()
            },
            is_ebgp: true,
            route_reflector_client: false,
            orr_vantage: None,
            per_client_best,
            interpret_rfc1997: true,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: vec![],
            negotiated_llgr_families: vec![],
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;
        receivers.push((peer, out_rx));
    }

    let advertised_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let advertised = make_route(advertised_prefix, Ipv4Addr::new(198, 51, 100, 1));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: advertised.peer,
        announced: vec![advertised.clone()],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    for (_, out_rx) in &mut receivers {
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert!(update.withdraw.is_empty());
        assert!(update.otc_blocked.is_empty());
    }

    let blocked_replacement = with_otc(advertised, 64512);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: blocked_replacement.peer,
        announced: vec![blocked_replacement],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    for (_, out_rx) in &mut receivers {
        let update = out_rx.recv().await.unwrap();
        assert!(update.announce.is_empty());
        assert_eq!(update.withdraw, vec![(Prefix::V4(advertised_prefix), 0)]);
        assert_eq!(update.otc_blocked.len(), 1);
    }

    let never_advertised_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 114, 0), 24);
    let never_advertised = with_otc(
        make_route(never_advertised_prefix, Ipv4Addr::new(198, 51, 100, 2)),
        64512,
    );
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: never_advertised.peer,
        announced: vec![never_advertised],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    for (peer, out_rx) in &mut receivers {
        let update = out_rx.recv().await.unwrap();
        assert!(update.announce.is_empty());
        assert!(update.withdraw.is_empty());
        assert_eq!(update.otc_blocked.len(), 1);

        let explain =
            query_explain_advertised_route(&tx, *peer, Prefix::V4(never_advertised_prefix)).await;
        assert_eq!(explain.decision, crate::update::ExplainDecision::Deny);
        let stop = explain
            .gates
            .iter()
            .find(|step| step.verdict == crate::update::ExportGateVerdict::Stop)
            .unwrap();
        assert_eq!((stop.gate, stop.code), ("otc", "otc_egress_blocked"));
    }

    for (peer, _) in &receivers {
        let (reply, result) = oneshot::channel();
        tx.send(RibUpdate::RefreshPeerOutbound { peer: *peer, reply })
            .await
            .unwrap();
        assert_eq!(result.await.unwrap(), Ok(()));
    }
    let _ = query_best_routes(&tx).await;
    let mut resyncs = 0;
    for (_, out_rx) in &mut receivers {
        while let Ok(update) = out_rx.try_recv() {
            resyncs += 1;
            assert!(
                update.otc_blocked.is_empty(),
                "force resync repeated an unchanged OTC edge"
            );
        }
    }
    assert!(
        resyncs > 0,
        "force resync proof did not observe an envelope"
    );
    for (peer, _) in &receivers {
        tx.send(RibUpdate::RouteRefreshRequest {
            peer: *peer,
            session_id: 7,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();
    }
    for (_, out_rx) in &mut receivers {
        let refresh = out_rx.recv().await.unwrap();
        assert_eq!(refresh.refresh_markers.len(), 2);
        assert!(
            refresh.otc_blocked.is_empty(),
            "route refresh repeated an unchanged OTC edge"
        );
    }

    let now_permitted = make_route(never_advertised_prefix, Ipv4Addr::new(198, 51, 100, 2));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: now_permitted.peer,
        announced: vec![now_permitted],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    for (_, out_rx) in &mut receivers {
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert!(update.withdraw.is_empty());
        assert!(
            update.otc_blocked.is_empty(),
            "a permitted replacement must clear the prior OTC denial residue"
        );
    }

    let blocked_again = with_otc(
        make_route(never_advertised_prefix, Ipv4Addr::new(198, 51, 100, 2)),
        64512,
    );
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: blocked_again.peer,
        announced: vec![blocked_again],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    for (_, out_rx) in &mut receivers {
        assert_eq!(out_rx.recv().await.unwrap().otc_blocked.len(), 1);
    }

    tx.send(RibUpdate::PeerDown {
        peer: grouped,
        session_id: 7,
    })
    .await
    .unwrap();
    let (out_tx, mut rejoined_rx) = mpsc::channel(16);
    tx.send(RibUpdate::SetPeerExportContext {
        peer: grouped,
        session_id: 8,
        local_role: Some(rustbgpd_wire::BgpRole::Customer),
    })
    .await
    .unwrap();
    tx.send(RibUpdate::PeerUp {
        peer: grouped,
        session_id: 8,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    })
    .await
    .unwrap();
    assert_eq!(rejoined_rx.recv().await.unwrap().otc_blocked.len(), 2);

    drop(tx);
    handle.await.unwrap();
}

async fn assert_otc_backpressure_dedup(per_client_best: bool) {
    tokio::time::pause();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let target: IpAddr = "192.0.2.20".parse().unwrap();
    tx.send(RibUpdate::SetPeerExportContext {
        peer: target,
        session_id: 7,
        local_role: Some(rustbgpd_wire::BgpRole::Customer),
    })
    .await
    .unwrap();
    let (out_tx, mut out_rx) = mpsc::channel(1);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        session_id: 7,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        // Keep the per-client-best variant genuinely private post
        // ADR-0126: a non-unicast-only session takes the residual
        // fallback (the grouped per-client-best backpressure path is
        // covered by the update-group OTC suite).
        sendable_families: if per_client_best {
            vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv4, Safi::MplsVpn)]
        } else {
            ipv4_sendable()
        },
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    })
    .await
    .unwrap();

    let blocked = with_otc(
        make_route(
            Ipv4Prefix::new(Ipv4Addr::new(203, 0, 120, 0), 24),
            Ipv4Addr::new(198, 51, 100, 20),
        ),
        64512,
    );
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: blocked.peer,
        announced: vec![blocked],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;

    for _ in 0..3 {
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
    }
    drain_eor(&mut out_rx).await;
    tokio::time::advance(Duration::from_secs(2)).await;
    let recovered = out_rx.recv().await.unwrap();
    assert!(recovered.announce.is_empty());
    assert_eq!(recovered.otc_blocked.len(), 1);
    let (reply, result) = oneshot::channel();
    tx.send(RibUpdate::RefreshPeerOutbound {
        peer: target,
        reply,
    })
    .await
    .unwrap();
    assert_eq!(result.await.unwrap(), Ok(()));
    let _ = query_best_routes(&tx).await;
    while let Ok(update) = out_rx.try_recv() {
        assert!(
            update.otc_blocked.is_empty(),
            "force retry repeated an unchanged OTC edge"
        );
    }

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn grouped_otc_backpressure_emits_one_deduplicated_diagnostic_on_recovery() {
    assert_otc_backpressure_dedup(false).await;
}

#[tokio::test]
async fn private_otc_backpressure_emits_one_deduplicated_diagnostic_on_recovery() {
    assert_otc_backpressure_dedup(true).await;
}

#[tokio::test]
async fn grouped_otc_source_withdraw_clears_pending_diagnostic_before_recovery() {
    tokio::time::pause();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let target: IpAddr = "192.0.2.21".parse().unwrap();
    tx.send(RibUpdate::SetPeerExportContext {
        peer: target,
        session_id: 8,
        local_role: Some(rustbgpd_wire::BgpRole::Customer),
    })
    .await
    .unwrap();
    let (out_tx, mut out_rx) = mpsc::channel(1);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        session_id: 8,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    })
    .await
    .unwrap();

    let blocked = with_otc(
        make_route(
            Ipv4Prefix::new(Ipv4Addr::new(203, 0, 121, 0), 24),
            Ipv4Addr::new(198, 51, 100, 21),
        ),
        64512,
    );
    let blocked_key = (blocked.prefix, blocked.path_id);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: blocked.peer,
        announced: vec![blocked.clone()],
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
        peer: blocked.peer,
        announced: vec![],
        withdrawn: vec![blocked_key],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;
    drain_eor(&mut out_rx).await;
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;
    assert!(
        out_rx.try_recv().is_err(),
        "empty dirty resync leaked an obsolete OTC diagnostic"
    );

    let permitted = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 122, 0), 24),
        Ipv4Addr::new(198, 51, 100, 22),
    );
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: permitted.peer,
        announced: vec![permitted.clone()],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let recovered = out_rx.recv().await.unwrap();
    assert_eq!(recovered.announce.len(), 1);
    assert_eq!(recovered.announce[0].prefix, permitted.prefix);
    assert!(
        recovered.otc_blocked.is_empty(),
        "withdrawn source must not leak an obsolete OTC diagnostic"
    );

    drop(tx);
    handle.await.unwrap();
}

fn assert_one_dual_stack_eor(out_rx: &mut mpsc::Receiver<OutboundRouteUpdate>) {
    let update = out_rx
        .try_recv()
        .expect("effective limit change triggers one resync");
    assert!(update.announce.is_empty());
    assert!(update.withdraw.is_empty());
    assert_eq!(
        update.end_of_rib,
        vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)]
    );
    assert!(
        matches!(out_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "effective limit change must trigger exactly one resync"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one lifecycle pins stale, idempotent, changed, and reverted family-limit updates"
)]
fn paths_limit_updates_resync_only_for_effective_unicast_changes() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let (out_tx, mut out_rx) = mpsc::channel(16);
    let v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    let v6 = Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32));

    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id: 7,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: dual_stack_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: dual_stack_sendable(),
        add_path_send_max: 8,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    assert_one_dual_stack_eor(&mut out_rx);

    // A stale session must neither alter stored limits nor trigger a resync.
    manager.handle_update(RibUpdate::PeerAddPathLimits {
        peer,
        session_id: 6,
        limits: vec![((Afi::Ipv4, Safi::Unicast), 1)],
    });
    assert!(!manager.peer_add_path_send_limits.contains_key(&peer));
    assert!(matches!(
        out_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    // Explicit scalar-equivalent limits are stored but do not change the
    // effective caps, so the PeerUp EoR is not repeated.
    manager.handle_update(RibUpdate::PeerAddPathLimits {
        peer,
        session_id: 7,
        limits: vec![
            ((Afi::Ipv4, Safi::Unicast), 8),
            ((Afi::Ipv6, Safi::Unicast), 8),
        ],
    });
    assert_eq!(manager.add_path_send_max_for_prefix(peer, &v4), 8);
    assert_eq!(manager.add_path_send_max_for_prefix(peer, &v6), 8);
    assert!(matches!(
        out_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    // An empty exact map also means scalar fallback for every negotiated
    // send family and remains idempotent while replacing the stored map.
    manager.handle_update(RibUpdate::PeerAddPathLimits {
        peer,
        session_id: 7,
        limits: vec![],
    });
    assert!(
        manager
            .peer_add_path_send_limits
            .get(&peer)
            .is_some_and(HashMap::is_empty)
    );
    assert_eq!(manager.add_path_send_max_for_prefix(peer, &v4), 8);
    assert_eq!(manager.add_path_send_max_for_prefix(peer, &v6), 8);
    assert!(matches!(
        out_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    // A family divergence installs the exact map and performs one resync.
    manager.handle_update(RibUpdate::PeerAddPathLimits {
        peer,
        session_id: 7,
        limits: vec![
            ((Afi::Ipv4, Safi::Unicast), 2),
            ((Afi::Ipv6, Safi::Unicast), 5),
        ],
    });
    assert_one_dual_stack_eor(&mut out_rx);
    assert_eq!(manager.add_path_send_max_for_prefix(peer, &v4), 2);
    assert_eq!(manager.add_path_send_max_for_prefix(peer, &v6), 5);

    // An identical retransmission replaces the map without another resync.
    manager.handle_update(RibUpdate::PeerAddPathLimits {
        peer,
        session_id: 7,
        limits: vec![
            ((Afi::Ipv4, Safi::Unicast), 2),
            ((Afi::Ipv6, Safi::Unicast), 5),
        ],
    });
    assert!(matches!(
        out_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    // Synthetic differing same-session maps pin the comparison and storage
    // guard only; production emits one immutable map per negotiation. Each
    // effective change still requests exactly one replay, and reverting an
    // override restores scalar fallback in the stored/effective view.
    manager.handle_update(RibUpdate::PeerAddPathLimits {
        peer,
        session_id: 7,
        limits: vec![
            ((Afi::Ipv4, Safi::Unicast), 3),
            ((Afi::Ipv6, Safi::Unicast), 5),
        ],
    });
    assert_one_dual_stack_eor(&mut out_rx);
    assert_eq!(manager.add_path_send_max_for_prefix(peer, &v4), 3);
    assert_eq!(manager.add_path_send_max_for_prefix(peer, &v6), 5);

    manager.handle_update(RibUpdate::PeerAddPathLimits {
        peer,
        session_id: 7,
        limits: vec![],
    });
    assert_one_dual_stack_eor(&mut out_rx);
    assert!(
        manager
            .peer_add_path_send_limits
            .get(&peer)
            .is_some_and(HashMap::is_empty)
    );
    assert_eq!(manager.add_path_send_max_for_prefix(peer, &v4), 8);
    assert_eq!(manager.add_path_send_max_for_prefix(peer, &v6), 8);
}

#[test]
fn paths_limit_ignores_entries_outside_negotiated_send_families() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer: IpAddr = "192.0.2.2".parse().unwrap();
    let (out_tx, mut out_rx) = mpsc::channel(8);
    let v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    let v6 = Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32));

    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id: 7,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: dual_stack_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![(Afi::Ipv4, Safi::Unicast)],
        add_path_send_max: 8,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    assert_one_dual_stack_eor(&mut out_rx);

    manager.handle_update(RibUpdate::PeerAddPathLimits {
        peer,
        session_id: 7,
        limits: vec![((Afi::Ipv6, Safi::Unicast), 2)],
    });

    assert!(
        manager
            .peer_add_path_send_limits
            .get(&peer)
            .is_some_and(HashMap::is_empty),
        "an unnegotiated family must not survive into the exact limit map"
    );
    assert_eq!(manager.add_path_send_max_for_prefix(peer, &v4), 8);
    assert_eq!(manager.add_path_send_max_for_prefix(peer, &v6), 0);
    assert!(
        matches!(out_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "rejecting an inert foreign-family limit must not replay the table"
    );
}

#[test]
fn paths_limit_survives_collision_failback() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer: IpAddr = "192.0.2.3".parse().unwrap();
    let v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    let v6 = Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32));
    let peer_up = |session_id, outbound_tx| RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: dual_stack_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: dual_stack_sendable(),
        add_path_send_max: 8,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    };

    // Survivor session comes up and sends its one per-family limit map.
    let (survivor_tx, _survivor_rx) = mpsc::channel(16);
    manager.handle_update(peer_up(7, survivor_tx));
    manager.handle_update(RibUpdate::PeerAddPathLimits {
        peer,
        session_id: 7,
        limits: vec![
            ((Afi::Ipv4, Safi::Unicast), 2),
            ((Afi::Ipv6, Safi::Unicast), 5),
        ],
    });
    assert_eq!(manager.add_path_send_max_for_prefix(peer, &v4), 2);
    assert_eq!(manager.add_path_send_max_for_prefix(peer, &v6), 5);

    // RFC 4271 §6.8 collision window: the loser's PeerUp replaces the
    // registration (clearing the stored limits), sends its own map, then
    // goes down — the registration fails back to the survivor.
    let (loser_tx, _loser_rx) = mpsc::channel(16);
    manager.handle_update(peer_up(8, loser_tx));
    manager.handle_update(RibUpdate::PeerAddPathLimits {
        peer,
        session_id: 8,
        limits: vec![
            ((Afi::Ipv4, Safi::Unicast), 1),
            ((Afi::Ipv6, Safi::Unicast), 1),
        ],
    });
    assert_eq!(manager.add_path_send_max_for_prefix(peer, &v4), 1);
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 8,
    });

    // The failback replay must restore the survivor's per-family caps, not
    // clamp every family to the scalar minimum.
    assert_eq!(
        manager.add_path_send_max_for_prefix(peer, &v4),
        2,
        "collision failback lost the survivor's per-family Paths-Limit map"
    );
    assert_eq!(manager.add_path_send_max_for_prefix(peer, &v6), 5);
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end dual-stack scenario covers initial dump, churn, withdrawal re-ranking, and refresh replay"
)]
async fn paths_limit_drives_dual_stack_initial_churn_withdraw_and_refresh() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let v4 = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let v6 = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);
    let mut v4_routes = Vec::new();
    let mut v6_routes = Vec::new();
    for host in 1..=3 {
        let v4_route = make_route(v4, Ipv4Addr::new(10, 0, 0, host));
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: v4_route.peer,
            announced: vec![v4_route.clone()],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
        v4_routes.push(v4_route);

        let v6_route = make_v6_route(v6, format!("2001:db8::{host}").parse().unwrap());
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: v6_route.peer,
            announced: vec![v6_route.clone()],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
        v6_routes.push(v6_route);
    }
    let (sync_tx, sync_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: sync_tx })
        .await
        .unwrap();
    assert_eq!(sync_rx.await.unwrap(), 2);

    let target: IpAddr = "192.0.2.9".parse().unwrap();
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        session_id: 7,
        peer_asn: 65100,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)],
        add_path_send_max: 1,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::PeerAddPathLimits {
        peer: target,
        session_id: 7,
        limits: vec![
            ((Afi::Ipv4, Safi::Unicast), 1),
            ((Afi::Ipv6, Safi::Unicast), 2),
        ],
    })
    .await
    .unwrap();
    let (sync_tx, sync_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: sync_tx })
        .await
        .unwrap();
    let _ = sync_rx.await.unwrap();
    let initial = drain_unicast_state(&mut out_rx);
    assert_eq!(
        initial.keys().filter(|(p, _)| *p == Prefix::V4(v4)).count(),
        1
    );
    assert_eq!(
        initial.keys().filter(|(p, _)| *p == Prefix::V6(v6)).count(),
        2
    );

    for route in [v4_routes.remove(0), v6_routes.remove(0)] {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: route.peer,
            announced: vec![],
            withdrawn: vec![(route.prefix, route.path_id)],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }
    let (sync_tx, sync_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: sync_tx })
        .await
        .unwrap();
    let _ = sync_rx.await.unwrap();
    let reranked = drain_unicast_state(&mut out_rx);
    assert_eq!(
        reranked
            .keys()
            .filter(|(p, _)| *p == Prefix::V4(v4))
            .count(),
        1
    );
    assert_eq!(
        reranked
            .keys()
            .filter(|(p, _)| *p == Prefix::V6(v6))
            .count(),
        2
    );

    for (afi, safi) in [(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)] {
        tx.send(RibUpdate::RouteRefreshRequest {
            peer: target,
            session_id: 7,
            afi,
            safi,
        })
        .await
        .unwrap();
    }
    let (sync_tx, sync_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: sync_tx })
        .await
        .unwrap();
    let _ = sync_rx.await.unwrap();
    let refreshed = drain_unicast_state(&mut out_rx);
    assert_eq!(
        refreshed
            .keys()
            .filter(|(p, _)| *p == Prefix::V4(v4))
            .count(),
        1
    );
    assert_eq!(
        refreshed
            .keys()
            .filter(|(p, _)| *p == Prefix::V6(v6))
            .count(),
        2
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn routes_received_and_queried() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

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
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].prefix, Prefix::V4(prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn closed_query_channel_does_not_block_primary_channel() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();

    let count = tokio::time::timeout(Duration::from_secs(1), reply_rx)
        .await
        .expect("query should not stall when query channel is closed")
        .unwrap();
    assert_eq!(count, 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn large_routes_received_batch_preserves_final_state() {
    let (tx, rx) = mpsc::channel(64);
    let (_query_tx, query_rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, query_rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let next_hop = Ipv4Addr::new(10, 0, 0, 1);
    let routes: Vec<Route> = (0..2500).map(|i| make_indexed_route(i, next_hop)).collect();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: routes,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();

    let count = tokio::time::timeout(Duration::from_secs(2), reply_rx)
        .await
        .expect("large chunked batch should still converge")
        .unwrap();
    assert_eq!(count, 2500);

    drop(tx);
    handle.await.unwrap();
}

/// PR3: a multi-chunk initial-load flood (>1024 routes in one batch)
/// distributes to each peer as ONE coalesced `OutboundRouteUpdate`, not one
/// per 1024-route chunk. `recompute_best` still runs per chunk (see
/// `query_channel_observes_partial_progress_during_large_batch`), so only
/// outbound distribution is deferred to batch-end. Asserts both the
/// coalescing (single outbound message) and correctness (every route is
/// advertised).
#[tokio::test]
async fn multi_chunk_flood_coalesces_into_one_outbound_batch() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Register an outbound observer peer first and drain its initial EoR.
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

    // Flood 2500 routes (3 chunks at the 1024 chunk size) from a source peer.
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let next_hop = Ipv4Addr::new(10, 0, 0, 1);
    let route_count = 2500_u32;
    let routes: Vec<Route> = (0..route_count)
        .map(|i| make_indexed_route(i, next_hop))
        .collect();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: routes,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Collect outbound updates until every route is advertised, counting how
    // many distinct OutboundRouteUpdate messages it took.
    let mut announced = 0usize;
    let mut messages = 0usize;
    while announced < route_count as usize {
        let update = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("outbound update should arrive")
            .expect("outbound channel open");
        messages += 1;
        announced += update.announce.len();
    }
    assert_eq!(
        announced, route_count as usize,
        "every flooded route must be advertised"
    );
    assert_eq!(
        messages, 1,
        "a multi-chunk flood must coalesce into one outbound batch, got {messages}"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn query_channel_observes_partial_progress_during_large_batch() {
    let (tx, rx) = mpsc::channel(64);
    let (query_tx, query_rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, query_rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let next_hop = Ipv4Addr::new(10, 0, 0, 1);
    let route_count = 20_000_u32;
    let routes: Vec<Route> = (0..route_count)
        .map(|i| make_indexed_route(i, next_hop))
        .collect();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: routes,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tokio::task::yield_now().await;

    let (reply_tx, reply_rx) = oneshot::channel();
    query_tx
        .send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();

    let count = tokio::time::timeout(Duration::from_secs(2), reply_rx)
        .await
        .expect("priority query should respond during chunked processing")
        .unwrap();
    assert!(count > 0, "query should observe some inserted routes");
    assert!(
        count < route_count as usize,
        "query should be serviced before the full batch completes"
    );

    drop(tx);
    drop(query_tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn peer_down_clears_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

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

    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 0,
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
    assert!(routes.is_empty());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn withdrawal_removes_route() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![
            make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1)),
            make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1)),
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
        peer,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix1), 0)],
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
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].prefix, Prefix::V4(prefix2));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn query_all_peers() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24),
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

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer2,
        announced: vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24),
            Ipv4Addr::new(10, 0, 0, 2),
        )],
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
        peer: None,
        reply: reply_tx,
    })
    .await
    .unwrap();

    let routes = reply_rx.await.unwrap();
    assert_eq!(routes.len(), 2);

    drop(tx);
    handle.await.unwrap();
}

// --- Loc-RIB integration tests ---

#[tokio::test]
async fn best_routes_returns_winner() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

    // Peer1: local_pref 100
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Peer2: local_pref 200 — should win
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer2,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

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
async fn peer_down_promotes_second_best() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
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
        peer: peer2,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Peer2 goes down — peer1 should be promoted
    tx.send(RibUpdate::PeerDown {
        peer: peer2,
        session_id: 0,
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();

    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer1);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn withdrawal_updates_best() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
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
        peer: peer2,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Peer2 withdraws the prefix
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

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();

    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer1);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn different_best_per_prefix() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix_a = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let prefix_b = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

    // Peer1 wins prefix_a (higher LP), peer2 wins prefix_b (higher LP)
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![
            make_route_with_lp(prefix_a, Ipv4Addr::new(1, 0, 0, 1), 200),
            make_route_with_lp(prefix_b, Ipv4Addr::new(1, 0, 0, 1), 100),
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
            make_route_with_lp(prefix_a, Ipv4Addr::new(1, 0, 0, 2), 100),
            make_route_with_lp(prefix_b, Ipv4Addr::new(1, 0, 0, 2), 200),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();

    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 2);

    let best_a = best
        .iter()
        .find(|r| r.prefix == Prefix::V4(prefix_a))
        .unwrap();
    let best_b = best
        .iter()
        .find(|r| r.prefix == Prefix::V4(prefix_b))
        .unwrap();
    assert_eq!(best_a.peer, peer1);
    assert_eq!(best_b.peer, peer2);

    drop(tx);
    handle.await.unwrap();
}

// --- M3 outbound distribution tests ---

#[tokio::test]
async fn peer_up_triggers_initial_table_dump() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Inject a route from source
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

    // Register target for outbound
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

    // Should receive initial table dump
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));
    assert!(update.withdraw.is_empty());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_change_distributes_to_peer() {
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

    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn single_best_send_normalizes_path_id_to_zero() {
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

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
    route.path_id = 42;

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

    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));
    assert_eq!(update.announce[0].path_id, 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn split_horizon_prevents_echo() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    // The route is FROM this peer — should not be sent back
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

    // Force a query to serialize the event loop
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    // Channel should be empty (no outbound update sent)
    assert!(out_rx.try_recv().is_err());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn query_peer_groups_returns_current_policy_context() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::SetPeerPolicyContext {
        peer,
        session_id: 0,
        peer_group: Some("transit".to_string()),
    })
    .await
    .unwrap();
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryPeerGroups { reply: reply_tx })
        .await
        .unwrap();

    let groups = reply_rx.await.unwrap();
    assert_eq!(groups.get(&peer).map(String::as_str), Some("transit"));

    drop(tx);
    handle.await.unwrap();
}

/// Like [`make_route`] but with iBGP origin (iBGP-learned route).
fn make_ibgp_route(prefix: Ipv4Prefix, next_hop: Ipv4Addr) -> Route {
    Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(next_hop),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(next_hop),
        attributes: Arc::new(vec![]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
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
async fn ibgp_route_not_sent_to_ibgp_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Source: iBGP peer
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Target: iBGP peer (is_ebgp: false)
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
    drain_eor(&mut out_rx).await;

    // iBGP-learned route should NOT be sent to iBGP peer
    assert!(out_rx.try_recv().is_err());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn ibgp_route_sent_to_ebgp_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Source: iBGP peer
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Target: eBGP peer (is_ebgp: true)
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

    // Initial dump includes the route (iBGP→eBGP is allowed)
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

    // Then EoR
    drain_eor(&mut out_rx).await;

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn ebgp_route_sent_to_ibgp_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Source: eBGP peer
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

    // Target: iBGP peer (is_ebgp: false)
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

    // Initial dump includes the route (eBGP→iBGP is allowed)
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

    // Then EoR
    drain_eor(&mut out_rx).await;

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn ibgp_split_horizon_withdraw_on_best_change() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Setup: eBGP source announces route, iBGP target receives it
    let ebgp_source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let ibgp_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Register iBGP target peer
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: ibgp_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
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
    drain_eor(&mut out_rx).await;

    // eBGP route → should be advertised to iBGP peer
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: ebgp_source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
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

    // Now the eBGP source goes down, replaced by iBGP source
    tx.send(RibUpdate::PeerDown {
        peer: ebgp_source,
        session_id: 0,
    })
    .await
    .unwrap();

    // Withdraw should be sent to iBGP target
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.withdraw.len(), 1);

    // iBGP source announces the same prefix
    let ibgp_source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: ibgp_source,
        announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 3))],
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

    // iBGP-learned route should NOT be sent to iBGP peer
    assert!(out_rx.try_recv().is_err());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn local_route_sent_to_ibgp_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Register iBGP target peer first
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
    drain_eor(&mut out_rx).await;

    // Inject a local route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: LOCAL_PEER,
        attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::InjectRoute {
        route,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let _ = reply_rx.await;

    // Local route SHOULD be sent to iBGP peer (unlike iBGP-learned routes)
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn local_route_in_initial_table_to_ibgp_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Inject a local route first
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: LOCAL_PEER,
        attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::InjectRoute {
        route,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let _ = reply_rx.await;

    // Register iBGP target peer — should receive local route in initial dump
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

    // Initial dump should include the local route
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

    // Then EoR
    drain_eor(&mut out_rx).await;

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn peer_down_cleans_up_outbound() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (out_tx, _out_rx) = mpsc::channel(64);
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

    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    })
    .await
    .unwrap();

    // Query advertised routes — should be empty after PeerDown
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

#[tokio::test]
async fn inject_route_enters_loc_rib_and_distributes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: LOCAL_PEER,
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
        ]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::InjectRoute {
        route,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    // Should be in Loc-RIB
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].prefix, Prefix::V4(prefix));

    // Should have been distributed
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn withdraw_injected_removes_and_distributes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: LOCAL_PEER,
        attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::InjectRoute {
        route,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let _ = reply_rx.await;

    // Consume the inject announcement
    let _ = out_rx.recv().await;

    // Now withdraw
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::WithdrawInjected {
        prefix: Prefix::V4(prefix),
        path_id: 0,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    // Should receive withdrawal
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.withdraw.len(), 1);
    assert_eq!(update.withdraw[0], (Prefix::V4(prefix), 0));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn distribute_changes_filters_unsendable_families() {
    use rustbgpd_wire::Ipv6Prefix;

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);

    // Register peer with IPv4-only sendable families
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

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

    let v4_route = make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1));
    let v6_route = Route {
        prefix: Prefix::V6(v6_prefix),
        next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: source,
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

    // Send both IPv4 and IPv6 routes
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![v4_route, v6_route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Should only receive IPv4 route
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(v4_prefix));
    assert!(update.withdraw.is_empty());

    // Adj-RIB-Out should only contain IPv4
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let advertised = reply_rx.await.unwrap();
    assert_eq!(advertised.len(), 1);
    assert_eq!(advertised[0].prefix, Prefix::V4(v4_prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn send_initial_table_filters_unsendable_families() {
    use rustbgpd_wire::Ipv6Prefix;

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

    let v4_route = make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1));
    let v6_route = Route {
        prefix: Prefix::V6(v6_prefix),
        next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: source,
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

    // Pre-populate Loc-RIB with both IPv4 and IPv6 routes
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![v4_route, v6_route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Register peer with IPv4-only sendable families — initial dump
    // should filter out the IPv6 route
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

    // Initial table dump should only contain IPv4
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(v4_prefix));
    assert!(update.withdraw.is_empty());

    // Adj-RIB-Out should only contain IPv4
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let advertised = reply_rx.await.unwrap();
    assert_eq!(advertised.len(), 1);
    assert_eq!(advertised[0].prefix, Prefix::V4(v4_prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn dual_stack_peer_receives_both_families() {
    use rustbgpd_wire::Ipv6Prefix;

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

    let v4_route = make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1));
    let v6_route = Route {
        prefix: Prefix::V6(v6_prefix),
        next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: source,
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

    // Pre-populate Loc-RIB
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![v4_route, v6_route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Register peer with dual-stack sendable families
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
        sendable_families: dual_stack_sendable(),
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

    // Should receive both routes in initial dump
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 2);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rr_client_route_reflected_to_all_ibgp() {
    // When RR receives a route from a client, it should reflect to all
    // iBGP peers (both clients and non-clients), except the source.
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 1));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let client_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let nonclient_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

    // Register source as iBGP client
    let (out_tx_src, _) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx_src,
        export_policy: None,
        sendable_families: ipv4_sendable(),
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

    // Register client target
    let (client_tx, mut client_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: client_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: client_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
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
    drain_eor(&mut client_rx).await;

    // Register non-client target
    let (nonclient_tx, mut nonclient_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: nonclient_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: nonclient_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
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
    drain_eor(&mut nonclient_rx).await;

    // Source client sends a route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 4))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Both targets should receive the reflected route
    let client_update = client_rx.recv().await.unwrap();
    assert!(
        !client_update.announce.is_empty(),
        "client should receive reflected route"
    );

    let nonclient_update = nonclient_rx.recv().await.unwrap();
    assert!(
        !nonclient_update.announce.is_empty(),
        "non-client should receive route reflected from client"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rr_nonclient_route_reflected_to_clients_only() {
    // Route from non-client → reflect to clients only (not non-clients).
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 1));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)); // non-client
    let client_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let nonclient_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));

    // Register source as non-client
    let (out_tx_src, _) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx_src,
        export_policy: None,
        sendable_families: ipv4_sendable(),
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

    // Register client target
    let (client_tx, mut client_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: client_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: client_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
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
    drain_eor(&mut client_rx).await;

    // Register non-client target
    let (nonclient_tx, mut nonclient_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: nonclient_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: nonclient_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
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
    drain_eor(&mut nonclient_rx).await;

    // Source sends a route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 2))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Client should get the route
    let update_c = client_rx.recv().await.unwrap();
    assert!(
        !update_c.announce.is_empty(),
        "client should receive non-client route"
    );

    // Non-client should NOT get the route (suppressed by RR)
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        nonclient_rx.try_recv().is_err(),
        "non-client should not receive non-client route"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn non_rr_ibgp_split_horizon_unchanged() {
    // Without cluster_id (no RR), standard split-horizon applies
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

    // Register target first (Loc-RIB empty, clean EoR)
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
        sendable_families: ipv4_sendable(),
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
    drain_eor(&mut out_rx).await;

    // Source sends iBGP route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 2))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // iBGP route should be suppressed (standard split-horizon)
    assert!(
        out_rx.try_recv().is_err(),
        "iBGP route should be suppressed without RR"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rr_ebgp_route_to_all_ibgp() {
    // eBGP-learned routes should go to all iBGP peers regardless of RR role
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 1));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)); // iBGP non-client

    // Register target first (Loc-RIB empty, clean EoR)
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
        sendable_families: ipv4_sendable(),
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
    drain_eor(&mut out_rx).await;

    // eBGP source sends a route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 5))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(
        !update.announce.is_empty(),
        "eBGP route should reach iBGP non-client"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rr_local_route_to_all_ibgp() {
    // Local routes should pass to all iBGP peers even with RR
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 1));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

    // Register target first (Loc-RIB empty, clean EoR)
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
        sendable_families: ipv4_sendable(),
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
    drain_eor(&mut out_rx).await;

    // Inject local route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: LOCAL_PEER,
        attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    let (reply_tx, _) = oneshot::channel();
    tx.send(RibUpdate::InjectRoute {
        route,
        reply: reply_tx,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(
        !update.announce.is_empty(),
        "local route should reach iBGP non-client via RR"
    );

    drop(tx);
    handle.await.unwrap();
}

// --- RPKI integration tests ---
