use super::*;
use crate::injection_lease::LeaseGeneration;
use crate::test_support::peer_v4;
use crate::update::{
    ExplainAdvertisedRoute, ExplainDecision, InjectOutcome, PeerRouteExport,
    RouteExportDisposition, RouteQueryScope,
};

fn connect(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
    family: (Afi, Safi),
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, outbound_rx) = mpsc::channel(64);
    let mut up = super::lifecycle::test_peer_up(peer, session_id, outbound_tx);
    if let RibUpdate::PeerUp {
        sendable_families, ..
    } = &mut up
    {
        *sendable_families = vec![family];
    }
    manager.handle_update(up);
    outbound_rx
}

fn drain(rx: &mut mpsc::Receiver<OutboundRouteUpdate>) -> Vec<OutboundRouteUpdate> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

fn local(prefix: Prefix, blackhole: bool) -> Route {
    let mut route = match prefix {
        Prefix::V4(prefix) => make_route(prefix, Ipv4Addr::UNSPECIFIED),
        Prefix::V6(prefix) => make_v6_route(prefix, Ipv6Addr::UNSPECIFIED),
    };
    set_peer(&mut route, LOCAL_PEER);
    route.origin_type = crate::route::RouteOrigin::Local;
    route.path_id = 17;
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::LocalPref(100),
    ];
    if blackhole {
        attributes.push(PathAttribute::Communities(vec![
            rustbgpd_wire::COMMUNITY_BLACKHOLE,
        ]));
    }
    route.attributes = AttrSet::new(attributes);
    route
}

fn inject(
    manager: &mut RibManager,
    route: Route,
    leased: bool,
) -> (InjectOutcome, Option<LeaseGeneration>) {
    if leased {
        let (reply, mut response) = oneshot::channel();
        manager.handle_update(RibUpdate::InjectLeasedRoute {
            route,
            owner: "deferral-mutation".to_string(),
            lease_seconds: 60,
            reply,
        });
        let (outcome, generation) = response.try_recv().unwrap().unwrap();
        (outcome, Some(generation))
    } else {
        let (reply, mut response) = oneshot::channel();
        manager.handle_update(RibUpdate::InjectRoute { route, reply });
        (response.try_recv().unwrap().unwrap(), None)
    }
}

fn snapshot(manager: &mut RibManager, scope: RouteQueryScope) -> Vec<Route> {
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryRoutesPage {
        scope,
        filter: None,
        after: None,
        expected_version: None,
        page_size: 16,
        reply,
    });
    let page = response.try_recv().unwrap().unwrap();
    assert!(!page.has_more);
    assert_eq!(page.total, u64::try_from(page.routes.len()).unwrap());
    page.routes
}

fn exports(manager: &mut RibManager, prefix: Prefix) -> Vec<PeerRouteExport> {
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryLocalRouteExport {
        keys: vec![(prefix, 17)],
        managed: None,
        resume: None,
        page_size: 16,
        reply,
    });
    let page = response.try_recv().unwrap().unwrap();
    assert!(page.next.is_none());
    assert_eq!(page.routes.len(), 1);
    assert!(page.routes[0].found);
    page.routes.into_iter().next().unwrap().peers
}

fn explain(manager: &mut RibManager, target: PeerId, prefix: Prefix) -> ExplainAdvertisedRoute {
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::ExplainAdvertisedRoute {
        peer: target,
        prefix,
        rd: None,
        labeled: false,
        source: None,
        reply,
    });
    response.try_recv().unwrap().unwrap()
}

#[expect(
    clippy::too_many_lines,
    reason = "one mutation transcript checks exact delivery, retained state, readback, and EoR recovery"
)]
fn removing_blackhole_from_same_key(prefix: Prefix, leased: bool) {
    let family = match prefix {
        Prefix::V4(_) => (Afi::Ipv4, Safi::Unicast),
        Prefix::V6(_) => (Afi::Ipv6, Safi::Unicast),
    };
    let waiter = peer_v4(Ipv4Addr::new(192, 0, 2, 1));
    let existing = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let late = peer_v4(Ipv4Addr::new(10, 0, 0, 3));
    let source = peer_v4(Ipv4Addr::new(10, 0, 0, 9));
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(crate::SelectionDeferralConfig {
            timeout: Duration::from_mins(2),
            waiters: vec![crate::SelectionDeferralWaiterConfig {
                peer: waiter,
                families: vec![family],
            }],
        });
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: waiter,
        session_id: 11,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![family],
        peer_enhanced_refresh: false,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let mut waiter_rx = connect(&mut manager, waiter, 11, family);
    let mut existing_rx = connect(&mut manager, existing, 22, family);
    let mut source_rx = connect(&mut manager, source, 99, family);
    assert!(manager.selection_deferred(family));
    assert!(drain(&mut existing_rx).is_empty());

    let mut fallback = local(prefix, false);
    set_peer(&mut fallback, source);
    fallback.origin_type = crate::route::RouteOrigin::Ebgp;
    fallback.path_id = 91;
    fallback.next_hop = match prefix {
        Prefix::V4(_) => IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
        Prefix::V6(_) => IpAddr::V6("2001:db8::9".parse().unwrap()),
    };
    fallback.attributes = AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65_009])],
        }),
        PathAttribute::LocalPref(300),
    ]);
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: source,
        session_id: 99,
        announced: vec![fallback],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    while manager.process_next_route_chunk() {}
    assert!(snapshot(&mut manager, RouteQueryScope::Best).is_empty());

    let tagged = local(prefix, true);
    assert!(
        tagged
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_BLACKHOLE)
    );
    let (outcome, generation) = inject(&mut manager, tagged, leased);
    assert_eq!(outcome, InjectOutcome::Created);
    let updates = drain(&mut existing_rx);
    assert!(
        updates
            .iter()
            .all(|update| update.withdraw.is_empty() && update.end_of_rib.is_empty())
    );
    assert_eq!(
        updates
            .iter()
            .flat_map(|update| update.announce.iter())
            .map(|route| {
                (
                    route.prefix,
                    route.path_id,
                    route.peer,
                    route
                        .communities()
                        .contains(&rustbgpd_wire::COMMUNITY_BLACKHOLE),
                )
            })
            .collect::<Vec<_>>(),
        vec![(prefix, 0, LOCAL_PEER, true)]
    );
    assert_eq!(
        exports(&mut manager, prefix)
            .iter()
            .find(|row| row.peer == existing)
            .unwrap()
            .disposition,
        RouteExportDisposition::Committed
    );

    let ordinary = local(prefix, false);
    assert!(
        !ordinary
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_BLACKHOLE)
    );
    let (outcome, replacement_generation) = inject(&mut manager, ordinary, leased);
    assert_eq!(outcome, InjectOutcome::Replaced);
    assert_eq!(
        replacement_generation, generation,
        "same-owner replacement preserves generation"
    );
    let local_rows = snapshot(
        &mut manager,
        RouteQueryScope::Received {
            peer: Some(LOCAL_PEER),
        },
    );
    assert_eq!(local_rows.len(), 1);
    assert_eq!((local_rows[0].prefix, local_rows[0].path_id), (prefix, 17));
    assert!(
        !local_rows[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_BLACKHOLE)
    );
    let replacement_exports = exports(&mut manager, prefix);
    let existing_export = replacement_exports
        .iter()
        .find(|row| row.peer == existing)
        .unwrap();
    assert_eq!(
        (existing_export.disposition, existing_export.reason.as_str()),
        (RouteExportDisposition::Pending, "selection_deferred")
    );
    let replacement_updates = drain(&mut existing_rx);
    let selected_after_replacement = snapshot(&mut manager, RouteQueryScope::Best);
    let existing_explain = explain(&mut manager, existing, prefix);

    let mut late_rx = connect(&mut manager, late, 33, family);
    let late_initial = drain(&mut late_rx);
    let late_explain = explain(&mut manager, late, prefix);
    let late_export = exports(&mut manager, prefix)
        .into_iter()
        .find(|row| row.peer == late)
        .unwrap();
    assert_eq!(
        (late_export.disposition, late_export.reason.as_str()),
        (RouteExportDisposition::Pending, "selection_deferred")
    );
    let retained = snapshot(
        &mut manager,
        RouteQueryScope::Received { peer: Some(source) },
    );
    assert_eq!(retained.len(), 1);
    assert_eq!((retained[0].peer, retained[0].path_id), (source, 91));
    assert!(!retained[0].is_stale && !retained[0].is_llgr_stale);
    assert!(manager.selection_deferred(family));

    assert_eq!(
        replacement_updates
            .iter()
            .flat_map(|update| update.withdraw.iter())
            .copied()
            .collect::<Vec<_>>(),
        vec![(prefix, 0)],
        "removing BLACKHOLE withdraws the old bypassed route before EoR; prefix={prefix}, leased={leased}; selected={selected_after_replacement:?}; explain={existing_explain:?}"
    );
    assert!(
        replacement_updates
            .iter()
            .all(|update| update.announce.is_empty() && update.end_of_rib.is_empty())
    );
    assert!(
        selected_after_replacement.is_empty(),
        "the ordinary replacement must stay unselected"
    );
    assert_eq!(existing_explain.decision, ExplainDecision::NoBestRoute);
    assert!(!existing_explain.already_advertised);
    assert!(
        late_initial.is_empty(),
        "a later initial table must not revive the old BLACKHOLE route"
    );
    assert_eq!(late_explain.decision, ExplainDecision::NoBestRoute);
    assert!(!late_explain.already_advertised);

    manager.handle_update(RibUpdate::EndOfRib {
        peer: waiter,
        session_id: 11,
        afi: family.0,
        safi: family.1,
    });
    let selected = snapshot(&mut manager, RouteQueryScope::Best);
    assert_eq!(selected.len(), 1);
    assert_eq!(
        (selected[0].prefix, selected[0].peer, selected[0].path_id),
        (prefix, source, 91)
    );
    for rx in [&mut existing_rx, &mut late_rx] {
        let updates = drain(rx);
        let mut terminal = false;
        let mut announced = Vec::new();
        let mut markers = 0;
        for update in updates {
            assert_eq!(update.withdraw, [] as [(Prefix, u32); 0]);
            for route in update.announce.iter() {
                assert!(!terminal, "fallback data must precede its EoR");
                announced.push((
                    route.prefix,
                    route.path_id,
                    route.peer,
                    route
                        .communities()
                        .contains(&rustbgpd_wire::COMMUNITY_BLACKHOLE),
                ));
            }
            if update.end_of_rib.contains(&family) {
                terminal = true;
                markers += 1;
            }
        }
        assert_eq!(announced, vec![(prefix, 0, source, false)]);
        assert_eq!(markers, 1);
    }
    let _ = drain(&mut waiter_rx);
    let _ = drain(&mut source_rx);
}

#[test]
fn unleased_ipv4_blackhole_removal_withdraws_same_key_before_release() {
    removing_blackhole_from_same_key(
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 18, 0, 0), 24)),
        false,
    );
}

#[test]
fn unleased_ipv6_blackhole_removal_withdraws_same_key_before_release() {
    removing_blackhole_from_same_key(
        Prefix::V6(Ipv6Prefix::new("2001:db8:10::".parse().unwrap(), 64)),
        false,
    );
}

#[test]
fn leased_ipv4_blackhole_removal_withdraws_same_key_before_release() {
    removing_blackhole_from_same_key(
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 18, 0, 0), 24)),
        true,
    );
}

#[test]
fn leased_ipv6_blackhole_removal_withdraws_same_key_before_release() {
    removing_blackhole_from_same_key(
        Prefix::V6(Ipv6Prefix::new("2001:db8:10::".parse().unwrap(), 64)),
        true,
    );
}
