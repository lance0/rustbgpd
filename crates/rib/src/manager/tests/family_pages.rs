use super::*;
use crate::update::{RibRowsPage, RoutePageError};

fn fixture() -> (RibManager, Ipv4Addr) {
    let (_tx, rx) = mpsc::channel(8);
    (
        RibManager::new(
            rx,
            dummy_query_rx(),
            None,
            Some(Ipv4Addr::new(192, 0, 2, 254)),
            BgpMetrics::new(),
        ),
        Ipv4Addr::new(192, 0, 2, 1),
    )
}

fn vpn_page(
    manager: &mut RibManager,
    scope: RouteQueryScope,
    after: Option<crate::update::VpnRouteQueryKey>,
    version: Option<RoutePageVersion>,
    size: usize,
) -> Result<RibRowsPage<crate::route::VpnRibRoute>, RoutePageError> {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryVpnRoutesPage {
        scope,
        filter: None,
        after,
        expected_version: version,
        page_size: size,
        reply,
    });
    rx.try_recv().unwrap()
}

#[test]
fn vpn_family_pages_bound_order_and_keep_add_path_candidates() {
    let (mut manager, peer) = fixture();
    let mut route = make_vpn_rib_route(peer, 1, 100, 100);
    manager.ribs.insert(peer.into(), AdjRibIn::new(peer.into()));
    for path in (0..1005).rev() {
        route.path_id = path;
        manager
            .ribs
            .get_mut(&peer.into())
            .unwrap()
            .insert_vpn(route.clone());
    }
    let scope = RouteQueryScope::Received {
        peer: Some(peer.into()),
    };
    let first = vpn_page(&mut manager, scope, None, None, usize::MAX).unwrap();
    assert_eq!(first.routes.len(), 1000);
    assert_eq!(first.total, 1005);
    assert!(first.has_more);
    assert!(
        first
            .routes
            .windows(2)
            .all(|pair| pair[0].path_id < pair[1].path_id)
    );
    let route = first.routes.last().unwrap();
    let after = (route.nlri.key(), route.peer, route.path_id);
    let next = vpn_page(&mut manager, scope, Some(after), Some(first.version), 10).unwrap();
    assert_eq!(next.routes.len(), 5);
    assert_eq!(next.total, 1005);
    assert!(!next.has_more);
    assert_eq!(next.routes[0].path_id, 1000);
    assert_eq!(
        vpn_page(&mut manager, RouteQueryScope::Best, None, None, 10)
            .unwrap()
            .total,
        0
    );
    let destination: IpAddr = "192.0.2.2".parse().unwrap();
    let mut out = AdjRibOut::new(destination);
    out.insert_vpn(first.routes[0].clone());
    manager.adj_ribs_out.insert(destination, out);
    let page = vpn_page(
        &mut manager,
        RouteQueryScope::Advertised { peer: destination },
        None,
        None,
        10,
    )
    .unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.routes[0].peer, IpAddr::V4(peer));
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryVpnRoutesPage {
        scope,
        filter: Some(Box::new(|r| r.path_id >= 1003)),
        after: None,
        expected_version: None,
        page_size: 1,
        reply,
    });
    let filtered = rx.try_recv().unwrap().unwrap();
    assert_eq!(filtered.total, 2);
    assert_eq!(filtered.routes.len(), 1);
    assert_eq!(filtered.routes[0].path_id, 1003);
    assert!(filtered.has_more);
}

#[test]
fn vpn_family_pages_invalidate_on_receive_withdraw_and_stale_sweep() {
    let (mut manager, peer) = fixture();
    let mut route = make_vpn_rib_route(peer, 1, 100, 100);
    let scope = RouteQueryScope::Received {
        peer: Some(peer.into()),
    };
    manager.handle_vpn_routes_received(peer.into(), vec![route.clone()], vec![]);
    let first = vpn_page(&mut manager, scope, None, None, 1).unwrap();
    let after = (route.nlri.key(), route.peer, route.path_id);
    route.next_hop = "192.0.2.9".parse().unwrap();
    manager.handle_vpn_routes_received(peer.into(), vec![route.clone()], vec![]);
    assert_eq!(
        vpn_page(&mut manager, scope, Some(after), Some(first.version), 1).unwrap_err(),
        RoutePageError::Invalidated
    );
    let fresh = vpn_page(&mut manager, scope, None, None, 1).unwrap();
    manager.handle_vpn_routes_received(peer.into(), vec![], vec![route.key()]);
    assert_eq!(
        vpn_page(&mut manager, scope, Some(after), Some(fresh.version), 1).unwrap_err(),
        RoutePageError::Invalidated
    );
    manager.handle_vpn_routes_received(peer.into(), vec![route.clone()], vec![]);
    let fresh = vpn_page(&mut manager, scope, None, None, 1).unwrap();
    manager
        .ribs
        .get_mut(&peer.into())
        .unwrap()
        .mark_stale_vpn(route.afi_safi());
    manager.sweep_gr_stale(peer.into());
    assert_eq!(
        vpn_page(&mut manager, scope, Some(after), Some(fresh.version), 1).unwrap_err(),
        RoutePageError::Invalidated
    );
}

fn labeled_page(
    manager: &mut RibManager,
    scope: RouteQueryScope,
    after: Option<crate::update::LabeledRouteQueryKey>,
    version: Option<RoutePageVersion>,
    size: usize,
) -> Result<RibRowsPage<crate::route::LabeledRibRoute>, RoutePageError> {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryLabeledRoutesPage {
        scope,
        filter: None,
        after,
        expected_version: version,
        page_size: size,
        reply,
    });
    rx.try_recv().unwrap()
}

#[test]
fn labeled_family_pages_bound_order_and_keep_add_path_candidates() {
    let (mut manager, peer) = fixture();
    let mut route = make_labeled_rib_route(peer, 1, 100, 100);
    manager.ribs.insert(peer.into(), AdjRibIn::new(peer.into()));
    for path in (0..1005).rev() {
        route.path_id = path;
        manager
            .ribs
            .get_mut(&peer.into())
            .unwrap()
            .insert_labeled(route.clone());
    }
    let scope = RouteQueryScope::Received {
        peer: Some(peer.into()),
    };
    let first = labeled_page(&mut manager, scope, None, None, usize::MAX).unwrap();
    assert_eq!(first.routes.len(), 1000);
    assert_eq!(first.total, 1005);
    assert!(first.has_more);
    assert!(
        first
            .routes
            .windows(2)
            .all(|pair| pair[0].path_id < pair[1].path_id)
    );
    let route = first.routes.last().unwrap();
    let after = (route.nlri.prefix, route.peer, route.path_id);
    let next = labeled_page(&mut manager, scope, Some(after), Some(first.version), 10).unwrap();
    assert_eq!(next.routes.len(), 5);
    assert_eq!(next.total, 1005);
    assert!(!next.has_more);
    assert_eq!(next.routes[0].path_id, 1000);
    assert_eq!(
        labeled_page(&mut manager, RouteQueryScope::Best, None, None, 10)
            .unwrap()
            .total,
        0
    );
    let destination: IpAddr = "192.0.2.2".parse().unwrap();
    let mut out = AdjRibOut::new(destination);
    out.insert_labeled(first.routes[0].clone());
    manager.adj_ribs_out.insert(destination, out);
    let page = labeled_page(
        &mut manager,
        RouteQueryScope::Advertised { peer: destination },
        None,
        None,
        10,
    )
    .unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.routes[0].peer, IpAddr::V4(peer));
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryLabeledRoutesPage {
        scope,
        filter: Some(Box::new(|r| r.path_id >= 1003)),
        after: None,
        expected_version: None,
        page_size: 1,
        reply,
    });
    let filtered = rx.try_recv().unwrap().unwrap();
    assert_eq!(filtered.total, 2);
    assert_eq!(filtered.routes.len(), 1);
    assert_eq!(filtered.routes[0].path_id, 1003);
    assert!(filtered.has_more);
}

#[test]
fn labeled_family_pages_invalidate_on_receive_withdraw_and_stale_sweep() {
    let (mut manager, peer) = fixture();
    let mut route = make_labeled_rib_route(peer, 1, 100, 100);
    let scope = RouteQueryScope::Received {
        peer: Some(peer.into()),
    };
    manager.handle_labeled_routes_received(peer.into(), vec![route.clone()], vec![]);
    let first = labeled_page(&mut manager, scope, None, None, 1).unwrap();
    let after = (route.nlri.prefix, route.peer, route.path_id);
    route.next_hop = "192.0.2.9".parse().unwrap();
    manager.handle_labeled_routes_received(peer.into(), vec![route.clone()], vec![]);
    assert_eq!(
        labeled_page(&mut manager, scope, Some(after), Some(first.version), 1).unwrap_err(),
        RoutePageError::Invalidated
    );
    let fresh = labeled_page(&mut manager, scope, None, None, 1).unwrap();
    manager.handle_labeled_routes_received(peer.into(), vec![], vec![route.key()]);
    assert_eq!(
        labeled_page(&mut manager, scope, Some(after), Some(fresh.version), 1).unwrap_err(),
        RoutePageError::Invalidated
    );
    manager.handle_labeled_routes_received(peer.into(), vec![route.clone()], vec![]);
    let fresh = labeled_page(&mut manager, scope, None, None, 1).unwrap();
    manager
        .ribs
        .get_mut(&peer.into())
        .unwrap()
        .mark_stale_labeled(route.afi_safi());
    manager.sweep_gr_stale(peer.into());
    assert_eq!(
        labeled_page(&mut manager, scope, Some(after), Some(fresh.version), 1).unwrap_err(),
        RoutePageError::Invalidated
    );
}

fn rtc_page(
    manager: &mut RibManager,
    scope: RouteQueryScope,
    after: Option<crate::update::RtcRouteQueryKey>,
    version: Option<RoutePageVersion>,
    size: usize,
) -> Result<RibRowsPage<crate::route::RtcRibRoute>, RoutePageError> {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryRtcRoutesPage {
        scope,
        filter: None,
        after,
        expected_version: version,
        page_size: size,
        reply,
    });
    rx.try_recv().unwrap()
}

#[test]
fn rtc_family_pages_bound_order_and_keep_add_path_candidates() {
    let (mut manager, peer) = fixture();
    let mut route = make_rtc_rib_route(peer, 1, 100);
    manager.ribs.insert(peer.into(), AdjRibIn::new(peer.into()));
    for path in (0..1005).rev() {
        route.path_id = path;
        manager
            .ribs
            .get_mut(&peer.into())
            .unwrap()
            .insert_rtc(route.clone());
    }
    let scope = RouteQueryScope::Received {
        peer: Some(peer.into()),
    };
    let first = rtc_page(&mut manager, scope, None, None, usize::MAX).unwrap();
    assert_eq!(first.routes.len(), 1000);
    assert_eq!(first.total, 1005);
    assert!(first.has_more);
    assert!(
        first
            .routes
            .windows(2)
            .all(|pair| pair[0].path_id < pair[1].path_id)
    );
    let route = first.routes.last().unwrap();
    let after = (route.nlri, route.peer, route.path_id);
    let next = rtc_page(&mut manager, scope, Some(after), Some(first.version), 10).unwrap();
    assert_eq!(next.routes.len(), 5);
    assert_eq!(next.total, 1005);
    assert!(!next.has_more);
    assert_eq!(next.routes[0].path_id, 1000);
    assert_eq!(
        rtc_page(&mut manager, RouteQueryScope::Best, None, None, 10)
            .unwrap()
            .total,
        0
    );
    let destination: IpAddr = "192.0.2.2".parse().unwrap();
    let mut out = AdjRibOut::new(destination);
    out.insert_rtc(first.routes[0].clone());
    manager.adj_ribs_out.insert(destination, out);
    let page = rtc_page(
        &mut manager,
        RouteQueryScope::Advertised { peer: destination },
        None,
        None,
        10,
    )
    .unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.routes[0].peer, IpAddr::V4(peer));
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryRtcRoutesPage {
        scope,
        filter: Some(Box::new(|r| r.path_id >= 1003)),
        after: None,
        expected_version: None,
        page_size: 1,
        reply,
    });
    let filtered = rx.try_recv().unwrap().unwrap();
    assert_eq!(filtered.total, 2);
    assert_eq!(filtered.routes.len(), 1);
    assert_eq!(filtered.routes[0].path_id, 1003);
    assert!(filtered.has_more);
}

#[test]
fn rtc_family_pages_invalidate_on_receive_withdraw_and_stale_sweep() {
    let (mut manager, peer) = fixture();
    let mut route = make_rtc_rib_route(peer, 1, 100);
    let scope = RouteQueryScope::Received {
        peer: Some(peer.into()),
    };
    manager.handle_rtc_routes_received(peer.into(), vec![route.clone()], vec![]);
    let first = rtc_page(&mut manager, scope, None, None, 1).unwrap();
    let after = (route.nlri, route.peer, route.path_id);
    route.next_hop = "192.0.2.9".parse().unwrap();
    manager.handle_rtc_routes_received(peer.into(), vec![route.clone()], vec![]);
    assert_eq!(
        rtc_page(&mut manager, scope, Some(after), Some(first.version), 1).unwrap_err(),
        RoutePageError::Invalidated
    );
    let fresh = rtc_page(&mut manager, scope, None, None, 1).unwrap();
    manager.handle_rtc_routes_received(peer.into(), vec![], vec![route.key()]);
    assert_eq!(
        rtc_page(&mut manager, scope, Some(after), Some(fresh.version), 1).unwrap_err(),
        RoutePageError::Invalidated
    );
    manager.handle_rtc_routes_received(peer.into(), vec![route.clone()], vec![]);
    let fresh = rtc_page(&mut manager, scope, None, None, 1).unwrap();
    manager
        .ribs
        .get_mut(&peer.into())
        .unwrap()
        .mark_stale_rtc(route.afi_safi());
    manager.sweep_gr_stale(peer.into());
    assert_eq!(
        rtc_page(&mut manager, scope, Some(after), Some(fresh.version), 1).unwrap_err(),
        RoutePageError::Invalidated
    );
}
#[test]
fn vpn_grouped_pages_apply_rtc_split_horizon_and_encoder_rejections() {
    let (mut manager, _) = fixture();
    let first: IpAddr = "192.0.2.10".parse().unwrap();
    let second: IpAddr = "192.0.2.11".parse().unwrap();
    let source = Ipv4Addr::new(192, 0, 2, 12);
    let mut receivers = Vec::new();
    for peer in [first, second] {
        let (outbound_tx, outbound_rx) = mpsc::channel(32);
        manager.handle_update(RibUpdate::PeerUp {
            peer,
            session_id: 0,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx,
            export_policy: None,
            sendable_families: vec![(Afi::Ipv4, Safi::MplsVpn), (Afi::Ipv4, Safi::RtConstrain)],
            is_ebgp: false,
            route_reflector_client: true,
            orr_vantage: None,
            per_client_best: false,
            interpret_rfc1997: true,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: vec![],
            negotiated_llgr_families: vec![],
        });
        receivers.push(outbound_rx);
    }
    assert!(
        manager.vpn_grouped_member_of(first).is_some(),
        "fixture must exercise group-owned VPN state"
    );
    assert_eq!(
        manager.vpn_grouped_member_of(first),
        manager.vpn_grouped_member_of(second)
    );
    let first_v4 = Ipv4Addr::new(192, 0, 2, 10);
    let second_v4 = Ipv4Addr::new(192, 0, 2, 11);
    let first_membership = make_rtc_rib_route(first_v4, 100, 100);
    let second_membership = make_rtc_rib_route(second_v4, 200, 100);
    manager.handle_rtc_routes_received(first, vec![first_membership.clone()], vec![]);
    manager.handle_rtc_routes_received(second, vec![second_membership], vec![]);
    let accepted = make_vpn_rib_route_with_rts(source, 1, vec![rt(100)]);
    let filtered = make_vpn_rib_route_with_rts(source, 2, vec![rt(200)]);
    let own = make_vpn_rib_route_with_rts(first_v4, 3, vec![rt(100)]);
    manager.handle_vpn_routes_received(
        source.into(),
        vec![accepted.clone(), filtered.clone()],
        vec![],
    );
    manager.handle_vpn_routes_received(first, vec![own], vec![]);
    let scope = RouteQueryScope::Advertised { peer: first };
    let page = vpn_page(&mut manager, scope, None, None, 10).unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.routes[0].nlri.key(), accepted.nlri.key());
    assert_eq!(page.routes[0].peer, IpAddr::V4(source));
    let second_page = vpn_page(
        &mut manager,
        RouteQueryScope::Advertised { peer: second },
        None,
        None,
        10,
    )
    .unwrap();
    assert_eq!(second_page.total, 1);
    assert_eq!(second_page.routes[0].nlri.key(), filtered.nlri.key());
    manager
        .peer_unexportable
        .entry(first)
        .or_default()
        .insert(ExactExportKey::Vpn(accepted.key()));
    assert_eq!(
        vpn_page(&mut manager, scope, None, None, 10).unwrap().total,
        0
    );
    manager.peer_unexportable.get_mut(&first).unwrap().clear();
    let before = vpn_page(&mut manager, scope, None, None, 10).unwrap();
    let after = (accepted.nlri.key(), accepted.peer, accepted.path_id);
    manager.mark_outbound_dirty(first);
    manager.handle_rtc_routes_received(
        first,
        vec![make_rtc_rib_route(first_v4, 200, 100)],
        vec![first_membership.key()],
    );
    assert_eq!(
        vpn_page(&mut manager, scope, Some(after), Some(before.version), 10).unwrap_err(),
        RoutePageError::Invalidated
    );
    assert_eq!(
        vpn_page(&mut manager, scope, None, None, 10).unwrap_err(),
        RoutePageError::ResyncInProgress
    );
    for receiver in &mut receivers {
        while receiver.try_recv().is_ok() {}
    }
    manager.resync_dirty_peers_bounded();
    let changed = vpn_page(&mut manager, scope, None, None, 10).unwrap();
    assert_eq!(changed.total, 1);
    assert_eq!(changed.routes[0].nlri.key(), filtered.nlri.key());
}

#[test]
fn vpn_grouped_page_refuses_unadmitted_announces_and_undelivered_withdraws() {
    use super::exportability::MockExactExportEncoder;
    let (mut manager, source) = fixture();
    let destination: IpAddr = "192.0.2.2".parse().unwrap();
    let (outbound_tx, mut receiver) = mpsc::channel(4);
    let padding = outbound_tx.clone();
    manager.handle_update(RibUpdate::PeerUp {
        peer: destination,
        session_id: 0,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv4, Safi::MplsVpn)],
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    while receiver.try_recv().is_ok() {}
    let encoder = MockExactExportEncoder::accepting(1);
    manager
        .peer_export_encoders
        .insert(destination, encoder.clone());
    let old = make_vpn_rib_route(source, 1, 100, 100);
    manager.handle_vpn_routes_received(source.into(), vec![old.clone()], vec![]);
    let accepted = receiver.try_recv().unwrap();
    assert_eq!(accepted.vpn_announce.len(), 1);
    assert_eq!(accepted.vpn_announce[0].nlri.key(), old.nlri.key());
    while receiver.try_recv().is_ok() {}
    let scope = RouteQueryScope::Advertised { peer: destination };
    let first = vpn_page(&mut manager, scope, None, None, 1).unwrap();
    assert_eq!(first.total, 1);
    let mut unexportable = make_vpn_rib_route(source, 2, 200, 100);
    unexportable.nlri.labels = vec![
        MplsLabelEntry::try_new(200, 0, false).unwrap(),
        MplsLabelEntry::try_new(201, 0, true).unwrap(),
    ];
    encoder.set_profile(2, [ExactExportKey::Vpn(unexportable.key())]);
    let probes_before = encoder.probed();
    for _ in 0..4 {
        padding.try_send(OutboundRouteUpdate::default()).unwrap();
    }
    manager.handle_vpn_routes_received(source.into(), vec![unexportable.clone()], vec![old.key()]);
    let gid = manager.vpn_grouped_member_of(destination).unwrap();
    assert!(
        manager.group_ribs[&gid]
            .table
            .get_vpn(&unexportable.key())
            .is_some()
    );
    assert!(manager.group_ribs[&gid].table.get_vpn(&old.key()).is_none());
    assert_eq!(
        encoder.probed(),
        probes_before,
        "a full channel stops before the exact-export probe"
    );
    assert!(
        !manager
            .peer_unexportable
            .get(&destination)
            .is_some_and(|keys| keys.contains(&ExactExportKey::Vpn(unexportable.key())))
    );
    assert_eq!(
        vpn_page(&mut manager, scope, None, None, 1).unwrap_err(),
        RoutePageError::ResyncInProgress
    );
    assert_eq!(
        vpn_page(
            &mut manager,
            scope,
            Some((old.nlri.key(), old.peer, old.path_id)),
            Some(first.version),
            1
        )
        .unwrap_err(),
        RoutePageError::Invalidated
    );
    while receiver.try_recv().is_ok() {}
    manager.resync_dirty_peers_bounded();
    assert!(
        manager.peer_unexportable[&destination].contains(&ExactExportKey::Vpn(unexportable.key()))
    );
    let settled = vpn_page(&mut manager, scope, None, None, 10).unwrap();
    assert_eq!(settled.total, 0);
    assert_eq!(settled.routes.len(), 0);
    let mut delivered_withdrawals = Vec::new();
    while let Ok(update) = receiver.try_recv() {
        delivered_withdrawals.extend(update.vpn_withdraw);
    }
    assert!(
        delivered_withdrawals
            .iter()
            .any(|key| key.nlri_key == old.nlri.key()),
        "the admitted old route is withdrawn during recovery"
    );
}

#[test]
fn vpn_grouped_page_rejects_closed_receiver_until_fresh_session() {
    let (mut manager, source) = fixture();
    let destination: IpAddr = "192.0.2.2".parse().unwrap();
    let register = |manager: &mut RibManager, session_id| {
        let (outbound_tx, receiver) = mpsc::channel(16);
        manager.handle_update(RibUpdate::PeerUp {
            peer: destination,
            session_id,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx,
            export_policy: None,
            sendable_families: vec![(Afi::Ipv4, Safi::MplsVpn)],
            is_ebgp: false,
            route_reflector_client: true,
            orr_vantage: None,
            per_client_best: false,
            interpret_rfc1997: true,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: vec![],
            negotiated_llgr_families: vec![],
        });
        receiver
    };
    let mut receiver = register(&mut manager, 0);
    while receiver.try_recv().is_ok() {}
    let old = make_vpn_rib_route(source, 1, 100, 100);
    manager.handle_vpn_routes_received(source.into(), vec![old.clone()], vec![]);
    assert_eq!(
        receiver.try_recv().unwrap().vpn_announce[0].key(),
        old.key()
    );
    let scope = RouteQueryScope::Advertised { peer: destination };
    assert_eq!(
        vpn_page(&mut manager, scope, None, None, 10).unwrap().total,
        1
    );

    drop(receiver);
    let new = make_vpn_rib_route(source, 2, 200, 100);
    manager.handle_vpn_routes_received(source.into(), vec![new.clone()], vec![old.key()]);
    let gid = manager.vpn_grouped_member_of(destination).unwrap();
    assert!(manager.group_ribs[&gid].table.get_vpn(&new.key()).is_some());
    assert!(manager.group_ribs[&gid].table.get_vpn(&old.key()).is_none());
    assert!(manager.outbound_channel_gone(destination));
    assert!(!manager.dirty_peers.contains(&destination));
    assert!(
        !manager.group_ribs[&gid]
            .dirty_members
            .contains(&destination)
    );
    assert_eq!(
        vpn_page(&mut manager, scope, None, None, 10).unwrap_err(),
        RoutePageError::ResyncInProgress,
        "closed delivery must not expose the staged announcement or hide the owed withdrawal"
    );

    manager.handle_update(RibUpdate::PeerDown {
        peer: destination,
        session_id: 0,
    });
    assert!(manager.vpn_grouped_member_of(destination).is_none());
    assert!(!manager.outbound_peers.contains_key(&destination));
    assert!(
        vpn_page(&mut manager, scope, None, None, 10)
            .unwrap()
            .routes
            .is_empty()
    );
    let mut fresh = register(&mut manager, 1);
    let mut admitted = Vec::new();
    while let Ok(update) = fresh.try_recv() {
        admitted.extend(update.vpn_announce.into_iter().map(|route| route.key()));
    }
    assert_eq!(admitted, vec![new.key()]);
    let page = vpn_page(&mut manager, scope, None, None, 10).unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.routes[0].key(), new.key());
}

fn bgpls_page(
    manager: &mut RibManager,
    scope: RouteQueryScope,
    after: Option<crate::update::BgpLsRouteQueryKey>,
    version: Option<RoutePageVersion>,
    size: usize,
) -> Result<RibRowsPage<BgpLsRibRoute>, RoutePageError> {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryBgpLsRoutesPage {
        scope,
        filter: None,
        after,
        expected_version: version,
        page_size: size,
        reply,
    });
    rx.try_recv().unwrap()
}

fn bgpls_query_key(route: &BgpLsRibRoute) -> crate::update::BgpLsRouteQueryKey {
    (
        route.family,
        route.nlri.nlri_type.as_u16(),
        route.nlri.route_distinguisher,
        route.nlri.payload.clone(),
        route.peer,
        route.path_id,
    )
}

/// A continuation walk over the selected BGP-LS table returns every row
/// exactly once in identity order, across both SAFIs and the clamp.
#[test]
fn bgpls_family_pages_walk_every_route_once_in_identity_order() {
    let (mut manager, peer) = fixture();
    let other = Ipv4Addr::new(192, 0, 2, 2);
    for suffix in (0..25).rev() {
        let advertiser = if suffix % 2 == 0 { peer } else { other };
        manager.handle_bgpls_routes_received(
            advertiser.into(),
            vec![make_bgpls_route(advertiser, suffix, 100)],
            vec![],
        );
    }
    let mut vpn = make_bgpls_route(peer, 0, 100);
    vpn.family = BgpLsFamily::LinkStateVpn;
    vpn.nlri.route_distinguisher = Some([0, 0, 0xfd, 0xe8, 0, 0, 0, 1]);
    manager.handle_bgpls_routes_received(peer.into(), vec![vpn], vec![]);

    let all = bgpls_page(&mut manager, RouteQueryScope::Best, None, None, usize::MAX).unwrap();
    assert_eq!(all.routes.len(), 26);
    assert!(!all.has_more);
    let expected: Vec<_> = all.routes.iter().map(bgpls_query_key).collect();
    assert!(expected.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(all.routes[25].family, BgpLsFamily::LinkStateVpn);

    let mut walked = Vec::new();
    let mut after = None;
    let mut version = None;
    loop {
        let page = bgpls_page(&mut manager, RouteQueryScope::Best, after, version, 4).unwrap();
        assert_eq!(page.total, 26);
        assert!(page.routes.len() <= 4);
        walked.extend(page.routes.iter().map(bgpls_query_key));
        if !page.has_more {
            break;
        }
        after = walked.last().cloned();
        version = Some(page.version);
    }
    assert_eq!(walked, expected);

    let received = bgpls_page(
        &mut manager,
        RouteQueryScope::Received {
            peer: Some(other.into()),
        },
        None,
        None,
        100,
    )
    .unwrap();
    assert_eq!(received.total, 12);
    assert!(received.routes.iter().all(|r| r.peer == IpAddr::V4(other)));
}

/// Receive, withdraw and advertised commits each fence an open BGP-LS walk.
#[test]
fn bgpls_family_pages_invalidate_on_receive_withdraw_and_export() {
    let (mut manager, peer) = fixture();
    let destination = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: destination,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: bgpls_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    });
    let routes: Vec<_> = (1..=2).map(|s| make_bgpls_route(peer, s, 100)).collect();
    manager.handle_bgpls_routes_received(peer.into(), routes.clone(), vec![]);
    while out_rx.try_recv().is_ok() {}

    let best = RouteQueryScope::Best;
    let first = bgpls_page(&mut manager, best, None, None, 1).unwrap();
    assert!(first.has_more);
    let after = Some(bgpls_query_key(&first.routes[0]));
    manager.handle_bgpls_routes_received(peer.into(), vec![make_bgpls_route(peer, 3, 100)], vec![]);
    assert_eq!(
        bgpls_page(&mut manager, best, after.clone(), Some(first.version), 1).unwrap_err(),
        RoutePageError::Invalidated
    );
    let fresh = bgpls_page(&mut manager, best, None, None, 1).unwrap();
    manager.handle_bgpls_routes_received(peer.into(), vec![], vec![routes[1].key()]);
    assert_eq!(
        bgpls_page(&mut manager, best, after, Some(fresh.version), 1).unwrap_err(),
        RoutePageError::Invalidated
    );

    let advertised = RouteQueryScope::Advertised { peer: destination };
    let first = bgpls_page(&mut manager, advertised, None, None, 1).unwrap();
    assert_eq!(first.total, 2, "routes 1 and 3 remain exported");
    let after = Some(bgpls_query_key(&first.routes[0]));
    manager.handle_bgpls_routes_received(peer.into(), vec![make_bgpls_route(peer, 4, 100)], vec![]);
    assert_eq!(
        bgpls_page(&mut manager, advertised, after, Some(first.version), 1).unwrap_err(),
        RoutePageError::Invalidated
    );
}

type OrrPage<T> = Result<RibRowsPage<T>, RoutePageError>;

fn orr_node_page(
    manager: &mut RibManager,
    after: Option<crate::update::OrrNodeQueryKey>,
    version: Option<RoutePageVersion>,
    size: usize,
) -> OrrPage<crate::orr::OrrNodeSnapshot> {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryOrrTopologyNodesPage {
        after,
        expected_version: version,
        page_size: size,
        reply,
    });
    rx.try_recv().unwrap()
}

fn orr_link_page(
    manager: &mut RibManager,
    after: Option<crate::update::OrrLinkQueryKey>,
    version: Option<RoutePageVersion>,
    size: usize,
) -> OrrPage<crate::orr::OrrLinkSnapshot> {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryOrrTopologyLinksPage {
        after,
        expected_version: version,
        page_size: size,
        reply,
    });
    rx.try_recv().unwrap()
}

/// Node and link walks visit every topology element once in identity
/// order. Two parallel links with identical endpoints, cost and (empty)
/// addresses differ only by their Link NLRI and must both appear.
#[test]
fn orr_topology_pages_walk_every_element_once_and_fence_on_change() {
    use crate::orr::fixtures::{X, Y, link_route, square_topology};
    let (mut manager, peer) = fixture();
    let link_id = |id: u8| {
        rustbgpd_wire::BgpLsTlv::new(258, bytes::Bytes::from(vec![0, 0, 0, id, 0, 0, 0, id]))
    };
    let mut routes = square_topology(peer);
    routes.push(link_route(peer, X, Y, Some(5), &[link_id(1)]));
    routes.push(link_route(peer, X, Y, Some(5), &[link_id(2)]));
    manager.handle_bgpls_routes_received(peer.into(), routes, vec![]);
    let topology =
        crate::orr::OrrTopology::build(manager.ribs.values().flat_map(AdjRibIn::iter_bgpls));
    assert_eq!(topology.links().len(), 6);

    let all = orr_node_page(&mut manager, None, None, usize::MAX).unwrap();
    assert_eq!(all.routes.len(), 4);
    assert!(!all.has_more);
    assert_eq!(all.routes.iter().map(|n| n.link_count).sum::<u32>(), 6);
    let mut expected_nodes: Vec<_> = topology
        .node_keys()
        .iter()
        .map(|key| key.as_bytes().to_vec())
        .collect();
    expected_nodes.sort();
    let mut walked = Vec::new();
    let (mut after, mut version) = (None, None);
    loop {
        let page = orr_node_page(&mut manager, after, version, 3).unwrap();
        assert_eq!(page.total, 4);
        walked.extend(page.routes.iter().map(|node| node.key_hex.clone()));
        if !page.has_more {
            break;
        }
        after = Some(expected_nodes[walked.len() - 1].clone());
        version = Some(page.version);
    }
    let mut keys: Vec<_> = topology.node_keys().iter().collect();
    keys.sort_by_key(|key| key.as_bytes());
    let expected_hex: Vec<_> = topology
        .render_nodes(keys)
        .into_iter()
        .map(|node| node.key_hex)
        .collect();
    assert_eq!(walked, expected_hex);

    let link_key = |link: &crate::orr::OrrLink| {
        (
            topology.node_key(link.local).unwrap().as_bytes().to_vec(),
            topology.node_key(link.remote).unwrap().as_bytes().to_vec(),
            link.nlri.route_distinguisher,
            link.nlri.payload.clone(),
        )
    };
    let mut sorted: Vec<_> = topology.links().iter().collect();
    sorted.sort_by_key(|link| link_key(link));
    let row = |link: &crate::orr::OrrLinkSnapshot| {
        (
            link.local_key_hex.clone(),
            link.remote_key_hex.clone(),
            link.cost,
            link.addresses.clone(),
        )
    };
    let expected_rows: Vec<_> = topology
        .render_links(sorted.iter().copied())
        .iter()
        .map(row)
        .collect();
    let mut walked = Vec::new();
    let (mut after, mut version) = (None, None);
    loop {
        let page = orr_link_page(&mut manager, after, version, 1).unwrap();
        assert_eq!(page.total, 6);
        walked.extend(page.routes.iter().map(row));
        if !page.has_more {
            break;
        }
        after = Some(link_key(sorted[walked.len() - 1]));
        version = Some(page.version);
    }
    assert_eq!(walked, expected_rows);
    assert_eq!(
        walked.iter().filter(|row| row.2 == 5).count(),
        2,
        "both parallel X->Y links appear"
    );

    let first = orr_node_page(&mut manager, None, None, 1).unwrap();
    manager.handle_bgpls_routes_received(
        peer.into(),
        vec![link_route(peer, Y, X, Some(7), &[])],
        vec![],
    );
    assert_eq!(
        orr_node_page(
            &mut manager,
            Some(expected_nodes[0].clone()),
            Some(first.version),
            1
        )
        .unwrap_err(),
        RoutePageError::Invalidated
    );
}

/// A topology walk keeps one source when the vantage set fills or empties:
/// the on-demand build and the vantage cache both exclude BGP-LS families
/// whose selection is still deferred, so the continuation sees the same
/// topology page 1 counted.
#[test]
fn orr_topology_pages_keep_one_source_across_vantage_changes() {
    use crate::orr::fixtures::{link_route, square_topology};
    let (manager, peer) = fixture();
    let waiter: IpAddr = "192.0.2.50".parse().unwrap();
    let mut manager = manager.with_selection_deferral(crate::SelectionDeferralConfig {
        timeout: std::time::Duration::from_secs(30),
        waiters: vec![crate::SelectionDeferralWaiterConfig {
            peer: waiter,
            families: vec![(Afi::BgpLs, Safi::BgpLsVpn)],
        }],
    });
    assert!(manager.selection_deferred((Afi::BgpLs, Safi::BgpLsVpn)));
    let mut routes = square_topology(peer);
    for (local, remote) in [(5, 6), (6, 5)] {
        let mut route = link_route(peer, local, remote, Some(1), &[]);
        route.family = BgpLsFamily::LinkStateVpn;
        route.nlri.route_distinguisher = Some([0, 0, 0, 1, 0, 0, 0, 1]);
        routes.push(route);
    }
    manager.handle_bgpls_routes_received(peer.into(), routes, vec![]);
    let mut keys: Vec<_> = manager
        .build_orr_topology()
        .node_keys()
        .iter()
        .map(|key| key.as_bytes().to_vec())
        .collect();
    keys.sort();

    let vantage = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 3));
    for fill in [true, false] {
        let first = orr_node_page(&mut manager, None, None, 1).unwrap();
        assert_eq!(
            first.total, 4,
            "deferred BGP-LS VPN links are not topology yet"
        );
        assert!(first.has_more);
        if fill {
            manager.peer_orr_vantage.insert(waiter, vantage);
        } else {
            manager.peer_orr_vantage.clear();
        }
        manager.recompute_orr();
        match orr_node_page(&mut manager, Some(keys[0].clone()), Some(first.version), 1) {
            Err(RoutePageError::Invalidated) => {}
            Ok(next) => assert_eq!(
                next.total, first.total,
                "a continuation must page the topology page 1 counted"
            ),
            Err(other) => panic!("unexpected page error {other:?}"),
        }
    }
}

fn register_destination(
    manager: &mut RibManager,
    destination: IpAddr,
    families: Vec<(Afi, Safi)>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, out_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: destination,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: families,
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    });
    out_rx
}

/// Removing a destination's non-empty Adj-RIB-Out fences an open BGP-LS
/// advertised walk, so the next page cannot read as a finished walk.
#[test]
fn bgpls_advertised_pages_invalidate_when_outbound_state_clears() {
    let (mut manager, peer) = fixture();
    let destination: IpAddr = "192.0.2.3".parse().unwrap();
    let _out = register_destination(&mut manager, destination, bgpls_sendable());
    let routes: Vec<_> = (1..=2).map(|s| make_bgpls_route(peer, s, 100)).collect();
    manager.handle_bgpls_routes_received(peer.into(), routes, vec![]);
    let scope = RouteQueryScope::Advertised { peer: destination };
    let first = bgpls_page(&mut manager, scope, None, None, 1).unwrap();
    assert_eq!(first.total, 2);
    let after = Some(bgpls_query_key(&first.routes[0]));
    manager.clear_outbound_peer_state(destination);
    assert_eq!(
        bgpls_page(&mut manager, scope, after, Some(first.version), 1).unwrap_err(),
        RoutePageError::Invalidated
    );
}

/// The same fence covers the sibling families, shown here for labeled
/// unicast, whose advertised rows also live only in the Adj-RIB-Out.
#[test]
fn labeled_advertised_pages_invalidate_when_outbound_state_clears() {
    let (mut manager, peer) = fixture();
    let destination: IpAddr = "192.0.2.3".parse().unwrap();
    let _out = register_destination(&mut manager, destination, labeled_sendable());
    let routes: Vec<_> = (1..=2)
        .map(|octet| make_labeled_rib_route(peer, octet, 100, 100))
        .collect();
    manager.handle_labeled_routes_received(peer.into(), routes, vec![]);
    let scope = RouteQueryScope::Advertised { peer: destination };
    let first = labeled_page(&mut manager, scope, None, None, 1).unwrap();
    assert_eq!(first.total, 2);
    let route = &first.routes[0];
    let after = Some((route.nlri.prefix, route.peer, route.path_id));
    manager.clear_outbound_peer_state(destination);
    assert_eq!(
        labeled_page(&mut manager, scope, after, Some(first.version), 1).unwrap_err(),
        RoutePageError::Invalidated
    );
}

/// Without vantages a whole node and link walk builds the topology once;
/// a topology change drops that build, fences the walk and the next page
/// rebuilds. A vantage cache takes over without keeping a second copy.
#[test]
fn orr_topology_page_walks_build_once_per_version() {
    use crate::orr::fixtures::{X, Y, link_route, square_topology};
    let (mut manager, peer) = fixture();
    let link_id = |id: u8| {
        rustbgpd_wire::BgpLsTlv::new(258, bytes::Bytes::from(vec![0, 0, 0, id, 0, 0, 0, id]))
    };
    let mut routes = square_topology(peer);
    routes.push(link_route(peer, X, Y, Some(5), &[link_id(1)]));
    routes.push(link_route(peer, X, Y, Some(5), &[link_id(2)]));
    manager.handle_bgpls_routes_received(peer.into(), routes, vec![]);

    let mut keys: Vec<_> = manager
        .build_orr_topology()
        .node_keys()
        .iter()
        .map(|key| key.as_bytes().to_vec())
        .collect();
    keys.sort();
    let mut nodes = Vec::new();
    let (mut after, mut version) = (None, None);
    loop {
        let page = orr_node_page(&mut manager, after, version, 1).unwrap();
        nodes.extend(page.routes);
        if !page.has_more {
            break;
        }
        after = Some(keys[nodes.len() - 1].clone());
        version = Some(page.version);
    }
    assert_eq!(nodes.len(), 4);
    let links = orr_link_page(&mut manager, None, None, 1000).unwrap();
    assert_eq!(links.total, 6);
    assert_eq!(
        manager.orr_page_topology_builds, 1,
        "one build serves the walk"
    );

    // Each reported outgoing count matches a brute-force count over the
    // links, including the two parallel X->Y links.
    let topology = manager.build_orr_topology();
    for node in &nodes {
        let brute = topology
            .links()
            .iter()
            .filter(|link| {
                topology
                    .node_key(link.local)
                    .is_some_and(|key| hex_of(key.as_bytes()) == node.key_hex)
            })
            .count();
        assert_eq!(node.link_count as usize, brute, "{}", node.key_hex);
    }
    let mut counts: Vec<_> = nodes.iter().map(|node| node.link_count).collect();
    counts.sort_unstable();
    assert_eq!(counts, [0, 2, 2, 2], "X counts both parallel links");

    let first = orr_node_page(&mut manager, None, None, 1).unwrap();
    manager.handle_bgpls_routes_received(
        peer.into(),
        vec![link_route(peer, Y, X, Some(7), &[])],
        vec![],
    );
    assert!(
        manager.orr_page_topology.is_none(),
        "a change drops the build"
    );
    assert_eq!(
        orr_node_page(&mut manager, Some(keys[0].clone()), Some(first.version), 1).unwrap_err(),
        RoutePageError::Invalidated
    );
    let fresh = orr_link_page(&mut manager, None, None, 1000).unwrap();
    assert_eq!(fresh.total, 7);
    assert_eq!(manager.orr_page_topology_builds, 2);

    manager
        .peer_orr_vantage
        .insert("192.0.2.9".parse().unwrap(), "10.0.1.3".parse().unwrap());
    manager.recompute_orr();
    assert!(
        manager.orr_page_topology.is_none(),
        "the vantage cache takes over"
    );
    assert_eq!(
        orr_link_page(&mut manager, None, None, 1000).unwrap().total,
        7
    );
    assert_eq!(manager.orr_page_topology_builds, 2);
}

fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
