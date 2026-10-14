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
