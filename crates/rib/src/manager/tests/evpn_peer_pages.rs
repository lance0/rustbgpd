use super::*;
use crate::update::{EvpnRoutePage, EvpnRouteQueryKey, RoutePageError, RoutePageVersion};

fn page(
    manager: &mut RibManager,
    scope: RouteQueryScope,
    after: Option<EvpnRouteQueryKey>,
    version: Option<RoutePageVersion>,
    size: usize,
) -> Result<EvpnRoutePage, RoutePageError> {
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryEvpnRoutesPage {
        scope,
        filter: None,
        after,
        expected_version: version,
        page_size: size,
        reply,
    });
    rx.try_recv().unwrap()
}

fn fixture() -> (RibManager, IpAddr) {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 254)),
        BgpMetrics::new(),
    );
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    manager.ribs.insert(peer, AdjRibIn::new(peer));
    (manager, peer)
}

#[test]
fn evpn_pages_bound_copy_and_order_without_losing_non_best_rows() {
    let (mut manager, peer) = fixture();
    for tag in (0..1005).rev() {
        manager
            .ribs
            .get_mut(&peer)
            .unwrap()
            .insert_evpn(make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), tag));
    }
    let scope = RouteQueryScope::Received { peer: Some(peer) };
    let first = page(&mut manager, scope, None, None, usize::MAX).unwrap();
    assert_eq!(first.routes.len(), 1000);
    assert_eq!(first.total, 1005);
    assert!(first.has_more);
    assert!(
        first
            .routes
            .windows(2)
            .all(|pair| pair[0].key() < pair[1].key())
    );
    assert_eq!(
        manager.loc_rib.iter_evpn().count(),
        0,
        "received does not use best table"
    );
    let last = first.routes.last().unwrap();
    let second = page(
        &mut manager,
        scope,
        Some((last.key(), last.peer)),
        Some(first.version),
        10,
    )
    .unwrap();
    assert_eq!(second.routes.len(), 5);
    assert_eq!(second.total, 1005);
    assert!(!second.has_more);
    assert!(second.routes[0].key() > last.key());
    assert_eq!(
        page(&mut manager, scope, None, Some(first.version), 10).unwrap_err(),
        RoutePageError::Invalidated
    );
    let (reply, mut rx) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryEvpnRoutesPage {
        scope,
        filter: Some(Box::new(|route| {
            matches!(route.route,
            EvpnRoute::Imet(ref route) if route.ethernet_tag.0 >= 1003)
        })),
        after: None,
        expected_version: None,
        page_size: 1,
        reply,
    });
    let filtered = rx.try_recv().unwrap().unwrap();
    assert_eq!(filtered.total, 2);
    assert_eq!(filtered.routes.len(), 1);
    assert!(filtered.has_more);
}

#[test]
fn evpn_received_pages_invalidate_for_types_three_four_and_attributes() {
    let (mut manager, peer) = fixture();
    let scope = RouteQueryScope::Received { peer: Some(peer) };
    let mut route = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    manager.process_evpn_announce_chunk(peer, vec![route.clone()]);
    let first = page(&mut manager, scope, None, None, 1).unwrap();
    let dataplane_generation = manager.evpn_dataplane_generation;
    Arc::make_mut(&mut route.attributes).push(PathAttribute::Communities(vec![123]));
    manager.process_evpn_announce_chunk(peer, vec![route.clone()]);
    assert_eq!(manager.evpn_dataplane_generation, dataplane_generation);
    assert_eq!(
        page(
            &mut manager,
            scope,
            Some((route.key(), peer)),
            Some(first.version),
            1
        )
        .unwrap_err(),
        RoutePageError::Invalidated
    );

    let before = page(&mut manager, scope, None, None, 1).unwrap();
    route.route = EvpnRoute::Es(rustbgpd_wire::EvpnEs {
        rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 100]),
        esi: EthernetSegmentIdentifier([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
        originator_ip: peer,
    });
    manager.process_evpn_announce_chunk(peer, vec![route.clone()]);
    assert_eq!(manager.evpn_dataplane_generation, dataplane_generation);
    assert_eq!(
        page(
            &mut manager,
            scope,
            Some((route.key(), peer)),
            Some(before.version),
            1
        )
        .unwrap_err(),
        RoutePageError::Invalidated
    );
    let before = page(&mut manager, scope, None, None, 1).unwrap();
    manager.process_evpn_withdraw_chunk(peer, vec![route.key()]);
    assert_eq!(
        page(
            &mut manager,
            scope,
            Some((route.key(), peer)),
            Some(before.version),
            1
        )
        .unwrap_err(),
        RoutePageError::Invalidated
    );
}

#[test]
fn evpn_advertised_scope_is_destination_and_mutation_version_tracks_commit() {
    let (mut manager, source) = fixture();
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(32);
    manager.handle_update(RibUpdate::PeerUp {
        peer: destination,
        session_id: 0,
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
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
        per_client_best: false,
        interpret_rfc1997: true,
    });
    while out_rx.try_recv().is_ok() {}
    manager.peer_is_rr_client.insert(source, true);
    let route = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let scope = RouteQueryScope::Advertised { peer: destination };
    let before = page(&mut manager, scope, None, None, 1).unwrap();
    manager.process_evpn_announce_chunk(source, vec![route.clone()]);
    let sent = out_rx
        .try_recv()
        .expect("reflection committed to destination");
    assert_eq!(sent.evpn_announce.len(), 1);
    let first = page(&mut manager, scope, None, None, 1).unwrap();
    assert_ne!(first.version, before.version);
    assert_eq!(first.routes.len(), 1);
    assert_eq!(first.routes[0].peer, source);
    assert_eq!(
        page(
            &mut manager,
            RouteQueryScope::Advertised { peer: source },
            None,
            None,
            1
        )
        .unwrap()
        .total,
        0
    );
    manager.handle_update(RibUpdate::PeerDown {
        peer: destination,
        session_id: 0,
    });
    assert_eq!(
        page(
            &mut manager,
            scope,
            Some((route.key(), source)),
            Some(first.version),
            1
        )
        .unwrap_err(),
        RoutePageError::Invalidated
    );
    assert_eq!(page(&mut manager, scope, None, None, 1).unwrap().total, 0);
    let received = RouteQueryScope::Received { peer: Some(source) };
    let first = page(&mut manager, received, None, None, 1).unwrap();
    manager.handle_update(RibUpdate::PeerDeleted { peer: source });
    assert_eq!(
        page(
            &mut manager,
            received,
            Some((route.key(), source)),
            Some(first.version),
            1
        )
        .unwrap_err(),
        RoutePageError::Invalidated
    );
}

#[tokio::test]
async fn evpn_pages_invalidate_across_gr_retention_and_eor_sweep() {
    let (mut manager, peer) = fixture();
    let scope = RouteQueryScope::Received { peer: Some(peer) };
    let route = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    manager.process_evpn_announce_chunk(peer, vec![route.clone()]);
    let first = page(&mut manager, scope, None, None, 1).unwrap();
    assert!(manager.handle_peer_graceful_restart(
        peer,
        0,
        120,
        360,
        evpn_sendable(),
        false,
        vec![],
        0
    ));
    let retained = page(&mut manager, scope, None, None, 1).unwrap();
    assert_eq!(retained.total, 1);
    assert!(retained.routes[0].is_stale);
    assert_ne!(retained.version, first.version);
    assert_eq!(
        page(
            &mut manager,
            scope,
            Some((route.key(), peer)),
            Some(first.version),
            1
        )
        .unwrap_err(),
        RoutePageError::Invalidated
    );
    manager.handle_end_of_rib(peer, Afi::L2Vpn, Safi::Evpn);
    assert_eq!(page(&mut manager, scope, None, None, 1).unwrap().total, 0);
    assert_eq!(
        page(
            &mut manager,
            scope,
            Some((route.key(), peer)),
            Some(retained.version),
            1
        )
        .unwrap_err(),
        RoutePageError::Invalidated
    );
}

#[test]
fn evpn_non_best_attribute_change_still_invalidates_received_pages() {
    let (mut manager, peer) = fixture();
    let other: IpAddr = "10.0.0.2".parse().unwrap();
    manager.ribs.insert(other, AdjRibIn::new(other));
    let mut best = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    best.attributes = Arc::new(vec![PathAttribute::LocalPref(200)]);
    let mut candidate = best.clone();
    candidate.peer = other;
    candidate.attributes = Arc::new(vec![PathAttribute::LocalPref(100)]);
    manager.process_evpn_announce_chunk(peer, vec![best.clone()]);
    manager.process_evpn_announce_chunk(other, vec![candidate.clone()]);
    let scope = RouteQueryScope::Received { peer: Some(other) };
    let before = page(&mut manager, scope, None, None, 1).unwrap();
    Arc::make_mut(&mut candidate.attributes).push(PathAttribute::Communities(vec![7]));
    manager.process_evpn_announce_chunk(other, vec![candidate]);
    assert_eq!(manager.loc_rib.get_evpn(&best.key()).unwrap().peer, peer);
    assert_eq!(
        page(
            &mut manager,
            scope,
            Some((best.key(), other)),
            Some(before.version),
            1
        )
        .unwrap_err(),
        RoutePageError::Invalidated
    );
}
