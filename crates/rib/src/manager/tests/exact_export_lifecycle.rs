use super::*;

fn test_manager() -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
}

fn peer_up(manager: &mut RibManager, peer: IpAddr, session_id: u64) {
    let (outbound_tx, _outbound_rx) = mpsc::channel(8);
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65001,
        peer_router_id: Ipv4Addr::new(192, 0, 2, 254),
        outbound_tx,
        export_policy: None,
        sendable_families: Vec::new(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: Vec::new(),
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    });
}

fn stable_overlay(manager: &mut RibManager) {
    let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let mut rib = AdjRibIn::new(source);
    rib.insert(make_route(
        prefix,
        match source {
            IpAddr::V4(source) => source,
            IpAddr::V6(_) => unreachable!(),
        },
    ));
    manager.ribs.insert(source, rib);
    manager.register_unicast_announcer(source, Prefix::V4(prefix));
    manager.peer_unexportable.insert(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200)),
        HashSet::from([ExactExportKey::Unicast(Prefix::V4(prefix), 0)]),
    );
}

#[test]
fn collision_and_stale_peer_down_skip_full_exact_export_prune() {
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let mut manager = test_manager();
    stable_overlay(&mut manager);
    peer_up(&mut manager, peer, 1);
    peer_up(&mut manager, peer, 2);

    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 1,
    });
    assert_eq!(manager.test_exact_export_full_prune_calls, 0);

    peer_up(&mut manager, peer, 3);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 1, 0), 24);
    let identity = ExactExportKey::Unicast(Prefix::V4(prefix), 0);
    let mut rib = AdjRibIn::new(peer);
    rib.insert(make_route(prefix, Ipv4Addr::new(192, 0, 2, 1)));
    manager.ribs.insert(peer, rib);
    manager.register_unicast_announcer(peer, Prefix::V4(prefix));
    let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 202));
    manager
        .peer_unexportable
        .insert(target, HashSet::from([identity]));
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 3,
    });
    assert_eq!(
        manager.test_exact_export_full_prune_calls, 0,
        "collision failover must use targeted retirement, not rebuild every live identity"
    );
    assert!(
        !manager.peer_unexportable.contains_key(&target),
        "failover must retire the departed session's identity through targeted cleanup"
    );
}

#[test]
fn authoritative_peer_down_keeps_full_exact_export_prune() {
    let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 201));
    let dead = ExactExportKey::Unicast(
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24)),
        0,
    );
    for (peer, session_id, register) in [
        (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 7, false),
        (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)), 8, true),
    ] {
        let mut manager = test_manager();
        manager
            .peer_unexportable
            .insert(target, HashSet::from([dead.clone()]));
        if register {
            peer_up(&mut manager, peer, session_id);
        }
        manager.handle_update(RibUpdate::PeerDown { peer, session_id });
        assert_eq!(manager.test_exact_export_full_prune_calls, 1);
        assert!(!manager.peer_unexportable.contains_key(&target));
    }
}

fn all_family_rib(peer: IpAddr) -> (AdjRibIn, HashSet<ExactExportKey>) {
    let source = match peer {
        IpAddr::V4(peer) => peer,
        IpAddr::V6(_) => unreachable!(),
    };
    let unicast = make_route(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 1, 0), 24), source);
    let flowspec = make_flowspec_route(source);
    let evpn = make_evpn_imet(source, 101);
    let bgpls = make_bgpls_route(source, 0x41, 100);
    let vpn = make_vpn_rib_route(source, 41, 1041, 100);
    let labeled = make_labeled_rib_route(source, 42, 1042, 100);
    let rtc = make_rtc_rib_route(source, 43, 100);
    let identities = HashSet::from([
        ExactExportKey::Unicast(unicast.prefix, unicast.path_id).nlri_identity(),
        ExactExportKey::FlowSpec(flowspec.selection_key()).nlri_identity(),
        ExactExportKey::Evpn(evpn.key()).nlri_identity(),
        ExactExportKey::BgpLs(bgpls.key()).nlri_identity(),
        ExactExportKey::Vpn(vpn.key()).nlri_identity(),
        ExactExportKey::Labeled(labeled.key()).nlri_identity(),
        ExactExportKey::Rtc(rtc.key()).nlri_identity(),
    ]);
    let mut rib = AdjRibIn::new(peer);
    rib.insert(unicast);
    rib.insert_flowspec(flowspec);
    rib.insert_evpn(evpn);
    rib.insert_bgpls(bgpls);
    rib.insert_vpn(vpn);
    rib.insert_labeled(labeled);
    rib.insert_rtc(rtc);
    (rib, identities)
}

#[test]
fn peer_clear_retires_departing_exact_export_identities_for_all_families() {
    let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4));
    let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4));
    let (rib, identities) = all_family_rib(source);
    assert_eq!(identities.len(), 7);
    let mut manager = test_manager();
    manager.ribs.insert(source, rib);
    manager.peer_unexportable.insert(target, identities.clone());

    manager.peer_down_teardown(source);

    let retained = manager.peer_unexportable.get(&target);
    for identity in identities {
        assert!(
            retained.is_none_or(|overlay| !overlay.contains(&identity)),
            "departing family identity remained live: {identity:?}"
        );
    }
    assert_eq!(manager.test_exact_export_full_prune_calls, 0);
}

#[test]
fn targeted_retirement_preserves_duplicate_source_identity() {
    let departing = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5));
    let surviving = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 6));
    let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 5, 0), 24);
    let identity = ExactExportKey::Unicast(Prefix::V4(prefix), 0);
    let mut manager = test_manager();
    for peer in [departing, surviving] {
        let mut rib = AdjRibIn::new(peer);
        rib.insert(make_route(
            prefix,
            match peer {
                IpAddr::V4(peer) => peer,
                IpAddr::V6(_) => unreachable!(),
            },
        ));
        manager.ribs.insert(peer, rib);
        manager.register_unicast_announcer(peer, Prefix::V4(prefix));
    }
    manager
        .peer_unexportable
        .insert(target, HashSet::from([identity.clone()]));

    manager.peer_down_teardown(departing);

    assert!(manager.peer_unexportable[&target].contains(&identity));
    assert_eq!(manager.test_exact_export_full_prune_calls, 0);
}
