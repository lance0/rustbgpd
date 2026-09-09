use super::*;
use rustbgpd_bmp::BmpReplay;

fn manager() -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
}

fn register_peer(
    manager: &mut RibManager,
    peer: IpAddr,
    families: Vec<(Afi, Safi)>,
    add_path: bool,
    capacity: usize,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, outbound_rx) = mpsc::channel(capacity);
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id: 7,
        peer_asn: 65_000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: families,
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: if add_path { ipv4_sendable() } else { vec![] },
        add_path_send_max: if add_path { 2 } else { 0 },
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    outbound_rx
}

fn receive_routes(manager: &mut RibManager, routes: Vec<Route>) {
    let source = routes[0].peer;
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: source,
        session_id: 0,
        announced: routes,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    drain_route_chunks(manager);
}

fn drain(receiver: &mut mpsc::Receiver<OutboundRouteUpdate>) -> Vec<OutboundRouteUpdate> {
    let mut updates = Vec::new();
    while let Ok(update) = receiver.try_recv() {
        updates.push(update);
    }
    updates
}

fn request(
    manager: &mut RibManager,
    peer: IpAddr,
    session_id: u64,
    families: Vec<(Afi, Safi)>,
    replay: &Arc<BmpReplay>,
) -> Result<(), crate::RibCommandError> {
    let (ack, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplayPeerOutbound {
        peer,
        session_id,
        families,
        replay: Arc::clone(replay),
        reply: ack,
    });
    response
        .try_recv()
        .expect("synchronous scheduling response")
}

#[test]
fn explicit_replay_preserves_private_grouped_and_add_path_inventory() {
    for (force_private, add_path) in [(true, false), (false, false), (false, true)] {
        let mut manager = manager();
        manager.test_force_ungrouped = force_private;
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
        receive_routes(
            &mut manager,
            vec![make_route_with_lp(prefix, Ipv4Addr::new(192, 0, 2, 1), 200)],
        );
        receive_routes(
            &mut manager,
            vec![make_route_with_lp(prefix, Ipv4Addr::new(192, 0, 2, 2), 100)],
        );
        let peer = "10.0.0.1".parse().unwrap();
        let sibling = "10.0.0.2".parse().unwrap();
        let mut outbound = register_peer(&mut manager, peer, ipv4_sendable(), add_path, 16);
        let mut other = register_peer(&mut manager, sibling, ipv4_sendable(), add_path, 16);
        let baseline = drain(&mut outbound);
        let expected: Vec<_> = baseline.iter().flat_map(|u| u.announce.iter()).collect();
        assert_eq!(expected.len(), if add_path { 2 } else { 1 });
        drain(&mut other);
        let group = manager.grouped_member_of(peer);
        if !add_path {
            assert_eq!(group.is_some(), !force_private);
        }
        let (replay, _enrolled) = BmpReplay::new(Duration::from_secs(5));
        request(&mut manager, peer, 7, ipv4_sendable(), &replay).unwrap();
        let updates = drain(&mut outbound);
        assert!(
            updates.len() >= 2,
            "routes must precede a dedicated terminal envelope"
        );
        let terminal = updates.last().unwrap();
        assert_eq!(terminal.end_of_rib, ipv4_sendable());
        assert!(terminal.announce.is_empty());
        assert!(Arc::ptr_eq(terminal.replay.as_ref().unwrap(), &replay));
        let routes: Vec<_> = updates.iter().flat_map(|u| u.announce.iter()).collect();
        assert_eq!(routes.len(), expected.len());
        for expected in expected {
            let actual = routes
                .iter()
                .find(|route| route.path_id == expected.path_id)
                .unwrap();
            assert_eq!(actual.prefix, expected.prefix);
            assert_eq!(actual.peer, expected.peer);
            assert_eq!(actual.next_hop, expected.next_hop);
            assert_eq!(actual.attributes, expected.attributes);
        }
        if add_path {
            let ids: BTreeSet<_> = routes.iter().map(|route| route.path_id).collect();
            assert_eq!(ids.len(), 2);
        }
        for update in &updates[..updates.len() - 1] {
            assert!(update.end_of_rib.is_empty());
            assert!(update.replay.is_none());
        }
        assert!(
            updates
                .iter()
                .all(|update| update.refresh_markers.is_empty())
        );
        assert!(
            other.try_recv().is_err(),
            "replay must stay on the named peer"
        );
        assert_eq!(manager.grouped_member_of(peer), group);
        assert!(replay.is_valid());
    }
}

#[test]
fn explicit_replay_completes_empty_negotiated_unsendable_ipv6() {
    let mut manager = manager();
    let peer = "10.0.0.1".parse().unwrap();
    let mut outbound = register_peer(&mut manager, peer, ipv4_sendable(), false, 16);
    drain(&mut outbound);
    let (replay, _enrolled) = BmpReplay::new(Duration::from_secs(5));
    request(&mut manager, peer, 7, dual_stack_sendable(), &replay).unwrap();
    let updates = drain(&mut outbound);
    assert!(
        updates
            .iter()
            .all(|u| u.announce.is_empty() && u.refresh_markers.is_empty())
    );
    let terminal = updates
        .last()
        .expect("even empty families need terminal EoRs");
    assert_eq!(terminal.end_of_rib, dual_stack_sendable());
    assert!(Arc::ptr_eq(terminal.replay.as_ref().unwrap(), &replay));
    assert!(
        updates[..updates.len() - 1]
            .iter()
            .all(|u| u.end_of_rib.is_empty())
    );
}

#[test]
fn explicit_replay_rejects_stale_session_and_orf_gate_without_output() {
    let mut manager = manager();
    let peer = "10.0.0.1".parse().unwrap();
    let mut outbound = register_peer(&mut manager, peer, ipv4_sendable(), false, 16);
    drain(&mut outbound);
    let (stale, _enrolled) = BmpReplay::new(Duration::from_secs(5));
    assert!(request(&mut manager, peer, 6, ipv4_sendable(), &stale).is_err());
    assert!(!stale.is_valid());
    assert!(outbound.try_recv().is_err());

    manager
        .peer_orf_pending
        .entry(peer)
        .or_default()
        .insert((Afi::Ipv4, Safi::Unicast));
    let (gated, _enrolled) = BmpReplay::new(Duration::from_secs(5));
    assert!(request(&mut manager, peer, 7, ipv4_sendable(), &gated).is_err());
    assert!(!gated.is_valid());
    assert!(manager.peer_orf_pending[&peer].contains(&(Afi::Ipv4, Safi::Unicast)));
    assert!(outbound.try_recv().is_err());
    assert!(!manager.pending_refresh.contains_key(&peer));
}

#[test]
fn explicit_replay_rejects_selection_deferral_without_releasing_gate() {
    let peer = "10.0.0.1".parse().unwrap();
    let mut manager = manager().with_selection_deferral(crate::SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: vec![crate::SelectionDeferralWaiterConfig {
            peer: "192.0.2.1".parse().unwrap(),
            families: ipv4_sendable(),
        }],
    });
    let mut outbound = register_peer(&mut manager, peer, ipv4_sendable(), false, 16);
    assert!(outbound.try_recv().is_err());
    let (replay, _enrolled) = BmpReplay::new(Duration::from_secs(5));
    assert!(request(&mut manager, peer, 7, ipv4_sendable(), &replay).is_err());
    assert!(!replay.is_valid());
    assert!(outbound.try_recv().is_err());
    assert!(!manager.pending_refresh.contains_key(&peer));
}

#[test]
fn explicit_replay_full_channel_cancels_without_terminal_or_refresh_retry() {
    let mut manager = manager();
    let peer = "10.0.0.1".parse().unwrap();
    let mut outbound = register_peer(&mut manager, peer, ipv4_sendable(), false, 1);
    // Keep the initial EoR queued to fill the sole channel slot.
    let (replay, _enrolled) = BmpReplay::new(Duration::from_secs(5));
    assert!(request(&mut manager, peer, 7, ipv4_sendable(), &replay).is_err());
    assert!(!replay.is_valid());
    let initial = outbound.try_recv().unwrap();
    assert!(initial.replay.is_none());
    assert!(outbound.try_recv().is_err());
    assert!(!manager.pending_refresh.contains_key(&peer));
}

#[test]
fn explicit_replay_terminal_admission_failure_invalidates_admitted_routes() {
    let mut manager = manager();
    let peer = "10.0.0.1".parse().unwrap();
    let mut outbound = register_peer(&mut manager, peer, ipv4_sendable(), false, 1);
    drain(&mut outbound);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    receive_routes(
        &mut manager,
        vec![make_route(prefix, Ipv4Addr::new(192, 0, 2, 1))],
    );
    assert_eq!(outbound.try_recv().unwrap().announce.len(), 1);
    let (replay, _enrolled) = BmpReplay::new(Duration::from_secs(5));
    assert!(request(&mut manager, peer, 7, ipv4_sendable(), &replay).is_err());
    assert!(!replay.is_valid());
    let admitted = outbound
        .try_recv()
        .expect("route replay consumed the sole slot");
    assert_eq!(admitted.announce.len(), 1);
    assert_eq!(admitted.announce[0].prefix, Prefix::V4(prefix));
    assert!(admitted.end_of_rib.is_empty());
    assert!(admitted.refresh_markers.is_empty());
    assert!(admitted.replay.is_none());
    assert!(
        outbound.try_recv().is_err(),
        "failed terminal admission cannot imply completion"
    );
    assert!(!manager.pending_refresh.contains_key(&peer));
}
