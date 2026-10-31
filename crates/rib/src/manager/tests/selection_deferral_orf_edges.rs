use super::*;
use crate::update::OutboundRouteUpdate;

const V4: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const V6: (Afi, Safi) = (Afi::Ipv6, Safi::Unicast);
const SOURCE_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 91);
const TARGET_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 92);
const SOURCE_SESSION: u64 = 11;
const TARGET_SESSION: u64 = 32;

fn ordinary_v4() -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24))
}

fn ordinary_v6(last: u16) -> Prefix {
    Prefix::V6(Ipv6Prefix::new(
        Ipv6Addr::new(0x2001, 0xdb8, last, 0, 0, 0, 0, 0),
        48,
    ))
}

fn connect(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
    restarting: bool,
    receive_orf: &[(Afi, Safi)],
    capacity: usize,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: restarting,
        peer_gr_helper: true,
        peer_gr_families: vec![V4, V6],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (outbound_tx, outbound_rx) = mpsc::channel(capacity);
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![V4, V6],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: receive_orf.to_vec(),
        negotiated_llgr_families: vec![],
    });
    outbound_rx
}

fn receive(manager: &mut RibManager, prefixes: &[Prefix]) {
    let announced = prefixes
        .iter()
        .map(|prefix| {
            let mut route = match prefix {
                Prefix::V4(prefix) => make_route(*prefix, SOURCE_ADDR),
                Prefix::V6(prefix) => {
                    make_v6_route(*prefix, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
                }
            };
            set_peer(&mut route, peer_v4(SOURCE_ADDR));
            route
        })
        .collect();
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE_ADDR),
        session_id: SOURCE_SESSION,
        announced,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(manager);
}

fn setup(
    receive_orf: &[(Afi, Safi)],
    capacity: usize,
    restarting: bool,
) -> (
    RibManager,
    mpsc::Receiver<OutboundRouteUpdate>,
    mpsc::Receiver<OutboundRouteUpdate>,
) {
    let source = peer_v4(SOURCE_ADDR);
    let target = peer_v4(TARGET_ADDR);
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: source,
                families: vec![V4],
            }],
        });
    let source_rx = connect(&mut manager, source, SOURCE_SESSION, false, &[], 64);
    receive(&mut manager, &[ordinary_v4(), ordinary_v6(0x100)]);
    assert!(manager.selection_convergence_held(V4));
    assert!(!manager.selection_convergence_held(V6));
    assert!(manager.loc_rib.get(&ordinary_v4()).is_none());
    assert!(manager.loc_rib.get(&ordinary_v6(0x100)).is_some());

    if restarting {
        let mut previous_rx = connect(&mut manager, target, 31, false, &[], 64);
        while previous_rx.try_recv().is_ok() {}
        manager.handle_update(RibUpdate::PeerGracefulRestart {
            peer: target,
            session_id: 31,
            restart_time: 120,
            stale_routes_time: 360,
            gr_families: vec![V4, V6],
            peer_llgr_capable: false,
            peer_llgr_families: vec![],
            llgr_stale_time: 0,
        });
        assert!(manager.gr_peers.contains_key(&target));
    }
    let target_rx = connect(
        &mut manager,
        target,
        TARGET_SESSION,
        restarting,
        receive_orf,
        capacity,
    );
    assert!(manager.grouped_member_of(target).is_none());
    (manager, source_rx, target_rx)
}

fn release_v4(manager: &mut RibManager) {
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(SOURCE_ADDR),
        session_id: SOURCE_SESSION,
        afi: V4.0,
        safi: V4.1,
    });
    assert!(!manager.selection_convergence_held(V4));
    assert!(manager.loc_rib.get(&ordinary_v4()).is_some());
}

fn refresh(manager: &mut RibManager, family: (Afi, Safi)) {
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        queued: Arc::default(),
        peer: peer_v4(TARGET_ADDR),
        session_id: TARGET_SESSION,
        afi: family.0,
        safi: family.1,
    });
}

fn observe(
    receiver: &mut mpsc::Receiver<OutboundRouteUpdate>,
    v4_open: bool,
    seen: &mut BTreeSet<Prefix>,
    eors: &mut HashMap<(Afi, Safi), usize>,
) -> usize {
    let mut updates = 0;
    while let Ok(update) = receiver.try_recv() {
        updates += 1;
        assert_eq!(update.withdraw, [] as [(Prefix, u32); 0]);
        for &(afi, safi, _) in &update.refresh_markers {
            assert!(
                v4_open || (afi, safi) != V4,
                "IPv4 refresh demarcation must wait for its own ORF refresh"
            );
        }
        for route in update.announce.iter() {
            assert_eq!(route.peer, peer_v4(SOURCE_ADDR));
            assert_eq!(route.path_id, 0);
            assert!(
                v4_open || route.prefix != ordinary_v4(),
                "IPv4 table must remain behind its ORF gate"
            );
            seen.insert(route.prefix);
        }
        for family in update.end_of_rib {
            assert!(
                v4_open || family != V4,
                "IPv4 initial EoR must wait for IPv4's own ORF refresh"
            );
            let required = match family {
                V4 => ordinary_v4(),
                V6 => ordinary_v6(0x100),
                _ => panic!("unexpected End-of-RIB family: {family:?}"),
            };
            assert!(
                seen.contains(&required),
                "family table must precede its EoR"
            );
            let count = eors.entry(family).or_default();
            *count += 1;
            assert_eq!(*count, 1, "each family owes exactly one initial EoR");
        }
    }
    updates
}

fn assert_completed(manager: &mut RibManager, receiver: &mut mpsc::Receiver<OutboundRouteUpdate>) {
    let target = peer_v4(TARGET_ADDR);
    assert!(!manager.pending_eor.contains_key(&target));
    assert!(!manager.gr_deferred_eor.contains_key(&target));
    assert!(!manager.peer_orf_pending.contains_key(&target));
    assert!(!manager.dirty_peers.contains(&target));
    manager.flush_pending_eor(target);
    assert!(
        receiver.try_recv().is_err(),
        "initial markers are consumed once"
    );
}

#[test]
fn selection_release_does_not_flush_an_orf_held_initial_eor() {
    let (mut manager, _source_rx, mut target_rx) = setup(&[V4, V6], 64, true);
    let target = peer_v4(TARGET_ADDR);
    assert!(!manager.dirty_peers.contains(&target));
    assert!(target_rx.try_recv().is_err());
    assert!(manager.peer_orf_pending[&target].contains(&V4));
    let mut seen = BTreeSet::new();
    let mut eors = HashMap::new();

    release_v4(&mut manager);
    observe(&mut target_rx, false, &mut seen, &mut eors);
    assert!(
        manager
            .pending_eor
            .get(&target)
            .is_some_and(|held| held.contains(&V4))
    );
    refresh(&mut manager, V6);
    assert!(observe(&mut target_rx, false, &mut seen, &mut eors) > 0);
    assert_eq!(eors, HashMap::from([(V6, 1)]));
    assert_eq!(seen, BTreeSet::from([ordinary_v6(0x100)]));
    assert!(manager.pending_eor[&target].contains(&V4));
    assert!(manager.peer_orf_pending[&target].contains(&V4));

    refresh(&mut manager, V4);
    assert!(observe(&mut target_rx, true, &mut seen, &mut eors) > 0);
    assert_eq!(eors, HashMap::from([(V4, 1), (V6, 1)]));
    assert_eq!(seen, BTreeSet::from([ordinary_v4(), ordinary_v6(0x100)]));
    assert_completed(&mut manager, &mut target_rx);
}

#[test]
fn dirty_ipv6_retry_does_not_piggyback_an_orf_held_ipv4_initial_eor() {
    let (mut manager, _source_rx, mut target_rx) = setup(&[V4], 2, true);
    let target = peer_v4(TARGET_ADDR);
    assert_eq!(manager.outbound_peers[&target].capacity(), 0);
    assert!(!manager.dirty_peers.contains(&target));
    receive(&mut manager, &[ordinary_v6(0x101)]);
    assert!(
        manager.dirty_peers.contains(&target),
        "IPv6 admission really failed"
    );

    // Main queues the selection-release EoR after distribution: retain the
    // genuine full channel through release, then free space for its retry.
    release_v4(&mut manager);
    assert!(manager.dirty_peers.contains(&target));
    assert!(manager.pending_eor[&target].contains(&V4));
    assert!(manager.peer_orf_pending[&target].contains(&V4));
    let mut seen = BTreeSet::new();
    let mut eors = HashMap::new();
    assert_eq!(observe(&mut target_rx, false, &mut seen, &mut eors), 2);
    assert_eq!(eors, HashMap::from([(V6, 1)]));
    assert_eq!(seen, BTreeSet::from([ordinary_v6(0x100)]));

    let commits = manager.dirty_resync_commits;
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    assert!(observe(&mut target_rx, false, &mut seen, &mut eors) > 0);
    assert!(manager.dirty_resync_commits > commits);
    assert!(
        seen.contains(&ordinary_v6(0x101)),
        "the missed IPv6 row recovered"
    );
    assert_eq!(eors, HashMap::from([(V6, 1)]));
    assert!(manager.pending_eor[&target].contains(&V4));
    assert!(manager.peer_orf_pending[&target].contains(&V4));

    refresh(&mut manager, V4);
    assert!(observe(&mut target_rx, true, &mut seen, &mut eors) > 0);
    assert_eq!(eors, HashMap::from([(V4, 1), (V6, 1)]));
    assert_eq!(
        seen,
        BTreeSet::from([ordinary_v4(), ordinary_v6(0x100), ordinary_v6(0x101)])
    );
    assert_completed(&mut manager, &mut target_rx);
}

#[test]
fn non_restarting_orf_peer_keeps_backpressured_honest_empty_initial_eor() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let _source_rx = connect(
        &mut manager,
        peer_v4(SOURCE_ADDR),
        SOURCE_SESSION,
        false,
        &[],
        64,
    );
    receive(&mut manager, &[ordinary_v4(), ordinary_v6(0x100)]);
    let target = peer_v4(TARGET_ADDR);
    let mut target_rx = connect(&mut manager, target, TARGET_SESSION, false, &[V4], 1);
    assert_eq!(manager.outbound_peers[&target].capacity(), 0);
    assert!(manager.dirty_peers.contains(&target));
    assert!(manager.pending_eor[&target].contains(&V4));
    assert!(manager.pending_eor[&target].contains(&V6));
    assert!(!manager.gr_deferred_eor.contains_key(&target));

    let initial = target_rx.try_recv().unwrap();
    assert_eq!(
        initial
            .announce
            .iter()
            .map(|route| route.prefix)
            .collect::<Vec<_>>(),
        [ordinary_v6(0x100)]
    );
    assert_eq!(initial.end_of_rib, [] as [(Afi, Safi); 0]);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    let completed = target_rx.try_recv().unwrap();
    assert_eq!(completed.announce.len(), 0);
    assert_eq!(completed.withdraw, [] as [(Prefix, u32); 0]);
    assert_eq!(completed.end_of_rib.len(), 2);
    assert_eq!(
        completed.end_of_rib.into_iter().collect::<HashSet<_>>(),
        HashSet::from([V4, V6]),
        "backpressure must preserve the fresh peer's honest-empty completion"
    );
    assert!(manager.peer_orf_pending[&target].contains(&V4));
    assert!(!manager.pending_eor.contains_key(&target));
    assert!(!manager.gr_deferred_eor.contains_key(&target));
    assert!(!manager.dirty_peers.contains(&target));
    manager.flush_pending_eor(target);
    assert!(
        target_rx.try_recv().is_err(),
        "initial completion is sent once"
    );
}

#[test]
fn dirty_ipv6_recovery_does_not_piggyback_an_orf_held_ipv4_initial_eor() {
    let (mut manager, _source_rx, mut target_rx) = setup(&[V4], 2, true);
    let target = peer_v4(TARGET_ADDR);
    assert_eq!(manager.outbound_peers[&target].capacity(), 0);
    assert!(!manager.dirty_peers.contains(&target));
    assert!(manager.gr_deferred_eor[&target].contains(&V4));

    // The real initial IPv6 table and its EoR occupy both writer slots.
    receive(&mut manager, &[ordinary_v6(0x101)]);
    assert!(
        manager.dirty_peers.contains(&target),
        "IPv6 admission really failed"
    );
    let mut seen = BTreeSet::new();
    let mut eors = HashMap::new();
    assert_eq!(observe(&mut target_rx, false, &mut seen, &mut eors), 2);
    assert_eq!(eors, HashMap::from([(V6, 1)]));
    assert_eq!(seen, BTreeSet::from([ordinary_v6(0x100)]));

    let commits = manager.dirty_resync_commits;
    release_v4(&mut manager);
    // A direct empty distribution pass is the ordinary dirty-timer retry.
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    assert!(observe(&mut target_rx, false, &mut seen, &mut eors) > 0);
    assert!(manager.dirty_resync_commits > commits);
    assert!(
        seen.contains(&ordinary_v6(0x101)),
        "the missed IPv6 row recovered"
    );
    assert_eq!(eors, HashMap::from([(V6, 1)]));
    assert!(manager.pending_eor[&target].contains(&V4));
    assert!(manager.gr_deferred_eor[&target].contains(&V4));
    assert!(manager.peer_orf_pending[&target].contains(&V4));

    refresh(&mut manager, V4);
    assert!(observe(&mut target_rx, true, &mut seen, &mut eors) > 0);
    assert_eq!(eors, HashMap::from([(V4, 1), (V6, 1)]));
    assert_eq!(
        seen,
        BTreeSet::from([ordinary_v4(), ordinary_v6(0x100), ordinary_v6(0x101)])
    );
    assert_completed(&mut manager, &mut target_rx);
}

#[test]
fn non_restarting_dirty_peer_keeps_orf_initial_eor_held_during_selection_release() {
    let (mut manager, _source_rx, mut target_rx) = setup(&[V4], 2, false);
    let target = peer_v4(TARGET_ADDR);
    assert_eq!(manager.outbound_peers[&target].capacity(), 0);
    assert!(!manager.dirty_peers.contains(&target));
    assert!(!manager.gr_peers.contains_key(&target));

    // The real initial IPv6 table and its EoR occupy both writer slots.
    receive(&mut manager, &[ordinary_v6(0x101)]);
    assert!(
        manager.dirty_peers.contains(&target),
        "IPv6 admission really failed"
    );
    let mut seen = BTreeSet::new();
    let mut eors = HashMap::new();
    assert_eq!(observe(&mut target_rx, false, &mut seen, &mut eors), 2);
    assert_eq!(eors, HashMap::from([(V6, 1)]));
    assert_eq!(seen, BTreeSet::from([ordinary_v6(0x100)]));

    let commits = manager.dirty_resync_commits;
    release_v4(&mut manager);
    // A direct empty distribution pass is the ordinary dirty-timer retry.
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    assert!(observe(&mut target_rx, false, &mut seen, &mut eors) > 0);
    assert!(manager.dirty_resync_commits > commits);
    assert!(
        seen.contains(&ordinary_v6(0x101)),
        "the missed IPv6 row recovered"
    );
    assert_eq!(eors, HashMap::from([(V6, 1)]));
    assert!(manager.pending_eor[&target].contains(&V4));
    assert!(manager.gr_deferred_eor[&target].contains(&V4));
    assert!(manager.peer_orf_pending[&target].contains(&V4));

    refresh(&mut manager, V4);
    assert!(observe(&mut target_rx, true, &mut seen, &mut eors) > 0);
    assert_eq!(eors, HashMap::from([(V4, 1), (V6, 1)]));
    assert_eq!(
        seen,
        BTreeSet::from([ordinary_v4(), ordinary_v6(0x100), ordinary_v6(0x101)])
    );
    assert_completed(&mut manager, &mut target_rx);
}

fn connect_withheld_v6(
    manager: &mut RibManager,
    helper: bool,
    capacity: usize,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let target = peer_v4(TARGET_ADDR);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: target,
        session_id: TARGET_SESSION,
        peer_restart_state: false,
        peer_gr_helper: helper,
        peer_gr_families: vec![],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    manager.handle_update(RibUpdate::SetPeerWithheldFamilies {
        peer: target,
        session_id: TARGET_SESSION,
        families: vec![(V6, crate::update::ExactExportErrorCode::MissingIpv6NextHop)],
    });
    let (outbound_tx, target_rx) = mpsc::channel(capacity);
    manager.handle_update(RibUpdate::PeerUp {
        peer: target,
        session_id: TARGET_SESSION,
        peer_asn: 65001,
        peer_router_id: TARGET_ADDR,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![V4],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![V6],
        negotiated_llgr_families: vec![],
    });
    target_rx
}

fn setup_withheld_v6() -> (
    RibManager,
    mpsc::Receiver<OutboundRouteUpdate>,
    mpsc::Receiver<OutboundRouteUpdate>,
) {
    let source = peer_v4(SOURCE_ADDR);
    let target = peer_v4(TARGET_ADDR);
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: source,
                families: vec![V6],
            }],
        });
    let source_rx = connect(&mut manager, source, SOURCE_SESSION, false, &[], 64);
    receive(&mut manager, &[ordinary_v4(), ordinary_v6(0x100)]);
    assert!(manager.selection_convergence_held(V6));
    assert!(!manager.selection_convergence_held(V4));

    let target_rx = connect_withheld_v6(&mut manager, false, 2);
    assert!(!manager.gr_peers.contains_key(&target));
    assert_eq!(manager.outbound_peers[&target].capacity(), 0);
    assert!(manager.pending_eor[&target].contains(&V6));
    (manager, source_rx, target_rx)
}

#[test]
fn withheld_family_unlock_keeps_orf_initial_eor_held_during_selection_release() {
    let (mut manager, _source_rx, mut target_rx) = setup_withheld_v6();
    let source = peer_v4(SOURCE_ADDR);
    let target = peer_v4(TARGET_ADDR);
    manager.handle_update(RibUpdate::PeerFamilySendable {
        peer: target,
        session_id: TARGET_SESSION,
        family: V6,
        add_path_send_limit: None,
    });
    assert!(manager.peer_sendable_families[&target].contains(&V6));
    assert_eq!(manager.registered_withheld_families(target), []);
    assert!(manager.peer_orf_pending[&target].contains(&V6));
    assert!(manager.dirty_peers.contains(&target));

    // The actual IPv4 initial data and EoR filled both writer slots.
    let initial = target_rx.try_recv().unwrap();
    assert_eq!(initial.announce.len(), 1);
    assert_eq!(initial.announce[0].prefix, ordinary_v4());
    assert_eq!(initial.end_of_rib, [] as [(Afi, Safi); 0]);
    let completed_v4 = target_rx.try_recv().unwrap();
    assert_eq!(completed_v4.announce.len(), 0);
    assert_eq!(completed_v4.end_of_rib, [V4]);
    let mut seen = BTreeSet::from([ordinary_v4()]);
    let mut eors = HashMap::from([(V4, 1)]);

    manager.handle_update(RibUpdate::EndOfRib {
        peer: source,
        session_id: SOURCE_SESSION,
        afi: V6.0,
        safi: V6.1,
    });
    assert!(!manager.selection_convergence_held(V6));
    assert!(manager.loc_rib.get(&ordinary_v6(0x100)).is_some());
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    while let Ok(update) = target_rx.try_recv() {
        assert_eq!(update.withdraw, [] as [(Prefix, u32); 0]);
        assert!(
            update
                .announce
                .iter()
                .all(|route| route.prefix != ordinary_v6(0x100)),
            "IPv6 table must wait for its own ORF refresh after becoming sendable"
        );
        assert!(
            !update.end_of_rib.contains(&V6),
            "IPv6 initial EoR must wait for its own ORF refresh after becoming sendable"
        );
        assert_eq!(update.end_of_rib, [] as [(Afi, Safi); 0]);
        seen.extend(update.announce.iter().map(|route| route.prefix));
    }
    assert_eq!(seen, BTreeSet::from([ordinary_v4()]));
    assert!(manager.pending_eor[&target].contains(&V6));
    assert!(manager.peer_orf_pending[&target].contains(&V6));

    refresh(&mut manager, V6);
    assert!(observe(&mut target_rx, true, &mut seen, &mut eors) > 0);
    assert_eq!(seen, BTreeSet::from([ordinary_v4(), ordinary_v6(0x100)]));
    assert_eq!(eors, HashMap::from([(V4, 1), (V6, 1)]));
    assert_completed(&mut manager, &mut target_rx);
}

#[test]
fn still_withheld_orf_family_keeps_fresh_empty_completion_on_selection_release() {
    let (mut manager, _source_rx, mut target_rx) = setup_withheld_v6();
    let source = peer_v4(SOURCE_ADDR);
    let target = peer_v4(TARGET_ADDR);
    let missed = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24));
    // A real runnable-family miss makes recovery necessary; IPv6 stays withheld.
    receive(&mut manager, &[missed]);
    assert!(manager.dirty_peers.contains(&target));
    assert!(!manager.peer_sendable_families[&target].contains(&V6));
    assert_eq!(
        manager.registered_withheld_families(target),
        [(V6, crate::update::ExactExportErrorCode::MissingIpv6NextHop)]
    );
    let mut seen = BTreeSet::new();
    let mut eors = HashMap::new();
    assert_eq!(observe(&mut target_rx, true, &mut seen, &mut eors), 2);
    assert_eq!(seen, BTreeSet::from([ordinary_v4()]));
    assert_eq!(eors, HashMap::from([(V4, 1)]));

    manager.handle_update(RibUpdate::EndOfRib {
        peer: source,
        session_id: SOURCE_SESSION,
        afi: V6.0,
        safi: V6.1,
    });
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    while let Ok(update) = target_rx.try_recv() {
        assert_eq!(update.withdraw, [] as [(Prefix, u32); 0]);
        for route in update.announce.iter() {
            assert_ne!(route.prefix, ordinary_v6(0x100));
            seen.insert(route.prefix);
        }
        for family in update.end_of_rib {
            *eors.entry(family).or_default() += 1;
        }
    }
    assert_eq!(seen, BTreeSet::from([ordinary_v4(), missed]));
    assert_eq!(eors, HashMap::from([(V4, 1), (V6, 1)]));
    assert!(manager.peer_orf_pending[&target].contains(&V6));
    assert!(!manager.pending_eor.contains_key(&target));
    assert!(!manager.gr_deferred_eor.contains_key(&target));
    assert!(!manager.dirty_peers.contains(&target));
    manager.flush_pending_eor(target);
    assert!(target_rx.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn withheld_family_unlock_keeps_orf_initial_eor_held_after_grace_release() {
    for replay_complete in [false, true] {
        let source = peer_v4(SOURCE_ADDR);
        let target = peer_v4(TARGET_ADDR);
        // Shorter than the ORF cap the unlock arms, so the grace release
        // alone is under test.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let (_tx, rx) = mpsc::channel(8);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
            .with_eor_grace(crate::EorGraceConfig {
                peers: vec![crate::EorGracePeerConfig {
                    peer: target.into(),
                    deadline,
                    families: vec![V4, V6],
                }],
                replay_owners: vec!["controller".into()],
            });
        let _source_rx = connect(&mut manager, source, SOURCE_SESSION, false, &[], 64);
        receive(&mut manager, &[ordinary_v4(), ordinary_v6(0x100)]);
        assert!(!manager.selection_convergence_held(V6));
        let mut target_rx = connect_withheld_v6(&mut manager, true, 64);
        assert!(!manager.gr_peers.contains_key(&target));
        assert!(manager.eor_grace_held(target, V6));
        assert!(manager.pending_eor[&target].contains(&V6));
        let mut seen = BTreeSet::new();
        let mut eors = HashMap::new();
        assert_eq!(observe(&mut target_rx, true, &mut seen, &mut eors), 1);
        assert_eq!(seen, BTreeSet::from([ordinary_v4()]));
        assert_eq!(eors, HashMap::new());

        manager.handle_update(RibUpdate::PeerFamilySendable {
            peer: target,
            session_id: TARGET_SESSION,
            family: V6,
            add_path_send_limit: None,
        });
        assert!(target_rx.try_recv().is_err());
        if replay_complete {
            let (reply, mut response) = oneshot::channel();
            manager.handle_update(RibUpdate::MarkReplayComplete {
                owner: "controller".into(),
                incarnation: manager.injection_leases.incarnation(),
                reply,
            });
            assert_eq!(
                response.try_recv().unwrap(),
                Ok(crate::ReplayComplete::Released)
            );
        } else {
            tokio::time::advance(Duration::from_secs(30)).await;
            manager.expire_eor_holds(deadline);
        }
        assert!(!manager.eor_grace_held(target, V6));
        observe(&mut target_rx, true, &mut seen, &mut eors);
        assert_eq!(seen, BTreeSet::from([ordinary_v4()]));
        assert_eq!(eors, HashMap::from([(V4, 1)]));
        assert!(manager.pending_eor[&target].contains(&V6));
        assert!(manager.peer_orf_pending[&target].contains(&V6));

        // A complete refresh for the runnable family cannot discharge IPv6.
        refresh(&mut manager, V4);
        let mut refreshed = BTreeSet::new();
        let mut refresh_eors = HashMap::new();
        observe(&mut target_rx, true, &mut refreshed, &mut refresh_eors);
        assert_eq!(refreshed, BTreeSet::from([ordinary_v4()]));
        assert_eq!(refresh_eors, HashMap::from([(V4, 1)]));
        assert!(manager.pending_eor[&target].contains(&V6));
        assert!(manager.gr_deferred_eor[&target].contains(&V6));
        assert!(manager.peer_orf_pending[&target].contains(&V6));

        refresh(&mut manager, V6);
        observe(&mut target_rx, true, &mut seen, &mut eors);
        assert_eq!(seen, BTreeSet::from([ordinary_v4(), ordinary_v6(0x100)]));
        assert_eq!(eors, HashMap::from([(V4, 1), (V6, 1)]));
        assert_completed(&mut manager, &mut target_rx);
    }
}

#[test]
fn still_withheld_orf_family_completes_on_clean_selection_release() {
    let (mut manager, _source_rx, mut target_rx) = setup_withheld_v6();
    let source = peer_v4(SOURCE_ADDR);
    let target = peer_v4(TARGET_ADDR);
    // Drain the real IPv4 table and EoR: the peer is clean and owes only the
    // selection-held marker of its withheld IPv6 family.
    let mut seen = BTreeSet::new();
    let mut eors = HashMap::new();
    assert_eq!(observe(&mut target_rx, true, &mut seen, &mut eors), 2);
    assert_eq!(seen, BTreeSet::from([ordinary_v4()]));
    assert_eq!(eors, HashMap::from([(V4, 1)]));
    assert!(!manager.dirty_peers.contains(&target));
    assert!(!manager.peer_sendable_families[&target].contains(&V6));
    assert!(manager.peer_orf_pending[&target].contains(&V6));

    manager.handle_update(RibUpdate::EndOfRib {
        peer: source,
        session_id: SOURCE_SESSION,
        afi: V6.0,
        safi: V6.1,
    });
    assert!(!manager.selection_convergence_held(V6));
    let mut released = Vec::new();
    while let Ok(update) = target_rx.try_recv() {
        assert_eq!(update.withdraw, [] as [(Prefix, u32); 0]);
        assert_eq!(update.announce.len(), 0, "a withheld family sends no table");
        released.extend(update.end_of_rib.iter().copied());
    }
    assert_eq!(
        released,
        [V6],
        "a withheld family's empty EoR must not wait for the peer's refresh"
    );
    assert!(manager.peer_orf_pending[&target].contains(&V6));
    assert!(!manager.pending_eor.contains_key(&target));
    assert!(!manager.gr_deferred_eor.contains_key(&target));
    assert!(!manager.dirty_peers.contains(&target));
}

/// Drain the writer, then run the dirty-resync retry until the target settles.
fn pump(
    manager: &mut RibManager,
    receiver: &mut mpsc::Receiver<OutboundRouteUpdate>,
    announced: &mut Vec<Prefix>,
    eors: &mut Vec<(Afi, Safi)>,
) {
    for _ in 0..16 {
        while let Ok(update) = receiver.try_recv() {
            assert_eq!(update.withdraw, [] as [(Prefix, u32); 0]);
            announced.extend(update.announce.iter().map(|route| route.prefix));
            eors.extend(update.end_of_rib.iter().copied());
        }
        if !manager.dirty_peers.contains(&peer_v4(TARGET_ADDR)) {
            return;
        }
        manager.distribute_changes(&HashSet::new(), &HashSet::new());
    }
    panic!("target never settled");
}

#[test]
fn withheld_orf_family_unlock_completion_ignores_writer_capacity() {
    for capacity in [1, 64] {
        let (_tx, rx) = mpsc::channel(8);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
        let _source_rx = connect(
            &mut manager,
            peer_v4(SOURCE_ADDR),
            SOURCE_SESSION,
            false,
            &[],
            64,
        );
        receive(&mut manager, &[ordinary_v4(), ordinary_v6(0x100)]);
        let target = peer_v4(TARGET_ADDR);
        let mut target_rx = connect_withheld_v6(&mut manager, false, capacity);
        assert!(!manager.gr_peers.contains_key(&target));
        assert!(!manager.eor_held(target, V6));
        assert_eq!(
            manager.pending_eor.contains_key(&target),
            capacity == 1,
            "capacity {capacity}: only the one-slot writer defers the PeerUp markers"
        );

        // Unlock IPv6 while any backpressured PeerUp marker is still queued.
        let mut announced = Vec::new();
        let mut eors = Vec::new();
        while let Ok(update) = target_rx.try_recv() {
            announced.extend(update.announce.iter().map(|route| route.prefix));
            eors.extend(update.end_of_rib.iter().copied());
        }
        manager.handle_update(RibUpdate::PeerFamilySendable {
            peer: target,
            session_id: TARGET_SESSION,
            family: V6,
            add_path_send_limit: None,
        });
        pump(&mut manager, &mut target_rx, &mut announced, &mut eors);
        eors.sort_unstable_by_key(|&(afi, safi)| (afi as u16, safi as u8));
        assert_eq!(announced, [ordinary_v4()], "capacity {capacity}");
        assert_eq!(
            eors,
            [V4, V6],
            "capacity {capacity}: one honest-empty IPv6 EoR, not held for the refresh"
        );
        assert!(manager.peer_orf_pending[&target].contains(&V6));
        assert!(!manager.pending_eor.contains_key(&target));
        assert!(!manager.gr_deferred_eor.contains_key(&target));

        // The peer's own refresh brings the table with its ordinary response
        // marker; no initial marker is left over for it.
        refresh(&mut manager, V6);
        let mut refreshed = Vec::new();
        let mut refresh_eors = Vec::new();
        pump(
            &mut manager,
            &mut target_rx,
            &mut refreshed,
            &mut refresh_eors,
        );
        assert_eq!(refreshed, [ordinary_v6(0x100)], "capacity {capacity}");
        assert_eq!(refresh_eors, [V6], "capacity {capacity}");
        assert!(!manager.peer_orf_pending.contains_key(&target));
        assert!(!manager.pending_eor.contains_key(&target));
        assert!(!manager.gr_deferred_eor.contains_key(&target));
    }
}

fn push_v4_orf(manager: &mut RibManager, when: WhenToRefresh) {
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::PeerOrfUpdate {
        peer: peer_v4(TARGET_ADDR),
        session_id: TARGET_SESSION,
        afi: V4.0,
        safi: V4.1,
        when,
        entries: vec![AddressPrefixOrf {
            action: OrfAction::Add,
            match_: OrfMatch::Permit,
            sequence: 1,
            min_len: 0,
            max_len: 32,
            prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))),
        }],
        reply,
    });
    response
        .try_recv()
        .expect("synchronous ORF reply")
        .expect("ORF update accepted");
}

#[test]
fn deferred_orf_update_keeps_the_initial_gate_through_selection_release() {
    let (mut manager, _source_rx, mut target_rx) = setup(&[V4], 64, true);
    let target = peer_v4(TARGET_ADDR);
    let mut seen = BTreeSet::new();
    let mut eors = HashMap::new();
    observe(&mut target_rx, false, &mut seen, &mut eors);
    assert_eq!(seen, BTreeSet::from([ordinary_v6(0x100)]));
    assert_eq!(eors, HashMap::from([(V6, 1)]));
    assert!(manager.gr_deferred_eor[&target].contains(&V4));

    // RFC 5291 §6: DEFER installs the entries but is not the refresh that
    // opens the family.
    push_v4_orf(&mut manager, WhenToRefresh::Defer);
    assert!(
        manager
            .peer_orf_pending
            .get(&target)
            .is_some_and(|gated| gated.contains(&V4)),
        "a DEFER ORF must not lift the initial-advertisement gate"
    );
    assert!(manager.peer_orf_filters[&target].contains_key(&V4));
    assert_eq!(observe(&mut target_rx, false, &mut seen, &mut eors), 0);

    // Release must not send the IPv4 table or EoR the peer has not asked for.
    release_v4(&mut manager);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    observe(&mut target_rx, false, &mut seen, &mut eors);
    assert_eq!(seen, BTreeSet::from([ordinary_v6(0x100)]));
    assert!(manager.gr_deferred_eor[&target].contains(&V4));
    assert!(manager.peer_orf_pending[&target].contains(&V4));

    push_v4_orf(&mut manager, WhenToRefresh::Immediate);
    assert!(observe(&mut target_rx, true, &mut seen, &mut eors) > 0);
    assert_eq!(seen, BTreeSet::from([ordinary_v4(), ordinary_v6(0x100)]));
    assert_eq!(eors, HashMap::from([(V4, 1), (V6, 1)]));
    assert_completed(&mut manager, &mut target_rx);
}
