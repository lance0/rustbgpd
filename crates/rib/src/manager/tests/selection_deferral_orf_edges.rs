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
    let target_rx = connect(
        &mut manager,
        target,
        TARGET_SESSION,
        true,
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
    let (mut manager, _source_rx, mut target_rx) = setup(&[V4, V6], 64);
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
    let (mut manager, _source_rx, mut target_rx) = setup(&[V4], 2);
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
