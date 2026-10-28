use super::*;
use crate::update::OutboundRouteUpdate;

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 44);
const WAITER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 45);
const OBSERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 46);
const LATE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 47);
const SOURCE_SESSION: u64 = 144;
const WAITER_SESSION: u64 = 145;
const LATE_SESSION: u64 = 147;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplayTiming {
    Disabled,
    BeforeSelectionRelease,
    AfterSelectionRelease,
}

fn connect(
    manager: &mut RibManager,
    address: Ipv4Addr,
    session_id: u64,
    capacity: usize,
    waiter: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = peer_v4(address);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: if waiter { vec![FAMILY] } else { vec![] },
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (outbound_tx, outbound_rx) = mpsc::channel(capacity);
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65000,
        peer_router_id: address,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![FAMILY],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    outbound_rx
}

fn receive(manager: &mut RibManager, announced: Vec<Route>, withdrawn: Vec<(Prefix, u32)>) {
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: SOURCE_SESSION,
        announced,
        withdrawn,
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(manager);
}

fn replay_complete(manager: &mut RibManager) {
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::MarkReplayComplete {
        owner: "backpressure-controller".to_string(),
        incarnation: manager.injection_leases().incarnation(),
        reply,
    });
    assert_eq!(
        result.try_recv().unwrap().unwrap(),
        crate::ReplayComplete::Released
    );
}

fn apply_wire(
    update: &OutboundRouteUpdate,
    wire: &mut std::collections::HashMap<(Prefix, u32), Route>,
    eors: &mut usize,
) {
    assert_eq!(
        update.refresh_markers,
        [] as [(Afi, Safi, rustbgpd_wire::RouteRefreshSubtype); 0]
    );
    assert!(update.flowspec_announce.is_empty() && update.flowspec_withdraw.is_empty());
    assert!(update.evpn_announce.is_empty() && update.evpn_withdraw.is_empty());
    for &(prefix, path_id) in &update.withdraw {
        assert!(
            wire.remove(&(prefix, path_id)).is_some(),
            "a withdrawal must name an actually admitted route"
        );
    }
    for route in update.announce.iter() {
        assert_eq!(*eors, 0, "initial route data must precede its EoR");
        wire.insert((route.prefix, route.path_id), route.clone());
    }
    for &family in &update.end_of_rib {
        assert_eq!(family, FAMILY);
        *eors += 1;
        assert_eq!(*eors, 1, "initial completion is admitted exactly once");
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one causal transcript checks release data admission, failed marker, queued churn and exact recovery"
)]
fn frozen_group_release_marker_backpressure_recaptures_exact_admission_before_churn() {
    for timing in [
        ReplayTiming::Disabled,
        ReplayTiming::BeforeSelectionRelease,
        ReplayTiming::AfterSelectionRelease,
    ] {
        let late = peer_v4(LATE);
        let (_tx, rx) = mpsc::channel(16);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
            .with_selection_deferral(SelectionDeferralConfig {
                timeout: Duration::from_secs(60),
                waiters: vec![SelectionDeferralWaiterConfig {
                    peer: peer_v4(WAITER),
                    families: vec![FAMILY],
                }],
            });
        if timing != ReplayTiming::Disabled {
            manager = manager.with_eor_grace(crate::EorGraceConfig {
                peers: vec![crate::EorGracePeerConfig {
                    peer: late.into(),
                    deadline: tokio::time::Instant::now() + Duration::from_secs(300),
                    families: vec![FAMILY],
                }],
                replay_owners: vec!["backpressure-controller".to_string()],
            });
        }

        let mut source_rx = connect(&mut manager, SOURCE, SOURCE_SESSION, 64, false);
        let mut observer_rx = connect(&mut manager, OBSERVER, 146, 64, false);
        assert!(!manager.selection_deferred(FAMILY));
        let first = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
        let second = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
        let third = Ipv4Prefix::new(Ipv4Addr::new(198, 18, 0, 0), 24);
        receive(
            &mut manager,
            vec![
                make_route_with_lp(first, SOURCE, 100),
                make_route_with_lp(second, SOURCE, 100),
            ],
            vec![],
        );
        while source_rx.try_recv().is_ok() {}
        while observer_rx.try_recv().is_ok() {}

        let _waiter_rx = connect(&mut manager, WAITER, WAITER_SESSION, 64, true);
        assert!(manager.selection_deferred(FAMILY));
        let mut late_rx = connect(&mut manager, LATE, LATE_SESSION, 1, false);
        assert!(late_rx.try_recv().is_err());
        let gid = manager
            .grouped_member_of(late)
            .expect("late observer is grouped");
        assert_eq!(manager.grouped_member_of(peer_v4(OBSERVER)), Some(gid));
        assert!(manager.retain_initial_group_admitted(late));
        assert!(manager.pending_group_admitted.contains_record(late));
        assert!(manager.pending_eor[&late].contains(&FAMILY));

        if timing == ReplayTiming::BeforeSelectionRelease {
            replay_complete(&mut manager);
            assert!(manager.selection_deferred(FAMILY));
            assert!(late_rx.try_recv().is_err());
        }
        manager.handle_update(RibUpdate::EndOfRib {
            peer: peer_v4(WAITER),
            session_id: WAITER_SESSION,
            afi: FAMILY.0,
            safi: FAMILY.1,
        });
        assert!(!manager.selection_convergence_held(FAMILY));
        assert_eq!(manager.outbound_peers[&late].capacity(), 0);
        if timing == ReplayTiming::AfterSelectionRelease {
            assert!(
                !manager.dirty_peers.contains(&late),
                "grace still holds only the marker"
            );
            assert!(manager.pending_eor[&late].contains(&FAMILY));
            assert!(!manager.retain_initial_group_admitted(late));
            assert!(!manager.pending_group_admitted.contains_record(late));
            replay_complete(&mut manager);
        }
        assert!(
            manager.dirty_peers.contains(&late),
            "{timing:?}: the data filled the sole slot before EoR"
        );
        assert!(manager.pending_eor[&late].contains(&FAMILY));
        assert!(
            manager.pending_group_admitted.contains_record(late),
            "failed EoR must recapture actual admitted data"
        );

        // Keep the admitted payload queued while the canonical group moves.
        receive(
            &mut manager,
            vec![
                make_route_with_lp(second, SOURCE, 200),
                make_route_with_lp(third, SOURCE, 100),
            ],
            vec![(Prefix::V4(first), 0)],
        );
        assert!(manager.dirty_peers.contains(&late));
        assert_eq!(manager.outbound_peers[&late].capacity(), 0);
        assert_eq!(manager.loc_rib.len(), 2);
        let mut wire = std::collections::HashMap::new();
        let mut eors = 0;
        let admitted = late_rx.try_recv().unwrap();
        assert_eq!(
            admitted.announce.len(),
            2,
            "the initial missing-row replay is one complete payload"
        );
        assert_eq!(admitted.end_of_rib, [] as [(Afi, Safi); 0]);
        apply_wire(&admitted, &mut wire, &mut eors);
        assert_eq!(wire.len(), 2);
        assert!(wire.contains_key(&(Prefix::V4(first), 0)));
        assert!(wire.contains_key(&(Prefix::V4(second), 0)));

        manager.distribute_changes(&HashSet::new(), &HashSet::new());
        let recovered = late_rx
            .try_recv()
            .expect("available capacity must admit recovery");
        apply_wire(&recovered, &mut wire, &mut eors);
        assert_eq!(eors, 1, "{timing:?}: recovery completes its first EoR");
        assert_eq!(wire.len(), 2);
        assert!(!wire.contains_key(&(Prefix::V4(first), 0)));
        for prefix in [Prefix::V4(second), Prefix::V4(third)] {
            assert!(wire.contains_key(&(prefix, 0)));
        }
        let advertised = manager.grouped_advertised_routes(late).unwrap();
        assert_eq!(advertised.len(), wire.len());
        for route in advertised {
            let admitted = &wire[&(route.prefix, route.path_id)];
            assert!(crate::manager::helpers::routes_equal(&route, admitted));
        }
        assert!(!manager.dirty_peers.contains(&late));
        assert!(!manager.pending_eor.contains_key(&late));
        assert!(!manager.retain_initial_group_admitted(late));
        assert!(!manager.pending_group_admitted.contains_record(late));
        assert!(!manager.pending_extra_withdraws.contains_key(&late));
        assert!(manager.group_ribs[&gid].tombstones.is_empty());
        assert!(late_rx.try_recv().is_err());
        manager.flush_pending_eor(late);
        manager.distribute_changes(&HashSet::new(), &HashSet::new());
        assert!(
            late_rx.try_recv().is_err(),
            "completed recovery must not repeat its terminal"
        );

        drop(late_rx);
        manager.mark_outbound_dirty(late);
        manager.distribute_changes(&HashSet::new(), &HashSet::new());
        assert!(
            !manager.dirty_peers.contains(&late),
            "a closed receiver cannot arm retries"
        );
        manager.handle_update(RibUpdate::PeerDown {
            peer: late,
            session_id: LATE_SESSION,
        });
        assert!(!manager.outbound_peers.contains_key(&late));
        assert!(!manager.pending_eor.contains_key(&late));
        assert!(!manager.pending_group_admitted.contains_record(late));
        assert!(manager.next_selection_deferral_deadline().is_none());
    }
}
