//! Selection can stage the winners after a collision, hold their End-of-RIB
//! for the surviving session's refresh, and defer selection again on a new waiter.

use super::*;

const SECOND: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);

fn waiter_up(manager: &mut RibManager, address: Ipv4Addr, session_id: u64) -> Receiver {
    let peer = peer_v4(address);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![EVPN],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    Receiver {
        peer,
        rx: up_sized(manager, peer, session_id, 4096, &[EVPN]),
        wire: Wire::default(),
    }
}

fn survivor_refresh(manager: &mut RibManager) {
    manager.handle_update(RibUpdate::BeginRouteRefresh {
        peer: peer_v4(WAITER),
        session_id: 11,
        afi: EVPN.0,
        safi: EVPN.1,
    });
    manager.handle_update(RibUpdate::EndRouteRefresh {
        peer: peer_v4(WAITER),
        session_id: 11,
        afi: EVPN.0,
        safi: EVPN.1,
    });
}

#[derive(Clone, Copy, Debug)]
enum Release {
    Refresh,
    RearmRestageRefresh,
    RearmEor,
    RearmTimer,
    StagedTimer,
}

impl Release {
    fn rearmed(self) -> bool {
        matches!(
            self,
            Self::RearmRestageRefresh | Self::RearmEor | Self::RearmTimer
        )
    }

    fn finish(self, manager: &mut RibManager) {
        match self {
            Self::Refresh => survivor_refresh(manager),
            Self::RearmRestageRefresh => {
                end_of_rib(manager, peer_v4(SECOND), 33, EVPN);
                assert!(!manager.selection_deferred(EVPN));
                assert!(manager.selection_convergence_held(EVPN));
                received(manager, &[(90_003, 3)], &[4]);
                survivor_refresh(manager);
            }
            Self::RearmEor => {
                survivor_refresh(manager);
                assert!(manager.selection_deferred(EVPN));
                end_of_rib(manager, peer_v4(SECOND), 33, EVPN);
            }
            Self::StagedTimer | Self::RearmTimer => manager.expire_selection_deferral(),
        }
        assert!(!manager.selection_convergence_held(EVPN));
    }
}

fn evict_late(manager: &mut RibManager, late: PeerId, readers: &mut [Receiver]) {
    // Keep the Loc-RIB small as distinct keys pass the stalled reader.
    for round in 0..160 {
        let start = 100_000 + round * 64;
        let fresh: Vec<_> = (start..start + 64).map(|index| (index, 1)).collect();
        let gone: Vec<_> = if round == 0 {
            vec![]
        } else {
            (start - 64..start).collect()
        };
        received(manager, &fresh, &gone);
        if manager.owed_row_evicted.contains(&late) {
            assert!(manager.eor.owes(late, EVPN));
            return;
        }
        for _ in 0..12 {
            tick(manager, readers);
        }
    }
    panic!("late receiver never reached the cursor cap");
}

fn stage_case(state: ReceiverState, release: Release, rows: u32, evict: bool) {
    let mut manager = manager(CREDIT).with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: [WAITER, SECOND]
            .map(|address| SelectionDeferralWaiterConfig {
                peer: peer_v4(address).into(),
                families: vec![EVPN],
            })
            .into(),
    });
    manager.test_force_ungrouped = false;
    let _source = up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]);
    let subject = Receiver::up(&mut manager, receiver(0), 16, &[V4, EVPN]);
    let mut receivers = vec![subject];
    received(&mut manager, &all(rows), &[]);
    received_unicast(&mut manager, 0..UNICAST);
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table, table(&all(rows)));
    prepare_receiver(&mut manager, &receivers[0], state);
    if release.rearmed() {
        manager.set_deferred_selection_limits_for_test(0, usize::MAX);
    }

    receivers.push(waiter_up(&mut manager, WAITER, 11));
    assert!(manager.selection_deferred(EVPN));
    received(&mut manager, &[(90_000, 1)], &[6]);
    if state == ReceiverState::Dirty && release.rearmed() {
        drain(&mut manager, &mut receivers);
        assert!(manager.held_evpn_rebuilds.contains(&receivers[0].peer));
    }
    let replacement = waiter_up(&mut manager, WAITER, 22);
    manager.handle_update(RibUpdate::PeerDown {
        peer: replacement.peer,
        session_id: 22,
    });
    drop(replacement);
    assert!(!manager.selection_deferred(EVPN));
    assert!(manager.selection_convergence_held(EVPN));

    let late = receiver(1);
    receivers.push(Receiver {
        peer: late,
        rx: up_sized(&mut manager, late, 0, 4096, &[V4, EVPN]),
        wire: Wire::default(),
    });
    assert!(manager.eor.owes(late, EVPN));
    received(&mut manager, &[(90_001, 1)], &[7]);
    if evict {
        receivers[2].write();
        assert_eq!(receivers[2].wire.markers, 0);
        evict_late(&mut manager, late, &mut receivers[..2]);
    }
    if release.rearmed() {
        receivers.push(waiter_up(&mut manager, SECOND, 33));
        assert!(manager.selection_deferred(EVPN));
        if state == ReceiverState::Dirty {
            let subject = &mut receivers[0];
            assert_eq!(
                subject.unicast_rows_on_operator_refresh(&mut manager),
                UNICAST as usize,
                "refresh during rearm"
            );
            assert!(subject.wire.table.contains_key(&key(5)), "EVPN still held");
        }
        received(&mut manager, &[(90_002, 2), (90_000, 2)], &[]);
    }
    received_unicast(&mut manager, UNICAST..UNICAST + 1);
    let before = manager.adj_rib_out_commit_stats.owed_drain_steps;
    release.finish(&mut manager);
    drain(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);

    let input: BTreeMap<_, _> = manager.ribs[&peer_v4(SOURCE)]
        .iter_evpn()
        .map(|route| (route.key(), format!("{:?}", route.attributes)))
        .collect();
    let selected = selected_evpn(&manager);
    assert_eq!(input, selected, "{state:?}/{release:?}: selected rows");
    assert!(!input.contains_key(&key(6)) && !input.contains_key(&key(7)));
    assert!(input.contains_key(&key(90_000)) && input.contains_key(&key(90_001)));
    assert_eq!(input.contains_key(&key(90_002)), release.rearmed());
    assert_eq!(
        input.contains_key(&key(90_003)),
        matches!(release, Release::RearmRestageRefresh)
    );
    for (i, receiver) in receivers.iter().enumerate() {
        assert_eq!(
            receiver.wire.table, selected,
            "{state:?}/{release:?}: {}",
            receiver.peer
        );
        assert_eq!(receiver.wire.markers, usize::from(i != 0));
        assert_eq!(receiver.wire.rows_after_marker, 0);
        if i == 0 || receiver.peer == late {
            assert_eq!(receiver.wire.unicast_table, unicast_table(UNICAST + 1));
        }
        assert!(!manager.eor.owes(receiver.peer, EVPN));
    }
    assert_idle(&manager, &receivers);
    if rows >= 1_000 {
        assert!(manager.adj_rib_out_commit_stats.owed_drain_steps - before >= 200);
    }
}

#[test]
fn collision_release_and_rearm_converge_across_receiver_states() {
    for state in ReceiverState::ALL {
        for release in [
            Release::Refresh,
            Release::RearmRestageRefresh,
            Release::RearmEor,
            Release::RearmTimer,
            Release::StagedTimer,
        ] {
            stage_case(state, release, 8, false);
        }
    }
}

#[test]
fn late_staged_receiver_keeps_its_end_of_rib_through_cap_eviction_and_rearm() {
    stage_case(ReceiverState::Clean, Release::RearmRestageRefresh, 8, true);
}

#[test]
fn staged_release_finishes_a_walk_of_hundreds_of_steps() {
    stage_case(ReceiverState::Cursor, Release::RearmEor, 2048, false);
}

#[test]
fn end_of_rib_covers_applied_input_with_a_later_ingress_chunk_queued() {
    let mut manager = deferral_manager(CREDIT);
    let _source = up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]);
    let mut waiter = hold(&mut manager);
    received(&mut manager, &[(1, 0)], &[]);
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![route(2, 1)],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    assert!(!manager.pending_route_batches.is_empty());
    release(&mut manager);
    // Inspect the table at the marker. The queued row may legitimately
    // arrive on either side of it; the row applied before release must be there.
    let read = |receiver: &mut Receiver| {
        while let Ok(update) = receiver.rx.try_recv() {
            receiver.wire.apply(&update);
            if update.end_of_rib.contains(&EVPN) {
                assert_eq!(
                    receiver.wire.table.get(&key(1)),
                    table(&[(1, 0)]).get(&key(1))
                );
            }
        }
    };
    manager.resync_dirty_peers_bounded();
    read(&mut waiter);
    drain_route_chunks(&mut manager);
    for _ in 0..16 {
        manager.resync_dirty_peers_bounded();
        read(&mut waiter);
        if !manager.resync_tick_pending() {
            break;
        }
    }
    assert!(!manager.resync_tick_pending());
    assert_eq!(waiter.wire.table, table(&[(1, 0), (2, 1)]));
    assert_eq!(waiter.wire.markers, 1);
    assert!(!manager.eor.owes(waiter.peer, EVPN));
    assert_idle(&manager, std::slice::from_ref(&waiter));
}
