//! Changes to the source and to an export while EVPN selection is held.

use super::*;

#[derive(Clone, Copy, Debug)]
enum HoldEvent {
    Withdraw,
    SourceDown,
    RestartEor,
    RestartTimeout,
    LongLivedTimeout,
    ReplacePolicy,
    OperatorRefresh,
    PeerRefresh,
}

const SECOND_SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);

fn second_source_rows(manager: &mut RibManager, rows: &[(u32, u32)]) {
    let evpn_announced = rows
        .iter()
        .map(|&(i, med)| {
            let mut row = make_evpn_imet(SECOND_SOURCE, i);
            row.attributes = route(i, med).attributes;
            row
        })
        .collect();
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SECOND_SOURCE),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced,
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(manager);
}

impl HoldEvent {
    fn apply(self, manager: &mut RibManager, subject: PeerId, state: ReceiverState) {
        let peer = peer_v4(SECOND_SOURCE);
        match self {
            Self::SourceDown => manager.handle_update(RibUpdate::PeerDown {
                peer,
                session_id: 0,
            }),
            Self::RestartEor | Self::RestartTimeout | Self::LongLivedTimeout => {
                let llgr = matches!(self, Self::LongLivedTimeout);
                manager.handle_update(RibUpdate::PeerGracefulRestart {
                    peer,
                    session_id: 0,
                    restart_time: 120,
                    stale_routes_time: 120,
                    gr_families: vec![EVPN],
                    peer_notification_gr: false,
                    peer_llgr_capable: llgr,
                    peer_llgr_families: if llgr {
                        vec![rustbgpd_wire::LlgrFamily {
                            afi: EVPN.0,
                            safi: EVPN.1,
                            forwarding_preserved: true,
                            stale_time: 600,
                        }]
                    } else {
                        vec![]
                    },
                    llgr_stale_time: if llgr { 600 } else { 0 },
                });
                drain_route_chunks(manager);
                if matches!(self, Self::RestartEor) {
                    let _replacement = up_sized(manager, peer, 0, 16, &[V4]);
                    second_source_rows(manager, &[(100, 3)]);
                    end_of_rib(manager, peer, 0, EVPN);
                } else {
                    manager.sweep_gr_stale(peer);
                    if llgr {
                        drain_route_chunks(manager);
                        assert_eq!(
                            manager.ribs[&peer]
                                .iter_evpn()
                                .filter(|r| r.is_llgr_stale)
                                .count(),
                            2
                        );
                        manager.sweep_llgr_stale(peer, &[EVPN]);
                    }
                }
            }
            Self::ReplacePolicy => {
                let previous_group = manager.grouped_member_of(subject);
                regroup(
                    manager,
                    subject,
                    (state != ReceiverState::Dirty).then(permit_all),
                );
                assert_ne!(manager.grouped_member_of(subject), previous_group);
            }
            Self::OperatorRefresh => {
                let (reply, mut result) = oneshot::channel();
                manager.handle_update(RibUpdate::RefreshPeerOutbound {
                    peer: subject,
                    reply,
                });
                result.try_recv().unwrap().unwrap();
            }
            Self::PeerRefresh => refresh_request(manager, subject),
            Self::Withdraw => {}
        }
        drain_route_chunks(manager);
    }
}

fn hold_case(event: HoldEvent, state: ReceiverState) {
    let overflow = matches!(
        state,
        ReceiverState::Clean | ReceiverState::Evicted | ReceiverState::Dirty
    );
    let mut manager = deferral_manager(CREDIT);
    manager.test_force_ungrouped = false;
    let _source = up_sized(&mut manager, peer_v4(SOURCE), 0, 128, &[V4]);
    let _second = up_sized(&mut manager, peer_v4(SECOND_SOURCE), 0, 128, &[V4]);
    let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 16, &[V4, EVPN])];
    received(&mut manager, &all(8), &[]);
    second_source_rows(&mut manager, &[(100, 0), (101, 0)]);
    received_unicast(&mut manager, 0..2);
    drain(&mut manager, &mut receivers);
    prepare_receiver(&mut manager, &receivers[0], state);

    if overflow {
        manager.set_deferred_selection_limits_for_test(0, usize::MAX);
    }
    receivers.push(hold(&mut manager));
    let peer = receiver(7);
    receivers.push(Receiver {
        peer,
        rx: up_sized(&mut manager, peer, 0, 64, &[V4, EVPN]),
        wire: Wire::default(),
    });
    received(&mut manager, &[(9000, 2)], &[6]);
    event.apply(&mut manager, receivers[0].peer, state);
    received_unicast(&mut manager, 2..4);
    for _ in 0..4 {
        tick(&mut manager, &mut receivers);
    }
    assert!(manager.selection_deferred(EVPN));
    assert_eq!(
        manager.deferred_selection_ledger_state_for_test(EVPN).1,
        overflow
    );
    assert!(receivers[1..].iter().all(|r| r.wire.markers == 0));
    release(&mut manager);
    drain(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);

    let expected = selected_evpn(&manager);
    assert_eq!(
        expected.get(&key(9000)),
        table(&[(9000, 2)]).get(&key(9000))
    );
    assert!(!expected.contains_key(&key(6)));
    assert_eq!(
        expected.contains_key(&key(5)),
        state == ReceiverState::Clean
    );
    let second_keys = [100, 101].map(|i| make_evpn_imet(SECOND_SOURCE, i).key());
    let kept = second_keys.map(|k| expected.contains_key(&k));
    assert_eq!(
        kept,
        match event {
            HoldEvent::SourceDown | HoldEvent::RestartTimeout | HoldEvent::LongLivedTimeout =>
                [false, false],
            HoldEvent::RestartEor => [true, false],
            _ => [true, true],
        }
    );
    if matches!(event, HoldEvent::RestartEor) {
        assert_eq!(
            expected[&second_keys[0]],
            format!("{:?}", route(100, 3).attributes)
        );
    }
    for (i, r) in receivers.iter().enumerate() {
        assert_eq!(r.wire.table, expected, "{event:?} {state:?} {}", r.peer);
        assert_eq!(r.wire.markers, usize::from(i != 0));
        assert_eq!(r.wire.rows_after_marker, 0);
        if i != 1 {
            assert_eq!(r.wire.unicast_table, unicast_table(4));
        }
    }
    if matches!(event, HoldEvent::OperatorRefresh) && state == ReceiverState::Clean {
        assert!(
            receivers[0].wire.unicast >= 6,
            "refresh must replay the two admitted IPv4 rows"
        );
    }
    if matches!(event, HoldEvent::PeerRefresh) {
        assert_eq!(
            receivers[0]
                .wire
                .sent
                .iter()
                .filter(|s| matches!(s, Sent::Answer(_)))
                .count(),
            1
        );
    }
    assert_idle(&manager, &receivers);
}

fn check_states(events: &[HoldEvent]) {
    for &event in events {
        for state in ReceiverState::ALL {
            hold_case(event, state);
        }
    }
}

#[test]
fn a_withdrawal_or_source_loss_during_a_hold_reaches_every_receiver() {
    check_states(&[HoldEvent::Withdraw, HoldEvent::SourceDown]);
}

#[test]
fn a_restart_sweep_during_a_hold_reaches_every_receiver() {
    check_states(&[
        HoldEvent::RestartEor,
        HoldEvent::RestartTimeout,
        HoldEvent::LongLivedTimeout,
    ]);
}

#[test]
fn a_policy_replacement_or_refresh_inside_a_hold_converges() {
    check_states(&[
        HoldEvent::ReplacePolicy,
        HoldEvent::OperatorRefresh,
        HoldEvent::PeerRefresh,
    ]);
}

/// The subject missed row 5's withdrawal before the EVPN hold and is ready
/// to resync in it. Keep the source and the waiter reading alongside it.
fn missed_withdrawal(manager: &mut RibManager, unicast_rows: u32) -> [Receiver; 3] {
    let source = peer_v4(SOURCE);
    let source = Receiver {
        peer: source,
        rx: up_sized(manager, source, 0, 16, &[V4]),
        wire: Wire::default(),
    };
    let peer = receiver(0);
    let mut subject = Receiver::up(manager, peer, 16, &[V4, EVPN]);
    received(manager, &all(8), &[]);
    received_unicast(manager, 0..unicast_rows);
    drain(manager, std::slice::from_mut(&mut subject));
    prepare_receiver(manager, &subject, ReceiverState::Dirty);
    let waiter = hold(manager);
    manager.owe_eor(peer, EVPN);
    [subject, waiter, source]
}

#[test]
fn a_held_evpn_rebuild_serves_ipv4_resync_and_both_refreshes() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let mut manager = deferral_manager(CREDIT);
    let mut receivers = missed_withdrawal(&mut manager, UNICAST);
    let peer = receivers[0].peer;
    let visits = Arc::new(AtomicUsize::new(0));
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let visits = Arc::clone(&visits);
        move |stage| {
            if stage == "resync_evpn_key" {
                visits.fetch_add(1, Ordering::Relaxed);
            }
        }
    }));
    drain(&mut manager, &mut receivers);
    assert!(!manager.dirty_peers.contains(&peer));
    assert!(receivers[0].wire.table.contains_key(&key(5)));
    assert!(manager.owes_held_rebuild(peer, FAMILY));
    for family in [
        OwedFamily::IPV4_UNICAST,
        OwedFamily::IPV6_UNICAST,
        OwedFamily::IPV4_LABELED,
        OwedFamily::IPV6_LABELED,
        OwedFamily::VPNV4,
        OwedFamily::VPNV6,
    ] {
        assert!(!manager.owes_held_rebuild(peer, family), "{family:?}");
    }

    manager.mark_outbound_dirty(peer);
    received_unicast(&mut manager, UNICAST..2 * UNICAST);
    drain(&mut manager, &mut receivers);
    let prefixes = unicast_table(2 * UNICAST);
    assert_eq!(receivers[0].wire.unicast_table, prefixes, "second resync");

    assert_eq!(
        receivers[0].unicast_rows_on_operator_refresh(&mut manager),
        prefixes.len(),
        "operator refresh"
    );
    assert!(!manager.force_outbound_peers.contains(&peer));

    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer,
        session_id: 0,
        afi: V4.0,
        safi: V4.1,
        queued: Arc::new(AtomicBool::new(true)),
    });
    let answer = receivers[0].rx.try_recv().expect("IPv4 refresh answer");
    assert_eq!(
        answer.refresh_markers,
        BRACKET.map(|(_, _, kind)| (V4.0, V4.1, kind))
    );
    assert_eq!(answer.announce.len(), prefixes.len());
    assert_eq!(
        answer
            .announce
            .iter()
            .map(|r| r.prefix)
            .collect::<BTreeSet<_>>(),
        prefixes
    );
    assert!(answer.evpn_announce.is_empty() && answer.evpn_withdraw.is_empty());
    drop(answer);
    assert!(!manager.pending_refresh.contains_key(&peer));
    assert!(!manager.resync_tick_pending());
    assert!(manager.selection_deferred(EVPN));
    assert_eq!(
        visits.load(Ordering::Relaxed),
        0,
        "no held EVPN inventory walked"
    );
    assert_eq!(receivers[0].wire.markers, 0);

    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    release(&mut manager);
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
    assert_eq!(
        visits.load(Ordering::Relaxed),
        0,
        "release only hands off the rebuild"
    );
    let (built, _) = drain_one_unit_a_tick(&mut manager, &mut receivers);
    assert_eq!(built, 1);
    assert!(visits.load(Ordering::Relaxed) > 0, "the unit walked EVPN");
    assert_eq!(receivers[0].wire.count(5), (1, 1));
    assert_eq!(receivers[0].wire.table, selected_evpn(&manager));
    assert_eq!(receivers[0].wire.markers, 1);
    assert_eq!(receivers[0].wire.rows_after_marker, 0);
    assert_idle(&manager, &receivers);
}

fn mixed_deferral_manager(v4_waiter: PeerId) -> RibManager {
    manager(CREDIT).with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: [(peer_v4(WAITER), EVPN), (v4_waiter, V4)]
            .map(|(peer, family)| SelectionDeferralWaiterConfig {
                peer: peer.into(),
                families: vec![family],
            })
            .into(),
    })
}

#[test]
fn a_force_waiting_for_unicast_leaves_the_evpn_release_rebuild_to_the_tick() {
    let v4_waiter = peer_v4(SECOND_SOURCE);
    let mut manager = mixed_deferral_manager(v4_waiter);
    // A suppressed IPv4 row would make the forced replay dirty as well.
    let mut receivers = Vec::from(missed_withdrawal(&mut manager, 0));
    drain(&mut manager, &mut receivers);
    let peer = receivers[0].peer;
    assert!(manager.owes_held_rebuild(peer, FAMILY));
    receivers.push(hold_family(&mut manager, v4_waiter, V4));
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::RefreshPeerOutbound { peer, reply });
    result.try_recv().unwrap().unwrap();
    assert!(manager.force_outbound_peers.contains(&peer));
    assert!(!manager.dirty_peers.contains(&peer));
    assert!(manager.selection_partial_caught_up(peer));
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    release(&mut manager);
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
    drain_one_unit_a_tick(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.count(5), (1, 1));
    assert_eq!(receivers[0].wire.markers, 1);
    assert_eq!(receivers[0].wire.rows_after_marker, 0);
    assert!(manager.selection_deferred(V4));
    end_of_rib(&mut manager, v4_waiter, 7, V4);
    drain_unicast_release(&mut manager);
    drain(&mut manager, &mut receivers);
    assert!(!manager.force_outbound_peers.contains(&peer));
    assert_idle(&manager, &receivers);
}

#[test]
fn a_discharged_evpn_rebuild_is_not_recorded_again_behind_the_unicast_hold() {
    let v4_waiter = peer_v4(SECOND_SOURCE);
    let mut manager = mixed_deferral_manager(v4_waiter);
    let mut receivers = Vec::from(missed_withdrawal(&mut manager, 0));
    drain(&mut manager, &mut receivers);
    let peer = receivers[0].peer;
    assert!(manager.owes_held_rebuild(peer, FAMILY));
    receivers.push(hold_family(&mut manager, v4_waiter, V4));
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::RefreshPeerOutbound { peer, reply });
    result.try_recv().unwrap().unwrap();
    let recoveries = recoveries_observed(&manager);
    release(&mut manager);
    // A unit refused after its build did not run: its rebuild stays owed.
    let encoder = manager
        .peer_export_encoders
        .remove(&peer)
        .expect("an exact export encoder");
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    tick(&mut manager, &mut receivers);
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds - builds, 1);
    assert_eq!(receivers[0].wire.count(5), (1, 0));
    assert!(manager.owes_held_rebuild(peer, FAMILY));
    manager.peer_export_encoders.insert(peer, encoder);
    drain_one_unit_a_tick(&mut manager, &mut receivers);
    // The unit ran: the missed withdrawal and the EVPN marker are on the
    // wire, and the receiver stays dirty only for the IPv4 hold.
    assert_eq!(receivers[0].wire.count(5), (1, 1));
    assert_eq!(receivers[0].wire.markers, 1);
    assert!(manager.selection_deferred(V4) && !manager.selection_deferred(EVPN));
    assert!(manager.dirty_peers.contains(&peer));
    assert!(!manager.owes_held_rebuild(peer, FAMILY));

    refresh_request(&mut manager, peer);
    receivers[0].write();
    let answers = |receiver: &Receiver| {
        receiver
            .wire
            .sent
            .iter()
            .filter(|sent| matches!(sent, Sent::Answer(_)))
            .count()
    };
    assert_eq!(answers(&receivers[0]), 1, "the EVPN refresh is answered");
    assert!(!manager.pending_refresh.contains_key(&peer));

    end_of_rib(&mut manager, v4_waiter, 7, V4);
    drain_unicast_release(&mut manager);
    drain(&mut manager, &mut receivers);
    assert_eq!(
        recoveries_observed(&manager),
        (recoveries.0 + 1, recoveries.1 + 1),
        "one admitted rebuild and the refused one"
    );
    assert_idle(&manager, &receivers);
}

#[test]
fn evpn_rebuild_waits_for_active_unicast_and_runs_while_a_late_join_is_parked() {
    let v4_waiter = peer_v4(SECOND_SOURCE);
    let mut manager = mixed_deferral_manager(v4_waiter);
    manager.test_force_ungrouped = false;
    let mut receivers = Vec::from(missed_withdrawal(&mut manager, UNICAST));
    let peer = receivers[0].peer;
    drain(&mut manager, &mut receivers);
    assert!(manager.grouped_member_of(peer).is_some());
    assert!(manager.owes_held_rebuild(peer, FAMILY));
    assert!(!manager.owed_row_evicted.contains(&peer));

    manager.mark_outbound_dirty(peer);
    received_unicast(&mut manager, UNICAST..UNICAST + 1);
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.unicast_table, unicast_table(UNICAST + 1));
    assert!(receivers[0].wire.table.contains_key(&key(5)));
    assert_eq!(receivers[0].wire.markers, 0);

    let metrics = manager.metrics.clone();
    let families = HashSet::from([V4]);
    let selection = manager.selection_deferral.as_mut().unwrap();
    assert_eq!(
        selection.classify_session(v4_waiter, 7, false, &families, &metrics),
        []
    );
    received_unicast(&mut manager, UNICAST + 1..300);
    let selection = manager.selection_deferral.as_mut().unwrap();
    selection.session_down(v4_waiter, 7, &metrics);
    let stage = selection
        .await_collision_failback_refresh(v4_waiter, 7, false, &families, true, &metrics)
        .unwrap();
    manager.apply_selection_deferral_transitions(stage, "test collision survivor");
    let before = manager.loc_rib.len();
    manager.advance_unicast_release();
    assert!(manager.loc_rib.len() > before && manager.owed_release_open(V4));

    let late = receiver(5);
    receivers.push(Receiver {
        peer: late,
        rx: up_sized(&mut manager, late, 0, 64, &[V4]),
        wire: Wire::default(),
    });
    assert!(manager.late_release_join_pending(late, V4));
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    release(&mut manager);
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
    assert!(manager.held_rebuild_due(peer));
    assert!(manager.release_resync_waits(peer));
    assert!(!manager.dirty_peers.contains(&peer));
    assert!(
        !manager.owed_eviction_pending(),
        "no retry for the blocked rebuild"
    );
    let captures = manager.adj_rib_out_commit_stats.group_table_captures;
    manager.promote_evicted_receiver();
    assert!(!manager.dirty_peers.contains(&peer), "no early promotion");
    assert_eq!(
        manager.adj_rib_out_commit_stats.group_table_captures,
        captures
    );
    for r in &mut receivers {
        r.write();
    }
    assert!(receivers[0].wire.table.contains_key(&key(5)));
    assert_eq!(receivers[0].wire.markers, 0);
    assert_eq!(receivers[3].wire.unicast_markers, 0);

    let selection = manager.selection_deferral.as_mut().unwrap();
    assert_eq!(
        selection.classify_session(v4_waiter, 8, false, &families, &metrics),
        []
    );
    manager.reselect_newly_deferred_local(&HashSet::new());
    assert!(manager.selection_deferred(V4) && manager.owed_release_open(V4));
    assert!(
        manager.owed_eviction_pending(),
        "EVPN can now make progress"
    );
    let (built, _) = drain_one_unit_a_tick(&mut manager, &mut receivers);
    assert_eq!(built, 1);
    assert_eq!(receivers[0].wire.count(5), (1, 1));
    assert_eq!(receivers[0].wire.table, selected_evpn(&manager));
    assert_eq!(receivers[0].wire.markers, 1);
    assert_eq!(receivers[0].wire.rows_after_marker, 0);
    assert!(manager.late_release_join_pending(late, V4));
    assert_eq!(receivers[3].wire.unicast_markers, 0);

    manager.expire_selection_deferral();
    drain_unicast_release(&mut manager);
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.unicast_table, unicast_table(300));
    let late_wire = &receivers[3].wire;
    assert_eq!(late_wire.unicast_table, unicast_table(300));
    assert_eq!(late_wire.unicast_markers, 1);
    assert_eq!(late_wire.unicast_rows_after_marker, 0);
    assert!(!manager.late_release_join_pending(late, V4));
}
