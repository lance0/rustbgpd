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
