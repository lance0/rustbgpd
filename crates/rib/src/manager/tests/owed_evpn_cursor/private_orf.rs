use super::*;

#[test]
fn a_private_handoff_keeps_its_admitted_rows_through_selection_release() {
    // The group ownership switch in owned_sibling is available in fixtures.
    // Slow isolation, handoff capture and the release use ordinary actor events.
    let (mut manager, mut subject, gid) = owned_sibling(deferral_manager(CREDIT));
    let peer = subject.peer;
    received(&mut manager, &[(0, 0), (1, 0)], &[]);
    drain(&mut manager, std::slice::from_mut(&mut subject));
    assert_eq!(subject.wire.table, table(&[(0, 0), (1, 0)]));
    assert_eq!(manager.evpn_grouped_member_of(peer), Some(gid));

    let waiter = hold(&mut manager);
    let sender = manager.outbound_peers[&peer].clone();
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
    manager.handle_update(RibUpdate::PeerSlowState {
        peer,
        session_id: 0,
        slow: true,
    });
    received(&mut manager, &[(1, 7), (2, 9)], &[0]);
    assert!(manager.has_private_evpn_handoff(peer));
    let handle = manager.evpn_recovery_handle(peer).unwrap();
    assert!(!manager.evpn_recovery.is_dormant(handle));
    assert!(manager.evpn_grouped_member_of(peer).is_none());
    assert!(!manager.owing_family_in_scope(peer, FAMILY));
    assert_no_cursor(&manager, peer, "handoff before release");
    subject.write();
    assert_eq!(subject.wire.table, table(&[(0, 0), (1, 0)]));

    let mut receivers = [subject, waiter];
    release(&mut manager);
    drain(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);
    let [subject, waiter] = &receivers;
    for receiver in &receivers {
        assert_eq!(receiver.wire.table, table(&[(1, 7), (2, 9)]));
    }
    assert_eq!(
        subject.wire.count(0).1,
        1,
        "withdraw the previously admitted row"
    );
    assert_eq!(
        subject.wire.markers, 0,
        "initial marker sent before the hold"
    );
    assert_eq!((waiter.wire.markers, waiter.wire.rows_after_marker), (1, 0));
    assert_no_cursor(&manager, peer, "settled handoff");
    assert!(!manager.has_private_evpn_handoff(peer));
    assert!(!manager.evpn_recovery_reset_pending(peer));
    assert_idle(&manager, &receivers);
}

fn reconnect_with_ipv4_orf(manager: &mut RibManager, peer: PeerId) -> Receiver {
    // The previous session's GR capability makes the new IPv4 End-of-RIB
    // follow the initial gated table, so its position is observable.
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id: 1,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![V4],
        peer_enhanced_refresh: false,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let _old = up_sized(manager, peer, 1, 8, &[V4, EVPN]);
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 1,
    });
    let mut rx = up_sized_with_orf(manager, peer, 0, 64, &[V4, EVPN], &[V4]);
    let mut initial = Wire::default();
    initial.write(&mut rx);
    assert_eq!((initial.markers, initial.unicast_markers), (1, 0));
    assert!(manager.eor_behind_orf_table(peer).contains(&V4));
    Receiver {
        peer,
        rx,
        wire: Wire::default(),
    }
}

#[test]
fn an_ipv4_orf_gate_stays_closed_across_evpn_cursor_eviction_and_dirty_release() {
    for state in [
        ReceiverState::Cursor,
        ReceiverState::Evicted,
        ReceiverState::Dirty,
    ] {
        let mut manager = deferral_manager(CREDIT);
        manager.test_force_ungrouped = false;
        let _source = up_sized(&mut manager, peer_v4(SOURCE), 0, 64, &[]);
        let peer = receiver(0);
        let mut subject = reconnect_with_ipv4_orf(&mut manager, peer);
        received(&mut manager, &all(8), &[]);
        received_unicast(&mut manager, 0..3);
        drain(&mut manager, std::slice::from_mut(&mut subject));
        assert_eq!(subject.wire.table, table(&all(8)));
        assert!(subject.wire.unicast_table.is_empty());

        prepare_receiver(&mut manager, &subject, state);
        let waiter = hold(&mut manager);
        assert!(manager.peer_orf_pending[&peer].contains(&V4));
        assert!(!manager.peer_orf_pending[&peer].contains(&EVPN));
        assert!(manager.grouped_member_of(peer).is_none());
        match state {
            ReceiverState::Cursor => assert!(manager.owes_whole(peer, FAMILY)),
            ReceiverState::Evicted => {
                assert!(manager.owed_row_evicted.contains(&peer));
                assert!(manager.dirty_peers.contains(&peer));
            }
            ReceiverState::Dirty => assert!(manager.dirty_peers.contains(&peer)),
            _ => unreachable!(),
        }
        received(&mut manager, &[(1, 7), (2, 9)], &[0]);
        let mut receivers = [subject, waiter];
        release(&mut manager);
        drain(&mut manager, &mut receivers);
        tick(&mut manager, &mut receivers);
        let expected = selected_evpn(&manager);
        for (key, attrs) in table(&[(1, 7), (2, 9)]) {
            assert_eq!(expected.get(&key), Some(&attrs));
        }
        assert!(!expected.contains_key(&key(0)));
        let [subject, waiter] = &receivers;
        assert_eq!(subject.wire.table, expected, "{state:?}");
        assert_eq!(waiter.wire.table, expected, "{state:?}");
        assert_eq!(
            subject.wire.count(0).1,
            1,
            "withdraw the previously admitted row"
        );
        assert_eq!(subject.wire.markers, 0);
        assert_eq!((waiter.wire.markers, waiter.wire.rows_after_marker), (1, 0));
        assert_eq!((subject.wire.unicast, subject.wire.unicast_markers), (0, 0));
        assert!(manager.peer_orf_pending[&peer].contains(&V4));
        assert!(manager.eor_behind_orf_table(peer).contains(&V4));
        manager.handle_update(RibUpdate::RouteRefreshRequest {
            peer,
            session_id: 0,
            afi: V4.0,
            safi: V4.1,
            queued: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        });
        drain(&mut manager, &mut receivers);
        tick(&mut manager, &mut receivers);
        let wire = &receivers[0].wire;
        assert_eq!(wire.unicast_table, unicast_table(3));
        assert_eq!(
            (wire.unicast_markers, wire.unicast_rows_after_marker),
            (1, 0)
        );
        assert!(!manager.peer_orf_pending.contains_key(&peer));
        assert_idle(&manager, &receivers);
    }
}
