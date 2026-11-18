use super::*;
use ReceiverState::Clean;

#[test]
fn rtc_membership_changed_during_a_hold_filters_the_released_evpn_table() {
    for state in ReceiverState::ALL {
        for grouped in [false, true] {
            membership_change(state, grouped);
        }
    }
}

fn membership_change(state: ReceiverState, grouped: bool) {
    let mut manager = deferral_manager(CREDIT);
    manager.test_force_ungrouped = !grouped;
    let _source = up_sized(&mut manager, peer_v4(SOURCE), 0, 64, &[V4]);
    let address = Ipv4Addr::new(10, 0, 9, 1);
    let peer = peer_v4(address);
    let mut families = vpn_rtc_sendable();
    families.push(EVPN);
    let mut subject = Receiver {
        peer,
        rx: up_sized(&mut manager, peer, 0, 64, &families),
        wire: Wire::default(),
    };
    // The clean receiver swaps RT 100 for 200. The other receivers narrow
    // default interest to RT 200 so debt can start on untagged rows.
    let mut initial = make_rtc_rib_route(address, 100, 100);
    if !matches!(state, Clean) {
        initial.nlri = rustbgpd_wire::RtcNlri::DEFAULT;
    }
    let prior = initial.key();
    manager.handle_update(RibUpdate::RtcRoutesReceived {
        peer,
        session_id: 0,
        announced: vec![initial],
        withdrawn: vec![],
    });
    end_of_rib(&mut manager, peer, 0, RTC);
    drain(&mut manager, std::slice::from_mut(&mut subject));
    assert_eq!(subject.wire.markers, 1);
    subject.wire = Wire::default();

    received_routes(
        &mut manager,
        (0..8).map(|i| route_rt(i, 0, &[100])).collect(),
        &[],
    );
    let old = route_rt(90_000, 0, &[100]);
    let new = route_rt(90_001, 0, &[200]);
    let gone = route_rt(90_002, 0, &[100, 200]);
    received_routes(&mut manager, vec![old.clone(), new.clone(), gone], &[]);
    drain(&mut manager, std::slice::from_mut(&mut subject));
    assert!(subject.wire.table.contains_key(&old.key()));
    assert_eq!(
        subject.wire.table.contains_key(&new.key()),
        !matches!(state, Clean)
    );
    prepare_receiver(&mut manager, &subject, state);
    assert_eq!(manager.vpn_grouped_member_of(peer).is_some(), grouped);
    assert!(manager.evpn_grouped_member_of(peer).is_none());

    let waiter = hold(&mut manager);
    let mut receivers = [subject, waiter];
    manager.handle_update(RibUpdate::RtcRoutesReceived {
        peer,
        session_id: 0,
        announced: vec![make_rtc_rib_route(address, 200, 100)],
        withdrawn: vec![prior],
    });
    let changed = route_rt(90_003, 1, &[100, 200]);
    received_routes(&mut manager, vec![changed.clone()], &[90_002]);
    tick(&mut manager, &mut receivers);
    assert!(manager.selection_deferred(EVPN));
    assert_eq!(receivers[1].wire.markers, 0);
    release(&mut manager);

    drain(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);
    let filtered = [new, changed].map(|r| (r.key(), format!("{:?}", r.attributes)));
    assert_eq!(
        receivers[0].wire.table,
        BTreeMap::from(filtered),
        "{state:?}, grouped={grouped}"
    );
    assert_eq!(receivers[0].wire.markers, 0);
    let waiter = &receivers[1].wire;
    assert_eq!(waiter.table, selected_evpn(&manager));
    assert_eq!((waiter.markers, waiter.rows_after_marker), (1, 0));
    assert_idle(&manager, &receivers);
}

#[test]
fn releasing_one_family_delivers_its_table_and_marker_while_the_other_is_held() {
    for state in ReceiverState::ALL {
        for first in [EVPN, V4] {
            split_release(state, first);
        }
    }
}

fn split_release(state: ReceiverState, first: (Afi, Safi)) {
    let peer = peer_v4(WAITER);
    let families = [V4, EVPN];
    let mut manager = manager(CREDIT).with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: vec![SelectionDeferralWaiterConfig {
            peer: peer.into(),
            families: families.to_vec(),
        }],
    });
    let _source = up_sized(&mut manager, peer_v4(SOURCE), 0, 64, &[V4]);
    let mut subject = Receiver::up(&mut manager, receiver(0), 64, &families);
    received(&mut manager, &all(8), &[]);
    received_unicast(&mut manager, 0..2);
    drain(&mut manager, std::slice::from_mut(&mut subject));
    prepare_receiver(&mut manager, &subject, state);

    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id: 7,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: families.to_vec(),
        peer_enhanced_refresh: false,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let waiter = Receiver {
        peer,
        rx: up_sized(&mut manager, peer, 7, 64, &families),
        wire: Wire::default(),
    };
    let mut receivers = [subject, waiter];
    assert!(manager.selection_deferred(V4) && manager.selection_deferred(EVPN));
    received(&mut manager, &[(90_000, 1)], &[6]);
    received_unicast(&mut manager, 2..4);
    let other = if first == EVPN { V4 } else { EVPN };
    end_of_rib(&mut manager, peer, 7, first);
    assert!(!manager.selection_deferred(first) && manager.selection_deferred(other));
    drain(&mut manager, &mut receivers);
    let wire = &receivers[1].wire;
    let expected_v4 = unicast_table(4);
    if first == EVPN {
        assert_eq!(wire.table, selected_evpn(&manager));
        assert!(wire.table.contains_key(&key(90_000)) && !wire.table.contains_key(&key(6)));
        assert!(wire.unicast_table.is_empty());
        assert_eq!((wire.markers, wire.unicast_markers), (1, 0));
    } else {
        assert_eq!(wire.unicast_table, expected_v4);
        assert!(!wire.table.contains_key(&key(90_000)));
        assert_eq!((wire.markers, wire.unicast_markers), (0, 1));
    }

    end_of_rib(&mut manager, peer, 7, other);
    assert!(!manager.selection_deferred(other));
    drain(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);
    let expected = selected_evpn(&manager);
    assert!(expected.contains_key(&key(90_000)) && !expected.contains_key(&key(6)));
    for (index, receiver) in receivers.iter().enumerate() {
        let wire = &receiver.wire;
        assert_eq!(wire.table, expected, "{state:?}/{first:?}");
        assert_eq!(wire.unicast_table, expected_v4);
        assert_eq!((wire.markers, wire.unicast_markers), (index, index));
        assert_eq!(wire.rows_after_marker + wire.unicast_rows_after_marker, 0);
    }
    assert_idle(&manager, &receivers);
}
