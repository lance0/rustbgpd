//! Receiver state and ownership cases for the VPN row cursor: a receiver
//! that is clean, owes keys, holds a cursor, was evicted by the list cap or
//! is dirty meets each event that can change its `VPNv4` export inside a
//! selection hold, and each collision-failback release; a refresh follows a
//! cap eviction; a grouped VPN sibling shares the release with a private
//! cursor holder; and VPN ownership moves between the group and the private
//! Adj-RIB-Out around a cursor. Each case ends with every receiver's exact
//! table against the Loc-RIB, one End-of-RIB after the last row, and
//! nothing owed, dirty or evicted; the owed index is checked against its
//! full-scan predicate along the way.

use super::*;
use rustbgpd_policy::{NeighborSetMatch, Policy, PolicyAction, PolicyChain};

const WAITER2: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 4);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Clean,
    Keyed,
    Cursor,
    Evicted,
    Dirty,
}

const STATES: [State; 5] = [
    State::Clean,
    State::Keyed,
    State::Cursor,
    State::Evicted,
    State::Dirty,
];

fn selected(manager: &RibManager) -> Table {
    manager
        .loc_rib
        .iter_vpn()
        .filter(|route| OwedFamily::vpn_of(&route.nlri.key()) == F4)
        .map(|route| entry(route, 0))
        .collect()
}

fn permit_all() -> PolicyChain {
    let mut statement = super::super::update_groups::deny_statement(Ipv4Prefix::new(SOURCE, 32));
    statement.prefix = None;
    statement.action = PolicyAction::Permit;
    PolicyChain::new(vec![Policy {
        entries: vec![statement],
        default_action: PolicyAction::Deny,
    }])
}

/// Permit-all whose never-matching neighbor-set statement makes the peer
/// ungrouped (`policy_peer_context`).
fn peer_context_permit() -> PolicyChain {
    let mut never = super::super::update_groups::deny_statement(Ipv4Prefix::new(
        Ipv4Addr::new(192, 168, 255, 0),
        24,
    ));
    never.match_neighbor_set = Some(NeighborSetMatch {
        addresses: vec![],
        remote_asns: vec![65099],
        peer_groups: vec![],
    });
    PolicyChain::new(vec![Policy {
        entries: vec![never],
        default_action: PolicyAction::Permit,
    }])
}

fn second_rows(manager: &mut RibManager, rows: &[(u32, u32)]) {
    send(
        manager,
        SECOND,
        rows.iter()
            .map(|&(index, label)| route_from(SECOND, P4, index, label, 100))
            .collect(),
        vec![],
    );
}

fn refresh_request(manager: &mut RibManager, peer: PeerId) {
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer,
        session_id: 0,
        afi: P4.0,
        safi: P4.1,
        queued: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    });
}

fn operator_refresh(manager: &mut RibManager, peer: PeerId) {
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::RefreshPeerOutbound { peer, reply });
    result.try_recv().unwrap().unwrap();
}

fn prepare(manager: &mut RibManager, model: &mut Model, subject: &Receiver, state: State) {
    let peer = subject.peer;
    assert!(subject.wire.holds(P4, 5));
    assert!(!manager.owes(peer, P4));
    if state == State::Clean {
        return;
    }
    if state == State::Dirty {
        subject.stall(manager);
        assert!(manager.mark_outbound_dirty(peer));
        model.send(manager, &[], &[5]);
        assert!(manager.dirty_peers.contains(&peer));
        return;
    }
    for label in 101..=116 {
        model.send(manager, &[(0, label), (1, label), (2, label)], &[]);
        if manager.owes(peer, P4) {
            break;
        }
    }
    model.send(manager, &[], &[5]);
    assert!(manager.owed_key_count(peer, F4) > 0 && !manager.owes_whole(peer, F4));
    if state == State::Keyed {
        return;
    }
    let mut previous = Vec::new();
    for round in 0..400u32 {
        let base = 1000 + round * 64;
        let fresh: Vec<_> = (base..base + 64).map(|index| (index, 100)).collect();
        model.send(manager, &fresh, &previous);
        if state == State::Cursor && manager.owes_whole(peer, F4) {
            assert!(!manager.owed_row_evicted.contains(&peer));
            return;
        }
        if state == State::Evicted && manager.owed_row_evicted.contains(&peer) {
            return;
        }
        previous = (base..base + 64).collect();
    }
    panic!("receiver never reached {state:?}");
}

/// [`drain`] with the owed index checked after every tick.
fn drain_checked(manager: &mut RibManager, receivers: &mut [Receiver]) {
    for _ in 0..100_000 {
        for receiver in receivers.iter_mut() {
            receiver.write();
        }
        if !manager.resync_tick_pending() {
            return;
        }
        tick(manager, receivers);
        manager.assert_owed_vpn_index();
    }
    panic!("the drain does not finish");
}

fn assert_idle(manager: &RibManager, receivers: &[Receiver], case: &str) {
    for receiver in receivers {
        let peer = receiver.peer;
        assert!(manager.eor_pending(peer).is_empty(), "{case}: {peer} eor");
        assert!(manager.owing(peer).is_none(), "{case}: {peer} owing");
        assert!(!manager.dirty_peers.contains(&peer), "{case}: {peer} dirty");
        assert!(!manager.owed_row_evicted.contains(&peer), "{case}: {peer}");
    }
    assert!(lists_freed(manager), "{case}: lists");
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

impl HoldEvent {
    const ALL: [Self; 8] = [
        Self::Withdraw,
        Self::SourceDown,
        Self::RestartEor,
        Self::RestartTimeout,
        Self::LongLivedTimeout,
        Self::ReplacePolicy,
        Self::OperatorRefresh,
        Self::PeerRefresh,
    ];

    fn apply(self, manager: &mut RibManager, subject: PeerId) {
        let peer = peer_v4(SECOND);
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
                    gr_families: vec![P4],
                    peer_llgr_capable: llgr,
                    peer_llgr_families: if llgr {
                        vec![rustbgpd_wire::LlgrFamily {
                            afi: P4.0,
                            safi: P4.1,
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
                    let _replacement = up(manager, peer, 0, 16, &[V4], 0);
                    second_rows(manager, &[(100, 303)]);
                    end_of_rib(manager, peer, 0, P4);
                } else {
                    manager.sweep_gr_stale(peer);
                    if llgr {
                        drain_route_chunks(manager);
                        manager.sweep_llgr_stale(peer, &[P4]);
                    }
                }
            }
            Self::ReplacePolicy => {
                manager
                    .replace_peer_export_policy_synchronously(subject, Some(permit_all()))
                    .unwrap();
            }
            Self::OperatorRefresh => operator_refresh(manager, subject),
            Self::PeerRefresh => refresh_request(manager, subject),
            Self::Withdraw => {}
        }
        drain_route_chunks(manager);
    }
}

/// Receiver state x event inside a `VPNv4` hold, ungrouped (VPN is private
/// only outside every group), with a receiver that joins inside the hold.
fn hold_case(event: HoldEvent, state: State) {
    let case = format!("{event:?}/{state:?}");
    let overflow = matches!(state, State::Clean | State::Evicted | State::Dirty);
    let mut manager = deferral_manager(CREDIT, &[P4]);
    sources_up(&mut manager);
    let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 16, &[P4], 0)];
    let mut model = Model::new(P4, &[]);
    model.send(&mut manager, &all(8), &[]);
    second_rows(&mut manager, &[(100, 300), (101, 300)]);
    drain_checked(&mut manager, &mut receivers);
    prepare(&mut manager, &mut model, &receivers[0], state);
    if overflow {
        manager.set_deferred_selection_limits_for_test(0, usize::MAX);
    }
    receivers.push(hold(&mut manager, &[P4]));
    receivers.push(join_held(&mut manager, 7, &[P4]));
    model.send(&mut manager, &[(9000, 222)], &[6]);
    event.apply(&mut manager, receivers[0].peer);
    for _ in 0..4 {
        tick(&mut manager, &mut receivers);
        manager.assert_owed_vpn_index();
    }
    assert!(manager.selection_deferred(P4), "{case}");
    assert!(
        receivers[1..].iter().all(|r| r.wire.markers[0] == 0),
        "{case}: no marker in the hold"
    );
    release(&mut manager, P4);
    manager.assert_owed_vpn_index();
    drain_checked(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);
    manager.assert_owed_vpn_index();

    let expected = selected(&manager);
    assert!(expected.contains_key(&(key(P4, 9000), 0)), "{case}");
    assert!(!expected.contains_key(&(key(P4, 6), 0)), "{case}");
    for (i, r) in receivers.iter().enumerate() {
        assert_eq!(r.wire.table, expected, "{case}: {} table", r.peer);
        assert_eq!(r.wire.markers[0], usize::from(i != 0), "{case}: {}", r.peer);
        assert_eq!(r.wire.rows_after_marker[0], 0, "{case}: {}", r.peer);
    }
    if event == HoldEvent::PeerRefresh {
        assert_eq!(
            receivers[0]
                .wire
                .sent
                .iter()
                .filter(|s| matches!(s, Sent::Answer(_)))
                .count(),
            1,
            "{case}: one answer"
        );
    }
    assert_idle(&manager, &receivers, &case);
}

#[test]
fn every_vpn_receiver_state_meets_every_hold_event_and_ends_with_the_released_table() {
    for event in HoldEvent::ALL {
        for state in STATES {
            hold_case(event, state);
        }
    }
}

fn waiter_up(manager: &mut RibManager, address: Ipv4Addr, session_id: u64) -> Receiver {
    let peer = peer_v4(address);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![P4],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    Receiver {
        peer,
        rx: up(manager, peer, session_id, 4096, &[P4], 0),
        wire: Wire::default(),
    }
}

fn survivor_refresh(manager: &mut RibManager) {
    manager.handle_update(RibUpdate::BeginRouteRefresh {
        peer: peer_v4(WAITER),
        session_id: 11,
        afi: P4.0,
        safi: P4.1,
    });
    manager.handle_update(RibUpdate::EndRouteRefresh {
        peer: peer_v4(WAITER),
        session_id: 11,
        afi: P4.0,
        safi: P4.1,
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

    fn finish(self, manager: &mut RibManager, model: &mut Model) {
        match self {
            Self::Refresh => survivor_refresh(manager),
            Self::RearmRestageRefresh => {
                end_of_rib(manager, peer_v4(WAITER2), 33, P4);
                assert!(!manager.selection_deferred(P4));
                assert!(manager.selection_convergence_held(P4));
                model.send(manager, &[(90_003, 503)], &[4]);
                survivor_refresh(manager);
            }
            Self::RearmEor => {
                survivor_refresh(manager);
                assert!(manager.selection_deferred(P4));
                end_of_rib(manager, peer_v4(WAITER2), 33, P4);
            }
            Self::StagedTimer | Self::RearmTimer => manager.expire_selection_deferral(),
        }
        assert!(!manager.selection_convergence_held(P4));
    }
}

/// Collision failback x receiver state, VPN, with a late joiner.
fn stage_case(state: State, release: Release) {
    let case = format!("{state:?}/{release:?}");
    let mut manager = manager(CREDIT).with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: [WAITER, WAITER2]
            .map(|address| SelectionDeferralWaiterConfig {
                peer: peer_v4(address).into(),
                families: vec![P4],
            })
            .into(),
    });
    sources_up(&mut manager);
    let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 16, &[P4], 0)];
    let mut model = Model::new(P4, &[]);
    model.send(&mut manager, &all(8), &[]);
    drain_checked(&mut manager, &mut receivers);
    prepare(&mut manager, &mut model, &receivers[0], state);
    if release.rearmed() {
        manager.set_deferred_selection_limits_for_test(0, usize::MAX);
    }
    receivers.push(waiter_up(&mut manager, WAITER, 11));
    assert!(manager.selection_deferred(P4));
    model.send(&mut manager, &[(90_000, 501)], &[6]);
    let replacement = waiter_up(&mut manager, WAITER, 22);
    manager.handle_update(RibUpdate::PeerDown {
        peer: replacement.peer,
        session_id: 22,
    });
    drop(replacement);
    assert!(!manager.selection_deferred(P4), "{case}");
    assert!(manager.selection_convergence_held(P4), "{case}");
    let late = receiver(1);
    receivers.push(Receiver {
        peer: late,
        rx: up(&mut manager, late, 0, 4096, &[P4], 0),
        wire: Wire::default(),
    });
    model.send(&mut manager, &[(90_001, 501)], &[7]);
    if release.rearmed() {
        receivers.push(waiter_up(&mut manager, WAITER2, 33));
        assert!(manager.selection_deferred(P4), "{case}");
        if state == State::Dirty {
            operator_refresh(&mut manager, receivers[0].peer);
            receivers[0].write();
        }
        model.send(&mut manager, &[(90_002, 502), (90_000, 502)], &[]);
        for _ in 0..4 {
            tick(&mut manager, &mut receivers);
            manager.assert_owed_vpn_index();
        }
    }
    release.finish(&mut manager, &mut model);
    drain_checked(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);
    manager.assert_owed_vpn_index();

    let expected = selected(&manager);
    assert_eq!(model.table(), expected, "{case}: selected rows");
    for (i, receiver) in receivers.iter().enumerate() {
        assert_eq!(receiver.wire.table, expected, "{case}: {}", receiver.peer);
        assert_eq!(
            receiver.wire.markers[0],
            usize::from(i != 0),
            "{case}: {} markers",
            receiver.peer
        );
        assert_eq!(receiver.wire.rows_after_marker[0], 0, "{case}");
        assert!(!manager.eor.owes(receiver.peer, P4), "{case}");
    }
    assert_idle(&manager, &receivers, &case);
}

#[test]
fn every_vpn_receiver_state_ends_exact_after_every_collision_failback_release() {
    for state in STATES {
        for release in [
            Release::Refresh,
            Release::RearmRestageRefresh,
            Release::RearmEor,
            Release::RearmTimer,
            Release::StagedTimer,
        ] {
            stage_case(state, release);
        }
    }
}

/// Grouped VPN members beside a private (policy-peer-context) receiver
/// that holds a VPN cursor: hold, churn, release with the private one
/// stalled, churn behind and ahead of its walk, a grouped and a private
/// joiner inside the hold. Every receiver ends with the Loc-RIB.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario: group, hold, joiners, release, churn behind and ahead in order"
)]
fn grouped_vpn_siblings_beside_a_private_cursor_holder_end_with_the_loc_rib() {
    for stalled_through_release in [false, true] {
        let case = format!("stalled={stalled_through_release}");
        let mut manager = deferral_manager(CREDIT, &[P4]);
        manager.test_force_ungrouped = false;
        sources_up(&mut manager);
        let mut receivers = vec![
            Receiver::up(&mut manager, receiver(0), 4096, &[P4], 0),
            Receiver::up(&mut manager, receiver(1), 4096, &[P4], 0),
        ];
        let private = receiver(2);
        let mut rx = up_with(
            &mut manager,
            private,
            0,
            4096,
            &[P4],
            0,
            Some(peer_context_permit()),
        );
        Wire::default().write(&mut rx);
        receivers.push(Receiver {
            peer: private,
            rx,
            wire: Wire::default(),
        });
        let mut model = Model::new(P4, &[]);
        model.send(&mut manager, &all(60), &[]);
        drain(&mut manager, &mut receivers);
        assert!(
            manager.vpn_grouped_member_of(receivers[0].peer).is_some(),
            "{case}: grouped"
        );
        assert_eq!(
            manager.vpn_grouped_member_of(receivers[0].peer),
            manager.vpn_grouped_member_of(receivers[1].peer)
        );
        assert!(
            manager.grouped_member_of(private).is_none(),
            "{case}: private"
        );
        for r in &receivers {
            assert_eq!(r.wire.table, model.table(), "{case}: initial");
        }
        receivers.push(hold(&mut manager, &[P4]));
        model.send(&mut manager, &[(3, 300), (60, 100), (61, 100)], &[5]);
        // A grouped joiner and a private joiner inside the hold.
        receivers.push(join_held(&mut manager, 5, &[P4]));
        let late_private = receiver(6);
        let mut rx = up_with(
            &mut manager,
            late_private,
            0,
            4096,
            &[P4],
            0,
            Some(peer_context_permit()),
        );
        Wire::default().write(&mut rx);
        receivers.push(Receiver {
            peer: late_private,
            rx,
            wire: Wire::default(),
        });
        assert!(manager.grouped_member_of(late_private).is_none());
        if stalled_through_release {
            receivers[2].stall(&manager);
        }
        for _ in 0..3 {
            tick(&mut manager, &mut receivers);
        }
        release(&mut manager, P4);
        manager.assert_owed_vpn_index();
        assert!(
            manager.owes_whole(late_private, F4),
            "{case}: the private joiner owes VPNv4 whole"
        );
        assert!(
            manager.owing(receivers[0].peer).is_none(),
            "{case}: grouped owes nothing"
        );
        tick(&mut manager, &mut receivers);
        // Behind and ahead of the walk.
        model.send(&mut manager, &[(0, 444), (59, 445), (62, 100)], &[7, 1]);
        manager.assert_owed_vpn_index();
        tick(&mut manager, &mut receivers);
        model.send(&mut manager, &[(1, 446)], &[0]);
        drain(&mut manager, &mut receivers);
        tick(&mut manager, &mut receivers);
        manager.assert_owed_vpn_index();
        let expected = model.table();
        assert_eq!(selected(&manager), expected);
        for (i, r) in receivers.iter().enumerate() {
            assert_eq!(r.wire.table, expected, "{case}: {i} {} table", r.peer);
            assert!(
                r.wire.markers[0] <= 1,
                "{case}: {i} markers {:?}",
                r.wire.markers
            );
            // The waiter and the grouped joiner take later churn after
            // their marker; the private joiner's walk spans the churn.
            if i != 3 && i != 4 {
                assert_eq!(r.wire.rows_after_marker[0], 0, "{case}: {i} after marker");
            }
        }
        for i in [4, 5] {
            assert_eq!(receivers[i].wire.markers[0], 1, "{case}: joiner {i} marker");
        }
        assert_idle(&manager, &receivers, &case);
    }
}

/// Refresh after eviction: two stalled receivers are evicted by the cap
/// (dirty), then one requests a ROUTE-REFRESH of `VPNv4` before (and, in
/// the other run, while still stalled, i.e. deferred) its unit runs.
#[test]
fn a_vpn_refresh_after_cap_eviction_is_answered_once_and_settles() {
    for still_stalled in [false, true] {
        let case = format!("still_stalled={still_stalled}");
        let (mut manager, mut receivers) = owing(manager(CREDIT), P4, &[P4], 3, 8, 4096);
        drain(&mut manager, &mut receivers);
        let model = evict_stalled(&mut manager, &mut receivers, P4);
        let peer = receivers[1].peer;
        assert!(manager.dirty_peers.contains(&peer));
        if !still_stalled {
            receivers[1].write();
        }
        refresh_request(&mut manager, peer);
        drain(&mut manager, &mut receivers);
        tick(&mut manager, &mut receivers);
        for r in &receivers {
            assert_eq!(r.wire.table, model.table(), "{case}: {}", r.peer);
            assert_eq!(r.wire.markers[0], 1, "{case}: {} markers", r.peer);
            assert!(!manager.dirty_peers.contains(&r.peer));
            assert!(manager.owing(r.peer).is_none());
        }
        let answers = receivers[1]
            .wire
            .sent
            .iter()
            .filter(|s| matches!(s, Sent::Answer(_)))
            .count();
        assert_eq!(answers, 1, "{case}: one answer");
        assert!(!manager.pending_refresh.contains_key(&peer), "{case}");
        assert!(manager.owed_row_evicted.is_empty(), "{case}");
        assert!(lists_freed(&manager), "{case}");
    }
}

fn slow(manager: &mut RibManager, peer: PeerId, slow: bool) {
    manager.handle_update(RibUpdate::PeerSlowState {
        peer,
        session_id: 0,
        slow,
    });
}

/// Contract 14 (ownership), grouped build: a stalled group member misses a
/// withdrawal, is isolated as slow (group -> private, with residue), owes
/// `VPNv4` whole from a release while stalled again (a cursor), takes churn
/// behind and ahead, then rejoins its group mid-walk (private -> group).
/// The sibling never owes. Every receiver ends with the Loc-RIB.
#[test]
fn vpn_ownership_moving_around_a_cursor_loses_no_row_and_sends_one_end_of_rib() {
    for rejoin_mid_walk in [false, true] {
        let case = format!("rejoin_mid_walk={rejoin_mid_walk}");
        let mut manager = deferral_manager(CREDIT, &[P4]);
        manager.test_force_ungrouped = false;
        sources_up(&mut manager);
        let mut receivers = vec![
            Receiver::up(&mut manager, receiver(0), 4096, &[P4], 0),
            Receiver::up(&mut manager, receiver(1), 4096, &[P4], 0),
        ];
        let mut model = Model::new(P4, &[]);
        model.send(&mut manager, &all(40), &[]);
        drain(&mut manager, &mut receivers);
        let (sibling, mover) = (receivers[0].peer, receivers[1].peer);
        let gid = manager.vpn_grouped_member_of(mover);
        assert!(
            gid.is_some() && gid == manager.vpn_grouped_member_of(sibling),
            "{case}"
        );
        // A withdrawal the stalled member misses, then isolation.
        receivers[1].stall(&manager);
        model.send(&mut manager, &[(2, 222)], &[5]);
        slow(&mut manager, mover, true);
        assert!(
            manager.grouped_member_of(mover).is_none(),
            "{case}: isolated"
        );
        manager.assert_owed_vpn_index();
        drain(&mut manager, &mut receivers);
        assert_eq!(
            receivers[1].wire.table,
            model.table(),
            "{case}: isolated table"
        );
        assert!(!manager.dirty_peers.contains(&mover), "{case}");
        // A hold, and a release while the private mover is stalled.
        receivers.push(hold(&mut manager, &[P4]));
        model.send(&mut manager, &[(3, 300), (40, 100)], &[6]);
        receivers[1].stall(&manager);
        release(&mut manager, P4);
        assert!(manager.owes_whole(mover, F4), "{case}: a cursor");
        assert!(
            manager.owing(sibling).is_none(),
            "{case}: the sibling owes nothing"
        );
        manager.assert_owed_vpn_index();
        receivers[1].write();
        tick(&mut manager, &mut receivers);
        model.send(&mut manager, &[(0, 444), (39, 445), (41, 100)], &[7]);
        if rejoin_mid_walk {
            assert!(manager.owes_whole(mover, F4), "{case}: still walking");
            slow(&mut manager, mover, false);
            assert!(
                manager.vpn_grouped_member_of(mover).is_some(),
                "{case}: rejoined"
            );
            assert!(
                manager.owing(mover).is_none(),
                "{case}: debt dropped at regroup"
            );
        }
        model.send(&mut manager, &[(1, 446)], &[0]);
        drain(&mut manager, &mut receivers);
        tick(&mut manager, &mut receivers);
        manager.assert_owed_vpn_index();
        let expected = model.table();
        for (i, r) in receivers.iter().enumerate() {
            assert_eq!(r.wire.table, expected, "{case}: {i} table");
            assert!(r.wire.markers[0] <= 1, "{case}: {i} markers");
        }
        assert_idle(&manager, &receivers, &case);
    }
}
