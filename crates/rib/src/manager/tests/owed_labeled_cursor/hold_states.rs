//! Receiver state x event cases for the labeled-unicast row cursor: a
//! receiver that is clean, owes keys, holds a cursor, was evicted by the
//! list cap or is dirty meets each event that can change its labeled export
//! inside a selection hold, a collision failback and a re-armed hold. Each
//! case ends by comparing every receiver's exact table against the Loc-RIB,
//! with one End-of-RIB after the last row. The cap's eviction and in-hold
//! rules (no unit inside a hold, one receiver a tick, no head-of-line wait)
//! are pinned here for labeled receivers, group members included.

use super::*;
use rustbgpd_policy::PolicyChain;

const WAITER2: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 4);
const PLAIN: u32 = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Clean,
    Keyed,
    Cursor,
    Evicted,
    Dirty,
}

impl State {
    const ALL: [Self; 5] = [
        Self::Clean,
        Self::Keyed,
        Self::Cursor,
        Self::Evicted,
        Self::Dirty,
    ];
}

fn grouped(credit: usize, held: &[(Afi, Safi)]) -> RibManager {
    let mut manager = deferral_manager(credit, held);
    manager.test_force_ungrouped = false;
    manager
}

fn selected(manager: &RibManager) -> Table {
    manager
        .loc_rib
        .iter_labeled()
        .map(|route| entry(route, 0))
        .collect()
}

fn plain_route(index: u32) -> Route {
    let mut route = make_indexed_route(index + 1, SOURCE);
    route.peer = peer_v4(SOURCE);
    route
}

fn plain_table(rows: u32) -> BTreeSet<Prefix> {
    (0..rows).map(|index| plain_route(index).prefix).collect()
}

fn plain(manager: &mut RibManager, announced: Vec<Route>, withdrawn: Vec<(Prefix, u32)>) {
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
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

fn plain_rows(manager: &mut RibManager, rows: std::ops::Range<u32>) {
    plain(manager, rows.map(plain_route).collect(), vec![]);
}

fn permit_all() -> PolicyChain {
    let mut statement = super::super::update_groups::deny_statement(Ipv4Prefix::new(SOURCE, 32));
    statement.prefix = None;
    statement.action = rustbgpd_policy::PolicyAction::Permit;
    PolicyChain::new(vec![rustbgpd_policy::Policy {
        entries: vec![statement],
        default_action: rustbgpd_policy::PolicyAction::Deny,
    }])
}

fn regroup(manager: &mut RibManager, peer: PeerId, policy: Option<PolicyChain>) {
    manager
        .replace_peer_export_policy_synchronously(peer, policy)
        .unwrap();
}

fn refresh_request(manager: &mut RibManager, peer: PeerId, family: (Afi, Safi)) {
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer,
        session_id: 0,
        afi: family.0,
        safi: family.1,
        queued: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    });
}

fn operator_refresh(manager: &mut RibManager, peer: PeerId) {
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::RefreshPeerOutbound { peer, reply });
    result.try_recv().unwrap().unwrap();
}

fn second_rows(manager: &mut RibManager, rows: &[(u32, u32)]) {
    send(
        manager,
        SECOND,
        rows.iter()
            .map(|&(index, label)| route_from(SECOND, L4, index, label, 100))
            .collect(),
        vec![],
    );
}

/// Stop reading after admitting rows 0..8. Except in the clean control,
/// row 5 is withdrawn before the hold while the receiver still holds it.
fn prepare(manager: &mut RibManager, model: &mut Model, subject: &Receiver, state: State) {
    let peer = subject.peer;
    assert!(subject.wire.holds(5));
    assert!(!manager.owes(peer, L4));
    assert!(!manager.dirty_peers.contains(&peer));
    if state == State::Clean {
        return;
    }
    if state == State::Dirty {
        subject.stall(manager);
        regroup(manager, peer, Some(permit_all()));
        model.send(manager, &[], &[5]);
        assert!(manager.dirty_peers.contains(&peer));
        assert!(!manager.owed_row_evicted.contains(&peer));
        return;
    }
    for label in 101..=116 {
        model.send(manager, &[(0, label), (1, label), (2, label)], &[]);
        if manager.owes(peer, L4) {
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

fn assert_idle(manager: &RibManager, receivers: &[Receiver], case: &str) {
    for receiver in receivers {
        let peer = receiver.peer;
        assert!(manager.eor_pending(peer).is_empty(), "{case}: {peer} eor");
        assert!(manager.owing(peer).is_none(), "{case}: {peer} owing");
        assert!(!manager.dirty_peers.contains(&peer), "{case}: {peer} dirty");
        assert!(!manager.owed_row_evicted.contains(&peer), "{case}: {peer}");
        assert!(!manager.owes_held_rebuild(peer, F4), "{case}: {peer} held");
        assert!(!manager.owes_held_rebuild(peer, F6), "{case}: {peer} held6");
    }
    assert!(
        manager.owed_rows.iter().all(|list| list.len() == 0),
        "{case}: lists"
    );
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
    fn apply(self, manager: &mut RibManager, subject: PeerId, state: State) {
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
                    gr_families: vec![L4],
                    peer_llgr_capable: llgr,
                    peer_llgr_families: if llgr {
                        vec![rustbgpd_wire::LlgrFamily {
                            afi: L4.0,
                            safi: L4.1,
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
                    end_of_rib(manager, peer, 0, L4);
                } else {
                    manager.sweep_gr_stale(peer);
                    if llgr {
                        drain_route_chunks(manager);
                        manager.sweep_llgr_stale(peer, &[L4]);
                    }
                }
            }
            Self::ReplacePolicy => {
                let previous_group = manager.grouped_member_of(subject);
                regroup(manager, subject, (state != State::Dirty).then(permit_all));
                assert_ne!(manager.grouped_member_of(subject), previous_group);
            }
            Self::OperatorRefresh => operator_refresh(manager, subject),
            Self::PeerRefresh => refresh_request(manager, subject, L4),
            Self::Withdraw => {}
        }
        drain_route_chunks(manager);
    }
}

/// Receiver state x event inside a labeled hold, in the default (grouped)
/// build, with a receiver that joins inside the hold.
fn hold_case(event: HoldEvent, state: State) {
    let case = format!("{event:?}/{state:?}");
    let overflow = matches!(state, State::Clean | State::Evicted | State::Dirty);
    let mut manager = grouped(CREDIT, &[L4]);
    sources_up(&mut manager);
    let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 16, &[V4, L4], 0)];
    let mut model = Model::default();
    model.send(&mut manager, &all(8), &[]);
    second_rows(&mut manager, &[(100, 300), (101, 300)]);
    plain_rows(&mut manager, 0..2);
    drain(&mut manager, &mut receivers);
    prepare(&mut manager, &mut model, &receivers[0], state);

    if overflow {
        manager.set_deferred_selection_limits_for_test(0, usize::MAX);
    }
    receivers.push(hold(&mut manager, &[L4]));
    receivers.push(join_held(&mut manager, 7, &[V4, L4]));
    model.send(&mut manager, &[(9000, 222)], &[6]);
    event.apply(&mut manager, receivers[0].peer, state);
    plain_rows(&mut manager, 2..4);
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    for _ in 0..4 {
        tick(&mut manager, &mut receivers);
    }
    assert!(manager.selection_deferred(L4), "{case}");
    assert!(
        receivers[1..].iter().all(|r| r.wire.markers[0] == 0),
        "{case}: no marker in the hold"
    );
    if state == State::Evicted {
        assert_eq!(
            manager.adj_rib_out_commit_stats.resync_builds, builds,
            "{case}: no unit built inside the hold"
        );
    }
    release(&mut manager, L4);
    drain(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);

    let expected = selected(&manager);
    assert!(expected.contains_key(&(prefix(L4, 9000), 0)), "{case}");
    assert!(!expected.contains_key(&(prefix(L4, 6), 0)), "{case}");
    assert_eq!(
        expected.contains_key(&(prefix(L4, 5), 0)),
        state == State::Clean,
        "{case}"
    );
    let kept = [100, 101].map(|index| expected.contains_key(&(prefix(L4, index), 0)));
    assert_eq!(
        kept,
        match event {
            HoldEvent::SourceDown | HoldEvent::RestartTimeout | HoldEvent::LongLivedTimeout =>
                [false, false],
            HoldEvent::RestartEor => [true, false],
            _ => [true, true],
        },
        "{case}"
    );
    for (i, r) in receivers.iter().enumerate() {
        assert_eq!(r.wire.table, expected, "{case}: {} table", r.peer);
        assert_eq!(r.wire.markers[0], usize::from(i != 0), "{case}: {}", r.peer);
        assert_eq!(r.wire.rows_after_marker[0], 0, "{case}: {}", r.peer);
        if i != 1 {
            assert_eq!(r.wire.unicast_table, plain_table(4), "{case}: {}", r.peer);
        }
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

fn check_states(events: &[HoldEvent]) {
    for &event in events {
        for state in State::ALL {
            hold_case(event, state);
        }
    }
}

#[test]
fn a_withdrawal_or_source_loss_in_a_labeled_hold_reaches_a_receiver_in_any_state() {
    check_states(&[HoldEvent::Withdraw, HoldEvent::SourceDown]);
}

#[test]
fn restart_sweeps_in_a_labeled_hold_reach_a_receiver_in_any_state() {
    check_states(&[
        HoldEvent::RestartEor,
        HoldEvent::RestartTimeout,
        HoldEvent::LongLivedTimeout,
    ]);
}

#[test]
fn a_policy_replacement_or_refresh_in_a_labeled_hold_reaches_a_receiver_in_any_state() {
    check_states(&[
        HoldEvent::ReplacePolicy,
        HoldEvent::OperatorRefresh,
        HoldEvent::PeerRefresh,
    ]);
}

fn waiter_up(manager: &mut RibManager, address: Ipv4Addr, session_id: u64) -> Receiver {
    let peer = peer_v4(address);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![L4],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    Receiver {
        peer,
        rx: up(manager, peer, session_id, 4096, &[L4], 0),
        wire: Wire::default(),
    }
}

fn survivor_refresh(manager: &mut RibManager) {
    manager.handle_update(RibUpdate::BeginRouteRefresh {
        peer: peer_v4(WAITER),
        session_id: 11,
        afi: L4.0,
        safi: L4.1,
    });
    manager.handle_update(RibUpdate::EndRouteRefresh {
        peer: peer_v4(WAITER),
        session_id: 11,
        afi: L4.0,
        safi: L4.1,
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
                end_of_rib(manager, peer_v4(WAITER2), 33, L4);
                assert!(!manager.selection_deferred(L4));
                assert!(manager.selection_convergence_held(L4));
                model.send(manager, &[(90_003, 503)], &[4]);
                survivor_refresh(manager);
            }
            Self::RearmEor => {
                survivor_refresh(manager);
                assert!(manager.selection_deferred(L4));
                end_of_rib(manager, peer_v4(WAITER2), 33, L4);
            }
            Self::StagedTimer | Self::RearmTimer => manager.expire_selection_deferral(),
        }
        assert!(!manager.selection_convergence_held(L4));
    }
}

/// Collision failback (staged convergence, an optional re-armed hold, then
/// the release) x receiver state, with a receiver that joins while staged.
fn stage_case(state: State, release: Release) {
    let case = format!("{state:?}/{release:?}");
    let mut manager = manager(CREDIT).with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: [WAITER, WAITER2]
            .map(|address| SelectionDeferralWaiterConfig {
                peer: peer_v4(address).into(),
                families: vec![L4],
            })
            .into(),
    });
    manager.test_force_ungrouped = false;
    sources_up(&mut manager);
    let subject = Receiver::up(&mut manager, receiver(0), 16, &[V4, L4], 0);
    let mut receivers = vec![subject];
    let mut model = Model::default();
    model.send(&mut manager, &all(8), &[]);
    plain_rows(&mut manager, 0..PLAIN);
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table, model.table());
    prepare(&mut manager, &mut model, &receivers[0], state);
    if release.rearmed() {
        manager.set_deferred_selection_limits_for_test(0, usize::MAX);
    }

    receivers.push(waiter_up(&mut manager, WAITER, 11));
    assert!(manager.selection_deferred(L4));
    model.send(&mut manager, &[(90_000, 501)], &[6]);
    if state == State::Dirty && release.rearmed() {
        drain(&mut manager, &mut receivers);
        assert!(manager.owes_held_rebuild(receivers[0].peer, F4), "{case}");
    }
    let replacement = waiter_up(&mut manager, WAITER, 22);
    manager.handle_update(RibUpdate::PeerDown {
        peer: replacement.peer,
        session_id: 22,
    });
    drop(replacement);
    assert!(!manager.selection_deferred(L4), "{case}");
    assert!(manager.selection_convergence_held(L4), "{case}");

    let late = receiver(1);
    receivers.push(Receiver {
        peer: late,
        rx: up(&mut manager, late, 0, 4096, &[V4, L4], 0),
        wire: Wire::default(),
    });
    assert!(manager.eor.owes(late, L4), "{case}");
    model.send(&mut manager, &[(90_001, 501)], &[7]);
    if release.rearmed() {
        receivers.push(waiter_up(&mut manager, WAITER2, 33));
        assert!(manager.selection_deferred(L4), "{case}");
        if state == State::Dirty {
            operator_refresh(&mut manager, receivers[0].peer);
            receivers[0].write();
            assert!(receivers[0].wire.holds(5), "{case}: labeled still held");
        }
        model.send(&mut manager, &[(90_002, 502), (90_000, 502)], &[]);
    }
    plain_rows(&mut manager, PLAIN..PLAIN + 1);
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    if release.rearmed() && state == State::Evicted {
        for _ in 0..4 {
            tick(&mut manager, &mut receivers);
        }
        assert_eq!(
            manager.adj_rib_out_commit_stats.resync_builds, builds,
            "{case}: no unit inside the re-armed hold"
        );
    }
    release.finish(&mut manager, &mut model);
    drain(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);

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
        if i == 0 || receiver.peer == late {
            assert_eq!(
                receiver.wire.unicast_table,
                plain_table(PLAIN + 1),
                "{case}"
            );
        }
        assert!(!manager.eor.owes(receiver.peer, L4), "{case}");
    }
    assert_idle(&manager, &receivers, &case);
}

#[test]
fn a_collision_release_or_rearmed_labeled_hold_settles_a_receiver_in_any_state() {
    for state in State::ALL {
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

/// Three stalled group members evicted by the labeled list cap; receiver 0
/// keeps up. Returns the model.
fn evict_members(manager: RibManager) -> (RibManager, Vec<Receiver>, Model) {
    let (mut manager, mut receivers) = owing(manager, &[V4, L4], 4, 8, 4096);
    let mut model = Model(all(8).into_iter().collect());
    plain_rows(&mut manager, 0..PLAIN);
    for receiver in &mut receivers {
        receiver.write();
        assert!(manager.grouped_member_of(receiver.peer).is_some());
    }
    for round in 0..400u32 {
        let base = 1000 + round * 64;
        let fresh: Vec<_> = (base..base + 64).map(|index| (index, 100)).collect();
        let gone: Vec<_> = (base - 64..base).filter(|_| round != 0).collect();
        model.send(&mut manager, &fresh, &gone);
        if receivers[1..]
            .iter()
            .all(|r| manager.owed_row_evicted.contains(&r.peer))
        {
            return (manager, receivers, model);
        }
        for _ in 0..12 {
            manager.resync_dirty_peers_bounded();
            receivers[0].write();
        }
    }
    panic!("never evicted");
}

/// A stalled, dirty, evicted member is refused its unit on every tick and
/// keeps no other evicted member waiting behind it.
#[test]
fn a_stalled_evicted_labeled_member_blocks_no_other_members_unit() {
    let (mut manager, mut receivers, model) = evict_members(grouped(CREDIT, &[]));
    manager.flush_poll_budget = Duration::from_secs(3600);
    let stuck = receivers[1].peer;
    receivers[1].stall(&manager);
    // Its group's unicast rows make the stalled member dirty: an evicted,
    // dirty receiver whose unit is refused on every tick.
    plain_rows(&mut manager, PLAIN..PLAIN + 1);
    assert!(manager.dirty_peers.contains(&stuck), "stalled and dirty");
    assert!(manager.owed_row_evicted.contains(&stuck));
    for _ in 0..500 {
        manager.resync_dirty_peers_bounded();
        for receiver in receivers.iter_mut().filter(|r| r.peer != stuck) {
            receiver.write();
        }
    }
    assert!(
        manager.owed_row_evicted.contains(&stuck),
        "the stalled one waits"
    );
    let expected = selected(&manager);
    assert_eq!(expected, model.table());
    for receiver in receivers.iter().filter(|r| r.peer != stuck) {
        assert!(
            !manager.owed_row_evicted.contains(&receiver.peer),
            "{} is blocked behind the stalled member",
            receiver.peer
        );
        assert_eq!(receiver.wire.table, expected, "{}", receiver.peer);
        assert_eq!(receiver.wire.markers[0], 1);
    }
    drain(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);
    for receiver in &receivers {
        assert_eq!(receiver.wire.table, expected, "{}", receiver.peer);
        assert_eq!(
            (receiver.wire.markers[0], receiver.wire.rows_after_marker[0]),
            (1, 0)
        );
    }
    assert_idle(&manager, &receivers, "stalled evicted");
}

/// Evicted members, then a labeled hold: no unit and no capture
/// inside the hold; a row withdrawn while they owed and one withdrawn in
/// the hold both leave after the release.
#[test]
fn no_unit_is_built_for_an_evicted_member_inside_a_labeled_hold() {
    let (mut manager, mut receivers, mut model) = evict_members(grouped(CREDIT, &[L4]));
    receivers.push(hold(&mut manager, &[L4]));
    let last = *model.0.keys().next_back().unwrap();
    model.send(&mut manager, &[(77_000, 100)], &[last]);
    let stats = manager.adj_rib_out_commit_stats;
    for _ in 0..50 {
        tick(&mut manager, &mut receivers);
    }
    let now = manager.adj_rib_out_commit_stats;
    assert_eq!(
        now.resync_builds, stats.resync_builds,
        "no unit in the hold"
    );
    assert_eq!(now.group_table_captures, stats.group_table_captures);
    for receiver in &receivers[1..4] {
        assert!(manager.owed_row_evicted.contains(&receiver.peer));
        assert!(!manager.dirty_peers.contains(&receiver.peer));
    }
    release(&mut manager, L4);
    assert_eq!(
        manager.adj_rib_out_commit_stats.resync_builds, stats.resync_builds,
        "none in the release turn"
    );
    manager.flush_poll_budget = Duration::from_secs(3600);
    for _ in 0..5000 {
        if !manager.resync_tick_pending() {
            break;
        }
        let before = manager.adj_rib_out_commit_stats;
        tick(&mut manager, &mut receivers);
        let after = manager.adj_rib_out_commit_stats;
        assert!(after.resync_builds - before.resync_builds <= 1);
        assert!(after.group_table_captures - before.group_table_captures <= 1);
    }
    let expected = selected(&manager);
    assert_eq!(expected, model.table());
    for receiver in &receivers {
        assert_eq!(receiver.wire.table, expected, "{}", receiver.peer);
        assert_eq!(
            (receiver.wire.markers[0], receiver.wire.rows_after_marker[0]),
            (1, 0),
            "{}",
            receiver.peer
        );
    }
    assert_idle(&manager, &receivers, "unit in hold");
}

/// Both labeled AFIs held; a receiver that lost an owed
/// withdrawal in each AFI resyncs dirty inside the holds; the gates release
/// apart. Each AFI's row leaves after its own release.
#[test]
fn a_dirty_receiver_in_two_labeled_holds_gets_each_afi_after_its_own_release() {
    for grouped_build in [false, true] {
        let mut manager = deferral_manager(CREDIT, &[L4, L6]);
        manager.test_force_ungrouped = !grouped_build;
        sources_up(&mut manager);
        let mut receivers = vec![Receiver::up(
            &mut manager,
            receiver(0),
            4096,
            &[V4, L4, L6],
            0,
        )];
        let peer = receivers[0].peer;
        let v6 = |rows: std::ops::Range<u32>| -> Vec<LabeledRibRoute> {
            rows.map(|index| route_from(SOURCE, L6, index, 100, 200))
                .collect()
        };
        received(&mut manager, &all(8), &[]);
        send(&mut manager, SOURCE, v6(0..8), vec![]);
        plain_rows(&mut manager, 0..2);
        drain(&mut manager, &mut receivers);
        assert_eq!(receivers[0].wire.table.len(), 16);
        // The receiver stops reading; both withdrawals are missed.
        receivers[0].stall(&manager);
        regroup(&mut manager, peer, Some(permit_all()));
        send(
            &mut manager,
            SOURCE,
            vec![],
            vec![prefix(L4, 5), prefix(L6, 5)],
        );
        assert!(manager.dirty_peers.contains(&peer));
        receivers.push(hold(&mut manager, &[L4, L6]));
        for _ in 0..20 {
            tick(&mut manager, &mut receivers);
        }
        assert!(!manager.dirty_peers.contains(&peer), "resynced in the hold");
        assert!(manager.owes_held_rebuild(peer, F4));
        assert!(manager.owes_held_rebuild(peer, F6));
        release(&mut manager, L4);
        drain(&mut manager, &mut receivers);
        tick(&mut manager, &mut receivers);
        assert!(
            !receivers[0].wire.table.contains_key(&(prefix(L4, 5), 0)),
            "grouped={grouped_build}: IPv4 row withdrawn after its release"
        );
        assert!(receivers[0].wire.table.contains_key(&(prefix(L6, 5), 0)));
        assert!(manager.owes_held_rebuild(peer, F6), "IPv6 still waits");
        assert!(!manager.dirty_peers.contains(&peer));
        release(&mut manager, L6);
        drain(&mut manager, &mut receivers);
        tick(&mut manager, &mut receivers);
        let expected = selected(&manager);
        assert_eq!(expected.len(), 14);
        for receiver in &receivers {
            assert_eq!(
                receiver.wire.table, expected,
                "grouped={grouped_build} {}",
                receiver.peer
            );
        }
        assert_eq!(receivers[1].wire.markers, [1, 1]);
        assert_eq!(receivers[1].wire.rows_after_marker, [0, 0]);
        assert_idle(&manager, &receivers, "two holds");
    }
}

/// The labeled list's cap is taken from the labeled table, not the unicast
/// one. A stalled receiver that owes the family while
/// a table larger than the slack is built in small passes is not evicted:
/// the list never holds more than the table.
#[test]
fn a_labeled_table_built_in_small_passes_evicts_nobody() {
    const ROWS: u32 = 6000;
    let (mut manager, mut receivers) = owing(manager(CREDIT), &[L4], 1, 8, 4096);
    let peer = receivers[0].peer;
    receivers[0].stall(&manager);
    let mut model = Model(all(8).into_iter().collect());
    for base in (8..ROWS).step_by(64) {
        let fresh: Vec<_> = (base..base + 64).map(|index| (index, 100)).collect();
        model.send(&mut manager, &fresh, &[]);
    }
    assert!(
        manager.owed_rows[LISTS[0]].len() > 4 * CHUNK_ROWS,
        "past the slack"
    );
    assert_eq!(fallbacks(&manager), 0.0, "nobody is evicted");
    assert!(!manager.owed_row_evicted.contains(&peer));
    assert!(manager.owes_whole(peer, F4) && !manager.dirty_peers.contains(&peer));
    drain(&mut manager, &mut receivers);
    assert_settled(&manager, &receivers, &model.table(), "small passes");
}

/// Rows no pass carried since the debt began, held by the receiver.
const STABLE: u32 = 256;

/// One stalled receiver that holds rows 0..[`STABLE`] and owes IPv4 labeled
/// whole from now on, then `passes` passes that each announce 64 fresh rows
/// and withdraw the previous 64, stopping early at the first eviction.
/// Returns the passes that ran.
fn rotate_past_a_stalled_cursor(passes: u32) -> (RibManager, Vec<Receiver>, Model, u32) {
    let mut manager = manager(CREDIT);
    sources_up(&mut manager);
    let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 4096, &[L4], 0)];
    let mut model = Model::default();
    model.send(&mut manager, &all(STABLE), &[]);
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table, model.table());
    manager.owe_eor(receivers[0].peer, L4);
    manager.owe_whole_family(receivers[0].peer, F4);
    receivers[0].stall(&manager);
    for pass in 0..passes {
        let base = 1000 + pass * 64;
        let fresh: Vec<_> = (base..base + 64).map(|index| (index, 100)).collect();
        let gone: Vec<_> = (base - 64..base).filter(|_| pass != 0).collect();
        model.send(&mut manager, &fresh, &gone);
        if fallbacks(&manager) != 0.0 {
            return (manager, receivers, model, pass + 1);
        }
    }
    (manager, receivers, model, passes)
}

/// A pass that changes no winner still logs its prefixes for the cursors,
/// so it can take a list over its cap, and it returns before the receiver
/// loop. The list is one rotation pass short of its cap; a losing path for
/// 64 rows the list does not hold then takes it over, and the stalled
/// receiver is evicted in that pass. Red when the cap is applied only
/// after the receiver loop: the list stays over its cap until some winner
/// changes.
#[test]
fn a_pass_with_no_winner_change_that_overfills_a_labeled_list_evicts_in_that_pass() {
    let (_, _, _, evicting) = rotate_past_a_stalled_cursor(400);
    assert!(evicting < 400, "the rotation never reaches the cap");
    let (mut manager, mut receivers, model, _) = rotate_past_a_stalled_cursor(evicting - 1);
    let peer = receivers[0].peer;
    assert_eq!(fallbacks(&manager), 0.0, "one pass short of the cap");
    assert!(manager.owes_whole(peer, F4));
    send(
        &mut manager,
        SECOND,
        (0..64)
            .map(|index| route_from(SECOND, L4, index, 300, 100))
            .collect(),
        vec![],
    );
    assert_eq!(selected(&manager), model.table(), "no winner changed");
    assert_eq!(
        fallbacks(&manager),
        1.0,
        "evicted in the pass that overfilled"
    );
    assert!(manager.dirty_peers.contains(&peer));
    drain(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table, model.table());
    assert_eq!(
        (
            receivers[0].wire.markers[0],
            receivers[0].wire.rows_after_marker[0]
        ),
        (1, 0)
    );
    assert_idle(&manager, &receivers, "no winner change");
}

/// The IPv6 labeled list has its own cap: fresh IPv6 rows rotating past a
/// stalled receiver that owes the family whole evict it, and its resync
/// leaves the exact table. Red when only the IPv4 list is capped: the
/// IPv6 list grows with every pass.
#[test]
fn an_ipv6_labeled_list_past_its_cap_evicts_the_stalled_receiver() {
    let mut manager = manager(CREDIT);
    sources_up(&mut manager);
    let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 4096, &[L6], 0)];
    let peer = receivers[0].peer;
    manager.owe_whole_family(peer, F6);
    receivers[0].stall(&manager);
    for pass in 0..400u32 {
        let base = 1000 + pass * 64;
        send(
            &mut manager,
            SOURCE,
            (base..base + 64)
                .map(|index| route_from(SOURCE, L6, index, 100, 200))
                .collect(),
            (base - 64..base)
                .filter(|_| pass != 0)
                .map(|index| prefix(L6, index))
                .collect(),
        );
        if fallbacks(&manager) != 0.0 {
            break;
        }
    }
    assert_eq!(fallbacks(&manager), 1.0, "evicted at the IPv6 list's cap");
    assert!(manager.dirty_peers.contains(&peer));
    assert_eq!(manager.owed_rows[LISTS[0]].len(), 0, "IPv4 list untouched");
    drain(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);
    let expected = selected(&manager);
    assert_eq!(expected.len(), 64);
    assert_eq!(receivers[0].wire.table, expected);
    assert_idle(&manager, &receivers, "IPv6 cap");
}

/// A receiver that waits for a held rebuild has no live cursor, also once
/// the release has owed it the family whole: its position holds no list
/// entry. Its session is stalled, so its unit is refused on every tick;
/// when the other receiver has caught up the list is freed. Red when the
/// waiting receiver's position still counts as a cursor: the released
/// inventory stays in the list for as long as the receiver is stalled.
#[test]
fn a_stalled_receiver_awaiting_a_held_rebuild_keeps_no_list_entries() {
    let mut manager = deferral_manager(CREDIT, &[L4]);
    sources_up(&mut manager);
    let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 16, &[V4, L4], 0)];
    let peer = receivers[0].peer;
    let mut model = Model::default();
    model.send(&mut manager, &all(8), &[]);
    plain_rows(&mut manager, 0..2);
    drain(&mut manager, &mut receivers);
    prepare(&mut manager, &mut model, &receivers[0], State::Dirty);
    receivers.push(hold(&mut manager, &[L4]));
    for _ in 0..4 {
        tick(&mut manager, &mut receivers);
    }
    assert!(manager.owes_held_rebuild(peer, F4), "resynced in the hold");
    receivers[0].stall(&manager);
    release(&mut manager, L4);
    assert!(
        manager.owes_whole(peer, F4),
        "the release owes it the family"
    );
    assert_ne!(manager.owed_rows[LISTS[0]].len(), 0, "inventory logged");
    for _ in 0..20 {
        manager.resync_dirty_peers_bounded();
        receivers[1].write();
    }
    assert!(manager.owes_held_rebuild(peer, F4), "its unit is refused");
    assert!(receivers[0].wire.holds(5), "and nothing reached it");
    assert_eq!(
        receivers[1].wire.table,
        model.table(),
        "the reader caught up"
    );
    assert_eq!(
        manager.owed_rows[LISTS[0]].len(),
        0,
        "a dead position holds no entries"
    );
    drain(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);
    for receiver in &receivers {
        assert_eq!(receiver.wire.table, model.table(), "{}", receiver.peer);
    }
    assert_idle(&manager, &receivers, "stalled held rebuild");
}
