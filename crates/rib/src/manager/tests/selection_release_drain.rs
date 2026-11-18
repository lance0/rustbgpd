//! An RFC 4724 selection release owes the released family to every receiver
//! that holds it in its own Adj-RIB-Out. The release turn stages nothing
//! toward them; the resync tick's owed-key drain sends each its table and
//! then its End-of-RIB.

use std::collections::BTreeSet;

use super::selection_deferral_dirty_rtbh::{connect, manager_with_dormant_waiter};
use super::*;
use crate::update::OutboundRouteUpdate;

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const WAITER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 83);
const SOURCE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);

fn row(index: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(10, 20, index, 0), 24)
}

fn receiver(index: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 9, 0, index + 1)
}

/// The source announces `announce` (row, local preference) and withdraws
/// `withdraw`.
fn receive(manager: &mut RibManager, announce: &[(u8, u32)], withdraw: &[u8]) {
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 0,
        announced: announce
            .iter()
            .map(|&(index, preference)| make_route_with_lp(row(index), SOURCE, preference))
            .collect(),
        withdrawn: withdraw
            .iter()
            .map(|&index| (Prefix::V4(row(index)), 0))
            .collect(),
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(manager);
}

/// What one receiver's session has written.
#[derive(Default)]
struct Wire {
    table: BTreeSet<Prefix>,
    announced: Vec<Prefix>,
    withdrawn: Vec<Prefix>,
    markers: usize,
}

impl Wire {
    /// Write everything queued on `rx`: no route may follow the End-of-RIB
    /// of the initial table.
    fn write(&mut self, rx: &mut mpsc::Receiver<OutboundRouteUpdate>, initial: bool) {
        while let Ok(update) = rx.try_recv().map(delivered) {
            for (prefix, _) in update.unicast_withdrawals() {
                self.table.remove(prefix);
                self.withdrawn.push(*prefix);
            }
            for route in update.announce.iter() {
                assert!(
                    !initial || self.markers == 0,
                    "a route followed the End-of-RIB"
                );
                self.table.insert(route.prefix);
                self.announced.push(route.prefix);
            }
            self.markers += update
                .end_of_rib
                .iter()
                .filter(|family| **family == FAMILY)
                .count();
        }
    }
}

type Receivers = Vec<(PeerId, mpsc::Receiver<OutboundRouteUpdate>)>;

/// A manager inside its selection hold with rows 0..`rows` received from
/// the source, and `receivers` private receivers that joined under the
/// hold and were sent nothing.
fn held(receivers: u8, rows: u8) -> (RibManager, Receivers) {
    let mut manager = manager_with_dormant_waiter();
    std::mem::forget(connect(&mut manager, WAITER, 64, true, false));
    assert!(manager.selection_deferred(FAMILY));
    register_test_peer(&mut manager, peer_v4(SOURCE), 0);
    let table: Vec<_> = (0..rows).map(|index| (index, 100)).collect();
    receive(&mut manager, &table, &[]);
    assert_eq!(manager.loc_rib.len(), 0, "selection is deferred");
    let receivers = (0..receivers)
        .map(|index| {
            let mut rx = connect(&mut manager, receiver(index), 64, false, true);
            let peer = peer_v4(receiver(index));
            assert!(manager.grouped_member_of(peer).is_none(), "private");
            assert!(rx.try_recv().is_err(), "the hold withholds the table");
            (peer, rx)
        })
        .collect();
    (manager, receivers)
}

fn release(manager: &mut RibManager, by_timer: bool) {
    if by_timer {
        manager.expire_selection_deferral();
    } else {
        manager.handle_update(RibUpdate::EndOfRib {
            peer: peer_v4(WAITER),
            session_id: u64::from(WAITER.octets()[3]),
            afi: FAMILY.0,
            safi: FAMILY.1,
        });
    }
    drain_unicast_release(manager);
    assert!(!manager.selection_convergence_held(FAMILY));
}

/// Run resync ticks, each session writing what it was sent, until no
/// resync work is left.
fn drain(manager: &mut RibManager, receivers: &mut Receivers, wires: &mut [Wire]) {
    for _ in 0..4 * receivers.len() + 8 {
        manager.resync_dirty_peers_bounded();
        for ((_, rx), wire) in receivers.iter_mut().zip(wires.iter_mut()) {
            wire.write(rx, true);
        }
    }
    assert!(!manager.resync_tick_pending());
}

/// After the global gate opens, an intervening grace expiry or teardown can
/// retire helper state. Peers awaiting a marker visit still need theirs.
#[test]
fn helper_ledger_survives_until_its_release_marker_visit() {
    let (mut manager, receivers) = held(70, 1);
    manager.expire_selection_deferral();
    while manager.selection_convergence_held(FAMILY) {
        assert!(manager.unicast_release_runnable());
        manager.advance_unicast_release();
    }
    let peer = receivers
        .iter()
        .map(|(peer, _)| *peer)
        .find(|&peer| manager.release_marker_pending(peer, FAMILY))
        .expect("a later marker page");
    assert!(manager.helper_stale_may_hold(peer));
    let owner = super::super::HoldWithdrawOwner::Peer(peer);
    let bound = crate::outbound_credit::CHUNK_ROWS;
    let rows = 3 * bound;
    let keys = (0..u32::try_from(rows).unwrap())
        .map(|index| (Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(index), 32)), 0));
    manager.record_hold_exempt_withdrawn(owner, keys, "helper_stale_exempt");
    manager.request_helper_stale_retire();
    assert_eq!(manager.hold_exempt_withdrawn[&owner].len(), rows);
    let mut remaining = rows;
    while manager.unicast_release_runnable() {
        manager.advance_unicast_release();
        let next = manager
            .hold_exempt_withdrawn
            .get(&owner)
            .map_or(0, BTreeSet::len);
        assert!(remaining - next <= bound, "one cleanup page");
        remaining = next;
    }
    assert!(!manager.helper_stale_may_hold(peer));
    assert_eq!(remaining, 0);
}

fn wires(receivers: &Receivers) -> Vec<Wire> {
    receivers.iter().map(|_| Wire::default()).collect()
}

fn rows(indexes: &[u8]) -> BTreeSet<Prefix> {
    indexes
        .iter()
        .map(|&index| Prefix::V4(row(index)))
        .collect()
}

/// The release turn stages nothing toward a private receiver, at 8 and at
/// 32 receivers, whether the waiter's End-of-RIB or the timer releases the
/// hold; the ticks after it deliver each receiver its table and then one
/// End-of-RIB. Red without the release owing the family: the receivers are
/// sent nothing at all.
#[test]
fn release_turn_stages_nothing_toward_private_receivers() {
    for count in [8, 32] {
        for by_timer in [false, true] {
            let case = format!("{count} receivers, by timer {by_timer}");
            let (mut manager, mut receivers) = held(count, 3);
            let before: Vec<_> = receivers
                .iter()
                .map(|(peer, _)| manager.outbound_stagings(*peer))
                .collect();
            release(&mut manager, by_timer);
            assert_eq!(manager.loc_rib.len(), 3, "{case}");
            for ((peer, rx), before) in receivers.iter_mut().zip(before) {
                assert_eq!(manager.outbound_stagings(*peer), before, "{case}");
                assert!(manager.owes(*peer, FAMILY), "{case}");
                assert!(!manager.dirty_peers.contains(peer), "{case}");
                assert!(
                    rx.try_recv().is_err(),
                    "{case}: nothing in the release turn"
                );
            }
            let mut wires = wires(&receivers);
            drain(&mut manager, &mut receivers, &mut wires);
            for ((peer, _), wire) in receivers.iter().zip(&wires) {
                assert_eq!(wire.table, rows(&[0, 1, 2]), "{case}");
                assert_eq!(wire.announced.len(), 3, "{case}: each row once");
                assert_eq!(wire.markers, 1, "{case}");
                assert!(!manager.owes(*peer, FAMILY), "{case}");
                assert!(!manager.dirty_peers.contains(peer), "{case}");
            }
        }
    }
}

/// Routes that change between the release and a receiver's drain step are
/// sent once, in their newest version: a row withdrawn before the step is
/// never announced, and a receiver already drained gets the change at once.
#[test]
fn changes_during_the_drain_reach_each_receiver_once() {
    let (mut manager, mut receivers) = held(2, 3);
    // One receiver per tick.
    manager.flush_poll_budget = Duration::ZERO;
    release(&mut manager, false);
    let mut wires = wires(&receivers);
    // Before any step: row 1 changes, row 2 goes, row 4 arrives.
    receive(&mut manager, &[(1, 200), (4, 100)], &[2]);
    for ((_, rx), wire) in receivers.iter_mut().zip(&mut wires) {
        wire.write(rx, true);
        assert!(wire.announced.is_empty(), "an owed family stages nothing");
    }
    manager.resync_dirty_peers_bounded();
    for ((_, rx), wire) in receivers.iter_mut().zip(&mut wires) {
        wire.write(rx, true);
    }
    let drained: Vec<_> = receivers
        .iter()
        .map(|(peer, _)| !manager.owes(*peer, FAMILY))
        .collect();
    assert_eq!(
        drained.iter().filter(|drained| **drained).count(),
        1,
        "one receiver per tick"
    );
    // Between the steps: row 0 goes.
    receive(&mut manager, &[], &[0]);
    for (((_, rx), wire), drained) in receivers.iter_mut().zip(&mut wires).zip(&drained) {
        wire.write(rx, false);
        assert_eq!(
            wire.withdrawn,
            if *drained {
                vec![Prefix::V4(row(0))]
            } else {
                vec![]
            },
            "only the drained receiver holds the row"
        );
    }
    for _ in 0..4 {
        manager.resync_dirty_peers_bounded();
        for ((_, rx), wire) in receivers.iter_mut().zip(&mut wires) {
            wire.write(rx, false);
        }
    }
    for (((peer, _), wire), drained) in receivers.iter().zip(&wires).zip(&drained) {
        assert_eq!(wire.table, rows(&[1, 4]));
        assert_eq!(wire.markers, 1);
        assert_eq!(
            wire.announced.len(),
            if *drained { 3 } else { 2 },
            "no row is announced twice, and a withdrawn row is not announced"
        );
        assert!(!wire.announced.contains(&Prefix::V4(row(2))));
        assert!(!manager.owes(*peer, FAMILY));
    }
}

/// A receiver whose session ends before its drain step owes nothing any
/// more; its next session takes an ordinary initial table and End-of-RIB.
#[test]
fn a_receiver_that_flaps_before_its_step_starts_over() {
    let (mut manager, mut receivers) = held(2, 3);
    release(&mut manager, false);
    let (peer, _) = receivers[0];
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: u64::from(receiver(0).octets()[3]),
    });
    assert!(
        manager.owing(peer).is_none(),
        "the debt ends with the session"
    );
    receivers[0].1 = connect(&mut manager, receiver(0), 64, false, true);
    let mut wires = wires(&receivers);
    drain(&mut manager, &mut receivers, &mut wires);
    for wire in &wires {
        assert_eq!(wire.table, rows(&[0, 1, 2]));
        assert_eq!(wire.announced.len(), 3);
        assert_eq!(wire.markers, 1);
    }
}

/// A receiver marked dirty before its drain step is covered by its resync:
/// the table once, then the End-of-RIB, and no debt is left.
#[test]
fn a_receiver_marked_dirty_before_its_step_is_resynced_once() {
    let (mut manager, mut receivers) = held(2, 3);
    release(&mut manager, false);
    let (peer, _) = receivers[0];
    manager.mark_outbound_dirty(peer);
    let mut wires = wires(&receivers);
    drain(&mut manager, &mut receivers, &mut wires);
    for wire in &wires {
        assert_eq!(wire.table, rows(&[0, 1, 2]));
        assert_eq!(wire.announced.len(), 3);
        assert_eq!(wire.markers, 1);
    }
    assert!(!manager.dirty_peers.contains(&peer));
    assert!(manager.owing(peer).is_none());
}

/// A receiver's ROUTE-REFRESH for a family the release still owes it,
/// whether it arrives under the hold (and is answered at the release) or
/// after the release and before the receiver's drain step. RFC 4724 has the
/// End-of-RIB follow the table, RFC 7313 section 4 forbids a `BoRR` before
/// that End-of-RIB and has the refreshed table sit between `BoRR` and
/// `EoRR`, so the receiver gets the owed table, its End-of-RIB, and then the
/// answer with both markers; the drain has nothing left to send it.
#[test]
fn a_refresh_of_an_owed_family_follows_the_table_and_its_end_of_rib() {
    use rustbgpd_wire::RouteRefreshSubtype::{BoRR, EoRR};
    for under_hold in [true, false] {
        let (mut manager, mut receivers) = held(2, 3);
        let (peer, _) = receivers[0];
        let refresh = RibUpdate::RouteRefreshRequest {
            queued: Arc::default(),
            peer,
            session_id: u64::from(receiver(0).octets()[3]),
            afi: FAMILY.0,
            safi: FAMILY.1,
        };
        if under_hold {
            manager.handle_update(refresh);
            assert!(receivers[0].1.try_recv().is_err(), "deferred by the hold");
            release(&mut manager, false);
            manager.retry_deferred_refreshes(std::time::Instant::now());
        } else {
            release(&mut manager, false);
            assert!(receivers[0].1.try_recv().is_err(), "owed, not sent");
            manager.handle_update(refresh);
        }
        let transcript: Vec<_> = std::iter::from_fn(|| receivers[0].1.try_recv().ok())
            .map(delivered)
            .map(|update| {
                assert_eq!(update.unicast_withdrawals().count(), 0);
                (
                    update.announce.iter().count(),
                    update.end_of_rib.clone(),
                    update
                        .refresh_markers
                        .iter()
                        .map(|&(_, _, subtype)| subtype)
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        // The answer to a refresh that waited under the hold carries no
        // End-of-RIB entry of its own; one answered later does, for a
        // receiver without enhanced refresh (the session sends an enhanced
        // one the two markers instead).
        let answer_end_of_rib = if under_hold { vec![] } else { vec![FAMILY] };
        assert_eq!(
            transcript,
            vec![
                (3, vec![], vec![]),
                (0, vec![FAMILY], vec![]),
                (3, answer_end_of_rib, vec![BoRR, EoRR]),
            ],
            "under hold {under_hold}"
        );
        assert!(!manager.owes(peer, FAMILY), "under hold {under_hold}");
        let mut wires = wires(&receivers);
        drain(&mut manager, &mut receivers, &mut wires);
        assert!(
            wires[0].announced.is_empty() && wires[0].markers == 0,
            "under hold {under_hold}: the drain repeats nothing"
        );
        assert_eq!(wires[1].announced.len(), 3);
        assert_eq!(wires[1].markers, 1);
    }
}

/// Receivers whose export chains differ are grouped one per group, not
/// private: the release serves them from their group tables in its own
/// turn and owes them nothing.
#[test]
fn single_member_groups_are_served_in_the_release_turn() {
    let (mut manager, _private) = held(0, 3);
    let mut receivers: Receivers = (0..2u8)
        .map(|index| {
            let peer = peer_v4(receiver(index));
            let (tx, rx) = mpsc::channel(64);
            let mut up = super::lifecycle::test_peer_up(peer, u64::from(index) + 1, tx);
            if let RibUpdate::PeerUp {
                sendable_families,
                export_policy,
                ..
            } = &mut up
            {
                *sendable_families = vec![FAMILY];
                *export_policy = Some(deny_prefixes_chain(&[Prefix::V4(Ipv4Prefix::new(
                    Ipv4Addr::new(192, 0, 2, index),
                    32,
                ))]));
            }
            manager.handle_update(up);
            (peer, rx)
        })
        .collect();
    let groups: Vec<_> = receivers
        .iter()
        .map(|(peer, _)| manager.grouped_member_of(*peer).expect("grouped"))
        .collect();
    assert_ne!(groups[0], groups[1], "one group per export chain");
    release(&mut manager, false);
    for (peer, rx) in &mut receivers {
        assert!(!manager.owes(*peer, FAMILY));
        let mut wire = Wire::default();
        wire.write(rx, true);
        assert_eq!(wire.table, rows(&[0, 1, 2]));
        assert_eq!(wire.markers, 1);
    }
}

/// With one receiver's credit spent, the ticks after the release serve the
/// receiver beside it and stage nothing toward the stalled one: its family
/// and its End-of-RIB stay owed, and it is not marked dirty. Red without
/// the credit read ahead of a waiting End-of-RIB's absorption in the drain
/// step, which stages the stalled receiver's family past its credit.
#[test]
fn a_stalled_receiver_holds_only_its_own_table_and_end_of_rib() {
    let (mut manager, mut receivers) = held(2, 3);
    let (stalled, healthy) = (receivers[0].0, receivers[1].0);
    let charge = crate::OutboundCharge::new(
        &manager.outbound_credit_handle(stalled),
        manager.outbound_row_credit(),
    );
    release(&mut manager, false);
    let mut wires = wires(&receivers);
    for _ in 0..4 {
        manager.resync_dirty_peers_bounded();
        for ((_, rx), wire) in receivers.iter_mut().zip(&mut wires) {
            wire.write(rx, true);
        }
    }
    assert_eq!(wires[1].table, rows(&[0, 1, 2]));
    assert_eq!(wires[1].markers, 1);
    assert!(!manager.owes(healthy, FAMILY));
    assert!(
        wires[0].announced.is_empty() && wires[0].markers == 0,
        "the stalled receiver was staged past its credit"
    );
    assert!(manager.owes(stalled, FAMILY));
    assert!(manager.eor_pending(stalled).contains(&FAMILY));
    assert!(!manager.dirty_peers.contains(&stalled));
    drop(charge);
    drain(&mut manager, &mut receivers, &mut wires);
    assert_eq!(wires[0].table, rows(&[0, 1, 2]));
    assert_eq!(wires[0].announced.len(), 3);
    assert_eq!(wires[0].markers, 1);
}

/// A receiver that is dirty at the release is left to its resync: the
/// release records no debt for it, here with the resync refused by a full
/// channel.
#[test]
fn a_dirty_receiver_is_not_owed_the_released_family() {
    let mut manager = manager_with_dormant_waiter();
    std::mem::forget(connect(&mut manager, WAITER, 64, true, false));
    register_test_peer(&mut manager, peer_v4(SOURCE), 0);
    receive(&mut manager, &[(0, 100), (1, 100), (2, 100)], &[]);
    let mut rx = connect(&mut manager, receiver(0), 1, false, true);
    let peer = peer_v4(receiver(0));
    assert!(manager.grouped_member_of(peer).is_none(), "private");
    manager.outbound_peers[&peer]
        .try_send(OutboundRouteUpdate::default())
        .expect("room for one envelope");
    manager.mark_outbound_dirty(peer);
    release(&mut manager, false);
    assert!(
        manager.dirty_peers.contains(&peer),
        "the resync was refused"
    );
    assert!(
        manager.owing(peer).is_none(),
        "its resync covers the family"
    );
    let mut wire = Wire::default();
    for _ in 0..8 {
        wire.write(&mut rx, true);
        manager.resync_dirty_peers_bounded();
    }
    wire.write(&mut rx, true);
    assert_eq!(wire.table, rows(&[0, 1, 2]));
    assert_eq!(wire.announced.len(), 3);
    assert_eq!(wire.markers, 1);
    assert!(!manager.dirty_peers.contains(&peer));
}

/// The release turn's work toward private receivers does not grow with
/// receivers times rows: going from 8 to 32 receivers adds the same number
/// of readiness checkpoints at 50 rows as at 200, and fewer per receiver
/// than there are rows. Red when the release pass visits the released
/// prefixes once per receiver that owes the family whole.
#[test]
fn release_turn_work_per_private_receiver_does_not_grow_with_rows() {
    use crate::manager::slice_timing::checkpoints;
    let work = |rows: u16, count: u8| {
        let mut manager = manager_with_dormant_waiter();
        std::mem::forget(connect(&mut manager, WAITER, 64, true, false));
        register_test_peer(&mut manager, peer_v4(SOURCE), 0);
        manager.handle_update(RibUpdate::RoutesReceived {
            peer: peer_v4(SOURCE),
            session_id: 0,
            announced: (0..rows)
                .map(|index| {
                    let [high, low] = index.to_be_bytes();
                    make_route_with_lp(
                        Ipv4Prefix::new(Ipv4Addr::new(10, 20 + high, low, 0), 24),
                        SOURCE,
                        100,
                    )
                })
                .collect(),
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        });
        drain_route_chunks(&mut manager);
        let receivers: Vec<_> = (0..count)
            .map(|index| connect(&mut manager, receiver(index), 4096, false, true))
            .collect();
        let before: usize = checkpoints().values().sum();
        release(&mut manager, false);
        let after: usize = checkpoints().values().sum();
        assert_eq!(manager.loc_rib.len(), usize::from(rows));
        for index in 0..count {
            assert!(manager.owes(peer_v4(receiver(index)), FAMILY));
        }
        drop(receivers);
        after - before
    };
    let added = |rows| work(rows, 32) - work(rows, 8);
    let (small, large) = (added(50), added(200));
    assert_eq!(
        small, large,
        "24 more receivers cost the same at 50 rows and at 200"
    );
    assert!(large / 24 < 50, "{} checkpoints per receiver", large / 24);
}

/// The same bound for an IPv4 `FlowSpec` release toward receivers that
/// negotiated all four `FlowSpec` families: 24 more receivers cost the same
/// at 50 rules as at 200. Red when the release pass reads the changed rules
/// once per receiver to find the families it carries.
#[test]
fn flowspec_release_turn_work_per_receiver_does_not_grow_with_rules() {
    use crate::manager::slice_timing::checkpoints;
    let families = [
        FLOWSPEC,
        (Afi::Ipv6, Safi::FlowSpec),
        (Afi::Ipv4, Safi::FlowSpecVpn),
        (Afi::Ipv6, Safi::FlowSpecVpn),
    ];
    let work = |rules: u8, count: u8| {
        let waiter = peer_v4(WAITER);
        let (_tx, rx) = mpsc::channel(8);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
            .with_selection_deferral(crate::SelectionDeferralConfig {
                timeout: Duration::from_mins(2),
                waiters: vec![crate::SelectionDeferralWaiterConfig {
                    peer: waiter.into(),
                    families: vec![FLOWSPEC],
                }],
            });
        super::arm_selection_waiter(&mut manager, waiter, &[FLOWSPEC]);
        let up = |manager: &mut RibManager, peer: PeerId, session_id: u64| {
            let (tx, rx) = mpsc::channel(4096);
            let mut up = super::lifecycle::test_peer_up(peer, session_id, tx);
            if let RibUpdate::PeerUp {
                sendable_families, ..
            } = &mut up
            {
                *sendable_families = families.to_vec();
            }
            manager.handle_update(up);
            rx
        };
        std::mem::forget(up(&mut manager, peer_v4(SOURCE), 0));
        manager.handle_update(RibUpdate::RoutesReceived {
            peer: peer_v4(SOURCE),
            session_id: 0,
            announced: vec![],
            withdrawn: vec![],
            flowspec_announced: (0..rules)
                .map(|index| {
                    let mut rule = crate::test_support::make_flowspec_route(SOURCE);
                    rule.rule.components =
                        vec![rustbgpd_wire::FlowSpecComponent::DestinationPrefix(
                            rustbgpd_wire::FlowSpecPrefix::V4(Ipv4Prefix::new(
                                Ipv4Addr::new(198, 18, index, 0),
                                24,
                            )),
                        )];
                    rule
                })
                .collect(),
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        });
        drain_route_chunks(&mut manager);
        assert_eq!(manager.loc_rib.flowspec_len(), 0, "selection is deferred");
        let receivers: Vec<_> = (0..count)
            .map(|index| up(&mut manager, peer_v4(receiver(index)), u64::from(index) + 1))
            .collect();
        let before: usize = checkpoints().values().sum();
        manager.expire_selection_deferral();
        let after: usize = checkpoints().values().sum();
        assert_eq!(manager.loc_rib.flowspec_len(), usize::from(rules));
        for index in 0..count {
            assert!(manager.owes(peer_v4(receiver(index)), FLOWSPEC));
        }
        drop(receivers);
        after - before
    };
    let added = |rules| work(rules, 32) - work(rules, 8);
    let (small, large) = (added(50), added(200));
    assert_eq!(
        small, large,
        "24 more receivers cost the same at 50 rules and at 200"
    );
    assert!(large / 24 < 50, "{} checkpoints per receiver", large / 24);
}

const FLOWSPEC: (Afi, Safi) = (Afi::Ipv4, Safi::FlowSpec);

/// Eight receivers that are update-group members for IPv4 unicast and hold
/// `FlowSpec` in their own Adj-RIB-Out, joined under a hold on both families
/// with 3 unicast rows and 5 `FlowSpec` rules received.
fn mixed() -> (RibManager, Receivers) {
    let waiter = peer_v4(Ipv4Addr::new(192, 0, 2, 1));
    let families = [FLOWSPEC, FAMILY];
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(crate::SelectionDeferralConfig {
            timeout: Duration::from_mins(2),
            waiters: vec![crate::SelectionDeferralWaiterConfig {
                peer: waiter.into(),
                families: families.to_vec(),
            }],
        });
    super::arm_selection_waiter(&mut manager, waiter, &families);
    let up = |manager: &mut RibManager, peer: PeerId, session_id: u64| {
        let (tx, rx) = mpsc::channel(256);
        let mut up = super::lifecycle::test_peer_up(peer, session_id, tx);
        if let RibUpdate::PeerUp {
            sendable_families, ..
        } = &mut up
        {
            *sendable_families = families.to_vec();
        }
        manager.handle_update(up);
        rx
    };
    std::mem::forget(up(&mut manager, peer_v4(SOURCE), 0));
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 0,
        announced: (0..3)
            .map(|index| make_route_with_lp(row(index), SOURCE, 100))
            .collect(),
        withdrawn: vec![],
        flowspec_announced: (0..5)
            .map(|index| {
                let mut rule = crate::test_support::make_flowspec_route(SOURCE);
                rule.rule.components = vec![rustbgpd_wire::FlowSpecComponent::DestinationPrefix(
                    rustbgpd_wire::FlowSpecPrefix::V4(Ipv4Prefix::new(
                        Ipv4Addr::new(198, 18, index, 0),
                        24,
                    )),
                )];
                rule
            })
            .collect(),
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    let receivers: Receivers = (0..8u8)
        .map(|index| {
            let peer = peer_v4(receiver(index));
            let mut rx = up(&mut manager, peer, u64::from(index) + 1);
            assert!(manager.grouped_member_of(peer).is_some(), "grouped");
            assert!(rx.try_recv().is_err(), "the hold withholds both tables");
            (peer, rx)
        })
        .collect();
    (manager, receivers)
}

/// One RIB turn in which the deferral timer releases `families`, in this
/// order: `expire_selection_deferral` with the order of its transitions
/// fixed (the timer takes them in the gate map's iteration order).
fn timer_releases(manager: &mut RibManager, families: &[(Afi, Safi)]) {
    use crate::manager::selection_deferral::SelectionDeferralTransition::{Release, Stage};
    let order = |transition: &_| match transition {
        Release { family, .. } => families.iter().position(|released| released == family),
        Stage { .. } => None,
    };
    let mut transitions = manager.selection_deferral.as_ref().unwrap().expire();
    transitions.retain(|transition| order(transition).is_some());
    transitions.sort_by_key(order);
    assert_eq!(transitions.len(), families.len());
    manager.apply_selection_deferral_transitions(transitions, "Selection_Deferral_Timer expired");
    drain_unicast_release(manager);
    manager.settle_eor_after_pass();
    for &family in families {
        assert!(!manager.selection_convergence_held(family));
    }
}

/// What one mixed receiver's session has written, per family.
#[derive(Default)]
struct MixedWire {
    unicast: usize,
    unicast_markers: usize,
    flowspec: usize,
    flowspec_markers: usize,
}

impl MixedWire {
    /// Write everything queued on `rx`: no row may follow the End-of-RIB of
    /// its own family.
    fn write(&mut self, rx: &mut mpsc::Receiver<OutboundRouteUpdate>) {
        while let Ok(update) = rx.try_recv().map(delivered) {
            let unicast = update.announce.iter().count();
            assert!(unicast == 0 || self.unicast_markers == 0);
            assert!(update.flowspec_announce.is_empty() || self.flowspec_markers == 0);
            self.unicast += unicast;
            self.flowspec += update.flowspec_announce.len();
            for family in &update.end_of_rib {
                self.unicast_markers += usize::from(*family == FAMILY);
                self.flowspec_markers += usize::from(*family == FLOWSPEC);
            }
        }
    }
}

/// A receiver that is an update-group member for one released family and
/// holds another in its own Adj-RIB-Out: the group family's release sends
/// its own table and End-of-RIB and leaves the owed family to the drain,
/// whichever family releases first and whether one turn releases both (the
/// deferral timer) or two do. Red when the group family's End-of-RIB settle
/// absorbs the receiver's other owed families: every receiver's `FlowSpec`
/// table then leaves inside the unicast release turn, with no credit read.
#[test]
fn a_group_family_release_leaves_an_owed_private_family_to_the_drain() {
    let sequences: [&[&[(Afi, Safi)]]; 3] = [
        &[&[FLOWSPEC], &[FAMILY]],
        &[&[FLOWSPEC, FAMILY]],
        &[&[FAMILY, FLOWSPEC]],
    ];
    for turns in sequences {
        let (mut manager, mut receivers) = mixed();
        for families in turns {
            timer_releases(&mut manager, families);
        }
        let mut wires: Vec<_> = receivers.iter().map(|_| MixedWire::default()).collect();
        for ((peer, rx), wire) in receivers.iter_mut().zip(&mut wires) {
            wire.write(rx);
            assert_eq!(
                (wire.unicast, wire.unicast_markers),
                (3, 1),
                "{turns:?}: the group family is served in its release turn"
            );
            assert_eq!(
                (wire.flowspec, wire.flowspec_markers),
                (0, 0),
                "{turns:?}: the owed family waits for the drain"
            );
            assert!(manager.owes(*peer, FLOWSPEC), "{turns:?}");
            assert!(manager.eor_pending(*peer).contains(&FLOWSPEC), "{turns:?}");
        }
        drain_resync_ticks(&mut manager);
        for ((peer, rx), wire) in receivers.iter_mut().zip(&mut wires) {
            wire.write(rx);
            assert_eq!((wire.unicast, wire.unicast_markers), (3, 1), "{turns:?}");
            assert_eq!((wire.flowspec, wire.flowspec_markers), (5, 1), "{turns:?}");
            assert!(!manager.owes(*peer, FLOWSPEC), "{turns:?}");
            assert!(!manager.dirty_peers.contains(peer), "{turns:?}");
        }
    }
}
