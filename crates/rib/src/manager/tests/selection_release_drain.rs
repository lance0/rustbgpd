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

/// A receiver's ROUTE-REFRESH absorbs the owed family ahead of its answer.
/// Whether it arrives under the hold (and is answered at the release) or
/// after the release and before the receiver's drain step, the receiver
/// gets the owed rows, then the answer's table, then one End-of-RIB.
#[test]
fn a_refresh_absorbs_the_owed_family_ahead_of_its_answer() {
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
        } else {
            release(&mut manager, false);
            manager.handle_update(refresh);
        }
        let mut wires = wires(&receivers);
        wires[0].write(&mut receivers[0].1, false);
        assert_eq!(wires[0].table, rows(&[0, 1, 2]), "under hold {under_hold}");
        assert!(!manager.owes(peer, FAMILY), "under hold {under_hold}");
        drain(&mut manager, &mut receivers, &mut wires);
        assert_eq!(
            wires[0].announced.len(),
            6,
            "under hold {under_hold}: the owed rows, then the answer"
        );
        assert_eq!(wires[0].markers, 1, "under hold {under_hold}");
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
