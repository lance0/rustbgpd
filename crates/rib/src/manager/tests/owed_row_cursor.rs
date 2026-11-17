//! The unicast row cursor (ADR-0099 amendment, slice 1b): a receiver that
//! owes a unicast family whole reads a shared list of the keys passes
//! carried since its debt began, in bounded steps charged against its
//! outbound credit, and its End-of-RIB leaves when it has caught up.

use std::collections::BTreeMap;

use super::super::eor_hold::{EorHold, EorTrigger};
use super::super::outbound_owing::OwedFamily;
use super::*;
use crate::outbound_credit::CHUNK_ROWS;

const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const V4: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const UNICAST: OwedFamily = OwedFamily::IPV4_UNICAST;
/// Rows of outbound credit: a step with the whole credit free takes
/// `CREDIT / 2` keys (a key may stage a withdrawal and an announcement).
const CREDIT: usize = 16;
const STEP: usize = CREDIT / 2;

/// A manager whose peers stay ungrouped (private unicast), one receiver
/// step per resync tick.
fn manager(credit: usize) -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 100)),
        BgpMetrics::new(),
    )
    .with_outbound_row_credit(credit);
    manager.test_force_ungrouped = true;
    manager.flush_poll_budget = Duration::ZERO;
    manager
}

fn up_session(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, output) = mpsc::channel(4096);
    manager.handle_update(RibUpdate::PeerUp {
        supersedes: None,
        per_client_best: false,
        interpret_rfc1997: true,
        session_id,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 200),
        outbound_tx,
        export_policy: None,
        sendable_families: vec![V4],
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    });
    output
}

fn receiver(index: u8) -> PeerId {
    peer_v4(Ipv4Addr::new(10, 0, 9, index + 1))
}

fn route(index: u32, variant: u32) -> Route {
    let mut route = make_indexed_route(index + 1, SOURCE);
    route.peer = peer_v4(SOURCE);
    route.attributes = AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::LocalPref(100),
        PathAttribute::Med(variant),
    ]);
    route
}

fn key(index: u32) -> Prefix {
    route(index, 0).prefix
}

/// The source announces `announce` (row, variant) and withdraws `withdraw`.
fn received(manager: &mut RibManager, announce: &[(u32, u32)], withdraw: &[u32]) {
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: announce
            .iter()
            .map(|&(index, variant)| route(index, variant))
            .collect(),
        withdrawn: withdraw.iter().map(|&index| (key(index), 0)).collect(),
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
    /// Each row held, with its attributes.
    table: BTreeMap<Prefix, String>,
    announced: Vec<Prefix>,
    withdrawn: Vec<Prefix>,
    markers: usize,
    /// Route rows written after the first End-of-RIB.
    rows_after_marker: usize,
    /// Route-bearing envelopes that held no credit, or an operation latch.
    uncharged: usize,
    latched: usize,
    /// Most rows one envelope carried.
    envelope_rows_max: usize,
}

impl Wire {
    /// Write everything queued on `rx`; the envelopes drop, which returns
    /// their credit.
    fn write(&mut self, rx: &mut mpsc::Receiver<OutboundRouteUpdate>) {
        while let Ok(update) = rx.try_recv() {
            let rows = update.announce.len() + update.unicast_withdrawals().count();
            if rows != 0 {
                self.uncharged += usize::from(update.credit.is_none());
                self.latched += usize::from(update.latch.is_some());
                self.envelope_rows_max = self.envelope_rows_max.max(rows);
                if self.markers != 0 {
                    self.rows_after_marker += rows;
                }
            }
            for (prefix, _) in update.unicast_withdrawals() {
                assert!(
                    self.table.remove(prefix).is_some(),
                    "withdrawal of {prefix}, which the receiver does not hold"
                );
                self.withdrawn.push(*prefix);
            }
            for route in update.announce.iter() {
                self.table
                    .insert(route.prefix, format!("{:?}", route.attributes));
                self.announced.push(route.prefix);
            }
            self.markers += update
                .end_of_rib
                .iter()
                .filter(|family| **family == V4)
                .count();
        }
    }

    fn count(&self, index: u32) -> (usize, usize) {
        let prefix = key(index);
        (
            self.announced.iter().filter(|p| **p == prefix).count(),
            self.withdrawn.iter().filter(|p| **p == prefix).count(),
        )
    }
}

/// The table a receiver must end with: rows `(index, variant)`.
fn table(rows: &[(u32, u32)]) -> BTreeMap<Prefix, String> {
    rows.iter()
        .map(|&(index, variant)| {
            let route = route(index, variant);
            (route.prefix, format!("{:?}", route.attributes))
        })
        .collect()
}

struct Receiver {
    peer: PeerId,
    rx: mpsc::Receiver<OutboundRouteUpdate>,
    wire: Wire,
}

impl Receiver {
    fn write(&mut self) {
        self.wire.write(&mut self.rx);
    }
}

/// `receivers` receivers that owe their End-of-RIB and IPv4 unicast whole
/// (as a selection release leaves them), then one pass carrying rows
/// 0..`rows`: the debt every cursor starts with. Nothing was staged.
fn owing(receivers: u8, rows: u32, credit: usize) -> (RibManager, Vec<Receiver>) {
    let mut manager = manager(credit);
    std::mem::forget(up_session(&mut manager, peer_v4(SOURCE), 0));
    let mut receivers: Vec<Receiver> = (0..receivers)
        .map(|index| {
            let peer = receiver(index);
            let mut rx = up_session(&mut manager, peer, 0);
            let mut wire = Wire::default();
            wire.write(&mut rx);
            assert_eq!(wire.markers, 1, "the empty initial table's End-of-RIB");
            wire.markers = 0;
            manager.owe_eor(peer, V4);
            manager.owe_whole_family(peer, UNICAST);
            Receiver { peer, rx, wire }
        })
        .collect();
    let all: Vec<_> = (0..rows).map(|index| (index, 0)).collect();
    received(&mut manager, &all, &[]);
    for receiver in &mut receivers {
        receiver.write();
        assert!(receiver.wire.announced.is_empty(), "owed, not staged");
        assert!(manager.owes_whole(receiver.peer, UNICAST));
    }
    (manager, receivers)
}

/// One resync tick (one receiver step), then every session writes.
fn tick(manager: &mut RibManager, receivers: &mut [Receiver]) {
    manager.resync_dirty_peers_bounded();
    for receiver in receivers.iter_mut() {
        receiver.write();
    }
}

/// Tick until no resync work is left.
fn drain(manager: &mut RibManager, receivers: &mut [Receiver]) {
    for _ in 0..100_000 {
        if !manager.resync_tick_pending() {
            return;
        }
        tick(manager, receivers);
    }
    panic!("the drain does not finish");
}

/// Every receiver ends with exactly `rows`, one End-of-RIB after its last
/// row, nothing owed, not dirty; the shared list is freed.
fn assert_settled(manager: &RibManager, receivers: &[Receiver], rows: &[(u32, u32)], case: &str) {
    let expected = table(rows);
    for receiver in receivers {
        assert_eq!(receiver.wire.table, expected, "{case}: exact table");
        assert_eq!(receiver.wire.markers, 1, "{case}: one End-of-RIB");
        assert_eq!(receiver.wire.rows_after_marker, 0, "{case}: marker last");
        assert!(!manager.owes(receiver.peer, V4), "{case}");
        assert!(!manager.dirty_peers.contains(&receiver.peer), "{case}");
    }
    assert_eq!(manager.owed_rows[0].len(), 0, "{case}: the list is freed");
}

/// Work count (E1): a whole-family debt of N keys drains in ceil(N / B)
/// steps per receiver, none reading more than B keys, whatever N is. Red
/// with an unbounded step: one step of N keys per receiver.
#[test]
fn a_whole_family_debt_drains_in_bounded_steps() {
    for (rows, count) in [(100usize, 100u32), (37, 37), (8, 8)] {
        let (mut manager, mut receivers) = owing(3, count, CREDIT);
        let before = manager.adj_rib_out_commit_stats;
        drain(&mut manager, &mut receivers);
        let stats = manager.adj_rib_out_commit_stats;
        assert_eq!(
            stats.owed_drain_steps - before.owed_drain_steps,
            3 * rows.div_ceil(STEP),
            "{rows} rows: ceil(N / B) steps per receiver"
        );
        assert_eq!(
            stats.owed_drain_rows_read - before.owed_drain_rows_read,
            3 * rows,
            "{rows} rows: each key read once per receiver"
        );
        assert!(stats.owed_drain_step_rows_max <= STEP, "{stats:?}");
        let all: Vec<_> = (0..count).map(|index| (index, 0)).collect();
        assert_settled(&manager, &receivers, &all, "bounded steps");
        for receiver in &receivers {
            assert_eq!(receiver.wire.announced.len(), rows, "each row once");
        }
    }
}

/// The step never exceeds one 1,024-row chunk, however much credit is
/// free. Red when the step is sized by the credit alone.
#[test]
fn a_step_is_at_most_one_chunk_of_keys() {
    let rows = 2 * u32::try_from(CHUNK_ROWS).unwrap() + 5;
    let (mut manager, mut receivers) = owing(1, rows, 1 << 20);
    drain(&mut manager, &mut receivers);
    let stats = manager.adj_rib_out_commit_stats;
    assert_eq!(stats.owed_drain_step_rows_max, CHUNK_ROWS);
    assert_eq!(stats.owed_drain_steps, 3);
    assert_eq!(receivers[0].wire.envelope_rows_max, CHUNK_ROWS);
    assert_eq!(receivers[0].wire.table.len(), rows as usize);
}

/// Credit (E2, E3): every envelope of the drain is an ordinary one charged
/// against the receiver's credit, no whole-table operation is taken, and
/// a receiver that reads nothing is queued at most its credit plus one
/// step, with its End-of-RIB still owed. Red when a waiting End-of-RIB
/// absorbs the family: one uncharged operation of N rows.
#[test]
fn a_cursor_drain_is_charged_and_takes_no_operation() {
    let rows = 100;
    let (mut manager, mut receivers) = owing(2, rows, CREDIT);
    // Receiver 1 never reads.
    for _ in 0..50 {
        manager.resync_dirty_peers_bounded();
        receivers[0].write();
        for receiver in &receivers {
            assert!(!manager.outbound_operation_live(receiver.peer));
        }
    }
    let stalled = receivers[1].peer;
    assert!(
        manager.outbound_credit_rows(stalled) <= CREDIT + STEP,
        "{} rows queued toward a receiver that reads nothing",
        manager.outbound_credit_rows(stalled)
    );
    assert!(manager.owes(stalled, V4));
    assert!(manager.eor_pending(stalled).contains(&V4));
    assert!(!manager.dirty_peers.contains(&stalled));
    // The reader finished meanwhile; the stalled one finishes once it reads.
    assert!(!manager.owes(receivers[0].peer, V4));
    drain(&mut manager, &mut receivers);
    let all: Vec<_> = (0..rows).map(|index| (index, 0)).collect();
    assert_settled(&manager, &receivers, &all, "charged");
    for receiver in &receivers {
        assert_eq!(receiver.wire.uncharged, 0, "every envelope is charged");
        assert_eq!(receiver.wire.latched, 0, "no operation latch");
        assert!(receiver.wire.envelope_rows_max <= STEP);
    }
}

/// A unicast cursor is an ordinary envelope: it does not wait for the
/// receiver's live whole-table operation, and it keeps the resync tick
/// runnable without one. Red when a unicast family owed whole still needs
/// the latch: nothing is sent while the operation is live.
#[test]
fn a_cursor_does_not_wait_for_a_live_operation() {
    let (mut manager, mut receivers) = owing(1, 20, CREDIT);
    let peer = receivers[0].peer;
    let operation = manager.begin_outbound_operation(peer, 1).unwrap();
    assert!(manager.outbound_operation_live(peer));
    assert!(!manager.owing_latch_pending());
    assert!(manager.owing_runnable());
    assert!(manager.owing_tick_due());
    drain(&mut manager, &mut receivers);
    assert!(manager.outbound_operation_live(peer), "still live");
    drop(operation);
    let all: Vec<_> = (0..20).map(|index| (index, 0)).collect();
    assert_settled(&manager, &receivers, &all, "live operation");
}

/// E4: a hold release in the middle of a walk (here the grace hold and a
/// pass's deferred settle) sends no row and no marker for a family whose
/// cursor is behind. Red when the cursor is not counted as owed keys: the
/// End-of-RIB leaves ahead of the rest of the table.
#[test]
fn a_hold_release_mid_walk_keeps_the_end_of_rib_and_stages_nothing() {
    let (mut manager, mut receivers) = owing(1, 40, CREDIT);
    tick(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);
    let peer = receivers[0].peer;
    let sent = receivers[0].wire.announced.len();
    assert_eq!(sent, 2 * STEP);
    let stagings = manager.outbound_stagings(peer);
    manager.release_eor_hold(peer, EorHold::Grace, EorTrigger::Release);
    manager.defer_eor_settle(peer);
    manager.settle_eor_after_pass();
    manager.settle_free_eor(peer);
    receivers[0].write();
    assert_eq!(manager.outbound_stagings(peer), stagings, "nothing staged");
    assert_eq!(receivers[0].wire.announced.len(), sent);
    assert_eq!(
        receivers[0].wire.markers, 0,
        "the marker waits for the walk"
    );
    drain(&mut manager, &mut receivers);
    let all: Vec<_> = (0..40).map(|index| (index, 0)).collect();
    assert_settled(&manager, &receivers, &all, "hold release");
}

/// The rows the first `steps` steps of receiver 0 sent, as row indexes.
fn sent_rows(receiver: &Receiver) -> Vec<u32> {
    (0..1000)
        .filter(|&index| receiver.wire.table.contains_key(&key(index)))
        .collect()
}

/// Contract (E5): a key that changes behind the cursor is visited again;
/// one that changes ahead is visited once, at its newer state; a key
/// withdrawn mid-walk is withdrawn if the receiver holds it and never
/// announced otherwise; a key re-announced with the state the receiver
/// holds produces no event. Red when a pass toward an owing receiver does
/// not log its keys: the changes behind the cursor are lost.
#[test]
fn changes_during_the_walk_reach_the_receiver_once_at_their_newest_state() {
    let rows = 40u32;
    let (mut manager, mut receivers) = owing(1, rows, CREDIT);
    tick(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);
    let behind = sent_rows(&receivers[0]);
    assert_eq!(behind.len(), 2 * STEP);
    let ahead: Vec<u32> = (0..rows).filter(|index| !behind.contains(index)).collect();
    let (changed_behind, withdrawn_behind, same_behind) = (behind[0], behind[1], behind[2]);
    let (changed_ahead, withdrawn_ahead) = (ahead[0], ahead[1]);
    // One pass changes two rows and withdraws two; a second pair of passes
    // takes a row the receiver holds away and brings it back unchanged.
    received(
        &mut manager,
        &[(changed_behind, 7), (changed_ahead, 7)],
        &[withdrawn_behind, withdrawn_ahead],
    );
    received(&mut manager, &[], &[same_behind]);
    received(&mut manager, &[(same_behind, 0)], &[]);
    receivers[0].write();
    assert_eq!(
        receivers[0].wire.announced.len(),
        2 * STEP,
        "a pass stages nothing toward a receiver that owes the family"
    );
    drain(&mut manager, &mut receivers);
    let wire = &receivers[0].wire;
    assert_eq!(wire.count(changed_behind), (2, 0), "visited again");
    assert_eq!(wire.count(changed_ahead), (1, 0), "visited once, newest");
    assert_eq!(wire.count(withdrawn_behind), (1, 1), "withdrawn once");
    assert_eq!(wire.count(withdrawn_ahead), (0, 0), "never announced");
    assert_eq!(wire.count(same_behind), (1, 0), "same state: no event");
    let expected: Vec<_> = (0..rows)
        .filter(|index| *index != withdrawn_behind && *index != withdrawn_ahead)
        .map(|index| {
            let changed = index == changed_behind || index == changed_ahead;
            (index, if changed { 7 } else { 0 })
        })
        .collect();
    assert_settled(&manager, &receivers, &expected, "changes mid-walk");
}

/// A second owe while the cursor is behind leaves it where it is: no row
/// is skipped, whatever the pass that follows carries, and none is sent
/// twice. Red when a second owe restarts the cursor at the end of the list:
/// the rows it had not reached are never sent.
#[test]
fn a_second_owe_mid_walk_skips_and_repeats_nothing() {
    let rows = 40u32;
    let (mut manager, mut receivers) = owing(2, rows, CREDIT);
    for _ in 0..3 {
        tick(&mut manager, &mut receivers);
    }
    for receiver in &receivers {
        manager.owe_whole_family(receiver.peer, UNICAST);
    }
    // The pass that follows carries one changed row only.
    let changed = sent_rows(&receivers[0])[0];
    received(&mut manager, &[(changed, 5)], &[]);
    drain(&mut manager, &mut receivers);
    let expected: Vec<_> = (0..rows)
        .map(|index| (index, if index == changed { 5 } else { 0 }))
        .collect();
    assert_settled(&manager, &receivers, &expected, "second owe");
    assert_eq!(receivers[0].wire.count(changed), (2, 0));
    assert_eq!(
        receivers[0].wire.announced.len(),
        rows as usize + 1,
        "each row once"
    );
}

/// A flap mid-walk drops the cursor with the session: the new session's
/// initial table is complete, and the old cursor no longer pins the list.
#[test]
fn a_flap_mid_walk_drops_the_cursor() {
    let rows = 40u32;
    let (mut manager, mut receivers) = owing(1, rows, CREDIT);
    tick(&mut manager, &mut receivers);
    let peer = receivers[0].peer;
    assert_ne!(manager.owed_rows[0].len(), 0);
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    });
    assert!(!manager.owes(peer, V4));
    assert_eq!(manager.owed_rows[0].len(), 0, "nothing pins the list");
    let mut rx = up_session(&mut manager, peer, 1);
    let mut wire = Wire::default();
    for _ in 0..64 {
        wire.write(&mut rx);
        manager.resync_dirty_peers_bounded();
    }
    let all: Vec<_> = (0..rows).map(|index| (index, 0)).collect();
    assert_eq!(wire.table, table(&all));
    assert_eq!(wire.markers, 1);
    assert_eq!(wire.rows_after_marker, 0);
    assert!(!manager.owes(peer, V4));
}

/// A receiver marked dirty mid-walk is resynced: the resync covers the
/// family, the cursor is dropped and the End-of-RIB follows the resync.
#[test]
fn a_dirty_receiver_mid_walk_is_resynced() {
    let rows = 40u32;
    let (mut manager, mut receivers) = owing(1, rows, 1 << 20);
    received(&mut manager, &[(3, 9)], &[5]);
    let peer = receivers[0].peer;
    manager.mark_outbound_dirty(peer);
    drain(&mut manager, &mut receivers);
    let expected: Vec<_> = (0..rows)
        .filter(|index| *index != 5)
        .map(|index| (index, if index == 3 { 9 } else { 0 }))
        .collect();
    assert_settled(&manager, &receivers, &expected, "dirty");
    assert_eq!(receivers[0].wire.announced.len(), expected.len());
}

/// A ROUTE-REFRESH mid-walk absorbs the rest of the walk into its own
/// operation: the owed rows, then the End-of-RIB that waited for them,
/// then the answer behind its `BoRR`. The cursor is gone afterwards.
#[test]
fn a_refresh_mid_walk_absorbs_the_rest_of_the_walk() {
    let rows = 40u32;
    let (mut manager, mut receivers) = owing(1, rows, CREDIT);
    tick(&mut manager, &mut receivers);
    let peer = receivers[0].peer;
    assert_eq!(receivers[0].wire.table.len(), STEP);
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer,
        session_id: 0,
        afi: V4.0,
        safi: V4.1,
        queued: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    });
    assert!(!manager.owes(peer, V4), "the refresh absorbed the family");
    assert_eq!(manager.owed_rows[0].len(), 0);
    let sent: Vec<_> = std::iter::from_fn(|| receivers[0].rx.try_recv().ok()).collect();
    let answer = sent
        .iter()
        .position(|update| !update.refresh_markers.is_empty())
        .expect("the answer carries its markers");
    let owed: usize = sent[..answer]
        .iter()
        .map(|update| update.announce.len())
        .sum();
    assert_eq!(owed, rows as usize - STEP, "the rest of the walk, once");
    let marker = sent[..answer]
        .iter()
        .position(|update| update.end_of_rib.contains(&V4))
        .expect("the End-of-RIB precedes the BoRR");
    assert!(
        sent[marker..answer]
            .iter()
            .all(|update| update.announce.is_empty()),
        "no owed row follows the End-of-RIB"
    );
    assert_eq!(
        sent[..answer]
            .iter()
            .filter(|update| update.end_of_rib.contains(&V4))
            .count(),
        1
    );
    assert_eq!(
        sent[answer..]
            .iter()
            .map(|update| update.announce.len())
            .sum::<usize>(),
        rows as usize,
        "the answer is the whole table"
    );
}

/// Shutdown mid-walk: the close flush sends the withdrawals behind the
/// cursor and leaves the announcements owed. The cursor does not move and
/// the rest of the walk is not copied into the receiver's own set.
#[test]
fn a_close_flush_mid_walk_sends_the_withdrawals_only() {
    let (mut manager, mut receivers) = owing(1, 40, CREDIT);
    tick(&mut manager, &mut receivers);
    let held = sent_rows(&receivers[0]);
    assert_eq!(held.len(), STEP);
    received(&mut manager, &[], &[held[0]]);
    let peer = receivers[0].peer;
    let listed = manager.owed_rows[0].len();
    manager.handle_update(RibUpdate::BeginClose);
    receivers[0].write();
    let wire = &receivers[0].wire;
    assert_eq!(wire.withdrawn, [key(held[0])], "the withdrawal is flushed");
    assert_eq!(wire.announced.len(), STEP, "no announcement is");
    assert!(manager.owes(peer, V4), "the announcements stay owed");
    assert_eq!(manager.owed_key_count(peer, UNICAST), 0);
    assert_eq!(manager.owed_rows[0].len(), listed);
}

fn inject_local(manager: &mut RibManager, prefix: Prefix) {
    let Prefix::V4(v4) = prefix else {
        unreachable!("IPv4 fixture");
    };
    let mut route = make_route(v4, SOURCE);
    route.peer = crate::PeerId::LOCAL;
    route.origin_type = crate::route::RouteOrigin::Local;
    route.attributes = AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
    ]);
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectRoute { route, reply });
    result.try_recv().unwrap().unwrap();
}

fn withdraw_local(manager: &mut RibManager, prefix: Prefix) {
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::WithdrawInjected {
        prefix,
        path_id: 0,
        allow_missing: false,
        owner: String::new(),
        override_owner: false,
        reply,
    });
    assert!(result.try_recv().unwrap().unwrap().removed);
}

/// The contract inside a GR selection hold: a cursor that is behind when
/// the hold begins sends only the rows the hold exempts (a local host
/// route, and its withdrawal), in bounded steps that stage nothing else,
/// and stops once it has read the list; a later local change re-arms it.
/// The held rows are not skipped: the release reads them again, and the
/// receiver ends with the exact table and one End-of-RIB after its last
/// row. Red when the hold moves the cursor itself: the held rows are
/// never sent.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the hold, its exempt rows and the release form one walk"
)]
fn a_cursor_inside_a_selection_hold_sends_exempt_rows_only() {
    const WAITER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 83);
    let rows = 40u32;
    let mut manager = manager(CREDIT).with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: vec![SelectionDeferralWaiterConfig {
            peer: peer_v4(WAITER).into(),
            families: vec![V4],
        }],
    });
    std::mem::forget(up_session(&mut manager, peer_v4(SOURCE), 0));
    // The receiver holds the table at variant 0, then owes the family: one
    // pass moves every row to variant 1 and one step sends the first eight.
    let peer = receiver(0);
    let rx = up_session(&mut manager, peer, 0);
    let mut receivers = vec![Receiver {
        peer,
        rx,
        wire: Wire::default(),
    }];
    let old: Vec<_> = (0..rows).map(|index| (index, 0)).collect();
    let new: Vec<_> = (0..rows).map(|index| (index, 1)).collect();
    for batch in old.chunks(STEP) {
        received(&mut manager, batch, &[]);
        receivers[0].write();
    }
    assert_eq!(receivers[0].wire.table, table(&old));
    // Count markers and rows from here: the initial table is behind.
    (
        receivers[0].wire.markers,
        receivers[0].wire.rows_after_marker,
    ) = (0, 0);
    manager.owe_eor(peer, V4);
    manager.owe_whole_family(peer, UNICAST);
    received(&mut manager, &new, &[]);
    tick(&mut manager, &mut receivers);
    let moved = |receiver: &Receiver| {
        let new = table(&new);
        receiver
            .wire
            .table
            .iter()
            .filter(|&(prefix, attributes)| new.get(prefix) == Some(attributes))
            .count()
    };
    assert_eq!(moved(&receivers[0]), STEP);
    // The hold begins with the cursor behind.
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: peer_v4(WAITER),
        session_id: 0,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![V4],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    // The waiter is a receiver too: it joins inside the hold and is sent
    // its table at the release.
    let rx = up_session(&mut manager, peer_v4(WAITER), 0);
    receivers.push(Receiver {
        peer: peer_v4(WAITER),
        rx,
        wire: Wire::default(),
    });
    assert!(manager.selection_deferred(V4));
    // The hold reads the rest of the list once and finds nothing exempt.
    let before = manager.adj_rib_out_commit_stats;
    drain(&mut manager, &mut receivers);
    assert!(!manager.owing_runnable(), "one read of the list per hold");
    assert_eq!(moved(&receivers[0]), STEP, "the held rows wait");
    assert_eq!(
        manager.adj_rib_out_commit_stats.owed_drain_rows_read, before.owed_drain_rows_read,
        "a held row is not staged"
    );
    let host = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 7), 32));
    inject_local(&mut manager, host);
    receivers[0].write();
    assert!(
        !receivers[0].wire.table.contains_key(&host),
        "owed, not staged"
    );
    assert!(manager.owing_runnable(), "an exempt row re-arms the hold");
    drain(&mut manager, &mut receivers);
    assert!(manager.selection_deferred(V4), "still inside the hold");
    assert!(
        receivers[0].wire.table.contains_key(&host),
        "sent in the hold"
    );
    assert_eq!(moved(&receivers[0]), STEP, "the held rows wait");
    assert_eq!(
        manager.adj_rib_out_commit_stats.owed_drain_rows_read - before.owed_drain_rows_read,
        1,
        "the hold stages the exempt row only"
    );
    assert!(manager.owes(peer, V4));
    assert_eq!(receivers[0].wire.markers, 0);
    // Its withdrawal goes out inside the hold too, then it comes back.
    withdraw_local(&mut manager, host);
    drain(&mut manager, &mut receivers);
    assert!(!receivers[0].wire.table.contains_key(&host));
    inject_local(&mut manager, host);
    drain(&mut manager, &mut receivers);
    assert!(receivers[0].wire.table.contains_key(&host));
    assert_eq!(moved(&receivers[0]), STEP);
    assert_eq!(receivers[0].wire.markers, 0);
    // The release reads the held rows again.
    manager.expire_selection_deferral();
    drain(&mut manager, &mut receivers);
    let wire = &receivers[0].wire;
    assert_eq!(wire.count(0), (2, 0), "each row once per variant");
    assert_eq!(wire.count(rows - 1), (2, 0));
    assert_eq!(wire.announced.len(), 2 * rows as usize + 2);
    assert_eq!(wire.uncharged, 0);
    assert_eq!(wire.latched, 0);
    assert_eq!(receivers[1].wire.announced.len(), rows as usize + 2);
    for receiver in &mut receivers {
        assert!(receiver.wire.table.remove(&host).is_some());
    }
    assert_settled(&manager, &receivers, &new, "hold");
}

/// The cap: a receiver that reads nothing pins the list while fresh keys
/// rotate through the table. Once the list holds more than twice the table
/// plus its slack, the slowest receiver is resynced instead and the list
/// is cut back; a receiver that keeps up is left alone. Red without the
/// cap: the list grows with every rotation.
#[test]
fn a_stalled_receiver_cannot_pin_the_list_past_its_cap() {
    let (mut manager, mut receivers) = owing(2, 8, CREDIT);
    let fallbacks = |manager: &RibManager| -> f64 {
        manager
            .metrics
            .registry()
            .gather()
            .into_iter()
            .filter(|family| family.name() == "bgp_rib_outbound_owing_fallback_total")
            .flat_map(|family| family.get_metric().to_vec())
            .map(|metric| metric.get_counter().get_value())
            .sum()
    };
    // The table holds the 8 rows and one round's 64 fresh ones.
    let cap = 2 * (8 + 64) + 4 * CHUNK_ROWS;
    let rounds = u32::try_from(cap).unwrap() / 64 + 8;
    // Receiver 0 reads and keeps up; receiver 1 reads nothing.
    let mut peak = 0;
    for round in 0..rounds {
        let base = 1000 + round * 64;
        let fresh: Vec<_> = (base..base + 64).map(|index| (index, 0)).collect();
        let gone: Vec<_> = if round == 0 {
            vec![]
        } else {
            (base - 64..base).collect()
        };
        received(&mut manager, &fresh, &gone);
        for _ in 0..12 {
            manager.resync_dirty_peers_bounded();
            receivers[0].write();
        }
        peak = peak.max(manager.owed_rows[0].len());
        assert!(peak <= cap, "{peak} keys in the list at round {round}");
        assert!(!manager.dirty_peers.contains(&receivers[0].peer));
    }
    assert!(
        peak > cap / 2,
        "the stalled receiver did pin the list: {peak}"
    );
    assert!(fallbacks(&manager) >= 1.0, "the slowest receiver resynced");
    // Once it reads again it converges on the same table.
    drain(&mut manager, &mut receivers);
    let last = 1000 + (rounds - 1) * 64;
    let expected: Vec<_> = (0..8)
        .chain(last..last + 64)
        .map(|index| (index, 0))
        .collect();
    for receiver in &receivers {
        assert_eq!(receiver.wire.table, table(&expected));
        assert!(!manager.owes(receiver.peer, V4));
        assert!(!manager.dirty_peers.contains(&receiver.peer));
    }
    assert_eq!(manager.owed_rows[0].len(), 0);
}

/// θ: a set that outgrows its byte cap stops growing and the receiver
/// starts a cursor for what changes afterwards. The set is kept (a row the
/// receiver holds that has since left the table is in no table to walk),
/// so the flip seeds nothing and the drain reads the keys owed, not the
/// table. Red when the flip drops the set: the stale rows are never
/// withdrawn.
#[test]
fn a_set_past_its_cap_keeps_its_keys_and_starts_a_cursor() {
    const CREDIT: usize = 1 << 20;
    let mut manager = manager(CREDIT);
    std::mem::forget(up_session(&mut manager, peer_v4(SOURCE), 0));
    let peer = receiver(0);
    let rx = up_session(&mut manager, peer, 0);
    let mut receivers = vec![Receiver {
        peer,
        rx,
        wire: Wire::default(),
    }];
    // A table the receiver holds in full: rows 0..200.
    let all: Vec<_> = (0..200).map(|index| (index, 0)).collect();
    received(&mut manager, &all, &[]);
    receivers[0].write();
    assert_eq!(receivers[0].wire.table.len(), 200);
    assert!(!manager.owes(peer, V4));
    // With the credit spent, rows 0..120 leave in one pass: more keys than
    // a quarter of the family, all of them rows the receiver holds.
    let charge =
        crate::outbound_credit::OutboundCharge::new(&manager.outbound_credit_handle(peer), CREDIT);
    let gone: Vec<u32> = (0..120).collect();
    received(&mut manager, &[], &gone);
    assert!(manager.owes_whole(peer, UNICAST), "past the byte cap");
    assert_eq!(
        manager.owed_key_count(peer, UNICAST),
        120,
        "the set is kept"
    );
    assert_eq!(manager.owed_rows[0].len(), 0, "the flip seeds nothing");
    // Two later passes change rows 150 and 151.
    received(&mut manager, &[(150, 3)], &[]);
    received(&mut manager, &[(151, 3)], &[]);
    assert_eq!(
        manager.owed_key_count(peer, UNICAST),
        120,
        "it stops growing"
    );
    assert_eq!(manager.owed_rows[0].len(), 2, "later passes are logged");
    receivers[0].write();
    assert_eq!(receivers[0].wire.table.len(), 200, "nothing was staged");
    drop(charge);
    let before = manager.adj_rib_out_commit_stats;
    drain(&mut manager, &mut receivers);
    let stats = manager.adj_rib_out_commit_stats;
    assert_eq!(
        stats.owed_drain_rows_read - before.owed_drain_rows_read,
        122,
        "the drain reads the keys owed, not the table"
    );
    let wire = &receivers[0].wire;
    for index in 0..120 {
        assert_eq!(wire.count(index), (1, 1), "stale row {index} is withdrawn");
    }
    assert_eq!(wire.count(150), (2, 0));
    assert_eq!(wire.count(151), (2, 0));
    let expected: Vec<_> = (120..200)
        .map(|index| (index, if index == 150 || index == 151 { 3 } else { 0 }))
        .collect();
    assert_eq!(wire.table, table(&expected));
    assert_eq!(wire.uncharged, 0);
    assert_eq!(wire.latched, 0);
    assert!(!manager.owes(peer, V4));
    assert_eq!(manager.owed_rows[0].len(), 0);
}

/// The list exists only while a receiver holds a cursor, and one pass logs
/// its keys once however many receivers hold one.
#[test]
fn a_pass_logs_its_keys_once_and_only_while_a_cursor_is_held() {
    // A receiver that owes keys below its cap holds no cursor.
    let mut keyed = manager(CREDIT);
    std::mem::forget(up_session(&mut keyed, peer_v4(SOURCE), 0));
    let peer = receiver(0);
    std::mem::forget(up_session(&mut keyed, peer, 0));
    let _charge =
        crate::outbound_credit::OutboundCharge::new(&keyed.outbound_credit_handle(peer), CREDIT);
    received(&mut keyed, &[(0, 0), (1, 0)], &[]);
    received(&mut keyed, &[(2, 0)], &[]);
    assert_eq!(keyed.owed_key_count(peer, UNICAST), 3);
    assert!(!keyed.owes_whole(peer, UNICAST));
    assert_eq!(keyed.owed_rows[0].len(), 0, "no cursor: nothing logged");
    assert_eq!(keyed.owed_rows[0].head(), 0);
    for count in [1u8, 8, 32] {
        let (manager, _receivers) = owing(count, 50, CREDIT);
        assert_eq!(manager.owed_rows[0].len(), 50, "{count} receivers");
        assert_eq!(manager.owed_rows[0].head(), 50, "{count} receivers");
    }
}
