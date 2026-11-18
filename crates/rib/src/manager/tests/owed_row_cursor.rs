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
/// Credit in unicast announcements: a step with the whole credit free takes
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
    .with_outbound_credit_bytes(unicast_rows(credit));
    manager.test_force_ungrouped = true;
    manager.flush_poll_budget = Duration::ZERO;
    manager
}

/// Hold the charge for `rows` unicast announcements.
fn charge_rows(manager: &mut RibManager, peer: PeerId, rows: usize) -> crate::OutboundCharge {
    crate::OutboundCharge::new(
        &manager.outbound_credit_handle(peer),
        rows,
        unicast_rows(rows),
    )
}

fn up_session(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    up_with(manager, peer, session_id, |_| {})
}

/// A session whose registration `edit` adjusts first.
fn up_with(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
    edit: impl FnOnce(&mut RibUpdate),
) -> mpsc::Receiver<OutboundRouteUpdate> {
    up_sized(manager, peer, session_id, 4096, edit)
}

/// [`up_with`] on an outbound channel of `channel` envelopes.
fn up_sized(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
    channel: usize,
    edit: impl FnOnce(&mut RibUpdate),
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, output) = mpsc::channel(channel);
    let mut registration = RibUpdate::PeerUp {
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
    };
    edit(&mut registration);
    manager.handle_update(registration);
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
    /// Each path announced, with its attributes, in order.
    paths: Vec<(Prefix, String)>,
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
            self.apply(&update);
        }
    }

    /// Write one envelope.
    fn apply(&mut self, update: &OutboundRouteUpdate) {
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
            let attributes = format!("{:?}", route.attributes);
            self.paths.push((route.prefix, attributes.clone()));
            self.table.insert(route.prefix, attributes);
            self.announced.push(route.prefix);
        }
        self.markers += update
            .end_of_rib
            .iter()
            .filter(|family| **family == V4)
            .count();
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
    owing_sized(receivers, rows, credit, 4096)
}

/// [`owing`] with outbound channels of `channel` envelopes.
fn owing_sized(
    receivers: u8,
    rows: u32,
    credit: usize,
    channel: usize,
) -> (RibManager, Vec<Receiver>) {
    let mut manager = manager(credit);
    std::mem::forget(up_session(&mut manager, peer_v4(SOURCE), 0));
    let mut receivers: Vec<Receiver> = (0..receivers)
        .map(|index| {
            let peer = receiver(index);
            let mut rx = up_sized(&mut manager, peer, 0, channel, |_| {});
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

fn counter(manager: &RibManager, name: &str) -> f64 {
    manager
        .metrics
        .registry()
        .gather()
        .into_iter()
        .filter(|family| family.name() == name)
        .flat_map(|family| family.get_metric().to_vec())
        .map(|metric| metric.get_counter().get_value())
        .sum()
}

fn fallbacks(manager: &RibManager) -> f64 {
    counter(manager, "bgp_rib_outbound_owing_fallback_total")
}

/// Families (of any receiver) that began to be owed whole.
fn flips(manager: &RibManager) -> f64 {
    counter(manager, "bgp_rib_outbound_owing_flips_total")
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
    // One byte short of an integral row limit: the last announcement may
    // spend the remaining credit, so exactly one byte can be overdrawn.
    manager.outbound_credit_override = Some(unicast_rows(CREDIT) - 1);
    // Receiver 1 never reads.
    for _ in 0..50 {
        manager.resync_dirty_peers_bounded();
        receivers[0].write();
        for receiver in &receivers {
            assert!(!manager.outbound_operation_live(receiver.peer));
        }
    }
    let stalled = receivers[1].peer;
    assert_eq!(manager.outbound_credit_rows(stalled), CREDIT);
    assert_eq!(manager.outbound_credit_bytes(stalled), unicast_rows(CREDIT));
    assert!(manager.owes(stalled, V4));
    assert!(manager.eor_pending(stalled).contains(&V4));
    assert!(!manager.dirty_peers.contains(&stalled));
    // The reader finished meanwhile; the stalled one finishes once it reads.
    assert!(!manager.owes(receivers[0].peer, V4));
    let stalled_receiver = &mut receivers[1];
    let mut held_rows = 0;
    while let Ok(update) = stalled_receiver.rx.try_recv() {
        let rows = update.announce.len();
        let charge = update.credit.as_ref().expect("charged cursor step");
        assert_eq!(charge.rows(), rows);
        assert_eq!(charge.bytes(), unicast_rows(rows));
        assert_eq!(update.end_of_rib, [], "marker overtook the stalled cursor");
        held_rows += rows;
        stalled_receiver.wire.apply(&update);
    }
    assert_eq!(held_rows, CREDIT);
    assert_eq!(manager.outbound_credit_rows(stalled), 0);
    assert_eq!(manager.outbound_credit_bytes(stalled), 0);
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
    // One answer, bracketed: both RFC 7313 markers, and the End-of-RIB a
    // peer without them reads instead (the session writes one or the other).
    assert_eq!(
        sent.iter()
            .filter(|update| !update.refresh_markers.is_empty())
            .count(),
        1,
        "answered once"
    );
    assert_eq!(sent[answer].refresh_markers, BRACKET);
    assert_eq!(sent[answer].end_of_rib, [V4]);
    assert!(!manager.pending_refresh.contains_key(&peer));
    drain(&mut manager, &mut receivers);
    assert!(receivers[0].rx.is_empty(), "nothing follows the answer");
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
/// rotate through the table. Once the list holds more than twice the most
/// keys one pass accounted for (the table after it plus the keys it
/// carried) plus its slack, the slowest receiver is resynced instead and
/// the list is cut back; a receiver that keeps up is left alone, and the
/// resynced one ends with the exact table and one End-of-RIB after its
/// last row. Red without the cap: the list grows with every rotation.
#[test]
fn a_stalled_receiver_cannot_pin_the_list_past_its_cap() {
    let (mut manager, mut receivers) = owing(2, 8, CREDIT);
    // The table holds the 8 rows and one round's 64 fresh ones, and a
    // round's pass carries those and the 64 it withdraws.
    let cap = 2 * (8 + 64 + 128) + 4 * CHUNK_ROWS;
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
        // The rotation went on after each marker; there is only one.
        assert_eq!(receiver.wire.markers, 1);
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
    let charge = charge_rows(&mut manager, peer, CREDIT);
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
    let _charge = charge_rows(&mut keyed, peer, CREDIT);
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

/// The cap is not reached by one large event with receivers that read: a
/// withdrawal of most of the table, or the source going away, leaves the
/// list holding keys the table no longer has, and no receiver is resynced
/// for it. Red when the cap is taken from the table after the pass: every
/// receiver is evicted and resynced.
#[test]
fn a_large_withdrawal_or_source_loss_evicts_no_reading_receiver() {
    let rows = 12_000u32;
    for source_lost in [false, true] {
        let (mut manager, mut receivers) = owing(3, rows, 1 << 20);
        // Every receiver reads and has taken one step.
        for _ in 0..3 {
            tick(&mut manager, &mut receivers);
        }
        let builds = manager.adj_rib_out_commit_stats.resync_builds;
        let rest: Vec<_> = if source_lost {
            manager.handle_update(RibUpdate::PeerDown {
                peer: peer_v4(SOURCE),
                session_id: 0,
            });
            drain_route_chunks(&mut manager);
            vec![]
        } else {
            let gone: Vec<u32> = (0..10_000).collect();
            received(&mut manager, &[], &gone);
            (10_000..rows).map(|index| (index, 0)).collect()
        };
        assert_eq!(manager.loc_rib.len(), rest.len());
        assert!(
            manager.owed_rows[0].len() > 2 * rest.len() + 4 * CHUNK_ROWS,
            "the list holds the withdrawn keys: {}",
            manager.owed_rows[0].len()
        );
        drain(&mut manager, &mut receivers);
        assert_eq!(fallbacks(&manager), 0.0, "source lost: {source_lost}");
        assert_eq!(
            manager.adj_rib_out_commit_stats.resync_builds, builds,
            "no receiver was resynced"
        );
        assert_settled(&manager, &receivers, &rest, "large withdrawal");
    }
}

/// The same at a selection release: the release pass carries every key
/// recorded during the hold, most of which left again before the release,
/// so the list holds far more keys than the released table. Receivers that
/// read are not resynced for it.
#[test]
fn a_selection_release_larger_than_its_table_evicts_no_reading_receiver() {
    const WAITER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 83);
    let rows = 12_000u32;
    let mut manager = manager(1 << 20).with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: vec![SelectionDeferralWaiterConfig {
            peer: peer_v4(WAITER).into(),
            families: vec![V4],
        }],
    });
    std::mem::forget(up_session(&mut manager, peer_v4(SOURCE), 0));
    // The receivers hold the whole table before the hold begins.
    let mut receivers: Vec<Receiver> = (0..3)
        .map(|index| {
            let peer = receiver(index);
            let rx = up_session(&mut manager, peer, 0);
            Receiver {
                peer,
                rx,
                wire: Wire::default(),
            }
        })
        .collect();
    let all: Vec<_> = (0..rows).map(|index| (index, 0)).collect();
    received(&mut manager, &all, &[]);
    for receiver in &mut receivers {
        receiver.write();
        assert_eq!(receiver.wire.table.len(), rows as usize);
        (receiver.wire.markers, receiver.wire.rows_after_marker) = (0, 0);
    }
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
    std::mem::forget(up_session(&mut manager, peer_v4(WAITER), 0));
    assert!(manager.selection_deferred(V4));
    // Inside the hold most of the table leaves.
    let gone: Vec<u32> = (0..10_000).collect();
    received(&mut manager, &[], &gone);
    for receiver in &mut receivers {
        receiver.write();
        assert_eq!(receiver.wire.table.len(), rows as usize, "held");
    }
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    manager.expire_selection_deferral();
    for receiver in &receivers {
        assert!(manager.owes_whole(receiver.peer, UNICAST), "owed whole");
    }
    assert!(
        manager.owed_rows[0].len() > 2 * manager.loc_rib.len() + 4 * CHUNK_ROWS,
        "the release logged the keys that left: {} keys, {} rows",
        manager.owed_rows[0].len(),
        manager.loc_rib.len()
    );
    drain(&mut manager, &mut receivers);
    assert_eq!(fallbacks(&manager), 0.0);
    assert_eq!(
        manager.adj_rib_out_commit_stats.resync_builds, builds,
        "no receiver was resynced"
    );
    let rest: Vec<_> = (10_000..rows).map(|index| (index, 0)).collect();
    for receiver in &receivers {
        assert_eq!(receiver.wire.table, table(&rest));
        assert!(receiver.wire.uncharged == 0 && receiver.wire.latched == 0);
        assert!(!manager.owes(receiver.peer, V4));
        assert!(!manager.dirty_peers.contains(&receiver.peer));
    }
    assert_eq!(manager.owed_rows[0].len(), 0);
}

/// Work count: the pass that finds the list over its cap builds no resync.
/// It marks the evicted receivers dirty after its member loop, and each is
/// then one unit of the dirty ring. Red when the cap is checked in the
/// pass preamble: that pass builds one whole-table resync per evicted
/// receiver in its own turn.
#[test]
fn an_eviction_pass_builds_no_resync_in_its_own_turn() {
    const STALLED: usize = 3;
    let (mut manager, mut receivers) = owing(1 + u8::try_from(STALLED).unwrap(), 8, CREDIT);
    let mut evicted = false;
    // Receiver 0 reads and keeps up; the others read nothing.
    for round in 0..200u32 {
        let base = 1000 + round * 64;
        let fresh: Vec<_> = (base..base + 64).map(|index| (index, 0)).collect();
        let gone: Vec<_> = if round == 0 {
            vec![]
        } else {
            (base - 64..base).collect()
        };
        let before = (
            fallbacks(&manager),
            manager.adj_rib_out_commit_stats.resync_builds,
        );
        received(&mut manager, &fresh, &gone);
        if fallbacks(&manager) > before.0 {
            assert_eq!(fallbacks(&manager) - before.0, 3.0, "one list, one cursor");
            assert_eq!(
                manager.adj_rib_out_commit_stats.resync_builds, before.1,
                "the evicting pass built a resync"
            );
            for receiver in &receivers[1..] {
                assert!(manager.dirty_peers.contains(&receiver.peer));
            }
            evicted = true;
            break;
        }
        for _ in 0..12 {
            manager.resync_dirty_peers_bounded();
            receivers[0].write();
        }
    }
    assert!(evicted, "the stalled receivers were never evicted");
    // One evicted receiver per unit of the ring.
    let mut units = 0;
    while receivers[1..]
        .iter()
        .any(|receiver| manager.dirty_peers.contains(&receiver.peer))
    {
        let builds = manager.adj_rib_out_commit_stats.resync_builds;
        manager.resync_dirty_peers_bounded();
        assert!(manager.adj_rib_out_commit_stats.resync_builds - builds <= 1);
        units += 1;
        assert!(units <= 64, "the ring does not finish");
    }
    assert!(units >= STALLED, "{units} units for {STALLED} receivers");
}

/// Work count: a key that changes again moves its one list entry, so a
/// list every key of which changed again holds no dead entries: the next
/// step sends a full chunk, the walk takes ceil(N / B) steps and each row
/// leaves once, at its newest state. Red when a changed key leaves a dead
/// entry behind: steps read dead entries and send less than a chunk.
#[test]
fn a_key_changed_again_leaves_no_dead_entry_for_a_step_to_read() {
    let rows = u32::try_from(8 * CHUNK_ROWS + 800).unwrap();
    let (mut manager, mut receivers) = owing(1, rows, 1 << 20);
    let again: Vec<_> = (0..rows).map(|index| (index, 1)).collect();
    received(&mut manager, &again, &[]);
    assert_eq!(manager.owed_rows[0].len(), rows as usize);
    let steps = manager.adj_rib_out_commit_stats.owed_drain_steps;
    tick(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.announced.len(), CHUNK_ROWS, "a full step");
    drain(&mut manager, &mut receivers);
    assert_eq!(manager.adj_rib_out_commit_stats.owed_drain_steps - steps, 9);
    assert_eq!(
        receivers[0].wire.announced.len(),
        rows as usize,
        "once each"
    );
    assert_settled(&manager, &receivers, &again, "changed again");
}

/// Two cursors, one key: a key that sits behind the faster cursor and ahead
/// of the slower one changes. The faster receiver is sent it again and the
/// slower one once, at the newest state. Red when a key that is still in
/// the list (the slower cursor keeps it there) does not move to the back:
/// the faster receiver keeps the old state.
#[test]
fn a_key_between_two_cursors_reaches_both_once_at_its_newest_state() {
    let rows = 40u32;
    let (mut manager, mut receivers) = owing(2, rows, CREDIT);
    // The slower receiver has no credit and takes no step.
    let charge = charge_rows(&mut manager, receivers[1].peer, CREDIT);
    for _ in 0..4 {
        tick(&mut manager, &mut receivers);
    }
    let behind = sent_rows(&receivers[0]);
    assert!(!behind.is_empty() && behind.len() < rows as usize);
    assert!(receivers[1].wire.announced.is_empty(), "no credit");
    let changed = behind[0];
    received(&mut manager, &[(changed, 7)], &[]);
    drop(charge);
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.count(changed), (2, 0), "visited again");
    assert_eq!(receivers[1].wire.count(changed), (1, 0), "visited once");
    assert_eq!(receivers[0].wire.announced.len(), rows as usize + 1);
    assert_eq!(receivers[1].wire.announced.len(), rows as usize);
    let expected: Vec<_> = (0..rows)
        .map(|index| (index, if index == changed { 7 } else { 0 }))
        .collect();
    assert_settled(&manager, &receivers, &expected, "between two cursors");
}

/// No fleet barrier: a receiver's End-of-RIB leaves when its own cursor
/// has caught up, whatever the others owe. One receiver reads and one has
/// no credit: the first gets its marker after its last row while the
/// second still owes and has none; once the second reads it drains and
/// gets exactly one marker after its last row. Red when a marker waits for
/// every cursor of the family, and when it leaves a tick after the step
/// that caught up.
#[test]
fn a_caught_up_receiver_gets_its_end_of_rib_while_another_is_stalled() {
    let rows = 40u32;
    let (mut manager, mut receivers) = owing(2, rows, CREDIT);
    let charge = charge_rows(&mut manager, receivers[1].peer, CREDIT);
    let mut caught_up = false;
    for _ in 0..64 {
        tick(&mut manager, &mut receivers);
        // The marker leaves in the step that catches up, not a tick later.
        let done = !manager.owes(receivers[0].peer, V4);
        assert_eq!(receivers[0].wire.markers, usize::from(done));
        caught_up |= done;
    }
    assert!(caught_up);
    let all: Vec<_> = (0..rows).map(|index| (index, 0)).collect();
    assert_eq!(receivers[0].wire.table, table(&all));
    assert_eq!(receivers[0].wire.markers, 1, "its own cursor caught up");
    assert_eq!(receivers[0].wire.rows_after_marker, 0);
    assert!(!manager.owes(receivers[0].peer, V4));
    assert!(manager.owes_whole(receivers[1].peer, UNICAST), "stalled");
    assert_eq!(receivers[1].wire.markers, 0);
    assert!(receivers[1].wire.announced.is_empty(), "no credit");
    drop(charge);
    drain(&mut manager, &mut receivers);
    assert_settled(&manager, &receivers, &all, "uneven speed");
}

/// The same for uneven debt: a receiver that starts its cursor late owes
/// only what changed afterwards and finishes first, with its marker, while
/// the receiver that owes the whole table is still mid-walk.
#[test]
fn a_receiver_that_owes_less_finishes_first_with_its_end_of_rib() {
    let rows = 40u32;
    let mut manager = manager(CREDIT);
    std::mem::forget(up_session(&mut manager, peer_v4(SOURCE), 0));
    let mut receivers: Vec<Receiver> = (0..2)
        .map(|index| {
            let peer = receiver(index);
            let rx = up_session(&mut manager, peer, 0);
            Receiver {
                peer,
                rx,
                wire: Wire::default(),
            }
        })
        .collect();
    let (early, late) = (receivers[0].peer, receivers[1].peer);
    manager.owe_eor(early, V4);
    manager.owe_whole_family(early, UNICAST);
    // The late receiver is sent the table as it arrives.
    let all: Vec<_> = (0..rows).map(|index| (index, 0)).collect();
    for batch in all.chunks(STEP) {
        received(&mut manager, batch, &[]);
        receivers[1].write();
    }
    assert_eq!(receivers[1].wire.table, table(&all));
    for receiver in &mut receivers {
        receiver.write();
        (receiver.wire.markers, receiver.wire.rows_after_marker) = (0, 0);
    }
    manager.owe_eor(late, V4);
    manager.owe_whole_family(late, UNICAST);
    received(&mut manager, &[(0, 5), (1, 5), (2, 5)], &[]);
    let expected: Vec<_> = (0..rows)
        .map(|index| (index, if index < 3 { 5 } else { 0 }))
        .collect();
    // One step each.
    tick(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);
    assert_eq!(receivers[1].wire.table, table(&expected));
    assert_eq!(receivers[1].wire.markers, 1, "three rows owed, then done");
    assert_eq!(receivers[1].wire.rows_after_marker, 0);
    assert!(!manager.owes(late, V4));
    assert!(manager.owes_whole(early, UNICAST), "still mid-walk");
    assert_eq!(receivers[0].wire.markers, 0);
    drain(&mut manager, &mut receivers);
    assert_settled(&manager, &receivers, &expected, "uneven debt");
}

/// One receiver, two cursors: IPv4 and IPv6 unicast owed whole together.
/// Each family's End-of-RIB leaves after that family's last row and not
/// before, and the family that finishes first does not wait for the other.
/// Red when a family is taken as caught up before its cursor reaches the
/// end of its own list.
#[test]
fn ipv4_and_ipv6_cursors_on_one_receiver_each_end_with_their_own_marker() {
    const V6: (Afi, Safi) = (Afi::Ipv6, Safi::Unicast);
    let counts = [40usize, 8];
    let mut manager = manager(CREDIT);
    std::mem::forget(up_session(&mut manager, peer_v4(SOURCE), 0));
    let peer = receiver(0);
    let mut rx = up_with(&mut manager, peer, 0, |registration| {
        if let RibUpdate::PeerUp {
            sendable_families, ..
        } = registration
        {
            *sendable_families = vec![V4, V6];
        }
    });
    while rx.try_recv().is_ok() {}
    for (family, owed) in [(V4, UNICAST), (V6, OwedFamily::IPV6_UNICAST)] {
        manager.owe_eor(peer, family);
        manager.owe_whole_family(peer, owed);
    }
    let mut announced: Vec<Route> = (0..40).map(|index| route(index, 0)).collect();
    announced.extend((0..8u16).map(|index| {
        let mut route = crate::test_support::make_v6_route(
            Ipv6Prefix::new(Ipv6Addr::new(0x2001, 0xdb8, index, 0, 0, 0, 0, 0), 48),
            Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 1),
        );
        route.peer = peer_v4(SOURCE);
        route.attributes = self::route(0, 0).attributes;
        route
    }));
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    assert!(rx.try_recv().is_err(), "owed, not staged");
    // Per family: rows written, markers, rows written after its marker.
    let mut seen = [[0usize; 3]; 2];
    let mut one_family_done = false;
    for _ in 0..1000 {
        if !manager.resync_tick_pending() {
            break;
        }
        manager.resync_dirty_peers_bounded();
        while let Ok(update) = rx.try_recv() {
            assert!(update.credit.is_some() || update.announce.is_empty());
            for route in update.announce.iter() {
                let family = usize::from(matches!(route.prefix, Prefix::V6(_)));
                seen[family][0] += 1;
                seen[family][2] += usize::from(seen[family][1] != 0);
            }
            for family in &update.end_of_rib {
                seen[usize::from(*family == V6)][1] += 1;
            }
        }
        for (index, family) in [V4, V6].into_iter().enumerate() {
            let done = !manager.owes(peer, family);
            assert_eq!(seen[index][1], usize::from(done), "{family:?} marker");
            assert!(!done || seen[index][0] == counts[index], "{family:?} rows");
        }
        one_family_done |= manager.owes(peer, V4) != manager.owes(peer, V6);
    }
    assert!(one_family_done, "one family finished before the other");
    assert_eq!(seen, [[40, 1, 0], [8, 1, 0]]);
    assert_eq!(manager.owed_rows[0].len() + manager.owed_rows[1].len(), 0);
}

/// The last step takes the last slot of the outbound channel, so the
/// End-of-RIB that follows it is refused. Every owed row was admitted: the
/// receiver is not marked dirty and no resync is built. The marker waits
/// for the tick's marker retry and leaves once, after the last row, when
/// the channel has room. Red when the refusal marks the receiver dirty:
/// the table is sent again as an uncharged whole-peer resync.
#[test]
fn a_full_channel_at_the_last_step_keeps_the_marker_for_the_tick() {
    let rows = 3u32;
    let (mut manager, mut receivers) = owing_sized(1, rows, 1 << 20, 1);
    let peer = receivers[0].peer;
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    // The step's one envelope fills the channel; nothing is read yet.
    manager.resync_dirty_peers_bounded();
    assert!(manager.outbound_channel_full(peer));
    assert!(!manager.owes(peer, V4), "every owed row was admitted");
    assert!(
        manager.eor_pending(peer).contains(&V4),
        "refused, still owed"
    );
    assert!(
        !manager.dirty_peers.contains(&peer),
        "no resync for a marker"
    );
    // Ticks against the full channel change nothing.
    for _ in 0..3 {
        manager.resync_dirty_peers_bounded();
        assert!(!manager.dirty_peers.contains(&peer));
    }
    receivers[0].write();
    assert_eq!(receivers[0].wire.announced.len(), rows as usize);
    assert_eq!(
        receivers[0].wire.markers, 0,
        "refused with the channel full"
    );
    // Room again: the next tick sends the marker, once.
    for _ in 0..4 {
        tick(&mut manager, &mut receivers);
        assert_eq!(receivers[0].wire.markers, 1);
    }
    assert_eq!(
        manager.adj_rib_out_commit_stats.resync_builds, builds,
        "no resync was built"
    );
    assert_eq!(
        receivers[0].wire.announced.len(),
        rows as usize,
        "once each"
    );
    assert!(receivers[0].wire.uncharged == 0 && receivers[0].wire.latched == 0);
    let all: Vec<_> = (0..rows).map(|index| (index, 0)).collect();
    assert_settled(&manager, &receivers, &all, "full channel");
}

/// Receiver 0 reads and keeps up while `stalled` others read nothing and
/// fresh keys rotate through the table, until the list cap evicts them.
/// Returns the table the rotation left.
fn evict_stalled(stalled: u8) -> (RibManager, Vec<Receiver>, Vec<(u32, u32)>) {
    let (mut manager, mut receivers) = owing(1 + stalled, 8, CREDIT);
    for round in 0..200u32 {
        let base = 1000 + round * 64;
        let fresh: Vec<_> = (base..base + 64).map(|index| (index, 0)).collect();
        let gone: Vec<_> = if round == 0 {
            vec![]
        } else {
            (base - 64..base).collect()
        };
        let before = fallbacks(&manager);
        received(&mut manager, &fresh, &gone);
        if fallbacks(&manager) > before {
            assert_eq!(fallbacks(&manager) - before, f64::from(stalled));
            for receiver in &receivers[1..] {
                assert!(manager.dirty_peers.contains(&receiver.peer));
                assert!(manager.owed_row_evicted.contains(&receiver.peer));
            }
            let table = (0..8).map(|index| (index, 0)).chain(fresh).collect();
            return (manager, receivers, table);
        }
        for _ in 0..12 {
            manager.resync_dirty_peers_bounded();
            receivers[0].write();
        }
    }
    panic!("the stalled receivers were never evicted");
}

/// Work count: a receiver the cap evicted is resynced by the resync tick
/// only. The ordinary passes that follow the eviction build no resync and
/// stage nothing toward the evicted receivers, though each has channel
/// room; the tick then builds one a unit, and each receiver ends with the
/// exact table and one End-of-RIB after it. Red when an ordinary pass
/// takes an evicted receiver as any dirty one: the first one-key pass
/// builds a whole-table resync for each of them in its own turn.
#[test]
fn an_ordinary_pass_builds_no_resync_for_an_evicted_receiver() {
    const STALLED: usize = 3;
    let (mut manager, mut receivers, mut expected) = evict_stalled(3);
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    // The evicted receivers read what their steps had queued.
    for receiver in &mut receivers[1..] {
        receiver.write();
    }
    for variant in 1..4 {
        received(&mut manager, &[(5, variant)], &[]);
        assert_eq!(
            manager.adj_rib_out_commit_stats.resync_builds, builds,
            "an ordinary pass built a resync"
        );
    }
    expected[5] = (5, 3);
    for receiver in &mut receivers[1..] {
        assert!(!manager.outbound_channel_full(receiver.peer), "it has room");
        let sent = receiver.wire.announced.len();
        receiver.write();
        assert_eq!(receiver.wire.announced.len(), sent, "nothing was staged");
        assert!(manager.dirty_peers.contains(&receiver.peer));
    }
    assert_eq!(manager.owed_row_evicted.len(), STALLED);
    // The tick: one evicted receiver a unit.
    for unit in 1..=STALLED {
        manager.resync_dirty_peers_bounded();
        assert_eq!(
            manager.adj_rib_out_commit_stats.resync_builds - builds,
            unit,
            "one resync a unit"
        );
        assert_eq!(manager.owed_row_evicted.len(), STALLED - unit);
    }
    drain(&mut manager, &mut receivers);
    assert!(manager.owed_row_evicted.is_empty());
    assert_eq!(
        manager.adj_rib_out_commit_stats.resync_builds - builds,
        STALLED,
        "one resync a receiver"
    );
    assert_settled(&manager, &receivers, &expected, "evicted");
}

/// The mark of an evicted receiver does not outlive what it stands for. A
/// tick that finds no room leaves the receiver dirty and marked; a flap, a
/// new session, a closed channel and a regroup each drop the mark, and the
/// receiver's next session or resync ends with the exact table and one
/// End-of-RIB.
#[test]
fn an_evicted_receivers_mark_ends_with_its_session_or_its_group() {
    // No room at the tick: still dirty, still the tick's.
    let (mut manager, mut receivers, expected) = evict_stalled(1);
    let peer = receivers[1].peer;
    let latch = manager
        .begin_outbound_operation(peer, 1)
        .expect("a live whole-table operation");
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    manager.resync_dirty_peers_bounded();
    received(&mut manager, &[(5, 0)], &[]);
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
    assert!(manager.dirty_peers.contains(&peer));
    assert!(manager.owed_row_evicted.contains(&peer));
    drop(latch);
    drain(&mut manager, &mut receivers);
    assert!(manager.owed_row_evicted.is_empty());
    assert_settled(&manager, &receivers, &expected, "no room at the tick");

    // A flap, and a new session over the old one.
    for flap in [true, false] {
        let (mut manager, mut receivers, expected) = evict_stalled(1);
        let peer = receivers[1].peer;
        if flap {
            manager.handle_update(RibUpdate::PeerDown {
                peer,
                session_id: 0,
            });
            assert!(!manager.dirty_peers.contains(&peer));
        }
        let rx = up_session(&mut manager, peer, 1);
        assert!(manager.owed_row_evicted.is_empty(), "flap: {flap}");
        receivers[1] = Receiver {
            peer,
            rx,
            wire: Wire::default(),
        };
        drain(&mut manager, &mut receivers);
        assert!(manager.owed_row_evicted.is_empty());
        assert_settled(&manager, &receivers, &expected, "new session");
    }

    // The channel closes before the tick reaches the receiver.
    let (mut manager, mut receivers, _) = evict_stalled(1);
    let gone = receivers.pop().unwrap();
    drop(gone.rx);
    manager.resync_dirty_peers_bounded();
    assert!(manager.owed_row_evicted.is_empty());
    assert!(!manager.dirty_peers.contains(&gone.peer));

    // A regroup: the receiver is dirty as any regrouped member is.
    let (mut manager, mut receivers, expected) = evict_stalled(1);
    let peer = receivers[1].peer;
    manager.test_force_ungrouped = false;
    drop(manager.recompute_update_group(peer));
    assert!(manager.grouped_member_of(peer).is_some());
    assert!(manager.owed_row_evicted.is_empty());
    assert!(manager.dirty_peers.contains(&peer));
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[1].wire.table, table(&expected));
    assert_eq!(receivers[1].wire.markers, 1);
    assert_eq!(receivers[1].wire.rows_after_marker, 0);
    assert!(!manager.dirty_peers.contains(&peer));
}

/// Observations of the owed-drain step histogram, every scope.
fn drain_steps_observed(manager: &RibManager) -> u64 {
    manager
        .metrics
        .registry()
        .gather()
        .into_iter()
        .filter(|family| family.name() == "bgp_rib_outbound_owed_drain_step_seconds")
        .flat_map(|family| family.get_metric().to_vec())
        .map(|metric| metric.get_histogram().get_sample_count())
        .sum()
}

/// Work count: a tick resyncs at most one evicted receiver, however much
/// of its poll budget is left: that resync is a whole table, and the tick
/// ends with it. The unit is not a drain step and is observed under no
/// scope of the step histogram. Red when the tick goes on to the next
/// evicted receiver while its budget lasts: one tick builds all three.
#[test]
fn a_tick_resyncs_one_evicted_receiver_whatever_its_budget() {
    const STALLED: usize = 3;
    let (mut manager, mut receivers, expected) = evict_stalled(3);
    // A budget no unit uses up.
    manager.flush_poll_budget = Duration::from_secs(3600);
    // The receiver that keeps up takes no step meanwhile.
    let charge = charge_rows(&mut manager, receivers[0].peer, CREDIT);
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    let observed = drain_steps_observed(&manager);
    for unit in 1..=STALLED {
        manager.resync_dirty_peers_bounded();
        assert_eq!(
            manager.adj_rib_out_commit_stats.resync_builds - builds,
            unit,
            "one evicted receiver a tick"
        );
        assert_eq!(manager.owed_row_evicted.len(), STALLED - unit);
    }
    assert_eq!(
        drain_steps_observed(&manager),
        observed,
        "a fallback resync is not a drain step"
    );
    drop(charge);
    drain(&mut manager, &mut receivers);
    assert_settled(&manager, &receivers, &expected, "one a tick");
}

/// The actor loop takes queued input between two evicted receivers'
/// resyncs. Three receivers wait for the tick, whose poll budget no unit
/// uses up. When the first has its table the other two have nothing, and
/// an update is queued: it runs before the second receiver's resync, so
/// that resync and the third carry the new state ahead of their End-of-RIB,
/// while the first receiver is sent it as an ordinary update after its
/// own. Red when a tick resyncs every evicted receiver its budget allows:
/// all three have their tables before the loop reads its queue.
#[tokio::test(start_paused = true)]
async fn queued_input_runs_between_two_evicted_receivers_resyncs() {
    let (mut manager, mut receivers, mut expected) = evict_stalled(3);
    for receiver in &mut receivers {
        receiver.write();
    }
    manager.flush_poll_budget = Duration::from_secs(3600);
    let (tx, rx) = mpsc::channel(8);
    manager.rx = rx;
    let actor = tokio::spawn(manager.run());
    // The first unit: one evicted receiver is sent its table.
    let first = {
        let [_, a, b, c] = &mut receivers[..] else {
            panic!("four receivers");
        };
        let (index, update) = tokio::select! {
            update = a.rx.recv() => (1, update),
            update = b.rx.recv() => (2, update),
            update = c.rx.recv() => (3, update),
        };
        receivers[index]
            .wire
            .apply(&update.expect("the session is up"));
        index
    };
    receivers[first].write();
    assert_eq!(receivers[first].wire.table.len(), expected.len());
    for (index, receiver) in receivers.iter().enumerate().skip(1) {
        assert!(
            index == first || receiver.rx.is_empty(),
            "receiver {index} was resynced in the first receiver's tick"
        );
    }
    // Queued behind the first unit, ahead of the second.
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: vec![route(5, 9)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    expected[5] = (5, 9);
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        for receiver in &mut receivers {
            receiver.write();
        }
    }
    for (index, receiver) in receivers.iter().enumerate() {
        assert_eq!(receiver.wire.table, table(&expected), "receiver {index}");
        assert_eq!(receiver.wire.markers, 1, "receiver {index}");
        if index != 0 {
            // The update ran after the first table, which had ended with
            // its marker, and before the other two, which carried it.
            let after = usize::from(index == first);
            assert_eq!(receiver.wire.rows_after_marker, after, "receiver {index}");
        }
    }
    drop(tx);
    actor.abort();
}

/// A deleted neighbor leaves nothing behind: an evicted receiver that is
/// deleted before the tick reaches it, with no session end first, is no
/// longer marked, dirty or owed an End-of-RIB, and the tick has nothing to
/// build. Red when the mark outlives the receiver's owed state.
#[test]
fn a_deleted_evicted_receiver_leaves_no_mark_and_no_end_of_rib() {
    let (mut manager, mut receivers, expected) = evict_stalled(1);
    let gone = receivers.pop().unwrap();
    assert!(manager.eor_pending(gone.peer).contains(&V4));
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    manager.handle_update(RibUpdate::PeerDeleted {
        peer: gone.peer,
        label: None,
        keep_series: false,
    });
    assert!(manager.owed_row_evicted.is_empty());
    assert!(!manager.dirty_peers.contains(&gone.peer));
    assert!(manager.eor_pending(gone.peer).is_empty(), "no marker owed");
    drain(&mut manager, &mut receivers);
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
    assert_settled(&manager, &receivers, &expected, "deleted");
}

fn second_path(index: u32, med: u32) -> Route {
    const SECOND: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    let mut route = route(index, med);
    route.peer = peer_v4(SECOND);
    route.attributes = AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::LocalPref(50),
        PathAttribute::Med(med),
    ]);
    route
}

fn received_from(manager: &mut RibManager, routes: Vec<Route>) {
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: routes[0].peer,
        announced: routes,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(manager);
}

/// A receiver whose export for a key is not the Loc-RIB best (Add-Path,
/// per-client best), mid-walk: a path that is not the best changes on a
/// row the cursor has passed, so the pass reports the key as affected only.
/// The row is visited again. Red when a pass logs only the keys whose best
/// changed: the receiver keeps the old path.
#[test]
fn a_non_best_change_behind_the_cursor_is_revisited() {
    const SECOND: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    let rows = 40u32;
    for per_client in [false, true] {
        let mut manager = manager(CREDIT);
        // The sources are sent nothing, so they cannot stall.
        for source in [SOURCE, SECOND] {
            drop(up_with(&mut manager, peer_v4(source), 0, |registration| {
                if let RibUpdate::PeerUp {
                    sendable_families, ..
                } = registration
                {
                    sendable_families.clear();
                }
            }));
        }
        let peer = receiver(0);
        // Add-Path sends both paths; per-client best sends the first
        // candidate that is not the receiver's own, and the receiver is
        // the source of every best.
        let rx = up_with(&mut manager, peer, 0, |registration| {
            if let RibUpdate::PeerUp {
                per_client_best,
                add_path_send_families,
                add_path_send_max,
                ..
            } = registration
            {
                if per_client {
                    *per_client_best = true;
                } else {
                    (*add_path_send_families, *add_path_send_max) = (vec![V4], 2);
                }
            }
        });
        let mut receivers = vec![Receiver {
            peer,
            rx,
            wire: Wire::default(),
        }];
        receivers[0].write();
        receivers[0].wire.markers = 0;
        manager.owe_eor(peer, V4);
        manager.owe_whole_family(peer, UNICAST);
        let best: Vec<Route> = (0..rows)
            .map(|index| {
                let mut route = route(index, 0);
                if per_client {
                    route.peer = peer;
                }
                route
            })
            .collect();
        received_from(&mut manager, best);
        received_from(
            &mut manager,
            (0..rows).map(|index| second_path(index, 1)).collect(),
        );
        receivers[0].write();
        assert!(receivers[0].wire.announced.is_empty(), "owed, not staged");
        for _ in 0..3 {
            tick(&mut manager, &mut receivers);
        }
        assert!(manager.owes_whole(peer, UNICAST), "still mid-walk");
        let passed = receivers[0].wire.announced[0];
        let index = (0..rows).find(|&index| key(index) == passed).unwrap();
        let old = (passed, format!("{:?}", second_path(index, 1).attributes));
        let new = (passed, format!("{:?}", second_path(index, 77).attributes));
        assert!(
            receivers[0].wire.paths.contains(&old),
            "per-client {per_client}: the receiver holds the second path"
        );
        let before = receivers[0].wire.paths.len();
        let best_before = manager.loc_rib.get(&passed).map(|route| route.peer);
        received_from(&mut manager, vec![second_path(index, 77)]);
        assert_eq!(
            manager.loc_rib.get(&passed).map(|route| route.peer),
            best_before,
            "the best did not change"
        );
        drain(&mut manager, &mut receivers);
        assert!(!manager.owes(peer, V4));
        assert!(
            receivers[0].wire.paths[before..].contains(&new),
            "per-client {per_client}: the change behind the cursor is lost"
        );
        assert_eq!(receivers[0].wire.markers, 1);
        assert_eq!(receivers[0].wire.rows_after_marker, 0);
    }
}

/// The markers of one ROUTE-REFRESH answer.
const BRACKET: [(Afi, Safi, rustbgpd_wire::RouteRefreshSubtype); 2] = [
    (V4.0, V4.1, rustbgpd_wire::RouteRefreshSubtype::BoRR),
    (V4.0, V4.1, rustbgpd_wire::RouteRefreshSubtype::EoRR),
];

/// One thing a receiver was sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sent {
    /// Route rows outside a refresh answer (one or more envelopes).
    Rows,
    /// An End-of-RIB outside a refresh answer.
    Eor,
    /// A refresh answer of this many rows: one envelope that carries `BoRR`
    /// and `EoRR` for a peer with RFC 7313 and an End-of-RIB for one
    /// without. The request has no subtype, so the answer is one envelope
    /// for both and the session writes the markers its peer negotiated.
    Answer(usize),
}

/// What `receiver` was sent since it last wrote, in order; it writes it.
fn sent(receiver: &mut Receiver) -> Vec<Sent> {
    let mut out = Vec::new();
    while let Ok(update) = receiver.rx.try_recv() {
        receiver.wire.apply(&update);
        if !update.refresh_markers.is_empty() {
            assert_eq!(update.refresh_markers, BRACKET);
            assert_eq!(update.end_of_rib, [V4]);
            out.push(Sent::Answer(update.announce.len()));
            continue;
        }
        let rows = update.announce.len() + update.unicast_withdrawals().count();
        if rows != 0 && out.last() != Some(&Sent::Rows) {
            out.push(Sent::Rows);
        }
        if update.end_of_rib.contains(&V4) {
            out.push(Sent::Eor);
        }
    }
    out
}

/// Tick until no resync work is left; receiver 0 writes, and what
/// receiver `index` was sent is returned.
fn drain_sent(manager: &mut RibManager, receivers: &mut [Receiver], index: usize) -> Vec<Sent> {
    let mut seen = sent(&mut receivers[index]);
    for _ in 0..100_000 {
        if !manager.resync_tick_pending() {
            return seen;
        }
        manager.resync_dirty_peers_bounded();
        receivers[0].write();
        for item in sent(&mut receivers[index]) {
            if item != Sent::Rows || seen.last() != Some(&Sent::Rows) {
                seen.push(item);
            }
        }
    }
    panic!("the drain does not finish");
}

fn refresh_request(manager: &mut RibManager, peer: PeerId) {
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer,
        session_id: 0,
        afi: V4.0,
        safi: V4.1,
        queued: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    });
}

/// A set kept at its cap keeps its cursor until it is empty. The cursor
/// starts at the head of the list, so the first step of the set finds it
/// caught up; the family stays owed whole while the set has keys, so later
/// passes are logged for the cursor and the set does not grow again. Red
/// when a caught-up cursor ends with keys left in its set: the next passes
/// mark the set (121 keys, nothing logged).
#[test]
fn a_kept_set_keeps_its_cursor_until_it_is_empty() {
    let mut manager = manager(2);
    std::mem::forget(up_session(&mut manager, peer_v4(SOURCE), 0));
    let peer = receiver(0);
    let mut rx = up_session(&mut manager, peer, 0);
    while rx.try_recv().is_ok() {}
    let charge = charge_rows(&mut manager, peer, 2);
    let rows: Vec<_> = (0..120).map(|index| (index, 0)).collect();
    received(&mut manager, &rows, &[]);
    assert!(manager.owes_whole(peer, UNICAST));
    assert_eq!(manager.owed_key_count(peer, UNICAST), 120);
    assert_eq!(manager.owed_rows[0].len(), 0);
    drop(charge);
    // One step of one key; the list is empty, so the cursor has caught up.
    manager.resync_dirty_peers_bounded();
    assert_eq!(manager.owed_key_count(peer, UNICAST), 119);
    assert!(
        manager.owes_whole(peer, UNICAST),
        "the cursor ended with keys left in its set"
    );
    received(&mut manager, &[(120, 0), (121, 0)], &[]);
    assert_eq!(
        (
            manager.owed_key_count(peer, UNICAST),
            manager.owed_rows[0].len()
        ),
        (119, 2),
        "the set is frozen and the pass is logged"
    );
}

/// Churn while a kept set drains: the family flips once, every pass is
/// logged and stages nothing, and the End-of-RIB leaves only when the set
/// is empty and the cursor has caught up. It is checked with the cursor
/// caught up and keys left in the set, and with the set empty and the
/// cursor behind. Red when the cursor ends at the first step: the passes
/// mark the set again and it flips again.
#[test]
fn churn_past_a_kept_set_flips_once_and_the_end_of_rib_waits_for_both() {
    let mut manager = manager(CREDIT);
    std::mem::forget(up_session(&mut manager, peer_v4(SOURCE), 0));
    let peer = receiver(0);
    let mut rx = up_session(&mut manager, peer, 0);
    let mut wire = Wire::default();
    wire.write(&mut rx);
    wire.markers = 0;
    let mut receivers = vec![Receiver { peer, rx, wire }];
    let charge = charge_rows(&mut manager, peer, CREDIT);
    let mut expected: Vec<_> = (0..120).map(|index| (index, 0)).collect();
    received(&mut manager, &expected, &[]);
    assert!(manager.owes_whole(peer, UNICAST));
    assert_eq!(flips(&manager), 1.0);
    manager.owe_eor(peer, V4);
    drop(charge);
    // Caught up (nothing is logged yet) with keys left in the set.
    tick(&mut manager, &mut receivers);
    let mut steps = 1;
    assert_eq!(manager.owed_key_count(peer, UNICAST), 120 - STEP);
    assert!(
        manager.owes_whole(peer, UNICAST),
        "caught up, set not empty"
    );
    assert_eq!(receivers[0].wire.markers, 0);
    while manager.owed_key_count(peer, UNICAST) != 0 {
        let round = u32::try_from(steps).unwrap();
        received(&mut manager, &[(200 + round, 0), (0, round)], &[]);
        expected.push((200 + round, 0));
        expected[0] = (0, round);
        receivers[0].write();
        assert_eq!(
            receivers[0].wire.announced.len(),
            steps * STEP,
            "a pass staged rows toward a receiver owed whole"
        );
        tick(&mut manager, &mut receivers);
        steps += 1;
        assert_eq!(manager.owed_key_count(peer, UNICAST), 120 - steps * STEP);
        assert!(manager.owes_whole(peer, UNICAST), "step {steps}");
        assert_eq!(flips(&manager), 1.0, "step {steps}: flipped again");
        assert_eq!(receivers[0].wire.markers, 0, "step {steps}");
    }
    // The set is empty; the cursor is behind the churn.
    assert_eq!(manager.owed_rows[0].len(), steps, "every pass was logged");
    assert!(manager.eor_pending(peer).contains(&V4));
    drain(&mut manager, &mut receivers);
    assert_eq!(flips(&manager), 1.0);
    assert_settled(&manager, &receivers, &expected, "kept set");
    assert_eq!(receivers[0].wire.uncharged, 0);
}

/// A ROUTE-REFRESH from a receiver the list cap evicted, whose initial
/// End-of-RIB is still owed, waits for the receiver's resync: the request
/// builds nothing in its own turn and stays pending, the tick's unit sends
/// the table and the End-of-RIB, and the answer follows with its markers,
/// once. The request has no subtype: a peer without RFC 7313 reads the
/// same answer's End-of-RIB. Red when the request is answered in its own
/// turn: an answer ahead of the initial End-of-RIB carries no marker
/// (RFC 7313 section 4), and the request is spent on it.
#[test]
fn a_refresh_from_an_evicted_receiver_follows_its_resync_with_its_markers() {
    let (mut manager, mut receivers, expected) = evict_stalled(1);
    let peer = receivers[1].peer;
    receivers[1].write();
    assert!(manager.owed_row_evicted.contains(&peer));
    assert!(manager.eor.owes(peer, V4));
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    refresh_request(&mut manager, peer);
    assert_eq!(sent(&mut receivers[1]), [], "built in the request's turn");
    assert!(manager.pending_refresh.contains_key(&peer), "still asked");
    assert!(manager.owed_row_evicted.contains(&peer));
    assert_eq!(
        drain_sent(&mut manager, &mut receivers, 1),
        [Sent::Rows, Sent::Eor, Sent::Answer(expected.len())]
    );
    assert_eq!(receivers[1].wire.table, table(&expected));
    assert_eq!(
        manager.adj_rib_out_commit_stats.resync_builds - builds,
        1,
        "one resync"
    );
    assert!(!manager.pending_refresh.contains_key(&peer), "answered");
    assert!(!manager.dirty_peers.contains(&peer));
    assert!(manager.owed_row_evicted.is_empty());
    assert!(manager.eor_pending(peer).is_empty());
    // The next request is answered at once, as for any clean receiver.
    refresh_request(&mut manager, peer);
    assert_eq!(
        drain_sent(&mut manager, &mut receivers, 1),
        [Sent::Answer(expected.len())]
    );
}

/// An operator refresh (`RefreshPeerOutbound`) of an evicted receiver
/// builds nothing in its own turn either: the receiver stays the tick's,
/// which sends the forced table and the End-of-RIB once. Red when a forced
/// pass takes an evicted receiver: the command's turn builds its table.
#[test]
fn an_operator_refresh_of_an_evicted_receiver_is_built_by_the_tick() {
    let (mut manager, mut receivers, expected) = evict_stalled(1);
    let peer = receivers[1].peer;
    receivers[1].write();
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    let (reply, mut answer) = oneshot::channel();
    manager.handle_update(RibUpdate::RefreshPeerOutbound { peer, reply });
    assert!(matches!(answer.try_recv(), Ok(Ok(()))));
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
    assert_eq!(sent(&mut receivers[1]), [], "built in the command's turn");
    assert!(manager.owed_row_evicted.contains(&peer));
    assert_eq!(
        drain_sent(&mut manager, &mut receivers, 1),
        [Sent::Rows, Sent::Eor]
    );
    assert_eq!(receivers[1].wire.table, table(&expected));
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds - builds, 1);
    assert!(!manager.force_outbound_peers.contains(&peer));
    assert!(!manager.dirty_peers.contains(&peer));
    assert!(manager.owed_row_evicted.is_empty());
}

/// An operator refresh mid-walk is a forced resync: it covers the family,
/// so the cursor and its set are dropped, the list is freed and the
/// End-of-RIB follows the table, once. Red when the resync leaves the
/// family owed: the cursor walks on behind the End-of-RIB.
#[test]
fn an_operator_refresh_mid_walk_resyncs_and_drops_the_cursor() {
    let rows = 40u32;
    let (mut manager, mut receivers) = owing(1, rows, CREDIT);
    tick(&mut manager, &mut receivers);
    let peer = receivers[0].peer;
    assert_eq!(receivers[0].wire.table.len(), STEP);
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    let (reply, mut answer) = oneshot::channel();
    manager.handle_update(RibUpdate::RefreshPeerOutbound { peer, reply });
    assert!(matches!(answer.try_recv(), Ok(Ok(()))));
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds - builds, 1);
    assert!(!manager.owes(peer, V4), "the resync covered the family");
    assert_eq!(manager.owed_rows[0].len(), 0);
    assert_eq!(
        drain_sent(&mut manager, &mut receivers, 0),
        [Sent::Rows, Sent::Eor]
    );
    let all: Vec<_> = (0..rows).map(|index| (index, 0)).collect();
    assert_eq!(receivers[0].wire.table, table(&all));
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds - builds, 1);
}

/// The list is cut back to its cap, twice the peak plus the slack, at the
/// end of every pass (so it never holds more than the cap plus one pass,
/// three times the peak plus the slack), with stalled cursors more than
/// one trim apart: `count` receivers start cursors `gap` keys apart and
/// read nothing while `fresh` new keys a pass rotate through the table.
/// Returns the longest list a pass left and the cap it had then. Red when
/// an eviction that leaves more than one trim of entries behind the next
/// cursor ends the cap's work for that pass: one receiver is evicted a
/// pass and the list outgrows the cap, then the bound.
fn stalled_staggered(count: u8, gap: u32, fresh: u32) -> (usize, usize) {
    let mut manager = manager(1 << 20);
    std::mem::forget(up_session(&mut manager, peer_v4(SOURCE), 0));
    let mut rxs: Vec<_> = (0..count)
        .map(|index| {
            let peer = receiver(index);
            (peer, up_sized(&mut manager, peer, 0, 1 << 16, |_| {}))
        })
        .collect();
    let (mut next, mut table, mut peak) = (0u32, 0usize, 0usize);
    for holder in 0..usize::from(count) {
        let rows: Vec<_> = (next..next + gap).map(|index| (index, 0)).collect();
        next += gap;
        received(&mut manager, &rows, &[]);
        table += gap as usize;
        if holder > 0 {
            peak = peak.max(table + gap as usize);
        }
        // Those without a cursor yet read; the rest never do.
        for (_, rx) in &mut rxs[holder..] {
            while rx.try_recv().is_ok() {}
        }
        manager.owe_whole_family(rxs[holder].0, UNICAST);
    }
    let mut previous: Vec<u32> = vec![];
    let (mut longest, mut cap_then) = (0, 0);
    for _ in 0..200 {
        let rows: Vec<_> = (next..next + fresh).map(|index| (index, 0)).collect();
        let gone = std::mem::replace(&mut previous, (next..next + fresh).collect());
        next += fresh;
        received(&mut manager, &rows, &gone);
        table = table + fresh as usize - gone.len();
        peak = peak.max(table + fresh as usize + gone.len());
        let (len, cap) = (manager.owed_rows[0].len(), 2 * peak + 4 * CHUNK_ROWS);
        assert!(len <= cap, "{len} keys in the list, cap {cap}");
        if len > longest {
            (longest, cap_then) = (len, cap);
        }
        if manager.owed_row_evicted.len() == usize::from(count) && !manager.owed_rows_trimming() {
            return (longest, cap_then);
        }
    }
    panic!("the stalled receivers were never all evicted");
}

#[test]
fn stalled_cursors_more_than_a_trim_apart_keep_the_list_under_its_bound() {
    let (longest, cap) = stalled_staggered(8, 4100, 20_000);
    assert!(longest > cap / 2, "the list did grow: {longest}");
}

/// The cap counts what each cursor still has to read, exactly: of two
/// stalled receivers eight keys apart, the pass that leaves the cap plus
/// eight keys after the slower one evicts it and keeps the other, which
/// has the cap after it; the list is left at the cap. Red when a receiver
/// with exactly the cap after its cursor is evicted too.
#[test]
fn a_receiver_with_exactly_the_cap_after_its_cursor_is_kept() {
    const FRESH: u32 = 515;
    let (mut manager, mut receivers) = owing(2, 16, CREDIT);
    // Receiver 0 never has credit; receiver 1 takes one step of eight
    // keys, then reads nothing.
    let stalled = charge_rows(&mut manager, receivers[0].peer, CREDIT);
    for _ in 0..2 {
        manager.resync_dirty_peers_bounded();
    }
    assert_eq!(manager.outbound_credit_rows(receivers[1].peer), STEP);
    // The table holds the 16 rows and one pass's fresh ones, and a pass
    // carries those and the ones it withdraws.
    let cap = 2 * (16 + 3 * FRESH as usize) + 4 * CHUNK_ROWS;
    for pass in 1..=14u32 {
        let base = 1000 + pass * FRESH;
        let fresh: Vec<_> = (base..base + FRESH).map(|index| (index, 0)).collect();
        let gone: Vec<u32> = if pass == 1 {
            vec![]
        } else {
            (base - FRESH..base).collect()
        };
        received(&mut manager, &fresh, &gone);
        if pass < 14 {
            assert_eq!(manager.owed_rows[0].len(), 16 + (pass * FRESH) as usize);
            assert_eq!(fallbacks(&manager), 0.0, "pass {pass}");
        }
    }
    // The last pass left the cap plus eight keys after receiver 0.
    assert_eq!(fallbacks(&manager), 1.0, "the slower receiver only");
    assert!(manager.owed_row_evicted.contains(&receivers[0].peer));
    assert!(manager.owes_whole(receivers[1].peer, UNICAST));
    assert!(!manager.dirty_peers.contains(&receivers[1].peer));
    assert_eq!(manager.owed_rows[0].len(), cap, "cut back to the cap");
    drop(stalled);
    drain(&mut manager, &mut receivers);
    for receiver in &receivers {
        assert_eq!(receiver.wire.markers, 1);
        assert_eq!(receiver.wire.table.len(), 16 + FRESH as usize);
    }
    assert_eq!(fallbacks(&manager), 1.0);
}

/// An evicted receiver whose unit is refused (here a live whole-table
/// operation) is no backlog: with nothing else pending the tick reports
/// none, so the timer keeps its ordinary interval, and the unit runs on
/// the tick after the operation ends. Red when the tick reports a backlog
/// for every evicted receiver it selected: it re-arms at the backlog
/// cadence for as long as the receiver stays blocked.
#[test]
fn a_refused_evicted_receiver_leaves_the_tick_at_its_ordinary_interval() {
    let (mut manager, mut receivers, expected) = evict_stalled(1);
    let peer = receivers[1].peer;
    receivers[1].write();
    let latch = manager
        .begin_outbound_operation(peer, 1)
        .expect("a live whole-table operation");
    // The receiver that keeps up finishes: nothing else is pending.
    for _ in 0..1000 {
        manager.resync_dirty_peers_bounded();
        receivers[0].write();
    }
    assert!(!manager.owes(receivers[0].peer, V4));
    assert_eq!(manager.owed_rows[0].len(), 0);
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    assert!(
        !manager.resync_dirty_peers_bounded(),
        "a refused unit was reported as a backlog"
    );
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
    assert!(manager.dirty_peers.contains(&peer));
    assert!(manager.owed_row_evicted.contains(&peer));
    drop(latch);
    assert!(manager.resync_dirty_peers_bounded(), "the unit ran");
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds - builds, 1);
    assert!(manager.owed_row_evicted.is_empty());
    drain(&mut manager, &mut receivers);
    for receiver in &mut receivers {
        receiver.write();
    }
    assert_settled(&manager, &receivers, &expected, "refused, then run");
}

/// The dirty peer the next resync tick selects first.
fn next_unit(manager: &RibManager) -> PeerId {
    let cursor = manager.dirty_resync_cursor;
    let after = manager
        .dirty_peers
        .iter()
        .find(|peer| cursor.is_none_or(|cursor| **peer > cursor));
    *after
        .or_else(|| manager.dirty_peers.iter().next())
        .expect("a dirty peer")
}

/// Commits of `peer` refused for want of an exact export encoder.
fn missing_encoder_refusals(manager: &RibManager, peer: PeerId) -> f64 {
    let label = peer.label();
    manager
        .metrics
        .registry()
        .gather()
        .into_iter()
        .filter(|family| family.name() == "bgp_outbound_commit_refusals_total")
        .flat_map(|family| family.get_metric().to_vec())
        .filter(|metric| {
            let labels = metric.get_label();
            labels
                .iter()
                .any(|l| l.name() == "peer" && l.value() == label)
                && labels
                    .iter()
                    .any(|l| l.name() == "reason" && l.value() == "missing_encoder")
        })
        .map(|metric| metric.get_counter().get_value())
        .sum()
}

/// Work count: a unit refused after its whole table was built (its commit
/// finds no exact export encoder) still ends the tick, whatever the poll
/// budget says. The tick that refuses the first of three evicted receivers
/// builds that table alone; the other two are built one a tick after it,
/// and the refused receiver stays dirty and marked until its commit is
/// admitted. Red when only an admitted unit ends the tick: the refused
/// unit leaves the receiver dirty, and the same tick goes on to build the
/// next evicted receiver's table.
#[test]
fn a_unit_refused_after_its_build_still_ends_the_tick() {
    const STALLED: usize = 3;
    let (mut manager, mut receivers, expected) = evict_stalled(3);
    manager.flush_poll_budget = Duration::from_secs(3600);
    // The receiver that keeps up takes no step meanwhile.
    let charge = charge_rows(&mut manager, receivers[0].peer, CREDIT);
    let refused = next_unit(&manager);
    assert!(manager.owed_row_evicted.contains(&refused));
    let encoder = manager
        .peer_export_encoders
        .remove(&refused)
        .expect("an exact export encoder");
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    manager.resync_dirty_peers_bounded();
    assert_eq!(
        manager.adj_rib_out_commit_stats.resync_builds - builds,
        1,
        "one whole table a tick, admitted or not"
    );
    assert_eq!(missing_encoder_refusals(&manager, refused), 1.0);
    assert_eq!(manager.owed_row_evicted.len(), STALLED, "none was admitted");
    assert!(manager.dirty_peers.contains(&refused));
    // The other two follow, one a tick; the refused receiver waits.
    for unit in 1..STALLED {
        manager.resync_dirty_peers_bounded();
        assert_eq!(
            manager.adj_rib_out_commit_stats.resync_builds - builds,
            1 + unit
        );
        assert_eq!(manager.owed_row_evicted.len(), STALLED - unit);
        assert!(manager.owed_row_evicted.contains(&refused));
    }
    assert_eq!(missing_encoder_refusals(&manager, refused), 1.0);
    manager.peer_export_encoders.insert(refused, encoder);
    drop(charge);
    drain(&mut manager, &mut receivers);
    assert!(manager.owed_row_evicted.is_empty());
    for receiver in &mut receivers {
        receiver.write();
    }
    assert_settled(&manager, &receivers, &expected, "refused after its build");
}

/// A unit refused after its build waits for the ordinary retry, as any
/// dirty peer whose send failed. With nothing else pending the tick reports
/// no backlog, so the timer re-arms at its ordinary interval, and each
/// retry builds the table once more until the commit is admitted. Red when
/// a built-then-refused unit is reported as a backlog: the timer re-arms at
/// the backlog cadence and rebuilds the receiver's whole table at that
/// cadence for as long as the refusal lasts.
#[test]
fn a_unit_refused_after_its_build_retries_at_the_ordinary_interval() {
    let (mut manager, mut receivers, expected) = evict_stalled(1);
    let peer = receivers[1].peer;
    receivers[1].write();
    // The receiver that keeps up finishes first: nothing else is pending.
    let latch = manager
        .begin_outbound_operation(peer, 1)
        .expect("a live whole-table operation");
    for _ in 0..1000 {
        manager.resync_dirty_peers_bounded();
        receivers[0].write();
    }
    assert!(!manager.owes(receivers[0].peer, V4));
    assert_eq!(manager.owed_rows[0].len(), 0);
    drop(latch);
    let encoder = manager
        .peer_export_encoders
        .remove(&peer)
        .expect("an exact export encoder");
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    for (retry, refusals) in [(1, 1.0), (2, 2.0)] {
        assert!(
            !manager.resync_dirty_peers_bounded(),
            "a unit refused after its build was reported as a backlog"
        );
        assert_eq!(
            manager.adj_rib_out_commit_stats.resync_builds - builds,
            retry
        );
        assert_eq!(missing_encoder_refusals(&manager, peer), refusals);
        assert!(manager.resync_tick_pending(), "the receiver is retried");
        assert!(manager.dirty_peers.contains(&peer));
        assert!(manager.owed_row_evicted.contains(&peer));
    }
    manager.peer_export_encoders.insert(peer, encoder);
    assert!(manager.resync_dirty_peers_bounded(), "the unit ran");
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds - builds, 3);
    assert!(manager.owed_row_evicted.is_empty());
    drain(&mut manager, &mut receivers);
    for receiver in &mut receivers {
        receiver.write();
    }
    assert_settled(
        &manager,
        &receivers,
        &expected,
        "refused after its build, then run",
    );
}

/// Work count: receivers tied at one position are evicted in one pass
/// with a fixed number of scans of the owing receivers, whatever their
/// number. Red when each eviction looks for the slowest receiver and trims
/// the list again: the pass visits them once per evicted receiver.
#[test]
fn tied_evictions_scan_the_owing_receivers_a_fixed_number_of_times() {
    for count in [75u32, 300] {
        let mut manager = manager(CREDIT);
        std::mem::forget(up_session(&mut manager, peer_v4(SOURCE), 0));
        let _rxs: Vec<_> = (0..count)
            .map(|index| {
                let peer = peer_v4(Ipv4Addr::from(0x0b00_0000 + index));
                let rx = up_sized(&mut manager, peer, 0, 64, |_| {});
                manager.owe_whole_family(peer, UNICAST);
                rx
            })
            .collect();
        let receivers = count as usize;
        // Nobody reads while fresh keys rotate through the table.
        let mut evicted = false;
        for round in 0..64u32 {
            let base = round * 1024;
            let fresh: Vec<_> = (base..base + 1024).map(|index| (index, 0)).collect();
            let gone: Vec<u32> = (base.saturating_sub(1024)..base).collect();
            let before = (
                fallbacks(&manager),
                manager.adj_rib_out_commit_stats.owed_peer_scans,
            );
            received(&mut manager, &fresh, &gone);
            if fallbacks(&manager) > before.0 {
                assert_eq!(
                    fallbacks(&manager) - before.0,
                    f64::from(count),
                    "every tied receiver in one pass"
                );
                let scans = manager.adj_rib_out_commit_stats.owed_peer_scans - before.1;
                assert!(
                    scans <= 16 * receivers,
                    "{scans} receiver visits to evict {receivers} tied receivers"
                );
                evicted = true;
                break;
            }
        }
        assert!(evicted, "{count} receivers were never evicted");
        assert_eq!(manager.owed_row_evicted.len(), receivers);
    }
}

/// The list its last cursor left empties on the resync tick alone, a
/// bounded trim a tick, with no pass to log a key. Red when a pending trim
/// does not keep the tick armed: the list stays until the next pass.
#[test]
fn a_list_left_by_its_last_cursor_empties_on_the_tick_alone() {
    let (mut manager, receivers) = owing(1, 9000, CREDIT);
    manager.handle_update(RibUpdate::PeerDown {
        peer: receivers[0].peer,
        session_id: 0,
    });
    assert_eq!(manager.owed_rows[0].len(), 9000 - 4 * CHUNK_ROWS);
    let mut ticks = 0;
    while manager.resync_tick_pending() {
        manager.resync_dirty_peers_bounded();
        ticks += 1;
        assert!(ticks <= 2, "the list does not empty");
    }
    assert_eq!((ticks, manager.owed_rows[0].len()), (2, 0));
}

/// A tick trims the list even when no owing receiver can take a step: one
/// receiver owes a key and has no credit, and the list the last cursor
/// left still empties in two ticks. Red when the tick's shortcut for
/// owing receivers that only wait for credit ignores a pending trim.
#[test]
fn a_tick_trims_the_list_while_no_owing_receiver_can_step() {
    let (mut manager, receivers) = owing(1, 9000, CREDIT);
    let waiting = receiver(7);
    let mut rx = up_session(&mut manager, waiting, 0);
    while rx.try_recv().is_ok() {}
    let _charge = charge_rows(&mut manager, waiting, CREDIT);
    received(&mut manager, &[(5, 1)], &[]);
    assert_eq!(manager.owed_key_count(waiting, UNICAST), 1);
    assert!(!manager.owes_whole(waiting, UNICAST));
    manager.handle_update(RibUpdate::PeerDown {
        peer: receivers[0].peer,
        session_id: 0,
    });
    assert!(manager.owed_rows_trimming());
    assert!(!manager.owing_tick_due(), "no receiver can step");
    let mut ticks = 0;
    while manager.owed_rows[0].len() != 0 {
        manager.resync_dirty_peers_bounded();
        ticks += 1;
        assert!(ticks <= 2, "the list does not empty");
    }
    assert_eq!(manager.owed_key_count(waiting, UNICAST), 1, "still owed");
}
