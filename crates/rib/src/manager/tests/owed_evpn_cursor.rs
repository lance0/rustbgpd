//! The EVPN row cursor (ADR-0099 amendment, slice 1b): a private receiver
//! that owes EVPN whole reads the shared list of the keys EVPN mutations
//! carried since its debt began, in bounded steps charged against its
//! outbound credit, and its End-of-RIB leaves when it has caught up.

mod private_orf;
mod release_filters;
mod release_hold;
mod release_stage;

use std::collections::{BTreeMap, BTreeSet};

use rustbgpd_wire::EvpnRouteKey;

use super::super::eor_hold::{EorHold, EorTrigger};
use super::super::outbound_owing::OwedFamily;
use super::*;
use crate::ingest_budget::IngestBudget;
use crate::outbound_credit::CHUNK_ROWS;

const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const WAITER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const EVPN: (Afi, Safi) = (Afi::L2Vpn, Safi::Evpn);
const V4: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const RTC: (Afi, Safi) = (Afi::Ipv4, Safi::RtConstrain);
const FAMILY: OwedFamily = OwedFamily::EVPN;
/// Rows of outbound credit: a step with the whole credit free takes
/// `CREDIT / 2` keys.
const CREDIT: usize = 16;
const STEP: usize = CREDIT / 2;

/// A manager whose peers stay ungrouped (private EVPN), one receiver step
/// per resync tick.
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

/// A session of `families` on an outbound channel of `channel` envelopes.
fn up_sized(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
    channel: usize,
    families: &[(Afi, Safi)],
) -> mpsc::Receiver<OutboundRouteUpdate> {
    up_sized_with_orf(manager, peer, session_id, channel, families, &[])
}

fn up_sized_with_orf(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
    channel: usize,
    families: &[(Afi, Safi)],
    orf_recv: &[(Afi, Safi)],
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, output) = mpsc::channel(channel);
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
        sendable_families: families.to_vec(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: orf_recv.to_vec(),
        negotiated_llgr_families: Vec::new(),
    });
    output
}

fn receiver(index: u8) -> PeerId {
    peer_v4(Ipv4Addr::new(10, 0, 9, index + 1))
}

/// EVPN row `index` at payload `variant`, carrying the Route Targets `rts`.
fn route_rt(index: u32, variant: u32, rts: &[u16]) -> EvpnRibRoute {
    let mut route = make_evpn_imet(SOURCE, index);
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::LocalPref(100),
        PathAttribute::Med(variant),
    ];
    if !rts.is_empty() {
        attributes.push(PathAttribute::ExtendedCommunities(
            rts.iter().map(|&value| rt(value)).collect(),
        ));
    }
    route.attributes = AttrSet::new(attributes);
    route
}

fn route(index: u32, variant: u32) -> EvpnRibRoute {
    route_rt(index, variant, &[])
}

fn key(index: u32) -> EvpnRouteKey {
    route(index, 0).key()
}

fn unicast_route(index: u32) -> Route {
    let mut route = make_indexed_route(index + 1, SOURCE);
    route.peer = peer_v4(SOURCE);
    route
}

fn received_routes(manager: &mut RibManager, announce: Vec<EvpnRibRoute>, withdraw: &[u32]) {
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: announce,
        evpn_withdrawn: withdraw.iter().map(|&index| key(index)).collect(),
        validated_with: None,
    });
    drain_route_chunks(manager);
}

/// The source announces `announce` (row, variant) and withdraws `withdraw`.
fn received(manager: &mut RibManager, announce: &[(u32, u32)], withdraw: &[u32]) {
    let announce = announce
        .iter()
        .map(|&(index, variant)| route(index, variant))
        .collect();
    received_routes(manager, announce, withdraw);
}

fn received_unicast(manager: &mut RibManager, rows: std::ops::Range<u32>) {
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: rows.map(unicast_route).collect(),
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(manager);
}

/// One thing a receiver was sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sent {
    /// EVPN rows outside a refresh answer (one or more envelopes).
    Rows,
    /// An EVPN End-of-RIB outside a refresh answer.
    Eor,
    /// A refresh answer of this many rows, carrying `BoRR` and `EoRR`.
    Answer(usize),
}

/// The markers of one EVPN ROUTE-REFRESH answer.
const BRACKET: [(Afi, Safi, rustbgpd_wire::RouteRefreshSubtype); 2] = [
    (EVPN.0, EVPN.1, rustbgpd_wire::RouteRefreshSubtype::BoRR),
    (EVPN.0, EVPN.1, rustbgpd_wire::RouteRefreshSubtype::EoRR),
];

/// What one receiver's session has written.
#[derive(Default)]
struct Wire {
    /// Each EVPN row held, with its attributes.
    table: BTreeMap<EvpnRouteKey, String>,
    announced: Vec<EvpnRouteKey>,
    withdrawn: Vec<EvpnRouteKey>,
    /// EVPN End-of-RIB markers outside a refresh answer.
    markers: usize,
    /// EVPN rows written after the first End-of-RIB, outside an answer.
    rows_after_marker: usize,
    /// Route-bearing envelopes that held no credit, or an operation latch.
    uncharged: usize,
    latched: usize,
    /// Most rows one envelope carried.
    envelope_rows_max: usize,
    /// What was sent, in order.
    sent: Vec<Sent>,
    /// IPv4 unicast rows held, its markers, and rows after the first.
    unicast: usize,
    unicast_table: BTreeSet<Prefix>,
    unicast_markers: usize,
    unicast_rows_after_marker: usize,
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
        let answer = !update.refresh_markers.is_empty();
        let rows = update.evpn_announce.len() + update.evpn_withdraw.len();
        let unicast = update.announce.len() + update.unicast_withdrawals().count();
        if rows + unicast != 0 && !answer {
            self.uncharged += usize::from(update.credit.is_none());
            self.latched += usize::from(update.latch.is_some());
            self.envelope_rows_max = self.envelope_rows_max.max(rows + unicast);
        }
        if rows != 0 && !answer {
            if self.markers != 0 {
                self.rows_after_marker += rows;
            }
            if self.sent.last() != Some(&Sent::Rows) {
                self.sent.push(Sent::Rows);
            }
        }
        if self.unicast_markers != 0 {
            self.unicast_rows_after_marker += unicast;
        }
        self.unicast += update.announce.len();
        self.unicast -= update.unicast_withdrawals().count();
        for (prefix, _) in update.unicast_withdrawals() {
            self.unicast_table.remove(prefix);
        }
        for route in update.announce.iter() {
            self.unicast_table.insert(route.prefix);
        }
        for key in &update.evpn_withdraw {
            assert!(
                self.table.remove(key).is_some(),
                "withdrawal of {key:?}, which the receiver does not hold"
            );
            self.withdrawn.push(*key);
        }
        for route in update.evpn_announce.iter() {
            self.table
                .insert(route.key(), format!("{:?}", route.attributes));
            self.announced.push(route.key());
        }
        if answer {
            assert_eq!(update.refresh_markers, BRACKET);
            self.sent.push(Sent::Answer(update.evpn_announce.len()));
            return;
        }
        for family in &update.end_of_rib {
            if *family == EVPN {
                self.markers += 1;
                self.sent.push(Sent::Eor);
            } else if *family == V4 {
                self.unicast_markers += 1;
            }
        }
    }

    fn count(&self, index: u32) -> (usize, usize) {
        let key = key(index);
        (
            self.announced.iter().filter(|k| **k == key).count(),
            self.withdrawn.iter().filter(|k| **k == key).count(),
        )
    }
}

/// The table a receiver must end with: rows `(index, variant)`.
fn table(rows: &[(u32, u32)]) -> BTreeMap<EvpnRouteKey, String> {
    rows.iter()
        .map(|&(index, variant)| {
            let route = route(index, variant);
            (route.key(), format!("{:?}", route.attributes))
        })
        .collect()
}

fn end_of_rib(manager: &mut RibManager, peer: PeerId, session_id: u64, family: (Afi, Safi)) {
    manager.handle_update(RibUpdate::EndOfRib {
        peer,
        session_id,
        afi: family.0,
        safi: family.1,
    });
}

fn selected_evpn(manager: &RibManager) -> BTreeMap<EvpnRouteKey, String> {
    manager
        .loc_rib
        .iter_evpn()
        .map(|route| (route.key(), format!("{:?}", route.attributes)))
        .collect()
}

fn assert_idle(manager: &RibManager, receivers: &[Receiver]) {
    for receiver in receivers {
        assert!(
            manager.eor_pending(receiver.peer).is_empty(),
            "{}",
            receiver.peer
        );
        assert!(manager.owing(receiver.peer).is_none(), "{}", receiver.peer);
        assert!(!manager.dirty_peers.contains(&receiver.peer));
        assert!(!manager.owed_row_evicted.contains(&receiver.peer));
    }
    assert_eq!(manager.owed_evpn_rows.len(), 0);
    assert!(manager.owed_rows.iter().all(|list| list.len() == 0));
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

    /// A receiver whose session came up with an empty table: it has
    /// written its initial markers, which are not counted.
    fn up(
        manager: &mut RibManager,
        peer: PeerId,
        channel: usize,
        families: &[(Afi, Safi)],
    ) -> Self {
        let mut rx = up_sized(manager, peer, 0, channel, families);
        let mut wire = Wire::default();
        wire.write(&mut rx);
        assert_eq!(wire.markers, 1, "the empty initial table's End-of-RIB");
        Self {
            peer,
            rx,
            wire: Wire::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiverState {
    Clean,
    Keyed,
    Cursor,
    Evicted,
    Dirty,
}

impl ReceiverState {
    const ALL: [Self; 5] = [
        Self::Clean,
        Self::Keyed,
        Self::Cursor,
        Self::Evicted,
        Self::Dirty,
    ];
}

/// Stop reading after admitting rows 0..8. Except in the clean control,
/// row 5 is withdrawn before the hold while the receiver still holds it.
fn prepare_receiver(manager: &mut RibManager, subject: &Receiver, state: ReceiverState) {
    let peer = subject.peer;
    assert!(subject.wire.table.contains_key(&key(5)));
    assert!(!manager.owes(peer, EVPN));
    assert!(!manager.dirty_peers.contains(&peer));
    if state == ReceiverState::Clean {
        return;
    }
    if state == ReceiverState::Dirty {
        let sender = &manager.outbound_peers[&peer];
        while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
        regroup(manager, peer, Some(permit_all()));
        received(manager, &[], &[5]);
        assert!(manager.dirty_peers.contains(&peer));
        assert!(!manager.owed_row_evicted.contains(&peer));
        return;
    }

    // Distinct payloads spend credit without increasing the keyed debt.
    for variant in 1..=16 {
        received(manager, &[(0, variant), (1, variant), (2, variant)], &[]);
        if manager.owes(peer, EVPN) {
            break;
        }
    }
    received(manager, &[], &[5]);
    assert!(manager.owed_key_count(peer, FAMILY) > 0 && !manager.owes_whole(peer, FAMILY));
    if state == ReceiverState::Keyed {
        return;
    }

    // Rotate disjoint batches so the live table stays small while the
    // unread receiver first crosses the kept-key cap, then the list cap.
    let mut previous = Vec::new();
    for round in 0..256 {
        let base = 1000 + round * 64;
        let rows: Vec<_> = (base..base + 64).map(|i| (i, 0)).collect();
        received(manager, &rows, &previous);
        if state == ReceiverState::Cursor && manager.owes_whole(peer, FAMILY) {
            assert!(!manager.owed_row_evicted.contains(&peer));
            return;
        }
        if state == ReceiverState::Evicted && manager.owed_row_evicted.contains(&peer) {
            return;
        }
        previous = (base..base + 64).collect();
    }
    panic!("receiver never reached {state:?}");
}

/// `receivers` receivers that owe their End-of-RIB and EVPN whole (as a
/// selection release leaves them), then one mutation carrying rows
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
    owing_from(manager(credit), &[EVPN], receivers, rows, channel)
}

/// [`owing_sized`] on `manager`, each receiver negotiating `families`.
fn owing_from(
    mut manager: RibManager,
    families: &[(Afi, Safi)],
    receivers: u8,
    rows: u32,
    channel: usize,
) -> (RibManager, Vec<Receiver>) {
    std::mem::forget(up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]));
    let mut receivers: Vec<Receiver> = (0..receivers)
        .map(|index| {
            let receiver = Receiver::up(&mut manager, receiver(index), channel, families);
            assert!(manager.evpn_grouped_member_of(receiver.peer).is_none());
            manager.owe_eor(receiver.peer, EVPN);
            manager.owe_whole_family(receiver.peer, FAMILY);
            receiver
        })
        .collect();
    let all: Vec<_> = (0..rows).map(|index| (index, 0)).collect();
    received(&mut manager, &all, &[]);
    for receiver in &mut receivers {
        receiver.write();
        assert!(receiver.wire.announced.is_empty(), "owed, not staged");
        assert!(manager.owes_whole(receiver.peer, FAMILY));
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

fn fallbacks(manager: &RibManager) -> f64 {
    manager
        .metrics
        .registry()
        .gather()
        .into_iter()
        .filter(|family| family.name() == "bgp_rib_outbound_owing_fallback_total")
        .flat_map(|family| family.get_metric().to_vec())
        .map(|metric| metric.get_counter().get_value())
        .sum()
}

/// Drain steps the step histogram recorded under `scope`.
fn steps_observed(manager: &RibManager, scope: &str) -> u64 {
    histogram_sample_counts_by_label(
        &manager.metrics,
        "bgp_rib_outbound_owed_drain_step_seconds",
        "scope",
    )[scope]
}

/// Eviction recoveries the histogram recorded: processed, then refused at
/// the commit.
fn recoveries_observed(manager: &RibManager) -> (u64, u64) {
    let samples = histogram_sample_counts_by_label(
        &manager.metrics,
        "bgp_rib_outbound_eviction_recovery_seconds",
        "outcome",
    );
    (samples["processed"], samples["commit_refused"])
}

/// Tick until no resync work is left; every session writes what it was
/// sent.
fn drain(manager: &mut RibManager, receivers: &mut [Receiver]) {
    for _ in 0..100_000 {
        for receiver in receivers.iter_mut() {
            receiver.write();
        }
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
        assert!(!manager.owes(receiver.peer, EVPN), "{case}");
        assert!(!manager.dirty_peers.contains(&receiver.peer), "{case}");
    }
    assert_eq!(manager.owed_evpn_rows.len(), 0, "{case}: the list is freed");
}

fn all(rows: u32) -> Vec<(u32, u32)> {
    (0..rows).map(|index| (index, 0)).collect()
}

/// Work count: an EVPN debt of N keys drains in ceil(N / B) steps per
/// receiver, none reading more than B keys, and never more than one
/// 1,024-key chunk however much credit is free. Red with an unbounded
/// step: one step of N keys per receiver.
#[test]
fn an_evpn_debt_drains_in_bounded_steps() {
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
        assert_settled(&manager, &receivers, &all(count), "bounded steps");
        for receiver in &receivers {
            assert_eq!(receiver.wire.announced.len(), rows, "each row once");
        }
    }
    let rows = 2 * u32::try_from(CHUNK_ROWS).unwrap() + 5;
    let (mut manager, mut receivers) = owing(1, rows, 1 << 20);
    drain(&mut manager, &mut receivers);
    let stats = manager.adj_rib_out_commit_stats;
    assert_eq!(stats.owed_drain_step_rows_max, CHUNK_ROWS);
    assert_eq!(stats.owed_drain_steps, 3, "ceil(N / 1,024) steps");
    assert_eq!(receivers[0].wire.envelope_rows_max, CHUNK_ROWS);
    assert_settled(&manager, &receivers, &all(rows), "one chunk a step");
}

/// Credit: every envelope of the drain is an ordinary one charged against
/// the receiver's credit, no whole-table operation is taken (and a live
/// one is not waited for), and a receiver that reads nothing is queued at
/// most its credit plus one step, with its End-of-RIB still owed. Every
/// step is observed under the histogram's `cursor` scope and none under
/// `whole`. Red when a waiting End-of-RIB absorbs the family: one uncharged
/// operation of N rows, observed as a `whole` step.
#[test]
fn an_evpn_cursor_drain_is_charged_and_takes_no_operation() {
    let rows = 100;
    let (mut manager, mut receivers) = owing(2, rows, CREDIT);
    let operation = manager
        .begin_outbound_operation(receivers[0].peer, 1)
        .unwrap();
    assert!(!manager.owing_latch_pending(), "a cursor needs no latch");
    // Receiver 1 never reads.
    for _ in 0..50 {
        manager.resync_dirty_peers_bounded();
        receivers[0].write();
        assert!(!manager.outbound_operation_live(receivers[1].peer));
    }
    drop(operation);
    let stalled = receivers[1].peer;
    assert!(
        manager.outbound_credit_rows(stalled) <= CREDIT + STEP,
        "{} rows queued toward a receiver that reads nothing",
        manager.outbound_credit_rows(stalled)
    );
    assert!(manager.owes(stalled, EVPN));
    assert!(manager.eor_pending(stalled).contains(&EVPN));
    assert!(!manager.dirty_peers.contains(&stalled));
    assert!(
        !manager.owes(receivers[0].peer, EVPN),
        "the reader finished"
    );
    drain(&mut manager, &mut receivers);
    assert_settled(&manager, &receivers, &all(rows), "charged");
    assert_eq!(
        steps_observed(&manager, "whole") + steps_observed(&manager, "keyed"),
        0,
        "an EVPN cursor's steps are observed as cursor steps only"
    );
    assert!(steps_observed(&manager, "cursor") >= 2 * u64::from(rows) / STEP as u64);
    for receiver in &receivers {
        assert_eq!(receiver.wire.uncharged, 0, "every envelope is charged");
        assert_eq!(receiver.wire.latched, 0, "no operation latch");
        assert!(receiver.wire.envelope_rows_max <= STEP);
        assert_eq!(receiver.wire.announced.len(), rows as usize, "once each");
    }
}

/// A hold release in the middle of a walk sends no row and no marker for a
/// family whose cursor is behind. Red when the cursor is not counted as
/// owed keys: the End-of-RIB leaves ahead of the rest of the table.
#[test]
fn a_hold_release_mid_walk_keeps_the_evpn_end_of_rib_and_stages_nothing() {
    let (mut manager, mut receivers) = owing(1, 40, CREDIT);
    tick(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);
    let peer = receivers[0].peer;
    assert_eq!(receivers[0].wire.announced.len(), 2 * STEP);
    let stagings = manager.outbound_stagings(peer);
    manager.release_eor_hold(peer, EorHold::Grace, EorTrigger::Release);
    manager.defer_eor_settle(peer);
    manager.settle_eor_after_pass();
    manager.settle_free_eor(peer);
    receivers[0].write();
    assert_eq!(manager.outbound_stagings(peer), stagings, "nothing staged");
    assert_eq!(receivers[0].wire.announced.len(), 2 * STEP);
    assert_eq!(receivers[0].wire.markers, 0, "the marker waits");
    drain(&mut manager, &mut receivers);
    assert_settled(&manager, &receivers, &all(40), "hold release");
}

/// Contract (move before and after the cursor): a key whose payload
/// changes behind the cursor is visited again; one that changes ahead is
/// visited once, at its newer state; an admitted key is withdrawn once and
/// an unread one never announced; a withdrawn key that returns unchanged
/// sends nothing; a second owe mid-walk leaves the position alone. A fast
/// receiver and one that lags a step behind both end exact, with no row
/// after their End-of-RIB. Mutations are logged once however many
/// receivers hold a cursor. Red when a key already in the list is not
/// moved to the back, and when a second owe restarts the position.
#[test]
fn evpn_changes_before_and_after_the_cursor_reach_each_receiver_at_their_newest_state() {
    let rows = 40u32;
    let (mut manager, mut receivers) = owing(2, rows, CREDIT);
    // Receiver 0 takes two steps, receiver 1 one.
    for _ in 0..3 {
        tick(&mut manager, &mut receivers);
    }
    let held = |receiver: &Receiver| -> Vec<u32> {
        (0..rows)
            .filter(|index| receiver.wire.table.contains_key(&key(*index)))
            .collect()
    };
    let behind = held(&receivers[0]);
    assert_eq!(behind.len(), 2 * STEP);
    assert_eq!(held(&receivers[1]).len(), STEP);
    let ahead: Vec<u32> = (0..rows).filter(|index| !behind.contains(index)).collect();
    let (changed_behind, withdrawn_behind, same_behind) = (behind[0], behind[1], behind[2]);
    let (changed_ahead, withdrawn_ahead) = (ahead[0], ahead[1]);
    let logs = manager.adj_rib_out_commit_stats.owed_evpn_logs;
    received(
        &mut manager,
        &[(changed_behind, 7), (changed_ahead, 7)],
        &[],
    );
    assert_eq!(
        manager.adj_rib_out_commit_stats.owed_evpn_logs - logs,
        1,
        "one log a mutation, not one a receiver"
    );
    received(&mut manager, &[], &[withdrawn_behind, withdrawn_ahead]);
    received(&mut manager, &[], &[same_behind]);
    received(&mut manager, &[(same_behind, 0)], &[]);
    // A second owe while both cursors are behind.
    for receiver in &receivers {
        manager.owe_whole_family(receiver.peer, FAMILY);
    }
    receivers[0].write();
    assert_eq!(
        receivers[0].wire.announced.len(),
        2 * STEP,
        "a mutation stages nothing toward a receiver that owes the family"
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
    for receiver in &receivers {
        let rows = receiver.wire.announced.len() + receiver.wire.withdrawn.len();
        assert!(rows <= expected.len() + 4, "{rows} rows: nothing repeated");
    }
}

/// Contract (refusal): a step refused for credit, then for channel room,
/// leaves the position where it was, and the rows resume exactly once
/// when room returns. When the final data step takes the last channel
/// slot, the End-of-RIB is refused, waits for the tick's marker retry and
/// leaves once: no resync is built and no row is sent again. The tick
/// reads the credit and the channel room the step's admission reads, so it
/// offers no step that would be refused; the step's own refusal is run
/// directly, against spent credit and against a full channel, and sends
/// nothing, reads on from the same position and marks nothing dirty. Red
/// when a refused step moves the position (rows are lost) and when the
/// refused marker marks the receiver dirty.
#[test]
fn a_refused_evpn_step_keeps_its_position_and_a_refused_marker_replays_nothing() {
    // Credit: the receiver reads nothing, so the second step is refused.
    let rows = 40u32;
    let (mut manager, mut receivers) = owing(1, rows, CREDIT);
    let peer = receivers[0].peer;
    for _ in 0..10 {
        manager.resync_dirty_peers_bounded();
    }
    let read = manager.adj_rib_out_commit_stats.owed_drain_rows_read;
    assert!(
        read <= CREDIT + STEP,
        "{read} keys read against spent credit"
    );
    assert!(!manager.dirty_peers.contains(&peer));
    drain(&mut manager, &mut receivers);
    assert_eq!(
        receivers[0].wire.announced.len(),
        rows as usize,
        "once each"
    );
    assert_settled(&manager, &receivers, &all(rows), "credit refusal");

    // Channel room: one slot, ample credit.
    let rows = 3 * u32::try_from(CHUNK_ROWS).unwrap();
    let (mut manager, mut receivers) = owing_sized(1, rows, 1 << 20, 1);
    let peer = receivers[0].peer;
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    for step in 1..=3usize {
        for _ in 0..3 {
            manager.resync_dirty_peers_bounded();
        }
        assert!(manager.outbound_channel_full(peer));
        assert_eq!(
            manager.adj_rib_out_commit_stats.owed_drain_rows_read,
            step * CHUNK_ROWS,
            "a full channel refuses the next step before it reads"
        );
        assert!(!manager.dirty_peers.contains(&peer));
        if step < 3 {
            receivers[0].write();
        }
    }
    // The last step took the only slot: its marker was refused.
    assert!(!manager.owes(peer, EVPN), "every owed row was admitted");
    assert!(manager.eor_pending(peer).contains(&EVPN));
    receivers[0].write();
    assert_eq!(receivers[0].wire.markers, 0);
    for _ in 0..4 {
        tick(&mut manager, &mut receivers);
        assert_eq!(receivers[0].wire.markers, 1);
    }
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
    assert_eq!(
        receivers[0].wire.announced.len(),
        rows as usize,
        "once each"
    );
    assert_eq!(receivers[0].wire.uncharged + receivers[0].wire.latched, 0);
    assert_settled(&manager, &receivers, &all(rows), "full channel");

    // The step's own refusal, past the tick's preflight.
    let rows = 40u32;
    for full_channel in [false, true] {
        let (mut manager, mut receivers) = owing(1, rows, CREDIT);
        let peer = receivers[0].peer;
        tick(&mut manager, &mut receivers);
        assert_eq!(receivers[0].wire.announced.len(), STEP);
        let credit = manager.outbound_credit_handle(peer);
        let sender = manager.outbound_peers[&peer].clone();
        let charge =
            (!full_channel).then(|| crate::outbound_credit::OutboundCharge::new(&credit, CREDIT));
        let slots: Vec<_> = std::iter::from_fn(|| sender.clone().try_reserve_owned().ok())
            .take(if full_channel { usize::MAX } else { 0 })
            .collect();
        assert_eq!(manager.outbound_channel_full(peer), full_channel);
        for _ in 0..3 {
            assert!(
                !manager.owing_drain_step(
                    peer,
                    FAMILY,
                    super::super::outbound_owing::DrainScope::All,
                    CREDIT
                ),
                "full channel {full_channel}: the step is refused"
            );
        }
        drop((charge, slots));
        receivers[0].write();
        assert_eq!(receivers[0].wire.announced.len(), STEP, "nothing sent");
        assert!(manager.owes_whole(peer, FAMILY));
        assert!(!manager.dirty_peers.contains(&peer));
        assert_eq!(fallbacks(&manager), 0.0);
        drain(&mut manager, &mut receivers);
        assert_eq!(
            receivers[0].wire.announced.len(),
            rows as usize,
            "full channel {full_channel}: every row once, none skipped"
        );
        assert_settled(&manager, &receivers, &all(rows), "refused step");
    }
}

fn refresh_request(manager: &mut RibManager, peer: PeerId) {
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer,
        session_id: 0,
        afi: EVPN.0,
        safi: EVPN.1,
        queued: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    });
}

/// Receiver 0 reads and keeps up while `stalled` others read nothing and
/// fresh keys rotate through the table, until the list cap evicts them.
/// Returns the table the rotation left.
fn evict_stalled(stalled: u8) -> (RibManager, Vec<Receiver>, Vec<(u32, u32)>) {
    evict_stalled_of(owing(1 + stalled, 8, CREDIT))
}

/// Unicast rows the grouped fixture's group table holds.
const UNICAST: u32 = 6;

fn unicast_table(rows: u32) -> BTreeSet<Prefix> {
    (0..rows).map(|index| unicast_route(index).prefix).collect()
}

/// [`owing`] as a default build has it: every receiver is a member of one
/// update group for IPv4 unicast, whose table holds [`UNICAST`] rows each
/// has been sent, and holds EVPN privately.
fn owing_grouped(receivers: u8) -> (RibManager, Vec<Receiver>) {
    let mut manager = manager(CREDIT);
    manager.test_force_ungrouped = false;
    let (mut manager, mut receivers) = owing_from(manager, &[V4, EVPN], receivers, 8, 4096);
    received_unicast(&mut manager, 0..UNICAST);
    let gid = manager.grouped_member_of(receivers[0].peer);
    assert!(gid.is_some(), "a group member");
    for receiver in &mut receivers {
        receiver.write();
        assert_eq!(manager.grouped_member_of(receiver.peer), gid, "one group");
        assert_eq!(receiver.wire.unicast_table, unicast_table(UNICAST));
        assert!(manager.owes_whole(receiver.peer, FAMILY));
    }
    (manager, receivers)
}

/// [`evict_stalled`] grouped ([`owing_grouped`]) or not.
fn evict_stalled_in(grouped: bool, stalled: u8) -> (RibManager, Vec<Receiver>, Vec<(u32, u32)>) {
    if grouped {
        evict_stalled_of(owing_grouped(1 + stalled))
    } else {
        evict_stalled(stalled)
    }
}

/// [`evict_stalled`] over the receivers of an `owing` fixture: all but the
/// first stall. The evicting pass builds no resync and walks no group
/// table; it leaves an ungrouped receiver dirty and a group member for the
/// resync tick to make dirty.
fn evict_stalled_of(
    (mut manager, mut receivers): (RibManager, Vec<Receiver>),
) -> (RibManager, Vec<Receiver>, Vec<(u32, u32)>) {
    let stalled = u8::try_from(receivers.len() - 1).unwrap();
    for round in 0..400u32 {
        let base = 1000 + round * 64;
        let fresh: Vec<_> = (base..base + 64).map(|index| (index, 0)).collect();
        let gone: Vec<_> = if round == 0 {
            vec![]
        } else {
            (base - 64..base).collect()
        };
        let before = fallbacks(&manager);
        let builds = manager.adj_rib_out_commit_stats.resync_builds;
        let captures = manager.adj_rib_out_commit_stats.group_table_captures;
        // Row 0, which every receiver holds, changes once, early: the cap
        // drops its entry from behind the stalled receivers' positions.
        let mut announce = fresh.clone();
        if round == 1 {
            announce.push((0, 1));
        }
        received(&mut manager, &announce, &gone);
        assert!(
            manager.owed_evpn_rows.dropped_max <= 4 * CHUNK_ROWS,
            "one call dropped {} list entries",
            manager.owed_evpn_rows.dropped_max
        );
        if fallbacks(&manager) > before {
            assert_eq!(fallbacks(&manager) - before, f64::from(stalled));
            assert_eq!(
                manager.adj_rib_out_commit_stats.resync_builds, builds,
                "the evicting pass builds no resync"
            );
            assert_eq!(
                manager.adj_rib_out_commit_stats.group_table_captures, captures,
                "the evicting pass walks no group table"
            );
            for receiver in &receivers[1..] {
                assert!(manager.owed_row_evicted.contains(&receiver.peer));
                assert_eq!(
                    manager.dirty_peers.contains(&receiver.peer),
                    manager.grouped_member_of(receiver.peer).is_none(),
                    "a group member is made dirty by the tick"
                );
            }
            assert!(round > 1, "evicted after row 0 changed");
            let table = (0..8)
                .map(|index| (index, u32::from(index == 0)))
                .chain(fresh)
                .collect();
            return (manager, receivers, table);
        }
        for _ in 0..12 {
            manager.resync_dirty_peers_bounded();
            receivers[0].write();
        }
    }
    panic!("the stalled receivers were never evicted");
}

/// Contract (refresh before the initial End-of-RIB). Mid-walk, a peer's
/// ROUTE-REFRESH absorbs the rest of the walk into its own operation: the
/// owed rows, the initial End-of-RIB, then the answer between its markers.
/// From a receiver the cap evicted the request builds nothing in its own
/// turn and is kept through a resync whose commit is first refused (no
/// export encoder); it is answered after the admitted resync and its
/// End-of-RIB. Each marker is counted once. Red when the walk's remaining
/// rows are left out of the absorption (the End-of-RIB leaves ahead of
/// them). An answer ahead of a marker still owed is refused by two checks
/// here, the evicted receiver's deferral and the refresh path's own; each
/// has its own test below.
#[test]
fn an_evpn_refresh_before_the_initial_end_of_rib_is_answered_after_it() {
    let rows = 40u32;
    let (mut manager, mut receivers) = owing(1, rows, CREDIT);
    tick(&mut manager, &mut receivers);
    let peer = receivers[0].peer;
    assert_eq!(receivers[0].wire.table.len(), STEP);
    refresh_request(&mut manager, peer);
    assert!(!manager.owes(peer, EVPN), "the refresh absorbed the family");
    drain(&mut manager, &mut receivers);
    let wire = &receivers[0].wire;
    assert_eq!(
        wire.sent,
        [Sent::Rows, Sent::Eor, Sent::Answer(rows as usize)],
        "owed rows, the initial End-of-RIB, then the bracketed answer"
    );
    assert_eq!(wire.announced.len(), 2 * rows as usize, "walk + answer");
    assert!(!manager.pending_refresh.contains_key(&peer));
    assert_settled(&manager, &receivers, &all(rows), "refresh mid-walk");

    // After eviction, with the recovery first refused: ungrouped, then as
    // a group member.
    for grouped in [false, true] {
        refresh_from_an_evicted_receiver_whose_recovery_is_refused(grouped);
    }
}

fn refresh_from_an_evicted_receiver_whose_recovery_is_refused(grouped: bool) {
    let (mut manager, mut receivers, expected) = evict_stalled_in(grouped, 1);
    let peer = receivers[1].peer;
    receivers[1].write();
    receivers[1].wire.sent.clear();
    assert!(manager.eor.owes(peer, EVPN));
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    refresh_request(&mut manager, peer);
    receivers[1].write();
    assert_eq!(receivers[1].wire.sent, [], "built in the request's turn");
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
    assert!(manager.pending_refresh.contains_key(&peer), "still asked");
    assert!(manager.owed_row_evicted.contains(&peer));
    // The recovery is first refused after its build.
    let encoder = manager
        .peer_export_encoders
        .remove(&peer)
        .expect("an exact export encoder");
    let mut refused = 0;
    for _ in 0..6 {
        let before = manager.adj_rib_out_commit_stats.resync_builds;
        tick(&mut manager, &mut receivers);
        let built = manager.adj_rib_out_commit_stats.resync_builds - before;
        assert!(built <= 1, "{built} tables built in one tick");
        refused += built;
    }
    assert!(refused != 0, "the recovery was built and refused");
    assert_eq!(receivers[1].wire.sent, [], "refused: nothing is sent");
    assert!(manager.pending_refresh.contains_key(&peer), "still asked");
    assert!(manager.owed_row_evicted.contains(&peer));
    assert!(manager.eor.owes(peer, EVPN));
    manager.peer_export_encoders.insert(peer, encoder);
    drain(&mut manager, &mut receivers);
    assert_eq!(
        receivers[1].wire.sent,
        [Sent::Rows, Sent::Eor, Sent::Answer(expected.len())]
    );
    assert_eq!(receivers[1].wire.table, table(&expected));
    assert_eq!(receivers[1].wire.markers, 1);
    assert_eq!(
        manager.adj_rib_out_commit_stats.resync_builds - builds,
        refused + 1,
        "one admitted resync"
    );
    assert_eq!(
        recoveries_observed(&manager),
        (1, u64::try_from(refused).unwrap()),
        "the refused builds and the admitted one are timed apart"
    );
    assert!(!manager.pending_refresh.contains_key(&peer), "answered");
    assert!(manager.owed_row_evicted.is_empty());
}

/// Work count: receivers the cap evicted are rebuilt by the resync tick
/// only, one per tick: the EVPN and unicast mutations that follow build no
/// resync for them. Red when an ordinary pass takes an evicted
/// receiver as any dirty one, and when a tick with budget left goes on to
/// the next evicted receiver.
#[test]
fn an_evicted_evpn_receiver_is_rebuilt_only_by_the_tick_one_per_tick() {
    let (mut manager, mut receivers, mut expected) = evict_stalled(3);
    // Whatever poll budget is left: the unit ends the tick.
    manager.flush_poll_budget = Duration::from_secs(3600);
    for receiver in &mut receivers[1..] {
        receiver.write();
    }
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    for index in 5000..5003 {
        received(&mut manager, &[(index, 0)], &[]);
        expected.push((index, 0));
    }
    // A unicast mutation's pass visits every dirty peer.
    received_unicast(&mut manager, 0..1);
    assert_eq!(
        manager.adj_rib_out_commit_stats.resync_builds, builds,
        "no mutation builds an evicted receiver's table"
    );
    let mut built = builds;
    for _ in 0..5000 {
        if !manager.resync_tick_pending() {
            break;
        }
        tick(&mut manager, &mut receivers);
        let now = manager.adj_rib_out_commit_stats.resync_builds;
        assert!(now - built <= 1, "{} tables built in one tick", now - built);
        built = now;
    }
    assert_eq!(built - builds, 3, "one resync per evicted receiver");
    assert_eq!(
        recoveries_observed(&manager),
        (3, 0),
        "each EVPN eviction recovery is timed"
    );
    assert!(manager.owed_row_evicted.is_empty());
    for (index, receiver) in receivers.iter().enumerate() {
        assert_eq!(
            receiver.wire.table.len(),
            expected.len(),
            "receiver {index}"
        );
        assert_eq!(receiver.wire.table, table(&expected), "receiver {index}");
        assert_eq!(receiver.wire.markers, 1, "receiver {index}");
    }
}

/// The cap never evicts a reading receiver for a mass withdrawal or the
/// loss of the source: the list then holds keys the table no longer has.
/// List maintenance stays bounded per call on the way down. Red when the
/// cap is taken from the table after the pass.
#[test]
fn a_large_evpn_withdrawal_or_source_loss_evicts_no_reading_receiver() {
    let rows = 12_000u32;
    for source_lost in [false, true] {
        let (mut manager, mut receivers) = owing(3, rows, 1 << 20);
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
        assert_eq!(manager.loc_rib.evpn_len(), rest.len());
        assert!(
            manager.owed_evpn_rows.len() > 2 * rest.len() + 4 * CHUNK_ROWS,
            "the list holds the withdrawn keys: {}",
            manager.owed_evpn_rows.len()
        );
        drain(&mut manager, &mut receivers);
        assert_eq!(fallbacks(&manager), 0.0, "source lost: {source_lost}");
        assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
        let dropped = manager.owed_evpn_rows.dropped_max;
        assert!(
            dropped != 0 && dropped <= 4 * CHUNK_ROWS,
            "one call dropped {dropped} list entries"
        );
        assert_settled(&manager, &receivers, &rest, "large withdrawal");
    }
}

/// Contract (session and dirty transitions): a receiver that flaps
/// mid-walk starts again from its own session's state; one that is
/// deleted leaves no position behind; one marked dirty mid-walk is
/// resynced, and the resync covers what it was owed. Each ends with the
/// exact table and one End-of-RIB after it, and the list is freed. Red
/// when the old session's position survives the flap.
#[test]
fn an_evpn_cursor_ends_with_its_session_and_a_resync_covers_it() {
    let rows = 40u32;
    // Flap.
    let (mut manager, mut receivers) = owing(2, rows, CREDIT);
    for _ in 0..4 {
        tick(&mut manager, &mut receivers);
    }
    let peer = receivers[0].peer;
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    });
    assert!(
        !manager.owes(peer, EVPN),
        "the position ends with its session"
    );
    let mut rx = up_sized(&mut manager, peer, 1, 4096, &[EVPN]);
    let mut wire = Wire::default();
    wire.write(&mut rx);
    assert!(
        !manager.owes_whole(peer, FAMILY),
        "no position carried over"
    );
    receivers[0] = Receiver { peer, rx, wire };
    drain(&mut manager, &mut receivers);
    assert_settled(&manager, &receivers, &all(rows), "flap");

    // Delete.
    let (mut manager, mut receivers) = owing(2, rows, CREDIT);
    for _ in 0..4 {
        tick(&mut manager, &mut receivers);
    }
    let gone = receivers.remove(0);
    manager.handle_update(RibUpdate::PeerDown {
        peer: gone.peer,
        session_id: 0,
    });
    assert!(manager.owing(gone.peer).is_none());
    drain(&mut manager, &mut receivers);
    assert_settled(&manager, &receivers, &all(rows), "delete");

    // Dirty mid-walk: the resync covers the debt.
    let (mut manager, mut receivers) = owing(2, rows, CREDIT);
    for _ in 0..4 {
        tick(&mut manager, &mut receivers);
    }
    let peer = receivers[0].peer;
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    manager.mark_outbound_dirty(peer);
    drain(&mut manager, &mut receivers);
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds - builds, 1);
    assert!(manager.owing(peer).is_none(), "covered by the resync");
    assert_settled(&manager, &receivers, &all(rows), "dirty");
    assert_eq!(
        receivers[0].wire.announced.len(),
        rows as usize,
        "once each"
    );
}

/// A receiver with a unicast cursor and an EVPN cursor at once: each
/// family's End-of-RIB follows its own last row, every envelope is
/// charged and no operation is taken. Red when one family's marker leaves
/// with the other's last step.
#[test]
fn unicast_and_evpn_cursors_on_one_receiver_each_end_with_their_own_marker() {
    let (unicast_rows, evpn_rows) = (24u32, 56u32);
    let mut manager = manager(CREDIT);
    std::mem::forget(up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]));
    let peer = receiver(0);
    let mut rx = up_sized(&mut manager, peer, 0, 4096, &[V4, EVPN]);
    Wire::default().write(&mut rx);
    for (family, owed) in [(V4, OwedFamily::IPV4_UNICAST), (EVPN, FAMILY)] {
        manager.owe_eor(peer, family);
        manager.owe_whole_family(peer, owed);
    }
    received_unicast(&mut manager, 0..unicast_rows);
    received(&mut manager, &all(evpn_rows), &[]);
    let mut receivers = vec![Receiver {
        peer,
        rx,
        wire: Wire::default(),
    }];
    receivers[0].write();
    assert_eq!(receivers[0].wire.unicast + receivers[0].wire.table.len(), 0);
    let mut marker_at = [None, None];
    for _ in 0..1000 {
        if !manager.resync_tick_pending() {
            break;
        }
        tick(&mut manager, &mut receivers);
        let wire = &receivers[0].wire;
        if wire.unicast_markers == 1 && marker_at[0].is_none() {
            marker_at[0] = Some((wire.unicast, wire.table.len()));
        }
        if wire.markers == 1 && marker_at[1].is_none() {
            marker_at[1] = Some((wire.unicast, wire.table.len()));
        }
    }
    let wire = &receivers[0].wire;
    let (unicast_rows, evpn_rows) = (unicast_rows as usize, evpn_rows as usize);
    assert_eq!(marker_at[0].unwrap().0, unicast_rows, "after its last row");
    assert!(
        marker_at[0].unwrap().1 < evpn_rows,
        "the unicast marker does not wait for EVPN"
    );
    assert_eq!(marker_at[1].unwrap(), (unicast_rows, evpn_rows));
    assert_eq!((wire.unicast_markers, wire.markers), (1, 1));
    assert_eq!(wire.unicast_rows_after_marker + wire.rows_after_marker, 0);
    assert_eq!(wire.uncharged + wire.latched, 0);
    assert!(wire.envelope_rows_max <= STEP);
    assert!(!manager.owes(peer, V4) && !manager.owes(peer, EVPN));
    assert_eq!(manager.owed_evpn_rows.len() + manager.owed_rows[0].len(), 0);
}

/// A manager that defers EVPN selection while `WAITER` restarts.
fn deferral_manager(credit: usize) -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 100)),
        BgpMetrics::new(),
    )
    .with_outbound_row_credit(credit)
    .with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: vec![SelectionDeferralWaiterConfig {
            peer: peer_v4(WAITER).into(),
            families: vec![EVPN],
        }],
    });
    manager.test_force_ungrouped = true;
    manager.flush_poll_budget = Duration::ZERO;
    manager
}

/// The waiter's session comes up restarting: the EVPN selection hold
/// begins. The waiter is a private EVPN receiver too, and reads.
fn hold(manager: &mut RibManager) -> Receiver {
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: peer_v4(WAITER),
        session_id: 7,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![EVPN],
        peer_enhanced_refresh: false,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let rx = up_sized(manager, peer_v4(WAITER), 7, 4096, &[EVPN]);
    assert!(manager.selection_deferred(EVPN));
    Receiver {
        peer: peer_v4(WAITER),
        rx,
        wire: Wire::default(),
    }
}

/// The waiter's End-of-RIB: the hold is released.
fn release(manager: &mut RibManager) {
    end_of_rib(manager, peer_v4(WAITER), 7, EVPN);
    assert!(!manager.selection_deferred(EVPN));
}

/// Contract (release with an unchanged winner): a winner installed before
/// a selection hold and unchanged through it reaches two receivers that
/// joined during the hold, each with one End-of-RIB after it. The release
/// logs its inventory once across the receivers, though no winner changed
/// and nothing fans out. With the held-key ledger overflowed, a frozen
/// winner the source withdrew during the hold is withdrawn from the
/// receiver that had admitted it. Red when the list is seeded from the
/// changed winners only, and (overflow) without the frozen Loc-RIB
/// inventory.
#[test]
fn an_evpn_release_seeds_unchanged_winners_once_for_every_receiver() {
    for overflow in [false, true] {
        let mut manager = deferral_manager(CREDIT);
        std::mem::forget(up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]));
        let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 4096, &[EVPN])];
        received(&mut manager, &all(20), &[]);
        drain(&mut manager, &mut receivers);
        assert_eq!(receivers[0].wire.table, table(&all(20)), "admitted");
        receivers[0].wire.announced.clear();
        if overflow {
            manager.set_deferred_selection_limits_for_test(0, usize::MAX);
        }
        let waiter = hold(&mut manager);
        // Two receivers join during the hold: nothing is sent to them.
        for index in 1..3 {
            let mut rx = up_sized(&mut manager, receiver(index), 0, 4096, &[EVPN]);
            let mut wire = Wire::default();
            wire.write(&mut rx);
            assert_eq!((wire.table.len(), wire.markers), (0, 0), "held");
            receivers.push(Receiver {
                peer: receiver(index),
                rx,
                wire,
            });
        }
        receivers.push(waiter);
        let expected = if overflow {
            received(&mut manager, &[], &[3]);
            (0..20)
                .filter(|index| *index != 3)
                .map(|i| (i, 0))
                .collect()
        } else {
            all(20)
        };
        let logs = manager.adj_rib_out_commit_stats.owed_evpn_logs;
        let stagings: Vec<_> = receivers[..3]
            .iter()
            .map(|receiver| manager.outbound_stagings(receiver.peer))
            .collect();
        release(&mut manager);
        assert_eq!(
            manager.adj_rib_out_commit_stats.owed_evpn_logs - logs,
            1,
            "overflow={overflow}: the release inventory is logged once"
        );
        for (receiver, before) in receivers[..3].iter_mut().zip(stagings) {
            receiver.write();
            assert_eq!(
                manager.outbound_stagings(receiver.peer),
                before,
                "the release turn stages no row"
            );
            assert_eq!(receiver.wire.announced.len(), 0);
            assert!(manager.owes_whole(receiver.peer, FAMILY));
        }
        drain(&mut manager, &mut receivers);
        for receiver in &receivers[1..3] {
            assert_eq!(receiver.wire.table, table(&expected), "overflow={overflow}");
            assert_eq!(receiver.wire.markers, 1, "one End-of-RIB");
            assert_eq!(receiver.wire.rows_after_marker, 0);
            assert_eq!(receiver.wire.announced.len(), expected.len(), "once each");
        }
        assert_eq!(receivers[0].wire.table, table(&expected));
        assert_eq!(receivers[0].wire.announced.len(), 0, "nothing repeated");
        assert_eq!(
            receivers[0].wire.withdrawn,
            if overflow { vec![key(3)] } else { vec![] }
        );
        for receiver in &receivers {
            assert_eq!(receiver.wire.uncharged + receiver.wire.latched, 0);
            assert!(!manager.owes(receiver.peer, EVPN));
        }
        assert_eq!(manager.owed_evpn_rows.len(), 0);
    }
}

/// Contract (a withdrawal that survives only in private debt): a receiver
/// owes the withdrawal of a row it holds, the row leaves every table, and
/// more owed keys take its set past the byte cap. The set is kept under
/// the cursor: one step drains part of it, fresh changes go to the shared
/// list and not to the set, and a selection release leaves it alone. The
/// withdrawal reaches the receiver, and the cursor ends only once the set
/// is empty and the position has caught up. Red when the set is cleared at
/// the flip or the release, and when a caught-up cursor ends with keys
/// left in its set.
#[test]
fn an_evpn_withdrawal_owed_only_in_the_kept_set_survives_a_flip_and_a_release() {
    let rows = 64u32;
    let mut manager = deferral_manager(CREDIT).with_owing_theta_floor(1);
    std::mem::forget(up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]));
    let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 4096, &[EVPN])];
    let peer = receivers[0].peer;
    received(&mut manager, &all(rows), &[]);
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table, table(&all(rows)), "admitted");
    assert!(!manager.owes(peer, EVPN));
    // It stops reading: one more pass spends its credit and owes the rest.
    let spend: Vec<_> = (8..24).map(|i| (i, 1)).collect();
    received(&mut manager, &spend, &[]);
    let owed = manager.owed_key_count(peer, FAMILY);
    assert!(owed != 0 && !manager.owes_whole(peer, FAMILY));
    // The withdrawal of row 0 is owed, and row 0 leaves every table.
    received(&mut manager, &[], &[0]);
    assert_eq!(manager.owed_key_count(peer, FAMILY), owed + 1);
    assert!(manager.loc_rib.get_evpn(&key(0)).is_none());
    assert!(manager.ribs[&peer_v4(SOURCE)].get_evpn(&key(0)).is_none());
    // More owed keys take the set past its cap: a cursor, the set kept.
    let more: Vec<_> = (24..rows).map(|i| (i, 2)).collect();
    received(&mut manager, &more, &[]);
    assert!(manager.owes_whole(peer, FAMILY), "past the byte cap");
    let kept = manager.owed_key_count(peer, FAMILY);
    assert!(kept > owed + 1, "the set is kept: {kept} keys");
    // It reads again: one step drains part of the set.
    receivers[0].write();
    tick(&mut manager, &mut receivers);
    let left = manager.owed_key_count(peer, FAMILY);
    assert!(left != 0 && left < kept, "{left} of {kept} keys left");
    assert!(manager.owes_whole(peer, FAMILY), "the cursor outlives it");
    // Fresh changes go to the shared list, not to the set.
    let list = manager.owed_evpn_rows.len();
    received(&mut manager, &[(100, 0), (101, 0)], &[]);
    assert_eq!(manager.owed_key_count(peer, FAMILY), left);
    assert_eq!(manager.owed_evpn_rows.len(), list + 2);
    // A selection release crosses the drain.
    receivers.push(hold(&mut manager));
    assert_eq!(manager.owed_key_count(peer, FAMILY), left);
    release(&mut manager);
    assert_eq!(manager.owed_key_count(peer, FAMILY), left, "kept");
    assert!(manager.owes_whole(peer, FAMILY));
    drain(&mut manager, &mut receivers);
    let expected: Vec<_> = (1..rows)
        .map(|i| {
            let variant = match i {
                24.. => 2,
                8..24 => 1,
                _ => 0,
            };
            (i, variant)
        })
        .chain([(100, 0), (101, 0)])
        .collect();
    assert_eq!(receivers[0].wire.table, table(&expected));
    assert_eq!(receivers[0].wire.count(0).1, 1, "the withdrawal arrived");
    assert!(!manager.owes(peer, EVPN));
    assert!(!manager.dirty_peers.contains(&peer));
    assert_eq!(fallbacks(&manager), 0.0);
    assert_eq!(manager.owed_evpn_rows.len(), 0);
}

/// Contract (live RT-Constrain change behind the cursor): receiver R holds
/// VPN in an update group and EVPN privately, and imports RT 100. Its
/// cursor has read A (RT 100, admitted) and B (RT 200, left out) and still
/// has rows to read when R's membership becomes RT 200, with both winners
/// as they were. R withdraws A and announces B before its initial
/// End-of-RIB and ends with exactly B and the rows carrying both targets;
/// a sibling that still imports RT 100 keeps A and never sees B. Red when
/// a receiver that owes the family whole discards the targeted restage.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one transcript checks the walk, the membership edit and both receivers' final tables"
)]
fn a_live_rtc_change_behind_an_evpn_cursor_revisits_the_keys_it_passed() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 100)),
        BgpMetrics::new(),
    )
    .with_outbound_row_credit(CREDIT);
    manager.flush_poll_budget = Duration::ZERO;
    let mut families = vpn_rtc_sendable();
    families.push(EVPN);
    std::mem::forget(up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]));
    let membership = |manager: &mut RibManager, index: u8, add: u16, drop: Option<u16>| {
        let address = Ipv4Addr::new(10, 0, 9, index + 1);
        manager.handle_update(RibUpdate::RtcRoutesReceived {
            peer: receiver(index),
            session_id: 0,
            announced: vec![make_rtc_rib_route(address, add, 100)],
            withdrawn: drop
                .map(|value| make_rtc_rib_route(address, value, 100).key())
                .into_iter()
                .collect(),
        });
    };
    let mut receivers: Vec<Receiver> = (0..2)
        .map(|index| {
            let peer = receiver(index);
            let mut rx = up_sized(&mut manager, peer, 0, 4096, &families);
            membership(&mut manager, index, 100, None);
            manager.handle_update(RibUpdate::EndOfRib {
                peer,
                session_id: 0,
                afi: RTC.0,
                safi: RTC.1,
            });
            let mut wire = Wire::default();
            wire.write(&mut rx);
            assert_eq!(wire.markers, 1, "the initial EVPN End-of-RIB");
            assert!(manager.vpn_grouped_member_of(peer).is_some(), "grouped VPN");
            assert!(manager.evpn_grouped_member_of(peer).is_none(), "private");
            Receiver {
                peer,
                rx,
                wire: Wire::default(),
            }
        })
        .collect();
    let (r, sibling) = (receivers[0].peer, receivers[1].peer);
    manager.owe_eor(r, EVPN);
    manager.owe_whole_family(r, FAMILY);
    // A and B first, so the first step reads both; then rows that carry
    // both targets.
    let (a, b) = (route_rt(0, 0, &[100]), route_rt(1, 0, &[200]));
    received_routes(&mut manager, vec![a.clone(), b.clone()], &[]);
    let rest: Vec<_> = (2..40).map(|i| route_rt(i, 0, &[100, 200])).collect();
    received_routes(&mut manager, rest.clone(), &[]);
    tick(&mut manager, &mut receivers);
    for key in [a.key(), b.key()] {
        assert!(manager.owed_evpn_cursor_passed(r, &key), "walked");
    }
    let wire = &receivers[0].wire;
    assert!(wire.table.contains_key(&a.key()), "A admitted");
    assert!(!wire.table.contains_key(&b.key()), "B left out");
    assert!(manager.owes_whole(r, FAMILY), "further debt outstanding");
    assert_eq!(wire.markers, 0);
    let logs = manager.adj_rib_out_commit_stats.owed_evpn_logs;
    let winners = |manager: &RibManager| {
        [a.key(), b.key()].map(|key| format!("{:?}", manager.loc_rib.get_evpn(&key)))
    };
    let before = winners(&manager);
    membership(&mut manager, 0, 200, Some(100));
    assert_eq!(winners(&manager), before, "both winners as they were");
    assert_eq!(
        manager.adj_rib_out_commit_stats.owed_evpn_logs, logs,
        "no EVPN winner changed"
    );
    assert!(manager.vpn_grouped_member_of(r).is_some());
    assert!(manager.evpn_grouped_member_of(r).is_none());
    assert!(!manager.dirty_peers.contains(&r), "no resync");
    // The corrections precede the initial End-of-RIB.
    let mut corrected_before_marker = false;
    for _ in 0..1000 {
        if !manager.resync_tick_pending() {
            break;
        }
        tick(&mut manager, &mut receivers);
        let wire = &receivers[0].wire;
        if wire.markers == 0 && wire.withdrawn == [a.key()] && wire.table.contains_key(&b.key()) {
            corrected_before_marker = true;
        }
    }
    assert!(corrected_before_marker, "A withdrawn and B announced first");
    let expect = |first: &EvpnRibRoute| -> BTreeMap<EvpnRouteKey, String> {
        std::iter::once(first)
            .chain(&rest)
            .map(|route| (route.key(), format!("{:?}", route.attributes)))
            .collect()
    };
    let wire = &receivers[0].wire;
    assert_eq!(wire.table, expect(&b), "R: B and not A");
    assert_eq!((wire.markers, wire.rows_after_marker), (1, 0));
    assert_eq!(wire.uncharged + wire.latched, 0);
    assert!(!manager.owes(r, EVPN));
    let wire = &receivers[1].wire;
    assert_eq!(wire.table, expect(&a), "the sibling: A and not B");
    assert!(!wire.announced.contains(&b.key()));
    assert!(manager.owing(sibling).is_none());
    assert_eq!(fallbacks(&manager), 0.0);
}

/// A chain that permits every route unmodified: another group key than no
/// chain at all, with the same exported rows.
fn permit_all() -> PolicyChain {
    let mut statement = super::update_groups::deny_statement(Ipv4Prefix::new(SOURCE, 32));
    statement.prefix = None;
    statement.action = rustbgpd_policy::PolicyAction::Permit;
    PolicyChain::new(vec![rustbgpd_policy::Policy {
        entries: vec![statement],
        default_action: rustbgpd_policy::PolicyAction::Deny,
    }])
}

/// Move `peer` under `policy` through the export-policy transaction.
fn regroup(manager: &mut RibManager, peer: PeerId, policy: Option<PolicyChain>) {
    manager
        .replace_peer_export_policy_synchronously(peer, policy)
        .unwrap();
}

/// A manager whose peers group, with the source and a sibling whose group
/// owns its members' EVPN rows: every other member of that group (the
/// [`permit_all`] chain) is group-owned, and a peer without a chain holds
/// EVPN privately. No build decides EVPN ownership from configuration, so
/// the sibling's group is given it while every table is empty; each later
/// move is the real regroup.
fn owned_sibling(mut manager: RibManager) -> (RibManager, Receiver, usize) {
    manager.test_force_ungrouped = false;
    std::mem::forget(up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]));
    let sibling = Receiver::up(&mut manager, receiver(0), 4096, &[EVPN]);
    regroup(&mut manager, sibling.peer, Some(permit_all()));
    let gid = manager.grouped_member_of(sibling.peer).unwrap();
    assert_eq!(manager.group_ribs[&gid].members.len(), 1);
    manager
        .group_ribs
        .get_mut(&gid)
        .unwrap()
        .set_evpn_ownership_for_test(true);
    assert!(manager.register_evpn_recovery(sibling.peer, false));
    assert_eq!(manager.evpn_grouped_member_of(sibling.peer), Some(gid));
    (manager, sibling, gid)
}

/// A group-owned receiver holds no private EVPN position.
fn assert_no_cursor(manager: &RibManager, peer: PeerId, at: &str) {
    assert!(!manager.owes_whole(peer, FAMILY), "{at}: a private cursor");
    assert!(!manager.owes(peer, EVPN), "{at}: private EVPN debt");
}

/// Contract (ownership, private to owned): a private receiver holds X and
/// its cursor is mid-walk when the source withdraws X, so that withdrawal
/// is owed to it by the shared list alone. Its policy then moves it into a
/// group that owns EVPN. The private position ends with the old ownership
/// and the list is freed; the owned destination's recovery withdraws X and
/// sends every row the walk had not reached, then one End-of-RIB. The
/// group-owned sibling never holds a private position. Red when the regroup
/// keeps the old position, and when the private rows it had admitted are
/// not captured for the destination.
#[test]
fn a_private_evpn_cursor_ends_when_its_receiver_becomes_group_owned() {
    let rows = 40u32;
    let (mut manager, sibling, owned) = owned_sibling(manager(CREDIT));
    let mover = Receiver::up(&mut manager, receiver(1), 4096, &[EVPN]);
    let (sibling_peer, peer) = (sibling.peer, mover.peer);
    assert!(manager.evpn_grouped_member_of(peer).is_none(), "private");
    let mut receivers = vec![sibling, mover];
    received(&mut manager, &[(0, 0)], &[]);
    drain(&mut manager, &mut receivers);
    for receiver in &receivers {
        assert_eq!(receiver.wire.table, table(&[(0, 0)]), "X admitted");
    }
    manager.owe_eor(peer, EVPN);
    manager.owe_whole_family(peer, FAMILY);
    let rest: Vec<_> = (1..rows).map(|index| (index, 0)).collect();
    received(&mut manager, &rest, &[]);
    tick(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);
    assert_eq!(receivers[1].wire.table.len(), 1 + 2 * STEP, "mid-walk");
    // X leaves every table: only the list owes the mover its withdrawal.
    received(&mut manager, &[], &[0]);
    receivers[1].write();
    assert!(manager.loc_rib.get_evpn(&key(0)).is_none());
    assert!(manager.ribs[&peer_v4(SOURCE)].get_evpn(&key(0)).is_none());
    assert!(
        receivers[1].wire.table.contains_key(&key(0)),
        "X still held"
    );
    assert_eq!(receivers[1].wire.table.len(), 1 + 2 * STEP);
    assert!(manager.owes_whole(peer, FAMILY));
    assert_eq!(manager.owed_key_count(peer, FAMILY), 0, "no kept set");
    assert_no_cursor(&manager, sibling_peer, "before the regroup");

    // Its channel is full, so the move's own turn cannot admit the
    // recovery: the position must end with the move, not with a resync.
    let sender = manager.outbound_peers[&peer].clone();
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
    regroup(&mut manager, peer, Some(permit_all()));
    assert_eq!(manager.evpn_grouped_member_of(peer), Some(owned));
    assert!(manager.dirty_peers.contains(&peer), "recovery refused");
    assert_no_cursor(&manager, peer, "the moved receiver");
    assert!(manager.owing(peer).is_none(), "the position ended");
    assert_eq!(
        manager.owed_evpn_rows.len(),
        0,
        "no cursor: the list is freed"
    );
    receivers[1].write();
    assert_eq!(receivers[1].wire.table.len(), 1 + 2 * STEP, "nothing sent");
    for _ in 0..1000 {
        tick(&mut manager, &mut receivers);
        assert_no_cursor(&manager, peer, "owned recovery");
        assert_no_cursor(&manager, sibling_peer, "sibling");
        if !manager.resync_tick_pending() {
            break;
        }
    }
    assert!(!manager.resync_tick_pending());
    let wire = &receivers[1].wire;
    assert_eq!(wire.table, table(&rest), "exact table");
    assert_eq!(wire.count(0), (1, 1), "X withdrawn once");
    assert_eq!((wire.markers, wire.rows_after_marker), (1, 0));
    assert!(!manager.eor_pending(peer).contains(&EVPN));
    assert!(!manager.dirty_peers.contains(&peer));
    let wire = &receivers[0].wire;
    assert_eq!(wire.table, table(&rest), "the sibling's table");
    assert_eq!(wire.announced.len(), rows as usize, "once each");
    assert_eq!(wire.markers, 0, "the sibling owed no End-of-RIB");
    assert_eq!(manager.owed_evpn_rows.len(), 0);
}

/// Contract (ownership, owned to private): a group-owned member holds X
/// and its channel is full when the source withdraws X, so only its
/// recovery proof owes it that withdrawal. Its policy then moves it to the
/// private path while another private receiver's cursor is mid-walk. The
/// moved receiver withdraws X and ends exact with one End-of-RIB; the other
/// cursor keeps its position and ends exact, each row once; the group-owned
/// sibling never holds a private position. Red when the proof of what the
/// member held is dropped at the move.
#[test]
fn a_member_leaving_an_owned_evpn_group_withdraws_what_only_it_was_owed() {
    let (rows, first) = (40u32, 10u32);
    let (mut manager, sibling, owned) = owned_sibling(manager(CREDIT));
    let mover = Receiver::up(&mut manager, receiver(1), 8, &[EVPN]);
    let other = Receiver::up(&mut manager, receiver(2), 4096, &[EVPN]);
    let (sibling_peer, peer, other_peer) = (sibling.peer, mover.peer, other.peer);
    regroup(&mut manager, peer, Some(permit_all()));
    assert_eq!(manager.evpn_grouped_member_of(peer), Some(owned));
    assert!(manager.evpn_grouped_member_of(other_peer).is_none());
    let mut receivers = vec![sibling, mover, other];
    received(&mut manager, &all(first), &[]);
    drain(&mut manager, &mut receivers);
    for receiver in &receivers {
        assert_eq!(receiver.wire.table, table(&all(first)), "admitted");
    }
    assert_eq!(receivers[1].wire.markers, 0);
    // The other private receiver owes EVPN whole and walks two steps.
    manager.owe_eor(other_peer, EVPN);
    manager.owe_whole_family(other_peer, FAMILY);
    let rest: Vec<_> = (first..first + rows).map(|index| (index, 0)).collect();
    received(&mut manager, &rest, &[]);
    tick(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);
    let walked = receivers[2].wire.table.len();
    assert_eq!(walked, first as usize + 2 * STEP, "mid-walk");
    assert_eq!(receivers[1].wire.table.len(), (first + rows) as usize);
    // The member's channel fills, then X leaves every table.
    manager.owe_eor(peer, EVPN);
    let sender = manager.outbound_peers[&peer].clone();
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
    received(&mut manager, &[], &[0]);
    assert!(manager.loc_rib.get_evpn(&key(0)).is_none());
    assert!(manager.ribs[&peer_v4(SOURCE)].get_evpn(&key(0)).is_none());
    assert!(manager.dirty_peers.contains(&peer), "admission refused");
    assert_no_cursor(&manager, peer, "a refused owned member");
    assert_no_cursor(&manager, sibling_peer, "before the regroup");
    // What the other cursor has left to read, its kept set and the keys
    // read so far.
    let position = |manager: &RibManager| {
        (
            manager.owed_evpn_rows.len(),
            manager.owed_key_count(other_peer, FAMILY),
            manager.adj_rib_out_commit_stats.owed_drain_rows_read,
        )
    };
    let before = position(&manager);
    assert_eq!((before.0, before.1), (rows as usize - 2 * STEP + 1, 0));

    regroup(&mut manager, peer, None);
    assert!(manager.evpn_grouped_member_of(peer).is_none(), "private");
    assert_eq!(manager.evpn_grouped_member_of(sibling_peer), Some(owned));
    assert_eq!(
        position(&manager),
        before,
        "the other position is untouched"
    );
    assert!(manager.owes_whole(other_peer, FAMILY));
    receivers[1].write();
    assert!(
        receivers[1].wire.table.contains_key(&key(0)),
        "X still held"
    );
    for _ in 0..1000 {
        tick(&mut manager, &mut receivers);
        assert_no_cursor(&manager, sibling_peer, "sibling");
        if !manager.resync_tick_pending() {
            break;
        }
    }
    assert!(!manager.resync_tick_pending());
    let expected: Vec<_> = (1..first + rows).map(|index| (index, 0)).collect();
    for (index, receiver) in receivers.iter().enumerate() {
        let wire = &receiver.wire;
        assert_eq!(wire.table, table(&expected), "receiver {index}");
        assert_eq!(wire.count(0), (1, 1), "receiver {index}: X withdrawn once");
        assert_eq!(wire.rows_after_marker, 0, "receiver {index}");
        assert!(!manager.owes(receiver.peer, EVPN), "receiver {index}");
        assert!(!manager.dirty_peers.contains(&receiver.peer));
        assert!(!manager.eor_pending(receiver.peer).contains(&EVPN));
    }
    assert_eq!(receivers[0].wire.markers, 0, "the sibling owed none");
    assert_eq!(receivers[1].wire.markers, 1, "the moved receiver");
    assert_eq!(receivers[2].wire.markers, 1, "the other receiver");
    assert_eq!(
        receivers[2].wire.announced.len(),
        (first + rows) as usize,
        "the other cursor read each row once"
    );
    assert!(!manager.has_private_evpn_handoff(peer));
    assert_eq!(manager.owed_evpn_rows.len(), 0);
}

/// Contract (forced resync): an operator refresh of a private receiver
/// whose cursor is mid-walk, with a withdrawal in its kept set, forces one
/// resync without marking it dirty. That one build covers the debt: the
/// cursor and its set are dropped, the list is freed, and the receiver is
/// sent rows and then its End-of-RIB, nothing after. Red when the resync
/// leaves the family owed: the walk goes on after the End-of-RIB.
#[test]
fn an_operator_refresh_mid_evpn_walk_resyncs_once_and_drops_the_cursor() {
    let rows = 40u32;
    let mut manager = manager(CREDIT).with_owing_theta_floor(1 << 20);
    std::mem::forget(up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]));
    let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 4096, &[EVPN])];
    let peer = receivers[0].peer;
    received(&mut manager, &all(rows), &[]);
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table, table(&all(rows)), "admitted");
    // It stops reading: changes spend its credit and the rest are owed by
    // key, the withdrawal of row 0 among them.
    let changed: Vec<_> = (8..32).map(|index| (index, 1)).collect();
    received(&mut manager, &changed, &[]);
    received(&mut manager, &[], &[0]);
    let kept = manager.owed_key_count(peer, FAMILY);
    assert!(kept != 0 && !manager.owes_whole(peer, FAMILY));
    // A cursor over the kept set, then rows for it to walk.
    manager.owe_eor(peer, EVPN);
    manager.owe_whole_family(peer, FAMILY);
    assert_eq!(
        manager.owed_key_count(peer, FAMILY),
        kept,
        "the set is kept"
    );
    let fresh: Vec<_> = (100..100 + rows).map(|index| (index, 0)).collect();
    received(&mut manager, &fresh, &[]);
    tick(&mut manager, &mut receivers);
    assert!(manager.owes_whole(peer, FAMILY), "mid-walk");
    assert!(manager.owed_evpn_rows.len() != 0);
    assert!(receivers[0].wire.table.contains_key(&key(0)), "row 0 held");
    assert_eq!(receivers[0].wire.markers, 0);
    receivers[0].wire.sent.clear();
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    let (reply, mut answer) = oneshot::channel();
    manager.handle_update(RibUpdate::RefreshPeerOutbound { peer, reply });
    assert!(matches!(answer.try_recv(), Ok(Ok(()))));
    assert!(!manager.dirty_peers.contains(&peer), "forced, not dirty");
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds - builds, 1);
    assert!(manager.owing(peer).is_none(), "cursor and kept set dropped");
    assert_eq!(manager.owed_evpn_rows.len(), 0, "the list is freed");
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.sent, [Sent::Rows, Sent::Eor]);
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds - builds, 1);
    assert_eq!(receivers[0].wire.count(0).1, 1, "row 0 withdrawn once");
    let expected: Vec<_> = (1..rows)
        .map(|index| (index, u32::from((8..32).contains(&index))))
        .chain(fresh)
        .collect();
    assert_settled(&manager, &receivers, &expected, "forced resync");
}

/// Contract (a stable owned sibling): a group-owned EVPN member beside a
/// private receiver never acquires a private position: not when its credit
/// is spent as a mutation fans out, and not at a selection release, which
/// starts the private receiver's cursor. Both end with the exact table.
/// Red when a group-owned family is in scope for owed keys.
#[test]
fn a_group_owned_evpn_sibling_never_acquires_a_private_cursor() {
    let rows = 20u32;
    let (mut manager, sibling, owned) = owned_sibling(deferral_manager(CREDIT));
    let private = Receiver::up(&mut manager, receiver(1), 4096, &[EVPN]);
    let (sibling_peer, private_peer) = (sibling.peer, private.peer);
    assert!(manager.evpn_grouped_member_of(private_peer).is_none());
    let mut receivers = vec![sibling, private];
    received(&mut manager, &all(rows), &[]);
    drain(&mut manager, &mut receivers);
    assert_no_cursor(&manager, sibling_peer, "converged");
    // Spent credit: a private receiver would owe these keys.
    let credit = manager.outbound_credit_handle(sibling_peer);
    let charge = crate::outbound_credit::OutboundCharge::new(&credit, CREDIT);
    received(&mut manager, &[(0, 1), (1, 1)], &[]);
    assert_no_cursor(&manager, sibling_peer, "spent credit");
    drop(charge);
    drain(&mut manager, &mut receivers);
    // A selection hold and its release.
    receivers.push(hold(&mut manager));
    received(&mut manager, &[(2, 1)], &[3]);
    assert_no_cursor(&manager, sibling_peer, "held");
    release(&mut manager);
    assert!(
        manager.owes_whole(private_peer, FAMILY),
        "the private cursor"
    );
    assert_eq!(manager.evpn_grouped_member_of(sibling_peer), Some(owned));
    assert_no_cursor(&manager, sibling_peer, "released");
    for _ in 0..1000 {
        tick(&mut manager, &mut receivers);
        assert_no_cursor(&manager, sibling_peer, "draining");
        if !manager.resync_tick_pending() {
            break;
        }
    }
    assert!(!manager.resync_tick_pending());
    let expected: Vec<_> = (0..rows)
        .filter(|index| *index != 3)
        .map(|index| (index, u32::from(index < 3)))
        .collect();
    for (index, receiver) in receivers.iter().enumerate() {
        assert_eq!(receiver.wire.table, table(&expected), "receiver {index}");
        assert_eq!(receiver.wire.rows_after_marker, 0, "receiver {index}");
        assert!(!manager.owes(receiver.peer, EVPN), "receiver {index}");
        assert!(!manager.dirty_peers.contains(&receiver.peer));
    }
    assert_eq!(receivers[0].wire.count(3), (1, 1));
    assert_eq!(manager.owed_evpn_rows.len(), 0);
}

/// One inbound message of a single kind whose paced fanout parks having
/// served exactly one of `receivers` (two that read and owe nothing).
/// Returns the index of the one it has not reached. Nothing here drains the
/// fanout: the caller's next events land between its slices.
fn park(
    manager: &mut RibManager,
    receivers: &[Receiver],
    announce: &[(u32, u32)],
    withdraw: &[u32],
) -> usize {
    park_charged(manager, receivers, announce, withdraw, None)
}

/// [`park`], the message charged to its session's ingest `budget`.
fn park_charged(
    manager: &mut RibManager,
    receivers: &[Receiver],
    announce: &[(u32, u32)],
    withdraw: &[u32],
    budget: Option<&Arc<IngestBudget>>,
) -> usize {
    assert_eq!(receivers.len(), 2);
    assert!(announce.is_empty() != withdraw.is_empty(), "one mutation");
    let before: Vec<_> = receivers
        .iter()
        .map(|receiver| manager.outbound_stagings(receiver.peer))
        .collect();
    let update = RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: announce
            .iter()
            .map(|&(index, variant)| route(index, variant))
            .collect(),
        evpn_withdrawn: withdraw.iter().map(|&index| key(index)).collect(),
        validated_with: None,
    };
    manager.handle_update(match budget {
        Some(budget) => update.metered(budget),
        None => update,
    });
    for _ in 0..=manager.outbound_peers.len() {
        let served: Vec<usize> = (0..2)
            .filter(|&index| manager.outbound_stagings(receivers[index].peer) != before[index])
            .collect();
        if let [served] = served[..] {
            assert!(manager.pending_evpn_fanout.is_some(), "parked");
            return 1 - served;
        }
        assert!(served.is_empty(), "one receiver per slice: {served:?}");
        assert!(manager.process_next_route_chunk());
    }
    panic!("the fanout reached no receiver");
}

/// A local origination of row `index`: one unpaced EVPN mutation.
fn inject(manager: &mut RibManager, index: u32) {
    let (reply, _result) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectEvpn {
        route: route(index, 0),
        reply,
    });
}

/// A local withdrawal of row `index`.
fn withdraw_injected(manager: &mut RibManager, index: u32) {
    let (reply, _result) = oneshot::channel();
    manager.handle_update(RibUpdate::WithdrawEvpn {
        key: key(index),
        reply,
    });
}

/// Fresh local rows rotate through the table, one in and one out, past
/// receivers that read nothing, until the list cap evicts `peer`. Returns
/// the row left in the table.
fn rotate_until_evicted(manager: &mut RibManager, peer: PeerId) -> u32 {
    let mut index = 2000;
    inject(manager, index);
    while !manager.owed_row_evicted.contains(&peer) {
        assert!(index < 20_000, "the receiver was never evicted");
        index += 1;
        inject(manager, index);
        withdraw_injected(manager, index - 1);
    }
    index
}

/// A ROUTE-REFRESH from a receiver the cap evicted long after its initial
/// End-of-RIB builds nothing in the request's turn: the tick's resync
/// sends the table, and the bracketed answer follows it, once. Red when
/// the request is answered in its own turn.
#[test]
fn an_evpn_refresh_from_an_evicted_receiver_that_owes_no_marker_follows_its_resync() {
    for grouped in [false, true] {
        refresh_from_an_evicted_receiver_that_owes_no_marker(grouped);
    }
}

fn refresh_from_an_evicted_receiver_that_owes_no_marker(grouped: bool) {
    let mut manager = manager(CREDIT).with_owing_theta_floor(1);
    manager.test_force_ungrouped = !grouped;
    std::mem::forget(up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]));
    let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 4096, &[EVPN])];
    let peer = receivers[0].peer;
    assert_eq!(manager.grouped_member_of(peer).is_some(), grouped);
    received(&mut manager, &all(4), &[]);
    drain(&mut manager, &mut receivers);
    let last = rotate_until_evicted(&mut manager, peer);
    receivers[0].write();
    receivers[0].wire.sent.clear();
    assert!(
        !manager.eor.owes(peer, EVPN),
        "its End-of-RIB left long ago"
    );
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    refresh_request(&mut manager, peer);
    receivers[0].write();
    assert_eq!(receivers[0].wire.sent, [], "built in the request's turn");
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
    assert!(manager.pending_refresh.contains_key(&peer), "still asked");
    assert!(manager.owed_row_evicted.contains(&peer));
    drain(&mut manager, &mut receivers);
    let mut expected = all(4);
    expected.push((last, 0));
    assert_eq!(
        receivers[0].wire.sent,
        [Sent::Rows, Sent::Answer(expected.len())],
        "the resync, then the bracketed answer"
    );
    assert_eq!(receivers[0].wire.table, table(&expected));
    assert_eq!(receivers[0].wire.markers, 0);
    assert!(!manager.pending_refresh.contains_key(&peer), "answered");
    assert!(manager.owed_row_evicted.is_empty());
}

/// A paced fanout logs its keys once and may park between receivers. A
/// receiver whose cursor starts while it is parked (local originations
/// spend its credit and take its owed set past the byte cap) has the
/// parked keys neither after its position nor, without the marks its start
/// adds, in its own set: it gets the parked announcements and the parked
/// withdrawal all the same, charged, with no resync. Both when no cursor
/// existed at the log (nothing was logged) and when another receiver's did.
/// Red when a cursor start ignores the parked fanout: the late receiver
/// never gets the parked rows and owes nothing.
#[test]
fn a_cursor_started_while_an_evpn_fanout_is_parked_gets_the_parked_keys() {
    for (cursor_at_log, withdrawal) in [(false, false), (false, true), (true, false), (true, true)]
    {
        let case = format!("cursor_at_log={cursor_at_log} withdrawal={withdrawal}");
        let mut manager = manager(CREDIT).with_owing_theta_floor(1);
        std::mem::forget(up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]));
        let mut receivers: Vec<Receiver> = (0..3)
            .map(|index| Receiver::up(&mut manager, receiver(index), 4096, &[EVPN]))
            .collect();
        received(&mut manager, &all(4), &[]);
        drain(&mut manager, &mut receivers);
        let mut expected = all(4);
        if cursor_at_log {
            // The third receiver stops reading and falls to a cursor.
            for index in 1000..1200 {
                inject(&mut manager, index);
                receivers[0].write();
                receivers[1].write();
                expected.push((index, 0));
            }
            assert!(manager.owes_whole(receivers[2].peer, FAMILY), "{case}");
        }
        for receiver in &receivers[..2] {
            assert!(!manager.owes(receiver.peer, EVPN), "{case}: streaming");
        }
        let logs = manager.adj_rib_out_commit_stats.owed_evpn_logs;
        let late = if withdrawal {
            expected.retain(|row| row.0 != 0);
            park(&mut manager, &receivers[..2], &[], &[0])
        } else {
            expected.extend([(10, 0), (11, 0)]);
            park(&mut manager, &receivers[..2], &[(10, 0), (11, 0)], &[])
        };
        assert_eq!(
            manager.adj_rib_out_commit_stats.owed_evpn_logs - logs,
            usize::from(cursor_at_log),
            "{case}: logged only for a cursor that exists"
        );
        let late_peer = receivers[late].peer;
        assert!(
            !manager.owes(late_peer, EVPN),
            "{case}: not reached, nothing owed"
        );
        // Unpaced local originations while the fanout is parked; nobody reads.
        for index in 2000..2200 {
            inject(&mut manager, index);
            expected.push((index, 0));
        }
        assert!(
            manager.pending_evpn_fanout.is_some(),
            "{case}: still parked"
        );
        assert!(
            manager.owes_whole(late_peer, FAMILY),
            "{case}: started mid-park"
        );
        let builds = manager.adj_rib_out_commit_stats.resync_builds;
        drain_route_chunks(&mut manager);
        assert!(manager.pending_evpn_fanout.is_none());
        drain(&mut manager, &mut receivers);
        for receiver in &receivers {
            assert_eq!(receiver.wire.table, table(&expected), "{case}");
            assert!(!manager.owes(receiver.peer, EVPN), "{case}");
            assert!(!manager.dirty_peers.contains(&receiver.peer), "{case}");
            assert_eq!(receiver.wire.uncharged + receiver.wire.latched, 0);
        }
        let parked = if withdrawal { (1, 1) } else { (1, 0) };
        let row = if withdrawal { 0 } else { 10 };
        assert_eq!(receivers[late].wire.count(row), parked, "{case}: once");
        assert_eq!(fallbacks(&manager), 0.0, "{case}: no resync");
        assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
        assert_eq!(manager.owed_evpn_rows.len(), 0, "{case}");
    }
}

/// A selection hold begins and is released while a fanout carrying a
/// withdrawal is parked. The release starts every receiver's cursor and
/// logs the inventory, which no longer names the withdrawn key: the
/// receiver the fanout had not reached still withdraws it, once. Red when
/// a cursor start ignores the parked fanout: that receiver keeps the row.
#[test]
fn a_release_while_an_evpn_fanout_is_parked_keeps_the_parked_withdrawal() {
    let mut manager = deferral_manager(CREDIT);
    std::mem::forget(up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]));
    let mut receivers: Vec<Receiver> = (0..2)
        .map(|index| Receiver::up(&mut manager, receiver(index), 4096, &[EVPN]))
        .collect();
    received(&mut manager, &all(4), &[]);
    drain(&mut manager, &mut receivers);
    let late = park(&mut manager, &receivers, &[], &[0]);
    let late_peer = receivers[late].peer;
    assert!(manager.loc_rib.get_evpn(&key(0)).is_none());
    assert_eq!(receivers[late].wire.count(0), (1, 0), "not reached");
    let waiter = hold(&mut manager);
    release(&mut manager);
    assert!(manager.pending_evpn_fanout.is_some(), "still parked");
    assert!(manager.owes_whole(late_peer, FAMILY), "owed by the release");
    drain_route_chunks(&mut manager);
    assert!(manager.pending_evpn_fanout.is_none());
    receivers.push(waiter);
    drain(&mut manager, &mut receivers);
    let expected: Vec<_> = (1..4).map(|index| (index, 0)).collect();
    for receiver in &receivers {
        assert_eq!(receiver.wire.table, table(&expected));
        assert!(!manager.owes(receiver.peer, EVPN));
        assert!(!manager.dirty_peers.contains(&receiver.peer));
    }
    assert_eq!(receivers[late].wire.count(0), (1, 1), "withdrawn once");
    assert_eq!(fallbacks(&manager), 0.0, "no resync");
    assert_eq!(manager.owed_evpn_rows.len(), 0);
}

/// Receivers whose table is built while a fanout is parked: one the list
/// cap evicts, the tick resyncs and local originations take back to a
/// cursor, and one that registers. Each build reads the Loc-RIB the parked
/// mutation already changed, so both end exact, and the marks a restarted
/// cursor takes from the parked fanout repeat no row.
#[test]
fn evpn_receivers_built_while_a_fanout_is_parked_end_exact() {
    let mut manager = manager(CREDIT).with_owing_theta_floor(1);
    std::mem::forget(up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]));
    let mut receivers: Vec<Receiver> = (0..2)
        .map(|index| Receiver::up(&mut manager, receiver(index), 4096, &[EVPN]))
        .collect();
    received(&mut manager, &all(4), &[]);
    drain(&mut manager, &mut receivers);
    let late = park(&mut manager, &receivers, &[(10, 0), (11, 0)], &[]);
    let late_peer = receivers[late].peer;
    // Fresh local keys rotate through the table past receivers that read
    // nothing: both fall to cursors, then the cap evicts them.
    let index = rotate_until_evicted(&mut manager, late_peer);
    assert!(manager.pending_evpn_fanout.is_some(), "still parked");
    // A receiver registers mid-park.
    let rx = up_sized(&mut manager, receiver(2), 0, 4096, &[EVPN]);
    receivers.push(Receiver {
        peer: receiver(2),
        rx,
        wire: Wire::default(),
    });
    // The tick resyncs the evicted receivers; the late one then stops
    // reading again and local originations restart its cursor.
    drain(&mut manager, &mut receivers);
    assert!(manager.owed_row_evicted.is_empty());
    assert!(!manager.owes(late_peer, EVPN));
    assert_eq!(receivers[late].wire.count(10), (1, 0), "by its resync");
    let mut expected: Vec<_> = all(4);
    expected.extend([(10, 0), (11, 0), (index, 0)]);
    for row in 30_000..30_200 {
        inject(&mut manager, row);
        expected.push((row, 0));
    }
    assert!(manager.owes_whole(late_peer, FAMILY), "restarted mid-park");
    assert!(manager.pending_evpn_fanout.is_some(), "still parked");
    drain_route_chunks(&mut manager);
    drain(&mut manager, &mut receivers);
    for receiver in &receivers {
        assert_eq!(receiver.wire.table, table(&expected));
        assert_eq!(receiver.wire.count(10), (1, 0), "the parked row, once");
        assert!(!manager.owes(receiver.peer, EVPN));
        assert!(!manager.dirty_peers.contains(&receiver.peer));
    }
    assert_eq!(manager.owed_evpn_rows.len(), 0);
}

/// A targeted restage no pass logged (an RT-Constrain membership change),
/// large enough to take the kept set past its byte cap, leaves a live
/// cursor where it is: the keys it has not read are named only by the
/// list after its position. Red when the cap check restarts the cursor at
/// the head: the unread rows are never sent and the End-of-RIB leaves.
#[test]
fn an_unlogged_restage_past_the_byte_cap_leaves_a_live_evpn_cursor_in_place() {
    let rows = 40u32;
    let (manager, mut receivers) = owing(1, rows, CREDIT);
    let mut manager = manager.with_owing_theta_floor(1);
    let peer = receivers[0].peer;
    tick(&mut manager, &mut receivers);
    let passed = |manager: &RibManager| -> Vec<u32> {
        (0..rows)
            .filter(|index| manager.owed_evpn_cursor_passed(peer, &key(*index)))
            .collect()
    };
    let before = passed(&manager);
    assert_eq!(before.len(), STEP);
    // Every key it has read and most it has not; ten stay named only by
    // the list after its position.
    let unread: Vec<u32> = (0..rows).filter(|index| !before.contains(index)).collect();
    let restaged: HashSet<_> = before
        .iter()
        .chain(&unread[10..])
        .map(|&index| key(index))
        .collect();
    manager.distribute_evpn_keys_to_peer(peer, &restaged, &mut || {});
    assert_eq!(manager.owed_key_count(peer, FAMILY), restaged.len());
    assert_eq!(passed(&manager), before, "the position did not move");
    drain(&mut manager, &mut receivers);
    assert_settled(&manager, &receivers, &all(rows), "unlogged restage");
}

/// A selection release that changes no winner logs its inventory and
/// returns before any fanout: the list is still cut back to its cap there,
/// and a receiver that reads nothing is evicted. Red when that return skips
/// the cap: the list grows with every such release.
#[test]
fn a_release_that_changes_no_winner_still_caps_the_evpn_list() {
    const BATCH: u32 = 512;
    let (mut manager, receivers) = owing(1, 8, CREDIT);
    let peer = receivers[0].peer;
    let cap = 2 * (8 + BATCH as usize) + 4 * CHUNK_ROWS;
    for round in 0..40 {
        // Keys a hold recorded that no table holds any more.
        let inventory: HashSet<_> = (0..BATCH)
            .map(|index| key(100_000 + round * BATCH + index))
            .collect();
        manager.recompute_and_distribute_released_evpn(&inventory);
        assert!(
            manager.owed_evpn_rows.len() <= cap,
            "round {round}: {} entries over the cap {cap}",
            manager.owed_evpn_rows.len()
        );
    }
    assert!(
        manager.owed_row_evicted.contains(&peer),
        "evicted, not pinned"
    );
    assert!(manager.dirty_peers.contains(&peer));
}

/// A mid-walk ROUTE-REFRESH whose absorption is admitted while the initial
/// End-of-RIB is held for another reason (the peer's RT-Constrain
/// membership): the rest of the walk goes out, the answer waits, and once
/// the hold ends the End-of-RIB leaves first and the bracketed answer
/// follows (RFC 7313 section 4). Red when the answer does not wait for the
/// marker: `BoRR` is sent ahead of the initial End-of-RIB.
#[test]
fn an_evpn_refresh_mid_walk_waits_for_a_held_initial_end_of_rib() {
    let rows = 40u32;
    let (mut manager, mut receivers) = owing(1, rows, CREDIT);
    let peer = receivers[0].peer;
    tick(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table.len(), STEP);
    manager.hold_eor_for_rt_membership(
        peer,
        tokio::time::Instant::now() + Duration::from_secs(3600),
    );
    refresh_request(&mut manager, peer);
    receivers[0].write();
    assert!(!manager.owes(peer, EVPN), "the refresh absorbed the walk");
    assert_eq!(receivers[0].wire.table, table(&all(rows)));
    assert!(manager.eor.owes(peer, EVPN), "the marker stays held");
    assert!(manager.pending_refresh.contains_key(&peer), "still asked");
    for _ in 0..4 {
        tick(&mut manager, &mut receivers);
    }
    assert_eq!(receivers[0].wire.sent, [Sent::Rows], "held: no answer");
    manager.end_rt_membership_hold(peer);
    drain(&mut manager, &mut receivers);
    assert_eq!(
        receivers[0].wire.sent,
        [Sent::Rows, Sent::Eor, Sent::Answer(rows as usize)],
        "the initial End-of-RIB, then the bracketed answer"
    );
    assert!(!manager.pending_refresh.contains_key(&peer), "answered");
    assert_settled(&manager, &receivers, &all(rows), "refresh behind a hold");
}

/// Tick until no resync work is left, every session writing: no tick builds
/// more than one table or captures more than one member's group table.
/// Returns the tables built and the captures made.
fn drain_one_unit_a_tick(manager: &mut RibManager, receivers: &mut [Receiver]) -> (usize, usize) {
    let start = manager.adj_rib_out_commit_stats;
    for _ in 0..5000 {
        if !manager.resync_tick_pending() {
            break;
        }
        let before = manager.adj_rib_out_commit_stats;
        tick(manager, receivers);
        let after = manager.adj_rib_out_commit_stats;
        let built = after.resync_builds - before.resync_builds;
        let captured = after.group_table_captures - before.group_table_captures;
        assert!(built <= 1, "{built} tables built in one tick");
        assert!(
            captured <= 1,
            "{captured} group tables captured in one tick"
        );
    }
    assert!(!manager.resync_tick_pending(), "the drain does not finish");
    let end = manager.adj_rib_out_commit_stats;
    (
        end.resync_builds - start.resync_builds,
        end.group_table_captures - start.group_table_captures,
    )
}

/// Work count (group members). In a default build a receiver is a member
/// of an update group for unicast and holds EVPN privately, and marking a
/// group member dirty walks its group's table twice to capture what it was
/// sent. A cap pass that evicts several stalled members of one group walks
/// no group table and builds nothing in the mutation's turn; the members
/// stay clean, so their group's unicast rows keep flowing to them while
/// EVPN waits. The resync tick then takes one member a tick: one capture
/// and one table, whatever poll budget is left. Each ends with the exact
/// tables of both families and one End-of-RIB after its last EVPN row. Red
/// when the cap marks each evicted member dirty: one capture per member in
/// the evicting turn.
#[test]
fn an_evpn_eviction_of_group_members_walks_no_group_table_in_its_turn() {
    const STALLED: u8 = 3;
    // The fixture asserts the evicting turn: no capture, no build.
    let (mut manager, mut receivers, mut expected) = evict_stalled_in(true, STALLED);
    manager.flush_poll_budget = Duration::from_secs(3600);
    for receiver in &mut receivers[1..] {
        receiver.write();
    }
    let stats = manager.adj_rib_out_commit_stats;
    received_unicast(&mut manager, UNICAST..UNICAST + 1);
    received(&mut manager, &[(5000, 0)], &[]);
    expected.push((5000, 0));
    for receiver in &mut receivers[1..] {
        receiver.write();
        assert_eq!(
            receiver.wire.unicast_table,
            unicast_table(UNICAST + 1),
            "its group's rows flow to an evicted member"
        );
        assert!(!receiver.wire.table.contains_key(&key(5000)), "EVPN waits");
        assert!(!manager.dirty_peers.contains(&receiver.peer));
        assert!(manager.owed_row_evicted.contains(&receiver.peer));
        assert!(manager.eor.owes(receiver.peer, EVPN), "its marker waits");
    }
    let now = manager.adj_rib_out_commit_stats;
    assert_eq!(
        (now.resync_builds, now.group_table_captures),
        (stats.resync_builds, stats.group_table_captures),
        "no mutation builds or captures for an evicted member"
    );
    let (built, captured) = drain_one_unit_a_tick(&mut manager, &mut receivers);
    assert_eq!(built, usize::from(STALLED), "one resync per evicted member");
    assert_eq!(captured, usize::from(STALLED), "one capture per member");
    assert_eq!(recoveries_observed(&manager), (u64::from(STALLED), 0));
    assert!(manager.owed_row_evicted.is_empty());
    for (index, receiver) in receivers.iter().enumerate() {
        assert_eq!(receiver.wire.table, table(&expected), "receiver {index}");
        assert_eq!(
            receiver.wire.unicast_table,
            unicast_table(UNICAST + 1),
            "receiver {index}"
        );
        assert_eq!(receiver.wire.markers, 1, "receiver {index}");
        assert_eq!(receiver.wire.rows_after_marker, 0, "receiver {index}");
        assert!(!manager.owes(receiver.peer, EVPN), "receiver {index}");
        assert!(!manager.dirty_peers.contains(&receiver.peer));
    }
    assert_eq!(manager.owed_evpn_rows.len(), 0, "the list is freed");
}

/// Evicted group members wait for the tick, and events reach them first:
/// one member's export policy moves it to another group (it is dirty as
/// any regrouped member is, no longer the tick's evicted unit, and its old
/// position is gone); another asks for an EVPN ROUTE-REFRESH (nothing is
/// built in the request's turn; the answer follows its resync and its
/// End-of-RIB); a third is refreshed by the operator (made dirty there, its
/// forced table left to the tick); unicast and EVPN then change. Every
/// tick builds at most one table and captures at most one group table, and
/// every receiver ends with the exact tables of both families, one
/// End-of-RIB after its last EVPN row (the regrouped member's precedes
/// the row that changed after its regroup). Red when the operator refresh
/// builds the table in its own turn, and when the tick never marks a
/// waiting member.
#[test]
fn evicted_group_members_meet_a_regroup_and_refreshes_before_their_units() {
    const STALLED: u8 = 3;
    let (mut manager, mut receivers, mut expected) = evict_stalled_in(true, STALLED);
    for receiver in &mut receivers[1..] {
        receiver.write();
        receiver.wire.sent.clear();
    }
    let (moved, asked, forced) = (receivers[1].peer, receivers[2].peer, receivers[3].peer);

    // A group change.
    let captures = manager.adj_rib_out_commit_stats.group_table_captures;
    regroup(&mut manager, moved, Some(permit_all()));
    assert!(manager.owing(moved).is_none(), "the old position is gone");
    assert!(!manager.owed_row_evicted.contains(&moved));
    assert!(
        manager.adj_rib_out_commit_stats.group_table_captures - captures <= 1,
        "the regroup captures its own member only"
    );
    receivers[1].write();
    assert_eq!(receivers[1].wire.markers, 1, "resynced by its regroup");

    // A peer refresh.
    let stats = manager.adj_rib_out_commit_stats;
    refresh_request(&mut manager, asked);
    receivers[2].write();
    assert_eq!(receivers[2].wire.sent, [], "built in the request's turn");
    let now = manager.adj_rib_out_commit_stats;
    assert_eq!(now.resync_builds, stats.resync_builds);
    assert_eq!(now.group_table_captures, stats.group_table_captures);
    assert!(manager.pending_refresh.contains_key(&asked), "still asked");
    assert!(manager.owed_row_evicted.contains(&asked));
    assert!(!manager.dirty_peers.contains(&asked));

    // An operator refresh.
    let (reply, mut answer) = oneshot::channel();
    manager.handle_update(RibUpdate::RefreshPeerOutbound {
        peer: forced,
        reply,
    });
    assert!(matches!(answer.try_recv(), Ok(Ok(()))));
    receivers[3].write();
    assert_eq!(receivers[3].wire.sent, [], "built in the command's turn");
    let now = manager.adj_rib_out_commit_stats;
    assert_eq!(now.resync_builds, stats.resync_builds);
    assert_eq!(now.group_table_captures - stats.group_table_captures, 1);
    assert!(
        manager.owed_row_evicted.contains(&forced),
        "the tick's unit"
    );
    assert!(manager.dirty_peers.contains(&forced));

    received_unicast(&mut manager, UNICAST..UNICAST + 1);
    received(&mut manager, &[(5000, 0)], &[]);
    expected.push((5000, 0));
    drain_one_unit_a_tick(&mut manager, &mut receivers);

    assert_eq!(
        receivers[2].wire.sent,
        [Sent::Rows, Sent::Eor, Sent::Answer(expected.len())],
        "the resync, its End-of-RIB, then the bracketed answer"
    );
    assert!(!manager.pending_refresh.contains_key(&asked), "answered");
    assert!(!manager.force_outbound_peers.contains(&forced));
    assert!(manager.owed_row_evicted.is_empty());
    for (index, receiver) in receivers.iter().enumerate() {
        assert_eq!(receiver.wire.table, table(&expected), "receiver {index}");
        assert_eq!(
            receiver.wire.unicast_table,
            unicast_table(UNICAST + 1),
            "receiver {index}"
        );
        assert_eq!(receiver.wire.markers, 1, "receiver {index}");
        // The regrouped member was resynced in the regroup's turn: the
        // row that changed afterward follows its End-of-RIB.
        assert_eq!(
            receiver.wire.rows_after_marker,
            usize::from(index == 1),
            "receiver {index}"
        );
        assert!(!manager.owes(receiver.peer, EVPN), "receiver {index}");
        assert!(!manager.dirty_peers.contains(&receiver.peer));
    }
    assert_eq!(manager.owed_evpn_rows.len(), 0, "the list is freed");
}

/// An evicted group member whose session ends before its unit leaves
/// nothing behind: no position, no eviction mark, no resync work. Its next
/// session starts from its own state and ends exact.
#[test]
fn an_evicted_group_member_that_flaps_before_its_unit_starts_again() {
    let (mut manager, mut receivers, expected) = evict_stalled_in(true, 2);
    let peer = receivers[1].peer;
    let stats = manager.adj_rib_out_commit_stats;
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    });
    assert!(manager.owing(peer).is_none());
    assert!(!manager.owed_row_evicted.contains(&peer));
    let mut rx = up_sized(&mut manager, peer, 1, 4096, &[V4, EVPN]);
    let mut wire = Wire::default();
    wire.write(&mut rx);
    receivers[1] = Receiver { peer, rx, wire };
    assert_eq!(
        manager.adj_rib_out_commit_stats.group_table_captures, stats.group_table_captures,
        "a flap captures nothing"
    );
    drain_one_unit_a_tick(&mut manager, &mut receivers);
    assert!(manager.owed_row_evicted.is_empty());
    for (index, receiver) in receivers.iter().enumerate() {
        assert_eq!(receiver.wire.table, table(&expected), "receiver {index}");
        assert_eq!(receiver.wire.unicast_table, unicast_table(UNICAST));
        assert_eq!(receiver.wire.markers, 1, "receiver {index}");
        assert_eq!(receiver.wire.rows_after_marker, 0, "receiver {index}");
        assert!(!manager.dirty_peers.contains(&receiver.peer));
    }
}

/// An evicted group member's position holds no list entry while it waits
/// for its unit: with every receiver evicted and no tick run, fresh keys
/// that keep rotating are logged for no one and the list is freed. Red
/// when such a position still counts as the slowest (the list is pinned
/// and grows with every mutation), when the cap evicts it again on every
/// pass, and when a drain step reads it: its End-of-RIB then leaves ahead
/// of the rows the resync sends.
#[test]
fn an_evicted_group_members_position_holds_no_list_entry() {
    let (mut manager, mut receivers, mut expected) = evict_stalled_in(true, 2);
    let mut fresh: Vec<(u32, u32)> = Vec::new();
    for round in 0..600u32 {
        let base = 100_000 + round * 64;
        let gone: Vec<u32> = fresh.iter().map(|&(index, _)| index).collect();
        fresh = (base..base + 64).map(|index| (index, 0)).collect();
        received(&mut manager, &fresh, &gone);
        if manager.owed_row_evicted.len() == receivers.len() && manager.owed_evpn_rows.len() == 0 {
            break;
        }
    }
    assert_eq!(
        manager.owed_row_evicted.len(),
        receivers.len(),
        "all evicted"
    );
    assert_eq!(manager.owed_evpn_rows.len(), 0, "the list is freed");
    assert!(
        manager.dirty_peers.is_empty(),
        "none is dirty before a tick"
    );
    assert!(
        (fallbacks(&manager) - 3.0).abs() < f64::EPSILON,
        "each receiver is evicted once"
    );
    expected.extend(fresh);
    let (built, captured) = drain_one_unit_a_tick(&mut manager, &mut receivers);
    assert_eq!((built, captured), (receivers.len(), receivers.len()));
    for (index, receiver) in receivers.iter().enumerate() {
        assert_eq!(receiver.wire.table, table(&expected), "receiver {index}");
        assert_eq!(receiver.wire.markers, 1, "receiver {index}");
        assert_eq!(receiver.wire.rows_after_marker, 0, "receiver {index}");
    }
}

/// Group members with small channels: the cap evicts `1 + readers` of
/// them. One (`stuck`) is dirty first, its channel full of its group's
/// unicast rows, and never writes; the others wait, clean. Returns the
/// unicast rows sent and the EVPN table every receiver must end with.
fn evict_one_stuck(readers: u8) -> (RibManager, Vec<Receiver>, u32, Vec<(u32, u32)>) {
    let mut manager = manager(CREDIT);
    manager.test_force_ungrouped = false;
    let (mut manager, mut receivers) = owing_from(manager, &[V4, EVPN], 2 + readers, 8, 8);
    received_unicast(&mut manager, 0..UNICAST);
    for receiver in &mut receivers {
        receiver.write();
    }
    let stuck = receivers[1].peer;
    let mut unicast = UNICAST;
    while !manager.dirty_peers.contains(&stuck) {
        assert!(unicast < UNICAST + 64, "the stuck member's channel fills");
        received_unicast(&mut manager, unicast..unicast + 1);
        unicast += 1;
        for (index, receiver) in receivers.iter_mut().enumerate() {
            if index != 1 {
                receiver.write();
            }
        }
    }
    let mut fresh: Vec<(u32, u32)> = Vec::new();
    for _round in 0..900u32 {
        let base = fresh.last().map_or(1000, |&(index, _)| index + 1);
        let gone: Vec<u32> = fresh.iter().map(|&(index, _)| index).collect();
        fresh = (base..base + 64).map(|index| (index, 0)).collect();
        received(&mut manager, &fresh, &gone);
        if manager.owed_row_evicted.len() == receivers.len() - 1 {
            break;
        }
        for _ in 0..12 {
            manager.resync_dirty_peers_bounded();
            receivers[0].write();
        }
    }
    assert_eq!(manager.owed_row_evicted.len(), receivers.len() - 1);
    assert!(manager.dirty_peers.contains(&stuck), "stuck is dirty");
    assert!(manager.outbound_channel_full(stuck));
    for receiver in &receivers[2..] {
        assert!(!manager.dirty_peers.contains(&receiver.peer), "waiting");
    }
    let expected = all(8).into_iter().chain(fresh).collect();
    (manager, receivers, unicast, expected)
}

/// Liveness: one evicted group member is stalled for good (dirty, its
/// channel full, its unit refused before it builds on every tick), and
/// several evicted members read. Every reader is rebuilt within two ticks
/// of its turn, each tick building at most one table and capturing at most
/// one group table, at any poll budget; the stalled member is rebuilt once
/// it reads. Red when a dirty evicted receiver that cannot build holds the
/// promotion of the others (no reader is ever rebuilt).
#[test]
fn a_stalled_evicted_member_holds_no_other_members_unit() {
    const READERS: u8 = 4;
    for budget in [Duration::ZERO, Duration::from_secs(3600)] {
        let (mut manager, mut receivers, unicast, expected) = evict_one_stuck(READERS);
        manager.flush_poll_budget = budget;
        let start = manager.adj_rib_out_commit_stats;
        let ticks = 2 * usize::from(READERS) + 2;
        for _ in 0..ticks {
            let before = manager.adj_rib_out_commit_stats;
            manager.resync_dirty_peers_bounded();
            for (index, receiver) in receivers.iter_mut().enumerate() {
                if index != 1 {
                    receiver.write();
                }
            }
            let after = manager.adj_rib_out_commit_stats;
            assert!(after.resync_builds - before.resync_builds <= 1);
            assert!(after.group_table_captures - before.group_table_captures <= 1);
        }
        let now = manager.adj_rib_out_commit_stats;
        assert_eq!(
            now.resync_builds - start.resync_builds,
            usize::from(READERS),
            "one table per reader, none for the stalled member ({budget:?})"
        );
        assert_eq!(
            now.group_table_captures - start.group_table_captures,
            usize::from(READERS),
            "one capture per reader"
        );
        for (index, receiver) in receivers.iter().enumerate().skip(2) {
            assert!(
                !manager.owed_row_evicted.contains(&receiver.peer),
                "reader {index} rebuilt within {ticks} ticks ({budget:?})"
            );
            assert_eq!(receiver.wire.table, table(&expected), "reader {index}");
            assert_eq!(receiver.wire.markers, 1, "reader {index}");
            assert_eq!(receiver.wire.rows_after_marker, 0, "reader {index}");
        }
        assert!(manager.owed_row_evicted.contains(&receivers[1].peer));
        // The stalled member reads at last.
        drain_one_unit_a_tick(&mut manager, &mut receivers);
        assert!(manager.owed_row_evicted.is_empty());
        for (index, receiver) in receivers.iter().enumerate() {
            assert_eq!(receiver.wire.table, table(&expected), "receiver {index}");
            assert_eq!(receiver.wire.unicast_table, unicast_table(unicast));
            assert_eq!(receiver.wire.markers, 1, "receiver {index}");
            assert_eq!(receiver.wire.rows_after_marker, 0, "receiver {index}");
            assert!(!manager.owes(receiver.peer, EVPN), "receiver {index}");
        }
        assert_eq!(manager.owed_evpn_rows.len(), 0, "the list is freed");
    }
}

/// An EVPN selection hold begins while two receivers the cap evicted still
/// wait for their units, and EVPN changes inside it. A resync inside the
/// hold enumerates no EVPN key, so no unit of theirs runs there, though
/// the ticks run for another dirty receiver: nothing is built or captured
/// for them, each keeps its eviction and its state (`dirty`:
/// already dirty when the hold began, as an ungrouped receiver always is;
/// otherwise a group member not yet promoted), and the tick does not stay
/// armed for them. After the release each is rebuilt by its unit, one a
/// tick, and ends exact. `admitted`: the receivers held the table before
/// they stalled, and row 5 was withdrawn while they owed EVPN whole (the
/// eviction dropped its list entry): the row leaves them. Otherwise they
/// still owe their End-of-RIB, which follows the rebuilt rows.
fn evicted_receivers_meet_a_hold(grouped: bool, dirty: bool, admitted: bool) {
    let case = format!("grouped={grouped} dirty={dirty} admitted={admitted}");
    let mut manager = deferral_manager(CREDIT);
    manager.test_force_ungrouped = !grouped;
    let (mut manager, mut receivers) = owing_from(manager, &[V4, EVPN], 3, 8, 4096);
    received_unicast(&mut manager, 0..UNICAST);
    if admitted {
        drain(&mut manager, &mut receivers);
        for receiver in &receivers {
            assert_eq!(receiver.wire.table, table(&all(8)), "{case}: admitted");
        }
    }
    let evicted = [receivers[1].peer, receivers[2].peer];
    let mut fresh: Vec<(u32, u32)> = Vec::new();
    let mut withdrawn = false;
    for _round in 0..900u32 {
        let base = fresh.last().map_or(1000, |&(index, _)| index + 1);
        let mut gone: Vec<u32> = fresh.iter().map(|&(index, _)| index).collect();
        if !withdrawn && evicted.iter().all(|&peer| manager.owes_whole(peer, FAMILY)) {
            gone.push(5);
            withdrawn = true;
        }
        fresh = (base..base + 64).map(|index| (index, 0)).collect();
        received(&mut manager, &fresh, &gone);
        if manager.owed_row_evicted.len() == 2 {
            break;
        }
        for _ in 0..12 {
            manager.resync_dirty_peers_bounded();
            receivers[0].write();
        }
    }
    assert!(withdrawn, "{case}");
    for peer in evicted {
        assert!(manager.owed_row_evicted.contains(&peer), "{case}: evicted");
        if dirty {
            // As a failed send leaves any receiver.
            manager.mark_outbound_dirty(peer);
        }
        assert_eq!(manager.dirty_peers.contains(&peer), dirty, "{case}");
    }
    let waiter = hold(&mut manager);
    receivers.push(waiter);
    received(&mut manager, &[(9000, 0)], &[6]);
    // The reader is dirty for a reason of its own, so ticks run their
    // whole course inside the hold: its resync is the only table built.
    manager.mark_outbound_dirty(receivers[0].peer);
    let stats = manager.adj_rib_out_commit_stats;
    for _ in 0..20 {
        tick(&mut manager, &mut receivers);
    }
    let now = manager.adj_rib_out_commit_stats;
    assert!(!manager.dirty_peers.contains(&receivers[0].peer), "{case}");
    assert_eq!(
        now.resync_builds - stats.resync_builds,
        1,
        "{case}: no evicted receiver's unit"
    );
    assert_eq!(
        now.group_table_captures, stats.group_table_captures,
        "{case}: no capture"
    );
    assert!(!manager.resync_tick_pending(), "{case}: the tick rests");
    for receiver in &receivers[1..3] {
        let peer = receiver.peer;
        assert!(manager.owed_row_evicted.contains(&peer), "{case}: kept");
        assert_eq!(manager.dirty_peers.contains(&peer), dirty, "{case}");
        assert_eq!(receiver.wire.table.contains_key(&key(5)), admitted);
        assert_eq!(receiver.wire.markers, usize::from(admitted), "{case}");
    }
    release(&mut manager);
    assert!(manager.resync_tick_pending(), "{case}: the release arms it");
    drain_one_unit_a_tick(&mut manager, &mut receivers);
    let expected: Vec<(u32, u32)> = (0..8)
        .filter(|index| *index != 5 && *index != 6)
        .map(|index| (index, 0))
        .chain(fresh)
        .chain([(9000, 0)])
        .collect();
    assert!(manager.owed_row_evicted.is_empty(), "{case}");
    for (index, receiver) in receivers[..3].iter().enumerate() {
        assert_eq!(receiver.wire.table, table(&expected), "{case}: {index}");
        assert_eq!(receiver.wire.markers, 1, "{case}: {index}");
        assert!(!manager.owes(receiver.peer, EVPN), "{case}: {index}");
        assert!(!manager.dirty_peers.contains(&receiver.peer), "{case}");
        if !admitted && index != 0 {
            assert_eq!(receiver.wire.rows_after_marker, 0, "{case}: {index}");
        }
    }
    assert_eq!(manager.owed_evpn_rows.len(), 0, "{case}: the list is freed");
}

/// Red when the tick promotes a waiting member inside the hold (its unit
/// clears the eviction with EVPN not enumerated, the kept position is read
/// again, and row 5 stays for good).
#[test]
fn a_hold_before_a_waiting_evicted_members_unit_loses_no_withdrawal() {
    evicted_receivers_meet_a_hold(true, false, true);
    evicted_receivers_meet_a_hold(true, false, false);
}

/// Red when the tick runs a dirty evicted receiver's unit inside the hold.
#[test]
fn a_hold_before_a_dirty_evicted_receivers_unit_loses_no_withdrawal() {
    for grouped in [true, false] {
        evicted_receivers_meet_a_hold(grouped, true, true);
        evicted_receivers_meet_a_hold(grouped, true, false);
    }
}

/// The state table's cells for a waiting evicted group member (not dirty,
/// debt kept, position dead), one event each; every case then ends exact
/// through `drain_one_unit_a_tick`.
/// - `channel_full`: the tick does not promote a member whose channel has
///   no room (no capture for a unit that would be refused); it does once
///   the member writes.
/// - `operation_live`: nor one whose whole-table operation is live.
/// - `channel_gone`: a member whose session is gone is dropped by the tick
///   in that tick, debt and eviction both.
/// - `absorb`: an operation that would absorb the family is refused as for
///   capacity; the debt and the eviction stay for the tick's unit.
/// - `close`: the shutdown flush reads no list entry from the dead
///   position.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table walks every event from the same waiting state to the same exact end"
)]
fn a_waiting_evicted_member_meets_each_event() {
    for case in [
        "channel_full",
        "operation_live",
        "channel_gone",
        "absorb",
        "close",
    ] {
        let (mut manager, mut receivers, _unicast, mut expected) = evict_one_stuck(2);
        // The stuck member reads now: only the case's member is special.
        receivers[1].write();
        let peer = receivers[2].peer;
        let stats = manager.adj_rib_out_commit_stats;
        let waits = |manager: &RibManager| {
            assert!(manager.owed_row_evicted.contains(&peer), "{case}: evicted");
            assert!(!manager.dirty_peers.contains(&peer), "{case}: clean");
            assert!(manager.owes_whole(peer, FAMILY), "{case}: debt kept");
        };
        waits(&manager);
        match case {
            "channel_full" => {
                let mut unicast = 100;
                while !manager.outbound_channel_full(peer) {
                    received_unicast(&mut manager, unicast..unicast + 1);
                    unicast += 1;
                    for (index, receiver) in receivers.iter_mut().enumerate() {
                        if index != 2 {
                            receiver.write();
                        }
                    }
                }
                waits(&manager);
                for _ in 0..8 {
                    manager.resync_dirty_peers_bounded();
                    for (index, receiver) in receivers.iter_mut().enumerate() {
                        if index != 2 {
                            receiver.write();
                        }
                    }
                }
                // (Every pass captures a clean member whose channel is
                // full, evicted or not, so captures are not counted here.)
                waits(&manager);
                assert_eq!(manager.owed_row_evicted.len(), 1, "{case}: the rest ran");
            }
            "operation_live" => {
                let operation = manager.begin_outbound_operation(peer, 1).unwrap();
                for _ in 0..8 {
                    tick(&mut manager, &mut receivers);
                }
                waits(&manager);
                assert_eq!(
                    manager.adj_rib_out_commit_stats.group_table_captures
                        - stats.group_table_captures,
                    1,
                    "{case}: the other waiting member only"
                );
                drop(operation);
            }
            "channel_gone" => {
                receivers.remove(2);
                manager.resync_dirty_peers_bounded();
                assert!(manager.owing(peer).is_none(), "{case}: in that tick");
                assert!(!manager.owing_peers.contains(&peer), "{case}");
                assert!(!manager.owed_row_evicted.contains(&peer), "{case}");
                assert!(!manager.dirty_peers.contains(&peer), "{case}");
            }
            "absorb" => {
                receivers[2].write();
                let rows = receivers[2].wire.announced.len();
                let mut operation = manager.begin_outbound_operation(peer, 2).unwrap();
                let absorbed = manager.absorb_owed_family(peer, EVPN, &mut operation);
                assert_eq!(
                    absorbed,
                    Err(crate::manager::outbound_credit::CREDIT_REFUSAL),
                    "{case}"
                );
                drop(operation);
                receivers[2].write();
                assert_eq!(receivers[2].wire.announced.len(), rows, "{case}");
                waits(&manager);
            }
            "close" => {
                // A live position, and two changes logged after the dead one.
                // The reader catches up by drain steps alone (no tick, so
                // nobody is promoted), then owes whole again from the head.
                for _ in 0..4096 {
                    if !manager.owes(receivers[0].peer, EVPN) {
                        break;
                    }
                    manager.drain_owing_bounded(std::time::Instant::now());
                    receivers[0].write();
                }
                assert!(!manager.owes(receivers[0].peer, EVPN), "{case}");
                manager.owe_whole_family(receivers[0].peer, FAMILY);
                received(&mut manager, &[(9000, 0)], &[3]);
                expected.retain(|&(index, _)| index != 3);
                expected.push((9000, 0));
                let kept: usize = receivers
                    .iter()
                    .map(|receiver| manager.owed_key_count(receiver.peer, FAMILY))
                    .sum();
                let read = manager.adj_rib_out_commit_stats.owed_drain_rows_read;
                manager.owing_close_flush();
                assert_eq!(
                    manager.adj_rib_out_commit_stats.owed_drain_rows_read - read,
                    kept + 2,
                    "{case}: each kept set and the live position's two keys"
                );
                waits(&manager);
            }
            _ => unreachable!(),
        }
        drain_one_unit_a_tick(&mut manager, &mut receivers);
        assert!(manager.owed_row_evicted.is_empty(), "{case}");
        for (index, receiver) in receivers.iter().enumerate() {
            assert_eq!(receiver.wire.table, table(&expected), "{case}: {index}");
            assert_eq!(receiver.wire.markers, 1, "{case}: {index}");
            assert!(!manager.owes(receiver.peer, EVPN), "{case}: {index}");
            assert!(!manager.dirty_peers.contains(&receiver.peer), "{case}");
        }
        assert_eq!(manager.owed_evpn_rows.len(), 0, "{case}: the list is freed");
    }
}

/// Two group members the cap evicted, still waiting (clean, debt kept),
/// that had admitted the table; row 5 was withdrawn while they owed EVPN
/// whole, so the eviction dropped its list entry. Then the EVPN selection
/// hold begins. Returns the rows received after the first eight.
fn two_waiting_in_a_hold() -> (RibManager, Vec<Receiver>, Vec<(u32, u32)>) {
    let mut manager = deferral_manager(CREDIT);
    manager.test_force_ungrouped = false;
    let (mut manager, mut receivers) = owing_from(manager, &[V4, EVPN], 3, 8, 4096);
    received_unicast(&mut manager, 0..UNICAST);
    drain(&mut manager, &mut receivers);
    let evicted = [receivers[1].peer, receivers[2].peer];
    let mut fresh: Vec<(u32, u32)> = Vec::new();
    let mut withdrawn = false;
    for _round in 0..900u32 {
        let base = fresh.last().map_or(1000, |&(index, _)| index + 1);
        let mut gone: Vec<u32> = fresh.iter().map(|&(index, _)| index).collect();
        if !withdrawn && evicted.iter().all(|&peer| manager.owes_whole(peer, FAMILY)) {
            gone.push(5);
            withdrawn = true;
        }
        fresh = (base..base + 64).map(|index| (index, 0)).collect();
        received(&mut manager, &fresh, &gone);
        if manager.owed_row_evicted.len() == 2 {
            break;
        }
        for _ in 0..12 {
            manager.resync_dirty_peers_bounded();
            receivers[0].write();
        }
    }
    assert!(withdrawn);
    assert_eq!(manager.owed_row_evicted.len(), 2);
    let waiter = hold(&mut manager);
    receivers.push(waiter);
    (manager, receivers, fresh)
}

/// A dirty resync inside an EVPN selection hold enumerates no EVPN key. A
/// receiver that holds row 5, whose withdrawal it missed before the hold,
/// is resynced there for a reason of its own: it ends clean for its other
/// families and waits as an evicted receiver does, so the release builds
/// nothing for it in its own turn and the tick's unit withdraws the row,
/// one table. A receiver that holds no EVPN row is resynced in the same
/// hold and is not made to wait: the release's inventory is its whole
/// table. Red when the in-hold resync leaves the first receiver clean and
/// owing nothing (row 5 stays for good).
#[test]
fn a_dirty_resync_inside_an_evpn_hold_loses_no_withdrawal() {
    let manager = deferral_manager(CREDIT);
    let (mut manager, mut receivers) = owing_from(manager, &[V4, EVPN], 2, 8, 4096);
    drain(&mut manager, &mut receivers);
    let peer = receivers[1].peer;
    assert_eq!(receivers[1].wire.table, table(&all(8)));
    // Unread rows spend the receiver's credit, so the withdrawal is owed.
    let mut fresh = Vec::new();
    for round in 0..4u32 {
        fresh.extend((2000 + round * 8..2008 + round * 8).map(|index| (index, 0)));
        received(&mut manager, &fresh, &[]);
    }
    received(&mut manager, &[], &[5]);
    assert!(manager.owes(peer, EVPN), "the withdrawal is owed");
    // As a failed send leaves any receiver: its debt is the dirty mark.
    manager.drop_peer_owing(peer);
    manager.mark_outbound_dirty(peer);
    receivers.push(hold(&mut manager));
    let empty = receiver(9);
    receivers.push(Receiver {
        peer: empty,
        rx: up_sized(&mut manager, empty, 0, 4096, &[V4, EVPN]),
        wire: Wire::default(),
    });
    manager.mark_outbound_dirty(empty);
    let stats = manager.adj_rib_out_commit_stats;
    for _ in 0..50 {
        tick(&mut manager, &mut receivers);
    }
    let held = manager.adj_rib_out_commit_stats;
    assert_eq!(held.resync_builds - stats.resync_builds, 2, "one each");
    assert!(!manager.dirty_peers.contains(&peer), "resynced in the hold");
    assert!(manager.owed_row_evicted.contains(&peer), "and waits");
    assert!(!manager.owed_row_evicted.contains(&receivers[3].peer));
    assert!(!manager.dirty_peers.contains(&receivers[3].peer));
    assert!(!manager.resync_tick_pending(), "the tick rests in the hold");
    assert!(receivers[1].wire.table.contains_key(&key(5)));
    release(&mut manager);
    assert_eq!(
        manager.adj_rib_out_commit_stats.resync_builds, held.resync_builds,
        "no table built in the release turn"
    );
    assert!(manager.owes_whole(receivers[3].peer, FAMILY), "a cursor");
    let (built, _) = drain_one_unit_a_tick(&mut manager, &mut receivers);
    assert_eq!(built, 1, "the waiting receiver's unit only");
    let expected: Vec<_> = all(8)
        .into_iter()
        .filter(|row| row.0 != 5)
        .chain(fresh)
        .collect();
    assert!(manager.owed_row_evicted.is_empty());
    for index in [0, 1, 3] {
        let receiver = &receivers[index];
        assert_eq!(receiver.wire.table, table(&expected), "{index}");
        assert!(!manager.owes(receiver.peer, EVPN), "{index}");
        assert!(!manager.dirty_peers.contains(&receiver.peer), "{index}");
    }
    assert_eq!(manager.owed_evpn_rows.len(), 0, "the list is freed");
}

/// The table's `regroup` cell inside an EVPN selection hold, for a waiting
/// evicted member and for a dirty one: the regroup's own resync runs in
/// the hold and enumerates no EVPN key, so the member waits again and row
/// 5, whose list entry the eviction dropped, leaves it by its unit after
/// the release. Red when the regroup leaves the member clean with no
/// eviction (row 5 stays for good).
#[test]
fn a_regroup_of_an_evicted_member_inside_an_evpn_hold_loses_no_withdrawal() {
    for dirty in [false, true] {
        let (mut manager, mut receivers, fresh) = two_waiting_in_a_hold();
        let moved = receivers[1].peer;
        if dirty {
            manager.mark_outbound_dirty(moved);
        }
        regroup(&mut manager, moved, Some(permit_all()));
        for _ in 0..50 {
            tick(&mut manager, &mut receivers);
        }
        assert!(!manager.dirty_peers.contains(&moved), "dirty={dirty}");
        assert!(manager.owed_row_evicted.contains(&moved), "dirty={dirty}");
        assert!(!manager.resync_tick_pending(), "dirty={dirty}: rests");
        release(&mut manager);
        drain_one_unit_a_tick(&mut manager, &mut receivers);
        let expected: Vec<_> = all(8)
            .into_iter()
            .filter(|row| row.0 != 5)
            .chain(fresh)
            .collect();
        assert!(manager.owed_row_evicted.is_empty(), "dirty={dirty}");
        for (index, receiver) in receivers[..3].iter().enumerate() {
            assert_eq!(receiver.wire.table, table(&expected), "{dirty}: {index}");
            assert!(!manager.owes(receiver.peer, EVPN), "{dirty}: {index}");
            assert!(!manager.dirty_peers.contains(&receiver.peer));
        }
        assert_eq!(manager.owed_evpn_rows.len(), 0, "dirty={dirty}");
    }
}

/// The table's `channel gone` cell for a dirty evicted member with a kept
/// debt: the tick that drops it drops the debt with the eviction mark. Red
/// when the mark alone is dropped (the dead position is live again).
#[test]
fn a_dirty_evicted_member_whose_channel_is_gone_keeps_no_debt() {
    let (mut manager, mut receivers, _unicast, _expected) = evict_one_stuck(1);
    let stuck = receivers[1].peer;
    assert!(manager.dirty_peers.contains(&stuck));
    assert!(manager.owes_whole(stuck, FAMILY), "debt kept");
    drop(receivers.remove(1));
    manager.resync_dirty_peers_bounded();
    assert!(!manager.dirty_peers.contains(&stuck));
    assert!(!manager.owed_row_evicted.contains(&stuck));
    assert!(manager.owing(stuck).is_none(), "in that tick");
    assert!(!manager.owing_peers.contains(&stuck));
}

/// The message whose fanout parks came from a session, so it carries that
/// session's ingest permit. What happens to a receiver while the fanout is
/// parked (its cursor starts, the cap evicts it, a release owes it whole,
/// its policy moves it) changes which receivers the later slices skip, not
/// when the message is finished: the budget is held after the event and
/// after every slice that leaves the fanout parked, and returns in the
/// step that reaches the last receiver. Red when the batch gives its permit
/// up as the fanout parks, and when a cursor start drops the parked fanout
/// (the batch finishes with receivers unreached).
#[test]
fn a_parked_evpn_fanout_keeps_its_ingest_budget_until_its_last_receiver() {
    for event in ["cursor", "eviction", "release", "regroup"] {
        let mut manager = if event == "release" {
            deferral_manager(CREDIT)
        } else {
            manager(CREDIT).with_owing_theta_floor(1)
        };
        std::mem::forget(up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]));
        let mut receivers: Vec<Receiver> = (0..2)
            .map(|index| Receiver::up(&mut manager, receiver(index), 4096, &[EVPN]))
            .collect();
        received(&mut manager, &all(4), &[]);
        drain(&mut manager, &mut receivers);
        let budget = IngestBudget::new();
        let parked = [(10, 0), (11, 0)];
        let late = park_charged(&mut manager, &receivers, &parked, &[], Some(&budget));
        let late_peer = receivers[late].peer;
        assert_eq!(budget.unfinished(), 2, "{event}: charged and parked");
        let mut expected = all(4);
        expected.extend(parked);
        match event {
            "cursor" => {
                for index in 2000..2200 {
                    inject(&mut manager, index);
                    expected.push((index, 0));
                }
                assert!(manager.owes_whole(late_peer, FAMILY), "{event}");
                assert!(
                    manager.owed_key_count(late_peer, FAMILY) >= 2,
                    "{event}: the parked keys joined its set"
                );
            }
            "eviction" => {
                let index = rotate_until_evicted(&mut manager, late_peer);
                expected.push((index, 0));
            }
            "release" => {
                receivers.push(hold(&mut manager));
                release(&mut manager);
                assert!(manager.owes_whole(late_peer, FAMILY), "{event}");
            }
            _ => regroup(&mut manager, late_peer, Some(permit_all())),
        }
        assert!(
            manager.pending_evpn_fanout.is_some(),
            "{event}: still parked"
        );
        assert_eq!(budget.unfinished(), 2, "{event}: held across the event");
        let mut steps = 0;
        while manager.pending_evpn_fanout.is_some() {
            steps += 1;
            assert!(steps < 64, "{event}: the fanout does not finish");
            assert!(manager.process_next_route_chunk());
            let held = if manager.pending_evpn_fanout.is_some() {
                2
            } else {
                0
            };
            assert_eq!(budget.unfinished(), held, "{event}: slice {steps}");
        }
        assert!(manager.pending_route_batches.is_empty(), "{event}");
        drain(&mut manager, &mut receivers);
        for receiver in &receivers {
            assert_eq!(receiver.wire.table, table(&expected), "{event}");
            assert!(!manager.owes(receiver.peer, EVPN), "{event}");
            assert!(!manager.dirty_peers.contains(&receiver.peer), "{event}");
        }
        assert_eq!(budget.unfinished(), 0, "{event}");
    }
}

/// The in-hold wait is for a dirty resync that ended clean, and for no
/// other resync. An operator refresh of a clean receiver forces a resync
/// inside the hold: the receiver missed nothing, so it does not wait. A
/// dirty resync whose commit is refused (no export encoder) leaves the
/// receiver dirty and not waiting, so the tick retries it inside the hold;
/// once a retry is admitted the receiver has its unicast rows there and
/// waits for its EVPN rebuild. Red when a forced resync waits too (every
/// refreshed receiver would be held until the release), and when a
/// still-dirty receiver is made to wait (the hold then holds its retry,
/// and its unicast rows with it).
#[test]
fn only_a_dirty_resync_that_ends_clean_inside_an_evpn_hold_waits() {
    let manager = deferral_manager(CREDIT);
    let (mut manager, mut receivers) = owing_from(manager, &[V4, EVPN], 2, 8, 4096);
    drain(&mut manager, &mut receivers);
    let (forced, refused) = (receivers[0].peer, receivers[1].peer);
    receivers.push(hold(&mut manager));

    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    let (reply, mut answer) = oneshot::channel();
    manager.handle_update(RibUpdate::RefreshPeerOutbound {
        peer: forced,
        reply,
    });
    assert!(matches!(answer.try_recv(), Ok(Ok(()))));
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds - builds, 1);
    assert!(!manager.force_outbound_peers.contains(&forced), "served");
    assert!(!manager.dirty_peers.contains(&forced));
    assert!(
        !manager.owed_row_evicted.contains(&forced),
        "a forced resync does not wait"
    );

    manager.mark_outbound_dirty(refused);
    let encoder = manager
        .peer_export_encoders
        .remove(&refused)
        .expect("an exact export encoder");
    received_unicast(&mut manager, 0..UNICAST);
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    for _ in 0..4 {
        tick(&mut manager, &mut receivers);
    }
    assert!(
        manager.adj_rib_out_commit_stats.resync_builds - builds >= 2,
        "the tick retries the refused resync inside the hold"
    );
    assert!(manager.dirty_peers.contains(&refused), "refused");
    assert!(
        !manager.owed_row_evicted.contains(&refused),
        "still dirty: not waiting"
    );
    assert!(receivers[1].wire.unicast_table.is_empty());
    manager.peer_export_encoders.insert(refused, encoder);
    for _ in 0..4 {
        tick(&mut manager, &mut receivers);
    }
    assert!(manager.selection_deferred(EVPN), "all inside the hold");
    assert_eq!(receivers[1].wire.unicast_table, unicast_table(UNICAST));
    assert!(!manager.dirty_peers.contains(&refused), "admitted");
    assert!(manager.owed_row_evicted.contains(&refused), "and waits");

    release(&mut manager);
    let (built, _) = drain_one_unit_a_tick(&mut manager, &mut receivers);
    assert_eq!(built, 1, "the waiting receiver's unit only");
    assert!(manager.owed_row_evicted.is_empty());
    for receiver in &receivers {
        assert_eq!(receiver.wire.table, table(&all(8)));
        assert!(!manager.owes(receiver.peer, EVPN));
        assert!(!manager.dirty_peers.contains(&receiver.peer));
    }
    assert_eq!(manager.owed_evpn_rows.len(), 0, "the list is freed");
}

/// The other side of the `channel gone` cell: a dirty receiver the cap did
/// not evict keeps its record, with its live position, when the tick drops
/// it from the retry; the record ends with the session. Red when the retry
/// drops every gone receiver's record.
#[test]
fn a_dirty_receiver_whose_channel_is_gone_keeps_a_live_position_for_its_session_end() {
    let (mut manager, mut receivers) = owing(2, 8, CREDIT);
    let gone = receivers[1].peer;
    manager.mark_outbound_dirty(gone);
    assert!(!manager.owed_row_evicted.contains(&gone));
    drop(receivers.remove(1));
    manager.resync_dirty_peers_bounded();
    assert!(!manager.dirty_peers.contains(&gone), "no retry");
    assert!(manager.owes_whole(gone, FAMILY), "the record is kept");
    assert!(manager.owing_peers.contains(&gone));
    manager.handle_update(RibUpdate::PeerDown {
        peer: gone,
        session_id: 0,
    });
    assert!(manager.owing(gone).is_none(), "ended with the session");
    drain(&mut manager, &mut receivers);
    assert_settled(&manager, &receivers, &all(8), "the other receiver");
}

/// A receiver in a private handoff inside an EVPN selection hold: a member
/// that left an EVPN-owning group dirty, with X withdrawn while its channel
/// was full, so only its recovery proof names X and it holds no EVPN row
/// of its own. Its resyncs inside the hold enumerate no EVPN key and cover
/// no proof, so its EVPN table stays owed through the hold, and the resync
/// after the release withdraws X. (It stays dirty there, so the in-hold
/// wait's recovery-handle condition is not what keeps it owed.)
#[test]
fn a_private_handoff_resynced_inside_an_evpn_hold_withdraws_after_the_release() {
    let first = 10u32;
    let (mut manager, sibling, owned) = owned_sibling(deferral_manager(CREDIT));
    let mover = Receiver::up(&mut manager, receiver(1), 8, &[EVPN]);
    let peer = mover.peer;
    regroup(&mut manager, peer, Some(permit_all()));
    assert_eq!(manager.evpn_grouped_member_of(peer), Some(owned));
    let mut receivers = vec![sibling, mover];
    received(&mut manager, &all(first), &[]);
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[1].wire.table, table(&all(first)), "admitted");
    let sender = manager.outbound_peers[&peer].clone();
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
    received(&mut manager, &[], &[0]);
    assert!(manager.dirty_peers.contains(&peer), "admission refused");
    receivers.push(hold(&mut manager));
    regroup(&mut manager, peer, None);
    assert!(manager.evpn_grouped_member_of(peer).is_none(), "private");
    assert!(manager.evpn_recovery_handle(peer).is_some(), "a proof");
    assert_eq!(
        manager
            .adj_ribs_out
            .get(&peer)
            .map_or(0, AdjRibOut::evpn_len),
        0,
        "no EVPN row of its own"
    );
    for _ in 0..50 {
        tick(&mut manager, &mut receivers);
    }
    assert!(manager.selection_deferred(EVPN));
    assert!(
        manager.dirty_peers.contains(&peer) || manager.owed_row_evicted.contains(&peer),
        "its EVPN table is still owed"
    );
    assert!(
        receivers[1].wire.table.contains_key(&key(0)),
        "X still held"
    );
    release(&mut manager);
    drain_one_unit_a_tick(&mut manager, &mut receivers);
    let expected: Vec<_> = (1..first).map(|index| (index, 0)).collect();
    assert_eq!(receivers[1].wire.table, table(&expected));
    assert_eq!(receivers[1].wire.count(0), (1, 1), "X withdrawn once");
    assert!(!manager.dirty_peers.contains(&peer));
    assert!(manager.owed_row_evicted.is_empty());
}
