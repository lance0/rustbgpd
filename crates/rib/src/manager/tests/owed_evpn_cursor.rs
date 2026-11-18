//! The EVPN row cursor (ADR-0099 amendment, slice 1b): a private receiver
//! that owes EVPN whole reads the shared list of the keys EVPN mutations
//! carried since its debt began, in bounded steps charged against its
//! outbound credit, and its End-of-RIB leaves when it has caught up.

use std::collections::BTreeMap;

use rustbgpd_wire::EvpnRouteKey;

use super::super::eor_hold::{EorHold, EorTrigger};
use super::super::outbound_owing::OwedFamily;
use super::*;
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
        negotiated_orf_recv: Vec::new(),
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
    let mut manager = manager(credit);
    std::mem::forget(up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]));
    let mut receivers: Vec<Receiver> = (0..receivers)
        .map(|index| {
            let receiver = Receiver::up(&mut manager, receiver(index), channel, &[EVPN]);
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
    let (mut manager, mut receivers) = owing(1 + stalled, 8, CREDIT);
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
        received(&mut manager, &fresh, &gone);
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

/// Contract (refresh before the initial End-of-RIB). Mid-walk, a peer's
/// ROUTE-REFRESH absorbs the rest of the walk into its own operation: the
/// owed rows, the initial End-of-RIB, then the answer between its markers.
/// From a receiver the cap evicted the request builds nothing in its own
/// turn and is kept through a resync whose commit is first refused (no
/// export encoder); it is answered after the admitted resync and its
/// End-of-RIB. Each marker is counted once. Red when the walk's remaining
/// rows are left out of the absorption (the End-of-RIB leaves ahead of
/// them), and when the request is spent while the evicted receiver's
/// initial End-of-RIB is still owed.
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

    // After eviction, with the recovery first refused.
    let (mut manager, mut receivers, expected) = evict_stalled(1);
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
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: 7,
        afi: EVPN.0,
        safi: EVPN.1,
    });
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
