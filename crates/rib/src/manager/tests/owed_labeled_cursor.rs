//! The labeled-unicast row cursor (ADR-0099 amendment, slice 1b): a
//! receiver that owes IPv4 or IPv6 labeled unicast whole reads the shared
//! list of the prefixes labeled passes carried since its debt began, in
//! bounded steps charged against its outbound credit, and its End-of-RIB
//! leaves when it has caught up. Every receiver holds these families in
//! its own Adj-RIB-Out, a member of an update group included.

use std::collections::{BTreeMap, BTreeSet};

use super::super::outbound_owing::{DrainScope, OwedFamily};
use super::*;
use crate::outbound_credit::CHUNK_ROWS;
use crate::route::{LabeledRibRoute, LabeledRibRouteKey};

const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const WAITER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// A second source, whose paths lose to [`SOURCE`]'s.
const SECOND: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
const V4: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const L4: (Afi, Safi) = (Afi::Ipv4, Safi::LabeledUnicast);
const L6: (Afi, Safi) = (Afi::Ipv6, Safi::LabeledUnicast);
const F4: OwedFamily = OwedFamily::IPV4_LABELED;
const F6: OwedFamily = OwedFamily::IPV6_LABELED;
/// Rows of outbound credit: a single-path step with the whole credit free
/// takes `CREDIT / 2` prefixes.
const CREDIT: usize = 16;
const STEP: usize = CREDIT / 2;
/// The labeled lists' slots in `RibManager::owed_rows`, after unicast's.
const LISTS: [usize; 2] = [2, 3];

/// What a receiver holds: each (prefix, path ID) with its label stack.
type Table = BTreeMap<(Prefix, u32), String>;

/// A manager whose peers stay ungrouped, one receiver step per resync tick.
fn manager(credit: usize) -> RibManager {
    deferral_manager(credit, &[])
}

/// [`manager`] with [`WAITER`] configured to hold selection of `held`.
fn deferral_manager(credit: usize, held: &[(Afi, Safi)]) -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 100)),
        BgpMetrics::new(),
    )
    .with_outbound_row_credit(credit);
    if !held.is_empty() {
        manager = manager.with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(WAITER).into(),
                families: held.to_vec(),
            }],
        });
    }
    manager.test_force_ungrouped = true;
    manager.flush_poll_budget = Duration::ZERO;
    manager
}

/// A session of `families` on a channel of `channel` envelopes, sending up
/// to `add_path` paths per labeled prefix (`u32::MAX`: all of them).
fn up(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
    channel: usize,
    families: &[(Afi, Safi)],
    add_path: u32,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, output) = mpsc::channel(channel);
    let labeled = |family: &&(Afi, Safi)| family.1 == Safi::LabeledUnicast;
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
        add_path_send_families: if add_path == 0 {
            vec![]
        } else {
            families.iter().filter(labeled).copied().collect()
        },
        add_path_send_max: add_path,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: Vec::new(),
    });
    output
}

/// Both sources come up; neither is sent labeled routes.
fn sources_up(manager: &mut RibManager) {
    for source in [SOURCE, SECOND] {
        std::mem::forget(up(manager, peer_v4(source), 0, 4096, &[V4], 0));
    }
}

fn receiver(index: u8) -> PeerId {
    peer_v4(Ipv4Addr::new(10, 0, 9, index + 1))
}

fn prefix(family: (Afi, Safi), index: u32) -> Prefix {
    if family == L6 {
        let address = (0x2001_0db8_u128 << 96) | u128::from(index);
        Prefix::V6(rustbgpd_wire::Ipv6Prefix::new(address.into(), 128))
    } else {
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(0x0b00_0000 + index), 32))
    }
}

/// Row `index` of `family` from `source`, with one label.
fn route_from(
    source: Ipv4Addr,
    family: (Afi, Safi),
    index: u32,
    label: u32,
    local_pref: u32,
) -> LabeledRibRoute {
    let mut route = make_labeled_rib_route(source, 0, label, local_pref);
    route.nlri.prefix = prefix(family, index);
    if family == L6 {
        route.next_hop = IpAddr::V6("2001:db8::1".parse().unwrap());
    }
    route
}

fn entry(route: &LabeledRibRoute, path_id: u32) -> ((Prefix, u32), String) {
    (
        (route.nlri.prefix, path_id),
        format!("{:?}", route.nlri.labels),
    )
}

/// The single-path table of `family` rows `(index, label)` from [`SOURCE`].
fn table_of(family: (Afi, Safi), rows: &[(u32, u32)]) -> Table {
    rows.iter()
        .map(|&(index, label)| entry(&route_from(SOURCE, family, index, label, 200), 0))
        .collect()
}

fn table(rows: &[(u32, u32)]) -> Table {
    table_of(L4, rows)
}

fn all(rows: u32) -> Vec<(u32, u32)> {
    (0..rows).map(|index| (index, 100)).collect()
}

fn send(
    manager: &mut RibManager,
    source: Ipv4Addr,
    announced: Vec<LabeledRibRoute>,
    withdrawn: Vec<Prefix>,
) {
    manager.handle_update(RibUpdate::LabeledRoutesReceived {
        peer: peer_v4(source),
        session_id: 0,
        announced,
        withdrawn: withdrawn
            .into_iter()
            .map(|prefix| LabeledRibRouteKey { prefix, path_id: 0 })
            .collect(),
    });
    drain_route_chunks(manager);
}

/// [`SOURCE`] announces IPv4 rows `(index, label)` and withdraws `withdraw`.
fn received(manager: &mut RibManager, announce: &[(u32, u32)], withdraw: &[u32]) {
    send(
        manager,
        SOURCE,
        announce
            .iter()
            .map(|&(index, label)| route_from(SOURCE, L4, index, label, 200))
            .collect(),
        withdraw.iter().map(|&index| prefix(L4, index)).collect(),
    );
}

/// The IPv4 rows [`SOURCE`] offers, kept beside what it sends.
#[derive(Default)]
struct Model(BTreeMap<u32, u32>);

impl Model {
    fn send(&mut self, manager: &mut RibManager, announce: &[(u32, u32)], withdraw: &[u32]) {
        self.0.extend(announce.iter().copied());
        for index in withdraw {
            self.0.remove(index);
        }
        received(manager, announce, withdraw);
    }

    fn table(&self) -> Table {
        table(&self.0.iter().map(|(&i, &l)| (i, l)).collect::<Vec<_>>())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sent {
    /// Labeled rows outside a refresh answer (one or more envelopes).
    Rows,
    /// An IPv4 labeled End-of-RIB outside a refresh answer.
    Eor,
    /// A refresh answer of this many rows.
    Answer(usize),
}

/// What one receiver's session has written.
#[derive(Default)]
struct Wire {
    table: Table,
    announced: Vec<Prefix>,
    withdrawn: Vec<Prefix>,
    /// End-of-RIB markers per labeled AFI, and rows written after the first.
    markers: [usize; 2],
    rows_after_marker: [usize; 2],
    /// Route-bearing envelopes that held no credit, or an operation latch.
    uncharged: usize,
    latched: usize,
    envelope_rows_max: usize,
    sent: Vec<Sent>,
    unicast_table: BTreeSet<Prefix>,
}

impl Wire {
    /// Write everything queued; the envelopes drop, returning their credit.
    fn write(&mut self, rx: &mut mpsc::Receiver<OutboundRouteUpdate>) {
        while let Ok(update) = rx.try_recv() {
            self.apply(&update);
        }
    }

    fn apply(&mut self, update: &OutboundRouteUpdate) {
        let answer = !update.refresh_markers.is_empty();
        let rows = update.labeled_announce.len() + update.labeled_withdraw.len();
        let unicast = update.announce.len() + update.unicast_withdrawals().count();
        if rows + unicast != 0 && !answer {
            self.uncharged += usize::from(update.credit.is_none());
            self.latched += usize::from(update.latch.is_some());
            self.envelope_rows_max = self.envelope_rows_max.max(rows + unicast);
        }
        for (prefix, _) in update.unicast_withdrawals() {
            self.unicast_table.remove(prefix);
        }
        for route in update.announce.iter() {
            self.unicast_table.insert(route.prefix);
        }
        let mut late = |prefix: &Prefix| {
            let afi = usize::from(matches!(prefix, Prefix::V6(_)));
            if self.markers[afi] != 0 && !answer {
                self.rows_after_marker[afi] += 1;
            }
        };
        for key in &update.labeled_withdraw {
            late(&key.prefix);
            assert!(
                self.table.remove(&(key.prefix, key.path_id)).is_some(),
                "withdrawal of {key:?}, which the receiver does not hold"
            );
            self.withdrawn.push(key.prefix);
        }
        for route in &update.labeled_announce {
            late(&route.nlri.prefix);
            let (key, labels) = entry(route, route.path_id);
            self.table.insert(key, labels);
            self.announced.push(route.nlri.prefix);
        }
        if answer {
            self.sent.push(Sent::Answer(update.labeled_announce.len()));
            return;
        }
        if rows != 0 && self.sent.last() != Some(&Sent::Rows) {
            self.sent.push(Sent::Rows);
        }
        for family in &update.end_of_rib {
            if *family == L4 {
                self.markers[0] += 1;
                self.sent.push(Sent::Eor);
            } else if *family == L6 {
                self.markers[1] += 1;
            }
        }
    }

    /// Announcements and withdrawals of IPv4 row `index`.
    fn count(&self, index: u32) -> (usize, usize) {
        let prefix = prefix(L4, index);
        (
            self.announced.iter().filter(|p| **p == prefix).count(),
            self.withdrawn.iter().filter(|p| **p == prefix).count(),
        )
    }

    fn holds(&self, index: u32) -> bool {
        self.table.contains_key(&(prefix(L4, index), 0))
    }
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

    /// A receiver whose session came up and wrote what it was sent then:
    /// that is not counted.
    fn up(
        manager: &mut RibManager,
        peer: PeerId,
        channel: usize,
        families: &[(Afi, Safi)],
        add_path: u32,
    ) -> Self {
        let mut rx = up(manager, peer, 0, channel, families, add_path);
        Wire::default().write(&mut rx);
        Self {
            peer,
            rx,
            wire: Wire::default(),
        }
    }

    /// Fill the session's channel: nothing more is admitted until it writes.
    fn stall(&self, manager: &RibManager) {
        let sender = &manager.outbound_peers[&self.peer];
        while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
    }
}

fn end_of_rib(manager: &mut RibManager, peer: PeerId, session_id: u64, family: (Afi, Safi)) {
    manager.handle_update(RibUpdate::EndOfRib {
        peer,
        session_id,
        afi: family.0,
        safi: family.1,
    });
}

/// The waiter's session comes up restarting: the selection hold of `held`
/// begins. The waiter is a labeled receiver too, and reads.
fn hold(manager: &mut RibManager, held: &[(Afi, Safi)]) -> Receiver {
    let peer = peer_v4(WAITER);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id: 7,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: held.to_vec(),
        peer_enhanced_refresh: false,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let rx = up(manager, peer, 7, 4096, held, 0);
    for &family in held {
        assert!(manager.selection_deferred(family));
    }
    Receiver {
        peer,
        rx,
        wire: Wire::default(),
    }
}

/// The waiter's End-of-RIB for `family`: that family's hold is released.
fn release(manager: &mut RibManager, family: (Afi, Safi)) {
    end_of_rib(manager, peer_v4(WAITER), 7, family);
    assert!(!manager.selection_deferred(family));
}

/// A receiver that joins inside a hold: nothing is sent to it.
fn join_held(manager: &mut RibManager, index: u8, families: &[(Afi, Safi)]) -> Receiver {
    let mut joiner = Receiver {
        peer: receiver(index),
        rx: up(manager, receiver(index), 0, 4096, families, 0),
        wire: Wire::default(),
    };
    joiner.write();
    assert_eq!((joiner.wire.table.len(), joiner.wire.markers), (0, [0, 0]));
    joiner
}

/// `receivers` receivers of `families` that owe their IPv4 labeled
/// End-of-RIB and the family whole (as a selection release leaves them),
/// then one pass carrying rows 0..`rows`: the debt every cursor starts
/// with. Nothing was staged.
fn owing(
    mut manager: RibManager,
    families: &[(Afi, Safi)],
    receivers: u8,
    rows: u32,
    channel: usize,
) -> (RibManager, Vec<Receiver>) {
    sources_up(&mut manager);
    let mut receivers: Vec<Receiver> = (0..receivers)
        .map(|index| {
            let receiver = Receiver::up(&mut manager, receiver(index), channel, families, 0);
            manager.owe_eor(receiver.peer, L4);
            manager.owe_whole_family(receiver.peer, F4);
            receiver
        })
        .collect();
    received(&mut manager, &all(rows), &[]);
    for receiver in &mut receivers {
        receiver.write();
        assert!(receiver.wire.announced.is_empty(), "owed, not staged");
        assert!(manager.owes_whole(receiver.peer, F4));
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

/// Whole-family drain steps the step histogram recorded.
fn whole_steps(manager: &RibManager) -> u64 {
    histogram_sample_counts_by_label(
        &manager.metrics,
        "bgp_rib_outbound_owed_drain_step_seconds",
        "scope",
    )
    .get("whole")
    .copied()
    .unwrap_or(0)
}

/// Every receiver ends with exactly `expected`, one IPv4 End-of-RIB after
/// its last row, every row charged, nothing owed, not dirty; the lists are
/// freed.
fn assert_settled(manager: &RibManager, receivers: &[Receiver], expected: &Table, case: &str) {
    for receiver in receivers {
        let wire = &receiver.wire;
        assert_eq!(&wire.table, expected, "{case}: exact table");
        assert_eq!(wire.markers[0], 1, "{case}: one End-of-RIB");
        assert_eq!(wire.rows_after_marker[0], 0, "{case}: marker last");
        assert_eq!(wire.uncharged + wire.latched, 0, "{case}: charged");
        assert!(!manager.owes(receiver.peer, L4), "{case}");
        assert!(!manager.dirty_peers.contains(&receiver.peer), "{case}");
        assert!(!manager.owed_row_evicted.contains(&receiver.peer));
    }
    assert!(manager.held_rebuilds.iter().all(HashSet::is_empty));
    assert!(
        manager.owed_rows.iter().all(|list| list.len() == 0),
        "{case}: the lists are freed"
    );
}

/// Contract 1 (release with unchanged winners): winners installed before a
/// hold and unchanged through it reach two receivers that joined during
/// the hold, each with one End-of-RIB after them. The release logs its
/// inventory once across the receivers, though no winner changed and
/// nothing fans out, and stages nothing in its turn. The sibling AFI stays
/// held: no cursor, no marker. With the held-key ledger overflowed, a
/// frozen winner withdrawn during the hold is withdrawn from the receiver
/// that had admitted it. Red when the list is seeded from the changed
/// winners only, and (overflow) without the frozen Loc-RIB inventory.
#[test]
fn a_labeled_release_seeds_unchanged_winners_once_for_every_receiver() {
    for overflow in [false, true] {
        let mut manager = deferral_manager(CREDIT, &[L4, L6]);
        sources_up(&mut manager);
        let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 4096, &[L4, L6], 0)];
        let mut model = Model::default();
        model.send(&mut manager, &all(20), &[]);
        drain(&mut manager, &mut receivers);
        assert_eq!(receivers[0].wire.table, model.table(), "admitted");
        receivers[0].wire.announced.clear();
        if overflow {
            manager.set_deferred_selection_limits_for_test(0, usize::MAX);
        }
        let waiter = hold(&mut manager, &[L4, L6]);
        for index in 1..3 {
            receivers.push(join_held(&mut manager, index, &[L4, L6]));
        }
        receivers.push(waiter);
        if overflow {
            model.send(&mut manager, &[], &[3]);
        }
        let logs = manager.adj_rib_out_commit_stats.owed_labeled_logs;
        let stagings: Vec<_> = receivers[..3]
            .iter()
            .map(|receiver| manager.outbound_stagings(receiver.peer))
            .collect();
        release(&mut manager, L4);
        assert_eq!(
            manager.adj_rib_out_commit_stats.owed_labeled_logs - logs,
            1,
            "overflow={overflow}: the release inventory is logged once"
        );
        for (receiver, before) in receivers[..3].iter_mut().zip(stagings) {
            receiver.write();
            assert_eq!(manager.outbound_stagings(receiver.peer), before);
            assert_eq!(receiver.wire.announced.len(), 0, "the turn stages no row");
            assert!(manager.owes_whole(receiver.peer, F4));
            assert!(!manager.owes_whole(receiver.peer, F6), "the sibling waits");
        }
        drain(&mut manager, &mut receivers);
        let expected = model.table();
        for receiver in &receivers[1..3] {
            let wire = &receiver.wire;
            assert_eq!(wire.table, expected, "overflow={overflow}");
            assert_eq!(wire.markers, [1, 0], "one End-of-RIB, the sibling's held");
            assert_eq!(wire.rows_after_marker, [0, 0]);
            assert_eq!(wire.announced.len(), expected.len(), "once each");
            assert_eq!(wire.uncharged + wire.latched, 0);
        }
        assert_eq!(receivers[0].wire.table, expected);
        assert_eq!(receivers[0].wire.announced.len(), 0, "nothing repeated");
        assert_eq!(
            receivers[0].wire.withdrawn,
            if overflow {
                vec![prefix(L4, 3)]
            } else {
                vec![]
            }
        );
        assert!(manager.selection_deferred(L6));
        assert!(receivers.iter().all(|r| !manager.owes(r.peer, L4)));
        assert_eq!(manager.owed_rows[LISTS[0]].len(), 0);
    }
}

/// `receivers[0]` takes one step while `receivers[1]` is stalled, so the
/// list keeps the entries behind the first position. Returns the rows the
/// first receiver has read, and those it has not.
fn one_step_ahead(
    manager: &mut RibManager,
    receivers: &mut [Receiver],
    rows: u32,
) -> [Vec<u32>; 2] {
    receivers[1].stall(manager);
    manager.resync_dirty_peers_bounded();
    manager.resync_dirty_peers_bounded();
    receivers[0].write();
    assert_eq!(receivers[0].wire.table.len(), STEP, "one step");
    let (passed, unread) = (0..rows).partition(|&index| receivers[0].wire.holds(index));
    [passed, unread]
}

/// Contract 2 (behind, ahead, re-announcement, second owe): with one
/// receiver a step into its walk and one that has read nothing, a row the
/// first has read changes, one it has not read changes, one it holds is
/// withdrawn and an unread one is withdrawn and announced again; then both
/// are owed the family a second time. The first receiver gets the changed
/// row again and an explicit withdrawal, each unread row once at its
/// newest state; the lagging one gets every row once. Red when the pass
/// does not log its prefixes for the cursors (the read row stays stale),
/// and when a second owe moves a live position to the head (the unread
/// rows are skipped).
#[test]
fn labeled_changes_behind_and_ahead_of_the_cursor_reach_each_receiver_at_their_newest_state() {
    const ROWS: u32 = 40;
    let (mut manager, mut receivers) = owing(manager(CREDIT), &[L4], 2, ROWS, 4096);
    let mut model = Model(all(ROWS).into_iter().collect());
    let [passed, unread] = one_step_ahead(&mut manager, &mut receivers, ROWS);
    let (a, c, b, d) = (passed[0], passed[1], unread[0], unread[1]);
    model.send(&mut manager, &[(a, 201), (b, 202)], &[c, d]);
    model.send(&mut manager, &[(d, 203)], &[]);
    for receiver in &receivers {
        manager.owe_whole_family(receiver.peer, F4);
    }
    drain(&mut manager, &mut receivers);
    assert_settled(&manager, &receivers, &model.table(), "behind and ahead");
    let fast = &receivers[0].wire;
    assert_eq!(fast.count(a), (2, 0), "read, then changed: sent again");
    assert_eq!(fast.count(c), (1, 1), "an explicit withdrawal");
    assert_eq!((fast.count(b), fast.count(d)), ((1, 0), (1, 0)), "once");
    let lagging = &receivers[1].wire;
    assert_eq!(lagging.announced.len(), model.0.len(), "each row once");
    assert_eq!(lagging.withdrawn, Vec::<Prefix>::new());
}

/// Contract 3 (relabel behind the cursor): a row the receiver has read
/// keeps its prefix, source, next hop and attributes and changes only its
/// label stack. It is replaced under the same key with no withdrawal, and
/// its sibling is not sent again. Red when a prefix already in the list is
/// not logged again: the cursor is past its entry and never returns.
#[test]
fn a_relabel_behind_a_labeled_cursor_replaces_the_row_under_its_key() {
    const ROWS: u32 = 24;
    let (mut manager, mut receivers) = owing(manager(CREDIT), &[L4], 2, ROWS, 4096);
    let mut model = Model(all(ROWS).into_iter().collect());
    let [passed, _] = one_step_ahead(&mut manager, &mut receivers, ROWS);
    let (relabeled, sibling) = (passed[0], passed[1]);
    model.send(&mut manager, &[(relabeled, 777)], &[]);
    drain(&mut manager, &mut receivers);
    assert_settled(&manager, &receivers, &model.table(), "relabel");
    let wire = &receivers[0].wire;
    assert_eq!(wire.count(relabeled), (2, 0), "replaced, never withdrawn");
    assert_eq!(wire.count(sibling), (1, 0), "the sibling is left alone");
    assert_eq!(receivers[1].wire.announced.len(), ROWS as usize);
}

/// Contract 4 (non-best change behind the cursor): an Add-Path receiver
/// holds ranks 1 and 2 of a prefix its cursor has read, and the second
/// candidate alone is withdrawn: no winner changes. The receiver gets an
/// explicit withdrawal of rank 2 and keeps rank 1; a single-path receiver
/// is sent nothing for it. Red when the list is seeded from the changed
/// winners instead of every affected prefix. The ORR vantage form of the
/// same widening is not exercised here.
#[test]
fn a_non_best_withdrawal_behind_a_labeled_cursor_reaches_an_add_path_receiver() {
    const ROWS: u32 = 40;
    const SHARED: u32 = 6;
    let mut manager = manager(CREDIT);
    sources_up(&mut manager);
    let mut receivers = vec![
        Receiver::up(&mut manager, receiver(0), 4096, &[L4], 0),
        Receiver::up(&mut manager, receiver(1), 4096, &[L4], 2),
    ];
    for receiver in &receivers {
        manager.owe_eor(receiver.peer, L4);
        manager.owe_whole_family(receiver.peer, F4);
    }
    let second = |index| route_from(SECOND, L4, index, 300, 100);
    send(
        &mut manager,
        SECOND,
        (0..SHARED).map(second).collect(),
        vec![],
    );
    received(&mut manager, &all(ROWS), &[]);
    let both = |wire: &Wire| {
        (0..SHARED).find(|&index| {
            wire.table.contains_key(&(prefix(L4, index), 1))
                && wire.table.contains_key(&(prefix(L4, index), 2))
        })
    };
    let mut passed = None;
    while passed.is_none() {
        assert!(manager.owes_whole(receivers[1].peer, F4), "still walking");
        tick(&mut manager, &mut receivers);
        passed = both(&receivers[1].wire);
    }
    let passed = passed.unwrap();
    assert!(manager.owes_whole(receivers[1].peer, F4), "mid-walk");
    send(&mut manager, SECOND, vec![], vec![prefix(L4, passed)]);
    drain(&mut manager, &mut receivers);
    let mut expected: Table = (0..ROWS)
        .map(|index| entry(&route_from(SOURCE, L4, index, 100, 200), 1))
        .collect();
    expected.extend(
        (0..SHARED)
            .filter(|&index| index != passed)
            .map(|index| entry(&second(index), 2)),
    );
    assert_settled(&manager, &receivers[1..], &expected, "add-path");
    assert_eq!(receivers[1].wire.withdrawn, [prefix(L4, passed)], "rank 2");
    assert_settled(&manager, &receivers[..1], &table(&all(ROWS)), "single-path");
    assert_eq!(
        receivers[0].wire.count(passed),
        (1, 0),
        "its best is unchanged"
    );
}

/// Contract 5 (a withdrawal owed only in the kept set): a receiver owes
/// the withdrawal of a row it holds, the row leaves every table, and more
/// owed prefixes take its set past the byte cap, then a selection hold is
/// released. The set is kept under the cursor through both, and the
/// withdrawal reaches the receiver. Red when the set is cleared as the
/// cursor starts.
#[test]
fn a_labeled_withdrawal_owed_only_in_the_kept_set_survives_a_flip_and_a_release() {
    let mut manager = deferral_manager(CREDIT, &[L4]);
    sources_up(&mut manager);
    let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 4096, &[L4], 0)];
    let peer = receivers[0].peer;
    let mut model = Model::default();
    model.send(&mut manager, &all(8), &[]);
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table, model.table());
    // Unread relabels spend the credit without growing the table.
    for label in 101..=116 {
        model.send(&mut manager, &[(0, label), (1, label), (2, label)], &[]);
        if manager.owes(peer, L4) {
            break;
        }
    }
    model.send(&mut manager, &[], &[5]);
    assert!(manager.owed_key_count(peer, F4) > 0 && !manager.owes_whole(peer, F4));
    // Disjoint batches rotate through the table until the set outgrows it.
    let mut previous = Vec::new();
    for round in 0..256u32 {
        let base = 1000 + round * 64;
        let fresh: Vec<_> = (base..base + 64).map(|index| (index, 100)).collect();
        model.send(&mut manager, &fresh, &previous);
        if manager.owes_whole(peer, F4) {
            break;
        }
        previous = (base..base + 64).collect();
    }
    assert!(manager.owes_whole(peer, F4), "a cursor");
    assert!(
        manager.owed_key_count(peer, F4) > 0,
        "the set survives the flip"
    );
    receivers.push(hold(&mut manager, &[L4]));
    release(&mut manager, L4);
    assert!(manager.owed_key_count(peer, F4) > 0, "and the release");
    drain(&mut manager, &mut receivers);
    let wire = &receivers[0].wire;
    assert_eq!(wire.table, model.table());
    assert_eq!(wire.count(5), (1, 1), "the owed withdrawal");
    assert_eq!(wire.uncharged + wire.latched, 0);
    assert!(!manager.owes(peer, L4) && !manager.dirty_peers.contains(&peer));
    assert!(manager.owed_rows.iter().all(|list| list.len() == 0));
}

/// Contract 6 (refusal): a step the channel refuses leaves the position
/// where it was, so every row is sent exactly once when the channel has
/// room again. A final marker the channel refuses (the last rows took its
/// last slot) is retried by itself: the peer is not made dirty and no row
/// is sent twice. Red when a refused step moves the position: the rows it
/// read are never sent.
#[test]
fn a_refused_labeled_step_keeps_its_position_and_a_refused_marker_replays_nothing() {
    const ROWS: u32 = 24;
    let (mut manager, mut receivers) = owing(manager(CREDIT), &[L4], 1, ROWS, 4096);
    let peer = receivers[0].peer;
    tick(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table.len(), STEP);
    receivers[0].stall(&manager);
    assert!(!manager.owing_drain_step(peer, F4, DrainScope::All, CREDIT));
    assert!(manager.owes_whole(peer, F4) && !manager.dirty_peers.contains(&peer));
    drain(&mut manager, &mut receivers);
    assert_settled(&manager, &receivers, &table(&all(ROWS)), "refused step");
    assert_eq!(
        receivers[0].wire.announced.len(),
        ROWS as usize,
        "once each"
    );

    // One slot: the only step's envelope fills it and the marker waits.
    let rows = u32::try_from(STEP).unwrap();
    let (mut manager, mut receivers) = owing(deferral_manager(CREDIT, &[]), &[L4], 1, rows, 1);
    let peer = receivers[0].peer;
    manager.resync_dirty_peers_bounded();
    assert!(!manager.owes(peer, L4), "every row was admitted");
    assert!(manager.eor.owes(peer, L4), "the marker was refused");
    assert!(
        !manager.dirty_peers.contains(&peer),
        "and waits for a retry"
    );
    drain(&mut manager, &mut receivers);
    assert_settled(&manager, &receivers, &table(&all(rows)), "refused marker");
    assert_eq!(receivers[0].wire.announced.len(), STEP, "no replay");
}

/// Contract 7 (refresh before the initial End-of-RIB): mid-walk, the
/// peer's ROUTE-REFRESH absorbs the rest of the walk into its own
/// operation: the owed rows, the initial End-of-RIB, then the answer. Red
/// when the cursor's remaining rows are left out of the absorption: the
/// End-of-RIB leaves ahead of them. The form after an eviction is the
/// shared path the EVPN tests pin; it is not repeated here.
#[test]
fn a_labeled_refresh_before_the_initial_end_of_rib_is_answered_after_it() {
    const ROWS: u32 = 40;
    let (mut manager, mut receivers) = owing(manager(CREDIT), &[L4], 1, ROWS, 4096);
    let peer = receivers[0].peer;
    tick(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table.len(), STEP);
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer,
        session_id: 0,
        afi: L4.0,
        safi: L4.1,
        queued: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    });
    assert!(!manager.owes(peer, L4), "the refresh absorbed the family");
    drain(&mut manager, &mut receivers);
    let wire = &receivers[0].wire;
    assert_eq!(
        wire.sent,
        [Sent::Rows, Sent::Eor, Sent::Answer(ROWS as usize)],
        "owed rows, the initial End-of-RIB, then the answer"
    );
    assert_eq!(wire.announced.len(), 2 * ROWS as usize, "walk + answer");
    assert_eq!(wire.table, table(&all(ROWS)));
    assert_eq!((wire.markers[0], wire.rows_after_marker[0]), (1, 0));
    assert!(!manager.pending_refresh.contains_key(&peer));
    assert!(manager.owed_rows.iter().all(|list| list.len() == 0));
}

/// Contract 8 (session, dirty and forced mid-walk): a session that ends
/// mid-walk takes its debt with it and its replacement starts from its own
/// initial table; a receiver made dirty mid-walk is covered by its resync,
/// which ends the cursor (no further step reads a row); an operator
/// refresh mid-walk likewise. Each ends with the exact table and one
/// End-of-RIB after its last row. Red when a resync leaves the record it
/// covered: the cursor walks on over rows the resync already sent.
#[test]
fn a_labeled_cursor_ends_with_its_session_and_a_resync_covers_it() {
    const ROWS: u32 = 24;
    let start = || {
        let (mut manager, mut receivers) = owing(manager(CREDIT), &[L4], 1, ROWS, 4096);
        tick(&mut manager, &mut receivers);
        assert_eq!(receivers[0].wire.table.len(), STEP);
        (manager, receivers)
    };

    let (mut manager, mut receivers) = start();
    let peer = receivers[0].peer;
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    });
    assert!(
        manager.owing(peer).is_none(),
        "the debt ends with the session"
    );
    receivers[0] = Receiver {
        peer,
        rx: up(&mut manager, peer, 1, 4096, &[L4], 0),
        wire: Wire::default(),
    };
    drain(&mut manager, &mut receivers);
    let wire = &receivers[0].wire;
    assert_eq!(wire.table, table(&all(ROWS)), "its own initial table");
    assert_eq!((wire.markers[0], wire.rows_after_marker[0]), (1, 0));
    assert_eq!(wire.announced.len(), ROWS as usize);
    assert!(manager.owing(peer).is_none());
    assert!(manager.owed_rows.iter().all(|list| list.len() == 0));

    for forced in [false, true] {
        let (mut manager, mut receivers) = start();
        let peer = receivers[0].peer;
        let steps = manager.adj_rib_out_commit_stats.owed_drain_steps;
        if forced {
            let (reply, mut result) = oneshot::channel();
            manager.handle_update(RibUpdate::RefreshPeerOutbound { peer, reply });
            result.try_recv().unwrap().unwrap();
        } else {
            manager.mark_outbound_dirty(peer);
        }
        drain(&mut manager, &mut receivers);
        let wire = &receivers[0].wire;
        assert_eq!(wire.table, table(&all(ROWS)), "forced={forced}");
        assert_eq!((wire.markers[0], wire.rows_after_marker[0]), (1, 0));
        assert!(!manager.owes(peer, L4) && !manager.dirty_peers.contains(&peer));
        assert_eq!(
            manager.adj_rib_out_commit_stats.owed_drain_steps, steps,
            "forced={forced}: the resync ended the cursor"
        );
        assert!(manager.owed_rows.iter().all(|list| list.len() == 0));
    }
}

/// Contract 9 (work and charge): 2,049 single-path rows per AFI released
/// to three receivers that joined in the hold drain in three steps per
/// AFI per receiver (1,024, 1,024, 1), none reading more than 1,024
/// prefixes, as ordinary charged envelopes with no operation latch and no
/// whole-family step; each release logs its inventory once for all of
/// them. Red when a step takes every prefix its credit allows.
#[test]
fn a_labeled_release_drains_in_steps_of_one_chunk_charged_and_unlatched() {
    let rows = u32::try_from(2 * CHUNK_ROWS + 1).unwrap();
    let mut manager = deferral_manager(4 * CHUNK_ROWS, &[L4, L6]);
    sources_up(&mut manager);
    for family in [L4, L6] {
        let routes = (0..rows).map(|index| route_from(SOURCE, family, index, 100, 200));
        send(&mut manager, SOURCE, routes.collect(), vec![]);
    }
    let waiter = hold(&mut manager, &[L4, L6]);
    let mut receivers = vec![
        join_held(&mut manager, 0, &[L4, L6]),
        join_held(&mut manager, 1, &[L4, L6]),
        waiter,
    ];
    let stats = manager.adj_rib_out_commit_stats;
    release(&mut manager, L4);
    release(&mut manager, L6);
    let logs = manager.adj_rib_out_commit_stats.owed_labeled_logs - stats.owed_labeled_logs;
    assert_eq!(logs, 2, "one inventory log per AFI, not per receiver");
    drain(&mut manager, &mut receivers);
    let now = manager.adj_rib_out_commit_stats;
    assert_eq!(now.owed_drain_steps - stats.owed_drain_steps, 3 * 2 * 3);
    assert_eq!(now.owed_drain_step_rows_max, CHUNK_ROWS);
    assert_eq!(now.resync_builds, stats.resync_builds, "no table built");
    assert_eq!(whole_steps(&manager), 0, "no whole-family operation");
    let mut expected = table_of(L4, &all(rows));
    expected.extend(table_of(L6, &all(rows)));
    for receiver in &receivers {
        let wire = &receiver.wire;
        assert_eq!(wire.table, expected);
        assert_eq!((wire.markers, wire.rows_after_marker), ([1, 1], [0, 0]));
        assert_eq!(wire.uncharged + wire.latched, 0, "charged, unlatched");
        assert!(wire.envelope_rows_max <= CHUNK_ROWS);
        assert!(manager.owing(receiver.peer).is_none());
    }
    assert!(manager.owed_rows.iter().all(|list| list.len() == 0));
}

/// Contract 10 (dirty resync inside the hold): a receiver holds a row
/// whose withdrawal it was owed when it went dirty and its debt was
/// dropped (as a failed send leaves it), and its resync then runs inside a
/// labeled selection hold, which enumerates no labeled prefix. The
/// receiver ends clean for its other families and owes a rebuild of the
/// held family; nothing is built in the release turn, and the tick's unit
/// after the release withdraws the row, which the release inventory does
/// not name. Red without the in-hold rule: the receiver keeps the row.
#[test]
fn a_dirty_resync_inside_a_labeled_hold_loses_no_withdrawal() {
    let manager = deferral_manager(CREDIT, &[L4]);
    let (mut manager, mut receivers) = owing(manager, &[L4], 2, 8, 4096);
    let mut model = Model(all(8).into_iter().collect());
    drain(&mut manager, &mut receivers);
    let peer = receivers[1].peer;
    assert_eq!(receivers[1].wire.table, model.table());
    // Unread rows spend the receiver's credit, so the withdrawal is owed.
    for round in 0..4u32 {
        let fresh: Vec<_> = (2000 + round * 8..2008 + round * 8)
            .map(|index| (index, 100))
            .collect();
        model.send(&mut manager, &fresh, &[]);
    }
    model.send(&mut manager, &[], &[5]);
    assert!(manager.owes(peer, L4), "the withdrawal is owed");
    manager.drop_peer_owing(peer);
    manager.mark_outbound_dirty(peer);
    receivers.push(hold(&mut manager, &[L4]));
    let stats = manager.adj_rib_out_commit_stats;
    for _ in 0..50 {
        tick(&mut manager, &mut receivers);
    }
    let held = manager.adj_rib_out_commit_stats;
    assert_eq!(held.resync_builds - stats.resync_builds, 1);
    assert!(!manager.dirty_peers.contains(&peer), "resynced in the hold");
    assert!(manager.owes_held_rebuild(peer, F4), "and waits");
    assert!(receivers[1].wire.holds(5));
    release(&mut manager, L4);
    assert_eq!(
        manager.adj_rib_out_commit_stats.resync_builds, held.resync_builds,
        "no table built in the release turn"
    );
    drain(&mut manager, &mut receivers);
    assert_eq!(
        manager.adj_rib_out_commit_stats.resync_builds - held.resync_builds,
        1,
        "the waiting receiver's unit only"
    );
    // The initial End-of-RIB left before the hold, and the subject's two
    // resyncs are whole-table operations: the tables are what count.
    assert_eq!(receivers[0].wire.uncharged + receivers[0].wire.latched, 0);
    for receiver in &receivers[..2] {
        assert_eq!(receiver.wire.table, model.table());
        assert!(!manager.owes(receiver.peer, L4));
        assert!(!manager.dirty_peers.contains(&receiver.peer));
    }
    assert_eq!(receivers[1].wire.count(5), (1, 1));
    assert!(manager.held_rebuilds.iter().all(HashSet::is_empty));
    assert!(manager.owed_rows.iter().all(|list| list.len() == 0));
}

/// Unicast rows the grouped fixture's group table holds.
const UNICAST: u32 = 6;

/// Contract 11 (cap eviction of group members). In a default build a
/// receiver is a member of an update group for unicast and holds labeled
/// unicast privately, and marking a member dirty walks its group's table
/// to capture what it was sent. Fresh prefixes rotate past three stalled
/// members until the list cap evicts them: the evicting pass walks no
/// group table and builds nothing, and the members stay clean. The resync
/// tick then takes one member a tick, one capture and one table each, and
/// every receiver ends with the exact tables of both families and one
/// End-of-RIB after its last labeled row. Red when the cap marks each
/// evicted member dirty: one capture per member in the evicting turn.
#[test]
fn a_labeled_eviction_of_group_members_walks_no_group_table_in_its_turn() {
    const STALLED: usize = 3;
    let mut manager = manager(CREDIT);
    manager.test_force_ungrouped = false;
    let (mut manager, mut receivers) = owing(manager, &[V4, L4], 4, 8, 4096);
    let mut model = Model(all(8).into_iter().collect());
    let unicast: Vec<Route> = (0..UNICAST)
        .map(|index| {
            let mut route = make_indexed_route(index + 1, SOURCE);
            route.peer = peer_v4(SOURCE);
            route
        })
        .collect();
    let unicast_table: BTreeSet<Prefix> = unicast.iter().map(|route| route.prefix).collect();
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: unicast,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    for receiver in &mut receivers {
        receiver.write();
        assert!(manager.grouped_member_of(receiver.peer).is_some());
        assert_eq!(receiver.wire.unicast_table, unicast_table);
    }
    let mut evicted = false;
    for round in 0..400u32 {
        let base = 1000 + round * 64;
        let fresh: Vec<_> = (base..base + 64).map(|index| (index, 100)).collect();
        let gone: Vec<_> = (base - 64..base).filter(|_| round != 0).collect();
        let before = fallbacks(&manager);
        let stats = manager.adj_rib_out_commit_stats;
        model.send(&mut manager, &fresh, &gone);
        if fallbacks(&manager) > before {
            let now = manager.adj_rib_out_commit_stats;
            assert_eq!(now.resync_builds, stats.resync_builds, "no resync built");
            assert_eq!(
                now.group_table_captures, stats.group_table_captures,
                "the evicting pass walks no group table"
            );
            for receiver in &receivers[1..] {
                assert!(manager.owed_row_evicted.contains(&receiver.peer));
                assert!(!manager.dirty_peers.contains(&receiver.peer));
            }
            evicted = true;
            break;
        }
        for _ in 0..12 {
            manager.resync_dirty_peers_bounded();
            receivers[0].write();
        }
    }
    assert!(evicted, "the stalled members were never evicted");
    manager.flush_poll_budget = Duration::from_secs(3600);
    let stats = manager.adj_rib_out_commit_stats;
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
    let now = manager.adj_rib_out_commit_stats;
    assert_eq!(now.resync_builds - stats.resync_builds, STALLED);
    assert_eq!(
        now.group_table_captures - stats.group_table_captures,
        STALLED
    );
    let expected = model.table();
    for receiver in &receivers {
        let wire = &receiver.wire;
        assert_eq!(wire.table, expected);
        assert_eq!(wire.unicast_table, unicast_table);
        assert_eq!((wire.markers[0], wire.rows_after_marker[0]), (1, 0));
        assert!(!manager.owes(receiver.peer, L4));
        assert!(!manager.dirty_peers.contains(&receiver.peer));
    }
    assert!(manager.owed_row_evicted.is_empty());
    assert!(manager.owed_rows.iter().all(|list| list.len() == 0));
}

/// Contract 12 (the two AFIs' gates release apart): the IPv4 release
/// starts IPv4 cursors only. A pass that then carries both AFIs logs its
/// IPv4 prefix and nothing for the held AFI, and the receivers get the
/// IPv4 table and its marker alone. The IPv6 release then delivers that
/// AFI, with the row that changed in between at its newest state, and its
/// own marker. Red when one release owes the sibling AFI too.
#[test]
fn labeled_afi_gates_that_release_apart_each_start_their_own_cursor() {
    const ROWS: u32 = 12;
    let mut manager = deferral_manager(CREDIT, &[L4, L6]);
    sources_up(&mut manager);
    let rows = |family, label: u32| -> Vec<LabeledRibRoute> {
        (0..ROWS)
            .map(|index| route_from(SOURCE, family, index, label, 200))
            .collect()
    };
    send(&mut manager, SOURCE, rows(L4, 100), vec![]);
    send(&mut manager, SOURCE, rows(L6, 100), vec![]);
    let waiter = hold(&mut manager, &[L4, L6]);
    let mut receivers = vec![
        join_held(&mut manager, 0, &[L4, L6]),
        join_held(&mut manager, 1, &[L4, L6]),
        waiter,
    ];
    release(&mut manager, L4);
    for receiver in &receivers {
        assert!(manager.owes_whole(receiver.peer, F4));
        assert!(!manager.owes_whole(receiver.peer, F6), "its gate is closed");
    }
    let changed = vec![
        route_from(SOURCE, L4, 1, 200, 200),
        route_from(SOURCE, L6, 1, 200, 200),
    ];
    send(&mut manager, SOURCE, changed, vec![]);
    assert_eq!(
        manager.owed_rows[LISTS[1]].len(),
        0,
        "a held AFI logs nothing"
    );
    drain(&mut manager, &mut receivers);
    let mut v4 = all(ROWS);
    v4[1].1 = 200;
    for receiver in &receivers {
        assert_eq!(receiver.wire.table, table_of(L4, &v4), "IPv4 only");
        assert_eq!(receiver.wire.markers, [1, 0]);
    }
    release(&mut manager, L6);
    drain(&mut manager, &mut receivers);
    let mut expected = table_of(L4, &v4);
    expected.extend(table_of(L6, &v4));
    for receiver in &receivers {
        let wire = &receiver.wire;
        assert_eq!(wire.table, expected);
        assert_eq!((wire.markers, wire.rows_after_marker), ([1, 1], [0, 0]));
        assert_eq!(wire.announced.len(), 2 * ROWS as usize, "once each");
        assert_eq!(wire.uncharged + wire.latched, 0);
        assert!(manager.owing(receiver.peer).is_none());
    }
    assert!(manager.owed_rows.iter().all(|list| list.len() == 0));
}

/// Contract 13 (Add-Path send-all work count): a receiver that is sent
/// every path of a prefix has no bound on the rows one prefix stages, so
/// its cursor takes one prefix a step: N prefixes with two paths each
/// drain in N steps, not ceil(N / 1,024), every row charged, with the
/// exact table and one End-of-RIB after the last row.
#[test]
fn a_send_all_add_path_labeled_cursor_takes_one_prefix_a_step() {
    const ROWS: u32 = 10;
    let mut manager = manager(CREDIT);
    sources_up(&mut manager);
    let mut receivers = vec![Receiver::up(
        &mut manager,
        receiver(0),
        4096,
        &[L4],
        u32::MAX,
    )];
    manager.owe_eor(receivers[0].peer, L4);
    manager.owe_whole_family(receivers[0].peer, F4);
    let second = |index| route_from(SECOND, L4, index, 300, 100);
    send(
        &mut manager,
        SECOND,
        (0..ROWS).map(second).collect(),
        vec![],
    );
    received(&mut manager, &all(ROWS), &[]);
    let steps = manager.adj_rib_out_commit_stats.owed_drain_steps;
    drain(&mut manager, &mut receivers);
    let stats = manager.adj_rib_out_commit_stats;
    assert_eq!(
        stats.owed_drain_steps - steps,
        ROWS as usize,
        "a prefix a step"
    );
    assert_eq!(stats.owed_drain_step_rows_max, 1);
    let expected: Table = (0..ROWS)
        .flat_map(|index| {
            [
                entry(&route_from(SOURCE, L4, index, 100, 200), 1),
                entry(&second(index), 2),
            ]
        })
        .collect();
    assert_settled(&manager, &receivers, &expected, "send-all");
    assert_eq!(receivers[0].wire.announced.len(), 2 * ROWS as usize);
}
