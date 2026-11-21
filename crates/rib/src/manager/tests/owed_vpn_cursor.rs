//! The VPN row cursor (ADR-0099 amendment, slice 1b): a receiver that owes
//! `VPNv4` or `VPNv6` whole reads the shared list of the route distinguisher
//! and prefix keys VPN passes carried since its debt began, in bounded
//! steps charged against its outbound credit, and its End-of-RIB leaves
//! when it has caught up. A receiver holds VPN in its own Adj-RIB-Out only
//! while it is outside every update group, as for unicast.

use std::collections::BTreeMap;

use rustbgpd_wire::{RouteDistinguisher, VpnPrefix, VpnRouteKey};

use super::super::outbound_owing::{DrainScope, OwedFamily};
use super::*;
use crate::outbound_credit::CHUNK_ROWS;
use crate::route::VpnRibRouteKey;

const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const WAITER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// A second source, whose paths lose to [`SOURCE`]'s.
const SECOND: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
const V4: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const P4: (Afi, Safi) = (Afi::Ipv4, Safi::MplsVpn);
const P6: (Afi, Safi) = (Afi::Ipv6, Safi::MplsVpn);
const F4: OwedFamily = OwedFamily::VPNV4;
const F6: OwedFamily = OwedFamily::VPNV6;
/// Rows of outbound credit: a single-path step with the whole credit free
/// takes `CREDIT / 2` keys.
const CREDIT: usize = 16;
const STEP: usize = CREDIT / 2;

/// What a receiver holds: each (RD/prefix key, path ID) with its labels.
type Table = BTreeMap<(VpnRouteKey, u32), String>;

fn owed_family(family: (Afi, Safi)) -> OwedFamily {
    if family == P6 { F6 } else { F4 }
}

fn afi(family: (Afi, Safi)) -> usize {
    usize::from(family == P6)
}

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
/// to `add_path` paths per VPN key (`u32::MAX`: all of them), with
/// `export_policy`.
fn up_with(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
    channel: usize,
    families: &[(Afi, Safi)],
    add_path: u32,
    export_policy: Option<PolicyChain>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, output) = mpsc::channel(channel);
    let vpn = |family: &&(Afi, Safi)| family.1 == Safi::MplsVpn;
    manager.handle_update(RibUpdate::PeerUp {
        supersedes: None,
        per_client_best: false,
        interpret_rfc1997: true,
        session_id,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 200),
        outbound_tx,
        export_policy,
        sendable_families: families.to_vec(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: if add_path == 0 {
            vec![]
        } else {
            families.iter().filter(vpn).copied().collect()
        },
        add_path_send_max: add_path,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: Vec::new(),
    });
    output
}

fn up(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
    channel: usize,
    families: &[(Afi, Safi)],
    add_path: u32,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    up_with(manager, peer, session_id, channel, families, add_path, None)
}

/// Both sources come up; neither is sent VPN routes.
fn sources_up(manager: &mut RibManager) {
    for source in [SOURCE, SECOND] {
        std::mem::forget(up(manager, peer_v4(source), 0, 4096, &[V4], 0));
    }
}

fn receiver(index: u8) -> PeerId {
    peer_v4(Ipv4Addr::new(10, 0, 9, index + 1))
}

/// Row `index` of `family`: rows `2n` and `2n + 1` share one prefix under
/// route distinguishers 65000:1 and 65000:2.
fn key(family: (Afi, Safi), index: u32) -> VpnRouteKey {
    let rd = 1 + u8::try_from(index % 2).unwrap();
    let host = index / 2;
    let prefix = if family == P6 {
        let address = (0x2001_0db8_u128 << 96) | u128::from(host);
        VpnPrefix::v6(address.into(), 128).unwrap()
    } else {
        VpnPrefix::v4(Ipv4Addr::from(0x0b00_0000 + host), 32).unwrap()
    };
    VpnRouteKey {
        route_distinguisher: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, rd]),
        prefix,
    }
}

/// Row `index` of `family` from `source`, with one label.
fn route_from(
    source: Ipv4Addr,
    family: (Afi, Safi),
    index: u32,
    label: u32,
    local_pref: u32,
) -> VpnRibRoute {
    let mut route = make_vpn_rib_route(source, 0, label, local_pref);
    let key = key(family, index);
    route.nlri.route_distinguisher = key.route_distinguisher;
    route.nlri.prefix = key.prefix;
    if family == P6 {
        route.next_hop = IpAddr::V6("2001:db8::1".parse().unwrap());
    }
    route
}

fn entry(route: &VpnRibRoute, path_id: u32) -> ((VpnRouteKey, u32), String) {
    (
        (route.nlri.key(), path_id),
        format!("{:?}", route.nlri.labels),
    )
}

/// The single-path table of `family` rows `(index, label)` from [`SOURCE`].
fn table_of(family: (Afi, Safi), rows: &[(u32, u32)]) -> Table {
    rows.iter()
        .map(|&(index, label)| entry(&route_from(SOURCE, family, index, label, 200), 0))
        .collect()
}

fn all(rows: u32) -> Vec<(u32, u32)> {
    (0..rows).map(|index| (index, 100)).collect()
}

fn send(
    manager: &mut RibManager,
    source: Ipv4Addr,
    announced: Vec<VpnRibRoute>,
    withdrawn: Vec<VpnRouteKey>,
) {
    manager.handle_update(RibUpdate::VpnRoutesReceived {
        peer: peer_v4(source),
        session_id: 0,
        announced,
        withdrawn: withdrawn
            .into_iter()
            .map(|nlri_key| VpnRibRouteKey {
                nlri_key,
                path_id: 0,
            })
            .collect(),
    });
    drain_route_chunks(manager);
}

/// [`SOURCE`] announces `family` rows `(index, label)` and withdraws
/// `withdraw`.
fn received(
    manager: &mut RibManager,
    family: (Afi, Safi),
    announce: &[(u32, u32)],
    withdraw: &[u32],
) {
    send(
        manager,
        SOURCE,
        announce
            .iter()
            .map(|&(index, label)| route_from(SOURCE, family, index, label, 200))
            .collect(),
        withdraw.iter().map(|&index| key(family, index)).collect(),
    );
}

/// The rows of one family [`SOURCE`] offers, kept beside what it sends.
struct Model {
    family: (Afi, Safi),
    rows: BTreeMap<u32, u32>,
}

impl Model {
    fn new(family: (Afi, Safi), rows: &[(u32, u32)]) -> Self {
        Self {
            family,
            rows: rows.iter().copied().collect(),
        }
    }

    fn send(&mut self, manager: &mut RibManager, announce: &[(u32, u32)], withdraw: &[u32]) {
        self.rows.extend(announce.iter().copied());
        for index in withdraw {
            self.rows.remove(index);
        }
        received(manager, self.family, announce, withdraw);
    }

    fn table(&self) -> Table {
        table_of(
            self.family,
            &self.rows.iter().map(|(&i, &l)| (i, l)).collect::<Vec<_>>(),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sent {
    /// VPN rows outside a refresh answer (one or more envelopes).
    Rows,
    /// A VPN End-of-RIB outside a refresh answer.
    Eor,
    /// A refresh answer of this many rows.
    Answer(usize),
}

/// What one receiver's session has written.
#[derive(Default)]
struct Wire {
    table: Table,
    announced: Vec<VpnRouteKey>,
    withdrawn: Vec<VpnRouteKey>,
    /// End-of-RIB markers per VPN AFI, and rows written after the first.
    markers: [usize; 2],
    rows_after_marker: [usize; 2],
    /// Route-bearing envelopes that held no credit, or an operation latch.
    uncharged: usize,
    latched: usize,
    envelope_rows_max: usize,
    sent: Vec<Sent>,
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
        let rows = update.vpn_announce.len() + update.vpn_withdraw.len();
        if rows != 0 && !answer {
            self.uncharged += usize::from(update.credit.is_none());
            self.latched += usize::from(update.latch.is_some());
            self.envelope_rows_max = self.envelope_rows_max.max(rows);
        }
        let mut late = |key: &VpnRouteKey| {
            let afi = usize::from(OwedFamily::vpn_of(key) == F6);
            if self.markers[afi] != 0 && !answer {
                self.rows_after_marker[afi] += 1;
            }
        };
        for key in &update.vpn_withdraw {
            late(&key.nlri_key);
            assert!(
                self.table.remove(&(key.nlri_key, key.path_id)).is_some(),
                "withdrawal of {key:?}, which the receiver does not hold"
            );
            self.withdrawn.push(key.nlri_key);
        }
        for route in update.vpn_announce.iter() {
            late(&route.nlri.key());
            let (key, labels) = entry(route, route.path_id);
            self.table.insert(key, labels);
            self.announced.push(route.nlri.key());
        }
        if answer {
            self.sent.push(Sent::Answer(update.vpn_announce.len()));
            return;
        }
        if rows != 0 && self.sent.last() != Some(&Sent::Rows) {
            self.sent.push(Sent::Rows);
        }
        for family in &update.end_of_rib {
            if *family == P4 {
                self.markers[0] += 1;
                self.sent.push(Sent::Eor);
            } else if *family == P6 {
                self.markers[1] += 1;
            }
        }
    }

    /// Announcements and withdrawals of `family` row `index`.
    fn count(&self, family: (Afi, Safi), index: u32) -> (usize, usize) {
        let key = key(family, index);
        (
            self.announced.iter().filter(|k| **k == key).count(),
            self.withdrawn.iter().filter(|k| **k == key).count(),
        )
    }

    fn holds(&self, family: (Afi, Safi), index: u32) -> bool {
        self.table.contains_key(&(key(family, index), 0))
    }

    fn rows_of(&self, family: (Afi, Safi)) -> usize {
        self.table
            .keys()
            .filter(|(key, _)| OwedFamily::vpn_of(key) == owed_family(family))
            .count()
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

fn gr_context(held: &[(Afi, Safi)]) -> RibUpdate {
    RibUpdate::SetPeerGracefulRestartContext {
        peer: peer_v4(WAITER),
        session_id: 7,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: held.to_vec(),
        peer_enhanced_refresh: false,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    }
}

/// The waiter's session comes up restarting: the selection hold of `held`
/// begins. The waiter is a VPN receiver too, and reads.
fn hold(manager: &mut RibManager, held: &[(Afi, Safi)]) -> Receiver {
    let peer = peer_v4(WAITER);
    manager.handle_update(gr_context(held));
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

/// `receivers` receivers of `families` that owe their `family` End-of-RIB
/// and the family whole (as a selection release leaves them), then one
/// pass carrying rows 0..`rows`: the debt every cursor starts with.
/// Nothing was staged.
fn owing(
    mut manager: RibManager,
    family: (Afi, Safi),
    families: &[(Afi, Safi)],
    receivers: u8,
    rows: u32,
    channel: usize,
) -> (RibManager, Vec<Receiver>) {
    sources_up(&mut manager);
    let mut receivers: Vec<Receiver> = (0..receivers)
        .map(|index| {
            let receiver = Receiver::up(&mut manager, receiver(index), channel, families, 0);
            manager.owe_eor(receiver.peer, family);
            manager.owe_whole_family(receiver.peer, owed_family(family));
            receiver
        })
        .collect();
    received(&mut manager, family, &all(rows), &[]);
    for receiver in &mut receivers {
        receiver.write();
        assert!(receiver.wire.announced.is_empty(), "owed, not staged");
        assert!(manager.owes_whole(receiver.peer, owed_family(family)));
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

/// Drain steps the step histogram recorded under `scope`.
fn steps_of(manager: &RibManager, scope: &str) -> u64 {
    histogram_sample_counts_by_label(
        &manager.metrics,
        "bgp_rib_outbound_owed_drain_step_seconds",
        "scope",
    )
    .get(scope)
    .copied()
    .unwrap_or(0)
}

fn lists_freed(manager: &RibManager) -> bool {
    manager.owed_vpn_rows.iter().all(|list| list.len() == 0)
}

/// Every receiver ends with exactly `expected`, one `family` End-of-RIB
/// after its last row, every row charged, nothing owed, not dirty; the
/// lists are freed.
fn assert_settled(
    manager: &RibManager,
    receivers: &[Receiver],
    family: (Afi, Safi),
    expected: &Table,
    case: &str,
) {
    let afi = afi(family);
    for receiver in receivers {
        let wire = &receiver.wire;
        assert_eq!(&wire.table, expected, "{case}: exact table");
        assert_eq!(wire.markers[afi], 1, "{case}: one End-of-RIB");
        assert_eq!(wire.rows_after_marker[afi], 0, "{case}: marker last");
        assert_eq!(wire.uncharged + wire.latched, 0, "{case}: charged");
        assert!(!manager.owes(receiver.peer, family), "{case}");
        assert!(!manager.dirty_peers.contains(&receiver.peer), "{case}");
        assert!(!manager.owed_row_evicted.contains(&receiver.peer));
    }
    assert!(lists_freed(manager), "{case}: the lists are freed");
}

/// Contract 1 (release with unchanged winners), each AFI: winners
/// installed before a hold and unchanged through it reach two receivers
/// that joined during the hold, each with one End-of-RIB after them. The
/// release logs its inventory once across the receivers, though no winner
/// changed and nothing fans out, and stages nothing in its turn. The
/// sibling AFI stays held: no cursor, no marker. With the held-key ledger
/// overflowed, a frozen winner withdrawn during the hold is withdrawn from
/// the receiver that had admitted it. Red when the pass logs the changed
/// winners only, and (overflow) without the frozen Loc-RIB inventory.
#[test]
fn a_vpn_release_seeds_unchanged_winners_once_for_every_receiver() {
    for (family, sibling) in [(P4, P6), (P6, P4)] {
        for overflow in [false, true] {
            let case = format!("{family:?}, overflow={overflow}");
            let mut manager = deferral_manager(CREDIT, &[P4, P6]);
            sources_up(&mut manager);
            let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 4096, &[P4, P6], 0)];
            let mut model = Model::new(family, &[]);
            model.send(&mut manager, &all(20), &[]);
            drain(&mut manager, &mut receivers);
            assert_eq!(receivers[0].wire.table, model.table(), "admitted");
            receivers[0].wire.announced.clear();
            if overflow {
                manager.set_deferred_selection_limits_for_test(0, usize::MAX);
            }
            let waiter = hold(&mut manager, &[P4, P6]);
            for index in 1..3 {
                receivers.push(join_held(&mut manager, index, &[P4, P6]));
            }
            receivers.push(waiter);
            if overflow {
                model.send(&mut manager, &[], &[3]);
            }
            let logs = manager.adj_rib_out_commit_stats.owed_vpn_logs;
            let stagings: Vec<_> = receivers[..3]
                .iter()
                .map(|receiver| manager.outbound_stagings(receiver.peer))
                .collect();
            release(&mut manager, family);
            assert_eq!(
                manager.adj_rib_out_commit_stats.owed_vpn_logs - logs,
                1,
                "{case}: the release inventory is logged once"
            );
            for (receiver, before) in receivers[..3].iter_mut().zip(stagings) {
                receiver.write();
                assert_eq!(manager.outbound_stagings(receiver.peer), before);
                assert_eq!(receiver.wire.announced.len(), 0, "the turn stages no row");
                assert!(manager.owes_whole(receiver.peer, owed_family(family)));
                assert!(
                    !manager.owes_whole(receiver.peer, owed_family(sibling)),
                    "the sibling waits"
                );
            }
            drain(&mut manager, &mut receivers);
            let expected = model.table();
            let mut markers = [0, 0];
            markers[afi(family)] = 1;
            for receiver in &receivers[1..3] {
                let wire = &receiver.wire;
                assert_eq!(wire.table, expected, "{case}");
                assert_eq!(wire.markers, markers, "{case}: the sibling's is held");
                assert_eq!(wire.rows_after_marker, [0, 0]);
                assert_eq!(wire.announced.len(), expected.len(), "once each");
                assert_eq!(wire.uncharged + wire.latched, 0);
            }
            assert_eq!(receivers[0].wire.table, expected, "{case}");
            assert_eq!(receivers[0].wire.announced.len(), 0, "nothing repeated");
            assert_eq!(
                receivers[0].wire.withdrawn,
                if overflow {
                    vec![key(family, 3)]
                } else {
                    vec![]
                },
                "{case}"
            );
            assert!(manager.selection_deferred(sibling));
            assert!(receivers.iter().all(|r| !manager.owes(r.peer, family)));
            assert!(lists_freed(&manager), "{case}");
        }
    }
}

/// `receivers[0]` takes one step while `receivers[1]` is stalled, so the
/// list keeps the entries behind the first position. Returns the rows the
/// first receiver has read, and those it has not.
fn one_step_ahead(
    manager: &mut RibManager,
    receivers: &mut [Receiver],
    family: (Afi, Safi),
    rows: u32,
) -> [Vec<u32>; 2] {
    receivers[1].stall(manager);
    manager.resync_dirty_peers_bounded();
    manager.resync_dirty_peers_bounded();
    receivers[0].write();
    assert_eq!(receivers[0].wire.table.len(), STEP, "one step");
    let (passed, unread) = (0..rows).partition(|&index| receivers[0].wire.holds(family, index));
    [passed, unread]
}

/// Contract 2 (behind, ahead, re-announcement, second owe), each AFI: with
/// one receiver a step into its walk and one that has read nothing, a row
/// the first has read changes, one it has not read changes, one it holds
/// is withdrawn and an unread one is withdrawn and announced again; then
/// both are owed the family a second time. The first receiver gets the
/// changed row again and an explicit withdrawal, each unread row once at
/// its newest state; the lagging one gets every row once. Red when the
/// pass does not log its keys for the cursors (the read row stays stale),
/// and when a second owe moves a live position to the head (the unread
/// rows are skipped).
#[test]
fn vpn_changes_behind_and_ahead_of_the_cursor_reach_each_receiver_at_their_newest_state() {
    const ROWS: u32 = 40;
    for family in [P4, P6] {
        let (mut manager, mut receivers) = owing(manager(CREDIT), family, &[family], 2, ROWS, 4096);
        let mut model = Model::new(family, &all(ROWS));
        let [passed, unread] = one_step_ahead(&mut manager, &mut receivers, family, ROWS);
        let (a, c, b, d) = (passed[0], passed[1], unread[0], unread[1]);
        model.send(&mut manager, &[(a, 201), (b, 202)], &[c, d]);
        model.send(&mut manager, &[(d, 203)], &[]);
        for receiver in &receivers {
            manager.owe_whole_family(receiver.peer, owed_family(family));
        }
        drain(&mut manager, &mut receivers);
        let case = format!("{family:?}: behind and ahead");
        assert_settled(&manager, &receivers, family, &model.table(), &case);
        let fast = &receivers[0].wire;
        assert_eq!(
            fast.count(family, a),
            (2, 0),
            "read, then changed: sent again"
        );
        assert_eq!(fast.count(family, c), (1, 1), "an explicit withdrawal");
        assert_eq!(
            (fast.count(family, b), fast.count(family, d)),
            ((1, 0), (1, 0)),
            "once"
        );
        let lagging = &receivers[1].wire;
        assert_eq!(lagging.announced.len(), model.rows.len(), "each row once");
        assert_eq!(lagging.withdrawn, Vec::<VpnRouteKey>::new());
    }
}

/// Contract 3 (relabel behind the cursor, two route distinguishers): a row
/// the receiver has read keeps its RD, prefix, source, next hop and
/// attributes and changes only its label stack. It is replaced under the
/// same key with no withdrawal, and the row with the same prefix under the
/// other RD is not sent again. Red when a key already in the list is not
/// logged again: the cursor is past its entry and never returns.
#[test]
fn a_relabel_behind_a_vpn_cursor_replaces_the_row_and_leaves_the_other_rd() {
    const ROWS: u32 = 24;
    let (mut manager, mut receivers) = owing(manager(CREDIT), P4, &[P4], 2, ROWS, 4096);
    let mut model = Model::new(P4, &all(ROWS));
    let [passed, _] = one_step_ahead(&mut manager, &mut receivers, P4, ROWS);
    let relabeled = passed[0];
    let sibling = relabeled ^ 1;
    assert_eq!(key(P4, relabeled).prefix, key(P4, sibling).prefix);
    assert_ne!(
        key(P4, relabeled).route_distinguisher,
        key(P4, sibling).route_distinguisher
    );
    model.send(&mut manager, &[(relabeled, 777)], &[]);
    drain(&mut manager, &mut receivers);
    assert_settled(&manager, &receivers, P4, &model.table(), "relabel");
    let wire = &receivers[0].wire;
    assert_eq!(
        wire.count(P4, relabeled),
        (2, 0),
        "replaced, never withdrawn"
    );
    assert_eq!(
        wire.count(P4, sibling),
        (1, 0),
        "the other RD is left alone"
    );
    assert_eq!(receivers[1].wire.announced.len(), ROWS as usize);
}

/// Contract 4 (non-best change behind the cursor): an Add-Path receiver
/// holds ranks 1 and 2 of a key its cursor has read, and the second
/// candidate alone is withdrawn: no winner changes. The receiver gets an
/// explicit withdrawal of rank 2 and keeps rank 1; a single-path receiver
/// is sent nothing for it. Red when the pass logs the changed winners
/// instead of every affected key. The ORR vantage form of the same
/// widening is not exercised here.
#[test]
fn a_non_best_withdrawal_behind_a_vpn_cursor_reaches_an_add_path_receiver() {
    const ROWS: u32 = 40;
    const SHARED: u32 = 6;
    let mut manager = manager(CREDIT);
    sources_up(&mut manager);
    let mut receivers = vec![
        Receiver::up(&mut manager, receiver(0), 4096, &[P4], 0),
        Receiver::up(&mut manager, receiver(1), 4096, &[P4], 2),
    ];
    for receiver in &receivers {
        manager.owe_eor(receiver.peer, P4);
        manager.owe_whole_family(receiver.peer, F4);
    }
    let second = |index| route_from(SECOND, P4, index, 300, 100);
    send(
        &mut manager,
        SECOND,
        (0..SHARED).map(second).collect(),
        vec![],
    );
    received(&mut manager, P4, &all(ROWS), &[]);
    let both = |wire: &Wire| {
        (0..SHARED).find(|&index| {
            wire.table.contains_key(&(key(P4, index), 1))
                && wire.table.contains_key(&(key(P4, index), 2))
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
    send(&mut manager, SECOND, vec![], vec![key(P4, passed)]);
    drain(&mut manager, &mut receivers);
    let mut expected: Table = (0..ROWS)
        .map(|index| entry(&route_from(SOURCE, P4, index, 100, 200), 1))
        .collect();
    expected.extend(
        (0..SHARED)
            .filter(|&index| index != passed)
            .map(|index| entry(&second(index), 2)),
    );
    assert_settled(&manager, &receivers[1..], P4, &expected, "add-path");
    assert_eq!(receivers[1].wire.withdrawn, [key(P4, passed)], "rank 2");
    assert_settled(
        &manager,
        &receivers[..1],
        P4,
        &table_of(P4, &all(ROWS)),
        "single-path",
    );
    assert_eq!(
        receivers[0].wire.count(P4, passed),
        (1, 0),
        "its best is unchanged"
    );
}

/// Contract 5 (a withdrawal owed only in the kept set): a receiver owes
/// the withdrawal of a row it holds, the row leaves every table, and more
/// owed keys take its set past the byte cap, then a selection hold is
/// released. The set is kept under the cursor through both, and the
/// withdrawal reaches the receiver. Red when the set is cleared as the
/// cursor starts.
#[test]
fn a_vpn_withdrawal_owed_only_in_the_kept_set_survives_a_flip_and_a_release() {
    let mut manager = deferral_manager(CREDIT, &[P4]);
    sources_up(&mut manager);
    let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 4096, &[P4], 0)];
    let peer = receivers[0].peer;
    let mut model = Model::new(P4, &[]);
    model.send(&mut manager, &all(8), &[]);
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table, model.table());
    // Unread relabels spend the credit without growing the table.
    for label in 101..=116 {
        model.send(&mut manager, &[(0, label), (1, label), (2, label)], &[]);
        if manager.owes(peer, P4) {
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
    receivers.push(hold(&mut manager, &[P4]));
    release(&mut manager, P4);
    assert!(manager.owed_key_count(peer, F4) > 0, "and the release");
    drain(&mut manager, &mut receivers);
    let wire = &receivers[0].wire;
    assert_eq!(wire.table, model.table());
    assert_eq!(wire.count(P4, 5), (1, 1), "the owed withdrawal");
    assert_eq!(wire.uncharged + wire.latched, 0);
    assert!(!manager.owes(peer, P4) && !manager.dirty_peers.contains(&peer));
    assert!(lists_freed(&manager));
}

/// Contract 6 (refusal): a step the channel refuses leaves the position
/// where it was, so every row is sent exactly once when the channel has
/// room again. A final marker the channel refuses (the last rows took its
/// last slot) is retried by itself: the peer is not made dirty and no row
/// is sent twice. Red when a refused step moves the position: the rows it
/// read are never sent.
#[test]
fn a_refused_vpn_step_keeps_its_position_and_a_refused_marker_replays_nothing() {
    const ROWS: u32 = 24;
    let (mut manager, mut receivers) = owing(manager(CREDIT), P6, &[P6], 1, ROWS, 4096);
    let peer = receivers[0].peer;
    tick(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table.len(), STEP);
    receivers[0].stall(&manager);
    assert!(!manager.owing_drain_step(peer, F6, DrainScope::All, CREDIT));
    assert!(manager.owes_whole(peer, F6) && !manager.dirty_peers.contains(&peer));
    drain(&mut manager, &mut receivers);
    let expected = table_of(P6, &all(ROWS));
    assert_settled(&manager, &receivers, P6, &expected, "refused step");
    assert_eq!(
        receivers[0].wire.announced.len(),
        ROWS as usize,
        "once each"
    );

    // One slot: the only step's envelope fills it and the marker waits.
    let rows = u32::try_from(STEP).unwrap();
    let (mut manager, mut receivers) = owing(deferral_manager(CREDIT, &[]), P4, &[P4], 1, rows, 1);
    let peer = receivers[0].peer;
    manager.resync_dirty_peers_bounded();
    assert!(!manager.owes(peer, P4), "every row was admitted");
    assert!(manager.eor.owes(peer, P4), "the marker was refused");
    assert!(
        !manager.dirty_peers.contains(&peer),
        "and waits for a retry"
    );
    drain(&mut manager, &mut receivers);
    let expected = table_of(P4, &all(rows));
    assert_settled(&manager, &receivers, P4, &expected, "refused marker");
    assert_eq!(receivers[0].wire.announced.len(), STEP, "no replay");
}

/// Contract 7 (refresh before the initial End-of-RIB, and the close
/// flush): mid-walk, the peer's ROUTE-REFRESH absorbs the rest of the walk
/// into its own operation: the owed rows, the initial End-of-RIB, then the
/// answer. Red when the cursor's remaining rows are left out of the
/// absorption: the End-of-RIB leaves ahead of them. Separately, a daemon
/// shutdown mid-walk sends the owed withdrawal of a row the receiver holds,
/// read from the list after its position, and leaves its debt as it was.
#[test]
fn a_vpn_refresh_before_the_initial_end_of_rib_is_answered_after_it() {
    const ROWS: u32 = 40;
    let (mut manager, mut receivers) = owing(manager(CREDIT), P4, &[P4], 1, ROWS, 4096);
    let peer = receivers[0].peer;
    tick(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table.len(), STEP);
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer,
        session_id: 0,
        afi: P4.0,
        safi: P4.1,
        queued: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    });
    assert!(!manager.owes(peer, P4), "the refresh absorbed the family");
    drain(&mut manager, &mut receivers);
    let wire = &receivers[0].wire;
    assert_eq!(
        wire.sent,
        [Sent::Rows, Sent::Eor, Sent::Answer(ROWS as usize)],
        "owed rows, the initial End-of-RIB, then the answer"
    );
    assert_eq!(wire.announced.len(), 2 * ROWS as usize, "walk + answer");
    assert_eq!(wire.table, table_of(P4, &all(ROWS)));
    assert_eq!((wire.markers[0], wire.rows_after_marker[0]), (1, 0));
    assert!(!manager.pending_refresh.contains_key(&peer));
    assert!(lists_freed(&manager));

    // Shutdown mid-walk: a held row withdrawn behind the position.
    let (mut manager, mut receivers) =
        owing(deferral_manager(CREDIT, &[]), P4, &[P4], 1, ROWS, 4096);
    let peer = receivers[0].peer;
    tick(&mut manager, &mut receivers);
    let held = (0..ROWS)
        .find(|&index| receivers[0].wire.holds(P4, index))
        .unwrap();
    let position = manager.owing(peer).unwrap().rendered();
    received(&mut manager, P4, &[], &[held]);
    manager.outbound_closing = true;
    manager.owing_close_flush();
    receivers[0].write();
    assert_eq!(receivers[0].wire.count(P4, held), (1, 1), "flushed");
    assert!(!receivers[0].wire.holds(P4, held));
    assert!(manager.owes_whole(peer, F4), "the announcements stay owed");
    assert_eq!(manager.owing(peer).unwrap().rendered(), position);
}

/// Contract 8 (session, dirty and forced mid-walk): a session that ends
/// mid-walk takes its debt with it and its replacement starts from its own
/// initial table; a receiver made dirty mid-walk is covered by its resync,
/// which ends the cursor (no further step reads a row); an operator
/// refresh mid-walk likewise. Each ends with the exact table and one
/// End-of-RIB after its last row. Red when a resync leaves the record it
/// covered: the cursor walks on over rows the resync already sent.
#[test]
fn a_vpn_cursor_ends_with_its_session_and_a_resync_covers_it() {
    const ROWS: u32 = 24;
    let start = || {
        let (mut manager, mut receivers) = owing(manager(CREDIT), P4, &[P4], 1, ROWS, 4096);
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
        rx: up(&mut manager, peer, 1, 4096, &[P4], 0),
        wire: Wire::default(),
    };
    drain(&mut manager, &mut receivers);
    let wire = &receivers[0].wire;
    assert_eq!(
        wire.table,
        table_of(P4, &all(ROWS)),
        "its own initial table"
    );
    assert_eq!((wire.markers[0], wire.rows_after_marker[0]), (1, 0));
    assert_eq!(wire.announced.len(), ROWS as usize);
    assert!(manager.owing(peer).is_none());
    assert!(lists_freed(&manager));

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
        assert_eq!(wire.table, table_of(P4, &all(ROWS)), "forced={forced}");
        assert_eq!((wire.markers[0], wire.rows_after_marker[0]), (1, 0));
        assert!(!manager.owes(peer, P4) && !manager.dirty_peers.contains(&peer));
        assert_eq!(
            manager.adj_rib_out_commit_stats.owed_drain_steps, steps,
            "forced={forced}: the resync ended the cursor"
        );
        assert!(lists_freed(&manager));
    }
}

/// Contract 9 (work and charge): 2,049 single-path rows per AFI released
/// to three receivers that joined in the hold drain in three steps per
/// AFI per receiver (1,024, 1,024, 1), none reading more than 1,024 keys,
/// as ordinary charged envelopes with no operation latch and no
/// whole-family step; each release logs its inventory once for all of
/// them. Red when a step takes every key its credit allows.
#[test]
fn a_vpn_release_drains_in_steps_of_one_chunk_charged_and_unlatched() {
    let rows = u32::try_from(2 * CHUNK_ROWS + 1).unwrap();
    let mut manager = deferral_manager(4 * CHUNK_ROWS, &[P4, P6]);
    sources_up(&mut manager);
    for family in [P4, P6] {
        let routes = (0..rows).map(|index| route_from(SOURCE, family, index, 100, 200));
        send(&mut manager, SOURCE, routes.collect(), vec![]);
    }
    let waiter = hold(&mut manager, &[P4, P6]);
    let mut receivers = vec![
        join_held(&mut manager, 0, &[P4, P6]),
        join_held(&mut manager, 1, &[P4, P6]),
        waiter,
    ];
    let stats = manager.adj_rib_out_commit_stats;
    release(&mut manager, P4);
    release(&mut manager, P6);
    let logs = manager.adj_rib_out_commit_stats.owed_vpn_logs - stats.owed_vpn_logs;
    assert_eq!(logs, 2, "one inventory log per AFI, not per receiver");
    drain(&mut manager, &mut receivers);
    let now = manager.adj_rib_out_commit_stats;
    assert_eq!(
        now.owed_drain_steps - stats.owed_drain_steps,
        3 * 2 * 3,
        "ceil(2,049 / 1,024) steps per AFI per receiver"
    );
    assert_eq!(now.owed_drain_step_rows_max, CHUNK_ROWS);
    assert_eq!(now.resync_builds, stats.resync_builds, "no table built");
    assert_eq!(steps_of(&manager, "whole"), 0, "no whole-family operation");
    assert_eq!(steps_of(&manager, "cursor"), 3 * 2 * 3);
    let mut expected = table_of(P4, &all(rows));
    expected.extend(table_of(P6, &all(rows)));
    for receiver in &receivers {
        let wire = &receiver.wire;
        assert_eq!(wire.table, expected);
        assert_eq!((wire.markers, wire.rows_after_marker), ([1, 1], [0, 0]));
        assert_eq!(wire.uncharged + wire.latched, 0, "charged, unlatched");
        assert!(wire.envelope_rows_max <= CHUNK_ROWS);
        assert!(manager.owing(receiver.peer).is_none());
    }
    assert!(lists_freed(&manager));
}

/// Contract 10 (dirty resync inside the hold): a receiver holds a row
/// whose withdrawal it was owed when it went dirty and its debt was
/// dropped (as a failed send leaves it), and its resync then runs inside a
/// VPN selection hold, which enumerates no key of the held AFI. The
/// selection-partial rule keeps it dirty for that AFI, so nothing is
/// recorded as a held rebuild, and its resync after the release withdraws
/// the row, which the release inventory does not name. A receiver that
/// joined inside the hold, then went dirty, has nothing of the held AFI to
/// withdraw and gets its table from the release. Red when the receiver
/// leaves the hold clean with the row.
#[test]
fn a_dirty_resync_inside_a_vpn_hold_loses_no_withdrawal() {
    for family in [P4, P6] {
        let manager = deferral_manager(CREDIT, &[family]);
        let (mut manager, mut receivers) = owing(manager, family, &[family], 2, 8, 4096);
        let mut model = Model::new(family, &all(8));
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
        assert!(manager.owes(peer, family), "the withdrawal is owed");
        manager.drop_peer_owing(peer);
        manager.mark_outbound_dirty(peer);
        receivers.push(hold(&mut manager, &[family]));
        let joiner = join_held(&mut manager, 7, &[family]);
        manager.mark_outbound_dirty(joiner.peer);
        receivers.push(joiner);
        for _ in 0..50 {
            tick(&mut manager, &mut receivers);
        }
        assert!(
            manager.dirty_peers.contains(&peer),
            "{family:?}: kept dirty for the held AFI"
        );
        assert!(manager.held_rebuilds.iter().all(HashSet::is_empty));
        assert!(receivers[1].wire.holds(family, 5));
        release(&mut manager, family);
        drain(&mut manager, &mut receivers);
        for (index, receiver) in receivers.iter().enumerate() {
            assert_eq!(receiver.wire.table, model.table(), "{family:?}: {index}");
            assert!(!manager.owes(receiver.peer, family));
            assert!(!manager.dirty_peers.contains(&receiver.peer));
        }
        assert_eq!(receivers[1].wire.count(family, 5), (1, 1));
        assert!(lists_freed(&manager));
    }
}

/// Contract 11 (a policy dataset swap with every winner unchanged): mid
/// walk, a swap of the dataset the receiver's export policy reads turns a
/// row it has already been sent into one it may not be sent, and a row it
/// has not read yet likewise. The re-evaluation's targeted pass logs its
/// keys, so the cursor visits the read row again and withdraws it, and
/// never sends the unread one. Red when the pass logs nothing before its
/// receiver loop (which skips a receiver owed the family whole).
#[test]
fn a_dataset_swap_behind_a_vpn_cursor_withdraws_a_row_already_sent() {
    use rustbgpd_policy::datasets::{DatasetBindings, DatasetData, DatasetHandle, DatasetKind};
    use rustbgpd_policy::rpol::RpolFile;
    use rustbgpd_policy::sets::{PrefixSet, PrefixSetEntry, SetStore};
    const ROWS: u32 = 24;
    let allowed = |rows: &[u32]| {
        DatasetData::Prefix(PrefixSet::new(rows.iter().map(|&index| {
            let VpnPrefix::V4 { addr, len } = key(P4, index).prefix else {
                unreachable!()
            };
            PrefixSetEntry {
                prefix: Prefix::V4(Ipv4Prefix::new(addr, len)),
                ge: None,
                le: None,
            }
        })))
    };
    // Even rows are under RD 65000:1 and odd ones under 65000:2, with
    // their prefixes shared in pairs: every prefix is allowed at first.
    let handle = Arc::new(DatasetHandle::new(
        "allowed",
        DatasetKind::Prefix,
        allowed(&(0..ROWS).collect::<Vec<_>>()),
    ));
    let mut bindings = DatasetBindings::new();
    bindings.insert(Arc::clone(&handle));
    let compiled = RpolFile::parse(
        "dataset prefix-set allowed\n\
         policy p { term pass { if route.prefix in allowed { accept } reject } }",
    )
    .unwrap()
    .compile_policy_bound("p", &[], &mut SetStore::new(), &bindings)
    .unwrap()
    .unwrap();
    let chain = PolicyChain::from_named(vec![rustbgpd_policy::NamedPolicy::from_rpol(
        "p".to_string(),
        Arc::new(compiled),
    )]);
    let mut manager = manager(CREDIT);
    sources_up(&mut manager);
    let peer = receiver(0);
    let mut rx = up_with(&mut manager, peer, 0, 4096, &[P4], 0, Some(chain));
    Wire::default().write(&mut rx);
    let mut receivers = vec![Receiver {
        peer,
        rx,
        wire: Wire::default(),
    }];
    manager.owe_eor(peer, P4);
    manager.owe_whole_family(peer, F4);
    received(&mut manager, P4, &all(ROWS), &[]);
    tick(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table.len(), STEP);
    let read = (0..ROWS)
        .find(|&index| receivers[0].wire.holds(P4, index))
        .unwrap();
    let unread = (0..ROWS)
        .find(|&index| {
            !receivers[0].wire.holds(P4, index) && !receivers[0].wire.holds(P4, index ^ 1)
        })
        .unwrap();
    // Deny both prefixes: both RDs of each go.
    let denied = [read, read ^ 1, unread, unread ^ 1];
    let kept: Vec<u32> = (0..ROWS).filter(|index| !denied.contains(index)).collect();
    let prior = handle.pin();
    assert!(handle.refresh(allowed(&kept)).is_some());
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::ReevaluatePeerExportPolicies {
        peers: vec![peer],
        swaps: Some(vec![crate::update::DatasetSwap {
            handle: Arc::clone(&handle),
            prior,
        }]),
        reply,
    });
    result.try_recv().unwrap().unwrap();
    drain(&mut manager, &mut receivers);
    let expected = table_of(
        P4,
        &kept.iter().map(|&index| (index, 100)).collect::<Vec<_>>(),
    );
    assert_settled(&manager, &receivers, P4, &expected, "dataset swap");
    let wire = &receivers[0].wire;
    assert_eq!(wire.count(P4, read), (1, 1), "sent, then withdrawn");
    assert_eq!(wire.count(P4, unread), (0, 0), "never sent");
}

/// Contract 12 (an RT-Constrain membership change mid-walk): a private
/// receiver that negotiated RT-Constrain is interested in RT 1, a step
/// into its walk of rows tagged RT 1 or RT 2; it then swaps its interest
/// to RT 2. The change resyncs it as a whole peer, which ends its cursor:
/// it ends with exactly the RT 2 rows, every RT 1 row it had read
/// withdrawn, and one End-of-RIB. A receiver without RT-Constrain keeps
/// its table and walks on.
#[test]
fn an_rt_constrain_change_mid_walk_resyncs_the_private_receiver() {
    const ROWS: u32 = 32;
    let rtc = (Afi::Ipv4, Safi::RtConstrain);
    let interest = |local_admin| make_rtc_rib_route(Ipv4Addr::new(10, 0, 9, 1), local_admin, 100);
    let mut manager = manager(CREDIT);
    sources_up(&mut manager);
    let mut receivers = vec![
        Receiver::up(&mut manager, receiver(0), 4096, &[P4, rtc], 0),
        Receiver::up(&mut manager, receiver(1), 4096, &[P4], 0),
    ];
    let rtc_peer = receivers[0].peer;
    manager.handle_update(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: rtc_peer,
        announced: vec![interest(1)],
        withdrawn: vec![],
    });
    end_of_rib(&mut manager, rtc_peer, 0, rtc);
    drain(&mut manager, &mut receivers);
    receivers[0].wire = Wire::default();
    for receiver in &receivers {
        manager.owe_eor(receiver.peer, P4);
        manager.owe_whole_family(receiver.peer, F4);
    }
    let tagged = |index: u32| {
        let mut route = route_from(SOURCE, P4, index, 100, 200);
        AttrSet::edit(&mut route.attributes, |attrs| {
            attrs.push(PathAttribute::ExtendedCommunities(vec![rt(
                1 + u16::try_from(index % 4 / 2).unwrap()
            )]));
        });
        route
    };
    send(
        &mut manager,
        SOURCE,
        (0..ROWS).map(tagged).collect(),
        vec![],
    );
    while receivers[0].wire.table.is_empty() {
        assert!(manager.owes_whole(rtc_peer, F4), "mid-walk");
        tick(&mut manager, &mut receivers);
    }
    assert!(manager.owes_whole(rtc_peer, F4), "mid-walk");
    let read: Vec<u32> = (0..ROWS)
        .filter(|&index| receivers[0].wire.holds(P4, index))
        .collect();
    assert!(read.iter().all(|index| index % 4 < 2), "RT 1 rows only");
    let old = interest(1).key();
    manager.handle_update(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: rtc_peer,
        announced: vec![interest(2)],
        withdrawn: vec![old],
    });
    drain(&mut manager, &mut receivers);
    let expected: Table = (0..ROWS)
        .filter(|index| index % 4 >= 2)
        .map(|index| entry(&tagged(index), 0))
        .collect();
    let wire = &receivers[0].wire;
    assert_eq!(wire.table, expected, "RT 2 rows only");
    for index in read {
        assert_eq!(wire.count(P4, index), (1, 1), "{index}: withdrawn");
    }
    assert_eq!((wire.markers[0], wire.rows_after_marker[0]), (1, 0));
    assert!(!manager.owes(rtc_peer, P4) && !manager.dirty_peers.contains(&rtc_peer));
    let all_rows: Table = (0..ROWS).map(|index| entry(&tagged(index), 0)).collect();
    assert_settled(&manager, &receivers[1..], P4, &all_rows, "fixed filter");
    assert_eq!(
        receivers[1].wire.announced.len(),
        ROWS as usize,
        "once each"
    );
}

/// Contract 13 (a private receiver holding an admitted-key proof): the
/// hold's activation captures what a private VPN receiver present at it
/// was sent (a recovery proof, and the selection-partial flag). Rows are
/// withdrawn and changed in the hold, and the release owes the receiver
/// the family with that proof still held. The cursor alone, from the
/// release inventory, brings it to the exact table: the proof names no
/// row that both the inventory and its Adj-RIB-Out lack.
#[test]
fn a_private_vpn_receiver_with_an_admitted_proof_settles_from_the_cursor() {
    for family in [P4, P6] {
        let mut manager = deferral_manager(CREDIT, &[family]);
        sources_up(&mut manager);
        let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 4096, &[family], 0)];
        let peer = receivers[0].peer;
        let mut model = Model::new(family, &[]);
        model.send(&mut manager, &all(16), &[]);
        drain(&mut manager, &mut receivers);
        assert_eq!(receivers[0].wire.table, model.table());
        receivers[0].wire.announced.clear();
        receivers.push(hold(&mut manager, &[family]));
        assert!(
            manager.pending_group_admitted.contains_key(&peer),
            "{family:?}: the activation captured a proof"
        );
        model.send(&mut manager, &[(1, 333), (40, 100)], &[2, 3]);
        release(&mut manager, family);
        assert!(manager.owes_whole(peer, owed_family(family)), "{family:?}");
        let builds = manager.adj_rib_out_commit_stats.resync_builds;
        drain(&mut manager, &mut receivers);
        let wire = &receivers[0].wire;
        assert_eq!(wire.table, model.table(), "{family:?}: exact table");
        assert_eq!(wire.markers, [0, 0], "its End-of-RIB left before the hold");
        assert_eq!(wire.uncharged + wire.latched, 0, "charged");
        assert!(!manager.owes(peer, family) && !manager.dirty_peers.contains(&peer));
        assert!(lists_freed(&manager));
        assert_eq!(
            manager.adj_rib_out_commit_stats.resync_builds, builds,
            "{family:?}: no resync"
        );
        let wire = &receivers[0].wire;
        assert_eq!(
            (wire.count(family, 2), wire.count(family, 3)),
            ((0, 1), (0, 1))
        );
        assert_eq!(wire.count(family, 1), (1, 0), "relabeled");
        assert_eq!(wire.count(family, 40), (1, 0), "new");
    }
}

/// Contract 14 (the two AFIs' gates release apart): the `VPNv4` release
/// starts `VPNv4` cursors only. A pass that then carries both AFIs logs its
/// `VPNv4` key and nothing for the held AFI, and the receivers get the `VPNv4`
/// table and its marker alone. The `VPNv6` release then delivers that AFI,
/// with the row that changed in between at its newest state, and its own
/// marker. Red when one release owes the sibling AFI too.
#[test]
fn vpn_afi_gates_that_release_apart_each_start_their_own_cursor() {
    const ROWS: u32 = 12;
    let mut manager = deferral_manager(CREDIT, &[P4, P6]);
    sources_up(&mut manager);
    let rows = |family, label: u32| -> Vec<VpnRibRoute> {
        (0..ROWS)
            .map(|index| route_from(SOURCE, family, index, label, 200))
            .collect()
    };
    send(&mut manager, SOURCE, rows(P4, 100), vec![]);
    send(&mut manager, SOURCE, rows(P6, 100), vec![]);
    let waiter = hold(&mut manager, &[P4, P6]);
    let mut receivers = vec![
        join_held(&mut manager, 0, &[P4, P6]),
        join_held(&mut manager, 1, &[P4, P6]),
        waiter,
    ];
    release(&mut manager, P4);
    for receiver in &receivers {
        assert!(manager.owes_whole(receiver.peer, F4));
        assert!(!manager.owes_whole(receiver.peer, F6), "its gate is closed");
    }
    let changed = vec![
        route_from(SOURCE, P4, 1, 200, 200),
        route_from(SOURCE, P6, 1, 200, 200),
    ];
    send(&mut manager, SOURCE, changed, vec![]);
    assert_eq!(manager.owed_vpn_rows[1].len(), 0, "a held AFI logs nothing");
    drain(&mut manager, &mut receivers);
    let mut v4 = all(ROWS);
    v4[1].1 = 200;
    for receiver in &receivers {
        assert_eq!(receiver.wire.table, table_of(P4, &v4), "VPNv4 only");
        assert_eq!(receiver.wire.markers, [1, 0]);
    }
    release(&mut manager, P6);
    drain(&mut manager, &mut receivers);
    let mut expected = table_of(P4, &v4);
    expected.extend(table_of(P6, &v4));
    for receiver in &receivers {
        let wire = &receiver.wire;
        assert_eq!(wire.table, expected);
        assert_eq!((wire.markers, wire.rows_after_marker), ([1, 1], [0, 0]));
        assert_eq!(wire.announced.len(), 2 * ROWS as usize, "once each");
        assert_eq!(wire.uncharged + wire.latched, 0);
        assert!(manager.owing(receiver.peer).is_none());
    }
    assert!(lists_freed(&manager));
}

/// Contract 15 (Add-Path send-all work count): a receiver that is sent
/// every path of a key has no bound on the rows one key stages, so its
/// cursor takes one key a step: N keys with two paths each drain in N
/// steps, not ceil(N / 1,024), every row charged, with the exact table
/// and one End-of-RIB after the last row.
#[test]
fn a_send_all_add_path_vpn_cursor_takes_one_key_a_step() {
    const ROWS: u32 = 10;
    let mut manager = manager(CREDIT);
    sources_up(&mut manager);
    let mut receivers = vec![Receiver::up(
        &mut manager,
        receiver(0),
        4096,
        &[P4],
        u32::MAX,
    )];
    manager.owe_eor(receivers[0].peer, P4);
    manager.owe_whole_family(receivers[0].peer, F4);
    let second = |index| route_from(SECOND, P4, index, 300, 100);
    send(
        &mut manager,
        SECOND,
        (0..ROWS).map(second).collect(),
        vec![],
    );
    received(&mut manager, P4, &all(ROWS), &[]);
    let steps = manager.adj_rib_out_commit_stats.owed_drain_steps;
    drain(&mut manager, &mut receivers);
    let stats = manager.adj_rib_out_commit_stats;
    assert_eq!(
        stats.owed_drain_steps - steps,
        ROWS as usize,
        "a key a step"
    );
    assert_eq!(stats.owed_drain_step_rows_max, 1);
    let expected: Table = (0..ROWS)
        .flat_map(|index| {
            [
                entry(&route_from(SOURCE, P4, index, 100, 200), 1),
                entry(&second(index), 2),
            ]
        })
        .collect();
    assert_settled(&manager, &receivers, P4, &expected, "send-all");
    assert_eq!(receivers[0].wire.announced.len(), 2 * ROWS as usize);
}

/// Fresh rows rotate past `receivers[1..]`, which stopped reading, until
/// the list cap evicts them. Returns the model.
fn evict_stalled(
    manager: &mut RibManager,
    receivers: &mut [Receiver],
    family: (Afi, Safi),
) -> Model {
    let mut model = Model::new(family, &all(8));
    for round in 0..400u32 {
        let base = 1000 + round * 64;
        let fresh: Vec<_> = (base..base + 64).map(|index| (index, 100)).collect();
        let gone: Vec<_> = (base - 64..base).filter(|_| round != 0).collect();
        let before = fallbacks(manager);
        let stats = manager.adj_rib_out_commit_stats;
        model.send(manager, &fresh, &gone);
        if fallbacks(manager) > before {
            let now = manager.adj_rib_out_commit_stats;
            assert_eq!(now.resync_builds, stats.resync_builds, "no resync built");
            assert_eq!(
                now.group_table_captures, stats.group_table_captures,
                "the evicting pass walks no group table"
            );
            for receiver in &receivers[1..] {
                assert!(manager.owed_row_evicted.contains(&receiver.peer));
                assert!(
                    manager.dirty_peers.contains(&receiver.peer),
                    "outside every group: dirty in the pass"
                );
                assert!(manager.owing(receiver.peer).is_none());
            }
            return model;
        }
        for _ in 0..12 {
            manager.resync_dirty_peers_bounded();
            receivers[0].write();
        }
    }
    panic!("the stalled receivers were never evicted");
}

/// Cap eviction (state D): fresh keys rotate past two receivers that
/// stopped reading until the `VPNv6` list cap evicts them. The evicting
/// pass builds nothing and walks no group table; the receivers are made
/// dirty there, and the resync tick builds one of them a tick. Every
/// receiver ends with the exact table and one End-of-RIB after its last
/// row. Red when the IPv6 list is not capped.
#[test]
fn a_stalled_vpn_receiver_is_evicted_in_the_pass_and_rebuilt_one_a_tick() {
    let (mut manager, mut receivers) = owing(manager(CREDIT), P6, &[P6], 3, 8, 4096);
    drain(&mut manager, &mut receivers);
    let model = evict_stalled(&mut manager, &mut receivers, P6);
    manager.flush_poll_budget = Duration::from_secs(3600);
    let stats = manager.adj_rib_out_commit_stats;
    for _ in 0..5000 {
        if !manager.resync_tick_pending() {
            break;
        }
        let before = manager.adj_rib_out_commit_stats;
        tick(&mut manager, &mut receivers);
        assert!(manager.adj_rib_out_commit_stats.resync_builds - before.resync_builds <= 1);
    }
    assert_eq!(
        manager.adj_rib_out_commit_stats.resync_builds - stats.resync_builds,
        2
    );
    for receiver in &receivers {
        assert_eq!(receiver.wire.table, model.table());
        // The End-of-RIB left with the first table; the rotation came after.
        assert_eq!(receiver.wire.markers, [0, 1]);
        assert!(!manager.owes(receiver.peer, P6));
        assert!(!manager.dirty_peers.contains(&receiver.peer));
    }
    assert!(manager.owed_row_evicted.is_empty());
    assert!(lists_freed(&manager));
}

/// An evicted receiver (state D) whose VPN selection hold begins before
/// its unit runs: the unit is not held back by the VPN hold, as for
/// unicast; it runs inside the hold and keeps the receiver dirty for the
/// held AFI by the selection-partial rule, and its resync after the
/// release sends the table. A row withdrawn inside the hold, which the
/// eviction's dropped entries may have named, never reaches it.
#[test]
fn an_evicted_vpn_receiver_in_a_vpn_hold_stays_dirty_until_the_release() {
    let manager = deferral_manager(CREDIT, &[P4]);
    let (mut manager, mut receivers) = owing(manager, P4, &[P4], 3, 8, 4096);
    drain(&mut manager, &mut receivers);
    let mut model = evict_stalled(&mut manager, &mut receivers, P4);
    receivers.push(hold(&mut manager, &[P4]));
    let first = *model.rows.keys().next().unwrap();
    model.send(&mut manager, &[], &[first]);
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    for _ in 0..50 {
        tick(&mut manager, &mut receivers);
    }
    assert_eq!(
        manager.adj_rib_out_commit_stats.resync_builds - builds,
        2,
        "each evicted receiver's unit ran inside the hold"
    );
    for receiver in &receivers[1..3] {
        assert!(
            manager.dirty_peers.contains(&receiver.peer),
            "dirty in the hold"
        );
    }
    assert!(manager.held_rebuilds.iter().all(HashSet::is_empty));
    release(&mut manager, P4);
    drain(&mut manager, &mut receivers);
    for receiver in &receivers[..3] {
        assert_eq!(receiver.wire.table, model.table());
        assert_eq!(receiver.wire.markers, [1, 0]);
        assert!(!manager.owes(receiver.peer, P4));
        assert!(!manager.dirty_peers.contains(&receiver.peer));
    }
    assert!(manager.owed_row_evicted.is_empty());
    assert!(lists_freed(&manager));
}

/// The VPN list's cap is taken from the VPN table. A stalled receiver that
/// owes the family while a table larger than the slack is built in small
/// passes is not evicted: the list never holds more than the table. Red
/// when the cap's peak is read from another family's table.
#[test]
fn a_vpn_table_built_in_small_passes_evicts_nobody() {
    const ROWS: u32 = 6000;
    let (mut manager, mut receivers) = owing(manager(CREDIT), P4, &[P4], 1, 8, 4096);
    let peer = receivers[0].peer;
    receivers[0].stall(&manager);
    let mut model = Model::new(P4, &all(8));
    for base in (8..ROWS).step_by(64) {
        let fresh: Vec<_> = (base..base + 64).map(|index| (index, 100)).collect();
        model.send(&mut manager, &fresh, &[]);
    }
    assert!(
        manager.owed_vpn_rows[0].len() > 4 * CHUNK_ROWS,
        "past the slack"
    );
    assert_eq!(fallbacks(&manager), 0.0, "nobody is evicted");
    assert!(!manager.owed_row_evicted.contains(&peer));
    assert!(manager.owes_whole(peer, F4) && !manager.dirty_peers.contains(&peer));
    drain(&mut manager, &mut receivers);
    assert_settled(&manager, &receivers, P4, &model.table(), "small passes");
}

/// One stalled receiver that holds rows 0..256 and owes `VPNv4` whole from
/// now on, then `passes` passes that each announce 64 fresh rows and
/// withdraw the previous 64, stopping early at the first eviction. Returns
/// the passes that ran.
fn rotate_past_a_stalled_cursor(passes: u32) -> (RibManager, Vec<Receiver>, Model, u32) {
    let mut manager = manager(CREDIT);
    sources_up(&mut manager);
    let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 4096, &[P4], 0)];
    let mut model = Model::new(P4, &[]);
    model.send(&mut manager, &all(256), &[]);
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table, model.table());
    manager.owe_eor(receivers[0].peer, P4);
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

/// A pass that changes no winner still logs its keys for the cursors, so
/// it can take a list over its cap, and it returns before the receiver
/// loop. The list is one rotation pass short of its cap; a losing path for
/// 64 rows the list does not hold then takes it over, and the stalled
/// receiver is evicted in that pass. Red when the cap is applied only
/// after the receiver loop: the list stays over its cap until some winner
/// changes.
#[test]
fn a_pass_with_no_winner_change_that_overfills_a_vpn_list_evicts_in_that_pass() {
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
            .map(|index| route_from(SECOND, P4, index, 300, 100))
            .collect(),
        vec![],
    );
    assert!(
        (0..64).all(|index| manager
            .loc_rib
            .get_vpn(&key(P4, index))
            .is_some_and(|best| best.peer == peer_v4(SOURCE))),
        "no winner changed"
    );
    assert_eq!(
        fallbacks(&manager),
        1.0,
        "evicted in the pass that overfilled"
    );
    assert!(manager.dirty_peers.contains(&peer));
    drain(&mut manager, &mut receivers);
    tick(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table, model.table());
    assert!(!manager.owes(peer, P4) && !manager.dirty_peers.contains(&peer));
    assert!(lists_freed(&manager));
}

mod actor;
