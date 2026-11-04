//! ADR-0145 slice 1b: owed-key sets for private families. A receiver whose
//! row credit is spent is owed keys instead of being marked dirty; the
//! resync tick drains them from current state, barriers absorb them, and
//! shutdown flushes their withdrawals.

use std::collections::BTreeMap;

use super::super::outbound_owing::OwedFamily;
use super::*;
use crate::outbound_credit::CHUNK_ROWS;

const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const V4: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const EVPN: (Afi, Safi) = (Afi::L2Vpn, Safi::Evpn);

/// A manager whose peers stay ungrouped (private unicast) at `credit` rows.
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
    manager
}

fn up_session(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
    families: Vec<(Afi, Safi)>,
    capacity: usize,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, output) = mpsc::channel(capacity);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 200),
        outbound_tx,
        export_policy: None,
        sendable_families: families,
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

fn up(
    manager: &mut RibManager,
    peer: PeerId,
    families: Vec<(Afi, Safi)>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    up_session(manager, peer, 0, families, 4096)
}

/// A session that reads everything queued: the envelopes drop.
fn send_all(output: &mut mpsc::Receiver<OutboundRouteUpdate>) -> Vec<OutboundRouteUpdate> {
    std::iter::from_fn(|| output.try_recv().ok().map(delivered)).collect()
}

/// Every queued envelope, still holding its charge and latch: a stalled
/// session.
fn held(output: &mut mpsc::Receiver<OutboundRouteUpdate>) -> Vec<OutboundRouteUpdate> {
    std::iter::from_fn(|| output.try_recv().ok()).collect()
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

fn evpn_route(tag: u32, variant: u32) -> EvpnRibRoute {
    let mut route = make_evpn_imet(SOURCE, tag);
    route.attributes = AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::LocalPref(100),
        PathAttribute::Med(variant),
    ]);
    route
}

fn received(
    manager: &mut RibManager,
    announced: Vec<Route>,
    withdrawn: Vec<(Prefix, u32)>,
    evpn_announced: Vec<EvpnRibRoute>,
    evpn_withdrawn: Vec<rustbgpd_wire::EvpnRouteKey>,
) {
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced,
        withdrawn,
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced,
        evpn_withdrawn,
        validated_with: None,
    });
    drain_route_chunks(manager);
}

fn rows(updates: &[OutboundRouteUpdate]) -> usize {
    updates
        .iter()
        .map(|update| {
            update.announce.len()
                + update.unicast_withdrawals().count()
                + update.evpn_announce.len()
                + update.evpn_withdraw.len()
        })
        .sum()
}

/// One receiver's view: each route it holds, and the order of everything.
#[derive(Default, Debug, PartialEq, Eq)]
struct Wire {
    unicast: BTreeMap<(Prefix, u32), String>,
    evpn: BTreeMap<String, String>,
}

impl Wire {
    fn apply(&mut self, updates: &[OutboundRouteUpdate]) {
        for update in updates {
            for key in update.unicast_withdrawals() {
                assert!(
                    self.unicast.remove(key).is_some(),
                    "withdrawal of {key:?}, which the receiver does not hold"
                );
            }
            for route in update.announce.iter() {
                self.unicast.insert(
                    (route.prefix, route.path_id),
                    format!("{:?}", route.attributes),
                );
            }
            for key in &update.evpn_withdraw {
                assert!(
                    self.evpn.remove(&format!("{key:?}")).is_some(),
                    "withdrawal of {key:?}, which the receiver does not hold"
                );
            }
            for route in update.evpn_announce.iter() {
                self.evpn.insert(
                    format!("{:?}", route.key()),
                    format!("{:?}", route.attributes),
                );
            }
        }
    }
}

/// Run resync ticks, reading `rx` into `wire` after each, until the peer
/// owes nothing and a tick sends nothing. Returns the rows delivered.
fn drain_owed(
    manager: &mut RibManager,
    peer: PeerId,
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    wire: &mut Wire,
) -> usize {
    let mut total = 0;
    for _ in 0..64 {
        let updates = send_all(rx);
        total += rows(&updates);
        wire.apply(&updates);
        if updates.is_empty() && manager.owing(peer).is_none() {
            return total;
        }
        manager.resync_dirty_peers_bounded();
    }
    panic!("{peer} still owes after 64 ticks");
}

/// `bgp_rib_outbound_owing_fallback_total`.
fn owing_fallbacks(manager: &RibManager) -> f64 {
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

fn owed(manager: &RibManager, peer: PeerId, family: (Afi, Safi)) -> usize {
    manager.owed_key_count(peer, OwedFamily::of(family).unwrap())
}

/// A stalled private unicast receiver with spent credit is owed the keys a
/// churning source changes, stays clean, and is sent each key once from its
/// current value when credit returns: rows delivered stay within the
/// distinct keys changed plus its credit, whatever the churn, and the final
/// state equals an always-reading receiver's. Red with slice 1a's refusal:
/// the receiver goes dirty.
#[test]
fn spent_credit_owes_keys_and_drains_each_once() {
    const KEYS: u32 = 32;
    const ROUNDS: u32 = 40;
    let credit = 64;
    let mut manager = manager(credit);
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable());
    let reference = peer_v4(Ipv4Addr::new(10, 0, 1, 1));
    let mut reference_rx = up(&mut manager, reference, ipv4_sendable());
    let stalled = peer_v4(Ipv4Addr::new(10, 0, 1, 2));
    let mut stalled_rx = up(&mut manager, stalled, ipv4_sendable());
    let mut reference_wire = Wire::default();
    let mut stalled_wire = Wire::default();
    reference_wire.apply(&send_all(&mut reference_rx));
    stalled_wire.apply(&send_all(&mut stalled_rx));
    let mut queued = Vec::new();
    for round in 0..ROUNDS {
        let announced = (0..KEYS).map(|key| route(key, round)).collect();
        received(&mut manager, announced, vec![], vec![], vec![]);
        send_all(&mut source);
        reference_wire.apply(&send_all(&mut reference_rx));
        queued.extend(held(&mut stalled_rx));
        assert!(
            !manager.dirty_peers.contains(&stalled),
            "round {round}: spent credit owes keys instead of a resync"
        );
    }
    assert!(owed(&manager, stalled, V4) > 0, "the receiver owes keys");
    assert!(
        rows(&queued) <= credit + 2,
        "{} rows queued against {credit}",
        rows(&queued)
    );
    stalled_wire.apply(&queued);
    let staged_while_stalled = rows(&queued);
    drop(queued);
    let drained = drain_owed(&mut manager, stalled, &mut stalled_rx, &mut stalled_wire);
    assert!(
        drained <= usize::try_from(KEYS).unwrap(),
        "{drained} rows drained for {KEYS} owed keys"
    );
    assert!(staged_while_stalled + drained <= usize::try_from(KEYS).unwrap() + credit + 2);
    assert_eq!(stalled_wire, reference_wire);
    assert!(manager.owing(stalled).is_none());
    assert!(!manager.dirty_peers.contains(&stalled));
    assert!(owing_fallbacks(&manager) < 0.5, "no gated batch fell back");
}

/// Fresh-key rotation toward stalled private EVPN receivers: each round
/// announces new keys and withdraws the last round's, so every owed key it
/// marks is cancelled once nothing offers it and the receiver never held
/// it. The owed state is the same size after 4× the rounds. Red without
/// cancellation (with the byte cap raised so it cannot flip): the sets
/// grow with the rounds.
#[test]
fn owed_keys_stay_flat_under_fresh_rotation() {
    const KEYS: u32 = 64;
    let run = |rounds: u32| {
        let mut manager = manager(64).with_owing_theta_floor(1 << 30);
        let mut source = up(&mut manager, peer_v4(SOURCE), evpn_sendable());
        let stalled: Vec<_> = (0..4)
            .map(|index| {
                let peer = peer_v4(Ipv4Addr::new(10, 0, 2, index + 1));
                let mut rx = up(&mut manager, peer, evpn_sendable());
                send_all(&mut rx);
                (peer, rx)
            })
            .collect();
        let mut queued = Vec::new();
        for round in 0..rounds {
            let base = round * KEYS;
            let announced = (0..KEYS).map(|key| evpn_route(base + key, 0)).collect();
            let withdrawn = if round == 0 {
                vec![]
            } else {
                (0..KEYS)
                    .map(|key| evpn_route(base - KEYS + key, 0).key())
                    .collect()
            };
            received(&mut manager, vec![], vec![], announced, withdrawn);
            send_all(&mut source);
        }
        let mut bytes = Vec::new();
        for (peer, mut rx) in stalled {
            queued.extend(held(&mut rx));
            assert!(!manager.dirty_peers.contains(&peer));
            assert!(!manager.owes_whole(peer, OwedFamily::EVPN));
            bytes.push((owed(&manager, peer, EVPN), manager.owing_bytes(peer)));
        }
        bytes
    };
    let short = run(64);
    let long = run(256);
    for (short, long) in short.iter().zip(&long) {
        assert_eq!(short.0, long.0, "owed keys flat in the churn rounds");
        // Capacity slack differs between runs; growth would be 4x.
        assert!(
            long.1 <= short.1 + short.1 / 2,
            "owed bytes {} after 4x the rounds against {}",
            long.1,
            short.1
        );
    }
    assert!(
        short.iter().all(|(keys, _)| *keys <= 2 * KEYS as usize),
        "{short:?}"
    );
}

/// The byte cap: a stalled receiver owed more keys than a quarter of its
/// family (or the floor) owes the family whole instead, and a later drain
/// sends the family by one diff and clears the flag. Red without the cap:
/// the set keeps every key.
#[test]
fn oversized_owed_set_flips_to_the_whole_family_and_drains() {
    let mut manager = manager(64).with_owing_theta_floor(256);
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable());
    let reference = peer_v4(Ipv4Addr::new(10, 0, 3, 1));
    let mut reference_rx = up(&mut manager, reference, ipv4_sendable());
    let stalled = peer_v4(Ipv4Addr::new(10, 0, 3, 2));
    let mut stalled_rx = up(&mut manager, stalled, ipv4_sendable());
    let mut reference_wire = Wire::default();
    let mut stalled_wire = Wire::default();
    reference_wire.apply(&send_all(&mut reference_rx));
    stalled_wire.apply(&send_all(&mut stalled_rx));
    let announced = (0..200).map(|key| route(key, 0)).collect();
    received(&mut manager, announced, vec![], vec![], vec![]);
    send_all(&mut source);
    reference_wire.apply(&send_all(&mut reference_rx));
    let queued = held(&mut stalled_rx);
    assert!(manager.owes_whole(stalled, OwedFamily::IPV4_UNICAST));
    assert_eq!(owed(&manager, stalled, V4), 0, "the set is dropped");
    assert!(!manager.dirty_peers.contains(&stalled));
    stalled_wire.apply(&queued);
    drop(queued);
    drain_owed(&mut manager, stalled, &mut stalled_rx, &mut stalled_wire);
    // The reference reads at once but has the same credit: it drains too.
    drain_owed(
        &mut manager,
        reference,
        &mut reference_rx,
        &mut reference_wire,
    );
    assert_eq!(stalled_wire.unicast.len(), 200);
    assert_eq!(stalled_wire, reference_wire);
    assert!(!manager.owes_whole(stalled, OwedFamily::IPV4_UNICAST));
}

/// A whole-family drain whose diff turns out empty (the churn reverted)
/// still settles the family: one tick clears the flag, drops the owed
/// state and stops the backlog cadence. Red when only a committed drain
/// settles: the flag stays and every tick re-enumerates the family.
#[test]
fn empty_whole_family_drain_clears_the_flag() {
    let mut manager = manager(8).with_owing_theta_floor(0);
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable());
    let stalled = peer_v4(Ipv4Addr::new(10, 0, 4, 2));
    let mut stalled_rx = up(&mut manager, stalled, ipv4_sendable());
    received(&mut manager, vec![route(0, 0)], vec![], vec![], vec![]);
    send_all(&mut source);
    let mut wire = Wire::default();
    wire.apply(&send_all(&mut stalled_rx));
    // Spend the credit, then change and revert one key while it is spent.
    let filler: Arc<crate::outbound_credit::OutboundCredit> =
        manager.outbound_credit_handle(stalled);
    let charge = crate::outbound_credit::OutboundCharge::new(&filler, 8);
    received(&mut manager, vec![route(0, 1)], vec![], vec![], vec![]);
    received(&mut manager, vec![route(0, 0)], vec![], vec![], vec![]);
    send_all(&mut source);
    assert!(manager.owes_whole(stalled, OwedFamily::IPV4_UNICAST));
    drop(charge);
    manager.resync_dirty_peers_bounded();
    assert!(
        send_all(&mut stalled_rx)
            .iter()
            .all(|update| update.announce.is_empty())
    );
    assert!(manager.owing(stalled).is_none(), "one tick settles it");
    assert!(!manager.resync_tick_pending(), "the backlog cadence stops");
}

/// An ordinary pass toward a receiver halfway through its credit stages
/// complete keys only until the remaining credit is used, and owes the
/// rest: rows queued stay within the credit plus one key. Red without the
/// budget: the whole pass is queued past the credit.
#[test]
fn pass_stages_within_the_remaining_credit() {
    let credit = 256;
    // A cap that never flips the set, so every unstaged key is counted.
    let mut manager = manager(credit).with_owing_theta_floor(1 << 30);
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 5, 1));
    let mut rx = up(&mut manager, peer, ipv4_sendable());
    send_all(&mut rx);
    let filler = manager.outbound_credit_handle(peer);
    let charge = crate::outbound_credit::OutboundCharge::new(&filler, credit / 2);
    let announced = (0..500).map(|key| route(key, 0)).collect();
    received(&mut manager, announced, vec![], vec![], vec![]);
    send_all(&mut source);
    let queued = held(&mut rx);
    assert!(
        credit / 2 + rows(&queued) <= credit + 1,
        "{} rows queued at {} of {credit}",
        rows(&queued),
        credit / 2
    );
    assert!(rows(&queued) > 0, "the remaining credit is used");
    assert_eq!(rows(&queued) + owed(&manager, peer, V4), 500);
    assert!(!manager.dirty_peers.contains(&peer));
    drop(charge);
}

/// A drain step refused for a reason that cannot clear by itself (here the
/// session has no export encoder) gives up on owed keys once: the peer
/// resyncs instead, and the drain does not retry every tick. Red when every
/// refusal re-owes: the peer keeps owing and the backlog cadence never
/// stops.
#[test]
fn persistent_drain_refusal_escalates_to_a_resync() {
    let mut manager = manager(8);
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 6, 1));
    let mut rx = up(&mut manager, peer, ipv4_sendable());
    send_all(&mut rx);
    let filler = manager.outbound_credit_handle(peer);
    let charge = crate::outbound_credit::OutboundCharge::new(&filler, 8);
    received(&mut manager, vec![route(0, 0)], vec![], vec![], vec![]);
    send_all(&mut source);
    assert_eq!(owed(&manager, peer, V4), 1);
    manager.peer_export_encoders.remove(&peer);
    drop(charge);
    let before = owing_fallbacks(&manager);
    manager.resync_dirty_peers_bounded();
    assert!(manager.owing(peer).is_none(), "the owed state is dropped");
    assert!(
        manager.dirty_peers.contains(&peer),
        "the peer resyncs instead"
    );
    assert!((owing_fallbacks(&manager) - before - 1.0).abs() < f64::EPSILON);
}

/// A session that ends while owing drops what it owed: the next session,
/// even one reusing the session id, starts from its initial table and is
/// never sent the old session's owed keys. Red without the fence at
/// registration: the old keys drain into the new session.
#[test]
fn a_new_session_owes_nothing_from_the_last() {
    let mut manager = manager(8);
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 7, 1));
    let mut rx = up(&mut manager, peer, ipv4_sendable());
    send_all(&mut rx);
    let filler = manager.outbound_credit_handle(peer);
    let charge = crate::outbound_credit::OutboundCharge::new(&filler, 8);
    received(&mut manager, vec![route(0, 0)], vec![], vec![], vec![]);
    send_all(&mut source);
    assert_eq!(owed(&manager, peer, V4), 1);
    // The replacement session registers (same id) before the old one's
    // teardown is seen, as a collision supersede does.
    let mut next = up_session(&mut manager, peer, 0, ipv4_sendable(), 4096);
    assert!(manager.owing(peer).is_none());
    drop(charge);
    drop(rx);
    let dump = send_all(&mut next);
    assert_eq!(rows(&dump), 1, "the initial table carries the route once");
    manager.resync_dirty_peers_bounded();
    assert!(
        send_all(&mut next).is_empty(),
        "no owed key of the old session follows"
    );
}

/// A mixed receiver (grouped unicast, private EVPN) whose credit is spent
/// owes its EVPN keys and stays clean, so its grouped unicast keeps the
/// shared emission and captures nothing. Red with slice 1a's refusal: the
/// member goes dirty and its group admission is captured.
#[test]
fn mixed_peer_owes_private_evpn_and_keeps_its_group() {
    let mut manager = manager(8);
    manager.test_force_ungrouped = false;
    let both = vec![V4, EVPN];
    let mut source = up(&mut manager, peer_v4(SOURCE), both.clone());
    let members: Vec<_> = (0..2)
        .map(|index| {
            let peer = peer_v4(Ipv4Addr::new(10, 0, 8, index + 1));
            let mut rx = up(&mut manager, peer, both.clone());
            send_all(&mut rx);
            (peer, rx)
        })
        .collect();
    let stalled = members[0].0;
    assert!(
        manager.grouped_member_of(stalled).is_some(),
        "grouped unicast"
    );
    assert!(
        manager.evpn_grouped_member_of(stalled).is_none(),
        "private EVPN"
    );
    let filler = manager.outbound_credit_handle(stalled);
    let charge = crate::outbound_credit::OutboundCharge::new(&filler, 8);
    received(
        &mut manager,
        vec![route(0, 0)],
        vec![],
        vec![evpn_route(1, 0)],
        vec![],
    );
    send_all(&mut source);
    assert_eq!(owed(&manager, stalled, EVPN), 1);
    assert!(!manager.dirty_peers.contains(&stalled));
    assert!(!manager.pending_group_admitted.contains_key(&stalled));
    let mut members = members;
    let queued = held(&mut members[0].1);
    assert!(
        queued.iter().any(|update| update
            .announce
            .iter()
            .any(|route| route.prefix == route_prefix(0))),
        "the grouped unicast still reaches the member"
    );
    drop(charge);
}

fn route_prefix(index: u32) -> Prefix {
    route(index, 0).prefix
}

/// Shutdown: a stalled private EVPN receiver owing 20 withdrawals and 5
/// announcements gets the withdrawals queued by `BeginClose`, ahead of its
/// Cease; the announcements stay owed. Red without the close flush: the
/// withdrawals stay owed and are lost with the session.
#[test]
fn begin_close_flushes_owed_withdrawals() {
    let mut manager = manager(1 << 20);
    let mut source = up(&mut manager, peer_v4(SOURCE), evpn_sendable());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 9, 1));
    let mut rx = up(&mut manager, peer, evpn_sendable());
    send_all(&mut rx);
    let gone: Vec<_> = (0..20).map(|tag| evpn_route(tag, 0)).collect();
    received(&mut manager, vec![], vec![], gone.clone(), vec![]);
    send_all(&mut source);
    let mut wire = Wire::default();
    wire.apply(&send_all(&mut rx));
    manager.outbound_row_credit_override = Some(1);
    let filler = manager.outbound_credit_handle(peer);
    let charge = crate::outbound_credit::OutboundCharge::new(&filler, 1);
    received(
        &mut manager,
        vec![],
        vec![],
        (100..105).map(|tag| evpn_route(tag, 0)).collect(),
        gone.iter().map(EvpnRibRoute::key).collect(),
    );
    send_all(&mut source);
    assert_eq!(owed(&manager, peer, EVPN), 25);
    assert!(held(&mut rx).is_empty(), "spent credit queues nothing");
    manager.handle_update(RibUpdate::BeginClose);
    let queued = held(&mut rx);
    let withdrawn: usize = queued.iter().map(|update| update.evpn_withdraw.len()).sum();
    let announced: usize = queued.iter().map(|update| update.evpn_announce.len()).sum();
    assert_eq!((withdrawn, announced), (20, 0));
    assert_eq!(owed(&manager, peer, EVPN), 5, "the announcements stay owed");
    wire.apply(&queued);
    assert!(wire.evpn.is_empty());
    drop(charge);
}

/// An End-of-RIB that waits on a family's owed keys is never sent ahead of
/// them by the pending-marker retry; the owed-key drain absorbs the keys
/// and sends the marker behind them once the live whole-table operation
/// drains. Red without the owed clause in the marker predicate: the retry
/// sends the End-of-RIB at once, ahead of the owed announcement.
#[test]
fn pending_marker_waits_behind_owed_keys() {
    let mut manager = manager(8);
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable());
    received(&mut manager, vec![route(5, 0)], vec![], vec![], vec![]);
    send_all(&mut source);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 11, 1));
    let mut rx = up(&mut manager, peer, ipv4_sendable());
    // The receiver does not read its initial table: its operation latch
    // stays live.
    let dump = held(&mut rx);
    assert!(manager.outbound_operation_live(peer));
    let filler = manager.outbound_credit_handle(peer);
    let charge = crate::outbound_credit::OutboundCharge::new(&filler, 8);
    received(&mut manager, vec![route(0, 0)], vec![], vec![], vec![]);
    send_all(&mut source);
    assert_eq!(owed(&manager, peer, V4), 1);
    manager.pending_eor.entry(peer).or_default().insert(V4);
    for _ in 0..3 {
        manager.retry_evpn_feed_markers_bounded();
        manager.resync_dirty_peers_bounded();
    }
    assert!(
        held(&mut rx)
            .iter()
            .all(|update| !update.end_of_rib.contains(&V4)),
        "no End-of-RIB while the key is owed and the latch is live"
    );
    assert!(
        manager
            .pending_eor
            .get(&peer)
            .is_some_and(|f| f.contains(&V4))
    );
    drop(dump);
    drop(charge);
    manager.resync_dirty_peers_bounded();
    let sent = send_all(&mut rx);
    let eor = sent
        .iter()
        .position(|update| update.end_of_rib.contains(&V4))
        .expect("the End-of-RIB is sent once the latch drains");
    let announced = sent
        .iter()
        .position(|update| update.announce.iter().any(|r| r.prefix == route_prefix(0)))
        .expect("the owed announcement is sent");
    assert!(announced < eor, "the owed key precedes the End-of-RIB");
    assert!(manager.owing(peer).is_none());
    assert!(!manager.dirty_peers.contains(&peer));
}

/// A ROUTE-REFRESH while the receiver owes the withdrawal of a route it
/// holds: the answer absorbs the owed key first, so the withdrawal reaches
/// the peer before the End-of-RIB/EoRR that closes the refresh, and never
/// after it. Red without absorption: the refresh re-announces the table
/// without the route, and the withdrawal follows the marker later.
#[test]
fn refresh_answer_absorbs_owed_withdrawal_first() {
    let mut manager = manager(8);
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 12, 1));
    let mut rx = up(&mut manager, peer, ipv4_sendable());
    received(
        &mut manager,
        vec![route(0, 0), route(1, 0)],
        vec![],
        vec![],
        vec![],
    );
    send_all(&mut source);
    let mut wire = Wire::default();
    wire.apply(&send_all(&mut rx));
    assert_eq!(wire.unicast.len(), 2);
    let filler = manager.outbound_credit_handle(peer);
    let charge = crate::outbound_credit::OutboundCharge::new(&filler, 8);
    received(
        &mut manager,
        vec![],
        vec![(route_prefix(0), 0)],
        vec![],
        vec![],
    );
    send_all(&mut source);
    assert_eq!(owed(&manager, peer, V4), 1);
    drop(charge);
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer,
        session_id: 0,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        queued: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    });
    let sent = send_all(&mut rx);
    let marker = sent
        .iter()
        .position(|update| update.end_of_rib.contains(&V4) || !update.refresh_markers.is_empty())
        .expect("the refresh answer carries its markers");
    let withdrawal = sent
        .iter()
        .position(|update| {
            update
                .unicast_withdrawals()
                .any(|(prefix, _)| *prefix == route_prefix(0))
        })
        .expect("the owed withdrawal is sent with the answer");
    assert!(withdrawal <= marker, "the withdrawal precedes the markers");
    assert!(manager.owing(peer).is_none(), "absorbed");
    wire.apply(&sent);
    assert_eq!(wire.unicast.len(), 1);
}

/// An operator replay refused at its acceptance point (another whole-table
/// update is live) sends nothing and leaves the owed keys exactly as they
/// were; accepted later, the owed keys go ahead of the families and the
/// terminal. Red when absorption pops the keys before acceptance: the
/// refused replay loses them.
#[test]
fn refused_replay_leaves_owed_keys_and_accepted_replay_absorbs_them() {
    let mut manager = manager(8);
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable());
    received(&mut manager, vec![route(5, 0)], vec![], vec![], vec![]);
    send_all(&mut source);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 13, 1));
    let mut rx = up(&mut manager, peer, ipv4_sendable());
    let dump = held(&mut rx);
    let filler = manager.outbound_credit_handle(peer);
    let charge = crate::outbound_credit::OutboundCharge::new(&filler, 8);
    received(
        &mut manager,
        vec![route(0, 0), route(1, 0)],
        vec![],
        vec![],
        vec![],
    );
    send_all(&mut source);
    assert_eq!(owed(&manager, peer, V4), 2);
    let bytes = manager.owing_bytes(peer);
    let replay = |manager: &mut RibManager| {
        let (token, _enrolled) = rustbgpd_bmp::BmpReplay::new(Duration::from_secs(5));
        let (ack, mut response) = oneshot::channel();
        manager.handle_update(RibUpdate::ReplayPeerOutbound {
            peer,
            session_id: 0,
            families: vec![V4],
            replay: token,
            reply: ack,
        });
        response.try_recv().expect("synchronous response")
    };
    assert!(replay(&mut manager).is_err(), "the live dump refuses it");
    assert!(held(&mut rx).is_empty(), "nothing sent");
    assert_eq!(owed(&manager, peer, V4), 2);
    assert_eq!(manager.owing_bytes(peer), bytes, "owed state untouched");
    drop(dump);
    drop(charge);
    assert!(replay(&mut manager).is_ok());
    let sent = send_all(&mut rx);
    let terminal = sent
        .iter()
        .position(|update| update.replay.is_some())
        .expect("terminal");
    assert_eq!(terminal, sent.len() - 1);
    assert!(manager.owing(peer).is_none(), "absorbed");
}

/// The keep-set: a marked key is kept while the peer holds it, a source
/// offers it, or a per-key record names it, and cancelled otherwise.
#[test]
fn owed_key_keep_set_follows_the_resync_sources() {
    use super::super::outbound_owing::OwedKey;
    let mut manager = manager(8);
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 14, 1));
    let mut rx = up(&mut manager, peer, ipv4_sendable());
    received(&mut manager, vec![route(0, 0)], vec![], vec![], vec![]);
    send_all(&mut source);
    send_all(&mut rx);
    let key = |index| OwedKey::Unicast(route_prefix(index));
    assert!(manager.owed_key_kept(peer, &key(0)), "offered and held");
    assert!(
        !manager.owed_key_kept(peer, &key(7)),
        "neither offered nor held"
    );
    // A retained policy denial names the key.
    manager
        .policy_filtered_routes
        .entry(peer)
        .or_default()
        .insert(
            route_prefix(7),
            crate::manager::PolicyFilteredBucket::One(crate::manager::PolicyFilteredRouteKey {
                target_peer: peer,
                source_peer: peer_v4(SOURCE),
                prefix: route_prefix(7),
                path_id: 0,
            }),
        );
    assert!(
        manager.owed_key_kept(peer, &key(7)),
        "a policy denial keeps it"
    );
    // An OTC block names the key.
    manager.policy_filtered_routes.remove(&peer);
    assert!(!manager.owed_key_kept(peer, &key(7)));
    manager
        .peer_otc_blocked
        .entry(peer)
        .or_default()
        .insert(route_prefix(7), HashSet::from([0]));
    assert!(
        manager.owed_key_kept(peer, &key(7)),
        "an OTC block keeps it"
    );
}

fn peer_up_message(
    peer: PeerId,
    families: Vec<(Afi, Safi)>,
    outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
) -> RibUpdate {
    RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 200),
        outbound_tx,
        export_policy: None,
        sendable_families: families,
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    }
}

async fn actor_barrier(tx: &mpsc::Sender<RibUpdate>) {
    for _ in 0..2 {
        let (reply, response) = oneshot::channel();
        tx.send(RibUpdate::QueryLocRibCount { reply })
            .await
            .unwrap();
        response.await.unwrap();
    }
}

/// Refill latency, through the actor's own loop on a paused clock: once a
/// stalled receiver reads its queue, the keys it was owed are sent by the
/// next backlog tick, 10 ms later, not at the 1 s resync interval. Red with
/// owed keys left on the ordinary interval: nothing arrives at 10 ms.
#[tokio::test(start_paused = true)]
async fn owed_keys_follow_returned_credit_within_one_backlog_tick() {
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_outbound_row_credit(4);
    manager.test_force_ungrouped = true;
    let handle = tokio::spawn(manager.run());
    let (source_tx, mut source_rx) = mpsc::channel(64);
    tx.send(peer_up_message(peer_v4(SOURCE), ipv4_sendable(), source_tx))
        .await
        .unwrap();
    let peer = peer_v4(Ipv4Addr::new(10, 0, 15, 1));
    let (peer_tx, mut peer_rx) = mpsc::channel(64);
    tx.send(peer_up_message(peer, ipv4_sendable(), peer_tx))
        .await
        .unwrap();
    actor_barrier(&tx).await;
    send_all(&mut peer_rx);
    let announce = |routes: Vec<Route>| RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: routes,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    };
    // Four rows spend the credit; the receiver holds them.
    tx.send(announce((0..4).map(|key| route(key, 0)).collect()))
        .await
        .unwrap();
    actor_barrier(&tx).await;
    let stalled = held(&mut peer_rx);
    assert_eq!(rows(&stalled), 4);
    tx.send(announce(vec![route(9, 0)])).await.unwrap();
    actor_barrier(&tx).await;
    while source_rx.try_recv().is_ok() {}
    assert!(held(&mut peer_rx).is_empty(), "the fifth key is owed");
    // The session reads its queue: credit returns without telling the RIB.
    drop(stalled);
    tokio::time::advance(Duration::from_millis(11)).await;
    actor_barrier(&tx).await;
    let sent = send_all(&mut peer_rx);
    assert!(
        sent.iter()
            .any(|update| update.announce.iter().any(|r| r.prefix == route_prefix(9))),
        "the owed key is sent by the next backlog tick"
    );
    drop(tx);
    handle.await.unwrap();
}

/// Owed keys of a selection-deferred family are neither drained nor polled
/// for: while the hold lasts the drain leaves them and the resync timer
/// disarms. After the release they drain. Red when the drain ignores the
/// gate: the deferred keys are staged inside the hold.
#[test]
fn owed_keys_of_a_deferred_family_wait_for_the_release() {
    use super::selection_deferral_dirty_rtbh::{connect, manager_with_dormant_waiter};
    const DEFERRAL_SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 81);
    const WAITER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 83);
    let mut manager = manager_with_dormant_waiter().with_outbound_row_credit(8);
    manager.test_force_ungrouped = true;
    let mut source = connect(&mut manager, DEFERRAL_SOURCE, 4096, false, false);
    let peer = peer_v4(Ipv4Addr::new(192, 0, 2, 90));
    let mut rx = connect(
        &mut manager,
        Ipv4Addr::new(192, 0, 2, 90),
        4096,
        false,
        false,
    );
    send_all(&mut rx);
    let filler = manager.outbound_credit_handle(peer);
    let charge = crate::outbound_credit::OutboundCharge::new(&filler, 8);
    let announced = (0..4u8)
        .map(|index| {
            make_route_with_lp(
                Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, index), 32),
                DEFERRAL_SOURCE,
                100,
            )
        })
        .collect();
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: u64::from(DEFERRAL_SOURCE.octets()[3]),
        peer: peer_v4(DEFERRAL_SOURCE),
        announced,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    send_all(&mut source);
    assert_eq!(owed(&manager, peer, V4), 4);
    // The waiter arrives: IPv4 selection is held.
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    assert!(manager.selection_deferred(V4));
    drop(charge);
    for _ in 0..3 {
        manager.resync_dirty_peers_bounded();
    }
    assert!(
        send_all(&mut rx)
            .iter()
            .all(|update| update.announce.is_empty()),
        "nothing of a held family is staged"
    );
    assert_eq!(owed(&manager, peer, V4), 4, "the keys stay owed");
    assert!(
        !manager.resync_tick_pending(),
        "the timer does not spin on them"
    );
    manager.expire_selection_deferral();
    let mut announced = 0;
    for _ in 0..8 {
        manager.resync_dirty_peers_bounded();
        announced += send_all(&mut rx)
            .iter()
            .map(|update| update.announce.len())
            .sum::<usize>();
    }
    assert_eq!(announced, 4, "released, the owed keys are sent");
    assert!(manager.owing(peer).is_none());
}

/// Several owed prefixes that each hold more paths than the receiver's
/// credit, toward an Add-Path send-all receiver: each drain step stages one
/// complete prefix, all its paths, and leaves the rest owed until the
/// receiver reads, so queued rows stay within the credit plus that one
/// prefix. Red with a flat key count per step: every prefix is staged at
/// once, four times the credit.
#[test]
fn oversized_send_all_keys_drain_one_per_credit_window() {
    const SOURCES: u8 = 40;
    const PREFIXES: u32 = 4;
    let credit = 32;
    let mut manager = manager(credit);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 16, 1));
    let (outbound_tx, mut rx) = mpsc::channel(4096);
    let mut registration = peer_up_message(peer, ipv4_sendable(), outbound_tx);
    if let RibUpdate::PeerUp {
        add_path_send_families,
        add_path_send_max,
        ..
    } = &mut registration
    {
        *add_path_send_families = ipv4_sendable();
        *add_path_send_max = u32::MAX;
    }
    manager.handle_update(registration);
    send_all(&mut rx);
    let mut sources = Vec::new();
    for index in 0..SOURCES {
        let address = Ipv4Addr::new(10, 0, 17, index + 1);
        sources.push(up(&mut manager, peer_v4(address), ipv4_sendable()));
    }
    let filler = manager.outbound_credit_handle(peer);
    let charge = crate::outbound_credit::OutboundCharge::new(&filler, credit);
    for index in 0..SOURCES {
        let address = Ipv4Addr::new(10, 0, 17, index + 1);
        let announced = (0..PREFIXES)
            .map(|key| {
                let mut path = route(key, u32::from(index));
                path.peer = peer_v4(address);
                path.next_hop = IpAddr::V4(address);
                path
            })
            .collect();
        manager.handle_update(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: peer_v4(address),
            announced,
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        });
        drain_route_chunks(&mut manager);
    }
    for source in &mut sources {
        send_all(source);
    }
    assert_eq!(owed(&manager, peer, V4), PREFIXES as usize);
    drop(charge);
    let paths = usize::from(SOURCES);
    for step in 0..PREFIXES as usize {
        manager.resync_dirty_peers_bounded();
        let queued = held(&mut rx);
        assert_eq!(
            rows(&queued),
            paths,
            "step {step}: one complete prefix, every path"
        );
        assert!(rows(&queued) <= credit + paths);
        assert_eq!(owed(&manager, peer, V4), PREFIXES as usize - step - 1);
        // Still held: the next tick finds the credit spent.
        manager.resync_dirty_peers_bounded();
        assert!(
            held(&mut rx).is_empty(),
            "step {step}: nothing past the credit"
        );
        drop(queued);
    }
    assert!(manager.owing(peer).is_none());
    assert!(!manager.dirty_peers.contains(&peer));
}

/// A resync tick whose poll budget the owed-key drain uses up still gives
/// the dirty ring its slice: a dirty peer is resynced in the same tick.
/// Red when the tick returns once the budget is spent after draining owed
/// keys: the dirty peer is never resynced, and under a paused clock the
/// backlog cadence spins forever.
#[test]
fn owed_key_drain_never_starves_the_dirty_ring() {
    let mut manager = manager(8);
    manager.flush_poll_budget = Duration::ZERO;
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable());
    let owing = peer_v4(Ipv4Addr::new(10, 0, 18, 1));
    let mut owing_rx = up(&mut manager, owing, ipv4_sendable());
    let dirty = peer_v4(Ipv4Addr::new(10, 0, 18, 2));
    let mut dirty_rx = up(&mut manager, dirty, ipv4_sendable());
    send_all(&mut owing_rx);
    send_all(&mut dirty_rx);
    let filler = manager.outbound_credit_handle(owing);
    let charge = crate::outbound_credit::OutboundCharge::new(&filler, 8);
    received(&mut manager, vec![route(0, 0)], vec![], vec![], vec![]);
    send_all(&mut source);
    send_all(&mut dirty_rx);
    assert_eq!(owed(&manager, owing, V4), 1);
    drop(charge);
    manager.mark_outbound_dirty(dirty);
    manager.resync_dirty_peers_bounded();
    assert!(manager.owing(owing).is_none(), "the owed key drained");
    assert!(
        !manager.dirty_peers.contains(&dirty),
        "the dirty peer resynced in the same tick"
    );
}

/// A drain step refused by a full channel keeps its keys owed, without a
/// resync, and they go out once the channel has room. Red when a refused
/// step drops what it popped: the keys are lost and the route never
/// reaches the peer.
#[test]
fn a_drain_refused_by_a_full_channel_keeps_its_keys() {
    let mut manager = manager(8);
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 19, 1));
    let mut rx = up_session(&mut manager, peer, 0, ipv4_sendable(), 4);
    send_all(&mut rx);
    let filler = manager.outbound_credit_handle(peer);
    let charge = crate::outbound_credit::OutboundCharge::new(&filler, 8);
    received(&mut manager, vec![route(0, 0)], vec![], vec![], vec![]);
    send_all(&mut source);
    assert_eq!(owed(&manager, peer, V4), 1);
    drop(charge);
    let sender = manager.outbound_peers[&peer].clone();
    let occupied: Vec<_> = std::iter::from_fn(|| sender.clone().try_reserve_owned().ok()).collect();
    manager.resync_dirty_peers_bounded();
    assert_eq!(
        owed(&manager, peer, V4),
        1,
        "the refused step re-owes its key"
    );
    assert!(!manager.dirty_peers.contains(&peer));
    drop(occupied);
    manager.resync_dirty_peers_bounded();
    let sent = send_all(&mut rx);
    assert!(
        sent.iter()
            .any(|update| update.announce.iter().any(|r| r.prefix == route_prefix(0))),
        "the key is sent once the channel has room"
    );
    assert!(manager.owing(peer).is_none());
}

/// A resync covers every family it enumerated: the peer owes nothing after
/// it, and no owed state is left to re-walk. Red when the resync leaves the
/// owed sets in place: the peer still owes after its resync.
#[test]
fn a_resync_settles_what_the_peer_owed() {
    let mut manager = manager(8);
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 20, 1));
    let mut rx = up(&mut manager, peer, ipv4_sendable());
    send_all(&mut rx);
    let filler = manager.outbound_credit_handle(peer);
    let charge = crate::outbound_credit::OutboundCharge::new(&filler, 8);
    received(
        &mut manager,
        vec![route(0, 0), route(1, 0)],
        vec![],
        vec![],
        vec![],
    );
    send_all(&mut source);
    assert_eq!(owed(&manager, peer, V4), 2);
    drop(charge);
    manager.mark_outbound_dirty(peer);
    manager.resync_dirty_peers_bounded();
    assert!(!manager.dirty_peers.contains(&peer), "the resync ran");
    assert!(
        manager.owing(peer).is_none(),
        "the resync covered the owed keys"
    );
    let mut wire = Wire::default();
    wire.apply(&send_all(&mut rx));
    assert_eq!(wire.unicast.len(), 2);
}

// ---------------------------------------------------------------------------
// Review round 1 reproductions (fail at the reviewed head).
// ---------------------------------------------------------------------------

fn inject_local(manager: &mut RibManager, prefix: Ipv4Prefix, blackhole: bool) {
    let mut route = make_route(prefix, SOURCE);
    route.peer = crate::PeerId::LOCAL;
    route.origin_type = crate::route::RouteOrigin::Local;
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
    ];
    if blackhole {
        attributes.push(PathAttribute::Communities(vec![
            rustbgpd_wire::COMMUNITY_BLACKHOLE,
        ]));
    }
    route.attributes = AttrSet::new(attributes);
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectRoute { route, reply });
    result.try_recv().unwrap().unwrap();
}

fn withdraw_local(manager: &mut RibManager, prefix: Ipv4Prefix) {
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::WithdrawInjected {
        prefix: Prefix::V4(prefix),
        path_id: 0,
        allow_missing: false,
        owner: String::new(),
        override_owner: false,
        reply,
    });
    assert!(result.try_recv().unwrap().unwrap().removed);
}

/// Review P1. Local host and BLACKHOLE routes are exempt from a GR
/// selection hold (they stage while ordinary routes are frozen). A
/// receiver whose credit is spent is owed the withdrawal of such a route;
/// once its credit returns the withdrawal goes out inside the hold, as it
/// did when spent credit meant a resync. Red at the reviewed head: the
/// drain treats the whole deferred family as gated, and the withdrawal
/// waits for the release.
#[test]
fn review_p1_owed_exempt_withdrawal_drains_inside_a_selection_hold() {
    for floor in [0, 1 << 30] {
        for blackhole in [false, true] {
            use super::selection_deferral_dirty_rtbh::{connect, manager_with_dormant_waiter};
            const DEFERRAL_SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 81);
            const WAITER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 83);
            let mut manager = manager_with_dormant_waiter()
                .with_outbound_row_credit(8)
                .with_owing_theta_floor(floor);
            manager.test_force_ungrouped = true;
            let _source = connect(&mut manager, DEFERRAL_SOURCE, 4096, false, false);
            let peer = peer_v4(Ipv4Addr::new(192, 0, 2, 91));
            let (target_tx, mut rx) = mpsc::channel(4096);
            let mut target = peer_up_message(peer, vec![V4], target_tx);
            if let RibUpdate::PeerUp { export_policy, .. } = &mut target {
                *export_policy = Some(super::selection_deferral_dirty_rtbh::private_policy(Some(
                    rustbgpd_wire::COMMUNITY_BLACKHOLE,
                )));
            }
            manager.handle_update(target);
            send_all(&mut rx);
            let _waiter = connect(&mut manager, WAITER, 64, true, false);
            assert!(manager.selection_deferred(V4));
            let rtbh = Ipv4Prefix::new(
                Ipv4Addr::new(198, 51, 100, 0),
                if blackhole { 24 } else { 32 },
            );
            inject_local(&mut manager, rtbh, blackhole);
            let mut wire = Wire::default();
            wire.apply(&send_all(&mut rx));
            assert!(
                wire.unicast.contains_key(&(Prefix::V4(rtbh), 0)),
                "the exempt RTBH is advertised inside the hold"
            );
            let filler = manager.outbound_credit_handle(peer);
            let charge = crate::outbound_credit::OutboundCharge::new(&filler, 8);
            withdraw_local(&mut manager, rtbh);
            assert!(
                send_all(&mut rx).is_empty(),
                "spent credit owes the withdrawal"
            );
            drop(charge);
            for _ in 0..3 {
                manager.resync_dirty_peers_bounded();
                wire.apply(&send_all(&mut rx));
            }
            assert!(manager.selection_deferred(V4), "still inside the hold");
            assert!(
                !wire.unicast.contains_key(&(Prefix::V4(rtbh), 0)),
                "the exempt withdrawal is sent inside the hold once credit returns"
            );

            // A whole family keeps its held remainder; later local changes re-arm it.
            inject_local(&mut manager, rtbh, blackhole);
            manager.resync_dirty_peers_bounded();
            wire.apply(&send_all(&mut rx));
            assert!(wire.unicast.contains_key(&(Prefix::V4(rtbh), 0)));
            withdraw_local(&mut manager, rtbh);
            manager.resync_dirty_peers_bounded();
            wire.apply(&send_all(&mut rx));
            assert!(!wire.unicast.contains_key(&(Prefix::V4(rtbh), 0)));
            assert!(manager.selection_deferred(V4));
        }
    }
}

/// Review P2 (fair draining). An old owed withdrawal and a set of hot keys
/// that change again before every credit window: each window's drain must
/// eventually reach the old key. Red at the reviewed head: the drain pops
/// the newest keys first, so the hot keys fill every window and the old
/// withdrawal never goes.
#[test]
fn review_p2_old_owed_withdrawal_is_not_starved_by_hot_keys() {
    let hot_keys = u32::try_from(CHUNK_ROWS).expect("the test chunk size fits u32");
    let credit = CHUNK_ROWS;
    let mut manager = manager(credit).with_owing_theta_floor(1 << 30);
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 21, 1));
    let mut rx = up(&mut manager, peer, ipv4_sendable());
    let old = route(hot_keys + 7, 0);
    received(&mut manager, vec![old.clone()], vec![], vec![], vec![]);
    send_all(&mut source);
    let mut wire = Wire::default();
    wire.apply(&send_all(&mut rx));
    assert!(wire.unicast.contains_key(&(old.prefix, 0)));
    // Spend the credit, then owe the old route's withdrawal first.
    let filler = manager.outbound_credit_handle(peer);
    let charge = crate::outbound_credit::OutboundCharge::new(&filler, credit);
    received(&mut manager, vec![], vec![(old.prefix, 0)], vec![], vec![]);
    let hot = |variant: u32| {
        (0..hot_keys)
            .map(|key| route(key, variant))
            .collect::<Vec<_>>()
    };
    received(&mut manager, hot(0), vec![], vec![], vec![]);
    send_all(&mut source);
    drop(charge);
    for window in 1..=4 {
        // One credit window drains; the receiver holds what it got while
        // the hot keys change again.
        manager.resync_dirty_peers_bounded();
        let queued = held(&mut rx);
        received(&mut manager, hot(window), vec![], vec![], vec![]);
        send_all(&mut source);
        wire.apply(&queued);
        drop(queued);
        if !wire.unicast.contains_key(&(old.prefix, 0)) {
            return;
        }
    }
    panic!("the old owed withdrawal was never drained in four credit windows");
}

/// Review P2 (Add-Path family caps). The scalar Add-Path send limit is the
/// smallest family cap; a VPN family negotiated with a larger cap stages
/// more paths per key. A pass must still stage within the remaining
/// credit plus one key. Red at the reviewed head: the pass estimates two
/// rows a path at the scalar cap, stages unbounded, and queues 128 rows
/// against 64.
#[test]
fn review_p2_vpn_add_path_pass_budgets_with_the_family_cap() {
    const KEYS: u8 = 16;
    const PATHS: u32 = 8;
    let credit = 64;
    let mut manager = manager(credit).with_owing_theta_floor(1 << 30);
    let vpn = (Afi::Ipv4, Safi::MplsVpn);
    let source_address = Ipv4Addr::new(10, 0, 22, 9);
    let (source_tx, mut source_rx) = mpsc::channel(4096);
    manager.handle_update(peer_up_message(
        peer_v4(source_address),
        vec![V4, vpn],
        source_tx,
    ));
    send_all(&mut source_rx);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 22, 1));
    let (outbound_tx, mut rx) = mpsc::channel(4096);
    let mut registration = peer_up_message(peer, vec![V4, vpn], outbound_tx);
    if let RibUpdate::PeerUp {
        add_path_send_families,
        add_path_send_max,
        ..
    } = &mut registration
    {
        *add_path_send_families = vec![V4, vpn];
        *add_path_send_max = 1;
    }
    manager.handle_update(registration);
    manager.handle_update(RibUpdate::PeerAddPathLimits {
        peer,
        session_id: 0,
        limits: vec![(V4, 1), (vpn, PATHS)],
    });
    send_all(&mut rx);
    let announced = (0..KEYS)
        .flat_map(|key| {
            (0..PATHS).map(move |path| {
                let mut route = make_vpn_rib_route(source_address, key + 1, 100 + path, 100);
                route.path_id = path + 1;
                route.attributes = AttrSet::new(vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::LocalPref(100),
                    PathAttribute::Med(path),
                ]);
                route
            })
        })
        .collect();
    manager.handle_update(RibUpdate::VpnRoutesReceived {
        peer: peer_v4(source_address),
        session_id: 0,
        announced,
        withdrawn: vec![],
    });
    drain_route_chunks(&mut manager);
    let queued = held(&mut rx);
    let rows: usize = queued
        .iter()
        .map(|update| update.vpn_announce.len() + update.vpn_withdraw.len())
        .sum();
    assert_eq!(rows, credit, "the pass uses exactly the available credit");
    assert!(
        rows <= credit + 2 * PATHS as usize,
        "{rows} VPN rows queued against {credit}"
    );
}

/// Review P2 (cadence). Owed keys that appear while the resync timer is
/// already armed at the one-second interval for unrelated work (a dirty
/// peer behind a full channel) are still drained at the backlog cadence
/// once credit returns. Red at the reviewed head: the armed one-second
/// deadline is kept, and nothing arrives within 10 ms.
#[tokio::test(start_paused = true)]
async fn review_p2_owed_keys_shorten_an_armed_one_second_timer() {
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_outbound_row_credit(4);
    manager.test_force_ungrouped = true;
    let handle = tokio::spawn(manager.run());
    let (source_tx, mut source_rx) = mpsc::channel(64);
    tx.send(peer_up_message(peer_v4(SOURCE), ipv4_sendable(), source_tx))
        .await
        .unwrap();
    // A peer whose one-slot channel stays full: it goes dirty and arms the
    // resync timer at the ordinary interval.
    let (blocked_tx, _blocked_rx) = {
        let (tx_inner, rx_inner) = mpsc::channel(1);
        tx_inner.try_send(OutboundRouteUpdate::default()).unwrap();
        (tx_inner, rx_inner)
    };
    tx.send(peer_up_message(
        peer_v4(Ipv4Addr::new(10, 0, 23, 9)),
        ipv4_sendable(),
        blocked_tx,
    ))
    .await
    .unwrap();
    let peer = peer_v4(Ipv4Addr::new(10, 0, 23, 1));
    let (peer_tx, mut peer_rx) = mpsc::channel(64);
    tx.send(peer_up_message(peer, ipv4_sendable(), peer_tx))
        .await
        .unwrap();
    actor_barrier(&tx).await;
    send_all(&mut peer_rx);
    let announce = |routes: Vec<Route>| RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: routes,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    };
    tx.send(announce((0..4).map(|key| route(key, 0)).collect()))
        .await
        .unwrap();
    actor_barrier(&tx).await;
    let stalled = held(&mut peer_rx);
    assert_eq!(rows(&stalled), 4);
    tx.send(announce(vec![route(9, 0)])).await.unwrap();
    actor_barrier(&tx).await;
    while source_rx.try_recv().is_ok() {}
    assert!(held(&mut peer_rx).is_empty(), "the fifth key is owed");
    drop(stalled);
    tokio::time::advance(Duration::from_millis(11)).await;
    actor_barrier(&tx).await;
    let sent = send_all(&mut peer_rx);
    assert!(
        sent.iter()
            .any(|update| update.announce.iter().any(|r| r.prefix == route_prefix(9))),
        "the owed key is sent by the next backlog tick"
    );
    drop(tx);
    handle.await.unwrap();
}

// ---------------------------------------------------------------------------
// Review round 1, further regressions.
// ---------------------------------------------------------------------------

/// A selection-deferral manager whose waiter holds `families`.
fn deferral_manager(families: Vec<(Afi, Safi)>, credit: usize) -> RibManager {
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 100)),
        BgpMetrics::new(),
    )
    .with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: vec![SelectionDeferralWaiterConfig {
            peer: peer_v4(Ipv4Addr::new(192, 0, 2, 83)),
            families,
        }],
    })
    .with_outbound_row_credit(credit);
    manager.test_force_ungrouped = true;
    manager
}

/// Register `address` for `families` on session `session_id`; a `waiter`
/// lists them as GR families, which arms a configured selection hold.
fn connect_families(
    manager: &mut RibManager,
    address: Ipv4Addr,
    families: Vec<(Afi, Safi)>,
    waiter: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = peer_v4(address);
    let session_id = u64::from(address.octets()[3]);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: if waiter { families.clone() } else { vec![] },
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (outbound_tx, outbound_rx) = mpsc::channel(4096);
    let mut registration = peer_up_message(peer, families, outbound_tx);
    if let RibUpdate::PeerUp { session_id: id, .. } = &mut registration {
        *id = session_id;
    }
    manager.handle_update(registration);
    outbound_rx
}

/// Inside a selection hold that covers EVPN, owed EVPN keys stay owed:
/// EVPN has no hold exemption, so nothing of it is staged until the
/// release, after which the keys drain. Pins the seam of the exempt-only
/// drain: a family without exemptions keeps its keys.
#[test]
fn owed_evpn_keys_wait_for_the_selection_release() {
    let mut manager = deferral_manager(vec![EVPN], 8);
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let mut source_rx = connect_families(&mut manager, source, evpn_sendable(), false);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 24, 1));
    let mut rx = connect_families(
        &mut manager,
        Ipv4Addr::new(10, 0, 24, 1),
        evpn_sendable(),
        false,
    );
    send_all(&mut rx);
    let filler = manager.outbound_credit_handle(peer);
    let charge = crate::outbound_credit::OutboundCharge::new(&filler, 8);
    let routes: Vec<_> = (0..3).map(|tag| evpn_route(tag, 0)).collect();
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 1,
        peer: peer_v4(source),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: routes,
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    send_all(&mut source_rx);
    assert_eq!(owed(&manager, peer, EVPN), 3);
    let _waiter = connect_families(
        &mut manager,
        Ipv4Addr::new(192, 0, 2, 83),
        evpn_sendable(),
        true,
    );
    assert!(manager.selection_deferred(EVPN));
    drop(charge);
    for _ in 0..3 {
        manager.resync_dirty_peers_bounded();
    }
    assert!(
        send_all(&mut rx)
            .iter()
            .all(|update| update.evpn_announce.is_empty()),
        "nothing of a held family without exemptions is staged"
    );
    assert_eq!(owed(&manager, peer, EVPN), 3);
    manager.expire_selection_deferral();
    let mut announced = 0;
    for _ in 0..8 {
        manager.resync_dirty_peers_bounded();
        announced += send_all(&mut rx)
            .iter()
            .map(|update| update.evpn_announce.len())
            .sum::<usize>();
    }
    assert_eq!(announced, 3, "released, the owed keys are sent");
    assert!(manager.owing(peer).is_none());
}

/// A locally injected `FlowSpec` rule is exempt from a GR selection hold.
/// Revoked while the receiver's credit is spent, its family is owed whole;
/// once credit returns the withdrawal goes out inside the hold, the family
/// stays owed for the release without a second pass, and the release
/// settles it. Red when the drain treats the held family as gated: the
/// withdrawal waits for the release.
#[test]
fn owed_flowspec_revocation_drains_inside_a_selection_hold() {
    let flowspec = (Afi::Ipv4, Safi::FlowSpec);
    let mut manager = deferral_manager(vec![flowspec], 8);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 25, 1));
    let mut rx = connect_families(
        &mut manager,
        Ipv4Addr::new(10, 0, 25, 1),
        vec![flowspec],
        false,
    );
    send_all(&mut rx);
    let _waiter = connect_families(
        &mut manager,
        Ipv4Addr::new(192, 0, 2, 83),
        vec![flowspec],
        true,
    );
    assert!(manager.selection_deferred(flowspec));
    let mut rule = make_flowspec_route(Ipv4Addr::UNSPECIFIED);
    rule.peer = crate::PeerId::LOCAL;
    let key = rule.selection_key();
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectFlowSpec { route: rule, reply });
    result.try_recv().unwrap().unwrap();
    let sent = send_all(&mut rx);
    assert!(
        sent.iter()
            .any(|update| !update.flowspec_announce.is_empty()),
        "the local rule is advertised inside the hold"
    );
    let filler = manager.outbound_credit_handle(peer);
    let charge = crate::outbound_credit::OutboundCharge::new(&filler, 8);
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::WithdrawFlowSpec {
        key: key.clone(),
        allow_missing: false,
        owner: String::new(),
        override_owner: false,
        reply,
    });
    result.try_recv().unwrap().unwrap();
    assert!(send_all(&mut rx).is_empty());
    assert!(manager.owes_whole(peer, OwedFamily::IPV4_FLOWSPEC));
    drop(charge);
    manager.resync_dirty_peers_bounded();
    let sent = send_all(&mut rx);
    assert!(
        sent.iter()
            .any(|update| update.flowspec_withdraw.contains(&key)),
        "the revocation is sent inside the hold"
    );
    assert!(
        manager.owes_whole(peer, OwedFamily::IPV4_FLOWSPEC),
        "the family stays owed for the release"
    );
    for _ in 0..3 {
        manager.resync_dirty_peers_bounded();
    }
    assert!(send_all(&mut rx).is_empty(), "one pass per hold");
    let mut rule = make_flowspec_route(Ipv4Addr::UNSPECIFIED);
    rule.peer = crate::PeerId::LOCAL;
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectFlowSpec { route: rule, reply });
    result.try_recv().unwrap().unwrap();
    manager.resync_dirty_peers_bounded();
    assert!(
        send_all(&mut rx)
            .iter()
            .any(|update| !update.flowspec_announce.is_empty()),
        "a new local change re-arms the held whole family"
    );
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::WithdrawFlowSpec {
        key: key.clone(),
        allow_missing: false,
        owner: String::new(),
        override_owner: false,
        reply,
    });
    result.try_recv().unwrap().unwrap();
    manager.resync_dirty_peers_bounded();
    assert!(
        send_all(&mut rx)
            .iter()
            .any(|update| update.flowspec_withdraw.contains(&key)),
        "a second revocation also drains inside the hold"
    );
    manager.expire_selection_deferral();
    for _ in 0..4 {
        manager.resync_dirty_peers_bounded();
        send_all(&mut rx);
    }
    assert!(manager.owing(peer).is_none(), "the release settles it");
}

/// An absorption that cannot be admitted (here the session has no export
/// encoder) escalates the peer to a resync and keeps its End-of-RIB
/// pending: the marker never goes out ahead of the routes the peer was
/// owed in that family. Red when the failed absorption reports success:
/// the End-of-RIB is sent at once.
#[test]
fn a_failed_absorption_keeps_the_end_of_rib() {
    let families = [V4, (Afi::Ipv6, Safi::Unicast)];
    let mut manager = manager(8);
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 26, 1));
    let mut rx = up(&mut manager, peer, families.to_vec());
    send_all(&mut rx);
    let filler = manager.outbound_credit_handle(peer);
    let charge = crate::outbound_credit::OutboundCharge::new(&filler, 8);
    received(&mut manager, vec![route(0, 0)], vec![], vec![], vec![]);
    send_all(&mut source);
    assert_eq!(owed(&manager, peer, V4), 1);
    drop(charge);
    manager
        .pending_eor
        .entry(peer)
        .or_default()
        .extend(families);
    let encoder = manager.peer_export_encoders.remove(&peer).unwrap();
    manager.flush_pending_eor(peer);
    assert!(
        send_all(&mut rx)
            .iter()
            .all(|update| update.end_of_rib.is_empty()),
        "no family End-of-RIB overtakes the failed absorption"
    );
    assert!(
        manager
            .pending_eor
            .get(&peer)
            .is_some_and(|pending| families.iter().all(|family| pending.contains(family)))
    );
    assert!(
        manager.dirty_peers.contains(&peer),
        "the peer resyncs instead"
    );
    manager.flush_pending_eor(peer);
    assert!(
        send_all(&mut rx).is_empty(),
        "a retry still waits for the resync"
    );
    manager.peer_export_encoders.insert(peer, encoder);
    manager.resync_dirty_peers_bounded();
    let recovered = send_all(&mut rx);
    let data = recovered
        .iter()
        .position(|update| !update.announce.is_empty())
        .unwrap();
    let marker = recovered
        .iter()
        .position(|update| update.end_of_rib.contains(&V4))
        .unwrap();
    assert!(data <= marker, "recovery admits data before its End-of-RIB");
    assert!(families.iter().all(|family| {
        recovered
            .iter()
            .any(|update| update.end_of_rib.contains(family))
    }));
    assert!(!manager.dirty_peers.contains(&peer));
    assert!(manager.owing(peer).is_none());
}

/// The byte cap compares bytes with bytes: a quarter of the family, priced
/// per key like the floor. A receiver of a 2,000-route table owes 300
/// changed keys as keys; most of the table changing owes it whole. Red
/// when the cap compares the set's bytes with a route count: 300 keys
/// already flip the family.
#[test]
fn byte_cap_is_a_quarter_of_the_family_in_bytes() {
    const TABLE: u32 = 2_000;
    let run = |changed: u32| {
        let mut manager = manager(1 << 20);
        let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable());
        let peer = peer_v4(Ipv4Addr::new(10, 0, 27, 1));
        let mut rx = up(&mut manager, peer, ipv4_sendable());
        received(
            &mut manager,
            (0..TABLE).map(|key| route(key, 0)).collect(),
            vec![],
            vec![],
            vec![],
        );
        send_all(&mut source);
        send_all(&mut rx);
        manager.outbound_row_credit_override = Some(8);
        let filler = manager.outbound_credit_handle(peer);
        let charge = crate::outbound_credit::OutboundCharge::new(&filler, 8);
        received(
            &mut manager,
            (0..changed).map(|key| route(key, 1)).collect(),
            vec![],
            vec![],
            vec![],
        );
        send_all(&mut source);
        drop(charge);
        (
            manager.owes_whole(peer, OwedFamily::IPV4_UNICAST),
            owed(&manager, peer, V4),
        )
    };
    assert_eq!(run(300), (false, 300), "300 of 2,000 keys stay keyed");
    assert!(run(1_900).0, "most of the table owes the family whole");
}

/// The labeled twin of the VPN family-cap regression: a labeled Add-Path
/// family negotiated with a larger cap than the scalar limit still stages
/// within the remaining credit plus one key. Red at the reviewed head:
/// 128 rows queued against 64.
#[test]
fn labeled_add_path_pass_budgets_with_the_family_cap() {
    const KEYS: u8 = 16;
    const PATHS: u32 = 8;
    let credit = 64;
    let mut manager = manager(credit).with_owing_theta_floor(1 << 30);
    let labeled = (Afi::Ipv4, Safi::LabeledUnicast);
    let source_address = Ipv4Addr::new(10, 0, 28, 9);
    let (source_tx, mut source_rx) = mpsc::channel(4096);
    manager.handle_update(peer_up_message(
        peer_v4(source_address),
        vec![V4, labeled],
        source_tx,
    ));
    send_all(&mut source_rx);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 28, 1));
    let (outbound_tx, mut rx) = mpsc::channel(4096);
    let mut registration = peer_up_message(peer, vec![V4, labeled], outbound_tx);
    if let RibUpdate::PeerUp {
        add_path_send_families,
        add_path_send_max,
        ..
    } = &mut registration
    {
        *add_path_send_families = vec![V4, labeled];
        *add_path_send_max = 1;
    }
    manager.handle_update(registration);
    manager.handle_update(RibUpdate::PeerAddPathLimits {
        peer,
        session_id: 0,
        limits: vec![(V4, 1), (labeled, PATHS)],
    });
    send_all(&mut rx);
    let announced = (0..KEYS)
        .flat_map(|key| {
            (0..PATHS).map(move |path| {
                let mut route = make_labeled_rib_route(source_address, key + 1, 100 + path, 100);
                route.path_id = path + 1;
                route.attributes = AttrSet::new(vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::LocalPref(100),
                    PathAttribute::Med(path),
                ]);
                route
            })
        })
        .collect();
    manager.handle_update(RibUpdate::LabeledRoutesReceived {
        peer: peer_v4(source_address),
        session_id: 0,
        announced,
        withdrawn: vec![],
    });
    drain_route_chunks(&mut manager);
    let queued = held(&mut rx);
    let rows: usize = queued
        .iter()
        .map(|update| update.labeled_announce.len() + update.labeled_withdraw.len())
        .sum();
    assert_eq!(rows, credit, "the pass uses exactly the available credit");
    assert!(
        rows <= credit + 2 * PATHS as usize,
        "{rows} labeled rows queued against {credit}"
    );
}

/// Whole-family debt that waits only for the receiver's live operation
/// latch keeps the resync timer armed, so the latch release drains it
/// with no other activity. Red when such debt does not keep the timer:
/// the timer disarms and the latch release wakes nothing.
#[tokio::test(start_paused = true)]
async fn whole_family_debt_behind_a_latch_drains_when_it_releases() {
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_outbound_row_credit(4)
        .with_owing_theta_floor(0);
    manager.test_force_ungrouped = true;
    let handle = tokio::spawn(manager.run());
    let (source_tx, mut source_rx) = mpsc::channel(64);
    tx.send(peer_up_message(peer_v4(SOURCE), ipv4_sendable(), source_tx))
        .await
        .unwrap();
    let announce = |routes: Vec<Route>| RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: routes,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    };
    tx.send(announce(vec![route(50, 0)])).await.unwrap();
    actor_barrier(&tx).await;
    let peer = peer_v4(Ipv4Addr::new(10, 0, 29, 1));
    let (peer_tx, mut peer_rx) = mpsc::channel(64);
    tx.send(peer_up_message(peer, ipv4_sendable(), peer_tx))
        .await
        .unwrap();
    actor_barrier(&tx).await;
    // The receiver holds its initial table: the operation latch stays live.
    let dump = held(&mut peer_rx);
    assert!(!dump.is_empty());
    tx.send(announce((0..4).map(|key| route(key, 0)).collect()))
        .await
        .unwrap();
    actor_barrier(&tx).await;
    let spent = held(&mut peer_rx);
    assert_eq!(rows(&spent), 4);
    // Owed now, and whole at a zero byte cap.
    tx.send(announce(vec![route(9, 0)])).await.unwrap();
    actor_barrier(&tx).await;
    while source_rx.try_recv().is_ok() {}
    drop(spent);
    // Credit is back, but the whole family needs the latch: let any timer
    // that would run expire before the latch drops.
    tokio::time::advance(Duration::from_secs(3)).await;
    actor_barrier(&tx).await;
    assert!(
        held(&mut peer_rx).is_empty(),
        "nothing before the latch drops"
    );
    drop(dump);
    // No query may wake the actor after the latch release.
    tokio::time::timeout(Duration::from_millis(50), async {
        loop {
            let update = peer_rx.recv().await.expect("the actor keeps its sender");
            if update
                .announce
                .iter()
                .any(|route| route.prefix == route_prefix(9))
            {
                break;
            }
        }
    })
    .await
    .expect("the latch release drains the whole family");
    drop(tx);
    handle.await.unwrap();
}

/// Owed keys drained by the actor across many poll slices: with a zero
/// poll budget each tick drains one owing peer's step, a query is served
/// between slices, the round-robin resumes after the last peer, and every
/// receiver converges exactly. Red without the owed lane's budget check:
/// the first tick drains every peer.
#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "actor ordering, pacing assertions and convergence form one scenario"
)]
async fn owed_keys_drain_across_poll_slices_through_the_actor() {
    const PEERS: u8 = 3;
    const KEYS: u32 = 12;
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_outbound_row_credit(4)
        .with_owing_theta_floor(1 << 30);
    manager.test_force_ungrouped = true;
    manager.flush_poll_budget = Duration::ZERO;
    let handle = tokio::spawn(manager.run());
    let (source_tx, mut source_rx) = mpsc::channel(4096);
    tx.send(peer_up_message(peer_v4(SOURCE), ipv4_sendable(), source_tx))
        .await
        .unwrap();
    let mut receivers = Vec::new();
    for index in 0..PEERS {
        let peer = peer_v4(Ipv4Addr::new(10, 0, 30, index + 1));
        let (peer_tx, peer_rx) = mpsc::channel(4096);
        tx.send(peer_up_message(peer, ipv4_sendable(), peer_tx))
            .await
            .unwrap();
        receivers.push((peer, peer_rx, Wire::default()));
    }
    actor_barrier(&tx).await;
    for (_, peer_rx, wire) in &mut receivers {
        wire.apply(&send_all(peer_rx));
    }
    let announce = |routes: Vec<Route>| RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: routes,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    };
    // Each receiver takes four rows of credit and owes the other keys.
    tx.send(announce((0..KEYS).map(|key| route(key, 0)).collect()))
        .await
        .unwrap();
    actor_barrier(&tx).await;
    while source_rx.try_recv().is_ok() {}
    let mut held_rows: Vec<Vec<OutboundRouteUpdate>> = receivers
        .iter_mut()
        .map(|(_, peer_rx, _)| held(peer_rx))
        .collect();
    for ((_, _, wire), queued) in receivers.iter_mut().zip(&held_rows) {
        assert_eq!(rows(queued), 4);
        wire.apply(queued);
    }
    held_rows.clear();
    // Each tick serves a query between slices and resumes after the last peer.
    let mut order = Vec::new();
    for _ in 0..PEERS {
        tokio::time::advance(Duration::from_millis(11)).await;
        actor_barrier(&tx).await;
        let progressed: Vec<_> = receivers
            .iter_mut()
            .filter_map(|(peer, peer_rx, wire)| {
                let sent = send_all(peer_rx);
                wire.apply(&sent);
                (!sent.is_empty()).then_some(*peer)
            })
            .collect();
        assert_eq!(
            progressed.len(),
            1,
            "a zero poll budget drains one peer per tick"
        );
        order.push(progressed[0]);
    }
    assert_eq!(
        order,
        receivers
            .iter()
            .map(|(peer, _, _)| *peer)
            .collect::<Vec<_>>(),
        "the cursor resumes at the next peer while each still owes more than one step"
    );
    // Later ticks, with the receivers reading, converge every receiver.
    for _ in 0..64 {
        tokio::time::advance(Duration::from_millis(11)).await;
        actor_barrier(&tx).await;
        for (_, peer_rx, wire) in &mut receivers {
            wire.apply(&send_all(peer_rx));
        }
    }
    let expected_keys: std::collections::BTreeSet<_> =
        (0..KEYS).map(|key| (route_prefix(key), 0)).collect();
    for (peer, _, wire) in &receivers {
        assert_eq!(
            wire.unicast
                .keys()
                .copied()
                .collect::<std::collections::BTreeSet<_>>(),
            expected_keys,
            "{peer} converged on every key"
        );
        let admitted: BTreeMap<_, _> = collect_advertised_routes(&tx, *peer)
            .await
            .into_iter()
            .map(|route| {
                (
                    (route.prefix, route.path_id),
                    format!("{:?}", route.attributes),
                )
            })
            .collect();
        assert_eq!(
            wire.unicast, admitted,
            "{peer} received every admitted attribute"
        );
        let (reply, response) = oneshot::channel();
        tx.send(RibUpdate::TestQueryPeerOutboundOwed { peer: *peer, reply })
            .await
            .unwrap();
        let owed = response.await.unwrap();
        assert!(owed.owed_pending.is_empty() && !owed.resync);
    }
    drop(tx);
    handle.await.unwrap();
}
