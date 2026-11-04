//! ADR-0145 slice 1b: owed-key sets for private families. A receiver whose
//! row credit is spent is owed keys instead of being marked dirty; the
//! resync tick drains them from current state, barriers absorb them, and
//! shutdown flushes their withdrawals.

use std::collections::BTreeMap;

use super::super::outbound_owing::OwedFamily;
use super::*;

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
