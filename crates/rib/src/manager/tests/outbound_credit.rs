//! Retained outbound payload: what queued envelopes pin for receivers that
//! stop reading, counted by unique allocation rather than by envelope.

use super::*;

const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

fn manager() -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 100)),
        BgpMetrics::new(),
    )
}

fn peer_up_v4(
    manager: &mut RibManager,
    peer: PeerId,
    capacity: usize,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, mut output) = mpsc::channel(capacity);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 200),
        outbound_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    });
    while output.try_recv().is_ok() {}
    output
}

fn source_route(index: u32) -> Route {
    let mut route = make_indexed_route(index + 1, SOURCE);
    route.peer = peer_v4(SOURCE);
    route
}

/// Heap bytes the unicast withdrawal vectors of `updates` pin: each shared
/// vector once, by allocation, and every envelope's own vector.
fn pinned_withdraw_bytes(updates: &[OutboundRouteUpdate]) -> usize {
    let row = std::mem::size_of::<(Prefix, u32)>();
    let mut seen = std::collections::HashSet::new();
    updates
        .iter()
        .map(|update| {
            let shared = if seen.insert(Arc::as_ptr(&update.shared_withdraw) as usize) {
                update.shared_withdraw.capacity() * row
            } else {
                0
            };
            shared + update.withdraw.capacity() * row
        })
        .sum()
}

/// T12. A 64-member update group with 16 members stalled while the rest
/// drain: 400 passes each announce 8 new prefixes and withdraw the previous
/// pass's 8. The withdrawal bytes the stalled queues pin stay those of one
/// member's queue, whatever the number of stalled members, because every
/// member's envelope holds the group's shared vector. Red with per-member
/// copies: the stalled members pin 16 copies.
#[test]
fn stalled_group_members_share_withdrawal_payload() {
    const MEMBERS: u8 = 64;
    const STALLED: usize = 16;
    const BATCHES: u32 = 400;
    const PER_BATCH: u32 = 8;
    let mut manager = manager();
    let mut source_output = peer_up_v4(&mut manager, peer_v4(SOURCE), 4096);
    let mut members: Vec<_> = (0..MEMBERS)
        .map(|index| {
            let peer = peer_v4(Ipv4Addr::new(10, 0, 1, index + 1));
            (peer, peer_up_v4(&mut manager, peer, 4096))
        })
        .collect();
    let group = manager.grouped_member_of(members[0].0);
    assert!(group.is_some());
    assert!(
        members
            .iter()
            .all(|(peer, _)| manager.grouped_member_of(*peer) == group),
        "one update group"
    );
    let mut stalled: Vec<Vec<OutboundRouteUpdate>> = (0..STALLED).map(|_| Vec::new()).collect();
    for batch in 0..BATCHES {
        let announced = (0..PER_BATCH)
            .map(|i| source_route(batch * PER_BATCH + i))
            .collect();
        let withdrawn = if batch == 0 {
            vec![]
        } else {
            (0..PER_BATCH)
                .map(|i| (source_route((batch - 1) * PER_BATCH + i).prefix, 0))
                .collect()
        };
        manager.handle_update(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: peer_v4(SOURCE),
            announced,
            withdrawn,
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        });
        drain_route_chunks(&mut manager);
        while source_output.try_recv().is_ok() {}
        for (index, (_, output)) in members.iter_mut().enumerate() {
            while let Ok(update) = output.try_recv() {
                // Holding the envelope is what a stalled session does.
                if index < STALLED {
                    stalled[index].push(update);
                }
            }
        }
    }
    for (peer, _) in &members {
        assert!(!manager.dirty_peers.contains(peer), "{peer} never refused");
    }
    let one_member = pinned_withdraw_bytes(&stalled[0]);
    let rows: usize = stalled[0]
        .iter()
        .map(|update| update.unicast_withdrawals().count())
        .sum();
    assert_eq!(rows, usize::try_from((BATCHES - 1) * PER_BATCH).unwrap());
    let all: Vec<_> = stalled.into_iter().flatten().collect();
    let pinned = pinned_withdraw_bytes(&all);
    assert!(
        pinned <= one_member + one_member / 4,
        "{STALLED} stalled members pin {pinned} withdrawal bytes; one member's queue is \
         {one_member}"
    );
    assert!(
        all.iter().any(|update| !update.shared_withdraw.is_empty()),
        "the grouped fanout queued shared withdrawals"
    );
}

// ---------------------------------------------------------------------------
// Row credit, operation latches and `BeginClose`.
// ---------------------------------------------------------------------------

use super::super::distribution::OutboundCommitBatch;
use crate::outbound_credit::{CHUNK_ROWS, chunk_plan, split_by_plan};

/// Register `peer` with `families`, channel `capacity` and Add-Path send
/// `add_path` (0 = off); its initial dump is left queued.
fn up(
    manager: &mut RibManager,
    peer: PeerId,
    families: Vec<(Afi, Safi)>,
    capacity: usize,
    add_path: u32,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    up_session(manager, peer, 0, families, capacity, add_path)
}

fn up_session(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
    families: Vec<(Afi, Safi)>,
    capacity: usize,
    add_path: u32,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, output) = mpsc::channel(capacity);
    let add_path_send_families = if add_path == 0 {
        vec![]
    } else {
        families
            .iter()
            .copied()
            .filter(|(_, safi)| *safi == Safi::Unicast)
            .collect()
    };
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
        add_path_send_families,
        add_path_send_max: add_path,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    });
    output
}

/// A session that sends everything queued: the envelopes drop.
fn send_all(output: &mut mpsc::Receiver<OutboundRouteUpdate>) -> Vec<OutboundRouteUpdate> {
    std::iter::from_fn(|| output.try_recv().ok().map(delivered)).collect()
}

/// Every envelope queued, still holding its charge and latch: a stalled
/// session.
fn held(output: &mut mpsc::Receiver<OutboundRouteUpdate>) -> Vec<OutboundRouteUpdate> {
    std::iter::from_fn(|| output.try_recv().ok()).collect()
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

fn routes_received(
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

/// Rows in `updates` (every family these tests use is private).
fn rows(updates: &[OutboundRouteUpdate]) -> usize {
    updates
        .iter()
        .map(|update| {
            update.announce.len()
                + update.unicast_withdrawals().count()
                + update.evpn_announce.len()
                + update.evpn_withdraw.len()
                + update.otc_blocked.len()
        })
        .sum()
}

/// Heap bytes the route vectors of `updates` pin, each shared allocation
/// once.
fn pinned_bytes(updates: &[OutboundRouteUpdate]) -> usize {
    let mut seen = std::collections::HashSet::new();
    let mut bytes = pinned_withdraw_bytes(updates);
    for update in updates {
        if seen.insert(Arc::as_ptr(&update.announce) as usize) {
            bytes += update.announce.capacity() * std::mem::size_of::<Route>();
        }
        if seen.insert(Arc::as_ptr(&update.evpn_announce).cast::<u8>() as usize) {
            bytes += update.evpn_announce.capacity() * std::mem::size_of::<EvpnRibRoute>();
        }
        bytes +=
            update.evpn_withdraw.capacity() * std::mem::size_of::<rustbgpd_wire::EvpnRouteKey>();
        bytes += update.otc_blocked.capacity() * std::mem::size_of::<Route>();
    }
    bytes
}

const T1_STALLED: u8 = 8;
const T1_KEYS: u32 = 64;
const T1_CREDIT: usize = 2 * CHUNK_ROWS;

struct StallOutcome {
    /// Rows charged to each stalled receiver's credit.
    charged: Vec<usize>,
    /// Every row queued for each stalled receiver.
    retained: Vec<usize>,
    /// Unique route-vector bytes queued across the stalled receivers.
    bytes: usize,
    /// Every stalled receiver owes keys and none is dirty.
    owing: bool,
}

/// `rounds` churn rounds of `T1_KEYS` private EVPN keys toward `T1_STALLED`
/// receivers that never drain, plus one that drains every round. `fresh`:
/// every round announces new keys and withdraws the previous round's.
fn stalled_private_evpn(rounds: u32, fresh: bool) -> StallOutcome {
    let mut manager = manager().with_outbound_row_credit(T1_CREDIT);
    let mut source = up(&mut manager, peer_v4(SOURCE), evpn_sendable(), 4096, 0);
    let control = peer_v4(Ipv4Addr::new(10, 0, 2, 1));
    let mut control_rx = up(&mut manager, control, evpn_sendable(), 4096, 0);
    let mut stalled: Vec<_> = (0..T1_STALLED)
        .map(|index| {
            let peer = peer_v4(Ipv4Addr::new(10, 0, 3, index + 1));
            let mut rx = up(&mut manager, peer, evpn_sendable(), 4096, 0);
            send_all(&mut rx);
            (peer, rx)
        })
        .collect();
    send_all(&mut control_rx);
    for round in 0..rounds {
        let base = if fresh { round * T1_KEYS } else { 0 };
        let announced = (0..T1_KEYS)
            .map(|key| evpn_route(base + key, round))
            .collect();
        let withdrawn = if fresh && round > 0 {
            (0..T1_KEYS)
                .map(|key| evpn_route(base - T1_KEYS + key, 0).key())
                .collect()
        } else {
            vec![]
        };
        routes_received(&mut manager, vec![], vec![], announced, withdrawn);
        send_all(&mut source);
        send_all(&mut control_rx);
        assert!(
            !manager.dirty_peers.contains(&control),
            "a draining receiver is never refused"
        );
    }
    let mut outcome = StallOutcome {
        charged: Vec::new(),
        retained: Vec::new(),
        bytes: 0,
        owing: true,
    };
    let mut all = Vec::new();
    for (peer, rx) in &mut stalled {
        outcome.charged.push(manager.outbound_credit_rows(*peer));
        let queued = held(rx);
        outcome.retained.push(rows(&queued));
        outcome.owing &= manager.owing(*peer).is_some() && !manager.dirty_peers.contains(peer);
        all.extend(queued);
    }
    outcome.bytes = pinned_bytes(&all);
    outcome
}

/// T1. Stalled private receivers hold no more than their credit plus one
/// pass, and the bytes they pin do not grow with the churn rounds: 4× the
/// rounds pin the same unique bytes within one pass. Charged rows are every
/// retained row here (no whole-table operation runs). Red without the
/// credit check: every round stays queued, so the bytes grow 4×.
#[test]
fn stalled_private_receivers_pin_bytes_flat_in_churn_rounds() {
    for fresh in [false, true] {
        let pass = usize::try_from(if fresh { 2 * T1_KEYS } else { T1_KEYS }).unwrap();
        let short = stalled_private_evpn(48, fresh);
        let long = stalled_private_evpn(192, fresh);
        eprintln!(
            "T1 fresh={fresh}: charged {:?} -> {:?}; retained rows {:?} -> {:?}; unique bytes {} -> {}",
            short.charged, long.charged, short.retained, long.retained, short.bytes, long.bytes
        );
        let pass_bytes = usize::from(T1_STALLED) * pass * std::mem::size_of::<EvpnRibRoute>();
        assert!(
            long.bytes <= short.bytes + pass_bytes,
            "fresh={fresh}: {} bytes at 192 rounds against {} at 48",
            long.bytes,
            short.bytes
        );
        for outcome in [&short, &long] {
            assert!(
                outcome.owing,
                "fresh={fresh}: spent credit leaves the peers owing keys, not dirty"
            );
            for (&charged, &retained) in outcome.charged.iter().zip(&outcome.retained) {
                assert!(
                    charged <= T1_CREDIT + pass,
                    "fresh={fresh}: {charged} rows charged against {T1_CREDIT}"
                );
                assert_eq!(
                    charged, retained,
                    "fresh={fresh}: every queued row is charged"
                );
            }
        }
    }
}

/// T1, diagnostic arm. A stalled private receiver whose local role blocks
/// every new OTC-bearing route gets no wire rows, only RFC 9234 egress
/// diagnostics, which retain full route bodies. Under fresh-key rotation
/// those are charged, so the credit bounds them too. Red without charging
/// diagnostics: the credit stays at zero and every round's diagnostics stay
/// queued.
#[test]
fn stalled_receiver_otc_diagnostics_are_charged_and_bounded() {
    const CREDIT: usize = 64;
    const KEYS: u32 = 16;
    let mut manager = manager().with_outbound_row_credit(CREDIT);
    manager.test_force_ungrouped = true;
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable(), 4096, 0);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 4, 1));
    manager.handle_update(RibUpdate::SetPeerExportContext {
        peer,
        session_id: 0,
        local_role: Some(rustbgpd_wire::BgpRole::Customer),
    });
    let mut rx = up(&mut manager, peer, ipv4_sendable(), 4096, 0);
    send_all(&mut rx);
    let blocked = |index: u32| {
        let mut route = source_route(index);
        AttrSet::edit(&mut route.attributes, |attrs| {
            attrs.push(PathAttribute::OnlyToCustomerPartial(64512));
        });
        route
    };
    for round in 0..64 {
        let announced = (0..KEYS).map(|key| blocked(round * KEYS + key)).collect();
        let withdrawn = if round > 0 {
            (0..KEYS)
                .map(|key| (blocked((round - 1) * KEYS + key).prefix, 0))
                .collect()
        } else {
            vec![]
        };
        routes_received(&mut manager, announced, withdrawn, vec![], vec![]);
        send_all(&mut source);
    }
    let charged = manager.outbound_credit_rows(peer);
    let queued = held(&mut rx);
    let diagnostics: usize = queued.iter().map(|update| update.otc_blocked.len()).sum();
    eprintln!(
        "T1 OTC: charged {charged}, retained rows {}, diagnostics {diagnostics}",
        rows(&queued)
    );
    assert!(diagnostics > 0, "the scenario produces diagnostics");
    assert!(charged > 0, "diagnostics hold credit");
    assert!(
        rows(&queued) <= CREDIT + 2 * usize::try_from(KEYS).unwrap(),
        "{} rows retained against {CREDIT}",
        rows(&queued)
    );
    assert!(manager.owing(peer).is_some() && !manager.dirty_peers.contains(&peer));
}

fn latches(updates: &[OutboundRouteUpdate]) -> std::collections::BTreeSet<usize> {
    updates
        .iter()
        .filter_map(|update| {
            update
                .latch
                .as_ref()
                .map(|latch| Arc::as_ptr(latch) as usize)
        })
        .collect()
}

fn refresh_request(manager: &mut RibManager, peer: PeerId, session_id: u64, family: (Afi, Safi)) {
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer,
        session_id,
        afi: family.0,
        safi: family.1,
        queued: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    });
}

fn force_resync(manager: &mut RibManager, peer: PeerId) {
    let (reply, _response) = oneshot::channel();
    manager.handle_update(RibUpdate::RefreshPeerOutbound { peer, reply });
}

/// T2. A stalled private peer never holds two whole-table operations: its
/// queued initial dump keeps the forced resync and a ROUTE-REFRESH answer
/// waiting, a flap's new session's dump waits for the old session's
/// still-held one, and so does a collision's. Every queued or held
/// envelope carries the same single latch. Once the envelopes drop, the
/// deferred work runs. Red without the latch check: each operation queues
/// its own table.
#[test]
fn a_stalled_peer_holds_one_whole_table_operation_across_flap_and_collision() {
    let mut manager = manager();
    manager.test_force_ungrouped = true;
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable(), 4096, 0);
    routes_received(
        &mut manager,
        (0..32).map(source_route).collect(),
        vec![],
        vec![],
        vec![],
    );
    send_all(&mut source);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 5, 1));
    let mut first = up_session(&mut manager, peer, 1, ipv4_sendable(), 4096, 0);
    let mut kept = held(&mut first);
    force_resync(&mut manager, peer);
    refresh_request(&mut manager, peer, 1, (Afi::Ipv4, Safi::Unicast));
    for _ in 0..4 {
        manager.resync_dirty_peers_bounded();
    }
    kept.extend(held(&mut first));
    // Flap: the old session's dump is still held when the new one registers.
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 1,
    });
    let mut second = up_session(&mut manager, peer, 2, ipv4_sendable(), 4096, 0);
    kept.extend(held(&mut second));
    // Collision: a third session registers over the second.
    let mut third = up_session(&mut manager, peer, 3, ipv4_sendable(), 4096, 0);
    for _ in 0..4 {
        manager.resync_dirty_peers_bounded();
    }
    kept.extend(held(&mut second));
    kept.extend(held(&mut third));
    let live = latches(&kept);
    assert_eq!(live.len(), 1, "{} whole-table operations live", live.len());
    assert!(
        kept.iter()
            .filter(|update| !update.announce.is_empty())
            .count()
            <= 1,
        "one table queued"
    );
    // The sessions send what they held; the deferred dump then runs.
    drop(kept);
    for _ in 0..4 {
        manager.resync_dirty_peers_bounded();
        send_all(&mut third);
    }
    let owed = !manager.dirty_peers.contains(&peer) && !manager.pending_refresh.contains_key(&peer);
    assert!(owed, "the deferred work ran once the operation drained");
    assert_eq!(
        manager.adj_ribs_out[&peer].len(),
        32,
        "the third session holds the whole table"
    );
}

/// T2, owned EVPN (the ROUTE-REFRESH amplifier): a stalled member sending
/// four ROUTE-REFRESH requests gets one complete feed; the other requests
/// leave one owed response. Red without the latch: four full feeds.
#[test]
fn repeated_peer_refresh_for_a_stalled_owned_member_queues_one_feed() {
    use super::evpn_group_storage::{received, register};
    use rustbgpd_wire::{EthernetTagId, EvpnRoute};
    const TABLE: u32 = 200;
    let mut manager = manager();
    let member = PeerId::from_addr(Ipv4Addr::new(192, 0, 2, 30).into());
    let (sender, mut output) = mpsc::channel(4096);
    register(&mut manager, member, sender);
    send_all(&mut output);
    let gid = manager.grouped_member_of(member).unwrap();
    manager
        .group_ribs
        .get_mut(&gid)
        .unwrap()
        .set_evpn_ownership_for_test(true);
    assert!(manager.register_evpn_recovery(member, false));
    let source = peer_v4(SOURCE);
    manager.ribs.insert(source, AdjRibIn::new(source));
    let route = |tag: u32| {
        let mut route = received(1);
        let EvpnRoute::Imet(ref mut imet) = route.route else {
            panic!("IMET fixture");
        };
        imet.ethernet_tag = EthernetTagId(tag);
        imet.originator_ip = IpAddr::V4(SOURCE);
        route.peer = source;
        route.next_hop = IpAddr::V4(SOURCE);
        route
    };
    manager.process_evpn_announce_chunk(source, (0..TABLE).map(route).collect());
    send_all(&mut output);
    let mut queued = Vec::new();
    for _ in 0..4 {
        refresh_request(&mut manager, member, 7, (Afi::L2Vpn, Safi::Evpn));
        queued.extend(held(&mut output));
    }
    let feeds = queued
        .iter()
        .filter(|update| update.evpn_announce.len() >= usize::try_from(TABLE / 2).unwrap())
        .count();
    assert_eq!(feeds, 1, "{feeds} full complete feeds queued");
    assert_eq!(latches(&queued).len(), 1);
    assert!(
        manager.pending_refresh[&member].contains(&(Afi::L2Vpn, Safi::Evpn)),
        "one owed response"
    );
}

/// N1: a held initial dump does not hold back ordinary updates. Its latch
/// gates only another whole-table operation; ordinary envelopes need
/// credit, which the uncharged dump leaves untouched.
#[test]
fn a_live_initial_dump_latch_does_not_block_ordinary_updates() {
    let mut manager = manager();
    manager.test_force_ungrouped = true;
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable(), 4096, 0);
    routes_received(&mut manager, vec![source_route(0)], vec![], vec![], vec![]);
    send_all(&mut source);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 5, 2));
    let mut rx = up(&mut manager, peer, ipv4_sendable(), 4096, 0);
    let dump = held(&mut rx);
    assert_eq!(latches(&dump).len(), 1);
    assert_eq!(
        manager.outbound_credit_rows(peer),
        0,
        "the dump is uncharged"
    );
    routes_received(&mut manager, vec![source_route(1)], vec![], vec![], vec![]);
    let update = held(&mut rx);
    assert_eq!(rows(&update), 1);
    assert!(update[0].latch.is_none() && update[0].credit.is_some());
    assert!(!manager.dirty_peers.contains(&peer));
}

fn v6_source_route(index: u16) -> Route {
    let mut route = make_v6_route(
        Ipv6Prefix::new(Ipv6Addr::new(0x2001, 0xdb8, index, 0, 0, 0, 0, 0), 48),
        "2001:db8:ffff::1".parse().unwrap(),
    );
    route.peer = peer_v4(SOURCE);
    route
}

fn replay_request(
    manager: &mut RibManager,
    peer: PeerId,
    replay: &Arc<rustbgpd_bmp::BmpReplay>,
) -> Result<(), crate::RibCommandError> {
    let (ack, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplayPeerOutbound {
        peer,
        session_id: 0,
        families: dual_stack_sendable(),
        replay: Arc::clone(replay),
        reply: ack,
    });
    response.try_recv().expect("synchronous response")
}

fn dual_stack_replay_fixture(
    capacity: usize,
) -> (RibManager, PeerId, mpsc::Receiver<OutboundRouteUpdate>) {
    let mut manager = manager();
    manager.test_force_ungrouped = true;
    let mut source = up(
        &mut manager,
        peer_v4(SOURCE),
        dual_stack_sendable(),
        4096,
        0,
    );
    routes_received(
        &mut manager,
        vec![source_route(0), v6_source_route(1)],
        vec![],
        vec![],
        vec![],
    );
    send_all(&mut source);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 6, 1));
    let rx = up(&mut manager, peer, dual_stack_sendable(), capacity, 0);
    (manager, peer, rx)
}

/// Refresh debt in several families is answered in one whole-table
/// operation once the live one drains, not one family per cycle. Red with a
/// per-family operation: the first family's answer latches the peer and the
/// second stays owed.
#[test]
fn owed_refreshes_in_several_families_answer_in_one_operation() {
    let (mut manager, peer, mut rx) = dual_stack_replay_fixture(64);
    let dump = held(&mut rx);
    for family in dual_stack_sendable() {
        refresh_request(&mut manager, peer, 0, family);
    }
    assert_eq!(
        manager.pending_refresh[&peer].len(),
        2,
        "deferred behind the dump"
    );
    drop(dump);
    manager.resync_dirty_peers_bounded();
    let answers = held(&mut rx);
    assert!(
        !manager.pending_refresh.contains_key(&peer),
        "both answered"
    );
    assert_eq!(latches(&answers).len(), 1, "in one operation");
    let announced: usize = answers.iter().map(|update| update.announce.len()).sum();
    assert_eq!(announced, 2, "each family's table");
    assert!(!manager.dirty_peers.contains(&peer));
}

/// An IPv4 RR client registering with a running actor.
fn actor_peer_up(peer: PeerId, outbound_tx: mpsc::Sender<OutboundRouteUpdate>) -> RibUpdate {
    RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 200),
        outbound_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    }
}

/// Register the source with a running actor and announce four routes.
async fn actor_source(tx: &mpsc::Sender<RibUpdate>) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (source_tx, source_rx) = mpsc::channel(64);
    tx.send(actor_peer_up(peer_v4(SOURCE), source_tx))
        .await
        .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: (0..4).map(source_route).collect(),
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    source_rx
}

/// Refresh-only retries run under the poll budget: when many latches drop
/// at once, each resync tick answers a bounded round-robin slice and the
/// actor serves ordinary messages between slices, until every owed answer
/// is sent. With a zero budget a tick answers one peer; an owed-state query
/// sent after the first answer is served before the next one is staged.
/// Red with an unbudgeted retry: the first tick answers every peer.
#[tokio::test(start_paused = true)]
async fn released_refresh_debt_is_answered_in_budgeted_slices() {
    const PEERS: u8 = 6;
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = true;
    manager.flush_poll_budget = Duration::ZERO;
    let handle = tokio::spawn(manager.run());
    let _source_rx = actor_source(&tx).await;
    let mut receivers = Vec::new();
    let mut dumps = Vec::new();
    for index in 0..PEERS {
        let peer = peer_v4(Ipv4Addr::new(10, 0, 20, index + 1));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(actor_peer_up(peer, out_tx)).await.unwrap();
        dumps.push(out_rx.recv().await.unwrap());
        dumps.push(out_rx.recv().await.unwrap());
        tx.send(RibUpdate::RouteRefreshRequest {
            peer,
            session_id: 0,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            queued: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        })
        .await
        .unwrap();
        receivers.push((peer, out_rx));
    }
    let owed = |peer| {
        let tx = tx.clone();
        async move {
            let (reply, response) = oneshot::channel();
            tx.send(RibUpdate::TestQueryPeerOutboundOwed { peer, reply })
                .await
                .unwrap();
            response.await.unwrap()
        }
    };
    for (peer, out_rx) in &mut receivers {
        assert!(
            !owed(*peer).await.refresh.is_empty(),
            "{peer} owes its answer"
        );
        assert!(out_rx.try_recv().is_err());
    }
    // Every latch drops at once.
    drop(dumps);
    let answered = loop {
        tokio::time::sleep(Duration::from_millis(1)).await;
        if let Some(index) = receivers.iter().position(|(_, rx)| !rx.is_empty()) {
            break index;
        }
    };
    let waiting = |receivers: &[(PeerId, mpsc::Receiver<OutboundRouteUpdate>)]| {
        receivers.iter().filter(|(_, rx)| rx.is_empty()).count()
    };
    assert_eq!(
        waiting(&receivers),
        usize::from(PEERS) - 1,
        "one peer per slice"
    );
    let other = receivers[(answered + 1) % receivers.len()].0;
    // An ordinary message, served before the next slice is staged.
    assert_eq!(owed(other).await.refresh, vec![(Afi::Ipv4, Safi::Unicast)]);
    assert_eq!(waiting(&receivers), usize::from(PEERS) - 1);
    for (peer, out_rx) in &mut receivers {
        let answer = tokio::time::timeout(Duration::from_secs(1), out_rx.recv())
            .await
            .expect("every owed answer is sent")
            .unwrap();
        assert_eq!(answer.announce.len(), 4, "{peer}");
    }
    for (peer, _) in &receivers {
        let owed = owed(*peer).await;
        assert!(owed.refresh.is_empty() && !owed.resync, "{peer}: {owed:?}");
    }
    drop(tx);
    let _ = handle.await;
}

/// T3. A two-family operator replay is accepted whole or not at all. With
/// room for less than both families and the terminal it is refused with
/// nothing sent; behind a live whole-table operation likewise; with room,
/// both families and then the terminal go out in order. Red with
/// per-family admission: the first family is published before the
/// terminal fails.
#[test]
fn two_family_operator_replay_is_all_or_nothing() {
    // Room for two of the three envelopes.
    let (mut manager, peer, mut rx) = dual_stack_replay_fixture(2);
    send_all(&mut rx);
    let (replay, _enrolled) = rustbgpd_bmp::BmpReplay::new(Duration::from_secs(5));
    assert!(replay_request(&mut manager, peer, &replay).is_err());
    assert!(rx.try_recv().is_err(), "a refused replay sends nothing");
    assert!(!manager.dirty_peers.contains(&peer));

    // Behind the still-held initial dump.
    let (mut manager, peer, mut rx) = dual_stack_replay_fixture(64);
    let dump = held(&mut rx);
    let (replay, _enrolled) = rustbgpd_bmp::BmpReplay::new(Duration::from_secs(5));
    assert!(replay_request(&mut manager, peer, &replay).is_err());
    assert!(rx.try_recv().is_err(), "a refused replay sends nothing");
    drop(dump);

    // With room: IPv4, IPv6, then the terminal.
    let (replay, _enrolled) = rustbgpd_bmp::BmpReplay::new(Duration::from_secs(5));
    assert!(replay_request(&mut manager, peer, &replay).is_ok());
    let sent = send_all(&mut rx);
    assert_eq!(sent.len(), 3);
    assert!(
        sent[0]
            .announce
            .iter()
            .all(|route| matches!(route.prefix, Prefix::V4(_)))
    );
    assert!(
        sent[1]
            .announce
            .iter()
            .all(|route| !matches!(route.prefix, Prefix::V4(_)))
    );
    assert!(sent[2].replay.is_some() && sent[2].announce.is_empty());
    assert_eq!(sent[2].end_of_rib, dual_stack_sendable());
}

/// T3 (acceptance point). The token is checked once, at acceptance: a
/// cancellation while the first family is being published neither stops
/// the second family nor the terminal, so nothing is half-sent. The
/// transport refuses to certify a terminal whose token is no longer valid.
/// Red with the per-family token re-check: IPv4 is published and the
/// replay fails before IPv6.
#[test]
fn replay_cancelled_after_acceptance_publishes_every_family_and_its_terminal() {
    let (mut manager, peer, mut rx) = dual_stack_replay_fixture(64);
    send_all(&mut rx);
    let (replay, _enrolled) = rustbgpd_bmp::BmpReplay::new(Duration::from_secs(5));
    let token = Arc::clone(&replay);
    manager.replacement_readiness_test_hook = Some(Arc::new(move |_| token.cancel()));
    assert!(replay_request(&mut manager, peer, &replay).is_ok());
    manager.replacement_readiness_test_hook = None;
    assert!(!replay.is_valid(), "cancelled during publication");
    let sent = send_all(&mut rx);
    assert_eq!(sent.len(), 3, "both families and the terminal");
    assert!(sent[2].replay.is_some());
}

/// T4. With every ordinary envelope refused (zero credit), whole-table
/// operations and their markers still go and never mark the peer dirty:
/// the initial dump and its End-of-RIB, a ROUTE-REFRESH answer with its
/// RFC 7313 markers, and a forced resync. An ordinary update is refused.
/// Red if latched operations needed credit: the dump is refused and the
/// peer goes dirty.
#[test]
fn whole_table_operations_and_markers_ignore_exhausted_credit() {
    let mut manager = manager().with_outbound_row_credit(0);
    manager.test_force_ungrouped = true;
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable(), 4096, 0);
    routes_received(
        &mut manager,
        (0..4).map(source_route).collect(),
        vec![],
        vec![],
        vec![],
    );
    send_all(&mut source);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 7, 1));
    let mut rx = up(&mut manager, peer, ipv4_sendable(), 4096, 0);
    let dump = send_all(&mut rx);
    assert_eq!(rows(&dump), 4);
    assert!(
        dump.last()
            .unwrap()
            .end_of_rib
            .contains(&(Afi::Ipv4, Safi::Unicast))
    );
    assert!(!manager.dirty_peers.contains(&peer));

    refresh_request(&mut manager, peer, 0, (Afi::Ipv4, Safi::Unicast));
    let answer = send_all(&mut rx);
    assert_eq!(rows(&answer), 4);
    assert!(
        answer
            .iter()
            .any(|update| update.refresh_markers.len() == 2)
    );
    assert!(!manager.dirty_peers.contains(&peer));
    assert!(!manager.pending_refresh.contains_key(&peer));

    force_resync(&mut manager, peer);
    let resync = send_all(&mut rx);
    assert_eq!(rows(&resync), 4);
    assert!(!manager.dirty_peers.contains(&peer));
    assert!(!manager.force_outbound_peers.contains(&peer));

    routes_received(&mut manager, vec![source_route(9)], vec![], vec![], vec![]);
    assert!(
        send_all(&mut rx).is_empty(),
        "an ordinary update needs credit"
    );
    assert!(
        manager.owes(peer, (Afi::Ipv4, Safi::Unicast)) && !manager.dirty_peers.contains(&peer),
        "it is owed, without a resync"
    );
}

/// The family `drive_producers` names `family`.
fn producer_family(family: &str) -> (Afi, Safi) {
    match family {
        "unicast" => (Afi::Ipv4, Safi::Unicast),
        "evpn" => (Afi::L2Vpn, Safi::Evpn),
        "flowspec" => (Afi::Ipv4, Safi::FlowSpec),
        "bgp-ls" => (Afi::BgpLs, Safi::BgpLs),
        "vpn" => (Afi::Ipv4, Safi::MplsVpn),
        "labeled" => (Afi::Ipv4, Safi::LabeledUnicast),
        _ => (Afi::Ipv4, Safi::RtConstrain),
    }
}

/// Drive each private-family producer toward one peer; per family, the
/// peer's staging entries, whether it now owes that family (keys or the
/// whole family), and whether anything was queued for it.
fn drive_producers(credit: usize, rtc: bool) -> Vec<(&'static str, usize, bool, bool)> {
    // RT-Constrain filters VPN and EVPN export, so it runs on its own peer.
    let families = if rtc {
        rtc_sendable()
    } else {
        vec![
            (Afi::Ipv4, Safi::Unicast),
            (Afi::L2Vpn, Safi::Evpn),
            (Afi::Ipv4, Safi::FlowSpec),
            (Afi::BgpLs, Safi::BgpLs),
            (Afi::Ipv4, Safi::MplsVpn),
            (Afi::Ipv4, Safi::LabeledUnicast),
        ]
    };
    let mut manager = manager().with_outbound_row_credit(credit);
    manager.test_force_ungrouped = true;
    let mut source = up(&mut manager, peer_v4(SOURCE), families.clone(), 4096, 0);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 8, 1));
    let mut rx = up(&mut manager, peer, families, 4096, 0);
    send_all(&mut rx);
    send_all(&mut source);
    let source_id = peer_v4(SOURCE);
    let routes = |announced: Vec<Route>, flowspec, evpn| RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source_id,
        announced,
        withdrawn: vec![],
        flowspec_announced: flowspec,
        flowspec_withdrawn: vec![],
        evpn_announced: evpn,
        evpn_withdrawn: vec![],
        validated_with: None,
    };
    let producers: Vec<(&'static str, RibUpdate)> = vec![
        ("unicast", routes(vec![source_route(0)], vec![], vec![])),
        ("evpn", routes(vec![], vec![], vec![evpn_route(1, 0)])),
        (
            "flowspec",
            routes(vec![], vec![make_flowspec_route(SOURCE)], vec![]),
        ),
        (
            "bgp-ls",
            RibUpdate::BgpLsRoutesReceived {
                peer: source_id,
                session_id: 0,
                announced: vec![make_bgpls_route(SOURCE, 1, 100)],
                withdrawn: vec![],
            },
        ),
        (
            "vpn",
            RibUpdate::VpnRoutesReceived {
                peer: source_id,
                session_id: 0,
                announced: vec![make_vpn_rib_route(SOURCE, 1, 100, 100)],
                withdrawn: vec![],
            },
        ),
        (
            "labeled",
            RibUpdate::LabeledRoutesReceived {
                peer: source_id,
                session_id: 0,
                announced: vec![make_labeled_rib_route(SOURCE, 1, 100, 100)],
                withdrawn: vec![],
            },
        ),
        (
            "rtc",
            RibUpdate::RtcRoutesReceived {
                peer: source_id,
                session_id: 0,
                announced: vec![make_rtc_rib_route(SOURCE, 1, 100)],
                withdrawn: vec![],
            },
        ),
    ];
    let mut outcome = Vec::new();
    for (family, update) in producers {
        if rtc != (family == "rtc") {
            continue;
        }
        let before = manager.outbound_stagings(peer);
        manager.handle_update(update);
        drain_route_chunks(&mut manager);
        send_all(&mut source);
        let sent = !send_all(&mut rx).is_empty();
        outcome.push((
            family,
            manager.outbound_stagings(peer) - before,
            manager.owes(peer, producer_family(family)),
            sent,
        ));
        assert!(
            !manager.dirty_peers.contains(&peer),
            "{family}: spent credit owes the family; the peer stays clean"
        );
    }
    outcome
}

/// T5. A private peer with no credit stages nothing in any family's
/// ordinary producer: unicast, EVPN, `FlowSpec`, BGP-LS, VPN, labeled unicast
/// and RT-Constrain each stop before building an envelope and owe the pass
/// instead (keys, or the whole family for `FlowSpec`, BGP-LS and
/// RT-Constrain), leaving the peer clean, where a peer with credit stages
/// and receives each. Red without the gate: every producer stages first.
#[test]
fn producers_stage_nothing_for_a_peer_without_credit() {
    for rtc in [false, true] {
        for (family, stagings, owed, sent) in drive_producers(1 << 20, rtc) {
            assert!(stagings > 0, "{family}: the control peer stages");
            assert!(sent && !owed, "{family}: the control peer receives it");
        }
        for (family, stagings, owed, _) in drive_producers(0, rtc) {
            assert_eq!(
                stagings, 0,
                "{family}: a peer without credit stages nothing"
            );
            assert!(owed, "{family}: the pass is owed");
        }
    }
}

/// A selection release's replay toward a private peer is an ordinary
/// envelope: with the peer's credit spent it stages nothing and leaves the
/// peer dirty, its End-of-RIB still owed; with credit it stages the family
/// and sends the End-of-RIB. Red without the preflight: the replay stages
/// the family before the send is refused.
#[test]
fn a_selection_release_without_credit_stages_nothing() {
    use super::selection_deferral_dirty_rtbh::{connect, manager_with_dormant_waiter};
    const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
    let waiter = Ipv4Addr::new(192, 0, 2, 83);
    let address = Ipv4Addr::new(192, 0, 2, 84);
    let peer = peer_v4(address);
    for spent in [false, true] {
        let mut manager = manager_with_dormant_waiter();
        let _waiter_rx = connect(&mut manager, waiter, 64, true, false);
        assert!(manager.selection_deferred(FAMILY));
        let mut rx = connect(&mut manager, address, 64, false, true);
        assert!(manager.grouped_member_of(peer).is_none(), "private");
        send_all(&mut rx);
        assert!(manager.pending_eor[&peer].contains(&FAMILY), "EoR held");
        let charge = spent.then(|| {
            crate::OutboundCharge::new(
                &manager.outbound_credit_handle(peer),
                manager.outbound_row_credit(),
            )
        });
        let before = manager.outbound_stagings(peer);
        manager.handle_update(RibUpdate::EndOfRib {
            peer: peer_v4(waiter),
            session_id: u64::from(waiter.octets()[3]),
            afi: FAMILY.0,
            safi: FAMILY.1,
        });
        assert!(!manager.selection_deferred(FAMILY), "released");
        let sent = send_all(&mut rx);
        let staged = manager.outbound_stagings(peer) - before;
        if spent {
            assert_eq!(staged, 0, "nothing staged without credit");
            assert!(manager.dirty_peers.contains(&peer));
            assert!(
                manager.pending_eor[&peer].contains(&FAMILY),
                "EoR still owed"
            );
            assert!(sent.iter().all(|update| update.end_of_rib.is_empty()));
        } else {
            assert!(staged > 0, "the release replays the family");
            assert!(
                sent.iter()
                    .any(|update| update.end_of_rib.contains(&FAMILY))
            );
            assert!(!manager.dirty_peers.contains(&peer));
        }
        drop(charge);
    }
}

/// `passes` passes of 1,024 new keys from the source, unicast or EVPN.
fn fresh_passes(manager: &mut RibManager, first: u32, passes: u32, evpn: bool) {
    for pass in first..first + passes {
        let keys = (pass * 1024..(pass + 1) * 1024).collect::<Vec<_>>();
        if evpn {
            let routes = keys.iter().map(|&key| evpn_route(key, 0)).collect();
            routes_received(manager, vec![], vec![], routes, vec![]);
        } else {
            let routes = keys.iter().map(|&key| source_route(key)).collect();
            routes_received(manager, routes, vec![], vec![], vec![]);
        }
    }
}

/// T6. Receivers that lag but drain never go dirty: three cycles of a stall
/// for `k` 1,024-row passes with `k · 1,024` below the credit, each then
/// drained, for private unicast and EVPN. A stall past twice the credit
/// is bounded by it: the receiver owes the rest of the passes (and never
/// goes dirty). Red without the credit check: the long stall stays under
/// the 4,096-envelope bound and owes nothing.
#[test]
fn lagging_receivers_within_credit_never_go_dirty() {
    const CREDIT: usize = 8_192;
    for evpn in [false, true] {
        let families = if evpn {
            evpn_sendable()
        } else {
            ipv4_sendable()
        };
        let run = |stall: u32, cycles: u32| {
            let mut manager = manager().with_outbound_row_credit(CREDIT);
            manager.test_force_ungrouped = true;
            let mut source = up(&mut manager, peer_v4(SOURCE), families.clone(), 4096, 0);
            let mut receivers: Vec<_> = (0..4u8)
                .map(|index| {
                    let peer = peer_v4(Ipv4Addr::new(10, 0, 9, index + 1));
                    let mut rx = up(&mut manager, peer, families.clone(), 4096, 0);
                    send_all(&mut rx);
                    (peer, rx)
                })
                .collect();
            let mut dirty = 0;
            let mut owing = 0;
            let mut next = 0;
            for _ in 0..cycles {
                for _ in 0..stall {
                    fresh_passes(&mut manager, next, 1, evpn);
                    next += 1;
                    send_all(&mut source);
                    dirty += receivers
                        .iter()
                        .filter(|(peer, _)| manager.dirty_peers.contains(peer))
                        .count();
                    owing += receivers
                        .iter()
                        .filter(|(peer, _)| manager.owing(*peer).is_some())
                        .count();
                }
                for (_, rx) in &mut receivers {
                    send_all(rx);
                }
            }
            (dirty, owing)
        };
        let within = u32::try_from(CREDIT / 1024).unwrap() - 1;
        assert_eq!(
            run(within, 3),
            (0, 0),
            "evpn={evpn}: a {within}-pass stall stays clean and owes nothing"
        );
        let past = 2 * u32::try_from(CREDIT / 1024).unwrap() + 1;
        let (dirty, owing) = run(past, 1);
        assert_eq!(
            dirty, 0,
            "evpn={evpn}: a {past}-pass stall never goes dirty"
        );
        assert!(owing > 0, "evpn={evpn}: a {past}-pass stall owes keys");
    }
}

fn evpn_withdrawals(updates: &[OutboundRouteUpdate]) -> usize {
    updates
        .iter()
        .map(|update| update.evpn_withdraw.len())
        .sum()
}

/// T7. A stalled private EVPN peer whose credit is spent still receives the
/// shutdown withdrawals after `BeginClose`, against channel capacity alone,
/// so the session's close drain sends them ahead of its Cease. Without it
/// they are refused. With the channel genuinely full they are refused too:
/// `BeginClose` lifts only the credit. Red without `BeginClose`: the 20
/// withdrawals are refused and the peer goes dirty.
#[test]
fn shutdown_withdrawals_bypass_spent_credit_after_begin_close() {
    let run = |begin_close: bool, fill: bool| {
        let mut manager = manager().with_outbound_row_credit(1 << 20);
        let mut source = up(&mut manager, peer_v4(SOURCE), evpn_sendable(), 4096, 0);
        let peer = peer_v4(Ipv4Addr::new(10, 0, 10, 1));
        let (tx, mut rx) = {
            let rx = up(&mut manager, peer, evpn_sendable(), 64, 0);
            (manager.outbound_peers[&peer].clone(), rx)
        };
        send_all(&mut rx);
        let routes: Vec<_> = (0..20).map(|tag| evpn_route(tag, 0)).collect();
        routes_received(&mut manager, vec![], vec![], routes.clone(), vec![]);
        send_all(&mut source);
        let stalled = held(&mut rx);
        assert_eq!(rows(&stalled), 20);
        manager.outbound_row_credit_override = Some(1);
        if fill {
            while tx.try_send(OutboundRouteUpdate::default()).is_ok() {}
        }
        if begin_close {
            manager.handle_update(RibUpdate::BeginClose);
        }
        for route in &routes {
            routes_received(&mut manager, vec![], vec![], vec![], vec![route.key()]);
        }
        send_all(&mut source);
        let queued = held(&mut rx);
        drop(stalled);
        (
            evpn_withdrawals(&queued),
            manager.dirty_peers.contains(&peer),
            manager.owed_key_count(peer, super::super::outbound_owing::OwedFamily::EVPN),
        )
    };
    assert_eq!(
        run(true, false),
        (20, false, 0),
        "all 20 queued ahead of the close"
    );
    assert_eq!(
        run(false, false),
        (0, false, 20),
        "without BeginClose spent credit leaves them owed, not sent"
    );
    let (queued, dirty, _) = run(true, true);
    assert_eq!(queued, 0, "a full channel still refuses them");
    assert!(dirty);
}

/// T7, Add-Path move. While closing, an envelope whose private rows only
/// withdraw, or announce keys they also withdraw (an RTBH Add-Path move),
/// is admitted against capacity alone; one announcing a key it does not
/// withdraw still needs credit. Red with a withdraw-only closing
/// predicate: the move is refused, and its withdrawal with it.
#[test]
fn closing_admits_withdrawals_and_moves_of_withdrawn_keys() {
    use crate::outbound_credit::PrivateFamilies;
    let private = PrivateFamilies {
        unicast: true,
        vpn: true,
        evpn: true,
    };
    let route = |index: u32, path_id: u32| {
        let mut route = source_route(index);
        route.path_id = path_id;
        route
    };
    let batch = |announce: Vec<Route>, withdraw: Vec<(Prefix, u32)>| {
        let next_hops = vec![None; announce.len()];
        OutboundCommitBatch {
            withdraw,
            ..OutboundCommitBatch::with_unicast(Arc::new(announce), Arc::new(next_hops))
        }
    };
    let moved = route(0, 2);
    let old = (moved.prefix, 1);
    assert!(batch(vec![], vec![old]).closing_admissible(private));
    assert!(
        batch(vec![moved.clone()], vec![old]).closing_admissible(private),
        "an Add-Path move of a withdrawn key"
    );
    assert!(
        !batch(vec![moved, route(1, 1)], vec![old]).closing_admissible(private),
        "a new key still needs credit"
    );
    let evpn = OutboundCommitBatch {
        evpn_announce: Arc::new(vec![evpn_route(1, 1)]),
        evpn_withdraw: vec![evpn_route(1, 0).key()],
        ..OutboundCommitBatch::default()
    };
    assert!(evpn.closing_admissible(private));
}

/// T10. Chunks preserve the envelope's exact order. 513 prefixes each hold
/// an RTBH Add-Path row and an ordinary row; the blackholing rows lead, so
/// no cut can keep every prefix in one chunk: rows are cut at R in phase
/// order, a prefix may span two chunks, each chunk's exempt count is its
/// own leading blackholing rows, next hops stay aligned, OTC diagnostics
/// are sized in and ride the first chunk, and one key with more rows than R
/// spans chunks in order. Red: a cut that reorders phases or drops the
/// alignment fails the concatenation.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture checks order, exempt counts, alignment and diagnostics across the cut"
)]
fn chunks_reproduce_the_envelope_order_at_r_rows() {
    let prefixes = 513u32;
    let prefix = |index: u32| make_indexed_route(index + 1, SOURCE).prefix;
    let row = |index: u32, path_id: u32| {
        let mut route = make_indexed_route(index + 1, SOURCE);
        route.path_id = path_id;
        route
    };
    let mut announce: Vec<Route> = (0..prefixes).map(|index| row(index, 1)).collect();
    announce.extend((0..prefixes).map(|index| row(index, 2)));
    let next_hop: Vec<Option<rustbgpd_policy::NextHopAction>> = (0..2 * prefixes)
        .map(|index| (index < prefixes).then_some(rustbgpd_policy::NextHopAction::Self_))
        .collect();
    let withdraw: Vec<(Prefix, u32)> = (0..300)
        .map(|index| (prefix(prefixes + index), 7))
        .collect();
    let evpn_withdraw: Vec<_> = (0..10).map(|tag| evpn_route(tag, 0).key()).collect();
    let otc_blocked: Vec<Route> = (0..5).map(|index| row(2_000 + index, 0)).collect();
    let update = OutboundRouteUpdate {
        announce: Arc::new(announce.clone()),
        next_hop_override: Arc::new(next_hop.clone()),
        exempt_announce: usize::try_from(prefixes).unwrap(),
        withdraw: withdraw.clone(),
        evpn_withdraw: evpn_withdraw.clone(),
        otc_blocked: otc_blocked.clone(),
        ..OutboundRouteUpdate::default()
    };
    assert!(crate::outbound_credit::chunkable(&update));
    let plan = chunk_plan(&update, CHUNK_ROWS);
    assert_eq!(plan, vec![1024, 1026 + 300 + 10 + 5 - 1024]);
    let chunks = split_by_plan(update, &plan);
    assert_eq!(chunks.len(), 2);
    for (chunk, &rows_in) in chunks.iter().zip(&plan) {
        assert_eq!(rows(std::slice::from_ref(chunk)), rows_in);
        assert_eq!(chunk.next_hop_override.len(), chunk.announce.len());
        for (route, action) in chunk.announce.iter().zip(chunk.next_hop_override.iter()) {
            assert_eq!(
                action.is_some(),
                route.path_id == 1,
                "next hop follows its row"
            );
        }
        let leading = chunk
            .announce
            .iter()
            .take_while(|route| route.path_id == 1)
            .count();
        assert_eq!(chunk.exempt_announce, leading);
        assert!(
            chunk.announce[leading..]
                .iter()
                .all(|route| route.path_id == 2)
        );
    }
    assert_eq!(
        chunks[0]
            .otc_blocked
            .iter()
            .map(|route| route.prefix)
            .collect::<Vec<_>>(),
        otc_blocked
            .iter()
            .map(|route| route.prefix)
            .collect::<Vec<_>>()
    );
    assert!(chunks[1].otc_blocked.is_empty());
    assert_eq!(chunks[0].withdraw, withdraw, "unicast withdrawals go first");
    let concatenated: Vec<_> = chunks
        .iter()
        .flat_map(|chunk| {
            chunk
                .announce
                .iter()
                .map(|route| (route.prefix, route.path_id))
        })
        .collect();
    let original: Vec<_> = announce
        .iter()
        .map(|route| (route.prefix, route.path_id))
        .collect();
    assert_eq!(concatenated, original);
    assert_eq!(
        chunks[0].exempt_announce + chunks[1].exempt_announce,
        usize::try_from(prefixes).unwrap()
    );
    let spanning = chunks[0]
        .announce
        .iter()
        .filter(|route| {
            chunks[1]
                .announce
                .iter()
                .any(|later| later.prefix == route.prefix)
        })
        .count();
    assert!(spanning > 0, "a prefix spans the two chunks, in order");
    assert_eq!(chunks[1].evpn_withdraw, evpn_withdraw);

    // Send-all: one key with more than R rows.
    let wide: Vec<Route> = (0..1500).map(|path_id| row(0, path_id + 1)).collect();
    let update = OutboundRouteUpdate {
        announce: Arc::new(wide.clone()),
        ..OutboundRouteUpdate::default()
    };
    let plan = chunk_plan(&update, CHUNK_ROWS);
    assert_eq!(plan, vec![1024, 476]);
    let chunks = split_by_plan(update, &plan);
    let concatenated: Vec<_> = chunks
        .iter()
        .flat_map(|chunk| chunk.announce.iter().map(|route| route.path_id))
        .collect();
    assert_eq!(
        concatenated,
        wide.iter().map(|route| route.path_id).collect::<Vec<_>>()
    );
}

/// T10, through the commit ladder: a 3,000-route pass toward a private peer
/// leaves as R-row envelopes, each charged its own rows, committed once.
#[test]
fn a_large_private_pass_leaves_as_charged_r_row_chunks() {
    let mut manager = manager();
    manager.test_force_ungrouped = true;
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable(), 4096, 0);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 11, 1));
    let mut rx = up(&mut manager, peer, ipv4_sendable(), 4096, 0);
    send_all(&mut rx);
    let commits = manager.adj_rib_out_commit_stats.successful_enqueues;
    routes_received(
        &mut manager,
        (0..3000).map(source_route).collect(),
        vec![],
        vec![],
        vec![],
    );
    send_all(&mut source);
    let chunks = held(&mut rx);
    let sizes: Vec<_> = chunks
        .iter()
        .map(|chunk| rows(std::slice::from_ref(chunk)))
        .collect();
    assert!(sizes.iter().all(|&size| size <= CHUNK_ROWS), "{sizes:?}");
    assert_eq!(sizes.iter().sum::<usize>(), 3000);
    assert!(chunks.len() > 1, "{sizes:?}");
    for chunk in &chunks {
        assert_eq!(
            chunk.credit.as_ref().map(crate::OutboundCharge::rows),
            Some(rows(std::slice::from_ref(chunk)))
        );
    }
    assert_eq!(manager.outbound_credit_rows(peer), 3000);
    drop(chunks);
    assert_eq!(manager.outbound_credit_rows(peer), 0);
    assert!(manager.adj_rib_out_commit_stats.successful_enqueues > commits);
}

/// T11. Every release path returns the credit to zero: a session that sends
/// its envelopes, a channel dropped with envelopes queued, envelopes of an
/// ended session held across a flap and then dropped, and a superseded
/// collision session's. No path releases twice (debug builds assert it).
#[test]
fn every_release_path_returns_the_credit_to_zero() {
    let mut manager = manager();
    manager.test_force_ungrouped = true;
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable(), 4096, 0);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 12, 1));
    let mut first = up_session(&mut manager, peer, 1, ipv4_sendable(), 4096, 0);
    send_all(&mut first);
    let mut next = 0;
    let mut churn = |manager: &mut RibManager, source: &mut mpsc::Receiver<OutboundRouteUpdate>| {
        routes_received(
            manager,
            (next..next + 8).map(source_route).collect(),
            vec![],
            vec![],
            vec![],
        );
        next += 8;
        send_all(source);
    };
    churn(&mut manager, &mut source);
    assert_eq!(manager.outbound_credit_rows(peer), 8);
    send_all(&mut first);
    assert_eq!(manager.outbound_credit_rows(peer), 0, "sent");

    churn(&mut manager, &mut source);
    let kept = held(&mut first);
    assert_eq!(manager.outbound_credit_rows(peer), 8);
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 1,
    });
    let mut second = up_session(&mut manager, peer, 2, ipv4_sendable(), 4096, 0);
    assert_eq!(
        manager.outbound_credit_rows(peer),
        8,
        "the ended session's envelopes still count"
    );
    drop(kept);
    drop(first);
    assert_eq!(
        manager.outbound_credit_rows(peer),
        0,
        "dropped after a flap"
    );

    send_all(&mut second);
    churn(&mut manager, &mut source);
    let _third = up_session(&mut manager, peer, 3, ipv4_sendable(), 4096, 0);
    assert_eq!(
        manager.outbound_credit_rows(peer),
        8,
        "superseded, still queued"
    );
    drop(second);
    assert_eq!(
        manager.outbound_credit_rows(peer),
        0,
        "the superseded channel dropped with its queue"
    );
}

/// M4. The per-peer credit divides `D` among every registered outbound
/// peer, read at each admission with no override: a peer that filled its
/// credit before more peers registered keeps the excess until its envelopes
/// drop and is refused meanwhile; a deregistered peer's retained envelopes
/// still count when it returns.
#[test]
fn row_credit_follows_the_registered_peer_count() {
    use crate::outbound_credit::{
        DAEMON_ROW_CREDIT, MAX_ROW_CREDIT, MIN_ROW_CREDIT, row_credit_for,
    };
    assert_eq!(row_credit_for(1), MAX_ROW_CREDIT);
    assert_eq!(row_credit_for(16), MAX_ROW_CREDIT);
    assert_eq!(row_credit_for(17), DAEMON_ROW_CREDIT / 17);
    assert_eq!(row_credit_for(2048), MIN_ROW_CREDIT);
    assert_eq!(row_credit_for(10_000), MIN_ROW_CREDIT);

    let mut manager = manager();
    // Sizing under test: no credit override.
    manager.outbound_row_credit_override = None;
    manager.test_force_ungrouped = true;
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable(), 4096, 0);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 13, 1));
    let mut rx = up_session(&mut manager, peer, 1, ipv4_sendable(), 4096, 0);
    send_all(&mut rx);
    assert_eq!(manager.outbound_row_credit(), row_credit_for(2));
    // The peer fills the larger credit it had with two registered peers.
    let filled = crate::OutboundCharge::new(
        &manager.outbound_credit_handle(peer),
        row_credit_for(20) + 1,
    );
    let _others: Vec<_> = (0..18u8)
        .map(|index| {
            up(
                &mut manager,
                peer_v4(Ipv4Addr::new(10, 0, 14, index + 1)),
                ipv4_sendable(),
                4096,
                0,
            )
        })
        .collect();
    assert_eq!(manager.outbound_row_credit(), row_credit_for(20));
    routes_received(&mut manager, vec![source_route(0)], vec![], vec![], vec![]);
    send_all(&mut source);
    assert!(
        send_all(&mut rx).is_empty(),
        "the retained excess refuses it"
    );
    assert!(
        manager.owing(peer).is_some() && !manager.dirty_peers.contains(&peer),
        "it is owed"
    );

    // Deregistered with the charge retained: it still counts on return.
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 1,
    });
    assert_eq!(manager.outbound_row_credit(), row_credit_for(19));
    let mut rx = up_session(&mut manager, peer, 2, ipv4_sendable(), 4096, 0);
    send_all(&mut rx);
    assert!(manager.outbound_credit_rows(peer) > manager.outbound_row_credit());
    routes_received(&mut manager, vec![source_route(1)], vec![], vec![], vec![]);
    send_all(&mut source);
    assert!(send_all(&mut rx).is_empty(), "still over the credit");
    drop(filled);
    assert_eq!(manager.outbound_credit_rows(peer), 0);
    manager.resync_dirty_peers_bounded();
    assert!(
        !send_all(&mut rx).is_empty(),
        "the owed key is sent once the excess drops"
    );
    routes_received(&mut manager, vec![source_route(2)], vec![], vec![], vec![]);
    send_all(&mut source);
    assert!(
        !send_all(&mut rx).is_empty(),
        "admitted once the excess drops"
    );
}

/// Membership changes after registration do not move the credit: grouped
/// peers count from registration, so a grouped peer that a policy
/// replacement or slow-peer isolation makes private is held to the same
/// fleet limit and refused at it, while grouped members still stream. Red
/// with the credit divided among private peers only: the two newly private
/// peers get the 1M-row ceiling and are admitted.
#[test]
fn peers_that_become_private_are_held_to_the_fleet_credit() {
    use crate::outbound_credit::row_credit_for;
    let mut manager = manager();
    // Sizing under test: no credit override.
    manager.outbound_row_credit_override = None;
    let mut source = peer_up_v4(&mut manager, peer_v4(SOURCE), 4096);
    let mut peers: Vec<_> = (0..40u8)
        .map(|index| {
            let peer = peer_v4(Ipv4Addr::new(10, 0, 18, index + 1));
            (peer, peer_up_v4(&mut manager, peer, 4096))
        })
        .collect();
    let fleet = row_credit_for(41);
    assert_eq!(manager.outbound_row_credit(), fleet, "default sizing");
    let (moved, slow) = (peers[0].0, peers[1].0);
    assert!(manager.grouped_member_of(moved).is_some());
    assert!(manager.grouped_member_of(slow).is_some());
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPolicy {
        peer: moved,
        export_policy: Some(super::update_groups_oracle::peer_context_permit_chain()),
        reply,
    });
    result.try_recv().unwrap().unwrap();
    manager.handle_update(RibUpdate::PeerSlowState {
        peer: slow,
        session_id: 0,
        slow: true,
    });
    assert!(
        manager.grouped_member_of(moved).is_none(),
        "policy made it private"
    );
    assert!(
        manager.grouped_member_of(slow).is_none(),
        "isolation made it private"
    );
    assert_eq!(
        manager.outbound_row_credit(),
        fleet,
        "the count did not move"
    );
    for (_, rx) in &mut peers {
        send_all(rx);
    }
    let held_charges = [moved, slow]
        .map(|peer| crate::OutboundCharge::new(&manager.outbound_credit_handle(peer), fleet));
    routes_received(&mut manager, vec![source_route(0)], vec![], vec![], vec![]);
    send_all(&mut source);
    for (index, peer) in [moved, slow].into_iter().enumerate() {
        assert!(
            send_all(&mut peers[index].1).is_empty(),
            "{peer} refused at the fleet credit"
        );
        assert!(manager.owing(peer).is_some(), "{peer} owes the key");
    }
    assert!(
        !send_all(&mut peers[2].1).is_empty(),
        "a grouped peer streams"
    );
    drop(held_charges);
}

/// A grouped peer's OTC egress diagnostics are charged rows, and grouped
/// peers are in the credit's divisor, so diagnostic-only traffic to a
/// grouped fleet is held to the same daemon-wide sum: a grouped customer at
/// the fleet credit is refused its diagnostic, the others are charged one
/// row each. Red with the credit divided among private peers only: no peer
/// is private, the credit is the 1M-row ceiling and the full one is admitted.
#[test]
fn grouped_otc_diagnostics_are_charged_against_the_fleet_credit() {
    use crate::outbound_credit::row_credit_for;
    let mut manager = manager();
    // Sizing under test: no credit override.
    manager.outbound_row_credit_override = None;
    let mut source = peer_up_v4(&mut manager, peer_v4(SOURCE), 4096);
    let peers: Vec<_> = (0..40u8)
        .map(|index| peer_v4(Ipv4Addr::new(10, 0, 19, index + 1)))
        .collect();
    let mut receivers: Vec<_> = peers
        .iter()
        .map(|&peer| {
            manager.handle_update(RibUpdate::SetPeerExportContext {
                peer,
                session_id: 0,
                local_role: Some(rustbgpd_wire::BgpRole::Customer),
            });
            peer_up_v4(&mut manager, peer, 4096)
        })
        .collect();
    assert!(
        peers
            .iter()
            .all(|peer| manager.grouped_member_of(*peer).is_some())
    );
    let fleet = row_credit_for(41);
    assert_eq!(manager.outbound_row_credit(), fleet);
    let full = peers[0];
    let held_charge = crate::OutboundCharge::new(&manager.outbound_credit_handle(full), fleet);
    let mut route = source_route(0);
    AttrSet::edit(&mut route.attributes, |attrs| {
        attrs.push(PathAttribute::OnlyToCustomerPartial(64512));
    });
    routes_received(&mut manager, vec![route], vec![], vec![], vec![]);
    send_all(&mut source);
    assert!(
        held(&mut receivers[0]).is_empty(),
        "refused at the fleet credit"
    );
    assert!(manager.dirty_peers.contains(&full));
    for (peer, rx) in peers.iter().zip(&mut receivers).skip(1) {
        let queued = held(rx);
        assert_eq!(rows(&queued), 1, "{peer}: one diagnostic, no wire row");
        assert_eq!(
            queued
                .iter()
                .map(|update| update.otc_blocked.len())
                .sum::<usize>(),
            1
        );
        assert_eq!(manager.outbound_credit_rows(*peer), 1, "{peer}: charged");
    }
    drop(held_charge);
}

/// M5. Sharing deduplicates one batch, not a group's history: members that
/// stall one after the other each pin their own window of distinct batches,
/// and together they pin the union. A 4-member group with 16-slot
/// channels: A stalls for 16 batches and goes dirty, then B stalls for the
/// next 16.
#[test]
fn staggered_stalled_members_pin_the_union_of_their_windows() {
    let mut manager = manager();
    let mut source = peer_up_v4(&mut manager, peer_v4(SOURCE), 4096);
    let mut members: Vec<_> = (0..4u8)
        .map(|index| {
            let peer = peer_v4(Ipv4Addr::new(10, 0, 15, index + 1));
            (peer, peer_up_v4(&mut manager, peer, 16))
        })
        .collect();
    for batch in 0..32u32 {
        let announced = (0..4).map(|i| source_route(batch * 4 + i)).collect();
        let withdrawn = if batch == 0 {
            vec![]
        } else {
            (0..4)
                .map(|i| (source_route((batch - 1) * 4 + i).prefix, 0))
                .collect()
        };
        routes_received(&mut manager, announced, withdrawn, vec![], vec![]);
        send_all(&mut source);
        for (index, (_, rx)) in members.iter_mut().enumerate() {
            let stalled_now = index == 0 || (index == 1 && batch >= 16);
            if !stalled_now {
                send_all(rx);
            }
        }
    }
    let shared = |updates: &[OutboundRouteUpdate]| -> std::collections::BTreeSet<usize> {
        updates
            .iter()
            .filter(|update| !update.shared_withdraw.is_empty())
            .map(|update| Arc::as_ptr(&update.shared_withdraw) as usize)
            .collect()
    };
    let stalled = [held(&mut members[0].1), held(&mut members[1].1)];
    assert!(
        manager.dirty_peers.contains(&members[0].0),
        "A went dirty at its window"
    );
    let a = shared(&stalled[0]);
    let b = shared(&stalled[1]);
    assert!(!a.is_empty() && !b.is_empty());
    assert!(a.is_disjoint(&b), "different batches are not shared");
    let all: Vec<_> = stalled.into_iter().flatten().collect();
    assert_eq!(
        shared(&all).len(),
        a.len() + b.len(),
        "the union of the windows"
    );
}

/// M1. A resync that owes a ROUTE-REFRESH answer sends it inside its own
/// operation, while the resync's envelope is still held, without marking
/// the peer dirty again. With room for the resync alone (LAN-2858's
/// one-slot shape) the answer stays refresh-only debt: the peer is not
/// re-dirtied, and the resync tick answers once the operation drains. Red
/// with the old refusal path (re-mark dirty): every tick resends the table
/// and the answer never goes.
#[test]
fn a_resync_answers_its_owed_refresh_without_redirtying() {
    let family = (Afi::Ipv4, Safi::Unicast);
    for capacity in [64, 1] {
        let mut manager = manager();
        manager.test_force_ungrouped = true;
        let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable(), 4096, 0);
        routes_received(&mut manager, vec![source_route(0)], vec![], vec![], vec![]);
        send_all(&mut source);
        let peer = peer_v4(Ipv4Addr::new(10, 0, 16, 1));
        let mut rx = up(&mut manager, peer, ipv4_sendable(), capacity, 0);
        send_all(&mut rx);
        manager
            .pending_refresh
            .entry(peer)
            .or_default()
            .insert(family);
        manager.mark_outbound_dirty(peer);
        // The next pass resyncs the dirty peer, with a diff to send.
        routes_received(&mut manager, vec![source_route(1)], vec![], vec![], vec![]);
        send_all(&mut source);
        let first = held(&mut rx);
        assert!(!manager.dirty_peers.contains(&peer), "capacity {capacity}");
        if capacity > 1 {
            assert_eq!(first.len(), 2, "the resync and the answer");
            assert_eq!(first[1].refresh_markers.len(), 2);
            assert_eq!(latches(&first).len(), 1, "one operation");
            assert!(!manager.pending_refresh.contains_key(&peer));
            continue;
        }
        assert_eq!(first.len(), 1, "the resync took the only slot");
        assert!(manager.pending_refresh[&peer].contains(&family));
        assert!(manager.resync_tick_pending());
        manager.resync_dirty_peers_bounded();
        assert!(
            rx.try_recv().is_err(),
            "the answer waits for the live operation"
        );
        assert!(!manager.dirty_peers.contains(&peer));
        drop(first);
        manager.resync_dirty_peers_bounded();
        let answer = send_all(&mut rx);
        assert_eq!(answer.len(), 1);
        assert_eq!(answer[0].refresh_markers.len(), 2);
        assert!(!manager.pending_refresh.contains_key(&peer));
        assert!(!manager.dirty_peers.contains(&peer));
    }
}

/// A whole-table operation deferred behind a live one runs within the
/// backlog cadence once the live one's envelopes drop, not at the next
/// one-second resync tick: a forced resync requested while the initial
/// dump is still held arrives within 50 ms of the session sending the dump.
/// Red without the latch's release wake: it waits for the full interval.
#[tokio::test(start_paused = true)]
async fn deferred_whole_table_work_runs_soon_after_the_latch_drops() {
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = true;
    let handle = tokio::spawn(manager.run());
    let _source_rx = actor_source(&tx).await;
    let peer = peer_v4(Ipv4Addr::new(10, 0, 17, 1));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(actor_peer_up(peer, out_tx)).await.unwrap();
    let table = out_rx.recv().await.unwrap();
    let eor = out_rx.recv().await.unwrap();
    assert!(table.latch.is_some() && eor.end_of_rib.len() == 1);
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::RefreshPeerOutbound { peer, reply })
        .await
        .unwrap();
    let _ = response.await;
    assert!(out_rx.try_recv().is_err(), "deferred behind the held dump");
    drop((table, eor));
    let resync = tokio::time::timeout(Duration::from_millis(50), out_rx.recv())
        .await
        .expect("the deferred resync runs at the backlog cadence")
        .unwrap();
    assert_eq!(resync.announce.len(), 4);
    drop(tx);
    let _ = handle.await;
}

/// A pass that changes nothing for a peer does not re-dirty it for spent
/// credit while the whole-table operation that already covers it is live:
/// the producer stages, finds no rows for the peer, and admits nothing,
/// instead of a second resync behind the first. Here the peer's refresh
/// answer is queued and a route from the peer itself, never sent back to
/// it, makes the pass. Red with the preflight refusing on credit alone: the
/// peer is dirty after a pass it had nothing to receive from.
#[test]
fn an_empty_pass_behind_a_live_operation_does_not_redirty_the_peer() {
    let family = (Afi::Ipv4, Safi::Unicast);
    let mut manager = manager();
    manager.test_force_ungrouped = true;
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable(), 4096, 0);
    routes_received(&mut manager, vec![source_route(0)], vec![], vec![], vec![]);
    send_all(&mut source);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 21, 1));
    let mut rx = up(&mut manager, peer, ipv4_sendable(), 4096, 0);
    send_all(&mut rx);
    refresh_request(&mut manager, peer, 0, family);
    let answer = held(&mut rx);
    assert_eq!(latches(&answer).len(), 1, "the answer is live");
    let spent = crate::OutboundCharge::new(
        &manager.outbound_credit_handle(peer),
        manager.outbound_row_credit(),
    );
    let mut own = source_route(7);
    own.peer = peer;
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![own],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    assert!(
        send_all(&mut source)
            .iter()
            .any(|update| !update.announce.is_empty()),
        "the pass ran"
    );
    assert!(send_all(&mut rx).is_empty(), "nothing for the peer itself");
    assert!(!manager.dirty_peers.contains(&peer), "no second resync");
    drop((answer, spent));
}

/// A dirty private receiver whose resync is admitted behind its stalled
/// envelopes keeps its live operation and its spent credit. Later passes
/// must not stage its rows only to refuse them: the preflight bypass for a
/// live operation is for clean peers. Five EVPN passes stage it once. Red
/// with the bypass also covering dirty peers: every pass stages.
#[test]
fn a_dirty_peer_behind_its_resync_is_not_restaged_every_pass() {
    const CREDIT: usize = 8;
    let mut manager = manager().with_outbound_row_credit(CREDIT);
    let mut source = up(&mut manager, peer_v4(SOURCE), evpn_sendable(), 4096, 0);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 50, 1));
    let mut rx = up(&mut manager, peer, evpn_sendable(), 4096, 0);
    send_all(&mut rx);
    let mut kept = Vec::new();
    let mut round = 0;
    let mut pass = |manager: &mut RibManager, kept: &mut Vec<_>, round: &mut u32| {
        routes_received(
            manager,
            vec![],
            vec![],
            (0..4).map(|key| evpn_route(key, *round)).collect(),
            vec![],
        );
        send_all(&mut source);
        kept.extend(held(&mut rx));
        *round += 1;
    };
    // The stalled envelopes hold the whole credit, and the peer is dirty
    // (spent credit alone now owes keys instead; any other refusal still
    // takes the resync path).
    pass(&mut manager, &mut kept, &mut round);
    let spent = crate::OutboundCharge::new(&manager.outbound_credit_handle(peer), CREDIT);
    manager.mark_outbound_dirty(peer);
    // A pass the dirty peer misses gives its resync a diff to send.
    pass(&mut manager, &mut kept, &mut round);
    manager.resync_dirty_peers_bounded();
    assert!(
        manager.outbound_operation_live(peer),
        "the resync is queued"
    );
    let before = manager.outbound_stagings(peer);
    for _ in 0..5 {
        pass(&mut manager, &mut kept, &mut round);
        // Still dirty behind its resync, or, once it commits, owing.
        assert!(manager.dirty_peers.contains(&peer) || manager.owing(peer).is_some());
    }
    assert!(
        manager.outbound_stagings(peer) - before <= 1,
        "{} stagings over five passes",
        manager.outbound_stagings(peer) - before
    );
    drop((kept, spent));
}

/// Commit refusals counted with `reason`, summed over peers.
fn refusals_for(metrics: &BgpMetrics, reason: &str) -> f64 {
    metrics
        .registry()
        .gather()
        .into_iter()
        .filter(|family| family.name() == "bgp_outbound_commit_refusals_total")
        .flat_map(|family| family.get_metric().to_vec())
        .filter(|metric| {
            metric
                .get_label()
                .iter()
                .any(|label| label.name() == "reason" && label.value() == reason)
        })
        .map(|metric| metric.get_counter().get_value())
        .sum()
}

/// A dirty peer whose resync keeps failing after its operation was
/// reserved (here: no export encoder) stays on the ordinary 1 s retry
/// interval: an abandoned, unsent reservation does not wake the RIB. Red
/// with every latch drop waking it: the resync retries every 10 ms.
#[tokio::test(start_paused = true)]
async fn an_unsent_resync_reservation_keeps_the_ordinary_retry_interval() {
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = true;
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable(), 4096, 0);
    routes_received(&mut manager, vec![source_route(0)], vec![], vec![], vec![]);
    send_all(&mut source);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 51, 1));
    let mut out = up(&mut manager, peer, ipv4_sendable(), 64, 0);
    send_all(&mut out);
    manager.peer_export_encoders.remove(&peer);
    routes_received(&mut manager, vec![source_route(1)], vec![], vec![], vec![]);
    send_all(&mut source);
    assert!(
        manager.dirty_peers.contains(&peer),
        "refused without an encoder"
    );
    let metrics = manager.metrics.clone();
    let refused = refusals_for(&metrics, "missing_encoder");
    let handle = tokio::spawn(manager.run());
    tokio::time::sleep(Duration::from_millis(3500)).await;
    let attempts = refusals_for(&metrics, "missing_encoder") - refused;
    assert!(attempts >= 1.0, "the resync was attempted");
    assert!(attempts <= 5.0, "{attempts} resync attempts in 3.5 s");
    drop(tx);
    let _ = handle.await;
}

/// A ROUTE-REFRESH held by the selection hold is answered at release
/// after the convergence End-of-RIB, so the answer carries none of its own.
/// When a live sibling-family operation defers that answer, the retry keeps
/// the suppression: the peer gets exactly one IPv4 End-of-RIB. Red with the
/// deferred intent saving only the family: the retried answer carries a
/// second End-of-RIB.
#[test]
fn a_deferred_answer_after_the_convergence_eor_sends_no_second_eor() {
    use super::selection_deferral_dirty_rtbh::{connect, manager_with_dormant_waiter};
    const V4: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
    const V6: (Afi, Safi) = (Afi::Ipv6, Safi::Unicast);
    let waiter = Ipv4Addr::new(192, 0, 2, 83);
    let mut manager = manager_with_dormant_waiter();
    let _waiter_rx = connect(&mut manager, waiter, 64, true, false);
    assert!(manager.selection_deferred(V4));
    let peer = peer_v4(Ipv4Addr::new(192, 0, 2, 86));
    let mut rx = up(&mut manager, peer, dual_stack_sendable(), 64, 0);
    let initial = send_all(&mut rx);
    assert!(
        initial
            .iter()
            .all(|update| !update.end_of_rib.contains(&V4)),
        "held"
    );
    // A live IPv6 answer: a whole-table operation the IPv4 answer waits on.
    refresh_request(&mut manager, peer, 0, V6);
    let sibling = held(&mut rx);
    assert_eq!(latches(&sibling).len(), 1);
    refresh_request(&mut manager, peer, 0, V4);
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(waiter),
        session_id: u64::from(waiter.octets()[3]),
        afi: V4.0,
        safi: V4.1,
    });
    assert!(!manager.selection_deferred(V4), "released");
    let mut sent = send_all(&mut rx);
    assert!(
        manager.pending_refresh[&peer].contains(&V4),
        "the IPv4 answer waits for the live operation"
    );
    drop(sibling);
    for _ in 0..4 {
        manager.resync_dirty_peers_bounded();
        sent.extend(send_all(&mut rx));
    }
    assert!(!manager.pending_refresh.contains_key(&peer), "answered");
    let eors = sent
        .iter()
        .filter(|update| update.end_of_rib.contains(&V4))
        .count();
    assert_eq!(eors, 1, "one IPv4 End-of-RIB");
}

/// The latch-release wake also reaches the resync timer while a long route
/// batch keeps the actor busy: work deferred behind a drained operation
/// runs between route chunks within tens of milliseconds, not after the
/// batch. Red with the wake consumed only where the actor waits: the
/// deferred resync waits for the whole batch.
#[tokio::test(start_paused = true)]
async fn deferred_work_runs_soon_after_the_latch_drops_under_ingest() {
    const BATCH: u32 = 100 * 1024;
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = true;
    let handle = tokio::spawn(manager.run());
    let _source_rx = actor_source(&tx).await;
    let peer = peer_v4(Ipv4Addr::new(10, 0, 52, 1));
    let (out_tx, mut out_rx) = mpsc::channel(1 << 16);
    tx.send(actor_peer_up(peer, out_tx)).await.unwrap();
    let dump = (out_rx.recv().await.unwrap(), out_rx.recv().await.unwrap());
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::RefreshPeerOutbound { peer, reply })
        .await
        .unwrap();
    let _ = response.await;
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: (100..100 + BATCH).map(source_route).collect(),
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    // The batch is admitted; its chunks run one per actor turn.
    tokio::task::yield_now().await;
    drop(dump);
    let started = tokio::time::Instant::now();
    loop {
        tokio::time::advance(Duration::from_millis(5)).await;
        tokio::task::yield_now().await;
        if !out_rx.is_empty() {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(2), "never resynced");
    }
    assert!(
        started.elapsed() <= Duration::from_millis(60),
        "the deferred resync ran {:?} after the release",
        started.elapsed()
    );
    drop(tx);
    let _ = handle.await;
}

/// A peer with spent credit is refused, and marked dirty, only by a pass
/// that touches a family it negotiated: an IPv4-only peer stays clean
/// through an IPv6-only change in unicast, `FlowSpec`, labeled unicast and
/// VPN, and the per-family producers stage nothing for it. Red with the preflight ahead
/// of the family check: the unrelated change schedules a resync.
#[test]
fn spent_credit_ignores_a_change_in_a_family_the_peer_lacks() {
    let v6_flowspec = || {
        let mut route = make_flowspec_route(SOURCE);
        route.afi = Afi::Ipv6;
        route
    };
    let v6_labeled = || {
        let mut route = make_labeled_rib_route(SOURCE, 1, 100, 100);
        route.nlri.prefix = Prefix::V6(Ipv6Prefix::new(
            Ipv6Addr::new(0x2001, 0xdb8, 7, 0, 0, 0, 0, 0),
            48,
        ));
        route
    };
    let source_id = peer_v4(SOURCE);
    let cases: Vec<(&str, Safi, RibUpdate)> = vec![
        (
            "unicast",
            Safi::Unicast,
            RibUpdate::RoutesReceived {
                session_id: 0,
                peer: source_id,
                announced: vec![v6_source_route(9)],
                withdrawn: vec![],
                flowspec_announced: vec![],
                flowspec_withdrawn: vec![],
                evpn_announced: vec![],
                evpn_withdrawn: vec![],
                validated_with: None,
            },
        ),
        (
            "flowspec",
            Safi::FlowSpec,
            RibUpdate::RoutesReceived {
                session_id: 0,
                peer: source_id,
                announced: vec![],
                withdrawn: vec![],
                flowspec_announced: vec![v6_flowspec()],
                flowspec_withdrawn: vec![],
                evpn_announced: vec![],
                evpn_withdrawn: vec![],
                validated_with: None,
            },
        ),
        (
            "labeled",
            Safi::LabeledUnicast,
            RibUpdate::LabeledRoutesReceived {
                peer: source_id,
                session_id: 0,
                announced: vec![v6_labeled()],
                withdrawn: vec![],
            },
        ),
        (
            "vpn",
            Safi::MplsVpn,
            RibUpdate::VpnRoutesReceived {
                peer: source_id,
                session_id: 0,
                announced: vec![make_vpn6_rib_route_with_rts(SOURCE, 1, vec![])],
                withdrawn: vec![],
            },
        ),
    ];
    for (name, safi, change) in cases {
        let mut manager = manager().with_outbound_row_credit(4);
        manager.test_force_ungrouped = true;
        let mut source = up(
            &mut manager,
            source_id,
            vec![(Afi::Ipv4, safi), (Afi::Ipv6, safi)],
            4096,
            0,
        );
        let peer = peer_v4(Ipv4Addr::new(10, 0, 53, 1));
        let mut rx = up(&mut manager, peer, vec![(Afi::Ipv4, safi)], 4096, 0);
        send_all(&mut rx);
        send_all(&mut source);
        let spent = crate::OutboundCharge::new(&manager.outbound_credit_handle(peer), 4);
        let stagings = manager.outbound_stagings(peer);
        manager.handle_update(change);
        drain_route_chunks(&mut manager);
        assert!(send_all(&mut rx).is_empty(), "{name}: nothing for the peer");
        assert!(
            !manager.dirty_peers.contains(&peer),
            "{name}: no resync owed"
        );
        // The unicast pass walks its changed prefixes for every peer and
        // finds none the peer negotiated; the other producers skip it.
        if safi != Safi::Unicast {
            assert_eq!(
                manager.outbound_stagings(peer),
                stagings,
                "{name}: nothing staged"
            );
        }
        drop(spent);
    }
}

// ---------------------------------------------------------------------------
// Row accounting, chunking and closing admission, pinned per family.
// ---------------------------------------------------------------------------

/// `n` copies of `item`.
fn copies<T: Clone>(item: &T, n: usize) -> Vec<T> {
    vec![item.clone(); n]
}

/// One route per family, to count rows with.
struct FamilyRows {
    unicast: Route,
    flowspec: FlowSpecRoute,
    bgpls: BgpLsRibRoute,
    labeled: crate::route::LabeledRibRoute,
    rtc: crate::route::RtcRibRoute,
    vpn: VpnRibRoute,
    evpn: EvpnRibRoute,
}

fn family_rows() -> FamilyRows {
    FamilyRows {
        unicast: source_route(0),
        flowspec: crate::test_support::make_flowspec_route(SOURCE),
        bgpls: make_bgpls_route(SOURCE, 1, 100),
        labeled: make_labeled_rib_route(SOURCE, 1, 100, 100),
        rtc: make_rtc_rib_route(SOURCE, 1, 100),
        vpn: make_vpn_rib_route(SOURCE, 1, 100, 100),
        evpn: evpn_route(1, 0),
    }
}

/// An envelope carrying rows in every family, each count distinct, so a
/// wrong operator or a dropped term changes the total.
fn mixed_envelope(rows: &FamilyRows) -> OutboundRouteUpdate {
    let key = (rows.unicast.prefix, 0);
    OutboundRouteUpdate {
        flowspec_announce: copies(&rows.flowspec, 1),
        flowspec_withdraw: copies(&rows.flowspec.selection_key(), 2),
        bgpls_announce: copies(&rows.bgpls, 3),
        bgpls_withdraw: copies(&rows.bgpls.key(), 5),
        labeled_announce: copies(&rows.labeled, 7),
        labeled_withdraw: copies(&rows.labeled.key(), 11),
        rtc_announce: copies(&rows.rtc, 13),
        rtc_withdraw: copies(&rows.rtc.key(), 17),
        otc_blocked: copies(&rows.unicast, 19),
        announce: Arc::new(copies(&rows.unicast, 23)),
        shared_withdraw: Arc::new(copies(&key, 29)),
        withdraw: copies(&key, 31),
        vpn_announce: Arc::new(copies(&rows.vpn, 37)),
        vpn_withdraw: copies(&rows.vpn.key(), 41),
        evpn_announce: Arc::new(copies(&rows.evpn, 43)),
        evpn_withdraw: copies(&rows.evpn.key(), 47),
        ..OutboundRouteUpdate::default()
    }
}

/// An envelope's charge counts every row of its private families, OTC
/// diagnostics included, and none of a family the peer holds in a group.
/// Red with any `+` of the sum turned into `*` or `-`.
#[test]
fn an_envelope_is_charged_its_rows_in_each_private_family() {
    use crate::outbound_credit::PrivateFamilies;
    let update = mixed_envelope(&family_rows());
    let always = 1 + 2 + 3 + 5 + 7 + 11 + 13 + 17 + 19;
    let (unicast, vpn, evpn) = (23 + 29 + 31, 37 + 41, 43 + 47);
    for (private, expected) in [
        (PrivateFamilies::default(), always),
        (
            PrivateFamilies {
                unicast: true,
                vpn: false,
                evpn: false,
            },
            always + unicast,
        ),
        (
            PrivateFamilies {
                unicast: false,
                vpn: true,
                evpn: false,
            },
            always + vpn,
        ),
        (
            PrivateFamilies {
                unicast: false,
                vpn: false,
                evpn: true,
            },
            always + evpn,
        ),
        (
            PrivateFamilies {
                unicast: true,
                vpn: true,
                evpn: true,
            },
            always + unicast + vpn + evpn,
        ),
    ] {
        assert_eq!(private.rows(&update), expected, "{private:?}");
    }
}

/// A batch with rows in every family, each count distinct.
fn mixed_batch(rows: &FamilyRows) -> OutboundCommitBatch {
    let key = (rows.unicast.prefix, 0);
    OutboundCommitBatch {
        flowspec_announce: copies(&rows.flowspec, 1),
        flowspec_withdraw: copies(&rows.flowspec.selection_key(), 2),
        bgpls_announce: copies(&rows.bgpls, 3),
        bgpls_withdraw: copies(&rows.bgpls.key(), 5),
        labeled_announce: copies(&rows.labeled, 7),
        labeled_withdraw: copies(&rows.labeled.key(), 11),
        rtc_announce: copies(&rows.rtc, 13),
        rtc_withdraw: copies(&rows.rtc.key(), 17),
        withdraw: copies(&key, 31),
        vpn_announce: Arc::new(copies(&rows.vpn, 37)),
        vpn_withdraw: copies(&rows.vpn.key(), 41),
        evpn_announce: Arc::new(copies(&rows.evpn, 43)),
        evpn_withdraw: copies(&rows.evpn.key(), 47),
        ..OutboundCommitBatch::with_unicast(
            Arc::new(copies(&rows.unicast, 23)),
            Arc::new(vec![None; 23]),
        )
    }
}

/// The admission count of a batch: every private family's rows plus the
/// peer's pending OTC diagnostics, and none of a family it holds in a group
/// (unicast and owned EVPN here). Red with a `+` turned into `*`, a family
/// test inverted, or a membership test widened to `||`.
#[test]
fn a_batch_counts_the_rows_of_the_families_the_peer_holds_privately() {
    let rows = family_rows();
    let always = 1 + 2 + 3 + 5 + 7 + 11 + 13 + 17;
    let (unicast, vpn, evpn) = (23 + 31, 37 + 41, 43 + 47);
    let manager = manager();
    let private = peer_v4(Ipv4Addr::new(10, 0, 60, 1));
    assert_eq!(
        mixed_batch(&rows).private_rows(&manager, private),
        always + unicast + vpn + evpn
    );
    // Pending OTC diagnostics of the peer are charged rows too.
    let mut manager = manager;
    manager
        .pending_otc_blocked
        .entry(private)
        .or_default()
        .insert((rows.unicast.prefix, 0), rows.unicast.clone());
    assert_eq!(
        mixed_batch(&rows).private_rows(&manager, private),
        always + unicast + vpn + evpn + 1
    );
    // A grouped unicast member that owns its EVPN routes in the group.
    let (manager, member, _gid, _output) = super::evpn_group_storage::fixture();
    assert!(manager.grouped_member_of(member).is_some());
    assert!(manager.evpn_grouped_member_of(member).is_some());
    let vpn_private = manager.vpn_grouped_member_of(member).is_none();
    assert_eq!(
        mixed_batch(&rows).private_rows(&manager, member),
        always + if vpn_private { vpn } else { 0 }
    );
}

/// While closing, a private VPN or EVPN announcement that is not a move is
/// not admitted on capacity alone; a move (the key withdrawn in the same
/// envelope) is, and so is any announcement of a family held in a group.
/// Red with either family's privacy test inverted.
#[test]
fn closing_admits_private_vpn_and_evpn_moves_only() {
    use crate::outbound_credit::PrivateFamilies;
    let rows = family_rows();
    let vpn = PrivateFamilies {
        unicast: false,
        vpn: true,
        evpn: false,
    };
    let evpn = PrivateFamilies {
        unicast: false,
        vpn: false,
        evpn: true,
    };
    let vpn_announcement = OutboundCommitBatch {
        vpn_announce: Arc::new(vec![rows.vpn.clone()]),
        ..OutboundCommitBatch::default()
    };
    assert!(
        !vpn_announcement.closing_admissible(vpn),
        "a private VPN announcement"
    );
    assert!(
        vpn_announcement.closing_admissible(evpn),
        "VPN held in a group"
    );
    let vpn_move = OutboundCommitBatch {
        vpn_announce: Arc::new(vec![rows.vpn.clone()]),
        vpn_withdraw: vec![rows.vpn.key()],
        ..OutboundCommitBatch::default()
    };
    assert!(vpn_move.closing_admissible(vpn), "a private VPN move");
    let evpn_announcement = OutboundCommitBatch {
        evpn_announce: Arc::new(vec![rows.evpn.clone()]),
        ..OutboundCommitBatch::default()
    };
    assert!(
        !evpn_announcement.closing_admissible(evpn),
        "a private EVPN announcement"
    );
    assert!(
        evpn_announcement.closing_admissible(vpn),
        "EVPN held in a group"
    );
    let evpn_move = OutboundCommitBatch {
        evpn_announce: Arc::new(vec![rows.evpn.clone()]),
        evpn_withdraw: vec![rows.evpn.key()],
        ..OutboundCommitBatch::default()
    };
    assert!(evpn_move.closing_admissible(evpn), "a private EVPN move");
}

/// An ordinary envelope is cut into pieces only above `CHUNK_ROWS` rows and
/// only when it carries no marker, request, replay terminal, shared group
/// payload, source exclusion or shared withdrawal, and its next-hop
/// overrides align with its announcements. Red with any condition dropped
/// or the boundary moved.
#[test]
fn only_a_plain_envelope_over_the_chunk_size_is_chunkable() {
    use crate::outbound_credit::chunkable;
    let routes = |n: u32| Arc::new((0..n).map(source_route).collect::<Vec<_>>());
    let rows = u32::try_from(CHUNK_ROWS).unwrap();
    let plain = |n: u32| OutboundRouteUpdate {
        announce: routes(n),
        ..OutboundRouteUpdate::default()
    };
    assert!(chunkable(&plain(rows + 1)), "one row over");
    assert!(!chunkable(&plain(rows)), "exactly one chunk");
    let aligned = OutboundRouteUpdate {
        next_hop_override: Arc::new(vec![None; CHUNK_ROWS + 1]),
        ..plain(rows + 1)
    };
    assert!(chunkable(&aligned), "aligned next-hop overrides");
    let (replay, _enrolled) = rustbgpd_bmp::BmpReplay::new(Duration::from_secs(5));
    let negatives: Vec<(&str, OutboundRouteUpdate)> = vec![
        (
            "End-of-RIB",
            OutboundRouteUpdate {
                end_of_rib: vec![(Afi::Ipv4, Safi::Unicast)],
                ..plain(rows + 1)
            },
        ),
        (
            "refresh marker",
            OutboundRouteUpdate {
                refresh_markers: vec![(
                    Afi::Ipv4,
                    Safi::Unicast,
                    rustbgpd_wire::RouteRefreshSubtype::BoRR,
                )],
                ..plain(rows + 1)
            },
        ),
        (
            "replay terminal",
            OutboundRouteUpdate {
                replay: Some(Arc::clone(&replay)),
                ..plain(rows + 1)
            },
        ),
        (
            "refresh request",
            OutboundRouteUpdate {
                request_refresh_all_negotiated: true,
                ..plain(rows + 1)
            },
        ),
        (
            "shared group encode",
            OutboundRouteUpdate {
                shared_group_encode: Some(Arc::default()),
                ..plain(rows + 1)
            },
        ),
        (
            "source exclusion",
            OutboundRouteUpdate {
                announce_source_exclusion: Some(peer_v4(SOURCE)),
                ..plain(rows + 1)
            },
        ),
        (
            "shared withdrawal",
            OutboundRouteUpdate {
                shared_withdraw: Arc::new(vec![(source_route(0).prefix, 0)]),
                ..plain(rows + 1)
            },
        ),
        (
            "misaligned next-hop overrides",
            OutboundRouteUpdate {
                next_hop_override: Arc::new(vec![None]),
                ..plain(rows + 1)
            },
        ),
    ];
    for (name, update) in negatives {
        assert!(!chunkable(&update), "{name}");
    }
}

/// Every chunk keeps the envelope's export snapshot, or the transport
/// resets the session on a route-bearing chunk without one. Red with the
/// snapshot dropped from the chunks.
#[test]
fn every_chunk_keeps_the_export_snapshot() {
    let update = OutboundRouteUpdate {
        announce: Arc::new((0..3_000).map(source_route).collect()),
        exact_export_snapshot: Some(Arc::new(crate::manager::PermissiveTestExactExport)),
        ..OutboundRouteUpdate::default()
    };
    let plan = chunk_plan(&update, CHUNK_ROWS);
    let chunks = split_by_plan(update, &plan);
    assert_eq!(chunks.len(), 3);
    assert!(
        chunks
            .iter()
            .all(|chunk| chunk.exact_export_snapshot.is_some())
    );
}

/// Deleting a neighbor forgets the credit of every unregistered peer whose
/// envelopes are all gone, and keeps a registered peer's and an
/// unregistered peer's that still holds rows or a live operation; those go
/// at a later deletion once idle. Red with the idle test inverted, either
/// half of it dropped, the registration test narrowed, or no sweep at all.
#[test]
fn deleting_a_neighbor_forgets_only_idle_unregistered_credit() {
    let mut manager = manager();
    manager.test_force_ungrouped = true;
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable(), 4096, 0);
    routes_received(&mut manager, vec![source_route(1)], vec![], vec![], vec![]);
    send_all(&mut source);
    let addr = |octet| peer_v4(Ipv4Addr::new(10, 0, 61, octet));
    let (idle, rows, latched, registered) = (addr(1), addr(2), addr(3), addr(4));
    let mut outputs: Vec<_> = [idle, rows, latched, registered]
        .into_iter()
        .map(|peer| up(&mut manager, peer, ipv4_sendable(), 4096, 0))
        .collect();
    // The latched peer keeps its initial dump: a live operation, no rows.
    let dump = held(&mut outputs[2]);
    assert_eq!(latches(&dump).len(), 1);
    for (index, output) in outputs.iter_mut().enumerate() {
        if index != 2 {
            send_all(output);
        }
    }
    routes_received(&mut manager, vec![source_route(0)], vec![], vec![], vec![]);
    send_all(&mut source);
    let charged = held(&mut outputs[1]);
    for index in [0, 2, 3] {
        send_all(&mut outputs[index]);
    }
    assert!(manager.outbound_credit_rows(rows) > 0);
    assert_eq!(
        manager.outbound_credit_rows(latched),
        0,
        "an operation charges no rows"
    );
    for peer in [idle, rows, latched] {
        manager.handle_update(RibUpdate::PeerDown {
            peer,
            session_id: 0,
        });
    }
    let deleted = addr(9);
    manager.handle_update(RibUpdate::PeerDeleted {
        peer: deleted,
        label: None,
        keep_series: false,
    });
    let kept = |manager: &RibManager, peer| manager.outbound_credit.contains_key(&peer);
    assert!(
        !kept(&manager, idle),
        "an idle unregistered peer is forgotten"
    );
    assert!(kept(&manager, rows), "live rows keep the entry");
    assert!(kept(&manager, latched), "a live operation keeps the entry");
    assert!(
        kept(&manager, registered),
        "a registered peer keeps its entry"
    );
    drop((dump, charged));
    manager.handle_update(RibUpdate::PeerDeleted {
        peer: deleted,
        label: None,
        keep_series: false,
    });
    assert!(
        !kept(&manager, rows) && !kept(&manager, latched),
        "swept once idle"
    );
    assert!(kept(&manager, registered));
}

/// Deferred refresh answers rotate across peers: with a zero poll budget a
/// tick answers one peer, and the next tick resumes after it even when that
/// peer owes again. Red with the cursor ignored: the first peer is answered
/// every tick and the others wait.
#[test]
fn deferred_refresh_retries_rotate_across_peers() {
    let family = (Afi::Ipv4, Safi::Unicast);
    let mut manager = manager();
    manager.test_force_ungrouped = true;
    manager.flush_poll_budget = Duration::ZERO;
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable(), 4096, 0);
    routes_received(&mut manager, vec![source_route(0)], vec![], vec![], vec![]);
    send_all(&mut source);
    let peers: Vec<_> = (1..=3u8)
        .map(|octet| peer_v4(Ipv4Addr::new(10, 0, 70, octet)))
        .collect();
    let mut outputs: Vec<_> = peers
        .iter()
        .map(|&peer| up(&mut manager, peer, ipv4_sendable(), 64, 0))
        .collect();
    let dumps: Vec<_> = outputs.iter_mut().map(held).collect();
    for &peer in &peers {
        refresh_request(&mut manager, peer, 0, family);
    }
    drop(dumps);
    manager.resync_dirty_peers_bounded();
    let first = held(&mut outputs[0]);
    assert!(!first.is_empty(), "the first peer is answered first");
    assert!(
        outputs[1].is_empty() && outputs[2].is_empty(),
        "one per tick"
    );
    // The first peer owes again behind its own answer, then reads it.
    refresh_request(&mut manager, peers[0], 0, family);
    drop(first);
    manager.resync_dirty_peers_bounded();
    assert!(
        !send_all(&mut outputs[1]).is_empty(),
        "the second peer is next"
    );
    assert!(outputs[0].is_empty(), "the first peer waits its turn");
}

/// The test-only owed query reports a resync for a dirty peer and for a
/// forced one. Red with the two conditions joined by `&&`.
#[test]
fn the_owed_query_reports_a_dirty_or_forced_resync() {
    let mut manager = manager();
    let peer = peer_v4(Ipv4Addr::new(10, 0, 71, 1));
    let mut rx = up(&mut manager, peer, ipv4_sendable(), 64, 0);
    send_all(&mut rx);
    let owed = |manager: &mut RibManager| {
        let (reply, mut response) = oneshot::channel();
        manager.handle_update(RibUpdate::TestQueryPeerOutboundOwed { peer, reply });
        response.try_recv().unwrap()
    };
    assert!(!owed(&mut manager).resync);
    manager.mark_outbound_dirty(peer);
    assert!(owed(&mut manager).resync, "dirty");
    manager.dirty_peers.remove(&peer);
    manager.force_outbound_peers.insert(peer);
    assert!(owed(&mut manager).resync, "forced");
}

/// A large pass is cut into chunks when the channel has room for exactly
/// as many envelopes: the first chunk takes the ladder's permit and the
/// rest reserve one each. Red with one permit too many reserved: the pass
/// goes as one envelope.
#[test]
fn a_large_pass_is_chunked_into_exactly_the_room_it_needs() {
    let mut manager = manager();
    manager.test_force_ungrouped = true;
    let mut source = up(&mut manager, peer_v4(SOURCE), ipv4_sendable(), 4096, 0);
    let peer = peer_v4(Ipv4Addr::new(10, 0, 72, 1));
    let mut rx = up(&mut manager, peer, ipv4_sendable(), 3, 0);
    send_all(&mut rx);
    routes_received(
        &mut manager,
        (0..3000).map(source_route).collect(),
        vec![],
        vec![],
        vec![],
    );
    send_all(&mut source);
    let sizes: Vec<_> = held(&mut rx)
        .iter()
        .map(|chunk| rows(std::slice::from_ref(chunk)))
        .collect();
    assert_eq!(sizes, vec![1024, 1024, 952]);
}

/// Two dual-stack peers whose IPv4 answers were released after the
/// convergence End-of-RIB and deferred behind a live IPv6 answer each, so
/// both owe an answer that carries no End-of-RIB. Returns the manager, the
/// peers (in address order), their receivers and the live IPv6 answers.
/// The receivers and the live IPv6 answers of each peer.
type PeerChannels = (
    Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    Vec<Vec<OutboundRouteUpdate>>,
);

fn two_peers_owing_suppressed_answers() -> (RibManager, [PeerId; 2], PeerChannels) {
    use super::selection_deferral_dirty_rtbh::{connect, manager_with_dormant_waiter};
    let waiter = Ipv4Addr::new(192, 0, 2, 83);
    let mut manager = manager_with_dormant_waiter();
    let _waiter_rx = connect(&mut manager, waiter, 64, true, false);
    let peers = [87, 88].map(|octet| peer_v4(Ipv4Addr::new(192, 0, 2, octet)));
    let mut outputs: Vec<_> = peers
        .iter()
        .map(|&peer| up(&mut manager, peer, dual_stack_sendable(), 64, 0))
        .collect();
    let mut siblings = Vec::new();
    for (index, &peer) in peers.iter().enumerate() {
        send_all(&mut outputs[index]);
        refresh_request(&mut manager, peer, 0, (Afi::Ipv6, Safi::Unicast));
        siblings.push(held(&mut outputs[index]));
        refresh_request(&mut manager, peer, 0, (Afi::Ipv4, Safi::Unicast));
    }
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(waiter),
        session_id: u64::from(waiter.octets()[3]),
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    });
    for (index, &peer) in peers.iter().enumerate() {
        let sent = send_all(&mut outputs[index]);
        assert_eq!(
            sent.iter()
                .filter(|update| update.end_of_rib.contains(&(Afi::Ipv4, Safi::Unicast)))
                .count(),
            1,
            "the convergence End-of-RIB"
        );
        assert!(
            manager
                .pending_refresh_suppress_eor
                .contains(&(peer, (Afi::Ipv4, Safi::Unicast)))
        );
    }
    (manager, peers, (outputs, siblings))
}

/// IPv4 End-of-RIB markers in `updates`.
fn ipv4_eors(updates: &[OutboundRouteUpdate]) -> usize {
    updates
        .iter()
        .filter(|update| update.end_of_rib.contains(&(Afi::Ipv4, Safi::Unicast)))
        .count()
}

/// Clearing one peer's refresh state at its session's end drops only that
/// peer's End-of-RIB suppression: the other peer's deferred answer still
/// carries no End-of-RIB, and the cleared peer keeps no flag into its next
/// session. Red with the retain inverted.
#[test]
fn a_session_end_clears_only_its_own_suppressed_answer() {
    let (mut manager, [first, second], (mut outputs, siblings)) =
        two_peers_owing_suppressed_answers();
    manager.handle_update(RibUpdate::PeerDown {
        peer: first,
        session_id: 0,
    });
    assert!(
        !manager
            .pending_refresh_suppress_eor
            .iter()
            .any(|(peer, _)| *peer == first),
        "the ended session's flag is gone"
    );
    drop(siblings);
    let mut sent = Vec::new();
    for _ in 0..4 {
        manager.resync_dirty_peers_bounded();
        sent.extend(send_all(&mut outputs[1]));
    }
    assert!(!manager.pending_refresh.contains_key(&second), "answered");
    assert_eq!(ipv4_eors(&sent), 0, "the answer carries no End-of-RIB");
}

/// A retry pass that drops a peer whose channel is gone drops only that
/// peer's End-of-RIB suppression: a live peer answered in the same pass
/// still sends no End-of-RIB. Red with the retain inverted.
#[test]
fn a_gone_channel_clears_only_its_own_suppressed_answer() {
    let (mut manager, [first, second], (mut outputs, siblings)) =
        two_peers_owing_suppressed_answers();
    let gone = outputs.remove(0);
    drop(gone);
    drop(siblings);
    let mut sent = Vec::new();
    for _ in 0..4 {
        manager.resync_dirty_peers_bounded();
        sent.extend(send_all(&mut outputs[0]));
    }
    assert!(
        !manager
            .pending_refresh_suppress_eor
            .iter()
            .any(|(peer, _)| *peer == first),
        "the gone peer's flag is dropped"
    );
    assert!(!manager.pending_refresh.contains_key(&second), "answered");
    assert_eq!(ipv4_eors(&sent), 0, "the answer carries no End-of-RIB");
}

/// Receive envelopes on `rx` until `keys` has yielded every key in
/// `wanted`, within 5,000 turns of 1 ms on the paused clock. The test drives
/// the clock and yields to the actor each turn, so an actor that waits, or
/// one that keeps yielding without delivering, fails here instead of
/// hanging the test.
async fn receive_wanted<K: std::hash::Hash + Eq>(
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    mut wanted: std::collections::HashSet<K>,
    keys: impl Fn(&OutboundRouteUpdate) -> Vec<K>,
) -> bool {
    for _ in 0..5_000 {
        while let Ok(update) = rx.try_recv() {
            for key in keys(&update) {
                wanted.remove(&key);
            }
        }
        if wanted.is_empty() {
            return true;
        }
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
    }
    false
}

fn announced_prefixes(update: &OutboundRouteUpdate) -> Vec<Prefix> {
    update.announce.iter().map(|route| route.prefix).collect()
}

fn other_source_route(other: Ipv4Addr, index: u32) -> Route {
    let mut route = make_indexed_route(index, other);
    route.peer = peer_v4(other);
    route
}

fn received(peer: PeerId, announced: Vec<Route>, evpn_announced: Vec<EvpnRibRoute>) -> RibUpdate {
    RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced,
        evpn_withdrawn: vec![],
        validated_with: None,
    }
}

/// A peer whose session has stopped taking envelopes (its writer held at
/// the byte budget, so its channel stays full) never makes the RIB wait:
/// a healthy peer keeps receiving every later batch, and later input and
/// End-of-RIB from another source are still applied, in order. `evpn` runs
/// the batches through the private EVPN path; `credit` caps every peer's
/// row credit, so the other source, which never reads its own channel,
/// spends its credit and is refused while the rest goes on. Red with any
/// wait on a stalled peer in the actor, such as reserving a slot on every
/// peer's channel before each turn.
async fn assert_held_peer_never_holds_the_rib(evpn: bool, credit: Option<usize>) -> BgpMetrics {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 100)),
        metrics.clone(),
    );
    if let Some(credit) = credit {
        manager = manager.with_outbound_row_credit(credit);
    }
    manager.test_force_ungrouped = true;
    let handle = tokio::spawn(manager.run());
    let families = if evpn {
        [ipv4_sendable(), evpn_sendable()].concat()
    } else {
        ipv4_sendable()
    };
    let up = |peer: Ipv4Addr, outbound| {
        let mut update = actor_peer_up(peer_v4(peer), outbound);
        if let RibUpdate::PeerUp {
            sendable_families, ..
        } = &mut update
        {
            sendable_families.clone_from(&families);
        }
        update
    };
    let (source_tx, _source_rx) = mpsc::channel(1 << 12);
    tx.send(up(SOURCE, source_tx)).await.unwrap();
    let other = Ipv4Addr::new(10, 0, 0, 2);
    let (other_tx, _other_rx) = mpsc::channel(1 << 12);
    tx.send(up(other, other_tx)).await.unwrap();
    // The held peer's channel takes one envelope and is never read.
    let (held_tx, _held_rx) = mpsc::channel(1);
    tx.send(up(Ipv4Addr::new(10, 0, 53, 1), held_tx))
        .await
        .unwrap();
    let (healthy_tx, mut healthy_rx) = mpsc::channel(1 << 12);
    tx.send(up(Ipv4Addr::new(10, 0, 53, 2), healthy_tx))
        .await
        .unwrap();

    for round in 0..8u32 {
        let keys = 100 + round * 16..116 + round * 16;
        let delivered = if evpn {
            let routes: Vec<_> = keys.map(|tag| evpn_route(tag, round)).collect();
            let wanted = routes.iter().map(EvpnRibRoute::key).collect();
            tx.send(received(peer_v4(SOURCE), vec![], routes))
                .await
                .unwrap();
            receive_wanted(&mut healthy_rx, wanted, |update| {
                update.evpn_announce.iter().map(EvpnRibRoute::key).collect()
            })
            .await
        } else {
            let routes: Vec<_> = keys.map(source_route).collect();
            let wanted = routes.iter().map(|route| route.prefix).collect();
            tx.send(received(peer_v4(SOURCE), routes, vec![]))
                .await
                .unwrap();
            receive_wanted(&mut healthy_rx, wanted, announced_prefixes).await
        };
        assert!(
            delivered,
            "round {round}: the healthy peer stalled behind the held one"
        );
    }

    // Another source's input, its End-of-RIB, then more input: all applied.
    let before = other_source_route(other, 5_000);
    let after = other_source_route(other, 5_001);
    let wanted = [before.prefix, after.prefix].into_iter().collect();
    tx.send(received(peer_v4(other), vec![before], vec![]))
        .await
        .unwrap();
    tx.send(RibUpdate::EndOfRib {
        peer: peer_v4(other),
        session_id: 0,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    tx.send(received(peer_v4(other), vec![after], vec![]))
        .await
        .unwrap();
    assert!(
        receive_wanted(&mut healthy_rx, wanted, announced_prefixes).await,
        "input after the other source's End-of-RIB was not applied"
    );
    drop(tx);
    let _ = handle.await;
    metrics
}

/// The other source of [`assert_held_peer_never_holds_the_rib`] reads none
/// of its updates, so with a small credit it is refused.
fn assert_other_source_refused(metrics: &BgpMetrics) {
    let refused = counter_metric_value(
        metrics,
        "bgp_outbound_commit_refusals_total",
        &[
            ("peer", &peer_v4(Ipv4Addr::new(10, 0, 0, 2)).label()),
            ("reason", "outbound_credit"),
        ],
    );
    assert!(refused > 0.0, "the other source's credit was spent");
}

#[tokio::test(start_paused = true)]
async fn a_peer_held_by_its_writer_never_holds_the_rib_or_a_healthy_peer() {
    assert_held_peer_never_holds_the_rib(false, None).await;
}

#[tokio::test(start_paused = true)]
async fn a_held_peer_with_spent_credit_never_holds_the_rib() {
    assert_other_source_refused(&assert_held_peer_never_holds_the_rib(false, Some(4)).await);
}

#[tokio::test(start_paused = true)]
async fn a_held_private_evpn_peer_never_holds_the_rib() {
    assert_held_peer_never_holds_the_rib(true, None).await;
    assert_other_source_refused(&assert_held_peer_never_holds_the_rib(true, Some(4)).await);
}
