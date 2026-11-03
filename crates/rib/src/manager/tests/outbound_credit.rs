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
    dirty: bool,
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
        dirty: true,
    };
    let mut all = Vec::new();
    for (peer, rx) in &mut stalled {
        outcome.charged.push(manager.outbound_credit_rows(*peer));
        let queued = held(rx);
        outcome.retained.push(rows(&queued));
        outcome.dirty &= manager.dirty_peers.contains(peer);
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
                outcome.dirty,
                "fresh={fresh}: credit refusals leave the peers dirty"
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
    assert!(manager.dirty_peers.contains(&peer));
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
    assert!(manager.dirty_peers.contains(&peer));
}

/// `bgp_outbound_commit_refusals_total{reason="outbound_credit"}`, summed.
fn credit_refusals(manager: &RibManager) -> f64 {
    manager
        .metrics
        .registry()
        .gather()
        .into_iter()
        .filter(|family| family.name() == "bgp_outbound_commit_refusals_total")
        .flat_map(|family| family.get_metric().to_vec())
        .filter(|metric| {
            metric
                .get_label()
                .iter()
                .any(|label| label.name() == "reason" && label.value() == "outbound_credit")
        })
        .map(|metric| metric.get_counter().get_value())
        .sum()
}

/// Drive each private-family producer toward one peer; per family, the
/// peer's staging entries, whether it ended dirty, and whether anything was
/// queued for it.
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
        let refusals = credit_refusals(&manager);
        manager.handle_update(update);
        drain_route_chunks(&mut manager);
        send_all(&mut source);
        let sent = !send_all(&mut rx).is_empty();
        outcome.push((
            family,
            manager.outbound_stagings(peer) - before,
            credit_refusals(&manager) > refusals,
            sent,
        ));
    }
    outcome
}

/// T5. A private peer with no credit stages nothing in any family's
/// ordinary producer: unicast, EVPN, `FlowSpec`, BGP-LS, VPN, labeled unicast
/// and RT-Constrain each refuse before building an envelope, counted as a
/// credit refusal, where a peer with credit stages and receives each. Red
/// without the preflight: every producer stages first and is refused at
/// the send.
#[test]
fn producers_stage_nothing_for_a_peer_without_credit() {
    for rtc in [false, true] {
        for (family, stagings, dirty, sent) in drive_producers(1 << 20, rtc) {
            assert!(stagings > 0, "{family}: the control peer stages");
            assert!(
                sent && !dirty,
                "{family}: the control peer receives, unrefused"
            );
        }
        for (family, stagings, dirty, _) in drive_producers(0, rtc) {
            assert_eq!(
                stagings, 0,
                "{family}: a peer without credit stages nothing"
            );
            assert!(dirty, "{family}: the pass is refused for credit");
        }
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
/// does go dirty. Red without the credit check: the long stall stays under
/// the 4,096-envelope bound and never goes dirty.
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
                }
                for (_, rx) in &mut receivers {
                    send_all(rx);
                }
            }
            dirty
        };
        let within = u32::try_from(CREDIT / 1024).unwrap() - 1;
        assert_eq!(
            run(within, 3),
            0,
            "evpn={evpn}: a {within}-pass stall stays clean"
        );
        let past = 2 * u32::try_from(CREDIT / 1024).unwrap() + 1;
        assert!(
            run(past, 1) > 0,
            "evpn={evpn}: a {past}-pass stall goes dirty"
        );
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
        )
    };
    assert_eq!(
        run(true, false),
        (20, false),
        "all 20 queued ahead of the close"
    );
    let (queued, dirty) = run(false, false);
    assert_eq!(queued, 0, "spent credit refuses them without BeginClose");
    assert!(dirty);
    let (queued, dirty) = run(true, true);
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
    assert!(manager.dirty_peers.contains(&peer));

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
        assert!(manager.dirty_peers.contains(&peer));
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
