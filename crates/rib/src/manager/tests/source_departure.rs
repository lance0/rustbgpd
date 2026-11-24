//! Source loss through the actor FIFO, including its actual executor poll boundaries.

use std::cell::Cell;
use std::future::{Future, poll_fn};

use rustbgpd_wire::{FlowSpecComponent, FlowSpecPrefix};

use super::exportability::ReusableExactExportEncoder;
use super::lifecycle::{test_peer_up, test_routes_received};
use super::*;
use crate::manager::source_departure::{
    DEPARTURE_MEMBERS_PER_POLL, KEYS_PER_PAGE, MEMBERS_PER_PAGE, RECEIVER_ROWS_PER_POLL,
    WIDE_KEYS_PER_PAGE, set_quiet_unit_cost, take_departure_pages, take_flowspec_withdrawal_work,
    take_receiver_rows,
};

const SOURCE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const OTHER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
const ROWS: u32 = 1024;
const POLL_LIMIT: usize = RECEIVER_ROWS_PER_POLL;
/// Receiver-keys one pressured private poll may visit: a narrow member page
/// over a narrow key page.
const PRIVATE_POLL_LIMIT: usize = MEMBERS_PER_PAGE * KEYS_PER_PAGE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Shape {
    Grouped,
    RsControl,
    Mixed,
    Private,
    FlowSpec,
}

fn prefix(index: u32) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::from(0x0a01_0000 + index), 32)
}

fn probe_prefix() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 254), 32)
}

fn announce(source: Ipv4Addr, pfx: Ipv4Prefix) -> RibUpdate {
    test_routes_received(peer_v4(source), vec![make_route(pfx, source)])
}

fn down(source: Ipv4Addr) -> RibUpdate {
    RibUpdate::PeerDown {
        peer: peer_v4(source),
        session_id: 0,
    }
}

fn rule_prefix(key: &crate::route::FlowSpecKey) -> Prefix {
    assert_eq!(key.afi, Afi::Ipv4);
    assert!(key.rd.is_none());
    let [FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(pfx))] =
        key.rule.components.as_slice()
    else {
        panic!("unexpected FlowSpec rule: {key:?}");
    };
    Prefix::V4(*pfx)
}

fn seed(manager: &mut RibManager, shape: Shape, rows: u32) {
    let mut update = test_routes_received(peer_v4(SOURCE), Vec::new());
    let RibUpdate::RoutesReceived {
        announced,
        flowspec_announced,
        ..
    } = &mut update
    else {
        unreachable!()
    };
    for pfx in (0..rows).map(prefix) {
        if shape == Shape::FlowSpec {
            let mut route = make_flowspec_route(SOURCE);
            route.rule.components = vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(
                pfx,
            ))];
            flowspec_announced.push(route);
        } else {
            announced.push(make_route(pfx, SOURCE));
        }
    }
    manager.handle_update(update);
    drain_route_chunks(manager);
}

fn join(manager: &mut RibManager, index: u16, shape: Shape) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = peer_v4(Ipv4Addr::from(0xc000_0201 + u32::from(index)));
    manager.handle_update(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 1,
        encoder: ReusableExactExportEncoder::new(u64::from(index) + 1, 1),
    });
    if shape == Shape::RsControl {
        manager.handle_update(RibUpdate::SetPeerRsControl {
            peer,
            session_id: 1,
            rs_control_asn: Some(65_000),
        });
    }
    let (outbound_tx, receiver) = mpsc::channel(256);
    let mut up = test_peer_up(peer, 1, outbound_tx);
    let RibUpdate::PeerUp {
        export_policy,
        peer_asn,
        sendable_families,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *peer_asn = 65_100 + u32::from(index);
    if shape == Shape::Private {
        *export_policy = Some(super::update_groups::peer_context_chain());
    } else if shape == Shape::RsControl {
        *sendable_families = dual_stack_sendable();
    } else if shape == Shape::FlowSpec {
        // Also negotiate v4 unicast to observe the independent UPDATE on this writer.
        sendable_families.extend(ipv4_flowspec_sendable());
    }
    manager.handle_update(up);
    if shape != Shape::FlowSpec {
        assert_eq!(
            manager.grouped_member_of(peer).is_some(),
            matches!(shape, Shape::Grouped | Shape::RsControl)
        );
    }
    if shape == Shape::RsControl {
        assert_eq!(manager.peer_rs_control.get(&peer), Some(&65_000));
    }
    receiver
}

fn expected_rows(count: u32) -> BTreeSet<Prefix> {
    (0..count).map(|row| Prefix::V4(prefix(row))).collect()
}

/// Each expectation comes from the routes the fixture fed to the actor.
fn assert_initial(receiver: &mut mpsc::Receiver<OutboundRouteUpdate>, shape: Shape, count: u32) {
    let mut initial = BTreeSet::new();
    while let Ok(update) = receiver.try_recv().map(delivered) {
        assert!(update.unicast_withdrawals().next().is_none());
        assert_eq!(
            update.flowspec_withdraw,
            [] as [crate::route::FlowSpecKey; 0]
        );
        for route in update.announce.iter() {
            assert_ne!(shape, Shape::FlowSpec);
            assert_eq!(
                (route.peer, route.next_hop, route.path_id),
                (peer_v4(SOURCE), IpAddr::V4(SOURCE), 0)
            );
            assert!(initial.insert(route.prefix));
        }
        for route in &update.flowspec_announce {
            assert_eq!(shape, Shape::FlowSpec);
            assert_eq!((route.peer, route.path_id), (peer_v4(SOURCE), 0));
            assert!(initial.insert(rule_prefix(&route.selection_key())));
        }
    }
    assert_eq!(initial, expected_rows(count));
}

thread_local! {
    // Only run_actor calls this observer, on the current-thread test executor.
    static SAW_DEPARTURE: Cell<bool> = const { Cell::new(false) };
    static MOST_UNITS_PER_TURN: Cell<usize> = const { Cell::new(0) };
    static WINNER_DURING_DEPARTURE: Cell<bool> = const { Cell::new(false) };
}

fn observe_winner(manager: &RibManager) {
    if manager.source_departure.is_some() {
        SAW_DEPARTURE.set(true);
    }
    MOST_UNITS_PER_TURN.set(
        MOST_UNITS_PER_TURN
            .get()
            .max(manager.departure_units_this_turn),
    );
    if manager.source_departure.is_some()
        && manager
            .loc_rib
            .get(&Prefix::V4(probe_prefix()))
            .is_some_and(|route| route.peer == peer_v4(OTHER))
    {
        WINNER_DURING_DEPARTURE.set(true);
    }
}

fn assert_departed(updates: &[OutboundRouteUpdate], shape: Shape, rows: u32) -> bool {
    let mut remaining = expected_rows(rows);
    let mut marker_seen = false;
    let mut withdrawal_after_marker = false;
    for update in updates {
        for (prefix, id) in update.unicast_withdrawals() {
            assert_ne!(shape, Shape::FlowSpec);
            assert_eq!(*id, 0);
            assert!(
                remaining.remove(prefix),
                "duplicate or unexpected withdrawal of {prefix}"
            );
            withdrawal_after_marker |= marker_seen;
        }
        for rule in &update.flowspec_withdraw {
            assert_eq!(shape, Shape::FlowSpec);
            assert!(
                remaining.remove(&rule_prefix(rule)),
                "duplicate or unexpected rule withdrawal"
            );
            withdrawal_after_marker |= marker_seen;
        }
        assert!(update.flowspec_announce.is_empty());
        for route in update.announce.iter() {
            assert!(!marker_seen, "duplicate unrelated update");
            assert_eq!(
                (route.peer, route.prefix, route.path_id),
                (peer_v4(OTHER), Prefix::V4(probe_prefix()), 0)
            );
            marker_seen = true;
        }
    }
    assert!(
        remaining.is_empty(),
        "missing {} withdrawals",
        remaining.len()
    );
    assert!(
        marker_seen,
        "independent source must be advertised to every receiver"
    );
    withdrawal_after_marker
}

struct PollCounts {
    inspected: usize,
    emitted: usize,
    envelope: usize,
    envelopes: usize,
    polls: usize,
    /// Units that ran while the FIFO held admissible work.
    pressured: usize,
    /// Most members classified or delivered to in one poll.
    members: usize,
}

fn register_source_only(manager: &mut RibManager) -> mpsc::Receiver<OutboundRouteUpdate> {
    // A source-only private session cannot change the unicast delivery budget.
    let source_only = peer_v4(Ipv4Addr::new(198, 51, 100, 99));
    let (outbound_tx, no_exports) = mpsc::channel(8);
    let mut up = test_peer_up(source_only, 0, outbound_tx);
    let RibUpdate::PeerUp {
        export_policy,
        sendable_families,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *export_policy = Some(super::update_groups::peer_context_chain());
    sendable_families.clear();
    manager.handle_update(up);
    assert!(manager.grouped_member_of(source_only).is_none());
    assert_eq!(
        manager.peer_sendable_families[&source_only],
        [] as [(Afi, Safi); 0]
    );
    no_exports
}

#[derive(Clone, Copy)]
enum ProbeArrival {
    Prequeued,
    AfterEmpty,
    AfterYield,
    /// Sent synchronously at the third quiet unit, inside a budget loop.
    InQuietLoop,
}

thread_local! {
    static ON_EMPTY: Cell<Option<Box<dyn FnOnce()>>> = const { Cell::new(None) };
    static PROBE_SENT: Cell<bool> = const { Cell::new(false) };
    static QUIET_COUNTDOWN: Cell<Option<(usize, mpsc::Sender<RibUpdate>)>> = const { Cell::new(None) };
}

pub(in crate::manager) fn after_empty_fifo() {
    if let Some(send) = ON_EMPTY.take() {
        send();
    }
    if let Some((left, tx)) = QUIET_COUNTDOWN.take() {
        if left == 0 {
            send_probe(&tx);
        } else {
            QUIET_COUNTDOWN.set(Some((left - 1, tx)));
        }
    }
}

fn send_probe(tx: &mpsc::Sender<RibUpdate>) {
    tx.try_send(announce(OTHER, probe_prefix())).unwrap();
    PROBE_SENT.set(true);
}

fn queue_probe(arrival: ProbeArrival, tx: mpsc::Sender<RibUpdate>) {
    PROBE_SENT.set(false);
    match arrival {
        ProbeArrival::Prequeued => {
            send_probe(&tx);
            // Keep a fenced FIFO head waiting through the last withdrawal.
            tx.try_send(down(SOURCE)).unwrap();
        }
        ProbeArrival::AfterEmpty => ON_EMPTY.set(Some(Box::new(move || send_probe(&tx)))),
        ProbeArrival::InQuietLoop => QUIET_COUNTDOWN.set(Some((2, tx))),
        ProbeArrival::AfterYield => {
            let (signal, ready) = oneshot::channel();
            ON_EMPTY.set(Some(Box::new(move || signal.send(()).unwrap())));
            tokio::spawn(async move {
                ready.await.unwrap();
                send_probe(&tx);
            });
        }
    }
}

/// A producer sharing this current-thread executor runs only after the actor
/// yields. One unit per turn keeps that seam for every unit.
fn pace_for_arrival(manager: &mut RibManager, arrival: ProbeArrival) {
    take_flowspec_withdrawal_work();
    MOST_UNITS_PER_TURN.set(0);
    if matches!(arrival, ProbeArrival::AfterYield) {
        manager.flush_poll_budget = Duration::ZERO;
    }
}

/// Receiver-keys one poll may visit while the probe waits. A prequeued UPDATE
/// keeps the first page narrow. A later arrival can find a wide quiet page,
/// which a private member page still bounds.
fn waiting_poll_limit(shape: Shape, arrival: ProbeArrival) -> usize {
    match (shape, arrival) {
        (Shape::Grouped | Shape::RsControl, _) => POLL_LIMIT,
        (_, ProbeArrival::Prequeued) => PRIVATE_POLL_LIMIT,
        _ => MEMBERS_PER_PAGE * WIDE_KEYS_PER_PAGE,
    }
}

async fn departure(shape: Shape, count: u8, rows: u32, arrival: ProbeArrival) -> PollCounts {
    let (tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.outbound_row_credit_override = None;
    super::distribution_window::untimed_window(&mut manager);
    for source in [SOURCE, OTHER] {
        register_test_peer(&mut manager, peer_v4(source), 0);
    }
    let _no_exports = register_source_only(&mut manager);
    let mut receivers: Vec<_> = (0..count)
        .map(|index| {
            let receiver = match shape {
                Shape::Mixed if index == count - 1 => Shape::Private,
                Shape::Mixed => Shape::Grouped,
                other => other,
            };
            join(&mut manager, index.into(), receiver)
        })
        .collect();
    seed(&mut manager, shape, rows);
    for rx in &mut receivers {
        assert_initial(rx, shape, rows);
    }
    assert!(manager.dirty_peers.is_empty());
    pace_for_arrival(&mut manager, arrival);
    WINNER_DURING_DEPARTURE.set(false);
    manager.actor_turn_check = Some(observe_winner);
    tx.try_send(down(SOURCE)).unwrap();
    queue_probe(arrival, tx);
    let mut actor = Box::pin(manager.run_actor());
    let mut streams: Vec<Vec<_>> = (0..count).map(|_| Vec::new()).collect();
    let (mut most, mut total, mut most_sent, mut polls) = (0, 0, 0, 0);
    take_receiver_rows();
    let end = poll_fn(|cx| {
        polls += 1;
        // The bound holds while admissible work waits; a fenced head is not.
        let waiting = PROBE_SENT.get() && !WINNER_DURING_DEPARTURE.get();
        let result = actor.as_mut().poll(cx);
        let work = take_receiver_rows();
        if waiting {
            most = most.max(work);
        }
        total += work;
        let mut sent = 0;
        for (receiver, stream) in receivers.iter_mut().zip(&mut streams) {
            while let Ok(update) = receiver.try_recv().map(delivered) {
                sent += update.unicast_withdrawals().count() + update.flowspec_withdraw.len();
                stream.push(update);
            }
        }
        if waiting {
            most_sent = most_sent.max(sent);
        }
        result
    })
    .await;
    assert!(end.source_departure.is_none());
    assert_eq!(
        end.loc_rib.get(&Prefix::V4(probe_prefix())).unwrap().peer,
        peer_v4(OTHER)
    );
    let mut interleaved = false;
    for updates in &streams {
        interleaved |= assert_departed(updates, shape, rows);
    }
    assert!(
        interleaved,
        "{shape:?} K={count}: unrelated UPDATE reached every writer only after departure finished"
    );
    assert!(
        WINNER_DURING_DEPARTURE.get(),
        "{shape:?} K={count}: independent winner never applied while departure owned unfinished work"
    );
    // Group members may consume a shared payload without walking its rows.
    // Private producers must inspect each departing key for every receiver.
    let private_count = match shape {
        Shape::Private | Shape::FlowSpec => count,
        Shape::Mixed => 1,
        Shape::Grouped | Shape::RsControl => 0,
    };
    if private_count > 0 {
        assert!(
            total >= usize::from(private_count) * usize::try_from(rows).unwrap(),
            "{shape:?} K={count}: receiver-key inspection witness too small: {total}"
        );
    }
    let limit = waiting_poll_limit(shape, arrival);
    assert!(
        most <= limit && most_sent <= limit,
        "{shape:?} K={count}: {most} receiver-keys and {most_sent} withdrawals in one physical actor poll, limit {limit}"
    );
    assert!(end.dirty_peers.is_empty());
    poll_counts(
        shape,
        count,
        rows,
        &streams,
        (most, total, most_sent, polls),
    )
}

fn poll_counts(
    shape: Shape,
    count: u8,
    rows: u32,
    streams: &[Vec<OutboundRouteUpdate>],
    counts: (usize, usize, usize, usize),
) -> PollCounts {
    let (most, total, most_sent, polls) = counts;
    let withdrawal_sizes = streams
        .iter()
        .flatten()
        .map(|update| update.unicast_withdrawals().count() + update.flowspec_withdraw.len())
        .filter(|&rows| rows != 0);
    let envelopes = withdrawal_sizes.clone().count();
    eprintln!(
        "{shape:?} K={count} rows={rows} queued_max_inspected_per_poll={most} queued_max_withdrawals_per_poll={most_sent} total_inspected={total} physical_polls={polls} withdrawal_envelopes={envelopes} total_withdrawals={}",
        withdrawal_sizes.clone().sum::<usize>()
    );
    PollCounts {
        inspected: most,
        emitted: most_sent,
        envelope: withdrawal_sizes.max().unwrap(),
        envelopes,
        polls,
        pressured: 0,
        members: 0,
    }
}

async fn check_sizes(shape: Shape) {
    // A group poll covers the poll budget over a 256-key page. Both rosters
    // must exceed it before a flat maximum shows the bound.
    let (small_count, large_count) = match shape {
        Shape::Grouped | Shape::RsControl => (72, 144),
        _ => (8, 32),
    };
    let small = Box::pin(departure(shape, small_count, ROWS, ProbeArrival::Prequeued)).await;
    let small_work = take_flowspec_withdrawal_work();
    let large = Box::pin(departure(shape, large_count, ROWS, ProbeArrival::Prequeued)).await;
    if shape == Shape::FlowSpec {
        let large_work = take_flowspec_withdrawal_work();
        eprintln!(
            "FlowSpec (staging clones, preflight probes, removals): K=8 {small_work:?}, K=32 {large_work:?}"
        );
        for (members, counts, (clones, probes, removed)) in
            [(8, &small, small_work), (32, &large, large_work)]
        {
            // Each receiver advertised all D rules. Its first probe must hit on
            // every page; the writer independently consumed every withdrawal.
            assert!(counts.envelopes > members, "fixture needs multiple pages");
            assert_eq!(clones, 0, "K={members}: staged owned withdrawal keys");
            assert_eq!(probes, counts.envelopes, "K={members}: full-page probes");
            assert_eq!(removed, members * usize::try_from(ROWS).unwrap());
        }
    }
    assert!(
        large.inspected <= small.inspected,
        "{shape:?} maximum inspected rows grew {} -> {}",
        small.inspected,
        large.inspected
    );
    assert!(
        large.emitted <= small.emitted,
        "{shape:?} maximum emitted withdrawals grew {} -> {}",
        small.emitted,
        large.emitted
    );
}

#[tokio::test(start_paused = true)]
async fn grouped_source_departure_yields_to_an_unrelated_update() {
    check_sizes(Shape::Grouped).await;
}

#[tokio::test(start_paused = true)]
async fn private_source_departure_yields_to_an_unrelated_update() {
    check_sizes(Shape::Private).await;
}

#[tokio::test(start_paused = true)]
async fn flowspec_source_departure_yields_to_an_unrelated_update() {
    check_sizes(Shape::FlowSpec).await;
}

#[test]
fn sparse_flowspec_departure_moves_only_advertised_identities_and_charges_their_rows() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = peer_v4(Ipv4Addr::new(192, 0, 2, 1));
    let (tx, mut writer) = mpsc::channel(8);
    let mut up = test_peer_up(peer, 1, tx);
    let RibUpdate::PeerUp {
        sendable_families, ..
    } = &mut up
    else {
        unreachable!()
    };
    *sendable_families = vec![
        (Afi::Ipv4, Safi::FlowSpec),
        (Afi::Ipv6, Safi::FlowSpec),
        (Afi::Ipv4, Safi::FlowSpecVpn),
        (Afi::Ipv6, Safi::FlowSpecVpn),
    ];
    manager.handle_update(up);
    while writer.try_recv().is_ok() {}

    // The components are valid for either AFI; only the AFI and RD distinguish the keys.
    let rule = |afi, rd| {
        let mut route = make_flowspec_route(SOURCE);
        route.rule.components = vec![FlowSpecComponent::IpProtocol(vec![
            rustbgpd_wire::NumericMatch {
                end_of_list: true,
                and_bit: false,
                lt: false,
                gt: false,
                eq: true,
                value: 6,
            },
        ])];
        route.afi = afi;
        route.rd = rd;
        route
    };
    let rd = |n| Some(RouteDistinguisher([0, 0, 0xfb, 0xf4, 0, 0, 0, n]));
    let page: HashSet<_> = [Afi::Ipv4, Afi::Ipv6]
        .into_iter()
        .flat_map(|afi| [None, rd(1), rd(2)].map(|rd| rule(afi, rd).selection_key()))
        .collect();
    let stored = [
        rule(Afi::Ipv4, None),
        rule(Afi::Ipv4, rd(2)),
        rule(Afi::Ipv6, rd(1)),
    ];
    let expected: HashSet<_> = stored.iter().map(FlowSpecRoute::selection_key).collect();
    let first_hit = 1 + page.iter().position(|key| expected.contains(key)).unwrap();
    let untouched = rule(Afi::Ipv6, rd(3));
    let unaffected_key = untouched.selection_key();
    let advertised = manager
        .adj_ribs_out
        .entry(peer)
        .or_insert_with(|| AdjRibOut::new(peer));
    for route in stored.into_iter().chain([untouched]) {
        advertised.insert_flowspec(route);
    }
    let components: HashMap<_, _> = advertised
        .advertised_flowspec_keys()
        .map(|key| (key.clone(), key.rule.components.as_ptr()))
        .collect();
    assert_eq!(manager.loc_rib.flowspec_len(), 0);
    take_flowspec_withdrawal_work();
    manager.distribute_flowspec_departure_page(&page, &[peer]);
    assert_eq!(manager.outbound_credit_rows(peer), expected.len());
    let update = delivered(writer.try_recv().unwrap());
    assert!(update.flowspec_announce.is_empty());
    assert_eq!(update.flowspec_withdraw.len(), expected.len());
    for key in &update.flowspec_withdraw {
        assert_eq!(
            key.rule.components.as_ptr(),
            components[key],
            "the writer must receive the advertised component allocation"
        );
    }
    assert_eq!(
        update.flowspec_withdraw.into_iter().collect::<HashSet<_>>(),
        expected
    );
    assert_eq!(
        take_flowspec_withdrawal_work(),
        (0, first_hit, expected.len())
    );
    let advertised = &manager.adj_ribs_out[&peer];
    assert_eq!(advertised.flowspec_len(), 1);
    assert!(advertised.get_flowspec(&unaffected_key).is_some());
    assert_eq!(advertised.family_lens().flowspec, [0, 0]);
    assert_eq!(advertised.family_lens().flowspec_vpn, [0, 1]);

    // The table is nonempty, but the same page now has an empty intersection.
    manager.distribute_flowspec_departure_page(&page, &[peer]);
    assert_eq!(take_flowspec_withdrawal_work(), (0, page.len(), 0));
    assert_eq!(manager.outbound_credit_rows(peer), 0);
    assert!(writer.try_recv().is_err());
    assert!(
        manager.adj_ribs_out[&peer]
            .get_flowspec(&unaffected_key)
            .is_some()
    );
}

#[tokio::test(start_paused = true)]
async fn rs_control_grouped_departure_yields_to_an_unrelated_update() {
    check_sizes(Shape::RsControl).await;
}

#[tokio::test(start_paused = true)]
async fn grouped_departure_chunks_an_uneven_member_tail_and_keeps_private_walks_small() {
    // 16,384 / 109 = 150 receivers per poll, with ten on the last page.
    // The extra source-only private registration in both fixtures cannot
    // disqualify the first fixture. A sendable private receiver must.
    let grouped = pressured_departure(Shape::Grouped, 160, 109);
    assert_eq!((grouped.envelope, grouped.emitted), (109, 150 * 109));
    let mixed = pressured_departure(Shape::Mixed, 5, 109);
    assert!(mixed.envelope <= 16);
    assert!(mixed.inspected <= 16 * 8 && mixed.emitted <= 16 * 8);
}

/// Drive a departure unit by unit while an admissible UPDATE stays queued,
/// so every unit runs under FIFO pressure.
fn pressured_departure(shape: Shape, count: u16, rows: u32) -> PollCounts {
    queued_departure(shape, count, rows, announce(OTHER, probe_prefix()))
}

/// Drive a departure unit by unit while `head` stays queued behind it.
fn queued_departure(shape: Shape, count: u16, rows: u32, head: RibUpdate) -> PollCounts {
    let (tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.outbound_row_credit_override = None;
    super::distribution_window::untimed_window(&mut manager);
    for source in [SOURCE, OTHER] {
        register_test_peer(&mut manager, peer_v4(source), 0);
    }
    let _no_exports = register_source_only(&mut manager);
    let mut receivers: Vec<_> = (0..count)
        .map(|index| {
            let receiver = match shape {
                Shape::Mixed if index == count - 1 => Shape::Private,
                Shape::Mixed => Shape::Grouped,
                other => other,
            };
            join(&mut manager, index, receiver)
        })
        .collect();
    seed(&mut manager, shape, rows);
    for rx in &mut receivers {
        assert_initial(rx, shape, rows);
    }
    tx.try_send(head).unwrap();
    manager.handle_update(down(SOURCE));
    assert!(manager.source_departure.is_some());
    take_receiver_rows();
    let (mut envelope, mut emitted, mut inspected, mut polls, mut pressured) = (0, 0, 0, 0, 0);
    let (mut members, mut envelopes) = (0, 0);
    while manager.source_departure.is_some() {
        pressured += usize::from(!manager.source_departure_quiet());
        let scans = manager.adj_rib_out_commit_stats.owed_peer_scans;
        manager.advance_source_departure();
        polls += 1;
        inspected = inspected.max(take_receiver_rows());
        let (mut sent, mut reached) = (0, 0);
        for receiver in &mut receivers {
            let mut got = false;
            while let Ok(update) = receiver.try_recv().map(delivered) {
                let rows = update.unicast_withdrawals().count();
                envelope = envelope.max(rows);
                sent += rows;
                got |= rows > 0;
            }
            reached += usize::from(got);
        }
        envelopes += reached;
        emitted = emitted.max(sent);
        // Members classified or delivered to in this poll.
        members = members
            .max(reached)
            .max(manager.adj_rib_out_commit_stats.owed_peer_scans - scans);
    }
    PollCounts {
        inspected,
        emitted,
        envelope,
        envelopes,
        polls,
        pressured,
        members,
    }
}

/// Departure polls are sized by receiver work, not by a fixed member page.
/// 572 keys toward 128 group members is 73,216 receiver-keys. Each member
/// walk takes about one poll per 16k of them, plus a few seams per key page,
/// whether or not an admissible UPDATE waits.
#[test]
fn group_departure_polls_scale_with_receiver_work() {
    const KEYS: u32 = 572;
    const MEMBERS: u16 = 128;
    let per_walk = (KEYS as usize * usize::from(MEMBERS)).div_ceil(16_384);
    let mut over = Vec::new();
    for shape in [Shape::Grouped, Shape::RsControl] {
        let pressured = pressured_departure(shape, MEMBERS, KEYS);
        let fenced = queued_departure(shape, MEMBERS, KEYS, down(OTHER));
        eprintln!(
            "{shape:?} keys={KEYS} members={MEMBERS}: pressured polls={} fenced polls={}",
            pressured.polls, fenced.polls
        );
        // Classify, RS count removal, RS restore and emission each walk the
        // roster on each of at most four key pages.
        let bound = 4 * 12 + 4 * per_walk;
        for polls in [pressured.polls, fenced.polls] {
            if polls > bound {
                over.push(format!("{shape:?}: {polls} departure polls, bound {bound}"));
            }
        }
    }
    assert!(over.is_empty(), "{over:?}");
}

/// A one-key page leaves nearly the whole receiver-key budget unused, but
/// each member still costs an envelope and a commit. The member ceiling
/// bounds a poll whether or not an admissible UPDATE waits.
#[test]
fn a_one_key_departure_to_a_large_group_visits_bounded_members_per_poll() {
    const MEMBERS: u16 = 600;
    for shape in [Shape::Grouped, Shape::RsControl] {
        for (head, label) in [
            (announce(OTHER, probe_prefix()), "pressured"),
            (down(OTHER), "fenced"),
        ] {
            let counts = queued_departure(shape, MEMBERS, 1, head);
            eprintln!(
                "{shape:?} {label} keys=1 members={MEMBERS}: polls={} max_members_per_poll={}",
                counts.polls, counts.members
            );
            assert!(
                counts.members <= DEPARTURE_MEMBERS_PER_POLL,
                "{shape:?} {label}: {} members in one poll",
                counts.members
            );
        }
    }
}

/// A flap-storm departure: 572 keys toward a 699-member route-server group,
/// with the next `PeerDown` queued behind it. Every key page visits every
/// member, and that visit costs more than its keys, so the quiet page width
/// must not shrink with the roster.
#[test]
fn a_flap_storm_departure_visits_each_member_once() {
    const KEYS: u32 = 572;
    const MEMBERS: u16 = 699;
    for (head, quiet) in [
        (down(OTHER), true),
        (announce(OTHER, probe_prefix()), false),
    ] {
        take_departure_pages();
        let counts = queued_departure(Shape::RsControl, MEMBERS, KEYS, head);
        let pages = take_departure_pages();
        eprintln!(
            "RS flap departure quiet={quiet} keys={KEYS} members={MEMBERS}: pages={pages} member_envelopes={} polls={} max_members_per_poll={}",
            counts.envelopes, counts.polls, counts.members
        );
        assert_eq!(counts.pressured == 0, quiet);
        // A waiting UPDATE keeps the pressured page width.
        let bound = if quiet {
            1
        } else {
            usize::try_from(KEYS).unwrap().div_ceil(WIDE_KEYS_PER_PAGE)
        };
        assert!(
            pages <= bound,
            "quiet={quiet}: {pages} pages, bound {bound}"
        );
        assert!(
            counts.envelopes <= bound * usize::from(MEMBERS),
            "quiet={quiet}: {} member envelopes",
            counts.envelopes
        );
        assert!(counts.members <= DEPARTURE_MEMBERS_PER_POLL);
    }
}

thread_local! {
    static FIRST_DEPARTURE_TURN: Cell<Option<usize>> = const { Cell::new(None) };
}

fn observe_quiet_turn(manager: &RibManager) {
    if manager.source_departure.is_some() && FIRST_DEPARTURE_TURN.get().is_none() {
        FIRST_DEPARTURE_TURN.set(Some(manager.departure_units_this_turn));
    }
    MOST_UNITS_PER_TURN.set(
        MOST_UNITS_PER_TURN
            .get()
            .max(manager.departure_units_this_turn),
    );
}

/// The quiet loop starts a unit only if one as long as the longest so far
/// still fits its budget, and the poll that tears the source down runs no
/// unit. A fake clock charges each unit 3 ms against the 10 ms budget.
#[tokio::test(start_paused = true)]
async fn the_quiet_loop_starts_only_units_that_fit_its_budget() {
    let (tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.outbound_row_credit_override = None;
    super::distribution_window::untimed_window(&mut manager);
    for source in [SOURCE, OTHER] {
        register_test_peer(&mut manager, peer_v4(source), 0);
    }
    let _no_exports = register_source_only(&mut manager);
    let mut receivers: Vec<_> = (0..64)
        .map(|index| join(&mut manager, index, Shape::RsControl))
        .collect();
    seed(&mut manager, Shape::RsControl, ROWS);
    for rx in &mut receivers {
        assert_initial(rx, Shape::RsControl, ROWS);
    }
    // The second PeerDown fences the first departure, so every unit is quiet.
    tx.try_send(down(SOURCE)).unwrap();
    tx.try_send(down(OTHER)).unwrap();
    drop(tx);
    FIRST_DEPARTURE_TURN.set(None);
    MOST_UNITS_PER_TURN.set(0);
    manager.actor_turn_check = Some(observe_quiet_turn);
    let cost = Duration::from_millis(3);
    let budget = crate::manager::source_departure::QUIET_LOOP_BUDGET;
    assert!(manager.flush_poll_budget >= budget);
    set_quiet_unit_cost(Some(cost));
    let end = Box::pin(manager.run_actor()).await;
    set_quiet_unit_cost(None);
    assert!(end.source_departure.is_none());
    for rx in &mut receivers {
        let updates: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok().map(delivered)).collect();
        let withdrawn: usize = updates
            .iter()
            .map(|update| update.unicast_withdrawals().count())
            .sum();
        assert_eq!(withdrawn, usize::try_from(ROWS).unwrap());
    }
    let most = MOST_UNITS_PER_TURN.get();
    let fit = usize::try_from(budget.as_millis() / cost.as_millis()).unwrap();
    eprintln!("quiet loop: unit=3ms budget={budget:?} most_units_per_turn={most}");
    assert_eq!(
        FIRST_DEPARTURE_TURN.get(),
        Some(0),
        "teardown poll ran units"
    );
    assert!(
        most > 1 && u32::try_from(most).unwrap() * cost <= budget,
        "{most} units of {cost:?} in one turn, budget {budget:?} (fit {fit})"
    );
}

/// The next `PeerDown` cannot run before this departure ends. Fencing it when
/// the departure starts lets the first page run quiet, as later pages do.
/// The driver skips the seam checks, so only that start can fence the head.
#[test]
fn a_peer_down_queued_behind_a_departure_lets_every_unit_run_quiet() {
    let fenced = queued_departure(Shape::RsControl, 16, ROWS, down(OTHER));
    assert_eq!(fenced.pressured, 0, "units ran under FIFO pressure");
    let pressured = pressured_departure(Shape::RsControl, 16, ROWS);
    assert_eq!(pressured.pressured, pressured.polls);
}

/// With one key page there is no later key boundary. All 32 members must
/// still consume the same delta, so the waiting UPDATE needs the seam
/// before the first page starts.
#[tokio::test(start_paused = true)]
async fn a_single_key_page_with_many_group_members_admits_the_waiting_update() {
    Box::pin(departure(Shape::Grouped, 32, 16, ProbeArrival::Prequeued)).await;
}

// A synchronous sender can arrive inside the quiet poll itself. A producer
// sharing the current-thread executor also needs a yield before it can enqueue.
#[tokio::test(start_paused = true)]
async fn a_late_update_reaches_the_loc_rib_before_the_last_withdrawal() {
    for shape in [Shape::Private, Shape::FlowSpec, Shape::Grouped] {
        for (members, arrival) in [
            (8, ProbeArrival::AfterEmpty),
            (32, ProbeArrival::AfterYield),
        ] {
            // All 64 keys fit in one quiet page, but the departure has enough
            // work to pace. A first empty observation still needs an admission seam.
            tokio::time::timeout(
                Duration::from_secs(5),
                Box::pin(departure(shape, members, 64, arrival)),
            )
            .await
            .expect("late producer must run during the small departure");
            let run = Box::pin(departure(shape, members, ROWS, arrival));
            let counts = tokio::time::timeout(Duration::from_secs(5), run)
                .await
                .expect("empty FIFO observation must wake the producer");
            if shape != Shape::Grouped {
                // A fixed 16-key page needs one withdrawal envelope per receiver
                // and at least one delivery poll per eight receivers per page.
                let narrow_envelopes = usize::from(members) * usize::try_from(ROWS / 16).unwrap();
                assert!(
                    counts.envelopes < narrow_envelopes,
                    "{shape:?} fixed-width withdrawals"
                );
                assert!(
                    counts.polls < narrow_envelopes / 8,
                    "{shape:?} fixed-width poll count"
                );
            }
        }
    }
}

const STABLE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 3);
const V4: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);

fn tagged(source: Ipv4Addr, index: u32, preference: u32) -> Route {
    let mut route = make_route_with_lp(prefix(index), source, preference);
    AttrSet::edit(&mut route.attributes, |attributes| {
        attributes.push(PathAttribute::Communities(vec![
            0xfde8_0000 + u32::from(source.octets()[3]),
        ]));
    });
    route
}

fn apply_row(table: &mut BTreeMap<Prefix, PeerId>, route: &Route) {
    assert_eq!(route.path_id, 0);
    assert_eq!(route.next_hop, route.peer.addr());
    let IpAddr::V4(source) = route.next_hop else {
        unreachable!()
    };
    assert_eq!(
        route.communities(),
        &[0xfde8_0000 + u32::from(source.octets()[3])]
    );
    table.insert(route.prefix, route.peer);
}

fn collect_table(receiver: &mut mpsc::Receiver<OutboundRouteUpdate>) -> BTreeMap<Prefix, PeerId> {
    let mut table = BTreeMap::new();
    while let Ok(update) = receiver.try_recv().map(delivered) {
        for route in update.announce.iter() {
            if update.announce_source_exclusion != Some(route.peer) {
                apply_row(&mut table, route);
            }
        }
        for &(key, path_id) in update.unicast_withdrawals() {
            assert_eq!(path_id, 0);
            assert!(table.remove(&key).is_some());
        }
    }
    table
}

#[tokio::test(start_paused = true)]
async fn refresh_between_departures_sees_reselected_routes_and_reconnect_owns_its_initial_table() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain};

    let (tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    for addr in [SOURCE, OTHER, STABLE] {
        register_test_peer(&mut manager, peer_v4(addr), 0);
    }
    // A lower preference path survives for keys 0 and 1. This receiver's
    // export policy denies the alternate for key 1 only.
    let mut deny = super::update_groups::deny_statement(prefix(1));
    deny.match_next_hop = Some(IpAddr::V4(OTHER));
    let policy = PolicyChain::new(vec![Policy {
        entries: vec![deny],
        default_action: PolicyAction::Permit,
    }]);
    let peer = peer_v4(Ipv4Addr::new(192, 0, 2, 16));
    manager.handle_update(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 1,
        encoder: ReusableExactExportEncoder::new(77, 1),
    });
    let (output, mut receiver) = mpsc::channel(64);
    let mut up = test_peer_up(peer, 1, output);
    let RibUpdate::PeerUp { export_policy, .. } = &mut up else {
        unreachable!()
    };
    *export_policy = Some(policy);
    manager.handle_update(up);
    let source_rows = 320;
    let extra = source_rows;
    let stable = source_rows + 1;
    for (addr, announcements) in [
        (
            SOURCE,
            (0..source_rows)
                .map(|row| tagged(SOURCE, row, 200))
                .collect(),
        ),
        (
            OTHER,
            vec![
                tagged(OTHER, 0, 100),
                tagged(OTHER, 1, 100),
                tagged(OTHER, extra, 100),
            ],
        ),
        (STABLE, vec![tagged(STABLE, stable, 100)]),
    ] {
        manager.handle_update(test_routes_received(peer_v4(addr), announcements));
        drain_route_chunks(&mut manager);
    }
    let table = collect_table(&mut receiver);
    assert_eq!(table.len(), usize::try_from(source_rows + 2).unwrap());
    assert!((0..source_rows).all(|i| table[&Prefix::V4(prefix(i))] == peer_v4(SOURCE)));

    tx.try_send(down(SOURCE)).unwrap();
    tx.try_send(RibUpdate::RouteRefreshRequest {
        peer,
        session_id: 1,
        afi: V4.0,
        safi: V4.1,
        queued: Arc::default(),
    })
    .unwrap();
    tx.try_send(down(OTHER)).unwrap();
    // The new session must seed itself only from the surviving source.
    tx.try_send(RibUpdate::SetPeerExportEncoder {
        peer: peer_v4(SOURCE),
        session_id: 2,
        encoder: ReusableExactExportEncoder::new(78, 1),
    })
    .unwrap();
    let (output, mut rejoined) = mpsc::channel(32);
    tx.try_send(test_peer_up(peer_v4(SOURCE), 2, output))
        .unwrap();
    // An old session's update must not resurrect its route after reassociation.
    tx.try_send(announce(SOURCE, prefix(stable + 1))).unwrap();
    drop(tx);
    SAW_DEPARTURE.set(false);
    manager.actor_turn_check = Some(observe_winner);
    // The refresh is a fenced head, so the departure runs quiet. Observe
    // each unit: one quiet turn could otherwise finish it.
    manager.flush_poll_budget = Duration::ZERO;
    let end = Box::pin(manager.run_actor()).await;
    assert!(
        SAW_DEPARTURE.get(),
        "the fixture must cross the paging threshold"
    );

    assert_eq!(end.loc_rib.len(), 1);
    assert!(end.source_departure.is_none());
    assert_refresh_then_reconnect(&mut receiver, &mut rejoined, table, source_rows);
}

fn assert_refresh_then_reconnect(
    receiver: &mut mpsc::Receiver<OutboundRouteUpdate>,
    rejoined: &mut mpsc::Receiver<OutboundRouteUpdate>,
    mut table: BTreeMap<Prefix, PeerId>,
    source_rows: u32,
) {
    use rustbgpd_wire::RouteRefreshSubtype::{BoRR, EoRR};

    let extra = source_rows;
    let stable = source_rows + 1;
    let expected_mid = BTreeMap::from([
        (Prefix::V4(prefix(0)), peer_v4(OTHER)),
        (Prefix::V4(prefix(extra)), peer_v4(OTHER)),
        (Prefix::V4(prefix(stable)), peer_v4(STABLE)),
    ]);
    let final_table = BTreeMap::from([(Prefix::V4(prefix(stable)), peer_v4(STABLE))]);
    let mut bracket = None;
    let mut replies = 0;
    let mut switches = 0;
    let mut withdrawn = BTreeSet::new();
    while let Ok(update) = receiver.try_recv().map(delivered) {
        if update.refresh_markers.contains(&(V4.0, V4.1, BoRR)) {
            assert_eq!(
                table, expected_mid,
                "refresh crossed unfinished first departure"
            );
            assert!(bracket.replace(BTreeMap::new()).is_none());
        }
        for &(key, path_id) in update.unicast_withdrawals() {
            assert_eq!(path_id, 0);
            assert!(table.remove(&key).is_some());
            assert!(withdrawn.insert(key));
        }
        for route in update.announce.iter() {
            if let Some(rows) = &mut bracket {
                assert!(!rows.contains_key(&route.prefix));
                apply_row(rows, route);
            } else {
                assert_eq!(
                    (route.prefix, route.peer),
                    (Prefix::V4(prefix(0)), peer_v4(OTHER)),
                    "only the usable alternate should be re-announced"
                );
                switches += 1;
            }
            apply_row(&mut table, route);
        }
        if update.refresh_markers.contains(&(V4.0, V4.1, EoRR)) {
            assert_eq!(bracket.take().unwrap(), expected_mid);
            replies += 1;
        }
    }
    assert_eq!((switches, replies), (1, 1));
    assert!(bracket.is_none());
    assert_eq!(withdrawn, expected_rows(source_rows + 1));
    assert_eq!(table, final_table);
    let mut initial = BTreeMap::new();
    let mut eor = 0;
    while let Ok(update) = rejoined.try_recv().map(delivered) {
        assert!(update.unicast_withdrawals().next().is_none());
        for route in update.announce.iter() {
            assert_eq!(eor, 0, "initial table sent after End-of-RIB");
            apply_row(&mut initial, route);
        }
        if update.end_of_rib.contains(&V4) {
            assert_eq!(initial, final_table);
            eor += 1;
        }
    }
    assert_eq!(eor, 1);
}

#[tokio::test(start_paused = true)]
async fn indebted_receiver_recovers_departure_withdrawals_before_its_marker() {
    const CREDIT: u32 = 32;
    let (tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_outbound_row_credit(usize::try_from(CREDIT).unwrap());
    register_test_peer(&mut manager, peer_v4(SOURCE), 0);
    register_test_peer(&mut manager, peer_v4(STABLE), 0);
    let mut slow = join(&mut manager, 0, Shape::Private);
    let mut fast = join(&mut manager, 1, Shape::Private);
    let mut closing = join(&mut manager, 2, Shape::Private);
    let slow_id = peer_v4(Ipv4Addr::new(192, 0, 2, 1));
    let mut slow_table = BTreeMap::new();
    let mut held = Vec::new();
    // Leave the last real envelope in the writer's hands, with its charge live.
    for batch in 0..3 {
        let routes = (batch * CREDIT..(batch + 1) * CREDIT)
            .map(|i| tagged(SOURCE, i, 100))
            .collect();
        manager.handle_update(test_routes_received(peer_v4(SOURCE), routes));
        drain_route_chunks(&mut manager);
        while let Ok(update) = slow.try_recv() {
            for route in update.announce.iter() {
                apply_row(&mut slow_table, route);
            }
            if batch == 2 {
                held.push(update);
            }
        }
        while fast.try_recv().is_ok() {}
        while closing.try_recv().is_ok() {}
    }
    assert_eq!(slow_table.len(), 3 * usize::try_from(CREDIT).unwrap());
    assert!(manager.outbound_credit_exhausted(slow_id));
    manager.handle_update(test_routes_received(
        peer_v4(STABLE),
        vec![tagged(STABLE, 99, 100)],
    ));
    drain_route_chunks(&mut manager);
    assert!(
        manager.owes(slow_id, V4),
        "slow peer must enter departure already owing rows"
    );
    manager.owe_eor(slow_id, V4);
    // Its session closes after accepting the source table, before withdrawal delivery.
    drop(closing);
    tx.try_send(down(SOURCE)).unwrap();
    tx.try_send(RibUpdate::PeerDown {
        peer: peer_v4(Ipv4Addr::new(192, 0, 2, 3)),
        session_id: 1,
    })
    .unwrap();
    drop(tx);
    SAW_DEPARTURE.set(false);
    manager.actor_turn_check = Some(observe_winner);
    let mut actor = Box::pin(manager.run_actor());
    let mut fast_withdrawals = BTreeSet::new();
    let mut fast_survivors = BTreeMap::new();
    let mut manager = poll_fn(|cx| {
        let progress = actor.as_mut().poll(cx);
        while let Ok(update) = fast.try_recv().map(delivered) {
            for &(key, path_id) in update.unicast_withdrawals() {
                assert_eq!(path_id, 0);
                assert!(fast_withdrawals.insert(key));
            }
            for route in update.announce.iter() {
                apply_row(&mut fast_survivors, route);
            }
        }
        progress
    })
    .await;
    assert!(manager.source_departure.is_none());
    assert!(
        SAW_DEPARTURE.get(),
        "the fixture must cross the paging threshold"
    );
    assert!(manager.owes(slow_id, V4));
    assert!(
        slow.try_recv().is_err(),
        "credit-starved receiver received a premature marker or uncharged rows"
    );
    let expected = BTreeMap::from([(Prefix::V4(prefix(99)), peer_v4(STABLE))]);
    assert_eq!(fast_survivors, expected);
    assert_eq!(fast_withdrawals, expected_rows(3 * CREDIT));
    drop(held);
    assert_debt_markers(&mut manager, &mut slow, slow_table, &expected);
    assert!(!manager.owes(slow_id, V4));
    assert!(!manager.resync_tick_pending());
}

fn assert_debt_markers(
    manager: &mut RibManager,
    slow: &mut mpsc::Receiver<OutboundRouteUpdate>,
    mut slow_table: BTreeMap<Prefix, PeerId>,
    expected: &BTreeMap<Prefix, PeerId>,
) {
    let mut markers = 0;
    for _ in 0..128 {
        manager.resync_dirty_peers_bounded();
        while let Ok(update) = slow.try_recv().map(delivered) {
            for &(key, path_id) in update.unicast_withdrawals() {
                assert_eq!((markers, path_id), (0, 0));
                assert!(
                    slow_table.remove(&key).is_some(),
                    "withdrawal of an unheld key {key}"
                );
            }
            for route in update.announce.iter() {
                assert_eq!(markers, 0);
                apply_row(&mut slow_table, route);
            }
            if update.end_of_rib.contains(&V4) {
                assert_eq!(
                    &slow_table, expected,
                    "marker preceded completion of its debt"
                );
                markers += 1;
            }
        }
        if !manager.resync_tick_pending() {
            break;
        }
    }
    assert_eq!(markers, 1);
    assert_eq!(&slow_table, expected);
}

/// The seventeenth identity is either disjoint or the only conflicting
/// identity. An unchecked suffix must never let a partial message overtake
/// departure. Rejecting all larger messages would also starve the disjoint case.
#[tokio::test(start_paused = true)]
async fn wire_update_checks_the_whole_head_before_dispatching_during_departure() {
    const DEPARTING: u32 = 257;
    for conflicting_tail in [false, true] {
        let (tx, rx) = mpsc::channel(8);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
        for source in [SOURCE, OTHER] {
            register_test_peer(&mut manager, peer_v4(source), 0);
        }
        let mut output = join(&mut manager, 0, Shape::Grouped);
        seed(&mut manager, Shape::Grouped, DEPARTING);
        assert_initial(&mut output, Shape::Grouped, DEPARTING);
        let mut keys = vec![probe_prefix()];
        keys.extend((0..15).map(|i| prefix(DEPARTING + i)));
        keys.push(if conflicting_tail {
            prefix(0)
        } else {
            prefix(DEPARTING + 15)
        });
        let routes = keys.iter().map(|&pfx| make_route(pfx, OTHER)).collect();
        let message =
            crate::update::WireRoutesReceived::new(test_routes_received(peer_v4(OTHER), routes), 0);
        assert_eq!(message.announced.len(), 17);
        WINNER_DURING_DEPARTURE.set(false);
        SAW_DEPARTURE.set(false);
        manager.actor_turn_check = Some(if conflicting_tail {
            |manager| {
                observe_winner(manager);
                if manager.source_departure.is_some() {
                    assert!(
                        manager
                            .loc_rib
                            .get(&Prefix::V4(prefix(DEPARTING + 16)))
                            .is_none(),
                        "FIFO follower bypassed the fenced head"
                    );
                }
            }
        } else {
            observe_winner
        });
        tx.try_send(down(SOURCE)).unwrap();
        tx.try_send(RibUpdate::WireRoutesReceived(message)).unwrap();
        let follower = Prefix::V4(prefix(DEPARTING + 16));
        tx.try_send(announce(OTHER, prefix(DEPARTING + 16)))
            .unwrap();
        drop(tx);
        let end = Box::pin(manager.run_actor()).await;
        assert!(SAW_DEPARTURE.get());
        assert_eq!(WINNER_DURING_DEPARTURE.get(), !conflicting_tail);
        let mut remaining = expected_rows(DEPARTING);
        let mut expected: BTreeSet<_> = keys.into_iter().map(Prefix::V4).collect();
        assert!(expected.insert(follower));
        let mut announced = BTreeSet::new();
        let mut overlapped = false;
        while let Ok(update) = output.try_recv().map(delivered) {
            for &(key, id) in update.unicast_withdrawals() {
                assert_eq!(id, 0);
                assert!(remaining.remove(&key));
            }
            for route in update.announce.iter() {
                assert_eq!((route.path_id, route.peer), (0, peer_v4(OTHER)));
                assert!(announced.insert(route.prefix));
                overlapped |= !remaining.is_empty();
            }
        }
        assert!(remaining.is_empty());
        assert_eq!(announced, expected);
        assert_eq!(
            overlapped, !conflicting_tail,
            "wire ordering for a head with conflicting tail={conflicting_tail}"
        );
        assert_eq!(end.loc_rib.len(), 18);
    }
}

const PARTIAL_GROUP_ROWS: u32 = 512;

struct PartialGroupWitness {
    input: Option<mpsc::Sender<RibUpdate>>,
    outputs: Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    withdrawn: Vec<BTreeSet<Prefix>>,
    first_batch: BTreeSet<Prefix>,
    saw_winner_with_work_left: bool,
}

thread_local! {
    static PARTIAL_GROUP: std::cell::RefCell<Option<PartialGroupWitness>> = const {
        std::cell::RefCell::new(None)
    };
}

impl PartialGroupWitness {
    fn observe(&mut self, manager: &RibManager) {
        let mut marker_sent = false;
        for (rx, held) in self.outputs.iter_mut().zip(&mut self.withdrawn) {
            while let Ok(update) = rx.try_recv().map(delivered) {
                let mut batch = BTreeSet::new();
                for &(key, path_id) in update.unicast_withdrawals() {
                    assert_eq!(path_id, 0);
                    assert!(held.insert(key));
                    batch.insert(key);
                }
                if self.first_batch.is_empty() && !batch.is_empty() {
                    self.first_batch = batch;
                }
                for route in update.announce.iter() {
                    assert_eq!(
                        (route.prefix, route.peer),
                        (Prefix::V4(probe_prefix()), peer_v4(OTHER))
                    );
                    assert!(
                        self.first_batch.is_subset(held),
                        "this receiver saw the marker ahead of its staged withdrawals"
                    );
                    marker_sent = true;
                }
            }
        }
        if self.first_batch.is_empty() {
            return;
        }
        let covered = self
            .withdrawn
            .iter()
            .filter(|seen| self.first_batch.is_subset(seen))
            .count();
        if let Some(input) = self.input.take() {
            assert!(
                covered > 0 && covered < self.outputs.len(),
                "expected to observe a partially delivered group before submitting its FIFO successor"
            );
            input.try_send(announce(OTHER, probe_prefix())).unwrap();
        }
        let winner_applied = manager
            .loc_rib
            .get(&Prefix::V4(probe_prefix()))
            .is_some_and(|route| route.peer == peer_v4(OTHER));
        if winner_applied || marker_sent {
            assert_eq!(
                covered,
                self.outputs.len(),
                "the unrelated UPDATE split a staged group delta"
            );
        }
        self.saw_winner_with_work_left |= winner_applied
            && manager.source_departure.is_some()
            && self
                .withdrawn
                .iter()
                .any(|rows| rows.len() < usize::try_from(PARTIAL_GROUP_ROWS).unwrap());
    }
}

#[tokio::test(start_paused = true)]
async fn a_grouped_departure_publishes_the_entire_key_page_before_dispatching_an_update() {
    // More members than one quiet delivery unit covers at this page width,
    // so a partially delivered group is observable between units.
    const MEMBERS: u8 = 80;
    let (tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    for source in [SOURCE, OTHER] {
        register_test_peer(&mut manager, peer_v4(source), 0);
    }
    let mut outputs: Vec<_> = (0..MEMBERS)
        .map(|index| join(&mut manager, index.into(), Shape::Grouped))
        .collect();
    let group = manager
        .grouped_member_of(peer_v4(Ipv4Addr::new(192, 0, 2, 1)))
        .unwrap();
    assert_eq!(
        manager.group_ribs[&group].members.len(),
        usize::from(MEMBERS)
    );
    seed(&mut manager, Shape::Grouped, PARTIAL_GROUP_ROWS);
    for receiver in &mut outputs {
        assert_initial(receiver, Shape::Grouped, PARTIAL_GROUP_ROWS);
    }
    tx.try_send(down(SOURCE)).unwrap();
    PARTIAL_GROUP.replace(Some(PartialGroupWitness {
        input: Some(tx),
        outputs,
        withdrawn: vec![BTreeSet::new(); usize::from(MEMBERS)],
        first_batch: BTreeSet::new(),
        saw_winner_with_work_left: false,
    }));
    manager.actor_turn_check = Some(|manager| {
        PARTIAL_GROUP.with_borrow_mut(|state| state.as_mut().unwrap().observe(manager));
    });
    // Observe each unit: a quiet turn could otherwise deliver the whole page.
    manager.flush_poll_budget = Duration::ZERO;
    let end = tokio::time::timeout(Duration::from_secs(5), Box::pin(manager.run_actor()))
        .await
        .expect("no partial group publication was observed to unblock the FIFO producer");
    let mut state = PARTIAL_GROUP.take().unwrap();
    state.observe(&end);
    assert!(state.input.is_none());
    assert!(state.saw_winner_with_work_left);
    let expected = expected_rows(PARTIAL_GROUP_ROWS);
    assert!(state.withdrawn.iter().all(|seen| seen == &expected));
}

const RS_STAGE_ROWS: u16 = 192;

fn rs_v6(index: u16) -> Ipv6Prefix {
    Ipv6Prefix::new(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, index), 128)
}

fn rs_body_tag(source: Ipv4Addr) -> u32 {
    (64_512 << 16) | u32::from(source.octets()[3])
}

/// IPv4 has no control communities. IPv6 changes from a winner suppressed
/// for member 1 to an alternate suppressed for member 0. These are separate
/// family stages regardless of the order of keys in the source's hash table.
fn rs_stage_routes(source: Ipv4Addr) -> RibUpdate {
    rs_stage_routes_suppressing(source, if source == SOURCE { 65_101 } else { 65_100 })
}

/// [`rs_stage_routes`] with the IPv6 control community naming `suppressed_asn`.
fn rs_stage_routes_suppressing(source: Ipv4Addr, suppressed_asn: u32) -> RibUpdate {
    let departing = source == SOURCE;
    let mut routes = Vec::new();
    for index in 0..RS_STAGE_ROWS {
        let mut v4 = make_route(prefix(u32::from(index)), source);
        let preference = if departing { 200 } else { 100 };
        v4.attributes = AttrSet::new(vec![
            PathAttribute::LocalPref(preference),
            PathAttribute::Communities(vec![rs_body_tag(source)]),
        ]);
        let mut v6 = v4.clone();
        v6.prefix = Prefix::V6(rs_v6(index));
        v6.next_hop = IpAddr::V6(Ipv6Addr::new(
            0x2001,
            0xdb8,
            2,
            0,
            0,
            0,
            0,
            u16::from(source.octets()[3]),
        ));
        v6.attributes = AttrSet::new(vec![
            PathAttribute::LocalPref(preference),
            PathAttribute::Communities(vec![rs_body_tag(source), suppressed_asn]),
        ]);
        if departing {
            routes.push(v4);
        }
        routes.push(v6);
    }
    test_routes_received(peer_v4(source), routes)
}

fn drain_rs_stage(
    output: &mut mpsc::Receiver<OutboundRouteUpdate>,
    source: Ipv4Addr,
) -> (BTreeSet<Prefix>, BTreeSet<Prefix>) {
    let (mut announced, mut withdrawn) = (BTreeSet::new(), BTreeSet::new());
    while let Ok(update) = output.try_recv().map(delivered) {
        for &(key, path_id) in update.unicast_withdrawals() {
            assert_eq!(path_id, 0);
            assert!(withdrawn.insert(key), "duplicate withdrawal {key}");
        }
        for route in update.announce.iter() {
            assert_eq!((route.peer, route.path_id), (peer_v4(source), 0));
            assert_eq!(
                route.communities(),
                &[rs_body_tag(source)],
                "the member's RS control tag should be scrubbed"
            );
            assert!(
                announced.insert(route.prefix),
                "duplicate announcement {}",
                route.prefix
            );
        }
    }
    (announced, withdrawn)
}

/// More RS-control members than one poll's receiver-key budget covers on a
/// 191-key family page.
const RS_WIDE_MEMBERS: u16 = 100;

async fn rs_control_departure(refusals_per_family: u16) {
    use crate::update::ExactExportKey;
    let (tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    for source in [SOURCE, OTHER] {
        register_test_peer(&mut manager, peer_v4(source), 0);
    }
    let mut outputs: Vec<_> = (0..RS_WIDE_MEMBERS)
        .map(|index| join(&mut manager, index, Shape::RsControl))
        .collect();
    let first = peer_v4(Ipv4Addr::new(192, 0, 2, 1));
    let group = manager.grouped_member_of(first).unwrap();
    assert_eq!(manager.group_ribs[&group].members.len(), outputs.len());
    if refusals_per_family > 0 {
        let encoder = super::exportability::MockExactExportEncoder::accepting(1);
        encoder.set_profile(
            1,
            (0..refusals_per_family).flat_map(|index| {
                [
                    Prefix::V4(prefix(u32::from(index))),
                    Prefix::V6(rs_v6(index)),
                ]
                .map(|prefix| ExactExportKey::Unicast(prefix, 0))
            }),
        );
        for &peer in &manager.group_ribs[&group].members {
            manager.peer_export_encoders.insert(peer, encoder.clone());
        }
    }
    for source in [SOURCE, OTHER] {
        manager.handle_update(rs_stage_routes(source));
        drain_route_chunks(&mut manager);
    }
    let plain: BTreeSet<_> = (refusals_per_family..RS_STAGE_ROWS)
        .map(|index| Prefix::V4(prefix(u32::from(index))))
        .collect();
    let tagged: BTreeSet<_> = (refusals_per_family..RS_STAGE_ROWS)
        .map(|index| Prefix::V6(rs_v6(index)))
        .collect();
    let both: BTreeSet<_> = plain.union(&tagged).copied().collect();
    for (index, output) in outputs.iter_mut().enumerate() {
        let (announced, withdrawn) = drain_rs_stage(output, SOURCE);
        assert_eq!(&announced, if index == 1 { &plain } else { &both });
        assert_eq!(withdrawn, BTreeSet::new());
    }
    SAW_DEPARTURE.set(false);
    manager.actor_turn_check = Some(observe_winner);
    // Measure one departure unit per actor turn. The second PeerDown is a
    // fenced head, so nothing admissible waits and the pages run wide.
    manager.flush_poll_budget = Duration::ZERO;
    tx.try_send(down(SOURCE)).unwrap();
    tx.try_send(down(SOURCE)).unwrap();
    drop(tx);
    take_receiver_rows();
    let mut actor = Box::pin(manager.run_actor());
    let (mut peak, mut work_polls) = (0, 0);
    let end = poll_fn(|cx| {
        let result = actor.as_mut().poll(cx);
        let rows = take_receiver_rows();
        work_polls += usize::from(rows > 0);
        peak = peak.max(rows);
        result
    })
    .await;
    assert!(SAW_DEPARTURE.get());
    assert!(end.source_departure.is_none());
    for (index, output) in outputs.iter_mut().enumerate() {
        let (announced, withdrawn) = drain_rs_stage(output, OTHER);
        let peer = peer_v4(Ipv4Addr::new(192, 0, 2, u8::try_from(index + 1).unwrap()));
        let v6_count = if index == 0 { 0 } else { tagged.len() };
        assert_eq!(
            end.grouped_advertised_unicast_lens(peer),
            Some([0, v6_count])
        );
        if index == 0 {
            assert_eq!(announced, BTreeSet::new());
            assert_eq!(withdrawn, both);
        } else {
            assert_eq!(announced, tagged);
            assert_eq!(withdrawn, plain);
        }
    }
    assert!(work_polls > 1, "expected multiple receiver pages");
    eprintln!(
        "RS-control plain-to-tagged departure: refusals_per_family={refusals_per_family} K={RS_WIDE_MEMBERS} rows_per_family={RS_STAGE_ROWS} max_inspected_per_poll={peak}"
    );
    assert!(
        peak > 0 && peak <= POLL_LIMIT,
        "{peak} receiver-key inspections in one quiet unit, limit {POLL_LIMIT}"
    );
}

#[tokio::test(start_paused = true)]
async fn grouped_source_departure_rechecks_rs_control_tags_for_each_family_stage() {
    rs_control_departure(0).await;
}

#[tokio::test(start_paused = true)]
async fn grouped_source_departure_bounds_rs_control_and_exact_refusals_together() {
    // RS checks and 96 retained refusals per member, over more members than
    // one poll's receiver-key budget covers.
    rs_control_departure(96).await;
}

/// Eight private receivers holding the departing table and 2,048 unrelated
/// rows from another source, each receiver's initial output drained.
fn private_receivers_with_unrelated_table() -> (RibManager, Vec<mpsc::Receiver<OutboundRouteUpdate>>)
{
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.outbound_row_credit_override = None;
    super::distribution_window::untimed_window(&mut manager);
    for source in [SOURCE, OTHER] {
        register_test_peer(&mut manager, peer_v4(source), 0);
    }
    let mut receivers: Vec<_> = (0..8)
        .map(|index| join(&mut manager, index, Shape::Private))
        .collect();
    let unrelated = (0..2048)
        .map(|row| make_route(prefix(ROWS + 10 + row), OTHER))
        .collect();
    manager.handle_update(test_routes_received(peer_v4(OTHER), unrelated));
    drain_route_chunks(&mut manager);
    seed(&mut manager, Shape::Private, ROWS);
    for receiver in &mut receivers {
        while receiver.try_recv().is_ok() {}
    }
    (manager, receivers)
}

/// A receiver owing a whole-table rebuild must leave it to the resync tick.
/// Building it inside a departure page would put its unrelated table in one poll.
fn assert_pending_rebuild_waits_for_departure(force: bool) {
    let (mut manager, mut receivers) = private_receivers_with_unrelated_table();
    let pending = peer_v4(Ipv4Addr::new(192, 0, 2, 1));
    if force {
        manager.force_outbound_peers.insert(pending);
    } else {
        manager.mark_outbound_dirty(pending);
    }
    assert_ne!(manager.dirty_peers.contains(&pending), force);
    manager.handle_update(down(SOURCE));
    assert!(manager.source_departure.is_some());
    take_receiver_rows();
    for receiver in &mut receivers {
        while receiver.try_recv().is_ok() {}
    }
    let (mut most, mut most_sent) = (0, 0);
    while manager.source_departure.is_some() {
        // The pending receiver keeps every page pressured and narrow.
        assert!(!manager.source_departure_quiet());
        manager.advance_source_departure();
        most = most.max(take_receiver_rows());
        let mut sent = 0;
        for receiver in &mut receivers {
            while let Ok(update) = receiver.try_recv().map(delivered) {
                sent += update.unicast_withdrawals().count() + update.announce.len();
            }
        }
        most_sent = most_sent.max(sent);
    }
    assert!(
        most <= PRIVATE_POLL_LIMIT,
        "force={force}: {most} receiver-keys inspected in one departure poll"
    );
    assert!(
        most_sent <= PRIVATE_POLL_LIMIT,
        "force={force}: {most_sent} rows sent in one departure poll"
    );
}

#[test]
fn dirty_private_receiver_is_not_rebuilt_inside_a_departure_page() {
    assert_pending_rebuild_waits_for_departure(false);
}

#[test]
fn forced_private_receiver_is_not_rebuilt_inside_a_departure_page() {
    assert_pending_rebuild_waits_for_departure(true);
}

#[test]
fn a_teardown_during_a_live_departure_stays_synchronous() {
    let (mut manager, _receivers) = private_receivers_with_unrelated_table();
    manager.handle_update(down(SOURCE));
    assert!(manager.source_departure.is_some());
    assert!(!manager.large_source_departure(usize::MAX));
    // The FIFO fences a second PeerDown. A direct call must neither replace
    // the live departure nor start a second one.
    manager.handle_update(down(OTHER));
    assert!(manager.source_departure.is_some());
    while manager.source_departure.is_some() {
        manager.advance_source_departure();
    }
    assert!(manager.loc_rib.is_empty());
}

/// An UPDATE that lands while consecutive quiet units run in one actor turn
/// ends that turn and reaches the Loc-RIB before the departure finishes.
#[tokio::test(start_paused = true)]
async fn an_update_queued_inside_a_quiet_budget_loop_applies_before_the_departure_ends() {
    for shape in [Shape::Private, Shape::Grouped, Shape::FlowSpec] {
        Box::pin(departure(shape, 8, ROWS, ProbeArrival::InQuietLoop)).await;
        assert!(
            MOST_UNITS_PER_TURN.get() > 1,
            "{shape:?}: no actor turn ran consecutive quiet departure units"
        );
    }
}

/// Three RS-control members whose departing winner is suppressed for member
/// 0 and whose alternate is suppressed for member 1, with the source gone.
fn rs_departure_fixture() -> (
    mpsc::Sender<RibUpdate>,
    RibManager,
    Vec<mpsc::Receiver<OutboundRouteUpdate>>,
) {
    rs_departure_fixture_with(3, None)
}

/// [`rs_departure_fixture`] with `members` members and `head` queued behind
/// the departing source.
fn rs_departure_fixture_with(
    members: u16,
    head: Option<RibUpdate>,
) -> (
    mpsc::Sender<RibUpdate>,
    RibManager,
    Vec<mpsc::Receiver<OutboundRouteUpdate>>,
) {
    let (tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    // Unlimited credit and no distribution window keep receivers out of the
    // owing and dirty sets, so the lifted pressure really makes a poll quiet.
    manager.outbound_row_credit_override = None;
    super::distribution_window::untimed_window(&mut manager);
    for source in [SOURCE, OTHER] {
        register_test_peer(&mut manager, peer_v4(source), 0);
    }
    let mut outputs: Vec<_> = (0..members)
        .map(|index| join(&mut manager, index, Shape::RsControl))
        .collect();
    // The departing winner is suppressed for member 0 and its alternate for
    // member 1, so a count restored on the wrong page lands on a member that
    // a narrow page does not visit first.
    for (source, suppressed) in [(SOURCE, 65_100), (OTHER, 65_101)] {
        manager.handle_update(rs_stage_routes_suppressing(source, suppressed));
        drain_route_chunks(&mut manager);
    }
    for output in &mut outputs {
        drain_rs_stage(output, SOURCE);
    }
    if let Some(head) = head {
        tx.try_send(head).unwrap();
    }
    manager.handle_update(down(SOURCE));
    assert!(manager.source_departure.is_some());
    (tx, manager, outputs)
}

fn assert_rs_departure_counts(
    manager: &RibManager,
    outputs: &mut [mpsc::Receiver<OutboundRouteUpdate>],
) {
    let tagged = usize::from(RS_STAGE_ROWS);
    for (index, output) in outputs.iter_mut().enumerate() {
        drain_rs_stage(output, OTHER);
        let peer = peer_v4(Ipv4Addr::new(192, 0, 2, u8::try_from(index + 1).unwrap()));
        assert_eq!(
            manager.grouped_advertised_unicast_lens(peer),
            Some([0, if index == 1 { 0 } else { tagged }]),
            "member {index} RS counts after the departure"
        );
    }
}

/// An RS-control group restores member counts in one poll and emits to the
/// same members in the next. A FIFO change between them must not widen the
/// emission past the restored page.
#[test]
fn rs_restore_and_emission_cover_one_member_page_across_a_pressure_change() {
    let (tx, mut manager, mut outputs) = rs_departure_fixture();
    let (mut pinned, mut flips, mut quiet_emissions) = (false, 0, 0);
    while manager.source_departure.is_some() {
        // Open each page quiet so it is wide. Deliver under pressure, so a
        // member page is narrow, then lift the pressure before its emission.
        let pressure = manager.departure_page_open() && !pinned;
        let queued = !manager.rx.is_empty();
        if pressure && !queued {
            tx.try_send(announce(OTHER, probe_prefix())).unwrap();
        } else if !pressure && queued {
            manager.rx.try_recv().unwrap();
        }
        quiet_emissions += usize::from(pinned && manager.source_departure_quiet());
        manager.advance_source_departure();
        let now_pinned = manager.departure_rs_restore_pinned();
        flips += usize::from(now_pinned && !pinned);
        pinned = now_pinned;
    }
    assert!(
        flips > 1,
        "expected several RS restore polls under pressure"
    );
    assert!(
        quiet_emissions > 0,
        "no pinned emission ran without FIFO pressure"
    );
    assert_rs_departure_counts(&manager, &mut outputs);
}

/// A quiet RS restore can be followed by an independent UPDATE before its
/// emission. The pinned emission then runs while that UPDATE waits, so the
/// restore page must already fit the pressured receiver-key budget.
#[test]
fn rs_restore_page_stays_within_the_pressured_limit_when_an_update_arrives_before_emission() {
    // A whole-roster page would exceed the receiver-key budget.
    let (tx, mut manager, mut outputs) = rs_departure_fixture_with(RS_WIDE_MEMBERS, None);
    take_receiver_rows();
    let (mut queued_peak, mut queued_sent, mut armed) = (0, 0, false);
    let mut seen: Vec<(BTreeSet<Prefix>, BTreeSet<Prefix>)> =
        vec![Default::default(); outputs.len()];
    while manager.source_departure.is_some() {
        let waiting = !manager.rx.is_empty();
        manager.advance_source_departure();
        let rows = take_receiver_rows();
        let mut sent = 0;
        for (output, (announced, withdrawn)) in outputs.iter_mut().zip(&mut seen) {
            let (more_announced, more_withdrawn) = drain_rs_stage(output, OTHER);
            sent += more_announced.len() + more_withdrawn.len();
            announced.extend(more_announced);
            withdrawn.extend(more_withdrawn);
        }
        if waiting {
            queued_peak = queued_peak.max(rows);
            queued_sent = queued_sent.max(sent);
        }
        if !armed && manager.departure_rs_restore_pinned() {
            assert!(!waiting, "the first RS restore must run quiet");
            tx.try_send(announce(OTHER, probe_prefix())).unwrap();
            armed = true;
        }
    }
    assert!(armed, "no RS restore poll ran");
    assert!(
        queued_peak <= POLL_LIMIT,
        "{queued_peak} receiver-keys in one poll while an UPDATE waited, limit {POLL_LIMIT}"
    );
    assert!(
        queued_sent > 0 && queued_sent <= POLL_LIMIT,
        "{queued_sent} rows emitted in one poll while an UPDATE waited, limit {POLL_LIMIT}"
    );
    assert_rs_departure_counts(&manager, &mut outputs);
}

/// Control-tagged departing and replacement routes make each member page
/// restore RS counts and then emit to the same members. At 128 members a
/// whole-roster family page exceeds one poll's receiver-key budget, so the
/// polls must split it, with or without a waiting UPDATE.
#[test]
fn a_tagged_rs_departure_paces_restores_and_emissions_by_receiver_work() {
    const MEMBERS: u16 = 128;
    let keys = 2 * usize::from(RS_STAGE_ROWS);
    let per_walk = (keys * usize::from(MEMBERS)).div_ceil(RECEIVER_ROWS_PER_POLL);
    let mut over = Vec::new();
    for (head, fenced) in [
        (announce(OTHER, probe_prefix()), false),
        (down(OTHER), true),
    ] {
        let (_tx, mut manager, mut outputs) = rs_departure_fixture_with(MEMBERS, Some(head));
        take_receiver_rows();
        let (mut polls, mut peak, mut pinned, mut quiet) = (0, 0, 0, 0);
        while manager.source_departure.is_some() {
            quiet += usize::from(manager.source_departure_quiet());
            manager.advance_source_departure();
            polls += 1;
            peak = peak.max(take_receiver_rows());
            pinned += usize::from(manager.departure_rs_restore_pinned());
            for output in &mut outputs {
                while output.try_recv().is_ok() {}
            }
        }
        eprintln!(
            "tagged RS fenced={fenced} members={MEMBERS} keys={keys}: polls={polls} pinned_restores={pinned} max_inspected_per_poll={peak}"
        );
        assert_eq!(quiet, if fenced { polls } else { 0 }, "fenced={fenced}");
        assert!(
            pinned > 1,
            "fenced={fenced}: restores did not pin member pages"
        );
        // Classify, RS count removal, restore and emission on at most four
        // family pages.
        let bound = 4 * 12 + 4 * per_walk;
        if polls > bound || peak > POLL_LIMIT {
            over.push(format!(
                "fenced={fenced}: {polls} polls (bound {bound}), {peak} receiver-keys in one poll"
            ));
        }
        assert_rs_departure_counts(&manager, &mut outputs);
    }
    assert!(over.is_empty(), "{over:?}");
}

/// Forced readiness checkpoints that bracket policy-filtered allocation in
/// one private departure of `rows` keys toward eight receivers.
fn private_departure_allocation_checkpoints(rows: u32) -> usize {
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.outbound_row_credit_override = None;
    super::distribution_window::untimed_window(&mut manager);
    for source in [SOURCE, OTHER] {
        register_test_peer(&mut manager, peer_v4(source), 0);
    }
    let mut receivers: Vec<_> = (0..8)
        .map(|index| join(&mut manager, index, Shape::Private))
        .collect();
    seed(&mut manager, Shape::Private, rows);
    for receiver in &mut receivers {
        assert_initial(receiver, Shape::Private, rows);
    }
    let work = super::work_scaling::checkpoints_in(|| {
        manager.handle_update(down(SOURCE));
        assert!(manager.source_departure.is_some());
        while manager.source_departure.is_some() {
            manager.advance_source_departure();
        }
    });
    work.get("policy_filtered_allocation")
        .copied()
        .unwrap_or_default()
}

/// A staged prefix with no filtered candidate allocates nothing, so its
/// receiver visit needs no forced readiness checkpoint. Departure work in
/// forced checkpoints stays flat as each member's prefixes grow.
#[test]
fn unfiltered_departure_forced_checkpoints_stay_flat_in_prefixes_per_member() {
    let small = private_departure_allocation_checkpoints(256);
    let large = private_departure_allocation_checkpoints(1024);
    assert_eq!(
        small, large,
        "forced allocation checkpoints grew {small} -> {large} with prefixes per member"
    );
}

/// An owning iterator can be empty yet still hold an allocation, as when a
/// producer reserves for a member and `retain` then excludes every entry.
/// Dropping that buffer is work the forced checkpoints must still bracket.
#[test]
fn an_empty_owning_iterator_still_brackets_its_drop_with_forced_checkpoints() {
    use crate::manager::PolicyFilteredRouteKey;

    let key = PolicyFilteredRouteKey {
        target_peer: peer_v4(Ipv4Addr::new(192, 0, 2, 1)),
        source_peer: peer_v4(SOURCE),
        prefix: Prefix::V4(prefix(0)),
        path_id: 0,
    };
    let mut excluded = Vec::with_capacity(4_096);
    excluded.push(key);
    excluded.retain(|_| false);
    assert!(excluded.is_empty() && excluded.capacity() >= 4_096);
    let mut routes = HashSet::new();
    let work = super::work_scaling::checkpoints_in(|| {
        crate::manager::extend_policy_filtered_routes_with_readiness(
            &mut routes,
            excluded.into_iter(),
            &None,
        );
    });
    assert!(
        work.get("policy_filtered_allocation")
            .copied()
            .unwrap_or_default()
            >= 2,
        "an allocated empty iterator was dropped without its forced checkpoints: {work:?}"
    );
}
