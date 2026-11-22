//! Source loss through the actor FIFO, including its actual executor poll boundaries.

use std::cell::Cell;
use std::future::{Future, poll_fn};

use rustbgpd_wire::{FlowSpecComponent, FlowSpecPrefix};

use super::exportability::ReusableExactExportEncoder;
use super::lifecycle::{test_peer_up, test_routes_received};
use super::*;
use crate::manager::source_departure::take_receiver_rows;

const SOURCE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const OTHER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
const ROWS: u32 = 1024;
const POLL_LIMIT: usize = 256;

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

fn join(manager: &mut RibManager, index: u8, shape: Shape) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = peer_v4(Ipv4Addr::new(192, 0, 2, index + 1));
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
    static WINNER_DURING_DEPARTURE: Cell<bool> = const { Cell::new(false) };
}

fn observe_winner(manager: &RibManager) {
    if manager.source_departure.is_some() {
        SAW_DEPARTURE.set(true);
    }
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

async fn departure(shape: Shape, count: u8, rows: u32) -> PollCounts {
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
    assert!(manager.dirty_peers.is_empty());
    WINNER_DURING_DEPARTURE.set(false);
    manager.actor_turn_check = Some(observe_winner);
    // Queue both events before the actor starts: no read probe, sleep, or task race.
    tx.try_send(down(SOURCE)).unwrap();
    tx.try_send(announce(OTHER, probe_prefix())).unwrap();
    drop(tx);
    let mut actor = Box::pin(manager.run_actor());
    let mut streams: Vec<Vec<_>> = (0..count).map(|_| Vec::new()).collect();
    let (mut most, mut total, mut most_sent) = (0, 0, 0);
    take_receiver_rows();
    let end = poll_fn(|cx| {
        let result = actor.as_mut().poll(cx);
        let work = take_receiver_rows();
        most = most.max(work);
        total += work;
        let mut sent = 0;
        for (receiver, stream) in receivers.iter_mut().zip(&mut streams) {
            while let Ok(update) = receiver.try_recv().map(delivered) {
                sent += update.unicast_withdrawals().count() + update.flowspec_withdraw.len();
                stream.push(update);
            }
        }
        most_sent = most_sent.max(sent);
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
    assert!(
        most <= POLL_LIMIT,
        "{shape:?} K={count}: {most} receiver-keys in one physical actor poll"
    );
    assert!(
        most_sent <= POLL_LIMIT,
        "{shape:?} K={count}: {most_sent} withdrawals delivered in one physical actor poll"
    );
    assert!(end.dirty_peers.is_empty());
    poll_counts(shape, count, rows, &streams, (most, total, most_sent))
}

fn poll_counts(
    shape: Shape,
    count: u8,
    rows: u32,
    streams: &[Vec<OutboundRouteUpdate>],
    counts: (usize, usize, usize),
) -> PollCounts {
    let (most, total, most_sent) = counts;
    eprintln!(
        "{shape:?} K={count} rows={rows} max_inspected_per_poll={most} max_withdrawals_per_poll={most_sent} total_inspected={total} total_withdrawals={}",
        streams
            .iter()
            .flatten()
            .map(|update| update.unicast_withdrawals().count() + update.flowspec_withdraw.len())
            .sum::<usize>()
    );
    PollCounts {
        inspected: most,
        emitted: most_sent,
        envelope: streams
            .iter()
            .flatten()
            .map(|update| update.unicast_withdrawals().count() + update.flowspec_withdraw.len())
            .max()
            .unwrap(),
    }
}

async fn check_sizes(shape: Shape) {
    let small = Box::pin(departure(shape, 8, ROWS)).await;
    let large = Box::pin(departure(shape, 32, ROWS)).await;
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

#[tokio::test(start_paused = true)]
async fn rs_control_grouped_departure_yields_to_an_unrelated_update() {
    check_sizes(Shape::RsControl).await;
}

#[tokio::test(start_paused = true)]
async fn grouped_departure_chunks_an_uneven_member_tail_and_keeps_private_walks_small() {
    // 256 / 109 = 2 receivers per poll, with one receiver on the last page.
    // The extra source-only private registration in both fixtures cannot
    // disqualify the first fixture. A sendable private receiver must.
    let grouped = Box::pin(departure(Shape::Grouped, 5, 109)).await;
    assert_eq!((grouped.envelope, grouped.emitted), (109, 218));
    let mixed = Box::pin(departure(Shape::Mixed, 5, 109)).await;
    assert!(mixed.envelope <= 16);
    assert!(mixed.inspected <= 16 * 8 && mixed.emitted <= 16 * 8);
}

/// With one key page there is no later key boundary. All 32 members must
/// still consume the same delta, so the waiting UPDATE needs the seam
/// before the first page starts.
#[tokio::test(start_paused = true)]
async fn a_single_key_page_with_many_group_members_admits_the_waiting_update() {
    Box::pin(departure(Shape::Grouped, 32, 16)).await;
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
        manager.actor_turn_check = Some(observe_winner);
        tx.try_send(down(SOURCE)).unwrap();
        tx.try_send(RibUpdate::WireRoutesReceived(message)).unwrap();
        drop(tx);
        let end = Box::pin(manager.run_actor()).await;
        assert!(SAW_DEPARTURE.get());
        assert_eq!(WINNER_DURING_DEPARTURE.get(), !conflicting_tail);
        let mut remaining = expected_rows(DEPARTING);
        let expected: BTreeSet<_> = keys.into_iter().map(Prefix::V4).collect();
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
        assert_eq!(end.loc_rib.len(), 17);
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
    const MEMBERS: u8 = 32;
    let (tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    for source in [SOURCE, OTHER] {
        register_test_peer(&mut manager, peer_v4(source), 0);
    }
    let mut outputs: Vec<_> = (0..MEMBERS)
        .map(|index| join(&mut manager, index, Shape::Grouped))
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
            PathAttribute::Communities(vec![
                rs_body_tag(source),
                if departing { 65_101 } else { 65_100 },
            ]),
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

#[tokio::test(start_paused = true)]
async fn grouped_source_departure_rechecks_rs_control_tags_for_each_family_stage() {
    let (tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    for source in [SOURCE, OTHER] {
        register_test_peer(&mut manager, peer_v4(source), 0);
    }
    let mut outputs: Vec<_> = (0..3)
        .map(|index| join(&mut manager, index, Shape::RsControl))
        .collect();
    let first = peer_v4(Ipv4Addr::new(192, 0, 2, 1));
    let group = manager.grouped_member_of(first).unwrap();
    assert_eq!(manager.group_ribs[&group].members.len(), outputs.len());
    for source in [SOURCE, OTHER] {
        manager.handle_update(rs_stage_routes(source));
        drain_route_chunks(&mut manager);
    }
    let plain = expected_rows(u32::from(RS_STAGE_ROWS));
    let tagged: BTreeSet<_> = (0..RS_STAGE_ROWS)
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
    tx.try_send(down(SOURCE)).unwrap();
    drop(tx);
    take_receiver_rows();
    let mut actor = Box::pin(manager.run_actor());
    let mut peak = 0;
    let end = poll_fn(|cx| {
        let result = actor.as_mut().poll(cx);
        peak = peak.max(take_receiver_rows());
        result
    })
    .await;
    assert!(SAW_DEPARTURE.get());
    assert!(end.source_departure.is_none());
    for (index, output) in outputs.iter_mut().enumerate() {
        let (announced, withdrawn) = drain_rs_stage(output, OTHER);
        if index == 0 {
            assert_eq!(announced, BTreeSet::new());
            assert_eq!(withdrawn, both);
        } else {
            assert_eq!(announced, tagged);
            assert_eq!(withdrawn, plain);
        }
    }
    eprintln!(
        "RS-control plain-to-tagged departure: K=3 rows_per_family={RS_STAGE_ROWS} max_inspected_per_poll={peak}"
    );
    assert!(
        peak > 0 && peak <= POLL_LIMIT,
        "{peak} physical receiver-key inspections in one poll, limit {POLL_LIMIT}"
    );
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
        most <= POLL_LIMIT,
        "force={force}: {most} receiver-keys inspected in one departure poll"
    );
    assert!(
        most_sent <= POLL_LIMIT,
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
