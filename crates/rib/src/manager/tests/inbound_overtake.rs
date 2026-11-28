//! The overtake lane of the primary intake: a small unicast UPDATE passes
//! other sessions' queued bring-up, teardown and route messages, and every
//! other queue keeps strict FIFO. Driven through the real actor loop.

use std::sync::Mutex;

use super::exportability::ReusableExactExportEncoder;
use super::lifecycle::{test_peer_up, test_routes_received};
use super::*;
use crate::manager::parked_primaries::OVERTAKE_ROWS;
use crate::manager::source_departure::take_departure_pages;

/// The unrelated session whose small UPDATE is measured.
const OTHER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 200);
/// Routes of one rejoining member in the measured flap shape.
const MEMBER_ROWS: u32 = 572;

pub(super) fn source(index: u8) -> Ipv4Addr {
    Ipv4Addr::new(198, 51, 100, 10 + index)
}

pub(super) fn prefix(index: u32) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::from(0x0a01_0000 + index), 32)
}

/// `count` rows from `from`, starting at prefix `base`.
fn rows(from: Ipv4Addr, base: u32, count: u32) -> RibUpdate {
    test_routes_received(
        peer_v4(from),
        (base..base + count)
            .map(|index| make_route(prefix(index), from))
            .collect(),
    )
}

fn down(from: Ipv4Addr) -> RibUpdate {
    RibUpdate::PeerDown {
        peer: peer_v4(from),
        session_id: 0,
    }
}

pub(super) type Log = Arc<Mutex<Vec<String>>>;

/// One receiver's UPDATE stream as `A <prefix> <source>` and `W <prefix>`.
fn record(wire: &Log, update: &OutboundRouteUpdate) {
    let mut wire = wire.lock().unwrap();
    for &(key, _) in update.unicast_withdrawals() {
        wire.push(format!("W {key:?}"));
    }
    for route in update.announce.iter() {
        if update.announce_source_exclusion != Some(route.peer) {
            wire.push(format!("A {:?} {}", route.prefix, route.peer));
        }
    }
}

/// Drain a receiver's writer into its wire log.
pub(super) fn collect(mut outbound_rx: mpsc::Receiver<OutboundRouteUpdate>) -> Log {
    let wire = Log::default();
    let seen = Arc::clone(&wire);
    tokio::spawn(async move {
        while let Some(update) = outbound_rx.recv().await {
            record(&seen, &delivered(update));
        }
    });
    wire
}

/// A manager with `sources` registered sources plus [`OTHER`], and
/// `receivers` grouped receivers whose writers are drained. Every dispatched
/// primary is logged as `routes:<source>:<rows>` or its turn kind.
fn fleet(sources: u8, receivers: u16) -> (mpsc::Sender<RibUpdate>, RibManager, Log) {
    let (tx, manager, log, _wires) = wired_fleet(sources, receivers);
    (tx, manager, log)
}

/// [`fleet`], with each receiver's wire log.
pub(super) fn wired_fleet(
    sources: u8,
    receivers: u16,
) -> (mpsc::Sender<RibUpdate>, RibManager, Log, Vec<Log>) {
    let (tx, rx) = mpsc::channel(2048);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.outbound_row_credit_override = None;
    // Window extension by row and message bounds only, not wall-clock time.
    super::distribution_window::untimed_window(&mut manager);
    for from in (0..sources).map(source).chain([OTHER]) {
        register_test_peer(&mut manager, peer_v4(from), 0);
    }
    let mut wires = Vec::new();
    for index in 0..receivers {
        let peer = peer_v4(Ipv4Addr::from(0xc000_0201 + u32::from(index)));
        manager.handle_update(RibUpdate::SetPeerExportEncoder {
            peer,
            session_id: 1,
            encoder: ReusableExactExportEncoder::new(u64::from(index) + 1, 1),
        });
        let (outbound_tx, outbound_rx) = mpsc::channel(256);
        manager.handle_update(test_peer_up(peer, 1, outbound_tx));
        wires.push(collect(outbound_rx));
    }
    let log = Log::default();
    let seen = Arc::clone(&log);
    manager.test_primary_update_hook = Some(Arc::new(move |update: &RibUpdate| {
        let label = match update {
            RibUpdate::RoutesReceived {
                peer,
                announced,
                withdrawn,
                ..
            } => format!("routes:{peer}:{}", announced.len() + withdrawn.len()),
            other => other.actor_turn_kind().as_str().to_owned(),
        };
        PAGES.set(PAGES.get() + take_departure_pages());
        if update.session_peer() == Some(peer_v4(OTHER)) {
            PAGES_BEFORE_OTHER.set(PAGES.get());
        }
        seen.lock()
            .unwrap()
            .push(format!("{label}@{}", PAGES.get()));
    }));
    (tx, manager, log, wires)
}

thread_local! {
    /// Departure key pages opened since the run started.
    static PAGES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PAGES_BEFORE_OTHER: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Queue `queue`, close the channel and run the actor until it has applied
/// everything. Returns the manager and the dispatch order.
async fn run(
    tx: mpsc::Sender<RibUpdate>,
    manager: RibManager,
    log: &Log,
    queue: Vec<RibUpdate>,
) -> (RibManager, Vec<String>) {
    log.lock().unwrap().clear();
    take_departure_pages();
    PAGES.set(0);
    for update in queue {
        tx.try_send(update).unwrap();
    }
    drop(tx);
    let manager = Box::pin(manager.run_actor()).await;
    // Let the writers' collectors drain.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let order = log
        .lock()
        .unwrap()
        .iter()
        .map(|seen| seen.split('@').next().unwrap().to_owned())
        .collect();
    (manager, order)
}

pub(super) fn overtakes(manager: &RibManager) -> Vec<(String, f64)> {
    manager
        .metrics
        .registry()
        .gather()
        .iter()
        .find(|family| family.name() == "bgp_rib_inbound_overtake_total")
        .expect("overtake counter is registered")
        .get_metric()
        .iter()
        .filter(|metric| metric.get_counter().get_value() != 0.0)
        .map(|metric| {
            (
                metric.get_label()[0].value().to_owned(),
                metric.get_counter().get_value(),
            )
        })
        .collect()
}

fn other(count: u32) -> String {
    format!("routes:{OTHER}:{count}")
}

/// Position of [`OTHER`]'s `count`-row UPDATE in the dispatch order.
fn position(order: &[String], count: u32) -> usize {
    let label = other(count);
    order
        .iter()
        .position(|seen| *seen == label)
        .unwrap_or_else(|| panic!("{label} was not dispatched: {order:?}"))
}

/// Departure key pages opened before an unrelated UPDATE, queued behind
/// `ends` session ends, is dispatched.
async fn pages_behind_session_ends(ends: u8, strict: bool) -> usize {
    let (tx, mut manager, log) = fleet(ends, 32);
    manager.parked.strict_fifo = strict;
    for index in 0..ends {
        manager.handle_update(rows(source(index), u32::from(index) * 1_000, 64));
        drain_route_chunks(&mut manager);
    }
    // The first departure is live when the rest arrive.
    manager.handle_update(down(source(0)));
    assert!(manager.source_departure.is_some());
    let mut queue: Vec<_> = (1..ends).map(|index| down(source(index))).collect();
    queue.push(rows(OTHER, 900_000, 1));
    let (manager, order) = Box::pin(run(tx, manager, &log, queue)).await;
    assert_eq!(
        order.iter().filter(|seen| *seen == "peer_down").count(),
        usize::from(ends) - 1
    );
    let expected: &[(String, f64)] = if strict {
        &[]
    } else {
        &[("departure".to_owned(), 1.0)]
    };
    assert_eq!(overtakes(&manager), expected, "{order:?}");
    PAGES_BEFORE_OTHER.get()
}

/// An UPDATE from an unrelated source is admitted at the first key-page seam
/// of the live departure, however many session ends are queued ahead of it.
/// In strict arrival order it waits for every departure but the last: 7 key
/// pages behind 8 session ends, 31 behind 32, 49 behind 50.
#[tokio::test(start_paused = true)]
async fn an_update_behind_queued_session_ends_waits_a_flat_number_of_pages() {
    let mut table = Vec::new();
    for ends in [8, 32, 50] {
        let fifo = Box::pin(pages_behind_session_ends(ends, true)).await;
        let lane = Box::pin(pages_behind_session_ends(ends, false)).await;
        eprintln!(
            "{ends} session ends: {fifo} key pages before the UPDATE in arrival order, {lane} with the lane"
        );
        assert_eq!(
            fifo,
            usize::from(ends) - 1,
            "arrival order behind {ends} session ends"
        );
        table.push(lane);
    }
    assert_eq!(
        table,
        [0, 0, 0],
        "key pages before the UPDATE behind 8, 32 and 50 session ends"
    );
}

/// Route messages of [`MEMBER_ROWS`] rows dispatched before a one-row UPDATE
/// queued behind `messages` of them, each from its own session.
async fn messages_ahead_of_one_row(messages: u8, strict: bool) -> usize {
    let (tx, mut manager, log) = fleet(messages, 8);
    manager.parked.strict_fifo = strict;
    let mut queue: Vec<_> = (0..messages)
        .map(|index| rows(source(index), u32::from(index) * 1_000, MEMBER_ROWS))
        .collect();
    queue.push(rows(OTHER, 900_000, 1));
    let (manager, order) = Box::pin(run(tx, manager, &log, queue)).await;
    assert_eq!(order.len(), usize::from(messages) + 1);
    let expected: &[(String, f64)] = if strict {
        &[]
    } else {
        &[("receive".to_owned(), 1.0)]
    };
    assert_eq!(overtakes(&manager), expected);
    position(&order, 1)
}

/// A one-row UPDATE behind a burst of rejoining members' tables is applied
/// before any of them, whatever the burst. In strict arrival order it waits
/// for all K tables, two per distribution flush.
#[tokio::test(start_paused = true)]
async fn a_one_row_update_behind_member_tables_waits_a_flat_number_of_messages() {
    let mut table = Vec::new();
    for messages in [8, 32] {
        let fifo = Box::pin(messages_ahead_of_one_row(messages, true)).await;
        let lane = Box::pin(messages_ahead_of_one_row(messages, false)).await;
        eprintln!(
            "{messages} member tables: {fifo} applied before the one-row UPDATE in arrival order, {lane} with the lane"
        );
        assert_eq!(
            fifo,
            usize::from(messages),
            "arrival order behind {messages} tables"
        );
        table.push(lane);
    }
    assert_eq!(
        table,
        [0, 0],
        "tables applied before the UPDATE behind 8 and 32"
    );
}

/// Under a steady supply of eligible small UPDATEs the queue still advances:
/// each overtake is followed by a FIFO admission before the next one (here a
/// whole distribution window of two member tables), and candidates leave in
/// their own arrival order.
#[tokio::test(start_paused = true)]
async fn overtakes_alternate_with_the_fifo_head_in_arrival_order() {
    const TABLES: u8 = 8;
    const SMALL: u8 = 8;
    let (tx, manager, log) = fleet(TABLES + SMALL, 8);
    let table = |index: u8| rows(source(index), u32::from(index) * 1_000, MEMBER_ROWS);
    // Distinct widths name each small UPDATE in the log.
    let small = |index: u8| {
        rows(
            source(TABLES + index),
            100_000 + u32::from(index) * 100,
            u32::from(index) + 1,
        )
    };
    let queue = (0..TABLES)
        .map(table)
        .chain((0..SMALL).map(small))
        .collect();
    let (manager, order) = Box::pin(run(tx, manager, &log, queue)).await;
    let label = |index: u8, count: u32| format!("routes:{}:{count}", source(index));
    let mut expected = Vec::new();
    for round in 0..TABLES / 2 {
        expected.push(label(TABLES + round, u32::from(round) + 1));
        expected.push(label(2 * round, MEMBER_ROWS));
        expected.push(label(2 * round + 1, MEMBER_ROWS));
    }
    // The tables are gone: the rest is the queue itself.
    expected.extend((TABLES / 2..SMALL).map(|index| label(TABLES + index, u32::from(index) + 1)));
    assert_eq!(order, expected);
    let heads_between: Vec<usize> = order
        .split(|seen| !seen.ends_with(&format!(":{MEMBER_ROWS}")))
        .map(<[String]>::len)
        .filter(|&heads| heads > 0)
        .collect();
    assert_eq!(heads_between, [2; 4], "head admissions after each overtake");
    assert_eq!(overtakes(&manager), [("receive".to_owned(), 4.0)]);
}

/// Run `ahead` then [`OTHER`]'s `last` and require strict FIFO: `last` is
/// dispatched after everything queued ahead of it, and nothing is counted.
async fn assert_fifo(case: &str, ahead: Vec<RibUpdate>, last: RibUpdate) {
    let (tx, manager, log) = fleet(2, 8);
    let count = match &last {
        RibUpdate::RoutesReceived {
            announced,
            withdrawn,
            ..
        } => u32::try_from(announced.len() + withdrawn.len()).unwrap(),
        _ => unreachable!(),
    };
    let queued = ahead.len();
    let mut queue = ahead;
    queue.push(last);
    let (manager, order) = Box::pin(run(tx, manager, &log, queue)).await;
    assert_eq!(position(&order, count), queued, "{case}: {order:?}");
    assert_eq!(overtakes(&manager), [], "{case}");
}

/// The positive control for the negative cases below: the same queue shape
/// with a passable message ahead does overtake.
#[tokio::test(start_paused = true)]
async fn a_small_update_passes_another_sessions_context_and_routes() {
    let (tx, manager, log) = fleet(2, 8);
    let queue = vec![
        rows(source(0), 0, MEMBER_ROWS),
        RibUpdate::SetPeerRsControl {
            peer: peer_v4(source(1)),
            session_id: 0,
            rs_control_asn: None,
        },
        rows(OTHER, 900_000, u32::try_from(OVERTAKE_ROWS).unwrap()),
    ];
    let (manager, order) = Box::pin(run(tx, manager, &log, queue)).await;
    assert_eq!(position(&order, 16), 0, "{order:?}");
    assert_eq!(overtakes(&manager), [("receive".to_owned(), 1.0)]);
}

#[tokio::test(start_paused = true)]
async fn an_update_never_passes_its_own_sessions_messages() {
    for (case, own) in [
        ("route message", rows(OTHER, 800_000, MEMBER_ROWS)),
        (
            "context",
            RibUpdate::SetPeerRsControl {
                peer: peer_v4(OTHER),
                session_id: 0,
                rs_control_asn: None,
            },
        ),
    ] {
        Box::pin(assert_fifo(
            case,
            vec![rows(source(0), 0, MEMBER_ROWS), own],
            rows(OTHER, 900_000, 1),
        ))
        .await;
    }
}

#[tokio::test(start_paused = true)]
async fn an_update_never_passes_a_route_message_that_shares_a_prefix() {
    // Announced by the message ahead.
    Box::pin(assert_fifo(
        "announced ahead",
        vec![rows(source(0), 0, MEMBER_ROWS)],
        rows(OTHER, MEMBER_ROWS - 1, 1),
    ))
    .await;
    // Withdrawn by the message ahead.
    let mut withdrawal = rows(source(0), 0, MEMBER_ROWS);
    let RibUpdate::RoutesReceived { withdrawn, .. } = &mut withdrawal else {
        unreachable!()
    };
    withdrawn.push((Prefix::V4(prefix(900_000)), 0));
    Box::pin(assert_fifo(
        "withdrawn ahead",
        vec![withdrawal],
        rows(OTHER, 900_000, 1),
    ))
    .await;
}

#[tokio::test(start_paused = true)]
async fn a_wide_or_non_unicast_update_keeps_fifo() {
    let wide = u32::try_from(OVERTAKE_ROWS).unwrap() + 1;
    Box::pin(assert_fifo(
        "17 rows",
        vec![rows(source(0), 0, MEMBER_ROWS)],
        rows(OTHER, 900_000, wide),
    ))
    .await;
    let mut flowspec = rows(OTHER, 900_000, 1);
    let RibUpdate::RoutesReceived {
        flowspec_announced, ..
    } = &mut flowspec
    else {
        unreachable!()
    };
    flowspec_announced.push(make_flowspec_route(OTHER));
    Box::pin(assert_fifo(
        "flowspec rider",
        vec![rows(source(0), 0, MEMBER_ROWS)],
        flowspec,
    ))
    .await;
}

/// Every kind off the passable allowlist closes the lane for what is behind
/// it: End-of-RIB, route refresh, a policy change, an injection and a query.
#[tokio::test(start_paused = true)]
async fn a_message_off_the_allowlist_closes_the_lane() {
    type Barrier = Box<dyn Fn() -> RibUpdate>;
    let barriers: Vec<(&str, Barrier)> = vec![
        (
            "end_of_rib",
            Box::new(|| RibUpdate::EndOfRib {
                peer: peer_v4(source(1)),
                session_id: 0,
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            }),
        ),
        (
            "route_refresh",
            Box::new(|| RibUpdate::RouteRefreshRequest {
                queued: Arc::default(),
                session_id: 0,
                peer: peer_v4(source(1)),
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            }),
        ),
        (
            "outbound_policy",
            Box::new(|| RibUpdate::ReplacePeerExportPolicy {
                peer: peer_v4(source(1)),
                export_policy: None,
                reply: oneshot::channel().0,
            }),
        ),
        (
            "injection",
            Box::new(|| RibUpdate::InjectRoute {
                route: make_route(prefix(700_000), Ipv4Addr::new(192, 0, 2, 250)),
                reply: oneshot::channel().0,
            }),
        ),
        (
            "query",
            Box::new(|| RibUpdate::QueryLocRibCount {
                reply: oneshot::channel().0,
            }),
        ),
        (
            "peer_lifecycle",
            Box::new(|| RibUpdate::PeerGracefulRestart {
                peer: peer_v4(source(1)),
                session_id: 0,
                restart_time: 120,
                stale_routes_time: 360,
                gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
                peer_notification_gr: false,
                peer_llgr_capable: false,
                peer_llgr_families: vec![],
                llgr_stale_time: 0,
            }),
        ),
    ];
    for (case, barrier) in barriers {
        Box::pin(assert_fifo(
            case,
            vec![rows(source(0), 0, MEMBER_ROWS), barrier()],
            rows(OTHER, 900_000, 1),
        ))
        .await;
    }
}

/// An owner that counts queued primaries keeps the lane closed: a captured
/// first-group commit frontier here. The same queue overtakes once it clears.
#[tokio::test(start_paused = true)]
async fn a_captured_commit_frontier_keeps_the_lane_closed() {
    let (tx, mut manager, _log) = fleet(1, 8);
    tx.try_send(rows(source(0), 0, MEMBER_ROWS)).unwrap();
    tx.try_send(rows(OTHER, 900_000, 1)).unwrap();
    manager.capture_first_group_commit_frontier();
    assert!(
        manager
            .take_overtake(RibInboundOvertakeSeam::Drain)
            .is_none()
    );
    assert_eq!(manager.parked.len(), 0, "a closed lane reads nothing ahead");
    manager.clear_first_group_commit_frontier();
    let passed = manager
        .take_overtake(RibInboundOvertakeSeam::Drain)
        .expect("the lane is open");
    assert_eq!(passed.session_peer(), Some(peer_v4(OTHER)));
    assert!(
        manager
            .take_overtake(RibInboundOvertakeSeam::Drain)
            .is_none(),
        "the head is owed before another overtake"
    );
}

/// The departing session owns the winning path for a prefix, and another
/// session's UPDATE for that prefix is queued behind its `PeerDown`. The
/// UPDATE keeps FIFO, and a stable receiver sees exactly the UPDATE and
/// withdrawal sequence of strict FIFO processing: passing the session end
/// would replace the withdrawal and announcement with one implicit replace.
#[tokio::test(start_paused = true)]
async fn an_update_never_passes_the_session_end_of_its_prefixes_holder() {
    const SHARED: u32 = 500_000;
    let mut sequences = Vec::new();
    for strict in [true, false] {
        let (tx, mut manager, log, wires) = wired_fleet(2, 8);
        manager.parked.strict_fifo = strict;
        manager.handle_update(rows(source(1), SHARED, 1));
        drain_route_chunks(&mut manager);
        assert_eq!(
            manager
                .loc_rib
                .get(&Prefix::V4(prefix(SHARED)))
                .map(|best| best.peer),
            Some(peer_v4(source(1))),
            "the departing session holds the winning path"
        );
        let queue = vec![
            rows(source(0), 0, MEMBER_ROWS),
            down(source(1)),
            rows(OTHER, SHARED, 1),
        ];
        let (manager, order) = Box::pin(run(tx, manager, &log, queue)).await;
        assert_eq!(position(&order, 1), 2, "strict={strict}: {order:?}");
        assert_eq!(overtakes(&manager), [], "strict={strict}");
        let wire = wires[0].lock().unwrap().clone();
        let shared = format!("{:?}", Prefix::V4(prefix(SHARED)));
        let on_shared: Vec<_> = wire
            .iter()
            .filter(|event| event.contains(&shared))
            .cloned()
            .collect();
        assert_eq!(
            on_shared,
            [
                format!("A {shared} {}", source(1)),
                format!("W {shared}"),
                format!("A {shared} {OTHER}"),
            ],
            "strict={strict}"
        );
        // Rows of one envelope leave in table order, which is not stable
        // between two managers: compare the prefix's sequence exactly and
        // the rest as a multiset.
        let mut rest = wire;
        rest.sort();
        sequences.push((on_shared, rest));
    }
    assert_eq!(
        sequences[0], sequences[1],
        "the lane changed a receiver's wire sequence"
    );
}

/// One seam classifies at most [`INSPECT_MESSAGES_PER_SEAM`] queued messages,
/// and the deque never buffers more than [`PARK_LIMIT`].
#[tokio::test(start_paused = true)]
async fn one_seam_inspects_a_bounded_number_of_queued_messages() {
    use crate::manager::parked_primaries::{INSPECT_MESSAGES_PER_SEAM, PARK_LIMIT};
    let context = || RibUpdate::SetPeerRsControl {
        peer: peer_v4(source(1)),
        session_id: 0,
        rs_control_asn: None,
    };
    let (tx, mut manager, _log) = fleet(2, 2);
    tx.try_send(rows(source(0), 0, MEMBER_ROWS)).unwrap();
    for _ in 0..INSPECT_MESSAGES_PER_SEAM {
        tx.try_send(context()).unwrap();
    }
    tx.try_send(rows(OTHER, 900_000, 1)).unwrap();
    assert!(
        manager
            .take_overtake(RibInboundOvertakeSeam::Drain)
            .is_none(),
        "the UPDATE lies beyond one seam's inspection"
    );
    assert_eq!(manager.parked.len(), INSPECT_MESSAGES_PER_SEAM);
    assert!(
        manager
            .take_overtake(RibInboundOvertakeSeam::Drain)
            .is_some()
    );

    let (tx, mut manager, _log) = fleet(2, 2);
    tx.try_send(rows(source(0), 0, MEMBER_ROWS)).unwrap();
    for _ in 0..PARK_LIMIT {
        tx.try_send(context()).unwrap();
    }
    tx.try_send(rows(OTHER, 900_000, 1)).unwrap();
    for _ in 0..8 {
        assert!(
            manager
                .take_overtake(RibInboundOvertakeSeam::Drain)
                .is_none()
        );
        assert!(manager.parked.len() <= PARK_LIMIT);
    }
    assert_eq!(manager.parked.len(), PARK_LIMIT);
    assert_eq!(manager.primary_backlog(), PARK_LIMIT + 2);
}

/// Every owner that counts or holds queued primaries keeps the lane closed
/// and unread: an armed expiry cutoff, a captured or sealed first-group
/// commit frontier, and a deferred first-group intent.
#[tokio::test(start_paused = true)]
async fn an_expiry_cutoff_or_first_group_fence_keeps_the_lane_closed() {
    type Fence = (&'static str, fn(&mut RibManager), fn(&mut RibManager));
    let fences: [Fence; 4] = [
        (
            "expiry cutoff",
            |manager| {
                let now = tokio::time::Instant::now();
                let backlog = manager.primary_backlog();
                manager
                    .expiry_cutoffs
                    .observe(ExpiryTimer::GrStale, Some(now), now, backlog);
            },
            |manager| manager.expiry_cutoffs.clear(ExpiryTimer::GrStale),
        ),
        (
            "captured frontier",
            RibManager::capture_first_group_commit_frontier,
            RibManager::clear_first_group_commit_frontier,
        ),
        (
            "sealed frontier",
            RibManager::seal_first_group_commit_frontier,
            RibManager::clear_first_group_commit_frontier,
        ),
        (
            "deferred intent",
            |manager| {
                manager
                    .first_group_deferred_intents
                    .push_back(rows(source(1), 5_000, 1));
            },
            |manager| manager.first_group_deferred_intents.clear(),
        ),
    ];
    for (case, close, open) in fences {
        let (tx, mut manager, _log) = fleet(2, 2);
        tx.try_send(rows(source(0), 0, MEMBER_ROWS)).unwrap();
        tx.try_send(rows(OTHER, 900_000, 1)).unwrap();
        close(&mut manager);
        assert!(
            manager
                .take_overtake(RibInboundOvertakeSeam::Drain)
                .is_none(),
            "{case}"
        );
        assert_eq!(
            manager.parked.len(),
            0,
            "{case}: a closed lane reads nothing"
        );
        open(&mut manager);
        assert!(
            manager
                .take_overtake(RibInboundOvertakeSeam::Drain)
                .is_some(),
            "{case}: the lane reopens"
        );
    }
}

/// A live departure advances at least one key page between two overtakes,
/// however many eligible small UPDATEs wait behind its fenced head.
#[tokio::test(start_paused = true)]
async fn a_departure_opens_a_key_page_between_overtakes() {
    const SMALL: u8 = 6;
    let (tx, mut manager, log) = fleet(2 + SMALL, 32);
    // Three quiet key pages.
    manager.handle_update(rows(source(0), 0, 3_000));
    drain_route_chunks(&mut manager);
    manager.handle_update(down(source(0)));
    assert!(manager.source_departure.is_some());
    let mut queue = vec![down(source(1))];
    queue.extend((0..SMALL).map(|index| rows(source(2 + index), 100_000 + u32::from(index), 1)));
    let (manager, _) = Box::pin(run(tx, manager, &log, queue)).await;
    let pages: Vec<usize> = log
        .lock()
        .unwrap()
        .iter()
        .filter(|seen| seen.starts_with("routes:"))
        .map(|seen| seen.split('@').nth(1).unwrap().parse().unwrap())
        .collect();
    // One at the seam before each of the three key pages.
    let passed = overtakes(&manager)
        .iter()
        .find(|(seam, _)| seam == "departure")
        .map_or(0.0, |(_, count)| *count);
    assert!(
        passed >= 3.0,
        "{passed} overtakes at departure seams: {pages:?}"
    );
    for pair in pages[..3].windows(2) {
        assert!(
            pair[1] > pair[0],
            "two overtakes at one key-page seam: pages {pages:?}"
        );
    }
}

/// A steady supply of eligible small UPDATEs cannot starve queued session
/// work: between two overtakes the head is admitted, here one context
/// message each time.
#[tokio::test(start_paused = true)]
async fn the_head_advances_between_overtakes() {
    const HEADS: u8 = 6;
    let (tx, manager, log) = fleet(2 * HEADS, 4);
    let mut queue = vec![rows(source(0), 0, MEMBER_ROWS)];
    queue.extend((1..HEADS).map(|index| RibUpdate::SetPeerRsControl {
        peer: peer_v4(source(index)),
        session_id: 0,
        rs_control_asn: None,
    }));
    queue
        .extend((0..HEADS).map(|index| rows(source(HEADS + index), 100_000 + u32::from(index), 1)));
    let (manager, order) = Box::pin(run(tx, manager, &log, queue)).await;
    let small = |seen: &String| seen.ends_with(":1");
    let passed = overtakes(&manager)
        .iter()
        .map(|(_, count)| *count)
        .sum::<f64>();
    assert!(
        (passed - f64::from(HEADS)).abs() < 0.5,
        "{passed}: {order:?}"
    );
    // Every overtake but the last is followed by a head admission.
    let heads_after: Vec<usize> = order.split(small).skip(1).map(<[String]>::len).collect();
    assert_eq!(heads_after, [1; HEADS as usize], "{order:?}");
}
