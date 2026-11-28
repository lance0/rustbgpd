//! The overtake lane of the primary intake: a small unicast UPDATE passes
//! other sessions' queued bring-up, teardown and route messages, and every
//! other queue keeps strict FIFO. Driven through the real actor loop.

use std::sync::Mutex;

use super::exportability::ReusableExactExportEncoder;
use super::lifecycle::{test_peer_up, test_routes_received};
use super::*;
use crate::manager::Overtake;
use crate::manager::parked_primaries::OVERTAKE_ROWS;
use crate::manager::source_departure::take_departure_pages;

/// The unrelated session whose small UPDATE is measured.
const OTHER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 200);
/// Routes of one rejoining member in the measured flap shape.
const MEMBER_ROWS: u32 = 572;
/// A session no source has registered: context that names it is staging.
const STAGED: u64 = 9;

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

/// One receiver's UPDATE stream as `A <prefix> <source>`, `W <prefix>` and
/// `E <family>` for an End-of-RIB marker, which follows its envelope's rows.
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
    for (afi, safi) in &update.end_of_rib {
        wire.push(format!("E {afi:?}/{safi:?}"));
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

/// [`fleet`] with private receivers: each has its own export policy.
fn private_fleet(sources: u8, receivers: u16) -> (mpsc::Sender<RibUpdate>, RibManager, Log) {
    let (tx, manager, log, _wires) = build_fleet(sources, receivers, true);
    (tx, manager, log)
}

/// [`fleet`], with each receiver's wire log.
pub(super) fn wired_fleet(
    sources: u8,
    receivers: u16,
) -> (mpsc::Sender<RibUpdate>, RibManager, Log, Vec<Log>) {
    build_fleet(sources, receivers, false)
}

fn build_fleet(
    sources: u8,
    receivers: u16,
    private: bool,
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
        let mut up = test_peer_up(peer, 1, outbound_tx);
        if private {
            let RibUpdate::PeerUp { export_policy, .. } = &mut up else {
                unreachable!()
            };
            *export_policy = Some(super::update_groups::peer_context_chain());
        }
        manager.handle_update(up);
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
        // The live departure has not yet done a poll's worth of its own
        // work, so the UPDATE passes at the receive seam once it ends.
        &[("receive".to_owned(), 1.0)]
    };
    assert_eq!(overtakes(&manager), expected, "{order:?}");
    PAGES_BEFORE_OTHER.get()
}

/// An UPDATE from an unrelated source is admitted when the live departure
/// ends, however many session ends are queued ahead of it.
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
        [1, 1, 1],
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
            session_id: STAGED,
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
                session_id: STAGED,
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
    assert!(matches!(
        manager.take_overtake(RibInboundOvertakeSeam::Drain),
        Overtake::Keep | Overtake::Read
    ));
    assert_eq!(manager.parked.len(), 0, "a closed lane reads nothing ahead");
    manager.clear_first_group_commit_frontier();
    let Overtake::Admit(passed) = manager.take_overtake(RibInboundOvertakeSeam::Drain) else {
        panic!("the lane is open");
    };
    assert_eq!(passed.session_peer(), Some(peer_v4(OTHER)));
    assert!(
        matches!(
            manager.take_overtake(RibInboundOvertakeSeam::Drain),
            Overtake::Keep | Overtake::Read
        ),
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
        session_id: STAGED,
        rs_control_asn: None,
    };
    let (tx, mut manager, _log) = fleet(2, 2);
    tx.try_send(rows(source(0), 0, MEMBER_ROWS)).unwrap();
    for _ in 0..INSPECT_MESSAGES_PER_SEAM {
        tx.try_send(context()).unwrap();
    }
    tx.try_send(rows(OTHER, 900_000, 1)).unwrap();
    assert!(
        matches!(
            manager.take_overtake(RibInboundOvertakeSeam::Drain),
            Overtake::Keep | Overtake::Read
        ),
        "the UPDATE lies beyond one seam's inspection"
    );
    // The head, and one seam's worth behind it.
    assert_eq!(manager.parked.len(), INSPECT_MESSAGES_PER_SEAM + 1);
    assert!(matches!(
        manager.take_overtake(RibInboundOvertakeSeam::Drain),
        Overtake::Admit(_)
    ));

    let (tx, mut manager, _log) = fleet(2, 2);
    tx.try_send(rows(source(0), 0, MEMBER_ROWS)).unwrap();
    for _ in 0..PARK_LIMIT {
        tx.try_send(context()).unwrap();
    }
    tx.try_send(rows(OTHER, 900_000, 1)).unwrap();
    for _ in 0..8 {
        assert!(matches!(
            manager.take_overtake(RibInboundOvertakeSeam::Drain),
            Overtake::Keep | Overtake::Read
        ));
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
            matches!(
                manager.take_overtake(RibInboundOvertakeSeam::Drain),
                Overtake::Keep | Overtake::Read
            ),
            "{case}"
        );
        assert_eq!(
            manager.parked.len(),
            0,
            "{case}: a closed lane reads nothing"
        );
        open(&mut manager);
        assert!(
            matches!(
                manager.take_overtake(RibInboundOvertakeSeam::Drain),
                Overtake::Admit(_)
            ),
            "{case}: the lane reopens"
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
        session_id: STAGED,
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

/// Receiver-keys a departure of `keys` routes owes this fleet's roster.
fn departure_rows(manager: &RibManager, keys: u32) -> usize {
    usize::try_from(keys).unwrap() * (manager.outbound_peers.len() - 1)
}

/// The cumulative key pages at each small UPDATE's dispatch, in order.
fn pages_at_small_dispatches(log: &Log) -> Vec<usize> {
    log.lock()
        .unwrap()
        .iter()
        .filter(|seen| seen.starts_with("routes:"))
        .map(|seen| seen.split('@').nth(1).unwrap().parse().unwrap())
        .collect()
}

fn departure_overtakes(manager: &RibManager) -> usize {
    let passed = overtakes(manager)
        .iter()
        .find(|(seam, _)| seam == "departure")
        .map_or(0.0, |(_, count)| *count);
    (0..1_000_u32)
        .find(|count| (f64::from(*count) - passed).abs() < 0.5)
        .map(|count| usize::try_from(count).unwrap())
        .expect("a small count")
}

/// One departure of `keys` routes toward `receivers` receivers, with a
/// fenced session end and `small` always-eligible UPDATEs queued behind it.
/// Returns the manager, the departure-seam overtakes, the key pages opened
/// and the pages at each small dispatch.
async fn departure_under_a_small_stream(
    private: bool,
    receivers: u16,
    keys: u32,
    small: u8,
) -> (RibManager, usize, usize, Vec<usize>) {
    let (tx, mut manager, log) = if private {
        private_fleet(2 + small, receivers)
    } else {
        fleet(2 + small, receivers)
    };
    manager.handle_update(rows(source(0), 0, keys));
    drain_route_chunks(&mut manager);
    manager.handle_update(down(source(0)));
    assert!(manager.source_departure.is_some());
    let mut queue = vec![down(source(1))];
    queue.extend((0..small).map(|index| rows(source(2 + index), 100_000 + u32::from(index), 1)));
    let (manager, _) = Box::pin(run(tx, manager, &log, queue)).await;
    let passed = departure_overtakes(&manager);
    (
        manager,
        passed,
        PAGES.get(),
        pages_at_small_dispatches(&log),
    )
}

/// A departure lets one parked UPDATE pass per [`RECEIVER_ROWS_PER_POLL`]
/// receiver-keys of its own completed pages, so the UPDATEs it admits are
/// bounded by its work and not by how many key pages that work is cut into.
/// A private roster cuts the same departure into many narrow pages.
#[tokio::test(start_paused = true)]
async fn departure_overtakes_are_bounded_by_its_own_work_whatever_the_page_width() {
    use crate::manager::source_departure::RECEIVER_ROWS_PER_POLL;
    const KEYS: u32 = 3_000;
    const RECEIVERS: u16 = 8;
    const SMALL: u8 = 16;
    let mut pages = Vec::new();
    for private in [false, true] {
        let (manager, passed, opened, at) = Box::pin(departure_under_a_small_stream(
            private, RECEIVERS, KEYS, SMALL,
        ))
        .await;
        let bound = departure_rows(&manager, KEYS) / RECEIVER_ROWS_PER_POLL;
        eprintln!(
            "private={private}: {opened} key pages, {passed} departure overtakes, bound {bound}"
        );
        assert!(
            (1..=bound).contains(&passed),
            "private={private}: {passed} overtakes over {opened} pages, bound {bound}"
        );
        // A key page completes between two overtakes.
        for pair in at[..passed].windows(2) {
            assert!(pair[1] > pair[0], "private={private}: pages {at:?}");
        }
        pages.push(opened);
    }
    assert!(
        pages[1] > 2 * pages[0],
        "the private roster should cut the departure into narrower pages: {pages:?}"
    );
}

thread_local! {
    /// Overtakes counted at the previous actor turn check, and whether any
    /// turn both ran more than one departure unit and admitted one.
    static TURN: std::cell::Cell<(usize, bool)> = const { std::cell::Cell::new((0, false)) };
}

fn observe_departure_turn(manager: &RibManager) {
    let (before, mixed) = TURN.get();
    let now = departure_overtakes(manager);
    TURN.set((
        now,
        mixed || (now > before && manager.departure_units_this_turn > 1),
    ));
}

/// A key page that completes in the middle of a run of quiet units ends the
/// run. The parked UPDATE is admitted as the first unit of the next poll, so
/// no poll both advances the departure and reads ahead and dispatches.
#[tokio::test(start_paused = true)]
async fn a_departure_seam_admits_only_as_the_first_unit_of_a_poll() {
    use crate::manager::source_departure::set_quiet_unit_costs;
    let (tx, mut manager, log) = fleet(3, 32);
    manager.handle_update(rows(source(0), 0, 3_000));
    drain_route_chunks(&mut manager);
    manager.handle_update(down(source(0)));
    assert!(manager.source_departure.is_some());
    TURN.set((0, false));
    manager.actor_turn_check = Some(observe_departure_turn);
    // Several quiet units fit one 10 ms poll; a dispatch costs half of it.
    set_quiet_unit_costs(Some([Duration::from_millis(1), Duration::from_millis(5)]));
    let queue = vec![down(source(1)), rows(source(2), 100_000, 1)];
    let (manager, _) = Box::pin(run(tx, manager, &log, queue)).await;
    set_quiet_unit_costs(None);
    assert_eq!(departure_overtakes(&manager), 1);
    assert!(
        !TURN.get().1,
        "a poll advanced the departure and admitted the parked UPDATE"
    );
}

/// The paced departure of D still owes prefix P when Y's UPDATE for P is
/// parked behind E's session end. P is not independent of the live
/// departure, so the UPDATE keeps FIFO at every key-page seam and a stable
/// receiver's sequence for P is that of strict arrival order.
#[tokio::test(start_paused = true)]
async fn an_update_for_a_key_the_live_departure_owes_keeps_fifo() {
    const KEYS: u32 = 3_000;
    let mut sequences = Vec::new();
    for strict in [true, false] {
        let (tx, mut manager, log, wires) = wired_fleet(2, 32);
        manager.parked.strict_fifo = strict;
        manager.handle_update(rows(source(0), 0, KEYS));
        drain_route_chunks(&mut manager);
        // Table order is not stable between managers: take a key the
        // departure reaches last.
        manager.handle_update(down(source(0)));
        let owed = Prefix::V4(prefix(0));
        assert!(manager.source_departure.is_some());
        let queue = vec![down(source(1)), rows(OTHER, 0, 1)];
        let (manager, order) = Box::pin(run(tx, manager, &log, queue)).await;
        assert_eq!(
            departure_overtakes(&manager),
            0,
            "strict={strict}: {order:?}"
        );
        let key = format!("{owed:?}");
        let on_key: Vec<_> = wires[0]
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.contains(&key))
            .cloned()
            .collect();
        sequences.push(on_key);
    }
    assert_eq!(sequences[0], sequences[1]);
    assert_eq!(
        sequences[0].len(),
        3,
        "announce, withdraw, announce: {sequences:?}"
    );
}

/// Sixty-five session ends are parked, the last one of a session that holds
/// prefix P, then a small UPDATE for P. Beyond [`RESET_SESSIONS_LIMIT`]
/// sessions nothing is checked and nothing passes.
#[tokio::test(start_paused = true)]
async fn nothing_passes_more_session_ends_than_the_lane_checks() {
    use crate::manager::parked_primaries::RESET_SESSIONS_LIMIT;
    let ends = u8::try_from(RESET_SESSIONS_LIMIT).unwrap() + 1;
    let (tx, mut manager, log) = fleet(ends + 1, 2);
    manager.handle_update(rows(source(ends), 500_000, 1));
    drain_route_chunks(&mut manager);
    let mut queue = vec![rows(source(0), 0, MEMBER_ROWS)];
    queue.extend((1..=ends).map(|index| down(source(index))));
    queue.push(rows(OTHER, 500_000, 1));
    let queued = queue.len() - 1;
    let (manager, order) = Box::pin(run(tx, manager, &log, queue)).await;
    assert_eq!(position(&order, 1), queued, "{order:?}");
    assert_eq!(overtakes(&manager), []);
}

/// Reading ahead stops once 65,536 route rows are parked, with the message
/// that crosses that parked too. Rows are hashed only when a small UPDATE
/// that could pass arrives, within each seam's budget, so the prefix index
/// never holds more than the parked rows.
#[tokio::test(start_paused = true)]
async fn parked_and_hashed_rows_stay_within_their_caps() {
    use crate::manager::parked_primaries::{INSPECT_WORK_PER_SEAM, PARK_ROW_LIMIT};
    const TABLE: u32 = 1_023;
    const CROSSING: u32 = 1_000;
    let tables = u8::try_from(PARK_ROW_LIMIT / 1_023).unwrap();
    let (tx, mut manager, _log) = fleet(tables + 2, 2);
    for index in 0..tables {
        tx.try_send(rows(source(index), u32::from(index) * 2_000, TABLE))
            .unwrap();
    }
    // 65,472 rows are parked; this one makes 66,472.
    tx.try_send(rows(source(tables), 400_000, CROSSING))
        .unwrap();
    tx.try_send(rows(OTHER, 900_000, 1)).unwrap();
    for _ in 0..4 {
        let work =
            manager
                .parked
                .read_ahead(&mut manager.rx, &manager.ribs, &|_: PeerId, _: u64| false);
        assert_eq!(work, 0, "nothing that could pass has arrived");
    }
    assert_eq!(
        manager.parked.len(),
        usize::from(tables) + 1,
        "nothing is read past the row cap"
    );
    assert_eq!(
        manager.parked.indexed_rows(),
        0,
        "tables alone are not hashed"
    );
    assert_eq!(manager.primary_backlog(), usize::from(tables) + 2);

    // The head leaves: the small UPDATE is read, and the rows ahead of it
    // are hashed over two seams.
    assert!(manager.parked.take().is_some());
    let mut seams = 0;
    while manager.parked.candidate().is_none() {
        let work =
            manager
                .parked
                .read_ahead(&mut manager.rx, &manager.ribs, &|_: PeerId, _: u64| false);
        assert!(
            (1..=INSPECT_WORK_PER_SEAM).contains(&work),
            "{work} hashes in one seam"
        );
        assert!(manager.parked.indexed_rows() <= manager.parked.parked_rows());
        assert!(manager.parked.parked_rows() <= PARK_ROW_LIMIT);
        seams += 1;
        assert!(seams <= 3, "the UPDATE was not decided");
    }
    assert_eq!(seams, 2);
    assert_eq!(
        manager.parked.indexed_rows(),
        usize::from(tables - 1) * usize::try_from(TABLE).unwrap()
            + usize::try_from(CROSSING).unwrap()
    );
}

/// Rows are hashed only for a message that could pass, a read-ahead that
/// hashed rows ends its poll even when nothing passes, and a burst of tables
/// with no small UPDATE behind it is never hashed.
#[tokio::test(start_paused = true)]
async fn only_a_message_that_could_pass_is_worth_hashing_for() {
    let (tx, mut manager, _log) = fleet(2, 2);
    tx.try_send(rows(source(0), 0, MEMBER_ROWS)).unwrap();
    tx.try_send(rows(source(1), 1_000, MEMBER_ROWS)).unwrap();
    assert!(matches!(
        manager.take_overtake(RibInboundOvertakeSeam::Receive),
        Overtake::Keep
    ));
    assert_eq!(manager.parked.len(), 2);
    assert_eq!(manager.parked.indexed_rows(), 0, "tables are not hashed");
    // A small UPDATE that shares a prefix with the first table: the rows
    // ahead are hashed, it does not pass, and the seam yields.
    tx.try_send(rows(OTHER, 0, 1)).unwrap();
    assert!(matches!(
        manager.take_overtake(RibInboundOvertakeSeam::Receive),
        Overtake::Read
    ));
    assert_eq!(
        manager.parked.indexed_rows(),
        2 * usize::try_from(MEMBER_ROWS).unwrap()
    );
    // Nothing new to read: the next look is free again.
    assert!(matches!(
        manager.take_overtake(RibInboundOvertakeSeam::Receive),
        Overtake::Keep
    ));

    // A head that is itself a small UPDATE is never passed: nothing is read.
    let (tx, mut manager, _log) = fleet(2, 2);
    tx.try_send(rows(source(0), 0, 1)).unwrap();
    tx.try_send(rows(source(1), 1_000, MEMBER_ROWS)).unwrap();
    tx.try_send(rows(OTHER, 900_000, 1)).unwrap();
    assert!(matches!(
        manager.take_overtake(RibInboundOvertakeSeam::Receive),
        Overtake::Keep
    ));
    assert_eq!(manager.parked.len(), 1);
}

/// A receiver capped at one prefix gives its slot to routes in arrival
/// order, so unrelated prefixes are not independent there: an UPDATE that
/// passed a queued table would take the slot the table's first route gets.
/// Any configured outbound prefix limit keeps strict arrival order.
#[tokio::test(start_paused = true)]
async fn an_outbound_prefix_limit_keeps_arrival_order_for_the_capped_slot() {
    use super::outbound_prefix_limits::{apply, limit_config, prepare};
    // The table fills a distribution window by itself, so in arrival order
    // its routes reach the capped receiver before the later UPDATE does.
    const TABLE: u32 = 1_100;
    let (tx, mut manager, log, wires) = wired_fleet(1, 4);
    let capped = peer_v4(Ipv4Addr::from(0xc000_0201));
    prepare(
        &mut manager,
        1,
        limit_config(&[(capped, Some(1), None)], &[]),
    )
    .expect("preflight passes");
    apply(&mut manager, 1, true).expect("activation passes");
    let queue = vec![rows(source(0), 0, TABLE), rows(OTHER, 900_000, 1)];
    let (manager, order) = Box::pin(run(tx, manager, &log, queue)).await;
    assert_eq!(overtakes(&manager), [], "{order:?}");
    let passed = format!("{:?}", Prefix::V4(prefix(900_000)));
    let routes = |wire: &Log| -> Vec<String> {
        wire.lock()
            .unwrap()
            .iter()
            .filter(|event| !event.starts_with("E "))
            .cloned()
            .collect()
    };
    let wire = routes(&wires[0]);
    assert_eq!(wire.len(), 1, "one slot: {wire:?}");
    assert!(
        !wire[0].contains(&passed),
        "the later UPDATE took the capped receiver's slot: {wire:?}"
    );
    // An uncapped receiver holds everything.
    assert_eq!(routes(&wires[1]).len(), usize::try_from(TABLE).unwrap() + 1);
}

/// The remaining owners that hold queued primaries each keep the lane
/// closed and unread: a full release read buffer, an owed ORR rebuild and
/// the ingest-stall fault injection.
#[tokio::test(start_paused = true)]
async fn a_full_read_buffer_an_owed_rebuild_or_an_ingest_stall_keeps_the_lane_closed() {
    type Fence = (&'static str, fn(&mut RibManager), fn(&mut RibManager));
    let fences: [Fence; 3] = [
        (
            "release read buffer",
            |manager| {
                for _ in 0..manager.rx.max_capacity() {
                    manager
                        .release_primary_reads
                        .push_back(RibUpdate::QueryLocRibCount {
                            reply: oneshot::channel().0,
                        });
                }
            },
            |manager| manager.release_primary_reads.clear(),
        ),
        (
            "owed ORR rebuild",
            |manager| manager.orr_rebuild_owed_updates = 1,
            |manager| manager.orr_rebuild_owed_updates = 0,
        ),
        (
            "ingest stall",
            |manager| manager.test_ingest_stall = Some(Duration::from_millis(1)),
            |manager| manager.test_ingest_stall = None,
        ),
    ];
    for (case, close, open) in fences {
        let (tx, mut manager, _log) = fleet(2, 2);
        tx.try_send(rows(source(0), 0, MEMBER_ROWS)).unwrap();
        tx.try_send(rows(OTHER, 900_000, 1)).unwrap();
        close(&mut manager);
        assert!(
            matches!(
                manager.take_overtake(RibInboundOvertakeSeam::Drain),
                Overtake::Keep
            ),
            "{case}"
        );
        assert_eq!(
            manager.parked.len(),
            0,
            "{case}: a closed lane reads nothing"
        );
        open(&mut manager);
        assert!(
            matches!(
                manager.take_overtake(RibInboundOvertakeSeam::Drain),
                Overtake::Admit(_)
            ),
            "{case}: the lane reopens"
        );
    }
}

/// Session context is passable only as staging for a session that has not
/// registered. A context change of a live session takes effect for later
/// exports without resyncing earlier ones, so an UPDATE behind it keeps
/// FIFO. The handler itself tells the two apart by the live session record.
#[tokio::test(start_paused = true)]
async fn a_live_sessions_context_change_keeps_fifo_and_staging_is_passed() {
    let context = |session_id: u64| RibUpdate::SetPeerPolicyContext {
        peer: peer_v4(source(1)),
        session_id,
        peer_group: Some("moved".to_owned()),
    };
    // Source 1 registered session 0.
    Box::pin(assert_fifo(
        "live context",
        vec![rows(source(0), 0, MEMBER_ROWS), context(0)],
        rows(OTHER, 900_000, 1),
    ))
    .await;
    // Staging for the session a queued PeerUp ahead is about to register.
    Box::pin(assert_fifo(
        "context behind its PeerUp",
        vec![
            rows(source(0), 0, MEMBER_ROWS),
            registering_peer_up(peer_v4(source(1)), STAGED),
            context(STAGED),
        ],
        rows(OTHER, 900_000, 1),
    ))
    .await;
    // Staging for a session nobody has registered is passed.
    let (tx, manager, log) = fleet(2, 8);
    let queue = vec![
        rows(source(0), 0, MEMBER_ROWS),
        context(STAGED),
        rows(OTHER, 900_000, 1),
    ];
    let (manager, order) = Box::pin(run(tx, manager, &log, queue)).await;
    assert_eq!(position(&order, 1), 0, "{order:?}");
    assert_eq!(overtakes(&manager), [("receive".to_owned(), 1.0)]);
}

/// At the drain seam a read-ahead that hashed rows takes the whole poll: it
/// admits neither a parked UPDATE nor the head, and the head is admitted by
/// the next call.
#[tokio::test(start_paused = true)]
async fn a_drain_seam_that_hashed_rows_admits_nothing_in_that_poll() {
    let (tx, mut manager, log) = fleet(2, 2);
    tx.try_send(rows(source(0), 0, MEMBER_ROWS)).unwrap();
    tx.try_send(rows(source(1), 1_000, MEMBER_ROWS)).unwrap();
    // It shares a prefix with the first table, so it does not pass.
    tx.try_send(rows(OTHER, 0, 1)).unwrap();
    log.lock().unwrap().clear();
    assert!(manager.drain_ready_updates().await, "the seam did work");
    assert!(
        log.lock().unwrap().is_empty(),
        "a primary was dispatched in the poll that hashed rows"
    );
    assert_eq!(manager.parked.len(), 3);
    assert_eq!(
        manager.parked.indexed_rows(),
        2 * usize::try_from(MEMBER_ROWS).unwrap()
    );
    assert!(manager.drain_ready_updates().await);
    assert_eq!(log.lock().unwrap().len(), 1, "the head is admitted next");
}

/// Reading ahead counts each parked message once: 512 messages behind one
/// head are about 512 visits, not one pass over the deque per message.
#[tokio::test(start_paused = true)]
async fn counting_parked_messages_is_linear_in_the_messages_read() {
    use crate::manager::parked_primaries::{INSPECT_MESSAGES_PER_SEAM, take_count_visits};
    let (tx, mut manager, _log) = fleet(2, 2);
    tx.try_send(rows(source(0), 0, MEMBER_ROWS)).unwrap();
    for _ in 0..INSPECT_MESSAGES_PER_SEAM {
        tx.try_send(RibUpdate::SetPeerRsControl {
            peer: peer_v4(source(1)),
            session_id: STAGED,
            rs_control_asn: None,
        })
        .unwrap();
    }
    take_count_visits();
    let noop = |_: PeerId, _: u64| false;
    manager
        .parked
        .read_ahead(&mut manager.rx, &manager.ribs, &noop);
    assert_eq!(manager.parked.len(), INSPECT_MESSAGES_PER_SEAM + 1);
    let visits = take_count_visits();
    assert!(
        visits <= INSPECT_MESSAGES_PER_SEAM + 1,
        "{visits} entries visited to count {INSPECT_MESSAGES_PER_SEAM} messages"
    );
    // A returned head is counted with the tail, still once each.
    let head = manager.parked.take().unwrap();
    manager.parked.put(head);
    tx.try_send(rows(OTHER, 900_000, 1)).unwrap();
    manager
        .parked
        .read_ahead(&mut manager.rx, &manager.ribs, &noop);
    assert!(manager.parked.candidate().is_some());
    assert!(take_count_visits() <= 3);
}

/// The table probes of the final check are charged to the seam's budget
/// before they run: 32,768 parked rows fill one seam, and the probes of a
/// 16-row UPDATE against 64 parked session ends wait for the next.
#[tokio::test(start_paused = true)]
async fn table_probes_are_reserved_within_the_seam_budget() {
    use crate::manager::parked_primaries::{INSPECT_WORK_PER_SEAM, RESET_SESSIONS_LIMIT};
    const TABLES: u8 = 32;
    let ends = u8::try_from(RESET_SESSIONS_LIMIT).unwrap();
    let (tx, mut manager, _log) = fleet(TABLES + ends, 2);
    for index in 0..TABLES {
        tx.try_send(rows(source(index), u32::from(index) * 2_000, 1_024))
            .unwrap();
    }
    for index in 0..ends {
        tx.try_send(down(source(TABLES + index))).unwrap();
    }
    tx.try_send(rows(OTHER, 900_000, u32::try_from(OVERTAKE_ROWS).unwrap()))
        .unwrap();
    let noop = |_: PeerId, _: u64| false;
    let first = manager
        .parked
        .read_ahead(&mut manager.rx, &manager.ribs, &noop);
    assert_eq!(first, INSPECT_WORK_PER_SEAM, "the hashes fill the seam");
    assert!(manager.parked.candidate().is_none(), "the probes wait");
    let second = manager
        .parked
        .read_ahead(&mut manager.rx, &manager.ribs, &noop);
    assert_eq!(second, usize::from(ends) * OVERTAKE_ROWS);
    assert!(manager.parked.candidate().is_some());
}

/// A small UPDATE parked behind the head is a route message like any other:
/// another session's UPDATE passes it when their prefixes differ and keeps
/// FIFO behind it when they share one. Order between two sessions on
/// different prefixes is not arrival order anywhere in the lane.
#[tokio::test(start_paused = true)]
async fn a_small_update_ahead_is_passed_only_on_different_prefixes() {
    // Source 0's own small UPDATE cannot pass its 17-row table; another
    // session's can pass both.
    let (tx, manager, log) = fleet(2, 8);
    let queue = vec![
        rows(source(0), 0, 17),
        rows(source(0), 100, 2),
        rows(OTHER, 900_000, 1),
    ];
    let (manager, order) = Box::pin(run(tx, manager, &log, queue)).await;
    assert_eq!(
        order,
        [
            other(1),
            format!("routes:{}:17", source(0)),
            format!("routes:{}:2", source(0)),
        ]
    );
    assert_eq!(overtakes(&manager), [("receive".to_owned(), 1.0)]);
    // The same prefix as the small UPDATE ahead: arrival order.
    Box::pin(assert_fifo(
        "shared with a small UPDATE ahead",
        vec![rows(source(0), 0, 17), rows(source(0), 100, 2)],
        rows(OTHER, 101, 1),
    ))
    .await;
}

/// With RFC 9117 validation, a rule's feasibility depends on covering and
/// more-specific unicast prefixes. A owns the cover and a rule that B's
/// more-specific route makes infeasible. If B's withdrawal passed A's
/// queued session end, the rule would become feasible and be exported, then
/// withdrawn; in arrival order it is never exported. Validation keeps the
/// queue in strict arrival order.
#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture: the cover, the rule, the conflicting route and the queue"
)]
async fn flowspec_validation_keeps_the_queue_in_arrival_order() {
    use rustbgpd_wire::{AsPath, AsPathSegment};
    async fn rule_events(strict: bool) -> (Vec<String>, f64) {
        let path = |asn: u32| {
            AttrSet::new(vec![PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![asn])],
            })])
        };
        let (tx, rx) = mpsc::channel(64);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
            .with_flowspec_validation(65_000);
        manager.outbound_row_credit_override = None;
        super::distribution_window::untimed_window(&mut manager);
        manager.parked.strict_fifo = strict;
        let (owner, rival, bulk) = (source(0), source(1), source(2));
        for from in [owner, rival, bulk] {
            register_test_peer(&mut manager, peer_v4(from), 0);
        }
        let receiver = peer_v4(Ipv4Addr::new(192, 0, 2, 200));
        let (outbound_tx, mut outbound_rx) = mpsc::channel(256);
        let mut up = test_peer_up(receiver, 1, outbound_tx);
        let RibUpdate::PeerUp {
            sendable_families, ..
        } = &mut up
        else {
            unreachable!()
        };
        sendable_families.extend(ipv4_flowspec_sendable());
        manager.handle_update(up);
        let events = Log::default();
        let seen = Arc::clone(&events);
        tokio::spawn(async move {
            while let Some(update) = outbound_rx.recv().await.map(delivered) {
                let mut seen = seen.lock().unwrap();
                seen.extend(
                    update
                        .flowspec_announce
                        .iter()
                        .map(|_| "announce".to_owned()),
                );
                seen.extend(
                    update
                        .flowspec_withdraw
                        .iter()
                        .map(|_| "withdraw".to_owned()),
                );
            }
        });

        let mut cover = make_route(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 0, 0), 16), owner);
        cover.attributes = path(65_001);
        let mut rule = make_flowspec_route(owner);
        rule.attributes = path(65_001);
        let specific = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 25);
        let mut conflicting = make_route(specific, rival);
        conflicting.attributes = path(65_002);
        let mut announcement = test_routes_received(peer_v4(owner), vec![cover]);
        let RibUpdate::RoutesReceived {
            flowspec_announced, ..
        } = &mut announcement
        else {
            unreachable!()
        };
        flowspec_announced.push(rule.clone());
        for update in [
            announcement,
            test_routes_received(peer_v4(rival), vec![conflicting]),
        ] {
            manager.handle_update(update);
            drain_route_chunks(&mut manager);
            while manager.process_flowspec_validation_chunk() {}
        }
        assert!(
            manager
                .loc_rib
                .get_flowspec(&rule.selection_key())
                .is_none(),
            "the more-specific route makes the rule infeasible"
        );
        // The rule was exported while it was feasible and withdrawn since.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(*events.lock().unwrap(), ["announce", "withdraw"]);
        events.lock().unwrap().clear();

        let mut withdrawal = test_routes_received(peer_v4(rival), Vec::new());
        let RibUpdate::RoutesReceived { withdrawn, .. } = &mut withdrawal else {
            unreachable!()
        };
        withdrawn.push((Prefix::V4(specific), 0));
        // A table, the end of the owner's session, then the withdrawal.
        tx.try_send(rows(bulk, 0, 1_100)).unwrap();
        tx.try_send(down(owner)).unwrap();
        tx.try_send(withdrawal).unwrap();
        let actor = tokio::spawn(manager.run_actor());
        tokio::time::sleep(Duration::from_secs(60)).await;
        drop(tx);
        let manager = actor.await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        let passed = overtakes(&manager).iter().map(|(_, count)| count).sum();
        let events = events.lock().unwrap().clone();
        (events, passed)
    }
    let (fifo, _) = Box::pin(rule_events(true)).await;
    assert_eq!(
        fifo,
        [] as [String; 0],
        "arrival order never exports the rule"
    );
    let (lane, passed) = Box::pin(rule_events(false)).await;
    assert_eq!(lane, fifo, "the receiver's FlowSpec stream changed");
    assert!(passed == 0.0, "an UPDATE passed with validation enabled");
}

/// A family that becomes sendable on a registered session exports its table
/// and then End-of-RIB. An UPDATE queued behind that unlock is announced
/// after the marker; had it passed the unlock it would ride inside the
/// table, before the marker. A live session's context change is a barrier,
/// so the receiver's sequence around End-of-RIB is that of arrival order.
#[tokio::test(start_paused = true)]
async fn an_update_behind_a_live_family_unlock_follows_its_end_of_rib() {
    const TABLE: u32 = 1_100;
    let mut sequences = Vec::new();
    for strict in [true, false] {
        let (tx, mut manager, log, _wires) = wired_fleet(1, 2);
        manager.parked.strict_fifo = strict;
        // A registered receiver with no sendable family yet.
        let late = peer_v4(Ipv4Addr::new(192, 0, 2, 250));
        let (outbound_tx, outbound_rx) = mpsc::channel(4096);
        let mut up = test_peer_up(late, 1, outbound_tx);
        let RibUpdate::PeerUp {
            sendable_families, ..
        } = &mut up
        else {
            unreachable!()
        };
        sendable_families.clear();
        manager.handle_update(up);
        let wire = collect(outbound_rx);
        let queue = vec![
            rows(source(0), 0, TABLE),
            RibUpdate::PeerFamilySendable {
                peer: late,
                session_id: 1,
                family: (Afi::Ipv4, Safi::Unicast),
                add_path_send_limit: None,
            },
            rows(OTHER, 900_000, 1),
        ];
        let (manager, order) = Box::pin(run(tx, manager, &log, queue)).await;
        assert_eq!(overtakes(&manager), [], "strict={strict}: {order:?}");
        let wire = wire.lock().unwrap().clone();
        let marker = wire
            .iter()
            .rposition(|event| event.starts_with("E "))
            .unwrap_or_else(|| panic!("strict={strict}: no End-of-RIB: {} events", wire.len()));
        let passed = format!("{:?}", Prefix::V4(prefix(900_000)));
        let announced = wire
            .iter()
            .position(|event| event.contains(&passed))
            .expect("the UPDATE reaches the receiver");
        assert!(
            announced > marker,
            "strict={strict}: the UPDATE was announced before End-of-RIB"
        );
        // The table before the marker in any order, then the UPDATE.
        let mut before: Vec<_> = wire[..=marker].to_vec();
        before.sort();
        sequences.push((before, wire[marker + 1..].to_vec()));
    }
    assert_eq!(sequences[0], sequences[1]);
}

/// Every session sends `PeerAddPathLimits` right after its `PeerUp`. With
/// no Paths-Limit entry it changes nothing a receiver is sent, so a small
/// UPDATE passes it even though its session is registered or about to be;
/// with an entry it can resend that session's table, and keeps FIFO.
#[tokio::test(start_paused = true)]
async fn an_empty_paths_limit_message_is_passed_and_one_with_entries_is_not() {
    let joiner = peer_v4(source(1));
    let limits = |limits: Vec<((Afi, Safi), u32)>| RibUpdate::PeerAddPathLimits {
        peer: joiner,
        session_id: STAGED,
        limits,
    };
    let (tx, manager, log) = fleet(2, 8);
    let queue = vec![
        rows(source(0), 0, MEMBER_ROWS),
        registering_peer_up(joiner, STAGED),
        limits(Vec::new()),
        rows(OTHER, 900_000, 1),
    ];
    let (manager, order) = Box::pin(run(tx, manager, &log, queue)).await;
    assert_eq!(position(&order, 1), 0, "{order:?}");
    assert_eq!(overtakes(&manager), [("receive".to_owned(), 1.0)]);

    Box::pin(assert_fifo(
        "Paths-Limit entries behind their PeerUp",
        vec![
            rows(source(0), 0, MEMBER_ROWS),
            registering_peer_up(joiner, STAGED),
            limits(vec![((Afi::Ipv4, Safi::Unicast), 4)]),
        ],
        rows(OTHER, 900_000, 1),
    ))
    .await;
}
