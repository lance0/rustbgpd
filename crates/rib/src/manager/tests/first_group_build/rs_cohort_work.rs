//! Route-server clients rejoining together page their initial tables. None
//! of them receives its whole table inside one physical actor poll.
use std::future::{Future, poll_fn};

use super::*;
use crate::loc_rib::REGISTRATION_PAGE_SIZE;

const RS_ASN: u32 = 65_000;
const PAGES: u16 = 4;

#[derive(Debug, Default)]
struct Rejoin {
    // Most rows any one poll delivered, over every joiner.
    peak_rows: usize,
    peak_visits: usize,
    polls: usize,
}

fn rs_client(
    manager: &mut RibManager,
    n: u8,
    capacity: usize,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = receiver(n);
    manager.handle_update(RibUpdate::SetPeerRsControl {
        peer,
        session_id: 1,
        rs_control_asn: Some(RS_ASN),
    });
    let (out, rx) = mpsc::channel(capacity);
    let mut up = test_peer_up(peer, 1, out);
    let RibUpdate::PeerUp {
        peer_asn,
        sendable_families,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *peer_asn = 64_600 + u32::from(n);
    *sendable_families = vec![(Afi::Ipv4, Safi::Unicast)];
    manager.handle_update(up);
    rx
}

const ROWS: usize = PAGES as usize * REGISTRATION_PAGE_SIZE;

/// A published single-best group of RS-control clients. Later
/// registrations queue behind actor work, as in a mass rejoin.
struct Published {
    manager: RibManager,
    tx: mpsc::Sender<RibUpdate>,
    _founder: mpsc::Receiver<OutboundRouteUpdate>,
}

fn published() -> Published {
    published_with(ROWS)
}

fn published_with(rows: usize) -> Published {
    let (mut manager, tx, _) = fixture(0);
    let table = (0..u16::try_from(rows).unwrap())
        .map(|index| route(prefixes(index)[0], SOURCE, 100))
        .collect();
    manager.handle_update(test_routes_received(peer_v4(SOURCE), table));
    drain_route_chunks(&mut manager);
    let mut founder = rs_client(&mut manager, 200, 1 << 12);
    assert!(manager.grouped_member_of(receiver(200)).is_some());
    while founder.try_recv().is_ok() {}

    manager.initial_member_replays.min_routes = Some(1);
    manager.initial_dump_defer_min_routes = 0;
    // Queued input makes each registration defer to the run loop.
    tx.try_send(test_routes_received(peer_v4(SOURCE), vec![]))
        .unwrap();
    Published {
        manager,
        tx,
        _founder: founder,
    }
}

async fn rejoin(joiners: u8) -> Rejoin {
    rejoin_within(joiners, None).await
}

/// [`rejoin`] with the proof budget room for `replays` paced tables.
async fn rejoin_within(joiners: u8, replays: Option<usize>) -> Rejoin {
    let rows = ROWS;
    let Published {
        mut manager,
        tx,
        _founder: founder,
    } = published();
    if let Some(replays) = replays {
        // A table's mask, keys and their bucket index, plus header slack
        // below half a table.
        use crate::manager::update_groups::admitted_recovery::Key;

        let table = ROWS * (size_of::<Key>() + 6 * size_of::<u32>() / 4) + ROWS / 8 + 1024;
        let ledger = &mut manager.pending_group_admitted;
        ledger.set_test_daemon_limit(ledger.bytes() + replays * table + table / 2);
    }
    let mut clients: Vec<_> = (1..=joiners)
        .map(|n| rs_client(&mut manager, n, 1 << 12))
        .collect();
    assert_eq!(
        manager.pending_initial_registrations.len(),
        usize::from(joiners)
    );

    let visits = || {
        crate::manager::slice_timing::group_work()
            .get("initial_member_replay_visits")
            .copied()
            .unwrap_or(0)
    };
    let mut actor = Box::pin(manager.run_actor());
    let mut tx = Some(tx);
    let mut work = Rejoin::default();
    let mut seen = vec![HashSet::new(); clients.len()];
    let mut markers = vec![0; clients.len()];
    poll_fn(|cx| {
        let before = visits();
        let result = actor.as_mut().poll(cx);
        work.peak_visits = work.peak_visits.max(visits() - before);
        let mut delivered = 0;
        for (index, rx) in clients.iter_mut().enumerate() {
            while let Ok(update) = rx.try_recv() {
                delivered += update.announce.len();
                for row in update.announce.iter() {
                    assert_eq!(markers[index], 0, "route after End-of-RIB");
                    assert!(seen[index].insert(row.prefix));
                }
                markers[index] += update.end_of_rib.len();
            }
        }
        work.peak_rows = work.peak_rows.max(delivered);
        work.polls += usize::from(delivered > 0);
        if markers.iter().all(|&count| count == 1) && tx.take().is_some() {
            cx.waker().wake_by_ref();
        }
        result
    })
    .await;
    for (index, rows_seen) in seen.iter().enumerate() {
        assert_eq!(rows_seen.len(), rows, "joiner {index}");
        assert_eq!(markers[index], 1, "joiner {index}");
    }
    drop(founder);
    work
}

// Each joiner's table goes out one page at a time, interleaved across the
// cohort, so the longest poll stays one page however many clients rejoin.
// A cohort replayed in one turn delivers every joiner's whole table at once.
#[tokio::test]
async fn rs_control_rejoin_cohort_pages_every_initial_table() {
    for joiners in [8, 32] {
        let work = rejoin(joiners).await;
        eprintln!("joiners={joiners}: {work:?}");
        assert!(
            work.peak_rows <= REGISTRATION_PAGE_SIZE,
            "joiners={joiners}: {work:?}"
        );
        assert!(
            work.peak_visits <= REGISTRATION_PAGE_SIZE,
            "joiners={joiners}: {work:?}"
        );
        assert!(
            work.polls >= usize::from(joiners) * usize::from(PAGES),
            "joiners={joiners}: {work:?}"
        );
    }
}

// With every paced replay slot taken, a later joiner waits in the queue
// rather than sending its whole table in one turn. A freed slot starts its
// paced replay.
#[test]
fn joiners_past_the_replay_cap_wait_for_a_slot() {
    use crate::manager::peer_lifecycle::MAX_JOIN_COHORT;

    let Published {
        mut manager,
        tx: _tx,
        _founder,
    } = published();
    // Writers that hold one page each park their replays and keep the slots.
    let cap = u8::try_from(MAX_JOIN_COHORT).unwrap();
    let mut parked: Vec<_> = (1..=cap).map(|n| rs_client(&mut manager, n, 1)).collect();
    for _ in 0..100_000 {
        if !manager.registration_runnable() {
            break;
        }
        manager.advance_pending_initial_registration();
    }
    assert!((1..=cap).all(|n| manager.is_initial_member_replay(receiver(n))));

    let mut late: Vec<_> = (cap + 1..=cap + 8)
        .map(|n| {
            (
                n,
                rs_client(&mut manager, n, 1 << 12),
                HashSet::new(),
                0,
                false,
            )
        })
        .collect();
    for _ in 0..1_000 {
        manager.advance_pending_initial_registration();
    }
    // Nothing advances while the slots stay held, and nothing spins.
    assert!(!manager.registration_runnable());
    for (n, rx, ..) in &mut late {
        assert!(rx.try_recv().is_err(), "joiner {n} sent while waiting");
        assert!(!manager.is_initial_member_replay(receiver(*n)));
    }

    // Closing the parked writers ends their replays and frees the slots.
    parked.clear();
    let mut peak = 0;
    for _ in 0..100_000 {
        if late.iter().all(|(.., markers, _)| *markers == 1) {
            break;
        }
        manager.wake_initial_member_replay();
        manager.advance_pending_initial_registration();
        let mut delivered = 0;
        for (n, rx, seen, markers, paced) in &mut late {
            *paced |= manager.is_initial_member_replay(receiver(*n));
            while let Ok(update) = rx.try_recv() {
                delivered += update.announce.len();
                seen.extend(update.announce.iter().map(|row| row.prefix));
                *markers += update.end_of_rib.len();
            }
        }
        peak = peak.max(delivered);
    }
    for (n, _, seen, markers, paced) in &late {
        assert_eq!((seen.len(), *markers), (ROWS, 1), "joiner {n}");
        assert!(paced, "joiner {n} was not paced");
    }
    assert!(peak <= REGISTRATION_PAGE_SIZE, "one turn sent {peak} rows");
}

// The proof budget has room for two paced tables at a time. The other
// joiners wait for a replay to end instead of sending a whole table in one
// turn under a refused enrollment.
#[tokio::test]
async fn joiners_past_the_proof_budget_wait_for_a_replay_to_end() {
    let work = rejoin_within(8, Some(2)).await;
    eprintln!("{work:?}");
    assert!(work.peak_rows <= REGISTRATION_PAGE_SIZE, "{work:?}");
    assert!(work.polls >= 8 * usize::from(PAGES), "{work:?}");
}

/// Ordered key comparisons plus bucket probes per row of one RS-control
/// joiner's paced replay over a `rows`-row table.
fn replay_comparisons_per_row(rows: usize) -> usize {
    use crate::manager::update_groups::admitted_recovery::KEY_COMPARISONS;

    let Published {
        mut manager,
        tx: _tx,
        _founder,
    } = published_with(rows);
    let mut rx = rs_client(&mut manager, 1, 1 << 16);
    let before = KEY_COMPARISONS.with(std::cell::Cell::get);
    let (mut seen, mut markers, mut paced) = (0, 0, false);
    for _ in 0..100_000 {
        if markers == 1 {
            break;
        }
        manager.advance_pending_initial_registration();
        paced |= manager.is_initial_member_replay(receiver(1));
        while let Ok(update) = rx.try_recv() {
            seen += update.announce.len();
            markers += update.end_of_rib.len();
        }
    }
    let comparisons = KEY_COMPARISONS.with(std::cell::Cell::get) - before;
    assert!(paced);
    assert_eq!((seen, markers), (rows, 1));
    comparisons.div_ceil(rows)
}

// Each replayed row finds its admission state by key bucket, so the
// comparisons per row stay flat as the table grows. A binary search over
// the replay universe pays one more comparison per doubling, on each of
// the several lookups a row takes.
#[test]
fn rs_control_replay_key_comparisons_per_row_stay_flat() {
    let small = replay_comparisons_per_row(4 * REGISTRATION_PAGE_SIZE);
    let large = replay_comparisons_per_row(32 * REGISTRATION_PAGE_SIZE);
    eprintln!("comparisons per row: 4 pages {small}, 32 pages {large}");
    assert!(large <= small, "4 pages {small}, 32 pages {large}");
    assert!(large <= 16, "32 pages {large}");
}
