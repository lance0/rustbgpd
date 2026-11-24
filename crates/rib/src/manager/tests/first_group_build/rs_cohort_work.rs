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
    client(
        manager,
        n,
        capacity,
        Some(RS_ASN),
        &[(Afi::Ipv4, Safi::Unicast)],
    )
}

fn client(
    manager: &mut RibManager,
    n: u8,
    capacity: usize,
    rs_control_asn: Option<u32>,
    families: &[(Afi, Safi)],
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = receiver(n);
    manager.handle_update(RibUpdate::SetPeerRsControl {
        peer,
        session_id: 1,
        rs_control_asn,
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
    *sendable_families = families.to_vec();
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
    _dual_founder: Option<mpsc::Receiver<OutboundRouteUpdate>>,
}

fn published() -> Published {
    published_with(ROWS)
}

fn published_with(rows: usize) -> Published {
    published_shape(rows, false)
}

/// With `dual`, the table also carries an IPv6 row per IPv4 row, and a
/// dual-stack RS-control founder publishes a second, twice-as-large group.
fn published_shape(rows: usize, dual: bool) -> Published {
    let (mut manager, tx, _) = fixture(0);
    let table = (0..u16::try_from(rows).unwrap())
        .flat_map(|index| {
            let [v4, v6] = prefixes(index);
            std::iter::once(v4).chain(dual.then_some(v6))
        })
        .map(|prefix| route(prefix, SOURCE, 100))
        .collect();
    manager.handle_update(test_routes_received(peer_v4(SOURCE), table));
    drain_route_chunks(&mut manager);
    let mut founder = rs_client(&mut manager, 200, 1 << 14);
    assert!(manager.grouped_member_of(receiver(200)).is_some());
    while founder.try_recv().is_ok() {}
    let mut dual_founder = dual.then(|| client(&mut manager, 201, 1 << 14, Some(RS_ASN), &DUAL));
    if let Some(rx) = &mut dual_founder {
        assert!(manager.grouped_member_of(receiver(201)).is_some());
        while rx.try_recv().is_ok() {}
    }

    manager.initial_member_replays.min_routes = Some(1);
    manager.initial_dump_defer_min_routes = 0;
    // Queued input makes each registration defer to the run loop.
    tx.try_send(test_routes_received(peer_v4(SOURCE), vec![]))
        .unwrap();
    Published {
        manager,
        tx,
        _founder: founder,
        _dual_founder: dual_founder,
    }
}

async fn rejoin(joiners: u8) -> Rejoin {
    Box::pin(rejoin_within(joiners, None)).await
}

/// [`rejoin`] with the proof budget room for `replays` paced tables.
async fn rejoin_within(joiners: u8, replays: Option<usize>) -> Rejoin {
    let Published {
        mut manager,
        tx,
        _founder,
        ..
    } = published();
    if let Some(replays) = replays {
        // A table's mask, keys and their bucket index, plus header slack
        // below half a table.
        use crate::manager::update_groups::admitted_recovery::Key;

        let table = ROWS * (size_of::<Key>() + 6 * size_of::<u32>() / 4) + ROWS / 8 + 1024;
        let ledger = &mut manager.pending_group_admitted;
        ledger.set_test_daemon_limit(ledger.bytes() + replays * table + table / 2);
    }
    let clients: Vec<_> = (1..=joiners)
        .map(|n| (rs_client(&mut manager, n, 1 << 12), ROWS, 1))
        .collect();
    assert_eq!(
        manager.pending_initial_registrations.len(),
        usize::from(joiners)
    );
    Box::pin(drive(manager, tx, clients)).await
}

/// Run the actor until each client holds its `rows` rows and its End-of-RIB
/// `markers`, then close its input. A stalled rejoin fails at a poll or
/// time bound instead of hanging the test.
async fn drive(
    manager: RibManager,
    tx: mpsc::Sender<RibUpdate>,
    mut clients: Vec<(mpsc::Receiver<OutboundRouteUpdate>, usize, usize)>,
) -> Rejoin {
    const MAX_POLLS: usize = 1_000_000;
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
    let mut total_polls = 0;
    let run = poll_fn(|cx| {
        total_polls += 1;
        assert!(total_polls < MAX_POLLS, "rejoin stalled: {work:?}");
        let before = visits();
        let result = actor.as_mut().poll(cx);
        work.peak_visits = work.peak_visits.max(visits() - before);
        let mut delivered = 0;
        for (index, (rx, ..)) in clients.iter_mut().enumerate() {
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
        let done = clients
            .iter()
            .zip(&markers)
            .all(|((_, _, expected), count)| count == expected);
        if done && tx.take().is_some() {
            cx.waker().wake_by_ref();
        }
        result
    });
    tokio::time::timeout(std::time::Duration::from_secs(120), run)
        .await
        .expect("rejoin stalled without a wakeup");
    for (index, (_, rows, expected)) in clients.iter().enumerate() {
        assert_eq!(seen[index].len(), *rows, "joiner {index}");
        assert_eq!(markers[index], *expected, "joiner {index}");
    }
    work
}

// Each joiner's table goes out one page at a time, interleaved across the
// cohort, so the longest poll stays one page however many clients rejoin.
// A cohort replayed in one turn delivers every joiner's whole table at once.
#[tokio::test]
async fn rs_control_rejoin_cohort_pages_every_initial_table() {
    for joiners in [8, 32] {
        let work = Box::pin(rejoin(joiners)).await;
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

/// Advance registrations until every queued one waits or none is left.
fn settle(manager: &mut RibManager) {
    for _ in 0..100_000 {
        if !manager.registration_runnable() {
            return;
        }
        manager.advance_pending_initial_registration();
    }
    panic!("registrations never settled");
}

/// Hold every replay slot with joiners whose one-page writers park them.
fn fill_replay_slots(manager: &mut RibManager) -> Vec<mpsc::Receiver<OutboundRouteUpdate>> {
    use crate::manager::peer_lifecycle::MAX_JOIN_COHORT;

    let cap = u8::try_from(MAX_JOIN_COHORT).unwrap();
    let parked: Vec<_> = (1..=cap).map(|n| rs_client(manager, n, 1)).collect();
    settle(manager);
    assert!((1..=cap).all(|n| manager.is_initial_member_replay(receiver(n))));
    parked
}

/// Close the parked writers and service their replays until each has ended.
fn release(manager: &mut RibManager, parked: &mut Vec<mpsc::Receiver<OutboundRouteUpdate>>) {
    let peers = 1..=u8::try_from(parked.len()).unwrap();
    parked.clear();
    for _ in 0..100_000 {
        if !peers
            .clone()
            .any(|n| manager.is_initial_member_replay(receiver(n)))
        {
            return;
        }
        manager.wake_initial_member_replay();
        manager.service_initial_member_replay();
    }
    panic!("parked replays never ended");
}

/// Advance until each receiver holds `rows` rows and `markers` End-of-RIB,
/// returning the most rows one turn delivered and whether each was paced.
fn advance_until_complete(
    manager: &mut RibManager,
    clients: &mut [(u8, mpsc::Receiver<OutboundRouteUpdate>)],
    rows: usize,
    markers: usize,
) -> (usize, Vec<bool>) {
    let mut seen = vec![HashSet::new(); clients.len()];
    let mut ends = vec![0; clients.len()];
    let mut paced = vec![false; clients.len()];
    let mut peak = 0;
    for _ in 0..100_000 {
        if ends.iter().all(|&count| count == markers) {
            break;
        }
        manager.wake_initial_member_replay();
        manager.advance_pending_initial_registration();
        let mut delivered = 0;
        for (index, (n, rx)) in clients.iter_mut().enumerate() {
            paced[index] |= manager.is_initial_member_replay(receiver(*n));
            while let Ok(update) = rx.try_recv() {
                delivered += update.announce.len();
                seen[index].extend(update.announce.iter().map(|row| row.prefix));
                ends[index] += update.end_of_rib.len();
            }
        }
        peak = peak.max(delivered);
    }
    for (index, (n, _)) in clients.iter().enumerate() {
        assert_eq!(
            (seen[index].len(), ends[index]),
            (rows, markers),
            "joiner {n}"
        );
    }
    (peak, paced)
}

// With every paced replay slot taken, a later joiner waits in the queue
// rather than sending its whole table in one turn. A replay's end makes the
// queue runnable again, and the run loop then pages each waiter's table.
#[tokio::test]
async fn joiners_past_the_replay_cap_wait_for_a_slot() {
    let Published {
        mut manager, tx, ..
    } = published();
    let mut parked = fill_replay_slots(&mut manager);
    let first = u8::try_from(parked.len()).unwrap() + 1;
    let mut late: Vec<_> = (first..first + 8)
        .map(|n| (n, rs_client(&mut manager, n, 1 << 12)))
        .collect();
    for _ in 0..1_000 {
        manager.advance_pending_initial_registration();
    }
    // Nothing advances while the slots stay held, and nothing spins.
    assert!(!manager.registration_runnable());
    for (n, rx) in &mut late {
        assert!(rx.try_recv().is_err(), "joiner {n} sent while waiting");
        assert!(!manager.is_initial_member_replay(receiver(*n)));
    }

    release(&mut manager, &mut parked);
    assert!(
        manager.registration_runnable(),
        "a freed slot left the waiters asleep"
    );
    let clients = late.into_iter().map(|(_, rx)| (rx, ROWS, 1)).collect();
    let work = Box::pin(drive(manager, tx, clients)).await;
    assert!(work.peak_rows <= REGISTRATION_PAGE_SIZE, "{work:?}");
}

// A founder whose cold group builds while every replay slot is taken still
// waits once its table is published, then pages it when a slot frees.
#[test]
fn a_cold_group_founder_at_the_replay_cap_waits_for_a_slot() {
    let Published {
        mut manager,
        tx: _tx,
        ..
    } = published();
    let mut parked = fill_replay_slots(&mut manager);
    let groups = manager.group_ribs.len();
    // A plain dual-stack client keys a group of its own.
    let n = 100;
    let mut founder = [(n, client(&mut manager, n, 1 << 12, None, &DUAL))];
    for _ in 0..10_000 {
        manager.advance_pending_initial_registration();
    }
    assert_eq!(manager.group_ribs.len(), groups + 1, "the build published");
    assert!(
        founder[0].1.try_recv().is_err(),
        "the founder sent while waiting"
    );
    assert!(manager.pending_initial_registrations.contains(&receiver(n)));

    release(&mut manager, &mut parked);
    let (peak, paced) = advance_until_complete(&mut manager, &mut founder, ROWS, 2);
    assert!(paced[0], "the founder was not paced");
    assert!(peak <= REGISTRATION_PAGE_SIZE, "one turn sent {peak} rows");
}

// A founder that leaves while it waits leaves no member and no waiter for
// its published table, which retires rather than stays staged.
#[test]
fn a_waiting_founders_group_retires_when_it_leaves() {
    let Published {
        mut manager,
        tx: _tx,
        ..
    } = published();
    let _parked = fill_replay_slots(&mut manager);
    let groups = manager.group_ribs.len();
    let n = 100;
    let _founder = client(&mut manager, n, 1 << 12, None, &DUAL);
    for _ in 0..10_000 {
        manager.advance_pending_initial_registration();
    }
    assert_eq!(manager.group_ribs.len(), groups + 1, "the build published");

    manager.handle_update(RibUpdate::PeerDown {
        peer: receiver(n),
        session_id: 1,
    });
    for _ in 0..10_000 {
        if manager.optional_destination_retirement_active() {
            manager.advance_optional_destination_retirement();
        } else if manager.group_ribs.len() == groups {
            break;
        } else {
            manager.advance_pending_initial_registration();
        }
    }
    assert_eq!(
        manager.group_ribs.len(),
        groups,
        "the unclaimed table stayed"
    );
    assert!(!manager.optional_destination_retirement_active());
}

/// With every replay slot held, register client `n` and advance until it
/// holds the IPv4 table: it must not wait for a slot.
fn sends_without_waiting(manager: &mut RibManager, n: u8, rx: mpsc::Receiver<OutboundRouteUpdate>) {
    let mut joiner = [(n, rx)];
    let (_, paced) = advance_until_complete(manager, &mut joiner, ROWS, 1);
    assert!(!paced[0], "joiner {n} was paced");
    assert!(
        manager.is_initial_member_replay(receiver(1)),
        "the slots were released"
    );
}

// A table the per-peer proof limit refuses can never start a paced replay,
// so a full set of slots must not hold it: it takes its one-turn send.
#[test]
fn a_table_that_can_never_fit_does_not_wait_for_a_slot() {
    let Published {
        mut manager,
        tx: _tx,
        ..
    } = published();
    let _parked = fill_replay_slots(&mut manager);
    manager.pending_group_admitted.set_test_peer_limit(ROWS);
    let rx = rs_client(&mut manager, 100, 1 << 12);
    sends_without_waiting(&mut manager, 100, rx);
}

// A joiner whose configured outbound prefix limit refuses its paced replay
// is limited before it registers, so it does not wait for a slot either.
#[test]
fn a_joiner_with_a_configured_prefix_limit_does_not_wait_for_a_slot() {
    use crate::manager::tests::outbound_prefix_limits::{apply, limit_config, prepare};

    let Published {
        mut manager,
        tx: _tx,
        ..
    } = published();
    let _parked = fill_replay_slots(&mut manager);
    let limit = u32::try_from(2 * ROWS).unwrap();
    prepare(
        &mut manager,
        1,
        limit_config(&[(receiver(100), Some(limit), None)], &[]),
    )
    .expect("no registered peer exceeds the limit");
    apply(&mut manager, 1, true).expect("applied");
    let rx = rs_client(&mut manager, 100, 1 << 12);
    sends_without_waiting(&mut manager, 100, rx);
}

// A waiting joiner's replacement session negotiates ORF, which keeps it off
// the paced replay (its table waits for the peer's filter). The queue length does not change, but the replacement
// must not be left waiting for a slot it no longer needs.
#[test]
fn a_replacement_session_that_cannot_pace_stops_waiting() {
    let Published {
        mut manager,
        tx: _tx,
        ..
    } = published();
    let _parked = fill_replay_slots(&mut manager);
    let n = 100;
    let _first = rs_client(&mut manager, n, 1 << 12);
    settle(&mut manager);
    assert!(!manager.registration_runnable(), "the joiner waits");
    let queued = manager.pending_initial_registrations.len();

    let (out, rx) = mpsc::channel(1 << 12);
    let mut up = test_peer_up(receiver(n), 2, out);
    let RibUpdate::PeerUp {
        peer_asn,
        sendable_families,
        negotiated_orf_recv,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *peer_asn = 64_600 + u32::from(n);
    *sendable_families = vec![(Afi::Ipv4, Safi::Unicast)];
    *negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
    manager.handle_update(up);
    assert_eq!(manager.pending_initial_registrations.len(), queued);
    assert!(
        manager.registration_runnable(),
        "the replacement stayed asleep"
    );
    // Without an ORF filter yet, its table is empty: End-of-RIB alone.
    let mut joiner = [(n, rx)];
    let (_, paced) = advance_until_complete(&mut manager, &mut joiner, 0, 1);
    assert!(!paced[0]);
    assert_eq!(manager.outbound_session_ids.get(&receiver(n)), Some(&2));
    assert!(
        manager.is_initial_member_replay(receiver(1)),
        "the slots were released"
    );
}

// The proof budget has room for two paced tables at a time. The other
// joiners wait for a replay to end instead of sending a whole table in one
// turn under a refused enrollment.
#[tokio::test]
async fn joiners_past_the_proof_budget_wait_for_a_replay_to_end() {
    let work = Box::pin(rejoin_within(8, Some(2))).await;
    eprintln!("{work:?}");
    assert!(work.peak_rows <= REGISTRATION_PAGE_SIZE, "{work:?}");
    assert!(work.polls >= 8 * usize::from(PAGES), "{work:?}");
}

/// A dual-stack table and an IPv4 one, with one parked IPv4 replay holding
/// proof budget. Returns the parked writer and that replay's proof charge.
fn budget_shape() -> (Published, mpsc::Receiver<OutboundRouteUpdate>, usize) {
    let mut published = published_shape(ROWS, true);
    let manager = &mut published.manager;
    let before = manager.pending_group_admitted.bytes();
    let parked = rs_client(manager, 1, 1);
    settle(manager);
    assert!(manager.is_initial_member_replay(receiver(1)));
    let charge = manager.pending_group_admitted.bytes() - before;
    (published, parked, charge)
}

// A dual-stack joiner waits for proof budget its table needs. A later IPv4
// joiner whose smaller table would fit must not start ahead of it: budget
// waits are first come, first served.
#[test]
fn proof_budget_waits_are_first_come_first_served() {
    let (published, parked, table) = budget_shape();
    let Published {
        mut manager,
        tx: _tx,
        ..
    } = published;
    let ledger = &mut manager.pending_group_admitted;
    // Room for one and a half IPv4 tables: the dual-stack one needs two.
    ledger.set_test_daemon_limit(ledger.bytes() + table * 3 / 2);
    let (wide, narrow) = (2, 3);
    let mut joiners = [
        (
            wide,
            client(&mut manager, wide, 1 << 12, Some(RS_ASN), &DUAL),
        ),
        (narrow, rs_client(&mut manager, narrow, 1 << 12)),
    ];
    for _ in 0..1_000 {
        manager.advance_pending_initial_registration();
    }
    for (n, rx) in &mut joiners {
        assert!(
            !manager.is_initial_member_replay(receiver(*n)),
            "joiner {n}"
        );
        assert!(rx.try_recv().is_err(), "joiner {n} sent while waiting");
    }

    // The parked replay completes, releasing its proof budget.
    let mut holder = [(1, parked)];
    advance_until_complete(&mut manager, &mut holder, ROWS, 1);
    settle(&mut manager);
    assert!(manager.is_initial_member_replay(receiver(wide)));
    assert!(!manager.is_initial_member_replay(receiver(narrow)));
    let (peak, paced) = advance_until_complete(&mut manager, &mut joiners[..1], 2 * ROWS, 2);
    assert!(paced[0] && peak <= REGISTRATION_PAGE_SIZE, "wide: {peak}");
    let (peak, paced) = advance_until_complete(&mut manager, &mut joiners[1..], ROWS, 1);
    assert!(paced[0] && peak <= REGISTRATION_PAGE_SIZE, "narrow: {peak}");
}

// A table too large for the budget even once every live replay ends does
// not wait for them: it is refused at once and sent in its own turn.
#[test]
fn a_table_past_the_budget_even_after_every_replay_does_not_wait() {
    let (published, _parked, table) = budget_shape();
    let Published {
        mut manager,
        tx: _tx,
        ..
    } = published;
    let ledger = &mut manager.pending_group_admitted;
    // Releasing the parked replay leaves room for 1.3 IPv4 tables: the
    // dual-stack one needs two.
    ledger.set_test_daemon_limit(ledger.bytes() + table * 3 / 10);
    let wide = 2;
    let mut joiner = [(
        wide,
        client(&mut manager, wide, 1 << 12, Some(RS_ASN), &DUAL),
    )];
    let (_, paced) = advance_until_complete(&mut manager, &mut joiner, 2 * ROWS, 2);
    assert!(!paced[0]);
    assert!(
        manager.is_initial_member_replay(receiver(1)),
        "the parked replay still holds"
    );
}

/// Ordered key comparisons plus bucket probes made by one RS-control
/// joiner's paced replay over a `rows`-row table. Mid-replay, half the
/// table is withdrawn, so admitted rows go out as withdrawals, and an
/// outbound prefix limit above the table applies to the later pages.
fn replay_comparisons(rows: usize) -> usize {
    use crate::manager::tests::outbound_prefix_limits::{apply, limit_config, prepare};
    use crate::manager::update_groups::admitted_recovery::KEY_COMPARISONS;

    let Published {
        mut manager,
        tx: _tx,
        ..
    } = published_with(rows);
    let peer = receiver(1);
    let mut rx = rs_client(&mut manager, 1, 1 << 16);
    let before = KEY_COMPARISONS.with(std::cell::Cell::get);
    let (mut seen, mut markers, mut paced) = (HashSet::new(), 0, false);
    let mut churned = false;
    for _ in 0..100_000 {
        if markers == 1 {
            break;
        }
        manager.advance_pending_initial_registration();
        paced |= manager.is_initial_member_replay(peer);
        while let Ok(update) = rx.try_recv() {
            seen.extend(update.announce.iter().map(|row| row.prefix));
            for (prefix, _) in update.unicast_withdrawals() {
                seen.remove(prefix);
            }
            markers += update.end_of_rib.len();
        }
        if !churned && seen.len() >= rows / 2 {
            churned = true;
            let limit = u32::try_from(rows).unwrap();
            prepare(
                &mut manager,
                1,
                limit_config(&[(peer, Some(limit), None)], &[]),
            )
            .expect("the admitted pages fit the limit");
            apply(&mut manager, 1, true).expect("applied mid-replay");
            let mut withdrawal = test_routes_received(peer_v4(SOURCE), vec![]);
            let RibUpdate::RoutesReceived { withdrawn, .. } = &mut withdrawal else {
                unreachable!()
            };
            withdrawn.extend(
                (0..u16::try_from(rows).unwrap())
                    .step_by(2)
                    .map(|index| (prefixes(index)[0], 0)),
            );
            manager.handle_update(withdrawal);
            drain_route_chunks(&mut manager);
        }
    }
    let comparisons = KEY_COMPARISONS.with(std::cell::Cell::get) - before;
    assert!(paced && churned);
    assert_eq!((seen.len(), markers), (rows / 2, 1));
    comparisons
}

// Each replayed row finds its admission state by key bucket, so the
// comparisons each further row costs stay flat as the table grows, for
// announcements, withdrawals and the prefix-limit count alike. A binary
// search over the replay universe pays one more comparison per doubling.
#[test]
fn rs_control_replay_key_comparisons_per_row_stay_flat() {
    // Half of the larger table stays below the replay's repair limit.
    let (small_rows, large_rows) = (2 * REGISTRATION_PAGE_SIZE, 4 * REGISTRATION_PAGE_SIZE);
    let small = replay_comparisons(small_rows);
    let large = replay_comparisons(large_rows);
    // The marginal cost per row, net of each replay's fixed work.
    let per_row = (large - small) / (large_rows - small_rows);
    eprintln!("comparisons: {small} at {small_rows} rows, {large} at {large_rows}: {per_row}/row");
    // About 11 with key buckets; a binary search on any one lookup path
    // (withdrawal match, prefix paths, admission, apply) adds at least 6.
    assert!(per_row <= 14, "{per_row} comparisons per row");
}
