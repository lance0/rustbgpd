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
    client(manager, n, capacity, Some(RS_ASN), &V4)
}

const V4: [(Afi, Safi); 1] = [(Afi::Ipv4, Safi::Unicast)];

fn client(
    manager: &mut RibManager,
    n: u8,
    capacity: usize,
    rs_control_asn: Option<u32>,
    families: &[(Afi, Safi)],
) -> mpsc::Receiver<OutboundRouteUpdate> {
    shaped_client(manager, n, capacity, rs_control_asn, families, false)
}

fn shaped_client(
    manager: &mut RibManager,
    n: u8,
    capacity: usize,
    rs_control_asn: Option<u32>,
    families: &[(Afi, Safi)],
    pcb: bool,
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
        per_client_best,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *peer_asn = 64_600 + u32::from(n);
    *sendable_families = families.to_vec();
    *per_client_best = pcb;
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
    advance_until_complete_with(manager, clients, rows, markers, |_| {})
}

/// [`advance_until_complete`], checking every announced row.
fn advance_until_complete_with(
    manager: &mut RibManager,
    clients: &mut [(u8, mpsc::Receiver<OutboundRouteUpdate>)],
    rows: usize,
    markers: usize,
    mut check: impl FnMut(&Route),
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
                for row in update.announce.iter() {
                    check(row);
                    assert!(seen[index].insert(row.prefix), "joiner {n}: duplicate row");
                }
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

/// Joiners of one shape waiting for a replay slot: none has sent, none
/// replays, and the queue sleeps.
fn assert_waiting(
    manager: &mut RibManager,
    joiners: &mut [(u8, mpsc::Receiver<OutboundRouteUpdate>)],
) {
    settle(manager);
    assert!(!manager.registration_runnable(), "the queue spins");
    for (n, rx) in joiners {
        assert!(rx.try_recv().is_err(), "joiner {n} sent while waiting");
        assert!(!manager.is_initial_member_replay(receiver(*n)));
        assert!(
            manager
                .pending_initial_registrations
                .contains(&receiver(*n))
        );
    }
}

// Every paced replay shape waits for a slot past the replay cap: a plain
// single-best member and an RS-control member joining the published group,
// and a per-client-best member and a dual-stack RS-control member founding
// their own. The per-client-best build publishes while its founder waits;
// the RS-control founder waits first and builds its group in one turn when
// a slot frees. Either founder then pages its table, and the second client
// of each shape joins whichever group the first is in.
#[test]
fn every_paced_shape_waits_for_a_replay_slot() {
    for (shape, rs, pcb, families, founds) in [
        ("single-best", None, false, &V4[..], false),
        ("per-client-best", None, true, &V4[..], true),
        ("rs-control", Some(RS_ASN), false, &V4[..], false),
        ("rs-control founder", Some(RS_ASN), false, &DUAL[..], true),
    ] {
        let Published {
            mut manager,
            tx: _tx,
            ..
        } = published();
        let mut parked = fill_replay_slots(&mut manager);
        let groups = manager.group_ribs.len();
        let mut joiners: Vec<_> = [100, 101]
            .into_iter()
            .map(|n| {
                let rx = shaped_client(&mut manager, n, 1 << 12, rs, families, pcb);
                (n, rx)
            })
            .collect();
        for _ in 0..10_000 {
            manager.advance_pending_initial_registration();
        }
        assert_waiting(&mut manager, &mut joiners);

        release(&mut manager, &mut parked);
        let markers = families.len();
        let (peak, paced) = advance_until_complete(&mut manager, &mut joiners, ROWS, markers);
        assert_eq!(paced, [true, true], "{shape}");
        assert!(
            peak <= REGISTRATION_PAGE_SIZE,
            "{shape}: one turn sent {peak} rows"
        );
        let group = manager.grouped_member_of(receiver(100));
        assert!(group.is_some(), "{shape}");
        assert_eq!(group, manager.grouped_member_of(receiver(101)), "{shape}");
        assert_eq!(
            group != manager.grouped_member_of(receiver(200)),
            founds,
            "{shape}"
        );
        assert_eq!(
            manager.group_ribs.len(),
            groups + usize::from(founds),
            "{shape}"
        );
        assert_eq!(
            manager.group_ribs[&group.unwrap()].per_client_best,
            pcb,
            "{shape}"
        );
    }
}

// A leader that cannot page its own table (its policy build fell back)
// still sends it in its turn, but must not take the joiners waiting for a
// replay slot along: they keep their place and page their own tables.
#[test]
fn a_leader_that_cannot_pace_leaves_slot_waiters_queued() {
    let Published {
        mut manager,
        tx: _tx,
        ..
    } = published();
    let mut parked = fill_replay_slots(&mut manager);
    let mut joiners: Vec<_> = (100..104)
        .map(|n| (n, rs_client(&mut manager, n, 1 << 12)))
        .collect();
    assert_waiting(&mut manager, &mut joiners);

    let leader = 110;
    let mut leader_rx = [(leader, rs_client(&mut manager, leader, 1 << 12))];
    manager
        .live_sessions
        .get_mut(&receiver(leader))
        .and_then(|sessions| sessions.last_mut())
        .unwrap()
        .registration_policy_fallback = true;
    let (_, paced) = advance_until_complete(&mut manager, &mut leader_rx, ROWS, 1);
    assert!(!paced[0]);
    assert_waiting(&mut manager, &mut joiners);

    release(&mut manager, &mut parked);
    let (peak, paced) = advance_until_complete(&mut manager, &mut joiners, ROWS, 1);
    assert!(paced.iter().all(|&p| p), "{paced:?}");
    assert!(peak <= REGISTRATION_PAGE_SIZE, "one turn sent {peak} rows");
}

// A joiner whose own paced replay would be refused (a configured outbound
// prefix limit, or a table no proof budget fits) gains nothing from its own
// turn, so it still shares the one-turn replay of a leader that cannot pace.
#[test]
fn a_joiner_refused_its_own_pacing_shares_a_fallback_leaders_turn() {
    use crate::manager::tests::outbound_prefix_limits::{apply, limit_config, prepare};

    for refusal in ["prefix_limit", "never_fits"] {
        let Published {
            mut manager,
            tx: _tx,
            ..
        } = published();
        let (leader, joiner) = (110, 111);
        if refusal == "prefix_limit" {
            let limit = u32::try_from(2 * ROWS).unwrap();
            prepare(
                &mut manager,
                1,
                limit_config(&[(receiver(joiner), Some(limit), None)], &[]),
            )
            .expect("no registered peer exceeds the limit");
            apply(&mut manager, 1, true).expect("applied");
        } else {
            manager.pending_group_admitted.set_test_peer_limit(ROWS);
        }
        let mut leader_rx = rs_client(&mut manager, leader, 1 << 12);
        manager
            .live_sessions
            .get_mut(&receiver(leader))
            .and_then(|sessions| sessions.last_mut())
            .unwrap()
            .registration_policy_fallback = true;
        let mut joiner_rx = rs_client(&mut manager, joiner, 1 << 12);
        assert!(manager.paced_replay_room(receiver(joiner)).is_none());

        let (mut leader_ends, mut joiner_rows, mut joiner_ends) = (0, 0, 0);
        for _ in 0..10_000 {
            manager.advance_pending_initial_registration();
            while let Ok(update) = leader_rx.try_recv() {
                leader_ends += update.end_of_rib.len();
            }
            while let Ok(update) = joiner_rx.try_recv() {
                joiner_rows += update.announce.len();
                joiner_ends += update.end_of_rib.len();
            }
            if leader_ends > 0 {
                break;
            }
        }
        assert_eq!(leader_ends, 1, "{refusal}");
        assert!(
            !manager
                .pending_initial_registrations
                .contains(&receiver(joiner)),
            "{refusal}: the joiner did not share the leader's turn"
        );
        assert_eq!((joiner_rows, joiner_ends), (ROWS, 1), "{refusal}");
    }
}

/// Release the slots and page the waiter's whole table once, then check
/// nothing follows its End-of-RIB.
fn complete_waiter(
    manager: &mut RibManager,
    parked: &mut Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    waiter: &mut [(u8, mpsc::Receiver<OutboundRouteUpdate>)],
    check: impl FnMut(&Route),
) {
    release(manager, parked);
    let (peak, paced) = advance_until_complete_with(manager, waiter, ROWS, 1, check);
    assert!(paced[0], "the waiter was not paced");
    assert!(peak <= REGISTRATION_PAGE_SIZE, "one turn sent {peak} rows");
    for _ in 0..1_000 {
        manager.wake_initial_member_replay();
        manager.advance_pending_initial_registration();
    }
    assert!(waiter[0].1.try_recv().is_err(), "output after End-of-RIB");
}

const REGROUP_TAG: u32 = 0xfde9_0001;

// A waiter whose export policy changes keeps waiting: the change neither
// sends a table nor starts a replay. Once a slot frees it registers under
// the new policy, in the new policy's group. A reload reaches a waiter the
// same way: the authoritative batch skips the unregistered peer and the
// session records the accepted chain for its registration.
#[test]
fn a_waiter_regrouped_or_reloaded_registers_under_its_new_policy() {
    use crate::manager::tests::update_groups::community_chain;
    use crate::update::PeerExportPolicyReplacement;

    for reload in [false, true] {
        let Published {
            mut manager,
            tx: _tx,
            ..
        } = published();
        let mut parked = fill_replay_slots(&mut manager);
        let n = 100;
        let mut waiter = [(n, client(&mut manager, n, 1 << 12, None, &V4))];
        assert_waiting(&mut manager, &mut waiter);
        let old = manager.group_ribs.len();

        let chain = community_chain(REGROUP_TAG);
        manager.handle_update(RibUpdate::SetPeerSessionExportPolicy {
            peer: receiver(n),
            session_id: 1,
            export_policy: Some(chain.clone()),
        });
        if reload {
            let (reply, mut response) = oneshot::channel();
            manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                replacements: vec![PeerExportPolicyReplacement {
                    peer: receiver(n),
                    export_policy: Some(chain),
                }],
                reply,
            });
            let residual = (0..128)
                .find_map(|_| {
                    let reply = response.try_recv().ok();
                    if reply.is_none() && manager.first_group_build.is_some() {
                        manager.advance_first_group_build();
                    }
                    reply
                })
                .expect("the reload replied");
            assert_eq!(residual.unwrap(), [], "the waiter is not a residual");
        }
        for _ in 0..10_000 {
            manager.advance_pending_initial_registration();
        }
        assert_waiting(&mut manager, &mut waiter);

        complete_waiter(&mut manager, &mut parked, &mut waiter, |row| {
            assert!(row.communities().contains(&REGROUP_TAG), "old-policy row");
        });
        assert!(manager.group_ribs.len() > old, "reload={reload}");
        assert_ne!(
            manager.grouped_member_of(receiver(n)),
            manager.grouped_member_of(receiver(1)),
            "reload={reload}"
        );
    }
}

// A Route Refresh from a waiter answers nothing before its registration:
// the table it is waiting to page is the answer. An ORF update from a
// waiter, which negotiated none, is refused. Neither starts work, and the
// waiter later gets its table once, with one End-of-RIB.
#[test]
fn refresh_and_orf_from_a_waiter_start_no_work() {
    use std::sync::Arc;

    let Published {
        mut manager,
        tx: _tx,
        ..
    } = published();
    let mut parked = fill_replay_slots(&mut manager);
    let n = 100;
    let mut waiter = [(n, client(&mut manager, n, 1 << 12, None, &V4))];
    assert_waiting(&mut manager, &mut waiter);

    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer: receiver(n),
        session_id: 1,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        queued: Arc::default(),
    });
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::PeerOrfUpdate {
        peer: receiver(n),
        session_id: 1,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        when: rustbgpd_wire::WhenToRefresh::Immediate,
        groups: Vec::new(),
        reply,
    });
    assert!(response.try_recv().unwrap().is_err(), "ORF was accepted");
    assert_waiting(&mut manager, &mut waiter);

    complete_waiter(&mut manager, &mut parked, &mut waiter, |_| {});
}

// An operator read of a waiter's Adj-RIB-Out shows nothing advertised, and
// it neither starts the waiter's replay nor wakes the waiting queue.
#[test]
fn reading_a_waiters_adj_rib_out_shows_nothing_and_starts_no_work() {
    let Published {
        mut manager,
        tx: _tx,
        ..
    } = published();
    let mut parked = fill_replay_slots(&mut manager);
    let n = 100;
    let mut waiter = [(n, client(&mut manager, n, 1 << 12, None, &V4))];
    assert_waiting(&mut manager, &mut waiter);

    let (reply, mut page) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryRoutesPage {
        accept_releasing: false,
        scope: RouteQueryScope::Advertised { peer: receiver(n) },
        filter: None,
        after: None,
        expected_version: None,
        page_size: 100,
        reply,
    });
    let (reply, mut count) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryAdvertisedCount {
        peer: receiver(n),
        reply,
    });
    let page = page.try_recv().expect("the read replied");
    assert!(
        page.is_ok_and(|page| page.routes.is_empty()),
        "advertised before its replay"
    );
    assert_eq!(count.try_recv().unwrap(), 0);
    assert!(!manager.registration_runnable(), "the read woke the queue");
    assert_waiting(&mut manager, &mut waiter);

    complete_waiter(&mut manager, &mut parked, &mut waiter, |_| {});
}

// A change that ends a waiter's reason to wait wakes the queue. A configured
// outbound prefix limit refuses the waiter's paced replay, so it sends its
// table in its own turn while the slots stay held.
#[test]
fn a_change_that_ends_a_wait_wakes_the_queue() {
    use crate::manager::tests::outbound_prefix_limits::{apply, limit_config, prepare};

    let Published {
        mut manager,
        tx: _tx,
        ..
    } = published();
    let _parked = fill_replay_slots(&mut manager);
    let n = 100;
    let mut waiter = [(n, client(&mut manager, n, 1 << 12, None, &V4))];
    assert_waiting(&mut manager, &mut waiter);

    let limit = u32::try_from(2 * ROWS).unwrap();
    prepare(
        &mut manager,
        1,
        limit_config(&[(receiver(n), Some(limit), None)], &[]),
    )
    .expect("no registered peer exceeds the limit");
    apply(&mut manager, 1, true).expect("applied");
    assert!(
        manager.registration_runnable(),
        "the limit left the waiter asleep"
    );
    let [(_, rx)] = waiter;
    sends_without_waiting(&mut manager, n, rx);
}
