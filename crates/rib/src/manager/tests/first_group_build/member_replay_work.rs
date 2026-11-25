//! Bound collection of an initial member's proof and routes within each physical RIB poll.
use std::future::{Future, poll_fn};

use super::*;
use crate::loc_rib::REGISTRATION_PAGE_SIZE;
use crate::manager::tests::update_groups::community_chain;

#[derive(Debug, Default)]
struct ReplayWork {
    peak: usize,
    total: usize,
    polls: usize,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Member {
    Plain,
    Policy,
    // An eBGP per-client-best member, with no export policy.
    PerClientBest,
}

async fn cold_join(pages: u16, member: Member) -> ReplayWork {
    cold_join_holding(pages, member, false).await
}

async fn cold_join_holding(pages: u16, member: Member, hold_last: bool) -> ReplayWork {
    cold_join_with(pages, member, hold_last, 0).await
}

/// `hold_last` keeps the newest envelope, and its operation latch, alive
/// across the next actor poll so the replay parks behind its own writer.
/// A nonzero `burst` lands that many new prefixes from another source after
/// the first page, more than the scan's repair log holds, so the replay
/// rewinds into a reconcile.
async fn cold_join_with(pages: u16, member: Member, hold_last: bool, burst: u16) -> ReplayWork {
    const TAG: u32 = 0xfde8_0007;
    let with_policy = member == Member::Policy;
    let (mut manager, tx, _) = fixture(0);
    manager.initial_member_replays.min_routes = Some(1);
    let rows = usize::from(pages) * REGISTRATION_PAGE_SIZE;
    let routes = (0..u16::try_from(rows).unwrap())
        .map(|index| route(prefixes(index)[0], SOURCE, 100))
        .collect();
    manager.handle_update(test_routes_received(peer_v4(SOURCE), routes));
    drain_route_chunks(&mut manager);
    assert_eq!(manager.loc_rib.len(), rows);

    let peer = receiver(1);
    let (out, mut rx) = mpsc::channel(32);
    let mut up = test_peer_up(peer, 1, out);
    let RibUpdate::PeerUp {
        sendable_families,
        is_ebgp,
        route_reflector_client,
        export_policy,
        per_client_best,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *sendable_families = vec![(Afi::Ipv4, Safi::Unicast)];
    *per_client_best = member == Member::PerClientBest;
    *is_ebgp = *per_client_best;
    *route_reflector_client = !*per_client_best;
    *export_policy = with_policy.then(|| community_chain(TAG));
    tx.try_send(up).unwrap();

    let visits = || {
        crate::manager::slice_timing::group_work()
            .get("initial_member_replay_visits")
            .copied()
            .unwrap_or(0)
    };
    let mut actor = Box::pin(manager.run_actor());
    let mut tx = Some(tx);
    let mut work = ReplayWork::default();
    let mut seen = HashSet::new();
    let mut markers = 0;
    let mut held = None;
    let mut burst_sent = burst == 0;
    poll_fn(|cx| {
        let before = visits();
        let result = actor.as_mut().poll(cx);
        let delta = visits() - before;
        work.peak = work.peak.max(delta);
        work.total += delta;
        work.polls += usize::from(delta > 0);
        held = None;
        while let Ok(update) = rx.try_recv() {
            for row in update.announce.iter() {
                assert_eq!(markers, 0);
                // A reconcile resends the rows its rescan visits.
                assert!(
                    seen.insert(row.prefix) || burst != 0,
                    "duplicate {:?}",
                    row.prefix
                );
                assert_eq!(row.communities().contains(&TAG), with_policy);
            }
            for family in &update.end_of_rib {
                assert_eq!(*family, (Afi::Ipv4, Safi::Unicast));
                assert_eq!(seen.len(), rows + usize::from(burst), "early End-of-RIB");
                markers += 1;
            }
            if !burst_sent {
                burst_sent = true;
                let routes = (0..burst)
                    .map(|i| route(prefixes(u16::try_from(rows).unwrap() + i)[0], OTHER, 100))
                    .collect();
                let tx = tx.as_ref().expect("input open");
                tx.try_send(test_routes_received(peer_v4(OTHER), routes))
                    .unwrap();
                cx.waker().wake_by_ref();
            }
            if hold_last {
                held = Some(update);
            }
        }
        if markers != 0 && tx.take().is_some() {
            cx.waker().wake_by_ref();
        }
        result
    })
    .await;
    assert_eq!(markers, 1);
    work
}

#[tokio::test]
async fn initial_member_replay_bounds_visits_per_physical_poll() {
    let mut results = Vec::new();
    for member in [Member::Plain, Member::Policy, Member::PerClientBest] {
        for pages in [8, 32] {
            let work = cold_join(pages, member).await;
            eprintln!("{member:?}, pages={pages}, {work:?}");
            results.push((pages, work));
        }
    }
    for (pages, work) in results {
        assert!(work.peak <= REGISTRATION_PAGE_SIZE, "{work:?}");
        // Each permitted row enters the admission universe and the cursor walk.
        assert!(
            work.total >= 2 * usize::from(pages) * REGISTRATION_PAGE_SIZE,
            "{work:?}"
        );
        assert!(work.polls >= 2 * usize::from(pages), "{work:?}");
    }
}

// Overflow mid-replay rewinds into a reconcile. Its rescan and proof sweep
// run in pages: per-poll work stays at one page however large the table, and
// total work stays linear in it.
#[tokio::test]
async fn reconcile_bounds_visits_per_physical_poll() {
    const BURST: u16 = 4_200;
    for member in [Member::Plain, Member::PerClientBest] {
        for pages in [8, 32] {
            let reconciles = || {
                crate::manager::slice_timing::group_work()
                    .get("initial_replay_reconciles")
                    .copied()
                    .unwrap_or(0)
            };
            let before = reconciles();
            let work = cold_join_with(pages, member, false, BURST).await;
            eprintln!("reconcile {member:?}, pages={pages}, {work:?}");
            assert_eq!(reconciles() - before, 1, "{member:?} pages={pages}");
            let rows = usize::from(pages) * REGISTRATION_PAGE_SIZE + usize::from(BURST);
            assert!(
                work.peak <= REGISTRATION_PAGE_SIZE,
                "{member:?} pages={pages}: {work:?}"
            );
            // The initial proof and partial walk, the rescan's bucket visits
            // and repairs, and the proof sweep: each at most once per row.
            assert!(work.total <= 5 * rows, "{member:?} pages={pages}: {work:?}");
        }
    }
}

// Every page parks its writer until the transport drops the page's latch.
// Resuming must continue at the member's cursor: a replay that rescans from
// the first bucket after each pause still sends each row once, but its total
// work grows with the square of the table.
#[tokio::test]
async fn paused_initial_member_replay_resumes_at_its_cursor() {
    for (pages, member) in [8, 32]
        .into_iter()
        .flat_map(|pages| [(pages, Member::Plain), (pages, Member::PerClientBest)])
    {
        let work = cold_join_holding(pages, member, true).await;
        let rows = usize::from(pages) * REGISTRATION_PAGE_SIZE;
        // One proof visit and at most two bucket visits per row, plus one
        // inclusive seek per proof page.
        assert!(
            work.total <= 3 * rows + usize::from(pages),
            "{member:?} pages={pages}: {work:?}"
        );
        assert!(
            work.peak <= REGISTRATION_PAGE_SIZE,
            "{member:?} pages={pages}: {work:?}"
        );
        eprintln!("held {member:?} pages={pages}: {work:?}");
    }
}
