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

async fn cold_join(pages: u16, with_policy: bool) -> ReplayWork {
    cold_join_holding(pages, with_policy, false).await
}

/// `hold_last` keeps the newest envelope, and its operation latch, alive
/// across the next actor poll so the replay parks behind its own writer.
async fn cold_join_holding(pages: u16, with_policy: bool, hold_last: bool) -> ReplayWork {
    const TAG: u32 = 0xfde8_0007;
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
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *sendable_families = vec![(Afi::Ipv4, Safi::Unicast)];
    *is_ebgp = false;
    *route_reflector_client = true;
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
                assert!(seen.insert(row.prefix), "duplicate {:?}", row.prefix);
                assert_eq!(row.communities().contains(&TAG), with_policy);
            }
            for family in &update.end_of_rib {
                assert_eq!(*family, (Afi::Ipv4, Safi::Unicast));
                assert_eq!(seen.len(), rows, "early End-of-RIB");
                markers += 1;
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
    for with_policy in [false, true] {
        for pages in [8, 32] {
            let work = cold_join(pages, with_policy).await;
            eprintln!("policy={with_policy}, pages={pages}, {work:?}");
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

// Every page parks its writer until the transport drops the page's latch.
// Resuming must continue at the member's cursor: a replay that rescans from
// the first bucket after each pause still sends each row once, but its total
// work grows with the square of the table.
#[tokio::test]
async fn paused_initial_member_replay_resumes_at_its_cursor() {
    for pages in [8, 32] {
        let work = cold_join_holding(pages, false, true).await;
        let rows = usize::from(pages) * REGISTRATION_PAGE_SIZE;
        // One proof visit and at most two bucket visits per row, plus one
        // inclusive seek per proof page.
        assert!(
            work.total <= 3 * rows + usize::from(pages),
            "pages={pages}: {work:?}"
        );
        assert!(
            work.peak <= REGISTRATION_PAGE_SIZE,
            "pages={pages}: {work:?}"
        );
        eprintln!("held pages={pages}: {work:?}");
    }
}
