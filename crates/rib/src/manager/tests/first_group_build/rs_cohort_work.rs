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

/// A published single-best group of RS-control clients, then `joiners`
/// more whose registrations queue behind actor work, as a mass rejoin does.
async fn rejoin(joiners: u8) -> Rejoin {
    let (mut manager, tx, _) = fixture(0);
    let rows = usize::from(PAGES) * REGISTRATION_PAGE_SIZE;
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
