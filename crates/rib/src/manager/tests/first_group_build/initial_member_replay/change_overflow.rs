//! Changes that overflow the ordered log coalesce into scan repairs.
use super::*;
use crate::update::{RoutePageError, RouteQueryScope};

/// New prefixes in the oversized UPDATE, within the sparse admission overlay.
const NEW: u16 = 900;

fn listing_refused(manager: &mut RibManager, peer: PeerId) -> bool {
    let (reply, mut response) = oneshot::channel();
    let scope = RouteQueryScope::Advertised { peer };
    manager.handle_query_routes_page_versioned(scope, None, None, None, 10_000, reply);
    matches!(
        response.try_recv().unwrap(),
        Err(RoutePageError::ResyncInProgress)
    )
}

fn withdraw(source: Ipv4Addr, keys: &[Prefix]) -> RibUpdate {
    let mut update = test_routes_received(peer_v4(source), Vec::new());
    let RibUpdate::RoutesReceived { withdrawn, .. } = &mut update else {
        unreachable!()
    };
    withdrawn.extend(keys.iter().map(|&key| (key, 0)));
    update
}

/// Release the held first page, run to End-of-RIB and return the final
/// inventory, per-key announcement counts and whether no resync was built.
async fn finish(
    mut manager: RibManager,
    tx: mpsc::Sender<RibUpdate>,
    mut rx: mpsc::Receiver<OutboundRouteUpdate>,
    first: OutboundRouteUpdate,
    peer: PeerId,
) -> (Inventory, BTreeMap<Prefix, usize>, bool) {
    let mut state: Inventory = BTreeMap::new();
    let mut announced = BTreeMap::new();
    for row in first.announce.iter() {
        state.insert(row.prefix, (row.peer, row.local_pref()));
        *announced.entry(row.prefix).or_default() += 1;
    }
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    drop(first);
    manager.wake_initial_member_replay();
    let actor = tokio::spawn(manager.run_actor());
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let page = rx.recv().await.unwrap();
            for &(prefix, _) in page.unicast_withdrawals() {
                assert!(state.remove(&prefix).is_some(), "withdrew unsent {prefix}");
            }
            for row in page.announce.iter() {
                state.insert(row.prefix, (row.peer, row.local_pref()));
                *announced.entry(row.prefix).or_default() += 1;
            }
            if !page.end_of_rib.is_empty() {
                assert_eq!(page.end_of_rib, [FAMILY]);
                break;
            }
        }
    })
    .await
    .expect("End-of-RIB");
    drop(tx);
    let manager = actor.await.unwrap();
    assert!(rx.is_empty());
    let clean = manager.adj_rib_out_commit_stats.resync_builds == builds
        && !manager.dirty_peers.contains(&peer);
    (state, announced, clean)
}

// One UPDATE that replaces every admitted key and adds new prefixes publishes
// a stage larger than a page. All of its keys are left to their repairs; the
// member still receives the exact table. New keys stay within the sparse
// admission overlay, whose own cap still hands larger bursts to a resync.
#[tokio::test(start_paused = true)]
async fn oversized_update_mid_replay_coalesces_into_repairs() {
    let (mut manager, tx, mut expected) = replay_fixture();
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 1, false, false);
    let first = first_page(&mut manager, &mut rx);
    let replaced: BTreeSet<_> = first.announce.iter().map(|row| row.prefix).collect();
    assert!(
        replaced.len() + usize::from(NEW) > 1024,
        "the stage exceeds a page"
    );
    let mut routes: Vec<_> = (0..NEW)
        .map(|i| route(prefixes(V4_ROWS + i)[0], OTHER, 100))
        .collect();
    routes.extend(replaced.iter().map(|&key| route(key, OTHER, 200)));
    manager.handle_update(test_routes_received(peer_v4(OTHER), routes));
    drain_route_chunks(&mut manager);
    assert!(manager.is_initial_member_replay(peer));
    assert!(manager.initial_member_replay_changes_pending(peer));
    assert!(
        listing_refused(&mut manager, peer),
        "listing read unsent rows"
    );
    for i in 0..NEW {
        expected.insert(prefixes(V4_ROWS + i)[0], (peer_v4(OTHER), 100));
    }
    for &key in &replaced {
        expected.insert(key, (peer_v4(OTHER), 200));
    }
    let (state, announced, clean) = Box::pin(finish(manager, tx, rx, first, peer)).await;
    assert!(clean, "the stage handed the replay to a whole-table resync");
    assert_eq!(state, expected);
    for (prefix, count) in announced {
        let allowed = if replaced.contains(&prefix) { 2 } else { 1 };
        assert!(count <= allowed, "{prefix} announced {count} times");
    }
}

// More changes to admitted keys than the log holds, followed by withdrawals
// of other admitted keys: the overflow keeps each key's latest state and the
// withdrawals reach the receiver from the repair pages.
#[tokio::test(start_paused = true)]
async fn change_log_overflow_mid_replay_keeps_latest_state_and_withdrawals() {
    let (mut manager, tx, mut expected) = replay_fixture();
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 1, false, false);
    let first = first_page(&mut manager, &mut rx);
    let sent: Vec<_> = first.announce.iter().map(|row| row.prefix).collect();
    let (replaced, removed) = sent.split_at(sent.len() - 50);
    // Enough rounds to overflow the 1,024-entry log.
    let rounds = u32::try_from(1024 / replaced.len() + 2).unwrap();
    let last = 100 + 100 * rounds;
    for pref in (1..=rounds).map(|round| 100 + 100 * round) {
        manager.handle_update(test_routes_received(
            peer_v4(OTHER),
            replaced
                .iter()
                .map(|&key| route(key, OTHER, pref))
                .collect(),
        ));
        drain_route_chunks(&mut manager);
    }
    manager.handle_update(withdraw(SOURCE, removed));
    drain_route_chunks(&mut manager);
    assert!(manager.is_initial_member_replay(peer));
    for &key in replaced {
        expected.insert(key, (peer_v4(OTHER), last));
    }
    for key in removed {
        expected.remove(key);
    }
    let (state, _, clean) = Box::pin(finish(manager, tx, rx, first, peer)).await;
    assert_eq!(state, expected);
    assert!(
        clean,
        "the log overflow handed the replay to a whole-table resync"
    );
}

// The log sends one change per writer operation. Churn of two changes per
// operation must not hold pages back: once the log overflows, later changes
// coalesce, the log drains and the remaining table reaches the member while the
// churn continues. Once the churn stops, the replay completes within a bounded
// number of operations.
#[tokio::test(start_paused = true)]
async fn churn_above_the_log_drain_rate_still_delivers_pages() {
    const CHURN_OPS: u32 = 3_000;
    const SETTLE_OPS: u32 = 64;
    let (mut manager, _tx, mut expected) = replay_fixture();
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 1, false, false);
    let first = first_page(&mut manager, &mut rx);
    let churned = [first.announce[0].prefix, first.announce[1].prefix];
    let mut state: Inventory = first
        .announce
        .iter()
        .map(|row| (row.prefix, (row.peer, row.local_pref())))
        .collect();
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    drop(first);
    let mut eor = false;
    // One writer operation: release the page, then let the replay take a turn.
    let mut operate = |manager: &mut RibManager, state: &mut Inventory, eor: &mut bool| {
        while let Ok(page) = rx.try_recv() {
            for &(prefix, _) in page.unicast_withdrawals() {
                state.remove(&prefix);
            }
            for row in page.announce.iter() {
                state.insert(row.prefix, (row.peer, row.local_pref()));
            }
            *eor |= !page.end_of_rib.is_empty();
        }
        manager.wake_initial_member_replay();
        manager.advance_pending_initial_registration();
    };
    let mut pref = 200;
    for _ in 0..CHURN_OPS {
        pref = if pref == 200 { 300 } else { 200 };
        manager.handle_update(test_routes_received(
            peer_v4(OTHER),
            churned.iter().map(|&key| route(key, OTHER, pref)).collect(),
        ));
        drain_route_chunks(&mut manager);
        operate(&mut manager, &mut state, &mut eor);
    }
    let delivered = expected
        .keys()
        .filter(|key| state.contains_key(*key))
        .count();
    assert_eq!(
        delivered,
        expected.len(),
        "{CHURN_OPS} operations of churn delivered {delivered} of {} rows",
        expected.len()
    );
    let mut settle = 0;
    while !eor && settle < SETTLE_OPS {
        operate(&mut manager, &mut state, &mut eor);
        settle += 1;
    }
    assert!(
        eor,
        "no End-of-RIB within {SETTLE_OPS} operations after churn stopped"
    );
    for key in churned {
        expected.insert(key, (peer_v4(OTHER), pref));
    }
    assert_eq!(state, expected);
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
    assert!(!manager.dirty_peers.contains(&peer));
}
