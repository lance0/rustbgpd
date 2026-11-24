//! A large source departure during a paced join stays inside the replay.
use super::*;

const DEPARTED: u16 = 600;

/// The member joins a table where `OTHER` owns `DEPARTED` winners, then
/// `OTHER` goes down behind the held first page. Returns the final inventory,
/// the departed keys that were already admitted and the resync builds.
async fn depart_during_replay() -> (BTreeSet<Prefix>, usize, BTreeSet<Prefix>, bool) {
    let (mut manager, tx, expected) = replay_fixture();
    let departed: BTreeSet<Prefix> = (0..DEPARTED).map(|i| prefixes(V4_ROWS + i)[0]).collect();
    manager.handle_update(test_routes_received(
        peer_v4(OTHER),
        departed.iter().map(|&key| route(key, OTHER, 100)).collect(),
    ));
    drain_route_chunks(&mut manager);
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 1, false, false);
    let first = first_page(&mut manager, &mut rx);
    let mut state: BTreeSet<_> = first.announce.iter().map(|row| row.prefix).collect();
    let admitted = state.intersection(&departed).count();
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    tx.try_send(RibUpdate::PeerDown {
        peer: peer_v4(OTHER),
        session_id: 0,
    })
    .unwrap();
    let actor = tokio::spawn(manager.run_actor());
    // Let the departure run while the page is still held.
    tokio::task::yield_now().await;
    drop(first);
    let mut withdrawn = BTreeSet::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let page = rx.recv().await.unwrap();
            for &(prefix, _) in page.unicast_withdrawals() {
                assert!(state.remove(&prefix), "withdrew an unsent {prefix}");
                assert!(withdrawn.insert(prefix), "repeated withdrawal of {prefix}");
            }
            for row in page.announce.iter() {
                assert!(
                    state.insert(row.prefix),
                    "duplicate announcement of {}",
                    row.prefix
                );
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
    assert_eq!(state, expected.keys().copied().collect());
    (
        withdrawn,
        admitted,
        departed,
        manager.adj_rib_out_commit_stats.resync_builds == builds
            && !manager.dirty_peers.contains(&peer),
    )
}

#[tokio::test(start_paused = true)]
async fn large_source_departure_mid_replay_withdraws_admitted_keys_without_resync() {
    let (withdrawn, admitted, departed, clean) = depart_during_replay().await;
    assert!(admitted > 0, "the first page carried departed keys");
    assert!(withdrawn.is_subset(&departed));
    assert_eq!(withdrawn.len(), admitted, "one withdrawal per admitted key");
    assert!(
        clean,
        "the departure handed the replay to a whole-table resync"
    );
}
