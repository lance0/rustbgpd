//! A large source departure during a paced join stays inside the replay.
use super::*;

struct Departure {
    withdrawn: BTreeSet<Prefix>,
    admitted: usize,
    departed: BTreeSet<Prefix>,
    clean: bool,
}

/// The member joins a table where `OTHER` owns `count` winners, then `OTHER`
/// goes down without graceful restart, behind the held first page or, with
/// `before_first_page`, while the proof is still being prepared.
async fn depart_during_replay(count: u16, before_first_page: bool) -> Departure {
    let (mut manager, tx, expected) = replay_fixture();
    let departed: BTreeSet<Prefix> = (0..count).map(|i| prefixes(V4_ROWS + i)[0]).collect();
    manager.handle_update(test_routes_received(
        peer_v4(OTHER),
        departed.iter().map(|&key| route(key, OTHER, 100)).collect(),
    ));
    drain_route_chunks(&mut manager);
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 1, false, false);
    let mut state = BTreeSet::new();
    let first = if before_first_page {
        for _ in 0..256 {
            if manager.is_initial_member_replay(peer) {
                break;
            }
            manager.advance_pending_initial_registration();
        }
        assert!(manager.is_initial_member_replay(peer));
        assert!(rx.is_empty(), "nothing is sent while the proof is prepared");
        None
    } else {
        let first = first_page(&mut manager, &mut rx);
        state.extend(first.announce.iter().map(|row| row.prefix));
        Some(first)
    };
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
    tokio::time::timeout(Duration::from_secs(60), async {
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
    Departure {
        withdrawn,
        admitted,
        departed,
        clean: manager.adj_rib_out_commit_stats.resync_builds == builds
            && !manager.dirty_peers.contains(&peer),
    }
}

fn assert_paced(departure: &Departure) {
    assert!(
        departure.clean,
        "the departure handed the replay to a whole-table resync"
    );
    assert!(departure.withdrawn.is_subset(&departure.departed));
    assert_eq!(
        departure.withdrawn.len(),
        departure.admitted,
        "one withdrawal per admitted key"
    );
}

#[tokio::test(start_paused = true)]
async fn large_source_departure_mid_replay_withdraws_admitted_keys_without_resync() {
    let departure = depart_during_replay(600, false).await;
    assert!(
        departure.admitted > 0,
        "the first page carried departed keys"
    );
    assert_paced(&departure);
}

// Just below the 4,096-key scan repair cap, the departure's withdrawals do
// not all fit the change log. Those that coalesce reach the receiver from the
// repair pages.
#[tokio::test(start_paused = true)]
async fn source_departure_near_the_repair_cap_stays_paced() {
    let departure = depart_during_replay(4_000, false).await;
    assert!(
        departure.admitted > 0,
        "the first page carried departed keys"
    );
    assert_paced(&departure);
}

#[tokio::test(start_paused = true)]
async fn source_departure_during_proof_preparation_sends_no_departed_key() {
    let departure = depart_during_replay(600, true).await;
    assert_eq!(departure.admitted, 0);
    assert_paced(&departure);
}
