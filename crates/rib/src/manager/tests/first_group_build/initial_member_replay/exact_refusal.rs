use super::*;
use crate::manager::slice_timing;
use crate::manager::tests::exportability::MockExactExportEncoder;
use crate::update::ExactExportKey;

fn replace_admitted_route(
    manager: &mut RibManager,
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    held: OutboundRouteUpdate,
    prefix: Prefix,
) -> OutboundRouteUpdate {
    manager.handle_update(test_routes_received(
        peer_v4(SOURCE),
        vec![route(prefix, SOURCE, 200)],
    ));
    drain_route_chunks(manager);
    drop(held);
    manager.wake_initial_member_replay();
    manager.advance_pending_initial_registration();
    rx.try_recv().expect("ordered replay change")
}

fn retained_refusal_prior_visits(rows: u16) -> usize {
    let (mut manager, _tx, _) = fixture(rows);
    manager.initial_member_replays.min_routes = Some(1);
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 1, false, false);
    let first = first_page(&mut manager, &mut rx);
    let refused = first.announce[0].prefix;
    let accepted = first.announce[1].prefix;
    let refused_key = ExactExportKey::Unicast(refused, 0);
    let encoder = MockExactExportEncoder::accepting(1);
    encoder.set_profile(2, [refused_key.clone()]);
    manager.peer_export_encoders.insert(peer, encoder.clone());

    let withdrawal = replace_admitted_route(&mut manager, &mut rx, first, refused);
    assert!(withdrawal.announce.is_empty());
    assert_eq!(
        withdrawal
            .unicast_withdrawals()
            .copied()
            .collect::<Vec<_>>(),
        [(refused, 0)]
    );
    assert!(manager.peer_unexportable[&peer].contains(&refused_key));

    let visits = || {
        slice_timing::group_work()
            .get("exact_export_prior_visits")
            .copied()
            .unwrap_or(0)
    };
    let before = visits();
    let announcement = replace_admitted_route(&mut manager, &mut rx, withdrawal, accepted);
    assert_eq!(announcement.unicast_withdrawals().count(), 0);
    assert_eq!(announcement.announce.len(), 1);
    assert_eq!(announcement.announce[0].prefix, accepted);
    assert_eq!(announcement.announce[0].local_pref(), 200);
    assert_eq!(
        encoder.probed(),
        [refused_key.clone(), ExactExportKey::Unicast(accepted, 0)]
    );
    assert!(manager.peer_unexportable[&peer].contains(&refused_key));
    assert!(manager.is_initial_member_replay(peer));
    visits() - before
}

#[tokio::test(start_paused = true)]
async fn retained_exact_refusal_only_reconciles_the_current_replay_candidate() {
    let small = retained_refusal_prior_visits(1024);
    let large = retained_refusal_prior_visits(4096);
    eprintln!("prior visits for one candidate: 1024 routes={small}, 4096 routes={large}");
    assert_eq!(
        small, large,
        "one candidate must cost the same at both table sizes"
    );
    assert!(
        (1..=8).contains(&large),
        "visited {large} keys for one replay candidate"
    );
}

// After the change log overflows, a change to an admitted key coalesces into
// its scan repair. When the repair page probes that key's current row and the
// exact export refuses it, the receiver must lose the advertised route even
// though the group row still exists, and no later page may offer it again.
#[tokio::test(start_paused = true)]
async fn coalesced_admitted_key_refused_by_exact_export_is_withdrawn() {
    let (mut manager, tx, mut expected) = replay_fixture();
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 1, false, false);
    let first = first_page(&mut manager, &mut rx);
    let refused = first.announce[0].prefix;
    let refused_key = ExactExportKey::Unicast(refused, 0);
    let others: Vec<_> = first
        .announce
        .iter()
        .skip(1)
        .map(|row| row.prefix)
        .collect();
    let mut state: Inventory = first
        .announce
        .iter()
        .map(|row| (row.prefix, (row.peer, row.local_pref())))
        .collect();
    let encoder = MockExactExportEncoder::accepting(1);
    encoder.set_profile(2, [refused_key.clone()]);
    manager.peer_export_encoders.insert(peer, encoder.clone());

    // Overflow the log with the other admitted keys, then change the refused
    // key, whose change now joins its repair instead of the log.
    let rounds = u32::try_from(1024 / others.len() + 2).unwrap();
    for round in 1..=rounds {
        manager.handle_update(test_routes_received(
            peer_v4(OTHER),
            others
                .iter()
                .map(|&key| route(key, OTHER, 100 + 100 * round))
                .collect(),
        ));
        drain_route_chunks(&mut manager);
    }
    manager.handle_update(test_routes_received(
        peer_v4(OTHER),
        vec![route(refused, OTHER, 900)],
    ));
    drain_route_chunks(&mut manager);
    assert!(manager.is_initial_member_replay(peer));
    assert!(encoder.probed().iter().all(|key| *key != refused_key));
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    drop(first);
    let actor = tokio::spawn(manager.run_actor());
    let mut refused_events = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let page = rx.recv().await.unwrap();
            for &(prefix, _) in page.unicast_withdrawals() {
                assert!(state.remove(&prefix).is_some(), "withdrew unsent {prefix}");
                if prefix == refused {
                    refused_events.push(false);
                }
            }
            for row in page.announce.iter() {
                state.insert(row.prefix, (row.peer, row.local_pref()));
                if row.prefix == refused {
                    refused_events.push(true);
                }
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
    assert_eq!(
        refused_events,
        [false],
        "one withdrawal and no re-announcement"
    );
    assert_eq!(
        encoder
            .probed()
            .iter()
            .filter(|key| **key == refused_key)
            .count(),
        1,
        "the refused key was probed again"
    );
    assert!(manager.peer_unexportable[&peer].contains(&refused_key));
    let last = 100 + 100 * rounds;
    for &key in &others {
        expected.insert(key, (peer_v4(OTHER), last));
    }
    expected.remove(&refused);
    assert_eq!(state, expected);
    assert_eq!(
        manager.actual_unicast_advertised_count(peer),
        expected.len()
    );
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
    assert!(!manager.dirty_peers.contains(&peer));
    assert!(rx.is_empty());
}
