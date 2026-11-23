use super::*;

#[tokio::test(start_paused = true)]
async fn sparse_reservation_refusal_recovers_a_withdrawal_queued_behind_it() {
    let (mut manager, tx, mut expected) = replay_fixture();
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 64, false, false);
    let first = first_page(&mut manager, &mut rx);
    let lost = first.announce[0].prefix;
    let mut actual: Inventory = first
        .announce
        .iter()
        .map(|row| (row.prefix, (row.peer, row.local_pref())))
        .collect();

    // Keep the first slot alive while two separate ingest turns queue the
    // sparse announcement before the withdrawal of an already admitted row.
    let sparse = prefixes(V4_ROWS + 1)[0];
    manager.handle_update(test_routes_received(
        peer_v4(SOURCE),
        vec![route(sparse, SOURCE, 150)],
    ));
    drain_route_chunks(&mut manager);
    let mut remove = test_routes_received(peer_v4(SOURCE), Vec::new());
    let RibUpdate::RoutesReceived { withdrawn, .. } = &mut remove else {
        unreachable!()
    };
    withdrawn.push((lost, 0));
    manager.handle_update(remove);
    drain_route_chunks(&mut manager);
    expected.insert(sparse, (peer_v4(SOURCE), 150));
    expected.remove(&lost).unwrap();
    let gid = manager.grouped_member_of(peer).unwrap();
    assert!(manager.is_initial_member_replay(peer));
    assert!(manager.group_ribs[&gid].table.get(&lost, 0).is_none());
    assert!(!manager.group_ribs[&gid].tombstones.contains(&(lost, 0)));
    assert!(
        manager
            .pending_extra_withdraws
            .get(&peer)
            .is_none_or(|extra| !extra.unicast.contains(&(lost, 0)))
    );
    drop(first);

    manager
        .pending_group_admitted
        .fail_next_allocation_for_test();
    manager.advance_pending_initial_registration();
    assert!(manager.dirty_peers.contains(&peer));
    assert!(!manager.is_initial_member_replay(peer));
    // The failed replay page hands the prior wire view to dirty recovery.
    assert!(
        manager
            .pending_group_admitted
            .get(&peer)
            .is_some_and(|proof| proof.contains(&crate::update::ExactExportKey::Unicast(lost, 0))),
        "reservation refusal lost the admitted withdrawal"
    );
    assert!(rx.is_empty(), "unreserved sparse announcement was sent");
    let actor = tokio::spawn(manager.run_actor());
    let mut withdrawals = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let page = rx.recv().await.unwrap();
            for &(prefix, path_id) in page.unicast_withdrawals() {
                withdrawals.push((prefix, path_id));
                actual.remove(&prefix);
            }
            for row in page.announce.iter() {
                actual.insert(row.prefix, (row.peer, row.local_pref()));
            }
            if !page.end_of_rib.is_empty() {
                assert_eq!(page.end_of_rib, [FAMILY]);
                break;
            }
        }
    })
    .await
    .expect("recovery End-of-RIB");
    assert_eq!(withdrawals, [(lost, 0)]);
    assert_eq!(actual, expected);
    drop(tx);
    let manager = actor.await.unwrap();
    assert!(!manager.dirty_peers.contains(&peer));
    assert!(rx.is_empty());
}
