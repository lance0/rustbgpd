use super::*;

#[test]
fn authoritative_reload_rolls_over_distinct_sources_and_preserves_every_export() {
    // Each prefix owns a different input attribute set, so sharing cannot
    // reduce the memo below the rollover threshold.
    let rows = u16::try_from(5 * PAGE).unwrap();
    let mut fleet = Fleet::new(0, false, OLD);
    let changes = (0..rows)
        .map(|i| route(prefixes(i)[0], SOURCE, u32::from(i) + 1))
        .collect();
    fleet
        .manager
        .handle_update(test_routes_received(peer_v4(SOURCE), changes));
    drain_route_chunks(&mut fleet.manager);
    fleet.read();
    fleet.manager.first_group_build_min_routes = 1;

    let mut reply = start(&mut fleet, &community_chain(NEW), false);
    let mut previous = 0;
    let mut rollovers = 0;
    for _ in 0..128 {
        let Some(sources) = fleet.manager.reload_memo_sources() else {
            break;
        };
        assert!(sources <= 2 * PAGE, "retained {sources} distinct inputs");
        if sources < previous {
            assert!(previous > PAGE && sources <= PAGE);
            rollovers += 1;
        }
        previous = sources;
        fleet.manager.advance_first_group_build();
    }
    assert!(rollovers > 0, "distinct sources must exhaust the memo");
    assert!(reply.received());
    fleet.read();

    let expected: Wire = (0..rows)
        .map(|i| {
            (
                prefixes(i)[0],
                (peer_v4(SOURCE), u32::from(i) + 1, vec![NEW]),
            )
        })
        .collect();
    let group = &fleet.manager.group_ribs[&fleet.manager.grouped_member_of(receiver(1)).unwrap()];
    let installed: Wire = group
        .table
        .iter()
        .map(|r| (r.prefix, (r.peer, r.local_pref(), r.communities().to_vec())))
        .collect();
    assert_eq!(installed, expected);
    for wire in &fleet.wire {
        assert_eq!(wire, &expected);
    }
}
