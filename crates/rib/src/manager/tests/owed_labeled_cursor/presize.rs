//! A private receiver's labeled-unicast cursor walk sizes its route and
//! prefix indexes once, at the first step that adds rows to a nearly empty
//! table, from what that step accepted per prefix and the prefixes still
//! ahead of its cursors.

use super::super::cursor_presize::{
    Growth, PRESIZE_ROWS, assert_fitted, deny_med_chain, set_med, tenth_med,
};
use super::*;

/// The receiver's labeled table: rows, and the capacities of its route
/// and prefix indexes.
fn tables(manager: &RibManager, peer: PeerId) -> (usize, [usize; 2]) {
    manager.adj_ribs_out.get(&peer).map_or((0, [0, 0]), |out| {
        let (routes, keys) = out.labeled_capacities();
        (out.labeled_len(), [routes, keys])
    })
}

/// Tick until no resync work is left, reading `peer`'s table after every
/// step.
fn walk(manager: &mut RibManager, receivers: &mut [Receiver], peer: PeerId) -> Growth {
    let mut growth = Growth::default();
    let (rows, capacities) = tables(manager, peer);
    growth.observe(rows, capacities);
    growth.rebuilds = [0, 0];
    for _ in 0..100_000 {
        for receiver in receivers.iter_mut() {
            receiver.write();
        }
        if !manager.resync_tick_pending() {
            return growth;
        }
        tick(manager, receivers);
        let (rows, capacities) = tables(manager, peer);
        growth.observe(rows, capacities);
    }
    panic!("the walk does not finish");
}

fn assert_indexes_fitted(manager: &RibManager, peer: PeerId, case: &str) {
    let out = &manager.adj_ribs_out[&peer];
    let (routes, keys) = out.labeled_capacities();
    assert_fitted(routes, out.labeled_len(), &format!("{case}: route index"));
    assert_fitted(
        keys,
        out.labeled_key_len(),
        &format!("{case}: prefix index"),
    );
}

fn rows(family: (Afi, Safi), range: std::ops::Range<u32>) -> Vec<LabeledRibRoute> {
    range
        .map(|index| route_from(SOURCE, family, index, 100, 200))
        .collect()
}

/// Both labeled AFIs released together to a receiver that joined in the
/// hold, 10,000 rows each into one shared pair of indexes: each index
/// changes capacity in one step, under the presize limit. Red without the
/// presize: five steps or more.
#[test]
fn a_private_labeled_walk_sizes_both_indexes_once() {
    const ROWS: u32 = 10_000;
    let mut manager = deferral_manager(4 * CHUNK_ROWS, &[L4, L6]);
    sources_up(&mut manager);
    for family in [L4, L6] {
        send(&mut manager, SOURCE, rows(family, 0..ROWS), vec![]);
    }
    let waiter = hold(&mut manager, &[L4, L6]);
    let mut receivers = vec![join_held(&mut manager, 0, &[L4, L6]), waiter];
    release(&mut manager, L4);
    release(&mut manager, L6);
    let peer = receivers[0].peer;
    let growth = walk(&mut manager, &mut receivers, peer);
    growth.assert_sized_once("both AFIs");
    let mut expected = table_of(L4, &all(ROWS));
    expected.extend(table_of(L6, &all(ROWS)));
    assert_eq!(receivers[0].wire.table, expected);
    assert_eq!(receivers[0].wire.markers, [1, 1]);
    assert_indexes_fitted(&manager, peer, "both AFIs");
}

/// A receiver whose export policy passes one row in ten: its indexes end
/// within 2.3 times what it holds. Red when the reserve is sized from the
/// prefixes ahead alone.
#[test]
fn a_filtered_labeled_walk_sizes_its_indexes_to_what_it_accepts() {
    const ROWS: u32 = 20_000;
    let tenth = |index| {
        let mut route = route_from(SOURCE, L4, index, 100, 200);
        set_med(&mut route.attributes, tenth_med(index));
        route
    };
    let mut manager = manager(4 * CHUNK_ROWS);
    sources_up(&mut manager);
    let peer = receiver(0);
    let (outbound_tx, mut rx) = mpsc::channel(4096);
    manager.handle_update(RibUpdate::PeerUp {
        supersedes: None,
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 200),
        outbound_tx,
        export_policy: Some(deny_med_chain()),
        sendable_families: vec![L4],
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: Vec::new(),
    });
    Wire::default().write(&mut rx);
    let mut receivers = vec![Receiver {
        peer,
        rx,
        wire: Wire::default(),
    }];
    manager.owe_eor(peer, L4);
    manager.owe_whole_family(peer, F4);
    send(&mut manager, SOURCE, (0..ROWS).map(tenth).collect(), vec![]);
    let growth = walk(&mut manager, &mut receivers, peer);
    let expected: Table = (0..ROWS)
        .filter(|index| index.is_multiple_of(10))
        .map(|index| entry(&tenth(index), 0))
        .collect();
    assert_eq!(receivers[0].wire.table, expected);
    assert_indexes_fitted(&manager, peer, "one row in ten");
    assert!(growth.rows_at_rebuild <= PRESIZE_ROWS, "{growth:?}");
}

/// An Add-Path receiver sent two paths of every prefix: the route index is
/// sized for two rows a prefix and the prefix index for one, each once.
/// Red when both are sized from the rows (the batch reserve's single
/// count): the prefix index ends past 2.3 times its prefixes.
#[test]
fn an_add_path_labeled_walk_sizes_each_index_by_its_own_count() {
    const PREFIXES: u32 = 8_000;
    let mut manager = manager(4 * CHUNK_ROWS);
    sources_up(&mut manager);
    let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 4096, &[L4], 2)];
    let peer = receivers[0].peer;
    manager.owe_eor(peer, L4);
    manager.owe_whole_family(peer, F4);
    let second = (0..PREFIXES).map(|index| route_from(SECOND, L4, index, 300, 100));
    send(&mut manager, SECOND, second.collect(), vec![]);
    send(&mut manager, SOURCE, rows(L4, 0..PREFIXES), vec![]);
    let growth = walk(&mut manager, &mut receivers, peer);
    growth.assert_sized_once("two paths a prefix");
    let out = &manager.adj_ribs_out[&peer];
    assert_eq!(out.labeled_len(), 2 * PREFIXES as usize);
    assert_eq!(out.labeled_key_len(), PREFIXES as usize);
    assert_eq!(receivers[0].wire.table.len(), 2 * PREFIXES as usize);
    assert_indexes_fitted(&manager, peer, "two paths a prefix");
}
