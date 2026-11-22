//! A private receiver's labeled-unicast cursor walk sizes its route and
//! prefix indexes once, while the table is nearly empty, from each AFI's
//! rows per prefix read so far and the prefixes still ahead of its cursor.

use super::super::cursor_presize::{
    Growth, PRESIZE_ROWS, assert_at_or_below_control, assert_fitted, dataset_chain, deny_med_chain,
    prefix_dataset, set_med, tenth_med, with_control,
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
    (growth.rebuilds, growth.resized) = ([0, 0], [0, 0]);
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
    growth.assert_sized_once_for_two_afis("both AFIs");
    let mut expected = table_of(L4, &all(ROWS));
    expected.extend(table_of(L6, &all(ROWS)));
    assert_eq!(receivers[0].wire.table, expected);
    assert_eq!(receivers[0].wire.markers, [1, 1]);
    assert_indexes_fitted(&manager, peer, "both AFIs");
}

/// Row `index` of `IPv4` labeled unicast with the MED [`deny_med_chain`]
/// passes one row in ten with.
fn tenth(index: u32) -> LabeledRibRoute {
    let mut route = route_from(SOURCE, L4, index, 100, 200);
    set_med(&mut route.attributes, tenth_med(index));
    route
}

/// A receiver behind [`deny_med_chain`] sending `add_path` paths a prefix
/// (`u32::MAX`: every path), owing `IPv4` labeled unicast whole.
fn filtered_receiver(manager: &mut RibManager, add_path: u32) -> Receiver {
    receiver_behind(manager, deny_med_chain(), add_path)
}

/// [`filtered_receiver`] behind `export_policy`.
fn receiver_behind(
    manager: &mut RibManager,
    export_policy: rustbgpd_policy::PolicyChain,
    add_path: u32,
) -> Receiver {
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
        export_policy: Some(export_policy),
        sendable_families: vec![L4],
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: if add_path == 0 { vec![] } else { vec![L4] },
        add_path_send_max: add_path,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: Vec::new(),
    });
    Wire::default().write(&mut rx);
    manager.owe_eor(peer, L4);
    manager.owe_whole_family(peer, F4);
    Receiver {
        peer,
        rx,
        wire: Wire::default(),
    }
}

/// Walk `rows` rows passing one in ten to a receiver sending `add_path`
/// paths a prefix: its indexes end within 2.3 times what it holds, after
/// one estimate.
fn filtered_walk(rows: u32, add_path: u32, case: &str) -> Growth {
    let mut manager = manager(4 * CHUNK_ROWS);
    sources_up(&mut manager);
    let mut receivers = vec![filtered_receiver(&mut manager, add_path)];
    let peer = receivers[0].peer;
    send(&mut manager, SOURCE, (0..rows).map(tenth).collect(), vec![]);
    let presizes = manager.adj_rib_out_commit_stats.walk_presizes;
    let growth = walk(&mut manager, &mut receivers, peer);
    let expected: Table = (0..rows)
        .filter(|index| index.is_multiple_of(10))
        .map(|index| entry(&tenth(index), u32::from(add_path != 0)))
        .collect();
    assert_eq!(receivers[0].wire.table, expected, "{case}");
    assert_indexes_fitted(&manager, peer, case);
    assert_eq!(
        manager.adj_rib_out_commit_stats.walk_presizes - presizes,
        1,
        "{case}: one estimate"
    );
    growth
}

/// A receiver whose export policy passes one row in ten: its indexes end
/// within 2.3 times what it holds. Red when the reserve is sized from the
/// prefixes ahead alone.
#[test]
fn a_filtered_labeled_walk_sizes_its_indexes_to_what_it_accepts() {
    let growth = filtered_walk(20_000, 0, "one row in ten");
    assert!(growth.rows_at_rebuild <= PRESIZE_ROWS, "{growth:?}");
}

/// An Add-Path send-all receiver (no `send_max`) reads one prefix a step;
/// its policy passes one row in ten. Red with a one-prefix sample: the
/// first accepted prefix reads as every prefix accepted.
#[test]
fn a_send_all_labeled_walk_sizes_its_indexes_to_what_it_accepts() {
    filtered_walk(20_000, u32::MAX, "send-all, one in ten");
}

/// An Add-Path receiver joins a hold and is released two paths of every
/// prefix. The prefix index is sized once, from the prefixes accepted per
/// prefix read; the route index for one row a prefix, since paths per
/// prefix vary with arrival order, and the steps grow it past that. Both
/// end at or below the walk with the presize off. Red when the prefix
/// index is sized from the clamped rows: it changes capacity in three
/// steps.
#[test]
fn an_add_path_labeled_walk_sizes_each_index_by_its_own_count() {
    const PREFIXES: u32 = 8_000;
    let shape = || {
        let mut manager = deferral_manager(4 * CHUNK_ROWS, &[L4]);
        sources_up(&mut manager);
        let second = (0..PREFIXES).map(|index| route_from(SECOND, L4, index, 300, 100));
        send(&mut manager, SECOND, second.collect(), vec![]);
        send(&mut manager, SOURCE, rows(L4, 0..PREFIXES), vec![]);
        let waiter = hold(&mut manager, &[L4]);
        let joiner = Receiver::up(&mut manager, receiver(0), 4096, &[L4], 2);
        let mut receivers = vec![joiner, waiter];
        release(&mut manager, L4);
        let peer = receivers[0].peer;
        let growth = walk(&mut manager, &mut receivers, peer);
        let out = &manager.adj_ribs_out[&peer];
        assert_eq!(out.labeled_len(), 2 * PREFIXES as usize);
        assert_eq!(out.labeled_key_len(), PREFIXES as usize);
        assert_eq!(receivers[0].wire.table.len(), 2 * PREFIXES as usize);
        assert_indexes_fitted(&manager, peer, "two paths a prefix");
        (growth.rebuilds[1], tables(&manager, peer).1)
    };
    let ((prefix_rebuilds, head), (_, control)) = with_control(shape);
    assert_eq!(prefix_rebuilds, 1, "the prefix index changes capacity once");
    assert_at_or_below_control(&head, &control, "two paths a prefix");
}

/// A restart walk at one row in ten with 8,000 of 50,000 prefixes
/// relabeled after the pass and before the first step. The relabels are
/// logged after the starting log, so the walk makes no estimate and the
/// table fits as without the presize. Red when the estimate ignores
/// prefixes logged after the starting log: one estimate.
#[test]
fn a_filtered_labeled_walk_with_relabels_ahead_fits() {
    const ROWS: u32 = 50_000;
    const AGAIN: u32 = 8_000;
    let relabeled = |index| {
        let mut route = route_from(SOURCE, L4, index, 101, 200);
        set_med(&mut route.attributes, tenth_med(index));
        route
    };
    let mut manager = manager(4 * CHUNK_ROWS);
    sources_up(&mut manager);
    let mut receivers = vec![filtered_receiver(&mut manager, 0)];
    let peer = receivers[0].peer;
    send(&mut manager, SOURCE, (0..ROWS).map(tenth).collect(), vec![]);
    let again = (ROWS - AGAIN..ROWS).map(relabeled).collect();
    send(&mut manager, SOURCE, again, vec![]);
    let presizes = manager.adj_rib_out_commit_stats.walk_presizes;
    walk(&mut manager, &mut receivers, peer);
    let expected: Table = (0..ROWS)
        .filter(|index| index.is_multiple_of(10))
        .map(|index| {
            let route = if index < ROWS - AGAIN {
                tenth(index)
            } else {
                relabeled(index)
            };
            entry(&route, 0)
        })
        .collect();
    assert_eq!(receivers[0].wire.table, expected);
    assert_indexes_fitted(&manager, peer, "one in ten, relabels ahead");
    assert_eq!(
        manager.adj_rib_out_commit_stats.walk_presizes - presizes,
        0,
        "no estimate"
    );
}

/// Add-Path send-all, every row accepted, in arrival order: [`SOURCE`]
/// sends 600 prefixes, [`SECOND`] the same 600 (a second path; each prefix
/// moves to the back of the list), then [`SOURCE`] 10,000 more. The second
/// path moves the 600 prefixes out of the walk's starting log, so nothing
/// is extrapolated over the later passes. Red when the estimate reads the
/// whole list ahead without the one-row clamp: the route index reserved
/// for two rows a prefix ahead, one capacity class past the walk without
/// the presize.
#[test]
fn a_send_all_labeled_walk_with_arrival_order_skew_fits() {
    const ROWS: u32 = 10_000;
    const DOUBLE: u32 = 600;
    let shape = || {
        let mut manager = manager(4 * CHUNK_ROWS);
        sources_up(&mut manager);
        let mut receivers = vec![Receiver::up(
            &mut manager,
            receiver(0),
            4096,
            &[L4],
            u32::MAX,
        )];
        let peer = receivers[0].peer;
        manager.owe_eor(peer, L4);
        manager.owe_whole_family(peer, F4);
        send(&mut manager, SOURCE, rows(L4, 0..DOUBLE), vec![]);
        let second = (0..DOUBLE).map(|index| route_from(SECOND, L4, index, 300, 100));
        send(&mut manager, SECOND, second.collect(), vec![]);
        send(
            &mut manager,
            SOURCE,
            rows(L4, DOUBLE..DOUBLE + ROWS),
            vec![],
        );
        walk(&mut manager, &mut receivers, peer);
        assert_eq!(
            receivers[0].wire.table.len(),
            (ROWS + 2 * DOUBLE) as usize,
            "every path sent"
        );
        assert_indexes_fitted(&manager, peer, "send-all, arrival skew");
        tables(&manager, peer).1
    };
    let (head, control) = with_control(shape);
    assert_at_or_below_control(&head, &control, "send-all, arrival skew");
}

/// 1,024 accepted prefixes, then 20,000 rejected in a later pass: only the
/// first pass after the cursor starts (its starting log) is a sample of
/// its own keys, so nothing is extrapolated over the rejected ones. Red
/// when the estimate extrapolates past the starting log: 28 times what the
/// table holds, against 1.75 times without the presize.
#[test]
fn an_accepted_labeled_block_ahead_of_a_rejected_one_fits() {
    const ACCEPTED: u32 = 1_024;
    let shape = || {
        let mut manager = manager(4 * CHUNK_ROWS);
        sources_up(&mut manager);
        let mut receivers = vec![filtered_receiver(&mut manager, 0)];
        let peer = receivers[0].peer;
        let row = |index: u32, med: u32| {
            let mut route = route_from(SOURCE, L4, index, 100, 200);
            set_med(&mut route.attributes, med);
            route
        };
        send(
            &mut manager,
            SOURCE,
            (0..ACCEPTED).map(|index| row(index, 0)).collect(),
            vec![],
        );
        let rejected = (ACCEPTED..ACCEPTED + 20_000).map(|index| row(index, 1));
        send(&mut manager, SOURCE, rejected.collect(), vec![]);
        drain(&mut manager, &mut receivers);
        assert_eq!(receivers[0].wire.table.len(), ACCEPTED as usize);
        assert_indexes_fitted(&manager, peer, "accepted, then rejected");
        tables(&manager, peer).1
    };
    let (head, control) = with_control(shape);
    assert_at_or_below_control(&head, &control, "accepted, then rejected");
}

/// One pass of 4,096 accepted and 20,000 denied prefixes (the starting
/// log), then the denied prefixes again at a new MED, before the first
/// step: the prefixes left in the starting log are the accepted ones. Red
/// with a rate per prefix read rather than per list position passed: 7
/// times what the table holds, against 1.75 times.
#[test]
fn denied_labeled_prefixes_logged_again_ahead_fit() {
    const ACCEPTED: u32 = 4_096;
    const TOTAL: u32 = ACCEPTED + 20_000;
    let shape = || {
        let mut manager = manager(4 * CHUNK_ROWS);
        sources_up(&mut manager);
        let mut receivers = vec![filtered_receiver(&mut manager, 0)];
        let peer = receivers[0].peer;
        let row = |index: u32, med: u32| {
            let mut route = route_from(SOURCE, L4, index, 100, 200);
            set_med(&mut route.attributes, med);
            route
        };
        let mixed = (0..TOTAL).map(|index| row(index, u32::from(index >= ACCEPTED)));
        send(&mut manager, SOURCE, mixed.collect(), vec![]);
        let again = (ACCEPTED..TOTAL).map(|index| row(index, 2));
        send(&mut manager, SOURCE, again.collect(), vec![]);
        drain(&mut manager, &mut receivers);
        assert_eq!(receivers[0].wire.table.len(), ACCEPTED as usize);
        assert_indexes_fitted(&manager, peer, "denied prefixes logged again");
        tables(&manager, peer).1
    };
    let (head, control) = with_control(shape);
    assert_at_or_below_control(&head, &control, "denied prefixes logged again");
}

/// The default step (credit 4,096, 1,024 prefixes): one in five of
/// 100,000 accepted, so the first step commits about 205 rows, under the
/// sample's 256. After it the source re-marks nine in ten accepted
/// prefixes so the receiver denies them, and the walk drains. The change
/// is logged after the starting log, so the walk makes no estimate. Red
/// when the estimate ignores prefixes logged after the starting log: 3.6
/// times what the table holds, against 1.8.
#[test]
fn accepted_labeled_prefixes_denied_after_a_default_step_fit() {
    const TOTAL: u32 = 100_000;
    let accepted = |i: u32| i.is_multiple_of(5);
    let kept = |i: u32| i.is_multiple_of(50);
    let row = |index: u32, med: u32| {
        let mut route = route_from(SOURCE, L4, index, 100, 200);
        set_med(&mut route.attributes, med);
        route
    };
    let shape = || {
        let mut manager = manager(4 * CHUNK_ROWS);
        sources_up(&mut manager);
        let mut receivers = vec![filtered_receiver(&mut manager, 0)];
        let peer = receivers[0].peer;
        let rows = (0..TOTAL).map(|i| row(i, u32::from(!accepted(i))));
        send(&mut manager, SOURCE, rows.collect(), vec![]);
        tick(&mut manager, &mut receivers);
        assert_eq!(
            manager.adj_rib_out_commit_stats.walk_presizes, 0,
            "the change lands before the estimate"
        );
        let again = (0..TOTAL)
            .filter(|&i| accepted(i) && !kept(i))
            .map(|i| row(i, 1));
        send(&mut manager, SOURCE, again.collect(), vec![]);
        drain(&mut manager, &mut receivers);
        assert_eq!(receivers[0].wire.table.len(), (TOTAL / 50) as usize);
        assert_indexes_fitted(&manager, peer, "denied after a default step");
        tables(&manager, peer).1
    };
    let (head, control) = with_control(shape);
    assert_at_or_below_control(&head, &control, "denied after a default step");
}

/// One in five labeled prefixes accepted through a policy dataset; after
/// one default step (about 205 rows) the peer manager publishes a swap to
/// one in fifty, and 8 steps run before the RIB receives the
/// re-evaluation. A receiver whose export policy reads a dataset makes no
/// estimate, so the table fits the control. Red when it estimates: the
/// sample mixes both contents' rows.
#[test]
fn a_labeled_dataset_swap_published_before_its_re_evaluation_fits() {
    use rustbgpd_policy::datasets::{DatasetHandle, DatasetKind};
    const TOTAL: u32 = 100_000;
    let allowed = |keep: fn(u32) -> bool| {
        prefix_dataset((0..TOTAL).filter(|&i| keep(i)).map(|i| prefix(L4, i)))
    };
    let shape = || {
        let handle = Arc::new(DatasetHandle::new(
            "allowed",
            DatasetKind::Prefix,
            allowed(|i| i % 5 == 0),
        ));
        let mut manager = manager(4 * CHUNK_ROWS);
        sources_up(&mut manager);
        let mut receivers = vec![receiver_behind(&mut manager, dataset_chain(&handle), 0)];
        let peer = receivers[0].peer;
        received(&mut manager, &all(TOTAL), &[]);
        tick(&mut manager, &mut receivers);
        let prior = handle.pin();
        assert!(handle.refresh(allowed(|i| i % 50 == 0)).is_some());
        for _ in 0..8 {
            tick(&mut manager, &mut receivers);
        }
        let (reply, mut result) = oneshot::channel();
        manager.handle_update(RibUpdate::ReevaluatePeerExportPolicies {
            peers: vec![peer],
            swaps: Some(vec![crate::update::DatasetSwap {
                handle: Arc::clone(&handle),
                prior,
            }]),
            reply,
        });
        result.try_recv().unwrap().unwrap();
        drain(&mut manager, &mut receivers);
        assert_eq!(receivers[0].wire.table.len(), (TOTAL / 50) as usize);
        (
            tables(&manager, peer).1,
            manager.adj_rib_out_commit_stats.walk_presizes,
        )
    };
    let ((head, presizes), (control, _)) = with_control(shape);
    assert_eq!(
        presizes, 0,
        "no estimate (capacities {head:?}, control {control:?})"
    );
    let spread = control.map(|capacity| capacity + capacity / 4);
    assert_at_or_below_control(&head, &spread, "dataset swap before its re-evaluation");
}
