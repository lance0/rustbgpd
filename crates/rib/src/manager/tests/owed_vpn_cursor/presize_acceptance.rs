//! Receiver shapes whose acceptance a walk's first keys misread: an
//! Add-Path send-all receiver reads one key a step, two AFIs accept
//! different fractions, a sparse receiver's early samples are noisy, and
//! paths per key vary with arrival order. Holes and withdrawals ahead of
//! the cursor, and rows the table held before the walk, must not count as
//! rows the walk committed for keys it read. The presize estimates once,
//! from the rows each AFI's cursor steps committed per key they read, so
//! each table ends within 2.3 times what it holds, as the steps' own
//! doubling leaves it.

use std::cell::RefCell;

use super::super::cursor_presize::{
    Growth, assert_at_or_below_control, assert_fitted, deny_med_chain, set_med, tenth_med,
    with_control, with_control_async,
};
use super::*;

/// Row `index` of `family` from `source` with `med`.
fn med_row(source: Ipv4Addr, family: (Afi, Safi), index: u32, med: u32) -> VpnRibRoute {
    let (label, pref) = if source == SOURCE {
        (100, 200)
    } else {
        (300, 100)
    };
    let mut route = route_from(source, family, index, label, pref);
    set_med(&mut route.attributes, med);
    route
}

fn assert_indexes_fitted(manager: &RibManager, peer: PeerId, case: &str) {
    let out = &manager.adj_ribs_out[&peer];
    let (routes, keys) = out.bench_vpn_capacities();
    assert_fitted(routes, out.vpn_len(), &format!("{case}: route index"));
    assert_fitted(keys, out.vpn_key_len(), &format!("{case}: key index"));
}

/// A receiver of `families` sending `add_path` paths a key (`u32::MAX`:
/// every path) behind `policy`, owing each family's End-of-RIB and the
/// family whole.
fn owing_receiver(
    manager: &mut RibManager,
    families: &[(Afi, Safi)],
    add_path: u32,
    policy: Option<PolicyChain>,
) -> Receiver {
    let peer = receiver(0);
    let mut rx = up_with(manager, peer, 0, 4096, families, add_path, policy);
    Wire::default().write(&mut rx);
    for &family in families {
        manager.owe_eor(peer, family);
        manager.owe_whole_family(peer, owed_family(family));
    }
    Receiver {
        peer,
        rx,
        wire: Wire::default(),
    }
}

/// Add-Path send-all (no `send_max`, the default): every cursor step reads
/// one key. Export policy passes one row in ten. Red with a one-key
/// sample: the first accepted key reads as every key accepted, about 14
/// times the table.
#[test]
fn a_send_all_vpn_walk_sizes_its_indexes_to_what_it_accepts() {
    const ROWS: u32 = 20_000;
    let mut manager = manager(4 * CHUNK_ROWS);
    sources_up(&mut manager);
    let mut receivers = vec![owing_receiver(
        &mut manager,
        &[P4],
        u32::MAX,
        Some(deny_med_chain()),
    )];
    let peer = receivers[0].peer;
    let rows = (0..ROWS).map(|i| med_row(SOURCE, P4, i, tenth_med(i)));
    send(&mut manager, SOURCE, rows.collect(), vec![]);
    let presizes = manager.adj_rib_out_commit_stats.walk_presizes;
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table.len(), (ROWS / 10) as usize);
    assert!(manager.owing(peer).is_none());
    assert_indexes_fitted(&manager, peer, "send-all, one in ten");
    assert_eq!(
        manager.adj_rib_out_commit_stats.walk_presizes - presizes,
        1,
        "one estimate"
    );
}

/// Add-Path send-all, every row accepted, the first 64 keys with two
/// paths and the rest with one: the route index is sized for one path a
/// key, not the most an early key had, and the steps grow it past that.
#[test]
fn a_send_all_vpn_walk_with_uneven_paths_sizes_routes_by_the_average() {
    const ROWS: u32 = 20_000;
    const DOUBLE: u32 = 64;
    let mut manager = manager(4 * CHUNK_ROWS);
    sources_up(&mut manager);
    let mut receivers = vec![owing_receiver(&mut manager, &[P4], u32::MAX, None)];
    let peer = receivers[0].peer;
    let first = (0..DOUBLE).map(|i| med_row(SOURCE, P4, i, 0)).collect();
    send(&mut manager, SOURCE, first, vec![]);
    let second = (0..DOUBLE).map(|i| med_row(SECOND, P4, i, 0)).collect();
    send(&mut manager, SECOND, second, vec![]);
    let rest = (DOUBLE..ROWS).map(|i| med_row(SOURCE, P4, i, 0)).collect();
    send(&mut manager, SOURCE, rest, vec![]);
    drain(&mut manager, &mut receivers);
    assert_eq!(
        receivers[0].wire.table.len(),
        (ROWS + DOUBLE) as usize,
        "every path sent"
    );
    assert_indexes_fitted(&manager, peer, "send-all, uneven paths");
}

/// Two VPN AFIs in one pair of indexes: `VPNv4` 2,000 rows all accepted,
/// `VPNv6` 20,000 rows of which one in ten is accepted. Each AFI adds its
/// own rate times its own keys ahead. Red with one rate for both lists:
/// about seven times the table.
#[test]
fn two_vpn_afis_accepting_differently_each_add_their_own_rate() {
    const V4_ROWS: u32 = 2_000;
    const V6_ROWS: u32 = 20_000;
    let mut manager = manager(4 * CHUNK_ROWS);
    sources_up(&mut manager);
    let mut receivers = vec![owing_receiver(
        &mut manager,
        &[P4, P6],
        0,
        Some(deny_med_chain()),
    )];
    let peer = receivers[0].peer;
    let v4 = (0..V4_ROWS).map(|i| med_row(SOURCE, P4, i, 0)).collect();
    send(&mut manager, SOURCE, v4, vec![]);
    let v6 = (0..V6_ROWS).map(|i| med_row(SOURCE, P6, i, tenth_med(i)));
    send(&mut manager, SOURCE, v6.collect(), vec![]);
    drain(&mut manager, &mut receivers);
    assert_eq!(
        receivers[0].wire.table.len(),
        (V4_ROWS + V6_ROWS / 10) as usize
    );
    assert_indexes_fitted(&manager, peer, "two AFIs, 100% and 10%");
}

/// About 1% of 100,000 keys accepted, scattered: the table stays under
/// the presize limit for most of the walk. One estimate, made once the
/// sample holds enough accepted rows. Red when every step under the limit
/// estimates again: the largest noisy estimate stays, one doubling more.
#[test]
fn a_sparse_vpn_walk_estimates_once_from_a_full_sample() {
    const ROWS: u32 = 100_000;
    let mut manager = manager(4 * CHUNK_ROWS);
    sources_up(&mut manager);
    let mut receivers = vec![owing_receiver(
        &mut manager,
        &[P4],
        0,
        Some(deny_med_chain()),
    )];
    let peer = receivers[0].peer;
    let accept = |i: u32| i.wrapping_mul(2_654_435_761).is_multiple_of(100);
    let rows = (0..ROWS).map(|i| med_row(SOURCE, P4, i, u32::from(!accept(i))));
    send(&mut manager, SOURCE, rows.collect(), vec![]);
    let presizes = manager.adj_rib_out_commit_stats.walk_presizes;
    drain(&mut manager, &mut receivers);
    let accepted = (0..ROWS).filter(|&i| accept(i)).count();
    assert_eq!(receivers[0].wire.table.len(), accepted);
    assert_indexes_fitted(&manager, peer, "1% scattered");
    assert_eq!(
        manager.adj_rib_out_commit_stats.walk_presizes - presizes,
        1,
        "one estimate"
    );
}

// Through the actor loop on a paused clock: a selection release starts
// the cursors.

/// What the actor-turn check last read of the watched receiver's VPN
/// table: rows, keys, and the two indexes' capacities.
#[derive(Debug, Default, Clone, Copy)]
struct Last {
    rows: usize,
    keys: usize,
    capacities: [usize; 2],
}

thread_local! {
    static WATCHED: RefCell<Option<(PeerId, Growth, Last)>> = const { RefCell::new(None) };
}

fn watch(manager: &RibManager) {
    WATCHED.with(|watched| {
        if let Some((peer, growth, last)) = watched.borrow_mut().as_mut()
            && let Some(out) = manager.adj_ribs_out.get(peer)
        {
            let (routes, keys) = out.bench_vpn_capacities();
            growth.observe(out.vpn_len(), [routes, keys]);
            *last = Last {
                rows: out.vpn_len(),
                keys: out.vpn_key_len(),
                capacities: [routes, keys],
            };
        }
    });
}

/// [`actor::peer_up`] with `add_path` paths a key and `export_policy`.
fn peer_up_with(
    peer: PeerId,
    families: &[(Afi, Safi)],
    add_path: u32,
    export_policy: Option<PolicyChain>,
) -> (RibUpdate, mpsc::Receiver<OutboundRouteUpdate>) {
    let (mut update, rx) = actor::peer_up(peer, 0, 4096, families);
    if let RibUpdate::PeerUp {
        export_policy: policy,
        add_path_send_families,
        add_path_send_max,
        ..
    } = &mut update
    {
        *policy = export_policy;
        if add_path != 0 {
            *add_path_send_families = families.to_vec();
        }
        *add_path_send_max = add_path;
    }
    (update, rx)
}

/// Hold both AFIs, send `rows`, join a receiver with `add_path` and
/// `policy`, release both AFIs with `after` queued in the same turn
/// (before any cursor step), and run `ticks` 10 ms ticks. The actor is
/// `RibManager::run` when `through_run`, else `RibManager::run_actor`,
/// which it wraps (the manager comes back to be checked). Returns the
/// receivers and the last reading of the joiner's table.
async fn actor_walk(
    rows: Vec<VpnRibRoute>,
    after: Vec<RibUpdate>,
    add_path: u32,
    policy: Option<PolicyChain>,
    ticks: usize,
    through_run: bool,
) -> (Vec<Receiver>, Last) {
    let mut manager = deferral_manager(4 * CHUNK_ROWS, &[P4, P6]);
    manager.actor_turn_check = Some(watch);
    let (tx, rx) = mpsc::channel(256);
    manager.rx = rx;
    let (run, run_actor) = if through_run {
        (Some(tokio::spawn(manager.run())), None)
    } else {
        (None, Some(tokio::spawn(manager.run_actor())))
    };
    let mut sources = Vec::new();
    for source in [SOURCE, SECOND] {
        let (update, rx) = actor::peer_up(peer_v4(source), 0, 4096, &[V4]);
        tx.send(update).await.unwrap();
        sources.push(rx);
    }
    tx.send(RibUpdate::VpnRoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 0,
        announced: rows,
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(gr_context(&[P4, P6])).await.unwrap();
    let (update, waiter_rx) = actor::peer_up(peer_v4(WAITER), 7, 4096, &[P4, P6]);
    tx.send(update).await.unwrap();
    let joiner = receiver(0);
    let (update, joiner_rx) = peer_up_with(joiner, &[P4, P6], add_path, policy);
    tx.send(update).await.unwrap();
    let mut receivers = vec![
        Receiver {
            peer: joiner,
            rx: joiner_rx,
            wire: Wire::default(),
        },
        Receiver {
            peer: peer_v4(WAITER),
            rx: waiter_rx,
            wire: Wire::default(),
        },
    ];
    actor::run_for(&tx, &mut receivers, &[true; 2], 5).await;
    assert!(receivers[0].wire.table.is_empty(), "the joiner waits");
    WATCHED.with(|watched| {
        *watched.borrow_mut() = Some((joiner, Growth::default(), Last::default()));
    });
    for family in [P4, P6] {
        tx.send(RibUpdate::EndOfRib {
            peer: peer_v4(WAITER),
            session_id: 7,
            afi: family.0,
            safi: family.1,
        })
        .await
        .unwrap();
    }
    for update in after {
        tx.send(update).await.unwrap();
    }
    actor::run_for(&tx, &mut receivers, &[true; 2], ticks).await;
    drop(tx);
    if let Some(run) = run {
        run.await.unwrap();
    }
    if let Some(run_actor) = run_actor {
        let manager = run_actor.await.unwrap();
        assert!(manager.owing(joiner).is_none(), "the joiner settled");
        assert_indexes_fitted(&manager, joiner, "actor loop");
    }
    drop(sources);
    let (_, _, last) = WATCHED.with(|watched| watched.borrow_mut().take()).unwrap();
    assert_eq!(receivers[0].wire.markers, [1, 1], "the joiner settled");
    (receivers, last)
}

/// Two AFIs accepting 100% and 10% through `RibManager::run_actor`.
#[tokio::test(start_paused = true)]
async fn two_vpn_afis_accepting_differently_through_the_actor_loop_fit() {
    const V4_ROWS: u32 = 1_000;
    const V6_ROWS: u32 = 10_000;
    let mut rows: Vec<_> = (0..V4_ROWS).map(|i| med_row(SOURCE, P4, i, 0)).collect();
    rows.extend((0..V6_ROWS).map(|i| med_row(SOURCE, P6, i, tenth_med(i))));
    let (receivers, _) = Box::pin(actor_walk(
        rows,
        vec![],
        0,
        Some(deny_med_chain()),
        400,
        false,
    ))
    .await;
    assert_eq!(
        receivers[0].wire.table.len(),
        (V4_ROWS + V6_ROWS / 10) as usize
    );
}

/// Add-Path send-all behind a policy passing one row in ten, through
/// `RibManager::run` (the daemon's entry point, with its slice timing):
/// the table read after the last actor turn fits what it holds. Red with
/// a one-key sample: about 18 times the table.
#[tokio::test(start_paused = true)]
async fn a_send_all_vpn_walk_through_the_run_loop_fits() {
    const ROWS: u32 = 4_000;
    let rows = (0..ROWS)
        .map(|i| med_row(SOURCE, P4, i, tenth_med(i)))
        .collect();
    let (receivers, last) = Box::pin(actor_walk(
        rows,
        vec![],
        u32::MAX,
        Some(deny_med_chain()),
        6_000,
        true,
    ))
    .await;
    assert_eq!(receivers[0].wire.table.len(), (ROWS / 10) as usize);
    assert_eq!(last.rows, (ROWS / 10) as usize, "{last:?}");
    assert_fitted(last.capacities[0], last.rows, "run loop: route index");
    assert_fitted(last.capacities[1], last.keys, "run loop: key index");
}

// The walk's own counts: rows added and keys read.

/// Row `index` of `VPNv4` with `label` and `med`: a new label logs the key
/// again.
fn labeled_row(index: u32, label: u32, med: u32) -> VpnRibRoute {
    let mut route = route_from(SOURCE, P4, index, label, 200);
    set_med(&mut route.attributes, med);
    route
}

/// Every key accepted; the source withdraws its last 700 keys after the
/// pass logs them and before the receiver's first step. A withdrawn key
/// stays a list entry ahead of the cursor and leaves the Loc-RIB. The
/// withdrawals are logged after the starting log, so the walk makes no
/// estimate and the table fits as without the presize (1.49 times what it
/// holds). Red when the estimate ignores keys logged after the starting
/// log: one estimate.
#[test]
fn withdrawals_ahead_of_a_vpn_cursor_do_not_inflate_the_rate() {
    const ROWS: u32 = 20_000;
    const GONE: u32 = 700;
    let mut manager = manager(4 * CHUNK_ROWS);
    sources_up(&mut manager);
    let mut receivers = vec![owing_receiver(&mut manager, &[P4], 0, None)];
    let peer = receivers[0].peer;
    let rows = (0..ROWS).map(|i| med_row(SOURCE, P4, i, 0)).collect();
    send(&mut manager, SOURCE, rows, vec![]);
    let gone = (ROWS - GONE..ROWS).map(|i| key(P4, i)).collect();
    send(&mut manager, SOURCE, vec![], gone);
    let presizes = manager.adj_rib_out_commit_stats.walk_presizes;
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table.len(), (ROWS - GONE) as usize);
    assert_indexes_fitted(&manager, peer, "withdrawals ahead");
    assert_eq!(
        manager.adj_rib_out_commit_stats.walk_presizes - presizes,
        0,
        "no estimate"
    );
}

/// As above with 1,400 keys relabeled instead of withdrawn: each leaves a
/// hole ahead of the cursor, with no Loc-RIB change. Red with the derived
/// count: about 2.9 times what it holds.
#[test]
fn relabels_ahead_of_a_vpn_cursor_do_not_inflate_the_rate() {
    const ROWS: u32 = 20_000;
    const AGAIN: u32 = 1_400;
    let mut manager = manager(4 * CHUNK_ROWS);
    sources_up(&mut manager);
    let mut receivers = vec![owing_receiver(&mut manager, &[P4], 0, None)];
    let peer = receivers[0].peer;
    let rows = (0..ROWS).map(|i| labeled_row(i, 100, 0)).collect();
    send(&mut manager, SOURCE, rows, vec![]);
    let again = (ROWS - AGAIN..ROWS)
        .map(|i| labeled_row(i, 101, 0))
        .collect();
    send(&mut manager, SOURCE, again, vec![]);
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table.len(), ROWS as usize);
    assert_indexes_fitted(&manager, peer, "relabels ahead");
}

/// A restart walk at one row in ten with 8,000 of 50,000 keys relabeled
/// after the pass and before the first step. The relabels are logged
/// after the starting log, so the walk makes no estimate and the table
/// fits as without the presize (1.43 times what it holds). Red when the
/// estimate ignores keys logged after the starting log: one estimate.
#[test]
fn a_filtered_vpn_walk_with_relabels_ahead_fits() {
    const ROWS: u32 = 50_000;
    const AGAIN: u32 = 8_000;
    let mut manager = manager(4 * CHUNK_ROWS);
    sources_up(&mut manager);
    let mut receivers = vec![owing_receiver(
        &mut manager,
        &[P4],
        0,
        Some(deny_med_chain()),
    )];
    let peer = receivers[0].peer;
    let rows = (0..ROWS).map(|i| labeled_row(i, 100, tenth_med(i)));
    send(&mut manager, SOURCE, rows.collect(), vec![]);
    let again = (ROWS - AGAIN..ROWS).map(|i| labeled_row(i, 101, tenth_med(i)));
    send(&mut manager, SOURCE, again.collect(), vec![]);
    let presizes = manager.adj_rib_out_commit_stats.walk_presizes;
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table.len(), (ROWS / 10) as usize);
    assert_indexes_fitted(&manager, peer, "one in ten, relabels ahead");
    assert_eq!(
        manager.adj_rib_out_commit_stats.walk_presizes - presizes,
        0,
        "no estimate"
    );
}

/// A receiver behind a one-in-ten policy already holds its 1,500 rows
/// (under the presize limit) when a cursor starts at the list head, and a
/// pass then relabels every key. The walk adds no row, so it makes no
/// estimate and the table keeps its size. Red without the rows held at
/// the first step left out: 1,500 rows over about 1,000 keys read, about
/// 19 times what it holds.
#[test]
fn a_small_populated_vpn_table_walked_again_keeps_its_size() {
    const ROWS: u32 = 15_000;
    let mut manager = manager(4 * CHUNK_ROWS);
    sources_up(&mut manager);
    let peer = receiver(0);
    let rx = up_with(
        &mut manager,
        peer,
        0,
        4096,
        &[P4],
        0,
        Some(deny_med_chain()),
    );
    let mut receivers = vec![Receiver {
        peer,
        rx,
        wire: Wire::default(),
    }];
    let first = (0..ROWS).map(|i| labeled_row(i, 100, tenth_med(i)));
    send(&mut manager, SOURCE, first.collect(), vec![]);
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table.len(), (ROWS / 10) as usize);
    let presizes = manager.adj_rib_out_commit_stats.walk_presizes;
    manager.owe_whole_family(peer, F4);
    let again = (0..ROWS).map(|i| labeled_row(i, 101, tenth_med(i)));
    send(&mut manager, SOURCE, again.collect(), vec![]);
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table.len(), (ROWS / 10) as usize);
    assert!(manager.owing(peer).is_none());
    assert_indexes_fitted(&manager, peer, "populated, walked again");
    assert_eq!(
        manager.adj_rib_out_commit_stats.walk_presizes, presizes,
        "the walk added no row"
    );
}

/// The shape above through `RibManager::run_actor` on a paused clock,
/// with no direct call: the receiver holds its 1,500 rows and stops
/// reading; one relabel pass overfills its owed set past the byte cap,
/// which starts the cursor at the list head, and a second logs every key
/// ahead of it. Then the receiver reads again. Red with the derived
/// count: about 38 times what it holds.
#[tokio::test(start_paused = true)]
async fn a_byte_cap_cursor_over_a_small_vpn_table_through_the_actor_loop_fits() {
    const ROWS: u32 = 15_000;
    let mut manager = deferral_manager(256, &[]);
    manager.actor_turn_check = Some(watch);
    let (tx, rx) = mpsc::channel(256);
    manager.rx = rx;
    let actor = tokio::spawn(manager.run_actor());
    let mut sources = Vec::new();
    for source in [SOURCE, SECOND] {
        let (update, rx) = actor::peer_up(peer_v4(source), 0, 4096, &[V4]);
        tx.send(update).await.unwrap();
        sources.push(rx);
    }
    let pass = |label| RibUpdate::VpnRoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 0,
        announced: (0..ROWS)
            .map(|i| labeled_row(i, label, tenth_med(i)))
            .collect(),
        withdrawn: vec![],
    };
    tx.send(pass(100)).await.unwrap();
    let peer = receiver(0);
    let (update, rx) = peer_up_with(peer, &[P4], 0, Some(deny_med_chain()));
    tx.send(update).await.unwrap();
    let mut receivers = vec![Receiver {
        peer,
        rx,
        wire: Wire::default(),
    }];
    actor::run_for(&tx, &mut receivers, &[true], 200).await;
    assert_eq!(receivers[0].wire.table.len(), (ROWS / 10) as usize);
    tx.send(pass(101)).await.unwrap();
    actor::run_for(&tx, &mut receivers, &[false], 5).await;
    tx.send(pass(102)).await.unwrap();
    actor::run_for(&tx, &mut receivers, &[false], 5).await;
    actor::run_for(&tx, &mut receivers, &[true], 2_000).await;
    drop(tx);
    let manager = actor.await.unwrap();
    drop(sources);
    assert!(manager.owing(peer).is_none(), "settled");
    assert_eq!(receivers[0].wire.table.len(), (ROWS / 10) as usize);
    assert!(
        receivers[0]
            .wire
            .table
            .values()
            .all(|row| row.contains("102")),
        "every row at its newest label"
    );
    assert_indexes_fitted(&manager, peer, "byte-cap cursor, small table");
}

/// The filtered walk with relabels ahead through `RibManager::run_actor`:
/// a selection release, then the relabel in the same turn, before any
/// step.
#[tokio::test(start_paused = true)]
async fn a_filtered_vpn_release_with_relabels_ahead_through_the_actor_loop_fits() {
    const ROWS: u32 = 50_000;
    const AGAIN: u32 = 8_000;
    let rows = (0..ROWS)
        .map(|i| labeled_row(i, 100, tenth_med(i)))
        .collect();
    let again = RibUpdate::VpnRoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 0,
        announced: (ROWS - AGAIN..ROWS)
            .map(|i| labeled_row(i, 101, tenth_med(i)))
            .collect(),
        withdrawn: vec![],
    };
    let (receivers, _) = Box::pin(actor_walk(
        rows,
        vec![again],
        0,
        Some(deny_med_chain()),
        400,
        false,
    ))
    .await;
    assert_eq!(receivers[0].wire.table.len(), (ROWS / 10) as usize);
}

/// Every key accepted, through `RibManager::run_actor`: a selection
/// release starts the cursor, and a withdrawal of the last 700 keys
/// arrives in the same turn, before any step. Red with keys read taken as
/// the Loc-RIB's keys less the entries ahead: about three times what it
/// holds (1.49 times without the presize).
#[tokio::test(start_paused = true)]
async fn withdrawals_ahead_of_a_vpn_release_through_the_actor_loop_fit() {
    const ROWS: u32 = 20_000;
    const GONE: u32 = 700;
    let shape = || {
        let rows = (0..ROWS).map(|i| med_row(SOURCE, P4, i, 0)).collect();
        let withdrawal = RibUpdate::VpnRoutesReceived {
            peer: peer_v4(SOURCE),
            session_id: 0,
            announced: vec![],
            withdrawn: (ROWS - GONE..ROWS)
                .map(|i| VpnRibRouteKey {
                    nlri_key: key(P4, i),
                    path_id: 0,
                })
                .collect(),
        };
        actor_walk(rows, vec![withdrawal], 0, None, 400, false)
    };
    let ((receivers, head), (_, control)) = Box::pin(with_control_async(shape)).await;
    assert_eq!(receivers[0].wire.table.len(), (ROWS - GONE) as usize);
    assert_at_or_below_control(&head.capacities, &control.capacities, "withdrawals ahead");
}

/// Add-Path send-all, every row accepted, in arrival order: [`SOURCE`]
/// sends 600 keys, [`SECOND`] the same 600 (a second path; each key moves
/// to the back of the list), then [`SOURCE`] 20,000 more. The second path
/// moves the 600 keys out of the walk's starting log, so nothing is
/// extrapolated over the later passes. Red when the estimate reads the
/// whole list ahead without the one-row clamp: the route index reserved
/// for two rows a key ahead (2.7 times what it holds, 1.35 times without
/// the presize).
#[test]
fn a_send_all_vpn_walk_with_arrival_order_skew_fits() {
    const ROWS: u32 = 20_000;
    const DOUBLE: u32 = 600;
    let shape = || {
        let mut manager = manager(4 * CHUNK_ROWS);
        sources_up(&mut manager);
        let mut receivers = vec![owing_receiver(&mut manager, &[P4], u32::MAX, None)];
        let peer = receivers[0].peer;
        let first = (0..DOUBLE).map(|i| med_row(SOURCE, P4, i, 0)).collect();
        send(&mut manager, SOURCE, first, vec![]);
        let second = (0..DOUBLE).map(|i| med_row(SECOND, P4, i, 0)).collect();
        send(&mut manager, SECOND, second, vec![]);
        let rest = (DOUBLE..DOUBLE + ROWS)
            .map(|i| med_row(SOURCE, P4, i, 0))
            .collect();
        send(&mut manager, SOURCE, rest, vec![]);
        drain(&mut manager, &mut receivers);
        assert_eq!(
            receivers[0].wire.table.len(),
            (ROWS + 2 * DOUBLE) as usize,
            "every path sent"
        );
        assert_indexes_fitted(&manager, peer, "send-all, arrival skew");
        let (routes, keys) = manager.adj_ribs_out[&peer].bench_vpn_capacities();
        [routes, keys]
    };
    let (head, control) = with_control(shape);
    assert_at_or_below_control(&head, &control, "send-all, arrival skew");
}

// Acceptance in blocks: the list is in arrival order across passes, so
// only the walk's starting log (one pass, logged from a hash set) is a
// random order of its keys. The first pass after the cursor starts is
// that log here, as a release's inventory is in the daemon.

/// What [`deny_med_chain`] passes: every row, none, or one in ten.
const ACCEPTED: fn(u32) -> u32 = |_| 0;
const REJECTED: fn(u32) -> u32 = |_| 1;
const TENTH: fn(u32) -> u32 = tenth_med;

/// One pass: its source, its keys and each key's MED.
type Pass = (Ipv4Addr, std::ops::Range<u32>, fn(u32) -> u32);

/// A `VPNv4` receiver sending `add_path` paths a key behind
/// [`deny_med_chain`] owes it whole, then each of `passes` (source, keys,
/// MED by key) arrives as one pass. Returns the rows sent and the index
/// capacities after the walk.
fn passes_walk(add_path: u32, passes: &[Pass], case: &str) -> (usize, [usize; 2]) {
    let mut manager = manager(4 * CHUNK_ROWS);
    sources_up(&mut manager);
    let mut receivers = vec![owing_receiver(
        &mut manager,
        &[P4],
        add_path,
        Some(deny_med_chain()),
    )];
    let peer = receivers[0].peer;
    for (source, keys, med) in passes {
        let rows = keys
            .clone()
            .map(|index| med_row(*source, P4, index, med(index)))
            .collect();
        send(&mut manager, *source, rows, vec![]);
    }
    drain(&mut manager, &mut receivers);
    assert_indexes_fitted(&manager, peer, case);
    let (routes, keys) = manager.adj_ribs_out[&peer].bench_vpn_capacities();
    (receivers[0].wire.table.len(), [routes, keys])
}

/// [`passes_walk`] with the presize and without: `rows` sent, and every
/// index at or below the control's.
fn assert_passes_fit(add_path: u32, passes: &[Pass], rows: u32, case: &str) {
    let ((sent, head), (_, control)) = with_control(|| passes_walk(add_path, passes, case));
    assert_eq!(sent, rows as usize, "{case}: rows sent");
    assert_at_or_below_control(&head, &control, case);
}

/// 1,024 accepted keys, then 20,000 rejected in a later pass. Red when the
/// estimate extrapolates past the starting log: both indexes 28 times what
/// they hold, against 1.75 times without the presize.
#[test]
fn an_accepted_block_ahead_of_a_rejected_one_fits() {
    assert_passes_fit(
        0,
        &[
            (SOURCE, 0..1_024, ACCEPTED),
            (SOURCE, 1_024..21_024, REJECTED),
        ],
        1_024,
        "accepted, then rejected",
    );
}

/// 2,000 accepted keys, then 50,000 at one in ten in a later pass (7,000
/// rows). Red when the estimate extrapolates past the starting log: 8.2
/// times what the table holds, against 1.02 times.
#[test]
fn an_accepted_block_ahead_of_a_tenth_fits() {
    assert_passes_fit(
        0,
        &[(SOURCE, 0..2_000, ACCEPTED), (SOURCE, 2_000..52_000, TENTH)],
        7_000,
        "accepted, then one in ten",
    );
}

/// A bounded Add-Path receiver (`send_max` 8), every row accepted, in
/// arrival order: [`SOURCE`] sends 600 keys, [`SECOND`] the same 600, then
/// [`SOURCE`] 20,000 more. The second path moves each of the 600 keys out
/// of the starting log, so nothing is extrapolated. Red when the estimate
/// reads the whole list ahead with only send-all clamped: the route index
/// 2.7 times what it holds, against 1.35 times.
#[test]
fn a_bounded_add_path_vpn_walk_with_arrival_order_skew_fits() {
    assert_passes_fit(
        8,
        &[
            (SOURCE, 0..600, ACCEPTED),
            (SECOND, 0..600, ACCEPTED),
            (SOURCE, 600..20_600, ACCEPTED),
        ],
        21_200,
        "send_max 8, arrival skew",
    );
}

/// A bounded Add-Path receiver (`send_max` 8) joins a hold and is released
/// 9,000 keys with two paths each; then [`SECOND`] withdraws its path of
/// 6,000 of them before the first step, which logs those keys again past
/// the release's inventory. The walk reads two-path keys, while the keys
/// ahead also count the holes the withdrawals left in the inventory, whose
/// keys now carry one path. Clamped at one row a key, those holes cost at
/// most a row each; at two rows a key the route index is reserved past
/// 14,336 for 12,000 rows. Red when a bounded Add-Path receiver is clamped
/// at its `send_max` rather than one row a key.
#[test]
fn a_bounded_add_path_release_with_second_paths_withdrawn_ahead_fits() {
    const KEYS: u32 = 9_000;
    const WITHDRAWN: u32 = 6_000;
    let shape = || {
        let mut manager = deferral_manager(4 * CHUNK_ROWS, &[P4]);
        sources_up(&mut manager);
        for source in [SECOND, SOURCE] {
            let rows = (0..KEYS).map(|i| med_row(source, P4, i, 0)).collect();
            send(&mut manager, source, rows, vec![]);
        }
        let waiter = hold(&mut manager, &[P4]);
        let joiner = Receiver::up(&mut manager, receiver(0), 4096, &[P4], 8);
        let mut receivers = vec![joiner, waiter];
        release(&mut manager, P4);
        let withdrawn = (KEYS - WITHDRAWN..KEYS)
            .map(|i| med_row(SECOND, P4, i, 0).key().nlri_key)
            .collect();
        send(&mut manager, SECOND, vec![], withdrawn);
        let peer = receivers[0].peer;
        drain(&mut manager, &mut receivers);
        assert_eq!(
            receivers[0].wire.table.len(),
            (2 * KEYS - WITHDRAWN) as usize
        );
        assert_indexes_fitted(&manager, peer, "second paths withdrawn ahead");
        let (routes, keys) = manager.adj_ribs_out[&peer].bench_vpn_capacities();
        [routes, keys]
    };
    let (head, control) = with_control(shape);
    assert_at_or_below_control(&head, &control, "second paths withdrawn ahead");
}

/// Through `RibManager::run` on a paused clock, no direct call: 1,024
/// accepted keys are held by a selection deferral while the receiver
/// joins, the release starts its cursor and logs them, and 20,000 rejected
/// keys arrive in the same turn, before any cursor step. Red when the
/// estimate extrapolates past the release's inventory: 28 times what the
/// table holds, in one rebuild, against 1.75 times.
#[tokio::test(start_paused = true)]
async fn a_clustered_vpn_release_through_the_run_loop_fits() {
    const ACCEPTED_KEYS: u32 = 1_024;
    let shape = || async {
        let rows = (0..ACCEPTED_KEYS)
            .map(|i| med_row(SOURCE, P4, i, 0))
            .collect();
        let rejected = RibUpdate::VpnRoutesReceived {
            peer: peer_v4(SOURCE),
            session_id: 0,
            announced: (ACCEPTED_KEYS..ACCEPTED_KEYS + 20_000)
                .map(|i| med_row(SOURCE, P4, i, 1))
                .collect(),
            withdrawn: vec![],
        };
        let (receivers, last) = Box::pin(actor_walk(
            rows,
            vec![rejected],
            0,
            Some(deny_med_chain()),
            600,
            true,
        ))
        .await;
        assert_eq!(receivers[0].wire.table.len(), ACCEPTED_KEYS as usize);
        assert_eq!(last.rows, ACCEPTED_KEYS as usize, "{last:?}");
        assert_fitted(last.capacities[0], last.rows, "run loop: route index");
        assert_fitted(last.capacities[1], last.keys, "run loop: key index");
        last.capacities
    };
    let (head, control) = Box::pin(with_control_async(shape)).await;
    assert_at_or_below_control(&head, &control, "clustered release, run loop");
}

/// The byte-cap shape above, with acceptance in blocks ahead of the
/// cursor: after the relabel pass starts it, 1,024 fresh accepted keys
/// arrive, then 20,000 fresh rejected keys, while the receiver is paused.
/// A byte-cap cursor has no starting log (every key ahead of it is a later
/// arrival), so its walk makes no estimate and the table grows as with the
/// presize off. Red when a byte-cap cursor extrapolates over the list
/// ahead: the accepted block's rate reserves the indexes for every
/// rejected key.
#[tokio::test(start_paused = true)]
async fn a_byte_cap_cursor_ahead_of_acceptance_in_blocks_makes_no_estimate() {
    const ROWS: u32 = 15_000;
    const FRESH: u32 = 1_024;
    let shape = || async {
        let mut manager = deferral_manager(256, &[]);
        manager.actor_turn_check = Some(watch);
        let (tx, rx) = mpsc::channel(256);
        manager.rx = rx;
        let actor = tokio::spawn(manager.run_actor());
        let mut sources = Vec::new();
        for source in [SOURCE, SECOND] {
            let (update, rx) = actor::peer_up(peer_v4(source), 0, 4096, &[V4]);
            tx.send(update).await.unwrap();
            sources.push(rx);
        }
        let pass =
            |keys: std::ops::Range<u32>, label, med: fn(u32) -> u32| RibUpdate::VpnRoutesReceived {
                peer: peer_v4(SOURCE),
                session_id: 0,
                announced: keys.map(|i| labeled_row(i, label, med(i))).collect(),
                withdrawn: vec![],
            };
        tx.send(pass(0..ROWS, 100, TENTH)).await.unwrap();
        let peer = receiver(0);
        let (update, rx) = peer_up_with(peer, &[P4], 0, Some(deny_med_chain()));
        tx.send(update).await.unwrap();
        let mut receivers = vec![Receiver {
            peer,
            rx,
            wire: Wire::default(),
        }];
        actor::run_for(&tx, &mut receivers, &[true], 200).await;
        assert_eq!(receivers[0].wire.table.len(), (ROWS / 10) as usize);
        tx.send(pass(0..ROWS, 101, TENTH)).await.unwrap();
        actor::run_for(&tx, &mut receivers, &[false], 5).await;
        tx.send(pass(ROWS..ROWS + FRESH, 100, ACCEPTED))
            .await
            .unwrap();
        actor::run_for(&tx, &mut receivers, &[false], 5).await;
        let rejected = ROWS + FRESH..ROWS + FRESH + 20_000;
        tx.send(pass(rejected, 100, REJECTED)).await.unwrap();
        actor::run_for(&tx, &mut receivers, &[false], 5).await;
        actor::run_for(&tx, &mut receivers, &[true], 2_000).await;
        drop(tx);
        let manager = actor.await.unwrap();
        drop(sources);
        assert!(manager.owing(peer).is_none(), "settled");
        assert_eq!(receivers[0].wire.table.len(), (ROWS / 10 + FRESH) as usize);
        let (routes, keys) = manager.adj_ribs_out[&peer].bench_vpn_capacities();
        let presizes = manager.adj_rib_out_commit_stats.walk_presizes;
        ([routes, keys], presizes)
    };
    let ((head, presizes), (control, _)) = with_control_async(shape).await;
    assert_at_or_below_control(&head, &control, "byte-cap cursor, blocks ahead");
    assert_eq!(presizes, 0, "no estimate");
}

// Holes correlated with rejection: the keys a receiver denies are logged
// again after the starting log (a MED, label or RT change that still
// denies them, a policy re-evaluation, a source re-sending part of its
// table), so the keys left in the starting log are the ones it accepts.
// The rate is per list position the walk passed, holes included, so the
// holes ahead cost what the holes passed dilute.

/// [`deny_med_chain`] passes the first 4,096 keys, denies the rest.
const FIRST_4K: fn(u32) -> u32 = |index| u32::from(index >= 4_096);
/// The first 2,048.
const FIRST_2K: fn(u32) -> u32 = |index| u32::from(index >= 2_048);
/// Denied at a new MED, so the key is logged again.
const DENIED_AGAIN: fn(u32) -> u32 = |_| 2;

/// One pass of 4,096 accepted and 20,000 denied keys (the starting log),
/// then the denied keys again, before the first step. Red with a rate per
/// key read: 7 times what the table holds, against 1.75 times.
#[test]
fn denied_keys_logged_again_ahead_of_a_vpn_cursor_fit() {
    assert_passes_fit(
        0,
        &[
            (SOURCE, 0..24_096, FIRST_4K),
            (SOURCE, 4_096..24_096, DENIED_AGAIN),
        ],
        4_096,
        "denied keys logged again",
    );
}

/// The same at 2,048 accepted and 50,000 denied. Red with a rate per key
/// read: 14 times, against 1.75 times.
#[test]
fn many_denied_keys_logged_again_ahead_of_a_vpn_cursor_fit() {
    assert_passes_fit(
        0,
        &[
            (SOURCE, 0..52_048, FIRST_2K),
            (SOURCE, 2_048..52_048, DENIED_AGAIN),
        ],
        2_048,
        "many denied keys logged again",
    );
}

fn vpn_pass(rows: impl Iterator<Item = VpnRibRoute>) -> RibUpdate {
    RibUpdate::VpnRoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 0,
        announced: rows.collect(),
        withdrawn: vec![],
    }
}

/// Through `RibManager::run` on a paused clock: the release logs 4,096
/// accepted and 20,000 denied keys (its inventory, the starting log), and
/// the denied keys arrive again in the same turn. With `held` empty the
/// release has no inventory, and the mixed pass arriving after it is the
/// starting log. Returns the joiner's last index capacities.
async fn denied_again_after_a_release(held: bool) -> [usize; 2] {
    let mixed = || (0..24_096).map(|i| med_row(SOURCE, P4, i, FIRST_4K(i)));
    let again = vpn_pass((4_096..24_096).map(|i| med_row(SOURCE, P4, i, 2)));
    let (rows, after) = if held {
        (mixed().collect(), vec![again])
    } else {
        (vec![], vec![vpn_pass(mixed()), again])
    };
    let (receivers, last) = Box::pin(actor_walk(
        rows,
        after,
        0,
        Some(deny_med_chain()),
        800,
        true,
    ))
    .await;
    assert_eq!(receivers[0].wire.table.len(), 4_096);
    assert_fitted(last.capacities[0], last.rows, "run loop: route index");
    assert_fitted(last.capacities[1], last.keys, "run loop: key index");
    last.capacities
}

/// Red with a rate per key read: 7 times what the table holds, in one
/// rebuild, against 1.75 times.
#[tokio::test(start_paused = true)]
async fn denied_keys_logged_again_after_a_vpn_release_through_the_run_loop_fit() {
    let (head, control) = Box::pin(with_control_async(|| denied_again_after_a_release(true))).await;
    assert_at_or_below_control(&head, &control, "denied again after a release");
}

/// The empty-inventory release: the next pass seals the start. Red with a
/// rate per key read: 7 times, against 1.75 times.
#[tokio::test(start_paused = true)]
async fn denied_keys_logged_again_after_an_empty_vpn_release_through_the_run_loop_fit() {
    let (head, control) =
        Box::pin(with_control_async(|| denied_again_after_a_release(false))).await;
    assert_at_or_below_control(&head, &control, "denied again after an empty release");
}

/// A start queued by a release-style owe whose walk ended on an empty list
/// stays queued with no log to seal it. The receiver then stops reading,
/// a 15,000-key pass overfills its owed keys past the byte cap and starts
/// a cursor at the same, unchanged head, and a later pass logs into the
/// list. That cursor has no starting log, so it makes no estimate. Red
/// when the queued entry seals any cursor live at its start: one estimate.
#[test]
fn a_stale_queued_start_never_seals_a_byte_cap_cursor() {
    let shape = || {
        let mut manager = manager(256);
        sources_up(&mut manager);
        let mut receivers = vec![owing_receiver(
            &mut manager,
            &[P4],
            0,
            Some(deny_med_chain()),
        )];
        let peer = receivers[0].peer;
        drain(&mut manager, &mut receivers);
        assert!(!manager.owes_whole(peer, F4), "the walk ended");
        let pass = |keys: std::ops::Range<u32>| {
            keys.map(|i| med_row(SOURCE, P4, i, tenth_med(i))).collect()
        };
        send(&mut manager, SOURCE, pass(0..15_000), vec![]);
        assert!(
            manager.owes_whole(peer, F4),
            "the byte cap started a cursor"
        );
        send(&mut manager, SOURCE, pass(15_000..35_000), vec![]);
        drain(&mut manager, &mut receivers);
        assert_eq!(receivers[0].wire.table.len(), 3_500);
        let (routes, keys) = manager.adj_ribs_out[&peer].bench_vpn_capacities();
        (
            [routes, keys],
            manager.adj_rib_out_commit_stats.walk_presizes,
        )
    };
    let ((head, presizes), (control, _)) = with_control(shape);
    assert_eq!(presizes, 0, "a byte-cap cursor makes no estimate");
    assert_at_or_below_control(&head, &control, "stale start, byte-cap cursor");
}
