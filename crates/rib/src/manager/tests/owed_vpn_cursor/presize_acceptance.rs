//! Receiver shapes whose acceptance a walk's first keys misread: an
//! Add-Path send-all receiver reads one key a step, two AFIs accept
//! different fractions, a sparse receiver's early samples are noisy, and
//! paths per key vary. The presize estimates once, from each AFI's
//! cumulative rate over a full sample, so each table ends within 2.3 times
//! what it holds, as the steps' own doubling leaves it.

use std::cell::RefCell;

use super::super::cursor_presize::{Growth, assert_fitted, deny_med_chain, set_med, tenth_med};
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
/// paths and the rest with one: the route index is sized for the average
/// paths per key read, not the most an early key had.
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
/// `policy`, release both AFIs, and run `ticks` 10 ms ticks. The actor is
/// `RibManager::run` when `through_run`, else `RibManager::run_actor`,
/// which it wraps (the manager comes back to be checked). Returns the
/// receivers and the last reading of the joiner's table.
async fn actor_walk(
    rows: Vec<VpnRibRoute>,
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
    let (receivers, _) = actor_walk(rows, 0, Some(deny_med_chain()), 400, false).await;
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
    let (receivers, last) = actor_walk(rows, u32::MAX, Some(deny_med_chain()), 6_000, true).await;
    assert_eq!(receivers[0].wire.table.len(), (ROWS / 10) as usize);
    assert_eq!(last.rows, (ROWS / 10) as usize, "{last:?}");
    assert_fitted(last.capacities[0], last.rows, "run loop: route index");
    assert_fitted(last.capacities[1], last.keys, "run loop: key index");
}
