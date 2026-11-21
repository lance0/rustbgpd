//! A private receiver's VPN cursor walk sizes its two VPN indexes once,
//! while the table is nearly empty, from each AFI's rows per key read so
//! far and its keys still ahead: the indexes do not double step after
//! step, and a receiver that accepts a fraction of the walk's starting
//! log gets a table sized to that fraction of it.

use std::cell::RefCell;

use super::super::cursor_presize::{
    Growth, PRESIZE_ROWS, assert_at_or_below_control, assert_fitted, deny_med_chain, set_med,
    tenth_med, with_control,
};
use super::*;

/// The receiver's VPN table: rows, and the capacities of its route and
/// key indexes.
fn tables(manager: &RibManager, peer: PeerId) -> (usize, [usize; 2]) {
    manager.adj_ribs_out.get(&peer).map_or((0, [0, 0]), |out| {
        let (routes, keys) = out.bench_vpn_capacities();
        (out.vpn_len(), [routes, keys])
    })
}

fn observe(manager: &RibManager, peer: PeerId, growth: &mut Growth) {
    let (rows, capacities) = tables(manager, peer);
    growth.observe(rows, capacities);
}

/// Tick until no resync work is left, reading `peer`'s table after every
/// step.
fn walk(manager: &mut RibManager, receivers: &mut [Receiver], peer: PeerId) -> Growth {
    let mut growth = Growth::default();
    observe(manager, peer, &mut growth);
    (growth.rebuilds, growth.resized) = ([0, 0], [0, 0]);
    for _ in 0..100_000 {
        for receiver in receivers.iter_mut() {
            receiver.write();
        }
        if !manager.resync_tick_pending() {
            return growth;
        }
        tick(manager, receivers);
        observe(manager, peer, &mut growth);
    }
    panic!("the walk does not finish");
}

fn assert_indexes_fitted(manager: &RibManager, peer: PeerId, case: &str) {
    let out = &manager.adj_ribs_out[&peer];
    let (routes, keys) = out.bench_vpn_capacities();
    assert_fitted(routes, out.vpn_len(), &format!("{case}: route index"));
    assert_fitted(keys, out.vpn_key_len(), &format!("{case}: key index"));
}

fn rows(family: (Afi, Safi), range: std::ops::Range<u32>, label: u32) -> Vec<VpnRibRoute> {
    range
        .map(|index| route_from(SOURCE, family, index, label, 200))
        .collect()
}

/// Row `index` of `IPv4` VPN with the MED [`deny_med_chain`] passes one row
/// in ten with.
fn tenth(index: u32) -> VpnRibRoute {
    let mut route = route_from(SOURCE, P4, index, 100, 200);
    set_med(&mut route.attributes, tenth_med(index));
    route
}

/// A receiver behind [`deny_med_chain`] that owes `VPNv4` whole.
fn filtered_receiver(manager: &mut RibManager) -> Receiver {
    let peer = receiver(0);
    let mut rx = up_with(manager, peer, 0, 4096, &[P4], 0, Some(deny_med_chain()));
    Wire::default().write(&mut rx);
    manager.owe_eor(peer, P4);
    manager.owe_whole_family(peer, F4);
    Receiver {
        peer,
        rx,
        wire: Wire::default(),
    }
}

/// Both VPN AFIs released together to a receiver that joined in the hold,
/// 10,000 rows each into one shared pair of indexes: each index changes
/// capacity in one step of the walk, while the table is under the presize
/// limit. Red without the presize: the indexes grow at every doubling
/// (five steps or more), the last ones well past the limit.
#[test]
fn a_private_vpn_walk_sizes_both_indexes_once() {
    const ROWS: u32 = 10_000;
    let mut manager = deferral_manager(4 * CHUNK_ROWS, &[P4, P6]);
    sources_up(&mut manager);
    for family in [P4, P6] {
        send(&mut manager, SOURCE, rows(family, 0..ROWS, 100), vec![]);
    }
    let waiter = hold(&mut manager, &[P4, P6]);
    let mut receivers = vec![join_held(&mut manager, 0, &[P4, P6]), waiter];
    release(&mut manager, P4);
    release(&mut manager, P6);
    let peer = receivers[0].peer;
    let growth = walk(&mut manager, &mut receivers, peer);
    growth.assert_sized_once_for_two_afis("both AFIs");
    let mut expected = table_of(P4, &all(ROWS));
    expected.extend(table_of(P6, &all(ROWS)));
    assert_eq!(receivers[0].wire.table, expected);
    assert_eq!(receivers[0].wire.markers, [1, 1]);
    assert_indexes_fitted(&manager, peer, "both AFIs");
    assert!(manager.owing(peer).is_none());
}

/// A receiver whose export policy passes one row in ten: its indexes end
/// within 2.3 times what it holds. Red when the reserve is sized from the
/// keys ahead alone (the Loc-RIB): about ten times what it holds.
#[test]
fn a_filtered_vpn_walk_sizes_its_indexes_to_what_it_accepts() {
    const ROWS: u32 = 20_000;
    let mut manager = manager(4 * CHUNK_ROWS);
    sources_up(&mut manager);
    let mut receivers = vec![filtered_receiver(&mut manager)];
    let peer = receivers[0].peer;
    send(&mut manager, SOURCE, (0..ROWS).map(tenth).collect(), vec![]);
    let growth = walk(&mut manager, &mut receivers, peer);
    let expected: Table = (0..ROWS)
        .filter(|index| index.is_multiple_of(10))
        .map(|index| entry(&tenth(index), 0))
        .collect();
    assert_eq!(receivers[0].wire.table, expected);
    assert_eq!(manager.adj_ribs_out[&peer].vpn_len(), expected.len());
    assert_indexes_fitted(&manager, peer, "one row in ten");
    assert!(growth.rows_at_rebuild <= PRESIZE_ROWS, "{growth:?}");
}

/// A first step whose keys the receiver's policy all rejects reserves
/// nothing. Those keys are the walk's starting log (the first pass after
/// the cursor starts); the accepted keys come in a later pass, so the
/// walk's sample says nothing of them: no estimate, and the table grows by
/// the steps' own reserves, as with the presize off. Red when the estimate
/// extrapolates past the starting log (one estimate, from a rate the
/// rejected block halves).
#[test]
fn a_vpn_walk_whose_starting_log_is_rejected_makes_no_estimate() {
    const ACCEPTED: u32 = 8_192;
    let rejected = u32::try_from(CHUNK_ROWS).unwrap();
    let denied = |index| {
        let mut route = route_from(SOURCE, P4, index, 100, 200);
        set_med(&mut route.attributes, 1);
        route
    };
    let shape = || {
        let mut manager = manager(4 * CHUNK_ROWS);
        sources_up(&mut manager);
        let mut receivers = vec![filtered_receiver(&mut manager)];
        let peer = receivers[0].peer;
        // The list holds the rejected keys first, a step's worth exactly.
        send(
            &mut manager,
            SOURCE,
            (0..rejected).map(denied).collect(),
            vec![],
        );
        let accepted = rows(P4, rejected..rejected + ACCEPTED, 100);
        send(&mut manager, SOURCE, accepted, vec![]);
        let presizes = manager.adj_rib_out_commit_stats.walk_presizes;
        tick(&mut manager, &mut receivers);
        assert!(
            receivers[0].wire.table.is_empty(),
            "the first step is rejected"
        );
        assert_eq!(tables(&manager, peer), (0, [0, 0]), "nothing reserved");
        walk(&mut manager, &mut receivers, peer);
        assert_eq!(
            manager.adj_rib_out_commit_stats.walk_presizes, presizes,
            "no estimate past the starting log"
        );
        let expected = table_of(
            P4,
            &(rejected..rejected + ACCEPTED)
                .map(|index| (index, 100))
                .collect::<Vec<_>>(),
        );
        assert_eq!(receivers[0].wire.table, expected);
        assert_indexes_fitted(&manager, peer, "after a rejected step");
        tables(&manager, peer).1
    };
    let (head, control) = with_control(shape);
    assert_at_or_below_control(&head, &control, "rejected starting log");
}

/// A receiver already holding more than the presize limit is owed the
/// family whole again with twice as many new rows: no step sizes its
/// table, which grows only by the steps' own reserves. The rows it holds
/// already make a sample before the first step, so no step completes one;
/// red when both that once-only rule and the limit are removed.
#[test]
fn a_populated_vpn_table_is_never_presized() {
    const HELD: u32 = 4_096;
    let mut manager = manager(4 * CHUNK_ROWS);
    sources_up(&mut manager);
    let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 4096, &[P4], 0)];
    let peer = receivers[0].peer;
    received(&mut manager, P4, &all(HELD), &[]);
    drain(&mut manager, &mut receivers);
    assert_eq!(manager.adj_ribs_out[&peer].vpn_len(), HELD as usize);
    assert!(HELD as usize > PRESIZE_ROWS);
    manager.owe_whole_family(peer, F4);
    send(&mut manager, SOURCE, rows(P4, HELD..3 * HELD, 100), vec![]);
    let presizes = manager.adj_rib_out_commit_stats.walk_presizes;
    walk(&mut manager, &mut receivers, peer);
    assert_eq!(
        manager.adj_rib_out_commit_stats.walk_presizes, presizes,
        "a populated table is not presized"
    );
    assert_eq!(receivers[0].wire.table, table_of(P4, &all(3 * HELD)));
}

/// A key logged again moves to the back of the list and leaves a hole
/// where it was, so the sequence numbers ahead of a cursor can count many
/// more entries than the list holds there: half the rows relabeled six
/// times before the receiver reads put four sequence numbers ahead of it
/// per live key. The rate counts the keys the walk read, step by step,
/// so the holes leave it alone: one estimate, and the table fits. Red
/// with keys read taken as the Loc-RIB's keys less the entries ahead: the
/// holes read as no sample, and the table grows by the steps' own
/// reserves instead.
#[test]
fn holes_ahead_of_a_vpn_cursor_leave_the_rate_alone() {
    const ROWS: u32 = 8_192;
    let (mut manager, mut receivers) = owing(manager(4 * CHUNK_ROWS), P4, &[P4], 1, ROWS, 4096);
    for label in 101..107 {
        send(
            &mut manager,
            SOURCE,
            rows(P4, ROWS / 2..ROWS, label),
            vec![],
        );
    }
    let list = &manager.owed_vpn_rows[0];
    assert_eq!(list.len(), ROWS as usize);
    assert_eq!(
        list.head(),
        4 * u64::from(ROWS),
        "four sequence numbers a key"
    );
    let peer = receivers[0].peer;
    let presizes = manager.adj_rib_out_commit_stats.walk_presizes;
    walk(&mut manager, &mut receivers, peer);
    assert_eq!(
        manager.adj_rib_out_commit_stats.walk_presizes - presizes,
        1,
        "one estimate, holes ahead or not"
    );
    let label = |index| if index < ROWS / 2 { 100 } else { 106 };
    let expected = table_of(
        P4,
        &(0..ROWS)
            .map(|index| (index, label(index)))
            .collect::<Vec<_>>(),
    );
    assert_eq!(receivers[0].wire.table, expected);
    assert_indexes_fitted(&manager, peer, "relabeled");
}

/// A `VPNv4` walk reads 2,000 keys, accepts none and ends while the
/// receiver's `VPNv6` walk goes on, so its owed record (and the `VPNv4`
/// counts in it) stays. The receiver is then owed `VPNv4` whole again and
/// 20,000 accepted keys arrive. The second walk counts only its own keys
/// read, so it sizes the table in one step. Red when a cursor start keeps
/// the last walk's counts: the 2,000 keys read before dilute the rate,
/// and the table grows by the steps' own reserves.
#[test]
fn a_second_vpn_walk_counts_only_its_own_keys() {
    const DENIED: u32 = 2_000;
    const ROWS: u32 = 20_000;
    let denied = |family, range: std::ops::Range<u32>| -> Vec<VpnRibRoute> {
        range
            .map(|index| {
                let mut route = route_from(SOURCE, family, index, 100, 200);
                set_med(&mut route.attributes, 1);
                route
            })
            .collect()
    };
    let mut manager = manager(4 * CHUNK_ROWS);
    sources_up(&mut manager);
    let peer = receiver(0);
    let mut rx = up_with(
        &mut manager,
        peer,
        0,
        4096,
        &[P4, P6],
        0,
        Some(deny_med_chain()),
    );
    Wire::default().write(&mut rx);
    let mut receivers = vec![Receiver {
        peer,
        rx,
        wire: Wire::default(),
    }];
    for (family, owed) in [(P4, F4), (P6, F6)] {
        manager.owe_eor(peer, family);
        manager.owe_whole_family(peer, owed);
    }
    send(&mut manager, SOURCE, denied(P4, 0..DENIED), vec![]);
    send(&mut manager, SOURCE, denied(P6, 0..10 * DENIED), vec![]);
    let owing = |manager: &RibManager, family| {
        manager
            .owing(peer)
            .is_some_and(|owing| owing.is_whole(family))
    };
    for _ in 0..1_000 {
        if !owing(&manager, F4) {
            break;
        }
        receivers[0].write();
        tick(&mut manager, &mut receivers);
    }
    assert!(!owing(&manager, F4), "the first VPNv4 walk ended");
    assert!(owing(&manager, F6), "the VPNv6 walk goes on");
    assert_eq!(manager.adj_ribs_out[&peer].vpn_len(), 0);
    manager.owe_whole_family(peer, F4);
    send(
        &mut manager,
        SOURCE,
        rows(P4, DENIED..DENIED + ROWS, 100),
        vec![],
    );
    let presizes = manager.adj_rib_out_commit_stats.walk_presizes;
    let growth = walk(&mut manager, &mut receivers, peer);
    growth.assert_sized_once("second walk");
    assert_eq!(manager.adj_rib_out_commit_stats.walk_presizes - presizes, 1);
    assert_eq!(manager.adj_ribs_out[&peer].vpn_len(), ROWS as usize);
    assert!(manager.owing(peer).is_none());
    assert_indexes_fitted(&manager, peer, "second walk");
}

/// An Add-Path receiver joins a hold and is released two paths of every
/// key. The key index is sized once, from the keys accepted per key read;
/// the route index for one row a key, since paths per key vary with
/// arrival order, and the steps grow it past that. Both end at or below
/// the walk with the presize off. Red when the key index is sized from the
/// clamped rows: half the keys, so it changes capacity in three steps.
#[test]
fn an_add_path_vpn_walk_sizes_each_index_by_its_own_count() {
    const KEYS: u32 = 8_000;
    let shape = || {
        let mut manager = deferral_manager(4 * CHUNK_ROWS, &[P4]);
        sources_up(&mut manager);
        let second = (0..KEYS).map(|index| route_from(SECOND, P4, index, 300, 100));
        send(&mut manager, SECOND, second.collect(), vec![]);
        send(&mut manager, SOURCE, rows(P4, 0..KEYS, 100), vec![]);
        let waiter = hold(&mut manager, &[P4]);
        let joiner = Receiver::up(&mut manager, receiver(0), 4096, &[P4], 2);
        let mut receivers = vec![joiner, waiter];
        release(&mut manager, P4);
        let peer = receivers[0].peer;
        let growth = walk(&mut manager, &mut receivers, peer);
        let out = &manager.adj_ribs_out[&peer];
        assert_eq!(out.vpn_len(), 2 * KEYS as usize);
        assert_eq!(out.vpn_key_len(), KEYS as usize);
        assert_eq!(receivers[0].wire.table.len(), 2 * KEYS as usize);
        assert_indexes_fitted(&manager, peer, "two paths a key");
        (growth.rebuilds[1], tables(&manager, peer).1)
    };
    let ((key_rebuilds, head), (_, control)) = with_control(shape);
    assert_eq!(key_rebuilds, 1, "the key index changes capacity once");
    assert_at_or_below_control(&head, &control, "two paths a key");
}

/// A receiver whose session ends mid-walk, after a step sized its table:
/// the sized table goes with the session. The next session comes up after
/// the hold, so its table is a whole-table send with its own exact
/// reserve, and no cursor step sizes it: it ends exact and fitted, with
/// nothing of the old size carried over.
#[test]
fn a_vpn_receiver_that_flaps_mid_walk_drops_its_sized_table() {
    const ROWS: u32 = 8_192;
    let mut manager = deferral_manager(4 * CHUNK_ROWS, &[P4]);
    sources_up(&mut manager);
    send(&mut manager, SOURCE, rows(P4, 0..ROWS, 100), vec![]);
    let waiter = hold(&mut manager, &[P4]);
    let mut receivers = vec![join_held(&mut manager, 0, &[P4]), waiter];
    release(&mut manager, P4);
    let peer = receivers[0].peer;
    while tables(&manager, peer).0 == 0 {
        tick(&mut manager, &mut receivers);
    }
    let (_, sized) = tables(&manager, peer);
    assert!(sized[0] >= ROWS as usize, "sized for the walk: {sized:?}");
    assert!(manager.owes_whole(peer, F4), "mid-walk");

    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    });
    assert!(!manager.adj_ribs_out.contains_key(&peer), "the table goes");
    assert!(manager.owing(peer).is_none(), "the walk goes");
    // The waiter finishes its own walk first.
    drain(&mut manager, &mut receivers[1..]);
    receivers[0] = Receiver {
        peer,
        rx: up(&mut manager, peer, 1, 4096, &[P4], 0),
        wire: Wire::default(),
    };
    let presizes = manager.adj_rib_out_commit_stats.walk_presizes;
    drain(&mut manager, &mut receivers);
    assert_eq!(receivers[0].wire.table, table_of(P4, &all(ROWS)));
    assert_eq!(receivers[0].wire.markers[0], 1);
    assert_eq!(
        manager.adj_rib_out_commit_stats.walk_presizes, presizes,
        "the next session's table is not a cursor walk"
    );
    assert_indexes_fitted(&manager, peer, "the next session");
}

thread_local! {
    /// The receiver whose table the actor-turn check reads, and what it
    /// saw.
    static WATCHED: RefCell<Option<(PeerId, Growth)>> = const { RefCell::new(None) };
}

fn watch(manager: &RibManager) {
    WATCHED.with(|watched| {
        if let Some((peer, growth)) = watched.borrow_mut().as_mut() {
            observe(manager, *peer, growth);
        }
    });
}

/// Through `RibManager::run_actor` on a paused clock: both VPN AFIs are
/// held while a receiver joins, then released, and the receiver reads
/// every 10 ms. After every actor turn its table is read: each index
/// changes capacity in one turn, under the presize limit, and the
/// receiver ends exact with one End-of-RIB per AFI.
#[tokio::test(start_paused = true)]
async fn a_vpn_release_through_the_actor_loop_sizes_the_joiner_table_once() {
    const ROWS: u32 = 6_000;
    let mut manager = deferral_manager(4 * CHUNK_ROWS, &[P4, P6]);
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
    for family in [P4, P6] {
        let announce = all(ROWS);
        tx.send(actor::vpn_update(family, &announce, &[]))
            .await
            .unwrap();
    }
    tx.send(gr_context(&[P4, P6])).await.unwrap();
    let (update, waiter_rx) = actor::peer_up(peer_v4(WAITER), 7, 4096, &[P4, P6]);
    tx.send(update).await.unwrap();
    let joiner = receiver(0);
    let (update, joiner_rx) = actor::peer_up(joiner, 0, 4096, &[P4, P6]);
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
    WATCHED.with(|watched| *watched.borrow_mut() = Some((joiner, Growth::default())));
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
    actor::run_for(&tx, &mut receivers, &[true; 2], 400).await;
    drop(tx);
    let manager = actor.await.unwrap();
    drop(sources);
    let (_, growth) = WATCHED.with(|watched| watched.borrow_mut().take()).unwrap();
    growth.assert_sized_once_for_two_afis("actor loop");
    let mut expected = table_of(P4, &all(ROWS));
    expected.extend(table_of(P6, &all(ROWS)));
    assert_eq!(receivers[0].wire.table, expected);
    assert_eq!(receivers[0].wire.markers, [1, 1]);
    assert!(manager.owing(joiner).is_none());
    assert_indexes_fitted(&manager, joiner, "actor loop");
}
