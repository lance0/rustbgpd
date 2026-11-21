//! A private receiver's EVPN cursor walk sizes its EVPN index (and the
//! slab's first segment) once, while the table is nearly empty, from the
//! rows per key read so far and the keys still ahead of its cursor.

use std::cell::RefCell;

use super::super::cursor_presize::{
    Growth, PRESIZE_ROWS, assert_fitted, deny_med_chain, tenth_med,
};
use super::*;

/// The receiver's EVPN table: rows, and the capacities of its index and
/// of the slab's first segment.
fn tables(manager: &RibManager, peer: PeerId) -> (usize, [usize; 2]) {
    manager.adj_ribs_out.get(&peer).map_or((0, [0, 0]), |out| {
        let (index, segment) = out.evpn_capacities();
        (out.evpn_len(), [index, segment])
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

fn assert_index_fitted(manager: &RibManager, peer: PeerId, case: &str) {
    let out = &manager.adj_ribs_out[&peer];
    assert_fitted(out.evpn_capacities().0, out.evpn_len(), case);
}

/// A debt of 20,000 EVPN keys: the index and the slab's first segment
/// each change capacity in one step, under the presize limit. Red without
/// the presize: the index grows at every doubling (five steps or more).
#[test]
fn a_private_evpn_walk_sizes_its_index_once() {
    const ROWS: u32 = 20_000;
    let (mut manager, mut receivers) = owing(1, ROWS, 4 * CHUNK_ROWS);
    let peer = receivers[0].peer;
    let growth = walk(&mut manager, &mut receivers, peer);
    growth.assert_sized_once("EVPN");
    assert_settled(&manager, &receivers, &all(ROWS), "EVPN");
    assert_index_fitted(&manager, peer, "EVPN");
}

/// A receiver whose export policy passes one row in ten: its index ends
/// within 2.3 times what it holds. Red when the reserve is sized from the
/// keys ahead alone.
#[test]
fn a_filtered_evpn_walk_sizes_its_index_to_what_it_accepts() {
    const ROWS: u32 = 20_000;
    let mut manager = manager(4 * CHUNK_ROWS);
    std::mem::forget(up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]));
    let peer = receiver(0);
    let (outbound_tx, mut rx) = mpsc::channel(4096);
    manager.handle_update(evpn_peer_up(peer, 0, outbound_tx, Some(deny_med_chain())));
    Wire::default().write(&mut rx);
    let mut receivers = vec![Receiver {
        peer,
        rx,
        wire: Wire::default(),
    }];
    manager.owe_eor(peer, EVPN);
    manager.owe_whole_family(peer, FAMILY);
    let rows: Vec<(u32, u32)> = (0..ROWS).map(|index| (index, tenth_med(index))).collect();
    received(&mut manager, &rows, &[]);
    let growth = walk(&mut manager, &mut receivers, peer);
    let accepted: Vec<(u32, u32)> = rows.iter().copied().filter(|row| row.1 == 0).collect();
    assert_eq!(receivers[0].wire.table, table(&accepted));
    assert_index_fitted(&manager, peer, "one row in ten");
    assert!(growth.rows_at_rebuild <= PRESIZE_ROWS, "{growth:?}");
}

/// About 1% of 100,000 keys accepted, scattered: the table stays under
/// the presize limit for most of the walk. One estimate, made once the
/// sample holds enough accepted rows, and the index fits. Red when every
/// step under the limit estimates again.
#[test]
fn a_sparse_evpn_walk_estimates_once_from_a_full_sample() {
    const ROWS: u32 = 100_000;
    let mut manager = manager(4 * CHUNK_ROWS);
    std::mem::forget(up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]));
    let peer = receiver(0);
    let (outbound_tx, mut rx) = mpsc::channel(4096);
    manager.handle_update(evpn_peer_up(peer, 0, outbound_tx, Some(deny_med_chain())));
    Wire::default().write(&mut rx);
    let mut receivers = vec![Receiver {
        peer,
        rx,
        wire: Wire::default(),
    }];
    manager.owe_eor(peer, EVPN);
    manager.owe_whole_family(peer, FAMILY);
    let accept = |index: u32| index.wrapping_mul(2_654_435_761).is_multiple_of(100);
    let rows: Vec<(u32, u32)> = (0..ROWS)
        .map(|index| (index, u32::from(!accept(index))))
        .collect();
    received(&mut manager, &rows, &[]);
    let presizes = manager.adj_rib_out_commit_stats.walk_presizes;
    walk(&mut manager, &mut receivers, peer);
    let accepted: Vec<(u32, u32)> = rows.iter().copied().filter(|row| row.1 == 0).collect();
    assert_eq!(receivers[0].wire.table, table(&accepted));
    assert_index_fitted(&manager, peer, "1% scattered");
    assert_eq!(
        manager.adj_rib_out_commit_stats.walk_presizes - presizes,
        1,
        "one estimate"
    );
}

/// A receiver already holding more than the presize limit is owed EVPN
/// whole again with twice as many new rows: no step sizes its table. Red
/// when both the once-only rule and the limit are removed, as for VPN.
#[test]
fn a_populated_evpn_table_is_never_presized() {
    const HELD: u32 = 4_096;
    let mut manager = manager(4 * CHUNK_ROWS);
    std::mem::forget(up_sized(&mut manager, peer_v4(SOURCE), 0, 4096, &[V4]));
    let mut receivers = vec![Receiver::up(&mut manager, receiver(0), 4096, &[EVPN])];
    let peer = receivers[0].peer;
    received(&mut manager, &all(HELD), &[]);
    drain(&mut manager, &mut receivers);
    assert_eq!(manager.adj_ribs_out[&peer].evpn_len(), HELD as usize);
    manager.owe_whole_family(peer, FAMILY);
    let fresh: Vec<_> = (HELD..3 * HELD).map(|index| (index, 0)).collect();
    received(&mut manager, &fresh, &[]);
    let presizes = manager.adj_rib_out_commit_stats.walk_presizes;
    walk(&mut manager, &mut receivers, peer);
    assert_eq!(
        manager.adj_rib_out_commit_stats.walk_presizes, presizes,
        "a populated table is not presized"
    );
    assert_eq!(receivers[0].wire.table, table(&all(3 * HELD)));
}

fn evpn_peer_up(
    peer: PeerId,
    session_id: u64,
    outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
    export_policy: Option<PolicyChain>,
) -> RibUpdate {
    RibUpdate::PeerUp {
        supersedes: None,
        per_client_best: false,
        interpret_rfc1997: true,
        session_id,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 200),
        outbound_tx,
        export_policy,
        sendable_families: vec![EVPN],
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: Vec::new(),
    }
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

/// Two queries in turn: every message queued before them has run.
async fn barrier(tx: &mpsc::Sender<RibUpdate>) {
    for _ in 0..2 {
        let (reply, response) = oneshot::channel();
        tx.send(RibUpdate::QueryLocRibCount { reply })
            .await
            .unwrap();
        response.await.unwrap();
    }
}

/// Advance the clock `ticks` times by 10 ms; every receiver writes after
/// each.
async fn run_for(tx: &mpsc::Sender<RibUpdate>, receivers: &mut [Receiver], ticks: usize) {
    for _ in 0..ticks {
        tokio::time::advance(Duration::from_millis(10)).await;
        barrier(tx).await;
        for receiver in receivers.iter_mut() {
            receiver.write();
        }
    }
}

/// Through `RibManager::run_actor` on a paused clock: EVPN is held while
/// a receiver joins, then released by the waiter's End-of-RIB, and the
/// receiver reads every 10 ms. After every actor turn its table is read:
/// the index and the slab's first segment each change capacity in one
/// turn, under the presize limit, and the receiver ends exact with one
/// End-of-RIB.
#[tokio::test(start_paused = true)]
async fn an_evpn_release_through_the_actor_loop_sizes_the_joiner_table_once() {
    const ROWS: u32 = 12_000;
    let mut manager = manager(4 * CHUNK_ROWS).with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_secs(60),
        waiters: vec![SelectionDeferralWaiterConfig {
            peer: peer_v4(WAITER).into(),
            families: vec![EVPN],
        }],
    });
    manager.actor_turn_check = Some(watch);
    let (tx, rx) = mpsc::channel(256);
    manager.rx = rx;
    let actor = tokio::spawn(manager.run_actor());
    let (source_tx, source_rx) = mpsc::channel(4096);
    let mut source = evpn_peer_up(peer_v4(SOURCE), 0, source_tx, None);
    if let RibUpdate::PeerUp {
        sendable_families, ..
    } = &mut source
    {
        *sendable_families = vec![V4];
    }
    tx.send(source).await.unwrap();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer_v4(SOURCE),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: (0..ROWS).map(|index| route(index, 0)).collect(),
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::SetPeerGracefulRestartContext {
        peer: peer_v4(WAITER),
        session_id: 7,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![EVPN],
        peer_enhanced_refresh: false,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    })
    .await
    .unwrap();
    let (waiter_tx, waiter_rx) = mpsc::channel(4096);
    tx.send(evpn_peer_up(peer_v4(WAITER), 7, waiter_tx, None))
        .await
        .unwrap();
    let joiner = receiver(0);
    let (joiner_tx, joiner_rx) = mpsc::channel(4096);
    tx.send(evpn_peer_up(joiner, 0, joiner_tx, None))
        .await
        .unwrap();
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
    run_for(&tx, &mut receivers, 5).await;
    assert!(receivers[0].wire.table.is_empty(), "the joiner waits");
    WATCHED.with(|watched| *watched.borrow_mut() = Some((joiner, Growth::default())));
    tx.send(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: 7,
        afi: EVPN.0,
        safi: EVPN.1,
    })
    .await
    .unwrap();
    run_for(&tx, &mut receivers, 400).await;
    drop(tx);
    let manager = actor.await.unwrap();
    drop(source_rx);
    let (_, growth) = WATCHED.with(|watched| watched.borrow_mut().take()).unwrap();
    growth.assert_sized_once("actor loop");
    assert_eq!(receivers[0].wire.table, table(&all(ROWS)));
    assert_eq!(receivers[0].wire.markers, 1);
    assert!(manager.owing(joiner).is_none());
    assert_index_fitted(&manager, joiner, "actor loop");
}
