//! A replay that loses track of its member's changes rewinds into a paced
//! reconcile: it rescans the Loc-RIB against admission, then sweeps the
//! admitted proof for keys that are gone. No whole-table unit runs, and the
//! member's End-of-RIB follows its complete table once.
use super::*;
use crate::manager::initial_member_replay::PacedFallbackCause;

/// Whole-table units: dirty resync builds (K1), one-turn initial tables (K2)
/// and synchronous group builds (K3).
fn whole_table_units(manager: &RibManager) -> [usize; 3] {
    let work = crate::manager::slice_timing::group_work();
    let count = |stage| work.get(stage).copied().unwrap_or(0);
    [
        manager.adj_rib_out_commit_stats.resync_builds,
        count("initial_table_turns"),
        count("synchronous_group_builds"),
    ]
}

fn reconciles() -> usize {
    crate::manager::slice_timing::group_work()
        .get("initial_replay_reconciles")
        .copied()
        .unwrap_or(0)
}

fn units_since(manager: &RibManager, before: [usize; 3]) -> [usize; 3] {
    let after = whole_table_units(manager);
    [0, 1, 2].map(|i| after[i] - before[i])
}

fn inventory(page: &OutboundRouteUpdate) -> Inventory {
    page.announce
        .iter()
        .map(|row| (row.prefix, (row.peer, row.local_pref())))
        .collect()
}

fn new_routes(source: Ipv4Addr, from: u16, count: u16, pref: u32) -> RibUpdate {
    test_routes_received(
        peer_v4(source),
        (0..count)
            .map(|i| route(prefixes(from + i)[0], source, pref))
            .collect(),
    )
}

fn withdraw(source: Ipv4Addr, keys: &[Prefix]) -> RibUpdate {
    let mut update = test_routes_received(peer_v4(source), Vec::new());
    let RibUpdate::RoutesReceived { withdrawn, .. } = &mut update else {
        unreachable!()
    };
    withdrawn.extend(keys.iter().map(|&key| (key, 0)));
    update
}

/// Apply pages to `state` through the member's one End-of-RIB, which must
/// find the table complete.
async fn drive_to_marker(
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    state: &mut Inventory,
    expected: &Inventory,
) {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let page = rx.recv().await.unwrap();
            for &(prefix, _) in page.unicast_withdrawals() {
                assert!(state.remove(&prefix).is_some(), "withdrew unsent {prefix}");
            }
            for row in page.announce.iter() {
                state.insert(row.prefix, (row.peer, row.local_pref()));
            }
            if !page.end_of_rib.is_empty() {
                assert_eq!(page.end_of_rib, [FAMILY]);
                assert_eq!(
                    *state, *expected,
                    "End-of-RIB before the table was complete"
                );
                break;
            }
        }
    })
    .await
    .expect("End-of-RIB");
}

// Three live replays meet one source departure larger than their repair
// logs. Each replay rewinds into a reconcile; none takes a whole-table resync.
#[tokio::test(start_paused = true)]
async fn a_departure_above_the_repair_cap_reconciles_every_live_replay() {
    const DEPARTED: u16 = 5_000;
    let (mut manager, tx, expected) = replay_fixture();
    manager.handle_update(new_routes(OTHER, V4_ROWS, DEPARTED, 100));
    drain_route_chunks(&mut manager);
    let mut members = Vec::new();
    for n in 1..=3 {
        let peer = receiver(n);
        let mut rx = member(&mut manager, peer, 1, false, false);
        let first = first_page(&mut manager, &mut rx);
        members.push((peer, rx, first));
    }
    assert!(
        members
            .iter()
            .all(|(peer, ..)| manager.is_initial_member_replay(*peer))
    );
    let before = whole_table_units(&manager);
    tx.try_send(RibUpdate::PeerDown {
        peer: peer_v4(OTHER),
        session_id: 0,
    })
    .unwrap();
    let actor = tokio::spawn(manager.run_actor());
    tokio::task::yield_now().await;
    let mut held = Vec::new();
    for (_, rx, first) in members {
        held.push((rx, inventory(&first)));
        drop(first);
    }
    for (rx, state) in &mut held {
        drive_to_marker(rx, state, &expected).await;
    }
    drop(tx);
    let manager = actor.await.unwrap();
    for (rx, _) in &held {
        assert!(rx.is_empty(), "output after End-of-RIB");
    }
    assert_eq!(units_since(&manager, before), [0; 3], "whole-table units");
    crate::manager::tests::assert_paced_fallbacks(&manager.metrics, &[]);
}

// New prefixes overflow the scan, then the source withdraws keys the member
// already holds. With the scan overflowed those withdrawals leave no repair:
// the reconcile's proof sweep must find them. End-of-RIB is sent once, after
// the complete table.
#[tokio::test(start_paused = true)]
async fn a_reconcile_withdraws_admitted_keys_the_loc_rib_dropped_during_the_overflow() {
    let (mut manager, tx, mut expected) = replay_fixture();
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 1, false, false);
    let first = first_page(&mut manager, &mut rx);
    let mut state = inventory(&first);
    manager.handle_update(new_routes(OTHER, V4_ROWS, 5_000, 100));
    drain_route_chunks(&mut manager);
    for i in 0..5_000 {
        expected.insert(prefixes(V4_ROWS + i)[0], (peer_v4(OTHER), 100));
    }
    let dropped: Vec<_> = state.keys().take(50).copied().collect();
    manager.handle_update(withdraw(SOURCE, &dropped));
    drain_route_chunks(&mut manager);
    for key in &dropped {
        expected.remove(key);
    }
    assert!(manager.is_initial_member_replay(peer));
    assert!(manager.initial_member_replay_changes_pending(peer));
    let before = whole_table_units(&manager);
    drop(first);
    let actor = tokio::spawn(manager.run_actor());
    drive_to_marker(&mut rx, &mut state, &expected).await;
    drop(tx);
    let manager = actor.await.unwrap();
    assert!(rx.is_empty(), "output after End-of-RIB");
    assert_eq!(units_since(&manager, before), [0; 3], "whole-table units");
    crate::manager::tests::assert_paced_fallbacks(&manager.metrics, &[]);
}

// One cell per cause that now rewinds: the replay stays live, keeps its
// writer and ends with the exact table and one End-of-RIB.
#[tokio::test(start_paused = true)]
async fn every_reconcilable_cause_rewinds_without_a_whole_table_unit() {
    for cause in [
        PacedFallbackCause::ScanRepairLimit,
        PacedFallbackCause::ChangeOutsideScan,
        PacedFallbackCause::ReleaseFanout,
        PacedFallbackCause::ForcedResync,
        PacedFallbackCause::SelectionRelease,
    ] {
        let (mut manager, tx, expected) = replay_fixture();
        let peer = receiver(1);
        let mut rx = member(&mut manager, peer, 1, false, false);
        let first = first_page(&mut manager, &mut rx);
        let mut state = inventory(&first);
        if cause == PacedFallbackCause::ForcedResync {
            manager.force_outbound_peers.insert(peer);
        }
        let before = whole_table_units(&manager);
        let _ = manager.recover_initial_member_replay(peer, cause);
        assert!(manager.is_initial_member_replay(peer), "{cause:?}");
        assert!(!manager.dirty_peers.contains(&peer), "{cause:?}");
        drop(first);
        let actor = tokio::spawn(manager.run_actor());
        drive_to_marker(&mut rx, &mut state, &expected).await;
        drop(tx);
        let manager = actor.await.unwrap();
        assert!(rx.is_empty(), "{cause:?}: output after End-of-RIB");
        assert!(!manager.force_outbound_peers.contains(&peer), "{cause:?}");
        assert_eq!(units_since(&manager, before), [0; 3], "{cause:?}");
        crate::manager::tests::assert_paced_fallbacks(&manager.metrics, &[]);
    }
}

// A forced outbound refresh (for example a GSHUT toggle) reaches a member
// mid-replay. Its reconcile resends every row forced; no whole-table unit.
#[tokio::test(start_paused = true)]
async fn a_forced_outbound_refresh_mid_replay_reconciles_in_pages() {
    let (mut manager, tx, expected) = replay_fixture();
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 1, false, false);
    let first = first_page(&mut manager, &mut rx);
    let mut state = inventory(&first);
    let before = whole_table_units(&manager);
    let (reply, result) = oneshot::channel();
    manager.handle_update(RibUpdate::RefreshPeerOutbound { peer, reply });
    assert!(manager.is_initial_member_replay(peer));
    drop(first);
    let actor = tokio::spawn(manager.run_actor());
    result.await.unwrap().unwrap();
    drive_to_marker(&mut rx, &mut state, &expected).await;
    drop(tx);
    let manager = actor.await.unwrap();
    assert!(rx.is_empty(), "output after End-of-RIB");
    assert!(!manager.force_outbound_peers.contains(&peer));
    assert_eq!(units_since(&manager, before), [0; 3], "whole-table units");
    crate::manager::tests::assert_paced_fallbacks(&manager.metrics, &[]);
}

/// Paused time until the member's next row once the actor runs.
async fn wait_for_next_row(
    manager: RibManager,
    mut rx: mpsc::Receiver<OutboundRouteUpdate>,
    tx: mpsc::Sender<RibUpdate>,
) -> Duration {
    while rx.try_recv().is_ok() {}
    let start = tokio::time::Instant::now();
    let actor = tokio::spawn(manager.run_actor());
    let waited = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let page = rx.recv().await.unwrap();
            if !page.announce.is_empty() {
                return start.elapsed();
            }
        }
    })
    .await
    .expect("a row");
    drop(tx);
    let _ = actor.await.unwrap();
    waited
}

// An idle actor must not leave a recovering member, whose End-of-RIB is
// held, waiting for the ordinary resync interval.
#[tokio::test(start_paused = true)]
async fn a_rewound_replay_sends_its_next_row_without_waiting_for_a_tick() {
    let (mut manager, tx, _) = replay_fixture();
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 64, false, false);
    drop(first_page(&mut manager, &mut rx));
    manager.handle_update(new_routes(OTHER, V4_ROWS, 5_000, 100));
    drain_route_chunks(&mut manager);
    let waited = wait_for_next_row(manager, rx, tx).await;
    assert!(
        waited < crate::manager::DIRTY_RESYNC_BACKLOG_INTERVAL,
        "the recovering member idled {waited:?}"
    );
}

// A cause that still takes the dirty resync runs it at the backlog cadence.
#[tokio::test(start_paused = true)]
async fn a_replay_fallback_resyncs_at_the_backlog_cadence() {
    let (mut manager, tx, _) = replay_fixture();
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 64, false, false);
    drop(first_page(&mut manager, &mut rx));
    let _ = manager.recover_initial_member_replay(peer, PacedFallbackCause::GroupChanged);
    assert!(manager.dirty_peers.contains(&peer));
    let waited = wait_for_next_row(manager, rx, tx).await;
    eprintln!("fallen-back member waited {waited:?}");
    assert!(
        waited <= crate::manager::DIRTY_RESYNC_BACKLOG_INTERVAL,
        "the fallen-back member idled {waited:?}"
    );
}

// A joiner registers while an ingest window holds Loc-RIB writes the group
// has not yet staged. Those writes predate the member's scan; publishing
// them must not knock the replay out of its initial mode.
#[tokio::test(start_paused = true)]
async fn a_replay_registered_inside_an_open_distribution_window_stays_initial() {
    let (mut manager, tx, mut expected) = replay_fixture();
    // A founder publishes the group first, so the joiner only replays it.
    let founder = receiver(9);
    let mut founder_rx = member(&mut manager, founder, 4096, false, false);
    for _ in 0..1024 {
        while founder_rx.try_recv().is_ok() {}
        if manager.pending_initial_registrations.is_empty()
            && manager.first_group_build.is_none()
            && !manager.is_initial_member_replay(founder)
        {
            break;
        }
        manager.advance_pending_initial_registration();
    }
    assert!(manager.grouped_member_of(founder).is_some());
    let keys: Vec<_> = expected.keys().copied().collect();
    manager.handle_update(test_routes_received(
        peer_v4(OTHER),
        keys.iter().map(|&key| route(key, OTHER, 200)).collect(),
    ));
    assert!(manager.process_next_route_chunk());
    assert!(
        !manager.pending_distribute_changed.is_empty(),
        "the first chunk leaves its window open"
    );
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 64, false, false);
    for _ in 0..256 {
        if manager.is_initial_member_replay(peer) {
            break;
        }
        manager.advance_pending_initial_registration();
    }
    assert!(manager.is_initial_member_replay(peer));
    assert!(!manager.pending_distribute_changed.is_empty());
    drain_route_chunks(&mut manager);
    for key in keys {
        expected.insert(key, (peer_v4(OTHER), 200));
    }
    let before = (whole_table_units(&manager), reconciles());
    let actor = tokio::spawn(manager.run_actor());
    let mut state = Inventory::new();
    drive_to_marker(&mut rx, &mut state, &expected).await;
    drop(tx);
    let manager = actor.await.unwrap();
    drop(founder_rx);
    assert_eq!(units_since(&manager, before.0), [0; 3], "whole-table units");
    assert_eq!(reconciles(), before.1, "the replay left its initial mode");
    crate::manager::tests::assert_paced_fallbacks(&manager.metrics, &[]);
}

// The resync tick is already armed at the ordinary interval for an unrelated
// dirty receiver when a replaying member regroups. The member's held
// End-of-RIB must not wait for that interval.
#[tokio::test(start_paused = true)]
async fn a_replay_fallback_does_not_wait_for_an_armed_resync_interval() {
    let (mut manager, tx, _) = replay_fixture();
    let unrelated = receiver(3);
    manager.initial_member_replays.min_routes = Some(usize::MAX);
    let mut unrelated_rx = member(&mut manager, unrelated, 4096, false, false);
    for _ in 0..64 {
        manager.advance_pending_initial_registration();
    }
    while unrelated_rx.try_recv().is_ok() {}
    assert!(manager.mark_outbound_dirty(unrelated));
    manager.initial_member_replays.min_routes = Some(1);
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 64, false, false);
    drop(first_page(&mut manager, &mut rx));
    while rx.try_recv().is_ok() {}
    let actor = tokio::spawn(manager.run_actor());
    tokio::task::yield_now().await;
    let start = tokio::time::Instant::now();
    let (reply, result) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer,
        export_policy: Some(community_chain(TAG)),
        reply,
    })
    .await
    .unwrap();
    result.await.unwrap().unwrap();
    let waited = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let page = rx.recv().await.unwrap();
            if !page.announce.is_empty() {
                return start.elapsed();
            }
        }
    })
    .await
    .expect("a row");
    drop(tx);
    let _ = actor.await.unwrap();
    drop(unrelated_rx);
    eprintln!("regrouped member waited {waited:?}");
    assert!(
        waited <= 2 * crate::manager::DIRTY_RESYNC_BACKLOG_INTERVAL,
        "the regrouped member idled {waited:?}"
    );
}

fn apply_page(state: &mut Inventory, page: &OutboundRouteUpdate) {
    for &(prefix, _) in page.unicast_withdrawals() {
        assert!(state.remove(&prefix).is_some(), "withdrew unsent {prefix}");
    }
    for row in page.announce.iter() {
        state.insert(row.prefix, (row.peer, row.local_pref()));
    }
    assert!(page.end_of_rib.is_empty(), "End-of-RIB during the churn");
}

// Churn that overflows the repair log on every rescan re-arms the replay a
// bounded number of times, then takes one counted `lag` fallback. The repair
// log never grows past its cap, and the member still ends with the exact
// table and one End-of-RIB.
#[tokio::test(start_paused = true)]
async fn a_replay_that_overflows_every_rescan_takes_one_lag_fallback() {
    const BURST: u16 = 5_000;
    let (mut manager, tx, mut expected) = replay_fixture();
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 64, false, false);
    let first = first_page(&mut manager, &mut rx);
    let mut state = inventory(&first);
    drop(first);
    let burst: Vec<_> = (0..BURST).map(|i| prefixes(V4_ROWS + i)[0]).collect();
    let mut announced = false;
    let mut rounds = 0;
    while manager.is_initial_member_replay(peer) {
        rounds += 1;
        assert!(rounds < 64, "the replay never left its reconcile");
        announced = !announced;
        manager.handle_update(if announced {
            new_routes(OTHER, V4_ROWS, BURST, 100)
        } else {
            withdraw(OTHER, &burst)
        });
        drain_route_chunks(&mut manager);
        for _ in 0..4 {
            manager.advance_pending_initial_registration();
            while let Ok(page) = rx.try_recv() {
                apply_page(&mut state, &page);
            }
            let repairs = manager.loc_rib.member_replay_repairs(peer).unwrap_or(0);
            assert!(repairs <= 4_096, "the repair log grew to {repairs}");
        }
    }
    crate::manager::tests::assert_paced_fallbacks(
        &manager.metrics,
        &[("initial_replay", "lag", 1.0)],
    );
    if announced {
        for &key in &burst {
            expected.insert(key, (peer_v4(OTHER), 100));
        }
    }
    let actor = tokio::spawn(manager.run_actor());
    drive_to_marker(&mut rx, &mut state, &expected).await;
    drop(tx);
    let _ = actor.await.unwrap();
    assert!(rx.is_empty(), "output after End-of-RIB");
}

// A forced outbound refresh rewinds the replay, which then falls back before
// its rescan resent a row. The resync that takes over must still be forced.
#[tokio::test(start_paused = true)]
async fn a_forced_reconcile_that_falls_back_keeps_its_resync_forced() {
    let (mut manager, tx, expected) = replay_fixture();
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 1, false, false);
    let first = first_page(&mut manager, &mut rx);
    let sent: BTreeSet<_> = first.announce.iter().map(|row| row.prefix).collect();
    let mut state = inventory(&first);
    let (reply, _result) = oneshot::channel();
    manager.handle_update(RibUpdate::RefreshPeerOutbound { peer, reply });
    assert!(manager.is_initial_member_replay(peer));
    assert!(!manager.force_outbound_peers.contains(&peer));
    let _ = manager.recover_initial_member_replay(peer, PacedFallbackCause::GroupChanged);
    assert!(!manager.is_initial_member_replay(peer));
    assert!(
        manager.force_outbound_peers.contains(&peer),
        "the fallback dropped the forced resync"
    );
    drop(first);
    let actor = tokio::spawn(manager.run_actor());
    let mut resent = BTreeSet::new();
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let page = rx.recv().await.unwrap();
            for &(prefix, _) in page.unicast_withdrawals() {
                state.remove(&prefix);
            }
            for row in page.announce.iter() {
                resent.insert(row.prefix);
                state.insert(row.prefix, (row.peer, row.local_pref()));
            }
            if !page.end_of_rib.is_empty() {
                break;
            }
        }
    })
    .await
    .expect("End-of-RIB");
    drop(tx);
    let _ = actor.await.unwrap();
    assert_eq!(state, expected);
    assert!(
        sent.is_subset(&resent),
        "{} rows sent before the forced refresh were not resent",
        sent.difference(&resent).count()
    );
}

/// Apply one page; a marker must find the table equal to `expected`.
fn apply_counting_markers(
    state: &mut Inventory,
    expected: &Inventory,
    markers: &mut usize,
    page: OutboundRouteUpdate,
) {
    let marker = !page.end_of_rib.is_empty();
    apply_page(
        state,
        &OutboundRouteUpdate {
            end_of_rib: Vec::new(),
            ..page
        },
    );
    if marker {
        *markers += 1;
        assert_eq!(
            *state, *expected,
            "End-of-RIB before the table was complete"
        );
    }
}

// One key changes before every reconcile turn. The writer keeps up, so the
// repair log never overflows and the `lag` bound never fires: the proof sweep
// must still advance while repairs drain, and End-of-RIB follows once.
#[tokio::test(start_paused = true)]
async fn single_key_churn_before_every_turn_still_completes_the_reconcile() {
    let (mut manager, tx, base) = replay_fixture();
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 64, false, false);
    let first = first_page(&mut manager, &mut rx);
    let mut state = inventory(&first);
    drop(first);
    assert!(manager.recover_initial_member_replay(peer, PacedFallbackCause::ChangeOutsideScan));
    let key = prefixes(V4_ROWS)[0];
    let mut with_key = base.clone();
    with_key.insert(key, (peer_v4(OTHER), 100));
    let mut present = false;
    let mut markers = 0;
    let mut turns = 0;
    while manager.is_initial_member_replay(peer) {
        turns += 1;
        // 21 turns: R1 alternates its discovery pages with repairs, then R2
        // alternates its three sweep pages with repairs.
        assert!(turns <= 24, "the reconcile never completed under churn");
        present = !present;
        manager.handle_update(if present {
            new_routes(OTHER, V4_ROWS, 1, 100)
        } else {
            withdraw(OTHER, &[key])
        });
        drain_route_chunks(&mut manager);
        manager.advance_pending_initial_registration();
        let expected = if present { &with_key } else { &base };
        while let Ok(page) = rx.try_recv() {
            apply_counting_markers(&mut state, expected, &mut markers, page);
        }
    }
    eprintln!("reconcile completed after {turns} turns");
    let expected = if present { with_key } else { base };
    let actor = tokio::spawn(manager.run_actor());
    drop(tx);
    let manager = actor.await.unwrap();
    while let Ok(page) = rx.try_recv() {
        apply_counting_markers(&mut state, &expected, &mut markers, page);
    }
    assert_eq!(markers, 1, "End-of-RIB count");
    assert_eq!(state, expected);
    crate::manager::tests::assert_paced_fallbacks(&manager.metrics, &[]);
}
