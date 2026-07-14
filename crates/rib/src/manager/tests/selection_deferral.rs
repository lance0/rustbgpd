use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Afi, Ipv4Prefix, Safi};
use tokio::sync::{mpsc, oneshot};

use super::{
    dummy_query_rx, make_bgpls_route, make_evpn_imet, make_flowspec_route, make_labeled_rib_route,
    make_route_with_lp, make_rtc_rib_route, make_vpn_rib_route, query_best_routes,
};
use crate::{
    PeerOutboundState, RibManager, RibUpdate, SelectionDeferralConfig,
    SelectionDeferralWaiterConfig,
};

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);

fn counter_value(metrics: &BgpMetrics, name: &str) -> f64 {
    metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == name)
        .map_or(0.0, |family| {
            family
                .get_metric()
                .iter()
                .map(|metric| metric.get_counter().value())
                .sum()
        })
}

fn assert_counter_value(metrics: &BgpMetrics, name: &str, expected: f64) {
    let actual = counter_value(metrics, name);
    assert!(
        (actual - expected).abs() < f64::EPSILON,
        "expected {name}={expected}, got {actual}"
    );
}

fn peer(octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet))
}

fn peer_up(
    peer: IpAddr,
    session_id: u64,
    outbound_tx: mpsc::Sender<crate::OutboundRouteUpdate>,
) -> RibUpdate {
    RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 254),
        outbound_tx,
        export_policy: None,
        sendable_families: vec![FAMILY],
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        per_client_best: false,
        add_path_send_families: Vec::new(),
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    }
}

async fn stage_gr_context(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr, session_id: u64) {
    stage_gr_context_with(tx, peer, session_id, false, vec![FAMILY]).await;
}

async fn stage_gr_context_with(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    session_id: u64,
    peer_restart_state: bool,
    peer_gr_families: Vec<(Afi, Safi)>,
) {
    tx.send(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state,
        peer_gr_families,
    })
    .await
    .unwrap();
}

async fn query_state(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr) -> PeerOutboundState {
    let (reply, rx) = oneshot::channel();
    tx.send(RibUpdate::QueryPeerOutboundState { peer, reply })
        .await
        .unwrap();
    rx.await.unwrap()
}

async fn advertised_count(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr) -> usize {
    let (reply, rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedCount { peer, reply })
        .await
        .unwrap();
    rx.await.unwrap()
}

async fn assert_table_before_eor(rx: &mut mpsc::Receiver<crate::OutboundRouteUpdate>) {
    let mut saw_table = false;
    loop {
        let update = rx.recv().await.unwrap();
        if update.end_of_rib.contains(&FAMILY) {
            assert!(saw_table, "EoR overtook the released initial table");
            return;
        }
        saw_table |= !update.announce.is_empty();
    }
}

fn config(timeout: Duration, peers: &[IpAddr]) -> SelectionDeferralConfig {
    SelectionDeferralConfig {
        timeout,
        waiters: peers
            .iter()
            .copied()
            .map(|peer| SelectionDeferralWaiterConfig {
                peer,
                families: vec![FAMILY],
            })
            .collect(),
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one adversarial scenario pins the complete replacement and release ordering"
)]
async fn frozen_roster_rearms_satisfied_peer_on_session_replacement() {
    let a = peer(1);
    let b = peer(2);
    let observer = peer(3);
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 254)),
        BgpMetrics::new(),
    )
    .with_selection_deferral(config(Duration::from_mins(1), &[a, b]));
    let handle = tokio::spawn(manager.run());

    let (a1_tx, mut a1_rx) = mpsc::channel(16);
    stage_gr_context(&tx, a, 1).await;
    tx.send(peer_up(a, 1, a1_tx)).await.unwrap();
    let (b_tx, mut b_rx) = mpsc::channel(16);
    stage_gr_context(&tx, b, 2).await;
    tx.send(peer_up(b, 2, b_tx)).await.unwrap();
    let (observer_tx, mut observer_rx) = mpsc::channel(16);
    tx.send(peer_up(observer, 7, observer_tx)).await.unwrap();

    tokio::task::yield_now().await;
    assert!(a1_rx.try_recv().is_err());
    assert!(b_rx.try_recv().is_err());
    assert!(observer_rx.try_recv().is_err());

    let route = make_route_with_lp(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
        Ipv4Addr::new(10, 0, 0, 2),
        100,
    );
    tx.send(RibUpdate::RoutesReceived {
        peer: b,
        session_id: 2,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    assert!(query_best_routes(&tx).await.is_empty());

    tx.send(RibUpdate::RouteRefreshRequest {
        peer: observer,
        session_id: 7,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .await
    .unwrap();
    tokio::task::yield_now().await;
    assert!(
        observer_rx.try_recv().is_err(),
        "route refresh leaked a gated family"
    );

    tx.send(RibUpdate::EndOfRib {
        peer: a,
        session_id: 1,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .await
    .unwrap();

    let (a3_tx, _a3_rx) = mpsc::channel(16);
    tx.send(peer_up(a, 3, a3_tx)).await.unwrap();
    tx.send(RibUpdate::EndOfRib {
        peer: b,
        session_id: 2,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .await
    .unwrap();

    let state = query_state(&tx, a).await;
    assert_eq!(state.selection_deferral.len(), 1);
    assert!(state.selection_deferral[0].active);
    assert_eq!(state.selection_deferral[0].waiter_state, "awaiting_session");
    assert_eq!(state.selection_deferral[0].waiter_session_id, None);
    assert_eq!(state.selection_deferral[0].blocking_waiters, 1);
    assert!(query_best_routes(&tx).await.is_empty());

    // Missing staged OPEN context fails closed. A later fully stamped
    // replacement binds the immutable roster entry to its new session.
    let (a4_tx, mut a4_rx) = mpsc::channel(16);
    stage_gr_context(&tx, a, 4).await;
    tx.send(peer_up(a, 4, a4_tx)).await.unwrap();
    let rebound = query_state(&tx, a).await;
    assert_eq!(rebound.selection_deferral[0].waiter_state, "awaiting_eor");
    assert_eq!(rebound.selection_deferral[0].waiter_session_id, Some(4));

    tx.send(RibUpdate::EndOfRib {
        peer: a,
        session_id: 1,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .await
    .unwrap();
    assert!(query_state(&tx, a).await.selection_deferral[0].active);

    tx.send(RibUpdate::EndOfRib {
        peer: a,
        session_id: 4,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .await
    .unwrap();
    let released = query_state(&tx, a).await;
    assert!(!released.selection_deferral[0].active);
    assert_eq!(released.selection_deferral[0].release_reason, "all_eor");
    assert_eq!(query_best_routes(&tx).await.len(), 1);
    assert_eq!(advertised_count(&tx, a).await, 1);
    assert_eq!(advertised_count(&tx, observer).await, 1);

    assert_table_before_eor(&mut observer_rx).await;
    assert_table_before_eor(&mut a4_rx).await;
    assert_eq!(b_rx.recv().await.unwrap().end_of_rib, vec![FAMILY]);
    let refresh = observer_rx.recv().await.unwrap();
    assert_eq!(refresh.announce.len(), 1);
    assert_eq!(
        refresh.refresh_markers,
        vec![
            (FAMILY.0, FAMILY.1, rustbgpd_wire::RouteRefreshSubtype::BoRR,),
            (FAMILY.0, FAMILY.1, rustbgpd_wire::RouteRefreshSubtype::EoRR,),
        ]
    );

    drop(a1_rx);
    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn restart_state_and_non_gr_sessions_are_excluded_without_waiting_for_eor() {
    let a = peer(1);
    let b = peer(2);
    let (tx, rx) = mpsc::channel(32);
    let manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 254)),
        BgpMetrics::new(),
    )
    .with_selection_deferral(config(Duration::from_mins(1), &[a, b]));
    let handle = tokio::spawn(manager.run());

    let (a_tx, mut a_rx) = mpsc::channel(8);
    stage_gr_context_with(&tx, a, 1, true, vec![FAMILY]).await;
    tx.send(peer_up(a, 1, a_tx)).await.unwrap();
    let a_state = query_state(&tx, a).await;
    assert!(a_state.selection_deferral[0].active);
    assert_eq!(a_state.selection_deferral[0].waiter_state, "excluded");
    assert_eq!(a_state.selection_deferral[0].blocking_waiters, 1);
    assert!(a_rx.try_recv().is_err());

    let (b_tx, mut b_rx) = mpsc::channel(8);
    stage_gr_context_with(&tx, b, 2, false, Vec::new()).await;
    tx.send(peer_up(b, 2, b_tx)).await.unwrap();

    let a_released = query_state(&tx, a).await;
    let b_released = query_state(&tx, b).await;
    assert!(!a_released.selection_deferral[0].active);
    assert_eq!(a_released.selection_deferral[0].waiter_state, "excluded");
    assert_eq!(b_released.selection_deferral[0].waiter_state, "excluded");
    assert_eq!(a_released.selection_deferral[0].release_reason, "all_eor");
    assert_eq!(a_rx.recv().await.unwrap().end_of_rib, vec![FAMILY]);
    assert_eq!(b_rx.recv().await.unwrap().end_of_rib, vec![FAMILY]);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn duplicate_address_roster_fails_closed_until_timer() {
    let a = peer(1);
    let (tx, rx) = mpsc::channel(16);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(config(Duration::from_secs(5), &[a, a]));
    let handle = tokio::spawn(manager.run());

    let (outbound_tx, mut outbound_rx) = mpsc::channel(8);
    stage_gr_context(&tx, a, 1).await;
    tx.send(peer_up(a, 1, outbound_tx)).await.unwrap();
    let blocked = query_state(&tx, a).await;
    assert!(blocked.selection_deferral[0].active);
    assert_eq!(
        blocked.selection_deferral[0].waiter_state,
        "awaiting_session"
    );
    assert!(outbound_rx.try_recv().is_err());

    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::task::yield_now().await;
    let released = query_state(&tx, a).await;
    assert!(!released.selection_deferral[0].active);
    assert_eq!(released.selection_deferral[0].release_reason, "timer");
    assert_eq!(outbound_rx.recv().await.unwrap().end_of_rib, vec![FAMILY]);

    drop(tx);
    handle.await.unwrap();
}

#[test]
fn collision_failback_excludes_only_the_rearmed_survivor() {
    let survivor = peer(1);
    let remaining = peer(2);
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone())
        .with_selection_deferral(config(Duration::from_mins(1), &[survivor, remaining]));
    let gr_families = HashSet::from([FAMILY]);
    let selection = manager.selection_deferral.as_mut().unwrap();

    assert!(
        selection
            .classify_session(survivor, 11, false, &gr_families, &metrics)
            .is_empty()
    );
    assert!(!selection.end_of_rib(survivor, 11, FAMILY, &metrics));
    selection.session_down(survivor, 11, &metrics);
    assert_eq!(
        selection.exclude_collision_failback_survivor(survivor, 11, &metrics),
        Some(Vec::new()),
        "the exact re-armed survivor should stop blocking without releasing a real waiter"
    );

    let survivor_row = selection.peer_snapshot(survivor).remove(0);
    assert!(survivor_row.active);
    assert_eq!(survivor_row.waiter_state, "excluded");
    assert_eq!(survivor_row.waiter_session_id, Some(11));
    assert_eq!(survivor_row.blocking_waiters, 1);
    assert!(
        !selection.end_of_rib(survivor, 12, FAMILY, &metrics),
        "an unrelated session must not satisfy the excluded survivor"
    );

    assert!(
        selection
            .classify_session(remaining, 21, false, &gr_families, &metrics)
            .is_empty()
    );
    assert!(selection.end_of_rib(remaining, 21, FAMILY, &metrics));
    selection.finalize_all_eor(FAMILY, &metrics);
    let remaining_row = selection.peer_snapshot(remaining).remove(0);
    assert!(!remaining_row.active);
    assert_eq!(remaining_row.release_reason, "all_eor");
}

#[test]
fn unstamped_or_ambiguous_collision_failback_stays_timer_bound() {
    let unstamped = peer(1);
    let duplicate = peer(2);
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(8);
    let mut manager =
        RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone()).with_selection_deferral(
            config(Duration::from_mins(1), &[unstamped, duplicate, duplicate]),
        );
    let selection = manager.selection_deferral.as_mut().unwrap();

    assert_eq!(
        selection.exclude_collision_failback_survivor(unstamped, 0, &metrics),
        None
    );
    assert_eq!(
        selection.exclude_collision_failback_survivor(duplicate, 22, &metrics),
        None
    );
    for peer in [unstamped, duplicate] {
        let row = selection.peer_snapshot(peer).remove(0);
        assert!(row.active);
        assert_eq!(row.waiter_state, "awaiting_session");
        assert_eq!(row.blocking_waiters, 2);
    }
}

#[tokio::test]
async fn exact_collision_failback_releases_table_before_eor_and_then_requests_refresh() {
    let survivor = peer(1);
    let remaining = peer(2);
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 254)),
        BgpMetrics::new(),
    )
    .with_selection_deferral(config(Duration::from_mins(1), &[survivor, remaining]));
    let handle = tokio::spawn(manager.run());

    let (survivor_tx, mut survivor_rx) = mpsc::channel(16);
    stage_gr_context(&tx, survivor, 11).await;
    tx.send(peer_up(survivor, 11, survivor_tx)).await.unwrap();
    tx.send(RibUpdate::EndOfRib {
        peer: survivor,
        session_id: 11,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .await
    .unwrap();

    let (replacement_tx, _replacement_rx) = mpsc::channel(8);
    stage_gr_context(&tx, survivor, 12).await;
    tx.send(peer_up(survivor, 12, replacement_tx))
        .await
        .unwrap();
    tx.send(RibUpdate::EndOfRib {
        peer: survivor,
        session_id: 11,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .await
    .unwrap();

    let (remaining_tx, _remaining_rx) = mpsc::channel(8);
    stage_gr_context(&tx, remaining, 21).await;
    tx.send(peer_up(remaining, 21, remaining_tx)).await.unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: remaining,
        session_id: 21,
        announced: vec![make_route_with_lp(
            Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
            Ipv4Addr::new(10, 0, 0, 2),
            100,
        )],
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        peer: remaining,
        session_id: 21,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .await
    .unwrap();
    assert!(query_state(&tx, survivor).await.selection_deferral[0].active);

    tx.send(RibUpdate::PeerDown {
        peer: survivor,
        session_id: 12,
    })
    .await
    .unwrap();

    let state = query_state(&tx, survivor).await;
    assert!(!state.selection_deferral[0].active);
    assert_eq!(state.selection_deferral[0].waiter_state, "excluded");
    assert_eq!(state.selection_deferral[0].waiter_session_id, Some(11));
    assert_eq!(state.selection_deferral[0].release_reason, "all_eor");
    assert_eq!(query_best_routes(&tx).await.len(), 1);

    let mut saw_table = false;
    let mut saw_eor = false;
    loop {
        let update = survivor_rx.recv().await.unwrap();
        if !update.announce.is_empty() {
            assert!(!saw_eor, "released table arrived after EoR");
            saw_table = true;
        }
        if update.end_of_rib.contains(&FAMILY) {
            assert!(saw_table, "EoR overtook the released table");
            saw_eor = true;
        }
        if update.request_refresh_all_negotiated {
            assert!(
                saw_eor,
                "best-effort refresh request overtook table and EoR"
            );
            break;
        }
    }

    drop(tx);
    handle.await.unwrap();
}

#[test]
fn unavailable_survivor_channel_does_not_rearm_released_selection() {
    for channel_closed in [false, true] {
        let survivor = peer(1);
        let metrics = BgpMetrics::new();
        let (_tx, rx) = mpsc::channel(8);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics)
            .with_selection_deferral(config(Duration::from_mins(1), &[survivor]));
        let (survivor_tx, mut survivor_rx) = mpsc::channel(1);
        manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
            peer: survivor,
            session_id: 11,
            peer_restart_state: false,
            peer_gr_families: vec![FAMILY],
        });
        manager.handle_update(peer_up(survivor, 11, survivor_tx.clone()));
        let (replacement_tx, _replacement_rx) = mpsc::channel(1);
        manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
            peer: survivor,
            session_id: 12,
            peer_restart_state: false,
            peer_gr_families: vec![FAMILY],
        });
        manager.handle_update(peer_up(survivor, 12, replacement_tx));

        if channel_closed {
            survivor_rx.close();
        } else {
            survivor_tx
                .try_send(crate::OutboundRouteUpdate::default())
                .unwrap();
        }
        manager.handle_update(RibUpdate::PeerDown {
            peer: survivor,
            session_id: 12,
        });

        let row = manager
            .selection_deferral
            .as_ref()
            .unwrap()
            .peer_snapshot(survivor)
            .remove(0);
        assert!(!row.active);
        assert_eq!(row.waiter_state, "excluded");
        assert_eq!(row.release_reason, "all_eor");
        if !channel_closed {
            let queued = survivor_rx.try_recv().unwrap();
            assert!(!queued.request_refresh_all_negotiated);
            assert!(survivor_rx.try_recv().is_err());
        }
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one overflow fixture pins complete sweep, ordering, and byte reclamation"
)]
fn collision_failback_overflow_sweeps_and_reclaims_before_release_eor() {
    let source = peer(1);
    let observer = peer(2);
    let (_tx, rx) = mpsc::channel(32);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 254)),
        metrics.clone(),
    );

    let (observer_tx, mut observer_rx) = mpsc::channel(16);
    manager.handle_update(peer_up(observer, 7, observer_tx));
    while observer_rx.try_recv().is_ok() {}

    let route_a = make_route_with_lp(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
        Ipv4Addr::new(10, 0, 0, 1),
        100,
    );
    let route_b = make_route_with_lp(
        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
        Ipv4Addr::new(10, 0, 0, 1),
        100,
    );
    let prefix_a = route_a.prefix;
    let prefix_b = route_b.prefix;
    manager.enqueue_routes_received(
        source,
        vec![route_a, route_b],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    while manager.process_next_route_chunk() {}
    assert!(manager.loc_rib.get(&prefix_a).is_some());
    assert!(manager.loc_rib.get(&prefix_b).is_some());
    while observer_rx.try_recv().is_ok() {}

    // Model a route restored before the planned-restart gate is installed.
    // Only one identity fits in this test ledger. The second marks the family
    // overflowed, after which later identities for that family are not retained.
    // Release must use the frozen Loc-RIB as the fail-safe identity source.
    manager = manager.with_selection_deferral(config(Duration::from_mins(1), &[source]));
    manager.set_deferred_selection_limits_for_test(1, 64 * 1024 * 1024);
    manager.record_deferred_unicast(&HashSet::from([prefix_a, prefix_b]));
    assert_counter_value(
        &metrics,
        "bgp_selection_deferral_ledger_overflows_total",
        1.0,
    );
    manager.enqueue_routes_received(
        source,
        Vec::new(),
        vec![(prefix_a, 0), (prefix_b, 0)],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    while manager.process_next_route_chunk() {}
    assert!(manager.loc_rib.get(&prefix_a).is_some());
    assert!(manager.loc_rib.get(&prefix_b).is_some());

    let peer_gr_families = HashSet::from([FAMILY]);
    let released = manager
        .selection_deferral
        .as_mut()
        .unwrap()
        .classify_session(source, 8, false, &peer_gr_families, &metrics);
    assert!(released.is_empty());
    manager
        .selection_deferral
        .as_mut()
        .unwrap()
        .session_down(source, 8, &metrics);
    let released = manager
        .selection_deferral
        .as_mut()
        .unwrap()
        .exclude_collision_failback_survivor(source, 8, &metrics)
        .unwrap();
    assert_eq!(released, vec![FAMILY]);
    manager.release_selection_families(&released, "test collision failback");

    assert!(manager.loc_rib.get(&prefix_a).is_none());
    assert!(manager.loc_rib.get(&prefix_b).is_none());
    assert_eq!(manager.adj_ribs_out.get(&observer).unwrap().len(), 0);
    let mut withdrawn = HashSet::new();
    loop {
        let update = observer_rx.try_recv().unwrap();
        if update.end_of_rib.contains(&FAMILY) {
            assert_eq!(
                withdrawn,
                HashSet::from([prefix_a, prefix_b]),
                "EoR overtook one or more deferred withdrawals"
            );
            break;
        }
        withdrawn.extend(update.withdraw.iter().map(|(prefix, _)| *prefix));
    }
    assert_counter_value(
        &metrics,
        "bgp_selection_deferral_ledger_overflows_total",
        1.0,
    );
    assert_eq!(
        manager.deferred_selection_ledger_state_for_test(FAMILY),
        (0, false),
        "complete failback release must reclaim the family byte charge and sticky overflow state"
    );
}

#[test]
fn overflow_fallback_sweeps_every_typed_loc_rib_store() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let route_peer = Ipv4Addr::new(10, 0, 0, 1);

    let unicast = make_route_with_lp(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
        route_peer,
        100,
    );
    let unicast_key = unicast.prefix;
    assert!(
        manager
            .loc_rib
            .recompute(unicast_key, std::iter::once(&unicast))
    );

    let flowspec = make_flowspec_route(route_peer);
    let flowspec_key = flowspec.selection_key();
    assert!(
        manager
            .loc_rib
            .recompute_flowspec(flowspec_key.clone(), std::iter::once(&flowspec))
    );

    let evpn = make_evpn_imet(route_peer, 101);
    let evpn_key = evpn.key();
    assert!(
        manager
            .loc_rib
            .recompute_evpn(evpn_key, std::iter::once(&evpn))
    );

    let vpn = make_vpn_rib_route(route_peer, 31, 100, 100);
    let vpn_key = vpn.nlri.key();
    manager.loc_rib.insert_vpn(vpn);

    let labeled = make_labeled_rib_route(route_peer, 32, 100, 100);
    let labeled_key = labeled.nlri.key();
    manager.loc_rib.insert_labeled(labeled);

    let bgpls = make_bgpls_route(route_peer, 33, 100);
    let bgpls_key = bgpls.key();
    let bgpls_family = bgpls.family.to_afi_safi();
    manager.loc_rib.insert_bgpls(bgpls);

    let rtc = make_rtc_rib_route(route_peer, 34, 100);
    let rtc_key = rtc.key();
    manager.loc_rib.insert_rtc(rtc);

    let families = [
        FAMILY,
        (Afi::Ipv4, Safi::FlowSpec),
        (Afi::L2Vpn, Safi::Evpn),
        (Afi::Ipv4, Safi::MplsVpn),
        (Afi::Ipv4, Safi::LabeledUnicast),
        bgpls_family,
        crate::route::RtcRibRouteKey::afi_safi(),
    ];
    for family in families {
        manager.mark_deferred_selection_overflow_for_test(family);
        manager.recompute_released_selection_family_for_test(family);
    }

    assert!(manager.loc_rib.get(&unicast_key).is_none());
    assert!(manager.loc_rib.get_flowspec(&flowspec_key).is_none());
    assert!(manager.loc_rib.get_evpn(&evpn_key).is_none());
    assert!(manager.loc_rib.get_vpn(&vpn_key).is_none());
    assert!(manager.loc_rib.get_labeled(&labeled_key).is_none());
    assert!(manager.loc_rib.get_bgpls(&bgpls_key).is_none());
    assert!(manager.loc_rib.get_rtc(&rtc_key).is_none());
}

#[test]
fn zero_byte_limit_overflows_all_real_recorders_once_per_family() {
    let route_peer = Ipv4Addr::new(10, 0, 0, 1);
    let bgpls_route = make_bgpls_route(route_peer, 33, 100);
    let families = vec![
        FAMILY,
        (Afi::Ipv4, Safi::FlowSpec),
        (Afi::L2Vpn, Safi::Evpn),
        (Afi::Ipv4, Safi::MplsVpn),
        (Afi::Ipv4, Safi::LabeledUnicast),
        bgpls_route.family.to_afi_safi(),
        crate::route::RtcRibRouteKey::afi_safi(),
    ];
    let selection_config = SelectionDeferralConfig {
        timeout: Duration::from_mins(1),
        waiters: vec![SelectionDeferralWaiterConfig {
            peer: peer(1),
            families,
        }],
    };
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone())
        .with_selection_deferral(selection_config);
    manager.set_deferred_selection_limits_for_test(1_000_000, 0);

    let unicast = HashSet::from([make_route_with_lp(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
        route_peer,
        100,
    )
    .prefix]);
    let flowspec = HashSet::from([make_flowspec_route(route_peer).selection_key()]);
    let evpn = HashSet::from([make_evpn_imet(route_peer, 101).key()]);
    let vpn = HashSet::from([make_vpn_rib_route(route_peer, 31, 100, 100).key()]);
    let labeled = HashSet::from([make_labeled_rib_route(route_peer, 32, 100, 100).key()]);
    let bgpls = HashSet::from([bgpls_route.key()]);
    let rtc = HashSet::from([make_rtc_rib_route(route_peer, 34, 100).key()]);

    for _ in 0..2 {
        manager.record_deferred_unicast(&unicast);
        manager.record_deferred_flowspec(&flowspec);
        manager.record_deferred_evpn(&evpn);
        manager.record_deferred_vpn(&vpn);
        manager.record_deferred_labeled(&labeled);
        manager.record_deferred_bgpls(&bgpls);
        manager.record_deferred_rtc(&rtc);
    }

    let overflow = metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == "bgp_selection_deferral_ledger_overflows_total")
        .expect("all seven recorders should publish overflow metrics");
    assert_eq!(
        overflow.get_metric().len(),
        7,
        "each gated family should have one metric series"
    );
    assert!(
        overflow
            .get_metric()
            .iter()
            .all(|metric| (metric.get_counter().value() - 1.0).abs() < f64::EPSILON),
        "sticky overflow must increment each family exactly once"
    );
}

#[test]
fn inactive_selection_gate_skips_identity_tracking_before_and_after_release() {
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let prefix = rustbgpd_wire::Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    let affected = HashSet::from([prefix]);

    manager.record_deferred_unicast_with_test_limit(&affected, 0);
    assert_counter_value(
        &metrics,
        "bgp_selection_deferral_ledger_overflows_total",
        0.0,
    );

    manager = manager.with_selection_deferral(config(Duration::from_secs(1), &[peer(1)]));
    let released = manager
        .selection_deferral
        .as_mut()
        .unwrap()
        .expire(&metrics);
    assert_eq!(released, vec![FAMILY]);
    manager.record_deferred_unicast_with_test_limit(&affected, 0);
    assert_counter_value(
        &metrics,
        "bgp_selection_deferral_ledger_overflows_total",
        0.0,
    );
}

#[test]
fn peer_teardown_discards_unconsumed_gr_context() {
    let a = peer(1);
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: a,
        session_id: 9,
        peer_restart_state: false,
        peer_gr_families: vec![FAMILY],
    });
    assert!(manager.pending_peer_gr_context.contains_key(&(a, 9)));
    manager.peer_down_teardown(a);
    assert!(!manager.pending_peer_gr_context.contains_key(&(a, 9)));
}

#[tokio::test(start_paused = true)]
async fn queued_route_is_applied_before_simultaneous_eor_and_timer_release() {
    let source = peer(1);
    let observer = peer(2);
    let (tx, rx) = mpsc::channel(32);
    let manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 254)),
        BgpMetrics::new(),
    )
    .with_selection_deferral(config(Duration::from_secs(5), &[source]));
    let handle = tokio::spawn(manager.run());

    let (source_tx, mut source_rx) = mpsc::channel(8);
    let (observer_tx, mut observer_rx) = mpsc::channel(8);
    tx.try_send(RibUpdate::SetPeerGracefulRestartContext {
        peer: source,
        session_id: 1,
        peer_restart_state: false,
        peer_gr_families: vec![FAMILY],
    })
    .unwrap();
    tx.try_send(peer_up(source, 1, source_tx)).unwrap();
    tx.try_send(peer_up(observer, 2, observer_tx)).unwrap();
    tx.try_send(RibUpdate::RoutesReceived {
        peer: source,
        session_id: 1,
        announced: vec![make_route_with_lp(
            Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
            Ipv4Addr::new(10, 0, 0, 1),
            100,
        )],
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
    })
    .unwrap();
    tx.try_send(RibUpdate::EndOfRib {
        peer: source,
        session_id: 1,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .unwrap();

    // The actor first runs with the channel batch and timer both ready.
    tokio::time::advance(Duration::from_secs(5)).await;
    let state = query_state(&tx, source).await;
    assert_eq!(state.selection_deferral[0].release_reason, "all_eor");
    assert_eq!(query_best_routes(&tx).await.len(), 1);
    assert_table_before_eor(&mut observer_rx).await;
    assert_eq!(source_rx.recv().await.unwrap().end_of_rib, vec![FAMILY]);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn full_outbound_channel_keeps_eor_pending_until_dirty_resync() {
    let source = peer(1);
    let observer = peer(2);
    let (tx, rx) = mpsc::channel(32);
    let manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 254)),
        BgpMetrics::new(),
    )
    .with_selection_deferral(config(Duration::from_mins(1), &[source]));
    let handle = tokio::spawn(manager.run());

    let (source_tx, mut source_rx) = mpsc::channel(8);
    stage_gr_context(&tx, source, 1).await;
    tx.send(peer_up(source, 1, source_tx)).await.unwrap();
    let (observer_tx, mut observer_rx) = mpsc::channel(1);
    tx.send(peer_up(observer, 2, observer_tx)).await.unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        session_id: 1,
        announced: vec![make_route_with_lp(
            Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24),
            Ipv4Addr::new(10, 0, 0, 1),
            100,
        )],
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        peer: source,
        session_id: 1,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .await
    .unwrap();

    let table = observer_rx.recv().await.unwrap();
    assert_eq!(table.announce.len(), 1);
    assert!(table.end_of_rib.is_empty());
    assert_eq!(source_rx.recv().await.unwrap().end_of_rib, vec![FAMILY]);

    // The one-slot observer channel rejected the first EoR attempt. Once
    // capacity is available, dirty resync must finish and only then flush it.
    tokio::time::advance(Duration::from_secs(1)).await;
    let resync = observer_rx.recv().await.unwrap();
    assert_eq!(resync.announce.len(), 1);
    assert_eq!(resync.end_of_rib, vec![FAMILY]);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn timer_releases_never_established_waiter_and_records_reason() {
    let a = peer(1);
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(16);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone())
        .with_selection_deferral(config(Duration::from_secs(5), &[a]));
    let handle = tokio::spawn(manager.run());

    tokio::time::advance(Duration::from_secs(5)).await;
    let state = query_state(&tx, a).await;
    assert_eq!(state.selection_deferral[0].release_reason, "timer");
    assert!(!state.selection_deferral[0].active);

    let families = metrics.registry().gather();
    let timeout = families
        .iter()
        .find(|family| family.name() == "bgp_selection_deferral_timeouts_total")
        .unwrap();
    assert!((timeout.get_metric()[0].get_counter().value() - 1.0).abs() < f64::EPSILON);

    drop(tx);
    handle.await.unwrap();
}
