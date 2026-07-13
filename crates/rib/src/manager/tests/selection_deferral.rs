use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Afi, Ipv4Prefix, Safi};
use tokio::sync::{mpsc, oneshot};

use super::{dummy_query_rx, make_route_with_lp, query_best_routes};
use crate::{
    PeerOutboundState, RibManager, RibUpdate, SelectionDeferralConfig,
    SelectionDeferralWaiterConfig,
};

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);

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
fn withdrawn_restored_key_is_recomputed_before_release_eor() {
    let source = peer(1);
    let observer = peer(2);
    let (_tx, rx) = mpsc::channel(32);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 254)),
        BgpMetrics::new(),
    );

    let (observer_tx, mut observer_rx) = mpsc::channel(16);
    manager.handle_update(peer_up(observer, 7, observer_tx));
    while observer_rx.try_recv().is_ok() {}

    let route = make_route_with_lp(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
        Ipv4Addr::new(10, 0, 0, 1),
        100,
    );
    let prefix = route.prefix;
    manager.enqueue_routes_received(
        source,
        vec![route],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    while manager.process_next_route_chunk() {}
    assert!(manager.loc_rib.get(&prefix).is_some());
    while observer_rx.try_recv().is_ok() {}

    // Model a route restored before the planned-restart gate is installed.
    // A withdrawal received while gated disappears from Adj-RIB-In, so the
    // deferred identity ledger is the only release-time evidence that the
    // stale Loc-RIB row must be removed.
    manager = manager.with_selection_deferral(config(Duration::from_mins(1), &[source]));
    manager.enqueue_routes_received(
        source,
        Vec::new(),
        vec![(prefix, 0)],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    while manager.process_next_route_chunk() {}
    assert!(manager.loc_rib.get(&prefix).is_some());

    let metrics = manager.metrics.clone();
    let peer_gr_families = HashSet::from([FAMILY]);
    let released = manager
        .selection_deferral
        .as_mut()
        .unwrap()
        .classify_session(source, 8, false, &peer_gr_families, &metrics);
    assert!(released.is_empty());
    assert!(manager.selection_deferral_end_of_rib(source, 8, FAMILY));
    manager.handle_end_of_rib(source, FAMILY.0, FAMILY.1);
    manager.finalize_selection_deferral_all_eor(FAMILY);
    manager.release_selection_families(&[FAMILY], "test all EoRs received");

    assert!(manager.loc_rib.get(&prefix).is_none());
    let mut saw_withdraw = false;
    loop {
        let update = observer_rx.try_recv().unwrap();
        if update.end_of_rib.contains(&FAMILY) {
            assert!(saw_withdraw, "EoR overtook the deferred withdrawal");
            break;
        }
        saw_withdraw |= update.withdraw.iter().any(|(p, _)| *p == prefix);
    }
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
