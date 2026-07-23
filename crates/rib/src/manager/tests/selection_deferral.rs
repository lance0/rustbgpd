use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Afi, Ipv4Prefix, RouteRefreshSubtype, Safi};
use tokio::sync::{mpsc, oneshot};

use super::{
    dummy_query_rx, make_bgpls_route, make_evpn_imet, make_flowspec_route, make_labeled_rib_route,
    make_route_with_lp, make_rtc_rib_route, make_vpn_rib_route, query_best_routes,
};
use crate::manager::selection_deferral::SelectionDeferralTransition;
use crate::{
    PeerOutboundState, RibManager, RibUpdate, SelectionDeferralConfig,
    SelectionDeferralWaiterConfig,
};

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const READY_FAMILY: (Afi, Safi) = (Afi::Ipv6, Safi::Unicast);

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

fn counter_values_by_label(
    metrics: &BgpMetrics,
    name: &str,
    label_name: &str,
) -> HashMap<String, f64> {
    metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == name)
        .map_or_else(HashMap::new, |family| {
            family
                .get_metric()
                .iter()
                .map(|metric| {
                    let label = metric
                        .get_label()
                        .iter()
                        .find(|label| label.name() == label_name)
                        .unwrap_or_else(|| panic!("{name} sample lacks {label_name}"));
                    (label.value().to_string(), metric.get_counter().value())
                })
                .collect()
        })
}

fn peer(octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet))
}

fn peer_up(
    peer: IpAddr,
    session_id: u64,
    outbound_tx: mpsc::Sender<crate::OutboundRouteUpdate>,
) -> RibUpdate {
    peer_up_with_families(peer, session_id, outbound_tx, vec![FAMILY])
}

fn peer_up_with_families(
    peer: IpAddr,
    session_id: u64,
    outbound_tx: mpsc::Sender<crate::OutboundRouteUpdate>,
    sendable_families: Vec<(Afi, Safi)>,
) -> RibUpdate {
    RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 254),
        outbound_tx,
        export_policy: None,
        sendable_families,
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
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
        peer_enhanced_refresh: true,
    })
    .await
    .unwrap();
}

/// Stage a GR-capable OPEN context whose session negotiated only plain
/// RFC 2918 route refresh (no RFC 7313 enhanced route refresh).
async fn stage_gr_context_plain_refresh(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    session_id: u64,
) {
    tx.send(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: false,
        peer_gr_families: vec![FAMILY],
        peer_enhanced_refresh: false,
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

/// Load-bearing proof: deleting the failure-series initialization from
/// `SelectionDeferral::new` leaves both maps empty in this fresh registry.
#[test]
fn selection_deferral_construction_materializes_failure_counter_children() {
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(8);
    let selection_config = SelectionDeferralConfig {
        timeout: Duration::from_mins(1),
        waiters: vec![SelectionDeferralWaiterConfig {
            peer: peer(1),
            families: vec![FAMILY, READY_FAMILY],
        }],
    };

    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone())
        .with_selection_deferral(selection_config);
    assert!(manager.selection_deferral.is_some());

    let expected = HashMap::from([
        ("ipv4_unicast".to_string(), 0.0),
        ("ipv6_unicast".to_string(), 0.0),
    ]);
    assert_eq!(
        counter_values_by_label(
            &metrics,
            "bgp_selection_deferral_timeouts_total",
            "afi_safi"
        ),
        expected
    );
    assert_eq!(
        counter_values_by_label(
            &metrics,
            "bgp_selection_deferral_ledger_overflows_total",
            "afi_safi"
        ),
        expected
    );
}

fn commit_control_markers(
    manager: &mut RibManager,
    peer: IpAddr,
    end_of_rib: Vec<(Afi, Safi)>,
    refresh_markers: Vec<(Afi, Safi, RouteRefreshSubtype)>,
) -> bool {
    manager.try_send_and_commit_outbound_update(
        peer,
        Vec::new().into(),
        Vec::new().into(),
        Vec::new(),
        end_of_rib,
        refresh_markers,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
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
    // Zero End-of-RIB markers were consumed: the recorded reason must not
    // claim `all_eor`.
    assert_eq!(
        a_released.selection_deferral[0].release_reason,
        "all_excluded"
    );
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
fn collision_failback_stages_then_waits_for_refresh_completion() {
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
    assert!(
        selection
            .end_of_rib(survivor, 11, FAMILY, &metrics)
            .is_none()
    );
    selection.session_down(survivor, 11, &metrics);
    assert_eq!(
        selection.await_collision_failback_refresh(
            survivor,
            11,
            false,
            &gr_families,
            true,
            &metrics
        ),
        Some(Vec::new()),
        "the exact re-armed survivor must wait for a post-failback refresh"
    );

    let survivor_row = selection.peer_snapshot(survivor).remove(0);
    assert!(survivor_row.active);
    assert_eq!(survivor_row.waiter_state, "awaiting_refresh");
    assert_eq!(survivor_row.waiter_session_id, Some(11));
    assert_eq!(survivor_row.blocking_waiters, 2);
    assert!(
        selection
            .end_of_rib(survivor, 12, FAMILY, &metrics)
            .is_none(),
        "an unrelated session must not satisfy the refresh waiter"
    );

    assert!(
        selection
            .classify_session(remaining, 21, false, &gr_families, &metrics)
            .is_empty()
    );
    assert_eq!(
        selection.end_of_rib(remaining, 21, FAMILY, &metrics),
        Some(SelectionDeferralTransition::Stage { family: FAMILY })
    );
    let staged = selection.peer_snapshot(survivor).remove(0);
    assert!(staged.active);
    assert_eq!(staged.waiter_state, "awaiting_refresh");
    assert_eq!(staged.blocking_waiters, 1);
    assert!(
        selection
            .begin_route_refresh(survivor, 11, FAMILY)
            .is_none()
    );
    let release = selection
        .end_route_refresh(survivor, 11, FAMILY, &metrics)
        .unwrap();
    assert!(matches!(
        release,
        SelectionDeferralTransition::Release {
            family: FAMILY,
            already_staged: true,
            ..
        }
    ));
    manager.apply_selection_deferral_transitions([release], "test refresh completion");
    let released = manager
        .selection_deferral
        .as_ref()
        .unwrap()
        .peer_snapshot(survivor)
        .remove(0);
    assert!(!released.active);
    assert_eq!(released.release_reason, "collision_refresh");
}

#[test]
fn multiple_failback_survivors_release_only_after_every_waiter_converges() {
    let first_survivor = peer(1);
    let second_survivor = peer(2);
    let ordinary = peer(3);
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone())
        .with_selection_deferral(config(
            Duration::from_mins(1),
            &[first_survivor, second_survivor, ordinary],
        ));
    let gr_families = HashSet::from([FAMILY]);
    let selection = manager.selection_deferral.as_mut().unwrap();

    for (peer, session_id) in [(first_survivor, 11), (second_survivor, 21)] {
        assert!(
            selection
                .classify_session(peer, session_id, false, &gr_families, &metrics)
                .is_empty()
        );
        assert!(
            selection
                .end_of_rib(peer, session_id, FAMILY, &metrics)
                .is_none()
        );
        selection.session_down(peer, session_id, &metrics);
        assert_eq!(
            selection.await_collision_failback_refresh(
                peer,
                session_id,
                false,
                &gr_families,
                true,
                &metrics
            ),
            Some(Vec::new())
        );
        let waiting = selection.peer_snapshot(peer).remove(0);
        assert!(waiting.active);
        assert_eq!(waiting.waiter_state, "awaiting_refresh");
    }
    assert!(
        selection
            .classify_session(ordinary, 31, false, &gr_families, &metrics)
            .is_empty()
    );

    assert!(
        selection
            .begin_route_refresh(first_survivor, 11, FAMILY)
            .is_none()
    );
    assert!(
        selection
            .end_route_refresh(first_survivor, 11, FAMILY, &metrics)
            .is_none(),
        "one survivor EoRR cannot release while another survivor and an ordinary waiter remain"
    );
    assert!(selection.peer_snapshot(ordinary)[0].active);

    assert!(
        selection
            .begin_route_refresh(second_survivor, 21, FAMILY)
            .is_none()
    );
    assert!(
        selection
            .end_route_refresh(second_survivor, 21, FAMILY, &metrics)
            .is_none(),
        "every survivor can finish refresh while the ordinary waiter still blocks selection"
    );
    let waiting = selection.peer_snapshot(ordinary).remove(0);
    assert!(waiting.active);
    assert_eq!(waiting.waiter_state, "awaiting_eor");
    assert_eq!(waiting.blocking_waiters, 1);

    let release = selection
        .end_of_rib(ordinary, 31, FAMILY, &metrics)
        .unwrap();
    assert!(
        matches!(
            release,
            SelectionDeferralTransition::Release {
                family: FAMILY,
                already_staged: false,
                ..
            }
        ),
        "the last ordinary EoR must perform the one full release recompute"
    );
    manager.apply_selection_deferral_transitions([release], "test ordinary completion");
    let released = manager
        .selection_deferral
        .as_ref()
        .unwrap()
        .peer_snapshot(ordinary)
        .remove(0);
    assert!(!released.active);
    assert_eq!(released.release_reason, "all_eor");
}

#[test]
fn staged_selection_rejects_eor_and_refresh_marker_commits() {
    let source = peer(1);
    let target = peer(2);
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone())
        .with_selection_deferral(config(Duration::from_mins(1), &[source]));
    let gr_families = HashSet::from([FAMILY]);
    let transitions = {
        let selection = manager.selection_deferral.as_mut().unwrap();
        assert!(
            selection
                .classify_session(source, 11, false, &gr_families, &metrics)
                .is_empty()
        );
        selection.session_down(source, 11, &metrics);
        selection
            .await_collision_failback_refresh(source, 11, false, &gr_families, true, &metrics)
            .unwrap()
    };
    assert_eq!(
        transitions,
        vec![SelectionDeferralTransition::Stage { family: FAMILY }]
    );
    manager.apply_selection_deferral_transitions(transitions, "test collision failback stage");
    assert!(manager.selection_convergence_held(FAMILY));
    assert!(!manager.selection_deferred(FAMILY));

    let (outbound_tx, mut outbound_rx) = mpsc::channel(4);
    manager.outbound_peers.insert(target, outbound_tx);
    assert!(
        !commit_control_markers(&mut manager, target, vec![FAMILY], Vec::new()),
        "staged selection must still reject a family EoR commit"
    );
    assert!(
        !commit_control_markers(
            &mut manager,
            target,
            Vec::new(),
            vec![
                (FAMILY.0, FAMILY.1, RouteRefreshSubtype::BoRR),
                (FAMILY.0, FAMILY.1, RouteRefreshSubtype::EoRR),
            ],
        ),
        "staged selection must still reject route-refresh marker commits"
    );
    assert!(outbound_rx.try_recv().is_err());
}

#[test]
fn staged_selection_classifies_refresh_response_as_convergence_deferred() {
    let source = peer(1);
    let target = peer(2);
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone())
        .with_selection_deferral(config(Duration::from_mins(1), &[source]));
    let gr_families = HashSet::from([FAMILY]);
    let transitions = {
        let selection = manager.selection_deferral.as_mut().unwrap();
        assert!(
            selection
                .classify_session(source, 11, false, &gr_families, &metrics)
                .is_empty()
        );
        selection.session_down(source, 11, &metrics);
        selection
            .await_collision_failback_refresh(source, 11, false, &gr_families, true, &metrics)
            .unwrap()
    };
    manager.apply_selection_deferral_transitions(transitions, "test collision failback stage");
    let (outbound_tx, mut outbound_rx) = mpsc::channel(4);
    manager.outbound_peers.insert(target, outbound_tx);

    manager.send_route_refresh_response(target, FAMILY.0, FAMILY.1);

    assert_eq!(
        manager.selection_deferred_refresh.get(&target),
        Some(&HashSet::from([FAMILY]))
    );
    assert!(!manager.pending_refresh.contains_key(&target));
    assert!(outbound_rx.try_recv().is_err());
}

#[test]
fn dirty_resync_sends_ready_eor_and_retains_held_family() {
    let source = peer(1);
    let target = peer(2);
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 254)),
        metrics.clone(),
    )
    .with_selection_deferral(config(Duration::from_mins(1), &[source]));
    let gr_families = HashSet::from([FAMILY]);
    let transitions = {
        let selection = manager.selection_deferral.as_mut().unwrap();
        assert!(
            selection
                .classify_session(source, 11, false, &gr_families, &metrics)
                .is_empty()
        );
        selection.session_down(source, 11, &metrics);
        selection
            .await_collision_failback_refresh(source, 11, false, &gr_families, true, &metrics)
            .unwrap()
    };
    manager.apply_selection_deferral_transitions(transitions, "test collision failback stage");

    let (outbound_tx, mut outbound_rx) = mpsc::channel(16);
    manager.handle_update(peer_up_with_families(
        target,
        21,
        outbound_tx,
        vec![FAMILY, READY_FAMILY],
    ));
    let initial_ready_eor = outbound_rx.try_recv().unwrap();
    assert_eq!(initial_ready_eor.end_of_rib, vec![READY_FAMILY]);

    let route = make_route_with_lp(
        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
        Ipv4Addr::new(10, 0, 0, 1),
        100,
    );
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
    assert!(!outbound_rx.try_recv().unwrap().announce.is_empty());

    manager
        .pending_eor
        .entry(target)
        .or_default()
        .insert(READY_FAMILY);
    manager.mark_outbound_dirty(target);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());

    let resync = outbound_rx.try_recv().unwrap();
    assert!(
        !resync.announce.is_empty(),
        "dirty resync omitted route payload"
    );
    assert_eq!(resync.end_of_rib, vec![READY_FAMILY]);
    assert_eq!(
        manager.pending_eor.get(&target),
        Some(&HashSet::from([FAMILY])),
        "successful mixed-family resync must retain only the convergence-held EoR"
    );

    let release = {
        let selection = manager.selection_deferral.as_mut().unwrap();
        assert!(selection.begin_route_refresh(source, 11, FAMILY).is_none());
        selection
            .end_route_refresh(source, 11, FAMILY, &metrics)
            .unwrap()
    };
    manager.apply_selection_deferral_transitions([release], "test refresh completion");
    assert_eq!(outbound_rx.try_recv().unwrap().end_of_rib, vec![FAMILY]);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one production-shaped transcript pins dirty resync, EoR, and refresh ordering"
)]
fn dirty_observer_emits_convergence_eor_before_deferred_refresh() {
    let survivor = peer(1);
    let route_source = peer(2);
    let observer = peer(3);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let (_tx, rx) = mpsc::channel(32);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 0, 0, 254)),
        BgpMetrics::new(),
    )
    .with_selection_deferral(config(Duration::from_mins(1), &[survivor]));

    let (survivor_tx, _survivor_rx) = mpsc::channel(16);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: survivor,
        session_id: 11,
        peer_restart_state: false,
        peer_gr_families: vec![FAMILY],
        peer_enhanced_refresh: true,
    });
    manager.handle_update(peer_up(survivor, 11, survivor_tx));
    let (replacement_tx, _replacement_rx) = mpsc::channel(16);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: survivor,
        session_id: 12,
        peer_restart_state: false,
        peer_gr_families: vec![FAMILY],
        peer_enhanced_refresh: true,
    });
    manager.handle_update(peer_up(survivor, 12, replacement_tx));

    let (source_tx, _source_rx) = mpsc::channel(16);
    manager.handle_update(peer_up(route_source, 21, source_tx));
    let (observer_tx, mut observer_rx) = mpsc::channel(16);
    manager.handle_update(peer_up(observer, 31, observer_tx));
    manager.enqueue_routes_received(
        route_source,
        vec![make_route_with_lp(prefix, Ipv4Addr::new(10, 0, 0, 2), 100)],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    while manager.process_next_route_chunk() {}
    assert!(
        manager
            .loc_rib
            .get(&rustbgpd_wire::Prefix::V4(prefix))
            .is_none()
    );
    assert!(observer_rx.try_recv().is_err());

    manager.handle_update(RibUpdate::PeerDown {
        peer: survivor,
        session_id: 12,
    });
    let staged = observer_rx.try_recv().unwrap();
    assert!(
        staged
            .announce
            .iter()
            .any(|route| route.prefix == rustbgpd_wire::Prefix::V4(prefix))
    );
    assert!(!staged.end_of_rib.contains(&FAMILY));
    while observer_rx.try_recv().is_ok() {}

    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer: observer,
        session_id: 31,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    assert_eq!(
        manager.selection_deferred_refresh.get(&observer),
        Some(&HashSet::from([FAMILY]))
    );
    assert!(observer_rx.try_recv().is_err());

    manager.handle_update(RibUpdate::BeginRouteRefresh {
        peer: survivor,
        session_id: 11,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    // Preserve the production EoRR ordering while injecting the dirty state
    // at the release boundary: the ordinary refresh finisher runs first, then
    // the selection transition consumes the peer EoRR.
    manager.handle_end_route_refresh(survivor, FAMILY.0, FAMILY.1);
    manager.mark_outbound_dirty(observer);
    let release = manager
        .selection_deferral_end_route_refresh(survivor, 11, FAMILY)
        .unwrap();
    manager.apply_selection_deferral_transitions([release], "test survivor EoRR completion");
    assert!(!manager.selection_convergence_held(FAMILY));
    assert!(manager.dirty_peers.contains(&observer));
    assert!(
        observer_rx.try_recv().is_err(),
        "dirty observer emitted deferred BoRR/routes/EoRR before convergence resync/EoR"
    );
    assert_eq!(
        manager.pending_eor.get(&observer),
        Some(&HashSet::from([FAMILY]))
    );
    assert_eq!(
        manager.pending_refresh.get(&observer),
        Some(&HashSet::from([FAMILY]))
    );

    manager.distribute_changes(&HashSet::new(), &HashSet::new());

    let convergence = observer_rx.try_recv().unwrap();
    assert_eq!(convergence.end_of_rib, vec![FAMILY]);
    assert!(convergence.refresh_markers.is_empty());
    assert!(
        convergence
            .announce
            .iter()
            .any(|route| route.prefix == rustbgpd_wire::Prefix::V4(prefix))
    );

    let refresh = observer_rx.try_recv().unwrap();
    assert_eq!(
        refresh.refresh_markers,
        vec![
            (FAMILY.0, FAMILY.1, RouteRefreshSubtype::BoRR),
            (FAMILY.0, FAMILY.1, RouteRefreshSubtype::EoRR),
        ]
    );
    assert!(
        refresh
            .announce
            .iter()
            .any(|route| route.prefix == rustbgpd_wire::Prefix::V4(prefix))
    );
    assert!(observer_rx.try_recv().is_err());
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one transcript pins the full-channel no-diff retry ordering"
)]
fn no_diff_dirty_resync_keeps_refresh_behind_failed_convergence_eor() {
    let survivor = peer(1);
    let observer = peer(2);
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone())
        .with_selection_deferral(config(Duration::from_mins(1), &[survivor]));
    let gr_families = HashSet::from([FAMILY]);
    let transitions = {
        let selection = manager.selection_deferral.as_mut().unwrap();
        assert!(
            selection
                .classify_session(survivor, 11, false, &gr_families, &metrics)
                .is_empty()
        );
        selection.session_down(survivor, 11, &metrics);
        selection
            .await_collision_failback_refresh(survivor, 11, false, &gr_families, true, &metrics)
            .unwrap()
    };
    manager.apply_selection_deferral_transitions(transitions, "test collision failback stage");

    let (observer_tx, mut observer_rx) = mpsc::channel(2);
    let fill_tx = observer_tx.clone();
    manager.handle_update(peer_up(observer, 21, observer_tx));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    manager.enqueue_routes_received(
        observer,
        vec![make_route_with_lp(prefix, Ipv4Addr::new(10, 0, 0, 2), 100)],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    while manager.process_next_route_chunk() {}
    assert!(
        manager
            .loc_rib
            .get(&rustbgpd_wire::Prefix::V4(prefix))
            .is_some()
    );
    assert!(observer_rx.try_recv().is_err());
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer: observer,
        session_id: 21,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    assert_eq!(
        manager.selection_deferred_refresh.get(&observer),
        Some(&HashSet::from([FAMILY]))
    );

    assert!(
        manager
            .selection_deferral_begin_route_refresh(survivor, 11, FAMILY)
            .is_none()
    );
    manager.mark_outbound_dirty(observer);
    let release = manager
        .selection_deferral_end_route_refresh(survivor, 11, FAMILY)
        .unwrap();
    manager.apply_selection_deferral_transitions([release], "test survivor EoRR completion");
    assert_eq!(
        manager.pending_eor.get(&observer),
        Some(&HashSet::from([FAMILY]))
    );
    assert_eq!(
        manager.pending_refresh.get(&observer),
        Some(&HashSet::from([FAMILY]))
    );
    assert!(observer_rx.try_recv().is_err());

    fill_tx
        .try_send(crate::OutboundRouteUpdate::default())
        .unwrap();
    fill_tx
        .try_send(crate::OutboundRouteUpdate::default())
        .unwrap();
    assert_eq!(fill_tx.capacity(), 0);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());

    assert_counter_value(&metrics, "bgp_outbound_route_drops_total", 0.0);
    assert!(
        manager.dirty_peers.contains(&observer),
        "pending_eor={:?} pending_refresh={:?} channel_capacity={}",
        manager.pending_eor.get(&observer),
        manager.pending_refresh.get(&observer),
        fill_tx.capacity()
    );
    assert_eq!(
        manager.pending_eor.get(&observer),
        Some(&HashSet::from([FAMILY]))
    );
    assert_eq!(
        manager.pending_refresh.get(&observer),
        Some(&HashSet::from([FAMILY]))
    );
    let _ = observer_rx.try_recv().unwrap();
    let _ = observer_rx.try_recv().unwrap();
    manager.distribute_changes(&HashSet::new(), &HashSet::new());

    let convergence = observer_rx.try_recv().unwrap();
    assert_eq!(convergence.end_of_rib, vec![FAMILY]);
    assert!(convergence.refresh_markers.is_empty());
    let refresh = observer_rx.try_recv().unwrap();
    assert_eq!(
        refresh.refresh_markers,
        vec![
            (FAMILY.0, FAMILY.1, RouteRefreshSubtype::BoRR),
            (FAMILY.0, FAMILY.1, RouteRefreshSubtype::EoRR),
        ]
    );
    assert!(observer_rx.try_recv().is_err());
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
    let gr_families = HashSet::from([FAMILY]);
    let selection = manager.selection_deferral.as_mut().unwrap();

    assert_eq!(
        selection.await_collision_failback_refresh(
            unstamped,
            0,
            false,
            &gr_families,
            true,
            &metrics
        ),
        None
    );
    assert_eq!(
        selection.await_collision_failback_refresh(
            duplicate,
            22,
            false,
            &gr_families,
            true,
            &metrics
        ),
        None
    );
    for peer in [unstamped, duplicate] {
        let row = selection.peer_snapshot(peer).remove(0);
        assert!(row.active);
        assert_eq!(row.waiter_state, "awaiting_session");
        assert_eq!(row.blocking_waiters, 2);
    }
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "one protocol transcript pins collision failback staging and convergence ordering"
)]
async fn collision_failback_withholds_eor_until_survivor_refresh_converges() {
    let survivor = peer(1);
    let remaining = peer(2);
    let observer = peer(3);
    let survivor_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let remaining_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
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
    tx.send(RibUpdate::RoutesReceived {
        peer: survivor,
        session_id: 11,
        announced: vec![make_route_with_lp(
            survivor_prefix,
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
            remaining_prefix,
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

    let (observer_tx, mut observer_rx) = mpsc::channel(16);
    tx.send(peer_up(observer, 31, observer_tx)).await.unwrap();
    assert!(query_state(&tx, survivor).await.selection_deferral[0].active);

    tx.send(RibUpdate::PeerDown {
        peer: survivor,
        session_id: 12,
    })
    .await
    .unwrap();

    let state = query_state(&tx, survivor).await;
    assert!(
        state.selection_deferral[0].active,
        "collision failback declared convergence before the survivor replayed its routes"
    );
    assert_eq!(state.selection_deferral[0].waiter_state, "awaiting_refresh");
    assert_eq!(state.selection_deferral[0].waiter_session_id, Some(11));
    assert!(state.selection_deferral[0].release_reason.is_empty());
    assert_eq!(query_best_routes(&tx).await.len(), 1);

    let mut survivor_saw_remaining = false;
    let mut survivor_saw_refresh_request = false;
    while let Ok(update) = survivor_rx.try_recv() {
        assert!(!update.end_of_rib.contains(&FAMILY));
        survivor_saw_remaining |= update
            .announce
            .iter()
            .any(|route| route.prefix == rustbgpd_wire::Prefix::V4(remaining_prefix));
        survivor_saw_refresh_request |= update.request_refresh_all_negotiated;
    }
    assert!(
        survivor_saw_remaining,
        "fast stage omitted the remaining route"
    );
    assert!(
        survivor_saw_refresh_request,
        "failback omitted the inbound refresh request"
    );
    let mut observer_saw_remaining = false;
    while let Ok(update) = observer_rx.try_recv() {
        assert!(!update.end_of_rib.contains(&FAMILY));
        observer_saw_remaining |= update
            .announce
            .iter()
            .any(|route| route.prefix == rustbgpd_wire::Prefix::V4(remaining_prefix));
    }
    assert!(observer_saw_remaining, "observer missed the fast stage");

    // Re-register the observer after staging. Its initial table is allowed,
    // but its EoR must stay pending. Force one full-channel failure so the
    // dirty-resync path calls `flush_pending_eor` while convergence is held.
    let (observer_retry_tx, mut observer_retry_rx) = mpsc::channel(2);
    let observer_fill_tx = observer_retry_tx.clone();
    tx.send(peer_up(observer, 32, observer_retry_tx))
        .await
        .unwrap();
    let _ = query_state(&tx, observer).await;
    observer_fill_tx
        .try_send(crate::OutboundRouteUpdate::default())
        .unwrap();
    let (reply, result) = oneshot::channel();
    tx.send(RibUpdate::RefreshPeerOutbound {
        peer: observer,
        reply,
    })
    .await
    .unwrap();
    assert_eq!(result.await.unwrap(), Ok(()));
    let mut retry_saw_remaining = false;
    while let Ok(update) = observer_retry_rx.try_recv() {
        assert!(!update.end_of_rib.contains(&FAMILY));
        retry_saw_remaining |= update
            .announce
            .iter()
            .any(|route| route.prefix == rustbgpd_wire::Prefix::V4(remaining_prefix));
    }
    assert!(
        retry_saw_remaining,
        "observer retry missed the staged table"
    );

    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    let _ = query_state(&tx, observer).await;
    let mut resync_saw_remaining = false;
    while let Ok(update) = observer_retry_rx.try_recv() {
        assert!(
            !update.end_of_rib.contains(&FAMILY),
            "dirty resync flushed EoR before collision-failback convergence"
        );
        resync_saw_remaining |= update
            .announce
            .iter()
            .any(|route| route.prefix == rustbgpd_wire::Prefix::V4(remaining_prefix));
    }
    assert!(resync_saw_remaining, "observer dirty resync did not run");
    observer_rx = observer_retry_rx;

    tx.send(RibUpdate::RouteRefreshRequest {
        peer: observer,
        session_id: 32,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .await
    .unwrap();
    let _ = query_state(&tx, observer).await;
    assert!(
        observer_rx.try_recv().is_err(),
        "route-refresh response escaped before collision-failback convergence"
    );

    // A late ordinary EoR from the survivor cannot prove that the requested
    // replay completed, and an EoRR without a post-failback BoRR is stray.
    tx.send(RibUpdate::EndOfRib {
        peer: survivor,
        session_id: 11,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndRouteRefresh {
        peer: survivor,
        session_id: 11,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .await
    .unwrap();
    assert!(query_state(&tx, survivor).await.selection_deferral[0].active);

    tx.send(RibUpdate::BeginRouteRefresh {
        peer: survivor,
        session_id: 11,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: survivor,
        session_id: 11,
        announced: vec![make_route_with_lp(
            survivor_prefix,
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
    let best_before_eorr = query_best_routes(&tx).await;
    assert_eq!(best_before_eorr.len(), 2);
    assert!(query_state(&tx, survivor).await.selection_deferral[0].active);
    assert!(survivor_rx.try_recv().is_err());
    let mut observer_saw_survivor = false;
    while let Ok(update) = observer_rx.try_recv() {
        assert!(!update.end_of_rib.contains(&FAMILY));
        assert!(update.refresh_markers.is_empty());
        observer_saw_survivor |= update
            .announce
            .iter()
            .any(|route| route.prefix == rustbgpd_wire::Prefix::V4(survivor_prefix));
    }
    assert!(observer_saw_survivor, "observer missed the survivor replay");

    tx.send(RibUpdate::EndRouteRefresh {
        peer: survivor,
        session_id: 11,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .await
    .unwrap();
    let released = query_state(&tx, survivor).await;
    assert!(!released.selection_deferral[0].active);
    assert_eq!(
        released.selection_deferral[0].release_reason,
        "collision_refresh"
    );
    assert_eq!(query_best_routes(&tx).await.len(), 2);
    assert_eq!(survivor_rx.recv().await.unwrap().end_of_rib, vec![FAMILY]);

    let mut observer_saw_convergence_eor = false;
    let mut observer_saw_deferred_refresh = false;
    while !observer_saw_convergence_eor || !observer_saw_deferred_refresh {
        let update = observer_rx.recv().await.unwrap();
        if update.end_of_rib.contains(&FAMILY) && update.refresh_markers.is_empty() {
            assert!(
                observer_saw_survivor,
                "convergence EoR overtook the survivor's replayed route"
            );
            observer_saw_convergence_eor = true;
        }
        if !update.refresh_markers.is_empty() {
            assert!(
                observer_saw_convergence_eor,
                "deferred route-refresh response overtook convergence EoR"
            );
            observer_saw_deferred_refresh = true;
        }
        observer_saw_survivor |= update
            .announce
            .iter()
            .any(|route| route.prefix == rustbgpd_wire::Prefix::V4(survivor_prefix));
    }

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn collision_failback_keeps_the_original_selection_deadline() {
    let survivor = peer(1);
    let (tx, rx) = mpsc::channel(32);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(config(Duration::from_secs(5), &[survivor]));
    let handle = tokio::spawn(manager.run());

    let (survivor_tx, mut survivor_rx) = mpsc::channel(16);
    stage_gr_context(&tx, survivor, 11).await;
    tx.send(peer_up(survivor, 11, survivor_tx)).await.unwrap();
    let (replacement_tx, _replacement_rx) = mpsc::channel(8);
    stage_gr_context(&tx, survivor, 12).await;
    tx.send(peer_up(survivor, 12, replacement_tx))
        .await
        .unwrap();
    assert!(query_state(&tx, survivor).await.selection_deferral[0].active);

    tokio::time::advance(Duration::from_secs(4)).await;
    tx.send(RibUpdate::PeerDown {
        peer: survivor,
        session_id: 12,
    })
    .await
    .unwrap();
    let staged = query_state(&tx, survivor).await;
    assert!(staged.selection_deferral[0].active);
    assert_eq!(
        staged.selection_deferral[0].waiter_state,
        "awaiting_refresh"
    );
    assert!(staged.selection_deferral[0].remaining_millis <= 1_000);

    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    let released = query_state(&tx, survivor).await;
    assert!(!released.selection_deferral[0].active);
    assert_eq!(released.selection_deferral[0].release_reason, "timer");
    let mut saw_eor = false;
    while let Ok(update) = survivor_rx.try_recv() {
        saw_eor |= update.end_of_rib.contains(&FAMILY);
    }
    assert!(
        saw_eor,
        "the original timer must remain a bounded EoR fallback"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn synthetic_refresh_timeout_cannot_complete_collision_failback() {
    let survivor = peer(1);
    let (tx, rx) = mpsc::channel(32);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(config(Duration::from_mins(1), &[survivor]));
    let handle = tokio::spawn(manager.run());

    let (survivor_tx, mut survivor_rx) = mpsc::channel(16);
    stage_gr_context(&tx, survivor, 11).await;
    tx.send(peer_up(survivor, 11, survivor_tx)).await.unwrap();
    let (replacement_tx, _replacement_rx) = mpsc::channel(8);
    stage_gr_context(&tx, survivor, 12).await;
    tx.send(peer_up(survivor, 12, replacement_tx))
        .await
        .unwrap();
    tx.send(RibUpdate::PeerDown {
        peer: survivor,
        session_id: 12,
    })
    .await
    .unwrap();
    assert!(query_state(&tx, survivor).await.selection_deferral[0].active);
    while let Ok(update) = survivor_rx.try_recv() {
        assert!(!update.end_of_rib.contains(&FAMILY));
    }

    tx.send(RibUpdate::BeginRouteRefresh {
        peer: survivor,
        session_id: 11,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RouteRefreshTimeout {
        peer: survivor,
        session_id: 11,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .await
    .unwrap();
    let held = query_state(&tx, survivor).await;
    assert!(held.selection_deferral[0].active);
    assert_eq!(held.selection_deferral[0].waiter_state, "awaiting_refresh");
    assert!(survivor_rx.try_recv().is_err());

    // The independent post-failback BoRR receipt survives the local sweep, so
    // a later real peer EoRR can still prove convergence.
    tx.send(RibUpdate::EndRouteRefresh {
        peer: survivor,
        session_id: 11,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .await
    .unwrap();
    let released = query_state(&tx, survivor).await;
    assert!(!released.selection_deferral[0].active);
    assert_eq!(
        released.selection_deferral[0].release_reason,
        "collision_refresh"
    );
    assert_eq!(survivor_rx.recv().await.unwrap().end_of_rib, vec![FAMILY]);

    drop(tx);
    handle.await.unwrap();
}

#[test]
fn unavailable_survivor_channel_keeps_convergence_timer_bound() {
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
            peer_enhanced_refresh: true,
        });
        manager.handle_update(peer_up(survivor, 11, survivor_tx.clone()));
        let (replacement_tx, _replacement_rx) = mpsc::channel(1);
        manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
            peer: survivor,
            session_id: 12,
            peer_restart_state: false,
            peer_gr_families: vec![FAMILY],
            peer_enhanced_refresh: true,
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
        assert!(row.active);
        assert_eq!(row.waiter_state, "awaiting_refresh");
        assert!(row.release_reason.is_empty());
        if !channel_closed {
            let queued = survivor_rx.try_recv().unwrap();
            assert!(!queued.request_refresh_all_negotiated);
            assert!(survivor_rx.try_recv().is_err());
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one parameterized overflow receipt pins admission, complete sweep, and release ordering"
)]
fn collision_failback_overflow_receipt(
    identity_cap: usize,
    logical_byte_cap: usize,
    expect_retained_identity: bool,
) {
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

    // Model routes restored before the planned-restart gate is installed.
    // Either admission cap marks the family overflowed; the receipt below
    // distinguishes whether one identity fit before overflow. Release must use
    // the full frozen Loc-RIB union as the fail-safe identity source.
    manager = manager.with_selection_deferral(config(Duration::from_mins(1), &[source]));
    manager.set_deferred_selection_limits_for_test(identity_cap, logical_byte_cap);
    manager.record_deferred_unicast(&HashSet::from([prefix_a, prefix_b]));
    assert_counter_value(
        &metrics,
        "bgp_selection_deferral_ledger_overflows_total",
        1.0,
    );
    let (retained_bytes, overflowed) = manager.deferred_selection_ledger_state_for_test(FAMILY);
    assert!(overflowed, "the selected admission cap must overflow");
    assert_eq!(
        retained_bytes > 0,
        expect_retained_identity,
        "the receipt must distinguish identity-cap overflow after one admission from logical-byte overflow before admission"
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
    let transitions = manager
        .selection_deferral
        .as_mut()
        .unwrap()
        .await_collision_failback_refresh(source, 8, false, &peer_gr_families, true, &metrics)
        .unwrap();
    assert_eq!(
        transitions,
        vec![SelectionDeferralTransition::Stage { family: FAMILY }]
    );
    manager.apply_selection_deferral_transitions(transitions, "test collision failback stage");

    assert!(manager.loc_rib.get(&prefix_a).is_none());
    assert!(manager.loc_rib.get(&prefix_b).is_none());
    assert_eq!(manager.adj_ribs_out.get(&observer).unwrap().len(), 0);
    let mut withdrawn = HashSet::new();
    while let Ok(update) = observer_rx.try_recv() {
        assert!(
            !update.end_of_rib.contains(&FAMILY),
            "staging must not declare convergence"
        );
        withdrawn.extend(update.withdraw.iter().map(|(prefix, _)| *prefix));
    }
    assert_eq!(withdrawn, HashSet::from([prefix_a, prefix_b]));

    assert!(
        manager
            .selection_deferral
            .as_mut()
            .unwrap()
            .begin_route_refresh(source, 8, FAMILY)
            .is_none()
    );
    let completed = manager
        .selection_deferral
        .as_mut()
        .unwrap()
        .end_route_refresh(source, 8, FAMILY, &metrics)
        .into_iter();
    manager.apply_selection_deferral_transitions(completed, "test refresh completion");
    let released = manager
        .selection_deferral
        .as_ref()
        .unwrap()
        .peer_snapshot(source)
        .into_iter()
        .find(|row| (row.afi, row.safi) == FAMILY)
        .expect("the IPv4-unicast selection-deferral row must remain observable");
    assert!(!released.active, "the complete family gate must release");
    assert_eq!(released.release_reason, "collision_refresh");
    loop {
        let update = observer_rx.try_recv().unwrap();
        if update.end_of_rib.contains(&FAMILY) {
            break;
        }
    }
    assert_counter_value(
        &metrics,
        "bgp_selection_deferral_ledger_overflows_total",
        1.0,
    );
    assert_eq!(
        manager.deferred_selection_ledger_state_for_test(FAMILY),
        (0, false),
        "complete release must reclaim retained bytes and sticky overflow state"
    );
}

#[test]
fn collision_failback_identity_cap_sweeps_full_unicast_union_before_release_eor() {
    collision_failback_overflow_receipt(1, usize::MAX, true);
}

#[test]
fn collision_failback_logical_byte_cap_sweeps_full_unicast_union_before_release_eor() {
    collision_failback_overflow_receipt(usize::MAX, 0, false);
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
        peer_enhanced_refresh: true,
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
        peer_enhanced_refresh: true,
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

#[tokio::test]
async fn deleted_peer_waiter_releases_family_when_remaining_waiters_satisfy() {
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

    let (a_tx, mut a_rx) = mpsc::channel(16);
    stage_gr_context(&tx, a, 1).await;
    tx.send(peer_up(a, 1, a_tx)).await.unwrap();
    let (b_tx, _b_rx) = mpsc::channel(16);
    stage_gr_context(&tx, b, 2).await;
    tx.send(peer_up(b, 2, b_tx)).await.unwrap();

    // Deleting b from configuration removes its waiter outright, but cannot
    // release the family while a still owes its End-of-RIB.
    tx.send(RibUpdate::PeerDeleted { peer: b }).await.unwrap();
    let held = query_state(&tx, a).await;
    assert!(held.selection_deferral[0].active);
    assert_eq!(held.selection_deferral[0].waiter_state, "awaiting_eor");
    assert_eq!(held.selection_deferral[0].blocking_waiters, 1);
    assert_eq!(
        query_state(&tx, b).await.selection_deferral[0].waiter_state,
        "not_in_roster"
    );

    // The remaining waiter's EoR must release the family without waiting
    // for the Selection_Deferral_Timer.
    tx.send(RibUpdate::EndOfRib {
        peer: a,
        session_id: 1,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .await
    .unwrap();
    let released = query_state(&tx, a).await;
    assert!(
        !released.selection_deferral[0].active,
        "family stayed gated after every remaining waiter satisfied"
    );
    assert_eq!(released.selection_deferral[0].release_reason, "all_eor");
    assert_eq!(a_rx.recv().await.unwrap().end_of_rib, vec![FAMILY]);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn failback_survivor_without_enhanced_refresh_is_not_left_awaiting_refresh() {
    let survivor = peer(1);
    let (tx, rx) = mpsc::channel(32);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(config(Duration::from_mins(1), &[survivor]));
    let handle = tokio::spawn(manager.run());

    let (survivor_tx, mut survivor_rx) = mpsc::channel(16);
    stage_gr_context_plain_refresh(&tx, survivor, 11).await;
    tx.send(peer_up(survivor, 11, survivor_tx)).await.unwrap();
    let (replacement_tx, _replacement_rx) = mpsc::channel(8);
    stage_gr_context_plain_refresh(&tx, survivor, 12).await;
    tx.send(peer_up(survivor, 12, replacement_tx))
        .await
        .unwrap();
    tx.send(RibUpdate::PeerDown {
        peer: survivor,
        session_id: 12,
    })
    .await
    .unwrap();

    // A survivor that never negotiated RFC 7313 cannot produce the
    // post-failback BoRR/EoRR pair: it must be excluded, not parked in an
    // unfulfillable awaiting_refresh that holds the family all window.
    let released = query_state(&tx, survivor).await;
    assert_ne!(
        released.selection_deferral[0].waiter_state,
        "awaiting_refresh"
    );
    assert_eq!(released.selection_deferral[0].waiter_state, "excluded");
    assert!(
        !released.selection_deferral[0].active,
        "plain-refresh survivor convergence-held the family"
    );
    assert_eq!(
        released.selection_deferral[0].release_reason,
        "all_excluded"
    );
    let mut saw_eor = false;
    while let Ok(update) = survivor_rx.try_recv() {
        saw_eor |= update.end_of_rib.contains(&FAMILY);
    }
    assert!(
        saw_eor,
        "release must deliver the family EoR to the survivor"
    );

    drop(tx);
    handle.await.unwrap();
}

#[test]
fn release_sends_single_eor_to_refresh_deferred_peer() {
    let source = peer(1);
    let target = peer(2);
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone())
        .with_selection_deferral(config(Duration::from_mins(1), &[source]));
    let gr_families = HashSet::from([FAMILY]);
    let transitions = {
        let selection = manager.selection_deferral.as_mut().unwrap();
        assert!(
            selection
                .classify_session(source, 11, false, &gr_families, &metrics)
                .is_empty()
        );
        selection.session_down(source, 11, &metrics);
        selection
            .await_collision_failback_refresh(source, 11, false, &gr_families, true, &metrics)
            .unwrap()
    };
    manager.apply_selection_deferral_transitions(transitions, "test collision failback stage");

    let (outbound_tx, mut outbound_rx) = mpsc::channel(16);
    manager.handle_update(peer_up(target, 21, outbound_tx));
    while outbound_rx.try_recv().is_ok() {}
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer: target,
        session_id: 21,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    assert_eq!(
        manager.selection_deferred_refresh.get(&target),
        Some(&HashSet::from([FAMILY]))
    );
    assert!(outbound_rx.try_recv().is_err());

    let release = {
        let selection = manager.selection_deferral.as_mut().unwrap();
        assert!(selection.begin_route_refresh(source, 11, FAMILY).is_none());
        selection
            .end_route_refresh(source, 11, FAMILY, &metrics)
            .unwrap()
    };
    manager.apply_selection_deferral_transitions([release], "test refresh completion");

    let mut eor_updates = 0;
    let mut saw_refresh_markers = false;
    while let Ok(update) = outbound_rx.try_recv() {
        if update.end_of_rib.contains(&FAMILY) {
            eor_updates += 1;
        }
        if !update.refresh_markers.is_empty() {
            assert!(
                update.end_of_rib.is_empty(),
                "deferred refresh response duplicated the convergence EoR"
            );
            saw_refresh_markers = true;
        }
    }
    assert_eq!(
        eor_updates, 1,
        "release must deliver exactly one genuine EoR to a refresh-deferred peer"
    );
    assert!(saw_refresh_markers);
}
