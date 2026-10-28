use std::net::Ipv4Addr;
use std::time::Duration;

use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Afi, Ipv4Prefix, Prefix, Safi};
use tokio::sync::mpsc;

use super::{dummy_query_rx, make_route_with_lp};
use crate::test_support::peer_v4;
use crate::{
    PeerId, RibManager, RibUpdate, SelectionDeferralConfig, SelectionDeferralWaiterConfig,
};

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

fn context(peer: PeerId, session_id: u64) -> RibUpdate {
    RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![FAMILY],
        peer_enhanced_refresh: true,
        peer_llgr_families: Vec::new(),
        local_llgr_stale_time: 0,
    }
}

fn up(
    peer: PeerId,
    session_id: u64,
    outbound_tx: mpsc::Sender<crate::OutboundRouteUpdate>,
) -> RibUpdate {
    RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65001,
        peer_router_id: ADDRESS,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![FAMILY],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: Vec::new(),
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    }
}

fn announce(peer: PeerId, session_id: u64, prefix: Ipv4Prefix, local_pref: u32) -> RibUpdate {
    RibUpdate::RoutesReceived {
        peer,
        session_id,
        announced: vec![make_route_with_lp(prefix, ADDRESS, local_pref)],
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
        validated_with: None,
    }
}

async fn stale_ingress_case(restarting: bool) {
    let peer = peer_v4(ADDRESS);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let (tx, rx) = mpsc::channel(32);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    if restarting {
        manager = manager.with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer,
                families: vec![FAMILY],
            }],
        });
    }
    manager.initial_dump_defer_min_routes = 0;
    let (old_tx, _old_rx) = mpsc::channel(16);
    let (current_tx, _current_rx) = mpsc::channel(16);
    for update in [
        context(peer, 11),
        up(peer, 11, old_tx),
        context(peer, 22),
        up(peer, 22, current_tx),
        announce(peer, 22, prefix, 100),
        announce(peer, 11, prefix, 300),
        RibUpdate::EndOfRib {
            peer,
            session_id: 22,
            afi: FAMILY.0,
            safi: FAMILY.1,
        },
    ] {
        tx.try_send(update).unwrap();
    }

    // The real run loop drains queued primary units before advancing a
    // deferred registration. Drive that same seam, including route chunks.
    for _ in 0..4 {
        assert!(manager.drain_ready_updates().await);
    }
    assert_eq!(
        manager.live_sessions[&peer]
            .iter()
            .map(|session| session.session_id)
            .collect::<Vec<_>>(),
        vec![11, 22]
    );
    assert!(!manager.outbound_session_ids.contains_key(&peer));
    assert!(manager.pending_initial_registrations.contains(&peer));
    if restarting {
        assert!(manager.selection_deferred(FAMILY));
    }

    let mut units = 0;
    while manager.primary_backlog() > 0 || !manager.pending_route_batches.is_empty() {
        assert!(manager.drain_ready_updates().await);
        units += 1;
        assert!(units <= 16, "the finite queued transcript must drain");
    }
    assert!(!manager.outbound_session_ids.contains_key(&peer));
    assert!(!manager.selection_convergence_held(FAMILY));
    let best = manager.loc_rib.get(&Prefix::V4(prefix)).unwrap();
    assert_eq!(
        best.local_pref(),
        100,
        "late data from superseded session 11 replaced session 22 before outbound registration"
    );
    assert_eq!(manager.ribs[&peer].len(), 1);
}

#[tokio::test]
async fn deferred_registration_rejects_stale_ingress_before_current_eor_release() {
    stale_ingress_case(true).await;
}

#[tokio::test]
async fn deferred_registration_rejects_stale_ingress_on_cold_boot() {
    stale_ingress_case(false).await;
}

async fn drain_primary(manager: &mut RibManager) {
    for _ in 0..32 {
        if !manager.drain_ready_updates().await {
            return;
        }
    }
    panic!("the finite queued transcript must drain");
}

async fn deferred_pair() -> (
    RibManager,
    mpsc::Sender<RibUpdate>,
    [mpsc::Receiver<crate::OutboundRouteUpdate>; 2],
) {
    let peer = peer_v4(ADDRESS);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let (tx, rx) = mpsc::channel(32);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.initial_dump_defer_min_routes = 0;
    let (old_tx, old_rx) = mpsc::channel(16);
    let (current_tx, current_rx) = mpsc::channel(16);
    for update in [
        context(peer, 11),
        up(peer, 11, old_tx),
        context(peer, 22),
        up(peer, 22, current_tx),
        announce(peer, 22, prefix, 100),
    ] {
        tx.try_send(update).unwrap();
    }
    drain_primary(&mut manager).await;
    assert!(!manager.outbound_session_ids.contains_key(&peer));
    assert!(manager.pending_initial_registrations.contains(&peer));
    (manager, tx, [old_rx, current_rx])
}

fn assert_current_route(manager: &RibManager, local_pref: u32) {
    let peer = peer_v4(ADDRESS);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    assert_eq!(manager.ribs[&peer].len(), 1);
    assert_eq!(
        manager.ribs[&peer].get(&prefix, 0).unwrap().local_pref(),
        local_pref
    );
    assert_eq!(
        manager.loc_rib.get(&prefix).unwrap().local_pref(),
        local_pref
    );
    assert_eq!(manager.ribs[&peer].retained_stale_count(), 0);
}

#[tokio::test]
async fn deferred_registration_rejects_stale_completion_markers() {
    let peer = peer_v4(ADDRESS);
    let (mut manager, tx, [mut old_rx, mut current_rx]) = deferred_pair().await;
    tx.try_send(RibUpdate::EndOfRib {
        peer,
        session_id: 22,
        afi: FAMILY.0,
        safi: FAMILY.1,
    })
    .unwrap();
    drain_primary(&mut manager).await;
    for update in [
        RibUpdate::EndOfRib {
            peer,
            session_id: 11,
            afi: FAMILY.0,
            safi: FAMILY.1,
        },
        RibUpdate::BeginRouteRefresh {
            peer,
            session_id: 11,
            afi: FAMILY.0,
            safi: FAMILY.1,
        },
        RibUpdate::EndRouteRefresh {
            peer,
            session_id: 11,
            afi: FAMILY.0,
            safi: FAMILY.1,
        },
    ] {
        tx.try_send(update).unwrap();
    }
    drain_primary(&mut manager).await;
    assert_current_route(&manager, 100);
    assert!(!manager.refresh_in_progress.contains_key(&peer));
    for (kind, expected) in [("eor", 1.0), ("refresh", 2.0)] {
        let count = super::counter_metric_value(
            &manager.metrics,
            "bgp_rib_stale_session_message_ignored_total",
            &[("peer", &peer.label()), ("kind", kind)],
        );
        assert!((count - expected).abs() < f64::EPSILON);
    }
    for update in [
        RibUpdate::BeginRouteRefresh {
            peer,
            session_id: 22,
            afi: FAMILY.0,
            safi: FAMILY.1,
        },
        RibUpdate::EndRouteRefresh {
            peer,
            session_id: 22,
            afi: FAMILY.0,
            safi: FAMILY.1,
        },
    ] {
        tx.try_send(update).unwrap();
    }
    drain_primary(&mut manager).await;
    assert!(
        manager
            .ribs
            .get(&peer)
            .is_none_or(crate::adj_rib_in::AdjRibIn::is_empty)
    );
    assert!(manager.loc_rib.is_empty());
    assert!(!manager.outbound_session_ids.contains_key(&peer));
    manager.advance_pending_initial_registration();
    assert_eq!(manager.outbound_session_ids.get(&peer), Some(&22));
    let update = current_rx.try_recv().unwrap();
    assert_eq!(update.end_of_rib, vec![FAMILY]);
    assert!(old_rx.try_recv().is_err());
}

#[tokio::test]
async fn deferred_current_session_teardown_restores_older_survivor_authority() {
    let down = 22;
    let survivor = 11;
    let peer = peer_v4(ADDRESS);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let (mut manager, tx, mut receivers) = deferred_pair().await;
    tx.try_send(RibUpdate::PeerDown {
        peer,
        session_id: down,
    })
    .unwrap();
    tx.try_send(announce(peer, survivor, prefix, 200)).unwrap();
    drain_primary(&mut manager).await;
    assert_eq!(manager.live_sessions[&peer].len(), 1);
    assert_eq!(manager.live_sessions[&peer][0].session_id, survivor);
    assert!(!manager.outbound_session_ids.contains_key(&peer));
    assert_current_route(&manager, 200);
    manager.advance_pending_initial_registration();
    assert_eq!(manager.outbound_session_ids.get(&peer), Some(&survivor));
    assert!(!manager.pending_initial_registrations.contains(&peer));
    assert_current_route(&manager, 200);
    let mut refreshes = 0;
    let mut eor = 0;
    for (index, receiver) in receivers.iter_mut().enumerate() {
        while let Ok(update) = receiver.try_recv() {
            assert_eq!(
                [11, 22][index],
                survivor,
                "only the surviving writer receives recovery"
            );
            assert!(update.announce.is_empty());
            refreshes += usize::from(update.request_refresh_all_negotiated);
            eor += usize::from(update.end_of_rib.contains(&FAMILY));
        }
    }
    assert_eq!(refreshes, 1);
    assert_eq!(eor, 1);
}

#[tokio::test]
async fn staged_open_context_does_not_replace_live_ingress_authority() {
    let peer = peer_v4(ADDRESS);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let (mut manager, tx, _receivers) = deferred_pair().await;
    manager.handle_update(context(peer, 7));
    assert!(manager.pending_peer_gr_context.contains_key(&(peer, 7)));
    tx.try_send(announce(peer, 22, prefix, 150)).unwrap();
    drain_primary(&mut manager).await;
    assert_current_route(&manager, 150);
    let (next_tx, _next_rx) = mpsc::channel(16);
    for update in [
        up(peer, 7, next_tx),
        announce(peer, 7, prefix, 200),
        announce(peer, 22, prefix, 400),
    ] {
        tx.try_send(update).unwrap();
    }
    drain_primary(&mut manager).await;
    assert!(!manager.pending_peer_gr_context.contains_key(&(peer, 7)));
    let current = manager.live_sessions[&peer].last().unwrap();
    assert_eq!(
        current.session_id, 7,
        "PeerUp arrival order owns ingress, not numeric session ID"
    );
    assert!(current.gr_context.as_ref().unwrap().peer_enhanced_refresh);
    assert_current_route(&manager, 200);
    assert!(!manager.outbound_session_ids.contains_key(&peer));
    manager.advance_pending_initial_registration();
    assert_eq!(manager.outbound_session_ids.get(&peer), Some(&7));
}

#[tokio::test]
async fn deferred_older_session_down_preserves_current_routes_before_replay() {
    let peer = peer_v4(ADDRESS);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    let (mut manager, tx, [mut old_rx, mut current_rx]) = deferred_pair().await;
    assert_current_route(&manager, 100);
    tx.try_send(RibUpdate::PeerDown {
        peer,
        session_id: 11,
    })
    .unwrap();
    drain_primary(&mut manager).await;
    // No replacement announcement has arrived: session 22 still owns the
    // already accepted route while only its older collision peer went down.
    let received = manager
        .ribs
        .get(&peer)
        .and_then(|rib| rib.get(&prefix, 0))
        .map(crate::route::Route::local_pref);
    assert_eq!(
        received,
        Some(100),
        "older session 11 teardown must preserve current session 22's existing route before any replay"
    );
    assert_current_route(&manager, 100);
    assert_eq!(manager.live_sessions[&peer].len(), 1);
    assert_eq!(manager.live_sessions[&peer][0].session_id, 22);
    assert!(manager.pending_initial_registrations.contains(&peer));
    assert!(!manager.outbound_session_ids.contains_key(&peer));
    assert!(old_rx.try_recv().is_err());
    assert!(
        current_rx.try_recv().is_err(),
        "older teardown must not reset the current registration or request a fresh replay"
    );
}
