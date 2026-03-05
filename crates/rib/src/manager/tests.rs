use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use rustbgpd_wire::{
    Afi, AsPath, AsPathSegment, FlowSpecComponent, FlowSpecPrefix, FlowSpecRule, Ipv4Prefix,
    Ipv6Prefix, Origin, PathAttribute, Prefix, RpkiValidation, Safi,
};
use tokio::sync::oneshot;

use super::*;
use crate::event::RouteEventType;
use crate::route::{FlowSpecRoute, Route};

/// Default sendable families for IPv4-only test peers.
fn ipv4_sendable() -> Vec<(Afi, Safi)> {
    vec![(Afi::Ipv4, Safi::Unicast)]
}

/// Sendable families for dual-stack test peers.
fn dual_stack_sendable() -> Vec<(Afi, Safi)> {
    vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)]
}

/// Sendable families for IPv4 `FlowSpec` test peers.
fn ipv4_flowspec_sendable() -> Vec<(Afi, Safi)> {
    vec![(Afi::Ipv4, Safi::FlowSpec)]
}

/// Drain the initial End-of-RIB marker sent at `PeerUp` time.
async fn drain_eor(out_rx: &mut mpsc::Receiver<OutboundRouteUpdate>) {
    let eor = out_rx.recv().await.unwrap();
    assert!(eor.announce.is_empty());
    assert!(eor.withdraw.is_empty());
    assert!(!eor.end_of_rib.is_empty());
}

async fn query_best_routes(tx: &mpsc::Sender<RibUpdate>) -> Vec<Route> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap()
}

async fn query_received_routes(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr) -> Vec<Route> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: Some(peer),
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap()
}

async fn query_mrt_snapshot(tx: &mpsc::Sender<RibUpdate>) -> crate::update::MrtSnapshotData {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryMrtSnapshot { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap()
}

fn make_route(prefix: Ipv4Prefix, next_hop: Ipv4Addr) -> Route {
    Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(next_hop),
        peer: IpAddr::V4(next_hop),
        attributes: vec![],
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
    }
}

fn make_v6_route(prefix: Ipv6Prefix, next_hop: Ipv6Addr) -> Route {
    Route {
        prefix: Prefix::V6(prefix),
        next_hop: IpAddr::V6(next_hop),
        peer: IpAddr::V6(next_hop),
        attributes: vec![],
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
    }
}

fn make_route_with_lp(prefix: Ipv4Prefix, peer: Ipv4Addr, local_pref: u32) -> Route {
    Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(peer),
        peer: IpAddr::V4(peer),
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001])],
            }),
            PathAttribute::LocalPref(local_pref),
        ],
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
    }
}

fn make_flowspec_route(peer: Ipv4Addr) -> FlowSpecRoute {
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    FlowSpecRoute {
        rule: FlowSpecRule {
            components: vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(
                prefix,
            ))],
        },
        afi: Afi::Ipv4,
        peer: IpAddr::V4(peer),
        attributes: vec![],
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    }
}

#[tokio::test]
async fn routes_received_and_queried() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: Some(peer),
        reply: reply_tx,
    })
    .await
    .unwrap();

    let routes = reply_rx.await.unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].prefix, Prefix::V4(prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn peer_down_clears_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerDown { peer }).await.unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: Some(peer),
        reply: reply_tx,
    })
    .await
    .unwrap();

    let routes = reply_rx.await.unwrap();
    assert!(routes.is_empty());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn withdrawal_removes_route() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![
            make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1)),
            make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1)),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix1), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: Some(peer),
        reply: reply_tx,
    })
    .await
    .unwrap();

    let routes = reply_rx.await.unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].prefix, Prefix::V4(prefix2));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn query_all_peers() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24),
            Ipv4Addr::new(10, 0, 0, 1),
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24),
            Ipv4Addr::new(10, 0, 0, 2),
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: None,
        reply: reply_tx,
    })
    .await
    .unwrap();

    let routes = reply_rx.await.unwrap();
    assert_eq!(routes.len(), 2);

    drop(tx);
    handle.await.unwrap();
}

// --- Loc-RIB integration tests ---

#[tokio::test]
async fn best_routes_returns_winner() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

    // Peer1: local_pref 100
    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Peer2: local_pref 200 — should win
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();

    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer2);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn peer_down_promotes_second_best() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Peer2 goes down — peer1 should be promoted
    tx.send(RibUpdate::PeerDown { peer: peer2 }).await.unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();

    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer1);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn withdrawal_updates_best() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Peer2 withdraws the prefix
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();

    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer1);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn different_best_per_prefix() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix_a = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let prefix_b = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

    // Peer1 wins prefix_a (higher LP), peer2 wins prefix_b (higher LP)
    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![
            make_route_with_lp(prefix_a, Ipv4Addr::new(1, 0, 0, 1), 200),
            make_route_with_lp(prefix_b, Ipv4Addr::new(1, 0, 0, 1), 100),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![
            make_route_with_lp(prefix_a, Ipv4Addr::new(1, 0, 0, 2), 100),
            make_route_with_lp(prefix_b, Ipv4Addr::new(1, 0, 0, 2), 200),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();

    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 2);

    let best_a = best
        .iter()
        .find(|r| r.prefix == Prefix::V4(prefix_a))
        .unwrap();
    let best_b = best
        .iter()
        .find(|r| r.prefix == Prefix::V4(prefix_b))
        .unwrap();
    assert_eq!(best_a.peer, peer1);
    assert_eq!(best_b.peer, peer2);

    drop(tx);
    handle.await.unwrap();
}

// --- M3 outbound distribution tests ---

#[tokio::test]
async fn peer_up_triggers_initial_table_dump() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Inject a route from source
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Register target for outbound
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    // Should receive initial table dump
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));
    assert!(update.withdraw.is_empty());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_change_distributes_to_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn single_best_send_normalizes_path_id_to_zero() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
    route.path_id = 42;

    tx.send(RibUpdate::RoutesReceived {
        peer: route.peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));
    assert_eq!(update.announce[0].path_id, 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn split_horizon_prevents_echo() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    // The route is FROM this peer — should not be sent back
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Force a query to serialize the event loop
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    // Channel should be empty (no outbound update sent)
    assert!(out_rx.try_recv().is_err());

    drop(tx);
    handle.await.unwrap();
}

/// Like [`make_route`] but with iBGP origin (iBGP-learned route).
fn make_ibgp_route(prefix: Ipv4Prefix, next_hop: Ipv4Addr) -> Route {
    Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(next_hop),
        peer: IpAddr::V4(next_hop),
        attributes: vec![],
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
    }
}

#[tokio::test]
async fn ibgp_route_not_sent_to_ibgp_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Source: iBGP peer
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Target: iBGP peer (is_ebgp: false)
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // iBGP-learned route should NOT be sent to iBGP peer
    assert!(out_rx.try_recv().is_err());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn ibgp_route_sent_to_ebgp_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Source: iBGP peer
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Target: eBGP peer (is_ebgp: true)
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    // Initial dump includes the route (iBGP→eBGP is allowed)
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

    // Then EoR
    drain_eor(&mut out_rx).await;

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn ebgp_route_sent_to_ibgp_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Source: eBGP peer
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Target: iBGP peer (is_ebgp: false)
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    // Initial dump includes the route (eBGP→iBGP is allowed)
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

    // Then EoR
    drain_eor(&mut out_rx).await;

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn ibgp_split_horizon_withdraw_on_best_change() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Setup: eBGP source announces route, iBGP target receives it
    let ebgp_source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let ibgp_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Register iBGP target peer
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: ibgp_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // eBGP route → should be advertised to iBGP peer
    tx.send(RibUpdate::RoutesReceived {
        peer: ebgp_source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);

    // Now the eBGP source goes down, replaced by iBGP source
    tx.send(RibUpdate::PeerDown { peer: ebgp_source })
        .await
        .unwrap();

    // Withdraw should be sent to iBGP target
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.withdraw.len(), 1);

    // iBGP source announces the same prefix
    let ibgp_source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    tx.send(RibUpdate::RoutesReceived {
        peer: ibgp_source,
        announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 3))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Force serialization
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    // iBGP-learned route should NOT be sent to iBGP peer
    assert!(out_rx.try_recv().is_err());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn local_route_sent_to_ibgp_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Register iBGP target peer first
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Inject a local route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        peer: LOCAL_PEER,
        attributes: vec![PathAttribute::Origin(Origin::Igp)],
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::InjectRoute {
        route,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let _ = reply_rx.await;

    // Local route SHOULD be sent to iBGP peer (unlike iBGP-learned routes)
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn local_route_in_initial_table_to_ibgp_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Inject a local route first
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        peer: LOCAL_PEER,
        attributes: vec![PathAttribute::Origin(Origin::Igp)],
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::InjectRoute {
        route,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let _ = reply_rx.await;

    // Register iBGP target peer — should receive local route in initial dump
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    // Initial dump should include the local route
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

    // Then EoR
    drain_eor(&mut out_rx).await;

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn peer_down_cleans_up_outbound() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (out_tx, _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerDown { peer }).await.unwrap();

    // Query advertised routes — should be empty after PeerDown
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer,
        reply: reply_tx,
    })
    .await
    .unwrap();

    let routes = reply_rx.await.unwrap();
    assert!(routes.is_empty());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn inject_route_enters_loc_rib_and_distributes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        peer: LOCAL_PEER,
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
        ],
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
    };

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::InjectRoute {
        route,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    // Should be in Loc-RIB
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].prefix, Prefix::V4(prefix));

    // Should have been distributed
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn withdraw_injected_removes_and_distributes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        peer: LOCAL_PEER,
        attributes: vec![PathAttribute::Origin(Origin::Igp)],
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
    };

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::InjectRoute {
        route,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let _ = reply_rx.await;

    // Consume the inject announcement
    let _ = out_rx.recv().await;

    // Now withdraw
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::WithdrawInjected {
        prefix: Prefix::V4(prefix),
        path_id: 0,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    // Should receive withdrawal
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.withdraw.len(), 1);
    assert_eq!(update.withdraw[0], (Prefix::V4(prefix), 0));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn export_policy_blocks_denied() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
    let export_policy = PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: Some(Prefix::V4(denied_prefix)),
            ge: None,
            le: None,
            action: PolicyAction::Deny,
            match_community: vec![],
            match_as_path: None,
            match_rpki_validation: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }]);

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, Some(export_policy), None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    // This route matches the deny entry
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(denied_prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Force serialization
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    // Should NOT have received the denied route
    assert!(out_rx.try_recv().is_err());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn query_advertised_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Wait for distribution
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();

    let routes = reply_rx.await.unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].prefix, Prefix::V4(prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn per_peer_export_policy() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
    let allowed_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Peer1 gets a deny policy on 10.0.0.0/8, peer2 has no per-peer policy
    let peer1_export = Some(PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: Some(Prefix::V4(denied_prefix)),
            ge: None,
            le: None,
            action: PolicyAction::Deny,
            match_community: vec![],
            match_as_path: None,
            match_rpki_validation: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }]));

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

    let (send_filtered, mut recv_filtered) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: peer1,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: send_filtered,
        export_policy: peer1_export,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut recv_filtered).await;

    let (send_unfiltered, mut recv_unfiltered) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: peer2,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: send_unfiltered,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut recv_unfiltered).await;

    // Source peer sends both prefixes
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![
            make_route(denied_prefix, Ipv4Addr::new(10, 0, 0, 1)),
            make_route(allowed_prefix, Ipv4Addr::new(10, 0, 0, 1)),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Peer1: should get only the allowed prefix (denied_prefix blocked)
    let filtered = recv_filtered.recv().await.unwrap();
    assert_eq!(filtered.announce.len(), 1);
    assert_eq!(filtered.announce[0].prefix, Prefix::V4(allowed_prefix));

    // Peer2: should get both (no per-peer policy, no global policy)
    let unfiltered = recv_unfiltered.recv().await.unwrap();
    assert_eq!(unfiltered.announce.len(), 2);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn peer_down_cleans_up_export_policy() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (out_tx, _out_rx) = mpsc::channel(64);
    let policy = Some(PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))),
            ge: None,
            le: None,
            action: PolicyAction::Deny,
            match_community: vec![],
            match_as_path: None,
            match_rpki_validation: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }]));

    tx.send(RibUpdate::PeerUp {
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: policy,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerDown { peer }).await.unwrap();

    // Query to confirm loop processed PeerDown
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let routes = reply_rx.await.unwrap();
    assert!(routes.is_empty());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
#[expect(clippy::too_many_lines)]
async fn channel_full_marks_dirty_and_resyncs() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

    // Channel capacity 1: fills after one send
    let (out_tx, mut out_rx) = mpsc::channel(1);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // First route: should succeed (channel empty → fits)
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Drain the successful send so we can verify AdjRibOut
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);

    // Verify AdjRibOut has the route
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let advertised = reply_rx.await.unwrap();
    assert_eq!(advertised.len(), 1);

    // Send prefix2 — fills the channel (capacity 1)
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // DON'T drain — channel is now full. Withdraw prefix1 to trigger
    // another distribute_changes that will fail on try_send.
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix1), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Force serialization
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    // After channel-full failure, AdjRibOut preserves last successfully
    // sent state: both prefix1 and prefix2 were sent before the failure.
    // The withdrawal of prefix1 was lost because the channel was full.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let advertised = reply_rx.await.unwrap();
    assert_eq!(
        advertised.len(),
        2,
        "AdjRibOut preserves last successfully sent state (prefix1+prefix2)"
    );

    // Now drain the channel to allow resync
    let _ = out_rx.recv().await.unwrap();

    // Advance time to trigger the dirty-peer resync timer — no external
    // route mutation needed; the timer fires independently.
    tokio::time::advance(Duration::from_secs(2)).await;

    // Drain the resync update
    let resync = out_rx.recv().await.unwrap();

    // The resync should withdraw prefix1 (no longer in Loc-RIB). Prefix2
    // was already successfully enqueued before the channel filled, so it
    // does not need to be re-announced unless it diverged.
    assert!(
        resync.withdraw.contains(&(Prefix::V4(prefix1), 0)),
        "resync should withdraw prefix1 (no longer in Loc-RIB)"
    );
    assert!(
        !resync.withdraw.contains(&(Prefix::V4(prefix2), 0)),
        "resync should not withdraw prefix2"
    );

    // After successful resync, AdjRibOut should match Loc-RIB
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let advertised = reply_rx.await.unwrap();
    assert_eq!(
        advertised.len(),
        1,
        "AdjRibOut matches Loc-RIB after resync (only prefix2)"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn dirty_resync_not_starved_by_query_traffic() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    let (out_tx, mut out_rx) = mpsc::channel(1);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    // Announce prefix1
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = out_rx.recv().await.unwrap(); // drain

    // Withdraw prefix1 — channel is empty so this fills it
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix1), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // That send succeeded (channel was empty). Now announce again to fill.
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Don't drain — channel full. Send another route to trigger a failed
    // distribute_changes, marking the peer dirty.
    let prefix3 = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12);
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix3, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Force serialization
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    // Drain the outbound channel to allow resync
    let _ = out_rx.recv().await.unwrap();

    // Advance 500ms — not enough for the 1s timer
    tokio::time::advance(Duration::from_millis(500)).await;

    // Send several queries to exercise the "message churn" path.
    // With the old code (sleep recreated each iteration), each query
    // would reset the 1s countdown, starving the timer.
    for _ in 0..5 {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;
    }

    // Advance the remaining 600ms — total 1100ms, past the 1s deadline
    // that was set before the query churn.
    tokio::time::advance(Duration::from_millis(600)).await;

    // The resync should fire despite the intervening queries.
    let resync = out_rx.recv().await.unwrap();
    assert!(
        !resync.announce.is_empty() || !resync.withdraw.is_empty(),
        "resync should produce updates despite query churn"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn initial_dump_failure_leaves_adjribout_empty() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Pre-populate Loc-RIB
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Use a closed channel (drop rx side immediately) to guarantee send failure
    let (out_tx, out_rx) = mpsc::channel(1);
    drop(out_rx);

    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    // AdjRibOut should be empty since initial dump send failed
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let advertised = reply_rx.await.unwrap();
    assert!(
        advertised.is_empty(),
        "AdjRibOut should be empty when initial dump send fails"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn initial_dump_failure_resyncs_via_timer() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Pre-populate Loc-RIB
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Use a full channel (capacity 1, pre-filled) to fail the initial dump
    // but keep the channel recoverable (unlike closed).
    let (out_tx, mut out_rx) = mpsc::channel(1);
    // Fill the channel so send_initial_table's try_send fails
    out_tx
        .send(OutboundRouteUpdate {
            next_hop_override: vec![],
            announce: vec![],
            withdraw: vec![],
            end_of_rib: vec![],
            refresh_markers: vec![],
            flowspec_announce: vec![],
            flowspec_withdraw: vec![],
        })
        .await
        .unwrap();

    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    // Force serialization — initial dump should have failed (channel full)
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let advertised = reply_rx.await.unwrap();
    assert!(
        advertised.is_empty(),
        "AdjRibOut should be empty after failed initial dump"
    );

    // Drain the channel to make room for the resync
    let _ = out_rx.recv().await.unwrap();

    // Advance time to trigger the resync timer
    tokio::time::advance(Duration::from_secs(2)).await;

    // The resync should deliver the initial table
    let resync = out_rx.recv().await.unwrap();
    assert_eq!(
        resync.announce.len(),
        1,
        "resync should announce the route from Loc-RIB"
    );
    assert_eq!(resync.announce[0].prefix, Prefix::V4(prefix));
    assert!(resync.withdraw.is_empty());
    assert_eq!(resync.end_of_rib, ipv4_sendable());

    // AdjRibOut should now reflect Loc-RIB
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let advertised = reply_rx.await.unwrap();
    assert_eq!(
        advertised.len(),
        1,
        "AdjRibOut should match Loc-RIB after resync"
    );

    drop(tx);
    handle.await.unwrap();
}

// --- Route event streaming tests ---

async fn subscribe_events(
    tx: &mpsc::Sender<RibUpdate>,
) -> tokio::sync::broadcast::Receiver<crate::event::RouteEvent> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::SubscribeRouteEvents { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap()
}

#[tokio::test]
async fn route_event_added_on_new_best() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mut events_rx = subscribe_events(&tx).await;

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_type, crate::event::RouteEventType::Added);
    assert_eq!(event.prefix, Prefix::V4(prefix));
    assert_eq!(event.peer, Some(peer));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_withdrawn_on_last_removed() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Subscribe after route is added
    let mut events_rx = subscribe_events(&tx).await;

    // Withdraw the route
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_type, crate::event::RouteEventType::Withdrawn);
    assert_eq!(event.prefix, Prefix::V4(prefix));
    assert!(event.peer.is_none());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_best_changed_on_better_path() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

    // Peer1 announces first
    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Subscribe after first route is installed
    let mut events_rx = subscribe_events(&tx).await;

    // Peer2 announces with higher local-pref — best changes
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_type, crate::event::RouteEventType::BestChanged);
    assert_eq!(event.prefix, Prefix::V4(prefix));
    assert_eq!(event.peer, Some(peer2));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multiple_subscribers_receive_same_events() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mut sub1 = subscribe_events(&tx).await;
    let mut sub2 = subscribe_events(&tx).await;

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let e1 = sub1.recv().await.unwrap();
    let e2 = sub2.recv().await.unwrap();
    assert_eq!(e1.prefix, Prefix::V4(prefix));
    assert_eq!(e2.prefix, Prefix::V4(prefix));
    assert_eq!(e1.event_type, e2.event_type);

    drop(tx);
    handle.await.unwrap();
}

// --- WatchRoutes event tests ---

#[tokio::test]
async fn route_event_withdrawn_carries_previous_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let mut events_rx = subscribe_events(&tx).await;

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_type, RouteEventType::Withdrawn);
    assert!(event.peer.is_none());
    assert_eq!(event.previous_peer, Some(peer));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_best_changed_carries_both_peers() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let mut events_rx = subscribe_events(&tx).await;

    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_type, RouteEventType::BestChanged);
    assert_eq!(event.peer, Some(peer2));
    assert_eq!(event.previous_peer, Some(peer1));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_has_timestamp() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mut events_rx = subscribe_events(&tx).await;

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert!(!event.timestamp.is_empty());
    // Should be a valid integer (Unix seconds)
    let ts: u64 = event
        .timestamp
        .parse()
        .expect("timestamp should be numeric");
    assert!(ts > 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_added_has_no_previous_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mut events_rx = subscribe_events(&tx).await;

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_type, RouteEventType::Added);
    assert_eq!(event.peer, Some(peer));
    assert!(event.previous_peer.is_none());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_carries_best_path_id() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mut events_rx = subscribe_events(&tx).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
    route.path_id = 42;
    let peer = route.peer;

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_type, RouteEventType::Added);
    assert_eq!(event.peer, Some(peer));
    assert_eq!(event.path_id, 42);

    drop(tx);
    handle.await.unwrap();
}

// --- Prometheus gauge tests ---

#[tokio::test]
#[expect(clippy::cast_possible_truncation)]
async fn rib_prefixes_gauge_tracks_adjribin() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Serialize
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    let families = metrics.registry().gather();
    let rib_gauge = families
        .iter()
        .find(|f| f.get_name() == "bgp_rib_prefixes")
        .expect("bgp_rib_prefixes metric not found");
    let sample = rib_gauge.get_metric()[0].get_gauge().get_value();
    assert_eq!(sample as i64, 1);

    // PeerDown should zero the gauge
    tx.send(RibUpdate::PeerDown { peer }).await.unwrap();
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    let families = metrics.registry().gather();
    let rib_gauge = families
        .iter()
        .find(|f| f.get_name() == "bgp_rib_prefixes")
        .expect("bgp_rib_prefixes metric not found");
    let sample = rib_gauge.get_metric()[0].get_gauge().get_value();
    assert_eq!(sample as i64, 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
#[expect(clippy::cast_possible_truncation)]
async fn loc_rib_gauge_tracks_best() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    let families = metrics.registry().gather();
    let loc_gauge = families
        .iter()
        .find(|f| f.get_name() == "bgp_rib_loc_prefixes")
        .expect("bgp_loc_rib_prefixes metric not found");
    let sample = loc_gauge.get_metric()[0].get_gauge().get_value();
    assert_eq!(sample as i64, 1);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
#[expect(clippy::cast_possible_truncation)]
async fn adj_rib_out_gauge_tracks_advertised() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    let (out_tx, mut _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    let families = metrics.registry().gather();
    let out_gauge = families
        .iter()
        .find(|f| f.get_name() == "bgp_rib_adj_out_prefixes")
        .expect("bgp_adj_rib_out_prefixes metric not found");
    let sample = out_gauge.get_metric()[0].get_gauge().get_value();
    assert_eq!(sample as i64, 1);

    drop(tx);
    handle.await.unwrap();
}

// --- Query count tests ---

#[tokio::test]
async fn query_loc_rib_count() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![
            make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1)),
            make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1)),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();
    let count = reply_rx.await.unwrap();
    assert_eq!(count, 2);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn query_advertised_count() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    let (out_tx, mut _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Serialize
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedCount {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let count = reply_rx.await.unwrap();
    assert_eq!(count, 1);

    // Unknown peer returns 0
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedCount {
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let count = reply_rx.await.unwrap();
    assert_eq!(count, 0);

    drop(tx);
    handle.await.unwrap();
}

// --- Sendable families filtering tests ---

#[tokio::test]
async fn distribute_changes_filters_unsendable_families() {
    use rustbgpd_wire::Ipv6Prefix;

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);

    // Register peer with IPv4-only sendable families
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

    let v4_route = make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1));
    let v6_route = Route {
        prefix: Prefix::V6(v6_prefix),
        next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
        peer: source,
        attributes: vec![],
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
    };

    // Send both IPv4 and IPv6 routes
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![v4_route, v6_route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Should only receive IPv4 route
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(v4_prefix));
    assert!(update.withdraw.is_empty());

    // Adj-RIB-Out should only contain IPv4
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let advertised = reply_rx.await.unwrap();
    assert_eq!(advertised.len(), 1);
    assert_eq!(advertised[0].prefix, Prefix::V4(v4_prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn send_initial_table_filters_unsendable_families() {
    use rustbgpd_wire::Ipv6Prefix;

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

    let v4_route = make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1));
    let v6_route = Route {
        prefix: Prefix::V6(v6_prefix),
        next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
        peer: source,
        attributes: vec![],
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
    };

    // Pre-populate Loc-RIB with both IPv4 and IPv6 routes
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![v4_route, v6_route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Register peer with IPv4-only sendable families — initial dump
    // should filter out the IPv6 route
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    // Initial table dump should only contain IPv4
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(v4_prefix));
    assert!(update.withdraw.is_empty());

    // Adj-RIB-Out should only contain IPv4
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let advertised = reply_rx.await.unwrap();
    assert_eq!(advertised.len(), 1);
    assert_eq!(advertised[0].prefix, Prefix::V4(v4_prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn dual_stack_peer_receives_both_families() {
    use rustbgpd_wire::Ipv6Prefix;

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

    let v4_route = make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1));
    let v6_route = Route {
        prefix: Prefix::V6(v6_prefix),
        next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
        peer: source,
        attributes: vec![],
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
    };

    // Pre-populate Loc-RIB
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![v4_route, v6_route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Register peer with dual-stack sendable families
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: dual_stack_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    // Should receive both routes in initial dump
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 2);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn send_initial_table_includes_flowspec_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let fs_route = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
    let fs_rule = fs_route.rule.clone();

    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![fs_route],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_flowspec_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert!(update.withdraw.is_empty());
    assert_eq!(update.flowspec_announce.len(), 1);
    assert_eq!(update.flowspec_announce[0].rule, fs_rule);
    assert!(update.flowspec_withdraw.is_empty());

    let eor = out_rx.recv().await.unwrap();
    assert_eq!(eor.end_of_rib, ipv4_flowspec_sendable());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_refresh_flowspec_re_advertises_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let fs_route = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
    let fs_rule = fs_route.rule.clone();

    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![fs_route],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_flowspec_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    // Drain the initial dump and its EoR before triggering route refresh.
    let _ = out_rx.recv().await.unwrap();
    let _ = out_rx.recv().await.unwrap();

    tx.send(RibUpdate::RouteRefreshRequest {
        peer: target,
        afi: Afi::Ipv4,
        safi: Safi::FlowSpec,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert!(update.withdraw.is_empty());
    assert_eq!(update.flowspec_announce.len(), 1);
    assert_eq!(update.flowspec_announce[0].rule, fs_rule);
    assert!(update.flowspec_withdraw.is_empty());
    assert_eq!(update.end_of_rib, vec![(Afi::Ipv4, Safi::FlowSpec)]);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_replacement_preserves_refreshed_route() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route.clone()],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::BeginRouteRefresh {
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::EndRouteRefresh {
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].prefix, Prefix::V4(prefix));

    let received = query_received_routes(&tx, peer).await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].prefix, Prefix::V4(prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_eorr_sweeps_unreplaced_route() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let route1 = make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1));
    let route2 = make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1));

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route1.clone(), route2],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::BeginRouteRefresh {
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    tokio::task::yield_now().await;

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route1],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    tokio::task::yield_now().await;

    tx.send(RibUpdate::EndRouteRefresh {
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].prefix, Prefix::V4(prefix1));

    let received = query_received_routes(&tx, peer).await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].prefix, Prefix::V4(prefix1));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_duplicate_borr_rebuilds_snapshot_safely() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route.clone()],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    for _ in 0..2 {
        tx.send(RibUpdate::BeginRouteRefresh {
            peer,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();
    }

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::EndRouteRefresh {
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].prefix, Prefix::V4(prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_eorr_without_active_state_is_ignored() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::EndRouteRefresh {
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].prefix, Prefix::V4(prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_timeout_sweeps_unreplaced_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let route1 = make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1));
    let route2 = make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1));

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route1.clone(), route2],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::BeginRouteRefresh {
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    tokio::task::yield_now().await;

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route1],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    tokio::time::advance(ERR_REFRESH_TIMEOUT + Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].prefix, Prefix::V4(prefix1));

    let received = query_received_routes(&tx, peer).await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].prefix, Prefix::V4(prefix1));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_timeout_is_family_isolated() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let v6_prefix = Ipv6Prefix::new(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0), 64);

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![
            make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1)),
            make_v6_route(v6_prefix, Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1)),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::BeginRouteRefresh {
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    tokio::task::yield_now().await;

    tokio::time::advance(ERR_REFRESH_TIMEOUT + Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].prefix, Prefix::V6(v6_prefix));

    let received = query_received_routes(&tx, peer).await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].prefix, Prefix::V6(v6_prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn dirty_resync_retries_flowspec_updates() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(1);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_flowspec_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    // The initial EoR occupies the single slot, so the next FlowSpec
    // update will fail to enqueue and mark the peer dirty.
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let fs_route = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
    let fs_rule = fs_route.rule.clone();
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![fs_route],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Drain the initial EoR to make room for the timer-driven resync.
    let initial = out_rx.recv().await.unwrap();
    assert_eq!(initial.end_of_rib, ipv4_flowspec_sendable());

    tokio::time::advance(Duration::from_secs(2)).await;

    let resync = out_rx.recv().await.unwrap();
    assert!(resync.announce.is_empty());
    assert!(resync.withdraw.is_empty());
    assert_eq!(resync.flowspec_announce.len(), 1);
    assert_eq!(resync.flowspec_announce[0].rule, fs_rule);
    assert!(resync.flowspec_withdraw.is_empty());

    drop(tx);
    handle.await.unwrap();
}

// --- Graceful Restart tests ---

#[tokio::test]
async fn gr_marks_stale_and_demotes_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Source sends a route
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);

    // Source enters graceful restart
    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Route should still be in Loc-RIB (stale but present)
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert!(best[0].is_stale, "route should be marked stale");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn gr_eor_clears_stale() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Source sends a route
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Source enters graceful restart
    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Verify stale
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert!(best[0].is_stale);

    // Send End-of-RIB
    tx.send(RibUpdate::EndOfRib {
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    // Route should no longer be stale
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert!(
        !best[0].is_stale,
        "route should no longer be stale after EoR"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn gr_timer_sweeps_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Source sends a route
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Source enters graceful restart with short timer
    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source,
        restart_time: 5,
        stale_routes_time: 10,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Route is stale but still in Loc-RIB
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert!(best[0].is_stale);

    // Advance past the GR timer (min(5, 10) = 5 seconds)
    tokio::time::advance(Duration::from_secs(6)).await;
    // Yield to let the manager process the expired GR timer
    tokio::task::yield_now().await;

    // Route should have been swept
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert!(best.is_empty(), "stale routes should be swept after timer");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn gr_peer_up_defers_stale_to_eor() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Source sends a route
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Source enters graceful restart
    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Verify route is stale
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert!(best[0].is_stale);

    // Source re-establishes — route should STILL be stale
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert!(best[0].is_stale, "route should still be stale after PeerUp");

    // End-of-RIB clears stale and completes GR
    tx.send(RibUpdate::EndOfRib {
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert!(
        !best[0].is_stale,
        "route should be non-stale after End-of-RIB"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn gr_peer_up_timer_expires_sweeps_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Source sends a route
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Source enters GR with short restart_time
    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source,
        restart_time: 5,
        stale_routes_time: 10,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Advance past restart_time but before stale_routes_time
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    // Source re-establishes — timer resets to stale_routes_time (10s)
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Route still stale (no EoR yet)
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert!(best[0].is_stale);

    // Advance past stale_routes_time — timer should sweep
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert!(best.is_empty(), "stale routes should be swept after timer");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn gr_peer_down_aborts_gr() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Source sends a route
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Source enters graceful restart
    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Source goes fully down during GR — aborts GR, clears all routes
    tx.send(RibUpdate::PeerDown { peer: source }).await.unwrap();

    // Routes should be gone
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert!(best.is_empty(), "routes cleared after PeerDown aborts GR");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn gr_withdraws_non_gr_family_routes() {
    use rustbgpd_wire::Ipv6Prefix;

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source: IpAddr = "10.0.0.1".parse().unwrap();
    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

    // Source sends both IPv4 and IPv6 routes
    let v6_route = Route {
        prefix: Prefix::V6(v6_prefix),
        next_hop: "2001:db8::1".parse().unwrap(),
        peer: source,
        attributes: vec![],
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
    };
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1)), v6_route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Verify both routes present
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 2);

    // GR with only IPv4 in GR capability — IPv6 should be withdrawn
    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // IPv4 route should be stale, IPv6 route should be gone
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1, "only IPv4 route should remain");
    assert!(
        matches!(best[0].prefix, Prefix::V4(_)),
        "remaining route should be IPv4"
    );
    assert!(best[0].is_stale, "IPv4 route should be stale");

    drop(tx);
    handle.await.unwrap();
}

// --- LLGR (RFC 9494) tests ---

#[tokio::test]
async fn llgr_gr_timer_promotes_to_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Source sends a route
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Source enters GR with LLGR enabled
    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source,
        restart_time: 5,
        stale_routes_time: 10,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 7200,
    })
    .await
    .unwrap();

    // Route should be GR-stale
    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert!(best[0].is_stale);
    assert!(!best[0].is_llgr_stale);

    // Advance past GR timer — should promote to LLGR-stale
    tokio::time::advance(Duration::from_secs(6)).await;
    tokio::task::yield_now().await;

    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1, "route should still be present during LLGR");
    assert!(!best[0].is_stale, "GR-stale flag should be cleared");
    assert!(best[0].is_llgr_stale, "route should be LLGR-stale");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn llgr_timer_sweeps_llgr_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // GR with LLGR, short timers for testing
    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: false,
            stale_time: 10,
        }],
        llgr_stale_time: 10,
    })
    .await
    .unwrap();

    // Ensure manager processes PeerGracefulRestart before advancing time
    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert!(best[0].is_stale);

    // Advance past GR timer → promotes to LLGR
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert!(best[0].is_llgr_stale);

    // Advance past LLGR timer → sweeps routes
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;

    let best = query_best_routes(&tx).await;
    assert!(best.is_empty(), "LLGR-stale routes should be swept");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn llgr_eor_clears_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 3600,
    })
    .await
    .unwrap();

    // Ensure manager processes PeerGracefulRestart
    let best = query_best_routes(&tx).await;
    assert!(best[0].is_stale);

    // Advance past GR timer → LLGR phase
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    let best = query_best_routes(&tx).await;
    assert!(best[0].is_llgr_stale);

    // Peer re-establishes during LLGR
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // EoR should clear LLGR-stale
    tx.send(RibUpdate::EndOfRib {
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    let best = query_best_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert!(
        !best[0].is_llgr_stale,
        "LLGR-stale should be cleared by EoR"
    );
    assert!(!best[0].is_stale, "GR-stale should also be cleared");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn llgr_peer_down_aborts_llgr() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 3600,
    })
    .await
    .unwrap();

    // Ensure manager processes PeerGracefulRestart
    let best = query_best_routes(&tx).await;
    assert!(best[0].is_stale);

    // Advance past GR timer → LLGR phase
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    let best = query_best_routes(&tx).await;
    assert!(best[0].is_llgr_stale);

    // PeerDown during LLGR — should clear everything
    tx.send(RibUpdate::PeerDown { peer: source }).await.unwrap();

    let best = query_best_routes(&tx).await;
    assert!(
        best.is_empty(),
        "routes should be cleared on PeerDown during LLGR"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn llgr_without_peer_capability_falls_through_to_sweep() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // GR without LLGR capability — timer expiry should purge
    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 3600, // local config, but peer doesn't support
    })
    .await
    .unwrap();

    // Ensure manager processes PeerGracefulRestart
    let best = query_best_routes(&tx).await;
    assert!(best[0].is_stale);

    // Advance past GR timer — should purge (no LLGR promotion)
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    let best = query_best_routes(&tx).await;
    assert!(
        best.is_empty(),
        "routes should be purged when peer lacks LLGR"
    );

    drop(tx);
    handle.await.unwrap();
}

// --- Route Reflector tests ---

#[tokio::test]
async fn rr_client_route_reflected_to_all_ibgp() {
    // When RR receives a route from a client, it should reflect to all
    // iBGP peers (both clients and non-clients), except the source.
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 1));
    let manager = RibManager::new(rx, None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let client_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let nonclient_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

    // Register source as iBGP client
    let (out_tx_src, _) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx_src,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    // Register client target
    let (client_tx, mut client_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        peer: client_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: client_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut client_rx).await;

    // Register non-client target
    let (nonclient_tx, mut nonclient_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        peer: nonclient_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: nonclient_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut nonclient_rx).await;

    // Source client sends a route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 4))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Both targets should receive the reflected route
    let client_update = client_rx.recv().await.unwrap();
    assert!(
        !client_update.announce.is_empty(),
        "client should receive reflected route"
    );

    let nonclient_update = nonclient_rx.recv().await.unwrap();
    assert!(
        !nonclient_update.announce.is_empty(),
        "non-client should receive route reflected from client"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rr_nonclient_route_reflected_to_clients_only() {
    // Route from non-client → reflect to clients only (not non-clients).
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 1));
    let manager = RibManager::new(rx, None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)); // non-client
    let client_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let nonclient_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));

    // Register source as non-client
    let (out_tx_src, _) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx_src,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    // Register client target
    let (client_tx, mut client_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        peer: client_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: client_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut client_rx).await;

    // Register non-client target
    let (nonclient_tx, mut nonclient_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        peer: nonclient_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: nonclient_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut nonclient_rx).await;

    // Source sends a route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 2))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Client should get the route
    let update_c = client_rx.recv().await.unwrap();
    assert!(
        !update_c.announce.is_empty(),
        "client should receive non-client route"
    );

    // Non-client should NOT get the route (suppressed by RR)
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        nonclient_rx.try_recv().is_err(),
        "non-client should not receive non-client route"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn non_rr_ibgp_split_horizon_unchanged() {
    // Without cluster_id (no RR), standard split-horizon applies
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

    // Register target first (Loc-RIB empty, clean EoR)
    let (out_tx, mut out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Source sends iBGP route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 2))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // iBGP route should be suppressed (standard split-horizon)
    assert!(
        out_rx.try_recv().is_err(),
        "iBGP route should be suppressed without RR"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rr_ebgp_route_to_all_ibgp() {
    // eBGP-learned routes should go to all iBGP peers regardless of RR role
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 1));
    let manager = RibManager::new(rx, None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)); // iBGP non-client

    // Register target first (Loc-RIB empty, clean EoR)
    let (out_tx, mut out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // eBGP source sends a route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 5))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(
        !update.announce.is_empty(),
        "eBGP route should reach iBGP non-client"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rr_local_route_to_all_ibgp() {
    // Local routes should pass to all iBGP peers even with RR
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 1));
    let manager = RibManager::new(rx, None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

    // Register target first (Loc-RIB empty, clean EoR)
    let (out_tx, mut out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Inject local route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        peer: LOCAL_PEER,
        attributes: vec![PathAttribute::Origin(Origin::Igp)],
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
    };
    let (reply_tx, _) = oneshot::channel();
    tx.send(RibUpdate::InjectRoute {
        route,
        reply: reply_tx,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(
        !update.announce.is_empty(),
        "local route should reach iBGP non-client via RR"
    );

    drop(tx);
    handle.await.unwrap();
}

// --- RPKI integration tests ---

fn make_route_with_as_path(prefix: Ipv4Prefix, peer: Ipv4Addr, asns: Vec<u32>) -> Route {
    Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(peer),
        peer: IpAddr::V4(peer),
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(asns)],
            }),
            PathAttribute::LocalPref(100),
        ],
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
    }
}

#[test]
fn validate_route_rpki_valid() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let table = VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]);
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65001],
    );
    assert_eq!(
        super::validate_route_rpki(&route, &table),
        RpkiValidation::Valid,
    );
}

#[test]
fn validate_route_rpki_invalid() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let table = VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]);
    // Origin AS 65002 doesn't match VRP
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65002],
    );
    assert_eq!(
        super::validate_route_rpki(&route, &table),
        RpkiValidation::Invalid,
    );
}

#[test]
fn validate_route_rpki_not_found() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let table = VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]);
    // Prefix 192.168.1.0/24 not covered by any VRP
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65001],
    );
    assert_eq!(
        super::validate_route_rpki(&route, &table),
        RpkiValidation::NotFound,
    );
}

#[test]
fn validate_route_rpki_no_as_path() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let table = VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]);
    // Route with no AS_PATH
    let route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
    );
    assert_eq!(
        super::validate_route_rpki(&route, &table),
        RpkiValidation::NotFound,
    );
}

#[test]
fn validate_route_rpki_empty_as_path() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let table = VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]);
    // Route with empty AS_PATH (no segments)
    let route = Route {
        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
        next_hop: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        peer: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
            PathAttribute::LocalPref(100),
        ],
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
    };
    assert_eq!(
        super::validate_route_rpki(&route, &table),
        RpkiValidation::NotFound,
    );
}

#[tokio::test]
async fn routes_validated_on_insert_with_vrp_table() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Send RPKI cache update first
    let table = Arc::new(VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]));
    tx.send(RibUpdate::RpkiCacheUpdate { table }).await.unwrap();

    // Now send a route with matching origin
    let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65001],
    );
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Query received routes — should have Valid validation state
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: Some(peer),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let routes = reply_rx.await.unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].validation_state, RpkiValidation::Valid);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rpki_cache_update_revalidates_existing_routes() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65001],
    );

    // Insert route (no VRP table yet → NotFound)
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Verify it's NotFound
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: Some(peer),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let routes = reply_rx.await.unwrap();
    assert_eq!(routes[0].validation_state, RpkiValidation::NotFound);

    // Now send VRP table that covers the route
    let table = Arc::new(VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]));
    tx.send(RibUpdate::RpkiCacheUpdate { table }).await.unwrap();

    // Query again — should be Valid now
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: Some(peer),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let routes = reply_rx.await.unwrap();
    assert_eq!(routes[0].validation_state, RpkiValidation::Valid);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rpki_cache_update_changes_best_path() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);

    // Both routes same LP, same AS_PATH length. peer1 has lower peer address → wins initially.
    let route1 = make_route_with_as_path(prefix, Ipv4Addr::new(1, 0, 0, 1), vec![65001]);
    let route2 = make_route_with_as_path(prefix, Ipv4Addr::new(1, 0, 0, 2), vec![65002]);

    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![route1],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![route2],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Before RPKI: peer1 should be best (lower address)
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer1);

    // Now send VRP that only validates peer2's origin
    let table = Arc::new(VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65002,
    }]));
    tx.send(RibUpdate::RpkiCacheUpdate { table }).await.unwrap();

    // After RPKI: peer2 should be best (Valid > NotFound)
    // But peer1's route has origin 65001, not covered → still NotFound.
    // peer2's route has origin 65002, covered with matching ASN → Valid.
    // Wait a moment for processing...
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    // peer2 wins: Valid beats NotFound
    assert_eq!(best[0].peer, peer2);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rpki_cache_update_invalid_demotes_best_path() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);

    // peer1 has lower address → wins initially
    let route1 = make_route_with_as_path(prefix, Ipv4Addr::new(1, 0, 0, 1), vec![65001]);
    let route2 = make_route_with_as_path(prefix, Ipv4Addr::new(1, 0, 0, 2), vec![65002]);

    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![route1],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![route2],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // VRP covers the prefix but only for AS 65002 → peer1 (65001) becomes Invalid
    let table = Arc::new(VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65002,
    }]));
    tx.send(RibUpdate::RpkiCacheUpdate { table }).await.unwrap();

    // peer1 is now Invalid (VRP covers prefix but wrong origin), peer2 is Valid
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer2);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rpki_no_table_all_not_found() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65001],
    );
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: Some(peer),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let routes = reply_rx.await.unwrap();
    assert_eq!(routes[0].validation_state, RpkiValidation::NotFound);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rpki_cache_update_no_change_no_redistribution() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let (out_tx, mut out_rx) = mpsc::channel(16);

    tx.send(RibUpdate::PeerUp {
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Insert route with origin 65001
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65001],
    );
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Consume the outbound update from route insertion (split-horizon blocks it
    // since peer == route.peer, so nothing should arrive)
    // Send an unrelated VRP table that doesn't cover our prefix
    let table = Arc::new(VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
        prefix_len: 16,
        max_len: 24,
        origin_asn: 65099,
    }]));
    tx.send(RibUpdate::RpkiCacheUpdate { table }).await.unwrap();

    // Verify route stays NotFound — no VRP covers 10.0.0.0/24
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: Some(peer),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let routes = reply_rx.await.unwrap();
    assert_eq!(routes[0].validation_state, RpkiValidation::NotFound);

    drop(tx);
    handle.await.unwrap();
}

// ---- Add-Path multi-path send tests ----

/// Helper: build a route with specific peer, AS path, and `LOCAL_PREF` for
/// multi-path tests. Routes from different peers with different AS paths
/// are distinguishable by best-path ordering.
fn make_multipath_route(
    prefix: Ipv4Prefix,
    peer: Ipv4Addr,
    asns: Vec<u32>,
    local_pref: u32,
) -> Route {
    Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(peer),
        peer: IpAddr::V4(peer),
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(asns)],
            }),
            PathAttribute::LocalPref(local_pref),
        ],
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
    }
}

/// Helper: build an IPv6 route with specific peer, AS path, and
/// `LOCAL_PREF` for dual-stack Add-Path tests.
fn make_multipath_route_v6(
    prefix: Ipv6Prefix,
    peer: Ipv4Addr,
    next_hop: Ipv6Addr,
    asns: Vec<u32>,
    local_pref: u32,
) -> Route {
    Route {
        prefix: Prefix::V6(prefix),
        next_hop: IpAddr::V6(next_hop),
        peer: IpAddr::V4(peer),
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(asns)],
            }),
            PathAttribute::LocalPref(local_pref),
        ],
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
    }
}

#[tokio::test]
async fn multipath_send_advertises_multiple_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Inject two routes for the same prefix from different peers
    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 1),
            vec![65001],
            200,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![65002],
            100,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Register multi-path target (send_max=5)
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 5,
    })
    .await
    .unwrap();

    // Initial dump should contain both routes
    let update = out_rx.recv().await.unwrap();
    assert_eq!(
        update.announce.len(),
        2,
        "multi-path peer should receive 2 routes"
    );
    // path_ids should be 1-indexed rank
    let mut path_ids: Vec<u32> = update.announce.iter().map(|r| r.path_id).collect();
    path_ids.sort_unstable();
    assert_eq!(path_ids, vec![1, 2]);
    // Higher LOCAL_PREF route should be path_id 1 (best)
    let best = update.announce.iter().find(|r| r.path_id == 1).unwrap();
    assert_eq!(best.next_hop, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_send_respects_send_max() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let peer3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Inject 3 routes
    for (peer, peer_addr, asn, lp) in [
        (peer1, Ipv4Addr::new(10, 0, 0, 1), 65001, 200),
        (peer2, Ipv4Addr::new(10, 0, 0, 2), 65002, 150),
        (peer3, Ipv4Addr::new(10, 0, 0, 3), 65003, 100),
    ] {
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_multipath_route(prefix, peer_addr, vec![asn], lp)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

    // Register target with send_max=2
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 2,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert_eq!(
        update.announce.len(),
        2,
        "send_max=2 should limit to 2 routes"
    );
    // Should be the top 2 by LOCAL_PREF (200 and 150)
    let next_hops: Vec<IpAddr> = update.announce.iter().map(|r| r.next_hop).collect();
    assert!(next_hops.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(next_hops.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_send_split_horizon() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Inject route from peer1 and target (target's own route)
    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 1),
            vec![65001],
            200,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: target,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![65002],
            100,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Register multi-path target
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 5,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert_eq!(
        update.announce.len(),
        1,
        "split-horizon should exclude target's own route"
    );
    assert_eq!(
        update.announce[0].next_hop,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_withdrawal_on_candidate_removal() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Register multi-path target first
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 5,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Inject 2 routes
    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 1),
            vec![65001],
            200,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);

    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![65002],
            100,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    // Should now have an announcement for the second path
    assert!(!update.announce.is_empty());

    // Now withdraw peer2's route
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    // Should have a withdrawal for the removed path
    assert!(
        !update.withdraw.is_empty(),
        "removing a candidate should produce a withdrawal"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn single_best_peer_unaffected_by_multipath_config() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Inject 2 routes
    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 1),
            vec![65001],
            200,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![65002],
            100,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Register single-best target (send_max=0)
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert_eq!(
        update.announce.len(),
        1,
        "single-best peer should get only 1 route"
    );
    assert_eq!(
        update.announce[0].path_id, 0,
        "single-best peer should get path_id=0"
    );
    assert_eq!(
        update.announce[0].next_hop,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        "single-best peer should get the best route"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_peer_down_cleans_up_state() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // Register multi-path target
    let (out_tx, _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 5,
    })
    .await
    .unwrap();

    // Peer goes down
    tx.send(RibUpdate::PeerDown { peer: target }).await.unwrap();

    // Re-register as single-best (send_max=0) — should work fine,
    // state was properly cleaned up
    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![65001],
            100,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reconnect_tx, mut reconnect_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: reconnect_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    let update = reconnect_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].path_id, 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_send_incremental_route_addition() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Register multi-path target
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 5,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Add first route
    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 1),
            vec![65001],
            200,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1, "first route announced");
    assert_eq!(update.announce[0].path_id, 1);

    // Add second route — should get an incremental update
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![65002],
            100,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    // The new route should be announced (path_id 2)
    let new_announcements: Vec<_> = update
        .announce
        .iter()
        .filter(|r| r.next_hop == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        .collect();
    assert!(
        !new_announcements.is_empty(),
        "second route should be announced incrementally"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_send_mixed_peers_single_and_multi() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let source2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let multi_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let single_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Inject 2 routes
    tx.send(RibUpdate::RoutesReceived {
        peer: source1,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 1),
            vec![65001],
            200,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: source2,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![65002],
            100,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Register multi-path target
    let (multi_tx, mut multi_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: multi_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: multi_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 5,
    })
    .await
    .unwrap();

    // Register single-best target
    let (single_tx, mut single_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: single_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: single_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();

    // Multi-path target gets 2 routes
    let multi_update = multi_rx.recv().await.unwrap();
    assert_eq!(multi_update.announce.len(), 2);

    // Single-best target gets 1 route
    let single_update = single_rx.recv().await.unwrap();
    assert_eq!(single_update.announce.len(), 1);
    assert_eq!(single_update.announce[0].path_id, 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_send_ipv6_advertises_multiple_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48);

    let mk = |peer_addr: Ipv4Addr, asn: u32, local_pref: u32| Route {
        prefix: Prefix::V6(prefix),
        next_hop: "2001:db8::1".parse().unwrap(),
        peer: IpAddr::V4(peer_addr),
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![asn])],
            }),
            PathAttribute::LocalPref(local_pref),
        ],
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
    };

    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![mk(Ipv4Addr::new(10, 0, 0, 1), 65001, 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![mk(Ipv4Addr::new(10, 0, 0, 2), 65002, 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv6, Safi::Unicast)],
        is_ebgp: false,
        route_reflector_client: false,
        add_path_send_families: vec![(Afi::Ipv6, Safi::Unicast)],
        add_path_send_max: 5,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert_eq!(
        update.announce.len(),
        2,
        "IPv6 multi-path peer should receive both routes"
    );
    let mut path_ids: Vec<u32> = update.announce.iter().map(|r| r.path_id).collect();
    path_ids.sort_unstable();
    assert_eq!(path_ids, vec![1, 2]);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_send_partial_negotiation_ipv4_only() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix4 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let prefix6 = Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48);

    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![
            make_multipath_route(prefix4, Ipv4Addr::new(10, 0, 0, 1), vec![65001], 200),
            make_multipath_route_v6(
                prefix6,
                Ipv4Addr::new(10, 0, 0, 1),
                "2001:db8::1".parse().unwrap(),
                vec![65001],
                200,
            ),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![
            make_multipath_route(prefix4, Ipv4Addr::new(10, 0, 0, 2), vec![65002], 100),
            make_multipath_route_v6(
                prefix6,
                Ipv4Addr::new(10, 0, 0, 2),
                "2001:db8::2".parse().unwrap(),
                vec![65002],
                100,
            ),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: dual_stack_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        add_path_send_families: vec![(Afi::Ipv4, Safi::Unicast)],
        add_path_send_max: 5,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    let v4_routes: Vec<_> = update
        .announce
        .iter()
        .filter(|r| r.prefix == Prefix::V4(prefix4))
        .collect();
    let v6_routes: Vec<_> = update
        .announce
        .iter()
        .filter(|r| r.prefix == Prefix::V6(prefix6))
        .collect();
    assert_eq!(v4_routes.len(), 2, "IPv4 should use multi-path send");
    assert_eq!(v6_routes.len(), 1, "IPv6 should fall back to single-best");
    let mut v4_path_ids: Vec<u32> = v4_routes.iter().map(|r| r.path_id).collect();
    v4_path_ids.sort_unstable();
    assert_eq!(v4_path_ids, vec![1, 2]);
    assert_eq!(v6_routes[0].path_id, 0);
    drain_eor(&mut out_rx).await;

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_send_partial_negotiation_ipv6_only() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix4 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let prefix6 = Ipv6Prefix::new("2001:db8:2::".parse().unwrap(), 48);

    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![
            make_multipath_route(prefix4, Ipv4Addr::new(10, 0, 0, 1), vec![65001], 200),
            make_multipath_route_v6(
                prefix6,
                Ipv4Addr::new(10, 0, 0, 1),
                "2001:db8::1".parse().unwrap(),
                vec![65001],
                200,
            ),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![
            make_multipath_route(prefix4, Ipv4Addr::new(10, 0, 0, 2), vec![65002], 100),
            make_multipath_route_v6(
                prefix6,
                Ipv4Addr::new(10, 0, 0, 2),
                "2001:db8::2".parse().unwrap(),
                vec![65002],
                100,
            ),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: dual_stack_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        add_path_send_families: vec![(Afi::Ipv6, Safi::Unicast)],
        add_path_send_max: 5,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    let v4_routes: Vec<_> = update
        .announce
        .iter()
        .filter(|r| r.prefix == Prefix::V4(prefix4))
        .collect();
    let v6_routes: Vec<_> = update
        .announce
        .iter()
        .filter(|r| r.prefix == Prefix::V6(prefix6))
        .collect();
    assert_eq!(v4_routes.len(), 1, "IPv4 should fall back to single-best");
    assert_eq!(v6_routes.len(), 2, "IPv6 should use multi-path send");
    assert_eq!(v4_routes[0].path_id, 0);
    let mut v6_path_ids: Vec<u32> = v6_routes.iter().map(|r| r.path_id).collect();
    v6_path_ids.sort_unstable();
    assert_eq!(v6_path_ids, vec![1, 2]);
    drain_eor(&mut out_rx).await;

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_refresh_partial_negotiation_respects_family_mode() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix4 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 10, 0), 24);
    let prefix6 = Ipv6Prefix::new("2001:db8:10::".parse().unwrap(), 48);

    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![
            make_multipath_route(prefix4, Ipv4Addr::new(10, 0, 0, 1), vec![65001], 200),
            make_multipath_route_v6(
                prefix6,
                Ipv4Addr::new(10, 0, 0, 1),
                "2001:db8::1".parse().unwrap(),
                vec![65001],
                200,
            ),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![
            make_multipath_route(prefix4, Ipv4Addr::new(10, 0, 0, 2), vec![65002], 100),
            make_multipath_route_v6(
                prefix6,
                Ipv4Addr::new(10, 0, 0, 2),
                "2001:db8::2".parse().unwrap(),
                vec![65002],
                100,
            ),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: dual_stack_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        add_path_send_families: vec![(Afi::Ipv4, Safi::Unicast)],
        add_path_send_max: 5,
    })
    .await
    .unwrap();
    let _ = out_rx.recv().await.unwrap();
    drain_eor(&mut out_rx).await;

    tx.send(RibUpdate::RouteRefreshRequest {
        peer: target,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    let v4_routes: Vec<_> = update
        .announce
        .iter()
        .filter(|r| r.prefix == Prefix::V4(prefix4))
        .collect();
    assert_eq!(v4_routes.len(), 2, "IPv4 refresh should be multi-path");
    let mut v4_path_ids: Vec<u32> = v4_routes.iter().map(|r| r.path_id).collect();
    v4_path_ids.sort_unstable();
    assert_eq!(v4_path_ids, vec![1, 2]);
    assert_eq!(update.end_of_rib, vec![(Afi::Ipv4, Safi::Unicast)]);

    tx.send(RibUpdate::RouteRefreshRequest {
        peer: target,
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    let v6_routes: Vec<_> = update
        .announce
        .iter()
        .filter(|r| r.prefix == Prefix::V6(prefix6))
        .collect();
    assert_eq!(v6_routes.len(), 1, "IPv6 refresh should be single-best");
    assert_eq!(v6_routes[0].path_id, 0);
    assert_eq!(update.end_of_rib, vec![(Afi::Ipv6, Safi::Unicast)]);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_send_max_one_uses_path_id_one() {
    // send_max=1 should behave like single-best but with path_id=1 (not 0).
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 1),
            vec![65001],
            200,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![65002],
            100,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 1,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1, "send_max=1 sends only one route");
    assert_eq!(
        update.announce[0].path_id, 1,
        "multi-path peer uses path_id=1 not 0"
    );
    assert_eq!(
        update.announce[0].next_hop,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        "should be the best route"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multipath_all_candidates_denied_by_export_policy() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

    // Deny all prefixes in 192.168.0.0/16
    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 16);
    let export_policy = PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: Some(Prefix::V4(denied_prefix)),
            ge: None,
            le: Some(32),
            action: PolicyAction::Deny,
            match_community: vec![],
            match_as_path: None,
            match_rpki_validation: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }]);

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, Some(export_policy), None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // Register multi-path target
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 5,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Inject 2 routes for the denied prefix
    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 1),
            vec![65001],
            200,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![make_multipath_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![65002],
            100,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Force serialization — query to ensure all RoutesReceived processed
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    // No outbound updates should have been sent (all denied)
    assert!(
        out_rx.try_recv().is_err(),
        "all candidates denied by export policy — nothing sent"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn mrt_snapshot_uses_adj_rib_in_routes_without_loc_rib_duplication() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    let snapshot = query_mrt_snapshot(&tx).await;
    assert_eq!(
        snapshot.routes.len(),
        1,
        "MRT snapshot should include only Adj-RIB-In routes (no Loc-RIB duplication)"
    );
    assert_eq!(snapshot.routes[0].prefix, Prefix::V4(prefix));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn mrt_peer_metadata_retained_during_gr() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer,
        peer_asn: 65001,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        peer,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let snapshot = query_mrt_snapshot(&tx).await;
    let meta = snapshot
        .peers
        .iter()
        .find(|entry| entry.peer_addr == peer)
        .expect("peer metadata should remain available during GR");
    assert_eq!(meta.peer_asn, 65001);
    assert_eq!(meta.peer_bgp_id, Ipv4Addr::new(10, 0, 0, 1));

    drop(tx);
    handle.await.unwrap();
}
