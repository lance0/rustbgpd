use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustbgpd_wire::{
    AddressPrefixOrf, Afi, AsPath, AsPathSegment, EthernetSegmentIdentifier, EthernetTagId,
    EvpnImet, EvpnMacIp, EvpnRoute, ExtendedCommunity, Ipv4Prefix, Ipv6Prefix, MacAddress,
    MplsLabel, OrfAction, OrfMatch, Origin, PathAttribute, Prefix, RouteDistinguisher,
    RpkiValidation, Safi, WhenToRefresh,
};
use tokio::sync::oneshot;

use super::*;
use crate::event::RouteEventType;
use crate::route::{EvpnRibRoute, FlowSpecRoute, NextHopScope, Route};
use crate::test_support::{make_flowspec_route, make_route, make_route_with_lp, make_v6_route};

fn evpn_sendable() -> Vec<(Afi, Safi)> {
    vec![(Afi::L2Vpn, Safi::Evpn)]
}

fn make_evpn_imet(peer: Ipv4Addr, ethernet_tag: u32) -> EvpnRibRoute {
    let route = EvpnRoute::Imet(EvpnImet {
        rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 100]),
        ethernet_tag: EthernetTagId(ethernet_tag),
        originator_ip: IpAddr::V4(peer),
    });
    EvpnRibRoute {
        route,
        next_hop: IpAddr::V4(peer),
        link_local_next_hop: None,
        peer: IpAddr::V4(peer),
        attributes: Arc::new(vec![]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: peer,
        is_stale: false,
        is_llgr_stale: false,
    }
}

/// Create a dummy (unused) query channel receiver for tests.
fn dummy_query_rx() -> mpsc::Receiver<RibUpdate> {
    mpsc::channel(1).1
}

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

async fn query_fib_install_candidates(
    tx: &mpsc::Sender<RibUpdate>,
    max_paths: u32,
) -> Vec<crate::route::FibInstallCandidate> {
    query_fib_install_candidates_opts(tx, max_paths, false, false).await
}

async fn query_fib_install_candidates_relax(
    tx: &mpsc::Sender<RibUpdate>,
    max_paths: u32,
    relax: bool,
) -> Vec<crate::route::FibInstallCandidate> {
    query_fib_install_candidates_opts(tx, max_paths, relax, false).await
}

async fn query_fib_install_candidates_weighted(
    tx: &mpsc::Sender<RibUpdate>,
    max_paths: u32,
    weighted: bool,
) -> Vec<crate::route::FibInstallCandidate> {
    query_fib_install_candidates_opts(tx, max_paths, false, weighted).await
}

async fn query_fib_install_candidates_opts(
    tx: &mpsc::Sender<RibUpdate>,
    max_paths: u32,
    relax: bool,
    weighted: bool,
) -> Vec<crate::route::FibInstallCandidate> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryFibInstallCandidates {
        max_paths,
        relax,
        weighted,
        reply: reply_tx,
    })
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

async fn query_evpn_routes(tx: &mpsc::Sender<RibUpdate>) -> Vec<EvpnRibRoute> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryEvpnRoutes { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap()
}

async fn query_explain_advertised_route(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    prefix: Prefix,
) -> crate::update::ExplainAdvertisedRoute {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::ExplainAdvertisedRoute {
        peer,
        prefix,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap().unwrap()
}

async fn query_mrt_snapshot(tx: &mpsc::Sender<RibUpdate>) -> crate::update::MrtSnapshotData {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryMrtSnapshot { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap()
}

async fn query_flowspec_routes(tx: &mpsc::Sender<RibUpdate>) -> Vec<FlowSpecRoute> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryFlowSpecRoutes { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap()
}

async fn query_explain_best_path(
    tx: &mpsc::Sender<RibUpdate>,
    prefix: Prefix,
) -> crate::update::ExplainBestPath {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::ExplainBestPath {
        prefix,
        peer: None,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx
        .await
        .unwrap()
        .expect("global-view explain never returns None")
}

/// Peer-scoped explain helper for the Add-Path explain tests.
/// `Some` = scoped to that peer; `None` = unknown-peer error path.
async fn query_explain_best_path_for_peer(
    tx: &mpsc::Sender<RibUpdate>,
    prefix: Prefix,
    peer: IpAddr,
) -> Option<crate::update::ExplainBestPath> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::ExplainBestPath {
        prefix,
        peer: Some(peer),
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap()
}

async fn query_neighbor_policy_stats(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
) -> crate::update::NeighborPolicyStats {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryNeighborPolicyStats {
        peer,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap()
}

fn policy_metric_value(
    metrics: &BgpMetrics,
    peer: &str,
    policy: &str,
    direction: &str,
    action: &str,
) -> f64 {
    metrics
        .registry()
        .gather()
        .iter()
        .find(|family| family.name() == "bgp_policy_routes_total")
        .and_then(|family| {
            family.metric.iter().find(|metric| {
                let mut labels = std::collections::HashMap::new();
                for label in metric.get_label() {
                    labels.insert(label.name(), label.value());
                }
                labels.get("peer") == Some(&peer)
                    && labels.get("policy") == Some(&policy)
                    && labels.get("direction") == Some(&direction)
                    && labels.get("action") == Some(&action)
            })
        })
        .map_or(0.0, |metric| metric.get_counter().value())
}

fn gauge_metric_value(metrics: &BgpMetrics, name: &str, labels: &[(&str, &str)]) -> f64 {
    metrics
        .registry()
        .gather()
        .iter()
        .find(|family| family.name() == name)
        .and_then(|family| {
            family.metric.iter().find(|metric| {
                labels.iter().all(|(expected_name, expected_value)| {
                    metric.get_label().iter().any(|label| {
                        label.name() == *expected_name && label.value() == *expected_value
                    })
                })
            })
        })
        .map_or(0.0, |metric| metric.get_gauge().value())
}

fn assert_refresh_metrics(
    metrics: &BgpMetrics,
    peer: &str,
    afi_safi: &str,
    active: f64,
    stale: f64,
) {
    let labels = &[("peer", peer), ("afi_safi", afi_safi)];
    let observed_active = gauge_metric_value(metrics, "bgp_route_refresh_in_progress", labels);
    let observed_stale = gauge_metric_value(metrics, "bgp_route_refresh_stale_entries", labels);
    assert!(
        (observed_active - active).abs() < f64::EPSILON,
        "active refresh gauge mismatch: expected {active}, observed {observed_active}"
    );
    assert!(
        (observed_stale - stale).abs() < f64::EPSILON,
        "stale refresh gauge mismatch: expected {stale}, observed {observed_stale}"
    );
}

fn make_indexed_route(index: u32, next_hop: Ipv4Addr) -> Route {
    let octets = index.to_be_bytes();
    make_route(
        Ipv4Prefix::new(Ipv4Addr::new(10, octets[1], octets[2], octets[3]), 32),
        next_hop,
    )
}

#[tokio::test]
async fn routes_received_and_queried() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
async fn closed_query_channel_does_not_block_primary_channel() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();

    let count = tokio::time::timeout(Duration::from_secs(1), reply_rx)
        .await
        .expect("query should not stall when query channel is closed")
        .unwrap();
    assert_eq!(count, 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn large_routes_received_batch_preserves_final_state() {
    let (tx, rx) = mpsc::channel(64);
    let (_query_tx, query_rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, query_rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let next_hop = Ipv4Addr::new(10, 0, 0, 1);
    let routes: Vec<Route> = (0..2500).map(|i| make_indexed_route(i, next_hop)).collect();

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: routes,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();

    let count = tokio::time::timeout(Duration::from_secs(2), reply_rx)
        .await
        .expect("large chunked batch should still converge")
        .unwrap();
    assert_eq!(count, 2500);

    drop(tx);
    handle.await.unwrap();
}

/// PR3: a multi-chunk initial-load flood (>1024 routes in one batch)
/// distributes to each peer as ONE coalesced `OutboundRouteUpdate`, not one
/// per 1024-route chunk. `recompute_best` still runs per chunk (see
/// `query_channel_observes_partial_progress_during_large_batch`), so only
/// outbound distribution is deferred to batch-end. Asserts both the
/// coalescing (single outbound message) and correctness (every route is
/// advertised).
#[tokio::test]
async fn multi_chunk_flood_coalesces_into_one_outbound_batch() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Register an outbound observer peer first and drain its initial EoR.
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
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Flood 2500 routes (3 chunks at the 1024 chunk size) from a source peer.
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let next_hop = Ipv4Addr::new(10, 0, 0, 1);
    let route_count = 2500_u32;
    let routes: Vec<Route> = (0..route_count)
        .map(|i| make_indexed_route(i, next_hop))
        .collect();
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: routes,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Collect outbound updates until every route is advertised, counting how
    // many distinct OutboundRouteUpdate messages it took.
    let mut announced = 0usize;
    let mut messages = 0usize;
    while announced < route_count as usize {
        let update = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("outbound update should arrive")
            .expect("outbound channel open");
        messages += 1;
        announced += update.announce.len();
    }
    assert_eq!(
        announced, route_count as usize,
        "every flooded route must be advertised"
    );
    assert_eq!(
        messages, 1,
        "a multi-chunk flood must coalesce into one outbound batch, got {messages}"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn query_channel_observes_partial_progress_during_large_batch() {
    let (tx, rx) = mpsc::channel(64);
    let (query_tx, query_rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, query_rx, None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let next_hop = Ipv4Addr::new(10, 0, 0, 1);
    let route_count = 20_000_u32;
    let routes: Vec<Route> = (0..route_count)
        .map(|i| make_indexed_route(i, next_hop))
        .collect();

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: routes,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tokio::task::yield_now().await;

    let (reply_tx, reply_rx) = oneshot::channel();
    query_tx
        .send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();

    let count = tokio::time::timeout(Duration::from_secs(2), reply_rx)
        .await
        .expect("priority query should respond during chunked processing")
        .unwrap();
    assert!(count > 0, "query should observe some inserted routes");
    assert!(
        count < route_count as usize,
        "query should be serviced before the full batch completes"
    );

    drop(tx);
    drop(query_tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn peer_down_clears_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix1), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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

#[tokio::test]
async fn query_peer_groups_returns_current_policy_context() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::SetPeerPolicyContext {
        peer,
        peer_group: Some("transit".to_string()),
    })
    .await
    .unwrap();
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryPeerGroups { reply: reply_tx })
        .await
        .unwrap();

    let groups = reply_rx.await.unwrap();
    assert_eq!(groups.get(&peer).map(String::as_str), Some("transit"));

    drop(tx);
    handle.await.unwrap();
}

/// Like [`make_route`] but with iBGP origin (iBGP-learned route).
fn make_ibgp_route(prefix: Ipv4Prefix, next_hop: Ipv4Addr) -> Route {
    Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(next_hop),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(next_hop),
        attributes: Arc::new(vec![]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

#[tokio::test]
async fn ibgp_route_not_sent_to_ibgp_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Inject a local route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: LOCAL_PEER,
        attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Inject a local route first
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: LOCAL_PEER,
        attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: LOCAL_PEER,
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
        ]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: LOCAL_PEER,
        attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
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
async fn export_policy_counter_records_single_best_permit() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.announce.len(), 1);

    assert!(
        (policy_metric_value(&metrics, "10.0.0.2", "inline", "export", "permit") - 1.0).abs()
            < f64::EPSILON
    );
    let stats = query_neighbor_policy_stats(&tx, target).await;
    assert_eq!(stats.export_policy_routes_permitted, 1);
    assert_eq!(stats.export_policy_routes_denied, 0);

    // Peer-down clears per-peer state including the export policy
    // counters. Without this cleanup the HashMap grows unbounded across
    // peer add/delete churn — see handle_peer_down in peer_lifecycle.rs.
    // The counter resets here matches the import-side per-session
    // contract: both directions zero on the next session.
    tx.send(RibUpdate::PeerDown { peer: target }).await.unwrap();
    let stats_after = query_neighbor_policy_stats(&tx, target).await;
    assert_eq!(
        stats_after.export_policy_routes_permitted, 0,
        "PeerDown must clear export_policy_stats; saw {stats_after:?}"
    );
    assert_eq!(stats_after.export_policy_routes_denied, 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn graceful_restart_clears_export_policy_stats() {
    // Mirror of the PeerDown cleanup assertion. A GR-driven session
    // teardown reuses the outbound peer state slot on reconnect, so the
    // export policy aggregates must reset alongside the rest of the
    // per-peer state cleared in handle_peer_graceful_restart. Without
    // this, `rustbgpctl neighbor show` shows import counters at 0
    // (reset on SessionDown in transport/session/fsm.rs) but export
    // counters carrying forward — a directional asymmetry that
    // confuses operators.
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    let _ = out_rx.recv().await.unwrap();

    let stats = query_neighbor_policy_stats(&tx, target).await;
    assert_eq!(stats.export_policy_routes_permitted, 1);

    tx.send(RibUpdate::PeerGracefulRestart {
        peer: target,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let stats_after = query_neighbor_policy_stats(&tx, target).await;
    assert_eq!(
        stats_after.export_policy_routes_permitted, 0,
        "PeerGracefulRestart must clear export_policy_stats; saw {stats_after:?}"
    );
    assert_eq!(stats_after.export_policy_routes_denied, 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn explain_advertised_route_does_not_increment_export_policy_counter() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    let _ = out_rx.recv().await.unwrap();

    let before = policy_metric_value(&metrics, "10.0.0.2", "inline", "export", "permit");
    let explain = query_explain_advertised_route(&tx, target, Prefix::V4(prefix)).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Advertise);
    let after = policy_metric_value(&metrics, "10.0.0.2", "inline", "export", "permit");
    assert!((after - before).abs() < f64::EPSILON);

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
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }]);

    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(
        rx,
        dummy_query_rx(),
        Some(export_policy),
        None,
        metrics.clone(),
    );
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    assert!(
        (policy_metric_value(&metrics, "10.0.0.2", "inline", "export", "deny") - 1.0).abs()
            < f64::EPSILON
    );
    let stats = query_neighbor_policy_stats(&tx, target).await;
    assert_eq!(stats.export_policy_routes_permitted, 0);
    assert_eq!(stats.export_policy_routes_denied, 1);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn query_advertised_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }]));

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
#[expect(clippy::too_many_lines)]
async fn replace_peer_export_policy_resyncs_outbound_state_and_emits_policy_filtered_event() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
    let deny_chain = Some(PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: Some(Prefix::V4(denied_prefix)),
            ge: None,
            le: None,
            action: PolicyAction::Deny,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }]));

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(denied_prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let initial = out_rx.recv().await.unwrap();
    assert_eq!(initial.announce.len(), 1);
    assert!(initial.withdraw.is_empty());

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: target,
        export_policy: deny_chain.clone(),
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert_eq!(reply_rx.await.unwrap(), Ok(()));

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert_eq!(update.withdraw, vec![(Prefix::V4(denied_prefix), 0)]);

    let history = query_route_event_history(
        &tx,
        Some(target),
        Some(Afi::Ipv4),
        Some(Prefix::V4(denied_prefix)),
        10,
    )
    .await;
    let policy_filtered = history
        .iter()
        .filter(|event| event.event_type == RouteEventType::PolicyFiltered)
        .collect::<Vec<_>>();
    assert_eq!(policy_filtered.len(), 1);
    assert_eq!(policy_filtered[0].peer, Some(source));
    assert_eq!(policy_filtered[0].target_peer, Some(target));
    assert_eq!(policy_filtered[0].reason, "policy_denied");

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: target,
        export_policy: deny_chain,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert_eq!(reply_rx.await.unwrap(), Ok(()));
    let history = query_route_event_history(
        &tx,
        Some(target),
        Some(Afi::Ipv4),
        Some(Prefix::V4(denied_prefix)),
        10,
    )
    .await;
    assert_eq!(
        history
            .iter()
            .filter(|event| event.event_type == RouteEventType::PolicyFiltered)
            .count(),
        1,
        "unchanged policy denial should not emit duplicate route events"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn export_policy_match_next_hop_filters_route() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

    let export_policy = Some(PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Deny,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }]));

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    assert!(
        out_rx.try_recv().is_err(),
        "export policy should filter the route by next-hop"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn explain_advertised_route_reports_no_best_route() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(8);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65002,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    let explain = query_explain_advertised_route(&tx, target, prefix).await;
    assert_eq!(
        explain.decision,
        crate::update::ExplainDecision::NoBestRoute
    );
    assert_eq!(explain.reasons[0].code, "no_best_route");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn explain_advertised_route_reports_policy_deny_without_mutation() {
    let (tx, rx) = mpsc::channel(64);
    let deny_policy = rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
        default_action: rustbgpd_policy::PolicyAction::Deny,
        entries: vec![],
    }]);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(8);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65002,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: Some(deny_policy),
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
        Ipv4Addr::new(10, 0, 0, 1),
    );
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    let explain = query_explain_advertised_route(&tx, target, prefix).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Deny);
    assert_eq!(explain.reasons[0].code, "policy_denied");

    let advertised = {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        reply_rx.await.unwrap()
    };
    assert!(advertised.is_empty());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn export_as_path_regex_still_filters_through_distribution() {
    // Pins the lazy-AS_PATH-string gate on the RIB distribution path: an export
    // policy that denies on a `match_as_path` regex must still filter a matching
    // route (the gate has to render the string and run the regex) while permitting
    // a non-matching one. A broken gate that skipped the string when needed would
    // run the regex against "" and wrongly permit the matching route.
    use rustbgpd_policy::{
        AsPathRegex, Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications,
    };
    use rustbgpd_wire::{AsPath, AsPathSegment, PathAttribute};

    let deny_65200 = PolicyStatement {
        prefix: None,
        ge: None,
        le: None,
        action: PolicyAction::Deny,
        match_community: vec![],
        match_as_path: Some(AsPathRegex::new("_65200_").unwrap()),
        match_neighbor_set: None,
        match_route_type: None,
        match_evpn_route_type: None,
        match_rpki_validation: None,
        match_aspa_validation: None,
        match_as_path_length_ge: None,
        match_as_path_length_le: None,
        match_local_pref_ge: None,
        match_local_pref_le: None,
        match_med_ge: None,
        match_med_le: None,
        match_next_hop: None,
        modifications: RouteModifications::default(),
    };
    let export_policy = PolicyChain::new(vec![Policy {
        entries: vec![deny_65200],
        default_action: PolicyAction::Permit,
    }]);

    let with_as_path = |prefix: Ipv4Prefix, asns: Vec<u32>| Route {
        attributes: Arc::new(vec![PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(asns)],
        })]),
        ..make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))
    };
    let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let permitted_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let denied = with_as_path(denied_prefix, vec![65100, 65200]);
    let permitted = with_as_path(permitted_prefix, vec![65100, 65300]);

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(8);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65002,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: Some(export_policy),
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![denied, permitted],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let advertised = {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        reply_rx.await.unwrap()
    };
    let prefixes: Vec<_> = advertised.iter().map(|r| r.prefix).collect();

    assert!(
        prefixes.contains(&Prefix::V4(permitted_prefix)),
        "AS_PATH not matching the deny regex must be advertised; saw {prefixes:?}"
    );
    assert!(
        !prefixes.contains(&Prefix::V4(denied_prefix)),
        "AS_PATH matching the deny regex must be filtered (string rendered + regex \
         applied through the gated export path); saw {prefixes:?}"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn explain_advertised_route_reports_modifications() {
    let (tx, rx) = mpsc::channel(64);
    let export_policy = rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
        default_action: rustbgpd_policy::PolicyAction::Permit,
        entries: vec![rustbgpd_policy::PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: rustbgpd_policy::RouteModifications {
                set_local_pref: Some(200),
                ..rustbgpd_policy::RouteModifications::default()
            },
            action: rustbgpd_policy::PolicyAction::Permit,
        }],
    }]);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(8);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65002,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: Some(export_policy),
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
        Ipv4Addr::new(10, 0, 0, 1),
    );
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    let explain = query_explain_advertised_route(&tx, target, prefix).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Advertise);
    assert_eq!(explain.route_peer, Some(source));
    assert_eq!(
        explain.route_type,
        Some(rustbgpd_policy::RouteType::External)
    );
    assert_eq!(explain.modifications.set_local_pref, Some(200));
    assert_eq!(explain.reasons[0].code, "ebgp_route");
    assert_eq!(explain.reasons[1].code, "policy_permitted");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn explain_advertised_route_reports_ipv6_next_hop_override() {
    let (tx, rx) = mpsc::channel(64);
    let export_policy = rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
        default_action: rustbgpd_policy::PolicyAction::Permit,
        entries: vec![rustbgpd_policy::PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: rustbgpd_policy::RouteModifications {
                set_next_hop: Some(rustbgpd_policy::NextHopAction::Specific(IpAddr::V6(
                    "2001:db8::42".parse().unwrap(),
                ))),
                ..rustbgpd_policy::RouteModifications::default()
            },
            action: rustbgpd_policy::PolicyAction::Permit,
        }],
    }]);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(8);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65002,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: Some(export_policy),
        sendable_families: vec![(Afi::Ipv6, Safi::Unicast)],
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let prefix = Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 64);
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_v6_route(prefix, "2001:db8::1".parse().unwrap())],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let explain = query_explain_advertised_route(&tx, target, Prefix::V6(prefix)).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Advertise);
    assert_eq!(
        explain.next_hop,
        Some(IpAddr::V6("2001:db8::42".parse().unwrap()))
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn peer_down_cleans_up_export_policy() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
            evpn_announce: vec![],
            evpn_withdraw: vec![],
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
        negotiated_orf_recv: Vec::new(),
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

async fn query_route_event_history(
    tx: &mpsc::Sender<RibUpdate>,
    peer: Option<IpAddr>,
    afi: Option<Afi>,
    prefix: Option<Prefix>,
    limit: usize,
) -> Vec<crate::event::RouteEvent> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryRouteEventHistory {
        peer,
        afi,
        prefix,
        limit,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap()
}

#[tokio::test]
async fn route_event_added_on_new_best() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_id, 1);
    assert_eq!(event.event_type, crate::event::RouteEventType::Added);
    assert_eq!(event.prefix, Prefix::V4(prefix));
    assert_eq!(event.peer, Some(peer));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_records_events_without_subscriber() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let history = query_route_event_history(&tx, None, Some(Afi::Ipv4), None, 100).await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].event_id, 1);
    assert_eq!(history[0].event_type, crate::event::RouteEventType::Added);
    assert_eq!(history[0].prefix, Prefix::V4(prefix));
    assert_eq!(history[0].peer, Some(peer));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_empty_query_returns_empty_vec() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let history = query_route_event_history(&tx, None, None, None, 0).await;
    assert!(history.is_empty());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_records_withdrawn_events() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let history = query_route_event_history(&tx, None, Some(Afi::Ipv4), None, 10).await;
    assert_eq!(history.len(), 2);
    assert_eq!(
        history[1].event_type,
        crate::event::RouteEventType::Withdrawn
    );
    assert_eq!(history[1].prefix, Prefix::V4(prefix));
    assert_eq!(history[1].peer, None);
    assert_eq!(history[1].previous_peer, Some(peer));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_filters_previous_peer_and_limit() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![
            make_route_with_lp(prefix1, Ipv4Addr::new(10, 0, 0, 1), 100),
            make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1)),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![make_route_with_lp(prefix1, Ipv4Addr::new(10, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let history = query_route_event_history(&tx, Some(peer1), Some(Afi::Ipv4), None, 2).await;
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].event_id, 2);
    assert_eq!(history[0].event_type, crate::event::RouteEventType::Added);
    assert!(matches!(history[0].prefix, Prefix::V4(_)));
    assert_eq!(history[0].peer, Some(peer1));
    assert_eq!(
        history[1].event_type,
        crate::event::RouteEventType::BestChanged
    );
    assert_eq!(history[1].event_id, 3);
    assert_eq!(history[1].prefix, Prefix::V4(prefix1));
    assert_eq!(history[1].peer, Some(peer2));
    assert_eq!(history[1].previous_peer, Some(peer1));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_filters_exact_ipv4_prefix() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let other = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);

    for prefix in [other, target] {
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

    let history = query_route_event_history(&tx, None, None, Some(Prefix::V4(target)), 10).await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].prefix, Prefix::V4(target));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_filters_exact_ipv6_prefix() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let target = Ipv6Prefix::new("2001:db8:100::".parse().unwrap(), 64);
    let other = Ipv6Prefix::new("2001:db8:200::".parse().unwrap(), 64);

    for prefix in [other, target] {
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_v6_route(prefix, Ipv6Addr::LOCALHOST)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

    let history = query_route_event_history(&tx, None, None, Some(Prefix::V6(target)), 10).await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].prefix, Prefix::V6(target));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_prefix_peer_and_limit_interact() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let other = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![make_route_with_lp(target, Ipv4Addr::new(10, 0, 0, 1), 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![make_route(other, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![make_route_with_lp(target, Ipv4Addr::new(10, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(target), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let history = query_route_event_history(
        &tx,
        Some(peer1),
        Some(Afi::Ipv4),
        Some(Prefix::V4(target)),
        2,
    )
    .await;
    assert_eq!(history.len(), 2);
    assert_eq!(
        history[0].event_type,
        crate::event::RouteEventType::BestChanged
    );
    assert_eq!(history[0].peer, Some(peer2));
    assert_eq!(history[0].previous_peer, Some(peer1));
    assert_eq!(
        history[1].event_type,
        crate::event::RouteEventType::BestChanged
    );
    assert_eq!(history[1].peer, Some(peer1));
    assert_eq!(history[1].previous_peer, Some(peer2));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_prefix_filter_no_matches_returns_empty() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let observed = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let missing = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(observed, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let history = query_route_event_history(&tx, None, None, Some(Prefix::V4(missing)), 10).await;
    assert!(history.is_empty());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_filters_ipv6_and_preserves_limited_order() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v4_prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let v6_prefix = Ipv6Prefix::new("2001:db8:100::".parse().unwrap(), 64);
    let v4_prefix2 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(v4_prefix1, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V6(Ipv6Addr::LOCALHOST),
        announced: vec![make_v6_route(v6_prefix, Ipv6Addr::LOCALHOST)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(v4_prefix2, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let v6_history = query_route_event_history(&tx, None, Some(Afi::Ipv6), None, 10).await;
    assert_eq!(v6_history.len(), 1);
    assert_eq!(v6_history[0].prefix, Prefix::V6(v6_prefix));

    let recent_two = query_route_event_history(&tx, None, None, None, 2).await;
    assert_eq!(recent_two.len(), 2);
    assert_eq!(recent_two[0].prefix, Prefix::V6(v6_prefix));
    assert_eq!(recent_two[1].prefix, Prefix::V4(v4_prefix2));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_limit_zero_returns_all_available() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 1), 32);
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 2), 32);
    for prefix in [prefix1, prefix2] {
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

    let history = query_route_event_history(&tx, None, None, None, 0).await;
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].prefix, Prefix::V4(prefix1));
    assert_eq!(history[1].prefix, Prefix::V4(prefix2));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_capacity_evicts_oldest_event() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    for index in 0..=ROUTE_EVENT_HISTORY_CAPACITY {
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_indexed_route(
                u32::try_from(index).unwrap(),
                Ipv4Addr::new(10, 0, 0, 1),
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

    let history = query_route_event_history(&tx, None, Some(Afi::Ipv4), None, 0).await;
    assert_eq!(history.len(), ROUTE_EVENT_HISTORY_CAPACITY);
    assert_eq!(history[0].event_id, 2);
    assert_eq!(
        history[0].prefix,
        make_indexed_route(1, Ipv4Addr::new(10, 0, 0, 1)).prefix
    );
    assert_eq!(
        history[ROUTE_EVENT_HISTORY_CAPACITY - 1].event_id,
        u64::try_from(ROUTE_EVENT_HISTORY_CAPACITY + 1).unwrap()
    );
    assert_eq!(
        history[ROUTE_EVENT_HISTORY_CAPACITY - 1].prefix,
        make_indexed_route(
            u32::try_from(ROUTE_EVENT_HISTORY_CAPACITY).unwrap(),
            Ipv4Addr::new(10, 0, 0, 1)
        )
        .prefix
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
#[expect(clippy::cast_possible_truncation)]
async fn route_event_history_gauges_track_depth_and_capacity() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let capacity = metrics
        .registry()
        .gather()
        .iter()
        .find(|family| family.name() == "bgp_route_event_history_capacity")
        .expect("capacity gauge registered")
        .metric[0]
        .gauge
        .value();
    assert_eq!(
        capacity as i64,
        i64::try_from(ROUTE_EVENT_HISTORY_CAPACITY).unwrap()
    );

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    for index in 0..3 {
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_indexed_route(index, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

    let _ = query_route_event_history(&tx, None, Some(Afi::Ipv4), None, 0).await;

    let depth = metrics
        .registry()
        .gather()
        .iter()
        .find(|family| family.name() == "bgp_route_event_history_depth")
        .expect("depth gauge registered")
        .metric[0]
        .gauge
        .value();
    assert_eq!(depth as i64, 3);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_withdrawn_on_last_removed() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        .find(|f| f.name() == "bgp_rib_prefixes")
        .expect("bgp_rib_prefixes metric not found");
    let sample = rib_gauge.metric[0].gauge.value();
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
        .find(|f| f.name() == "bgp_rib_prefixes")
        .expect("bgp_rib_prefixes metric not found");
    let sample = rib_gauge.metric[0].gauge.value();
    assert_eq!(sample as i64, 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
#[expect(clippy::cast_possible_truncation)]
async fn loc_rib_gauge_tracks_best() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        .find(|f| f.name() == "bgp_rib_loc_prefixes")
        .expect("bgp_loc_rib_prefixes metric not found");
    let sample = loc_gauge.metric[0].gauge.value();
    assert_eq!(sample as i64, 1);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
#[expect(clippy::cast_possible_truncation)]
async fn adj_rib_out_gauge_tracks_advertised() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
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
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        .find(|f| f.name() == "bgp_rib_adj_out_prefixes")
        .expect("bgp_adj_rib_out_prefixes metric not found");
    let sample = out_gauge.metric[0].gauge.value();
    assert_eq!(sample as i64, 1);

    drop(tx);
    handle.await.unwrap();
}

// --- Query count tests ---

#[tokio::test]
async fn query_loc_rib_count() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: source,
        attributes: Arc::new(vec![]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };

    // Send both IPv4 and IPv6 routes
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![v4_route, v6_route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

    let v4_route = make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1));
    let v6_route = Route {
        prefix: Prefix::V6(v6_prefix),
        next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: source,
        attributes: Arc::new(vec![]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };

    // Pre-populate Loc-RIB with both IPv4 and IPv6 routes
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![v4_route, v6_route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

    let v4_route = make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1));
    let v6_route = Route {
        prefix: Prefix::V6(v6_prefix),
        next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: source,
        attributes: Arc::new(vec![]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };

    // Pre-populate Loc-RIB
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![v4_route, v6_route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap();
    tokio::task::yield_now().await;

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let metrics = BgpMetrics::new();
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap();
    assert_refresh_metrics(&metrics, "10.0.0.1", "ipv4_unicast", 1.0, 2.0);

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route1],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap();
    assert_refresh_metrics(&metrics, "10.0.0.1", "ipv4_unicast", 1.0, 1.0);

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
    assert_refresh_metrics(&metrics, "10.0.0.1", "ipv4_unicast", 0.0, 0.0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_duplicate_borr_rebuilds_snapshot_safely() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await.unwrap();

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route1],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await.unwrap();

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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
async fn gr_flowspec_eor_recomputes_and_redistributes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100));
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
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let source_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let source_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let mut route_a = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
    route_a.attributes.push(PathAttribute::LocalPref(200));
    let mut route_b = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 2));
    route_b.attributes.push(PathAttribute::LocalPref(100));
    let rule = route_a.rule.clone();

    tx.send(RibUpdate::RoutesReceived {
        peer: source_a,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![route_a],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let initial = out_rx.recv().await.unwrap();
    assert_eq!(initial.flowspec_announce.len(), 1);
    assert_eq!(initial.flowspec_announce[0].peer, source_a);

    tx.send(RibUpdate::RoutesReceived {
        peer: source_b,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![route_b],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let best_before = query_flowspec_routes(&tx).await;
    assert_eq!(best_before.len(), 1);
    assert_eq!(best_before[0].peer, source_a);

    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source_a,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::FlowSpec)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let stale_switch = out_rx.recv().await.unwrap();
    assert_eq!(stale_switch.flowspec_announce.len(), 1);
    assert_eq!(stale_switch.flowspec_announce[0].peer, source_b);

    let best_during_gr = query_flowspec_routes(&tx).await;
    assert_eq!(best_during_gr.len(), 1);
    assert_eq!(best_during_gr[0].peer, source_b);

    tx.send(RibUpdate::EndOfRib {
        peer: source_a,
        afi: Afi::Ipv4,
        safi: Safi::FlowSpec,
    })
    .await
    .unwrap();

    let eor_switch = out_rx.recv().await.unwrap();
    assert_eq!(eor_switch.flowspec_announce.len(), 1);
    assert_eq!(eor_switch.flowspec_announce[0].peer, source_a);
    assert_eq!(eor_switch.flowspec_announce[0].rule, rule);

    let best_after_eor = query_flowspec_routes(&tx).await;
    assert_eq!(best_after_eor.len(), 1);
    assert_eq!(best_after_eor[0].peer, source_a);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn gr_eor_clears_stale() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source: IpAddr = "10.0.0.1".parse().unwrap();
    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

    // Source sends both IPv4 and IPv6 routes
    let v6_route = Route {
        prefix: Prefix::V6(v6_prefix),
        next_hop: "2001:db8::1".parse().unwrap(),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: source,
        attributes: Arc::new(vec![]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1)), v6_route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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

// --- GR/LLGR expiry session-hygiene tests ---
//
// Direct-manager style: these assert internal per-peer map state across
// the retention-expiry sweeps, which the channel-driven tests above
// cannot observe.

/// Apply all queued `RoutesReceived` chunks (the channel-driven manager
/// drains these from its run loop).
fn drain_route_chunks(manager: &mut RibManager) {
    while manager.process_next_route_chunk() {}
}

/// `PeerUp` with the boilerplate defaulted; returns the outbound receiver
/// so the channel stays open for the initial dump + `EoR`.
fn establish_peer(manager: &mut RibManager, peer: IpAddr) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, out_rx) = mpsc::channel(16);
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        peer_asn: 65001,
        peer_router_id: Ipv4Addr::new(1, 1, 1, 1),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    });
    out_rx
}

#[tokio::test]
async fn llgr_reestablish_uses_captured_stale_routes_time() {
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // GR with LLGR and a non-default stale_routes_time.
    manager.handle_update(RibUpdate::PeerGracefulRestart {
        peer,
        restart_time: 2,
        stale_routes_time: 77,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 3600,
    });

    // GR deadline expires → promotion to the LLGR stale phase.
    manager.sweep_gr_stale(peer);
    assert!(manager.llgr_peers.contains_key(&peer));

    // Peer re-establishes during LLGR: the re-armed GR deadline must use
    // the stale_routes_time captured at GR entry, not the 360 s default.
    let _out_rx = establish_peer(&mut manager, peer);
    assert_eq!(
        manager.gr_stale_routes_time.get(&peer),
        Some(&77),
        "re-establishment during LLGR must honor the captured stale_routes_time"
    );
}

#[tokio::test]
async fn llgr_expiry_sweep_drops_llgr_peer_config() {
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    manager.handle_update(RibUpdate::PeerGracefulRestart {
        peer,
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
    });

    manager.sweep_gr_stale(peer);
    assert!(
        manager.llgr_peer_config.contains_key(&peer),
        "LLGR config must survive GR→LLGR promotion (handle_peer_up reads it)"
    );

    // LLGR expires with the peer still gone — the config must not leak.
    manager.sweep_llgr_stale(peer);
    assert!(
        !manager.llgr_peer_config.contains_key(&peer),
        "LLGR expiry must drop the per-peer LLGR config"
    );
}

#[tokio::test]
async fn gr_expiry_without_reestablish_releases_peer_state() {
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    let _out_rx = establish_peer(&mut manager, peer);
    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer,
        peer_group: Some("edge".to_string()),
    });
    manager.handle_update(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    drain_route_chunks(&mut manager);
    assert!(manager.ribs.contains_key(&peer));

    // GR flap without LLGR; the peer never re-establishes, so when the
    // retention expires nothing references its per-peer state anymore.
    manager.handle_update(RibUpdate::PeerGracefulRestart {
        peer,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });
    manager.sweep_gr_stale(peer);

    assert!(
        !manager.ribs.contains_key(&peer),
        "GR expiry without re-establishment must release the Adj-RIB-In shell"
    );
    assert!(
        !manager.peer_asn.contains_key(&peer),
        "GR expiry without re-establishment must release peer_asn"
    );
    assert!(
        !manager.peer_bgp_id.contains_key(&peer),
        "GR expiry without re-establishment must release peer_bgp_id"
    );
    assert!(
        !manager.peer_group.contains_key(&peer),
        "GR expiry without re-establishment must release peer_group"
    );
}

#[tokio::test]
async fn llgr_expiry_without_reestablish_releases_peer_state() {
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    let _out_rx = establish_peer(&mut manager, peer);
    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer,
        peer_group: Some("edge".to_string()),
    });
    manager.handle_update(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    drain_route_chunks(&mut manager);

    manager.handle_update(RibUpdate::PeerGracefulRestart {
        peer,
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
    });
    manager.sweep_gr_stale(peer);
    assert!(manager.ribs.contains_key(&peer), "LLGR retains the rib");

    // LLGR expires with the peer still gone.
    manager.sweep_llgr_stale(peer);

    assert!(
        !manager.ribs.contains_key(&peer),
        "LLGR expiry without re-establishment must release the Adj-RIB-In shell"
    );
    assert!(
        !manager.peer_asn.contains_key(&peer),
        "LLGR expiry without re-establishment must release peer_asn"
    );
    assert!(
        !manager.peer_bgp_id.contains_key(&peer),
        "LLGR expiry without re-establishment must release peer_bgp_id"
    );
    assert!(
        !manager.peer_group.contains_key(&peer),
        "LLGR expiry without re-establishment must release peer_group"
    );
}

#[tokio::test]
async fn gr_expiry_sweep_spares_reestablished_peer_awaiting_eor() {
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    let _out_rx = establish_peer(&mut manager, peer);
    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer,
        peer_group: Some("edge".to_string()),
    });
    manager.handle_update(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    drain_route_chunks(&mut manager);

    manager.handle_update(RibUpdate::PeerGracefulRestart {
        peer,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });

    // Peer re-establishes during GR, but its End-of-RIB is late: the
    // stale-time sweep fires while the session is up. Stale routes go,
    // the live session's state must not.
    let _out_rx2 = establish_peer(&mut manager, peer);
    manager.sweep_gr_stale(peer);

    assert_eq!(
        manager
            .ribs
            .get(&peer)
            .map(crate::adj_rib_in::AdjRibIn::len),
        Some(0),
        "stale routes are swept but the Adj-RIB-In entry survives"
    );
    assert!(
        manager.peer_asn.contains_key(&peer),
        "identity must survive a sweep that fires before a late EoR"
    );
    assert!(manager.peer_bgp_id.contains_key(&peer));
    assert!(manager.peer_group.contains_key(&peer));
    assert!(
        manager.outbound_peers.contains_key(&peer),
        "outbound registration must survive a sweep that fires before a late EoR"
    );
}

// --- Route Reflector tests ---

#[tokio::test]
async fn rr_client_route_reflected_to_all_ibgp() {
    // When RR receives a route from a client, it should reflect to all
    // iBGP peers (both clients and non-clients), except the source.
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 1));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        negotiated_orf_recv: Vec::new(),
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        negotiated_orf_recv: Vec::new(),
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Inject local route
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: LOCAL_PEER,
        attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
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
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(peer),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(asns)],
            }),
            PathAttribute::LocalPref(100),
        ]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
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
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
            PathAttribute::LocalPref(100),
        ]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![route2],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![route2],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
async fn aspa_cache_update_revalidates_with_stored_downstream_context() {
    use rustbgpd_rpki::{AspaRecord, AspaTable};

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 4));
    let mut route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 4),
        vec![65004, 65003, 65002, 65001],
    );
    route.aspa_context = rustbgpd_wire::AspaValidationContext {
        neighbor_asn: Some(65004),
        local_role: Some(rustbgpd_wire::BgpRole::Customer),
        first_as_check_exempt: false,
    };

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let table = Arc::new(AspaTable::new(vec![
        AspaRecord {
            customer_asn: 65004,
            provider_asns: vec![65003],
        },
        AspaRecord {
            customer_asn: 65003,
            provider_asns: vec![65002],
        },
        AspaRecord {
            customer_asn: 65002,
            provider_asns: vec![65001],
        },
    ]));
    tx.send(RibUpdate::AspaTableUpdate { table }).await.unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: Some(peer),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let routes = reply_rx.await.unwrap();
    assert_eq!(routes[0].aspa_state, rustbgpd_wire::AspaValidation::Valid);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rpki_cache_update_no_change_no_redistribution() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(peer),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(asns)],
            }),
            PathAttribute::LocalPref(local_pref),
        ]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
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
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(peer),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(asns)],
            }),
            PathAttribute::LocalPref(local_pref),
        ]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

#[tokio::test]
async fn multipath_send_advertises_multiple_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48);

    let mk = |peer_addr: Ipv4Addr, asn: u32, local_pref: u32| Route {
        prefix: Prefix::V6(prefix),
        next_hop: "2001:db8::1".parse().unwrap(),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(peer_addr),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![asn])],
            }),
            PathAttribute::LocalPref(local_pref),
        ]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };

    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![mk(Ipv4Addr::new(10, 0, 0, 1), 65001, 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![mk(Ipv4Addr::new(10, 0, 0, 2), 65002, 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
#[expect(
    clippy::too_many_lines,
    reason = "large end-to-end test covering many route-refresh edge cases"
)]
async fn route_refresh_partial_negotiation_respects_family_mode() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        negotiated_orf_recv: Vec::new(),
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
#[expect(clippy::too_many_lines)]
async fn multipath_policy_filtered_events_for_denied_candidates() {
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
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }]);

    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(
        rx,
        dummy_query_rx(),
        Some(export_policy),
        None,
        metrics.clone(),
    );
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let history = query_route_event_history(&tx, Some(target), Some(Afi::Ipv4), None, 10).await;
    let policy_filtered = history
        .iter()
        .filter(|event| event.event_type == RouteEventType::PolicyFiltered)
        .collect::<Vec<_>>();
    assert_eq!(policy_filtered.len(), 2);
    assert!(policy_filtered.iter().all(|event| {
        event.target_peer == Some(target)
            && event.prefix == Prefix::V4(prefix)
            && event.reason == "policy_denied"
    }));
    assert!(
        (policy_metric_value(&metrics, "10.0.0.3", "inline", "export", "deny") - 3.0).abs()
            < f64::EPSILON
    );
    let stats = query_neighbor_policy_stats(&tx, target).await;
    assert_eq!(stats.export_policy_routes_permitted, 0);
    assert_eq!(stats.export_policy_routes_denied, 3);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn mrt_snapshot_uses_adj_rib_in_routes_without_loc_rib_duplication() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
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
        negotiated_orf_recv: Vec::new(),
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
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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

#[tokio::test]
async fn explain_best_path_returns_candidates_without_winner() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer_a = Ipv4Addr::new(1, 0, 0, 1);
    let peer_b = Ipv4Addr::new(1, 0, 0, 2);

    // Route from peer_a has higher LOCAL_PREF → should be best.
    let route_a = make_route_with_lp(prefix, peer_a, 200);
    let route_b = make_route_with_lp(prefix, peer_b, 100);

    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer_a),
        announced: vec![route_a],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer_b),
        announced: vec![route_b],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Give the RIB manager time to process.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let explain = query_explain_best_path(&tx, Prefix::V4(prefix)).await;

    // Best route should be from peer_a (higher LP).
    assert!(explain.best.is_some());
    let best = explain.best.unwrap();
    assert_eq!(best.peer, IpAddr::V4(peer_a));

    // Candidates should NOT include the winner.
    assert_eq!(explain.candidates.len(), 1);
    let loser = &explain.candidates[0];
    assert_eq!(loser.route.peer, IpAddr::V4(peer_b));
    assert_eq!(
        loser.vs_best_reason,
        crate::best_path::BestPathReason::HigherLocalPref
    );
    assert_eq!(loser.vs_best_ordering, std::cmp::Ordering::Greater);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn explain_best_path_no_candidates() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    let explain = query_explain_best_path(&tx, prefix).await;

    assert!(explain.best.is_none());
    assert!(explain.candidates.is_empty());
    assert!(explain.peer.is_none());
    assert_eq!(explain.add_path_send_max, 0);

    drop(tx);
    handle.await.unwrap();
}

/// Add-Path explain: a peer with `send_max=2` and 3 candidate routes
/// should see exactly 2 candidates with non-zero `advertised_path_id`
/// (ranks 1 + 2 by best-path order), and the third one with a zero
/// `advertised_path_id` (it would be dropped past the limit).
#[tokio::test]
async fn explain_best_path_for_addpath_peer_marks_top_n_with_path_id() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let peer3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

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
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

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
        add_path_send_max: 2,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let explain = query_explain_best_path_for_peer(&tx, Prefix::V4(prefix), target)
        .await
        .expect("known peer");

    assert_eq!(explain.peer, Some(target));
    assert_eq!(explain.add_path_send_max, 2);
    assert!(explain.best.is_some(), "best should be peer1 (LP=200)");
    let best = explain.best.as_ref().unwrap();
    assert_eq!(best.peer, peer1);

    // Candidates exclude the winner; that's the existing contract.
    // The remaining two are peer2 (advertised at rank 2) and peer3
    // (filtered, beyond send_max).
    assert_eq!(explain.candidates.len(), 2);
    let by_peer: std::collections::HashMap<IpAddr, &crate::update::BestPathCandidate> = explain
        .candidates
        .iter()
        .map(|c| (c.route.peer, c))
        .collect();

    let cand_peer2 = by_peer.get(&peer2).expect("peer2 is a candidate");
    assert_eq!(
        cand_peer2.advertised_path_id, 2,
        "peer2 (LP=150) should be advertised at rank 2"
    );

    let cand_peer3 = by_peer.get(&peer3).expect("peer3 is a candidate");
    assert_eq!(
        cand_peer3.advertised_path_id, 0,
        "peer3 (LP=100) should be filtered (beyond send_max)"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Regression: when the target peer is itself the source of the
/// Loc-RIB best (split-horizon excludes it from the export-filtered
/// set), single-best send mode (`send_max=0`) must not fall back to
/// the next-best candidate. `distribute_single_best_prefix` would
/// advertise nothing in this case; explain must reflect the same
/// answer or it lies to the operator.
#[tokio::test]
async fn explain_best_path_single_best_does_not_fall_back_when_winner_is_target() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let peer_winner = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer_runner_up = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    // peer_winner has the higher LP and *is* the target peer.
    // Under split-horizon, peer_winner cannot receive its own route
    // back — so single-best advertises nothing.
    for (peer, addr, asn, lp) in [
        (peer_winner, Ipv4Addr::new(10, 0, 0, 1), 65001, 200),
        (peer_runner_up, Ipv4Addr::new(10, 0, 0, 2), 65002, 100),
    ] {
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_multipath_route(prefix, addr, vec![asn], lp)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

    let (out_tx, _out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: peer_winner, // <-- target IS the winner
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let explain = query_explain_best_path_for_peer(&tx, Prefix::V4(prefix), peer_winner)
        .await
        .expect("known peer");
    assert_eq!(explain.add_path_send_max, 0);
    // No candidate may have a non-zero advertised_path_id. Before
    // the fix, peer_runner_up would have been promoted to rank 1.
    for cand in &explain.candidates {
        assert_eq!(
            cand.advertised_path_id, 0,
            "single-best must not fall back; cand={:?}",
            cand.route.peer
        );
    }

    drop(tx);
    handle.await.unwrap();
}

/// Add-Path explain: a peer with `send_max=0` (single-best mode)
/// only advertises the global best, even when more candidates exist.
#[tokio::test]
async fn explain_best_path_for_single_best_peer_marks_only_winner_path_id_zero() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    for (peer, addr, asn, lp) in [
        (peer1, Ipv4Addr::new(10, 0, 0, 1), 65001, 200),
        (peer2, Ipv4Addr::new(10, 0, 0, 2), 65002, 100),
    ] {
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_multipath_route(prefix, addr, vec![asn], lp)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

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
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let explain = query_explain_best_path_for_peer(&tx, Prefix::V4(prefix), target)
        .await
        .expect("known peer");

    assert_eq!(explain.peer, Some(target));
    assert_eq!(explain.add_path_send_max, 0);
    // Best = peer1 (LP=200). The losing candidate is peer2; under
    // single-best send mode it would not be advertised even with
    // a higher rank, so its advertised_path_id is 0.
    assert!(explain.best.is_some());
    assert_eq!(explain.candidates.len(), 1);
    assert_eq!(explain.candidates[0].advertised_path_id, 0);

    drop(tx);
    handle.await.unwrap();
}

/// Regression: when the prefix's AFI/SAFI isn't in the peer's
/// `add_path_send_families`, the response's `add_path_send_max`
/// must reflect 0 — not the bare config knob — to match what
/// distribution would actually do.
#[tokio::test]
async fn explain_best_path_effective_send_max_zero_on_family_mismatch() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    for (peer, addr, asn, lp) in [
        (peer1, Ipv4Addr::new(10, 0, 0, 1), 65001, 200),
        (peer2, Ipv4Addr::new(10, 0, 0, 2), 65002, 100),
    ] {
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_multipath_route(prefix, addr, vec![asn], lp)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

    // Peer registered with sendable_families = IPv4 unicast, but
    // add_path_send_families = IPv6 unicast. Asking about an IPv4
    // prefix → effective send_max should be 0.
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
        add_path_send_families: vec![(Afi::Ipv6, Safi::Unicast)],
        add_path_send_max: 4,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let explain = query_explain_best_path_for_peer(&tx, Prefix::V4(prefix), target)
        .await
        .expect("known peer");

    assert_eq!(
        explain.add_path_send_max, 0,
        "effective send_max should be 0 when the prefix's family isn't in add_path_send_families"
    );
    for cand in &explain.candidates {
        assert_eq!(cand.advertised_path_id, 0);
    }

    drop(tx);
    handle.await.unwrap();
}

/// Add-Path explain: an unknown peer returns `None` (not Found at the
/// gRPC layer) rather than silently giving the global view.
#[tokio::test]
async fn explain_best_path_for_unknown_peer_returns_none() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let unknown = IpAddr::V4(Ipv4Addr::new(10, 99, 99, 99));

    let result = query_explain_best_path_for_peer(&tx, Prefix::V4(prefix), unknown).await;
    assert!(result.is_none(), "unknown peer should yield None");

    drop(tx);
    handle.await.unwrap();
}

/// Global-view explain (no peer scope) preserves the v0.7.0 shape
/// even after the Add-Path extensions.
#[tokio::test]
async fn explain_best_path_global_view_unchanged() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer_a = Ipv4Addr::new(1, 0, 0, 1);
    let peer_b = Ipv4Addr::new(1, 0, 0, 2);

    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer_a),
        announced: vec![make_route_with_lp(prefix, peer_a, 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer_b),
        announced: vec![make_route_with_lp(prefix, peer_b, 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let explain = query_explain_best_path(&tx, Prefix::V4(prefix)).await;
    assert!(explain.peer.is_none());
    assert_eq!(explain.add_path_send_max, 0);
    // Every candidate has advertised_path_id == 0 in global view.
    for cand in &explain.candidates {
        assert_eq!(cand.advertised_path_id, 0);
    }

    drop(tx);
    handle.await.unwrap();
}

/// Regression: EVPN routes learned from a peer that goes down must be
/// withdrawn from remaining peers. Before this fix, `handle_peer_down` removed
/// the dead peer's Adj-RIB-In but never called `recompute_and_distribute_evpn`,
/// leaving the Loc-RIB advertising stale MAC/IP reachability.
#[tokio::test]
async fn peer_down_withdraws_evpn_routes_from_remaining_peers() {
    let (tx, rx) = mpsc::channel(64);
    // Cluster-ID is required for iBGP→iBGP reflection (RFC 4456); without it,
    // should_suppress_ibgp_inner falls back to standard split-horizon.
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Register target as RR client for L2VPN/EVPN (iBGP, same AS).
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Register source as an RR client too — the RibManager needs an outbound
    // entry for the source or it skips reflection evaluation entirely; the
    // source's own announces will round-trip to itself but split-horizon
    // suppresses them at the stage step.
    let (source_out_tx, mut source_out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut source_out_rx).await;

    // Source advertises a Type 3 IMET route.
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet_key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Target receives the reflected EVPN announce.
    let announce = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("target should receive EVPN announce within 2s")
        .expect("outbound channel open");
    assert_eq!(announce.evpn_announce.len(), 1);
    assert_eq!(announce.evpn_announce[0].key(), imet_key);
    assert!(
        announce.evpn_withdraw.is_empty(),
        "announce phase should have no withdrawals"
    );

    // Source goes down.
    tx.send(RibUpdate::PeerDown { peer: source }).await.unwrap();

    // Target should receive a withdrawal for that EVPN key.
    let withdraw = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("target should receive EVPN withdrawal within 2s")
        .expect("outbound channel still open");
    assert!(
        withdraw.evpn_announce.is_empty(),
        "peer-down should not produce announces"
    );
    assert_eq!(
        withdraw.evpn_withdraw,
        vec![imet_key],
        "target must see the withdrawal for the dead peer's EVPN route"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Regression: an RR must not reflect an EVPN route back to the peer
/// that originated it (source-peer split horizon). Prior to the fix the
/// distribution path went `loc_rib.get_evpn()` → RR suppression check →
/// stage for all peers including the source. FRR dropped the
/// self-reflection via `ORIGINATOR_ID`, but RFC 4456 hygiene says we
/// shouldn't emit it in the first place.
#[tokio::test]
async fn evpn_is_not_reflected_back_to_source_peer() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Source is an RR client.
    let (source_out_tx, mut source_out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut source_out_rx).await;

    // A second RR client so reflection has somewhere to go.
    let (other_out_tx, mut other_out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: other,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: other_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut other_out_rx).await;

    // Source advertises a Type 3 IMET.
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet_key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // The "other" client must receive a reflected announce.
    let other_announce = tokio::time::timeout(Duration::from_secs(2), other_out_rx.recv())
        .await
        .expect("other peer should receive reflection within 2s")
        .expect("outbound channel still open");
    assert_eq!(other_announce.evpn_announce.len(), 1);
    assert_eq!(other_announce.evpn_announce[0].key(), imet_key);

    // The source must NOT receive its own route back. A short wait is
    // enough — if the bug exists, the bad announce fires on the same
    // distribute_changes as the reflection to "other".
    match tokio::time::timeout(Duration::from_millis(300), source_out_rx.recv()).await {
        Err(_) => {
            // Timeout — correct behavior. Source saw nothing.
        }
        Ok(Some(msg)) => {
            assert!(
                msg.evpn_announce.is_empty(),
                "source peer must not receive its own EVPN route back (got {:?})",
                msg.evpn_announce,
            );
        }
        Ok(None) => panic!("source outbound channel closed unexpectedly"),
    }

    drop(tx);
    handle.await.unwrap();
}

/// Regression: when an EVPN update fails to send (outbound channel full),
/// the peer is marked dirty; a later `distribute_changes` must resync EVPN
/// routes, not only unicast / `FlowSpec`. Before this fix, dirty resync
/// rebuilt unicast prefixes + `FlowSpec` rules but never gathered EVPN keys
/// or staged EVPN routes, so EVPN deltas could be silently dropped.
#[tokio::test]
async fn dirty_resync_includes_evpn_routes_after_channel_full() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Target's outbound channel is size 1 — after the EoR, one more slot.
    // We'll fill it, then the EVPN announce will fail and mark target dirty.
    let (out_tx, mut out_rx) = mpsc::channel(1);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Source as RR client so reflection isn't suppressed.
    let (source_out_tx, mut source_out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut source_out_rx).await;

    // Fill the target's outbound channel by NOT draining — send two EVPN
    // announces in a row. The first lands in the channel (queue size 1);
    // the second fails `try_send` and marks target dirty.
    let imet1 = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet1_key = imet1.key();
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet1],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Give the RibManager a tick to process and fill the channel.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Second EVPN route arrives; target's channel is full → target goes dirty.
    let imet2 = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 200);
    let imet2_key = imet2.key();
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet2],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Drain the first queued update to make room, then drain anything the
    // resync timer delivers.
    let first = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("first EVPN announce must arrive")
        .expect("channel open");
    assert_eq!(first.evpn_announce.len(), 1);
    assert_eq!(first.evpn_announce[0].key(), imet1_key);

    // Collect EVPN announces until we see imet2_key — the dirty-resync path
    // must eventually deliver it. Time out after 10s (resync timer is faster).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut saw_imet2 = false;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), out_rx.recv()).await {
            Ok(Some(update)) => {
                if update.evpn_announce.iter().any(|r| r.key() == imet2_key) {
                    saw_imet2 = true;
                    break;
                }
            }
            Ok(None) => panic!("outbound channel closed unexpectedly"),
            Err(_) => {}
        }
    }
    assert!(
        saw_imet2,
        "dirty resync must eventually deliver the second EVPN announce (imet2) to the target peer"
    );

    drop(tx);
    handle.await.unwrap();
}

// ---------------------------------------------------------------------------
// EVPN GR/LLGR tests (Gate 2) — mirror the unicast + FlowSpec GR/LLGR suite.
// Each test spawns a RibManager with a cluster-id so iBGP reflection works,
// registers two peers (source + target, both RR clients), and drives
// RibUpdate events to exercise the stale lifecycle.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn evpn_gr_marks_stale_and_demotes_routes() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Source enters graceful restart
    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 1, "EVPN route should remain in Loc-RIB");
    assert!(best[0].is_stale, "EVPN route should be marked stale");
    assert!(!best[0].is_llgr_stale);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_gr_eor_clears_stale() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert!(best[0].is_stale);

    tx.send(RibUpdate::EndOfRib {
        peer: source,
        afi: Afi::L2Vpn,
        safi: Safi::Evpn,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert!(!best[0].is_stale, "EoR should clear stale flag");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_gr_timer_sweeps_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // GR without LLGR — stale routes should be purged on timer expiry.
    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert!(best[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    let best = query_evpn_routes(&tx).await;
    assert!(
        best.is_empty(),
        "GR timer expiry must sweep stale EVPN routes"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_llgr_gr_timer_promotes_to_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source,
        restart_time: 5,
        stale_routes_time: 10,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 7200,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert!(best[0].is_stale);
    assert!(!best[0].is_llgr_stale);

    // Advance past GR timer — promotes to LLGR-stale
    tokio::time::advance(Duration::from_secs(6)).await;
    tokio::task::yield_now().await;

    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 1, "EVPN route retained during LLGR");
    assert!(!best[0].is_stale);
    assert!(best[0].is_llgr_stale);
    // LLGR_STALE community injected locally
    assert!(
        best[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "promoted EVPN route must carry LLGR_STALE community"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_llgr_timer_sweeps_llgr_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            forwarding_preserved: false,
            stale_time: 10,
        }],
        llgr_stale_time: 10,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert!(best[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let best = query_evpn_routes(&tx).await;
    assert!(best[0].is_llgr_stale);

    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;

    let best = query_evpn_routes(&tx).await;
    assert!(
        best.is_empty(),
        "LLGR timer expiry must sweep LLGR-stale EVPN routes"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_llgr_eor_clears_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 3600,
    })
    .await
    .unwrap();

    // Force the manager to process PeerGracefulRestart before advancing time
    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert!(best[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let best = query_evpn_routes(&tx).await;
    assert!(best[0].is_llgr_stale);
    assert!(
        best[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
    );

    // EoR during LLGR phase: clears is_llgr_stale + strips locally-injected
    // LLGR_STALE community
    tx.send(RibUpdate::EndOfRib {
        peer: source,
        afi: Afi::L2Vpn,
        safi: Safi::Evpn,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert!(!best[0].is_llgr_stale, "LLGR-stale flag must be cleared");
    assert!(
        !best[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "locally-injected LLGR_STALE community must be stripped"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_gr_no_llgr_community_drops_route_on_promotion() {
    use rustbgpd_wire::{EthernetTagId, EvpnImet, EvpnRoute, RouteDistinguisher};

    tokio::time::pause();

    // Build an EVPN route carrying COMMUNITY_NO_LLGR so it must be dropped
    // when the GR timer expires rather than promoted to LLGR-stale.
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = EvpnRoute::Imet(EvpnImet {
        rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 100]),
        ethernet_tag: EthernetTagId(100),
        originator_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    });
    let imet = EvpnRibRoute {
        route,
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        link_local_next_hop: None,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        attributes: Arc::new(vec![PathAttribute::Communities(vec![
            rustbgpd_wire::COMMUNITY_NO_LLGR,
        ])]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        is_stale: false,
        is_llgr_stale: false,
    };
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: true,
        peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            forwarding_preserved: false,
            stale_time: 3600,
        }],
        llgr_stale_time: 3600,
    })
    .await
    .unwrap();

    // Force the manager to process PeerGracefulRestart before advancing time
    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert!(best[0].is_stale);

    // Advance past GR timer — NO_LLGR route must be removed, not promoted.
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let best = query_evpn_routes(&tx).await;
    assert!(
        best.is_empty(),
        "NO_LLGR EVPN route must be dropped on GR timer expiry"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Gate 6: controller-driven EVPN injection. `InjectEvpn` places a
/// `RouteOrigin::Local` EVPN route into the RR's Loc-RIB and reflects
/// it to peers negotiating L2VPN/EVPN — same shape as `InjectFlowSpec`.
#[tokio::test]
async fn inject_evpn_reflects_to_peer() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Construct an EVPN Type 3 IMET anchored on a synthetic local
    // originator (0.0.0.0, matches LOCAL_PEER in the manager).
    let mut imet = make_evpn_imet(Ipv4Addr::UNSPECIFIED, 100);
    imet.origin_type = crate::route::RouteOrigin::Local;
    let injected_key = imet.key();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::InjectEvpn {
        route: imet,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx
        .await
        .expect("inject reply")
        .expect("inject must succeed");

    // Peer must see the reflected local route as an announce.
    let msg = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("peer should receive the injected route within 2s")
        .expect("outbound channel open");
    assert_eq!(msg.evpn_announce.len(), 1);
    assert_eq!(msg.evpn_announce[0].key(), injected_key);

    // Withdraw through the same channel; peer must see the retraction.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::WithdrawEvpn {
        key: injected_key,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx
        .await
        .expect("withdraw reply")
        .expect("withdraw must succeed");

    let msg = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("peer should receive withdraw within 2s")
        .expect("outbound channel open");
    assert!(msg.evpn_announce.is_empty());
    assert_eq!(msg.evpn_withdraw, vec![injected_key]);

    drop(tx);
    handle.await.unwrap();
}

/// Withdrawing an unknown EVPN key surfaces a user-visible error
/// (controller got a bad route identifier).
#[tokio::test]
async fn withdraw_evpn_unknown_key_returns_error() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let fake_key = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 999).key();
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::WithdrawEvpn {
        key: fake_key,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let result = reply_rx.await.expect("withdraw reply");
    assert!(result.is_err(), "unknown key must return an error");

    drop(tx);
    handle.await.unwrap();
}

/// Regression: a peer that joins AFTER the EVPN Loc-RIB has been
/// populated must receive the existing routes in its initial dump.
/// Prior to the fix, `send_initial_table` never called
/// `stage_evpn_routes` and hardcoded `evpn_announce: vec![]`, so a
/// late-joining VTEP saw an EVPN End-of-RIB with zero routes and
/// cleared any stale state — operating with no EVPN reachability for
/// the existing fabric until unrelated RIB churn forced redistribution.
/// The M30-M33 harnesses miss this because they bring up peers before
/// any EVPN advertisements; production VTEPs reconnect into a
/// converged fabric all the time.
#[tokio::test]
async fn late_joining_peer_receives_existing_evpn_routes_in_initial_dump() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let early = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (early_out_tx, mut early_out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        peer: early,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: early_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut early_out_rx).await;

    // Early peer advertises a Type 3 IMET — this populates the RR's
    // EVPN Loc-RIB before the late peer connects.
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet_key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        peer: early,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Drain side-effects so the early peer's reflection (if any) is
    // processed before we register the late peer.
    let _ = query_evpn_routes(&tx).await;

    // Now a late-joining peer connects to the same RR.
    let late = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (late_out_tx, mut late_out_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        peer: late,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: late_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    // First message to the late peer must be the initial dump carrying
    // the existing EVPN route. Without the fix this is just an empty
    // EoR and the route is silently absent.
    let msg = tokio::time::timeout(Duration::from_secs(2), late_out_rx.recv())
        .await
        .expect("late peer should receive an outbound update within 2s")
        .expect("outbound channel open");

    assert_eq!(
        msg.evpn_announce.len(),
        1,
        "late-joining peer must see the existing EVPN route in initial dump"
    );
    assert_eq!(msg.evpn_announce[0].key(), imet_key);

    drop(tx);
    handle.await.unwrap();
}

/// Regression: RFC 7313 Enhanced Route Refresh on the L2VPN/EVPN family
/// must remove re-advertised keys from the per-peer stale set, otherwise
/// `EoRR` sweeps every reflected EVPN route off the RIB. The unicast and
/// `FlowSpec` chunks already do this; the EVPN chunks were missing the
/// hook entirely.
#[tokio::test]
async fn enhanced_route_refresh_evpn_replacement_preserves_route() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // Stage 1: peer advertises one EVPN Type 3 IMET route.
    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet_key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet.clone()],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Stage 2: peer initiates ERR for L2VPN/EVPN. The manager snapshots
    // imet_key into refresh_stale_evpn[peer] at this point.
    tx.send(RibUpdate::BeginRouteRefresh {
        peer,
        afi: Afi::L2Vpn,
        safi: Safi::Evpn,
    })
    .await
    .unwrap();

    // Quiesce the manager so the BoRR snapshot lands before the
    // re-advertisement races it.
    let _drain = query_evpn_routes(&tx).await;

    // Stage 3: peer re-advertises the same key — must remove it from
    // the stale set. Without the fix this is a no-op on the stale set.
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Stage 4: peer ends the refresh window. EoRR sweeps anything left
    // in the stale set; with the fix that set is empty, so the route
    // survives. Without the fix, the route gets withdrawn here.
    tx.send(RibUpdate::EndRouteRefresh {
        peer,
        afi: Afi::L2Vpn,
        safi: Safi::Evpn,
    })
    .await
    .unwrap();

    let best = query_evpn_routes(&tx).await;
    assert_eq!(best.len(), 1, "refreshed EVPN route must survive EoRR");
    assert_eq!(best[0].key(), imet_key);

    drop(tx);
    handle.await.unwrap();
}

/// Regression: EVPN export-policy `RouteModifications` (community add,
/// `LocalPref` override, etc.) must be applied to the announced route.
/// Before the fix, `evaluate_chain`'s result was checked for Permit/Deny
/// but `result.modifications` was discarded, so RT/community/`LocalPref`
/// rewrite policy silently had no effect on EVPN exports.
#[tokio::test]
#[expect(clippy::too_many_lines)]
async fn evpn_export_policy_applies_modifications() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

    // Permit-all with a community-add side effect.
    let added_community: u32 = (65000u32 << 16) | 0x3E7;
    let mut mods = RouteModifications::default();
    mods.communities_add.push(added_community);
    let export_policy = PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Permit,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: mods,
        }],
        default_action: PolicyAction::Permit,
    }]);

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(
        rx,
        dummy_query_rx(),
        Some(export_policy),
        cluster_id,
        BgpMetrics::new(),
    );
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let (source_out_tx, mut source_out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut source_out_rx).await;

    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let announce = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("target should receive EVPN announce within 2s")
        .expect("outbound channel open");
    assert_eq!(announce.evpn_announce.len(), 1);

    let attrs = announce.evpn_announce[0].attributes.as_ref();
    let comms_attr = attrs
        .iter()
        .find_map(|a| {
            if let PathAttribute::Communities(c) = a {
                Some(c)
            } else {
                None
            }
        })
        .expect("export policy must add Communities attribute when modifications include communities_add");
    assert!(
        comms_attr.contains(&added_community),
        "added community {added_community:#x} must appear on the reflected EVPN route"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Regression: `PendingRoutesReceived::has_more()` previously omitted
/// the EVPN iterators, so a `RoutesReceived` carrying more than
/// `ROUTES_RECEIVED_CHUNK_SIZE` EVPN routes had everything past the
/// first chunk silently dropped at distribution.rs's `if has_more()
/// push_front` re-enqueue site. This test drains a 2-chunk-sized batch
/// of EVPN announces and verifies every route appears in the chunk
/// stream.
#[test]
fn pending_routes_received_drains_full_evpn_announce_batch() {
    let total = ROUTES_RECEIVED_CHUNK_SIZE * 2 + 7;
    let peer = Ipv4Addr::new(192, 0, 2, 1);
    let evpn_announced: Vec<EvpnRibRoute> = (0..u32::try_from(total).unwrap())
        .map(|tag| make_evpn_imet(peer, tag))
        .collect();

    let mut pending = PendingRoutesReceived::new(
        IpAddr::V4(peer),
        vec![],
        vec![],
        vec![],
        vec![],
        evpn_announced,
        vec![],
    );

    let mut drained: usize = 0;
    let mut last_was_evpn = false;
    while let Some(chunk) = pending.next_chunk() {
        match chunk {
            PendingRouteChunk::EvpnAnnounced(routes) => {
                drained += routes.len();
                last_was_evpn = true;
            }
            PendingRouteChunk::EvpnWithdrawn(routes) => {
                drained += routes.len();
                last_was_evpn = true;
            }
            _ => last_was_evpn = false,
        }
    }
    assert!(last_was_evpn, "final chunk must be EVPN");
    assert_eq!(
        drained, total,
        "every EVPN route must be drained; has_more() must keep the batch alive"
    );
    assert!(
        !pending.has_more(),
        "after full drain, has_more() must report false"
    );
}

/// Regression: same drain check for EVPN withdrawals, since they also
/// flow through the `evpn_withdrawn` iterator and `has_more()`.
#[test]
fn pending_routes_received_drains_full_evpn_withdraw_batch() {
    let total = ROUTES_RECEIVED_CHUNK_SIZE + 1;
    let peer = Ipv4Addr::new(192, 0, 2, 2);
    let withdrawn: Vec<rustbgpd_wire::EvpnRouteKey> = (0..u32::try_from(total).unwrap())
        .map(|tag| make_evpn_imet(peer, tag).key())
        .collect();

    let mut pending = PendingRoutesReceived::new(
        IpAddr::V4(peer),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        withdrawn,
    );

    let mut drained: usize = 0;
    while let Some(chunk) = pending.next_chunk() {
        if let PendingRouteChunk::EvpnWithdrawn(keys) = chunk {
            drained += keys.len();
        }
    }
    assert_eq!(drained, total);
    assert!(!pending.has_more());
}

// --- EVPN route event streaming tests (Gate 7c) ---

/// Build a Type 2 (`MacIp`) `EvpnRibRoute` carrying an optional MAC
/// Mobility extended community. Tests use this to simulate received
/// routes with varying mobility sequences.
fn make_evpn_macip(
    peer: Ipv4Addr,
    mac: [u8; 6],
    mobility_seq: Option<u32>,
    sticky: bool,
) -> EvpnRibRoute {
    let route = EvpnRoute::MacIp(EvpnMacIp {
        rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 100]),
        esi: EthernetSegmentIdentifier::ZERO,
        ethernet_tag: EthernetTagId(100),
        mac: MacAddress::new(mac),
        ip: None,
        label1: MplsLabel::new(100),
        label2: None,
    });

    let mut attrs: Vec<PathAttribute> = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::NextHop(peer),
    ];
    if let Some(seq) = mobility_seq {
        attrs.push(PathAttribute::ExtendedCommunities(vec![
            ExtendedCommunity::mac_mobility(sticky, seq),
        ]));
    }

    EvpnRibRoute {
        route,
        next_hop: IpAddr::V4(peer),
        link_local_next_hop: None,
        peer: IpAddr::V4(peer),
        attributes: Arc::new(attrs),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: peer,
        is_stale: false,
        is_llgr_stale: false,
    }
}

async fn subscribe_evpn_events(
    tx: &mpsc::Sender<RibUpdate>,
) -> tokio::sync::broadcast::Receiver<crate::event::EvpnRouteEvent> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::SubscribeEvpnRouteEvents { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap()
}

async fn query_evpn_event_history(
    tx: &mpsc::Sender<RibUpdate>,
    peer: Option<IpAddr>,
    route_type: Option<u8>,
    rd: Option<RouteDistinguisher>,
    event_types: BTreeSet<RouteEventType>,
    limit: usize,
) -> Vec<crate::event::EvpnRouteEvent> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryEvpnRouteEventHistory {
        peer,
        route_type,
        rd,
        event_types,
        limit,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap()
}

#[tokio::test]
async fn evpn_route_event_added_on_new_best() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mut events_rx = subscribe_evpn_events(&tx).await;

    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    let route = make_evpn_macip(
        peer_addr,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        Some(0),
        false,
    );
    let key = route.key();
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![route],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let event = tokio::time::timeout(Duration::from_secs(2), events_rx.recv())
        .await
        .expect("EVPN broadcast should deliver event within 2s")
        .expect("broadcast not closed");
    assert_eq!(event.event_type, crate::event::RouteEventType::Added);
    assert_eq!(event.key, key);
    assert_eq!(event.peer, Some(peer));
    assert!(event.previous_peer.is_none());
    assert!(event.best.is_some(), "Added must carry a best path");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_event_history_records_events_without_subscriber() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    let route = make_evpn_macip(
        peer_addr,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x77],
        Some(0),
        false,
    );
    let key = route.key();
    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![route],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let history = query_evpn_event_history(&tx, None, Some(2), None, BTreeSet::new(), 10).await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].event_type, RouteEventType::Added);
    assert_eq!(history[0].key, key);
    assert_eq!(history[0].peer, Some(peer));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_event_history_filters_peer_rd_type_and_limit() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mac = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x02];
    let peer1_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer2_addr = Ipv4Addr::new(10, 0, 0, 2);
    let peer1 = IpAddr::V4(peer1_addr);
    let peer2 = IpAddr::V4(peer2_addr);
    let route1 = make_evpn_macip(peer1_addr, mac, Some(0), false);
    let rd = crate::event::evpn_key_rd(&route1.key());

    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![route1],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![make_evpn_macip(peer2_addr, mac, Some(1), false)],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let mut event_types = BTreeSet::new();
    event_types.insert(RouteEventType::BestChanged);
    let history =
        query_evpn_event_history(&tx, Some(peer1), Some(2), Some(rd), event_types, 1).await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].event_type, RouteEventType::BestChanged);
    assert_eq!(history[0].peer, Some(peer2));
    assert_eq!(history[0].previous_peer, Some(peer1));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_event_history_capacity_evicts_oldest_event() {
    let (tx, rx) = mpsc::channel(256);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    for index in 0..=EVPN_ROUTE_EVENT_HISTORY_CAPACITY {
        let index_bytes = u32::try_from(index)
            .expect("test history capacity fits in u32")
            .to_be_bytes();
        let mac = [
            0x02,
            0x00,
            0x00,
            index_bytes[1],
            index_bytes[2],
            index_bytes[3],
        ];
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![make_evpn_macip(peer_addr, mac, Some(0), false)],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

    let history = query_evpn_event_history(&tx, None, Some(2), None, BTreeSet::new(), 0).await;
    assert_eq!(history.len(), EVPN_ROUTE_EVENT_HISTORY_CAPACITY);
    assert_eq!(history[0].key.route_type(), 2);
    let rustbgpd_wire::EvpnRouteKey::MacIp { mac: first_mac, .. } = history[0].key else {
        panic!("expected Type 2 key");
    };
    assert_eq!(first_mac.octets(), [0x02, 0x00, 0x00, 0, 0, 1]);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_route_event_best_changed_on_higher_mobility() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mac = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01];
    let original_peer = Ipv4Addr::new(10, 0, 0, 1);
    let new_peer = Ipv4Addr::new(10, 0, 0, 2);

    // First peer originates with seq=0.
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(original_peer),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![make_evpn_macip(original_peer, mac, Some(0), false)],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Subscribe after the initial Added event so the next event we
    // observe is the contended best-path move.
    let mut events_rx = subscribe_evpn_events(&tx).await;

    // Second peer originates the same MAC with a higher mobility seq.
    // Best-path tiebreak (RFC 7432 §15.1) prefers the higher seq.
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(new_peer),
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![make_evpn_macip(new_peer, mac, Some(1), false)],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let event = tokio::time::timeout(Duration::from_secs(2), events_rx.recv())
        .await
        .expect("EVPN broadcast should deliver event within 2s")
        .expect("broadcast not closed");
    assert_eq!(event.event_type, crate::event::RouteEventType::BestChanged);
    assert_eq!(event.peer, Some(IpAddr::V4(new_peer)));
    assert_eq!(event.previous_peer, Some(IpAddr::V4(original_peer)));
    let best = event.best.expect("BestChanged must carry a best path");
    assert_eq!(best.peer, IpAddr::V4(new_peer));
    let prior = event
        .previous_best
        .expect("BestChanged must carry the prior best path");
    assert_eq!(prior.peer, IpAddr::V4(original_peer));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn evpn_route_event_withdrawn_on_last_removed() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer_addr = Ipv4Addr::new(10, 0, 0, 3);
    let peer = IpAddr::V4(peer_addr);
    let route = make_evpn_macip(
        peer_addr,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x66],
        Some(0),
        false,
    );
    let key = route.key();

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![route],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let mut events_rx = subscribe_evpn_events(&tx).await;

    tx.send(RibUpdate::RoutesReceived {
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![key],
    })
    .await
    .unwrap();

    let event = tokio::time::timeout(Duration::from_secs(2), events_rx.recv())
        .await
        .expect("EVPN broadcast should deliver event within 2s")
        .expect("broadcast not closed");
    assert_eq!(event.event_type, crate::event::RouteEventType::Withdrawn);
    assert_eq!(event.key, key);
    assert!(event.peer.is_none());
    assert_eq!(event.previous_peer, Some(peer));
    assert!(event.best.is_none(), "Withdrawn must not carry a best");
    let prior = event
        .previous_best
        .expect("Withdrawn must carry the prior best so consumers recover VNI");
    assert_eq!(prior.peer, peer);

    drop(tx);
    handle.await.unwrap();
}

// --- FIB install-candidate view (multipath/ECMP) ---

#[tokio::test]
async fn fib_install_candidates_groups_equal_cost_ecmp() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));
    // Two equal-cost eBGP paths (empty attrs ⇒ same LP/AS/origin/MED/class).
    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 2))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let cands = query_fib_install_candidates(&tx, 2).await;
    assert_eq!(cands.len(), 1);
    let c = &cands[0];
    let nhs: Vec<IpAddr> = c.next_hops.iter().map(|n| n.next_hop).collect();
    assert_eq!(nhs.len(), 2, "both equal-cost next-hops installed");
    // best (lower peer addr tiebreak) is index 0
    assert_eq!(c.next_hops[0].next_hop, c.best.next_hop);
    assert!(nhs.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(nhs.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn fib_install_candidates_preserve_link_local_next_hop_scope() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let scope = NextHopScope {
        interface: Arc::from("eth1"),
        ifindex: 7,
    };
    let route = Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V6("fe80::1".parse().unwrap()),
        link_local_next_hop: Some("fe80::1".parse().unwrap()),
        next_hop_scope: Some(Box::new(scope.clone())),
        peer: IpAddr::V6("fe80::2".parse().unwrap()),
        attributes: Arc::new(vec![]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    tx.send(RibUpdate::RoutesReceived {
        peer: route.peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let cands = query_fib_install_candidates(&tx, 1).await;
    assert_eq!(cands.len(), 1);
    assert_eq!(cands[0].best.next_hop_scope.as_deref(), Some(&scope));
    assert_eq!(cands[0].next_hops[0].next_hop_scope, Some(scope));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn fib_install_candidates_keep_same_link_local_on_distinct_ifindexes() {
    // ADR-0069: two equal-cost routes whose next-hop is the same fe80::/10
    // address but reached over different interfaces are distinct forwarding
    // next-hops. The ECMP dedup keys on (next-hop, ifindex), so both must
    // install as ECMP rather than collapsing to one path on the bare address.
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let shared_nh = IpAddr::V6("fe80::1".parse().unwrap());
    let make_scoped = |ifname: &'static str, ifindex: u32, peer: &str| Route {
        prefix: Prefix::V4(prefix),
        next_hop: shared_nh,
        link_local_next_hop: Some("fe80::1".parse().unwrap()),
        next_hop_scope: Some(Box::new(NextHopScope {
            interface: Arc::from(ifname),
            ifindex,
        })),
        peer: IpAddr::V6(peer.parse().unwrap()),
        attributes: Arc::new(vec![]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    for route in [
        make_scoped("eth1", 7, "fe80::2"),
        make_scoped("eth2", 9, "fe80::3"),
    ] {
        tx.send(RibUpdate::RoutesReceived {
            peer: route.peer,
            announced: vec![route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

    let cands = query_fib_install_candidates(&tx, 2).await;
    assert_eq!(cands.len(), 1, "one prefix");
    let mut ifindexes: Vec<u32> = cands[0]
        .next_hops
        .iter()
        .filter_map(|nh| nh.next_hop_scope.as_ref().map(|scope| scope.ifindex))
        .collect();
    ifindexes.sort_unstable();
    assert_eq!(
        ifindexes,
        vec![7, 9],
        "same fe80:: next-hop on two ifindexes must install as two ECMP paths"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn fib_install_candidates_multipath_relax_groups_different_as_paths() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = Ipv4Addr::new(1, 0, 0, 1);
    let peer2 = Ipv4Addr::new(1, 0, 0, 2);
    // Same AS_PATH *length* (2), different ASNs: strict refuses to group, relax
    // (ADR-0066 multipath-relax) groups them as ECMP.
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer1),
        announced: vec![make_route_with_as_path(prefix, peer1, vec![65001, 65010])],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer2),
        announced: vec![make_route_with_as_path(prefix, peer2, vec![65001, 65020])],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Strict: exact AS_PATH required → only the best installs (1 next-hop).
    let strict = query_fib_install_candidates_relax(&tx, 2, false).await;
    assert_eq!(strict.len(), 1);
    assert_eq!(
        strict[0].next_hops.len(),
        1,
        "strict mode: different AS_PATHs do not group"
    );

    // Relax: equal-length AS_PATHs co-install (2 next-hops).
    let relaxed = query_fib_install_candidates_relax(&tx, 2, true).await;
    assert_eq!(relaxed.len(), 1);
    assert_eq!(
        relaxed[0].next_hops.len(),
        2,
        "multipath-relax: equal-length AS_PATHs group as ECMP"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Attach a Link Bandwidth Extended Community (bytes/second) to a route.
fn make_route_with_link_bw(
    prefix: Ipv4Prefix,
    peer: Ipv4Addr,
    asns: Vec<u32>,
    bw: Option<f32>,
) -> Route {
    let mut route = make_route_with_as_path(prefix, peer, asns);
    if let Some(bw) = bw {
        Arc::make_mut(&mut route.attributes).push(PathAttribute::ExtendedCommunities(vec![
            ExtendedCommunity::link_bandwidth(65001, bw),
        ]));
    }
    route
}

#[tokio::test]
async fn fib_install_candidates_weighted_proportional_to_link_bandwidth() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = Ipv4Addr::new(1, 0, 0, 1); // best (lowest peer), 40G
    let peer2 = Ipv4Addr::new(1, 0, 0, 2); // sibling, 10G
    for (peer, bw) in [(peer1, 40e9), (peer2, 10e9)] {
        tx.send(RibUpdate::RoutesReceived {
            peer: IpAddr::V4(peer),
            announced: vec![make_route_with_link_bw(
                prefix,
                peer,
                vec![65001, 65010],
                Some(bw),
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

    // Weighting on: 40G best maps to 256, the 10G sibling to 64 (ratio 1:4).
    let weighted = query_fib_install_candidates_weighted(&tx, 2, true).await;
    assert_eq!(weighted.len(), 1);
    let nhs = &weighted[0].next_hops;
    assert_eq!(nhs.len(), 2);
    assert_eq!(nhs[0].next_hop, IpAddr::V4(peer1));
    assert_eq!(nhs[0].weight, 256);
    assert_eq!(nhs[1].next_hop, IpAddr::V4(peer2));
    assert_eq!(nhs[1].weight, 64);

    // Weighting off: same group, every next-hop equal-cost (weight 1).
    let equal = query_fib_install_candidates_weighted(&tx, 2, false).await;
    assert!(equal[0].next_hops.iter().all(|nh| nh.weight == 1));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn fib_install_candidates_weighted_all_or_nothing_on_missing_bandwidth() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = Ipv4Addr::new(1, 0, 0, 1);
    let peer2 = Ipv4Addr::new(1, 0, 0, 2);
    // peer1 carries a Link Bandwidth community; peer2 does not.
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer1),
        announced: vec![make_route_with_link_bw(
            prefix,
            peer1,
            vec![65001, 65010],
            Some(40e9),
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer2),
        announced: vec![make_route_with_link_bw(
            prefix,
            peer2,
            vec![65001, 65010],
            None,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // A single path missing the community ⇒ the whole prefix stays equal-cost.
    let weighted = query_fib_install_candidates_weighted(&tx, 2, true).await;
    assert_eq!(weighted[0].next_hops.len(), 2);
    assert!(
        weighted[0].next_hops.iter().all(|nh| nh.weight == 1),
        "all-or-nothing: one missing bandwidth disables weighting for the group"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn fib_install_candidates_respects_max_paths() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    for (peer, nh) in [
        (
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            Ipv4Addr::new(10, 0, 0, 1),
        ),
        (
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2)),
            Ipv4Addr::new(10, 0, 0, 2),
        ),
    ] {
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, nh)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

    // max_paths=1 ⇒ single best next-hop only (today's behavior).
    let cands = query_fib_install_candidates(&tx, 1).await;
    assert_eq!(cands.len(), 1);
    assert_eq!(cands[0].next_hops.len(), 1);
    assert_eq!(cands[0].next_hops[0].next_hop, cands[0].best.next_hop);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn fib_install_candidates_dedupes_same_next_hop_before_cap() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let shared_nh = Ipv4Addr::new(10, 0, 0, 9);
    // Two peers advertising the SAME next-hop ⇒ collapses to one ECMP member.
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));
    let mut r1 = make_route(prefix, shared_nh);
    r1.peer = peer1;
    let mut r2 = make_route(prefix, shared_nh);
    r2.peer = peer2;
    tx.send(RibUpdate::RoutesReceived {
        peer: peer1,
        announced: vec![r1],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: peer2,
        announced: vec![r2],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let cands = query_fib_install_candidates(&tx, 2).await;
    assert_eq!(cands.len(), 1);
    assert_eq!(
        cands[0].next_hops.len(),
        1,
        "same next-hop deduped before cap"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn fib_install_candidates_excludes_non_equal_cost() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    // peer2 has higher LOCAL_PREF ⇒ it is the sole best; peer1 is not equal-cost.
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2)),
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let cands = query_fib_install_candidates(&tx, 4).await;
    assert_eq!(cands.len(), 1);
    assert_eq!(
        cands[0].next_hops.len(),
        1,
        "lower-LP path is not co-installed"
    );
    assert_eq!(cands[0].best.peer, IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2)));

    drop(tx);
    handle.await.unwrap();
}

// ── Outbound Route Filtering (ORF) — RFC 5291/5292 ──────────────────────

fn orf_permit(seq: u32, min: u8, max: u8, p: Ipv4Prefix) -> AddressPrefixOrf {
    AddressPrefixOrf {
        action: OrfAction::Add,
        match_: OrfMatch::Permit,
        sequence: seq,
        min_len: min,
        max_len: max,
        prefix: Some(Prefix::V4(p)),
    }
}

fn orf_deny(seq: u32, min: u8, max: u8, p: Ipv4Prefix) -> AddressPrefixOrf {
    AddressPrefixOrf {
        action: OrfAction::Add,
        match_: OrfMatch::Deny,
        sequence: seq,
        min_len: min,
        max_len: max,
        prefix: Some(Prefix::V4(p)),
    }
}

async fn send_peer_orf(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    when: WhenToRefresh,
    entries: Vec<AddressPrefixOrf>,
) {
    let (rtx, rrx) = oneshot::channel();
    tx.send(RibUpdate::PeerOrfUpdate {
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        when,
        entries,
        reply: rtx,
    })
    .await
    .unwrap();
    rrx.await.unwrap().unwrap();
}

/// Drain outbound updates until `count` prefixes have been announced.
async fn collect_announced(
    out_rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    count: usize,
) -> Vec<Prefix> {
    let mut prefixes = Vec::new();
    while prefixes.len() < count {
        let u = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("outbound update should arrive")
            .expect("outbound channel open");
        prefixes.extend(u.announce.iter().map(|r| r.prefix));
    }
    prefixes
}

/// Set up a manager with two routes (10/8, 192.168/16) in the Loc-RIB and a
/// gated ORF-receive target peer; returns the tx, the target peer, and the
/// target's outbound receiver after draining the (route-less) initial `EoR`.
async fn orf_setup() -> (
    mpsc::Sender<RibUpdate>,
    tokio::task::JoinHandle<()>,
    IpAddr,
    mpsc::Receiver<OutboundRouteUpdate>,
) {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::RoutesReceived {
        peer: source,
        announced: vec![
            make_route(
                Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8),
                Ipv4Addr::new(10, 0, 0, 1),
            ),
            make_route(
                Ipv4Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 16),
                Ipv4Addr::new(10, 0, 0, 1),
            ),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![(Afi::Ipv4, Safi::Unicast)],
    })
    .await
    .unwrap();

    // RFC 5291 §6 gate: the initial dump must advertise no routes for the
    // gated family — only the EoR marker.
    let initial = out_rx.recv().await.unwrap();
    assert!(
        initial.announce.is_empty(),
        "gated family must not advertise routes initially, got {}",
        initial.announce.len()
    );
    assert!(
        !initial.end_of_rib.is_empty(),
        "EoR still sent for gated family"
    );

    (tx, handle, target, out_rx)
}

#[tokio::test]
async fn orf_gate_lifts_and_floods_filtered_table() {
    let (tx, handle, target, mut out_rx) = orf_setup().await;

    // Permit everything (0/0 le 32) ⇒ gate lifts, both routes flood.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Immediate,
        vec![orf_permit(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0),
        )],
    )
    .await;
    let announced = collect_announced(&mut out_rx, 2).await;
    assert!(announced.contains(&Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))));
    assert!(announced.contains(&Prefix::V4(Ipv4Prefix::new(
        Ipv4Addr::new(192, 168, 0, 0),
        16
    ))));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn orf_filter_constrains_advertised_set() {
    let (tx, handle, target, mut out_rx) = orf_setup().await;

    // Permit only 10/8 (le 32); 192.168/16 is not covered ⇒ implicit deny.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Immediate,
        vec![orf_permit(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8),
        )],
    )
    .await;
    let announced = collect_announced(&mut out_rx, 1).await;
    assert_eq!(
        announced,
        vec![Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))]
    );
    // No further announce: 192.168/16 must stay filtered out.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), out_rx.recv())
            .await
            .is_err(),
        "192.168/16 must not be advertised under a 10/8-only ORF"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn orf_immediate_withdraws_now_denied_prefix() {
    let (tx, handle, target, mut out_rx) = orf_setup().await;

    // Gate-lift with permit-all → both advertised.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Immediate,
        vec![orf_permit(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0),
        )],
    )
    .await;
    let _ = collect_announced(&mut out_rx, 2).await;

    // Now tighten: permit only 10/8 (IMMEDIATE) → 192.168/16 must be withdrawn.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Immediate,
        vec![orf_permit(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8),
        )],
    )
    .await;
    let mut withdrawn = Vec::new();
    while withdrawn.is_empty() {
        let u = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("withdraw should arrive")
            .unwrap();
        withdrawn.extend(u.withdraw.iter().map(|(p, _)| *p));
    }
    assert!(withdrawn.contains(&Prefix::V4(Ipv4Prefix::new(
        Ipv4Addr::new(192, 168, 0, 0),
        16
    ))));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn orf_defer_does_not_sweep_existing_routes() {
    let (tx, handle, target, mut out_rx) = orf_setup().await;

    // Gate-lift with permit-all → both advertised.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Immediate,
        vec![orf_permit(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0),
        )],
    )
    .await;
    let _ = collect_announced(&mut out_rx, 2).await;

    // DEFER deny-all: filter installs, but the existing advertised routes are
    // NOT swept (RFC 5291 When-to-refresh). No outbound update should arrive.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Defer,
        vec![orf_deny(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0),
        )],
    )
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), out_rx.recv())
            .await
            .is_err(),
        "DEFER must not sweep already-advertised routes"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn orf_defer_then_plain_refresh_withdraws_now_denied_prefix() {
    let (tx, handle, target, mut out_rx) = orf_setup().await;

    // Gate-lift with permit-all → both advertised.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Immediate,
        vec![orf_permit(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0),
        )],
    )
    .await;
    let _ = collect_announced(&mut out_rx, 2).await;

    // Install a deferred filter that keeps 10/8 and denies everything else.
    // DEFER itself must not sweep.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Defer,
        vec![orf_permit(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8),
        )],
    )
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), out_rx.recv())
            .await
            .is_err(),
        "DEFER must not sweep already-advertised routes"
    );

    // A later plain ROUTE-REFRESH is the deferred sweep point: permitted routes
    // are re-advertised and previously-advertised routes denied by the installed
    // ORF must be explicitly withdrawn.
    tx.send(RibUpdate::RouteRefreshRequest {
        peer: target,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    let denied = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 16));
    let mut withdrawn = Vec::new();
    while withdrawn.is_empty() {
        let update = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("refresh response should arrive")
            .expect("outbound channel open");
        withdrawn.extend(update.withdraw.iter().map(|(p, _)| *p));
    }
    assert!(
        withdrawn.contains(&denied),
        "plain refresh after deferred ORF must withdraw the denied prefix"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Regression: a graceful-restart flap must clear the RFC 5291 §6
/// initial-advertisement gate. The gate is per-session; previously
/// `handle_peer_graceful_restart` left `peer_orf_pending` populated, so a
/// peer re-establishing WITHOUT ORF inherited the dead session's gate —
/// `send_initial_table` skipped the family and churn stayed suppressed,
/// advertising nothing indefinitely (the new session never negotiated ORF,
/// so it has no reason to send the ROUTE-REFRESH that lifts a gate).
#[tokio::test]
async fn graceful_restart_clears_stale_orf_gate() {
    // orf_setup leaves the target gated (ORF negotiated, no refresh yet).
    let (tx, handle, target, _out_rx) = orf_setup().await;

    tx.send(RibUpdate::PeerGracefulRestart {
        peer: target,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Re-establish WITHOUT ORF: the initial dump must carry the full table.
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
        negotiated_orf_recv: vec![],
    })
    .await
    .unwrap();

    let announced = collect_announced(&mut out_rx, 2).await;
    assert!(
        announced.contains(&Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))),
        "post-GR non-ORF session must receive the initial table (stale gate leak)"
    );
    assert!(announced.contains(&Prefix::V4(Ipv4Prefix::new(
        Ipv4Addr::new(192, 168, 0, 0),
        16
    ))));

    drop(tx);
    handle.await.unwrap();
}

/// Regression: a graceful-restart flap must clear the installed ORF filter
/// set. Previously `handle_peer_graceful_restart` left `peer_orf_filters`
/// populated, so a peer re-establishing WITHOUT ORF kept being filtered by
/// the dead session's prefix list — a ghost filter constraining routes the
/// new session never asked to filter.
#[tokio::test]
async fn graceful_restart_clears_orf_filter() {
    let (tx, handle, target, mut out_rx) = orf_setup().await;

    // First session installs a 10/8-only filter (lifts its gate too).
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Immediate,
        vec![orf_permit(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8),
        )],
    )
    .await;
    let announced = collect_announced(&mut out_rx, 1).await;
    assert_eq!(
        announced,
        vec![Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))]
    );

    tx.send(RibUpdate::PeerGracefulRestart {
        peer: target,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Re-establish WITHOUT ORF: both routes must flood — the dead session's
    // 10/8-only filter must not survive into the new session.
    let (out_tx, mut out_rx2) = mpsc::channel(64);
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
        negotiated_orf_recv: vec![],
    })
    .await
    .unwrap();

    let announced = collect_announced(&mut out_rx2, 2).await;
    assert!(announced.contains(&Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))));
    assert!(
        announced.contains(&Prefix::V4(Ipv4Prefix::new(
            Ipv4Addr::new(192, 168, 0, 0),
            16
        ))),
        "post-GR initial dump must carry the full table"
    );

    // The ghost filter bites on churn, not the initial dump (the initial
    // dump deliberately bypasses ORF filters): announce a fresh prefix the
    // dead session's 10/8-only filter would deny and assert it floods.
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        announced: vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12),
            Ipv4Addr::new(10, 0, 0, 1),
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let churned = collect_announced(&mut out_rx2, 1).await;
    assert_eq!(
        churned,
        vec![Prefix::V4(Ipv4Prefix::new(
            Ipv4Addr::new(172, 16, 0, 0),
            12
        ))],
        "post-GR non-ORF session must not inherit the dead session's filter"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Flap `target` into graceful restart (it becomes a GR RESTARTER we are
/// helping) and re-establish it with the given ORF-receive families; returns
/// the new session's outbound receiver.
async fn gr_flap_and_reup(
    tx: &mpsc::Sender<RibUpdate>,
    target: IpAddr,
    gr_families: Vec<(Afi, Safi)>,
    sendable_families: Vec<(Afi, Safi)>,
    negotiated_orf_recv: Vec<(Afi, Safi)>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    tx.send(RibUpdate::PeerGracefulRestart {
        peer: target,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families,
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let (out_tx, out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families,
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv,
    })
    .await
    .unwrap();
    out_rx
}

/// Drain outbound updates until one carries an `EoR` for `family`; return
/// every update seen, including the `EoR`-bearing one. Panics if no such
/// `EoR` arrives within 5 s.
async fn drain_until_eor(
    out_rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    family: (Afi, Safi),
) -> Vec<OutboundRouteUpdate> {
    let mut updates = Vec::new();
    loop {
        let update = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("EoR-bearing update should arrive")
            .expect("outbound channel open");
        let done = update.end_of_rib.contains(&family);
        updates.push(update);
        if done {
            return updates;
        }
    }
}

/// Prefixes announced across `updates`. Announces inside the `EoR`-bearing
/// update itself count as before-`EoR`: transport encodes a single update's
/// `EoR` markers after its route UPDATEs.
fn prefixes_announced(updates: &[OutboundRouteUpdate]) -> Vec<Prefix> {
    updates
        .iter()
        .flat_map(|u| u.announce.iter().map(|r| r.prefix))
        .collect()
}

/// A GR RESTARTER (RFC 4724) whose family is behind the RFC 5291 §6 ORF
/// initial-advertisement gate must NOT receive the immediate initial-table
/// `EoR`: the restarter takes `EoR` as "this peer's initial update is
/// complete", proceeds with route selection, and sweeps the stale routes it
/// retained from our previous session — before the gated flood has been
/// sent, a self-inflicted blackhole window. The `EoR` must instead follow
/// the gated flood once the gate lifts.
#[tokio::test]
async fn gr_restarter_defers_eor_for_orf_gated_family() {
    let (tx, handle, target, _old_rx) = orf_setup().await;
    let mut out_rx = gr_flap_and_reup(
        &tx,
        target,
        vec![(Afi::Ipv4, Safi::Unicast)],
        ipv4_sendable(),
        vec![(Afi::Ipv4, Safi::Unicast)],
    )
    .await;

    // Nothing — neither routes nor EoR — before the gate lifts.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), out_rx.recv())
            .await
            .is_err(),
        "GR restarter must not receive EoR while the family is still ORF-gated"
    );

    // Gate lifts via an IMMEDIATE ORF push: the filtered flood arrives with
    // the EoR ordered behind it.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Immediate,
        vec![orf_permit(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0),
        )],
    )
    .await;
    let updates = drain_until_eor(&mut out_rx, (Afi::Ipv4, Safi::Unicast)).await;
    let announced = prefixes_announced(&updates);
    assert!(
        announced.contains(&Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))),
        "gated flood must precede the deferred EoR"
    );
    assert!(announced.contains(&Prefix::V4(Ipv4Prefix::new(
        Ipv4Addr::new(192, 168, 0, 0),
        16
    ))));

    drop(tx);
    handle.await.unwrap();
}

/// Same deferral when the gate is lifted by a plain ROUTE-REFRESH carrying
/// no ORF payload: the refresh response is the gated flood, and the deferred
/// `EoR` follows it.
#[tokio::test]
async fn gr_restarter_deferred_eor_follows_plain_refresh_flood() {
    let (tx, handle, target, _old_rx) = orf_setup().await;
    let mut out_rx = gr_flap_and_reup(
        &tx,
        target,
        vec![(Afi::Ipv4, Safi::Unicast)],
        ipv4_sendable(),
        vec![(Afi::Ipv4, Safi::Unicast)],
    )
    .await;

    assert!(
        tokio::time::timeout(Duration::from_millis(200), out_rx.recv())
            .await
            .is_err(),
        "GR restarter must not receive EoR while the family is still ORF-gated"
    );

    tx.send(RibUpdate::RouteRefreshRequest {
        peer: target,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();

    let updates = drain_until_eor(&mut out_rx, (Afi::Ipv4, Safi::Unicast)).await;
    let announced = prefixes_announced(&updates);
    assert!(
        announced.contains(&Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))),
        "gated flood must precede the deferred EoR"
    );
    assert!(announced.contains(&Prefix::V4(Ipv4Prefix::new(
        Ipv4Addr::new(192, 168, 0, 0),
        16
    ))));

    drop(tx);
    handle.await.unwrap();
}

/// Two independently gated families lift independently: each family's
/// deferred `EoR` follows its OWN gate-lift flood, and a still-gated
/// family's `EoR` does not ride along.
#[tokio::test]
async fn gr_restarter_deferred_eor_lifts_per_family() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
    let v6_prefix = Ipv6Prefix::new("2001:db8:100::".parse().unwrap(), 64);
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        announced: vec![
            make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1)),
            make_v6_route(v6_prefix, "2001:db8::1".parse().unwrap()),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let both = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
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
        negotiated_orf_recv: both.clone(),
    })
    .await
    .unwrap();
    // First (non-GR) session: both families gated, immediate honest-empty EoR.
    let initial = out_rx.recv().await.unwrap();
    assert!(initial.announce.is_empty());
    assert!(!initial.end_of_rib.is_empty());

    let mut out_rx = gr_flap_and_reup(&tx, target, both.clone(), dual_stack_sendable(), both).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), out_rx.recv())
            .await
            .is_err(),
        "GR restarter must not receive EoR while both families are still gated"
    );

    // Lift IPv4 only: the v4 flood + v4 EoR arrive; the v6 EoR must wait.
    tx.send(RibUpdate::RouteRefreshRequest {
        peer: target,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let updates = drain_until_eor(&mut out_rx, (Afi::Ipv4, Safi::Unicast)).await;
    assert!(prefixes_announced(&updates).contains(&Prefix::V4(v4_prefix)));
    assert!(
        updates
            .iter()
            .all(|u| !u.end_of_rib.contains(&(Afi::Ipv6, Safi::Unicast))),
        "the still-gated family's EoR must wait for its own gate lift"
    );

    // Lift IPv6: its flood + EoR follow.
    tx.send(RibUpdate::RouteRefreshRequest {
        peer: target,
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let updates = drain_until_eor(&mut out_rx, (Afi::Ipv6, Safi::Unicast)).await;
    assert!(prefixes_announced(&updates).contains(&Prefix::V6(v6_prefix)));

    drop(tx);
    handle.await.unwrap();
}

/// Regression: a NON-GR ORF peer keeps today's immediate initial-table `EoR`
/// (an honest "empty table so far"). `orf_setup` itself asserts the initial
/// dump carries the `EoR` marker and no routes for the gated family — a
/// client that never sends ROUTE-REFRESH must still see `EoR`.
#[tokio::test]
async fn non_gr_orf_peer_keeps_immediate_initial_eor() {
    let (tx, handle, _target, _out_rx) = orf_setup().await;
    drop(tx);
    handle.await.unwrap();
}

/// Regression: a GR restarter WITHOUT ORF (no gate) keeps the immediate
/// initial dump and `EoR` — no ROUTE-REFRESH is needed.
#[tokio::test]
async fn gr_restarter_without_orf_keeps_immediate_eor() {
    let (tx, handle, target, _old_rx) = orf_setup().await;
    let mut out_rx = gr_flap_and_reup(
        &tx,
        target,
        vec![(Afi::Ipv4, Safi::Unicast)],
        ipv4_sendable(),
        vec![],
    )
    .await;

    // The EoR arrives on its own — no refresh is ever sent here — with the
    // full table ahead of it.
    let updates = drain_until_eor(&mut out_rx, (Afi::Ipv4, Safi::Unicast)).await;
    let announced = prefixes_announced(&updates);
    assert!(
        announced.contains(&Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))),
        "ungated GR restarter must receive the immediate initial table"
    );
    assert!(announced.contains(&Prefix::V4(Ipv4Prefix::new(
        Ipv4Addr::new(192, 168, 0, 0),
        16
    ))));

    drop(tx);
    handle.await.unwrap();
}

/// Peer down while an `EoR` deferral is outstanding must clear the deferral
/// (it is per-session state, torn down with the rest of
/// `clear_outbound_peer_state`).
#[tokio::test]
async fn peer_down_clears_gr_deferred_eor() {
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let family = (Afi::Ipv4, Safi::Unicast);

    // Session 1 (no ORF), then a GR flap.
    let (out_tx, _out_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
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
        negotiated_orf_recv: vec![],
    });
    manager.handle_update(RibUpdate::PeerGracefulRestart {
        peer,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![family],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });

    // Session 2: the restarter comes back with ORF — the deferral arms.
    let (out_tx2, _out_rx2) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx2,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![family],
    });
    assert!(
        manager
            .gr_deferred_eor
            .get(&peer)
            .is_some_and(|families| families.contains(&family)),
        "GR restarter with a gated family must have its EoR deferral armed"
    );

    // Peer down mid-deferral: the deferral must not leak into a later session.
    manager.handle_update(RibUpdate::PeerDown { peer });
    assert!(
        !manager.gr_deferred_eor.contains_key(&peer),
        "peer down must clear the outstanding EoR deferral"
    );
}

#[test]
fn test_ingest_stall_override_parse_rules() {
    // Unset → no stall.
    assert_eq!(test_ingest_stall_override(None), None);
    // Valid positive milliseconds → stall, whitespace tolerated.
    assert_eq!(
        test_ingest_stall_override(Some("1500")),
        Some(Duration::from_millis(1500))
    );
    assert_eq!(
        test_ingest_stall_override(Some(" 250 ")),
        Some(Duration::from_millis(250))
    );
    // Zero disables (a zero-length stall is not a stall).
    assert_eq!(test_ingest_stall_override(Some("0")), None);
    // Garbage and empty values disable rather than erroring.
    assert_eq!(test_ingest_stall_override(Some("")), None);
    assert_eq!(test_ingest_stall_override(Some("fast")), None);
    assert_eq!(test_ingest_stall_override(Some("-5")), None);
    assert_eq!(test_ingest_stall_override(Some("1.5")), None);
}

#[tokio::test]
async fn peer_deleted_reaps_metric_series_peer_down_does_not() {
    fn peer_series_count(metrics: &BgpMetrics, peer: &str) -> usize {
        metrics
            .registry()
            .gather()
            .iter()
            .flat_map(|family| family.get_metric().iter())
            .filter(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "peer" && label.value() == peer)
            })
            .count()
    }

    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    // Seed per-peer series the way the RIB emitters do (bare address).
    metrics.set_rib_prefixes("10.0.0.2", "ipv4_unicast", 42);
    metrics.set_gr_active("10.0.0.2", true);

    // A session flap: PeerDown zeroes / rewrites gauges but must keep
    // the label sets — the peer still exists.
    manager.handle_update(RibUpdate::PeerDown { peer });
    assert!(
        peer_series_count(&metrics, "10.0.0.2") > 0,
        "PeerDown must not remove the peer's label sets"
    );

    // A deletion: the PeerDeleted marker (queued by the peer manager
    // behind the session's PeerDown) removes the label sets entirely.
    manager.handle_update(RibUpdate::PeerDeleted { peer });
    assert_eq!(peer_series_count(&metrics, "10.0.0.2"), 0);

    // Re-deleting an already-reaped peer is a no-op (no panic).
    manager.handle_update(RibUpdate::PeerDeleted { peer });
    assert_eq!(peer_series_count(&metrics, "10.0.0.2"), 0);
}
