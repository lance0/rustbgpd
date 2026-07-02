use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustbgpd_wire::{
    AddressPrefixOrf, Afi, AsPath, AsPathSegment, EthernetSegmentIdentifier, EthernetTagId,
    EvpnImet, EvpnMacIp, EvpnRoute, ExtendedCommunity, Ipv4Prefix, Ipv6Prefix, MacAddress,
    MplsLabel, MplsLabelEntry, OrfAction, OrfMatch, Origin, PathAttribute, Prefix,
    RouteDistinguisher, RpkiValidation, Safi, VpnNlri, VpnPrefix, WhenToRefresh,
    bgpls::decode_bgpls_nlri,
};
use tokio::sync::oneshot;

use super::*;
use crate::event::RouteEventType;
use crate::route::{
    BgpLsFamily, BgpLsRibRoute, BgpLsRouteKey, EvpnRibRoute, FlowSpecRoute, NextHopScope, Route,
    VpnRibRoute,
};
use crate::test_support::{make_flowspec_route, make_route, make_route_with_lp, make_v6_route};

fn evpn_sendable() -> Vec<(Afi, Safi)> {
    vec![(Afi::L2Vpn, Safi::Evpn)]
}

fn bgpls_sendable() -> Vec<(Afi, Safi)> {
    vec![(Afi::BgpLs, Safi::BgpLs)]
}

fn deny_default_prefix_chain() -> rustbgpd_policy::PolicyChain {
    rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
        entries: vec![rustbgpd_policy::PolicyStatement {
            prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))),
            ge: None,
            le: None,
            action: rustbgpd_policy::PolicyAction::Deny,
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
            modifications: rustbgpd_policy::RouteModifications::default(),
        }],
        default_action: rustbgpd_policy::PolicyAction::Permit,
    }])
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

fn make_bgpls_route(peer: Ipv4Addr, payload_suffix: u8, local_pref: u32) -> BgpLsRibRoute {
    let nlri = decode_bgpls_nlri(&[0xfd, 0xe8, 0, 4, 0xde, 0xad, 0xbe, payload_suffix])
        .expect("fixture BGP-LS NLRI decodes")
        .pop()
        .expect("fixture contains one BGP-LS NLRI");
    BgpLsRibRoute {
        family: BgpLsFamily::LinkState,
        nlri,
        next_hop: IpAddr::V4(peer),
        peer: IpAddr::V4(peer),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::LocalPref(local_pref),
        ]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: peer,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    }
}

fn vpn_sendable() -> Vec<(Afi, Safi)> {
    vec![(Afi::Ipv4, Safi::MplsVpn)]
}

fn rtc_sendable() -> Vec<(Afi, Safi)> {
    vec![(Afi::Ipv4, Safi::RtConstrain)]
}

/// An RT-Constrain membership NLRI route from `peer`: interest in
/// `RT:65001:<local_admin>` at /96, origin AS 65001.
fn make_rtc_rib_route(
    peer: Ipv4Addr,
    local_admin: u16,
    local_pref: u32,
) -> crate::route::RtcRibRoute {
    let nlri =
        rustbgpd_wire::RtcNlri::new(65001, 0x0002_FDE9_0000_0000 | u64::from(local_admin), 96)
            .unwrap();
    crate::route::RtcRibRoute {
        nlri,
        next_hop: IpAddr::V4(peer),
        peer: IpAddr::V4(peer),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::LocalPref(local_pref),
        ]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: peer,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    }
}

/// A `VPNv4` route from `peer` with a distinct prefix octet, MPLS label, and
/// `LOCAL_PREF`. Same octet from two peers = same RIB key (labels are route
/// data, not identity).
fn make_vpn_rib_route(
    peer: Ipv4Addr,
    prefix_octet: u8,
    label: u32,
    local_pref: u32,
) -> VpnRibRoute {
    let nlri = VpnNlri {
        labels: vec![MplsLabelEntry::try_new(label, 0, true).unwrap()],
        route_distinguisher: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 1]),
        prefix: VpnPrefix::v4(Ipv4Addr::new(10, 0, prefix_octet, 0), 24).unwrap(),
    };
    VpnRibRoute {
        nlri,
        next_hop: IpAddr::V4(peer),
        peer: IpAddr::V4(peer),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::LocalPref(local_pref),
        ]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: peer,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
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

async fn query_bgpls_routes(tx: &mpsc::Sender<RibUpdate>) -> Vec<BgpLsRibRoute> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBgpLsRoutes { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap()
}

async fn query_orr_topology(tx: &mpsc::Sender<RibUpdate>) -> crate::orr::OrrTopologySnapshot {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryOrrTopology { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap()
}

async fn query_vpn_routes(tx: &mpsc::Sender<RibUpdate>) -> Vec<VpnRibRoute> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryVpnRoutes { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap()
}

async fn query_rtc_routes(tx: &mpsc::Sender<RibUpdate>) -> Vec<crate::route::RtcRibRoute> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryRtcRoutes { reply: reply_tx })
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
        session_id: 0,
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
async fn bgpls_routes_received_recompute_and_withdraw() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let first_advertiser = Ipv4Addr::new(10, 0, 0, 1);
    let better_advertiser = Ipv4Addr::new(10, 0, 0, 2);
    let first_peer = IpAddr::V4(first_advertiser);
    let better_peer = IpAddr::V4(better_advertiser);
    let route_a = make_bgpls_route(first_advertiser, 7, 100);
    let route_b = make_bgpls_route(better_advertiser, 7, 200);
    let key: BgpLsRouteKey = route_a.key();
    assert_eq!(route_b.key(), key);

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: first_peer,
        announced: vec![route_a],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let best_after_first = query_bgpls_routes(&tx).await;
    assert_eq!(best_after_first.len(), 1);
    assert_eq!(best_after_first[0].peer, first_peer);

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: better_peer,
        announced: vec![route_b],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let best_after_second = query_bgpls_routes(&tx).await;
    assert_eq!(best_after_second.len(), 1);
    assert_eq!(best_after_second[0].peer, better_peer);

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: better_peer,
        announced: vec![],
        withdrawn: vec![key.clone()],
    })
    .await
    .unwrap();

    let best_after_withdraw_b = query_bgpls_routes(&tx).await;
    assert_eq!(best_after_withdraw_b.len(), 1);
    assert_eq!(best_after_withdraw_b[0].peer, first_peer);

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: first_peer,
        announced: vec![],
        withdrawn: vec![key],
    })
    .await
    .unwrap();

    let best_after_withdraw_a = query_bgpls_routes(&tx).await;
    assert!(best_after_withdraw_a.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// The topology query builds from every peer's Adj-RIB-In union — NOT the
/// Loc-RIB best-only view. Two peers advertise disjoint links; the
/// snapshot must contain both.
#[tokio::test]
async fn query_topology_reflects_adj_rib_in_across_multiple_peers() {
    use crate::orr::fixtures::{A, B, X, Y, link_route};

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = Ipv4Addr::new(10, 0, 0, 1);
    let peer2 = Ipv4Addr::new(10, 0, 0, 2);
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer1),
        announced: vec![link_route(peer1, A, X, Some(1), &[])],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer2),
        announced: vec![link_route(peer2, B, Y, Some(1), &[])],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let snapshot = query_orr_topology(&tx).await;
    assert_eq!(
        snapshot.nodes.len(),
        4,
        "endpoints from both peers interned"
    );
    assert_eq!(
        snapshot.links.len(),
        2,
        "disjoint links from both peers kept"
    );
    assert!(snapshot.prefixes.is_empty());

    drop(tx);
    handle.await.unwrap();
}

async fn query_orr_status(tx: &mpsc::Sender<RibUpdate>) -> crate::orr::OrrStatusSnapshot {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryOrrStatus { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap()
}

/// Value of a label-less counter metric (0.0 when never incremented).
fn counter_metric_value(metrics: &BgpMetrics, name: &str) -> f64 {
    metrics
        .registry()
        .gather()
        .iter()
        .find(|family| family.name() == name)
        .and_then(|family| family.metric.first())
        .map_or(0.0, |metric| metric.get_counter().value())
}

/// Bring up an iBGP RR-client peer with the given ORR vantage and drain
/// its initial-table `EoR` so the channel starts empty.
async fn orr_client_peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    vantage: Option<IpAddr>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: vantage,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;
    out_rx
}

/// The arc-wide square topology, fed through the normal BGP-LS receive
/// path from `peer`.
async fn feed_square_topology(tx: &mpsc::Sender<RibUpdate>, peer: Ipv4Addr) {
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer),
        announced: crate::orr::fixtures::square_topology(peer),
        withdrawn: vec![],
    })
    .await
    .unwrap();
}

/// Interface address of fixture node A (`10.0.A.X`) — resolves to A.
fn vantage_at_node_a() -> IpAddr {
    use crate::orr::fixtures::{A, X};
    IpAddr::V4(Ipv4Addr::new(10, 0, A, X))
}

/// `PeerUp` with an `orr_vantage` registers the vantage (visible through
/// `QueryOrrStatus` and the topology gauges); tearing the peer down
/// clears the registry and empties the cached state again.
#[tokio::test]
async fn peer_up_registers_orr_vantage_and_teardown_clears() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let feed = Ipv4Addr::new(10, 9, 9, 9);
    feed_square_topology(&tx, feed).await;

    // Before any vantage: the cache is intentionally empty.
    let status = query_orr_status(&tx).await;
    assert!(status.vantages.is_empty());
    assert_eq!(status.topology_nodes, 0);

    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let _out_rx = orr_client_peer_up(&tx, client, Some(vantage_at_node_a())).await;

    let status = query_orr_status(&tx).await;
    assert_eq!(status.vantages.len(), 1);
    assert_eq!(status.vantages[0].vantage, vantage_at_node_a());
    assert!(status.vantages[0].resolved);
    assert_eq!(status.vantages[0].peers, vec![client]);
    assert_eq!(status.topology_nodes, 4);
    assert_eq!(status.topology_links, 4);
    assert!(
        (gauge_metric_value(&metrics, "bgp_orr_topology_nodes", &[]) - 4.0).abs() < f64::EPSILON
    );

    tx.send(RibUpdate::PeerDown {
        peer: client,
        session_id: 0,
    })
    .await
    .unwrap();

    let status = query_orr_status(&tx).await;
    assert!(
        status.vantages.is_empty(),
        "teardown clears the vantage registry"
    );
    assert_eq!(status.topology_nodes, 0, "cached state emptied");
    assert!(gauge_metric_value(&metrics, "bgp_orr_topology_nodes", &[]).abs() < f64::EPSILON);

    drop(tx);
    handle.await.unwrap();
}

/// `QueryOrrStatus` reports a resolved vantage (with node descriptors +
/// SPF reach) and an unresolved one (no node, zero reach) side by side,
/// sorted by vantage IP, with the unresolved gauge tracking.
#[tokio::test]
async fn orr_status_reports_resolved_and_unresolved_vantages() {
    use crate::orr::fixtures::A;

    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    feed_square_topology(&tx, Ipv4Addr::new(10, 9, 9, 9)).await;

    let client1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let client2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let outside = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let _out1 = orr_client_peer_up(&tx, client1, Some(vantage_at_node_a())).await;
    let _out2 = orr_client_peer_up(&tx, client2, Some(outside)).await;

    let status = query_orr_status(&tx).await;
    assert_eq!(status.vantages.len(), 2);
    // Sorted by vantage IP: 10.0.1.3 < 203.0.113.9.
    let resolved = &status.vantages[0];
    assert_eq!(resolved.vantage, vantage_at_node_a());
    assert!(resolved.resolved);
    assert!(!resolved.node_key_hex.is_empty());
    assert_eq!(resolved.asn, Some(64512));
    assert_eq!(resolved.router_id_hex, format!("00000000000{A:x}"));
    // From A the square reaches A, X, and Y — never B.
    assert_eq!(resolved.reachable_nodes, 3);
    assert_eq!(resolved.peers, vec![client1]);

    let unresolved = &status.vantages[1];
    assert_eq!(unresolved.vantage, outside);
    assert!(!unresolved.resolved);
    assert!(unresolved.node_key_hex.is_empty());
    assert_eq!(unresolved.reachable_nodes, 0);
    assert_eq!(unresolved.peers, vec![client2]);

    assert!(
        (gauge_metric_value(&metrics, "bgp_orr_unresolved_vantages", &[]) - 1.0).abs()
            < f64::EPSILON
    );

    drop(tx);
    handle.await.unwrap();
}

/// The cached SPF state rebuilds at the BGP-LS mutation seams — and the GR
/// stale window deliberately does NOT count as a mutation for the topology:
/// a vantage registered before any topology is unresolved, resolves when
/// BGP-LS routes arrive through the receive path, STAYS resolved while the
/// feed peer's routes are GR-preserved as stale (the ORR-stability
/// motivation — `iter_bgpls` keeps feeding stale entries to the topology),
/// and unresolves only when the GR timer expiry finally sweeps them.
#[tokio::test]
async fn bgpls_gr_stale_topology_keeps_orr_vantages_resolved() {
    tokio::time::pause();

    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let _out_rx = orr_client_peer_up(&tx, client, Some(vantage_at_node_a())).await;

    let status = query_orr_status(&tx).await;
    assert!(!status.vantages[0].resolved, "no topology yet");

    let feed = Ipv4Addr::new(10, 9, 9, 9);
    feed_square_topology(&tx, feed).await;

    let status = query_orr_status(&tx).await;
    assert!(
        status.vantages[0].resolved,
        "receive path rebuilt the cache"
    );
    assert_eq!(status.topology_nodes, 4);
    let runs_after_receive = counter_metric_value(&metrics, "bgp_orr_spf_runs_total");
    assert!(runs_after_receive >= 1.0, "SPF ran for the vantage");

    // GR entry with (BgpLs, BgpLs) in the capability preserves the feed
    // peer's routes as stale — the topology, and the vantage, must survive.
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: IpAddr::V4(feed),
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::BgpLs, Safi::BgpLs)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let status = query_orr_status(&tx).await;
    assert!(
        status.vantages[0].resolved,
        "GR-stale BGP-LS routes must keep feeding the topology"
    );
    assert_eq!(status.topology_nodes, 4);

    // GR timer expiry sweeps the stale routes — NOW the vantage unresolves.
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    let status = query_orr_status(&tx).await;
    assert!(
        !status.vantages[0].resolved,
        "GR expiry sweep rebuilt the cache against the emptied topology"
    );
    assert_eq!(status.topology_nodes, 0);

    drop(tx);
    handle.await.unwrap();
}

/// The early-out pin: with no vantage configured, BGP-LS churn (and even
/// an RR client without a vantage) never triggers a topology rebuild or
/// an SPF run — the `bgp_orr_spf_runs_total` counter stays at zero and
/// the topology gauges stay untouched.
#[tokio::test]
async fn no_vantage_configured_skips_topology_rebuild() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let _out_rx = orr_client_peer_up(&tx, client, None).await;

    // BGP-LS churn: announce, re-announce, withdraw.
    let feed = Ipv4Addr::new(10, 9, 9, 9);
    feed_square_topology(&tx, feed).await;
    feed_square_topology(&tx, feed).await;
    let keys: Vec<_> = crate::orr::fixtures::square_topology(feed)
        .iter()
        .map(crate::route::BgpLsRibRoute::key)
        .collect();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(feed),
        announced: vec![],
        withdrawn: keys,
    })
    .await
    .unwrap();

    // Sync point so all churn above has been processed.
    let status = query_orr_status(&tx).await;
    assert!(status.vantages.is_empty());
    assert!(
        counter_metric_value(&metrics, "bgp_orr_spf_runs_total").abs() < f64::EPSILON,
        "no SPF may run without a configured vantage"
    );
    assert!(gauge_metric_value(&metrics, "bgp_orr_topology_nodes", &[]).abs() < f64::EPSILON);

    drop(tx);
    handle.await.unwrap();
}

/// Collect the unicast staging stream (announce prefixes + withdraws per
/// update) an RR client sees for a fixed scenario, with or without an
/// ORR vantage configured on it.
async fn unicast_stream_with_vantage(vantage: Option<IpAddr>) -> Vec<(Vec<String>, Vec<String>)> {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // The BGP-LS topology is present in BOTH runs; the vantage config is
    // the only variable.
    feed_square_topology(&tx, Ipv4Addr::new(10, 9, 9, 9)).await;

    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = orr_client_peer_up(&tx, client, vantage).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
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
    // Sync point between the batches: without it the manager may
    // coalesce them (distribute-coalesce), making the CHUNKING of the
    // staged stream timing-dependent — this test compares two runs and
    // needs both paced identically.
    let _ = query_best_routes(&tx).await;
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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

    // Sync point: both batches processed and distributed.
    let _ = query_best_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let mut stream = Vec::new();
    while let Ok(update) = out_rx.try_recv() {
        // Order WITHIN one staged update is HashSet-iteration incidental;
        // sort so the comparison pins semantics, not hasher state.
        let mut announce: Vec<String> = update
            .announce
            .iter()
            .map(|r| r.prefix.to_string())
            .collect();
        announce.sort();
        let mut withdraw: Vec<String> =
            update.withdraw.iter().map(|(p, _)| p.to_string()).collect();
        withdraw.sort();
        stream.push((announce, withdraw));
    }
    stream
}

/// Distribution-switch pin: this scenario's next-hop lies OUTSIDE the
/// BGP-LS topology (unknown vantage cost) and each prefix has a single
/// candidate, so the per-vantage ORR path must stage output identical
/// to the standard path — a configured vantage may never perturb what
/// it cannot rank. (Originally the pre-switch "zero effect" guardrail;
/// still load-bearing as the unknown-cost/no-divergence pin.)
#[tokio::test]
async fn staged_output_identical_with_and_without_vantages() {
    let without = unicast_stream_with_vantage(None).await;
    let with = unicast_stream_with_vantage(Some(vantage_at_node_a())).await;
    assert!(
        !without.is_empty(),
        "scenario must actually stage unicast output"
    );
    assert_eq!(
        without, with,
        "a configured vantage must not change the staged unicast stream"
    );
}

// --- RFC 9107 ORR per-vantage best selection ---

/// Feed peer for the square topology (never registered for outbound).
const ORR_FEED: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 9);
/// iBGP source announcing via NH-X — lower peer address, so its route
/// is the standard Loc-RIB best when everything else ties.
const ORR_SRC_X: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// iBGP source announcing via NH-Y.
const ORR_SRC_Y: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);

/// Neighbor address of the A→X link — resolves to node X
/// (interior cost 1 from vantage A, 10 from vantage B).
fn orr_nh_x() -> IpAddr {
    use crate::orr::fixtures::{A, X};
    IpAddr::V4(Ipv4Addr::new(10, 0, X, A))
}

/// Neighbor address of the A→Y link — resolves to node Y
/// (interior cost 10 from vantage A, 1 from vantage B).
fn orr_nh_y() -> IpAddr {
    use crate::orr::fixtures::{A, Y};
    IpAddr::V4(Ipv4Addr::new(10, 0, Y, A))
}

/// Interface address of the B→X link (`10.0.B.X`) — resolves to B.
fn vantage_at_node_b() -> IpAddr {
    use crate::orr::fixtures::{B, X};
    IpAddr::V4(Ipv4Addr::new(10, 0, B, X))
}

/// The contested prefix of the divergence scenario.
fn orr_prefix() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24)
}

/// Adj-RIB-Out map key of the scenario prefix as a single best.
fn orr_prefix_key() -> (Prefix, u32) {
    (Prefix::V4(orr_prefix()), 0)
}

/// An iBGP-learned route for `prefix` from `peer` with the given
/// next-hop. Attributes are identical across sources so only the ORR
/// interior-cost step and the final peer-address tiebreak can decide.
fn ibgp_route(prefix: Ipv4Prefix, peer: Ipv4Addr, next_hop: IpAddr) -> Route {
    Route {
        prefix: Prefix::V4(prefix),
        next_hop,
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(peer),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::LocalPref(100),
        ]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: peer,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

/// An RR-mode manager (cluster id set, so iBGP-learned routes reflect
/// to clients) with the square topology already fed from `ORR_FEED`.
async fn orr_rr_manager() -> (mpsc::Sender<RibUpdate>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(10, 255, 0, 1)),
        BgpMetrics::new(),
    );
    let handle = tokio::spawn(manager.run());
    feed_square_topology(&tx, ORR_FEED).await;
    (tx, handle)
}

/// Announce unicast routes from `peer` (unregistered sources pass the
/// stale-session gate with session id 0).
async fn announce_unicast(tx: &mpsc::Sender<RibUpdate>, peer: Ipv4Addr, announced: Vec<Route>) {
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer),
        announced,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
}

/// The arc's divergence scenario: the SAME prefix from two iBGP sources
/// with next-hops at node X and node Y, followed by a sync point so both
/// batches are recomputed and distributed.
async fn announce_divergent_bests(tx: &mpsc::Sender<RibUpdate>) {
    announce_unicast(
        tx,
        ORR_SRC_X,
        vec![ibgp_route(orr_prefix(), ORR_SRC_X, orr_nh_x())],
    )
    .await;
    announce_unicast(
        tx,
        ORR_SRC_Y,
        vec![ibgp_route(orr_prefix(), ORR_SRC_Y, orr_nh_y())],
    )
    .await;
    let _ = query_best_routes(tx).await;
}

/// Drain every queued outbound update and fold to the final advertised
/// unicast state: `(prefix, path_id)` → the last announced route.
fn drain_final_unicast(
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
) -> HashMap<(Prefix, u32), Route> {
    let mut state = HashMap::new();
    while let Ok(update) = rx.try_recv() {
        for route in &update.announce {
            state.insert((route.prefix, route.path_id), route.clone());
        }
        for (prefix, path_id) in &update.withdraw {
            state.remove(&(*prefix, *path_id));
        }
    }
    state
}

/// THE arc's signature behavior: two RR clients bound to different
/// vantages receive DIVERGENT bests for the same prefix — each exits
/// via the next-hop closest to its own IGP location, not the RR's.
#[tokio::test]
async fn two_clients_different_vantages_receive_divergent_bests() {
    let (tx, handle) = orr_rr_manager().await;
    let client_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut out_a = orr_client_peer_up(&tx, client_a, Some(vantage_at_node_a())).await;
    let mut out_b = orr_client_peer_up(&tx, client_b, Some(vantage_at_node_b())).await;

    announce_divergent_bests(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_a = drain_final_unicast(&mut out_a);
    let final_b = drain_final_unicast(&mut out_b);
    assert_eq!(
        final_a.get(&orr_prefix_key()).map(|r| r.next_hop),
        Some(orr_nh_x()),
        "client at A exits via X (cost 1 < 10)"
    );
    assert_eq!(
        final_b.get(&orr_prefix_key()).map(|r| r.next_hop),
        Some(orr_nh_y()),
        "client at B exits via Y (cost 1 < 10)"
    );
}

/// A topology metric flip re-stages ONLY the peers bound to the vantage
/// whose SPF surface changed: the affected client's best flips, while
/// the other vantage's client and a non-ORR client see zero messages.
#[tokio::test]
async fn topology_metric_flip_marks_only_affected_vantage_peers_dirty_and_flips_best() {
    use crate::orr::fixtures::{A, X, link_route, v4_interface, v4_neighbor};

    let (tx, handle) = orr_rr_manager().await;
    let client_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let client_c = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let mut out_a = orr_client_peer_up(&tx, client_a, Some(vantage_at_node_a())).await;
    let mut out_b = orr_client_peer_up(&tx, client_b, Some(vantage_at_node_b())).await;
    let mut out_c = orr_client_peer_up(&tx, client_c, None).await;

    announce_divergent_bests(&tx).await;
    // Steady state reached — empty every channel before the flip.
    let _ = drain_final_unicast(&mut out_a);
    let _ = drain_final_unicast(&mut out_b);
    let _ = drain_final_unicast(&mut out_c);

    // Flip A→X to metric 100 (the SAME Link NLRI — identical descriptors
    // — so the entry is replaced, not duplicated). From A the SPF now
    // prefers Y (10 < 100); distances from B are untouched.
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(ORR_FEED),
        announced: vec![link_route(
            ORR_FEED,
            A,
            X,
            Some(100),
            &[
                v4_interface(Ipv4Addr::new(10, 0, A, X)),
                v4_neighbor(Ipv4Addr::new(10, 0, X, A)),
            ],
        )],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_a = drain_final_unicast(&mut out_a);
    assert_eq!(
        final_a.get(&orr_prefix_key()).map(|r| r.next_hop),
        Some(orr_nh_y()),
        "affected client flips to Y (cost 10 < 100)"
    );
    assert!(
        out_b.try_recv().is_err(),
        "unaffected vantage's client must see zero messages"
    );
    assert!(
        out_c.try_recv().is_err(),
        "non-ORR client must see zero messages"
    );
}

/// A vantage that does not resolve to a topology node silently falls
/// back to the standard single-best: the ORR client's advertisement is
/// identical to a vantage-less peer's.
#[tokio::test]
async fn unresolved_vantage_falls_back_to_loc_rib_best() {
    let (tx, handle) = orr_rr_manager().await;
    let orr_client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let plain_client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let outside = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let mut out_orr = orr_client_peer_up(&tx, orr_client, Some(outside)).await;
    let mut out_plain = orr_client_peer_up(&tx, plain_client, None).await;

    announce_divergent_bests(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_orr = drain_final_unicast(&mut out_orr);
    let final_plain = drain_final_unicast(&mut out_plain);
    let unresolved = final_orr
        .get(&orr_prefix_key())
        .expect("unresolved-vantage client is advertised the prefix");
    let plain = final_plain
        .get(&orr_prefix_key())
        .expect("vantage-less client is advertised the prefix");
    assert_eq!(unresolved.next_hop, orr_nh_x(), "the Loc-RIB best");
    assert_eq!(unresolved.next_hop, plain.next_hop);
    assert_eq!(unresolved.attributes, plain.attributes);
    assert_eq!(unresolved.peer, plain.peer);
    assert_eq!(unresolved.path_id, plain.path_id);
}

/// Withdrawing every BGP-LS link unresolves all vantages: ORR clients
/// revert to the standard best. The client whose vantage best already
/// matched it sees zero messages (equality suppression).
#[tokio::test]
async fn bgpls_withdrawal_of_all_links_reverts_orr_peers_to_standard_best() {
    let (tx, handle) = orr_rr_manager().await;
    let client_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut out_a = orr_client_peer_up(&tx, client_a, Some(vantage_at_node_a())).await;
    let mut out_b = orr_client_peer_up(&tx, client_b, Some(vantage_at_node_b())).await;

    announce_divergent_bests(&tx).await;
    let _ = drain_final_unicast(&mut out_a);
    let _ = drain_final_unicast(&mut out_b);

    let keys: Vec<BgpLsRouteKey> = crate::orr::fixtures::square_topology(ORR_FEED)
        .iter()
        .map(BgpLsRibRoute::key)
        .collect();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(ORR_FEED),
        announced: vec![],
        withdrawn: keys,
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_b = drain_final_unicast(&mut out_b);
    assert_eq!(
        final_b.get(&orr_prefix_key()).map(|r| r.next_hop),
        Some(orr_nh_x()),
        "client at B reverts from NH-Y to the standard best NH-X"
    );
    assert!(
        out_a.try_recv().is_err(),
        "client at A already held the standard best — zero messages"
    );
}

/// A client that establishes AFTER the routes and topology are in place
/// gets its per-vantage best in the initial table dump.
#[tokio::test]
async fn orr_client_initial_dump_gets_vantage_best() {
    let (tx, handle) = orr_rr_manager().await;
    announce_divergent_bests(&tx).await;

    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let (out_tx, mut out_b) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: client_b,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: Some(vantage_at_node_b()),
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_b = drain_final_unicast(&mut out_b);
    assert_eq!(
        final_b.get(&orr_prefix_key()).map(|r| r.next_hop),
        Some(orr_nh_y()),
        "initial dump carries the vantage best, not the Loc-RIB best"
    );
}

/// A ROUTE-REFRESH replay re-derives the same per-vantage best the live
/// distribution path sent.
#[tokio::test]
async fn route_refresh_replays_vantage_best() {
    let (tx, handle) = orr_rr_manager().await;
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut out_b = orr_client_peer_up(&tx, client_b, Some(vantage_at_node_b())).await;

    announce_divergent_bests(&tx).await;
    let _ = drain_final_unicast(&mut out_b);

    tx.send(RibUpdate::RouteRefreshRequest {
        peer: client_b,
        session_id: 0,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let _ = query_best_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_b = drain_final_unicast(&mut out_b);
    let replayed = final_b
        .get(&orr_prefix_key())
        .expect("refresh replays the prefix (empty refresh view forces a re-emit)");
    assert_eq!(
        replayed.next_hop,
        orr_nh_y(),
        "the replay is the vantage best"
    );
}

/// `ExplainAdvertisedRoute` for an ORR-bound peer surfaces the vantage,
/// every candidate with its interior cost (ranked per-vantage best
/// first, unknown-cost last per RFC 9107 §3.1), and the decisive
/// interior-cost reason with the compared costs.
#[tokio::test]
async fn explain_advertised_route_reports_orr_vantage_and_costs() {
    let (tx, handle) = orr_rr_manager().await;
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let _out_b = orr_client_peer_up(&tx, client_b, Some(vantage_at_node_b())).await;

    announce_divergent_bests(&tx).await;
    // A third source whose next-hop resolves nowhere in the topology —
    // unknown cost, must rank least preferred.
    let src_unknown = Ipv4Addr::new(192, 0, 2, 3);
    let nh_unknown = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99));
    announce_unicast(
        &tx,
        src_unknown,
        vec![ibgp_route(orr_prefix(), src_unknown, nh_unknown)],
    )
    .await;

    let explain = query_explain_advertised_route(&tx, client_b, Prefix::V4(orr_prefix())).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Advertise);
    assert_eq!(
        explain.next_hop,
        Some(orr_nh_y()),
        "vantage B's best exits via Y, not the Loc-RIB best via X"
    );
    assert_eq!(explain.orr_vantage, Some(vantage_at_node_b()));

    let candidates = &explain.orr_candidates;
    assert_eq!(candidates.len(), 3, "all surviving candidates listed");
    assert_eq!(candidates[0].next_hop, orr_nh_y());
    assert_eq!(candidates[0].cost, Some(1));
    assert!(candidates[0].selected);
    assert_eq!(candidates[1].next_hop, orr_nh_x());
    assert_eq!(candidates[1].cost, Some(10));
    assert!(!candidates[1].selected);
    assert_eq!(
        candidates[2].next_hop, nh_unknown,
        "unknown-cost candidate ranks last (RFC 9107 §3.1)"
    );
    assert_eq!(candidates[2].cost, None);
    assert!(!candidates[2].selected);

    let orr_reason = explain
        .reasons
        .iter()
        .find(|reason| reason.code == "orr_interior_cost")
        .expect("interior-cost step decided the winner");
    assert!(
        orr_reason.message.contains("orr_cost 1 < 10"),
        "compared vantage costs rendered: {}",
        orr_reason.message
    );

    drop(tx);
    handle.await.unwrap();
}

/// Regression: a peer with NO ORR vantage gets the pre-ORR explain
/// shape in the same scenario — Loc-RIB best, no vantage, no candidate
/// list, no ORR reason codes.
#[tokio::test]
async fn explain_advertised_route_non_orr_peer_unchanged() {
    let (tx, handle) = orr_rr_manager().await;
    let plain_client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let _out = orr_client_peer_up(&tx, plain_client, None).await;

    announce_divergent_bests(&tx).await;

    let explain = query_explain_advertised_route(&tx, plain_client, Prefix::V4(orr_prefix())).await;
    assert_eq!(explain.decision, crate::update::ExplainDecision::Advertise);
    assert_eq!(
        explain.next_hop,
        Some(orr_nh_x()),
        "non-ORR peer explains the Loc-RIB best"
    );
    assert_eq!(explain.orr_vantage, None);
    assert!(explain.orr_candidates.is_empty());
    assert!(
        explain
            .reasons
            .iter()
            .all(|reason| !reason.code.starts_with("orr")),
        "no ORR reasons on a non-ORR explain"
    );

    drop(tx);
    handle.await.unwrap();
}

/// An ORR peer whose vantage-visible candidate set is empty (the only
/// path came from the peer itself) explains as no-candidate instead of
/// leaking the split-horizon-suppressed route.
#[tokio::test]
async fn explain_advertised_route_orr_no_surviving_candidate() {
    let (tx, handle) = orr_rr_manager().await;
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let client_b_v4 = Ipv4Addr::new(10, 0, 0, 3);
    let _out_b = orr_client_peer_up(&tx, client_b, Some(vantage_at_node_b())).await;

    // The only path is client B's own announcement.
    announce_unicast(
        &tx,
        client_b_v4,
        vec![ibgp_route(orr_prefix(), client_b_v4, orr_nh_x())],
    )
    .await;

    let explain = query_explain_advertised_route(&tx, client_b, Prefix::V4(orr_prefix())).await;
    assert_eq!(
        explain.decision,
        crate::update::ExplainDecision::NoBestRoute
    );
    assert_eq!(explain.orr_vantage, Some(vantage_at_node_b()));
    assert!(explain.orr_candidates.is_empty());
    assert_eq!(explain.reasons[0].code, "no_orr_candidate");

    drop(tx);
    handle.await.unwrap();
}

/// Split horizon and RFC 4456 reflection suppression run BEFORE the ORR
/// ranking: a cost-0 candidate the target must not receive can never
/// win.
#[tokio::test]
async fn split_horizon_and_rr_suppression_apply_before_orr_ranking() {
    let (tx, handle) = orr_rr_manager().await;
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let client_b_v4 = Ipv4Addr::new(10, 0, 0, 3);
    let mut out_b = orr_client_peer_up(&tx, client_b, Some(vantage_at_node_b())).await;

    // A non-client iBGP peer bound to the same vantage. (Config
    // validation rejects orr_vantage without rr-client; the RIB layer
    // trusts PeerUp, and the suppression seam must hold regardless.)
    let peer_d = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let (out_tx_d, mut out_d) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: peer_d,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx_d,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: Some(vantage_at_node_b()),
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_d).await;

    // prefix1 — split-horizon probe: client B's OWN route has interior
    // cost 0 (next-hop at its vantage node); a non-client source offers
    // cost 10 via NH-X.
    let prefix1 = orr_prefix();
    announce_unicast(
        &tx,
        client_b_v4,
        vec![ibgp_route(prefix1, client_b_v4, vantage_at_node_b())],
    )
    .await;
    announce_unicast(
        &tx,
        ORR_SRC_X,
        vec![ibgp_route(prefix1, ORR_SRC_X, orr_nh_x())],
    )
    .await;

    // prefix2 — RR-suppression probe: the cost-0 candidate comes from a
    // NON-client (never reflectable to the non-client target D); client
    // B offers cost 10 via NH-X (client routes reflect to everyone).
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 101, 0), 24);
    announce_unicast(
        &tx,
        ORR_SRC_Y,
        vec![ibgp_route(prefix2, ORR_SRC_Y, vantage_at_node_b())],
    )
    .await;
    announce_unicast(
        &tx,
        client_b_v4,
        vec![ibgp_route(prefix2, client_b_v4, orr_nh_x())],
    )
    .await;

    let _ = query_best_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_b = drain_final_unicast(&mut out_b);
    assert_eq!(
        final_b.get(&(Prefix::V4(prefix1), 0)).map(|r| r.next_hop),
        Some(orr_nh_x()),
        "the target's own cost-0 route is split-horizoned before ranking"
    );
    let final_d = drain_final_unicast(&mut out_d);
    assert_eq!(
        final_d.get(&(Prefix::V4(prefix2), 0)).map(|r| r.next_hop),
        Some(orr_nh_x()),
        "the cost-0 non-client candidate is RR-suppressed before ranking"
    );
}

/// Add-Path send to an ORR peer ranks the advertised paths by the
/// vantage's interior cost (comparator swap in the multipath sort):
/// path id 1 is the vantage-closest exit, not the standard-chain
/// winner.
#[tokio::test]
async fn orr_with_addpath_send_ranks_by_vantage_cost() {
    let (tx, handle) = orr_rr_manager().await;
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let (out_tx, mut out_b) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: client_b,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: Some(vantage_at_node_b()),
        add_path_send_families: vec![(Afi::Ipv4, Safi::Unicast)],
        add_path_send_max: 2,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_b).await;

    announce_divergent_bests(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_b = drain_final_unicast(&mut out_b);
    // Standard ranking would put NH-X first (lower peer address); from
    // vantage B the costs are Y=1, X=10 — the ORR comparator must rank
    // NH-Y as path 1.
    assert_eq!(
        final_b
            .get(&(Prefix::V4(orr_prefix()), 1))
            .map(|r| r.next_hop),
        Some(orr_nh_y()),
        "rank 1 is the vantage-closest path"
    );
    assert_eq!(
        final_b
            .get(&(Prefix::V4(orr_prefix()), 2))
            .map(|r| r.next_hop),
        Some(orr_nh_x()),
        "rank 2 is the vantage-farther path"
    );
}

#[tokio::test]
async fn bgpls_routes_received_reflects_and_withdraws_to_eligible_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: bgpls_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100);
    let key = route.key();

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route.clone()],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert!(update.withdraw.is_empty());
    assert_eq!(update.bgpls_announce.len(), 1);
    assert_eq!(update.bgpls_announce[0].key(), key);
    assert!(update.bgpls_withdraw.is_empty());

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![key.clone()],
    })
    .await
    .unwrap();

    let withdraw = out_rx.recv().await.unwrap();
    assert!(withdraw.bgpls_announce.is_empty());
    assert_eq!(withdraw.bgpls_withdraw, vec![key]);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn bgpls_export_policy_does_not_match_dummy_default_prefix() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: Some(deny_default_prefix_chain()),
        sendable_families: bgpls_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 36, 100);
    let key = route.key();

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert_eq!(
        update.bgpls_announce.len(),
        1,
        "BGP-LS topology NLRIs are prefixless and must not match 0.0.0.0/0 policy"
    );
    assert_eq!(update.bgpls_announce[0].key(), key);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn bgpls_routes_received_does_not_reflect_back_to_source_peer() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (source_out_tx, mut source_out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_out_tx,
        export_policy: None,
        sendable_families: bgpls_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut source_out_rx).await;

    let (other_out_tx, mut other_out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: other,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: other_out_tx,
        export_policy: None,
        sendable_families: bgpls_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut other_out_rx).await;

    let route = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 32, 100);
    let key = route.key();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let reflected = other_out_rx.recv().await.unwrap();
    assert_eq!(reflected.bgpls_announce.len(), 1);
    assert_eq!(reflected.bgpls_announce[0].key(), key);

    let source_self_echo =
        tokio::time::timeout(Duration::from_millis(50), source_out_rx.recv()).await;
    assert!(
        source_self_echo.is_err(),
        "BGP-LS routes must not be reflected back to the source peer"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn bgpls_routes_received_does_not_reflect_to_unsendable_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        announced: vec![make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 32, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let no_update = tokio::time::timeout(Duration::from_millis(50), out_rx.recv()).await;
    assert!(
        no_update.is_err(),
        "peer without BGP-LS in sendable_families must not receive reflected routes"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn dirty_resync_includes_bgpls_routes_after_channel_full() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (out_tx, mut out_rx) = mpsc::channel(1);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: bgpls_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let route1 = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 34, 100);
    let key1 = route1.key();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route1],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let route2 = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 35, 100);
    let key2 = route2.key();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route2],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let first = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("first BGP-LS announce must arrive")
        .expect("channel open");
    assert_eq!(first.bgpls_announce.len(), 1);
    assert_eq!(first.bgpls_announce[0].key(), key1);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut saw_key2 = false;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), out_rx.recv()).await {
            Ok(Some(update)) => {
                if update
                    .bgpls_announce
                    .iter()
                    .any(|route| route.key() == key2)
                {
                    saw_key2 = true;
                    break;
                }
            }
            Ok(None) => panic!("outbound channel closed unexpectedly"),
            Err(_) => {}
        }
    }
    assert!(
        saw_key2,
        "dirty resync must eventually deliver the second BGP-LS announce to the target peer"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn send_initial_table_includes_bgpls_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 33, 100);
    let key = route.key();

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: bgpls_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert_eq!(update.bgpls_announce.len(), 1);
    assert_eq!(update.bgpls_announce[0].key(), key);
    assert!(update.bgpls_withdraw.is_empty());

    let eor = out_rx.recv().await.unwrap();
    assert_eq!(eor.end_of_rib, bgpls_sendable());

    drop(tx);
    handle.await.unwrap();
}

/// A peer going down must drop its BGP-LS routes from the Loc-RIB the same way
/// unicast/FlowSpec/EVPN do — otherwise the entries strand until process
/// restart and `QueryBgpLsRoutes`/`ListBgpLsRoutes` keep reporting a dead
/// peer's routes as live. Two peers advertise the same key so we can assert the
/// Loc-RIB *falls back* to the surviving peer on the first teardown, then
/// *empties* on the second.
#[tokio::test]
async fn bgpls_peer_down_clears_or_falls_back_loc_rib() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let best_advertiser = Ipv4Addr::new(10, 0, 0, 1);
    let alternate_advertiser = Ipv4Addr::new(10, 0, 0, 2);
    let best_peer = IpAddr::V4(best_advertiser);
    let alternate_peer = IpAddr::V4(alternate_advertiser);

    // Same opaque key (same NLRI payload suffix), different LOCAL_PREF so the
    // tie-break has a defined winner: peer A (200) beats peer B (100).
    let route_a = make_bgpls_route(best_advertiser, 9, 200);
    let route_b = make_bgpls_route(alternate_advertiser, 9, 100);
    let key: BgpLsRouteKey = route_a.key();
    assert_eq!(route_b.key(), key);

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: best_peer,
        announced: vec![route_a],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: alternate_peer,
        announced: vec![route_b],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let best_before = query_bgpls_routes(&tx).await;
    assert_eq!(best_before.len(), 1);
    assert_eq!(
        best_before[0].peer, best_peer,
        "higher LOCAL_PREF peer should win before teardown"
    );

    // Tear down the winner — the Loc-RIB must fall back to the surviving peer.
    tx.send(RibUpdate::PeerDown {
        peer: best_peer,
        session_id: 0,
    })
    .await
    .unwrap();

    let after_winner_down = query_bgpls_routes(&tx).await;
    assert_eq!(
        after_winner_down.len(),
        1,
        "Loc-RIB must fall back to the surviving peer, not strand the dead peer's route"
    );
    assert_eq!(
        after_winner_down[0].peer, alternate_peer,
        "surviving peer's route should be selected after the winner goes down"
    );

    // Tear down the last advertiser — the key must leave the Loc-RIB entirely.
    tx.send(RibUpdate::PeerDown {
        peer: alternate_peer,
        session_id: 0,
    })
    .await
    .unwrap();

    let after_last_down = query_bgpls_routes(&tx).await;
    assert!(
        after_last_down.is_empty(),
        "Loc-RIB must be empty once no peer advertises the BGP-LS key"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A peer entering GR with (`BgpLs`, `BgpLs`) in its capability keeps its
/// BGP-LS objects as stale (RFC 4724 helper retention). Staleness demotes
/// the tiebreak rank, so a fresh route from another peer takes over the
/// Loc-RIB; when every advertiser is stale, the normal tiebreak order
/// re-applies among the stale candidates and the key stays visible.
#[tokio::test]
async fn bgpls_gr_marks_stale_and_demotes_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let best_advertiser = Ipv4Addr::new(10, 0, 0, 1);
    let alternate_advertiser = Ipv4Addr::new(10, 0, 0, 2);
    let best_peer = IpAddr::V4(best_advertiser);
    let alternate_peer = IpAddr::V4(alternate_advertiser);

    let route_a = make_bgpls_route(best_advertiser, 10, 200);
    let route_b = make_bgpls_route(alternate_advertiser, 10, 100);
    assert_eq!(route_a.key(), route_b.key());

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: best_peer,
        announced: vec![route_a],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: alternate_peer,
        announced: vec![route_b],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let best_before = query_bgpls_routes(&tx).await;
    assert_eq!(best_before.len(), 1);
    assert_eq!(best_before[0].peer, best_peer);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: best_peer,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::BgpLs, Safi::BgpLs)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let after_winner_gr = query_bgpls_routes(&tx).await;
    assert_eq!(after_winner_gr.len(), 1);
    assert_eq!(
        after_winner_gr[0].peer, alternate_peer,
        "stale demotion must hand the Loc-RIB to the fresh alternate route"
    );
    assert!(!after_winner_gr[0].is_stale);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: alternate_peer,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::BgpLs, Safi::BgpLs)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let after_last_gr = query_bgpls_routes(&tx).await;
    assert_eq!(
        after_last_gr.len(),
        1,
        "GR must retain the stale BGP-LS route instead of dropping the key"
    );
    assert_eq!(
        after_last_gr[0].peer, best_peer,
        "with both candidates stale the normal tiebreak (higher LOCAL_PREF) re-applies"
    );
    assert!(after_last_gr[0].is_stale);

    drop(tx);
    handle.await.unwrap();
}

/// A peer whose GR capability does NOT list (`BgpLs`, `BgpLs`) must have its
/// BGP-LS routes withdrawn on GR entry — RFC 4724 retains only families in
/// the advertised capability.
#[tokio::test]
async fn bgpls_gr_family_not_in_capability_is_withdrawn() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let advertiser = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(advertiser);
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_bgpls_route(advertiser, 10, 200)],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    assert_eq!(query_bgpls_routes(&tx).await.len(), 1);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
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

    assert!(
        query_bgpls_routes(&tx).await.is_empty(),
        "BGP-LS absent from the GR capability must be withdrawn, not retained stale"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Re-advertisement during the restart window replaces the stale route;
/// End-of-RIB clears the survivors' stale flags and removes what was not
/// re-advertised (RFC 4724 §4.1).
#[tokio::test]
async fn bgpls_gr_eor_clears_stale() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let advertiser = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(advertiser);
    let kept = make_bgpls_route(advertiser, 10, 200);
    let dropped = make_bgpls_route(advertiser, 20, 200);
    let kept_key = kept.key();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![kept.clone(), dropped],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::BgpLs, Safi::BgpLs)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();
    let stale = query_bgpls_routes(&tx).await;
    assert_eq!(stale.len(), 2);
    assert!(stale.iter().all(|r| r.is_stale));

    // Only `kept` is re-advertised before End-of-RIB.
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![kept],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer,
        afi: Afi::BgpLs,
        safi: Safi::BgpLs,
    })
    .await
    .unwrap();

    let after_eor = query_bgpls_routes(&tx).await;
    assert_eq!(
        after_eor.len(),
        1,
        "the non-readvertised stale route must be removed at End-of-RIB"
    );
    assert_eq!(after_eor[0].key(), kept_key);
    assert!(!after_eor[0].is_stale, "EoR must clear the stale flag");

    drop(tx);
    handle.await.unwrap();
}

/// GR timer expiry without LLGR purges the stale BGP-LS routes.
#[tokio::test]
async fn bgpls_gr_timer_sweeps_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let advertiser = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(advertiser);
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_bgpls_route(advertiser, 10, 200)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::BgpLs, Safi::BgpLs)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();
    let stale = query_bgpls_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    assert!(
        query_bgpls_routes(&tx).await.is_empty(),
        "GR timer expiry must sweep stale BGP-LS routes"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A second GR entry while routes are still stale (consecutive restart
/// without a refresh in between) deletes them instead of re-marking
/// (RFC 4724 §4.1), and the deletion propagates to the Loc-RIB.
#[tokio::test]
async fn bgpls_gr_consecutive_restart_deletes_stale_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let advertiser = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(advertiser);
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_bgpls_route(advertiser, 10, 200)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let gr_entry = |session_id| RibUpdate::PeerGracefulRestart {
        session_id,
        peer,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::BgpLs, Safi::BgpLs)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    };
    tx.send(gr_entry(0)).await.unwrap();
    let stale = query_bgpls_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    // The peer comes back and restarts again without re-advertising.
    tx.send(gr_entry(0)).await.unwrap();
    assert!(
        query_bgpls_routes(&tx).await.is_empty(),
        "a route still stale at the next restart must be deleted, not re-marked"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A peer entering GR with (IPv4, `MplsVpn`) in its capability keeps its VPN
/// routes as stale. Staleness demotes the tiebreak rank, so a fresh route
/// from another peer takes over; with every candidate stale the normal
/// tiebreak re-applies and the key stays reflected.
#[tokio::test]
async fn vpn_gr_marks_stale_and_demotes_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let best_advertiser = Ipv4Addr::new(10, 0, 0, 1);
    let alternate_advertiser = Ipv4Addr::new(10, 0, 0, 3);
    let best_peer = IpAddr::V4(best_advertiser);
    let alternate_peer = IpAddr::V4(alternate_advertiser);

    // Same RD + prefix (octet) from both peers ⇒ same RIB key.
    let route_a = make_vpn_rib_route(best_advertiser, 31, 100, 200);
    let route_b = make_vpn_rib_route(alternate_advertiser, 31, 200, 100);
    assert_eq!(route_a.key(), route_b.key());
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: best_peer,
        announced: vec![route_a],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: alternate_peer,
        announced: vec![route_b],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let best_before = query_vpn_routes(&tx).await;
    assert_eq!(best_before.len(), 1);
    assert_eq!(best_before[0].peer, best_peer);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: best_peer,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::MplsVpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let after_winner_gr = query_vpn_routes(&tx).await;
    assert_eq!(after_winner_gr.len(), 1);
    assert_eq!(
        after_winner_gr[0].peer, alternate_peer,
        "stale demotion must hand the Loc-RIB to the fresh alternate route"
    );
    assert!(!after_winner_gr[0].is_stale);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: alternate_peer,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::MplsVpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let after_last_gr = query_vpn_routes(&tx).await;
    assert_eq!(
        after_last_gr.len(),
        1,
        "GR must retain the stale VPN route instead of dropping the key"
    );
    assert_eq!(
        after_last_gr[0].peer, best_peer,
        "with both candidates stale the normal tiebreak (higher LOCAL_PREF) re-applies"
    );
    assert!(after_last_gr[0].is_stale);

    drop(tx);
    handle.await.unwrap();
}

/// A peer whose GR capability does NOT list (IPv4, `MplsVpn`) must have its
/// VPN routes withdrawn on GR entry and the withdrawal staged downstream.
#[tokio::test]
async fn vpn_gr_family_not_in_capability_is_withdrawn() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vpn_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100);
    let key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.vpn_announce.len(), 1);

    // GR capability carries only unicast: VPN is withdrawn, not retained.
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
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

    let withdraw = out_rx.recv().await.unwrap();
    assert_eq!(
        withdraw.vpn_withdraw,
        vec![key],
        "GR entry must withdraw VPN routes absent from the capability"
    );
    assert!(
        query_vpn_routes(&tx).await.is_empty(),
        "VPN absent from the GR capability must not be retained stale"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Re-advertisement during the restart window replaces the stale VPN route;
/// End-of-RIB clears the survivor's stale flag and removes (and withdraws
/// downstream) what was not re-advertised (RFC 4724 §4.1).
#[tokio::test]
async fn vpn_gr_eor_clears_stale() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vpn_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 60, 100, 100);
    let dropped = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 61, 100, 100);
    let kept_key = kept.key();
    let dropped_key = dropped.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept.clone(), dropped],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.vpn_announce.len(), 2);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::MplsVpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();
    let stale = query_vpn_routes(&tx).await;
    assert_eq!(stale.len(), 2);
    assert!(stale.iter().all(|r| r.is_stale));

    // Only `kept` is re-advertised before End-of-RIB.
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();

    let after_eor = query_vpn_routes(&tx).await;
    assert_eq!(
        after_eor.len(),
        1,
        "the non-readvertised stale VPN route must be removed at End-of-RIB"
    );
    assert_eq!(after_eor[0].key(), kept_key);
    assert!(!after_eor[0].is_stale, "EoR must clear the stale flag");

    // The removal must be withdrawn downstream.
    loop {
        let update = out_rx.recv().await.unwrap();
        if update.vpn_withdraw.is_empty() {
            continue;
        }
        assert_eq!(update.vpn_withdraw, vec![dropped_key.clone()]);
        break;
    }

    drop(tx);
    handle.await.unwrap();
}

/// GR timer expiry without LLGR purges the stale VPN routes.
#[tokio::test]
async fn vpn_gr_timer_sweeps_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::Ipv4, Safi::MplsVpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();
    let stale = query_vpn_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    assert!(
        query_vpn_routes(&tx).await.is_empty(),
        "GR timer expiry must sweep stale VPN routes"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A second GR entry while VPN routes are still stale deletes them
/// (RFC 4724 §4.1: no retention across consecutive restarts).
#[tokio::test]
async fn vpn_gr_consecutive_restart_deletes_stale_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let gr_entry = || RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::MplsVpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    };
    tx.send(gr_entry()).await.unwrap();
    let stale = query_vpn_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    tx.send(gr_entry()).await.unwrap();
    assert!(
        query_vpn_routes(&tx).await.is_empty(),
        "a route still stale at the next restart must be deleted, not re-marked"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A received VPN route must be reflected to an eligible (eBGP-export) peer,
/// and a withdrawal must be staged with the RD + prefix key.
#[tokio::test]
async fn vpn_routes_received_reflects_and_withdraws_to_eligible_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vpn_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100);
    let key = route.key();

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route.clone()],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert!(update.withdraw.is_empty());
    assert_eq!(update.vpn_announce.len(), 1);
    assert_eq!(update.vpn_announce[0].key(), key);
    assert_eq!(
        update.vpn_announce[0].nlri, route.nlri,
        "RD + label stack must pass through reflection verbatim"
    );
    assert_eq!(update.vpn_announce[0].next_hop, route.next_hop);
    assert!(update.vpn_withdraw.is_empty());

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![key.clone()],
    })
    .await
    .unwrap();

    let withdraw = out_rx.recv().await.unwrap();
    assert!(withdraw.vpn_announce.is_empty());
    assert_eq!(withdraw.vpn_withdraw, vec![key]);

    drop(tx);
    handle.await.unwrap();
}

/// RFC 7911 VPN receive: distinct path IDs for the same RD+prefix are
/// distinct Adj-RIB-In entries, and a withdraw keyed by path ID removes
/// only that one — the surviving path takes over the Loc-RIB best.
#[tokio::test]
async fn vpn_addpath_ingest_distinct_path_ids_stored_and_withdrawn_independently() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let mut path_1 = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 200);
    path_1.path_id = 1;
    let mut path_2 = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100);
    path_2.path_id = 2;
    assert_eq!(path_1.nlri.key(), path_2.nlri.key());
    assert_ne!(path_1.key(), path_2.key());

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![path_1.clone(), path_2.clone()],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let best = query_vpn_routes(&tx).await;
    assert_eq!(best.len(), 1, "one Loc-RIB best per RD+prefix identity");
    assert_eq!(
        best[0].path_id, 1,
        "the higher-LOCAL_PREF received path wins"
    );

    // Withdraw ONLY path 1 — path 2 must survive and take over.
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![path_1.key()],
    })
    .await
    .unwrap();
    let best = query_vpn_routes(&tx).await;
    assert_eq!(best.len(), 1, "path 2 must survive a path-1-only withdraw");
    assert_eq!(best[0].path_id, 2);

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![path_2.key()],
    })
    .await
    .unwrap();
    assert!(query_vpn_routes(&tx).await.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// RFC 7911 VPN send: an Add-Path-send target receives up to `send_max`
/// candidates per RD+prefix with outbound path IDs 1..=N ranked by the VPN
/// tiebreak, a non-Add-Path target keeps single-best (`path_id = 0`), and
/// a source withdraw shrinks the staged set by outbound path ID.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "covers Add-Path top-N, single-best parity, and withdraw re-ranking in one scenario"
)]
async fn vpn_addpath_send_stages_top_n_and_single_best_unchanged() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let addpath_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (addpath_out_tx, mut addpath_out) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: addpath_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: addpath_out_tx,
        export_policy: None,
        sendable_families: vpn_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![(Afi::Ipv4, Safi::MplsVpn)],
        add_path_send_max: 2,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut addpath_out).await;

    let plain_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let (plain_out_tx, mut plain_out) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: plain_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: plain_out_tx,
        export_policy: None,
        sendable_families: vpn_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut plain_out).await;

    // Same RD+prefix from three sources, ranked by LOCAL_PREF: 300 > 200 > 100.
    let best = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 11), 31, 100, 300);
    let second = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 12), 31, 200, 200);
    let third = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 13), 31, 300, 100);
    let nlri_key = best.nlri.key();
    for route in [&best, &second, &third] {
        tx.send(RibUpdate::VpnRoutesReceived {
            session_id: 0,
            peer: route.peer,
            announced: vec![route.clone()],
            withdrawn: vec![],
        })
        .await
        .unwrap();
    }
    let _ = query_vpn_routes(&tx).await; // sync point

    let staged = drain_final_vpn(&mut addpath_out);
    assert_eq!(
        staged.len(),
        2,
        "send_max=2 caps the staged set at two paths, not three"
    );
    let rank_1 = staged
        .get(&crate::route::VpnRibRouteKey {
            nlri_key,
            path_id: 1,
        })
        .expect("outbound path_id 1 staged");
    let rank_2 = staged
        .get(&crate::route::VpnRibRouteKey {
            nlri_key,
            path_id: 2,
        })
        .expect("outbound path_id 2 staged");
    assert_eq!(rank_1.next_hop, best.next_hop, "rank 1 = best by tiebreak");
    assert_eq!(rank_2.next_hop, second.next_hop, "rank 2 = runner-up");

    let plain_staged = drain_final_vpn(&mut plain_out);
    assert_eq!(plain_staged.len(), 1, "non-Add-Path peer stays single-best");
    let single = plain_staged
        .get(&crate::route::VpnRibRouteKey {
            nlri_key,
            path_id: 0,
        })
        .expect("single-best staged at path_id 0");
    assert_eq!(single.next_hop, best.next_hop);

    // The best source withdraws: the staged top-2 becomes {second, third}
    // re-ranked as path IDs 1..2; the diff withdraws by outbound path ID.
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: best.peer,
        announced: vec![],
        withdrawn: vec![best.key()],
    })
    .await
    .unwrap();
    let _ = query_vpn_routes(&tx).await; // sync point

    let staged = drain_final_vpn(&mut addpath_out);
    // drain_final_vpn folds over the earlier state: ranks 1..2 re-announced.
    let rank_1 = staged
        .get(&crate::route::VpnRibRouteKey {
            nlri_key,
            path_id: 1,
        })
        .expect("outbound path_id 1 restaged after withdraw");
    let rank_2 = staged
        .get(&crate::route::VpnRibRouteKey {
            nlri_key,
            path_id: 2,
        })
        .expect("outbound path_id 2 restaged after withdraw");
    assert_eq!(rank_1.next_hop, second.next_hop);
    assert_eq!(rank_2.next_hop, third.next_hop);

    drop(tx);
    handle.await.unwrap();
}

/// RFC 4456 eligibility on VPN reflection: a non-client iBGP route is
/// reflected to RR clients, suppressed toward other non-clients, and never
/// echoed back to the source.
#[tokio::test]
async fn vpn_rr_reflects_non_client_route_to_clients_only() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let non_client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

    let mut rxs = Vec::new();
    for (peer, is_client) in [(source, false), (client, true), (non_client, false)] {
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            session_id: 0,
            peer,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: vpn_sendable(),
            is_ebgp: false,
            route_reflector_client: is_client,
            orr_vantage: None,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;
        rxs.push(out_rx);
    }
    let mut non_client_rx = rxs.pop().unwrap();
    let mut client_rx = rxs.pop().unwrap();
    let mut source_rx = rxs.pop().unwrap();

    let route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 32, 100, 100);
    let key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let reflected = client_rx.recv().await.unwrap();
    assert_eq!(reflected.vpn_announce.len(), 1);
    assert_eq!(reflected.vpn_announce[0].key(), key);

    let non_client_echo =
        tokio::time::timeout(Duration::from_millis(50), non_client_rx.recv()).await;
    assert!(
        non_client_echo.is_err(),
        "non-client iBGP route must not be reflected to another non-client"
    );
    let source_echo = tokio::time::timeout(Duration::from_millis(50), source_rx.recv()).await;
    assert!(
        source_echo.is_err(),
        "VPN routes must not be reflected back to the source peer"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A same-peer relabel (same RD + prefix key, new MPLS label stack) must be
/// re-advertised: the label is route data with no analog in the BGP-LS
/// template, and `vpn_routes_equal` must catch the `nlri` change.
#[tokio::test]
async fn vpn_same_peer_relabel_triggers_re_advertise() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vpn_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 33, 100, 100);
    let relabeled = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 33, 200, 100);
    assert_eq!(
        route.key(),
        relabeled.key(),
        "label must not change the key"
    );

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.vpn_announce.len(), 1);
    assert_eq!(first.vpn_announce[0].nlri.labels[0].label, 100);

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![relabeled],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let second = out_rx.recv().await.unwrap();
    assert_eq!(
        second.vpn_announce.len(),
        1,
        "same-peer relabel must re-advertise"
    );
    assert_eq!(second.vpn_announce[0].nlri.labels[0].label, 200);

    drop(tx);
    handle.await.unwrap();
}

/// A dirty-resync (here: an export-policy replace, which forces a full
/// restage against the real Adj-RIB-Out) must not re-send a VPN route whose
/// staged form is unchanged.
#[tokio::test]
async fn vpn_dirty_resync_equality_skip_does_not_resend_unchanged_route() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vpn_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 34, 100, 100);
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.vpn_announce.len(), 1);

    // Policy replace marks the peer dirty and runs a full resync; the staged
    // route equals the committed Adj-RIB-Out entry, so nothing is re-sent.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::ReplacePeerExportPolicy {
        peer: target,
        export_policy: None,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap().unwrap();

    let resend = tokio::time::timeout(Duration::from_millis(50), out_rx.recv()).await;
    assert!(
        resend.is_err(),
        "unchanged VPN route must be skipped by the dirty-resync equality check"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A peer that comes up after the VPN table converged must receive the full
/// table in its initial dump, followed by the SAFI-128 `EoR`.
#[tokio::test]
async fn send_initial_table_includes_vpn_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 35, 100, 100);
    let key = route.key();

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vpn_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert_eq!(update.vpn_announce.len(), 1);
    assert_eq!(update.vpn_announce[0].key(), key);
    assert!(update.vpn_withdraw.is_empty());

    let eor = out_rx.recv().await.unwrap();
    assert_eq!(eor.end_of_rib, vpn_sendable());

    drop(tx);
    handle.await.unwrap();
}

/// A plain ROUTE-REFRESH request for (IPv4, `MplsVpn`) must replay the staged
/// VPN routes between the BoRR/EoRR markers.
#[tokio::test]
async fn route_refresh_vpn_re_advertises_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 36, 100, 100);
    let key = route.key();

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vpn_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    let _initial = out_rx.recv().await.unwrap();
    let _eor = out_rx.recv().await.unwrap();

    tx.send(RibUpdate::RouteRefreshRequest {
        session_id: 0,
        peer: target,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert!(update.withdraw.is_empty());
    assert_eq!(update.vpn_announce.len(), 1);
    assert_eq!(update.vpn_announce[0].key(), key);
    assert!(update.vpn_withdraw.is_empty());
    assert_eq!(update.end_of_rib, vec![(Afi::Ipv4, Safi::MplsVpn)]);
    assert_eq!(
        update.refresh_markers,
        vec![
            (
                Afi::Ipv4,
                Safi::MplsVpn,
                rustbgpd_wire::RouteRefreshSubtype::BoRR
            ),
            (
                Afi::Ipv4,
                Safi::MplsVpn,
                rustbgpd_wire::RouteRefreshSubtype::EoRR
            ),
        ]
    );

    drop(tx);
    handle.await.unwrap();
}

/// Bring up a peer with RTC sendable and return its outbound receiver.
/// Does NOT drain anything — the caller asserts the initial dump / `EoR`.
async fn rtc_peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    is_ebgp: bool,
    rr_client: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: rtc_sendable(),
        is_ebgp,
        route_reflector_client: rr_client,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    out_rx
}

/// Every peer-up with the RTC family triggers the lazy default origination,
/// so the initial dump always carries at least the local default NLRI
/// followed by the SAFI-132 `EoR`. Drain both.
async fn drain_rtc_initial_dump(out_rx: &mut mpsc::Receiver<OutboundRouteUpdate>) {
    let dump = out_rx.recv().await.unwrap();
    assert!(
        dump.rtc_announce.iter().any(|r| r.nlri.is_default()),
        "initial dump must carry the locally-originated default RTC NLRI"
    );
    let eor = out_rx.recv().await.unwrap();
    assert_eq!(eor.end_of_rib, rtc_sendable());
}

/// Received RTC routes land in the typed Adj-RIB-In / Loc-RIB and are
/// queryable through `QueryRtcRoutes`.
#[tokio::test]
async fn rtc_routes_received_stored_and_queryable() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route.clone()],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let stored = query_rtc_routes(&tx).await;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].nlri, route.nlri);
    assert_eq!(stored[0].peer, source);
    assert_eq!(stored[0].nlri.prefix_len, 96);

    drop(tx);
    handle.await.unwrap();
}

/// A withdraw for a stored RTC key removes it from the Loc-RIB.
#[tokio::test]
async fn rtc_withdraw_removes_route() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    let key = route.key();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    assert_eq!(query_rtc_routes(&tx).await.len(), 1);

    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![],
        withdrawn: vec![key],
    })
    .await
    .unwrap();
    assert!(query_rtc_routes(&tx).await.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// A peer-advertised default (zero-length) RTC NLRI is a valid route
/// identity of its own.
#[tokio::test]
async fn rtc_default_nlri_stored() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let mut route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 0, 100);
    route.nlri = rustbgpd_wire::RtcNlri::DEFAULT;
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let stored = query_rtc_routes(&tx).await;
    assert_eq!(stored.len(), 1);
    assert!(stored[0].nlri.is_default());
    assert_eq!(stored[0].peer, source);

    drop(tx);
    handle.await.unwrap();
}

/// RFC 4684 §3.2: RTC routes reflect between iBGP RR clients through the
/// shared reflection machinery (`ORIGINATOR_ID` / `CLUSTER_LIST` are
/// attached by transport's `prepare_outbound_attributes_rtc`, pinned in
/// the transport tests).
#[tokio::test]
async fn rtc_route_reflects_between_ibgp_clients_with_originator_and_cluster_list() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let client_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut a_rx = rtc_peer_up(&tx, client_a, false, true).await;
    drain_rtc_initial_dump(&mut a_rx).await;
    let mut b_rx = rtc_peer_up(&tx, client_b, false, true).await;
    drain_rtc_initial_dump(&mut b_rx).await;

    let route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    let key = route.key();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: client_a,
        announced: vec![route.clone()],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let reflected = b_rx.recv().await.unwrap();
    assert_eq!(reflected.rtc_announce.len(), 1);
    assert_eq!(reflected.rtc_announce[0].key(), key);
    assert_eq!(
        reflected.rtc_announce[0].nlri, route.nlri,
        "membership NLRI must pass through reflection verbatim"
    );
    assert_eq!(
        reflected.rtc_announce[0].peer_router_id,
        route.peer_router_id
    );
    assert_eq!(
        reflected.rtc_announce[0].origin_type,
        crate::route::RouteOrigin::Ibgp,
        "reflected route keeps iBGP origin so transport attaches ORIGINATOR_ID/CLUSTER_LIST"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Split horizon: an RTC route is never echoed back to its source.
#[tokio::test]
async fn rtc_route_not_reflected_to_source_peer() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let mut source_rx = rtc_peer_up(&tx, source, false, true).await;
    drain_rtc_initial_dump(&mut source_rx).await;

    let route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let echo = tokio::time::timeout(Duration::from_millis(50), source_rx.recv()).await;
    assert!(
        echo.is_err(),
        "RTC routes must not be reflected back to the source peer"
    );

    drop(tx);
    handle.await.unwrap();
}

/// RFC 4456: an iBGP route learned from a non-client is reflected to
/// clients only — another non-client must not receive it.
#[tokio::test]
async fn rtc_route_suppressed_nonclient_to_nonclient() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let non_client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut source_rx = rtc_peer_up(&tx, source, false, false).await;
    drain_rtc_initial_dump(&mut source_rx).await;
    let mut non_client_rx = rtc_peer_up(&tx, non_client, false, false).await;
    drain_rtc_initial_dump(&mut non_client_rx).await;

    let route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let echo = tokio::time::timeout(Duration::from_millis(50), non_client_rx.recv()).await;
    assert!(
        echo.is_err(),
        "non-client iBGP RTC route must not be reflected to another non-client"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A peer that comes up after RTC state converged must receive the full
/// SAFI-132 table (peer routes + local default) in its initial dump,
/// followed by the SAFI-132 `EoR` — without any GR involvement (RFC 4684
/// §5: RTC `EoR` SHOULD be sent regardless of GR).
#[tokio::test]
async fn send_initial_table_includes_rtc_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    let key = route.key();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, target, true, false).await;

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert!(
        update.rtc_announce.iter().any(|r| r.key() == key),
        "initial dump must carry the converged RTC table"
    );
    assert!(
        update.rtc_announce.iter().any(|r| r.nlri.is_default()),
        "initial dump must carry the locally-originated default"
    );
    assert!(update.rtc_withdraw.is_empty());

    // EoR pin: emitted for (IPv4, RtConstrain) with no GR state at all.
    let eor = out_rx.recv().await.unwrap();
    assert_eq!(eor.end_of_rib, rtc_sendable());

    drop(tx);
    handle.await.unwrap();
}

/// The first RTC-capable peer-up lazily originates the local default NLRI
/// (wildcard RT interest) and delivers it in that peer's initial dump.
#[tokio::test]
async fn peer_up_with_rtc_family_originates_default_rtc_to_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, peer, true, false).await;

    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.rtc_announce.len(), 1);
    let default = &update.rtc_announce[0];
    assert!(default.nlri.is_default());
    assert_eq!(default.origin_type, crate::route::RouteOrigin::Local);
    assert!(
        default.next_hop.is_unspecified(),
        "local default stores an unspecified next-hop; transport emits the session-local address"
    );
    // AS_PATH is well-known mandatory even when empty: without it, RFC 7606
    // peers treat-as-withdraw the default-RTC UPDATE and never send the RR
    // their VPN routes (M75 regression).
    assert!(
        default
            .attributes
            .iter()
            .any(|attr| matches!(attr, rustbgpd_wire::PathAttribute::AsPath(_))),
        "locally-originated default RTC NLRI must carry an (empty) AS_PATH"
    );

    let eor = out_rx.recv().await.unwrap();
    assert_eq!(eor.end_of_rib, rtc_sendable());

    let stored = query_rtc_routes(&tx).await;
    assert_eq!(stored.len(), 1);
    assert!(stored[0].nlri.is_default());

    drop(tx);
    handle.await.unwrap();
}

/// A peer without the RTC family must not trigger default origination.
#[tokio::test]
async fn default_rtc_not_originated_to_non_rtc_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    assert!(
        query_rtc_routes(&tx).await.is_empty(),
        "default RTC origination is lazy: no RTC peer, no default"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Repeated RTC peer-ups (flap or additional peers) must not duplicate the
/// local default NLRI.
#[tokio::test]
async fn default_rtc_origination_idempotent_across_peer_ups() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, peer, true, false).await;
    drain_rtc_initial_dump(&mut out_rx).await;

    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    })
    .await
    .unwrap();

    // Same peer returns; a second RTC peer joins too.
    let mut out_rx = rtc_peer_up(&tx, peer, true, false).await;
    drain_rtc_initial_dump(&mut out_rx).await;
    let second = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut second_rx = rtc_peer_up(&tx, second, true, false).await;
    drain_rtc_initial_dump(&mut second_rx).await;

    let stored = query_rtc_routes(&tx).await;
    assert_eq!(
        stored.len(),
        1,
        "default origination must be idempotent across peer-ups"
    );
    assert!(stored[0].nlri.is_default());

    drop(tx);
    handle.await.unwrap();
}

/// Peer teardown removes the departed peer's RTC routes and withdraws them
/// from remaining peers.
#[tokio::test]
async fn peer_down_withdraws_rtc_routes_from_other_peers() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, target, true, false).await;
    drain_rtc_initial_dump(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    let key = route.key();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.rtc_announce.len(), 1);

    tx.send(RibUpdate::PeerDown {
        peer: source,
        session_id: 0,
    })
    .await
    .unwrap();

    let withdraw = out_rx.recv().await.unwrap();
    assert!(withdraw.rtc_announce.is_empty());
    assert_eq!(withdraw.rtc_withdraw, vec![key]);

    // Only the local default survives (LOCAL_PEER is not a session).
    let remaining = query_rtc_routes(&tx).await;
    assert_eq!(remaining.len(), 1);
    assert!(remaining[0].nlri.is_default());

    drop(tx);
    handle.await.unwrap();
}

/// A peer whose GR capability does NOT list (IPv4, `RtConstrain`) must have
/// its RTC routes withdrawn on GR entry — RFC 4724 retains only families in
/// the advertised capability.
#[tokio::test]
async fn rtc_gr_family_not_in_capability_is_withdrawn() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, target, true, false).await;
    drain_rtc_initial_dump(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    let key = route.key();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.rtc_announce.len(), 1);

    // GR entry with only unicast in the capability: SAFI 132 is not
    // covered, so the peer's RTC routes are withdrawn, not marked stale.
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
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

    let withdraw = out_rx.recv().await.unwrap();
    assert_eq!(
        withdraw.rtc_withdraw,
        vec![key],
        "GR entry must withdraw RTC routes absent from the capability"
    );

    let remaining = query_rtc_routes(&tx).await;
    assert_eq!(
        remaining.len(),
        1,
        "only the local default survives GR entry"
    );
    assert!(remaining[0].nlri.is_default());

    drop(tx);
    handle.await.unwrap();
}

/// A peer entering GR with (IPv4, `RtConstrain`) in its capability keeps its
/// RTC routes as stale: they stay in the Loc-RIB (demoted-rank candidates)
/// and are NOT withdrawn from other RTC peers.
#[tokio::test]
async fn rtc_gr_marks_stale_and_demotes_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, target, true, false).await;
    drain_rtc_initial_dump(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    let key = route.key();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.rtc_announce.len(), 1);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::RtConstrain)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    let retained = query_rtc_routes(&tx).await;
    let stale_route = retained
        .iter()
        .find(|r| r.key() == key)
        .expect("GR-covered RTC route must be retained in the Loc-RIB");
    assert!(stale_route.is_stale, "retained RTC route must be stale");

    // No withdraw may reach the other RTC peer during the retention window
    // (a benign re-announce of the unchanged route is tolerated).
    while let Ok(Some(update)) =
        tokio::time::timeout(Duration::from_millis(50), out_rx.recv()).await
    {
        assert!(
            update.rtc_withdraw.is_empty(),
            "GR-preserved RTC routes must not be withdrawn from other peers"
        );
    }

    drop(tx);
    handle.await.unwrap();
}

/// End-of-RIB after re-establishment clears the re-advertised RTC route's
/// stale flag and removes (and withdraws downstream) interest that was not
/// re-advertised (RFC 4724 §4.1).
#[tokio::test]
async fn rtc_gr_eor_clears_stale() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, target, true, false).await;
    drain_rtc_initial_dump(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    let dropped = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 200, 100);
    let kept_key = kept.key();
    let dropped_key = dropped.key();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept.clone(), dropped],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.rtc_announce.len(), 2);

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::RtConstrain)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Only `kept` is re-advertised before End-of-RIB.
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::RtConstrain,
    })
    .await
    .unwrap();

    let after_eor = query_rtc_routes(&tx).await;
    assert!(
        after_eor.iter().all(|r| r.key() != dropped_key),
        "the non-readvertised stale RTC route must be removed at End-of-RIB"
    );
    let kept_route = after_eor
        .iter()
        .find(|r| r.key() == kept_key)
        .expect("re-advertised RTC route survives EoR");
    assert!(!kept_route.is_stale, "EoR must clear the stale flag");

    drop(tx);
    handle.await.unwrap();
}

/// GR timer expiry without LLGR purges the stale RTC routes and withdraws
/// them from other peers.
#[tokio::test]
async fn rtc_gr_timer_sweeps_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    let key = route.key();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 2,
        stale_routes_time: 5,
        gr_families: vec![(Afi::Ipv4, Safi::RtConstrain)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();
    let retained = query_rtc_routes(&tx).await;
    assert!(retained.iter().any(|r| r.key() == key && r.is_stale));

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    let after_sweep = query_rtc_routes(&tx).await;
    assert!(
        after_sweep.iter().all(|r| r.key() != key),
        "GR timer expiry must sweep stale RTC routes"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A second GR entry while RTC routes are still stale deletes them
/// (RFC 4724 §4.1: no retention across consecutive restarts) and the
/// deletion is withdrawn from other RTC peers.
#[tokio::test]
async fn rtc_gr_consecutive_restart_deletes_stale_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, target, true, false).await;
    drain_rtc_initial_dump(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    let key = route.key();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.rtc_announce.len(), 1);

    let gr_entry = || RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: source,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::RtConstrain)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    };
    tx.send(gr_entry()).await.unwrap();
    let retained = query_rtc_routes(&tx).await;
    assert!(retained.iter().any(|r| r.key() == key && r.is_stale));

    tx.send(gr_entry()).await.unwrap();
    let after_second = query_rtc_routes(&tx).await;
    assert!(
        after_second.iter().all(|r| r.key() != key),
        "a route still stale at the next restart must be deleted"
    );
    // Skip any benign re-announce staged by the first GR entry; the
    // deletion itself must surface as a downstream withdraw.
    loop {
        let update = out_rx.recv().await.unwrap();
        if update.rtc_withdraw.is_empty() {
            continue;
        }
        assert_eq!(
            update.rtc_withdraw,
            vec![key],
            "the consecutive-restart deletion must be withdrawn downstream"
        );
        break;
    }

    drop(tx);
    handle.await.unwrap();
}

/// A plain ROUTE-REFRESH request for (IPv4, `RtConstrain`) must replay the
/// staged RTC routes between the BoRR/EoRR markers.
#[tokio::test]
async fn route_refresh_rtc_re_advertises_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, target, true, false).await;
    drain_rtc_initial_dump(&mut out_rx).await;

    tx.send(RibUpdate::RouteRefreshRequest {
        session_id: 0,
        peer: target,
        afi: Afi::Ipv4,
        safi: Safi::RtConstrain,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(
        update.rtc_announce.iter().any(|r| r.nlri.is_default()),
        "refresh replay must re-send the local default"
    );
    assert_eq!(update.end_of_rib, rtc_sendable());
    assert_eq!(
        update.refresh_markers,
        vec![
            (
                Afi::Ipv4,
                Safi::RtConstrain,
                rustbgpd_wire::RouteRefreshSubtype::BoRR
            ),
            (
                Afi::Ipv4,
                Safi::RtConstrain,
                rustbgpd_wire::RouteRefreshSubtype::EoRR
            ),
        ]
    );

    drop(tx);
    handle.await.unwrap();
}

// --- RFC 4684 VPN reflection filter (RT-Constrain membership) ---

/// Sendable families for a peer that negotiated VPNv4+VPNv6 and RT-Constrain.
fn vpn_rtc_sendable() -> Vec<(Afi, Safi)> {
    vec![
        (Afi::Ipv4, Safi::MplsVpn),
        (Afi::Ipv6, Safi::MplsVpn),
        (Afi::Ipv4, Safi::RtConstrain),
    ]
}

/// A two-octet-AS Route Target `RT:65001:<local_admin>` — the family that
/// `make_rtc_rib_route`'s /96 membership NLRI covers.
fn rt(local_admin: u16) -> ExtendedCommunity {
    ExtendedCommunity::new(0x0002_FDE9_0000_0000 | u64::from(local_admin))
}

/// An RT membership route from `peer` carrying an arbitrary NLRI.
fn make_rtc_rib_route_with_nlri(
    peer: Ipv4Addr,
    nlri: rustbgpd_wire::RtcNlri,
) -> crate::route::RtcRibRoute {
    let mut route = make_rtc_rib_route(peer, 0, 100);
    route.nlri = nlri;
    route
}

/// A `VPNv4` route from `peer` carrying the given extended communities.
fn make_vpn_rib_route_with_rts(
    peer: Ipv4Addr,
    prefix_octet: u8,
    rts: Vec<ExtendedCommunity>,
) -> VpnRibRoute {
    let mut route = make_vpn_rib_route(peer, prefix_octet, 100, 100);
    Arc::make_mut(&mut route.attributes).push(PathAttribute::ExtendedCommunities(rts));
    route
}

/// A `VPNv6` route from `peer` carrying the given extended communities.
fn make_vpn6_rib_route_with_rts(
    peer: Ipv4Addr,
    segment: u16,
    rts: Vec<ExtendedCommunity>,
) -> VpnRibRoute {
    let nlri = VpnNlri {
        labels: vec![MplsLabelEntry::try_new(100, 0, true).unwrap()],
        route_distinguisher: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 1]),
        prefix: VpnPrefix::v6(Ipv6Addr::new(0x2001, 0xdb8, segment, 0, 0, 0, 0, 0), 48).unwrap(),
    };
    VpnRibRoute {
        nlri,
        next_hop: IpAddr::V4(peer),
        peer: IpAddr::V4(peer),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::LocalPref(100),
            PathAttribute::ExtendedCommunities(rts),
        ]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: peer,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    }
}

/// Bring up an eBGP peer that negotiated VPN + RT-Constrain families.
/// Does NOT drain — callers assert the initial dump.
async fn vpn_rtc_peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vpn_rtc_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    out_rx
}

/// Drain a VPN+RTC peer's initial dump + `EoR`, asserting the RFC 4684
/// strict rule: the dump carries the local default RTC NLRI and ZERO VPN
/// routes (SAFI 132 negotiated + empty membership ⇒ advertise nothing).
async fn drain_strict_vpn_rtc_initial_dump(out_rx: &mut mpsc::Receiver<OutboundRouteUpdate>) {
    let dump = out_rx.recv().await.unwrap();
    assert!(
        dump.rtc_announce.iter().any(|r| r.nlri.is_default()),
        "initial dump must carry the locally-originated default RTC NLRI"
    );
    assert!(
        dump.vpn_announce.is_empty(),
        "empty RTC membership must withhold every VPN route from the initial dump"
    );
    assert!(dump.vpn_withdraw.is_empty());
    let eor = out_rx.recv().await.unwrap();
    assert_eq!(eor.end_of_rib, vpn_rtc_sendable());
}

/// Send RT membership NLRI (interest in `RT:65001:<la>` per entry) from `peer`.
async fn send_rtc_interest(tx: &mpsc::Sender<RibUpdate>, peer: Ipv4Addr, local_admins: &[u16]) {
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer),
        announced: local_admins
            .iter()
            .map(|&la| make_rtc_rib_route(peer, la, 100))
            .collect(),
        withdrawn: vec![],
    })
    .await
    .unwrap();
}

/// SAFI 132 negotiated + no RTC interest received ⇒ NO VPN routes advertised
/// (the strict rule) — the initial dump stages zero VPN routes.
#[tokio::test]
async fn vpn_not_advertised_to_rtc_peer_with_empty_membership() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_vpn_rib_route_with_rts(
            Ipv4Addr::new(10, 0, 0, 1),
            60,
            vec![rt(100)],
        )],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = vpn_rtc_peer_up(&tx, target).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    drop(tx);
    handle.await.unwrap();
}

/// When a matching RTC NLRI arrives, the withheld VPN route is announced as a
/// minimal delta — no session reset, and already-correct Adj-RIB-Out state is
/// not re-sent.
#[tokio::test]
async fn vpn_advertised_after_matching_rtc_nlri_arrives_without_reset() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route_a = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]);
    let route_b = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 61, vec![rt(200)]);
    let key_a = route_a.key();
    let key_b = route_b.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route_a, route_b],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    send_rtc_interest(&tx, target, &[100]).await;
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.vpn_announce.len(), 1);
    assert_eq!(first.vpn_announce[0].key(), key_a);
    assert!(first.vpn_withdraw.is_empty());

    // Widening the membership announces ONLY the newly-covered route — the
    // already-advertised one is suppressed by the Adj-RIB-Out equality check.
    send_rtc_interest(&tx, target, &[200]).await;
    let second = out_rx.recv().await.unwrap();
    assert_eq!(second.vpn_announce.len(), 1);
    assert_eq!(second.vpn_announce[0].key(), key_b);
    assert!(second.vpn_withdraw.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// Withdrawing the covering RTC NLRI withdraws the VPN route from that peer.
#[tokio::test]
async fn vpn_withdrawn_when_rtc_nlri_withdrawn() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 62, vec![rt(100)]);
    let vpn_key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    send_rtc_interest(&tx, target, &[100]).await;
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.vpn_announce.len(), 1);

    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(target),
        announced: vec![],
        withdrawn: vec![make_rtc_rib_route(target, 100, 100).key()],
    })
    .await
    .unwrap();
    let withdrawn = out_rx.recv().await.unwrap();
    assert!(withdrawn.vpn_announce.is_empty());
    assert_eq!(withdrawn.vpn_withdraw, vec![vpn_key]);

    drop(tx);
    handle.await.unwrap();
}

/// The zero-length default NLRI is wildcard interest: every VPN route passes,
/// including one with no Route Target extended community at all.
#[tokio::test]
async fn default_rtc_nlri_matches_all_vpn_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![
            make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]),
            // No extended communities at all — only default interest covers it.
            make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 61, 100, 100),
        ],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(target),
        announced: vec![make_rtc_rib_route_with_nlri(
            target,
            rustbgpd_wire::RtcNlri::DEFAULT,
        )],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    assert_eq!(
        update.vpn_announce.len(),
        2,
        "default RTC NLRI must admit every VPN route"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A /48 membership NLRI (origin AS + RT type/subtype bytes) admits the whole
/// two-octet-AS RT family regardless of local admin, while an RT of a
/// different type encoding stays filtered — prefix matching is masked, not
/// exact.
#[tokio::test]
async fn rtc_prefix_match_gates_by_masked_bits() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let covered_a = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]);
    let covered_b = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 61, vec![rt(999)]);
    // Type 0x01 (IPv4-administrator) Route Target: outside the /48's
    // type/subtype bits, so it must stay filtered.
    let uncovered = make_vpn_rib_route_with_rts(
        Ipv4Addr::new(10, 0, 0, 1),
        62,
        vec![ExtendedCommunity::new(0x0102_0A00_0001_0064)],
    );
    let covered_keys: HashSet<_> = [covered_a.key(), covered_b.key()].into();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![covered_a, covered_b, uncovered],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    // /48 = origin AS 65001 (32 bits) + RT type 0x00 / subtype 0x02 (16 bits).
    let nlri = rustbgpd_wire::RtcNlri::new(65001, 0x0002_0000_0000_0000, 48).unwrap();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(target),
        announced: vec![make_rtc_rib_route_with_nlri(target, nlri)],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let update = out_rx.recv().await.unwrap();
    let announced_keys: HashSet<_> = update
        .vpn_announce
        .iter()
        .map(crate::route::VpnRibRoute::key)
        .collect();
    assert_eq!(
        announced_keys, covered_keys,
        "the /48 must admit the whole RT:65001:* family and nothing else"
    );

    drop(tx);
    handle.await.unwrap();
}

/// One membership gates BOTH `VPNv4` and `VPNv6` keys.
#[tokio::test]
async fn rtc_filter_applies_to_both_vpnv4_and_vpnv6() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v4_covered = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]);
    let v6_covered = make_vpn6_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 1, vec![rt(100)]);
    let v4_other = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 61, vec![rt(200)]);
    let v6_other = make_vpn6_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 2, vec![rt(200)]);
    let covered_keys: HashSet<_> = [v4_covered.key(), v6_covered.key()].into();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![v4_covered, v6_covered, v4_other, v6_other],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    send_rtc_interest(&tx, target, &[100]).await;
    let update = out_rx.recv().await.unwrap();
    let announced_keys: HashSet<_> = update
        .vpn_announce
        .iter()
        .map(crate::route::VpnRibRoute::key)
        .collect();
    assert_eq!(
        announced_keys, covered_keys,
        "the RTC gate must admit the matching VPNv4 AND VPNv6 routes only"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A peer that did NOT negotiate SAFI 132 keeps today's unfiltered VPN
/// reflection — the regression guard for the `None`-filter path.
#[tokio::test]
async fn non_rtc_peer_reflection_unchanged() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]);
    let key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vpn_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.vpn_announce.len(), 1);
    assert_eq!(update.vpn_announce[0].key(), key);

    drop(tx);
    handle.await.unwrap();
}

/// A VPN route with several Route Targets passes when ANY of them matches
/// the peer's membership.
#[tokio::test]
async fn route_with_any_matching_rt_passes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(555), rt(100)]);
    let key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    send_rtc_interest(&tx, target, &[100]).await;
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.vpn_announce.len(), 1);
    assert_eq!(update.vpn_announce[0].key(), key);

    drop(tx);
    handle.await.unwrap();
}

/// Membership derives from the peer's OWN Adj-RIB-In — all paths, never the
/// Loc-RIB best: when two peers advertise the same RTC NLRI, the tiebreak
/// loser's interest still opens its VPN filter.
#[tokio::test]
async fn membership_rebuilt_from_all_adjribin_paths_not_locrib_best() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]);
    let key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let winner = Ipv4Addr::new(10, 0, 0, 2);
    let loser = Ipv4Addr::new(10, 0, 0, 3);
    let mut winner_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(winner)).await;
    drain_strict_vpn_rtc_initial_dump(&mut winner_rx).await;
    let mut loser_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(loser)).await;
    drain_strict_vpn_rtc_initial_dump(&mut loser_rx).await;

    // Winner's copy of the NLRI takes the Loc-RIB tiebreak (higher LOCAL_PREF)
    // and gets reflected to the loser.
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(winner),
        announced: vec![make_rtc_rib_route(winner, 100, 200)],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let winner_vpn = winner_rx.recv().await.unwrap();
    assert_eq!(winner_vpn.vpn_announce.len(), 1);
    let reflected = loser_rx.recv().await.unwrap();
    assert_eq!(reflected.rtc_announce.len(), 1);

    // The loser advertises the SAME NLRI with a losing LOCAL_PREF: the
    // Loc-RIB best is unchanged, but the loser's own membership must still
    // open — the filter reads the peer's Adj-RIB-In, not the Loc-RIB.
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(loser),
        announced: vec![make_rtc_rib_route(loser, 100, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let loser_vpn = loser_rx.recv().await.unwrap();
    assert_eq!(
        loser_vpn.vpn_announce.len(),
        1,
        "tiebreak-losing RTC path must still open the loser's VPN filter"
    );
    assert_eq!(loser_vpn.vpn_announce[0].key(), key);

    drop(tx);
    handle.await.unwrap();
}

/// An enhanced-refresh `EoRR` sweep that removes an unreplaced RTC route must
/// shrink the peer's membership and withdraw the now-uncovered VPN route.
#[tokio::test]
async fn rtc_refresh_eorr_sweep_restages_vpn() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route_a = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]);
    let route_b = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 61, vec![rt(200)]);
    let key_b = route_b.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route_a, route_b],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    send_rtc_interest(&tx, target, &[100, 200]).await;
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.vpn_announce.len(), 2);

    tx.send(RibUpdate::BeginRouteRefresh {
        peer: IpAddr::V4(target),
        session_id: 0,
        afi: Afi::Ipv4,
        safi: Safi::RtConstrain,
    })
    .await
    .unwrap();
    // Only the RT:100 interest is re-announced inside the window; RT:200
    // stays marked stale.
    send_rtc_interest(&tx, target, &[100]).await;
    tx.send(RibUpdate::EndRouteRefresh {
        peer: IpAddr::V4(target),
        session_id: 0,
        afi: Afi::Ipv4,
        safi: Safi::RtConstrain,
    })
    .await
    .unwrap();

    let swept = out_rx.recv().await.unwrap();
    assert!(swept.vpn_announce.is_empty());
    assert_eq!(
        swept.vpn_withdraw,
        vec![key_b],
        "the EoRR sweep must withdraw the VPN route whose RTC interest was not replayed"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A peer whose GR capability omits SAFI 132 has its RTC interest withdrawn
/// on GR entry, so it re-establishes with a strict empty membership and only
/// receives VPN routes once its interest re-arrives.
#[tokio::test]
async fn gr_reestablish_without_rtc_in_capability_starts_strict() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]);
    let key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;
    send_rtc_interest(&tx, target, &[100]).await;
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.vpn_announce.len(), 1);

    // GR capability covers only VPN — the peer's RTC interest is NOT
    // retained (RFC 4724: only families in the capability are preserved).
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: IpAddr::V4(target),
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::MplsVpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Re-establish: the strict initial dump proves the membership did not
    // survive the restart — no VPN routes until the interest re-arrives.
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    send_rtc_interest(&tx, target, &[100]).await;
    let reannounced = out_rx.recv().await.unwrap();
    assert_eq!(reannounced.vpn_announce.len(), 1);
    assert_eq!(reannounced.vpn_announce[0].key(), key);

    drop(tx);
    handle.await.unwrap();
}

/// A peer whose GR capability covers SAFI 132 keeps its RT interest as stale
/// through the restart window: the re-establish initial dump serves VPN
/// routes immediately from the preserved membership (no wait for the
/// interest to re-arrive), and the End-of-RIB sweep of interest the peer did
/// NOT re-advertise withdraws the corresponding VPN routes.
#[tokio::test]
async fn rtc_gr_preserves_vpn_membership_through_restart_window() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route_a = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]);
    let route_b = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 61, vec![rt(200)]);
    let key_a = route_a.key();
    let key_b = route_b.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route_a, route_b],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;
    send_rtc_interest(&tx, target, &[100, 200]).await;
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.vpn_announce.len(), 2);

    // GR capability covers both VPN and RTC: the peer's RT interest is
    // preserved as stale.
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer: IpAddr::V4(target),
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::MplsVpn), (Afi::Ipv4, Safi::RtConstrain)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Re-establish: VPN routes flow in the INITIAL dump, filtered by the
    // stale membership — before any RTC re-advertisement arrives.
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    let dump = out_rx.recv().await.unwrap();
    let dumped: Vec<_> = dump.vpn_announce.iter().map(VpnRibRoute::key).collect();
    assert!(
        dumped.contains(&key_a) && dumped.contains(&key_b),
        "the initial dump must serve VPN routes from the GR-preserved membership, got {dumped:?}"
    );

    // The peer re-advertises interest in RT 100 only; RT 200 stays stale.
    send_rtc_interest(&tx, target, &[100]).await;
    // End-of-RIB for SAFI 132 sweeps the non-readvertised interest —
    // membership shrinks and the uncovered VPN route is withdrawn.
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: IpAddr::V4(target),
        afi: Afi::Ipv4,
        safi: Safi::RtConstrain,
    })
    .await
    .unwrap();

    loop {
        let update = out_rx.recv().await.unwrap();
        if update.vpn_withdraw.is_empty() {
            continue;
        }
        assert_eq!(
            update.vpn_withdraw,
            vec![key_b.clone()],
            "the EoR sweep must withdraw the VPN route whose stale interest was not re-advertised"
        );
        assert!(update.vpn_announce.is_empty());
        break;
    }

    drop(tx);
    handle.await.unwrap();
}

/// The initial table dump to an RTC peer stages zero VPN routes, and the
/// table flows as soon as matching interest arrives — no flap needed.
#[tokio::test]
async fn initial_dump_to_rtc_peer_stages_no_vpn_then_flows_on_interest() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route_with_rts(Ipv4Addr::new(10, 0, 0, 1), 60, vec![rt(100)]);
    let key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    send_rtc_interest(&tx, target, &[100]).await;
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.vpn_announce.len(), 1);
    assert_eq!(update.vpn_announce[0].key(), key);

    drop(tx);
    handle.await.unwrap();
}

/// A duplicate RTC announce leaves the rebuilt membership equal to the old
/// one and must NOT trigger a dirty resync — nothing is re-sent.
#[tokio::test]
async fn rtc_membership_unchanged_skips_restage() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_vpn_rib_route_with_rts(
            Ipv4Addr::new(10, 0, 0, 1),
            60,
            vec![rt(100)],
        )],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    send_rtc_interest(&tx, target, &[100]).await;
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.vpn_announce.len(), 1);

    // Duplicate announce: membership rebuild compares equal — no restage.
    send_rtc_interest(&tx, target, &[100]).await;
    let resend = tokio::time::timeout(Duration::from_millis(50), out_rx.recv()).await;
    assert!(
        resend.is_err(),
        "unchanged RTC membership must skip the dirty resync entirely"
    );

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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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

    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
    tx.send(RibUpdate::PeerDown {
        peer: peer2,
        session_id: 0,
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
async fn withdrawal_updates_best() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
        peer: ibgp_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // eBGP route → should be advertised to iBGP peer
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
    tx.send(RibUpdate::PeerDown {
        peer: ebgp_source,
        session_id: 0,
    })
    .await
    .unwrap();

    // Withdraw should be sent to iBGP target
    let update = out_rx.recv().await.unwrap();
    assert_eq!(update.withdraw.len(), 1);

    // iBGP source announces the same prefix
    let ibgp_source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    })
    .await
    .unwrap();

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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
    tx.send(RibUpdate::PeerDown {
        peer: target,
        session_id: 0,
    })
    .await
    .unwrap();
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
    // this, `rbgp neighbor show` shows import counters at 0
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
        peer: peer1,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: send_filtered,
        export_policy: peer1_export,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut recv_filtered).await;

    let (send_unfiltered, mut recv_unfiltered) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: peer2,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: send_unfiltered,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
#[expect(
    clippy::too_many_lines,
    reason = "scenario test keeps policy setup, stimulus, and assertions together"
)]
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65002,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
        peer: target,
        peer_asn: 65002,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: Some(deny_policy),
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65002,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: Some(export_policy),
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65002,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: Some(export_policy),
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65002,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: Some(export_policy),
        sendable_families: vec![(Afi::Ipv6, Safi::Unicast)],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let prefix = Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 64);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: policy,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    })
    .await
    .unwrap();

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
#[expect(
    clippy::too_many_lines,
    reason = "channel-backpressure scenario needs setup, retry clock, and assertions together"
)]
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // First route: should succeed (channel empty → fits)
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    // Announce prefix1
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
            bgpls_announce: vec![],
            bgpls_withdraw: vec![],
            vpn_announce: vec![],
            rtc_announce: vec![],
            vpn_withdraw: vec![],
            rtc_withdraw: vec![],
            request_refresh_all_negotiated: false,
        })
        .await
        .unwrap();

    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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

#[test]
fn route_event_id_exhaustion_saturates_instead_of_panicking() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.next_route_event_id = u64::MAX;

    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    for _ in 0..2 {
        manager.publish_route_event(crate::event::RouteEvent {
            event_id: 0,
            event_type: RouteEventType::Added,
            prefix,
            peer: None,
            previous_peer: None,
            target_peer: None,
            timestamp: String::new(),
            path_id: 0,
            reason: String::new(),
        });
    }

    assert_eq!(manager.route_event_history.len(), 2);
    assert!(manager.route_event_id_exhausted);
    assert!(
        manager
            .route_event_history
            .iter()
            .all(|event| event.event_id == u64::MAX)
    );
    assert_eq!(
        manager.next_route_event_id,
        u64::MAX,
        "saturated id should remain stable after exhaustion"
    );
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
            session_id: 0,
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
            session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
            session_id: 0,
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
            session_id: 0,
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
#[expect(
    clippy::cast_possible_truncation,
    reason = "test fixture counts are small and cast only for gauge comparison"
)]
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
            session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
#[expect(
    clippy::cast_possible_truncation,
    reason = "test fixture counts are small and cast only for gauge comparison"
)]
async fn rib_prefixes_gauge_tracks_adjribin() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    })
    .await
    .unwrap();
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
#[expect(
    clippy::cast_possible_truncation,
    reason = "test fixture counts are small and cast only for gauge comparison"
)]
async fn loc_rib_gauge_tracks_best() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
#[expect(
    clippy::cast_possible_truncation,
    reason = "test fixture counts are small and cast only for gauge comparison"
)]
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: dual_stack_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_flowspec_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_flowspec_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
async fn route_refresh_bgpls_re_advertises_routes() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 34, 100);
    let key = route.key();

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: bgpls_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    let _initial = out_rx.recv().await.unwrap();
    let _eor = out_rx.recv().await.unwrap();

    tx.send(RibUpdate::RouteRefreshRequest {
        session_id: 0,
        peer: target,
        afi: Afi::BgpLs,
        safi: Safi::BgpLs,
    })
    .await
    .unwrap();

    let update = out_rx.recv().await.unwrap();
    assert!(update.announce.is_empty());
    assert!(update.withdraw.is_empty());
    assert_eq!(update.bgpls_announce.len(), 1);
    assert_eq!(update.bgpls_announce[0].key(), key);
    assert!(update.bgpls_withdraw.is_empty());
    assert_eq!(update.end_of_rib, vec![(Afi::BgpLs, Safi::BgpLs)]);
    assert_eq!(
        update.refresh_markers,
        vec![
            (
                Afi::BgpLs,
                Safi::BgpLs,
                rustbgpd_wire::RouteRefreshSubtype::BoRR
            ),
            (
                Afi::BgpLs,
                Safi::BgpLs,
                rustbgpd_wire::RouteRefreshSubtype::EoRR
            ),
        ]
    );

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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
            session_id: 0,
            peer,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();
    }

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
async fn enhanced_route_refresh_bgpls_eorr_sweeps_unreplaced_route() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    let route1 = make_bgpls_route(peer_addr, 21, 100);
    let route2 = make_bgpls_route(peer_addr, 22, 100);
    let key1 = route1.key();

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route1.clone(), route2],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::BgpLs,
        safi: Safi::BgpLs,
    })
    .await
    .unwrap();
    let before_refresh = query_bgpls_routes(&tx).await;
    assert_eq!(before_refresh.len(), 2);
    assert_refresh_metrics(&metrics, "10.0.0.1", "bgpls", 1.0, 2.0);

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route1],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let during_refresh = query_bgpls_routes(&tx).await;
    assert_eq!(during_refresh.len(), 2);
    assert_refresh_metrics(&metrics, "10.0.0.1", "bgpls", 1.0, 1.0);

    tx.send(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::BgpLs,
        safi: Safi::BgpLs,
    })
    .await
    .unwrap();

    let after_refresh = query_bgpls_routes(&tx).await;
    assert_eq!(after_refresh.len(), 1);
    assert_eq!(after_refresh[0].key(), key1);
    assert_refresh_metrics(&metrics, "10.0.0.1", "bgpls", 0.0, 0.0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_bgpls_withdraw_clears_stale_marker() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    let route = make_bgpls_route(peer_addr, 23, 100);
    let key = route.key();

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::BgpLs,
        safi: Safi::BgpLs,
    })
    .await
    .unwrap();
    let before_withdraw = query_bgpls_routes(&tx).await;
    assert_eq!(before_withdraw.len(), 1);
    assert_refresh_metrics(&metrics, "10.0.0.1", "bgpls", 1.0, 1.0);

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![key],
    })
    .await
    .unwrap();
    let after_withdraw = query_bgpls_routes(&tx).await;
    assert!(after_withdraw.is_empty());
    assert_refresh_metrics(&metrics, "10.0.0.1", "bgpls", 1.0, 0.0);

    tx.send(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::BgpLs,
        safi: Safi::BgpLs,
    })
    .await
    .unwrap();

    let after_refresh = query_bgpls_routes(&tx).await;
    assert!(after_refresh.is_empty());
    assert_refresh_metrics(&metrics, "10.0.0.1", "bgpls", 0.0, 0.0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_vpn_eorr_sweeps_unreplaced_route() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    let route1 = make_vpn_rib_route(peer_addr, 21, 100, 100);
    let route2 = make_vpn_rib_route(peer_addr, 22, 100, 100);
    let key1 = route1.key();

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route1.clone(), route2],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();
    let before_refresh = query_vpn_routes(&tx).await;
    assert_eq!(before_refresh.len(), 2);
    assert_refresh_metrics(&metrics, "10.0.0.1", "l3vpn_ipv4_unicast", 1.0, 2.0);

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route1],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let during_refresh = query_vpn_routes(&tx).await;
    assert_eq!(during_refresh.len(), 2);
    assert_refresh_metrics(&metrics, "10.0.0.1", "l3vpn_ipv4_unicast", 1.0, 1.0);

    tx.send(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();

    let after_refresh = query_vpn_routes(&tx).await;
    assert_eq!(after_refresh.len(), 1);
    assert_eq!(after_refresh[0].key(), key1);
    assert_refresh_metrics(&metrics, "10.0.0.1", "l3vpn_ipv4_unicast", 0.0, 0.0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn enhanced_route_refresh_vpn_withdraw_clears_stale_marker() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    let route = make_vpn_rib_route(peer_addr, 23, 100, 100);
    let key = route.key();

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();
    let before_withdraw = query_vpn_routes(&tx).await;
    assert_eq!(before_withdraw.len(), 1);
    assert_refresh_metrics(&metrics, "10.0.0.1", "l3vpn_ipv4_unicast", 1.0, 1.0);

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![key],
    })
    .await
    .unwrap();
    let after_withdraw = query_vpn_routes(&tx).await;
    assert!(after_withdraw.is_empty());
    assert_refresh_metrics(&metrics, "10.0.0.1", "l3vpn_ipv4_unicast", 1.0, 0.0);

    tx.send(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();

    let after_refresh = query_vpn_routes(&tx).await;
    assert!(after_refresh.is_empty());
    assert_refresh_metrics(&metrics, "10.0.0.1", "l3vpn_ipv4_unicast", 0.0, 0.0);

    drop(tx);
    handle.await.unwrap();
}

/// The `EoRR` sweep of an unrefreshed VPN route must flow through the Loc-RIB
/// recompute and surface as a reflected withdrawal to other eligible peers,
/// not just vanish from the sweeping peer's Adj-RIB-In.
#[tokio::test]
async fn enhanced_route_refresh_vpn_eorr_reflects_withdrawal_to_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vpn_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let source_addr = Ipv4Addr::new(10, 0, 0, 1);
    let source = IpAddr::V4(source_addr);
    let survivor = make_vpn_rib_route(source_addr, 24, 100, 100);
    let omitted = make_vpn_rib_route(source_addr, 25, 100, 100);
    let omitted_key = omitted.key();

    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![survivor.clone(), omitted],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announce = out_rx.recv().await.unwrap();
    assert_eq!(announce.vpn_announce.len(), 2);

    tx.send(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();
    // Reannounce only the survivor; the omitted route stays stale.
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![survivor],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();

    let swept = out_rx.recv().await.unwrap();
    assert!(swept.vpn_announce.is_empty());
    assert_eq!(swept.vpn_withdraw, vec![omitted_key]);

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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_flowspec_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Source sends a route
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_flowspec_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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
    tx.send(RibUpdate::PeerDown {
        peer: source,
        session_id: 0,
    })
    .await
    .unwrap();

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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // EoR should clear LLGR-stale
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
    tx.send(RibUpdate::PeerDown {
        peer: source,
        session_id: 0,
    })
    .await
    .unwrap();

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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer,
        peer_asn: 65001,
        peer_router_id: Ipv4Addr::new(1, 1, 1, 1),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    });
    out_rx
}

#[tokio::test]
async fn stale_peer_policy_context_from_superseded_session_is_discarded() {
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    let _out_rx = establish_peer(&mut manager, peer);

    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer,
        session_id: 0,
        peer_group: Some("active".to_string()),
    });
    assert_eq!(
        manager.peer_group.get(&peer).map(String::as_str),
        Some("active")
    );

    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer,
        session_id: 7,
        peer_group: Some("stale".to_string()),
    });
    assert_eq!(
        manager.peer_group.get(&peer).map(String::as_str),
        Some("active"),
        "stale policy context from a superseded session must not overwrite the active registration"
    );

    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer,
        session_id: 0,
        peer_group: None,
    });
    assert!(
        !manager.peer_group.contains_key(&peer),
        "matching session id must still be able to clear policy context"
    );
}

#[tokio::test]
async fn llgr_reestablish_uses_captured_stale_routes_time() {
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // GR with LLGR and a non-default stale_routes_time.
    manager.handle_update(RibUpdate::PeerGracefulRestart {
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer_group: Some("edge".to_string()),
    });
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer_group: Some("edge".to_string()),
    });
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer_group: Some("edge".to_string()),
    });
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx_src,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    // Register client target
    let (client_tx, mut client_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: client_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: client_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
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
        session_id: 0,
        peer: nonclient_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: nonclient_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx_src,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    // Register client target
    let (client_tx, mut client_rx) = mpsc::channel(16);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: client_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: client_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
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
        session_id: 0,
        peer: nonclient_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: nonclient_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
            session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 5,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Inject 2 routes
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 5,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    // Peer goes down
    tx.send(RibUpdate::PeerDown {
        peer: target,
        session_id: 0,
    })
    .await
    .unwrap();

    // Re-register as single-best (send_max=0) — should work fine,
    // state was properly cleaned up
    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: reconnect_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 5,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Add first route
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: multi_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: multi_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 5,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    // Register single-best target
    let (single_tx, mut single_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: single_target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: single_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv6, Safi::Unicast)],
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: dual_stack_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: dual_stack_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: dual_stack_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![(Afi::Ipv4, Safi::Unicast)],
        add_path_send_max: 5,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    let _ = out_rx.recv().await.unwrap();
    drain_eor(&mut out_rx).await;

    tx.send(RibUpdate::RouteRefreshRequest {
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
#[expect(
    clippy::too_many_lines,
    reason = "multipath policy-filter scenario keeps both peers and assertions together"
)]
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: ipv4_sendable(),
        add_path_send_max: 5,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Inject 2 routes for the denied prefix
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer,
        peer_asn: 65001,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
    assert_eq!(loser.vs_best_detail, "local_pref 100 < 200");
    assert_eq!(
        loser.multipath,
        crate::best_path::MultipathEligibility::None
    );

    // Winner attribution: with one competitor, that competitor is the
    // runner-up — the winner's decisive step is the same ladder step,
    // rendered winner-side.
    assert_eq!(
        explain.best_reason,
        Some(crate::best_path::BestPathReason::HigherLocalPref)
    );
    assert_eq!(explain.best_reason_detail, "local_pref 200 > 100");

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
    assert!(explain.best_reason.is_none());
    assert!(explain.best_reason_detail.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// Single-path prefix: the winner is trivial — no runner-up exists, so
/// there is no decisive step to report (`best_reason = None`; the API
/// layer renders that as "`only_path`").
#[tokio::test]
async fn explain_best_path_single_path_has_no_best_reason() {
    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer = Ipv4Addr::new(1, 0, 0, 1);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer),
        announced: vec![make_route_with_lp(prefix, peer, 100)],
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
    assert_eq!(
        explain.best.as_ref().map(|r| r.peer),
        Some(IpAddr::V4(peer))
    );
    assert!(explain.candidates.is_empty());
    assert!(explain.best_reason.is_none());
    assert!(explain.best_reason_detail.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// Tiebreaker attribution across a multi-step elimination matrix: each
/// loser reports the step that eliminated it (with compared values),
/// the winner reports the step that beat the *runner-up* (the deepest-
/// surviving competitor), and the multipath cut is classified per
/// candidate. Also pins explain-vs-comparator agreement: the route the
/// explain calls best must be the `best_path_cmp` minimum.
#[tokio::test]
async fn explain_best_path_attributes_each_loss_and_the_winning_step() {
    use crate::best_path::{BestPathReason, MultipathEligibility, best_path_cmp};

    let (tx, rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let handle = tokio::spawn(RibManager::new(rx, dummy_query_rx(), None, None, metrics).run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let winner_peer = Ipv4Addr::new(1, 0, 0, 1);
    let sibling_peer = Ipv4Addr::new(1, 0, 0, 2); // exact AS_PATH twin → ECMP-eligible, runner-up
    let relax_peer = Ipv4Addr::new(1, 0, 0, 4); // same AS_PATH length, different ASN
    let aspath_peer = Ipv4Addr::new(1, 0, 0, 5); // longer AS_PATH
    let lp_peer = Ipv4Addr::new(1, 0, 0, 6); // lower LOCAL_PREF

    let routes = [
        (winner_peer, vec![65001], 200),
        (sibling_peer, vec![65001], 200),
        (relax_peer, vec![65009], 200),
        (aspath_peer, vec![65001, 65002], 200),
        (lp_peer, vec![65001], 100),
    ];
    let all: Vec<Route> = routes
        .iter()
        .map(|(peer, asns, lp)| make_multipath_route(prefix, *peer, asns.clone(), *lp))
        .collect();
    for route in &all {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: route.peer,
            announced: vec![route.clone()],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    let explain = query_explain_best_path(&tx, Prefix::V4(prefix)).await;

    // Agreement: explain's winner == the comparator's minimum over the
    // same input set.
    let expected_best = all.iter().min_by(|a, b| best_path_cmp(a, b)).unwrap();
    let best = explain.best.as_ref().expect("best route");
    assert_eq!(best.peer, expected_best.peer);
    assert_eq!(best.peer, IpAddr::V4(winner_peer));

    // Winner attribution: the runner-up is the ECMP sibling (ties every
    // attribute step, loses on peer address), so the winning step is
    // the final tiebreaker.
    assert_eq!(explain.best_reason, Some(BestPathReason::LowerPeerAddress));
    assert_eq!(explain.best_reason_detail, "peer 1.0.0.1 < 1.0.0.2");

    // Each loser: the step that eliminated it + compared values +
    // multipath-cut classification.
    let by_peer = |peer: Ipv4Addr| {
        explain
            .candidates
            .iter()
            .find(|c| c.route.peer == IpAddr::V4(peer))
            .unwrap_or_else(|| panic!("candidate {peer} missing"))
    };

    let sibling = by_peer(sibling_peer);
    assert_eq!(sibling.vs_best_reason, BestPathReason::LowerPeerAddress);
    assert_eq!(sibling.vs_best_detail, "peer 1.0.0.2 > 1.0.0.1");
    assert_eq!(sibling.multipath, MultipathEligibility::Eligible);

    let relax = by_peer(relax_peer);
    assert_eq!(relax.vs_best_reason, BestPathReason::LowerPeerAddress);
    assert_eq!(relax.vs_best_detail, "peer 1.0.0.4 > 1.0.0.1");
    assert_eq!(relax.multipath, MultipathEligibility::RelaxOnly);

    let aspath = by_peer(aspath_peer);
    assert_eq!(aspath.vs_best_reason, BestPathReason::ShorterAsPath);
    assert_eq!(aspath.vs_best_detail, "as_path_len 2 > 1");
    assert_eq!(aspath.multipath, MultipathEligibility::None);

    let lp = by_peer(lp_peer);
    assert_eq!(lp.vs_best_reason, BestPathReason::HigherLocalPref);
    assert_eq!(lp.vs_best_detail, "local_pref 100 < 200");
    assert_eq!(lp.multipath, MultipathEligibility::None);

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
            session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
            session_id: 0,
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
        session_id: 0,
        peer: peer_winner, // <-- target IS the winner
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
            session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
            session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
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
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
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
        session_id: 0,
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
    tx.send(RibUpdate::PeerDown {
        peer: source,
        session_id: 0,
    })
    .await
    .unwrap();

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
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
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
        session_id: 0,
        peer: other,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: other_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
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
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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

/// Regression test for the silent advertisement wedge (ROADMAP, observed
/// in an M66 CI run, root-caused in the stale-PeerDown deregistration
/// entry): two sessions for one peer address overlap during the RFC 4271
/// §6.8 collision window, the loser's `PeerDown` is processed AFTER the
/// winner's `PeerUp`, and — before session-identity stamping — it
/// deregistered the surviving session's outbound sender, silently
/// wedging every later advertisement while the session stayed
/// Established (keepalives are writer-owned in transport).
///
/// With the fix, `PeerUp`/`PeerDown` carry the transport session id and
/// the whole `handle_peer_down` teardown is gated on it: the stale
/// collision-loser `PeerDown` is discarded, the winner's Adj-RIB-In
/// survives, and a post-convergence advertisement MUST be delivered on
/// the winner's outbound channel.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "collision regression keeps both session orderings and assertions together"
)]
async fn stale_peer_down_after_replacement_peer_up_is_discarded() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    let peer_up =
        |outbound_tx: mpsc::Sender<OutboundRouteUpdate>, session_id: u64| RibUpdate::PeerUp {
            peer,
            session_id,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            outbound_tx,
            export_policy: None,
            sendable_families: evpn_sendable(),
            is_ebgp: false,
            route_reflector_client: true,
            orr_vantage: None,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
        };

    // Session A (collision loser) reaches Established first and registers.
    let (loser_tx, mut loser_rx) = mpsc::channel(8);
    tx.send(peer_up(loser_tx, 1)).await.unwrap();
    drain_eor(&mut loser_rx).await;

    // Session B (collision winner) reaches Established while A is still
    // registered — same peer address, fresh outbound channel, new session
    // id. The session task keeps its own sender clone alive (it does in
    // production), so a deregistration in the manager closes nothing.
    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    let winner_session_tx = winner_tx.clone();
    tx.send(peer_up(winner_tx, 2)).await.unwrap();
    drain_eor(&mut winner_rx).await;

    // The winner session receives a route from the peer — state a stale
    // PeerDown must NOT destroy (the id check gates the whole teardown,
    // Adj-RIB-In included, not just outbound deregistration).
    let imet_winner = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 2), 50);
    let imet_winner_key = imet_winner.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 2,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet_winner],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // The dumped loser's teardown lands last, stamped with ITS session id.
    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 1,
    })
    .await
    .unwrap();

    // The stale PeerDown must not have cleared the winner session's
    // Adj-RIB-In: the route it received is still in the Loc-RIB.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryEvpnRoutes { reply: reply_tx })
        .await
        .unwrap();
    let evpn_routes = reply_rx.await.unwrap();
    assert!(
        evpn_routes.iter().any(|r| r.key() == imet_winner_key),
        "stale PeerDown must not clear the surviving session's Adj-RIB-In"
    );

    // A post-convergence advertisement arrives from another RR client —
    // the analogue of pe1's fresh Type 2 origination / drain withdrawals.
    let (source_tx, _source_rx) = mpsc::channel(8);
    tx.send(RibUpdate::PeerUp {
        peer: source,
        session_id: 3,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet_key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 3,
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

    // Delivery assert: the winner session is still registered, so the new
    // advertisement MUST reach its outbound channel. (Before the fix this
    // never arrived — the stale PeerDown had removed the peer from
    // `outbound_peers`, so distribution skipped it forever.)
    let delivered = tokio::time::timeout(Duration::from_secs(5), winner_rx.recv())
        .await
        .expect(
            "stale collision-loser PeerDown wedged distribution — no advertisement \
             reached the surviving session's outbound channel",
        )
        .expect("winner outbound channel closed unexpectedly");
    assert!(
        delivered.evpn_announce.iter().any(|r| r.key() == imet_key),
        "delivered update must carry the post-convergence EVPN announce"
    );

    drop(winner_session_tx);
    drop(tx);
    handle.await.unwrap();
}

/// GR flavor of the stale collision-loser teardown: a
/// `PeerGracefulRestart` from a superseded session must be discarded by
/// the same session-identity rule. Before stamping, a stale GR-down
/// would mark the surviving session's routes stale AND deregister its
/// outbound sender (`clear_outbound_peer_state` runs on the GR path
/// too) — the same silent wedge. A GR-down whose id matches the
/// registered session keeps its stale-path-retention semantics
/// unchanged.
#[tokio::test]
async fn stale_graceful_restart_from_superseded_session_is_discarded() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    let peer_up =
        |outbound_tx: mpsc::Sender<OutboundRouteUpdate>, session_id: u64| RibUpdate::PeerUp {
            peer,
            session_id,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            outbound_tx,
            export_policy: None,
            sendable_families: evpn_sendable(),
            is_ebgp: false,
            route_reflector_client: true,
            orr_vantage: None,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
        };

    let (loser_tx, mut loser_rx) = mpsc::channel(8);
    tx.send(peer_up(loser_tx, 1)).await.unwrap();
    drain_eor(&mut loser_rx).await;

    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    let winner_session_tx = winner_tx.clone();
    tx.send(peer_up(winner_tx, 2)).await.unwrap();
    drain_eor(&mut winner_rx).await;

    // The dumped loser goes down with GR retention — stamped with ITS id.
    tx.send(RibUpdate::PeerGracefulRestart {
        peer,
        session_id: 1,
        restart_time: 30,
        stale_routes_time: 30,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // The winner session must still be registered: a new advertisement
    // reaches its outbound channel.
    let (source_tx, _source_rx) = mpsc::channel(8);
    tx.send(RibUpdate::PeerUp {
        peer: source,
        session_id: 3,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet_key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 3,
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

    let delivered = tokio::time::timeout(Duration::from_secs(5), winner_rx.recv())
        .await
        .expect(
            "stale collision-loser PeerGracefulRestart wedged distribution — no \
             advertisement reached the surviving session's outbound channel",
        )
        .expect("winner outbound channel closed unexpectedly");
    assert!(
        delivered.evpn_announce.iter().any(|r| r.key() == imet_key),
        "delivered update must carry the post-convergence EVPN announce"
    );

    drop(winner_session_tx);
    drop(tx);
    handle.await.unwrap();
}

/// The SYMMETRIC collision interleaving to
/// `stale_peer_down_after_replacement_peer_up_is_discarded`: the winner
/// session registers FIRST, the loser's `PeerUp` arrives later (cross-task
/// mpsc interleaving is arbitrary — per-sender FIFO only), and then the
/// loser's `PeerDown` lands. The loser's `PeerUp` is treated as a
/// replacement (clearing the winner's Adj-RIB-In and registering the
/// loser's outbound channel + session id), so the loser's `PeerDown`
/// MATCHES the registered id and runs the full teardown — leaving the
/// winner Established but deregistered with its Adj-RIB-In destroyed.
///
/// The completed design keeps every live session for the peer address in a
/// bounded per-peer map: when the active registration's session goes down
/// while another live session remains, the registration FAILS OVER to the
/// survivor (re-register its channel, re-run the initial table dump,
/// request an inbound ROUTE-REFRESH through its channel) instead of
/// tearing the peer down.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "failover regression keeps session interleaving and recovery assertions together"
)]
async fn peer_down_of_replacement_session_fails_over_to_surviving_session() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    let peer_up =
        |outbound_tx: mpsc::Sender<OutboundRouteUpdate>, session_id: u64| RibUpdate::PeerUp {
            peer,
            session_id,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            outbound_tx,
            export_policy: None,
            sendable_families: evpn_sendable(),
            is_ebgp: false,
            route_reflector_client: true,
            orr_vantage: None,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
        };

    // Session W (collision winner) registers first.
    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    let winner_session_tx = winner_tx.clone();
    tx.send(peer_up(winner_tx, 1)).await.unwrap();
    drain_eor(&mut winner_rx).await;

    // W's session delivers a route into its Adj-RIB-In.
    let imet_winner = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 2), 50);
    let imet_winner_key = imet_winner.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 1,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet_winner],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Session L (collision loser) reaches Established too; its PeerUp is
    // processed AFTER the winner's. The manager treats it as a
    // replacement and registers L's channel + id.
    let (loser_tx, mut loser_rx) = mpsc::channel(8);
    tx.send(peer_up(loser_tx, 2)).await.unwrap();
    drain_eor(&mut loser_rx).await;

    // The loser is torn down by collision resolution; its PeerDown is
    // stamped with ITS session id — which matches the registration.
    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 2,
    })
    .await
    .unwrap();

    // FAILOVER, half 1 — outbound: W's channel must be re-registered and
    // receive the failover initial-table dump (at minimum an EoR for its
    // sendable families).
    let dump = tokio::time::timeout(Duration::from_secs(5), winner_rx.recv())
        .await
        .expect(
            "PeerDown of the replacement (loser) session tore down the surviving \
             (winner) session's registration — no failover dump reached the \
             winner's outbound channel",
        )
        .expect("winner outbound channel closed unexpectedly");
    assert!(
        !dump.end_of_rib.is_empty() || dump.request_refresh_all_negotiated,
        "first post-failover update must be the initial dump EoR or the inbound \
         refresh request, got announce={} withdraw={}",
        dump.announce.len(),
        dump.withdraw.len(),
    );

    // FAILOVER, half 2 — inbound: W's Adj-RIB-In was cleared by the
    // loser's replacement reset (and W's routes were discarded by the
    // session-identity gate while superseded). The manager must
    // request an inbound ROUTE-REFRESH through W's channel so the peer
    // re-advertises; family selection is delegated to the session task's
    // negotiated set (the session task also enforces the RFC 2918
    // capability).
    let mut saw_refresh_request = dump.request_refresh_all_negotiated;
    if !saw_refresh_request {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(250), winner_rx.recv()).await {
                Ok(Some(update)) => {
                    if update.request_refresh_all_negotiated {
                        saw_refresh_request = true;
                        break;
                    }
                }
                Ok(None) => panic!("winner outbound channel closed unexpectedly"),
                Err(_) => {}
            }
        }
    }
    assert!(
        saw_refresh_request,
        "failover must request an inbound ROUTE-REFRESH toward the surviving \
         session (its Adj-RIB-In was cleared by the replacement reset; the \
         session task picks the families from its negotiated set)"
    );

    // The peer answers the refresh: W's route lands back in the Loc-RIB.
    let imet_again = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 2), 50);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 1,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet_again],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let evpn_routes = query_evpn_routes(&tx).await;
    assert!(
        evpn_routes.iter().any(|r| r.key() == imet_winner_key),
        "the surviving session's re-advertised route must land in the Loc-RIB"
    );

    // A post-convergence advertisement from another RR client must still
    // reach W — the registration survived the whole interleaving.
    let (source_tx, _source_rx) = mpsc::channel(8);
    tx.send(RibUpdate::PeerUp {
        peer: source,
        session_id: 3,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();

    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    let imet_key = imet.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 3,
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

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut delivered = false;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(250), winner_rx.recv()).await {
            Ok(Some(update)) => {
                if update.evpn_announce.iter().any(|r| r.key() == imet_key) {
                    delivered = true;
                    break;
                }
            }
            Ok(None) => panic!("winner outbound channel closed unexpectedly"),
            Err(_) => {}
        }
    }
    assert!(
        delivered,
        "post-convergence advertisement must reach the surviving session's \
         outbound channel after failover"
    );

    drop(winner_session_tx);
    drop(tx);
    handle.await.unwrap();
}

/// GR flavor of the registration failover: a `PeerGracefulRestart` from
/// the ACTIVE (replacement) session while another live session remains
/// must fail the registration over to the survivor — NOT enter GR
/// stale-path retention. Retention bridges a session that is gone; here
/// an Established session for the address exists and is refreshed
/// immediately instead.
#[tokio::test]
async fn graceful_restart_of_replacement_session_fails_over_to_surviving_session() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let metrics = BgpMetrics::new();
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let peer_up =
        |outbound_tx: mpsc::Sender<OutboundRouteUpdate>, session_id: u64| RibUpdate::PeerUp {
            peer,
            session_id,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            outbound_tx,
            export_policy: None,
            sendable_families: evpn_sendable(),
            is_ebgp: false,
            route_reflector_client: true,
            orr_vantage: None,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
        };

    // Winner registers first, loser's PeerUp replaces the registration.
    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    let winner_session_tx = winner_tx.clone();
    tx.send(peer_up(winner_tx, 1)).await.unwrap();
    drain_eor(&mut winner_rx).await;

    let (loser_tx, mut loser_rx) = mpsc::channel(8);
    tx.send(peer_up(loser_tx, 2)).await.unwrap();
    drain_eor(&mut loser_rx).await;

    // The loser goes down WITH GR — stamped with the ACTIVE session id.
    tx.send(RibUpdate::PeerGracefulRestart {
        peer,
        session_id: 2,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::L2Vpn, Safi::Evpn)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // Failover, not retention: the winner's channel receives the failover
    // initial dump and the inbound refresh request.
    let mut saw_refresh_request = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(250), winner_rx.recv()).await {
            Ok(Some(update)) => {
                if update.request_refresh_all_negotiated {
                    saw_refresh_request = true;
                    break;
                }
            }
            Ok(None) => panic!("winner outbound channel closed unexpectedly"),
            Err(_) => {}
        }
    }
    assert!(
        saw_refresh_request,
        "GR-down of the active session with a live survivor must fail over and \
         request an inbound ROUTE-REFRESH toward the survivor"
    );

    // GR retention must NOT have been entered for the peer (no stale
    // phase while an Established session holds the registration).
    let gr_active = gauge_metric_value(&metrics, "bgp_gr_active_peers", &[("peer", "10.0.0.2")]);
    assert!(
        gr_active.abs() < f64::EPSILON,
        "failover must not enter GR stale-path retention, gr_active = {gr_active}"
    );

    drop(winner_session_tx);
    drop(tx);
    handle.await.unwrap();
}

/// The failover inbound refresh must NOT be limited to the sendable
/// (outbound) family subset the manager sees in `PeerUp` — a family
/// negotiated for receive but pruned from the sendable set (e.g. IPv6
/// with no usable local IPv6 next-hop) still needs its Adj-RIB-In
/// repopulated. The manager therefore delegates family selection to the
/// session task via `request_refresh_all_negotiated`. Modeled here as
/// the extreme case: a survivor whose sendable set is EMPTY must still
/// get the refresh request (a sendable-derived selection would request
/// nothing at all).
#[tokio::test]
async fn failover_inbound_refresh_covers_negotiated_but_not_sendable_families() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Both sessions advertise an EMPTY sendable set — every negotiated
    // family is receive-only from the manager's point of view.
    let peer_up =
        |outbound_tx: mpsc::Sender<OutboundRouteUpdate>, session_id: u64| RibUpdate::PeerUp {
            peer,
            session_id,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            outbound_tx,
            export_policy: None,
            sendable_families: vec![],
            is_ebgp: false,
            route_reflector_client: true,
            orr_vantage: None,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
        };

    // Winner registers first, loser's PeerUp replaces the registration,
    // loser goes down — the registration fails over to the winner. (No
    // EoR drain: with an empty sendable set there is no initial dump.)
    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    let winner_session_tx = winner_tx.clone();
    tx.send(peer_up(winner_tx, 1)).await.unwrap();
    let (loser_tx, _loser_rx) = mpsc::channel(8);
    tx.send(peer_up(loser_tx, 2)).await.unwrap();
    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 2,
    })
    .await
    .unwrap();

    let mut saw_refresh_request = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(250), winner_rx.recv()).await {
            Ok(Some(update)) => {
                if update.request_refresh_all_negotiated {
                    saw_refresh_request = true;
                    break;
                }
            }
            Ok(None) => panic!("winner outbound channel closed unexpectedly"),
            Err(_) => {}
        }
    }
    assert!(
        saw_refresh_request,
        "failover must request the inbound ROUTE-REFRESH even when the \
         survivor's sendable family set is empty — the refresh covers \
         receive-side families the manager cannot see, so family selection \
         belongs to the session task"
    );

    drop(winner_session_tx);
    drop(tx);
    handle.await.unwrap();
}

/// `RibUpdate::PeerUp` boilerplate for the stale-data-message tests
/// below: an iBGP RR-client peer with the given sendable families.
fn session_peer_up(
    peer: IpAddr,
    session_id: u64,
    outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
    sendable_families: Vec<(Afi, Safi)>,
) -> RibUpdate {
    RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx,
        export_policy: None,
        sendable_families,
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    }
}

/// `RoutesReceived` queued by a superseded session and processed after
/// the replacement's `PeerUp` must be discarded by session identity —
/// otherwise stale routes from the dumped session land in the
/// replacement session's Adj-RIB-In (an announce/withdraw race can
/// leave entries the new session never sent). The ACTIVE session's
/// routes must still be accepted.
#[tokio::test]
async fn stale_routes_received_from_superseded_session_is_discarded() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Loser registers, winner's PeerUp replaces the registration.
    let (loser_tx, mut loser_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 1, loser_tx, evpn_sendable()))
        .await
        .unwrap();
    drain_eor(&mut loser_rx).await;
    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 2, winner_tx, evpn_sendable()))
        .await
        .unwrap();
    drain_eor(&mut winner_rx).await;

    // Stale routes from the superseded session, queued behind the
    // winner's PeerUp.
    let imet_stale = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 2), 50);
    let imet_stale_key = imet_stale.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 1,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet_stale],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let evpn_routes = query_evpn_routes(&tx).await;
    assert!(
        !evpn_routes.iter().any(|r| r.key() == imet_stale_key),
        "stale RoutesReceived from a superseded session must not land in the \
         replacement session's Adj-RIB-In"
    );

    // The ACTIVE session's routes still flow.
    let imet_active = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 2), 60);
    let imet_active_key = imet_active.key();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 2,
        peer,
        announced: vec![],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![imet_active],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let evpn_routes = query_evpn_routes(&tx).await;
    assert!(
        evpn_routes.iter().any(|r| r.key() == imet_active_key),
        "the active session's RoutesReceived must not be discarded"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A stale `EndOfRib` from a superseded session must not complete the
/// registered session's graceful-restart window for the family — a
/// premature completion ends stale-route retention on the strength of
/// a table dump the surviving session never finished.
#[tokio::test]
async fn stale_end_of_rib_from_superseded_session_is_discarded() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let metrics = BgpMetrics::new();
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Session 1 establishes, announces a route, then goes down with GR —
    // the route is retained stale, awaiting the reconnect's End-of-RIB.
    let (s1_tx, mut s1_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 1, s1_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut s1_rx).await;
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 1,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 2))],
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
        session_id: 1,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();

    // The peer reconnects as session 2 (re-registers during the GR
    // window; GR completion now waits on SESSION 2's End-of-RIB).
    let (s2_tx, mut s2_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 2, s2_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut s2_rx).await;

    // A stale EoR from the dumped session must NOT complete the sweep.
    tx.send(RibUpdate::EndOfRib {
        peer,
        session_id: 1,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    // Barrier: the query is processed after the EoR (same channel).
    let _ = query_received_routes(&tx, peer).await;
    let gr_active = gauge_metric_value(&metrics, "bgp_gr_active_peers", &[("peer", "10.0.0.2")]);
    assert!(
        (gr_active - 1.0).abs() < f64::EPSILON,
        "stale EndOfRib from a superseded session must not complete the \
         registered session's GR window, gr_active = {gr_active}"
    );

    // The ACTIVE session's EoR completes GR normally.
    tx.send(RibUpdate::EndOfRib {
        peer,
        session_id: 2,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let _ = query_received_routes(&tx, peer).await;
    let gr_active = gauge_metric_value(&metrics, "bgp_gr_active_peers", &[("peer", "10.0.0.2")]);
    assert!(
        gr_active.abs() < f64::EPSILON,
        "the active session's EndOfRib must complete GR, gr_active = {gr_active}"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Stale RFC 7313 demarcation markers (`BoRR`/`EoRR`) from a superseded
/// session must be discarded — a stale `BoRR` would mark the
/// replacement session's Adj-RIB-In refresh-stale and a stale `EoRR`
/// would close the window and sweep routes the new session was about
/// to re-send. The ACTIVE session's markers keep their semantics.
#[tokio::test]
async fn stale_enhanced_refresh_markers_from_superseded_session_are_discarded() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (loser_tx, mut loser_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 1, loser_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut loser_rx).await;
    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 2, winner_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut winner_rx).await;

    // The active session's route sits in the Adj-RIB-In.
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 2,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 2))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Stale BoRR + EoRR from the superseded session: without the gate,
    // this pair opens a refresh window over the active session's
    // Adj-RIB-In and immediately sweeps every route in the family.
    for subtype_is_begin in [true, false] {
        let update = if subtype_is_begin {
            RibUpdate::BeginRouteRefresh {
                peer,
                session_id: 1,
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            }
        } else {
            RibUpdate::EndRouteRefresh {
                peer,
                session_id: 1,
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            }
        };
        tx.send(update).await.unwrap();
    }
    let received = query_received_routes(&tx, peer).await;
    assert!(
        received.iter().any(|r| r.prefix == Prefix::V4(prefix)),
        "stale BoRR/EoRR from a superseded session must not sweep the \
         registered session's Adj-RIB-In"
    );

    // The ACTIVE session's BoRR + EoRR keep their semantics: the route
    // is not re-announced inside the window, so it is swept at EoRR.
    tx.send(RibUpdate::BeginRouteRefresh {
        peer,
        session_id: 2,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndRouteRefresh {
        peer,
        session_id: 2,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let received = query_received_routes(&tx, peer).await;
    assert!(
        !received.iter().any(|r| r.prefix == Prefix::V4(prefix)),
        "the active session's BoRR/EoRR must still sweep unreplaced routes"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A stale `RouteRefreshRequest` from a superseded session must be
/// discarded (it would only trigger a spurious re-advertisement, but
/// the same active-or-drop rule applies to every session-scoped
/// message); the ACTIVE session's request still gets the full
/// refresh response.
#[tokio::test]
async fn stale_route_refresh_request_from_superseded_session_is_discarded() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (loser_tx, mut loser_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 1, loser_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut loser_rx).await;
    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 2, winner_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut winner_rx).await;

    // Stale request: no refresh response may reach the active session's
    // outbound channel.
    tx.send(RibUpdate::RouteRefreshRequest {
        peer,
        session_id: 1,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    // Barrier: the query reply proves the request was processed.
    let _ = query_received_routes(&tx, peer).await;
    assert!(
        winner_rx.try_recv().is_err(),
        "stale RouteRefreshRequest from a superseded session must not \
         trigger a re-advertisement"
    );

    // The ACTIVE session's request produces the refresh response (EoR +
    // demarcation markers even with an empty table).
    tx.send(RibUpdate::RouteRefreshRequest {
        peer,
        session_id: 2,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), winner_rx.recv())
        .await
        .expect("the active session's RouteRefreshRequest must get a response")
        .expect("winner outbound channel closed unexpectedly");
    assert!(
        !response.refresh_markers.is_empty() || !response.end_of_rib.is_empty(),
        "refresh response must carry the demarcation markers / EoR"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Stale ORF entries from a superseded session must not install or
/// modify the replacement session's outbound filter — ORF state is
/// per-session (RFC 5291). The discard is observable on the reply
/// channel; the ACTIVE session's ORF update still applies.
#[tokio::test]
async fn stale_orf_update_from_superseded_session_is_discarded() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (loser_tx, mut loser_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 1, loser_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut loser_rx).await;
    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 2, winner_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut winner_rx).await;

    let entry = AddressPrefixOrf {
        action: OrfAction::Add,
        match_: OrfMatch::Deny,
        sequence: 10,
        min_len: 0,
        max_len: 32,
        prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 16))),
    };

    // Stale ORF push: rejected on the reply channel, filter not installed.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::PeerOrfUpdate {
        peer,
        session_id: 1,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        when: WhenToRefresh::Defer,
        entries: vec![entry],
        reply: reply_tx,
    })
    .await
    .unwrap();
    let result = reply_rx.await.unwrap();
    assert!(
        result.is_err(),
        "stale PeerOrfUpdate from a superseded session must be rejected, got {result:?}"
    );

    // The ACTIVE session's ORF push is accepted.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::PeerOrfUpdate {
        peer,
        session_id: 2,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        when: WhenToRefresh::Defer,
        entries: vec![entry],
        reply: reply_tx,
    })
    .await
    .unwrap();
    let result = reply_rx.await.unwrap();
    assert!(
        result.is_ok(),
        "the active session's PeerOrfUpdate must be accepted, got {result:?}"
    );

    drop(winner_rx);
    drop(tx);
    handle.await.unwrap();
}

/// No-false-drops guard for the session-identity gate on data messages:
/// every message kind stamped with the ACTIVE session's id (and the
/// legacy id-0 flavor on an id-0 registration) flows exactly as before
/// stamping.
#[tokio::test]
async fn active_session_messages_flow_after_replacement() {
    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Replacement scenario: the gate sees a non-trivial registration.
    let (loser_tx, mut loser_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 1, loser_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut loser_rx).await;
    let (winner_tx, mut winner_rx) = mpsc::channel(8);
    tx.send(session_peer_up(peer, 2, winner_tx, ipv4_sendable()))
        .await
        .unwrap();
    drain_eor(&mut winner_rx).await;

    // Routes from the active session land in the Adj-RIB-In.
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 2,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 2))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let received = query_received_routes(&tx, peer).await;
    assert!(
        received.iter().any(|r| r.prefix == Prefix::V4(prefix)),
        "the active session's routes must be accepted"
    );

    // A refresh request from the active session gets its response.
    tx.send(RibUpdate::RouteRefreshRequest {
        peer,
        session_id: 2,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    })
    .await
    .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), winner_rx.recv())
        .await
        .expect("the active session's RouteRefreshRequest must get a response")
        .expect("winner outbound channel closed unexpectedly");
    assert!(
        !response.refresh_markers.is_empty() || !response.end_of_rib.is_empty(),
        "refresh response must carry the demarcation markers / EoR"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn unregistered_session_message_keeps_legacy_accept_behavior() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 44, 0, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 77,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 2))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let received = query_received_routes(&tx, peer).await;
    assert!(
        received
            .iter()
            .any(|route| route.prefix == Prefix::V4(prefix)),
        "unregistered data messages intentionally retain the legacy accept behavior"
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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

// --- Typed-family LLGR two-phase lifecycle (RFC 9494): VPN, BGP-LS, RTC ---

/// GR entry with LLGR negotiated for the given family tuples. The per-family
/// LLGR stale time equals `llgr_stale_time`.
fn gr_with_llgr(
    peer: IpAddr,
    restart_time: u16,
    gr_families: Vec<(Afi, Safi)>,
    llgr_families: Vec<(Afi, Safi)>,
    llgr_stale_time: u32,
) -> RibUpdate {
    RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer,
        restart_time,
        stale_routes_time: 360,
        gr_families,
        peer_llgr_capable: true,
        peer_llgr_families: llgr_families
            .into_iter()
            .map(|(afi, safi)| rustbgpd_wire::LlgrFamily {
                afi,
                safi,
                forwarding_preserved: false,
                stale_time: llgr_stale_time,
            })
            .collect(),
        llgr_stale_time,
    }
}

/// Bring up an iBGP route-reflector client negotiating `sendable`, for
/// observing typed-family re-exports.
async fn llgr_target_peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    sendable: Vec<(Afi, Safi)>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: sendable,
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    out_rx
}

/// GR-timer expiry with LLGR negotiated promotes GR-stale VPN routes to
/// LLGR-stale: flag flip, locally-injected `LLGR_STALE` community, and a
/// DEEPER tiebreak demotion — an LLGR-stale candidate loses to a GR-stale
/// one regardless of `LOCAL_PREF` (RFC 9494 §4.3).
#[tokio::test]
async fn vpn_llgr_gr_timer_promotes_to_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    // Same key from both peers; A wins the LOCAL_PREF tiebreak.
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: peer_a,
        announced: vec![make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 200)],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: peer_b,
        announced: vec![make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 3), 31, 100, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::Ipv4, Safi::MplsVpn)];
    tx.send(gr_with_llgr(
        peer_a,
        2,
        family.clone(),
        family.clone(),
        3600,
    ))
    .await
    .unwrap();
    tx.send(gr_with_llgr(peer_b, 10, family.clone(), family, 3600))
        .await
        .unwrap();

    let best = query_vpn_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_a, "both GR-stale: LOCAL_PREF tiebreak");
    assert!(best[0].is_stale);
    assert!(!best[0].is_llgr_stale);

    // Past A's GR timer only: A is promoted to LLGR-stale and now ranks
    // BELOW B's GR-stale route despite the higher LOCAL_PREF.
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let best = query_vpn_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_b, "GR-stale must outrank LLGR-stale");
    assert!(best[0].is_stale);

    // Past B's GR timer too: both LLGR-stale, the LOCAL_PREF tiebreak
    // re-applies and the promoted route carries the injected community.
    tokio::time::advance(Duration::from_secs(8)).await;
    tokio::task::yield_now().await;
    let best = query_vpn_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_a);
    assert!(!best[0].is_stale);
    assert!(best[0].is_llgr_stale);
    assert!(
        best[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "promoted VPN route must carry LLGR_STALE community"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn bgpls_llgr_gr_timer_promotes_to_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    // Same key from both peers; A wins the LOCAL_PREF tiebreak.
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: peer_a,
        announced: vec![make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 0x01, 200)],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: peer_b,
        announced: vec![make_bgpls_route(Ipv4Addr::new(10, 0, 0, 3), 0x01, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::BgpLs, Safi::BgpLs)];
    tx.send(gr_with_llgr(
        peer_a,
        2,
        family.clone(),
        family.clone(),
        3600,
    ))
    .await
    .unwrap();
    tx.send(gr_with_llgr(peer_b, 10, family.clone(), family, 3600))
        .await
        .unwrap();

    let best = query_bgpls_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_a, "both GR-stale: LOCAL_PREF tiebreak");
    assert!(best[0].is_stale);
    assert!(!best[0].is_llgr_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let best = query_bgpls_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_b, "GR-stale must outrank LLGR-stale");
    assert!(best[0].is_stale);

    tokio::time::advance(Duration::from_secs(8)).await;
    tokio::task::yield_now().await;
    let best = query_bgpls_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_a);
    assert!(!best[0].is_stale);
    assert!(best[0].is_llgr_stale);
    assert!(
        best[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "promoted BGP-LS route must carry LLGR_STALE community"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rtc_llgr_gr_timer_promotes_to_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    // Same NLRI from both peers; A wins the LOCAL_PREF tiebreak.
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: peer_a,
        announced: vec![make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 200)],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: peer_b,
        announced: vec![make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 3), 100, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::Ipv4, Safi::RtConstrain)];
    tx.send(gr_with_llgr(
        peer_a,
        2,
        family.clone(),
        family.clone(),
        3600,
    ))
    .await
    .unwrap();
    tx.send(gr_with_llgr(peer_b, 10, family.clone(), family, 3600))
        .await
        .unwrap();

    let best = query_rtc_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_a, "both GR-stale: LOCAL_PREF tiebreak");
    assert!(best[0].is_stale);
    assert!(!best[0].is_llgr_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let best = query_rtc_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_b, "GR-stale must outrank LLGR-stale");
    assert!(best[0].is_stale);

    tokio::time::advance(Duration::from_secs(8)).await;
    tokio::task::yield_now().await;
    let best = query_rtc_routes(&tx).await;
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer_a);
    assert!(!best[0].is_stale);
    assert!(best[0].is_llgr_stale);
    assert!(
        best[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "promoted RTC route must carry LLGR_STALE community"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn vpn_llgr_timer_sweeps_llgr_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::Ipv4, Safi::MplsVpn)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 10))
        .await
        .unwrap();
    let stale = query_vpn_routes(&tx).await;
    assert!(stale[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let promoted = query_vpn_routes(&tx).await;
    assert!(promoted[0].is_llgr_stale);

    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;
    assert!(
        query_vpn_routes(&tx).await.is_empty(),
        "LLGR timer expiry must sweep LLGR-stale VPN routes"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn bgpls_llgr_timer_sweeps_llgr_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 0x01, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::BgpLs, Safi::BgpLs)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 10))
        .await
        .unwrap();
    let stale = query_bgpls_routes(&tx).await;
    assert!(stale[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let promoted = query_bgpls_routes(&tx).await;
    assert!(promoted[0].is_llgr_stale);

    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;
    assert!(
        query_bgpls_routes(&tx).await.is_empty(),
        "LLGR timer expiry must sweep LLGR-stale BGP-LS routes"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rtc_llgr_timer_sweeps_llgr_stale_routes() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::Ipv4, Safi::RtConstrain)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 10))
        .await
        .unwrap();
    let stale = query_rtc_routes(&tx).await;
    assert!(stale[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let promoted = query_rtc_routes(&tx).await;
    assert!(promoted[0].is_llgr_stale);

    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;
    assert!(
        query_rtc_routes(&tx).await.is_empty(),
        "LLGR timer expiry must sweep LLGR-stale RTC routes"
    );

    drop(tx);
    handle.await.unwrap();
}

/// `EoR` during the LLGR phase: re-advertised routes survive with the flag
/// cleared and the locally-injected `LLGR_STALE` community gone; a
/// peer-originated `LLGR_STALE` community is preserved; what was NOT
/// re-advertised is deleted and withdrawn downstream (RFC 4724 §4.1 via
/// RFC 9494 §4.2).
#[tokio::test]
async fn vpn_llgr_eor_clears_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = llgr_target_peer_up(&tx, target, vpn_sendable()).await;
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 60, 100, 100);
    let mut kept_tagged = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 61, 100, 100);
    Arc::make_mut(&mut kept_tagged.attributes).push(PathAttribute::Communities(vec![
        rustbgpd_wire::COMMUNITY_LLGR_STALE,
    ]));
    let dropped = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 62, 100, 100);
    let kept_key = kept.key();
    let kept_tagged_key = kept_tagged.key();
    let dropped_key = dropped.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept.clone(), kept_tagged.clone(), dropped],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.vpn_announce.len(), 3);

    let family = vec![(Afi::Ipv4, Safi::MplsVpn)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    let stale = query_vpn_routes(&tx).await;
    assert!(stale.iter().all(|r| r.is_stale));

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let promoted = query_vpn_routes(&tx).await;
    assert!(promoted.iter().all(|r| r.is_llgr_stale));

    // Only the two `kept` routes are re-advertised before End-of-RIB; the
    // tagged one still carries its peer-originated LLGR_STALE community.
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept, kept_tagged],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();

    let after_eor = query_vpn_routes(&tx).await;
    assert!(
        after_eor.iter().all(|r| r.key() != dropped_key),
        "the non-readvertised LLGR-stale VPN route must be removed at End-of-RIB"
    );
    let plain = after_eor
        .iter()
        .find(|r| r.key() == kept_key)
        .expect("re-advertised VPN route survives EoR");
    assert!(!plain.is_llgr_stale, "EoR must clear the LLGR-stale flag");
    assert!(
        !plain
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "the locally-injected LLGR_STALE community must not survive EoR"
    );
    let tagged = after_eor
        .iter()
        .find(|r| r.key() == kept_tagged_key)
        .expect("re-advertised tagged VPN route survives EoR");
    assert!(!tagged.is_llgr_stale);
    assert!(
        tagged
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "a peer-originated LLGR_STALE community must be preserved"
    );

    // The EoR removal must be withdrawn downstream.
    loop {
        let update = out_rx.recv().await.unwrap();
        if update.vpn_withdraw.is_empty() {
            continue;
        }
        assert_eq!(update.vpn_withdraw, vec![dropped_key.clone()]);
        break;
    }

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn bgpls_llgr_eor_clears_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = llgr_target_peer_up(&tx, target, bgpls_sendable()).await;
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 0x60, 100);
    let mut kept_tagged = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 0x61, 100);
    Arc::make_mut(&mut kept_tagged.attributes).push(PathAttribute::Communities(vec![
        rustbgpd_wire::COMMUNITY_LLGR_STALE,
    ]));
    let dropped = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 0x62, 100);
    let kept_key = kept.key();
    let kept_tagged_key = kept_tagged.key();
    let dropped_key = dropped.key();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept.clone(), kept_tagged.clone(), dropped],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.bgpls_announce.len(), 3);

    let family = vec![(Afi::BgpLs, Safi::BgpLs)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    let stale = query_bgpls_routes(&tx).await;
    assert!(stale.iter().all(|r| r.is_stale));

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let promoted = query_bgpls_routes(&tx).await;
    assert!(promoted.iter().all(|r| r.is_llgr_stale));

    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept, kept_tagged],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::BgpLs,
        safi: Safi::BgpLs,
    })
    .await
    .unwrap();

    let after_eor = query_bgpls_routes(&tx).await;
    assert!(
        after_eor.iter().all(|r| r.key() != dropped_key),
        "the non-readvertised LLGR-stale BGP-LS route must be removed at End-of-RIB"
    );
    let plain = after_eor
        .iter()
        .find(|r| r.key() == kept_key)
        .expect("re-advertised BGP-LS route survives EoR");
    assert!(!plain.is_llgr_stale, "EoR must clear the LLGR-stale flag");
    assert!(
        !plain
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "the locally-injected LLGR_STALE community must not survive EoR"
    );
    let tagged = after_eor
        .iter()
        .find(|r| r.key() == kept_tagged_key)
        .expect("re-advertised tagged BGP-LS route survives EoR");
    assert!(!tagged.is_llgr_stale);
    assert!(
        tagged
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "a peer-originated LLGR_STALE community must be preserved"
    );

    loop {
        let update = out_rx.recv().await.unwrap();
        if update.bgpls_withdraw.is_empty() {
            continue;
        }
        assert_eq!(update.bgpls_withdraw, vec![dropped_key.clone()]);
        break;
    }

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rtc_llgr_eor_clears_llgr_stale() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, target, true, false).await;
    drain_rtc_initial_dump(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let kept = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    let mut kept_tagged = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 101, 100);
    Arc::make_mut(&mut kept_tagged.attributes).push(PathAttribute::Communities(vec![
        rustbgpd_wire::COMMUNITY_LLGR_STALE,
    ]));
    let dropped = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 102, 100);
    let kept_key = kept.key();
    let kept_tagged_key = kept_tagged.key();
    let dropped_key = dropped.key();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept.clone(), kept_tagged.clone(), dropped],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.rtc_announce.len(), 3);

    let family = vec![(Afi::Ipv4, Safi::RtConstrain)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    let stale = query_rtc_routes(&tx).await;
    assert!(stale.iter().all(|r| r.nlri.is_default() || r.is_stale));

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let promoted = query_rtc_routes(&tx).await;
    assert!(
        promoted
            .iter()
            .all(|r| r.nlri.is_default() || r.is_llgr_stale)
    );

    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![kept, kept_tagged],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::EndOfRib {
        session_id: 0,
        peer: source,
        afi: Afi::Ipv4,
        safi: Safi::RtConstrain,
    })
    .await
    .unwrap();

    let after_eor = query_rtc_routes(&tx).await;
    assert!(
        after_eor.iter().all(|r| r.key() != dropped_key),
        "the non-readvertised LLGR-stale RTC route must be removed at End-of-RIB"
    );
    let plain = after_eor
        .iter()
        .find(|r| r.key() == kept_key)
        .expect("re-advertised RTC route survives EoR");
    assert!(!plain.is_llgr_stale, "EoR must clear the LLGR-stale flag");
    assert!(
        !plain
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "the locally-injected LLGR_STALE community must not survive EoR"
    );
    let tagged = after_eor
        .iter()
        .find(|r| r.key() == kept_tagged_key)
        .expect("re-advertised tagged RTC route survives EoR");
    assert!(!tagged.is_llgr_stale);
    assert!(
        tagged
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "a peer-originated LLGR_STALE community must be preserved"
    );

    loop {
        let update = out_rx.recv().await.unwrap();
        if update.rtc_withdraw.is_empty() {
            continue;
        }
        assert_eq!(update.rtc_withdraw, vec![dropped_key.clone()]);
        break;
    }

    drop(tx);
    handle.await.unwrap();
}

/// RFC 9494 §4.3: a route carrying `NO_LLGR` must not enter the LLGR phase —
/// it is removed at GR-timer expiry instead of being promoted.
#[tokio::test]
async fn vpn_llgr_no_llgr_community_drops_route_on_promotion() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let mut route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100);
    Arc::make_mut(&mut route.attributes).push(PathAttribute::Communities(vec![
        rustbgpd_wire::COMMUNITY_NO_LLGR,
    ]));
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::Ipv4, Safi::MplsVpn)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    let stale = query_vpn_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(
        query_vpn_routes(&tx).await.is_empty(),
        "NO_LLGR VPN route must be dropped on GR timer expiry"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn bgpls_llgr_no_llgr_community_drops_route_on_promotion() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let mut route = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 0x01, 100);
    Arc::make_mut(&mut route.attributes).push(PathAttribute::Communities(vec![
        rustbgpd_wire::COMMUNITY_NO_LLGR,
    ]));
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::BgpLs, Safi::BgpLs)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    let stale = query_bgpls_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(
        query_bgpls_routes(&tx).await.is_empty(),
        "NO_LLGR BGP-LS route must be dropped on GR timer expiry"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rtc_llgr_no_llgr_community_drops_route_on_promotion() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let mut route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    Arc::make_mut(&mut route.attributes).push(PathAttribute::Communities(vec![
        rustbgpd_wire::COMMUNITY_NO_LLGR,
    ]));
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let family = vec![(Afi::Ipv4, Safi::RtConstrain)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    let stale = query_rtc_routes(&tx).await;
    assert_eq!(stale.len(), 1);
    assert!(stale[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(
        query_rtc_routes(&tx).await.is_empty(),
        "NO_LLGR RTC route must be dropped on GR timer expiry"
    );

    drop(tx);
    handle.await.unwrap();
}

/// RFC 9494 §4.3: a promoted LLGR-stale route re-exported to another iBGP
/// peer carries the `LLGR_STALE` community — it must not be removed on
/// re-advertisement.
#[tokio::test]
async fn vpn_llgr_stale_reexport_carries_community() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = llgr_target_peer_up(&tx, target, vpn_sendable()).await;
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100);
    let key = route.key();
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.vpn_announce.len(), 1);
    assert!(
        !first.vpn_announce[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
    );

    let family = vec![(Afi::Ipv4, Safi::MplsVpn)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    // Force the manager to process PeerGracefulRestart before advancing time.
    assert!(query_vpn_routes(&tx).await[0].is_stale);
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    // Sync point: promotion processed and distributed, then drain the
    // staged updates. The GR-entry restage may re-announce the still-plain
    // stale route first; the promotion restage must carry the community.
    assert!(query_vpn_routes(&tx).await[0].is_llgr_stale);
    let mut seen = false;
    while let Ok(update) = out_rx.try_recv() {
        if let Some(re) = update.vpn_announce.iter().find(|r| r.key() == key)
            && re
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
        {
            seen = true;
        }
    }
    assert!(
        seen,
        "re-exported LLGR-stale VPN route must carry LLGR_STALE"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn bgpls_llgr_stale_reexport_carries_community() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = llgr_target_peer_up(&tx, target, bgpls_sendable()).await;
    drain_eor(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 0x01, 100);
    let key = route.key();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.bgpls_announce.len(), 1);
    assert!(
        !first.bgpls_announce[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
    );

    let family = vec![(Afi::BgpLs, Safi::BgpLs)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    // Force the manager to process PeerGracefulRestart before advancing time.
    assert!(query_bgpls_routes(&tx).await[0].is_stale);
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    // Sync point: promotion processed and distributed.
    assert!(query_bgpls_routes(&tx).await[0].is_llgr_stale);
    let mut seen = false;
    while let Ok(update) = out_rx.try_recv() {
        if let Some(re) = update.bgpls_announce.iter().find(|r| r.key() == key)
            && re
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
        {
            seen = true;
        }
    }
    assert!(
        seen,
        "re-exported LLGR-stale BGP-LS route must carry LLGR_STALE"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rtc_llgr_stale_reexport_carries_community() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 100));
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut out_rx = rtc_peer_up(&tx, target, false, true).await;
    drain_rtc_initial_dump(&mut out_rx).await;

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let route = make_rtc_rib_route(Ipv4Addr::new(10, 0, 0, 1), 100, 100);
    let key = route.key();
    tx.send(RibUpdate::RtcRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let first = out_rx.recv().await.unwrap();
    assert_eq!(first.rtc_announce.len(), 1);
    assert!(
        !first.rtc_announce[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
    );

    let family = vec![(Afi::Ipv4, Safi::RtConstrain)];
    tx.send(gr_with_llgr(source, 2, family.clone(), family, 3600))
        .await
        .unwrap();
    // Force the manager to process PeerGracefulRestart before advancing time.
    assert!(
        query_rtc_routes(&tx)
            .await
            .iter()
            .any(|r| r.key() == key && r.is_stale)
    );
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    // Sync point: promotion processed and distributed.
    assert!(
        query_rtc_routes(&tx)
            .await
            .iter()
            .any(|r| r.key() == key && r.is_llgr_stale)
    );
    let mut seen = false;
    while let Ok(update) = out_rx.try_recv() {
        if let Some(re) = update.rtc_announce.iter().find(|r| r.key() == key)
            && re
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
        {
            seen = true;
        }
    }
    assert!(
        seen,
        "re-exported LLGR-stale RTC route must carry LLGR_STALE"
    );

    drop(tx);
    handle.await.unwrap();
}

/// A peer whose LLGR capability covers VPN but NOT BGP-LS splits at GR-timer
/// expiry: the VPN route is promoted to LLGR-stale, the BGP-LS route is
/// purged (RFC 9494 §4.3: only LLGR-negotiated families are retained).
#[tokio::test]
async fn llgr_families_split_promote_vs_purge_for_typed_families() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_vpn_rib_route(Ipv4Addr::new(10, 0, 0, 1), 31, 100, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_bgpls_route(Ipv4Addr::new(10, 0, 0, 1), 0x01, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    tx.send(gr_with_llgr(
        source,
        2,
        vec![(Afi::Ipv4, Safi::MplsVpn), (Afi::BgpLs, Safi::BgpLs)],
        vec![(Afi::Ipv4, Safi::MplsVpn)],
        3600,
    ))
    .await
    .unwrap();
    assert!(query_vpn_routes(&tx).await[0].is_stale);
    assert!(query_bgpls_routes(&tx).await[0].is_stale);

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    let vpn = query_vpn_routes(&tx).await;
    assert_eq!(vpn.len(), 1, "LLGR-covered VPN route must be retained");
    assert!(vpn[0].is_llgr_stale);
    assert!(
        vpn[0]
            .communities()
            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
    );
    assert!(
        query_bgpls_routes(&tx).await.is_empty(),
        "BGP-LS outside the LLGR capability must purge at GR expiry"
    );

    drop(tx);
    handle.await.unwrap();
}

/// The LLGR-expiry sweep is where a down peer's GR/LLGR-preserved RT
/// interest finally dies: after the sweep, a re-established session's
/// initial dump must withhold VPN routes again (empty membership), whereas
/// during the retention window the preserved membership kept serving them.
#[tokio::test]
async fn rtc_llgr_sweep_drops_preserved_vpn_membership() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_vpn_rib_route_with_rts(
            Ipv4Addr::new(10, 0, 0, 1),
            60,
            vec![rt(100)],
        )],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let target = Ipv4Addr::new(10, 0, 0, 2);
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;
    send_rtc_interest(&tx, target, &[100]).await;
    let announced = out_rx.recv().await.unwrap();
    assert_eq!(announced.vpn_announce.len(), 1);

    // GR entry preserving RTC through both retention phases.
    tx.send(gr_with_llgr(
        IpAddr::V4(target),
        2,
        vec![(Afi::Ipv4, Safi::RtConstrain)],
        vec![(Afi::Ipv4, Safi::RtConstrain)],
        10,
    ))
    .await
    .unwrap();

    // Past the GR timer: the interest is promoted, not purged.
    // Force the manager to process PeerGracefulRestart before advancing time.
    let marked = query_rtc_routes(&tx).await;
    assert!(marked.iter().any(|r| !r.nlri.is_default() && r.is_stale));

    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let retained = query_rtc_routes(&tx).await;
    assert!(
        retained
            .iter()
            .any(|r| !r.nlri.is_default() && r.is_llgr_stale),
        "RT interest must survive the GR→LLGR promotion"
    );

    // Past the LLGR timer: the interest is swept and the membership dies.
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;
    let after_sweep = query_rtc_routes(&tx).await;
    assert!(
        after_sweep.iter().all(|r| r.nlri.is_default()),
        "LLGR expiry must sweep the preserved RT interest"
    );

    // Re-establish: the strict dump helper asserts ZERO VPN routes — the
    // preserved membership is gone, so nothing may be served.
    let mut out_rx = vpn_rtc_peer_up(&tx, IpAddr::V4(target)).await;
    drain_strict_vpn_rtc_initial_dump(&mut out_rx).await;

    drop(tx);
    handle.await.unwrap();
}

/// LLGR-stale BGP-LS routes keep feeding the ORR topology (RFC 9107
/// vantages stay resolved) through BOTH retention phases; the LLGR-expiry
/// sweep is where the vantage finally unresolves.
#[tokio::test]
async fn bgpls_llgr_stale_topology_keeps_orr_vantages_resolved_until_llgr_sweep() {
    tokio::time::pause();

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let _out_rx = orr_client_peer_up(&tx, client, Some(vantage_at_node_a())).await;

    let feed = Ipv4Addr::new(10, 9, 9, 9);
    feed_square_topology(&tx, feed).await;
    let status = query_orr_status(&tx).await;
    assert!(status.vantages[0].resolved);
    assert_eq!(status.topology_nodes, 4);

    let family = vec![(Afi::BgpLs, Safi::BgpLs)];
    tx.send(gr_with_llgr(
        IpAddr::V4(feed),
        2,
        family.clone(),
        family,
        10,
    ))
    .await
    .unwrap();
    let status = query_orr_status(&tx).await;
    assert!(
        status.vantages[0].resolved,
        "GR-stale BGP-LS routes must keep feeding the topology"
    );

    // Past the GR timer: promotion to LLGR-stale keeps the routes in the
    // Adj-RIB-In, so the topology (and the vantage) must survive.
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    let status = query_orr_status(&tx).await;
    assert!(
        status.vantages[0].resolved,
        "LLGR-stale BGP-LS routes must keep feeding the topology"
    );
    assert_eq!(status.topology_nodes, 4);

    // Past the LLGR timer: the sweep empties the topology — NOW the
    // vantage unresolves.
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;
    let status = query_orr_status(&tx).await;
    assert!(
        !status.vantages[0].resolved,
        "the LLGR expiry sweep must rebuild the cache against the emptied topology"
    );
    assert_eq!(status.topology_nodes, 0);

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
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
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
        session_id: 0,
        peer: early,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: early_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer: late,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: late_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
#[expect(
    clippy::too_many_lines,
    reason = "EVPN export-policy regression keeps route setup and modification assertions together"
)]
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    let (source_out_tx, mut source_out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: source,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
        outbound_tx: source_out_tx,
        export_policy: None,
        sendable_families: evpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut source_out_rx).await;

    let imet = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
            session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
            session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
            session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
            session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
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

/// Drain outbound updates until `prefix` has been announced.
async fn collect_until_announced(out_rx: &mut mpsc::Receiver<OutboundRouteUpdate>, prefix: Prefix) {
    let deadline = Duration::from_secs(5);
    let result = tokio::time::timeout(deadline, async {
        loop {
            let u = out_rx.recv().await.expect("outbound channel open");
            if u.announce.iter().any(|route| route.prefix == prefix) {
                break;
            }
        }
    })
    .await;
    assert!(
        result.is_ok(),
        "expected {prefix:?} to be announced within {deadline:?}"
    );
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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

#[tokio::test]
async fn orf_unknown_when_resets_filter_and_sweeps() {
    let (tx, handle, target, mut out_rx) = orf_setup().await;

    // First install a restrictive ORF that permits only 10/8, proving the
    // 192.168/16 route is currently suppressed.
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
    assert!(
        tokio::time::timeout(Duration::from_millis(200), out_rx.recv())
            .await
            .is_err(),
        "192.168/16 must be suppressed before the malformed ORF control update"
    );

    // RFC 5291 only defines IMMEDIATE and DEFER. An unknown timing value must
    // not silently install the peer's entries as deferred state; reset the
    // negotiated ORF list and force a safe resync.
    send_peer_orf(
        &tx,
        target,
        WhenToRefresh::Unknown(0x7f),
        vec![orf_deny(
            1,
            0,
            32,
            Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0),
        )],
    )
    .await;
    collect_until_announced(
        &mut out_rx,
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 16)),
    )
    .await;

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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families,
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: dual_stack_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
        session_id: 0,
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
        session_id: 0,
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
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
    });
    manager.handle_update(RibUpdate::PeerGracefulRestart {
        session_id: 0,
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
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx2,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
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
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    });
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
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    });
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

#[test]
fn evpn_withdraw_gcs_attr_intern_under_mac_mobility() {
    // Regression: RFC 7432 §7.7 MAC Mobility re-advertises the SAME EVPN route
    // key with a fresh attribute set on every move (the sequence number carried
    // in the MAC Mobility extended community increments each time). `insert_evpn`
    // interns each distinct attribute set, so the EVPN withdraw paths MUST GC the
    // intern table — otherwise every move permanently orphans one interned set
    // and the table grows unbounded under sustained mobility (observed as a
    // ~258 MB/h RSS leak on every node, RR included, in the M67 link-drain soak).
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    // Churn well past the bounded event-history ring so an unbounded intern
    // table is unmistakable: pre-fix this grows one orphaned interned set per
    // move (→ `moves` sets); post-fix the withdraw GC reclaims every set not
    // still referenced by the ring, so it plateaus at/below the ring capacity.
    let moves = u32::try_from(EVPN_ROUTE_EVENT_HISTORY_CAPACITY).unwrap() + 2000;
    for seq in 0..moves {
        // Same key, distinct attribute set per "move" — `Med(seq)` stands in
        // for the incrementing MAC Mobility sequence so each set interns anew.
        let mut route = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
        route.attributes = Arc::new(vec![PathAttribute::Med(seq)]);
        let key = route.key();
        manager.process_evpn_announce_chunk(peer, vec![route]);
        manager.process_evpn_withdraw_chunk(peer, vec![key]);
    }

    let intern = manager.ribs[&peer].intern_len();
    assert!(
        intern <= EVPN_ROUTE_EVENT_HISTORY_CAPACITY,
        "EVPN attribute intern table grew unbounded under MAC-mobility churn: \
         {intern} interned sets after {moves} moves (must stay bounded by the \
         {EVPN_ROUTE_EVENT_HISTORY_CAPACITY}-entry event-history ring)"
    );
    assert_eq!(
        manager.ribs[&peer].evpn_len(),
        0,
        "every churned route was withdrawn from the Adj-RIB-In"
    );
}

#[test]
fn evpn_announce_replace_reclaims_attr_intern() {
    // The dominant M67 leak path: MAC Mobility re-advertises the SAME key with
    // a fresh attribute set on every move *without* an intervening withdraw
    // (the route is replaced in place, e.g. by originator re-injection). The
    // announce path must reclaim the stranded interned set or steady-state
    // re-advertise churn leaks unbounded.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let moves = u32::try_from(EVPN_ROUTE_EVENT_HISTORY_CAPACITY).unwrap() + 2000;
    for seq in 0..moves {
        let mut route = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
        route.attributes = Arc::new(vec![PathAttribute::Med(seq)]);
        manager.process_evpn_announce_chunk(peer, vec![route]);
    }

    let intern = manager.ribs[&peer].intern_len();
    // Bounded by the event-history ring plus the single live route and the
    // in-flight event (~ring + 2); pre-fix this grew to `moves` (6096).
    let bound = EVPN_ROUTE_EVENT_HISTORY_CAPACITY + 16;
    assert!(
        intern <= bound,
        "EVPN re-advertise (replace, no withdraw) churn leaked the intern table: \
         {intern} interned sets after {moves} replaces (must stay bounded near the \
         {EVPN_ROUTE_EVENT_HISTORY_CAPACITY}-entry event-history ring, <= {bound})"
    );
    assert_eq!(
        manager.ribs[&peer].evpn_len(),
        1,
        "the same key collapses to a single live route"
    );
}

#[test]
fn handle_withdraw_evpn_gcs_attr_intern_for_injected_routes() {
    // Companion to the above for the locally-injected origination path
    // (`RibUpdate::WithdrawEvpn` -> `handle_withdraw_evpn`): re-originating a
    // MAC route on every mobility move churns a fresh interned set in the
    // LOCAL_PEER Adj-RIB-In, which must be GC'd on withdraw.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());

    for seq in 0..64u32 {
        let mut route = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100);
        route.attributes = Arc::new(vec![PathAttribute::Med(seq)]);
        let key = route.key();
        manager
            .ribs
            .entry(LOCAL_PEER)
            .or_insert_with(|| AdjRibIn::new(LOCAL_PEER))
            .insert_evpn(route);
        let (reply_tx, _reply_rx) = oneshot::channel();
        manager.handle_withdraw_evpn(key, reply_tx);
    }

    let intern = manager.ribs[&LOCAL_PEER].intern_len();
    assert!(
        intern <= 1,
        "injected EVPN re-origination leaked the intern table: {intern} sets (expected <= 1)"
    );
}

#[test]
fn unicast_withdraw_reclaims_selected_attr_intern_after_loc_rib_recompute() {
    // Pure withdraw of the current best path must GC after Loc-RIB recompute:
    // before that recompute, the selected-route Arc keeps the withdrawn
    // attribute set alive and a pre-recompute GC cannot reclaim it.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
    route.attributes = Arc::new(vec![PathAttribute::Med(100)]);
    manager.process_announce_chunk(peer, vec![route]);
    assert_eq!(
        manager.loc_rib.get(&Prefix::V4(prefix)).map(|r| r.peer),
        Some(peer)
    );
    assert_eq!(manager.ribs[&peer].intern_len(), 1);

    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    drain_route_chunks(&mut manager);

    assert_eq!(
        manager.ribs[&peer].len(),
        0,
        "withdraw batch must remove the route from Adj-RIB-In"
    );
    assert!(
        manager.loc_rib.get(&Prefix::V4(prefix)).is_none(),
        "withdraw recompute must remove the selected Loc-RIB clone"
    );
    assert_eq!(
        manager.ribs[&peer].intern_len(),
        0,
        "post-recompute GC must reclaim the withdrawn route's interned attributes"
    );
}

#[test]
fn unicast_inject_replace_reclaims_attr_intern_after_loc_rib_recompute() {
    // The local injection path can replace the same prefix repeatedly without
    // an intervening withdraw. GC must run after recompute drops the selected
    // Loc-RIB clone of the previous local route; otherwise the final replaced
    // attribute set survives until one more unrelated GC event.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let moves = 5000u32;
    for seq in 0..moves {
        let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
        route.attributes = Arc::new(vec![PathAttribute::Med(seq)]);
        let (reply_tx, _reply_rx) = oneshot::channel();
        manager.handle_inject_route(route, reply_tx);
    }

    assert_eq!(
        manager.loc_rib.get(&Prefix::V4(prefix)).map(|r| r.peer),
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
    );
    assert_eq!(
        manager.ribs[&LOCAL_PEER].intern_len(),
        1,
        "injected unicast re-originations must leave only the live route's interned attrs"
    );
}

#[test]
fn unicast_withdraw_injected_reclaims_attr_intern_after_loc_rib_recompute() {
    // Withdrawing the selected local route must GC after recompute, because
    // the Loc-RIB clone keeps its interned attribute set alive during the
    // Adj-RIB-In removal itself.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
    route.attributes = Arc::new(vec![PathAttribute::Med(100)]);
    let (reply_tx, _reply_rx) = oneshot::channel();
    manager.handle_inject_route(route, reply_tx);
    assert_eq!(manager.ribs[&LOCAL_PEER].intern_len(), 1);

    let (reply_tx, _reply_rx) = oneshot::channel();
    manager.handle_withdraw_injected(Prefix::V4(prefix), 0, reply_tx);

    assert!(
        manager.loc_rib.get(&Prefix::V4(prefix)).is_none(),
        "withdrawing the injected route must recompute it out of the Loc-RIB"
    );
    assert_eq!(
        manager.ribs[&LOCAL_PEER].intern_len(),
        0,
        "withdraw-injected must reclaim the selected route's interned attrs"
    );
}

#[test]
fn llgr_eor_reclaims_stale_clear_attr_intern_after_loc_rib_recompute() {
    // LLGR promotion injects a local LLGR_STALE community through COW while
    // the Loc-RIB still holds the selected pre-promotion Arc. EoR later strips
    // that local community through another COW. The EoR path must GC after the
    // Loc-RIB recompute drops the stale selected-route clone, otherwise the old
    // interned set survives until an unrelated future GC event.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
    route.attributes = Arc::new(vec![PathAttribute::Med(100)]);
    manager.process_announce_chunk(peer, vec![route]);
    assert_eq!(
        manager.loc_rib.get(&Prefix::V4(prefix)).map(|r| r.peer),
        Some(peer)
    );
    assert_eq!(manager.ribs[&peer].intern_len(), 1);

    manager.handle_update(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer,
        restart_time: 120,
        stale_routes_time: 120,
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
    manager.sweep_gr_stale(peer);
    assert!(
        manager
            .ribs
            .get(&peer)
            .and_then(|rib| rib.iter().next())
            .is_some_and(|route| route.is_llgr_stale),
        "GR expiry should promote the retained route into LLGR stale state"
    );
    assert_eq!(
        manager.ribs[&peer].intern_len(),
        0,
        "GR expiry must reclaim the pre-promotion interned set after Loc-RIB recompute"
    );

    manager.handle_update(RibUpdate::EndOfRib {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    });

    assert!(
        manager
            .ribs
            .get(&peer)
            .and_then(|rib| rib.iter().next())
            .is_some_and(|route| !route.is_llgr_stale),
        "End-of-RIB should clear LLGR stale on the retained route"
    );
    assert_eq!(
        manager.ribs[&peer].intern_len(),
        0,
        "LLGR EoR stale-clear must reclaim the orphaned pre-promotion interned set"
    );
}

#[test]
fn gr_expiry_reclaims_stale_attr_intern_after_loc_rib_recompute() {
    // Plain GR expiry removes the route from Adj-RIB-In while the selected
    // Loc-RIB clone still holds the interned attribute Arc. The second GC must
    // run after recompute drops that clone; otherwise one set survives per
    // expired selected route.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
    route.attributes = Arc::new(vec![PathAttribute::Med(100)]);
    manager.process_announce_chunk(peer, vec![route]);
    assert_eq!(
        manager.loc_rib.get(&Prefix::V4(prefix)).map(|r| r.peer),
        Some(peer)
    );
    assert_eq!(manager.ribs[&peer].intern_len(), 1);

    manager.handle_update(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer,
        restart_time: 120,
        stale_routes_time: 120,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });
    let (outbound_tx, _outbound_rx) = mpsc::channel(8);
    manager.outbound_peers.insert(peer, outbound_tx);
    manager.sweep_gr_stale(peer);

    assert!(
        manager.loc_rib.get(&Prefix::V4(prefix)).is_none(),
        "GR expiry should remove the stale route from the Loc-RIB"
    );
    assert_eq!(
        manager.ribs[&peer].intern_len(),
        0,
        "GR expiry must reclaim the selected route's interned attrs after recompute"
    );
}

#[test]
fn unicast_announce_replace_reclaims_attr_intern() {
    // Unicast analogue of `evpn_announce_replace_reclaims_attr_intern`: a peer
    // re-advertises the SAME prefix with a fresh attribute set on every update
    // (e.g. MED / AS-path oscillation) and never withdraws it. Each distinct
    // set interns, so the announce path must reclaim the set stranded by the
    // in-place replacement — otherwise steady-state re-advertise churn leaks
    // unbounded. The GC fires only when a replacement occurred, so the
    // all-new-keys initial-load flood pays nothing.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let moves = 5000u32;
    for seq in 0..moves {
        let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
        route.attributes = Arc::new(vec![PathAttribute::Med(seq)]);
        manager.process_announce_chunk(peer, vec![route]);
    }

    let intern = manager.ribs[&peer].intern_len();
    assert_eq!(
        intern, 1,
        "unicast re-advertise (replace, no withdraw) churn leaked the intern table: \
         {intern} interned sets after {moves} replaces (must collapse to the single \
         live route's set)"
    );
    assert_eq!(
        manager.ribs[&peer].len(),
        1,
        "the same prefix collapses to one live route"
    );
}

#[test]
fn bgpls_withdraw_reclaims_attr_intern_after_loc_rib_recompute() {
    // BGP-LS routes use the same per-peer attribute intern table as unicast
    // and EVPN. A pure withdraw must GC after the affected Loc-RIB key is
    // recomputed; otherwise the selected route clone keeps the withdrawn
    // attribute set alive during the sweep and leaves one orphan behind per
    // churn cycle.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let moves = 256u32;
    for seq in 0..moves {
        let route = make_bgpls_route(peer_addr, 24, seq);
        let key = route.key();
        manager.handle_bgpls_routes_received(peer, vec![route], vec![]);
        manager.handle_bgpls_routes_received(peer, vec![], vec![key]);
    }

    let rib = &manager.ribs[&peer];
    assert_eq!(
        rib.bgpls_len(),
        0,
        "every churned BGP-LS route was withdrawn from the Adj-RIB-In"
    );
    assert_eq!(
        manager.loc_rib.iter_bgpls().count(),
        0,
        "every churned BGP-LS route was removed from the Loc-RIB"
    );
    assert_eq!(
        rib.intern_len(),
        0,
        "BGP-LS pure-withdraw churn leaked the intern table: {} interned sets after {moves} withdraws",
        rib.intern_len()
    );
}

#[test]
fn graceful_restart_entry_gcs_attr_intern_after_family_prune() {
    // A GR-down that preserves some families keeps the peer Adj-RIB-In shell
    // alive. If EVPN is not preserved, that GR entry prunes EVPN routes through
    // a direct removal path; the associated interned attribute sets must be
    // reclaimed immediately rather than leaking until a future unrelated
    // withdraw happens to run GC for this peer.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let rib = manager
        .ribs
        .entry(peer)
        .or_insert_with(|| AdjRibIn::new(peer));

    for seq in 0..64u32 {
        let mut route = make_evpn_imet(Ipv4Addr::new(10, 0, 0, 1), 100 + seq);
        route.attributes = Arc::new(vec![PathAttribute::Med(seq)]);
        rib.insert_evpn(route);
    }
    assert_eq!(manager.ribs[&peer].intern_len(), 64);

    manager.handle_update(RibUpdate::PeerGracefulRestart {
        peer,
        session_id: 0,
        restart_time: 120,
        stale_routes_time: 120,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });

    let rib = manager
        .ribs
        .get(&peer)
        .expect("GR-preserved peer shell should stay alive");
    assert_eq!(rib.evpn_len(), 0, "EVPN was not GR-preserved");
    assert_eq!(
        rib.intern_len(),
        0,
        "GR family pruning must reclaim EVPN attribute intern entries"
    );
}

#[test]
fn graceful_restart_entry_gcs_attr_intern_for_loc_rib_selected_bgpls() {
    // BGP-LS is never GR-preserved, so a GR-down withdraws all of a peer's
    // BGP-LS routes. Unlike the EVPN prune test above (which inserts directly
    // into the Adj-RIB-In), these routes are SELECTED into the Loc-RIB via the
    // receive path, so the Loc-RIB holds a second Arc clone of each interned
    // attribute set. GC must therefore run AFTER the GR-entry Loc-RIB recompute;
    // otherwise the gc that runs before it is a no-op for every selected route
    // (strong_count is still 2) and each GR cycle leaks one interned set per
    // BGP-LS route.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let count = 64u32;
    for seq in 0..count {
        // Distinct payload suffix => distinct key; distinct LOCAL_PREF =>
        // distinct interned attribute set, so each route is selected into the
        // Loc-RIB carrying its own Arc clone.
        let route = make_bgpls_route(peer_addr, u8::try_from(seq).unwrap(), 100 + seq);
        manager.handle_bgpls_routes_received(peer, vec![route], vec![]);
    }
    assert_eq!(manager.ribs[&peer].intern_len(), count as usize);
    assert_eq!(manager.loc_rib.iter_bgpls().count(), count as usize);

    manager.handle_update(RibUpdate::PeerGracefulRestart {
        peer,
        session_id: 0,
        restart_time: 120,
        stale_routes_time: 120,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });

    let rib = manager
        .ribs
        .get(&peer)
        .expect("GR-preserved peer shell should stay alive");
    assert_eq!(rib.bgpls_len(), 0, "BGP-LS is never GR-preserved");
    assert_eq!(
        manager.loc_rib.iter_bgpls().count(),
        0,
        "GR entry withdraws BGP-LS from the Loc-RIB"
    );
    assert_eq!(
        rib.intern_len(),
        0,
        "GR entry must reclaim the interned attribute sets of the Loc-RIB-selected \
         BGP-LS routes it withdraws (gc must run after the Loc-RIB recompute)"
    );
}

#[test]
fn enhanced_route_refresh_bgpls_eorr_gcs_attr_intern_for_swept_route() {
    // An Enhanced Route Refresh that sweeps an omitted BGP-LS route at EoRR must
    // reclaim that route's interned attribute set. The swept route was selected
    // into the Loc-RIB, so the Loc-RIB held a second Arc clone; GC must run
    // AFTER finish_route_refresh's Loc-RIB recompute, not before it. The two
    // routes carry DISTINCT attributes so the swept route has its own interned
    // set (identical attributes would share one set kept alive by the survivor,
    // masking the leak).
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let survivor = make_bgpls_route(peer_addr, 21, 100);
    let omitted = make_bgpls_route(peer_addr, 22, 200);
    manager.handle_bgpls_routes_received(peer, vec![survivor.clone(), omitted], vec![]);
    assert_eq!(manager.ribs[&peer].intern_len(), 2);

    manager.handle_update(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::BgpLs,
        safi: Safi::BgpLs,
    });
    // Reannounce only the survivor; the omitted route stays stale and is swept.
    manager.handle_bgpls_routes_received(peer, vec![survivor], vec![]);
    manager.handle_update(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::BgpLs,
        safi: Safi::BgpLs,
    });

    assert_eq!(
        manager.loc_rib.iter_bgpls().count(),
        1,
        "EoRR sweeps the omitted BGP-LS route, leaving only the survivor"
    );
    assert_eq!(
        manager.ribs[&peer].intern_len(),
        1,
        "EoRR sweep must reclaim the swept route's interned attribute set \
         (gc must run after finish_route_refresh's Loc-RIB recompute)"
    );
}

#[test]
fn enhanced_route_refresh_vpn_eorr_gcs_attr_intern_for_swept_route() {
    // Same ordering hazard as the BGP-LS test above, for SAFI 128: the swept
    // VPN route was selected into the Loc-RIB, so its interned attribute set
    // has a second Arc clone until finish_route_refresh's Loc-RIB recompute
    // drops it. GC must run after that recompute. Distinct LOCAL_PREF values
    // give each route its own interned set so the leak can't be masked.
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);
    manager.ribs.insert(peer, AdjRibIn::new(peer));

    let survivor = make_vpn_rib_route(peer_addr, 21, 100, 100);
    let omitted = make_vpn_rib_route(peer_addr, 22, 100, 200);
    manager.handle_vpn_routes_received(peer, vec![survivor.clone(), omitted], vec![]);
    assert_eq!(manager.ribs[&peer].intern_len(), 2);

    manager.handle_update(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    });
    // Reannounce only the survivor; the omitted route stays stale and is swept.
    manager.handle_vpn_routes_received(peer, vec![survivor], vec![]);
    manager.handle_update(RibUpdate::EndRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    });

    assert_eq!(
        manager.loc_rib.iter_vpn().count(),
        1,
        "EoRR sweeps the omitted VPN route, leaving only the survivor"
    );
    assert_eq!(
        manager.ribs[&peer].intern_len(),
        1,
        "EoRR sweep must reclaim the swept VPN route's interned attribute set \
         (gc must run after finish_route_refresh's Loc-RIB recompute)"
    );
}

#[test]
fn vpn_peer_down_during_refresh_clears_stale_state() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer = IpAddr::V4(peer_addr);

    manager.handle_vpn_routes_received(
        peer,
        vec![make_vpn_rib_route(peer_addr, 26, 100, 100)],
        vec![],
    );
    manager.handle_update(RibUpdate::BeginRouteRefresh {
        session_id: 0,
        peer,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    });
    assert!(
        manager
            .refresh_stale_vpn
            .get(&peer)
            .is_some_and(|stale| stale.len() == 1),
        "BoRR must snapshot the peer's Adj-RIB-In VPN keys as stale"
    );

    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    });
    assert!(
        !manager.refresh_stale_vpn.contains_key(&peer),
        "peer-down during an active refresh must clear the VPN stale snapshot"
    );
    assert!(!manager.refresh_in_progress.contains_key(&peer));
    assert!(
        manager
            .refresh_stale_counts
            .keys()
            .all(|(stale_peer, _, _)| *stale_peer != peer),
        "peer-down must drop the peer's refresh-stale counters"
    );
}

// --- RFC 9107 VPN-ORR: per-vantage best selection for SAFI 128 ---

/// Sendable families for a VPNv6-only test peer.
fn vpn6_sendable() -> Vec<(Afi, Safi)> {
    vec![(Afi::Ipv6, Safi::MplsVpn)]
}

/// A `VPNv4` route from `peer` with an explicit next-hop (identical
/// attributes across sources so only the ORR interior-cost step and the
/// final peer-address tiebreak can decide).
fn vpn_route_at(peer: Ipv4Addr, next_hop: IpAddr, prefix_octet: u8) -> VpnRibRoute {
    let mut route = make_vpn_rib_route(peer, prefix_octet, 100, 100);
    route.next_hop = next_hop;
    route
}

/// A `VPNv6` route from `peer` with an explicit next-hop.
fn vpn6_route_at(peer: Ipv4Addr, next_hop: IpAddr, segment: u16) -> VpnRibRoute {
    let mut route = make_vpn6_rib_route_with_rts(peer, segment, vec![]);
    route.next_hop = next_hop;
    route
}

/// Bring up an iBGP VPN-capable peer with the given ORR vantage and
/// RR-client flag, draining the initial-table `EoR`.
async fn vpn_orr_peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    vantage: Option<IpAddr>,
    sendable_families: Vec<(Afi, Safi)>,
    route_reflector_client: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families,
        is_ebgp: false,
        route_reflector_client,
        orr_vantage: vantage,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;
    out_rx
}

/// Announce VPN routes from `peer` through the normal receive path.
async fn announce_vpn(tx: &mpsc::Sender<RibUpdate>, peer: Ipv4Addr, announced: Vec<VpnRibRoute>) {
    tx.send(RibUpdate::VpnRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer),
        announced,
        withdrawn: vec![],
    })
    .await
    .unwrap();
}

/// The VPN divergence scenario: the SAME RD+prefix key from two iBGP
/// PEs with next-hops at node X and node Y, followed by a sync point.
/// Returns the contested key.
async fn announce_divergent_vpn_bests(
    tx: &mpsc::Sender<RibUpdate>,
    prefix_octet: u8,
) -> crate::route::VpnRibRouteKey {
    let route_x = vpn_route_at(ORR_SRC_X, orr_nh_x(), prefix_octet);
    let key = route_x.key();
    announce_vpn(tx, ORR_SRC_X, vec![route_x]).await;
    announce_vpn(
        tx,
        ORR_SRC_Y,
        vec![vpn_route_at(ORR_SRC_Y, orr_nh_y(), prefix_octet)],
    )
    .await;
    let _ = query_vpn_routes(tx).await;
    key
}

/// Drain every queued outbound update and fold to the final advertised
/// VPN state: key → the last announced route.
fn drain_final_vpn(
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
) -> HashMap<crate::route::VpnRibRouteKey, VpnRibRoute> {
    let mut state = HashMap::new();
    while let Ok(update) = rx.try_recv() {
        for route in &update.vpn_announce {
            state.insert(route.key(), route.clone());
        }
        for key in &update.vpn_withdraw {
            state.remove(key);
        }
    }
    state
}

/// The composed differentiators: two RR clients bound to different
/// vantages receive DIVERGENT VPN bests for the same RD+prefix — each
/// exits via the PE closest to its own IGP location, not the RR's.
#[tokio::test]
async fn two_vpn_clients_different_vantages_receive_divergent_bests() {
    let (tx, handle) = orr_rr_manager().await;
    let client_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut out_a = vpn_orr_peer_up(
        &tx,
        client_a,
        Some(vantage_at_node_a()),
        vpn_sendable(),
        true,
    )
    .await;
    let mut out_b = vpn_orr_peer_up(
        &tx,
        client_b,
        Some(vantage_at_node_b()),
        vpn_sendable(),
        true,
    )
    .await;

    let key = announce_divergent_vpn_bests(&tx, 80).await;
    drop(tx);
    handle.await.unwrap();

    let final_a = drain_final_vpn(&mut out_a);
    let final_b = drain_final_vpn(&mut out_b);
    assert_eq!(
        final_a.get(&key).map(|r| r.next_hop),
        Some(orr_nh_x()),
        "client at A exits via X (cost 1 < 10)"
    );
    assert_eq!(
        final_b.get(&key).map(|r| r.next_hop),
        Some(orr_nh_y()),
        "client at B exits via Y (cost 1 < 10)"
    );
}

/// RFC 9107 + RFC 7911 composed: an ORR client with Add-Path send ranks
/// its staged top-N by the VANTAGE's interior costs — `path_id` 1 is the
/// vantage-closest exit, not the RR-local best.
#[tokio::test]
async fn vpn_orr_addpath_ranking_uses_vantage_costs() {
    let (tx, handle) = orr_rr_manager().await;
    let client_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (out_tx, mut out_a) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: client_a,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: Some(vantage_at_node_a()),
        add_path_send_families: vec![(Afi::Ipv4, Safi::MplsVpn)],
        add_path_send_max: 2,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_a).await;

    // Same RD+prefix via X (cost 1 from vantage A) and Y (cost 10).
    let key = announce_divergent_vpn_bests(&tx, 81).await;
    drop(tx);
    handle.await.unwrap();

    let staged = drain_final_vpn(&mut out_a);
    assert_eq!(staged.len(), 2, "both candidates staged under send_max=2");
    assert_eq!(
        staged
            .get(&crate::route::VpnRibRouteKey {
                nlri_key: key.nlri_key,
                path_id: 1,
            })
            .map(|r| r.next_hop),
        Some(orr_nh_x()),
        "path_id 1 = vantage-closest exit (cost 1 via X)"
    );
    assert_eq!(
        staged
            .get(&crate::route::VpnRibRouteKey {
                nlri_key: key.nlri_key,
                path_id: 2,
            })
            .map(|r| r.next_hop),
        Some(orr_nh_y()),
        "path_id 2 = the farther exit (cost 10 via Y)"
    );
}

/// `VPNv6` divergence — the candidate handling is family-agnostic, so
/// the same scenario over SAFI 128 IPv6 keys diverges identically.
#[tokio::test]
async fn two_vpn6_clients_different_vantages_receive_divergent_bests() {
    let (tx, handle) = orr_rr_manager().await;
    let client_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut out_a = vpn_orr_peer_up(
        &tx,
        client_a,
        Some(vantage_at_node_a()),
        vpn6_sendable(),
        true,
    )
    .await;
    let mut out_b = vpn_orr_peer_up(
        &tx,
        client_b,
        Some(vantage_at_node_b()),
        vpn6_sendable(),
        true,
    )
    .await;

    let route_x = vpn6_route_at(ORR_SRC_X, orr_nh_x(), 0x60);
    let key = route_x.key();
    announce_vpn(&tx, ORR_SRC_X, vec![route_x]).await;
    announce_vpn(
        &tx,
        ORR_SRC_Y,
        vec![vpn6_route_at(ORR_SRC_Y, orr_nh_y(), 0x60)],
    )
    .await;
    let _ = query_vpn_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_a = drain_final_vpn(&mut out_a);
    let final_b = drain_final_vpn(&mut out_b);
    assert_eq!(final_a.get(&key).map(|r| r.next_hop), Some(orr_nh_x()));
    assert_eq!(final_b.get(&key).map(|r| r.next_hop), Some(orr_nh_y()));
}

/// A topology metric flip re-stages ONLY the peers bound to the vantage
/// whose SPF surface changed: the affected client's VPN best flips,
/// while the other vantage's client and a non-ORR client see zero
/// messages.
#[tokio::test]
async fn vpn_orr_topology_metric_flip_moves_only_affected_client() {
    use crate::orr::fixtures::{A, X, link_route, v4_interface, v4_neighbor};

    let (tx, handle) = orr_rr_manager().await;
    let client_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let client_c = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let mut out_a = vpn_orr_peer_up(
        &tx,
        client_a,
        Some(vantage_at_node_a()),
        vpn_sendable(),
        true,
    )
    .await;
    let mut out_b = vpn_orr_peer_up(
        &tx,
        client_b,
        Some(vantage_at_node_b()),
        vpn_sendable(),
        true,
    )
    .await;
    let mut out_c = vpn_orr_peer_up(&tx, client_c, None, vpn_sendable(), true).await;

    let key = announce_divergent_vpn_bests(&tx, 81).await;
    // Steady state reached — empty every channel before the flip.
    let _ = drain_final_vpn(&mut out_a);
    let _ = drain_final_vpn(&mut out_b);
    let _ = drain_final_vpn(&mut out_c);

    // Flip A→X to metric 100: from A the SPF now prefers Y (10 < 100).
    tx.send(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(ORR_FEED),
        announced: vec![link_route(
            ORR_FEED,
            A,
            X,
            Some(100),
            &[
                v4_interface(Ipv4Addr::new(10, 0, A, X)),
                v4_neighbor(Ipv4Addr::new(10, 0, X, A)),
            ],
        )],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let _ = query_vpn_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_a = drain_final_vpn(&mut out_a);
    assert_eq!(
        final_a.get(&key).map(|r| r.next_hop),
        Some(orr_nh_y()),
        "affected client's VPN best flips to Y (cost 10 < 100)"
    );
    assert!(
        out_b.try_recv().is_err(),
        "unaffected vantage's client must see zero messages"
    );
    assert!(
        out_c.try_recv().is_err(),
        "non-ORR client must see zero messages"
    );
}

/// A vantage that does not resolve to a topology node silently falls
/// back to the standard Loc-RIB best: the ORR client's VPN
/// advertisement is identical to a vantage-less peer's.
#[tokio::test]
async fn vpn_orr_unresolved_vantage_falls_back_to_loc_rib_best() {
    let (tx, handle) = orr_rr_manager().await;
    let orr_client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let plain_client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let outside = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let mut out_orr = vpn_orr_peer_up(&tx, orr_client, Some(outside), vpn_sendable(), true).await;
    let mut out_plain = vpn_orr_peer_up(&tx, plain_client, None, vpn_sendable(), true).await;

    let key = announce_divergent_vpn_bests(&tx, 82).await;
    drop(tx);
    handle.await.unwrap();

    let final_orr = drain_final_vpn(&mut out_orr);
    let final_plain = drain_final_vpn(&mut out_plain);
    let unresolved = final_orr
        .get(&key)
        .expect("unresolved-vantage client is advertised the key");
    let plain = final_plain
        .get(&key)
        .expect("vantage-less client is advertised the key");
    assert_eq!(unresolved.next_hop, orr_nh_x(), "the Loc-RIB best");
    assert_eq!(unresolved.next_hop, plain.next_hop);
    assert_eq!(unresolved.attributes, plain.attributes);
    assert_eq!(unresolved.peer, plain.peer);
    assert_eq!(unresolved.nlri, plain.nlri);
}

/// Regression guard: a VPN peer with NO ORR vantage keeps the exact
/// pre-ORR behavior in the divergence scenario — the Loc-RIB best, with
/// no re-advertisement when the losing candidate arrives.
#[tokio::test]
async fn non_orr_vpn_peer_unchanged() {
    let (tx, handle) = orr_rr_manager().await;
    let plain_client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let mut out = vpn_orr_peer_up(&tx, plain_client, None, vpn_sendable(), true).await;

    let key = announce_divergent_vpn_bests(&tx, 83).await;
    drop(tx);
    handle.await.unwrap();

    let mut announces = 0;
    let mut last = None;
    while let Ok(update) = out.try_recv() {
        for route in &update.vpn_announce {
            announces += 1;
            last = Some(route.clone());
        }
        assert!(update.vpn_withdraw.is_empty());
    }
    assert_eq!(
        announces, 1,
        "the second candidate must not re-stage a non-ORR peer"
    );
    let last = last.unwrap();
    assert_eq!(last.key(), key);
    assert_eq!(last.next_hop, orr_nh_x(), "the Loc-RIB best");
}

/// RFC 4684 composes with VPN-ORR on the WINNER: the RT-Constrain
/// membership gate applies to the vantage winner's Route Targets — the
/// route actually being advertised — not the Loc-RIB best's.
#[tokio::test]
async fn vpn_orr_rtc_filter_applies_to_vantage_winner() {
    let (tx, handle) = orr_rr_manager().await;

    // Same key from two PEs: the Loc-RIB best (X, lower peer address)
    // carries RT 100; the vantage-B winner (Y, cost 1 < 10) carries
    // RT 200.
    let mut route_x = make_vpn_rib_route_with_rts(ORR_SRC_X, 84, vec![rt(100)]);
    route_x.next_hop = orr_nh_x();
    let key = route_x.key();
    let mut route_y = make_vpn_rib_route_with_rts(ORR_SRC_Y, 84, vec![rt(200)]);
    route_y.next_hop = orr_nh_y();
    announce_vpn(&tx, ORR_SRC_X, vec![route_x]).await;
    announce_vpn(&tx, ORR_SRC_Y, vec![route_y]).await;
    let _ = query_vpn_routes(&tx).await;

    // An iBGP RR client at vantage B that negotiated VPNv4 + RTC.
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv4, Safi::MplsVpn), (Afi::Ipv4, Safi::RtConstrain)],
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: Some(vantage_at_node_b()),
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    let _ = query_vpn_routes(&tx).await;
    assert!(
        drain_final_vpn(&mut out_rx).is_empty(),
        "strict RFC 4684: empty membership withholds every VPN route"
    );

    // Interest in the LOC-RIB BEST's RT only: the vantage winner (RT
    // 200) misses the gate, so nothing may be advertised — gating on
    // the Loc-RIB best's RT 100 would wrongly announce here.
    send_rtc_interest(&tx, Ipv4Addr::new(10, 0, 0, 3), &[100]).await;
    let _ = query_vpn_routes(&tx).await;
    assert!(
        !drain_final_vpn(&mut out_rx).contains_key(&key),
        "the gate must apply to the vantage winner's RTs, not the Loc-RIB best's"
    );

    // Interest in the WINNER's RT: the vantage best flows.
    send_rtc_interest(&tx, Ipv4Addr::new(10, 0, 0, 3), &[200]).await;
    let _ = query_vpn_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();
    let advertised = drain_final_vpn(&mut out_rx);
    assert_eq!(
        advertised.get(&key).map(|r| r.next_hop),
        Some(orr_nh_y()),
        "matching the winner's RT admits the vantage best"
    );
}

/// Split horizon and RFC 4456 reflection suppression run BEFORE the ORR
/// ranking: a cost-0 VPN candidate the target must not receive can
/// never win.
#[tokio::test]
async fn vpn_orr_split_horizon_and_rr_suppression_before_ranking() {
    let (tx, handle) = orr_rr_manager().await;
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let client_b_v4 = Ipv4Addr::new(10, 0, 0, 3);
    let mut out_b = vpn_orr_peer_up(
        &tx,
        client_b,
        Some(vantage_at_node_b()),
        vpn_sendable(),
        true,
    )
    .await;
    // A non-client iBGP peer bound to the same vantage (the RIB layer
    // trusts PeerUp; the suppression seam must hold regardless).
    let peer_d = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let mut out_d = vpn_orr_peer_up(
        &tx,
        peer_d,
        Some(vantage_at_node_b()),
        vpn_sendable(),
        false,
    )
    .await;

    // key1 — split-horizon probe: client B's OWN route has interior
    // cost 0 (next-hop at its vantage node); a non-client source offers
    // cost 10 via NH-X.
    let own = vpn_route_at(client_b_v4, vantage_at_node_b(), 85);
    let key1 = own.key();
    announce_vpn(&tx, client_b_v4, vec![own]).await;
    announce_vpn(
        &tx,
        ORR_SRC_X,
        vec![vpn_route_at(ORR_SRC_X, orr_nh_x(), 85)],
    )
    .await;

    // key2 — RR-suppression probe: the cost-0 candidate comes from a
    // NON-client (never reflectable to the non-client target D); client
    // B offers cost 10 via NH-X (client routes reflect to everyone).
    let non_client_route = vpn_route_at(ORR_SRC_Y, vantage_at_node_b(), 86);
    let key2 = non_client_route.key();
    announce_vpn(&tx, ORR_SRC_Y, vec![non_client_route]).await;
    announce_vpn(
        &tx,
        client_b_v4,
        vec![vpn_route_at(client_b_v4, orr_nh_x(), 86)],
    )
    .await;

    let _ = query_vpn_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_b = drain_final_vpn(&mut out_b);
    assert_eq!(
        final_b.get(&key1).map(|r| r.next_hop),
        Some(orr_nh_x()),
        "the target's own cost-0 route is split-horizoned before ranking"
    );
    let final_d = drain_final_vpn(&mut out_d);
    assert_eq!(
        final_d.get(&key2).map(|r| r.next_hop),
        Some(orr_nh_x()),
        "the cost-0 non-client candidate is RR-suppressed before ranking"
    );
}

/// A client that establishes AFTER the VPN routes and topology are in
/// place gets its per-vantage best in the initial table dump.
#[tokio::test]
async fn vpn_orr_initial_dump_gets_vantage_best() {
    let (tx, handle) = orr_rr_manager().await;
    let key = announce_divergent_vpn_bests(&tx, 87).await;

    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let (out_tx, mut out_b) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        session_id: 0,
        peer: client_b,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: vpn_sendable(),
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: Some(vantage_at_node_b()),
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
    })
    .await
    .unwrap();
    let _ = query_vpn_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_b = drain_final_vpn(&mut out_b);
    assert_eq!(
        final_b.get(&key).map(|r| r.next_hop),
        Some(orr_nh_y()),
        "initial dump carries the vantage best, not the Loc-RIB best"
    );
}

/// A ROUTE-REFRESH replay re-derives the same per-vantage VPN best the
/// live distribution path sent.
#[tokio::test]
async fn vpn_orr_route_refresh_replays_vantage_best() {
    let (tx, handle) = orr_rr_manager().await;
    let client_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let mut out_b = vpn_orr_peer_up(
        &tx,
        client_b,
        Some(vantage_at_node_b()),
        vpn_sendable(),
        true,
    )
    .await;

    let key = announce_divergent_vpn_bests(&tx, 88).await;
    let _ = drain_final_vpn(&mut out_b);

    tx.send(RibUpdate::RouteRefreshRequest {
        peer: client_b,
        session_id: 0,
        afi: Afi::Ipv4,
        safi: Safi::MplsVpn,
    })
    .await
    .unwrap();
    let _ = query_vpn_routes(&tx).await;
    drop(tx);
    handle.await.unwrap();

    let final_b = drain_final_vpn(&mut out_b);
    assert_eq!(
        final_b.get(&key).map(|r| r.next_hop),
        Some(orr_nh_y()),
        "the replay is the vantage best"
    );
}
