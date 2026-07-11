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

/// A chain with one exact-match Deny statement per prefix, default Permit.
fn deny_prefixes_chain(prefixes: &[Prefix]) -> rustbgpd_policy::PolicyChain {
    rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
        entries: prefixes
            .iter()
            .map(|prefix| rustbgpd_policy::PolicyStatement {
                prefix: Some(*prefix),
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
            })
            .collect(),
        default_action: rustbgpd_policy::PolicyAction::Permit,
    }])
}

fn deny_default_prefix_chain() -> rustbgpd_policy::PolicyChain {
    deny_prefixes_chain(&[Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))])
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

fn labeled_sendable() -> Vec<(Afi, Safi)> {
    vec![(Afi::Ipv4, Safi::LabeledUnicast)]
}

/// An IPv4 labeled-unicast route from `peer` with a distinct prefix octet,
/// MPLS label, and `LOCAL_PREF`. Same octet from two peers = same RIB key
/// (labels are route data, not identity).
fn make_labeled_rib_route(
    peer: Ipv4Addr,
    prefix_octet: u8,
    label: u32,
    local_pref: u32,
) -> crate::route::LabeledRibRoute {
    let nlri = rustbgpd_wire::LabeledNlri {
        labels: vec![MplsLabelEntry::try_new(label, 0, true).unwrap()],
        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, prefix_octet, 0), 24)),
    };
    crate::route::LabeledRibRoute {
        nlri,
        next_hop: IpAddr::V4(peer),
        link_local_next_hop: None,
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
        link_local_next_hop: None,
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

async fn query_labeled_routes(tx: &mpsc::Sender<RibUpdate>) -> Vec<crate::route::LabeledRibRoute> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLabeledRoutes { reply: reply_tx })
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
        rd: None,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap().unwrap()
}

/// VPN-key export explain helper (`rd` set) for the export-explain tests.
async fn query_explain_advertised_vpn_route(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    prefix: Prefix,
    rd: rustbgpd_wire::RouteDistinguisher,
) -> crate::update::ExplainAdvertisedRoute {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::ExplainAdvertisedRoute {
        peer,
        prefix,
        rd: Some(rd),
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

/// Drain every queued outbound update and fold to the final advertised
/// labeled state: key → the last announced route.
fn drain_final_labeled(
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
) -> HashMap<crate::route::LabeledRibRouteKey, crate::route::LabeledRibRoute> {
    let mut state = HashMap::new();
    while let Ok(update) = rx.try_recv() {
        for route in &update.labeled_announce {
            state.insert(route.key(), route.clone());
        }
        for key in &update.labeled_withdraw {
            state.remove(key);
        }
    }
    state
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

/// Bring up an iBGP RR-client peer with the given ORR vantage and drain
/// its initial-table `EoR` so the channel starts empty.
async fn orr_client_peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    vantage: Option<IpAddr>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
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
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;
    out_rx
}

async fn query_orr_status(tx: &mpsc::Sender<RibUpdate>) -> crate::orr::OrrStatusSnapshot {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryOrrStatus { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap()
}

/// Interface address of fixture node A (`10.0.A.X`) — resolves to A.
fn vantage_at_node_a() -> IpAddr {
    use crate::orr::fixtures::{A, X};
    IpAddr::V4(Ipv4Addr::new(10, 0, A, X))
}

/// Apply all queued `RoutesReceived` chunks (the channel-driven manager
/// drains these from its run loop).
fn drain_route_chunks(manager: &mut RibManager) {
    while manager.process_next_route_chunk() {}
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
        link_local_next_hop: None,
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

/// A two-octet-AS Route Target `RT:65001:<local_admin>` — the family that
/// `make_rtc_rib_route`'s /96 membership NLRI covers.
fn rt(local_admin: u16) -> ExtendedCommunity {
    ExtendedCommunity::new(0x0002_FDE9_0000_0000 | u64::from(local_admin))
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
        per_client_best: false,
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
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    out_rx
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

/// Bring up an eBGP peer that negotiated VPN + RT-Constrain families.
/// Does NOT drain — callers assert the initial dump.
async fn vpn_rtc_peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
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
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    out_rx
}

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

/// Sendable families for a peer that negotiated VPNv4+VPNv6 and RT-Constrain.
fn vpn_rtc_sendable() -> Vec<(Afi, Safi)> {
    vec![
        (Afi::Ipv4, Safi::MplsVpn),
        (Afi::Ipv6, Safi::MplsVpn),
        (Afi::Ipv4, Safi::RtConstrain),
    ]
}

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

/// Bring up an outbound target with an explicit eBGP/LLGR shape (and
/// optional Add-Path send) for the RFC 9494 export-gate tests.
async fn llgr_gate_peer_up(
    tx: &mpsc::Sender<RibUpdate>,
    peer: IpAddr,
    sendable: Vec<(Afi, Safi)>,
    is_ebgp: bool,
    llgr_families: Vec<(Afi, Safi)>,
    add_path: Option<((Afi, Safi), u32)>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out_tx, out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: sendable,
        is_ebgp,
        route_reflector_client: !is_ebgp,
        orr_vantage: None,
        add_path_send_families: add_path.map(|(family, _)| vec![family]).unwrap_or_default(),
        add_path_send_max: add_path.map_or(0, |(_, max)| max),
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: llgr_families,
    })
    .await
    .unwrap();
    out_rx
}

mod attr_intern;
mod bgpls;
mod bmp;
mod events_metrics;
mod evpn;
mod explain_mrt;
mod export_explain;
mod flowspec;
mod gr_llgr;
mod incremental_best;
mod labeled;
mod lifecycle;
mod llgr_families;
mod multipath_fib;
mod orf;
mod orr;
mod paged_query;
mod per_client_best;
mod policy;
mod refresh;
mod rpki;
mod rtc;
mod unicast;
mod update_groups;
mod update_groups_fault_corpus;
mod update_groups_oracle;
mod vpn;
