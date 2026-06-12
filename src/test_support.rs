//! Shared fixtures for the daemon binary's unit tests.
//!
//! Canonical test-only constructors that used to be copied across the
//! EVPN, FIB, and runtime test modules. Keep new cross-module test
//! builders here so a field addition touches one place instead of one
//! copy per test module.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

use prometheus::Encoder;
use rustbgpd_evpn::{EvpnInstance, EvpnInstanceId, RouteTarget};
use rustbgpd_rib::route::{NextHopScope, Route, RouteOrigin};
use rustbgpd_rib::{RouteEvent, RouteEventType};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    AsPath, MacAddress, Origin, PathAttribute, Prefix, RouteDistinguisher, RpkiValidation,
};

use crate::config::FibTableConfig;
use crate::fib::FibRouteKey;

pub(crate) fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

pub(crate) fn vni(n: u32) -> EvpnInstanceId {
    EvpnInstanceId::new(n).unwrap()
}

pub(crate) fn mac(b: u8) -> MacAddress {
    MacAddress::new([b; 6])
}

pub(crate) fn rd(asn: u16, val: u32) -> RouteDistinguisher {
    let mut bytes = [0u8; 8];
    bytes[2..4].copy_from_slice(&asn.to_be_bytes());
    bytes[4..8].copy_from_slice(&val.to_be_bytes());
    RouteDistinguisher::new(bytes)
}

pub(crate) fn gather_metrics_text(metrics: &BgpMetrics) -> String {
    let encoder = prometheus::TextEncoder::new();
    let families = metrics.registry().gather();
    let mut buf = Vec::new();
    encoder.encode(&families, &mut buf).unwrap();
    String::from_utf8(buf).unwrap()
}

/// Canonical local EVPN instance: VTEP `10.0.0.1`, type-0 RD/RT
/// `asn:rd_value`. The per-module wrappers pin their historical ASN
/// (65000 vs 65001), bridge name, and SVI flag.
pub(crate) fn evpn_instance(
    asn: u16,
    v: u32,
    rd_value: u32,
    bridge: Option<String>,
    advertise_svi: bool,
) -> EvpnInstance {
    EvpnInstance::new(
        vni(v),
        rd(asn, rd_value),
        vec![RouteTarget::TwoOctetAs {
            asn,
            value: rd_value,
        }],
        ip("10.0.0.1"),
        bridge,
        advertise_svi,
    )
    .unwrap()
}

pub(crate) fn fib_table(
    name: &str,
    table_id: u32,
    metric: u32,
    families: &[&str],
) -> FibTableConfig {
    FibTableConfig {
        name: name.to_string(),
        table_id,
        metric,
        families: families
            .iter()
            .map(|family| (*family).to_string())
            .collect(),
        allowed_peer_groups: Vec::new(),
        allowed_neighbors: Vec::new(),
        max_routes: None,
        maximum_paths: None,
        maximum_paths_ebgp: None,
        maximum_paths_ibgp: None,
    }
}

/// Single-family `ipv4_unicast` table at metric 200 — the common
/// control-plane test shape.
pub(crate) fn basic_fib_table(name: &str, table_id: u32) -> FibTableConfig {
    fib_table(name, table_id, 200, &["ipv4_unicast"])
}

pub(crate) fn fib_route_key(prefix: Prefix) -> FibRouteKey {
    FibRouteKey {
        table_id: 1000,
        metric: 200,
        prefix,
    }
}

pub(crate) fn route_from_peer(
    prefix: Prefix,
    next_hop: IpAddr,
    origin_type: RouteOrigin,
    path_id: u32,
    peer: IpAddr,
) -> Route {
    Route {
        prefix,
        next_hop,
        link_local_next_hop: None,
        next_hop_scope: None,
        peer,
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
        ]),
        received_at: Instant::now(),
        origin_type,
        peer_router_id: Ipv4Addr::new(192, 0, 2, 1),
        is_stale: false,
        is_llgr_stale: false,
        path_id,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

pub(crate) fn scoped_route(prefix: Prefix, next_hop: IpAddr, ifindex: u32) -> Route {
    let mut route = route_from_peer(prefix, next_hop, RouteOrigin::Ebgp, 0, ip("198.51.100.1"));
    route.next_hop_scope = Some(Box::new(NextHopScope {
        interface: Arc::from("fib0"),
        ifindex,
    }));
    route
}

pub(crate) fn route_event(prefix: Prefix, peer: IpAddr) -> RouteEvent {
    RouteEvent {
        event_id: 0,
        event_type: RouteEventType::BestChanged,
        prefix,
        peer: Some(peer),
        previous_peer: None,
        target_peer: None,
        timestamp: "0".to_string(),
        path_id: 0,
        reason: String::new(),
    }
}
