//! Shared fixtures for this crate's unit tests.
//!
//! Canonical test-only route constructors used by the manager,
//! Adj-RIB-In, Adj-RIB-Out, and Loc-RIB test modules. Keep new
//! test-only `Route` / `FlowSpecRoute` builders here so a field
//! addition touches one place instead of one copy per test module.
//!
//! Bench and integration-test helpers (`benches/`, `tests/`) compile
//! as separate units and cannot see this private module; they keep
//! their own builders.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use rustbgpd_wire::{
    Afi, AsPath, AsPathSegment, FlowSpecComponent, FlowSpecPrefix, FlowSpecRule, Ipv4Prefix,
    Ipv6Prefix, Origin, PathAttribute, Prefix,
};

use crate::attr_set::AttrSet;
use crate::route::{FlowSpecRoute, Route, RouteOrigin};

/// The BGP Identifier of the session peer at `peer`: the address itself
/// for IPv4, its lowest nonzero 32-bit word for IPv6. A session route never
/// carries the `0.0.0.0` injection sentinel, so these fixtures must not
/// either — pairing `Ebgp` with the sentinel builds a route the daemon
/// cannot, and decides the identifier step by a state it cannot reach.
pub(crate) fn session_router_id(peer: IpAddr) -> Ipv4Addr {
    match peer {
        IpAddr::V4(addr) => addr,
        // The lowest nonzero 32-bit word, so a `::`-tailed peer does not
        // project onto the sentinel; `::` itself is never a session peer.
        IpAddr::V6(addr) => Ipv4Addr::from(
            addr.octets()
                .rchunks(4)
                .map(|w| u32::from_be_bytes([w[0], w[1], w[2], w[3]]))
                .find(|&w| w != 0)
                .unwrap_or(1),
        ),
    }
}

pub(crate) fn make_route(prefix: Ipv4Prefix, next_hop: Ipv4Addr) -> Route {
    Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(next_hop),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(next_hop),
        attributes: AttrSet::new(vec![]),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: session_router_id(IpAddr::V4(next_hop)),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        received_as_path: None,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

pub(crate) fn make_v6_route(prefix: Ipv6Prefix, next_hop: Ipv6Addr) -> Route {
    Route {
        prefix: Prefix::V6(prefix),
        next_hop: IpAddr::V6(next_hop),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V6(next_hop),
        attributes: AttrSet::new(vec![]),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: session_router_id(IpAddr::V6(next_hop)),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        received_as_path: None,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

/// Move a fixture route to `peer`, keeping `peer_router_id` derived from
/// the new peer rather than the constructor's. `LOCAL_PEER` (`0.0.0.0`)
/// yields the injection sentinel, matching a locally originated route.
pub(crate) fn set_peer(route: &mut Route, peer: IpAddr) {
    route.peer = peer;
    route.peer_router_id = session_router_id(peer);
}

pub(crate) fn make_route_with_lp(prefix: Ipv4Prefix, peer: Ipv4Addr, local_pref: u32) -> Route {
    Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(peer),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(peer),
        attributes: AttrSet::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001])],
            }),
            PathAttribute::LocalPref(local_pref),
        ]),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: session_router_id(IpAddr::V4(peer)),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        received_as_path: None,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

/// Add-path shaped route: fixed next-hop/peer, caller-chosen path id.
pub(crate) fn make_route_with_path_id(prefix: Prefix, path_id: u32) -> Route {
    Route {
        prefix,
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        attributes: AttrSet::new(vec![]),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::new(1, 1, 1, 1),
        is_stale: false,
        is_llgr_stale: false,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        received_as_path: None,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        path_id,
    }
}

pub(crate) fn make_flowspec_route(peer: Ipv4Addr) -> FlowSpecRoute {
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
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: session_router_id(IpAddr::V4(peer)),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    }
}

mod tests {
    use super::*;

    /// A session-origin fixture must carry a real BGP Identifier, never
    /// the injection sentinel reserved for locally originated routes.
    #[test]
    fn session_fixtures_never_carry_the_injection_sentinel() {
        let v4 = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
        let peer = Ipv4Addr::new(192, 0, 2, 7);
        let routes = [
            make_route(v4, peer),
            make_v6_route(
                Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32),
                "2001:db8::7".parse().unwrap(),
            ),
            // Low 32 bits all zero: must not project onto the sentinel.
            make_v6_route(
                Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32),
                "2001:db8::".parse().unwrap(),
            ),
            make_route_with_lp(v4, peer, 100),
            make_route_with_path_id(Prefix::V4(v4), 1),
        ];
        for route in &routes {
            assert_ne!(route.origin_type, RouteOrigin::Local);
            assert_ne!(route.peer_router_id, Ipv4Addr::UNSPECIFIED, "{route:?}");
        }
        let flowspec = make_flowspec_route(peer);
        assert_ne!(flowspec.origin_type, RouteOrigin::Local);
        assert_ne!(flowspec.peer_router_id, Ipv4Addr::UNSPECIFIED);
    }
}
