use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use rustbgpd_rpki::{AspaTable, VrpTable};
use rustbgpd_wire::{Afi, AspaValidation, LlgrFamily, Prefix, RpkiValidation, Safi};

/// Sentinel peer address for locally-injected routes.
pub(super) const LOCAL_PEER: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// How long to wait before retrying distribution to dirty peers.
pub(super) const DIRTY_RESYNC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// How long to wait for an inbound enhanced route refresh window to complete
/// before sweeping unreplaced state.
pub(super) const ERR_REFRESH_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(5);

/// Per-peer LLGR configuration stored when `PeerGracefulRestart` is received.
///
/// The entry stays alive through the LLGR stale phase — `handle_peer_up`
/// reads `stale_routes_time` when the peer re-establishes during LLGR, and a
/// second GR-deadline expiry re-promotes from it. It is removed at every
/// terminal point: GR/LLGR completion on End-of-RIB, LLGR expiry sweep,
/// the no-LLGR purge branch of the GR expiry sweep, and `handle_peer_down`.
#[derive(Clone)]
pub(super) struct LlgrPeerConfig {
    pub(super) peer_llgr_capable: bool,
    pub(super) peer_llgr_families: Vec<LlgrFamily>,
    pub(super) local_llgr_stale_time: u32,
    /// Configured stale-routes-time for use if peer re-establishes during LLGR.
    pub(super) stale_routes_time: u64,
}

/// Safe cast from usize to i64 for gauge metrics.
#[expect(
    clippy::cast_possible_wrap,
    reason = "Prometheus gauge values are bounded by in-memory route counts in practice"
)]
pub(super) fn gauge_val(n: usize) -> i64 {
    n as i64
}

/// Compare two routes for outbound equality (same attributes, next-hop, peer).
/// Used to avoid re-announcing unchanged routes to multi-path peers.
pub(super) fn routes_equal(a: &crate::route::Route, b: &crate::route::Route) -> bool {
    a.next_hop == b.next_hop
        && a.peer == b.peer
        && (Arc::ptr_eq(&a.attributes, &b.attributes) || a.attributes == b.attributes)
}

/// EVPN counterpart of [`routes_equal`]. Skip the deep attribute compare
/// when the underlying `Arc<Vec<PathAttribute>>` is the same allocation.
pub(super) fn evpn_routes_equal(
    a: &crate::route::EvpnRibRoute,
    b: &crate::route::EvpnRibRoute,
) -> bool {
    a.next_hop == b.next_hop
        && a.peer == b.peer
        && a.route == b.route
        && (Arc::ptr_eq(&a.attributes, &b.attributes) || a.attributes == b.attributes)
}

#[must_use]
pub(super) fn prefix_family(prefix: &Prefix) -> (Afi, Safi) {
    match prefix {
        Prefix::V4(_) => (Afi::Ipv4, Safi::Unicast),
        Prefix::V6(_) => (Afi::Ipv6, Safi::Unicast),
    }
}

#[must_use]
pub(super) fn afi_safi_label(afi: Afi, safi: Safi) -> &'static str {
    match (afi, safi) {
        (Afi::Ipv4, Safi::Unicast) => "ipv4_unicast",
        (Afi::Ipv6, Safi::Unicast) => "ipv6_unicast",
        (Afi::Ipv4, Safi::FlowSpec) => "ipv4_flowspec",
        (Afi::Ipv6, Safi::FlowSpec) => "ipv6_flowspec",
        (Afi::L2Vpn, Safi::Evpn) => "l2vpn_evpn",
        (Afi::Ipv4, Safi::Multicast) => "ipv4_multicast",
        (Afi::Ipv6, Safi::Multicast) => "ipv6_multicast",
        (Afi::Ipv4 | Afi::Ipv6, Safi::Evpn)
        | (Afi::L2Vpn, Safi::Unicast | Safi::Multicast | Safi::FlowSpec) => "unsupported",
    }
}

/// iBGP split-horizon / RFC 4456 reflection logic, extracted as a free
/// function so it can be called when `self.adj_ribs_out` is mutably borrowed.
///
/// RFC 4456 reflection rules (when `cluster_id` is `Some`, i.e. we are an RR):
/// - eBGP-learned or Local routes: never suppress to anyone
/// - iBGP-learned from an RR client: reflect to all (clients + non-clients)
/// - iBGP-learned from a non-client: reflect to clients only
///
/// Standard iBGP split-horizon (no RR): suppress all iBGP-learned routes to iBGP peers.
pub(super) fn should_suppress_ibgp_inner(
    route: &crate::route::Route,
    target_is_ebgp: bool,
    target_is_rr_client: bool,
    cluster_id: Option<Ipv4Addr>,
    peer_is_rr_client: &HashMap<IpAddr, bool>,
) -> bool {
    // eBGP targets never suppressed
    if target_is_ebgp {
        return false;
    }
    // eBGP-learned and Local routes always pass to iBGP peers
    if route.origin_type != crate::route::RouteOrigin::Ibgp {
        return false;
    }
    // At this point: route is iBGP-learned, target is iBGP
    match cluster_id {
        Some(_) => {
            // RR mode: check if source was a client
            let source_is_client = peer_is_rr_client.get(&route.peer).copied().unwrap_or(false);
            if source_is_client {
                // Client route → reflect to all (clients + non-clients)
                false
            } else {
                // Non-client route → reflect to clients only
                !target_is_rr_client
            }
        }
        None => {
            // Standard iBGP split-horizon: suppress all iBGP-learned
            true
        }
    }
}

/// Validate a route's origin against the VRP table (RFC 6811).
///
/// Extracts the origin ASN from the route's `AS_PATH` (last AS in rightmost
/// `AS_SEQUENCE`). Returns `NotFound` if no `AS_PATH` is present.
pub(super) fn validate_route_rpki(route: &crate::route::Route, table: &VrpTable) -> RpkiValidation {
    let origin = route.as_path().and_then(rustbgpd_wire::AsPath::origin_asn);
    match origin {
        Some(asn) => table.validate(&route.prefix, asn),
        None => RpkiValidation::NotFound,
    }
}

/// Validate a route's `AS_PATH` against the ASPA table.
///
/// Runs the same role-aware ASPA verification that was used at import time.
/// Returns `Unknown` if no `AS_PATH` is present.
///
/// Per `draft-ietf-sidrops-aspa-verification-25` §6.2, ASPA applies only
/// to IPv4/IPv6 unicast. This helper is invoked from unicast-RIB contexts
/// only (distribution and graceful-restart revalidation of unicast
/// routes), so the §6.2 precondition is satisfied by construction. If
/// non-unicast routes are ever routed through this helper, callers must
/// gate via [`ValidationSnapshot::validate_aspa`], which carries the
/// explicit family check.
pub(super) fn validate_route_aspa(
    route: &crate::route::Route,
    table: &AspaTable,
) -> AspaValidation {
    match route.as_path() {
        Some(path) => rustbgpd_rpki::aspa_verify::verify(path, table, route.aspa_context),
        None => AspaValidation::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn afi_safi_label_marks_impossible_pairs_as_unsupported() {
        assert_eq!(afi_safi_label(Afi::Ipv4, Safi::Evpn), "unsupported");
        assert_eq!(afi_safi_label(Afi::Ipv6, Safi::Evpn), "unsupported");
        assert_eq!(afi_safi_label(Afi::L2Vpn, Safi::FlowSpec), "unsupported");
        assert_eq!(afi_safi_label(Afi::L2Vpn, Safi::Evpn), "l2vpn_evpn");
    }
}
