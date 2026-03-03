use std::collections::HashMap;
use std::net::IpAddr;

use rustbgpd_wire::{Afi, Prefix, Safi};

use crate::route::Route;

/// Per-peer Adj-RIB-In: stores the routes received from a single peer.
///
/// Routes are keyed by `(Prefix, path_id)` to support Add-Path (RFC 7911).
/// Non-Add-Path peers always use `path_id = 0`.
#[derive(Debug)]
pub struct AdjRibIn {
    peer: IpAddr,
    routes: HashMap<(Prefix, u32), Route>,
}

impl AdjRibIn {
    #[must_use]
    pub fn new(peer: IpAddr) -> Self {
        Self {
            peer,
            routes: HashMap::new(),
        }
    }

    #[must_use]
    pub fn peer(&self) -> IpAddr {
        self.peer
    }

    pub fn insert(&mut self, route: Route) {
        self.routes.insert((route.prefix, route.path_id), route);
    }

    pub fn withdraw(&mut self, prefix: &Prefix, path_id: u32) -> bool {
        self.routes.remove(&(*prefix, path_id)).is_some()
    }

    pub fn clear(&mut self) {
        self.routes.clear();
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Route> {
        self.routes.values()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Route> {
        self.routes.values_mut()
    }

    #[must_use]
    pub fn get(&self, prefix: &Prefix, path_id: u32) -> Option<&Route> {
        self.routes.get(&(*prefix, path_id))
    }

    /// Iterate over all routes for a given prefix (all path IDs).
    pub fn iter_prefix(&self, prefix: &Prefix) -> impl Iterator<Item = &Route> {
        let target = *prefix;
        self.routes.values().filter(move |r| r.prefix == target)
    }

    /// Mark all routes matching the given address family as stale.
    pub fn mark_stale(&mut self, family: (Afi, Safi)) {
        for route in self.routes.values_mut() {
            if route_matches_family(route, family) {
                route.is_stale = true;
            }
        }
    }

    /// Clear the stale flag on routes matching the given address family.
    pub fn clear_stale(&mut self, family: (Afi, Safi)) {
        for route in self.routes.values_mut() {
            if route_matches_family(route, family) {
                route.is_stale = false;
            }
        }
    }

    /// Remove all routes whose family is NOT in `keep`, returning their
    /// prefixes.  Used during graceful restart to withdraw routes for
    /// families not covered by the peer's GR capability.
    pub fn withdraw_families_except(&mut self, keep: &[(Afi, Safi)]) -> Vec<Prefix> {
        let to_remove: Vec<(Prefix, u32)> = self
            .routes
            .iter()
            .filter(|(_, r)| !keep.iter().any(|&fam| route_matches_family(r, fam)))
            .map(|(k, _)| *k)
            .collect();
        let mut prefixes = Vec::new();
        for key in &to_remove {
            prefixes.push(key.0);
            self.routes.remove(key);
        }
        prefixes
    }

    /// Remove all stale routes, returning their prefixes.
    pub fn sweep_stale(&mut self) -> Vec<Prefix> {
        let stale: Vec<(Prefix, u32)> = self
            .routes
            .iter()
            .filter(|(_, r)| r.is_stale)
            .map(|(k, _)| *k)
            .collect();
        let mut prefixes = Vec::new();
        for key in &stale {
            prefixes.push(key.0);
            self.routes.remove(key);
        }
        prefixes
    }
}

/// Check whether a route's prefix matches an AFI/SAFI family.
fn route_matches_family(route: &Route, family: (Afi, Safi)) -> bool {
    family.1 == Safi::Unicast
        && matches!(
            (&route.prefix, family.0),
            (Prefix::V4(_), Afi::Ipv4) | (Prefix::V6(_), Afi::Ipv6)
        )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::Instant;

    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix};

    use super::*;

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
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        }
    }

    #[test]
    fn insert_and_get() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

        rib.insert(route);
        assert_eq!(rib.len(), 1);
        assert!(rib.get(&Prefix::V4(prefix), 0).is_some());
    }

    #[test]
    fn withdraw_returns_true_if_present() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        rib.insert(make_route(prefix, Ipv4Addr::new(10, 0, 0, 1)));

        assert!(rib.withdraw(&Prefix::V4(prefix), 0));
        assert_eq!(rib.len(), 0);
    }

    #[test]
    fn withdraw_returns_false_if_absent() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        assert!(!rib.withdraw(&Prefix::V4(prefix), 0));
    }

    #[test]
    fn clear_removes_all() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        rib.insert(make_route(
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8),
            Ipv4Addr::new(10, 0, 0, 1),
        ));
        rib.insert(make_route(
            Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12),
            Ipv4Addr::new(10, 0, 0, 1),
        ));
        assert_eq!(rib.len(), 2);

        rib.clear();
        assert!(rib.is_empty());
    }

    #[test]
    fn mark_stale_by_family() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        rib.insert(make_route(prefix, Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!rib.get(&Prefix::V4(prefix), 0).unwrap().is_stale);

        rib.mark_stale((Afi::Ipv4, Safi::Unicast));
        assert!(rib.get(&Prefix::V4(prefix), 0).unwrap().is_stale);
    }

    #[test]
    fn mark_stale_ignores_wrong_family() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        rib.insert(make_route(prefix, Ipv4Addr::new(10, 0, 0, 1)));

        rib.mark_stale((Afi::Ipv6, Safi::Unicast));
        assert!(!rib.get(&Prefix::V4(prefix), 0).unwrap().is_stale);
    }

    #[test]
    fn clear_stale_by_family() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        rib.insert(make_route(prefix, Ipv4Addr::new(10, 0, 0, 1)));

        rib.mark_stale((Afi::Ipv4, Safi::Unicast));
        assert!(rib.get(&Prefix::V4(prefix), 0).unwrap().is_stale);

        rib.clear_stale((Afi::Ipv4, Safi::Unicast));
        assert!(!rib.get(&Prefix::V4(prefix), 0).unwrap().is_stale);
    }

    #[test]
    fn sweep_stale_removes_stale_routes() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let p1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let p2 = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
        rib.insert(make_route(p1, Ipv4Addr::new(10, 0, 0, 1)));
        rib.insert(make_route(p2, Ipv4Addr::new(10, 0, 0, 1)));

        rib.mark_stale((Afi::Ipv4, Safi::Unicast));
        // Insert a fresh (non-stale) route for p2
        rib.insert(make_route(p2, Ipv4Addr::new(10, 0, 0, 1)));

        let swept = rib.sweep_stale();
        assert_eq!(swept.len(), 1);
        assert_eq!(swept[0], Prefix::V4(p1));
        assert_eq!(rib.len(), 1); // p2 remains
    }

    #[test]
    fn insert_replaces_existing() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        rib.insert(make_route(prefix, Ipv4Addr::new(10, 0, 0, 1)));
        rib.insert(make_route(prefix, Ipv4Addr::new(10, 0, 0, 2)));

        assert_eq!(rib.len(), 1);
        assert_eq!(
            rib.get(&Prefix::V4(prefix), 0).unwrap().next_hop,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn withdraw_families_except_removes_non_matching() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let v4 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let v6 = Ipv6Prefix::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32);

        rib.insert(make_route(v4, Ipv4Addr::new(10, 0, 0, 1)));
        rib.insert(make_v6_route(
            v6,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        ));
        assert_eq!(rib.len(), 2);

        // Keep only IPv4 — IPv6 should be withdrawn
        let removed = rib.withdraw_families_except(&[(Afi::Ipv4, Safi::Unicast)]);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], Prefix::V6(v6));
        assert_eq!(rib.len(), 1);
        assert!(rib.get(&Prefix::V4(v4), 0).is_some());
        assert!(rib.get(&Prefix::V6(v6), 0).is_none());
    }

    #[test]
    fn withdraw_families_except_keeps_all_when_matching() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let v4 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        rib.insert(make_route(v4, Ipv4Addr::new(10, 0, 0, 1)));

        let removed =
            rib.withdraw_families_except(&[(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)]);
        assert!(removed.is_empty());
        assert_eq!(rib.len(), 1);
    }

    #[test]
    fn insert_same_prefix_different_path_ids() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        let mut r1 = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
        r1.path_id = 1;
        let mut r2 = make_route(prefix, Ipv4Addr::new(10, 0, 0, 2));
        r2.path_id = 2;

        rib.insert(r1);
        rib.insert(r2);
        assert_eq!(rib.len(), 2);

        assert!(rib.get(&Prefix::V4(prefix), 1).is_some());
        assert!(rib.get(&Prefix::V4(prefix), 2).is_some());
        assert!(rib.get(&Prefix::V4(prefix), 0).is_none());
    }

    #[test]
    fn withdraw_specific_path_id() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        let mut r1 = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
        r1.path_id = 1;
        let mut r2 = make_route(prefix, Ipv4Addr::new(10, 0, 0, 2));
        r2.path_id = 2;

        rib.insert(r1);
        rib.insert(r2);

        assert!(rib.withdraw(&Prefix::V4(prefix), 1));
        assert_eq!(rib.len(), 1);
        assert!(rib.get(&Prefix::V4(prefix), 1).is_none());
        assert!(rib.get(&Prefix::V4(prefix), 2).is_some());
    }

    #[test]
    fn iter_prefix_yields_all_path_ids() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let other = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);

        let mut r1 = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
        r1.path_id = 1;
        let mut r2 = make_route(prefix, Ipv4Addr::new(10, 0, 0, 2));
        r2.path_id = 2;
        rib.insert(r1);
        rib.insert(r2);
        rib.insert(make_route(other, Ipv4Addr::new(10, 0, 0, 3)));

        let routes: Vec<_> = rib.iter_prefix(&Prefix::V4(prefix)).collect();
        assert_eq!(routes.len(), 2);
    }
}
