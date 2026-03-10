use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use rustbgpd_wire::{Afi, FlowSpecRule, Prefix, Safi};

use crate::route::{FlowSpecRoute, Route};

/// Per-peer Adj-RIB-In: stores the routes received from a single peer.
///
/// Routes are keyed by `(Prefix, path_id)` to support Add-Path (RFC 7911).
/// Non-Add-Path peers always use `path_id = 0`.
///
/// A secondary `prefix_index` maps each prefix to its set of path IDs,
/// enabling O(candidates) `iter_prefix()` lookups instead of O(N) full scans.
///
/// Path attribute interning: routes from the same peer that share identical
/// attributes reuse a single `Arc<Vec<PathAttribute>>` allocation.  This is
/// common in bulk advertisements where every prefix has the same ORIGIN,
/// `AS_PATH`, `NEXT_HOP`, `LOCAL_PREF`, MED, and communities.
#[derive(Debug)]
pub struct AdjRibIn {
    peer: IpAddr,
    routes: HashMap<(Prefix, u32), Route>,
    /// Secondary index: prefix → set of path IDs stored for that prefix.
    prefix_index: HashMap<Prefix, HashSet<u32>>,
    /// Route keys where `LLGR_STALE` was injected locally by this daemon.
    llgr_stale_local_tags: HashSet<(Prefix, u32)>,
    /// `FlowSpec` routes keyed by `(rule, path_id)`.
    flowspec_routes: HashMap<(FlowSpecRule, u32), FlowSpecRoute>,
    /// Intern table: deduplicates identical attribute sets across routes.
    /// Lookup by content returns the shared `Arc`.  Entries with
    /// `strong_count == 1` (only the intern table itself) are garbage-
    /// collected on `gc_intern_table()`.
    attr_intern: HashSet<Arc<Vec<rustbgpd_wire::PathAttribute>>>,
}

impl AdjRibIn {
    /// Create a new empty Adj-RIB-In for the given peer.
    #[must_use]
    pub fn new(peer: IpAddr) -> Self {
        Self::with_capacity(peer, 0, 0)
    }

    /// Create a new Adj-RIB-In with estimated capacities for the first batch.
    #[must_use]
    pub fn with_capacity(peer: IpAddr, route_capacity: usize, flowspec_capacity: usize) -> Self {
        let route_capacity = route_capacity.max(16);
        let flowspec_capacity = flowspec_capacity.max(4);
        Self {
            peer,
            routes: HashMap::with_capacity(route_capacity),
            prefix_index: HashMap::with_capacity(route_capacity),
            llgr_stale_local_tags: HashSet::new(),
            flowspec_routes: HashMap::with_capacity(flowspec_capacity),
            attr_intern: HashSet::with_capacity(route_capacity.clamp(16, 64)),
        }
    }

    /// Return the peer address this RIB belongs to.
    #[must_use]
    pub fn peer(&self) -> IpAddr {
        self.peer
    }

    /// Insert or replace a route. Clears any stale tag on the key.
    ///
    /// The route's attributes are interned: if an identical attribute set
    /// already exists from a previous route, the existing `Arc` is reused
    /// instead of keeping a separate allocation.
    pub fn insert(&mut self, mut route: Route) {
        let key = (route.prefix, route.path_id);
        self.prefix_index
            .entry(route.prefix)
            .or_default()
            .insert(route.path_id);
        self.llgr_stale_local_tags.remove(&key);

        // Intern: reuse an existing Arc if one matches
        if let Some(existing) = self.attr_intern.get(&route.attributes) {
            route.attributes = existing.clone();
        } else {
            self.attr_intern.insert(route.attributes.clone());
        }

        self.routes.insert(key, route);
    }

    /// Withdraw a route by prefix and path ID. Returns `true` if it existed.
    pub fn withdraw(&mut self, prefix: &Prefix, path_id: u32) -> bool {
        let key = (*prefix, path_id);
        self.llgr_stale_local_tags.remove(&key);
        let removed = self.routes.remove(&key).is_some();
        if removed {
            self.remove_from_prefix_index(prefix, path_id);
        }
        removed
    }

    /// Remove all routes and stale tags.
    pub fn clear(&mut self) {
        self.routes.clear();
        self.prefix_index.clear();
        self.llgr_stale_local_tags.clear();
        self.attr_intern.clear();
    }

    /// Return the number of unicast routes stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Return `true` if no unicast routes are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Iterate over all stored routes.
    pub fn iter(&self) -> impl Iterator<Item = &Route> {
        self.routes.values()
    }

    /// Iterate mutably over all stored routes.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Route> {
        self.routes.values_mut()
    }

    /// Look up a route by prefix and path ID.
    #[must_use]
    pub fn get(&self, prefix: &Prefix, path_id: u32) -> Option<&Route> {
        self.routes.get(&(*prefix, path_id))
    }

    /// Iterate over all routes for a given prefix (all path IDs).
    ///
    /// Uses a secondary prefix index for O(candidates) lookup instead of
    /// scanning the entire RIB.
    pub fn iter_prefix(&self, prefix: &Prefix) -> impl Iterator<Item = &Route> {
        let path_ids = self.prefix_index.get(prefix);
        let target = *prefix;
        let routes = &self.routes;
        path_ids.into_iter().flat_map(move |ids| {
            ids.iter()
                .filter_map(move |&pid| routes.get(&(target, pid)))
        })
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
        let mut clear_local_llgr = Vec::new();
        for (key, route) in &mut self.routes {
            if route_matches_family(route, family) {
                route.is_stale = false;
                route.is_llgr_stale = false;
                if self.llgr_stale_local_tags.contains(key) {
                    clear_local_llgr.push(*key);
                }
            }
        }
        self.clear_local_llgr_stale_community(&clear_local_llgr);
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
            self.llgr_stale_local_tags.remove(key);
            self.routes.remove(key);
            self.remove_from_prefix_index(&key.0, key.1);
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
            self.llgr_stale_local_tags.remove(key);
            self.routes.remove(key);
            self.remove_from_prefix_index(&key.0, key.1);
        }
        prefixes
    }

    /// Remove stale routes for a specific family, returning their prefixes.
    /// Used when a family was in GR but not in the peer's LLGR capability.
    pub fn sweep_stale_family(&mut self, family: (Afi, Safi)) -> Vec<Prefix> {
        let stale: Vec<(Prefix, u32)> = self
            .routes
            .iter()
            .filter(|(_, r)| r.is_stale && route_matches_family(r, family))
            .map(|(k, _)| *k)
            .collect();
        let mut prefixes = Vec::new();
        for key in &stale {
            prefixes.push(key.0);
            self.llgr_stale_local_tags.remove(key);
            self.routes.remove(key);
            self.remove_from_prefix_index(&key.0, key.1);
        }
        prefixes
    }

    /// Promote GR-stale routes to LLGR-stale for the given family (RFC 9494).
    ///
    /// - Routes with `NO_LLGR` community are removed (must not enter LLGR).
    /// - Remaining stale routes: `is_stale=false`, `is_llgr_stale=true`,
    ///   `LLGR_STALE` community added.
    ///
    /// Returns prefixes affected (for best-path recalc).
    pub fn promote_to_llgr_stale(&mut self, family: (Afi, Safi)) -> Vec<Prefix> {
        use rustbgpd_wire::{COMMUNITY_LLGR_STALE, COMMUNITY_NO_LLGR, PathAttribute};

        // First pass: remove routes with NO_LLGR community
        let no_llgr_keys: Vec<(Prefix, u32)> = self
            .routes
            .iter()
            .filter(|(_, r)| {
                r.is_stale
                    && route_matches_family(r, family)
                    && r.communities().contains(&COMMUNITY_NO_LLGR)
            })
            .map(|(k, _)| *k)
            .collect();
        let mut affected: Vec<Prefix> = no_llgr_keys.iter().map(|(p, _)| *p).collect();
        for key in &no_llgr_keys {
            self.llgr_stale_local_tags.remove(key);
            self.routes.remove(key);
            self.remove_from_prefix_index(&key.0, key.1);
        }

        // Second pass: promote remaining stale routes to LLGR-stale
        for route in self.routes.values_mut() {
            if route.is_stale && route_matches_family(route, family) {
                route.is_stale = false;
                route.is_llgr_stale = true;
                // Add LLGR_STALE community
                let attrs = Arc::make_mut(&mut route.attributes);
                if let Some(PathAttribute::Communities(comms)) = attrs
                    .iter_mut()
                    .find(|a| matches!(a, PathAttribute::Communities(_)))
                {
                    if !comms.contains(&COMMUNITY_LLGR_STALE) {
                        comms.push(COMMUNITY_LLGR_STALE);
                        self.llgr_stale_local_tags
                            .insert((route.prefix, route.path_id));
                    }
                } else {
                    attrs.push(PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE]));
                    self.llgr_stale_local_tags
                        .insert((route.prefix, route.path_id));
                }
                affected.push(route.prefix);
            }
        }

        affected
    }

    /// Remove all LLGR-stale routes, returning their prefixes.
    pub fn sweep_llgr_stale(&mut self) -> Vec<Prefix> {
        let stale: Vec<(Prefix, u32)> = self
            .routes
            .iter()
            .filter(|(_, r)| r.is_llgr_stale)
            .map(|(k, _)| *k)
            .collect();
        let mut prefixes = Vec::new();
        for key in &stale {
            prefixes.push(key.0);
            self.llgr_stale_local_tags.remove(key);
            self.routes.remove(key);
            self.remove_from_prefix_index(&key.0, key.1);
        }
        prefixes
    }

    /// Clear the LLGR-stale flag on routes matching the given family.
    /// Called when `EoR` is received during LLGR phase.
    pub fn clear_llgr_stale(&mut self, family: (Afi, Safi)) {
        let mut clear_local_llgr = Vec::new();
        for (key, route) in &mut self.routes {
            if route_matches_family(route, family) {
                route.is_llgr_stale = false;
                if self.llgr_stale_local_tags.contains(key) {
                    clear_local_llgr.push(*key);
                }
            }
        }
        self.clear_local_llgr_stale_community(&clear_local_llgr);
    }

    /// Garbage-collect interned attribute sets that are no longer referenced
    /// by any route (only the intern table itself holds the `Arc`).
    pub fn gc_intern_table(&mut self) {
        self.attr_intern.retain(|arc| Arc::strong_count(arc) > 1);
    }

    /// Return the number of unique interned attribute sets.
    #[must_use]
    pub fn intern_len(&self) -> usize {
        self.attr_intern.len()
    }

    // --- FlowSpec methods ---

    /// Insert or replace a `FlowSpec` route.
    pub fn insert_flowspec(&mut self, route: FlowSpecRoute) {
        self.flowspec_routes
            .insert((route.rule.clone(), route.path_id), route);
    }

    /// Withdraw a `FlowSpec` route by rule and path ID. Returns `true` if it existed.
    pub fn withdraw_flowspec(&mut self, rule: &FlowSpecRule, path_id: u32) -> bool {
        self.flowspec_routes
            .remove(&(rule.clone(), path_id))
            .is_some()
    }

    /// Iterate over all `FlowSpec` routes.
    pub fn iter_flowspec(&self) -> impl Iterator<Item = &FlowSpecRoute> {
        self.flowspec_routes.values()
    }

    /// Iterate all `FlowSpec` routes matching a given rule (all path IDs).
    pub fn iter_flowspec_rule(&self, rule: &FlowSpecRule) -> impl Iterator<Item = &FlowSpecRoute> {
        let target = rule.clone();
        self.flowspec_routes
            .values()
            .filter(move |r| r.rule == target)
    }

    /// Return the number of `FlowSpec` routes stored.
    #[must_use]
    pub fn flowspec_len(&self) -> usize {
        self.flowspec_routes.len()
    }

    /// Mark `FlowSpec` routes matching the given address family as stale.
    pub fn mark_stale_flowspec(&mut self, family: (Afi, Safi)) {
        if family.1 != Safi::FlowSpec {
            return;
        }
        for route in self.flowspec_routes.values_mut() {
            if route.afi == family.0 {
                route.is_stale = true;
            }
        }
    }

    /// Remove all stale `FlowSpec` routes, returning their rules.
    pub fn sweep_stale_flowspec(&mut self) -> Vec<FlowSpecRule> {
        let stale: Vec<(FlowSpecRule, u32)> = self
            .flowspec_routes
            .iter()
            .filter(|(_, r)| r.is_stale)
            .map(|(k, _)| k.clone())
            .collect();
        let mut rules = Vec::new();
        for key in &stale {
            rules.push(key.0.clone());
            self.flowspec_routes.remove(key);
        }
        rules
    }

    /// Clear all `FlowSpec` routes.
    pub fn clear_flowspec(&mut self) {
        self.flowspec_routes.clear();
    }

    /// Clear the stale flag on `FlowSpec` routes matching the given family.
    pub fn clear_stale_flowspec(&mut self, family: (Afi, Safi)) {
        if family.1 != Safi::FlowSpec {
            return;
        }
        for route in self.flowspec_routes.values_mut() {
            if route.afi == family.0 {
                route.is_stale = false;
            }
        }
    }

    /// Remove a `path_id` from the prefix index, cleaning up empty entries.
    fn remove_from_prefix_index(&mut self, prefix: &Prefix, path_id: u32) {
        if let Some(ids) = self.prefix_index.get_mut(prefix) {
            ids.remove(&path_id);
            if ids.is_empty() {
                self.prefix_index.remove(prefix);
            }
        }
    }

    fn clear_local_llgr_stale_community(&mut self, keys: &[(Prefix, u32)]) {
        for key in keys {
            if let Some(route) = self.routes.get_mut(key) {
                remove_llgr_stale_community(route);
            }
            self.llgr_stale_local_tags.remove(key);
        }
    }
}

/// Remove the `LLGR_STALE` community from a route's attributes, if present.
fn remove_llgr_stale_community(route: &mut Route) {
    use rustbgpd_wire::{COMMUNITY_LLGR_STALE, PathAttribute};
    use std::sync::Arc;
    for attr in Arc::make_mut(&mut route.attributes) {
        if let PathAttribute::Communities(comms) = attr {
            comms.retain(|&c| c != COMMUNITY_LLGR_STALE);
        }
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
    use std::sync::Arc;
    use std::time::Instant;

    use rustbgpd_wire::{COMMUNITY_LLGR_STALE, Ipv4Prefix, Ipv6Prefix, PathAttribute};

    use super::*;

    fn make_route(prefix: Ipv4Prefix, next_hop: Ipv4Addr) -> Route {
        Route {
            prefix: Prefix::V4(prefix),
            next_hop: IpAddr::V4(next_hop),
            peer: IpAddr::V4(next_hop),
            attributes: Arc::new(vec![]),
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
            attributes: Arc::new(vec![]),
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

    #[test]
    fn clear_llgr_stale_preserves_peer_originated_llgr_stale_community() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);

        let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
        route.is_llgr_stale = true;
        Arc::make_mut(&mut route.attributes)
            .push(PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE]));
        rib.insert(route);

        rib.clear_llgr_stale((Afi::Ipv4, Safi::Unicast));
        let route = rib.get(&Prefix::V4(prefix), 0).unwrap();
        assert!(!route.is_llgr_stale);
        assert!(route.communities().contains(&COMMUNITY_LLGR_STALE));
    }

    #[test]
    fn clear_llgr_stale_removes_locally_added_llgr_stale_community() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);

        let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
        route.is_stale = true;
        rib.insert(route);

        rib.promote_to_llgr_stale((Afi::Ipv4, Safi::Unicast));
        assert!(
            rib.get(&Prefix::V4(prefix), 0)
                .unwrap()
                .communities()
                .contains(&COMMUNITY_LLGR_STALE)
        );

        rib.clear_llgr_stale((Afi::Ipv4, Safi::Unicast));
        let route = rib.get(&Prefix::V4(prefix), 0).unwrap();
        assert!(!route.is_llgr_stale);
        assert!(!route.communities().contains(&COMMUNITY_LLGR_STALE));
    }

    #[test]
    fn intern_deduplicates_identical_attributes() {
        use rustbgpd_wire::Origin;

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);

        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::LocalPref(100),
        ];

        let p1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let p2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);
        let p3 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 3, 0), 24);

        let mut r1 = make_route(p1, Ipv4Addr::new(10, 0, 0, 1));
        r1.attributes = Arc::new(attrs.clone());
        let mut r2 = make_route(p2, Ipv4Addr::new(10, 0, 0, 1));
        r2.attributes = Arc::new(attrs.clone());
        let mut r3 = make_route(p3, Ipv4Addr::new(10, 0, 0, 1));
        r3.attributes = Arc::new(attrs);

        rib.insert(r1);
        rib.insert(r2);
        rib.insert(r3);

        // All three routes should share the same Arc
        let a1 = &rib.get(&Prefix::V4(p1), 0).unwrap().attributes;
        let a2 = &rib.get(&Prefix::V4(p2), 0).unwrap().attributes;
        let a3 = &rib.get(&Prefix::V4(p3), 0).unwrap().attributes;
        assert!(Arc::ptr_eq(a1, a2));
        assert!(Arc::ptr_eq(a2, a3));

        // Only one unique entry in the intern table
        assert_eq!(rib.intern_len(), 1);
    }

    #[test]
    fn intern_separates_different_attributes() {
        use rustbgpd_wire::Origin;

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);

        let p1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let p2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

        let mut r1 = make_route(p1, Ipv4Addr::new(10, 0, 0, 1));
        r1.attributes = Arc::new(vec![PathAttribute::Origin(Origin::Igp)]);
        let mut r2 = make_route(p2, Ipv4Addr::new(10, 0, 0, 1));
        r2.attributes = Arc::new(vec![PathAttribute::Origin(Origin::Egp)]);

        rib.insert(r1);
        rib.insert(r2);

        let a1 = &rib.get(&Prefix::V4(p1), 0).unwrap().attributes;
        let a2 = &rib.get(&Prefix::V4(p2), 0).unwrap().attributes;
        assert!(!Arc::ptr_eq(a1, a2));
        assert_eq!(rib.intern_len(), 2);
    }

    #[test]
    fn gc_intern_table_removes_orphaned_entries() {
        use rustbgpd_wire::Origin;

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);

        let p1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let p2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

        let attrs = vec![PathAttribute::Origin(Origin::Igp)];
        let mut r1 = make_route(p1, Ipv4Addr::new(10, 0, 0, 1));
        r1.attributes = Arc::new(attrs.clone());
        let mut r2 = make_route(p2, Ipv4Addr::new(10, 0, 0, 1));
        r2.attributes = Arc::new(vec![PathAttribute::Origin(Origin::Egp)]);

        rib.insert(r1);
        rib.insert(r2);
        assert_eq!(rib.intern_len(), 2);

        // Withdraw p2 — its unique attrs become orphaned
        rib.withdraw(&Prefix::V4(p2), 0);
        assert_eq!(rib.intern_len(), 2); // still there before GC

        rib.gc_intern_table();
        assert_eq!(rib.intern_len(), 1); // orphan cleaned up
    }
}
