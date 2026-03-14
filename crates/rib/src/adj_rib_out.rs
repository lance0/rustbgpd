use std::collections::HashMap;
use std::net::IpAddr;

use rustbgpd_wire::{FlowSpecRule, Prefix};
use smallvec::SmallVec;

use crate::route::{FlowSpecRoute, Route};

/// Per-peer Adj-RIB-Out: routes advertised to a specific peer.
///
/// Routes are keyed by `(Prefix, path_id)` for Add-Path (RFC 7911).
/// In single-best mode, `path_id` is always 0.
pub struct AdjRibOut {
    peer: IpAddr,
    routes: HashMap<(Prefix, u32), Route>,
    /// Secondary index: prefix → path IDs for O(1) per-prefix lookup.
    /// `SmallVec<[u32; 1]>` inlines the single-best case (`path_id=0`) without
    /// heap allocation; Add-Path multi-path spills to heap transparently.
    prefix_path_ids: HashMap<Prefix, SmallVec<[u32; 1]>>,
    /// `FlowSpec` routes advertised to this peer (always single-best, `path_id=0`).
    flowspec_routes: HashMap<FlowSpecRule, FlowSpecRoute>,
}

impl AdjRibOut {
    /// Create a new empty Adj-RIB-Out for the given peer.
    #[must_use]
    pub fn new(peer: IpAddr) -> Self {
        Self::with_capacity(peer, 0)
    }

    /// Create a new Adj-RIB-Out with pre-sized capacity.
    ///
    /// Use `LocRib::len()` as a good estimate — each peer's outbound view
    /// converges to approximately the same prefix count as the best-path table.
    #[must_use]
    pub fn with_capacity(peer: IpAddr, capacity: usize) -> Self {
        Self {
            peer,
            routes: HashMap::with_capacity(capacity),
            prefix_path_ids: HashMap::with_capacity(capacity),
            flowspec_routes: HashMap::new(),
        }
    }

    /// Return the peer address this RIB belongs to.
    #[must_use]
    pub fn peer(&self) -> IpAddr {
        self.peer
    }

    /// Insert or replace an advertised route.
    pub fn insert(&mut self, route: Route) {
        let prefix = route.prefix;
        let path_id = route.path_id;
        self.routes.insert((prefix, path_id), route);
        let ids = self.prefix_path_ids.entry(prefix).or_default();
        if !ids.contains(&path_id) {
            ids.push(path_id);
        }
    }

    /// Withdraw a route by prefix and path ID. Returns `true` if it existed.
    pub fn withdraw(&mut self, prefix: &Prefix, path_id: u32) -> bool {
        if self.routes.remove(&(*prefix, path_id)).is_some() {
            if let Some(ids) = self.prefix_path_ids.get_mut(prefix) {
                ids.retain(|id| *id != path_id);
                if ids.is_empty() {
                    self.prefix_path_ids.remove(prefix);
                }
            }
            true
        } else {
            false
        }
    }

    /// Look up a route by prefix and path ID.
    #[must_use]
    pub fn get(&self, prefix: &Prefix, path_id: u32) -> Option<&Route> {
        self.routes.get(&(*prefix, path_id))
    }

    /// Iterate over all advertised routes.
    pub fn iter(&self) -> impl Iterator<Item = &Route> {
        self.routes.values()
    }

    /// Iterate over all routes for a given prefix (all path IDs).
    pub fn iter_prefix(&self, prefix: &Prefix) -> impl Iterator<Item = &Route> + '_ {
        let prefix = *prefix;
        self.prefix_path_ids
            .get(&prefix)
            .into_iter()
            .flat_map(move |ids| {
                ids.iter()
                    .filter_map(move |&id| self.routes.get(&(prefix, id)))
            })
    }

    /// Return all path IDs currently advertised for a given prefix.
    #[must_use]
    pub fn path_ids_for_prefix(&self, prefix: &Prefix) -> &[u32] {
        self.prefix_path_ids
            .get(prefix)
            .map_or(&[], SmallVec::as_slice)
    }

    /// Remove all advertised routes.
    pub fn clear(&mut self) {
        self.routes.clear();
        self.prefix_path_ids.clear();
    }

    /// Return the number of advertised routes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Return `true` if no routes are advertised.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    // --- FlowSpec methods ---

    /// Insert or replace an advertised `FlowSpec` route.
    pub fn insert_flowspec(&mut self, route: FlowSpecRoute) {
        self.flowspec_routes.insert(route.rule.clone(), route);
    }

    /// Remove a `FlowSpec` route by rule. Returns `true` if it existed.
    pub fn remove_flowspec(&mut self, rule: &FlowSpecRule) -> bool {
        self.flowspec_routes.remove(rule).is_some()
    }

    /// Look up a `FlowSpec` route by rule.
    #[must_use]
    pub fn get_flowspec(&self, rule: &FlowSpecRule) -> Option<&FlowSpecRoute> {
        self.flowspec_routes.get(rule)
    }

    /// Iterate over all advertised `FlowSpec` routes.
    pub fn iter_flowspec(&self) -> impl Iterator<Item = &FlowSpecRoute> {
        self.flowspec_routes.values()
    }

    /// Return the number of advertised `FlowSpec` routes.
    #[must_use]
    pub fn flowspec_len(&self) -> usize {
        self.flowspec_routes.len()
    }

    /// Remove all advertised `FlowSpec` routes.
    pub fn clear_flowspec(&mut self) {
        self.flowspec_routes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use rustbgpd_wire::{Ipv4Prefix, Prefix};

    use crate::route::{Route, RouteOrigin};

    fn make_route(prefix: Prefix, path_id: u32) -> Route {
        Route {
            prefix,
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            peer: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            attributes: Arc::new(vec![]),
            received_at: std::time::Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::new(1, 1, 1, 1),
            is_stale: false,
            is_llgr_stale: false,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            path_id,
        }
    }

    fn prefix_a() -> Prefix {
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24))
    }

    fn prefix_b() -> Prefix {
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 1, 0), 24))
    }

    #[test]
    fn index_tracks_single_best_insert_withdraw() {
        let mut rib = AdjRibOut::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let p = prefix_a();

        assert!(rib.path_ids_for_prefix(&p).is_empty());
        rib.insert(make_route(p, 0));
        assert_eq!(rib.path_ids_for_prefix(&p), [0]);

        assert!(rib.withdraw(&p, 0));
        assert!(rib.path_ids_for_prefix(&p).is_empty());
        assert!(!rib.withdraw(&p, 0));
    }

    #[test]
    fn index_tracks_add_path_multiple_ids() {
        let mut rib = AdjRibOut::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let p = prefix_a();

        rib.insert(make_route(p, 1));
        rib.insert(make_route(p, 2));
        rib.insert(make_route(p, 3));

        let mut ids = rib.path_ids_for_prefix(&p).to_vec();
        ids.sort_unstable();
        assert_eq!(ids, [1, 2, 3]);

        rib.withdraw(&p, 2);
        let mut ids = rib.path_ids_for_prefix(&p).to_vec();
        ids.sort_unstable();
        assert_eq!(ids, [1, 3]);
    }

    #[test]
    fn index_handles_duplicate_insert() {
        let mut rib = AdjRibOut::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let p = prefix_a();

        rib.insert(make_route(p, 0));
        rib.insert(make_route(p, 0)); // replace, not duplicate
        assert_eq!(rib.path_ids_for_prefix(&p), [0]);
        assert_eq!(rib.len(), 1);
    }

    #[test]
    fn index_isolated_per_prefix() {
        let mut rib = AdjRibOut::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let pa = prefix_a();
        let pb = prefix_b();

        rib.insert(make_route(pa, 0));
        rib.insert(make_route(pb, 0));
        rib.insert(make_route(pb, 1));

        assert_eq!(rib.path_ids_for_prefix(&pa), [0]);
        let mut ids_b = rib.path_ids_for_prefix(&pb).to_vec();
        ids_b.sort_unstable();
        assert_eq!(ids_b, [0, 1]);

        rib.withdraw(&pa, 0);
        assert!(rib.path_ids_for_prefix(&pa).is_empty());
        assert_eq!(rib.path_ids_for_prefix(&pb).len(), 2);
    }

    #[test]
    fn clear_resets_index() {
        let mut rib = AdjRibOut::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        rib.insert(make_route(prefix_a(), 0));
        rib.insert(make_route(prefix_b(), 1));

        rib.clear();
        assert!(rib.path_ids_for_prefix(&prefix_a()).is_empty());
        assert!(rib.path_ids_for_prefix(&prefix_b()).is_empty());
        assert!(rib.is_empty());
    }

    #[test]
    fn iter_prefix_uses_index() {
        let mut rib = AdjRibOut::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let pa = prefix_a();
        let pb = prefix_b();

        rib.insert(make_route(pa, 1));
        rib.insert(make_route(pa, 2));
        rib.insert(make_route(pb, 0));

        let routes_a: Vec<_> = rib.iter_prefix(&pa).collect();
        assert_eq!(routes_a.len(), 2);
        assert!(routes_a.iter().all(|r| r.prefix == pa));

        let routes_b: Vec<_> = rib.iter_prefix(&pb).collect();
        assert_eq!(routes_b.len(), 1);

        let routes_none: Vec<_> = rib
            .iter_prefix(&Prefix::V4(Ipv4Prefix::new(
                Ipv4Addr::new(192, 168, 0, 0),
                16,
            )))
            .collect();
        assert!(routes_none.is_empty());
    }
}
