use std::collections::HashMap;
use std::net::IpAddr;

use rustbgpd_wire::{FlowSpecRule, Prefix};

use crate::route::{FlowSpecRoute, Route};

/// Per-peer Adj-RIB-Out: routes advertised to a specific peer.
///
/// Routes are keyed by `(Prefix, path_id)` for Add-Path (RFC 7911).
/// In single-best mode, `path_id` is always 0.
pub struct AdjRibOut {
    peer: IpAddr,
    routes: HashMap<(Prefix, u32), Route>,
    /// `FlowSpec` routes advertised to this peer (always single-best, `path_id=0`).
    flowspec_routes: HashMap<FlowSpecRule, FlowSpecRoute>,
}

impl AdjRibOut {
    /// Create a new empty Adj-RIB-Out for the given peer.
    #[must_use]
    pub fn new(peer: IpAddr) -> Self {
        Self {
            peer,
            routes: HashMap::new(),
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
        self.routes.insert((route.prefix, route.path_id), route);
    }

    /// Withdraw a route by prefix and path ID. Returns `true` if it existed.
    pub fn withdraw(&mut self, prefix: &Prefix, path_id: u32) -> bool {
        self.routes.remove(&(*prefix, path_id)).is_some()
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
    pub fn iter_prefix(&self, prefix: &Prefix) -> impl Iterator<Item = &Route> {
        let target = *prefix;
        self.routes.values().filter(move |r| r.prefix == target)
    }

    /// Return all path IDs currently advertised for a given prefix.
    #[must_use]
    pub fn path_ids_for_prefix(&self, prefix: &Prefix) -> Vec<u32> {
        let target = *prefix;
        self.routes
            .keys()
            .filter(|(p, _)| *p == target)
            .map(|(_, id)| *id)
            .collect()
    }

    /// Remove all advertised routes.
    pub fn clear(&mut self) {
        self.routes.clear();
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
