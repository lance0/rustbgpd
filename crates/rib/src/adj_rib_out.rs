use std::collections::HashMap;
use std::net::IpAddr;

use rustbgpd_wire::Prefix;

use crate::route::Route;

/// Per-peer Adj-RIB-Out: routes advertised to a specific peer.
///
/// Routes are keyed by `(Prefix, path_id)` for Add-Path (RFC 7911).
/// In single-best mode, `path_id` is always 0.
pub struct AdjRibOut {
    peer: IpAddr,
    routes: HashMap<(Prefix, u32), Route>,
}

impl AdjRibOut {
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

    #[must_use]
    pub fn get(&self, prefix: &Prefix, path_id: u32) -> Option<&Route> {
        self.routes.get(&(*prefix, path_id))
    }

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
}
