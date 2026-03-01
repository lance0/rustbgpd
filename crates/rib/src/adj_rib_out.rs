use std::collections::HashMap;
use std::net::IpAddr;

use rustbgpd_wire::Prefix;

use crate::route::Route;

/// Per-peer Adj-RIB-Out: routes advertised to a specific peer.
pub struct AdjRibOut {
    peer: IpAddr,
    routes: HashMap<Prefix, Route>,
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
        self.routes.insert(route.prefix, route);
    }

    pub fn withdraw(&mut self, prefix: &Prefix) -> bool {
        self.routes.remove(prefix).is_some()
    }

    #[must_use]
    pub fn get(&self, prefix: &Prefix) -> Option<&Route> {
        self.routes.get(prefix)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Route> {
        self.routes.values()
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
