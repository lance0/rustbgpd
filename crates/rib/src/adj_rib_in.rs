use std::collections::HashMap;
use std::net::IpAddr;

use rustbgpd_wire::Ipv4Prefix;

use crate::route::Route;

/// Per-peer Adj-RIB-In: stores the routes received from a single peer.
#[derive(Debug)]
pub struct AdjRibIn {
    peer: IpAddr,
    routes: HashMap<Ipv4Prefix, Route>,
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
        self.routes.insert(route.prefix, route);
    }

    pub fn withdraw(&mut self, prefix: &Ipv4Prefix) -> bool {
        self.routes.remove(prefix).is_some()
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

    #[must_use]
    pub fn get(&self, prefix: &Ipv4Prefix) -> Option<&Route> {
        self.routes.get(prefix)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    use super::*;

    fn make_route(prefix: Ipv4Prefix, next_hop: Ipv4Addr) -> Route {
        Route {
            prefix,
            next_hop,
            peer: IpAddr::V4(next_hop),
            attributes: vec![],
            received_at: Instant::now(),
            is_ebgp: true,
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
        assert!(rib.get(&prefix).is_some());
    }

    #[test]
    fn withdraw_returns_true_if_present() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        rib.insert(make_route(prefix, Ipv4Addr::new(10, 0, 0, 1)));

        assert!(rib.withdraw(&prefix));
        assert_eq!(rib.len(), 0);
    }

    #[test]
    fn withdraw_returns_false_if_absent() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        assert!(!rib.withdraw(&prefix));
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
    fn insert_replaces_existing() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        rib.insert(make_route(prefix, Ipv4Addr::new(10, 0, 0, 1)));
        rib.insert(make_route(prefix, Ipv4Addr::new(10, 0, 0, 2)));

        assert_eq!(rib.len(), 1);
        assert_eq!(
            rib.get(&prefix).unwrap().next_hop,
            Ipv4Addr::new(10, 0, 0, 2)
        );
    }
}
