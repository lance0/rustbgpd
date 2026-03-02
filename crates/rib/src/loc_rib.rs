//! Loc-RIB — best-path selection results.
//!
//! Stores the single best route per prefix, selected via `best_path_cmp`.

use std::collections::HashMap;

use rustbgpd_wire::Prefix;

use crate::best_path::best_path_cmp;
use crate::route::Route;

/// The local RIB storing the best route per prefix.
pub struct LocRib {
    routes: HashMap<Prefix, Route>,
}

impl LocRib {
    #[must_use]
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    /// Recompute the best route for `prefix` from the given candidates.
    ///
    /// Returns `true` if the best route changed (installed, updated, or removed).
    pub fn recompute<'a>(
        &mut self,
        prefix: Prefix,
        candidates: impl Iterator<Item = &'a Route>,
    ) -> bool {
        let best = candidates.min_by(|a, b| best_path_cmp(a, b)).cloned();

        match best {
            Some(new_best) => {
                let changed = self
                    .routes
                    .get(&prefix)
                    .is_none_or(|old| best_path_cmp(old, &new_best) != std::cmp::Ordering::Equal);
                if changed {
                    self.routes.insert(prefix, new_best);
                }
                changed
            }
            None => self.routes.remove(&prefix).is_some(),
        }
    }

    /// Iterate over all best routes.
    pub fn iter(&self) -> impl Iterator<Item = &Route> {
        self.routes.values()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    #[must_use]
    pub fn get(&self, prefix: &Prefix) -> Option<&Route> {
        self.routes.get(prefix)
    }
}

impl Default for LocRib {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    use rustbgpd_wire::{AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute};

    use super::*;

    fn make_route(peer_oct: u8, prefix: Ipv4Prefix, local_pref: u32) -> Route {
        let peer = Ipv4Addr::new(10, 0, 0, peer_oct);
        Route {
            prefix: Prefix::V4(prefix),
            next_hop: IpAddr::V4(peer),
            peer: IpAddr::V4(peer),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65001])],
                }),
                PathAttribute::LocalPref(local_pref),
            ],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ebgp,
            is_stale: false,
        }
    }

    #[test]
    fn single_candidate_installed() {
        let v4 = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let prefix = Prefix::V4(v4);
        let route = make_route(1, v4, 100);
        let mut loc = LocRib::new();

        assert!(loc.recompute(prefix, [&route].into_iter()));
        assert_eq!(loc.len(), 1);
        assert_eq!(
            loc.get(&prefix).unwrap().peer,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn better_route_replaces() {
        let v4 = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let prefix = Prefix::V4(v4);
        let route_a = make_route(1, v4, 100);
        let route_b = make_route(2, v4, 200);
        let mut loc = LocRib::new();

        loc.recompute(prefix, [&route_a].into_iter());
        assert!(loc.recompute(prefix, [&route_a, &route_b].into_iter()));
        assert_eq!(
            loc.get(&prefix).unwrap().peer,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn withdraw_removes() {
        let v4 = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let prefix = Prefix::V4(v4);
        let route = make_route(1, v4, 100);
        let mut loc = LocRib::new();

        loc.recompute(prefix, [&route].into_iter());
        let empty: Vec<&Route> = vec![];
        assert!(loc.recompute(prefix, empty.into_iter()));
        assert!(loc.is_empty());
    }

    #[test]
    fn unchanged_returns_false() {
        let v4 = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let prefix = Prefix::V4(v4);
        let route = make_route(1, v4, 100);
        let mut loc = LocRib::new();

        loc.recompute(prefix, [&route].into_iter());
        assert!(!loc.recompute(prefix, [&route].into_iter()));
    }

    #[test]
    fn multi_candidate_picks_winner() {
        let v4 = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let prefix = Prefix::V4(v4);
        let r1 = make_route(1, v4, 100);
        let r2 = make_route(2, v4, 200);
        let r3 = make_route(3, v4, 150);
        let mut loc = LocRib::new();

        loc.recompute(prefix, [&r1, &r2, &r3].into_iter());
        // r2 has highest local_pref (200)
        assert_eq!(
            loc.get(&prefix).unwrap().peer,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }
}
