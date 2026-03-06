//! Loc-RIB — best-path selection results.
//!
//! Stores the single best route per prefix, selected via `best_path_cmp`.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::IpAddr;

use rustbgpd_wire::{AsPath, FlowSpecRule, Prefix};

use crate::best_path::best_path_cmp;
use crate::route::{FlowSpecRoute, Route};

/// The local RIB storing the best route per prefix.
pub struct LocRib {
    routes: HashMap<Prefix, Route>,
    /// `FlowSpec` Loc-RIB: best route per `FlowSpec` rule.
    flowspec_routes: HashMap<FlowSpecRule, FlowSpecRoute>,
}

impl LocRib {
    /// Create an empty Loc-RIB.
    #[must_use]
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            flowspec_routes: HashMap::new(),
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

    /// Return the number of best routes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Return `true` if no best routes are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Look up the best route for a prefix.
    #[must_use]
    pub fn get(&self, prefix: &Prefix) -> Option<&Route> {
        self.routes.get(prefix)
    }

    // --- FlowSpec methods ---

    /// Recompute the best `FlowSpec` route for a rule from the given candidates.
    ///
    /// Uses the same full BGP preference chain as `flowspec_tiebreak()`.
    /// Returns `true` if the selection changed.
    pub fn recompute_flowspec<'a>(
        &mut self,
        rule: FlowSpecRule,
        candidates: impl Iterator<Item = &'a FlowSpecRoute>,
    ) -> bool {
        let best = candidates.min_by(|a, b| flowspec_tiebreak(a, b)).cloned();
        match best {
            Some(new_best) => {
                let changed = self
                    .flowspec_routes
                    .get(&rule)
                    .is_none_or(|old| old.peer != new_best.peer || old.path_id != new_best.path_id);
                if changed {
                    self.flowspec_routes.insert(rule, new_best);
                }
                changed
            }
            None => self.flowspec_routes.remove(&rule).is_some(),
        }
    }

    /// Look up the best `FlowSpec` route for a rule.
    #[must_use]
    pub fn get_flowspec(&self, rule: &FlowSpecRule) -> Option<&FlowSpecRoute> {
        self.flowspec_routes.get(rule)
    }

    /// Iterate over all best `FlowSpec` routes.
    pub fn iter_flowspec(&self) -> impl Iterator<Item = &FlowSpecRoute> {
        self.flowspec_routes.values()
    }

    /// Return the number of best `FlowSpec` routes.
    #[must_use]
    pub fn flowspec_len(&self) -> usize {
        self.flowspec_routes.len()
    }

    /// Remove the best `FlowSpec` route for a rule. Returns `true` if it existed.
    pub fn remove_flowspec(&mut self, rule: &FlowSpecRule) -> bool {
        self.flowspec_routes.remove(rule).is_some()
    }
}

/// Full BGP best-path comparison for `FlowSpec` routes.
///
/// Uses the same preference chain as unicast `best_path_cmp`:
/// stale → `LOCAL_PREF` → `AS_PATH` length → ORIGIN → MED →
/// eBGP>iBGP → `CLUSTER_LIST` → `ORIGINATOR_ID` → peer address.
///
/// RPKI validation is not applicable to `FlowSpec` routes.
fn flowspec_tiebreak(a: &FlowSpecRoute, b: &FlowSpecRoute) -> Ordering {
    // 0. Non-stale preferred over stale (RFC 4724)
    let cmp = a.is_stale.cmp(&b.is_stale);
    if cmp != Ordering::Equal {
        return cmp;
    }

    // 1. Highest LOCAL_PREF wins → reverse comparison
    let cmp = b.local_pref().cmp(&a.local_pref());
    if cmp != Ordering::Equal {
        return cmp;
    }

    // 2. Shortest AS_PATH
    let a_len = a.as_path().map_or(0, AsPath::len);
    let b_len = b.as_path().map_or(0, AsPath::len);
    let cmp = a_len.cmp(&b_len);
    if cmp != Ordering::Equal {
        return cmp;
    }

    // 3. Lowest ORIGIN (IGP=0 < EGP=1 < Incomplete=2)
    let cmp = a.origin().cmp(&b.origin());
    if cmp != Ordering::Equal {
        return cmp;
    }

    // 4. Lowest MED (always-compare / deterministic)
    let cmp = a.med().cmp(&b.med());
    if cmp != Ordering::Equal {
        return cmp;
    }

    // 5. eBGP over iBGP
    let cmp = b.is_ebgp().cmp(&a.is_ebgp());
    if cmp != Ordering::Equal {
        return cmp;
    }

    // 5.5. Shortest CLUSTER_LIST length (RFC 4456 §9)
    let cmp = a.cluster_list().len().cmp(&b.cluster_list().len());
    if cmp != Ordering::Equal {
        return cmp;
    }

    // 5.6. Lowest ORIGINATOR_ID (RFC 4456 §9) — only when both present
    if let (Some(a_oid), Some(b_oid)) = (a.originator_id(), b.originator_id()) {
        let cmp = a_oid.cmp(&b_oid);
        if cmp != Ordering::Equal {
            return cmp;
        }
    }

    // 6. Lowest peer address (final tiebreaker)
    cmp_ipaddr(&a.peer, &b.peer)
}

/// Compare two `IpAddr` values, treating V4 < V6.
fn cmp_ipaddr(a: &IpAddr, b: &IpAddr) -> std::cmp::Ordering {
    match (a, b) {
        (IpAddr::V4(a4), IpAddr::V4(b4)) => a4.cmp(b4),
        (IpAddr::V6(a6), IpAddr::V6(b6)) => a6.cmp(b6),
        (IpAddr::V4(_), IpAddr::V6(_)) => std::cmp::Ordering::Less,
        (IpAddr::V6(_), IpAddr::V4(_)) => std::cmp::Ordering::Greater,
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

    use rustbgpd_wire::{
        Afi, AsPath, AsPathSegment, FlowSpecComponent, FlowSpecRule, Ipv4Prefix, NumericMatch,
        Origin, PathAttribute,
    };

    use super::*;
    use crate::route::RouteOrigin;

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
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
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

    // --- FlowSpec best-path tests ---

    fn make_flowspec_rule() -> FlowSpecRule {
        FlowSpecRule {
            components: vec![FlowSpecComponent::IpProtocol(vec![NumericMatch {
                end_of_list: true,
                and_bit: false,
                lt: false,
                gt: false,
                eq: true,
                value: 6,
            }])],
        }
    }

    fn make_flowspec_route(
        peer_oct: u8,
        router_id_oct: u8,
        attrs: Vec<PathAttribute>,
        origin_type: RouteOrigin,
    ) -> FlowSpecRoute {
        FlowSpecRoute {
            rule: make_flowspec_rule(),
            afi: Afi::Ipv4,
            peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, peer_oct)),
            attributes: attrs,
            received_at: Instant::now(),
            origin_type,
            peer_router_id: Ipv4Addr::new(1, 1, 1, router_id_oct),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        }
    }

    #[test]
    fn flowspec_higher_local_pref_wins() {
        let rule = make_flowspec_rule();
        let r1 = make_flowspec_route(1, 1, vec![PathAttribute::LocalPref(100)], RouteOrigin::Ibgp);
        let r2 = make_flowspec_route(2, 2, vec![PathAttribute::LocalPref(200)], RouteOrigin::Ibgp);
        let mut loc = LocRib::new();

        loc.recompute_flowspec(rule.clone(), [&r1, &r2].into_iter());
        let best = loc.get_flowspec(&rule).unwrap();
        assert_eq!(best.peer, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn flowspec_shorter_as_path_wins() {
        let rule = make_flowspec_rule();
        let r1 = make_flowspec_route(
            1,
            1,
            vec![
                PathAttribute::LocalPref(100),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65001, 65002, 65003])],
                }),
            ],
            RouteOrigin::Ebgp,
        );
        let r2 = make_flowspec_route(
            2,
            2,
            vec![
                PathAttribute::LocalPref(100),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65001])],
                }),
            ],
            RouteOrigin::Ebgp,
        );
        let mut loc = LocRib::new();

        loc.recompute_flowspec(rule.clone(), [&r1, &r2].into_iter());
        let best = loc.get_flowspec(&rule).unwrap();
        assert_eq!(best.peer, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn flowspec_ebgp_over_ibgp() {
        let rule = make_flowspec_rule();
        let internal =
            make_flowspec_route(1, 1, vec![PathAttribute::LocalPref(100)], RouteOrigin::Ibgp);
        let external =
            make_flowspec_route(2, 2, vec![PathAttribute::LocalPref(100)], RouteOrigin::Ebgp);
        let mut loc = LocRib::new();

        loc.recompute_flowspec(rule.clone(), [&internal, &external].into_iter());
        let best = loc.get_flowspec(&rule).unwrap();
        assert_eq!(best.peer, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn flowspec_stale_demoted() {
        let rule = make_flowspec_rule();
        let mut r_stale =
            make_flowspec_route(1, 1, vec![PathAttribute::LocalPref(200)], RouteOrigin::Ebgp);
        r_stale.is_stale = true;
        let r_fresh =
            make_flowspec_route(2, 2, vec![PathAttribute::LocalPref(100)], RouteOrigin::Ebgp);
        let mut loc = LocRib::new();

        loc.recompute_flowspec(rule.clone(), [&r_stale, &r_fresh].into_iter());
        let best = loc.get_flowspec(&rule).unwrap();
        // Fresh route wins despite lower LOCAL_PREF
        assert_eq!(best.peer, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn flowspec_lowest_med_wins() {
        let rule = make_flowspec_rule();
        let r1 = make_flowspec_route(
            1,
            1,
            vec![PathAttribute::LocalPref(100), PathAttribute::Med(500)],
            RouteOrigin::Ebgp,
        );
        let r2 = make_flowspec_route(
            2,
            2,
            vec![PathAttribute::LocalPref(100), PathAttribute::Med(100)],
            RouteOrigin::Ebgp,
        );
        let mut loc = LocRib::new();

        loc.recompute_flowspec(rule.clone(), [&r1, &r2].into_iter());
        let best = loc.get_flowspec(&rule).unwrap();
        assert_eq!(best.peer, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn flowspec_lowest_peer_tiebreaker() {
        let rule = make_flowspec_rule();
        // All attributes identical, eBGP, same router-id
        let r1 = make_flowspec_route(3, 1, vec![PathAttribute::LocalPref(100)], RouteOrigin::Ebgp);
        let r2 = make_flowspec_route(1, 1, vec![PathAttribute::LocalPref(100)], RouteOrigin::Ebgp);
        let mut loc = LocRib::new();

        loc.recompute_flowspec(rule.clone(), [&r1, &r2].into_iter());
        let best = loc.get_flowspec(&rule).unwrap();
        // Lowest peer IP wins
        assert_eq!(best.peer, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }
}
