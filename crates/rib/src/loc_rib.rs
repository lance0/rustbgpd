//! Loc-RIB — best-path selection results.
//!
//! Stores the single best route per prefix, selected via `best_path_cmp`.

use std::cmp::Ordering;
use std::net::IpAddr;

use rustbgpd_wire::{AsPath, EvpnRouteKey, FlowSpecRule, Prefix};
// FxHash (rustc-hash) on the route-bearing maps — see `adj_rib_in` for the
// rationale (internal keys, faster hasher on the convergence hot path).
// Aliased to the std name so the storage types read unchanged.
use rustc_hash::{FxBuildHasher, FxHashMap as HashMap};

use crate::best_path::best_path_cmp;
use crate::route::{EvpnRibRoute, FlowSpecRoute, Route};

/// The local RIB storing the best route per prefix.
pub struct LocRib {
    routes: HashMap<Prefix, Route>,
    /// `FlowSpec` Loc-RIB: best route per `FlowSpec` rule.
    flowspec_routes: HashMap<FlowSpecRule, FlowSpecRoute>,
    /// EVPN Loc-RIB: best route per RFC 7432 route identity.
    evpn_routes: HashMap<EvpnRouteKey, EvpnRibRoute>,
}

impl LocRib {
    /// Create an empty Loc-RIB.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    /// Create a Loc-RIB with pre-sized capacity for the routes map.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            routes: HashMap::with_capacity_and_hasher(capacity, FxBuildHasher),
            flowspec_routes: HashMap::default(),
            evpn_routes: HashMap::default(),
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

    // --- EVPN methods (RFC 7432) ---

    /// Recompute the best EVPN route for a key from the given candidates.
    ///
    /// Tie-break: Type 2 routes first run the MAC Mobility head (sticky
    /// flag + sequence number per RFC 7432 §15.1); all types then fall
    /// through to the standard BGP chain (`LocalPref` → `AS_PATH` → MED
    /// → eBGP>iBGP → peer address). DF-election hints for Type 1/4 are
    /// left to downstream VTEPs; the RR just reflects.
    ///
    /// Returns `true` if the selection changed.
    pub fn recompute_evpn<'a>(
        &mut self,
        key: EvpnRouteKey,
        candidates: impl Iterator<Item = &'a EvpnRibRoute>,
    ) -> bool {
        let best = candidates
            .min_by(|a, b| evpn_tiebreak_simple(a, b))
            .cloned();
        match best {
            Some(new_best) => {
                // Detect peer switches, GR/LLGR stale flips, AND same-peer
                // payload / attribute churn. A single originator updating a
                // Type 2 route with a new MAC Mobility sequence, sticky
                // flag flip, label/VNI change, Router MAC, ESI Label, or
                // any other attribute change must trigger redistribution —
                // `peer` alone would miss all of these cases.
                let changed = self.evpn_routes.get(&key).is_none_or(|old| {
                    old.peer != new_best.peer
                        || old.is_stale != new_best.is_stale
                        || old.is_llgr_stale != new_best.is_llgr_stale
                        || old.next_hop != new_best.next_hop
                        || old.peer_router_id != new_best.peer_router_id
                        || old.route != new_best.route
                        || old.attributes != new_best.attributes
                });
                if changed {
                    self.evpn_routes.insert(key, new_best);
                }
                changed
            }
            None => self.evpn_routes.remove(&key).is_some(),
        }
    }

    /// Look up the best EVPN route for a key.
    #[must_use]
    pub fn get_evpn(&self, key: &EvpnRouteKey) -> Option<&EvpnRibRoute> {
        self.evpn_routes.get(key)
    }

    /// Iterate over all best EVPN routes.
    pub fn iter_evpn(&self) -> impl Iterator<Item = &EvpnRibRoute> {
        self.evpn_routes.values()
    }

    /// Return the number of best EVPN routes.
    #[must_use]
    pub fn evpn_len(&self) -> usize {
        self.evpn_routes.len()
    }

    /// Remove the best EVPN route for a key. Returns `true` if it existed.
    pub fn remove_evpn(&mut self, key: &EvpnRouteKey) -> bool {
        self.evpn_routes.remove(key).is_some()
    }
}

/// Three-tier stale ranking for EVPN: fresh (0) > GR-stale (1) > LLGR-stale (2).
/// Lower value = more preferred.
fn evpn_stale_rank(route: &EvpnRibRoute) -> u8 {
    if route.is_llgr_stale {
        2
    } else {
        u8::from(route.is_stale)
    }
}

/// BGP-preference + EVPN-aware tie-break for EVPN routes (RFC 7432 §15).
///
/// For Type 2 (MAC/IP Advertisement) routes, runs a MAC Mobility head
/// first: higher sequence number wins, with sticky-MAC preservation —
/// a sticky MAC is not displaced by a non-sticky advertisement even at
/// a higher sequence number. Absence of the MAC Mobility community is
/// treated as sequence=0, sticky=false per RFC 7432 §7.7.
///
/// All route types then fall through to the standard BGP chain, matching
/// unicast `best_path_cmp` and `flowspec_tiebreak`:
/// stale → `LocalPref` → `AS_PATH` length → ORIGIN → MED →
/// eBGP > iBGP → `CLUSTER_LIST` length → `ORIGINATOR_ID` → peer address.
fn evpn_tiebreak_simple(a: &EvpnRibRoute, b: &EvpnRibRoute) -> Ordering {
    // 0. Three-tier freshness: fresh (0) > GR-stale (1) > LLGR-stale (2)
    //    per RFC 4724 §4.2 / RFC 9494 §4.7. LLGR promotion clears
    //    `is_stale` and sets `is_llgr_stale` (see AdjRibIn::promote_evpn_to_llgr_stale),
    //    so a single rank function avoids the inversion that two independent
    //    bool comparisons would cause when the bools are not nested.
    //
    //    Runs BEFORE the Type 2 MAC Mobility head — otherwise a stale route
    //    with a higher MAC Mobility sequence (or sticky bit) would beat a
    //    fresh alternative inside the head and skip this check entirely.
    match evpn_stale_rank(a).cmp(&evpn_stale_rank(b)) {
        Ordering::Equal => {}
        other => return other,
    }

    // Type-specific head for Type 2 (MAC/IP): MAC Mobility sequence + sticky.
    if a.route_type() == 2 && b.route_type() == 2 {
        let (a_sticky, a_seq) = extract_mac_mobility(a);
        let (b_sticky, b_seq) = extract_mac_mobility(b);
        // Sticky protects against displacement by non-sticky. If one is
        // sticky and the other isn't, the sticky wins regardless of seq.
        match (a_sticky, b_sticky) {
            (true, false) => return Ordering::Less,
            (false, true) => return Ordering::Greater,
            _ => {}
        }
        // Higher sequence wins — reverse for `min_by`.
        match b_seq.cmp(&a_seq) {
            Ordering::Equal => {}
            other => return other,
        }
    }

    // 1. Higher LocalPref is better — reverse for `min_by`.
    match b.local_pref().cmp(&a.local_pref()) {
        Ordering::Equal => {}
        other => return other,
    }
    // 2. Shorter AS_PATH is better.
    let a_len = a.as_path().map_or(0, AsPath::len);
    let b_len = b.as_path().map_or(0, AsPath::len);
    match a_len.cmp(&b_len) {
        Ordering::Equal => {}
        other => return other,
    }
    // 3. Lowest ORIGIN (IGP=0 < EGP=1 < Incomplete=2).
    match a.origin().cmp(&b.origin()) {
        Ordering::Equal => {}
        other => return other,
    }
    // 4. Lower MED is better.
    match a.med().cmp(&b.med()) {
        Ordering::Equal => {}
        other => return other,
    }
    // 5. eBGP preferred over iBGP.
    match (a.is_ebgp(), b.is_ebgp()) {
        (true, false) => return Ordering::Less,
        (false, true) => return Ordering::Greater,
        _ => {}
    }
    // 6. Shorter CLUSTER_LIST wins (RFC 4456 §9).
    match a.cluster_list().len().cmp(&b.cluster_list().len()) {
        Ordering::Equal => {}
        other => return other,
    }
    // 7. Lower ORIGINATOR_ID wins (falls back to peer router-id, RFC 4456 §9).
    let a_oid = a.originator_id().unwrap_or(a.peer_router_id);
    let b_oid = b.originator_id().unwrap_or(b.peer_router_id);
    match a_oid.cmp(&b_oid) {
        Ordering::Equal => {}
        other => return other,
    }
    // 8. Final tiebreak: lower peer address wins (deterministic).
    a.peer.cmp(&b.peer)
}

/// Extract `(sticky, sequence_number)` from the MAC Mobility extended
/// community, if present. Absent community → `(false, 0)` per RFC 7432 §7.7.
fn extract_mac_mobility(route: &EvpnRibRoute) -> (bool, u32) {
    for ec in route.extended_communities() {
        if let Some((sticky, seq)) = ec.as_mac_mobility() {
            return (sticky, seq);
        }
    }
    (false, 0)
}

/// Three-tier stale ranking for `FlowSpec`: fresh (0) > GR-stale (1) > LLGR-stale (2).
/// Lower value = more preferred. Same shape as `evpn_stale_rank` and
/// unicast `best_path::stale_rank` — separate `is_stale` / `is_llgr_stale`
/// comparisons would invert because LLGR promotion clears `is_stale`.
fn flowspec_stale_rank(route: &FlowSpecRoute) -> u8 {
    if route.is_llgr_stale {
        2
    } else {
        u8::from(route.is_stale)
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
    // 0. Three-tier freshness: fresh > GR-stale > LLGR-stale
    //    (RFC 4724 §4.2 / RFC 9494 §4.7).
    let cmp = flowspec_stale_rank(a).cmp(&flowspec_stale_rank(b));
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
    use std::sync::Arc;
    use std::time::Instant;

    use rustbgpd_wire::{
        Afi, AsPath, AsPathSegment, ExtendedCommunity, FlowSpecComponent, FlowSpecRule, Ipv4Prefix,
        NumericMatch, Origin, PathAttribute,
    };

    use super::*;
    use crate::route::RouteOrigin;

    fn make_route(peer_oct: u8, prefix: Ipv4Prefix, local_pref: u32) -> Route {
        let peer = Ipv4Addr::new(10, 0, 0, peer_oct);
        Route {
            prefix: Prefix::V4(prefix),
            next_hop: IpAddr::V4(peer),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: IpAddr::V4(peer),
            attributes: Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65001])],
                }),
                PathAttribute::LocalPref(local_pref),
            ]),
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        }
    }

    #[test]
    fn route_link_bandwidth_accessor() {
        let v4 = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let mut route = make_route(1, v4, 100);

        // No extended communities → no link bandwidth.
        assert!(route.link_bandwidth().is_none());

        // A Link Bandwidth community surfaces its bandwidth (bytes/second);
        // an unrelated Route Target sitting alongside it is ignored.
        let rt = ExtendedCommunity::new(u64::from_be_bytes([0x00, 0x02, 0xFD, 0xE9, 0, 0, 0, 100]));
        let lb = ExtendedCommunity::link_bandwidth(65001, 1.25e9_f32);
        Arc::make_mut(&mut route.attributes).push(PathAttribute::ExtendedCommunities(vec![rt, lb]));

        let bw = route.link_bandwidth().expect("link bandwidth present");
        // Exact round-trip through IEEE-754 bytes — assert bitwise equality.
        assert_eq!(bw.to_bits(), 1.25e9_f32.to_bits());
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

    /// Regression: GR-stale outranks LLGR-stale (RFC 9494 §4.7), and
    /// LLGR-stale must not beat fresh — even with higher `LocalPref`.
    /// Mirrors EVPN promotion state: GR-stale carries
    /// `is_stale=true, is_llgr_stale=false`; LLGR-stale carries
    /// `is_stale=false, is_llgr_stale=true`. Two independent boolean
    /// comparisons would invert this; the single rank function
    /// gives the correct three-tier ordering.
    #[test]
    fn flowspec_gr_stale_beats_llgr_stale() {
        let rule = make_flowspec_rule();
        // GR-stale at LP=100 vs LLGR-stale at LP=200 → GR-stale must win.
        let mut gr =
            make_flowspec_route(1, 1, vec![PathAttribute::LocalPref(100)], RouteOrigin::Ebgp);
        gr.is_stale = true;
        gr.is_llgr_stale = false;
        let mut llgr =
            make_flowspec_route(2, 2, vec![PathAttribute::LocalPref(200)], RouteOrigin::Ebgp);
        llgr.is_stale = false;
        llgr.is_llgr_stale = true;
        let mut loc = LocRib::new();
        loc.recompute_flowspec(rule.clone(), [&gr, &llgr].into_iter());
        assert_eq!(
            loc.get_flowspec(&rule).unwrap().peer,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "GR-stale must outrank LLGR-stale"
        );
    }

    #[test]
    fn flowspec_fresh_beats_llgr_stale_with_higher_localpref() {
        let rule = make_flowspec_rule();
        let fresh =
            make_flowspec_route(1, 1, vec![PathAttribute::LocalPref(50)], RouteOrigin::Ebgp);
        let mut llgr =
            make_flowspec_route(2, 2, vec![PathAttribute::LocalPref(500)], RouteOrigin::Ebgp);
        llgr.is_stale = false;
        llgr.is_llgr_stale = true;
        let mut loc = LocRib::new();
        loc.recompute_flowspec(rule.clone(), [&fresh, &llgr].into_iter());
        assert_eq!(
            loc.get_flowspec(&rule).unwrap().peer,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "fresh must outrank LLGR-stale even with lower LocalPref"
        );
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

    // ---- EVPN MAC mobility tie-break tests (RFC 7432 §15.1) ------------

    fn make_evpn_type2(peer_oct: u8, extra_attrs: Vec<PathAttribute>) -> EvpnRibRoute {
        use rustbgpd_wire::{
            EthernetTagId, EvpnMacIp, EvpnRoute, MacAddress, MplsLabel, RouteDistinguisher,
        };
        let peer = Ipv4Addr::new(10, 0, 0, peer_oct);
        let mac_ip = EvpnRoute::MacIp(EvpnMacIp {
            rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 100]),
            esi: rustbgpd_wire::EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(100),
            mac: MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            ip: None,
            label1: MplsLabel::new(10_000),
            label2: None,
        });
        let mut attrs: Vec<PathAttribute> = vec![PathAttribute::LocalPref(100)];
        attrs.extend(extra_attrs);
        EvpnRibRoute {
            route: mac_ip,
            next_hop: IpAddr::V4(peer),
            link_local_next_hop: None,
            peer: IpAddr::V4(peer),
            attributes: Arc::new(attrs),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ibgp,
            peer_router_id: peer,
            is_stale: false,
            is_llgr_stale: false,
        }
    }

    #[test]
    fn evpn_mac_mobility_higher_sequence_wins() {
        let mm_low = PathAttribute::ExtendedCommunities(vec![
            rustbgpd_wire::ExtendedCommunity::mac_mobility(false, 1),
        ]);
        let mm_high = PathAttribute::ExtendedCommunities(vec![
            rustbgpd_wire::ExtendedCommunity::mac_mobility(false, 10),
        ]);
        let r_low = make_evpn_type2(2, vec![mm_low]);
        let r_high = make_evpn_type2(3, vec![mm_high]);
        assert_eq!(evpn_tiebreak_simple(&r_high, &r_low), Ordering::Less);
        assert_eq!(evpn_tiebreak_simple(&r_low, &r_high), Ordering::Greater);
    }

    #[test]
    fn evpn_mac_mobility_sticky_preserved_against_higher_non_sticky() {
        let sticky = PathAttribute::ExtendedCommunities(vec![
            rustbgpd_wire::ExtendedCommunity::mac_mobility(true, 1),
        ]);
        let non_sticky_high = PathAttribute::ExtendedCommunities(vec![
            rustbgpd_wire::ExtendedCommunity::mac_mobility(false, 99),
        ]);
        let r_sticky = make_evpn_type2(2, vec![sticky]);
        let r_non_sticky = make_evpn_type2(3, vec![non_sticky_high]);
        // Sticky wins even with a lower sequence.
        assert_eq!(
            evpn_tiebreak_simple(&r_sticky, &r_non_sticky),
            Ordering::Less
        );
    }

    #[test]
    fn evpn_mac_mobility_missing_treated_as_seq_zero() {
        // No MAC Mobility community = implicit (false, 0).
        let r_no = make_evpn_type2(2, vec![]);
        let mm = PathAttribute::ExtendedCommunities(vec![
            rustbgpd_wire::ExtendedCommunity::mac_mobility(false, 5),
        ]);
        let r_mm = make_evpn_type2(3, vec![mm]);
        assert_eq!(evpn_tiebreak_simple(&r_mm, &r_no), Ordering::Less);
    }

    /// Regression: `recompute_evpn` must report change when the same
    /// originating peer re-advertises the same key with a different
    /// MAC Mobility sequence. Previously only `peer` and stale flags were
    /// compared, so same-peer attribute churn was silently swallowed at
    /// the Loc-RIB layer and never redistributed.
    #[test]
    fn evpn_same_peer_mac_mobility_bump_triggers_change() {
        let mm1 = PathAttribute::ExtendedCommunities(vec![
            rustbgpd_wire::ExtendedCommunity::mac_mobility(false, 1),
        ]);
        let mm2 = PathAttribute::ExtendedCommunities(vec![
            rustbgpd_wire::ExtendedCommunity::mac_mobility(false, 2),
        ]);
        let r1 = make_evpn_type2(2, vec![mm1]);
        let r2 = make_evpn_type2(2, vec![mm2]);
        let key = r1.key();

        let mut loc = LocRib::new();
        // First install — that's always a change.
        assert!(loc.recompute_evpn(key, [&r1].into_iter()));
        // Same peer, bumped sequence — must also report a change.
        assert!(
            loc.recompute_evpn(key, [&r2].into_iter()),
            "same-peer MAC Mobility sequence bump must be detected"
        );
        // Same input again — no change.
        assert!(!loc.recompute_evpn(key, [&r2].into_iter()));
    }

    /// Regression: a GR-stale EVPN route must NOT beat a fresh alternative
    /// on local-pref or `AS_PATH`. Prior to the fix the EVPN tie-break ran
    /// `LocalPref` first without consulting `is_stale`, so a stale route
    /// with pref=200 would displace a fresh pref=100 — exactly backwards
    /// from the RFC 4724 intent.
    #[test]
    fn evpn_fresh_beats_stale_even_with_lower_localpref() {
        let mut fresh = make_evpn_type2(2, vec![PathAttribute::LocalPref(100)]);
        let mut stale = make_evpn_type2(3, vec![PathAttribute::LocalPref(200)]);
        fresh.is_stale = false;
        stale.is_stale = true;
        assert_eq!(evpn_tiebreak_simple(&fresh, &stale), Ordering::Less);
        assert_eq!(evpn_tiebreak_simple(&stale, &fresh), Ordering::Greater);
    }

    /// Regression: GR-stale outranks LLGR-stale (RFC 9494 §4.7).
    ///
    /// Mirrors the production state set by
    /// `AdjRibIn::promote_evpn_to_llgr_stale`: GR-stale routes carry
    /// `is_stale=true, is_llgr_stale=false`; LLGR-stale routes carry
    /// `is_stale=false, is_llgr_stale=true`. Two independent boolean
    /// comparisons would invert this ordering — both routes were
    /// previously checked sequentially and `is_stale` short-circuited
    /// the wrong way for LLGR. The single `evpn_stale_rank` function
    /// gives the correct three-tier ordering.
    #[test]
    fn evpn_gr_stale_beats_llgr_stale() {
        // LLGR-stale carries higher LocalPref to prove rank, not LP, decides.
        let mut gr = make_evpn_type2(2, vec![PathAttribute::LocalPref(100)]);
        let mut llgr = make_evpn_type2(3, vec![PathAttribute::LocalPref(200)]);
        gr.is_stale = true;
        gr.is_llgr_stale = false;
        llgr.is_stale = false;
        llgr.is_llgr_stale = true;
        assert_eq!(
            evpn_tiebreak_simple(&gr, &llgr),
            Ordering::Less,
            "GR-stale must outrank LLGR-stale"
        );
        assert_eq!(
            evpn_tiebreak_simple(&llgr, &gr),
            Ordering::Greater,
            "LLGR-stale must rank below GR-stale"
        );
    }

    /// Regression: a fresh route with low `LocalPref` still beats
    /// LLGR-stale with high `LocalPref`. The freshness check must run
    /// before the BGP preference chain.
    #[test]
    fn evpn_fresh_beats_llgr_stale_even_with_lower_localpref() {
        let mut fresh = make_evpn_type2(2, vec![PathAttribute::LocalPref(50)]);
        let mut llgr = make_evpn_type2(3, vec![PathAttribute::LocalPref(500)]);
        fresh.is_stale = false;
        fresh.is_llgr_stale = false;
        llgr.is_stale = false;
        llgr.is_llgr_stale = true;
        assert_eq!(evpn_tiebreak_simple(&fresh, &llgr), Ordering::Less);
    }

    /// Regression: a GR-stale Type 2 route with a HIGHER MAC Mobility
    /// sequence must still lose to a fresh non-stale alternative. Prior
    /// to the fix the Type 2 head returned on the sequence comparison
    /// before the stale check fired, so any MAC that had ever moved
    /// (i.e. carried a MAC Mobility ext-community) would let staleness
    /// win during the GR window — exactly opposite to RFC 4724 §4.2.
    #[test]
    fn evpn_fresh_beats_stale_with_higher_mac_mobility_sequence() {
        let stale_high = PathAttribute::ExtendedCommunities(vec![
            rustbgpd_wire::ExtendedCommunity::mac_mobility(false, 100),
        ]);
        let fresh_low = PathAttribute::ExtendedCommunities(vec![
            rustbgpd_wire::ExtendedCommunity::mac_mobility(false, 5),
        ]);
        let mut stale = make_evpn_type2(2, vec![stale_high]);
        let mut fresh = make_evpn_type2(3, vec![fresh_low]);
        stale.is_stale = true;
        fresh.is_stale = false;
        assert_eq!(evpn_tiebreak_simple(&fresh, &stale), Ordering::Less);
        assert_eq!(evpn_tiebreak_simple(&stale, &fresh), Ordering::Greater);
    }

    /// Regression: a stale sticky Type 2 route must still lose to a
    /// fresh non-sticky alternative. Same root cause as the sequence
    /// case — the sticky branch in the Type 2 head was returning
    /// before the stale check ran.
    #[test]
    fn evpn_fresh_non_sticky_beats_stale_sticky() {
        let stale_sticky = PathAttribute::ExtendedCommunities(vec![
            rustbgpd_wire::ExtendedCommunity::mac_mobility(true, 1),
        ]);
        let fresh_non_sticky = PathAttribute::ExtendedCommunities(vec![
            rustbgpd_wire::ExtendedCommunity::mac_mobility(false, 1),
        ]);
        let mut stale = make_evpn_type2(2, vec![stale_sticky]);
        let mut fresh = make_evpn_type2(3, vec![fresh_non_sticky]);
        stale.is_stale = true;
        fresh.is_stale = false;
        assert_eq!(evpn_tiebreak_simple(&fresh, &stale), Ordering::Less);
    }

    /// Regression: among otherwise-equal candidates, shorter `CLUSTER_LIST`
    /// wins (RFC 4456 §9). Previously the chain stopped at eBGP-vs-iBGP
    /// and went straight to peer-address.
    #[test]
    fn evpn_shorter_cluster_list_wins() {
        let short = make_evpn_type2(
            2,
            vec![PathAttribute::ClusterList(vec![Ipv4Addr::new(
                10, 0, 0, 100,
            )])],
        );
        let long = make_evpn_type2(
            3,
            vec![PathAttribute::ClusterList(vec![
                Ipv4Addr::new(10, 0, 0, 100),
                Ipv4Addr::new(10, 0, 0, 200),
            ])],
        );
        assert_eq!(evpn_tiebreak_simple(&short, &long), Ordering::Less);
    }

    /// Regression: lower `ORIGINATOR_ID` breaks ties before peer address.
    #[test]
    fn evpn_lower_originator_id_wins() {
        let a = make_evpn_type2(
            2,
            vec![PathAttribute::OriginatorId(Ipv4Addr::new(10, 0, 0, 50))],
        );
        let b = make_evpn_type2(
            3,
            vec![PathAttribute::OriginatorId(Ipv4Addr::new(10, 0, 0, 150))],
        );
        assert_eq!(evpn_tiebreak_simple(&a, &b), Ordering::Less);
    }

    /// Regression: same-peer payload change (e.g. VNI / `label1` update)
    /// must trigger redistribution. Previously only peer + stale flags
    /// were compared at the Loc-RIB layer.
    #[test]
    fn evpn_same_peer_label_change_triggers_change() {
        use rustbgpd_wire::{
            EthernetTagId, EvpnMacIp, EvpnRoute, MacAddress, MplsLabel, RouteDistinguisher,
        };

        fn make_with_label(vni: u32) -> EvpnRibRoute {
            let peer = Ipv4Addr::new(10, 0, 0, 2);
            let mac_ip = EvpnRoute::MacIp(EvpnMacIp {
                rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 100]),
                esi: rustbgpd_wire::EthernetSegmentIdentifier::ZERO,
                ethernet_tag: EthernetTagId(100),
                mac: MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                ip: None,
                label1: MplsLabel::new(vni),
                label2: None,
            });
            EvpnRibRoute {
                route: mac_ip,
                next_hop: IpAddr::V4(peer),
                link_local_next_hop: None,
                peer: IpAddr::V4(peer),
                attributes: Arc::new(vec![PathAttribute::LocalPref(100)]),
                received_at: Instant::now(),
                origin_type: RouteOrigin::Ibgp,
                peer_router_id: peer,
                is_stale: false,
                is_llgr_stale: false,
            }
        }

        let r1 = make_with_label(10_000);
        let r2 = make_with_label(20_000);
        let key = r1.key();
        let mut loc = LocRib::new();
        assert!(loc.recompute_evpn(key, [&r1].into_iter()));
        assert!(
            loc.recompute_evpn(key, [&r2].into_iter()),
            "same-peer VNI change must be detected"
        );
    }
}
