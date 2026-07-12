//! Loc-RIB — best-path selection results.
//!
//! Stores the single best route per prefix, selected via `best_path_cmp`.

use std::cmp::Ordering;
use std::net::IpAddr;
use std::time::SystemTime;

use rustbgpd_wire::{AsPath, EvpnRouteKey, Origin, PathAttribute, Prefix};
// FxHash (rustc-hash) on the route-bearing maps — see `adj_rib_in` for the
// rationale (internal keys, faster hasher on the convergence hot path).
// Aliased to the std name so the storage types read unchanged.
use rustc_hash::{FxBuildHasher, FxHashMap as HashMap};

use crate::best_path::best_path_cmp;
use crate::route::{
    BgpLsRibRoute, BgpLsRouteKey, EvpnRibRoute, FlowSpecKey, FlowSpecRoute, LabeledRibRoute, Route,
    RtcRibRoute, RtcRibRouteKey, VpnRibRoute,
};

/// The local RIB storing the best route per prefix.
pub struct LocRib {
    /// Best route per prefix, paired with its wall-clock install time —
    /// captured when the best last changed. The RFC 9069 BMP dump path
    /// reads the stored stamp (not a reconstruction from the monotonic
    /// clock), so an NTP step between install and dump cannot skew the
    /// per-peer header timestamp (LAN-193).
    ///
    /// Deliberately NOT slab-backed (LAN-335): this map keeps its route
    /// bodies inline. Both compact-storage candidates were measured and
    /// rejected on this lookup-hot recompute path — the prefix trie
    /// regressed it (see `prefix_map`), and a `u32` slab handle regressed
    /// `loc_rib_recompute/1` by ~14% (extra indirection + a second probe
    /// per hit) for only ~4 MiB of the ~19 MiB the Adj-RIB slab conversion
    /// saved at the 2p×100k profile shape.
    routes: HashMap<Prefix, (Route, SystemTime)>,
    /// `FlowSpec` Loc-RIB: best route per `FlowSpec` rule.
    flowspec_routes: HashMap<FlowSpecKey, FlowSpecRoute>,
    /// EVPN Loc-RIB: best route per RFC 7432 route identity.
    evpn_routes: HashMap<EvpnRouteKey, EvpnRibRoute>,
    /// BGP-LS Loc-RIB: best route per opaque RFC 9552 identity.
    bgpls_routes: HashMap<BgpLsRouteKey, BgpLsRibRoute>,
    /// VPNv4/VPNv6 Loc-RIB: best route per RFC 4364 RD + prefix identity.
    /// Selected VPN routes keyed by RD+prefix identity alone: Loc-RIB best
    /// selection collapses Add-Path path IDs — the winning route's own
    /// `path_id` records which received path won. Paired with the
    /// wall-clock install time, like `routes`.
    vpn_routes: HashMap<rustbgpd_wire::VpnRouteKey, (VpnRibRoute, SystemTime)>,
    /// Labeled-unicast Loc-RIB: best route per prefix identity, collapsing
    /// Add-Path path IDs like `vpn_routes` — the winning route's own
    /// `path_id` records which received path won. Deliberately separate from
    /// the unicast `routes` map (ADR-0077 §2).
    labeled_routes: HashMap<Prefix, LabeledRibRoute>,
    /// RT-Constrain Loc-RIB: best route per RFC 4684 RT membership identity.
    rtc_routes: HashMap<RtcRibRouteKey, RtcRibRoute>,
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
            bgpls_routes: HashMap::default(),
            vpn_routes: HashMap::default(),
            labeled_routes: HashMap::default(),
            rtc_routes: HashMap::default(),
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
                // Detect preference-relevant changes AND same-peer payload
                // churn. `best_path_cmp` compares only the fields that drive
                // selection and tiebreaks on the peer address, so the same
                // peer re-advertising the prefix with a new next-hop or
                // changed attributes (communities, equal-length AS_PATH
                // content, ...) would compare Equal and the stale payload
                // would never be redistributed to single-best downstream
                // peers or FIB install candidates. Mirrors the
                // `recompute_evpn` payload comparison below.
                let changed = self.routes.get(&prefix).is_none_or(|(old, _)| {
                    best_path_cmp(old, &new_best) != std::cmp::Ordering::Equal
                        || old.next_hop != new_best.next_hop
                        || old.link_local_next_hop != new_best.link_local_next_hop
                        || old.next_hop_scope != new_best.next_hop_scope
                        || old.path_id != new_best.path_id
                        || old.peer_router_id != new_best.peer_router_id
                        || old.attributes != new_best.attributes
                });
                if changed {
                    self.routes.insert(prefix, (new_best, SystemTime::now()));
                }
                changed
            }
            None => self.routes.remove(&prefix).is_some(),
        }
    }

    /// Iterate over all best routes.
    pub fn iter(&self) -> impl Iterator<Item = &Route> {
        self.routes.values().map(|(route, _)| route)
    }

    /// Return the number of best routes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Return the backing capacity of the unicast best-path map.
    ///
    /// Exposed only to benchmark / memory-profile harnesses so they can
    /// distinguish route-count growth from hash-table capacity cliffs.
    #[cfg(feature = "bench-internals")]
    #[must_use]
    pub fn bench_route_capacity(&self) -> usize {
        self.routes.capacity()
    }

    /// Return `true` if no best routes are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Look up the best route for a prefix.
    #[must_use]
    pub fn get(&self, prefix: &Prefix) -> Option<&Route> {
        self.routes.get(prefix).map(|(route, _)| route)
    }

    /// Look up the best route for a prefix together with its
    /// wall-clock Loc-RIB install time (RFC 9069 per-peer header
    /// timestamp for the BMP dump path).
    #[must_use]
    pub fn get_with_install_time(&self, prefix: &Prefix) -> Option<(&Route, SystemTime)> {
        self.routes
            .get(prefix)
            .map(|(route, installed_at)| (route, *installed_at))
    }

    /// Wall-clock install time of the current best for `prefix`,
    /// captured when the best last changed.
    #[must_use]
    pub fn install_time(&self, prefix: &Prefix) -> Option<SystemTime> {
        self.routes
            .get(prefix)
            .map(|(_, installed_at)| *installed_at)
    }

    // --- FlowSpec methods ---

    /// Recompute the best `FlowSpec` route for a rule from the given candidates.
    ///
    /// Uses the same full BGP preference chain as `flowspec_tiebreak()`.
    /// Returns `true` if the selection changed.
    pub fn recompute_flowspec<'a>(
        &mut self,
        key: FlowSpecKey,
        candidates: impl Iterator<Item = &'a FlowSpecRoute>,
    ) -> bool {
        let best = candidates.min_by(|a, b| flowspec_tiebreak(a, b)).cloned();
        match best {
            Some(new_best) => {
                // Same-peer attribute churn must count as change: a FlowSpec
                // action lives in the extended communities (rate-limit,
                // redirect, ...), so a peer updating only the action keeps
                // `peer`/`path_id` identical. Comparing those two alone
                // would silently swallow the new action. Mirrors the
                // `recompute_evpn` payload comparison below.
                let changed = self.flowspec_routes.get(&key).is_none_or(|old| {
                    old.peer != new_best.peer
                        || old.path_id != new_best.path_id
                        || old.is_stale != new_best.is_stale
                        || old.is_llgr_stale != new_best.is_llgr_stale
                        || old.peer_router_id != new_best.peer_router_id
                        || old.attributes != new_best.attributes
                });
                if changed {
                    self.flowspec_routes.insert(key, new_best);
                }
                changed
            }
            None => self.flowspec_routes.remove(&key).is_some(),
        }
    }

    /// Look up the best `FlowSpec` route for a rule.
    #[must_use]
    pub fn get_flowspec(&self, key: &FlowSpecKey) -> Option<&FlowSpecRoute> {
        self.flowspec_routes.get(key)
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
    pub fn remove_flowspec(&mut self, key: &FlowSpecKey) -> bool {
        self.flowspec_routes.remove(key).is_some()
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

    // --- BGP-LS methods (RFC 9552) ---

    /// Recompute the selected BGP-LS route for a key from the given candidates.
    ///
    /// Uses the same family-agnostic BGP preference chain as `FlowSpec`: stale
    /// rank, `LOCAL_PREF`, `AS_PATH`, `ORIGIN`, MED, eBGP/iBGP, cluster length,
    /// originator ID, then peer address. The opaque BGP-LS NLRI identity remains
    /// the map key and is not parsed for selection.
    pub fn recompute_bgpls<'a>(
        &mut self,
        key: BgpLsRouteKey,
        candidates: impl Iterator<Item = &'a BgpLsRibRoute>,
    ) -> bool {
        let best = candidates.min_by(|a, b| bgpls_tiebreak(a, b)).cloned();
        match best {
            Some(new_best) => {
                let changed = self.bgpls_routes.get(&key).is_none_or(|old| {
                    old.peer != new_best.peer
                        || old.path_id != new_best.path_id
                        || old.is_stale != new_best.is_stale
                        || old.is_llgr_stale != new_best.is_llgr_stale
                        || old.next_hop != new_best.next_hop
                        || old.peer_router_id != new_best.peer_router_id
                        || old.attributes != new_best.attributes
                });
                if changed {
                    self.bgpls_routes.insert(key, new_best);
                }
                changed
            }
            None => self.bgpls_routes.remove(&key).is_some(),
        }
    }

    /// Insert or replace the selected BGP-LS route for a key.
    pub fn insert_bgpls(&mut self, route: BgpLsRibRoute) {
        self.bgpls_routes.insert(route.key(), route);
    }

    /// Look up the selected BGP-LS route for a key.
    #[must_use]
    pub fn get_bgpls(&self, key: &BgpLsRouteKey) -> Option<&BgpLsRibRoute> {
        self.bgpls_routes.get(key)
    }

    /// Iterate over all selected BGP-LS routes.
    pub fn iter_bgpls(&self) -> impl Iterator<Item = &BgpLsRibRoute> {
        self.bgpls_routes.values()
    }

    /// Return the number of selected BGP-LS routes.
    #[must_use]
    pub fn bgpls_len(&self) -> usize {
        self.bgpls_routes.len()
    }

    /// Remove the selected BGP-LS route for a key. Returns `true` if it existed.
    pub fn remove_bgpls(&mut self, key: &BgpLsRouteKey) -> bool {
        self.bgpls_routes.remove(key).is_some()
    }

    /// Recompute the best VPNv4/VPNv6 route for `key` from the candidates.
    ///
    /// Uses the same family-agnostic BGP preference chain as BGP-LS: stale rank,
    /// `LOCAL_PREF`, `AS_PATH`, `ORIGIN`, MED, eBGP/iBGP, cluster length,
    /// originator ID, then peer address. The MPLS label stack is route data, not
    /// a selection input; a same-peer relabel is caught by the `nlri` change
    /// check so the reflected label stays current.
    pub fn recompute_vpn<'a>(
        &mut self,
        key: rustbgpd_wire::VpnRouteKey,
        candidates: impl Iterator<Item = &'a VpnRibRoute>,
    ) -> bool {
        let best = candidates.min_by(|a, b| vpn_tiebreak(a, b)).cloned();
        match best {
            Some(new_best) => {
                let changed = self.vpn_routes.get(&key).is_none_or(|(old, _)| {
                    old.peer != new_best.peer
                        || old.path_id != new_best.path_id
                        || old.is_stale != new_best.is_stale
                        || old.is_llgr_stale != new_best.is_llgr_stale
                        || old.next_hop != new_best.next_hop
                        || old.peer_router_id != new_best.peer_router_id
                        || old.nlri != new_best.nlri
                        || old.attributes != new_best.attributes
                });
                if changed {
                    self.vpn_routes.insert(key, (new_best, SystemTime::now()));
                }
                changed
            }
            None => self.vpn_routes.remove(&key).is_some(),
        }
    }

    /// Insert or replace the selected VPN route for a key.
    pub fn insert_vpn(&mut self, route: VpnRibRoute) {
        self.vpn_routes
            .insert(route.nlri.key(), (route, SystemTime::now()));
    }

    /// Look up the selected VPN route for an RD+prefix identity.
    #[must_use]
    pub fn get_vpn(&self, key: &rustbgpd_wire::VpnRouteKey) -> Option<&VpnRibRoute> {
        self.vpn_routes.get(key).map(|(route, _)| route)
    }

    /// Look up the selected VPN route together with its wall-clock
    /// Loc-RIB install time (RFC 9069 per-peer header timestamp for
    /// the BMP dump path).
    #[must_use]
    pub fn get_vpn_with_install_time(
        &self,
        key: &rustbgpd_wire::VpnRouteKey,
    ) -> Option<(&VpnRibRoute, SystemTime)> {
        self.vpn_routes
            .get(key)
            .map(|(route, installed_at)| (route, *installed_at))
    }

    /// Wall-clock install time of the current selected VPN route for
    /// `key`, captured when the selection last changed.
    #[must_use]
    pub fn vpn_install_time(&self, key: &rustbgpd_wire::VpnRouteKey) -> Option<SystemTime> {
        self.vpn_routes
            .get(key)
            .map(|(_, installed_at)| *installed_at)
    }

    /// Iterate over all selected VPN routes.
    pub fn iter_vpn(&self) -> impl Iterator<Item = &VpnRibRoute> {
        self.vpn_routes.values().map(|(route, _)| route)
    }

    /// Return the number of selected VPN routes.
    #[must_use]
    pub fn vpn_len(&self) -> usize {
        self.vpn_routes.len()
    }

    /// Remove the selected VPN route for a key. Returns `true` if it existed.
    pub fn remove_vpn(&mut self, key: &rustbgpd_wire::VpnRouteKey) -> bool {
        self.vpn_routes.remove(key).is_some()
    }

    /// Recompute the best labeled-unicast route for `key` from the
    /// candidates.
    ///
    /// Uses the same family-agnostic BGP preference chain as VPN: stale rank,
    /// `LOCAL_PREF`, `AS_PATH`, `ORIGIN`, MED, eBGP/iBGP, cluster length,
    /// originator ID, then peer address. The MPLS label stack is route data,
    /// not a selection input; a same-peer relabel is caught by the `nlri`
    /// change check so the reflected label stays current.
    pub fn recompute_labeled<'a>(
        &mut self,
        key: Prefix,
        candidates: impl Iterator<Item = &'a LabeledRibRoute>,
    ) -> bool {
        let best = candidates.min_by(|a, b| labeled_tiebreak(a, b)).cloned();
        match best {
            Some(new_best) => {
                let changed = self.labeled_routes.get(&key).is_none_or(|old| {
                    old.peer != new_best.peer
                        || old.path_id != new_best.path_id
                        || old.is_stale != new_best.is_stale
                        || old.is_llgr_stale != new_best.is_llgr_stale
                        || old.next_hop != new_best.next_hop
                        || old.peer_router_id != new_best.peer_router_id
                        || old.nlri != new_best.nlri
                        || old.attributes != new_best.attributes
                });
                if changed {
                    self.labeled_routes.insert(key, new_best);
                }
                changed
            }
            None => self.labeled_routes.remove(&key).is_some(),
        }
    }

    /// Insert or replace the selected labeled route for a key.
    pub fn insert_labeled(&mut self, route: LabeledRibRoute) {
        self.labeled_routes.insert(route.nlri.key(), route);
    }

    /// Look up the selected labeled route for a prefix identity.
    #[must_use]
    pub fn get_labeled(&self, key: &Prefix) -> Option<&LabeledRibRoute> {
        self.labeled_routes.get(key)
    }

    /// Iterate over all selected labeled routes.
    pub fn iter_labeled(&self) -> impl Iterator<Item = &LabeledRibRoute> {
        self.labeled_routes.values()
    }

    /// Return the number of selected labeled routes.
    #[must_use]
    pub fn labeled_len(&self) -> usize {
        self.labeled_routes.len()
    }

    /// Remove the selected labeled route for a key. Returns `true` if it
    /// existed.
    pub fn remove_labeled(&mut self, key: &Prefix) -> bool {
        self.labeled_routes.remove(key).is_some()
    }

    /// Recompute the best RT-Constrain route for `key` from the candidates.
    ///
    /// Uses the same family-agnostic BGP preference chain as VPN: stale rank,
    /// `LOCAL_PREF`, `AS_PATH`, `ORIGIN`, MED, eBGP/iBGP, cluster length,
    /// originator ID, then peer address.
    pub fn recompute_rtc<'a>(
        &mut self,
        key: RtcRibRouteKey,
        candidates: impl Iterator<Item = &'a RtcRibRoute>,
    ) -> bool {
        let best = candidates.min_by(|a, b| rtc_tiebreak(a, b)).cloned();
        match best {
            Some(new_best) => {
                let changed = self.rtc_routes.get(&key).is_none_or(|old| {
                    old.peer != new_best.peer
                        || old.path_id != new_best.path_id
                        || old.is_stale != new_best.is_stale
                        || old.is_llgr_stale != new_best.is_llgr_stale
                        || old.next_hop != new_best.next_hop
                        || old.peer_router_id != new_best.peer_router_id
                        || old.nlri != new_best.nlri
                        || old.attributes != new_best.attributes
                });
                if changed {
                    self.rtc_routes.insert(key, new_best);
                }
                changed
            }
            None => self.rtc_routes.remove(&key).is_some(),
        }
    }

    /// Insert or replace the selected RTC route for a key.
    pub fn insert_rtc(&mut self, route: RtcRibRoute) {
        self.rtc_routes.insert(route.key(), route);
    }

    /// Look up the selected RTC route for a key.
    #[must_use]
    pub fn get_rtc(&self, key: &RtcRibRouteKey) -> Option<&RtcRibRoute> {
        self.rtc_routes.get(key)
    }

    /// Iterate over all selected RTC routes.
    pub fn iter_rtc(&self) -> impl Iterator<Item = &RtcRibRoute> {
        self.rtc_routes.values()
    }

    /// Return the number of selected RTC routes.
    #[must_use]
    pub fn rtc_len(&self) -> usize {
        self.rtc_routes.len()
    }

    /// Remove the selected RTC route for a key. Returns `true` if it existed.
    pub fn remove_rtc(&mut self, key: &RtcRibRouteKey) -> bool {
        self.rtc_routes.remove(key).is_some()
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

fn bgpls_tiebreak(a: &BgpLsRibRoute, b: &BgpLsRibRoute) -> Ordering {
    let cmp = bgpls_stale_rank(a).cmp(&bgpls_stale_rank(b));
    if cmp != Ordering::Equal {
        return cmp;
    }

    let cmp = bgpls_local_pref(b).cmp(&bgpls_local_pref(a));
    if cmp != Ordering::Equal {
        return cmp;
    }

    let a_len = bgpls_as_path(a).map_or(0, AsPath::len);
    let b_len = bgpls_as_path(b).map_or(0, AsPath::len);
    let cmp = a_len.cmp(&b_len);
    if cmp != Ordering::Equal {
        return cmp;
    }

    let cmp = bgpls_origin(a).cmp(&bgpls_origin(b));
    if cmp != Ordering::Equal {
        return cmp;
    }

    let cmp = bgpls_med(a).cmp(&bgpls_med(b));
    if cmp != Ordering::Equal {
        return cmp;
    }

    let cmp = b.is_ebgp().cmp(&a.is_ebgp());
    if cmp != Ordering::Equal {
        return cmp;
    }

    let cmp = bgpls_cluster_list_len(a).cmp(&bgpls_cluster_list_len(b));
    if cmp != Ordering::Equal {
        return cmp;
    }

    if let (Some(a_oid), Some(b_oid)) = (bgpls_originator_id(a), bgpls_originator_id(b)) {
        let cmp = a_oid.cmp(&b_oid);
        if cmp != Ordering::Equal {
            return cmp;
        }
    }

    cmp_ipaddr(&a.peer, &b.peer)
}

fn bgpls_stale_rank(route: &BgpLsRibRoute) -> u8 {
    if route.is_llgr_stale {
        2
    } else {
        u8::from(route.is_stale)
    }
}

fn bgpls_local_pref(route: &BgpLsRibRoute) -> u32 {
    route
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::LocalPref(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(100)
}

fn bgpls_as_path(route: &BgpLsRibRoute) -> Option<&AsPath> {
    route.attributes.iter().find_map(|attr| match attr {
        PathAttribute::AsPath(path) => Some(path),
        _ => None,
    })
}

fn bgpls_origin(route: &BgpLsRibRoute) -> Origin {
    route
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::Origin(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(Origin::Incomplete)
}

fn bgpls_med(route: &BgpLsRibRoute) -> u32 {
    route
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::Med(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(0)
}

fn bgpls_cluster_list_len(route: &BgpLsRibRoute) -> usize {
    route
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::ClusterList(ids) => Some(ids.len()),
            _ => None,
        })
        .unwrap_or(0)
}

fn bgpls_originator_id(route: &BgpLsRibRoute) -> Option<std::net::Ipv4Addr> {
    route.attributes.iter().find_map(|attr| match attr {
        PathAttribute::OriginatorId(id) => Some(*id),
        _ => None,
    })
}

pub(crate) fn vpn_tiebreak(a: &VpnRibRoute, b: &VpnRibRoute) -> Ordering {
    vpn_cmp_chain(a, b, None)
}

/// Compare two VPN routes under RFC 9107 Optimal Route Reflection.
///
/// The standard [`vpn_tiebreak`] chain with one extra step between the
/// eBGP/iBGP step and `CLUSTER_LIST` — the same slot as
/// [`crate::best_path::best_path_cmp_orr`]: the configured vantage's
/// interior (SPF) cost to each route's `NEXT_HOP`. Lower cost wins; a
/// known cost beats an unknown one (RFC 9107 §3.1); equal or
/// both-unknown falls through.
pub(crate) fn vpn_tiebreak_orr(
    a: &VpnRibRoute,
    b: &VpnRibRoute,
    cost_a: Option<u64>,
    cost_b: Option<u64>,
) -> Ordering {
    vpn_cmp_chain(a, b, Some((cost_a, cost_b)))
}

/// The shared decision chain behind [`vpn_tiebreak`] (`orr_costs = None`,
/// the Loc-RIB selection — byte-identical to the pre-ORR chain) and
/// [`vpn_tiebreak_orr`] (`orr_costs = Some(..)`, per-vantage staging).
fn vpn_cmp_chain(
    a: &VpnRibRoute,
    b: &VpnRibRoute,
    orr_costs: Option<(Option<u64>, Option<u64>)>,
) -> Ordering {
    let cmp = vpn_stale_rank(a).cmp(&vpn_stale_rank(b));
    if cmp != Ordering::Equal {
        return cmp;
    }

    let cmp = vpn_local_pref(b).cmp(&vpn_local_pref(a));
    if cmp != Ordering::Equal {
        return cmp;
    }

    let a_len = vpn_as_path(a).map_or(0, AsPath::len);
    let b_len = vpn_as_path(b).map_or(0, AsPath::len);
    let cmp = a_len.cmp(&b_len);
    if cmp != Ordering::Equal {
        return cmp;
    }

    let cmp = vpn_origin(a).cmp(&vpn_origin(b));
    if cmp != Ordering::Equal {
        return cmp;
    }

    let cmp = vpn_med(a).cmp(&vpn_med(b));
    if cmp != Ordering::Equal {
        return cmp;
    }

    let cmp = b.is_ebgp().cmp(&a.is_ebgp());
    if cmp != Ordering::Equal {
        return cmp;
    }

    // RFC 9107 ORR interior cost to NEXT_HOP — only when the caller
    // supplies vantage costs (the Loc-RIB never does). Lower cost wins;
    // Some beats None (unknown metric MUST be least preferred); equal
    // or both-None falls through.
    if let Some((cost_a, cost_b)) = orr_costs {
        let cmp = match (cost_a, cost_b) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        };
        if cmp != Ordering::Equal {
            return cmp;
        }
    }

    let cmp = vpn_cluster_list_len(a).cmp(&vpn_cluster_list_len(b));
    if cmp != Ordering::Equal {
        return cmp;
    }

    if let (Some(a_oid), Some(b_oid)) = (vpn_originator_id(a), vpn_originator_id(b)) {
        let cmp = a_oid.cmp(&b_oid);
        if cmp != Ordering::Equal {
            return cmp;
        }
    }

    cmp_ipaddr(&a.peer, &b.peer)
}

fn vpn_stale_rank(route: &VpnRibRoute) -> u8 {
    if route.is_llgr_stale {
        2
    } else {
        u8::from(route.is_stale)
    }
}

fn vpn_local_pref(route: &VpnRibRoute) -> u32 {
    route
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::LocalPref(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(100)
}

fn vpn_as_path(route: &VpnRibRoute) -> Option<&AsPath> {
    route.attributes.iter().find_map(|attr| match attr {
        PathAttribute::AsPath(path) => Some(path),
        _ => None,
    })
}

fn vpn_origin(route: &VpnRibRoute) -> Origin {
    route
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::Origin(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(Origin::Incomplete)
}

fn vpn_med(route: &VpnRibRoute) -> u32 {
    route
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::Med(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(0)
}

fn vpn_cluster_list_len(route: &VpnRibRoute) -> usize {
    route
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::ClusterList(ids) => Some(ids.len()),
            _ => None,
        })
        .unwrap_or(0)
}

fn vpn_originator_id(route: &VpnRibRoute) -> Option<std::net::Ipv4Addr> {
    route.attributes.iter().find_map(|attr| match attr {
        PathAttribute::OriginatorId(id) => Some(*id),
        _ => None,
    })
}

pub(crate) fn labeled_tiebreak(a: &LabeledRibRoute, b: &LabeledRibRoute) -> Ordering {
    labeled_cmp_chain(a, b, None)
}

/// Compare two labeled-unicast routes under RFC 9107 Optimal Route
/// Reflection.
///
/// The standard [`labeled_tiebreak`] chain with one extra step between the
/// eBGP/iBGP step and `CLUSTER_LIST` — the same slot as
/// [`crate::best_path::best_path_cmp_orr`]: the configured vantage's
/// interior (SPF) cost to each route's `NEXT_HOP`. Lower cost wins; a
/// known cost beats an unknown one (RFC 9107 §3.1); equal or
/// both-unknown falls through.
pub(crate) fn labeled_tiebreak_orr(
    a: &LabeledRibRoute,
    b: &LabeledRibRoute,
    cost_a: Option<u64>,
    cost_b: Option<u64>,
) -> Ordering {
    labeled_cmp_chain(a, b, Some((cost_a, cost_b)))
}

/// The shared decision chain behind [`labeled_tiebreak`] (`orr_costs =
/// None`, the Loc-RIB selection) and [`labeled_tiebreak_orr`] (`orr_costs =
/// Some(..)`, per-vantage staging), mirroring `vpn_cmp_chain`.
fn labeled_cmp_chain(
    a: &LabeledRibRoute,
    b: &LabeledRibRoute,
    orr_costs: Option<(Option<u64>, Option<u64>)>,
) -> Ordering {
    let cmp = labeled_stale_rank(a).cmp(&labeled_stale_rank(b));
    if cmp != Ordering::Equal {
        return cmp;
    }

    let cmp = labeled_local_pref(b).cmp(&labeled_local_pref(a));
    if cmp != Ordering::Equal {
        return cmp;
    }

    let a_len = labeled_as_path(a).map_or(0, AsPath::len);
    let b_len = labeled_as_path(b).map_or(0, AsPath::len);
    let cmp = a_len.cmp(&b_len);
    if cmp != Ordering::Equal {
        return cmp;
    }

    let cmp = labeled_origin(a).cmp(&labeled_origin(b));
    if cmp != Ordering::Equal {
        return cmp;
    }

    let cmp = labeled_med(a).cmp(&labeled_med(b));
    if cmp != Ordering::Equal {
        return cmp;
    }

    let cmp = b.is_ebgp().cmp(&a.is_ebgp());
    if cmp != Ordering::Equal {
        return cmp;
    }

    // RFC 9107 ORR interior cost to NEXT_HOP — only when the caller
    // supplies vantage costs (the Loc-RIB never does). Lower cost wins;
    // Some beats None (unknown metric MUST be least preferred); equal
    // or both-None falls through.
    if let Some((cost_a, cost_b)) = orr_costs {
        let cmp = match (cost_a, cost_b) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        };
        if cmp != Ordering::Equal {
            return cmp;
        }
    }

    let cmp = labeled_cluster_list_len(a).cmp(&labeled_cluster_list_len(b));
    if cmp != Ordering::Equal {
        return cmp;
    }

    if let (Some(a_oid), Some(b_oid)) = (labeled_originator_id(a), labeled_originator_id(b)) {
        let cmp = a_oid.cmp(&b_oid);
        if cmp != Ordering::Equal {
            return cmp;
        }
    }

    cmp_ipaddr(&a.peer, &b.peer)
}

fn labeled_stale_rank(route: &LabeledRibRoute) -> u8 {
    if route.is_llgr_stale {
        2
    } else {
        u8::from(route.is_stale)
    }
}

fn labeled_local_pref(route: &LabeledRibRoute) -> u32 {
    route
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::LocalPref(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(100)
}

fn labeled_as_path(route: &LabeledRibRoute) -> Option<&AsPath> {
    route.attributes.iter().find_map(|attr| match attr {
        PathAttribute::AsPath(path) => Some(path),
        _ => None,
    })
}

fn labeled_origin(route: &LabeledRibRoute) -> Origin {
    route
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::Origin(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(Origin::Incomplete)
}

fn labeled_med(route: &LabeledRibRoute) -> u32 {
    route
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::Med(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(0)
}

fn labeled_cluster_list_len(route: &LabeledRibRoute) -> usize {
    route
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::ClusterList(ids) => Some(ids.len()),
            _ => None,
        })
        .unwrap_or(0)
}

fn labeled_originator_id(route: &LabeledRibRoute) -> Option<std::net::Ipv4Addr> {
    route.attributes.iter().find_map(|attr| match attr {
        PathAttribute::OriginatorId(id) => Some(*id),
        _ => None,
    })
}

fn rtc_tiebreak(a: &RtcRibRoute, b: &RtcRibRoute) -> Ordering {
    let cmp = rtc_stale_rank(a).cmp(&rtc_stale_rank(b));
    if cmp != Ordering::Equal {
        return cmp;
    }

    let cmp = rtc_local_pref(b).cmp(&rtc_local_pref(a));
    if cmp != Ordering::Equal {
        return cmp;
    }

    let a_len = rtc_as_path(a).map_or(0, AsPath::len);
    let b_len = rtc_as_path(b).map_or(0, AsPath::len);
    let cmp = a_len.cmp(&b_len);
    if cmp != Ordering::Equal {
        return cmp;
    }

    let cmp = rtc_origin(a).cmp(&rtc_origin(b));
    if cmp != Ordering::Equal {
        return cmp;
    }

    let cmp = rtc_med(a).cmp(&rtc_med(b));
    if cmp != Ordering::Equal {
        return cmp;
    }

    let cmp = b.is_ebgp().cmp(&a.is_ebgp());
    if cmp != Ordering::Equal {
        return cmp;
    }

    let cmp = rtc_cluster_list_len(a).cmp(&rtc_cluster_list_len(b));
    if cmp != Ordering::Equal {
        return cmp;
    }

    if let (Some(a_oid), Some(b_oid)) = (rtc_originator_id(a), rtc_originator_id(b)) {
        let cmp = a_oid.cmp(&b_oid);
        if cmp != Ordering::Equal {
            return cmp;
        }
    }

    cmp_ipaddr(&a.peer, &b.peer)
}

fn rtc_stale_rank(route: &RtcRibRoute) -> u8 {
    if route.is_llgr_stale {
        2
    } else {
        u8::from(route.is_stale)
    }
}

fn rtc_local_pref(route: &RtcRibRoute) -> u32 {
    route
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::LocalPref(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(100)
}

fn rtc_as_path(route: &RtcRibRoute) -> Option<&AsPath> {
    route.attributes.iter().find_map(|attr| match attr {
        PathAttribute::AsPath(path) => Some(path),
        _ => None,
    })
}

fn rtc_origin(route: &RtcRibRoute) -> Origin {
    route
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::Origin(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(Origin::Incomplete)
}

fn rtc_med(route: &RtcRibRoute) -> u32 {
    route
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::Med(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(0)
}

fn rtc_cluster_list_len(route: &RtcRibRoute) -> usize {
    route
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::ClusterList(ids) => Some(ids.len()),
            _ => None,
        })
        .unwrap_or(0)
}

fn rtc_originator_id(route: &RtcRibRoute) -> Option<std::net::Ipv4Addr> {
    route.attributes.iter().find_map(|attr| match attr {
        PathAttribute::OriginatorId(id) => Some(*id),
        _ => None,
    })
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
        LabeledNlri, MplsLabelEntry, NumericMatch, Origin, PathAttribute, RouteDistinguisher,
        RtcNlri, VpnNlri, VpnPrefix,
    };

    use super::*;
    use crate::route::{BgpLsFamily, RouteOrigin};

    fn make_route(peer_oct: u8, prefix: Ipv4Prefix, local_pref: u32) -> Route {
        crate::test_support::make_route_with_lp(
            prefix,
            Ipv4Addr::new(10, 0, 0, peer_oct),
            local_pref,
        )
    }

    fn bgpls_nlri(payload_suffix: u8) -> rustbgpd_wire::bgpls::BgpLsNlri {
        let bytes = [0xfd, 0xe8, 0, 3, 0xaa, 0xbb, payload_suffix];
        rustbgpd_wire::bgpls::decode_bgpls_nlri(&bytes)
            .expect("fixture BGP-LS NLRI decodes")
            .pop()
            .expect("fixture contains one NLRI")
    }

    fn make_bgpls_route(
        family: BgpLsFamily,
        nlri: rustbgpd_wire::bgpls::BgpLsNlri,
        peer_oct: u8,
    ) -> BgpLsRibRoute {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, peer_oct));
        BgpLsRibRoute {
            family,
            nlri,
            next_hop: peer,
            peer,
            attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::new(192, 0, 2, peer_oct),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        }
    }

    fn vpn_nlri(addr: [u8; 4], len: u8, label: u32) -> VpnNlri {
        VpnNlri {
            labels: vec![MplsLabelEntry::try_new(label, 0, true).unwrap()],
            route_distinguisher: RouteDistinguisher::new([0, 0, 0, 0, 0, 0, 0, 1]),
            prefix: VpnPrefix::v4(Ipv4Addr::from(addr), len).unwrap(),
        }
    }

    fn make_vpn_route(nlri: VpnNlri, peer_oct: u8, local_pref: u32) -> VpnRibRoute {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, peer_oct));
        VpnRibRoute {
            nlri,
            next_hop: peer,
            link_local_next_hop: None,
            peer,
            attributes: Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::LocalPref(local_pref),
            ]),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::new(192, 0, 2, peer_oct),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        }
    }

    #[test]
    fn recompute_vpn_higher_local_pref_wins() {
        let nlri = vpn_nlri([10, 0, 1, 0], 24, 100);
        let key = nlri.key();
        let r1 = make_vpn_route(nlri.clone(), 1, 100);
        let r2 = make_vpn_route(nlri, 2, 200);
        let mut loc = LocRib::new();

        assert!(loc.recompute_vpn(key, [&r1, &r2].into_iter()));
        assert_eq!(loc.vpn_len(), 1);
        assert_eq!(
            loc.get_vpn(&key).unwrap().peer,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            "higher LOCAL_PREF candidate must win"
        );
    }

    #[test]
    fn recompute_vpn_stale_demoted_despite_higher_local_pref() {
        let nlri = vpn_nlri([10, 0, 1, 0], 24, 100);
        let key = nlri.key();
        let mut r_stale = make_vpn_route(nlri.clone(), 1, 200);
        r_stale.is_stale = true;
        let r_fresh = make_vpn_route(nlri, 2, 100);
        let mut loc = LocRib::new();

        loc.recompute_vpn(key, [&r_stale, &r_fresh].into_iter());
        assert_eq!(
            loc.get_vpn(&key).unwrap().peer,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            "fresh route wins over a stale route with higher LOCAL_PREF"
        );
    }

    #[test]
    fn recompute_vpn_empty_candidates_removes_existing_key() {
        let nlri = vpn_nlri([10, 0, 1, 0], 24, 100);
        let key = nlri.key();
        let route = make_vpn_route(nlri, 1, 100);
        let mut loc = LocRib::new();

        loc.recompute_vpn(key, [&route].into_iter());
        assert_eq!(loc.vpn_len(), 1);

        let empty: Vec<&VpnRibRoute> = vec![];
        assert!(
            loc.recompute_vpn(key, empty.into_iter()),
            "removing an existing key returns true"
        );
        assert_eq!(loc.vpn_len(), 0);
        assert!(loc.get_vpn(&key).is_none());

        let empty: Vec<&VpnRibRoute> = vec![];
        assert!(
            !loc.recompute_vpn(key, empty.into_iter()),
            "removing an absent key returns false"
        );
    }

    /// Oracle: the public `vpn_tiebreak` chain is byte-identical to the
    /// pre-ORR behavior — `vpn_tiebreak_orr` with equal or both-unknown
    /// costs yields the same ordering across a matrix of pairs that
    /// exercise every decision step.
    #[test]
    fn vpn_tiebreak_unchanged_without_orr() {
        let nlri = vpn_nlri([10, 0, 3, 0], 24, 100);
        let base = make_vpn_route(nlri.clone(), 1, 100);
        let higher_lp = make_vpn_route(nlri.clone(), 2, 200);
        let mut stale = make_vpn_route(nlri.clone(), 3, 100);
        stale.is_stale = true;
        let mut longer_path = make_vpn_route(nlri.clone(), 4, 100);
        Arc::make_mut(&mut longer_path.attributes).push(PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65001, 65002])],
        }));
        let mut clustered = make_vpn_route(nlri.clone(), 5, 100);
        Arc::make_mut(&mut clustered.attributes).push(PathAttribute::ClusterList(vec![
            Ipv4Addr::new(10, 255, 0, 1),
            Ipv4Addr::new(10, 255, 0, 2),
        ]));
        let peer_tiebreak = make_vpn_route(nlri, 6, 100);
        let routes = [
            base,
            higher_lp,
            stale,
            longer_path,
            clustered,
            peer_tiebreak,
        ];

        for a in &routes {
            for b in &routes {
                let plain = vpn_tiebreak(a, b);
                assert_eq!(vpn_tiebreak_orr(a, b, None, None), plain);
                assert_eq!(vpn_tiebreak_orr(a, b, Some(7), Some(7)), plain);
            }
        }
    }

    /// The ORR interior-cost step decides ONLY at its slot — below the
    /// eBGP/iBGP step (`LOCAL_PREF` etc. still win first) and above
    /// `CLUSTER_LIST` / peer-address (which it overrides on a tie).
    #[test]
    fn vpn_orr_cost_only_breaks_ties_below_ebgp_step() {
        let nlri = vpn_nlri([10, 0, 4, 0], 24, 100);
        // LOCAL_PREF outranks a better interior cost.
        let preferred = make_vpn_route(nlri.clone(), 1, 200);
        let closer = make_vpn_route(nlri.clone(), 2, 100);
        assert_eq!(
            vpn_tiebreak_orr(&preferred, &closer, Some(1000), Some(0)),
            Ordering::Less,
            "LOCAL_PREF wins before the interior-cost step"
        );
        // On a full upper-chain tie, the lower cost beats the lower peer
        // address (route 1 would win the final tiebreak).
        let a = make_vpn_route(nlri.clone(), 1, 100);
        let b = make_vpn_route(nlri, 2, 100);
        assert_eq!(
            vpn_tiebreak_orr(&a, &b, Some(10), Some(5)),
            Ordering::Greater
        );
        assert_eq!(vpn_tiebreak_orr(&a, &b, Some(5), Some(10)), Ordering::Less);
        // Equal costs fall through to the peer-address tiebreak.
        assert_eq!(vpn_tiebreak_orr(&a, &b, Some(5), Some(5)), Ordering::Less);
    }

    /// RFC 9107 §3.1: an unknown metric-to-next-hop MUST be least
    /// preferred — a known cost beats None regardless of magnitude.
    #[test]
    fn vpn_orr_unknown_cost_least_preferred() {
        let nlri = vpn_nlri([10, 0, 5, 0], 24, 100);
        let a = make_vpn_route(nlri.clone(), 1, 100);
        let b = make_vpn_route(nlri, 2, 100);
        assert_eq!(
            vpn_tiebreak_orr(&a, &b, Some(u64::MAX), None),
            Ordering::Less
        );
        assert_eq!(
            vpn_tiebreak_orr(&a, &b, None, Some(u64::MAX)),
            Ordering::Greater
        );
        // Both unknown falls through (peer address decides).
        assert_eq!(vpn_tiebreak_orr(&a, &b, None, None), Ordering::Less);
    }

    #[test]
    fn vpn_loc_rib_is_isolated_from_unicast_best_routes() {
        let mut loc = LocRib::new();
        loc.insert_vpn(make_vpn_route(vpn_nlri([10, 0, 2, 0], 24, 100), 1, 100));

        assert_eq!(loc.vpn_len(), 1);
        assert_eq!(loc.len(), 0);
        assert!(loc.is_empty(), "legacy unicast emptiness is unchanged");
    }

    fn labeled_nlri(addr: [u8; 4], len: u8, label: u32) -> LabeledNlri {
        LabeledNlri {
            labels: vec![MplsLabelEntry::try_new(label, 0, true).unwrap()],
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(addr), len)),
        }
    }

    fn make_labeled_route(nlri: LabeledNlri, peer_oct: u8, local_pref: u32) -> LabeledRibRoute {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, peer_oct));
        LabeledRibRoute {
            nlri,
            next_hop: peer,
            link_local_next_hop: None,
            peer,
            attributes: Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::LocalPref(local_pref),
            ]),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::new(192, 0, 2, peer_oct),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        }
    }

    #[test]
    fn recompute_labeled_higher_local_pref_wins() {
        let nlri = labeled_nlri([10, 0, 1, 0], 24, 100);
        let key = nlri.key();
        let r1 = make_labeled_route(nlri.clone(), 1, 100);
        let r2 = make_labeled_route(nlri, 2, 200);
        let mut loc = LocRib::new();

        assert!(loc.recompute_labeled(key, [&r1, &r2].into_iter()));
        assert_eq!(loc.labeled_len(), 1);
        assert_eq!(
            loc.get_labeled(&key).unwrap().peer,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn recompute_labeled_stale_demoted_despite_higher_local_pref() {
        let nlri = labeled_nlri([10, 0, 1, 0], 24, 100);
        let key = nlri.key();
        let mut r_stale = make_labeled_route(nlri.clone(), 1, 200);
        r_stale.is_stale = true;
        let r_fresh = make_labeled_route(nlri, 2, 100);
        let mut loc = LocRib::new();

        loc.recompute_labeled(key, [&r_stale, &r_fresh].into_iter());
        assert_eq!(
            loc.get_labeled(&key).unwrap().peer,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            "fresh route must beat GR-stale despite lower LOCAL_PREF"
        );
    }

    #[test]
    fn recompute_labeled_same_peer_relabel_triggers_change() {
        // The label stack is route data, not identity: a same-peer relabel of
        // the same prefix must still report a change (nlri differs) so the
        // reflected label stays current.
        let key = labeled_nlri([10, 0, 1, 0], 24, 100).key();
        let r1 = make_labeled_route(labeled_nlri([10, 0, 1, 0], 24, 100), 1, 100);
        let r2 = make_labeled_route(labeled_nlri([10, 0, 1, 0], 24, 999), 1, 100);
        let mut loc = LocRib::new();

        assert!(loc.recompute_labeled(key, [&r1].into_iter()));
        assert!(
            loc.recompute_labeled(key, [&r2].into_iter()),
            "relabel must be a change"
        );
        assert_eq!(loc.get_labeled(&key).unwrap().nlri.labels[0].label, 999);
        assert!(
            !loc.recompute_labeled(key, [&r2].into_iter()),
            "identical candidate must not be a change"
        );
    }

    #[test]
    fn recompute_labeled_empty_candidates_removes_existing_key() {
        let nlri = labeled_nlri([10, 0, 1, 0], 24, 100);
        let key = nlri.key();
        let route = make_labeled_route(nlri, 1, 100);
        let mut loc = LocRib::new();

        loc.recompute_labeled(key, [&route].into_iter());
        assert_eq!(loc.labeled_len(), 1);

        let empty: [&LabeledRibRoute; 0] = [];
        assert!(
            loc.recompute_labeled(key, empty.into_iter()),
            "removal is a change"
        );
        assert_eq!(loc.labeled_len(), 0);
        assert!(loc.get_labeled(&key).is_none());

        let empty: [&LabeledRibRoute; 0] = [];
        assert!(
            !loc.recompute_labeled(key, empty.into_iter()),
            "removing an absent key is not a change"
        );
    }

    /// Oracle: the public `labeled_tiebreak` chain is byte-identical to the
    /// plain (no-ORR) behavior — `labeled_tiebreak_orr` with equal or
    /// both-unknown costs must agree with `labeled_tiebreak` on every pair,
    /// including the stale-rank step.
    #[test]
    fn labeled_tiebreak_unchanged_without_orr() {
        let nlri = labeled_nlri([10, 0, 3, 0], 24, 100);
        let base = make_labeled_route(nlri.clone(), 1, 100);
        let higher_lp = make_labeled_route(nlri.clone(), 2, 200);
        let mut stale = make_labeled_route(nlri.clone(), 3, 100);
        stale.is_stale = true;
        let mut llgr_stale = make_labeled_route(nlri.clone(), 4, 100);
        llgr_stale.is_llgr_stale = true;
        let mut longer_path = make_labeled_route(nlri.clone(), 5, 100);
        Arc::make_mut(&mut longer_path.attributes).push(PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65001, 65002])],
        }));
        let mut clustered = make_labeled_route(nlri.clone(), 6, 100);
        Arc::make_mut(&mut clustered.attributes).push(PathAttribute::ClusterList(vec![
            Ipv4Addr::new(10, 255, 0, 1),
            Ipv4Addr::new(10, 255, 0, 2),
        ]));
        let peer_tiebreak = make_labeled_route(nlri, 7, 100);
        let routes = [
            base,
            higher_lp,
            stale,
            llgr_stale,
            longer_path,
            clustered,
            peer_tiebreak,
        ];

        for a in &routes {
            for b in &routes {
                let plain = labeled_tiebreak(a, b);
                assert_eq!(labeled_tiebreak_orr(a, b, None, None), plain);
                assert_eq!(labeled_tiebreak_orr(a, b, Some(7), Some(7)), plain);
            }
        }
    }

    /// The ORR interior-cost step decides ONLY at its slot — below the
    /// eBGP/iBGP step (`LOCAL_PREF` etc. still win first) and above
    /// `CLUSTER_LIST` / peer-address (which it overrides on a tie), with a
    /// known cost beating an unknown one (RFC 9107 §3.1).
    #[test]
    fn labeled_orr_cost_only_breaks_ties_below_ebgp_step() {
        let nlri = labeled_nlri([10, 0, 4, 0], 24, 100);
        // LOCAL_PREF outranks a better interior cost.
        let preferred = make_labeled_route(nlri.clone(), 1, 200);
        let closer = make_labeled_route(nlri.clone(), 2, 100);
        assert_eq!(
            labeled_tiebreak_orr(&preferred, &closer, Some(1000), Some(0)),
            Ordering::Less,
            "LOCAL_PREF must outrank interior cost"
        );

        // On an otherwise-tied pair, cost decides before the peer address.
        let a = make_labeled_route(nlri.clone(), 1, 100);
        let b = make_labeled_route(nlri, 2, 100);
        assert_eq!(
            labeled_tiebreak_orr(&a, &b, Some(10), Some(5)),
            Ordering::Greater
        );
        assert_eq!(
            labeled_tiebreak_orr(&a, &b, Some(5), Some(10)),
            Ordering::Less
        );
        // Equal costs fall through to the peer-address step.
        assert_eq!(
            labeled_tiebreak_orr(&a, &b, Some(5), Some(5)),
            Ordering::Less
        );
        // Known beats unknown regardless of magnitude.
        assert_eq!(
            labeled_tiebreak_orr(&a, &b, Some(u64::MAX), None),
            Ordering::Less
        );
        assert_eq!(
            labeled_tiebreak_orr(&a, &b, None, Some(u64::MAX)),
            Ordering::Greater
        );
    }

    #[test]
    fn labeled_loc_rib_is_isolated_from_unicast_best_routes() {
        let mut loc = LocRib::new();
        loc.insert_labeled(make_labeled_route(
            labeled_nlri([10, 0, 2, 0], 24, 100),
            1,
            100,
        ));

        assert_eq!(loc.labeled_len(), 1);
        assert_eq!(loc.len(), 0);
        assert!(loc.is_empty(), "legacy unicast emptiness is unchanged");

        assert!(loc.remove_labeled(&labeled_nlri([10, 0, 2, 0], 24, 100).key()));
        assert_eq!(loc.labeled_len(), 0);
    }

    fn rtc_test_nlri(local_admin: u32) -> RtcNlri {
        // 2-octet-AS RT:65001:<local_admin>, origin AS 65001, full /96.
        let rt = 0x0002_FDE9_0000_0000_u64 | u64::from(local_admin);
        RtcNlri::new(65001, rt, 96).unwrap()
    }

    fn make_rtc_route(nlri: RtcNlri, peer_oct: u8, local_pref: u32) -> RtcRibRoute {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, peer_oct));
        RtcRibRoute {
            nlri,
            next_hop: peer,
            peer,
            attributes: Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::LocalPref(local_pref),
            ]),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::new(192, 0, 2, peer_oct),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        }
    }

    #[test]
    fn recompute_rtc_higher_local_pref_wins() {
        let nlri = rtc_test_nlri(100);
        let key = RtcRibRouteKey { nlri, path_id: 0 };
        let r1 = make_rtc_route(nlri, 1, 100);
        let r2 = make_rtc_route(nlri, 2, 200);
        let mut loc = LocRib::new();

        assert!(loc.recompute_rtc(key.clone(), [&r1, &r2].into_iter()));
        assert_eq!(loc.rtc_len(), 1);
        assert_eq!(
            loc.get_rtc(&key).unwrap().peer,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            "higher LOCAL_PREF candidate must win"
        );
    }

    #[test]
    fn recompute_rtc_stale_demoted_despite_higher_local_pref() {
        let nlri = rtc_test_nlri(100);
        let key = RtcRibRouteKey { nlri, path_id: 0 };
        let mut r_stale = make_rtc_route(nlri, 1, 200);
        r_stale.is_stale = true;
        let r_fresh = make_rtc_route(nlri, 2, 100);
        let mut loc = LocRib::new();

        loc.recompute_rtc(key.clone(), [&r_stale, &r_fresh].into_iter());
        assert_eq!(
            loc.get_rtc(&key).unwrap().peer,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            "fresh route wins over a stale route with higher LOCAL_PREF"
        );
    }

    #[test]
    fn recompute_rtc_empty_candidates_removes_existing_key() {
        let nlri = rtc_test_nlri(100);
        let key = RtcRibRouteKey { nlri, path_id: 0 };
        let route = make_rtc_route(nlri, 1, 100);
        let mut loc = LocRib::new();

        loc.recompute_rtc(key.clone(), [&route].into_iter());
        assert_eq!(loc.rtc_len(), 1);

        let empty: Vec<&RtcRibRoute> = vec![];
        assert!(
            loc.recompute_rtc(key.clone(), empty.into_iter()),
            "removing an existing key returns true"
        );
        assert_eq!(loc.rtc_len(), 0);
        assert!(loc.get_rtc(&key).is_none());

        let empty: Vec<&RtcRibRoute> = vec![];
        assert!(
            !loc.recompute_rtc(key, empty.into_iter()),
            "removing an absent key returns false"
        );
    }

    #[test]
    fn rtc_loc_rib_is_isolated_from_unicast_and_vpn_best_routes() {
        let mut loc = LocRib::new();
        loc.insert_rtc(make_rtc_route(rtc_test_nlri(100), 1, 100));

        assert_eq!(loc.rtc_len(), 1);
        assert_eq!(loc.len(), 0);
        assert_eq!(loc.vpn_len(), 0);
        assert!(loc.is_empty(), "legacy unicast emptiness is unchanged");
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
    fn bgpls_insert_replace_remove_preserves_opaque_identity() {
        let mut loc = LocRib::new();
        let nlri = bgpls_nlri(11);
        let key = BgpLsRouteKey {
            family: BgpLsFamily::LinkState,
            nlri: nlri.key(),
            path_id: 0,
        };

        loc.insert_bgpls(make_bgpls_route(BgpLsFamily::LinkState, nlri.clone(), 1));
        assert_eq!(loc.bgpls_len(), 1);
        assert_eq!(loc.iter_bgpls().count(), 1);
        assert_eq!(
            loc.get_bgpls(&key).unwrap().nlri.payload.as_ref(),
            &[0xaa, 0xbb, 11]
        );

        loc.insert_bgpls(make_bgpls_route(BgpLsFamily::LinkState, nlri, 2));
        assert_eq!(loc.bgpls_len(), 1, "same opaque key should replace");
        assert_eq!(
            loc.get_bgpls(&key).unwrap().peer,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );

        assert!(loc.remove_bgpls(&key));
        assert_eq!(loc.bgpls_len(), 0);
        assert!(!loc.remove_bgpls(&key));
    }

    #[test]
    fn bgpls_loc_rib_is_isolated_from_unicast_best_routes() {
        let mut loc = LocRib::new();
        loc.insert_bgpls(make_bgpls_route(BgpLsFamily::LinkState, bgpls_nlri(12), 1));

        assert_eq!(loc.bgpls_len(), 1);
        assert_eq!(loc.len(), 0);
        assert!(loc.is_empty(), "legacy unicast emptiness is unchanged");
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

    fn flowspec_key(rule: &FlowSpecRule) -> FlowSpecKey {
        FlowSpecKey {
            afi: Afi::Ipv4,
            rule: rule.clone(),
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

        loc.recompute_flowspec(flowspec_key(&rule), [&r1, &r2].into_iter());
        let best = loc.get_flowspec(&flowspec_key(&rule)).unwrap();
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

        loc.recompute_flowspec(flowspec_key(&rule), [&r1, &r2].into_iter());
        let best = loc.get_flowspec(&flowspec_key(&rule)).unwrap();
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

        loc.recompute_flowspec(flowspec_key(&rule), [&internal, &external].into_iter());
        let best = loc.get_flowspec(&flowspec_key(&rule)).unwrap();
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

        loc.recompute_flowspec(flowspec_key(&rule), [&r_stale, &r_fresh].into_iter());
        let best = loc.get_flowspec(&flowspec_key(&rule)).unwrap();
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
        loc.recompute_flowspec(flowspec_key(&rule), [&gr, &llgr].into_iter());
        assert_eq!(
            loc.get_flowspec(&flowspec_key(&rule)).unwrap().peer,
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
        loc.recompute_flowspec(flowspec_key(&rule), [&fresh, &llgr].into_iter());
        assert_eq!(
            loc.get_flowspec(&flowspec_key(&rule)).unwrap().peer,
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

        loc.recompute_flowspec(flowspec_key(&rule), [&r1, &r2].into_iter());
        let best = loc.get_flowspec(&flowspec_key(&rule)).unwrap();
        assert_eq!(best.peer, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn flowspec_lowest_peer_tiebreaker() {
        let rule = make_flowspec_rule();
        // All attributes identical, eBGP, same router-id
        let r1 = make_flowspec_route(3, 1, vec![PathAttribute::LocalPref(100)], RouteOrigin::Ebgp);
        let r2 = make_flowspec_route(1, 1, vec![PathAttribute::LocalPref(100)], RouteOrigin::Ebgp);
        let mut loc = LocRib::new();

        loc.recompute_flowspec(flowspec_key(&rule), [&r1, &r2].into_iter());
        let best = loc.get_flowspec(&flowspec_key(&rule)).unwrap();
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

    /// Regression: `recompute` must report change when the same peer
    /// re-advertises the same prefix with a new next-hop or changed
    /// attributes. Previously the change detector was `best_path_cmp`
    /// alone, which compares only preference-relevant fields and
    /// tiebreaks on the peer address — so same-peer payload churn was
    /// silently swallowed and never redistributed.
    #[test]
    fn unicast_same_peer_payload_churn_triggers_change() {
        let v4 = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let prefix = Prefix::V4(v4);
        let r1 = make_route(1, v4, 100);

        // Same peer, same preference fields, new next-hop.
        let mut r_nh = r1.clone();
        r_nh.next_hop = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));

        // Same peer, same preference fields, new community set.
        let mut r_attr = r1.clone();
        Arc::make_mut(&mut r_attr.attributes).push(PathAttribute::Communities(vec![0x0001_0001]));

        let mut loc = LocRib::new();
        // First install — always a change.
        assert!(loc.recompute(prefix, [&r1].into_iter()));
        // Identical re-announcement — no change, no event spam.
        assert!(!loc.recompute(prefix, [&r1.clone()].into_iter()));
        // Next-hop moved — must be detected.
        assert!(
            loc.recompute(prefix, [&r_nh].into_iter()),
            "same-peer next-hop change must be detected"
        );
        assert_eq!(
            loc.get(&prefix).unwrap().next_hop,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99))
        );
        // Attribute payload changed — must be detected.
        assert!(
            loc.recompute(prefix, [&r_attr].into_iter()),
            "same-peer attribute change must be detected"
        );
        // Same input again — no change.
        assert!(!loc.recompute(prefix, [&r_attr.clone()].into_iter()));
    }

    /// Regression: `recompute_flowspec` must report change when the same
    /// peer re-advertises the same rule with a different action (the
    /// action lives in the extended communities — rate-limit, redirect).
    /// Previously only `peer` and `path_id` were compared, so a same-peer
    /// action update was silently swallowed and the old action stayed
    /// advertised (and installed, where enforcement applies).
    #[test]
    fn flowspec_same_peer_action_change_triggers_change() {
        let rule = make_flowspec_rule();
        let limit_1mbps =
            PathAttribute::ExtendedCommunities(vec![ExtendedCommunity::new(u64::from_be_bytes([
                0x80, 0x06, 0, 0, 0x49, 0x74, 0x24, 0x00,
            ]))]);
        let limit_drop =
            PathAttribute::ExtendedCommunities(vec![ExtendedCommunity::new(u64::from_be_bytes([
                0x80, 0x06, 0, 0, 0, 0, 0, 0,
            ]))]);
        let r1 = make_flowspec_route(1, 1, vec![limit_1mbps], RouteOrigin::Ebgp);
        let r2 = make_flowspec_route(1, 1, vec![limit_drop], RouteOrigin::Ebgp);

        let mut loc = LocRib::new();
        // First install — always a change.
        assert!(loc.recompute_flowspec(flowspec_key(&rule), [&r1].into_iter()));
        // Same peer, action flipped from rate-limit to drop — must be detected.
        assert!(
            loc.recompute_flowspec(flowspec_key(&rule), [&r2].into_iter()),
            "same-peer FlowSpec action change must be detected"
        );
        // Same input again — no change.
        assert!(!loc.recompute_flowspec(flowspec_key(&rule), [&r2.clone()].into_iter()));
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
