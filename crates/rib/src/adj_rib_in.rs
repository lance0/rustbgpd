use std::net::IpAddr;
use std::sync::Arc;

// Route-bearing maps use FxHash (rustc-hash) rather than the default SipHash
// for a pure insert/lookup speedup on the convergence + churn hot path.
//
// HashDoS tradeoff (deliberate): these keys — `Prefix`, `(Prefix, path_id)`,
// `EvpnRouteKey`, `FlowSpecRule`, and the interned attribute sets — ARE
// peer-fed (decoded from received UPDATE NLRI / attributes), and FxHash is
// deterministic, so it gives no collision resistance against an adversary who
// crafts colliding keys. We accept that here because the BGP peer threat model
// differs fundamentally from the anonymous-client scenario SipHash defends:
//   1. Peers are explicitly configured + (typically) authenticated — not
//      arbitrary internet clients.
//   2. Per-peer prefix count is bounded by enforced `max_prefixes` (the
//      transport session is torn down past the limit, see
//      `transport::session::inbound`), which caps any collision chain. Set it
//      for lower-trust neighbors.
//   3. A peer able to mount this already has strictly higher-impact vectors
//      (route hijack / leak / churn flood) that dominate the threat model.
// This matches the non-DoS-resistant internal hash tables FRR and BIRD use.
// `BgpLsRouteKey` joins the same class once ADR-0077 receive wiring lands.
// Aliased to the std names so the storage type declarations read unchanged.
use rustbgpd_wire::{Afi, EvpnRouteKey, FlowSpecRule, PathAttribute, Prefix, Safi};
use rustc_hash::{FxBuildHasher, FxHashMap as HashMap, FxHashSet as HashSet};
use smallvec::SmallVec;

use crate::prefix_map::FamilyPrefixMap;
use crate::route::{
    BgpLsRibRoute, BgpLsRouteKey, EvpnRibRoute, FlowSpecRoute, Route, RtcRibRoute, RtcRibRouteKey,
    VpnRibRoute, VpnRibRouteKey,
};

/// Per-peer Adj-RIB-In: stores the routes received from a single peer.
///
/// Routes are keyed by `(Prefix, path_id)` to support Add-Path (RFC 7911).
/// Non-Add-Path peers always use `path_id = 0`.
///
/// A secondary `prefix_index` maps each prefix to its path IDs,
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
    /// Secondary index: prefix → path IDs stored for that prefix, backed by a
    /// family-split prefix trie. `SmallVec<[u32; 1]>` inlines the single-path
    /// case (`path_id=0`, no Add-Path) without a per-prefix heap allocation;
    /// Add-Path multi-path spills to the heap transparently. Mirrors
    /// `AdjRibOut::prefix_path_ids`.
    prefix_index: FamilyPrefixMap<SmallVec<[u32; 1]>>,
    /// Route keys where `LLGR_STALE` was injected locally by this daemon.
    llgr_stale_local_tags: HashSet<(Prefix, u32)>,
    /// `FlowSpec` routes keyed by `(rule, path_id)`.
    flowspec_routes: HashMap<(FlowSpecRule, u32), FlowSpecRoute>,
    /// `FlowSpec` route keys where `LLGR_STALE` was injected locally.
    flowspec_llgr_stale_local_tags: HashSet<(FlowSpecRule, u32)>,
    /// EVPN routes keyed by RFC 7432 route identity.
    evpn_routes: HashMap<EvpnRouteKey, EvpnRibRoute>,
    /// BGP-LS routes keyed by opaque RFC 9552 route identity.
    bgpls_routes: HashMap<BgpLsRouteKey, BgpLsRibRoute>,
    /// VPNv4/VPNv6 routes keyed by RFC 4364 RD + prefix identity.
    vpn_routes: HashMap<VpnRibRouteKey, VpnRibRoute>,
    /// RT-Constrain routes keyed by RFC 4684 RT membership identity.
    rtc_routes: HashMap<RtcRibRouteKey, RtcRibRoute>,
    /// EVPN route keys where `LLGR_STALE` was injected locally by this daemon
    /// during promotion from GR-stale → LLGR-stale. Used to distinguish
    /// locally-injected communities (which we strip on clear) from
    /// peer-originated ones (which must be preserved).
    evpn_llgr_stale_local_tags: HashSet<EvpnRouteKey>,
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
            routes: HashMap::with_capacity_and_hasher(route_capacity, FxBuildHasher),
            prefix_index: FamilyPrefixMap::default(),
            llgr_stale_local_tags: HashSet::default(),
            flowspec_routes: HashMap::with_capacity_and_hasher(flowspec_capacity, FxBuildHasher),
            flowspec_llgr_stale_local_tags: HashSet::default(),
            evpn_routes: HashMap::default(),
            bgpls_routes: HashMap::default(),
            vpn_routes: HashMap::default(),
            rtc_routes: HashMap::default(),
            evpn_llgr_stale_local_tags: HashSet::default(),
            attr_intern: HashSet::with_capacity_and_hasher(
                route_capacity.clamp(16, 64),
                FxBuildHasher,
            ),
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
    ///
    /// Returns `true` if an existing route at the same `(prefix, path_id)` was
    /// replaced. A replacement may strand the previous route's interned
    /// attribute set, so a caller processing a batch should run
    /// [`Self::gc_intern_table`] once afterwards when any insert returned
    /// `true` (see the unicast announce path in the RIB manager). A first-time
    /// insert orphans nothing, so the initial-load flood skips the GC.
    pub fn insert(&mut self, mut route: Route) -> bool {
        let key = (route.prefix, route.path_id);
        let ids = self.prefix_index.entry_or_default(route.prefix);
        if !ids.contains(&route.path_id) {
            ids.push(route.path_id);
        }
        self.llgr_stale_local_tags.remove(&key);

        // Intern: reuse an existing Arc if one matches
        if let Some(existing) = self.attr_intern.get(&route.attributes) {
            route.attributes = existing.clone();
        } else {
            self.attr_intern.insert(route.attributes.clone());
        }

        self.routes.insert(key, route).is_some()
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

    /// Remove every route from this Adj-RIB-In — unicast, `FlowSpec`, EVPN,
    /// BGP-LS, VPN, and RTC — plus all secondary indices, stale tags, and the
    /// attribute intern table. Used when the per-peer Adj-RIB-In needs to be
    /// wiped without also dropping the [`AdjRibIn`] struct itself.
    pub fn clear(&mut self) {
        self.routes.clear();
        self.prefix_index.clear();
        self.flowspec_routes.clear();
        self.evpn_routes.clear();
        self.bgpls_routes.clear();
        self.vpn_routes.clear();
        self.rtc_routes.clear();
        self.llgr_stale_local_tags.clear();
        self.flowspec_llgr_stale_local_tags.clear();
        self.evpn_llgr_stale_local_tags.clear();
        self.attr_intern.clear();
    }

    /// Return the number of unicast routes stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Return the backing capacity of the unicast route map.
    ///
    /// Exposed only to benchmark / memory-profile harnesses so they can
    /// distinguish route-count growth from hash-table capacity cliffs.
    #[cfg(feature = "bench-internals")]
    #[must_use]
    pub fn bench_route_capacity(&self) -> usize {
        self.routes.capacity()
    }

    /// Return the number of exact prefixes in the secondary unicast index.
    #[cfg(feature = "bench-internals")]
    #[must_use]
    pub fn bench_prefix_index_len(&self) -> usize {
        self.prefix_index.len()
    }

    /// Return the prefix trie's structural memory, excluding stored values'
    /// own heap allocations.
    #[cfg(feature = "bench-internals")]
    #[must_use]
    pub fn bench_prefix_index_mem_size(&self) -> usize {
        self.prefix_index.mem_size()
    }

    /// Return the number of interned attribute sets.
    #[cfg(feature = "bench-internals")]
    #[must_use]
    pub fn bench_attr_intern_len(&self) -> usize {
        self.attr_intern.len()
    }

    /// Return the backing capacity of the attribute intern table.
    #[cfg(feature = "bench-internals")]
    #[must_use]
    pub fn bench_attr_intern_capacity(&self) -> usize {
        self.attr_intern.capacity()
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
        self.flowspec_llgr_stale_local_tags
            .remove(&(route.rule.clone(), route.path_id));
        self.flowspec_routes
            .insert((route.rule.clone(), route.path_id), route);
    }

    /// Withdraw a `FlowSpec` route by rule and path ID. Returns `true` if it existed.
    pub fn withdraw_flowspec(&mut self, rule: &FlowSpecRule, path_id: u32) -> bool {
        self.flowspec_llgr_stale_local_tags
            .remove(&(rule.clone(), path_id));
        self.flowspec_routes
            .remove(&(rule.clone(), path_id))
            .is_some()
    }

    /// Iterate over all `FlowSpec` routes.
    pub fn iter_flowspec(&self) -> impl Iterator<Item = &FlowSpecRoute> {
        self.flowspec_routes.values()
    }

    // --- EVPN methods (RFC 7432) ---
    //
    // Insert / withdraw / iter for route-reflector distribution, plus full
    // GR + LLGR stale handling parallel to unicast and FlowSpec: see
    // mark_stale_evpn / clear_stale_evpn / sweep_stale_evpn /
    // promote_to_llgr_stale_evpn / sweep_llgr_stale_evpn /
    // clear_llgr_stale_evpn below.

    /// Insert or replace an EVPN route, keyed by its RFC 7432 identity.
    ///
    /// Re-advertising the same key with a new attribute set (notably RFC 7432
    /// §7.7 MAC Mobility, which increments a sequence number on every move)
    /// strands the previous interned set. Callers must run [`Self::gc_intern_table`]
    /// after a batch of inserts/withdraws to reclaim it — see the EVPN
    /// announce/withdraw/inject paths in the RIB manager.
    ///
    /// Returns `true` if an existing route at the same key was replaced.
    pub fn insert_evpn(&mut self, mut route: EvpnRibRoute) -> bool {
        let key = route.key();
        // Re-advertising a key drops any record that *we* locally injected
        // LLGR_STALE on the prior version of it — exactly as unicast `insert`
        // and FlowSpec `insert_flowspec` clear their stale tags. Without this,
        // a later EoR (`clear_llgr_stale_evpn`) would treat this fresh route as
        // locally tagged and strip a peer-originated LLGR_STALE off it.
        self.evpn_llgr_stale_local_tags.remove(&key);
        // Intern attributes so identical attribute sets share one Arc.
        if let Some(existing) = self.attr_intern.get(&route.attributes) {
            route.attributes = existing.clone();
        } else {
            self.attr_intern.insert(route.attributes.clone());
        }
        self.evpn_routes.insert(key, route).is_some()
    }

    /// Withdraw an EVPN route. Returns `true` if it existed.
    pub fn withdraw_evpn(&mut self, key: &EvpnRouteKey) -> bool {
        // Mirror unicast `withdraw` / FlowSpec `withdraw_flowspec`: a withdrawn
        // key can no longer carry a locally-injected LLGR_STALE tag.
        self.evpn_llgr_stale_local_tags.remove(key);
        self.evpn_routes.remove(key).is_some()
    }

    /// Iterate over all EVPN routes in this Adj-RIB-In.
    pub fn iter_evpn(&self) -> impl Iterator<Item = &EvpnRibRoute> {
        self.evpn_routes.values()
    }

    /// Return the number of EVPN routes stored.
    #[must_use]
    pub fn evpn_len(&self) -> usize {
        self.evpn_routes.len()
    }

    /// Iterate mutably over all EVPN routes.
    pub fn iter_evpn_mut(&mut self) -> impl Iterator<Item = &mut EvpnRibRoute> {
        self.evpn_routes.values_mut()
    }

    // --- EVPN GR/LLGR stale handling (RFC 4724 + RFC 9494) ---
    //
    // Follows the unicast pattern (not FlowSpec): EvpnRibRoute attributes
    // are Arc<Vec<PathAttribute>>, so community injection goes through
    // Arc::make_mut to preserve the intern-table sharing invariant.
    //
    // EVPN has a single family tuple (Afi::L2Vpn, Safi::Evpn), so family
    // match checks reduce to direct equality.

    /// Mark all EVPN routes as stale if `family == (L2Vpn, Evpn)`.
    pub fn mark_stale_evpn(&mut self, family: (Afi, Safi)) {
        if family != (Afi::L2Vpn, Safi::Evpn) {
            return;
        }
        for route in self.evpn_routes.values_mut() {
            route.is_stale = true;
        }
    }

    /// Clear the stale flag on EVPN routes (both `is_stale` and
    /// `is_llgr_stale`), stripping any locally-injected `LLGR_STALE`
    /// community. Peer-originated `LLGR_STALE` communities are preserved.
    pub fn clear_stale_evpn(&mut self, family: (Afi, Safi)) {
        if family != (Afi::L2Vpn, Safi::Evpn) {
            return;
        }
        let mut clear_local_llgr = Vec::new();
        for (key, route) in &mut self.evpn_routes {
            route.is_stale = false;
            route.is_llgr_stale = false;
            if self.evpn_llgr_stale_local_tags.contains(key) {
                clear_local_llgr.push(*key);
            }
        }
        self.clear_local_llgr_stale_evpn_community(&clear_local_llgr);
    }

    /// Remove all stale EVPN routes, returning their keys.
    pub fn sweep_stale_evpn(&mut self) -> Vec<EvpnRouteKey> {
        let stale: Vec<EvpnRouteKey> = self
            .evpn_routes
            .iter()
            .filter(|(_, r)| r.is_stale)
            .map(|(k, _)| *k)
            .collect();
        for key in &stale {
            self.evpn_llgr_stale_local_tags.remove(key);
            self.evpn_routes.remove(key);
        }
        stale
    }

    /// Remove stale EVPN routes if `family == (L2Vpn, Evpn)`. Used when a
    /// family was in GR but not in the peer's LLGR capability.
    pub fn sweep_stale_family_evpn(&mut self, family: (Afi, Safi)) -> Vec<EvpnRouteKey> {
        if family != (Afi::L2Vpn, Safi::Evpn) {
            return Vec::new();
        }
        self.sweep_stale_evpn()
    }

    /// Promote GR-stale EVPN routes to LLGR-stale (RFC 9494).
    ///
    /// - Routes with `NO_LLGR` community are removed (must not enter LLGR).
    /// - Remaining stale routes: `is_stale=false`, `is_llgr_stale=true`,
    ///   `LLGR_STALE` community added via `Arc::make_mut`.
    ///
    /// Returns keys affected (for best-path recalc).
    pub fn promote_to_llgr_stale_evpn(&mut self, family: (Afi, Safi)) -> Vec<EvpnRouteKey> {
        use rustbgpd_wire::{COMMUNITY_LLGR_STALE, COMMUNITY_NO_LLGR};

        if family != (Afi::L2Vpn, Safi::Evpn) {
            return Vec::new();
        }

        // First pass: remove routes carrying NO_LLGR
        let no_llgr_keys: Vec<EvpnRouteKey> = self
            .evpn_routes
            .iter()
            .filter(|(_, r)| r.is_stale && r.communities().contains(&COMMUNITY_NO_LLGR))
            .map(|(k, _)| *k)
            .collect();
        let mut affected: Vec<EvpnRouteKey> = no_llgr_keys.clone();
        for key in &no_llgr_keys {
            self.evpn_llgr_stale_local_tags.remove(key);
            self.evpn_routes.remove(key);
        }

        // Second pass: promote remaining stale routes to LLGR-stale
        for route in self.evpn_routes.values_mut() {
            if route.is_stale {
                route.is_stale = false;
                route.is_llgr_stale = true;
                let attrs = Arc::make_mut(&mut route.attributes);
                if let Some(PathAttribute::Communities(comms)) = attrs
                    .iter_mut()
                    .find(|a| matches!(a, PathAttribute::Communities(_)))
                {
                    if !comms.contains(&COMMUNITY_LLGR_STALE) {
                        comms.push(COMMUNITY_LLGR_STALE);
                        self.evpn_llgr_stale_local_tags.insert(route.key());
                    }
                } else {
                    attrs.push(PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE]));
                    self.evpn_llgr_stale_local_tags.insert(route.key());
                }
                affected.push(route.key());
            }
        }

        affected
    }

    /// Remove all LLGR-stale EVPN routes, returning their keys.
    pub fn sweep_llgr_stale_evpn(&mut self) -> Vec<EvpnRouteKey> {
        let stale: Vec<EvpnRouteKey> = self
            .evpn_routes
            .iter()
            .filter(|(_, r)| r.is_llgr_stale)
            .map(|(k, _)| *k)
            .collect();
        for key in &stale {
            self.evpn_llgr_stale_local_tags.remove(key);
            self.evpn_routes.remove(key);
        }
        stale
    }

    /// Clear the LLGR-stale flag on EVPN routes. Called when `EoR` is
    /// received during LLGR phase.
    pub fn clear_llgr_stale_evpn(&mut self, family: (Afi, Safi)) {
        if family != (Afi::L2Vpn, Safi::Evpn) {
            return;
        }
        let mut clear_local_llgr = Vec::new();
        for (key, route) in &mut self.evpn_routes {
            route.is_llgr_stale = false;
            if self.evpn_llgr_stale_local_tags.contains(key) {
                clear_local_llgr.push(*key);
            }
        }
        self.clear_local_llgr_stale_evpn_community(&clear_local_llgr);
    }

    // --- BGP-LS methods (ADR-0077 receive/API slice) ---

    /// Insert or replace a BGP-LS route, keyed by opaque RFC 9552 identity.
    ///
    /// Returns `true` if an existing route at the same opaque key was replaced.
    /// A replacement may strand the previous route's interned attribute set.
    /// BGP-LS batch callers run [`Self::gc_intern_table`] once after any
    /// replacement or real withdrawal, after Loc-RIB recomputation has dropped
    /// any selected-route clone.
    pub fn insert_bgpls(&mut self, mut route: BgpLsRibRoute) -> bool {
        let key = route.key();
        if let Some(existing) = self.attr_intern.get(&route.attributes) {
            route.attributes = existing.clone();
        } else {
            self.attr_intern.insert(route.attributes.clone());
        }
        self.bgpls_routes.insert(key, route).is_some()
    }

    /// Withdraw a BGP-LS route. Returns `true` if it existed.
    pub fn withdraw_bgpls(&mut self, key: &BgpLsRouteKey) -> bool {
        self.bgpls_routes.remove(key).is_some()
    }

    /// Withdraw all BGP-LS routes from this Adj-RIB-In.
    ///
    /// BGP-LS GR/LLGR stale preservation is not implemented yet, so GR entry
    /// uses this helper to make the conservative exclusion explicit instead of
    /// accidentally retaining stale controller-feed objects as live.
    pub fn withdraw_all_bgpls(&mut self) -> Vec<BgpLsRouteKey> {
        let keys: Vec<_> = self.bgpls_routes.keys().cloned().collect();
        self.bgpls_routes.clear();
        keys
    }

    /// Look up a BGP-LS route by opaque key.
    #[must_use]
    pub fn get_bgpls(&self, key: &BgpLsRouteKey) -> Option<&BgpLsRibRoute> {
        self.bgpls_routes.get(key)
    }

    /// Iterate over all BGP-LS routes in this Adj-RIB-In.
    pub fn iter_bgpls(&self) -> impl Iterator<Item = &BgpLsRibRoute> {
        self.bgpls_routes.values()
    }

    /// Return the number of BGP-LS routes stored.
    #[must_use]
    pub fn bgpls_len(&self) -> usize {
        self.bgpls_routes.len()
    }

    /// Insert or replace a VPNv4/VPNv6 route, interning its attribute set.
    ///
    /// Returns `true` if an existing route at the same RD + prefix + path-id was
    /// replaced. A replacement may strand the previous route's interned attribute
    /// set; VPN batch callers run [`Self::gc_intern_table`] once after any
    /// replacement or real withdrawal, after Loc-RIB recomputation has dropped
    /// any selected-route clone.
    pub fn insert_vpn(&mut self, mut route: VpnRibRoute) -> bool {
        let key = route.key();
        if let Some(existing) = self.attr_intern.get(&route.attributes) {
            route.attributes = existing.clone();
        } else {
            self.attr_intern.insert(route.attributes.clone());
        }
        self.vpn_routes.insert(key, route).is_some()
    }

    /// Withdraw a VPN route. Returns `true` if it existed.
    pub fn withdraw_vpn(&mut self, key: &VpnRibRouteKey) -> bool {
        self.vpn_routes.remove(key).is_some()
    }

    /// Withdraw all VPN routes from this Adj-RIB-In.
    ///
    /// VPN GR/LLGR stale preservation is not implemented yet, so GR entry uses
    /// this helper to make the conservative exclusion explicit instead of
    /// accidentally retaining stale controller-feed routes as live.
    pub fn withdraw_all_vpn(&mut self) -> Vec<VpnRibRouteKey> {
        let keys: Vec<_> = self.vpn_routes.keys().cloned().collect();
        self.vpn_routes.clear();
        keys
    }

    /// Look up a VPN route by RD + prefix + path-id key.
    #[must_use]
    pub fn get_vpn(&self, key: &VpnRibRouteKey) -> Option<&VpnRibRoute> {
        self.vpn_routes.get(key)
    }

    /// Iterate over all VPN routes in this Adj-RIB-In.
    pub fn iter_vpn(&self) -> impl Iterator<Item = &VpnRibRoute> {
        self.vpn_routes.values()
    }

    /// Return the number of VPN routes stored.
    #[must_use]
    pub fn vpn_len(&self) -> usize {
        self.vpn_routes.len()
    }

    /// Insert or replace an RT-Constrain route, interning its attribute set.
    ///
    /// Returns `true` if an existing route at the same NLRI + path-id was
    /// replaced. A replacement may strand the previous route's interned
    /// attribute set; RTC batch callers run [`Self::gc_intern_table`] once
    /// after any replacement or real withdrawal, after Loc-RIB recomputation
    /// has dropped any selected-route clone.
    pub fn insert_rtc(&mut self, mut route: RtcRibRoute) -> bool {
        let key = route.key();
        if let Some(existing) = self.attr_intern.get(&route.attributes) {
            route.attributes = existing.clone();
        } else {
            self.attr_intern.insert(route.attributes.clone());
        }
        self.rtc_routes.insert(key, route).is_some()
    }

    /// Withdraw an RTC route. Returns `true` if it existed.
    pub fn withdraw_rtc(&mut self, key: &RtcRibRouteKey) -> bool {
        self.rtc_routes.remove(key).is_some()
    }

    /// Withdraw all RTC routes from this Adj-RIB-In.
    ///
    /// RTC GR/LLGR stale preservation is not implemented, so GR entry uses
    /// this helper to make the conservative exclusion explicit instead of
    /// accidentally retaining stale membership routes as live.
    pub fn withdraw_all_rtc(&mut self) -> Vec<RtcRibRouteKey> {
        let keys: Vec<_> = self.rtc_routes.keys().cloned().collect();
        self.rtc_routes.clear();
        keys
    }

    /// Look up an RTC route by NLRI + path-id key.
    #[must_use]
    pub fn get_rtc(&self, key: &RtcRibRouteKey) -> Option<&RtcRibRoute> {
        self.rtc_routes.get(key)
    }

    /// Iterate over all RTC routes in this Adj-RIB-In.
    pub fn iter_rtc(&self) -> impl Iterator<Item = &RtcRibRoute> {
        self.rtc_routes.values()
    }

    /// Return the number of RTC routes stored.
    #[must_use]
    pub fn rtc_len(&self) -> usize {
        self.rtc_routes.len()
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
            self.flowspec_llgr_stale_local_tags.remove(key);
            self.flowspec_routes.remove(key);
        }
        rules
    }

    /// Clear all `FlowSpec` routes.
    pub fn clear_flowspec(&mut self) {
        self.flowspec_routes.clear();
        self.flowspec_llgr_stale_local_tags.clear();
    }

    /// Clear the stale flag on `FlowSpec` routes matching the given family.
    pub fn clear_stale_flowspec(&mut self, family: (Afi, Safi)) {
        if family.1 != Safi::FlowSpec {
            return;
        }
        for route in self.flowspec_routes.values_mut() {
            if route.afi == family.0 {
                route.is_stale = false;
                route.is_llgr_stale = false;
            }
        }
    }

    /// Remove stale `FlowSpec` routes for a specific family, returning their rules.
    pub fn sweep_stale_flowspec_family(&mut self, family: (Afi, Safi)) -> Vec<FlowSpecRule> {
        if family.1 != Safi::FlowSpec {
            return Vec::new();
        }
        let stale: Vec<(FlowSpecRule, u32)> = self
            .flowspec_routes
            .iter()
            .filter(|(_, r)| r.is_stale && r.afi == family.0)
            .map(|(k, _)| k.clone())
            .collect();
        let mut rules = Vec::new();
        for key in &stale {
            rules.push(key.0.clone());
            self.flowspec_llgr_stale_local_tags.remove(key);
            self.flowspec_routes.remove(key);
        }
        rules
    }

    /// Promote GR-stale `FlowSpec` routes to LLGR-stale for the given family.
    ///
    /// Routes with `NO_LLGR` community are removed. Remaining stale routes
    /// get `is_stale=false`, `is_llgr_stale=true`, `LLGR_STALE` community added.
    ///
    /// Returns rules affected (for best-path recalc).
    pub fn promote_to_llgr_stale_flowspec(&mut self, family: (Afi, Safi)) -> Vec<FlowSpecRule> {
        use rustbgpd_wire::{COMMUNITY_LLGR_STALE, COMMUNITY_NO_LLGR, PathAttribute};

        if family.1 != Safi::FlowSpec {
            return Vec::new();
        }

        // First pass: remove routes with NO_LLGR community
        let no_llgr_keys: Vec<(FlowSpecRule, u32)> = self
            .flowspec_routes
            .iter()
            .filter(|(_, r)| {
                r.is_stale
                    && r.afi == family.0
                    && r.attributes
                        .iter()
                        .any(|a| matches!(a, PathAttribute::Communities(c) if c.contains(&COMMUNITY_NO_LLGR)))
            })
            .map(|(k, _)| k.clone())
            .collect();
        let mut affected: Vec<FlowSpecRule> = no_llgr_keys.iter().map(|(r, _)| r.clone()).collect();
        for key in &no_llgr_keys {
            self.flowspec_routes.remove(key);
        }

        // Second pass: promote remaining stale routes to LLGR-stale
        for route in self.flowspec_routes.values_mut() {
            if route.is_stale && route.afi == family.0 {
                route.is_stale = false;
                route.is_llgr_stale = true;
                if let Some(PathAttribute::Communities(comms)) = route
                    .attributes
                    .iter_mut()
                    .find(|a| matches!(a, PathAttribute::Communities(_)))
                {
                    if !comms.contains(&COMMUNITY_LLGR_STALE) {
                        comms.push(COMMUNITY_LLGR_STALE);
                        self.flowspec_llgr_stale_local_tags
                            .insert((route.rule.clone(), route.path_id));
                    }
                } else {
                    route
                        .attributes
                        .push(PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE]));
                    self.flowspec_llgr_stale_local_tags
                        .insert((route.rule.clone(), route.path_id));
                }
                affected.push(route.rule.clone());
            }
        }

        affected
    }

    /// Remove all LLGR-stale `FlowSpec` routes, returning their rules.
    pub fn sweep_llgr_stale_flowspec(&mut self) -> Vec<FlowSpecRule> {
        let stale: Vec<(FlowSpecRule, u32)> = self
            .flowspec_routes
            .iter()
            .filter(|(_, r)| r.is_llgr_stale)
            .map(|(k, _)| k.clone())
            .collect();
        let mut rules = Vec::new();
        for key in &stale {
            rules.push(key.0.clone());
            self.flowspec_llgr_stale_local_tags.remove(key);
            self.flowspec_routes.remove(key);
        }
        rules
    }

    /// Clear the LLGR-stale flag on `FlowSpec` routes matching the given family.
    pub fn clear_llgr_stale_flowspec(&mut self, family: (Afi, Safi)) {
        if family.1 != Safi::FlowSpec {
            return;
        }
        let mut clear_local_llgr = Vec::new();
        for route in self.flowspec_routes.values_mut() {
            if route.afi == family.0 {
                route.is_llgr_stale = false;
                let key = (route.rule.clone(), route.path_id);
                if self.flowspec_llgr_stale_local_tags.contains(&key) {
                    clear_local_llgr.push(key);
                }
            }
        }
        self.clear_local_llgr_stale_flowspec_community(&clear_local_llgr);
    }

    /// Remove a `path_id` from the prefix index, cleaning up empty entries.
    fn remove_from_prefix_index(&mut self, prefix: &Prefix, path_id: u32) {
        if let Some(ids) = self.prefix_index.get_mut(prefix) {
            ids.retain(|id| *id != path_id);
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

    fn clear_local_llgr_stale_flowspec_community(&mut self, keys: &[(FlowSpecRule, u32)]) {
        for key in keys {
            if let Some(route) = self.flowspec_routes.get_mut(key) {
                remove_llgr_stale_community_attrs(&mut route.attributes);
            }
            self.flowspec_llgr_stale_local_tags.remove(key);
        }
    }

    fn clear_local_llgr_stale_evpn_community(&mut self, keys: &[EvpnRouteKey]) {
        for key in keys {
            if let Some(route) = self.evpn_routes.get_mut(key) {
                remove_llgr_stale_community_attrs(Arc::make_mut(&mut route.attributes));
            }
            self.evpn_llgr_stale_local_tags.remove(key);
        }
    }
}

/// Remove the `LLGR_STALE` community from a route's attributes, if present.
fn remove_llgr_stale_community(route: &mut Route) {
    use std::sync::Arc;
    remove_llgr_stale_community_attrs(Arc::make_mut(&mut route.attributes));
}

fn remove_llgr_stale_community_attrs(attrs: &mut Vec<PathAttribute>) {
    use rustbgpd_wire::COMMUNITY_LLGR_STALE;
    for attr in attrs {
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

    use rustbgpd_wire::{
        Afi, COMMUNITY_LLGR_STALE, Ipv4Prefix, Ipv6Prefix, MplsLabelEntry, Origin, PathAttribute,
        RouteDistinguisher, RtcNlri, Safi, VpnNlri, VpnPrefix,
    };

    use super::*;

    use crate::route::BgpLsFamily;
    use crate::test_support::{make_flowspec_route, make_route, make_v6_route};

    fn bgpls_nlri(payload_suffix: u8) -> rustbgpd_wire::bgpls::BgpLsNlri {
        let bytes = [0xfd, 0xe8, 0, 3, 0xaa, 0xbb, payload_suffix];
        rustbgpd_wire::bgpls::decode_bgpls_nlri(&bytes)
            .expect("fixture BGP-LS NLRI decodes")
            .pop()
            .expect("fixture contains one NLRI")
    }

    fn bgpls_vpn_nlri(payload_suffix: u8) -> rustbgpd_wire::bgpls::BgpLsNlri {
        let bytes = [
            0xfd,
            0xe8,
            0,
            11, // 8-byte RD + 3-byte opaque payload
            0,
            0,
            0xfd,
            0xe8,
            0,
            0,
            0,
            42,
            0xaa,
            0xbb,
            payload_suffix,
        ];
        rustbgpd_wire::bgpls::decode_bgpls_vpn_nlri(&bytes)
            .expect("fixture BGP-LS VPN NLRI decodes")
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
            origin_type: crate::route::RouteOrigin::Ibgp,
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

    fn make_vpn_route(nlri: VpnNlri, peer_oct: u8) -> VpnRibRoute {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, peer_oct));
        VpnRibRoute {
            nlri,
            next_hop: peer,
            peer,
            attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::new(192, 0, 2, peer_oct),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
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
    fn vpn_insert_get_replace_withdraw_round_trip() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let nlri = vpn_nlri([10, 0, 1, 0], 24, 100);
        let key = VpnRibRouteKey {
            nlri_key: nlri.key(),
            path_id: 0,
        };

        assert!(!rib.insert_vpn(make_vpn_route(nlri.clone(), 1)));
        assert_eq!(rib.vpn_len(), 1);
        assert_eq!(rib.iter_vpn().count(), 1);
        assert_eq!(
            rib.get_vpn(&key).unwrap().next_hop,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );

        // Same RD + prefix + path_id replaces in place.
        assert!(rib.insert_vpn(make_vpn_route(nlri, 2)));
        assert_eq!(rib.vpn_len(), 1, "same key should replace");
        assert_eq!(
            rib.get_vpn(&key).unwrap().next_hop,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );

        assert!(rib.withdraw_vpn(&key));
        assert_eq!(rib.vpn_len(), 0);
        assert!(!rib.withdraw_vpn(&key));
    }

    #[test]
    fn vpn_withdraw_all_returns_keys_and_empties_table() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let a = vpn_nlri([10, 0, 1, 0], 24, 100);
        let b = vpn_nlri([10, 0, 2, 0], 24, 200);
        rib.insert_vpn(make_vpn_route(a.clone(), 1));
        rib.insert_vpn(make_vpn_route(b.clone(), 1));
        assert_eq!(rib.vpn_len(), 2);

        let mut keys = rib.withdraw_all_vpn();
        keys.sort_by_key(|k| k.nlri_key.prefix.to_string());
        assert_eq!(
            keys,
            vec![
                VpnRibRouteKey {
                    nlri_key: a.key(),
                    path_id: 0
                },
                VpnRibRouteKey {
                    nlri_key: b.key(),
                    path_id: 0
                },
            ]
        );
        assert_eq!(rib.vpn_len(), 0);
    }

    #[test]
    fn vpn_insert_reports_replacement_for_intern_gc() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let nlri = vpn_nlri([10, 0, 1, 0], 24, 100);

        assert!(!rib.insert_vpn(make_vpn_route(nlri.clone(), 1)));
        assert_eq!(rib.intern_len(), 1);

        let mut replacement = make_vpn_route(nlri, 2);
        replacement.attributes = Arc::new(vec![PathAttribute::Origin(Origin::Egp)]);

        assert!(rib.insert_vpn(replacement));
        assert_eq!(
            rib.intern_len(),
            2,
            "replacement strands the previous interned attribute set before GC"
        );

        rib.gc_intern_table();
        assert_eq!(rib.intern_len(), 1);
    }

    #[test]
    fn vpn_storage_is_isolated_from_unicast_index() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        rib.insert_vpn(make_vpn_route(vpn_nlri([10, 0, 9, 0], 24, 100), 1));

        assert_eq!(rib.vpn_len(), 1);
        assert_eq!(rib.len(), 0, "VPN storage must not touch unicast count");

        rib.clear();
        assert_eq!(rib.vpn_len(), 0);
        assert!(rib.is_empty());
    }

    fn rtc_nlri(local_admin: u32) -> RtcNlri {
        // 2-octet-AS RT:65001:<local_admin>, origin AS 65001, full /96.
        let rt = 0x0002_FDE9_0000_0000_u64 | u64::from(local_admin);
        RtcNlri::new(65001, rt, 96).unwrap()
    }

    fn make_rtc_route(nlri: RtcNlri, peer_oct: u8) -> RtcRibRoute {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, peer_oct));
        RtcRibRoute {
            nlri,
            next_hop: peer,
            peer,
            attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::new(192, 0, 2, peer_oct),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        }
    }

    #[test]
    fn rtc_insert_get_replace_withdraw_round_trip() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let nlri = rtc_nlri(100);
        let key = RtcRibRouteKey { nlri, path_id: 0 };

        assert!(!rib.insert_rtc(make_rtc_route(nlri, 1)));
        assert_eq!(rib.rtc_len(), 1);
        assert_eq!(rib.iter_rtc().count(), 1);
        assert_eq!(
            rib.get_rtc(&key).unwrap().next_hop,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );

        // Same NLRI + path_id replaces in place.
        assert!(rib.insert_rtc(make_rtc_route(nlri, 2)));
        assert_eq!(rib.rtc_len(), 1, "same key should replace");
        assert_eq!(
            rib.get_rtc(&key).unwrap().next_hop,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );

        assert!(rib.withdraw_rtc(&key));
        assert_eq!(rib.rtc_len(), 0);
        assert!(!rib.withdraw_rtc(&key));
    }

    #[test]
    fn rtc_withdraw_all_returns_keys_and_empties_table() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let a = rtc_nlri(100);
        let b = rtc_nlri(200);
        rib.insert_rtc(make_rtc_route(a, 1));
        rib.insert_rtc(make_rtc_route(b, 1));
        assert_eq!(rib.rtc_len(), 2);

        let mut keys = rib.withdraw_all_rtc();
        keys.sort_by_key(|k| k.nlri.route_target_bits);
        assert_eq!(
            keys,
            vec![
                RtcRibRouteKey {
                    nlri: a,
                    path_id: 0
                },
                RtcRibRouteKey {
                    nlri: b,
                    path_id: 0
                },
            ]
        );
        assert_eq!(rib.rtc_len(), 0);
    }

    #[test]
    fn rtc_insert_reports_replacement_for_intern_gc() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let nlri = rtc_nlri(100);

        assert!(!rib.insert_rtc(make_rtc_route(nlri, 1)));
        assert_eq!(rib.intern_len(), 1);

        let mut replacement = make_rtc_route(nlri, 2);
        replacement.attributes = Arc::new(vec![PathAttribute::Origin(Origin::Egp)]);

        assert!(rib.insert_rtc(replacement));
        assert_eq!(
            rib.intern_len(),
            2,
            "replacement strands the previous interned attribute set before GC"
        );

        rib.gc_intern_table();
        assert_eq!(rib.intern_len(), 1);
    }

    #[test]
    fn rtc_storage_is_isolated_from_unicast_and_vpn_tables() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        rib.insert_rtc(make_rtc_route(rtc_nlri(100), 1));

        assert_eq!(rib.rtc_len(), 1);
        assert_eq!(rib.len(), 0, "RTC storage must not touch unicast count");
        assert_eq!(rib.vpn_len(), 0, "RTC storage must not touch VPN table");
        assert_eq!(rib.bgpls_len(), 0, "RTC storage must not touch BGP-LS");

        rib.clear();
        assert_eq!(rib.rtc_len(), 0);
        assert!(rib.is_empty());
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
    fn bgpls_insert_replace_withdraw_preserves_opaque_key() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let nlri = bgpls_nlri(1);
        let key = BgpLsRouteKey {
            family: BgpLsFamily::LinkState,
            nlri: nlri.key(),
            path_id: 0,
        };

        assert!(!rib.insert_bgpls(make_bgpls_route(BgpLsFamily::LinkState, nlri.clone(), 1)));
        assert_eq!(rib.bgpls_len(), 1);
        assert_eq!(rib.iter_bgpls().count(), 1);
        assert_eq!(
            rib.get_bgpls(&key).unwrap().nlri.payload.as_ref(),
            &[0xaa, 0xbb, 1]
        );

        assert!(rib.insert_bgpls(make_bgpls_route(BgpLsFamily::LinkState, nlri, 2)));
        assert_eq!(rib.bgpls_len(), 1, "same opaque key should replace");
        assert_eq!(
            rib.get_bgpls(&key).unwrap().next_hop,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );

        assert!(rib.withdraw_bgpls(&key));
        assert_eq!(rib.bgpls_len(), 0);
        assert!(!rib.withdraw_bgpls(&key));
    }

    #[test]
    fn bgpls_base_and_vpn_keys_are_distinct() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let base = bgpls_nlri(7);
        let vpn = bgpls_vpn_nlri(7);
        let base_key = BgpLsRouteKey {
            family: BgpLsFamily::LinkState,
            nlri: base.key(),
            path_id: 0,
        };
        let vpn_key = BgpLsRouteKey {
            family: BgpLsFamily::LinkStateVpn,
            nlri: vpn.key(),
            path_id: 0,
        };

        rib.insert_bgpls(make_bgpls_route(BgpLsFamily::LinkState, base, 1));
        rib.insert_bgpls(make_bgpls_route(BgpLsFamily::LinkStateVpn, vpn, 2));

        assert_eq!(rib.bgpls_len(), 2);
        assert_ne!(base_key, vpn_key);
        assert!(rib.get_bgpls(&base_key).is_some());
        assert!(rib.get_bgpls(&vpn_key).is_some());
    }

    #[test]
    fn bgpls_insert_reports_replacement_for_intern_gc() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let nlri = bgpls_nlri(8);

        assert!(!rib.insert_bgpls(make_bgpls_route(BgpLsFamily::LinkState, nlri.clone(), 1)));
        assert_eq!(rib.intern_len(), 1);

        let mut replacement = make_bgpls_route(BgpLsFamily::LinkState, nlri, 2);
        replacement.attributes = Arc::new(vec![PathAttribute::Origin(Origin::Egp)]);

        assert!(rib.insert_bgpls(replacement));
        assert_eq!(
            rib.intern_len(),
            2,
            "replacement strands the previous interned attribute set before GC"
        );

        rib.gc_intern_table();
        assert_eq!(rib.intern_len(), 1);
    }

    #[test]
    fn bgpls_clear_removes_routes_and_keeps_unicast_index_isolated() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        rib.insert_bgpls(make_bgpls_route(BgpLsFamily::LinkState, bgpls_nlri(9), 1));

        assert_eq!(rib.bgpls_len(), 1);
        assert_eq!(rib.len(), 0, "BGP-LS storage must not touch unicast count");

        rib.clear();
        assert_eq!(rib.bgpls_len(), 0);
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
    fn clear_llgr_stale_flowspec_removes_locally_added_llgr_stale_community() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);

        let mut route = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
        route.is_stale = true;
        rib.insert_flowspec(route);

        rib.promote_to_llgr_stale_flowspec((Afi::Ipv4, Safi::FlowSpec));
        let route = rib.iter_flowspec().next().unwrap();
        assert!(route.is_llgr_stale);
        assert!(route.attributes.iter().any(
            |a| matches!(a, PathAttribute::Communities(c) if c.contains(&COMMUNITY_LLGR_STALE))
        ));

        rib.clear_llgr_stale_flowspec((Afi::Ipv4, Safi::FlowSpec));
        let route = rib.iter_flowspec().next().unwrap();
        assert!(!route.is_llgr_stale);
        assert!(!route.attributes.iter().any(
            |a| matches!(a, PathAttribute::Communities(c) if c.contains(&COMMUNITY_LLGR_STALE))
        ));
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

    #[test]
    fn evpn_insert_and_withdraw() {
        use rustbgpd_wire::{EthernetTagId, EvpnImet, EvpnRoute, EvpnRouteKey, RouteDistinguisher};
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer_ip);

        let rd = RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 100]);
        let tag = EthernetTagId(100);
        let originator = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let imet = EvpnRoute::Imet(EvpnImet {
            rd,
            ethernet_tag: tag,
            originator_ip: originator,
        });
        let route = EvpnRibRoute {
            route: imet,
            next_hop: peer_ip,
            link_local_next_hop: None,
            peer: peer_ip,
            attributes: Arc::new(vec![]),
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
            is_stale: false,
            is_llgr_stale: false,
        };

        rib.insert_evpn(route);
        assert_eq!(rib.evpn_len(), 1);
        assert_eq!(rib.iter_evpn().count(), 1);

        let expected_key = EvpnRouteKey::Imet {
            rd,
            ethernet_tag: tag,
            originator_ip: originator,
        };
        assert!(rib.withdraw_evpn(&expected_key));
        assert_eq!(rib.evpn_len(), 0);
        assert!(
            !rib.withdraw_evpn(&expected_key),
            "second withdraw is no-op"
        );
    }

    // --- EVPN GR/LLGR stale handling tests (Gate 2) ---

    fn insert_evpn_imet(
        rib: &mut AdjRibIn,
        peer: Ipv4Addr,
        ethernet_tag: u32,
        attrs: Vec<PathAttribute>,
    ) -> rustbgpd_wire::EvpnRouteKey {
        use rustbgpd_wire::{EthernetTagId, EvpnImet, EvpnRoute, RouteDistinguisher};
        let route = EvpnRoute::Imet(EvpnImet {
            rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 100]),
            ethernet_tag: EthernetTagId(ethernet_tag),
            originator_ip: IpAddr::V4(peer),
        });
        let key = route.key();
        rib.insert_evpn(EvpnRibRoute {
            route,
            next_hop: IpAddr::V4(peer),
            link_local_next_hop: None,
            peer: IpAddr::V4(peer),
            attributes: Arc::new(attrs),
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ibgp,
            peer_router_id: peer,
            is_stale: false,
            is_llgr_stale: false,
        });
        key
    }

    #[test]
    fn mark_stale_evpn_tags_l2vpn_evpn_only() {
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer_ip);

        // Mix of unicast + EVPN routes
        rib.insert(make_route(
            Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24),
            Ipv4Addr::new(10, 0, 0, 1),
        ));
        let evpn_key = insert_evpn_imet(&mut rib, Ipv4Addr::new(10, 0, 0, 1), 100, vec![]);

        // Non-EVPN family: EVPN routes stay non-stale
        rib.mark_stale_evpn((Afi::Ipv4, Safi::Unicast));
        assert!(!rib.iter_evpn().any(|r| r.is_stale));

        // EVPN family: EVPN routes become stale
        rib.mark_stale_evpn((Afi::L2Vpn, Safi::Evpn));
        assert!(rib.iter_evpn().all(|r| r.is_stale));

        // And unicast routes are untouched by mark_stale_evpn
        assert!(!rib.iter().any(|r| r.is_stale));

        // Sanity: the EVPN key is still present
        assert_eq!(rib.evpn_len(), 1);
        let _ = evpn_key;
    }

    #[test]
    fn clear_stale_evpn_strips_local_llgr_community() {
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer_ip);
        let key = insert_evpn_imet(&mut rib, Ipv4Addr::new(10, 0, 0, 1), 100, vec![]);

        // Stale → promote → LLGR_STALE community locally injected
        rib.mark_stale_evpn((Afi::L2Vpn, Safi::Evpn));
        rib.promote_to_llgr_stale_evpn((Afi::L2Vpn, Safi::Evpn));
        let promoted = &rib.evpn_routes[&key];
        assert!(promoted.is_llgr_stale);
        assert!(promoted.communities().contains(&COMMUNITY_LLGR_STALE));

        // clear_stale strips both flags and the locally-injected community
        rib.clear_stale_evpn((Afi::L2Vpn, Safi::Evpn));
        let route = &rib.evpn_routes[&key];
        assert!(!route.is_stale);
        assert!(!route.is_llgr_stale);
        assert!(!route.communities().contains(&COMMUNITY_LLGR_STALE));
    }

    #[test]
    fn clear_stale_evpn_preserves_peer_originated_llgr_community() {
        // Route arrives *already* carrying LLGR_STALE (peer injected it, e.g.
        // during its own LLGR window). Our clear_stale_evpn must not strip it.
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer_ip);
        let peer_attrs = vec![PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE])];
        let key = insert_evpn_imet(&mut rib, Ipv4Addr::new(10, 0, 0, 1), 100, peer_attrs);

        // Mark stale without going through promotion — no local tag inserted.
        rib.mark_stale_evpn((Afi::L2Vpn, Safi::Evpn));
        assert!(rib.evpn_routes[&key].is_stale);

        rib.clear_stale_evpn((Afi::L2Vpn, Safi::Evpn));
        let route = &rib.evpn_routes[&key];
        assert!(!route.is_stale);
        // Peer-originated LLGR_STALE community preserved.
        assert!(route.communities().contains(&COMMUNITY_LLGR_STALE));
    }

    #[test]
    fn insert_evpn_clears_llgr_stale_local_tag_on_readvertise() {
        // Regression: promotion injects LLGR_STALE locally and records the key
        // in evpn_llgr_stale_local_tags. If the peer RE-ADVERTISES the same key
        // during LLGR recovery, insert_evpn must drop that tag — otherwise the
        // subsequent EoR (clear_llgr_stale_evpn) strips a peer-originated
        // LLGR_STALE off the fresh route, mistaking it for our local injection.
        // (Unicast `insert` and FlowSpec `insert_flowspec` already clear their
        // stale tags on the same path.)
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer_ip);
        let key = insert_evpn_imet(&mut rib, Ipv4Addr::new(10, 0, 0, 1), 100, vec![]);

        rib.mark_stale_evpn((Afi::L2Vpn, Safi::Evpn));
        rib.promote_to_llgr_stale_evpn((Afi::L2Vpn, Safi::Evpn));
        assert!(
            rib.evpn_llgr_stale_local_tags.contains(&key),
            "promotion should record the local LLGR_STALE injection"
        );

        // Peer re-advertises the same key, itself carrying LLGR_STALE.
        let readvertised = insert_evpn_imet(
            &mut rib,
            Ipv4Addr::new(10, 0, 0, 1),
            100,
            vec![PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE])],
        );
        assert_eq!(readvertised, key);
        assert!(
            !rib.evpn_llgr_stale_local_tags.contains(&key),
            "re-advertise must clear the stale local tag"
        );

        // EoR: the peer-originated LLGR_STALE must survive.
        rib.clear_llgr_stale_evpn((Afi::L2Vpn, Safi::Evpn));
        assert!(
            rib.evpn_routes[&key]
                .communities()
                .contains(&COMMUNITY_LLGR_STALE),
            "peer-originated LLGR_STALE was wrongly stripped from the re-advertised route"
        );
    }

    #[test]
    fn withdraw_evpn_clears_llgr_stale_local_tag() {
        // A withdrawn key can no longer carry a locally-injected LLGR_STALE
        // tag; leaving it set would mistag a later re-insert at the same key.
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer_ip);
        let key = insert_evpn_imet(&mut rib, Ipv4Addr::new(10, 0, 0, 1), 100, vec![]);
        rib.mark_stale_evpn((Afi::L2Vpn, Safi::Evpn));
        rib.promote_to_llgr_stale_evpn((Afi::L2Vpn, Safi::Evpn));
        assert!(rib.evpn_llgr_stale_local_tags.contains(&key));

        assert!(rib.withdraw_evpn(&key));
        assert!(
            !rib.evpn_llgr_stale_local_tags.contains(&key),
            "withdraw must clear the stale local tag"
        );
    }

    #[test]
    fn promote_to_llgr_stale_evpn_drops_no_llgr_routes() {
        use rustbgpd_wire::COMMUNITY_NO_LLGR;

        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer_ip);
        let keep_key = insert_evpn_imet(&mut rib, Ipv4Addr::new(10, 0, 0, 1), 100, vec![]);
        let no_llgr_key = insert_evpn_imet(
            &mut rib,
            Ipv4Addr::new(10, 0, 0, 1),
            200,
            vec![PathAttribute::Communities(vec![COMMUNITY_NO_LLGR])],
        );

        rib.mark_stale_evpn((Afi::L2Vpn, Safi::Evpn));
        let affected = rib.promote_to_llgr_stale_evpn((Afi::L2Vpn, Safi::Evpn));

        // NO_LLGR route removed entirely
        assert!(!rib.evpn_routes.contains_key(&no_llgr_key));
        // Other route promoted to LLGR-stale
        assert!(rib.evpn_routes[&keep_key].is_llgr_stale);
        assert!(
            rib.evpn_routes[&keep_key]
                .communities()
                .contains(&COMMUNITY_LLGR_STALE)
        );
        // Both keys should appear in affected (NO_LLGR drop + promotion)
        assert!(affected.contains(&keep_key));
        assert!(affected.contains(&no_llgr_key));
    }

    #[test]
    fn promote_to_llgr_stale_evpn_arc_make_mut_preserves_other_routes() {
        // Two routes share an Arc<Vec<PathAttribute>> via the intern table.
        // Promoting one must only mutate that route's copy, not the shared
        // Arc — otherwise both routes would gain LLGR_STALE when only one
        // is being promoted.
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer_ip);
        // Both routes get identical attrs → interned to the same Arc
        let key_a = insert_evpn_imet(&mut rib, Ipv4Addr::new(10, 0, 0, 1), 100, vec![]);
        let key_b = insert_evpn_imet(&mut rib, Ipv4Addr::new(10, 0, 0, 1), 200, vec![]);

        // Confirm they actually share the Arc pre-promotion
        let before_a = Arc::as_ptr(&rib.evpn_routes[&key_a].attributes);
        let before_b = Arc::as_ptr(&rib.evpn_routes[&key_b].attributes);
        assert_eq!(
            before_a, before_b,
            "intern table should have shared the Arc"
        );

        // Mark only route A stale, promote — route B must NOT gain LLGR_STALE
        rib.evpn_routes.get_mut(&key_a).unwrap().is_stale = true;
        rib.promote_to_llgr_stale_evpn((Afi::L2Vpn, Safi::Evpn));

        assert!(
            rib.evpn_routes[&key_a]
                .communities()
                .contains(&COMMUNITY_LLGR_STALE)
        );
        assert!(
            !rib.evpn_routes[&key_b]
                .communities()
                .contains(&COMMUNITY_LLGR_STALE),
            "route B was not stale — must not be mutated"
        );
    }

    #[test]
    fn sweep_stale_family_evpn_ignores_non_evpn_family() {
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer_ip);
        let key = insert_evpn_imet(&mut rib, Ipv4Addr::new(10, 0, 0, 1), 100, vec![]);
        rib.evpn_routes.get_mut(&key).unwrap().is_stale = true;

        // Non-EVPN family: no-op
        let swept = rib.sweep_stale_family_evpn((Afi::Ipv4, Safi::Unicast));
        assert!(swept.is_empty());
        assert_eq!(rib.evpn_len(), 1);

        // EVPN family: sweeps the stale route
        let swept = rib.sweep_stale_family_evpn((Afi::L2Vpn, Safi::Evpn));
        assert_eq!(swept, vec![key]);
        assert_eq!(rib.evpn_len(), 0);
    }
}
