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
use rustbgpd_wire::{Afi, EvpnRouteKey, PathAttribute, Prefix, Safi};
use rustc_hash::{FxBuildHasher, FxHashMap as HashMap, FxHashSet as HashSet};
use smallvec::SmallVec;

use crate::prefix_map::FamilyPrefixMap;
use crate::route::{
    BgpLsFamily, BgpLsRibRoute, BgpLsRouteKey, EvpnRibRoute, FlowSpecKey, FlowSpecRoute,
    FlowSpecRouteKey, LabeledRibRoute, LabeledRibRouteKey, Route, RtcRibRoute, RtcRibRouteKey,
    VpnRibRoute, VpnRibRouteKey,
};
use crate::slab::RouteSlab;
use crate::update::{RouteQueryKey, route_query_key};

/// Per-peer Adj-RIB-In: stores the routes received from a single peer.
///
/// Routes are keyed by `(Prefix, path_id)` to support Add-Path (RFC 7911).
/// Non-Add-Path peers always use `path_id = 0`.
///
/// A secondary `prefix_index` maps each prefix to its path IDs,
/// enabling O(candidates) `iter_prefix()` lookups instead of O(N) full scans.
///
/// Path attribute interning happens *before* routes reach this table: the
/// RIB manager deduplicates identical `Arc<Vec<PathAttribute>>` allocations
/// across ALL peers through its global [`crate::attr_intern::AttrInternTable`]
/// (LAN-336), so this struct only stores whatever `Arc`s it is handed.
#[derive(Debug)]
pub struct AdjRibIn {
    peer: IpAddr,
    /// Unicast route bodies, stored densely behind `u32` handles (LAN-335).
    /// The `(prefix, path_id)` identity lives on the routes themselves and in
    /// `prefix_index`; there is no separate keyed route map — a hashbrown
    /// bucket array carrying inline `Route` values was the dominant heap cost
    /// at high N (docs/perf/rebaseline-2026-07.md).
    routes: RouteSlab<Route>,
    /// Primary index: prefix → `(path_id, slab handle)` pairs stored for that
    /// prefix, backed by a family-split prefix trie. `SmallVec<[(u32, u32); 1]>`
    /// inlines the single-path case (`path_id=0`, no Add-Path) without a
    /// per-prefix heap allocation; Add-Path multi-path spills to the heap
    /// transparently. Mirrors `AdjRibOut::prefix_path_ids`.
    prefix_index: FamilyPrefixMap<SmallVec<[(u32, u32); 1]>>,
    /// Route keys where `LLGR_STALE` was injected locally by this daemon.
    llgr_stale_local_tags: HashSet<(Prefix, u32)>,
    /// `FlowSpec` routes keyed by AFI, rule, and Add-Path ID.
    flowspec_routes: HashMap<FlowSpecRouteKey, FlowSpecRoute>,
    /// `FlowSpec` route keys where `LLGR_STALE` was injected locally.
    flowspec_llgr_stale_local_tags: HashSet<FlowSpecRouteKey>,
    /// EVPN routes keyed by RFC 7432 route identity.
    evpn_routes: HashMap<EvpnRouteKey, EvpnRibRoute>,
    /// BGP-LS routes keyed by opaque RFC 9552 route identity.
    bgpls_routes: HashMap<BgpLsRouteKey, BgpLsRibRoute>,
    /// VPNv4/VPNv6 routes keyed by RFC 4364 RD + prefix identity.
    vpn_routes: HashMap<VpnRibRouteKey, VpnRibRoute>,
    /// Secondary index: VPN RD+prefix identity → Add-Path path IDs stored for
    /// it (the SAFI 128 analog of `prefix_index`). `SmallVec<[u32; 1]>`
    /// inlines the non-Add-Path case (`path_id=0`) without heap allocation.
    vpn_key_index: HashMap<rustbgpd_wire::VpnRouteKey, SmallVec<[u32; 1]>>,
    /// Labeled-unicast routes keyed by RFC 8277 prefix + path-id identity.
    /// Deliberately separate from the unicast `routes` map (ADR-0077 §2).
    labeled_routes: HashMap<LabeledRibRouteKey, LabeledRibRoute>,
    /// Secondary index: labeled prefix → Add-Path path IDs stored for it
    /// (the SAFI 4 analog of `vpn_key_index`).
    labeled_key_index: HashMap<Prefix, SmallVec<[u32; 1]>>,
    /// RT-Constrain routes keyed by RFC 4684 RT membership identity.
    rtc_routes: HashMap<RtcRibRouteKey, RtcRibRoute>,
    /// EVPN route keys where `LLGR_STALE` was injected locally by this daemon
    /// during promotion from GR-stale → LLGR-stale. Used to distinguish
    /// locally-injected communities (which we strip on clear) from
    /// peer-originated ones (which must be preserved).
    evpn_llgr_stale_local_tags: HashSet<EvpnRouteKey>,
    /// BGP-LS route keys where `LLGR_STALE` was injected locally (see
    /// `evpn_llgr_stale_local_tags`).
    bgpls_llgr_stale_local_tags: HashSet<BgpLsRouteKey>,
    /// VPN route keys where `LLGR_STALE` was injected locally (see
    /// `evpn_llgr_stale_local_tags`).
    vpn_llgr_stale_local_tags: HashSet<VpnRibRouteKey>,
    /// Labeled-unicast route keys where `LLGR_STALE` was injected locally
    /// (see `evpn_llgr_stale_local_tags`).
    labeled_llgr_stale_local_tags: HashSet<LabeledRibRouteKey>,
    /// RTC route keys where `LLGR_STALE` was injected locally (see
    /// `evpn_llgr_stale_local_tags`).
    rtc_llgr_stale_local_tags: HashSet<RtcRibRouteKey>,
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
            routes: RouteSlab::with_capacity(route_capacity),
            prefix_index: FamilyPrefixMap::default(),
            llgr_stale_local_tags: HashSet::default(),
            flowspec_routes: HashMap::with_capacity_and_hasher(flowspec_capacity, FxBuildHasher),
            flowspec_llgr_stale_local_tags: HashSet::default(),
            evpn_routes: HashMap::default(),
            bgpls_routes: HashMap::default(),
            vpn_routes: HashMap::default(),
            vpn_key_index: HashMap::default(),
            labeled_routes: HashMap::default(),
            labeled_key_index: HashMap::default(),
            rtc_routes: HashMap::default(),
            evpn_llgr_stale_local_tags: HashSet::default(),
            bgpls_llgr_stale_local_tags: HashSet::default(),
            vpn_llgr_stale_local_tags: HashSet::default(),
            labeled_llgr_stale_local_tags: HashSet::default(),
            rtc_llgr_stale_local_tags: HashSet::default(),
        }
    }

    /// Return the peer address this RIB belongs to.
    #[must_use]
    pub fn peer(&self) -> IpAddr {
        self.peer
    }

    /// Insert or replace a route. Clears any stale tag on the key.
    ///
    /// Attribute interning is the caller's job: the RIB manager interns
    /// `route.attributes` through its global
    /// [`crate::attr_intern::AttrInternTable`] before insertion.
    ///
    /// Returns `true` if an existing route at the same `(prefix, path_id)` was
    /// replaced. A replacement may strand the previous route's interned
    /// attribute set, so a caller processing a batch should run
    /// [`crate::attr_intern::AttrInternTable::gc`] once afterwards when any
    /// insert returned `true` (see the unicast announce path in the RIB
    /// manager). A first-time insert orphans nothing, so the initial-load
    /// flood skips the GC.
    pub fn insert(&mut self, route: Route) -> bool {
        self.llgr_stale_local_tags
            .remove(&(route.prefix, route.path_id));

        let path_id = route.path_id;
        let ids = self.prefix_index.entry_or_default(route.prefix);
        if let Some((_, handle)) = ids.iter().find(|(id, _)| *id == path_id) {
            self.routes.set(*handle, route);
            true
        } else {
            let handle = self.routes.insert(route);
            ids.push((path_id, handle));
            false
        }
    }

    /// Withdraw a route by prefix and path ID. Returns `true` if it existed.
    pub fn withdraw(&mut self, prefix: &Prefix, path_id: u32) -> bool {
        self.llgr_stale_local_tags.remove(&(*prefix, path_id));
        self.remove_route_entry(prefix, path_id).is_some()
    }

    /// Slab handle for the route stored at `(prefix, path_id)`, if any.
    fn route_handle(&self, prefix: &Prefix, path_id: u32) -> Option<u32> {
        self.prefix_index
            .get(prefix)?
            .iter()
            .find(|(id, _)| *id == path_id)
            .map(|&(_, handle)| handle)
    }

    /// Remove a route from both the prefix index and the slab, freeing its
    /// slot. Every unicast removal path routes through here so the index and
    /// slab can never disagree.
    fn remove_route_entry(&mut self, prefix: &Prefix, path_id: u32) -> Option<Route> {
        let ids = self.prefix_index.get_mut(prefix)?;
        let pos = ids.iter().position(|(id, _)| *id == path_id)?;
        let (_, handle) = ids.swap_remove(pos);
        if ids.is_empty() {
            self.prefix_index.remove(prefix);
        }
        self.routes.remove(handle)
    }

    /// Remove every route from this Adj-RIB-In — unicast, `FlowSpec`, EVPN,
    /// BGP-LS, VPN, labeled-unicast, and RTC — plus all secondary indices
    /// and stale tags. Used when the per-peer Adj-RIB-In needs to be wiped
    /// without also dropping the [`AdjRibIn`] struct itself. The caller must
    /// follow up with [`crate::attr_intern::AttrInternTable::gc`] to reclaim
    /// attribute sets the dropped routes were the last users of.
    pub fn clear(&mut self) {
        self.routes.clear();
        self.prefix_index.clear();
        self.flowspec_routes.clear();
        self.evpn_routes.clear();
        self.bgpls_routes.clear();
        self.vpn_routes.clear();
        self.vpn_key_index.clear();
        self.labeled_routes.clear();
        self.labeled_key_index.clear();
        self.rtc_routes.clear();
        self.llgr_stale_local_tags.clear();
        self.flowspec_llgr_stale_local_tags.clear();
        self.evpn_llgr_stale_local_tags.clear();
        self.bgpls_llgr_stale_local_tags.clear();
        self.vpn_llgr_stale_local_tags.clear();
        self.labeled_llgr_stale_local_tags.clear();
        self.rtc_llgr_stale_local_tags.clear();
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

    /// Return `true` if no unicast routes are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Iterate over all stored routes.
    pub fn iter(&self) -> impl Iterator<Item = &Route> {
        self.routes.iter()
    }

    /// Iterate unicast routes in route-query identity order, beginning at
    /// the cursor prefix and excluding identities at or before `after`.
    ///
    /// The existing compact prefix trie supplies the ordered continuation;
    /// path handles are copied into a `SmallVec` and sorted per prefix so
    /// Add-Path insertion order cannot leak into API ordering. The normal
    /// single-path case stays inline and allocation-free.
    pub fn iter_ordered_from(&self, after: Option<RouteQueryKey>) -> impl Iterator<Item = &Route> {
        let routes = &self.routes;
        self.prefix_index
            .iter_from(after.map(|cursor| cursor.0))
            .flat_map(move |(_, ids)| {
                let mut ordered = ids.clone();
                ordered
                    .sort_unstable_by_key(|(_, handle)| routes.get(*handle).map(route_query_key));
                ordered
                    .into_iter()
                    .filter_map(move |(_, handle)| routes.get(handle))
            })
            .filter(move |route| after.is_none_or(|cursor| route_query_key(route) > cursor))
    }

    /// Iterate mutably over all stored routes.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Route> {
        self.routes.iter_mut()
    }

    /// Look up a route by prefix and path ID.
    #[must_use]
    pub fn get(&self, prefix: &Prefix, path_id: u32) -> Option<&Route> {
        self.routes.get(self.route_handle(prefix, path_id)?)
    }

    /// Iterate over all routes for a given prefix (all path IDs).
    ///
    /// Uses the prefix index for O(candidates) lookup instead of an O(N)
    /// full scan.
    pub fn iter_prefix(&self, prefix: &Prefix) -> impl Iterator<Item = &Route> {
        let routes = &self.routes;
        self.prefix_index
            .get(prefix)
            .into_iter()
            .flat_map(move |ids| {
                ids.iter()
                    .filter_map(move |&(_, handle)| routes.get(handle))
            })
    }

    /// Mark all routes matching the given address family as stale
    /// (RFC 4724 §4.1 helper retention on session drop).
    ///
    /// A route that is already *GR*-stale when a new mark arrives survived a
    /// previous restart without ever being refreshed and is deleted instead
    /// of re-marked (RFC 4724 §4.1: stale routes must not be retained across
    /// consecutive restarts). An *LLGR*-stale route is the RFC 9494
    /// exception: it is retained as-is across consecutive resets — neither
    /// deleted nor demoted back to GR-stale — until its original per-family
    /// Long-Lived Stale Time deadline (held by the manager) expires.
    /// Returns the deleted prefixes so the caller can withdraw them
    /// downstream.
    pub fn mark_stale(&mut self, family: (Afi, Safi)) -> Vec<Prefix> {
        let already_stale: Vec<(Prefix, u32)> = self
            .routes
            .iter()
            .filter(|r| r.is_stale && route_matches_family(r, family))
            .map(|r| (r.prefix, r.path_id))
            .collect();
        let mut deleted = Vec::new();
        for key in &already_stale {
            deleted.push(key.0);
            self.llgr_stale_local_tags.remove(key);
            self.remove_route_entry(&key.0, key.1);
        }
        for route in self.routes.iter_mut() {
            if route_matches_family(route, family) && !route.is_llgr_stale {
                route.is_stale = true;
            }
        }
        deleted
    }

    /// Clear the stale flag on routes matching the given address family.
    pub fn clear_stale(&mut self, family: (Afi, Safi)) {
        let mut clear_local_llgr = Vec::new();
        for route in self.routes.iter_mut() {
            if route_matches_family(route, family) {
                route.is_stale = false;
                route.is_llgr_stale = false;
                let key = (route.prefix, route.path_id);
                if self.llgr_stale_local_tags.contains(&key) {
                    clear_local_llgr.push(key);
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
            .filter(|r| !keep.iter().any(|&fam| route_matches_family(r, fam)))
            .map(|r| (r.prefix, r.path_id))
            .collect();
        let mut prefixes = Vec::new();
        for key in &to_remove {
            prefixes.push(key.0);
            self.llgr_stale_local_tags.remove(key);
            self.remove_route_entry(&key.0, key.1);
        }
        prefixes
    }

    /// Remove all stale routes, returning their prefixes.
    pub fn sweep_stale(&mut self) -> Vec<Prefix> {
        let stale: Vec<(Prefix, u32)> = self
            .routes
            .iter()
            .filter(|r| r.is_stale)
            .map(|r| (r.prefix, r.path_id))
            .collect();
        let mut prefixes = Vec::new();
        for key in &stale {
            prefixes.push(key.0);
            self.llgr_stale_local_tags.remove(key);
            self.remove_route_entry(&key.0, key.1);
        }
        prefixes
    }

    /// Remove stale routes for a specific family, returning their prefixes.
    /// Used when a family was in GR but not in the peer's LLGR capability.
    pub fn sweep_stale_family(&mut self, family: (Afi, Safi)) -> Vec<Prefix> {
        let stale: Vec<(Prefix, u32)> = self
            .routes
            .iter()
            .filter(|r| r.is_stale && route_matches_family(r, family))
            .map(|r| (r.prefix, r.path_id))
            .collect();
        let mut prefixes = Vec::new();
        for key in &stale {
            prefixes.push(key.0);
            self.llgr_stale_local_tags.remove(key);
            self.remove_route_entry(&key.0, key.1);
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
    pub fn promote_to_llgr_stale(
        &mut self,
        family: (Afi, Safi),
        attr_intern: &mut crate::attr_intern::AttrInternTable,
    ) -> Vec<Prefix> {
        use rustbgpd_wire::{COMMUNITY_LLGR_STALE, COMMUNITY_NO_LLGR, PathAttribute};

        // First pass: remove routes with NO_LLGR community
        let no_llgr_keys: Vec<(Prefix, u32)> = self
            .routes
            .iter()
            .filter(|r| {
                r.is_stale
                    && route_matches_family(r, family)
                    && r.communities().contains(&COMMUNITY_NO_LLGR)
            })
            .map(|r| (r.prefix, r.path_id))
            .collect();
        let mut affected: Vec<Prefix> = no_llgr_keys.iter().map(|(p, _)| *p).collect();
        for key in &no_llgr_keys {
            self.llgr_stale_local_tags.remove(key);
            self.remove_route_entry(&key.0, key.1);
        }

        // Second pass: promote remaining stale routes to LLGR-stale
        for route in self.routes.iter_mut() {
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
                attr_intern.intern(&mut route.attributes);
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
            .filter(|r| r.is_llgr_stale)
            .map(|r| (r.prefix, r.path_id))
            .collect();
        let mut prefixes = Vec::new();
        for key in &stale {
            prefixes.push(key.0);
            self.llgr_stale_local_tags.remove(key);
            self.remove_route_entry(&key.0, key.1);
        }
        prefixes
    }

    /// Remove LLGR-stale routes for a specific family, returning their
    /// prefixes. `EoR` during the LLGR phase deletes what was not
    /// re-advertised (RFC 4724 §4.1 via RFC 9494 §4.2).
    pub fn sweep_llgr_stale_family(&mut self, family: (Afi, Safi)) -> Vec<Prefix> {
        let stale: Vec<(Prefix, u32)> = self
            .routes
            .iter()
            .filter(|r| r.is_llgr_stale && route_matches_family(r, family))
            .map(|r| (r.prefix, r.path_id))
            .collect();
        let mut prefixes = Vec::new();
        for key in &stale {
            prefixes.push(key.0);
            self.llgr_stale_local_tags.remove(key);
            self.remove_route_entry(&key.0, key.1);
        }
        prefixes
    }

    /// Clear the LLGR-stale flag on routes matching the given family.
    /// Called when `EoR` is received during LLGR phase.
    pub fn clear_llgr_stale(&mut self, family: (Afi, Safi)) {
        let mut clear_local_llgr = Vec::new();
        for route in self.routes.iter_mut() {
            if route_matches_family(route, family) {
                route.is_llgr_stale = false;
                let key = (route.prefix, route.path_id);
                if self.llgr_stale_local_tags.contains(&key) {
                    clear_local_llgr.push(key);
                }
            }
        }
        self.clear_local_llgr_stale_community(&clear_local_llgr);
    }

    // --- FlowSpec methods ---

    /// Insert or replace a `FlowSpec` route.
    pub fn insert_flowspec(&mut self, route: FlowSpecRoute) {
        self.flowspec_llgr_stale_local_tags.remove(&route.key());
        self.flowspec_routes.insert(route.key(), route);
    }

    /// Withdraw a `FlowSpec` route by family-complete key.
    pub fn withdraw_flowspec(&mut self, key: &FlowSpecRouteKey) -> bool {
        self.flowspec_llgr_stale_local_tags.remove(key);
        self.flowspec_routes.remove(key).is_some()
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
    /// strands the previous interned set. Callers must run
    /// [`crate::attr_intern::AttrInternTable::gc`] after a batch of
    /// inserts/withdraws to reclaim it — see the EVPN
    /// announce/withdraw/inject paths in the RIB manager.
    ///
    /// Returns `true` if an existing route at the same key was replaced.
    pub fn insert_evpn(&mut self, route: EvpnRibRoute) -> bool {
        let key = route.key();
        // Re-advertising a key drops any record that *we* locally injected
        // LLGR_STALE on the prior version of it — exactly as unicast `insert`
        // and FlowSpec `insert_flowspec` clear their stale tags. Without this,
        // a later EoR (`clear_llgr_stale_evpn`) would treat this fresh route as
        // locally tagged and strip a peer-originated LLGR_STALE off it.
        self.evpn_llgr_stale_local_tags.remove(&key);
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
    ///
    /// A route that is *already* stale (GR or LLGR) when a new mark arrives
    /// survived a previous restart without ever being refreshed and is deleted
    /// instead of re-marked (RFC 4724 §4.1: stale routes must not be retained
    /// across consecutive restarts). Returns the deleted keys so the caller
    /// can withdraw them downstream.
    pub fn mark_stale_evpn(&mut self, family: (Afi, Safi)) -> Vec<EvpnRouteKey> {
        if family != (Afi::L2Vpn, Safi::Evpn) {
            return Vec::new();
        }
        let already_stale: Vec<EvpnRouteKey> = self
            .evpn_routes
            .iter()
            .filter(|(_, r)| r.is_stale)
            .map(|(k, _)| *k)
            .collect();
        for key in &already_stale {
            self.evpn_llgr_stale_local_tags.remove(key);
            self.evpn_routes.remove(key);
        }
        // LLGR-stale routes are retained as-is (RFC 9494: consecutive resets
        // neither delete nor re-mark them; the original deadline governs).
        for route in self.evpn_routes.values_mut() {
            if !route.is_llgr_stale {
                route.is_stale = true;
            }
        }
        already_stale
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
    pub fn promote_to_llgr_stale_evpn(
        &mut self,
        family: (Afi, Safi),
        attr_intern: &mut crate::attr_intern::AttrInternTable,
    ) -> Vec<EvpnRouteKey> {
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
                attr_intern.intern(&mut route.attributes);
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

    /// Remove LLGR-stale EVPN routes if `family == (L2Vpn, Evpn)`, returning
    /// their keys. `EoR` during the LLGR phase deletes what was not
    /// re-advertised (RFC 4724 §4.1 via RFC 9494 §4.2).
    pub fn sweep_llgr_stale_family_evpn(&mut self, family: (Afi, Safi)) -> Vec<EvpnRouteKey> {
        if family != (Afi::L2Vpn, Safi::Evpn) {
            return Vec::new();
        }
        self.sweep_llgr_stale_evpn()
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
    /// BGP-LS batch callers run [`crate::attr_intern::AttrInternTable::gc`]
    /// once after any replacement or real withdrawal, after Loc-RIB
    /// recomputation has dropped any selected-route clone.
    pub fn insert_bgpls(&mut self, route: BgpLsRibRoute) -> bool {
        let key = route.key();
        // Mirror unicast `insert` / `insert_evpn`: a re-advertised key drops
        // any record that *we* locally injected LLGR_STALE on its prior
        // version, so a later EoR never strips a peer-originated community.
        self.bgpls_llgr_stale_local_tags.remove(&key);
        self.bgpls_routes.insert(key, route).is_some()
    }

    /// Withdraw a BGP-LS route. Returns `true` if it existed.
    pub fn withdraw_bgpls(&mut self, key: &BgpLsRouteKey) -> bool {
        // A withdrawn key can no longer carry a locally-injected LLGR_STALE tag.
        self.bgpls_llgr_stale_local_tags.remove(key);
        self.bgpls_routes.remove(key).is_some()
    }

    /// Withdraw all BGP-LS routes from this Adj-RIB-In.
    ///
    /// BGP-LS GR/LLGR stale preservation is not wired into GR entry yet (the
    /// stale-lifecycle helpers below are the substrate), so GR entry uses this
    /// helper to make the conservative exclusion explicit instead of
    /// accidentally retaining stale controller-feed objects as live.
    pub fn withdraw_all_bgpls(&mut self) -> Vec<BgpLsRouteKey> {
        let keys: Vec<_> = self.bgpls_routes.keys().cloned().collect();
        self.bgpls_routes.clear();
        self.bgpls_llgr_stale_local_tags.clear();
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

    // --- BGP-LS GR/LLGR stale handling (RFC 4724 + RFC 9494) ---
    //
    // Follows the EVPN pattern: BgpLsRibRoute attributes are
    // Arc<Vec<PathAttribute>>, so community injection goes through
    // Arc::make_mut to preserve the intern-table sharing invariant.
    //
    // Unlike EVPN, BGP-LS spans two family tuples — (BgpLs, BgpLs) and
    // (BgpLs, BgpLsVpn) — which the GR capability lists separately, so every
    // helper filters by the exact tuple via BgpLsFamily.

    /// Mark BGP-LS routes of the given family tuple as stale (RFC 4724 §4.1
    /// helper retention on session drop).
    ///
    /// A route that is *already* stale (GR or LLGR) when a new mark arrives
    /// survived a previous restart without ever being refreshed and is deleted
    /// instead of re-marked (RFC 4724 §4.1: stale routes must not be retained
    /// across consecutive restarts). Returns the deleted keys so the caller
    /// can withdraw them downstream.
    pub fn mark_stale_bgpls(&mut self, family: (Afi, Safi)) -> Vec<BgpLsRouteKey> {
        let Some(fam) = BgpLsFamily::from_afi_safi(family.0, family.1) else {
            return Vec::new();
        };
        let already_stale: Vec<BgpLsRouteKey> = self
            .bgpls_routes
            .iter()
            .filter(|(_, r)| r.is_stale && r.family == fam)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &already_stale {
            self.bgpls_llgr_stale_local_tags.remove(key);
            self.bgpls_routes.remove(key);
        }
        // LLGR-stale routes are retained as-is (RFC 9494: consecutive resets
        // neither delete nor re-mark them; the original deadline governs).
        for route in self.bgpls_routes.values_mut() {
            if route.family == fam && !route.is_llgr_stale {
                route.is_stale = true;
            }
        }
        already_stale
    }

    /// Clear the stale flag on BGP-LS routes of the given family tuple (both
    /// `is_stale` and `is_llgr_stale`), stripping any locally-injected
    /// `LLGR_STALE` community. Peer-originated `LLGR_STALE` communities are
    /// preserved. Called when the session re-establishes (RFC 4724 §4.1).
    pub fn clear_stale_bgpls(&mut self, family: (Afi, Safi)) {
        let Some(fam) = BgpLsFamily::from_afi_safi(family.0, family.1) else {
            return;
        };
        let mut clear_local_llgr = Vec::new();
        for (key, route) in &mut self.bgpls_routes {
            if route.family == fam {
                route.is_stale = false;
                route.is_llgr_stale = false;
                if self.bgpls_llgr_stale_local_tags.contains(key) {
                    clear_local_llgr.push(key.clone());
                }
            }
        }
        self.clear_local_llgr_stale_bgpls_community(&clear_local_llgr);
    }

    /// Remove all stale BGP-LS routes (both tuples), returning their keys.
    /// Timer-expiry purge (RFC 4724 §4.1: stale routes deleted when the
    /// restart timer expires or `EoR` sweeps).
    pub fn sweep_stale_bgpls(&mut self) -> Vec<BgpLsRouteKey> {
        let stale: Vec<BgpLsRouteKey> = self
            .bgpls_routes
            .iter()
            .filter(|(_, r)| r.is_stale)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &stale {
            self.bgpls_llgr_stale_local_tags.remove(key);
            self.bgpls_routes.remove(key);
        }
        stale
    }

    /// Remove stale BGP-LS routes of the given family tuple, returning their
    /// keys. Used when a family was in GR but not in the peer's LLGR
    /// capability.
    pub fn sweep_stale_family_bgpls(&mut self, family: (Afi, Safi)) -> Vec<BgpLsRouteKey> {
        let Some(fam) = BgpLsFamily::from_afi_safi(family.0, family.1) else {
            return Vec::new();
        };
        let stale: Vec<BgpLsRouteKey> = self
            .bgpls_routes
            .iter()
            .filter(|(_, r)| r.is_stale && r.family == fam)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &stale {
            self.bgpls_llgr_stale_local_tags.remove(key);
            self.bgpls_routes.remove(key);
        }
        stale
    }

    /// Promote GR-stale BGP-LS routes of the given family tuple to LLGR-stale
    /// (RFC 9494 §4.2/§4.3).
    ///
    /// - Routes with `NO_LLGR` community are removed (must not enter LLGR).
    /// - Remaining stale routes: `is_stale=false`, `is_llgr_stale=true`,
    ///   `LLGR_STALE` community added via `Arc::make_mut`.
    ///
    /// Returns keys affected (for best-path recalc).
    pub fn promote_to_llgr_stale_bgpls(
        &mut self,
        family: (Afi, Safi),
        attr_intern: &mut crate::attr_intern::AttrInternTable,
    ) -> Vec<BgpLsRouteKey> {
        use rustbgpd_wire::{COMMUNITY_LLGR_STALE, COMMUNITY_NO_LLGR};

        let Some(fam) = BgpLsFamily::from_afi_safi(family.0, family.1) else {
            return Vec::new();
        };

        // First pass: remove routes carrying NO_LLGR
        let no_llgr_keys: Vec<BgpLsRouteKey> = self
            .bgpls_routes
            .iter()
            .filter(|(_, r)| {
                r.is_stale && r.family == fam && r.communities().contains(&COMMUNITY_NO_LLGR)
            })
            .map(|(k, _)| k.clone())
            .collect();
        let mut affected: Vec<BgpLsRouteKey> = no_llgr_keys.clone();
        for key in &no_llgr_keys {
            self.bgpls_llgr_stale_local_tags.remove(key);
            self.bgpls_routes.remove(key);
        }

        // Second pass: promote remaining stale routes to LLGR-stale
        for route in self.bgpls_routes.values_mut() {
            if route.is_stale && route.family == fam {
                route.is_stale = false;
                route.is_llgr_stale = true;
                let attrs = Arc::make_mut(&mut route.attributes);
                if let Some(PathAttribute::Communities(comms)) = attrs
                    .iter_mut()
                    .find(|a| matches!(a, PathAttribute::Communities(_)))
                {
                    if !comms.contains(&COMMUNITY_LLGR_STALE) {
                        comms.push(COMMUNITY_LLGR_STALE);
                        self.bgpls_llgr_stale_local_tags.insert(route.key());
                    }
                } else {
                    attrs.push(PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE]));
                    self.bgpls_llgr_stale_local_tags.insert(route.key());
                }
                attr_intern.intern(&mut route.attributes);
                affected.push(route.key());
            }
        }

        affected
    }

    /// Remove all LLGR-stale BGP-LS routes, returning their keys
    /// (RFC 9494 §4.3: LLGR timer expiry).
    pub fn sweep_llgr_stale_bgpls(&mut self) -> Vec<BgpLsRouteKey> {
        let stale: Vec<BgpLsRouteKey> = self
            .bgpls_routes
            .iter()
            .filter(|(_, r)| r.is_llgr_stale)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &stale {
            self.bgpls_llgr_stale_local_tags.remove(key);
            self.bgpls_routes.remove(key);
        }
        stale
    }

    /// Remove LLGR-stale BGP-LS routes of the given family tuple, returning
    /// their keys. `EoR` during the LLGR phase deletes what was not
    /// re-advertised (RFC 4724 §4.1 via RFC 9494 §4.2).
    pub fn sweep_llgr_stale_family_bgpls(&mut self, family: (Afi, Safi)) -> Vec<BgpLsRouteKey> {
        let Some(fam) = BgpLsFamily::from_afi_safi(family.0, family.1) else {
            return Vec::new();
        };
        let stale: Vec<BgpLsRouteKey> = self
            .bgpls_routes
            .iter()
            .filter(|(_, r)| r.is_llgr_stale && r.family == fam)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &stale {
            self.bgpls_llgr_stale_local_tags.remove(key);
            self.bgpls_routes.remove(key);
        }
        stale
    }

    /// Clear the LLGR-stale flag on BGP-LS routes of the given family tuple,
    /// stripping only locally-injected `LLGR_STALE` communities. Called when
    /// `EoR` is received during the LLGR phase (RFC 9494 §4.2).
    pub fn clear_llgr_stale_bgpls(&mut self, family: (Afi, Safi)) {
        let Some(fam) = BgpLsFamily::from_afi_safi(family.0, family.1) else {
            return;
        };
        let mut clear_local_llgr = Vec::new();
        for (key, route) in &mut self.bgpls_routes {
            if route.family == fam {
                route.is_llgr_stale = false;
                if self.bgpls_llgr_stale_local_tags.contains(key) {
                    clear_local_llgr.push(key.clone());
                }
            }
        }
        self.clear_local_llgr_stale_bgpls_community(&clear_local_llgr);
    }

    /// Insert or replace a VPNv4/VPNv6 route.
    ///
    /// Returns `true` if an existing route at the same RD + prefix + path-id was
    /// replaced. A replacement may strand the previous route's interned attribute
    /// set; VPN batch callers run [`crate::attr_intern::AttrInternTable::gc`]
    /// once after any replacement or real withdrawal, after Loc-RIB
    /// recomputation has dropped any selected-route clone.
    pub fn insert_vpn(&mut self, route: VpnRibRoute) -> bool {
        let key = route.key();
        // Mirror unicast `insert` / `insert_evpn`: a re-advertised key drops
        // any record that *we* locally injected LLGR_STALE on its prior
        // version, so a later EoR never strips a peer-originated community.
        self.vpn_llgr_stale_local_tags.remove(&key);
        let ids = self.vpn_key_index.entry(key.nlri_key).or_default();
        if !ids.contains(&key.path_id) {
            ids.push(key.path_id);
        }
        self.vpn_routes.insert(key, route).is_some()
    }

    /// Withdraw a VPN route. Returns `true` if it existed.
    pub fn withdraw_vpn(&mut self, key: &VpnRibRouteKey) -> bool {
        self.remove_vpn_entry(key)
    }

    /// Shared VPN removal: drops the route, its locally-injected LLGR tag,
    /// and its `vpn_key_index` entry. Every VPN removal path (withdraw and
    /// the GR/LLGR stale sweeps) must route through here so the secondary
    /// index never dangles.
    fn remove_vpn_entry(&mut self, key: &VpnRibRouteKey) -> bool {
        // A removed key can no longer carry a locally-injected LLGR_STALE tag.
        self.vpn_llgr_stale_local_tags.remove(key);
        let removed = self.vpn_routes.remove(key).is_some();
        if removed && let Some(ids) = self.vpn_key_index.get_mut(&key.nlri_key) {
            ids.retain(|id| *id != key.path_id);
            if ids.is_empty() {
                self.vpn_key_index.remove(&key.nlri_key);
            }
        }
        removed
    }

    /// Iterate the VPN routes stored for one RD+prefix identity across all
    /// Add-Path path IDs (the SAFI 128 analog of `iter_prefix`).
    pub fn iter_vpn_for_nlri<'a>(
        &'a self,
        nlri_key: &'a rustbgpd_wire::VpnRouteKey,
    ) -> impl Iterator<Item = &'a VpnRibRoute> + 'a {
        self.vpn_key_index
            .get(nlri_key)
            .into_iter()
            .flat_map(move |ids| {
                ids.iter().filter_map(move |path_id| {
                    self.vpn_routes.get(&VpnRibRouteKey {
                        nlri_key: *nlri_key,
                        path_id: *path_id,
                    })
                })
            })
    }

    /// Withdraw all VPN routes from this Adj-RIB-In.
    ///
    /// VPN GR/LLGR stale preservation is not wired into GR entry yet (the
    /// stale-lifecycle helpers below are the substrate), so GR entry uses this
    /// helper to make the conservative exclusion explicit instead of
    /// accidentally retaining stale controller-feed routes as live.
    pub fn withdraw_all_vpn(&mut self) -> Vec<VpnRibRouteKey> {
        let keys: Vec<_> = self.vpn_routes.keys().cloned().collect();
        self.vpn_routes.clear();
        self.vpn_key_index.clear();
        self.vpn_llgr_stale_local_tags.clear();
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

    // --- VPN GR/LLGR stale handling (RFC 4724 + RFC 9494) ---
    //
    // Follows the EVPN pattern: VpnRibRoute attributes are
    // Arc<Vec<PathAttribute>>, so community injection goes through
    // Arc::make_mut to preserve the intern-table sharing invariant.
    //
    // Unlike EVPN, VPN spans two family tuples — (Ipv4, MplsVpn) and
    // (Ipv6, MplsVpn) — which the GR capability lists separately, so every
    // helper filters by the exact tuple via VpnRibRoute::afi_safi().

    /// Mark VPN routes of the given family tuple as stale (RFC 4724 §4.1
    /// helper retention on session drop).
    ///
    /// A route that is *already* stale (GR or LLGR) when a new mark arrives
    /// survived a previous restart without ever being refreshed and is deleted
    /// instead of re-marked (RFC 4724 §4.1: stale routes must not be retained
    /// across consecutive restarts). Returns the deleted keys so the caller
    /// can withdraw them downstream.
    pub fn mark_stale_vpn(&mut self, family: (Afi, Safi)) -> Vec<VpnRibRouteKey> {
        if family.1 != Safi::MplsVpn {
            return Vec::new();
        }
        let already_stale: Vec<VpnRibRouteKey> = self
            .vpn_routes
            .iter()
            .filter(|(_, r)| r.is_stale && r.afi_safi() == family)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &already_stale {
            self.remove_vpn_entry(key);
        }
        // LLGR-stale routes are retained as-is (RFC 9494: consecutive resets
        // neither delete nor re-mark them; the original deadline governs).
        for route in self.vpn_routes.values_mut() {
            if route.afi_safi() == family && !route.is_llgr_stale {
                route.is_stale = true;
            }
        }
        already_stale
    }

    /// Clear the stale flag on VPN routes of the given family tuple (both
    /// `is_stale` and `is_llgr_stale`), stripping any locally-injected
    /// `LLGR_STALE` community. Peer-originated `LLGR_STALE` communities are
    /// preserved. Called when the session re-establishes (RFC 4724 §4.1).
    pub fn clear_stale_vpn(&mut self, family: (Afi, Safi)) {
        if family.1 != Safi::MplsVpn {
            return;
        }
        let mut clear_local_llgr = Vec::new();
        for (key, route) in &mut self.vpn_routes {
            if route.afi_safi() == family {
                route.is_stale = false;
                route.is_llgr_stale = false;
                if self.vpn_llgr_stale_local_tags.contains(key) {
                    clear_local_llgr.push(key.clone());
                }
            }
        }
        self.clear_local_llgr_stale_vpn_community(&clear_local_llgr);
    }

    /// Remove all stale VPN routes (both tuples), returning their keys.
    /// Timer-expiry purge (RFC 4724 §4.1: stale routes deleted when the
    /// restart timer expires or `EoR` sweeps).
    pub fn sweep_stale_vpn(&mut self) -> Vec<VpnRibRouteKey> {
        let stale: Vec<VpnRibRouteKey> = self
            .vpn_routes
            .iter()
            .filter(|(_, r)| r.is_stale)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &stale {
            self.remove_vpn_entry(key);
        }
        stale
    }

    /// Remove stale VPN routes of the given family tuple, returning their
    /// keys. Used when a family was in GR but not in the peer's LLGR
    /// capability.
    pub fn sweep_stale_family_vpn(&mut self, family: (Afi, Safi)) -> Vec<VpnRibRouteKey> {
        if family.1 != Safi::MplsVpn {
            return Vec::new();
        }
        let stale: Vec<VpnRibRouteKey> = self
            .vpn_routes
            .iter()
            .filter(|(_, r)| r.is_stale && r.afi_safi() == family)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &stale {
            self.remove_vpn_entry(key);
        }
        stale
    }

    /// Promote GR-stale VPN routes of the given family tuple to LLGR-stale
    /// (RFC 9494 §4.2/§4.3).
    ///
    /// - Routes with `NO_LLGR` community are removed (must not enter LLGR).
    /// - Remaining stale routes: `is_stale=false`, `is_llgr_stale=true`,
    ///   `LLGR_STALE` community added via `Arc::make_mut`.
    ///
    /// Returns keys affected (for best-path recalc).
    pub fn promote_to_llgr_stale_vpn(
        &mut self,
        family: (Afi, Safi),
        attr_intern: &mut crate::attr_intern::AttrInternTable,
    ) -> Vec<VpnRibRouteKey> {
        use rustbgpd_wire::{COMMUNITY_LLGR_STALE, COMMUNITY_NO_LLGR};

        if family.1 != Safi::MplsVpn {
            return Vec::new();
        }

        // First pass: remove routes carrying NO_LLGR
        let no_llgr_keys: Vec<VpnRibRouteKey> = self
            .vpn_routes
            .iter()
            .filter(|(_, r)| {
                r.is_stale && r.afi_safi() == family && r.communities().contains(&COMMUNITY_NO_LLGR)
            })
            .map(|(k, _)| k.clone())
            .collect();
        let mut affected: Vec<VpnRibRouteKey> = no_llgr_keys.clone();
        for key in &no_llgr_keys {
            self.remove_vpn_entry(key);
        }

        // Second pass: promote remaining stale routes to LLGR-stale
        for route in self.vpn_routes.values_mut() {
            if route.is_stale && route.afi_safi() == family {
                route.is_stale = false;
                route.is_llgr_stale = true;
                let attrs = Arc::make_mut(&mut route.attributes);
                if let Some(PathAttribute::Communities(comms)) = attrs
                    .iter_mut()
                    .find(|a| matches!(a, PathAttribute::Communities(_)))
                {
                    if !comms.contains(&COMMUNITY_LLGR_STALE) {
                        comms.push(COMMUNITY_LLGR_STALE);
                        self.vpn_llgr_stale_local_tags.insert(route.key());
                    }
                } else {
                    attrs.push(PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE]));
                    self.vpn_llgr_stale_local_tags.insert(route.key());
                }
                attr_intern.intern(&mut route.attributes);
                affected.push(route.key());
            }
        }

        affected
    }

    /// Remove all LLGR-stale VPN routes, returning their keys
    /// (RFC 9494 §4.3: LLGR timer expiry).
    pub fn sweep_llgr_stale_vpn(&mut self) -> Vec<VpnRibRouteKey> {
        let stale: Vec<VpnRibRouteKey> = self
            .vpn_routes
            .iter()
            .filter(|(_, r)| r.is_llgr_stale)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &stale {
            self.remove_vpn_entry(key);
        }
        stale
    }

    /// Remove LLGR-stale VPN routes of the given family tuple, returning
    /// their keys. `EoR` during the LLGR phase deletes what was not
    /// re-advertised (RFC 4724 §4.1 via RFC 9494 §4.2).
    pub fn sweep_llgr_stale_family_vpn(&mut self, family: (Afi, Safi)) -> Vec<VpnRibRouteKey> {
        if family.1 != Safi::MplsVpn {
            return Vec::new();
        }
        let stale: Vec<VpnRibRouteKey> = self
            .vpn_routes
            .iter()
            .filter(|(_, r)| r.is_llgr_stale && r.afi_safi() == family)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &stale {
            self.remove_vpn_entry(key);
        }
        stale
    }

    /// Clear the LLGR-stale flag on VPN routes of the given family tuple,
    /// stripping only locally-injected `LLGR_STALE` communities. Called when
    /// `EoR` is received during the LLGR phase (RFC 9494 §4.2).
    pub fn clear_llgr_stale_vpn(&mut self, family: (Afi, Safi)) {
        if family.1 != Safi::MplsVpn {
            return;
        }
        let mut clear_local_llgr = Vec::new();
        for (key, route) in &mut self.vpn_routes {
            if route.afi_safi() == family {
                route.is_llgr_stale = false;
                if self.vpn_llgr_stale_local_tags.contains(key) {
                    clear_local_llgr.push(key.clone());
                }
            }
        }
        self.clear_local_llgr_stale_vpn_community(&clear_local_llgr);
    }

    /// Insert or replace a labeled-unicast route.
    ///
    /// Returns `true` if an existing route at the same prefix + path-id was
    /// replaced (RFC 8277 §2.3 implicit-replace: a relabel of the same prefix
    /// lands on the same key). A replacement may strand the previous route's
    /// interned attribute set; labeled batch callers run
    /// [`crate::attr_intern::AttrInternTable::gc`] once after any replacement
    /// or real withdrawal, after Loc-RIB recomputation has dropped any
    /// selected-route clone.
    pub fn insert_labeled(&mut self, route: LabeledRibRoute) -> bool {
        let key = route.key();
        // Mirror unicast `insert` / `insert_vpn`: a re-advertised key drops
        // any record that *we* locally injected LLGR_STALE on its prior
        // version, so a later EoR never strips a peer-originated community.
        self.labeled_llgr_stale_local_tags.remove(&key);
        let ids = self.labeled_key_index.entry(key.prefix).or_default();
        if !ids.contains(&key.path_id) {
            ids.push(key.path_id);
        }
        self.labeled_routes.insert(key, route).is_some()
    }

    /// Withdraw a labeled-unicast route. Returns `true` if it existed.
    pub fn withdraw_labeled(&mut self, key: &LabeledRibRouteKey) -> bool {
        self.remove_labeled_entry(key)
    }

    /// Shared labeled removal: drops the route, its locally-injected LLGR
    /// tag, and its `labeled_key_index` entry. Every labeled removal path
    /// (withdraw and the GR/LLGR stale sweeps) must route through here so
    /// the secondary index never dangles.
    fn remove_labeled_entry(&mut self, key: &LabeledRibRouteKey) -> bool {
        // A removed key can no longer carry a locally-injected LLGR_STALE tag.
        self.labeled_llgr_stale_local_tags.remove(key);
        let removed = self.labeled_routes.remove(key).is_some();
        if removed && let Some(ids) = self.labeled_key_index.get_mut(&key.prefix) {
            ids.retain(|id| *id != key.path_id);
            if ids.is_empty() {
                self.labeled_key_index.remove(&key.prefix);
            }
        }
        removed
    }

    /// Iterate the labeled routes stored for one prefix identity across all
    /// Add-Path path IDs (the SAFI 4 analog of `iter_vpn_for_nlri`).
    pub fn iter_labeled_for_prefix<'a>(
        &'a self,
        prefix: &'a Prefix,
    ) -> impl Iterator<Item = &'a LabeledRibRoute> + 'a {
        self.labeled_key_index
            .get(prefix)
            .into_iter()
            .flat_map(move |ids| {
                ids.iter().filter_map(move |path_id| {
                    self.labeled_routes.get(&LabeledRibRouteKey {
                        prefix: *prefix,
                        path_id: *path_id,
                    })
                })
            })
    }

    /// Withdraw all labeled-unicast routes from this Adj-RIB-In.
    pub fn withdraw_all_labeled(&mut self) -> Vec<LabeledRibRouteKey> {
        let keys: Vec<_> = self.labeled_routes.keys().copied().collect();
        self.labeled_routes.clear();
        self.labeled_key_index.clear();
        self.labeled_llgr_stale_local_tags.clear();
        keys
    }

    /// Look up a labeled route by prefix + path-id key.
    #[must_use]
    pub fn get_labeled(&self, key: &LabeledRibRouteKey) -> Option<&LabeledRibRoute> {
        self.labeled_routes.get(key)
    }

    /// Iterate over all labeled routes in this Adj-RIB-In.
    pub fn iter_labeled(&self) -> impl Iterator<Item = &LabeledRibRoute> {
        self.labeled_routes.values()
    }

    /// Return the number of labeled routes stored.
    #[must_use]
    pub fn labeled_len(&self) -> usize {
        self.labeled_routes.len()
    }

    // --- Labeled-unicast GR/LLGR stale handling (RFC 4724 + RFC 9494) ---
    //
    // Follows the VPN pattern: LabeledRibRoute attributes are
    // Arc<Vec<PathAttribute>>, so community injection goes through
    // Arc::make_mut to preserve the intern-table sharing invariant.
    //
    // Like VPN, labeled-unicast spans two family tuples — (Ipv4,
    // LabeledUnicast) and (Ipv6, LabeledUnicast) — which the GR capability
    // lists separately, so every helper filters by the exact tuple via
    // LabeledRibRoute::afi_safi().

    /// Mark labeled routes of the given family tuple as stale (RFC 4724 §4.1
    /// helper retention on session drop).
    ///
    /// A route that is *already* stale (GR or LLGR) when a new mark arrives
    /// survived a previous restart without ever being refreshed and is deleted
    /// instead of re-marked (RFC 4724 §4.1: stale routes must not be retained
    /// across consecutive restarts). Returns the deleted keys so the caller
    /// can withdraw them downstream.
    pub fn mark_stale_labeled(&mut self, family: (Afi, Safi)) -> Vec<LabeledRibRouteKey> {
        if family.1 != Safi::LabeledUnicast {
            return Vec::new();
        }
        let already_stale: Vec<LabeledRibRouteKey> = self
            .labeled_routes
            .iter()
            .filter(|(_, r)| r.is_stale && r.afi_safi() == family)
            .map(|(k, _)| *k)
            .collect();
        for key in &already_stale {
            self.remove_labeled_entry(key);
        }
        // LLGR-stale routes are retained as-is (RFC 9494: consecutive resets
        // neither delete nor re-mark them; the original deadline governs).
        for route in self.labeled_routes.values_mut() {
            if route.afi_safi() == family && !route.is_llgr_stale {
                route.is_stale = true;
            }
        }
        already_stale
    }

    /// Clear the stale flag on labeled routes of the given family tuple (both
    /// `is_stale` and `is_llgr_stale`), stripping any locally-injected
    /// `LLGR_STALE` community. Peer-originated `LLGR_STALE` communities are
    /// preserved. Called when the session re-establishes (RFC 4724 §4.1).
    pub fn clear_stale_labeled(&mut self, family: (Afi, Safi)) {
        if family.1 != Safi::LabeledUnicast {
            return;
        }
        let mut clear_local_llgr = Vec::new();
        for (key, route) in &mut self.labeled_routes {
            if route.afi_safi() == family {
                route.is_stale = false;
                route.is_llgr_stale = false;
                if self.labeled_llgr_stale_local_tags.contains(key) {
                    clear_local_llgr.push(*key);
                }
            }
        }
        self.clear_local_llgr_stale_labeled_community(&clear_local_llgr);
    }

    /// Remove all stale labeled routes (both tuples), returning their keys.
    /// Timer-expiry purge (RFC 4724 §4.1: stale routes deleted when the
    /// restart timer expires or `EoR` sweeps).
    pub fn sweep_stale_labeled(&mut self) -> Vec<LabeledRibRouteKey> {
        let stale: Vec<LabeledRibRouteKey> = self
            .labeled_routes
            .iter()
            .filter(|(_, r)| r.is_stale)
            .map(|(k, _)| *k)
            .collect();
        for key in &stale {
            self.remove_labeled_entry(key);
        }
        stale
    }

    /// Remove stale labeled routes of the given family tuple, returning their
    /// keys. Used when a family was in GR but not in the peer's LLGR
    /// capability.
    pub fn sweep_stale_family_labeled(&mut self, family: (Afi, Safi)) -> Vec<LabeledRibRouteKey> {
        if family.1 != Safi::LabeledUnicast {
            return Vec::new();
        }
        let stale: Vec<LabeledRibRouteKey> = self
            .labeled_routes
            .iter()
            .filter(|(_, r)| r.is_stale && r.afi_safi() == family)
            .map(|(k, _)| *k)
            .collect();
        for key in &stale {
            self.remove_labeled_entry(key);
        }
        stale
    }

    /// Promote GR-stale labeled routes of the given family tuple to
    /// LLGR-stale (RFC 9494 §4.2/§4.3).
    ///
    /// - Routes with `NO_LLGR` community are removed (must not enter LLGR).
    /// - Remaining stale routes: `is_stale=false`, `is_llgr_stale=true`,
    ///   `LLGR_STALE` community added via `Arc::make_mut`.
    ///
    /// Returns keys affected (for best-path recalc).
    pub fn promote_to_llgr_stale_labeled(
        &mut self,
        family: (Afi, Safi),
        attr_intern: &mut crate::attr_intern::AttrInternTable,
    ) -> Vec<LabeledRibRouteKey> {
        use rustbgpd_wire::{COMMUNITY_LLGR_STALE, COMMUNITY_NO_LLGR};

        if family.1 != Safi::LabeledUnicast {
            return Vec::new();
        }

        // First pass: remove routes carrying NO_LLGR
        let no_llgr_keys: Vec<LabeledRibRouteKey> = self
            .labeled_routes
            .iter()
            .filter(|(_, r)| {
                r.is_stale && r.afi_safi() == family && r.communities().contains(&COMMUNITY_NO_LLGR)
            })
            .map(|(k, _)| *k)
            .collect();
        let mut affected: Vec<LabeledRibRouteKey> = no_llgr_keys.clone();
        for key in &no_llgr_keys {
            self.remove_labeled_entry(key);
        }

        // Second pass: promote remaining stale routes to LLGR-stale
        for route in self.labeled_routes.values_mut() {
            if route.is_stale && route.afi_safi() == family {
                route.is_stale = false;
                route.is_llgr_stale = true;
                let attrs = Arc::make_mut(&mut route.attributes);
                if let Some(PathAttribute::Communities(comms)) = attrs
                    .iter_mut()
                    .find(|a| matches!(a, PathAttribute::Communities(_)))
                {
                    if !comms.contains(&COMMUNITY_LLGR_STALE) {
                        comms.push(COMMUNITY_LLGR_STALE);
                        self.labeled_llgr_stale_local_tags.insert(route.key());
                    }
                } else {
                    attrs.push(PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE]));
                    self.labeled_llgr_stale_local_tags.insert(route.key());
                }
                attr_intern.intern(&mut route.attributes);
                affected.push(route.key());
            }
        }

        affected
    }

    /// Remove all LLGR-stale labeled routes, returning their keys
    /// (RFC 9494 §4.3: LLGR timer expiry).
    pub fn sweep_llgr_stale_labeled(&mut self) -> Vec<LabeledRibRouteKey> {
        let stale: Vec<LabeledRibRouteKey> = self
            .labeled_routes
            .iter()
            .filter(|(_, r)| r.is_llgr_stale)
            .map(|(k, _)| *k)
            .collect();
        for key in &stale {
            self.remove_labeled_entry(key);
        }
        stale
    }

    /// Remove LLGR-stale labeled routes of the given family tuple, returning
    /// their keys. `EoR` during the LLGR phase deletes what was not
    /// re-advertised (RFC 4724 §4.1 via RFC 9494 §4.2).
    pub fn sweep_llgr_stale_family_labeled(
        &mut self,
        family: (Afi, Safi),
    ) -> Vec<LabeledRibRouteKey> {
        if family.1 != Safi::LabeledUnicast {
            return Vec::new();
        }
        let stale: Vec<LabeledRibRouteKey> = self
            .labeled_routes
            .iter()
            .filter(|(_, r)| r.is_llgr_stale && r.afi_safi() == family)
            .map(|(k, _)| *k)
            .collect();
        for key in &stale {
            self.remove_labeled_entry(key);
        }
        stale
    }

    /// Clear the LLGR-stale flag on labeled routes of the given family tuple,
    /// stripping only locally-injected `LLGR_STALE` communities. Called when
    /// `EoR` is received during the LLGR phase (RFC 9494 §4.2).
    pub fn clear_llgr_stale_labeled(&mut self, family: (Afi, Safi)) {
        if family.1 != Safi::LabeledUnicast {
            return;
        }
        let mut clear_local_llgr = Vec::new();
        for (key, route) in &mut self.labeled_routes {
            if route.afi_safi() == family {
                route.is_llgr_stale = false;
                if self.labeled_llgr_stale_local_tags.contains(key) {
                    clear_local_llgr.push(*key);
                }
            }
        }
        self.clear_local_llgr_stale_labeled_community(&clear_local_llgr);
    }

    /// Insert or replace an RT-Constrain route.
    ///
    /// Returns `true` if an existing route at the same NLRI + path-id was
    /// replaced. A replacement may strand the previous route's interned
    /// attribute set; RTC batch callers run
    /// [`crate::attr_intern::AttrInternTable::gc`] once after any replacement
    /// or real withdrawal, after Loc-RIB recomputation has dropped any
    /// selected-route clone.
    pub fn insert_rtc(&mut self, route: RtcRibRoute) -> bool {
        let key = route.key();
        // Mirror unicast `insert` / `insert_evpn`: a re-advertised key drops
        // any record that *we* locally injected LLGR_STALE on its prior
        // version, so a later EoR never strips a peer-originated community.
        self.rtc_llgr_stale_local_tags.remove(&key);
        self.rtc_routes.insert(key, route).is_some()
    }

    /// Withdraw an RTC route. Returns `true` if it existed.
    pub fn withdraw_rtc(&mut self, key: &RtcRibRouteKey) -> bool {
        // A withdrawn key can no longer carry a locally-injected LLGR_STALE tag.
        self.rtc_llgr_stale_local_tags.remove(key);
        self.rtc_routes.remove(key).is_some()
    }

    /// Withdraw all RTC routes from this Adj-RIB-In.
    ///
    /// RTC GR/LLGR stale preservation is not wired into GR entry yet (the
    /// stale-lifecycle helpers below are the substrate), so GR entry uses this
    /// helper to make the conservative exclusion explicit instead of
    /// accidentally retaining stale membership routes as live.
    pub fn withdraw_all_rtc(&mut self) -> Vec<RtcRibRouteKey> {
        let keys: Vec<_> = self.rtc_routes.keys().cloned().collect();
        self.rtc_routes.clear();
        self.rtc_llgr_stale_local_tags.clear();
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

    // --- RTC GR/LLGR stale handling (RFC 4724 + RFC 9494) ---
    //
    // Follows the EVPN pattern: RtcRibRoute attributes are
    // Arc<Vec<PathAttribute>>, so community injection goes through
    // Arc::make_mut to preserve the intern-table sharing invariant.
    //
    // Like EVPN, RTC has a single family tuple (Ipv4, RtConstrain), so family
    // match checks reduce to direct equality.

    /// Mark all RTC routes as stale if `family == (Ipv4, RtConstrain)`
    /// (RFC 4724 §4.1 helper retention on session drop).
    ///
    /// A route that is *already* stale (GR or LLGR) when a new mark arrives
    /// survived a previous restart without ever being refreshed and is deleted
    /// instead of re-marked (RFC 4724 §4.1: stale routes must not be retained
    /// across consecutive restarts). Returns the deleted keys so the caller
    /// can withdraw them downstream.
    pub fn mark_stale_rtc(&mut self, family: (Afi, Safi)) -> Vec<RtcRibRouteKey> {
        if family != RtcRibRouteKey::afi_safi() {
            return Vec::new();
        }
        let already_stale: Vec<RtcRibRouteKey> = self
            .rtc_routes
            .iter()
            .filter(|(_, r)| r.is_stale)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &already_stale {
            self.rtc_llgr_stale_local_tags.remove(key);
            self.rtc_routes.remove(key);
        }
        // LLGR-stale routes are retained as-is (RFC 9494: consecutive resets
        // neither delete nor re-mark them; the original deadline governs).
        for route in self.rtc_routes.values_mut() {
            if !route.is_llgr_stale {
                route.is_stale = true;
            }
        }
        already_stale
    }

    /// Clear the stale flag on RTC routes (both `is_stale` and
    /// `is_llgr_stale`), stripping any locally-injected `LLGR_STALE`
    /// community. Peer-originated `LLGR_STALE` communities are preserved.
    /// Called when the session re-establishes (RFC 4724 §4.1).
    pub fn clear_stale_rtc(&mut self, family: (Afi, Safi)) {
        if family != RtcRibRouteKey::afi_safi() {
            return;
        }
        let mut clear_local_llgr = Vec::new();
        for (key, route) in &mut self.rtc_routes {
            route.is_stale = false;
            route.is_llgr_stale = false;
            if self.rtc_llgr_stale_local_tags.contains(key) {
                clear_local_llgr.push(key.clone());
            }
        }
        self.clear_local_llgr_stale_rtc_community(&clear_local_llgr);
    }

    /// Remove all stale RTC routes, returning their keys. Timer-expiry purge
    /// (RFC 4724 §4.1: stale routes deleted when the restart timer expires or
    /// `EoR` sweeps).
    pub fn sweep_stale_rtc(&mut self) -> Vec<RtcRibRouteKey> {
        let stale: Vec<RtcRibRouteKey> = self
            .rtc_routes
            .iter()
            .filter(|(_, r)| r.is_stale)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &stale {
            self.rtc_llgr_stale_local_tags.remove(key);
            self.rtc_routes.remove(key);
        }
        stale
    }

    /// Remove stale RTC routes if `family == (Ipv4, RtConstrain)`. Used when
    /// a family was in GR but not in the peer's LLGR capability.
    pub fn sweep_stale_family_rtc(&mut self, family: (Afi, Safi)) -> Vec<RtcRibRouteKey> {
        if family != RtcRibRouteKey::afi_safi() {
            return Vec::new();
        }
        self.sweep_stale_rtc()
    }

    /// Promote GR-stale RTC routes to LLGR-stale (RFC 9494 §4.2/§4.3).
    ///
    /// - Routes with `NO_LLGR` community are removed (must not enter LLGR).
    /// - Remaining stale routes: `is_stale=false`, `is_llgr_stale=true`,
    ///   `LLGR_STALE` community added via `Arc::make_mut`.
    ///
    /// Returns keys affected (for best-path recalc).
    pub fn promote_to_llgr_stale_rtc(
        &mut self,
        family: (Afi, Safi),
        attr_intern: &mut crate::attr_intern::AttrInternTable,
    ) -> Vec<RtcRibRouteKey> {
        use rustbgpd_wire::{COMMUNITY_LLGR_STALE, COMMUNITY_NO_LLGR};

        if family != RtcRibRouteKey::afi_safi() {
            return Vec::new();
        }

        // First pass: remove routes carrying NO_LLGR
        let no_llgr_keys: Vec<RtcRibRouteKey> = self
            .rtc_routes
            .iter()
            .filter(|(_, r)| r.is_stale && r.communities().contains(&COMMUNITY_NO_LLGR))
            .map(|(k, _)| k.clone())
            .collect();
        let mut affected: Vec<RtcRibRouteKey> = no_llgr_keys.clone();
        for key in &no_llgr_keys {
            self.rtc_llgr_stale_local_tags.remove(key);
            self.rtc_routes.remove(key);
        }

        // Second pass: promote remaining stale routes to LLGR-stale
        for route in self.rtc_routes.values_mut() {
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
                        self.rtc_llgr_stale_local_tags.insert(route.key());
                    }
                } else {
                    attrs.push(PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE]));
                    self.rtc_llgr_stale_local_tags.insert(route.key());
                }
                attr_intern.intern(&mut route.attributes);
                affected.push(route.key());
            }
        }

        affected
    }

    /// Remove all LLGR-stale RTC routes, returning their keys
    /// (RFC 9494 §4.3: LLGR timer expiry).
    pub fn sweep_llgr_stale_rtc(&mut self) -> Vec<RtcRibRouteKey> {
        let stale: Vec<RtcRibRouteKey> = self
            .rtc_routes
            .iter()
            .filter(|(_, r)| r.is_llgr_stale)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &stale {
            self.rtc_llgr_stale_local_tags.remove(key);
            self.rtc_routes.remove(key);
        }
        stale
    }

    /// Remove LLGR-stale RTC routes if `family == (Ipv4, RtConstrain)`,
    /// returning their keys. `EoR` during the LLGR phase deletes what was
    /// not re-advertised (RFC 4724 §4.1 via RFC 9494 §4.2).
    pub fn sweep_llgr_stale_family_rtc(&mut self, family: (Afi, Safi)) -> Vec<RtcRibRouteKey> {
        if family != RtcRibRouteKey::afi_safi() {
            return Vec::new();
        }
        self.sweep_llgr_stale_rtc()
    }

    /// Clear the LLGR-stale flag on RTC routes, stripping only
    /// locally-injected `LLGR_STALE` communities. Called when `EoR` is
    /// received during the LLGR phase (RFC 9494 §4.2).
    pub fn clear_llgr_stale_rtc(&mut self, family: (Afi, Safi)) {
        if family != RtcRibRouteKey::afi_safi() {
            return;
        }
        let mut clear_local_llgr = Vec::new();
        for (key, route) in &mut self.rtc_routes {
            route.is_llgr_stale = false;
            if self.rtc_llgr_stale_local_tags.contains(key) {
                clear_local_llgr.push(key.clone());
            }
        }
        self.clear_local_llgr_stale_rtc_community(&clear_local_llgr);
    }

    /// Iterate all `FlowSpec` routes matching a given rule (all path IDs).
    pub fn iter_flowspec_key<'a>(
        &'a self,
        key: &'a FlowSpecKey,
    ) -> impl Iterator<Item = &'a FlowSpecRoute> + 'a {
        self.flowspec_routes
            .values()
            .filter(move |route| route.afi == key.afi && route.rule == key.rule)
    }

    /// Return the number of `FlowSpec` routes stored.
    #[must_use]
    pub fn flowspec_len(&self) -> usize {
        self.flowspec_routes.len()
    }

    /// Mark `FlowSpec` routes matching the given address family as stale.
    ///
    /// A route that is *already* stale (GR or LLGR) when a new mark arrives
    /// survived a previous restart without ever being refreshed and is deleted
    /// instead of re-marked (RFC 4724 §4.1: stale routes must not be retained
    /// across consecutive restarts). Returns the deleted rules so the caller
    /// can withdraw them downstream.
    pub fn mark_stale_flowspec(&mut self, family: (Afi, Safi)) -> Vec<FlowSpecKey> {
        if family.1 != Safi::FlowSpec {
            return Vec::new();
        }
        let already_stale: Vec<FlowSpecRouteKey> = self
            .flowspec_routes
            .iter()
            .filter(|(_, r)| r.is_stale && r.afi == family.0)
            .map(|(k, _)| k.clone())
            .collect();
        let mut deleted = Vec::new();
        for key in &already_stale {
            deleted.push(FlowSpecKey {
                afi: key.afi,
                rule: key.rule.clone(),
            });
            self.flowspec_llgr_stale_local_tags.remove(key);
            self.flowspec_routes.remove(key);
        }
        // LLGR-stale routes are retained as-is (RFC 9494: consecutive resets
        // neither delete nor re-mark them; the original deadline governs).
        for route in self.flowspec_routes.values_mut() {
            if route.afi == family.0 && !route.is_llgr_stale {
                route.is_stale = true;
            }
        }
        deleted
    }

    /// Remove all stale `FlowSpec` routes, returning their rules.
    pub fn sweep_stale_flowspec(&mut self) -> Vec<FlowSpecKey> {
        let stale: Vec<FlowSpecRouteKey> = self
            .flowspec_routes
            .iter()
            .filter(|(_, r)| r.is_stale)
            .map(|(k, _)| k.clone())
            .collect();
        let mut rules = Vec::new();
        for key in &stale {
            rules.push(FlowSpecKey {
                afi: key.afi,
                rule: key.rule.clone(),
            });
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
    pub fn sweep_stale_flowspec_family(&mut self, family: (Afi, Safi)) -> Vec<FlowSpecKey> {
        if family.1 != Safi::FlowSpec {
            return Vec::new();
        }
        let stale: Vec<FlowSpecRouteKey> = self
            .flowspec_routes
            .iter()
            .filter(|(_, r)| r.is_stale && r.afi == family.0)
            .map(|(k, _)| k.clone())
            .collect();
        let mut rules = Vec::new();
        for key in &stale {
            rules.push(FlowSpecKey {
                afi: key.afi,
                rule: key.rule.clone(),
            });
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
    pub fn promote_to_llgr_stale_flowspec(&mut self, family: (Afi, Safi)) -> Vec<FlowSpecKey> {
        use rustbgpd_wire::{COMMUNITY_LLGR_STALE, COMMUNITY_NO_LLGR, PathAttribute};

        if family.1 != Safi::FlowSpec {
            return Vec::new();
        }

        // First pass: remove routes with NO_LLGR community
        let no_llgr_keys: Vec<FlowSpecRouteKey> = self
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
        let mut affected: Vec<FlowSpecKey> = no_llgr_keys
            .iter()
            .map(|key| FlowSpecKey {
                afi: key.afi,
                rule: key.rule.clone(),
            })
            .collect();
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
                        self.flowspec_llgr_stale_local_tags.insert(route.key());
                    }
                } else {
                    route
                        .attributes
                        .push(PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE]));
                    self.flowspec_llgr_stale_local_tags.insert(route.key());
                }
                affected.push(route.selection_key());
            }
        }

        affected
    }

    /// Remove all LLGR-stale `FlowSpec` routes, returning their rules.
    pub fn sweep_llgr_stale_flowspec(&mut self) -> Vec<FlowSpecKey> {
        let stale: Vec<FlowSpecRouteKey> = self
            .flowspec_routes
            .iter()
            .filter(|(_, r)| r.is_llgr_stale)
            .map(|(k, _)| k.clone())
            .collect();
        let mut rules = Vec::new();
        for key in &stale {
            rules.push(FlowSpecKey {
                afi: key.afi,
                rule: key.rule.clone(),
            });
            self.flowspec_llgr_stale_local_tags.remove(key);
            self.flowspec_routes.remove(key);
        }
        rules
    }

    /// Remove LLGR-stale `FlowSpec` routes for a specific family, returning
    /// their rules. `EoR` during the LLGR phase deletes what was not
    /// re-advertised (RFC 4724 §4.1 via RFC 9494 §4.2).
    pub fn sweep_llgr_stale_flowspec_family(&mut self, family: (Afi, Safi)) -> Vec<FlowSpecKey> {
        if family.1 != Safi::FlowSpec {
            return Vec::new();
        }
        let stale: Vec<FlowSpecRouteKey> = self
            .flowspec_routes
            .iter()
            .filter(|(_, r)| r.is_llgr_stale && r.afi == family.0)
            .map(|(k, _)| k.clone())
            .collect();
        let mut rules = Vec::new();
        for key in &stale {
            rules.push(FlowSpecKey {
                afi: key.afi,
                rule: key.rule.clone(),
            });
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
                let key = route.key();
                if self.flowspec_llgr_stale_local_tags.contains(&key) {
                    clear_local_llgr.push(key);
                }
            }
        }
        self.clear_local_llgr_stale_flowspec_community(&clear_local_llgr);
    }

    fn clear_local_llgr_stale_community(&mut self, keys: &[(Prefix, u32)]) {
        for key in keys {
            if let Some(handle) = self.route_handle(&key.0, key.1)
                && let Some(route) = self.routes.get_mut(handle)
            {
                remove_llgr_stale_community(route);
            }
            self.llgr_stale_local_tags.remove(key);
        }
    }

    fn clear_local_llgr_stale_flowspec_community(&mut self, keys: &[FlowSpecRouteKey]) {
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

    fn clear_local_llgr_stale_bgpls_community(&mut self, keys: &[BgpLsRouteKey]) {
        for key in keys {
            if let Some(route) = self.bgpls_routes.get_mut(key) {
                remove_llgr_stale_community_attrs(Arc::make_mut(&mut route.attributes));
            }
            self.bgpls_llgr_stale_local_tags.remove(key);
        }
    }

    fn clear_local_llgr_stale_vpn_community(&mut self, keys: &[VpnRibRouteKey]) {
        for key in keys {
            if let Some(route) = self.vpn_routes.get_mut(key) {
                remove_llgr_stale_community_attrs(Arc::make_mut(&mut route.attributes));
            }
            self.vpn_llgr_stale_local_tags.remove(key);
        }
    }

    fn clear_local_llgr_stale_labeled_community(&mut self, keys: &[LabeledRibRouteKey]) {
        for key in keys {
            if let Some(route) = self.labeled_routes.get_mut(key) {
                remove_llgr_stale_community_attrs(Arc::make_mut(&mut route.attributes));
            }
            self.labeled_llgr_stale_local_tags.remove(key);
        }
    }

    fn clear_local_llgr_stale_rtc_community(&mut self, keys: &[RtcRibRouteKey]) {
        for key in keys {
            if let Some(route) = self.rtc_routes.get_mut(key) {
                remove_llgr_stale_community_attrs(Arc::make_mut(&mut route.attributes));
            }
            self.rtc_llgr_stale_local_tags.remove(key);
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
        Afi, COMMUNITY_LLGR_STALE, FlowSpecRule, Ipv4Prefix, Ipv6Prefix, LabeledNlri,
        MplsLabelEntry, Origin, PathAttribute, RouteDistinguisher, RtcNlri, Safi, VpnNlri,
        VpnPrefix,
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
            link_local_next_hop: None,
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
        let mut intern = crate::attr_intern::AttrInternTable::new();
        let nlri = vpn_nlri([10, 0, 1, 0], 24, 100);

        let mut first = make_vpn_route(nlri.clone(), 1);
        intern.intern(&mut first.attributes);
        assert!(!rib.insert_vpn(first));
        assert_eq!(intern.len(), 1);

        let mut replacement = make_vpn_route(nlri, 2);
        replacement.attributes = Arc::new(vec![PathAttribute::Origin(Origin::Egp)]);
        intern.intern(&mut replacement.attributes);

        assert!(rib.insert_vpn(replacement));
        assert_eq!(
            intern.len(),
            2,
            "replacement strands the previous interned attribute set before GC"
        );

        intern.gc();
        assert_eq!(intern.len(), 1);
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
        let mut intern = crate::attr_intern::AttrInternTable::new();
        let nlri = rtc_nlri(100);

        let mut first = make_rtc_route(nlri, 1);
        intern.intern(&mut first.attributes);
        assert!(!rib.insert_rtc(first));
        assert_eq!(intern.len(), 1);

        let mut replacement = make_rtc_route(nlri, 2);
        replacement.attributes = Arc::new(vec![PathAttribute::Origin(Origin::Egp)]);
        intern.intern(&mut replacement.attributes);

        assert!(rib.insert_rtc(replacement));
        assert_eq!(
            intern.len(),
            2,
            "replacement strands the previous interned attribute set before GC"
        );

        intern.gc();
        assert_eq!(intern.len(), 1);
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
        let mut intern = crate::attr_intern::AttrInternTable::new();
        let nlri = bgpls_nlri(8);

        let mut first = make_bgpls_route(BgpLsFamily::LinkState, nlri.clone(), 1);
        intern.intern(&mut first.attributes);
        assert!(!rib.insert_bgpls(first));
        assert_eq!(intern.len(), 1);

        let mut replacement = make_bgpls_route(BgpLsFamily::LinkState, nlri, 2);
        replacement.attributes = Arc::new(vec![PathAttribute::Origin(Origin::Egp)]);
        intern.intern(&mut replacement.attributes);

        assert!(rib.insert_bgpls(replacement));
        assert_eq!(
            intern.len(),
            2,
            "replacement strands the previous interned attribute set before GC"
        );

        intern.gc();
        assert_eq!(intern.len(), 1);
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
    fn mark_stale_consecutive_restart_deletes_gr_stale_and_retains_llgr_stale() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let gr_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let llgr_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

        // First cycle: one route goes GR-stale, then GR expiry promotes it
        // to LLGR-stale (real promotion path — injects the community).
        rib.insert(make_route(llgr_prefix, Ipv4Addr::new(10, 0, 0, 1)));
        rib.mark_stale((Afi::Ipv4, Safi::Unicast));
        rib.promote_to_llgr_stale(
            (Afi::Ipv4, Safi::Unicast),
            &mut crate::attr_intern::AttrInternTable::new(),
        );

        // Reconnect re-advertises a second prefix (not the first); the
        // session drops again, marking the fresh route GR-stale.
        rib.insert(make_route(gr_prefix, Ipv4Addr::new(10, 0, 0, 1)));
        assert!(rib.mark_stale((Afi::Ipv4, Safi::Unicast)).is_empty());

        // Third drop before any refresh: the GR-stale route is deleted
        // (RFC 4724 §4.1: no retention across consecutive restarts) but the
        // LLGR-stale route is retained unchanged (RFC 9494: its original
        // stale-time deadline governs), keeping flag and community coupled.
        let deleted = rib.mark_stale((Afi::Ipv4, Safi::Unicast));
        assert_eq!(deleted, vec![Prefix::V4(gr_prefix)]);
        assert_eq!(rib.len(), 1);
        // The secondary prefix index is maintained through the deletion.
        assert_eq!(rib.iter_prefix(&Prefix::V4(gr_prefix)).count(), 0);
        let retained = rib.get(&Prefix::V4(llgr_prefix), 0).unwrap();
        assert!(retained.is_llgr_stale);
        assert!(!retained.is_stale, "LLGR-stale must not be re-marked");
        assert!(
            retained
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
            "retained LLGR-stale route keeps its LLGR_STALE community"
        );
    }

    /// Transport's `apply_llgr_stale_export_form` detects LLGR staleness by
    /// scanning for the `LLGR_STALE` community (the superset — it also
    /// catches routes tagged by an upstream helper). That is only safe for
    /// locally promoted routes if every mutation path keeps the
    /// `is_llgr_stale` flag and the community coupled: flag set ⇒ community
    /// present. This walks the full lifecycle and asserts the invariant
    /// after every step (LAN-191).
    #[test]
    fn llgr_stale_flag_implies_community_across_mutations() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let family = (Afi::Ipv4, Safi::Unicast);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        let assert_coupled = |rib: &AdjRibIn, step: &str| {
            for route in rib.iter() {
                assert!(
                    !route.is_llgr_stale
                        || route
                            .communities()
                            .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE),
                    "flag set without LLGR_STALE community after {step}"
                );
            }
        };

        rib.insert(make_route(prefix, Ipv4Addr::new(10, 0, 0, 1)));
        assert_coupled(&rib, "insert");

        rib.mark_stale(family); // session drop
        assert_coupled(&rib, "mark_stale");

        rib.promote_to_llgr_stale(family, &mut crate::attr_intern::AttrInternTable::new()); // GR timer expiry
        assert_coupled(&rib, "promote_to_llgr_stale");
        assert!(rib.iter().any(|r| r.is_llgr_stale));

        rib.mark_stale(family); // consecutive reset: LLGR-stale retained
        assert_coupled(&rib, "mark_stale on LLGR-stale");
        assert!(rib.iter().any(|r| r.is_llgr_stale));

        // Re-advertisement replaces the entry, clearing the flag with the
        // (locally added) community gone from the fresh attributes.
        rib.insert(make_route(prefix, Ipv4Addr::new(10, 0, 0, 1)));
        assert_coupled(&rib, "re-advertisement insert");
        assert!(rib.iter().all(|r| !r.is_llgr_stale));

        // Second cycle ending in End-of-RIB hygiene: both clear paths drop
        // the flag together with the locally injected community.
        rib.mark_stale(family);
        rib.promote_to_llgr_stale(family, &mut crate::attr_intern::AttrInternTable::new());
        rib.clear_llgr_stale(family);
        assert_coupled(&rib, "clear_llgr_stale");
        assert!(rib.iter().all(|r| !r.is_llgr_stale));

        rib.mark_stale(family);
        rib.promote_to_llgr_stale(family, &mut crate::attr_intern::AttrInternTable::new());
        rib.clear_stale(family);
        assert_coupled(&rib, "clear_stale");
        assert!(rib.iter().all(|r| !r.is_llgr_stale));
    }

    #[test]
    fn sweep_llgr_stale_family_scopes_to_family() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let v4 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let v6 = Ipv6Prefix::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32);
        rib.insert(make_route(v4, Ipv4Addr::new(10, 0, 0, 1)));
        rib.insert(make_v6_route(
            v6,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        ));
        for route in rib.iter_mut() {
            route.is_llgr_stale = true;
        }

        let swept = rib.sweep_llgr_stale_family((Afi::Ipv4, Safi::Unicast));
        assert_eq!(swept, vec![Prefix::V4(v4)]);
        assert_eq!(rib.len(), 1, "v6 LLGR-stale route must survive a v4 sweep");
        assert!(rib.get(&Prefix::V6(v6), 0).unwrap().is_llgr_stale);
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

        rib.promote_to_llgr_stale(
            (Afi::Ipv4, Safi::Unicast),
            &mut crate::attr_intern::AttrInternTable::new(),
        );
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
    fn mark_stale_flowspec_consecutive_restart_deletes_gr_stale_and_retains_llgr_stale() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let llgr_route = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
        let llgr_rule = llgr_route.rule.clone();
        let mut gr_route = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
        gr_route.rule = FlowSpecRule {
            components: vec![rustbgpd_wire::FlowSpecComponent::DestinationPrefix(
                rustbgpd_wire::FlowSpecPrefix::V4(Ipv4Prefix::new(
                    Ipv4Addr::new(198, 51, 100, 0),
                    24,
                )),
            )],
        };
        let gr_rule = gr_route.rule.clone();

        // First cycle: rule goes GR-stale, then promotes to LLGR-stale.
        rib.insert_flowspec(llgr_route);
        rib.mark_stale_flowspec((Afi::Ipv4, Safi::FlowSpec));
        rib.promote_to_llgr_stale_flowspec((Afi::Ipv4, Safi::FlowSpec));

        // Reconnect advertises a second rule; two more drops follow.
        rib.insert_flowspec(gr_route);
        assert!(
            rib.mark_stale_flowspec((Afi::Ipv4, Safi::FlowSpec))
                .is_empty()
        );
        let deleted = rib.mark_stale_flowspec((Afi::Ipv4, Safi::FlowSpec));
        assert_eq!(
            deleted,
            vec![FlowSpecKey {
                afi: Afi::Ipv4,
                rule: gr_rule,
            }]
        );
        assert_eq!(rib.flowspec_len(), 1);
        let retained = rib
            .flowspec_routes
            .get(&FlowSpecRouteKey {
                afi: Afi::Ipv4,
                rule: llgr_rule,
                path_id: 0,
            })
            .unwrap();
        assert!(retained.is_llgr_stale && !retained.is_stale);
        assert!(
            retained
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
        );
    }

    #[test]
    fn sweep_llgr_stale_flowspec_family_scopes_to_family() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let mut v4_route = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
        v4_route.is_llgr_stale = true;
        let v4_rule = v4_route.rule.clone();
        let mut v6_route = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
        v6_route.afi = Afi::Ipv6;
        v6_route.path_id = 1; // distinct key from the v4 fixture rule
        v6_route.is_llgr_stale = true;
        rib.insert_flowspec(v4_route);
        rib.insert_flowspec(v6_route);

        let swept = rib.sweep_llgr_stale_flowspec_family((Afi::Ipv4, Safi::FlowSpec));
        assert_eq!(
            swept,
            vec![FlowSpecKey {
                afi: Afi::Ipv4,
                rule: v4_rule,
            }]
        );
        assert_eq!(
            rib.flowspec_len(),
            1,
            "v6 LLGR-stale rule must survive a v4 sweep"
        );
        assert!(rib.iter_flowspec().next().unwrap().is_llgr_stale);
    }

    #[test]
    fn interned_routes_share_one_arc_in_storage() {
        use rustbgpd_wire::Origin;

        use crate::attr_intern::AttrInternTable;

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let mut intern = AttrInternTable::new();

        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::LocalPref(100),
        ];

        let p1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let p2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);
        let p3 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 3, 0), 24);

        for (prefix, set) in [
            (p1, attrs.clone()),
            (p2, attrs.clone()),
            (p3, attrs.clone()),
        ] {
            let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
            route.attributes = Arc::new(set);
            intern.intern(&mut route.attributes);
            rib.insert(route);
        }

        // All three routes should share the same Arc
        let a1 = &rib.get(&Prefix::V4(p1), 0).unwrap().attributes;
        let a2 = &rib.get(&Prefix::V4(p2), 0).unwrap().attributes;
        let a3 = &rib.get(&Prefix::V4(p3), 0).unwrap().attributes;
        assert!(Arc::ptr_eq(a1, a2));
        assert!(Arc::ptr_eq(a2, a3));

        // Only one unique entry in the intern table
        assert_eq!(intern.len(), 1);
    }

    #[test]
    fn gc_after_withdraw_removes_orphaned_intern_entries() {
        use rustbgpd_wire::Origin;

        use crate::attr_intern::AttrInternTable;

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let mut intern = AttrInternTable::new();

        let p1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let p2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

        let mut r1 = make_route(p1, Ipv4Addr::new(10, 0, 0, 1));
        r1.attributes = Arc::new(vec![PathAttribute::Origin(Origin::Igp)]);
        intern.intern(&mut r1.attributes);
        let mut r2 = make_route(p2, Ipv4Addr::new(10, 0, 0, 1));
        r2.attributes = Arc::new(vec![PathAttribute::Origin(Origin::Egp)]);
        intern.intern(&mut r2.attributes);

        rib.insert(r1);
        rib.insert(r2);
        assert_eq!(intern.len(), 2);

        // Withdraw p2 — its unique attrs become orphaned
        rib.withdraw(&Prefix::V4(p2), 0);
        assert_eq!(intern.len(), 2); // still there before GC

        intern.gc();
        assert_eq!(intern.len(), 1); // orphan cleaned up
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
    fn mark_stale_evpn_consecutive_restart_deletes_gr_stale_and_retains_llgr_stale() {
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer_ip);

        // First cycle: one route goes GR-stale, then promotes to LLGR-stale.
        let llgr_key = insert_evpn_imet(&mut rib, Ipv4Addr::new(10, 0, 0, 1), 200, vec![]);
        rib.mark_stale_evpn((Afi::L2Vpn, Safi::Evpn));
        rib.promote_to_llgr_stale_evpn(
            (Afi::L2Vpn, Safi::Evpn),
            &mut crate::attr_intern::AttrInternTable::new(),
        );

        // Reconnect advertises a second route; two more drops follow. The
        // GR-stale route is deleted (RFC 4724 §4.1), the LLGR-stale one is
        // retained unchanged (RFC 9494: original deadline governs).
        let gr_key = insert_evpn_imet(&mut rib, Ipv4Addr::new(10, 0, 0, 1), 100, vec![]);
        assert!(rib.mark_stale_evpn((Afi::L2Vpn, Safi::Evpn)).is_empty());
        let deleted = rib.mark_stale_evpn((Afi::L2Vpn, Safi::Evpn));
        assert_eq!(deleted, vec![gr_key]);
        assert_eq!(rib.evpn_len(), 1);
        let retained = rib.evpn_routes.get(&llgr_key).unwrap();
        assert!(retained.is_llgr_stale && !retained.is_stale);
        assert!(
            retained
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
        );
    }

    #[test]
    fn clear_stale_evpn_strips_local_llgr_community() {
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer_ip);
        let key = insert_evpn_imet(&mut rib, Ipv4Addr::new(10, 0, 0, 1), 100, vec![]);

        // Stale → promote → LLGR_STALE community locally injected
        rib.mark_stale_evpn((Afi::L2Vpn, Safi::Evpn));
        rib.promote_to_llgr_stale_evpn(
            (Afi::L2Vpn, Safi::Evpn),
            &mut crate::attr_intern::AttrInternTable::new(),
        );
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
        rib.promote_to_llgr_stale_evpn(
            (Afi::L2Vpn, Safi::Evpn),
            &mut crate::attr_intern::AttrInternTable::new(),
        );
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
        rib.promote_to_llgr_stale_evpn(
            (Afi::L2Vpn, Safi::Evpn),
            &mut crate::attr_intern::AttrInternTable::new(),
        );
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
        let affected = rib.promote_to_llgr_stale_evpn(
            (Afi::L2Vpn, Safi::Evpn),
            &mut crate::attr_intern::AttrInternTable::new(),
        );

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
        // Two routes share an Arc<Vec<PathAttribute>> — in production the
        // manager's global intern table produces this sharing (LAN-336).
        // Promoting one must only mutate that route's copy, not the shared
        // Arc — otherwise both routes would gain LLGR_STALE when only one
        // is being promoted.
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer_ip);
        let key_a = insert_evpn_imet(&mut rib, Ipv4Addr::new(10, 0, 0, 1), 100, vec![]);
        let key_b = insert_evpn_imet(&mut rib, Ipv4Addr::new(10, 0, 0, 1), 200, vec![]);
        // Share the allocation explicitly, as the intern table would.
        let shared = Arc::clone(&rib.evpn_routes[&key_a].attributes);
        rib.evpn_routes.get_mut(&key_b).unwrap().attributes = shared;

        // Confirm they actually share the Arc pre-promotion
        let before_a = Arc::as_ptr(&rib.evpn_routes[&key_a].attributes);
        let before_b = Arc::as_ptr(&rib.evpn_routes[&key_b].attributes);
        assert_eq!(before_a, before_b, "routes must share the Arc");

        // Mark only route A stale, promote — route B must NOT gain LLGR_STALE
        rib.evpn_routes.get_mut(&key_a).unwrap().is_stale = true;
        rib.promote_to_llgr_stale_evpn(
            (Afi::L2Vpn, Safi::Evpn),
            &mut crate::attr_intern::AttrInternTable::new(),
        );

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

    // --- VPN / BGP-LS / RTC GR/LLGR stale handling tests ---
    //
    // Mirror the EVPN suite above, plus the per-tuple scoping VPN and BGP-LS
    // need (each spans two (Afi, Safi) tuples the GR capability lists
    // separately) and the RFC 4724 consecutive-restart delete-on-remark.

    const VPN_V4: (Afi, Safi) = (Afi::Ipv4, Safi::MplsVpn);
    const VPN_V6: (Afi, Safi) = (Afi::Ipv6, Safi::MplsVpn);
    const LU_V4: (Afi, Safi) = (Afi::Ipv4, Safi::LabeledUnicast);
    const LU_V6: (Afi, Safi) = (Afi::Ipv6, Safi::LabeledUnicast);
    const LS_BASE: (Afi, Safi) = (Afi::BgpLs, Safi::BgpLs);
    const LS_VPN: (Afi, Safi) = (Afi::BgpLs, Safi::BgpLsVpn);
    const RTC_FAM: (Afi, Safi) = (Afi::Ipv4, Safi::RtConstrain);

    fn vpn_nlri_v6(seg: u16, len: u8, label: u32) -> VpnNlri {
        VpnNlri {
            labels: vec![MplsLabelEntry::try_new(label, 0, true).unwrap()],
            route_distinguisher: RouteDistinguisher::new([0, 0, 0, 0, 0, 0, 0, 2]),
            prefix: VpnPrefix::v6(Ipv6Addr::new(0x2001, 0xdb8, seg, 0, 0, 0, 0, 0), len).unwrap(),
        }
    }

    fn insert_vpn_with(
        rib: &mut AdjRibIn,
        nlri: VpnNlri,
        attrs: Vec<PathAttribute>,
    ) -> VpnRibRouteKey {
        let mut route = make_vpn_route(nlri, 1);
        route.attributes = Arc::new(attrs);
        let key = route.key();
        rib.insert_vpn(route);
        key
    }

    fn insert_bgpls_with(
        rib: &mut AdjRibIn,
        family: BgpLsFamily,
        nlri: rustbgpd_wire::bgpls::BgpLsNlri,
        attrs: Vec<PathAttribute>,
    ) -> BgpLsRouteKey {
        let mut route = make_bgpls_route(family, nlri, 1);
        route.attributes = Arc::new(attrs);
        let key = route.key();
        rib.insert_bgpls(route);
        key
    }

    fn insert_rtc_with(
        rib: &mut AdjRibIn,
        nlri: RtcNlri,
        attrs: Vec<PathAttribute>,
    ) -> RtcRibRouteKey {
        let mut route = make_rtc_route(nlri, 1);
        route.attributes = Arc::new(attrs);
        let key = route.key();
        rib.insert_rtc(route);
        key
    }

    #[test]
    fn mark_stale_vpn_scopes_to_family_tuple() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let v4_key = insert_vpn_with(&mut rib, vpn_nlri([10, 0, 1, 0], 24, 100), vec![]);
        let v6_key = insert_vpn_with(&mut rib, vpn_nlri_v6(1, 48, 200), vec![]);

        // Wrong SAFI: no-op
        assert!(rib.mark_stale_vpn((Afi::Ipv4, Safi::Unicast)).is_empty());
        assert!(!rib.vpn_routes[&v4_key].is_stale);

        // VPNv4: only the v4-tuple route becomes stale
        assert!(rib.mark_stale_vpn(VPN_V4).is_empty());
        assert!(rib.vpn_routes[&v4_key].is_stale);
        assert!(
            !rib.vpn_routes[&v6_key].is_stale,
            "v6 tuple must be untouched"
        );
    }

    #[test]
    fn mark_stale_vpn_consecutive_restart_deletes_gr_stale_and_retains_llgr_stale() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);

        // First cycle: one route goes GR-stale, then promotes to LLGR-stale.
        let llgr_key = insert_vpn_with(&mut rib, vpn_nlri([10, 0, 2, 0], 24, 200), vec![]);
        rib.mark_stale_vpn(VPN_V4);
        rib.promote_to_llgr_stale_vpn(VPN_V4, &mut crate::attr_intern::AttrInternTable::new());

        // Reconnect advertises a second route; two more drops follow. The
        // GR-stale route is deleted (RFC 4724 §4.1), the LLGR-stale one is
        // retained unchanged (RFC 9494: original deadline governs).
        let gr_key = insert_vpn_with(&mut rib, vpn_nlri([10, 0, 1, 0], 24, 100), vec![]);
        assert!(rib.mark_stale_vpn(VPN_V4).is_empty());
        let deleted = rib.mark_stale_vpn(VPN_V4);
        assert_eq!(deleted, vec![gr_key]);
        assert_eq!(rib.vpn_len(), 1);
        let retained = rib.vpn_routes.get(&llgr_key).unwrap();
        assert!(retained.is_llgr_stale && !retained.is_stale);
        assert!(
            retained
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
        );
    }

    #[test]
    fn clear_stale_vpn_strips_local_llgr_community() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let key = insert_vpn_with(&mut rib, vpn_nlri([10, 0, 1, 0], 24, 100), vec![]);

        rib.mark_stale_vpn(VPN_V4);
        rib.promote_to_llgr_stale_vpn(VPN_V4, &mut crate::attr_intern::AttrInternTable::new());
        let promoted = &rib.vpn_routes[&key];
        assert!(promoted.is_llgr_stale);
        assert!(promoted.communities().contains(&COMMUNITY_LLGR_STALE));
        assert!(rib.vpn_llgr_stale_local_tags.contains(&key));

        rib.clear_stale_vpn(VPN_V4);
        let route = &rib.vpn_routes[&key];
        assert!(!route.is_stale);
        assert!(!route.is_llgr_stale);
        assert!(!route.communities().contains(&COMMUNITY_LLGR_STALE));
    }

    #[test]
    fn clear_stale_vpn_preserves_peer_originated_llgr_community() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let peer_attrs = vec![PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE])];
        let key = insert_vpn_with(&mut rib, vpn_nlri([10, 0, 1, 0], 24, 100), peer_attrs);

        rib.mark_stale_vpn(VPN_V4);
        rib.clear_stale_vpn(VPN_V4);
        let route = &rib.vpn_routes[&key];
        assert!(!route.is_stale);
        assert!(route.communities().contains(&COMMUNITY_LLGR_STALE));
    }

    #[test]
    fn sweep_stale_family_vpn_sweeps_only_matching_tuple() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let v4_key = insert_vpn_with(&mut rib, vpn_nlri([10, 0, 1, 0], 24, 100), vec![]);
        let v6_key = insert_vpn_with(&mut rib, vpn_nlri_v6(1, 48, 200), vec![]);
        rib.mark_stale_vpn(VPN_V4);
        rib.mark_stale_vpn(VPN_V6);

        let swept = rib.sweep_stale_family_vpn(VPN_V4);
        assert_eq!(swept, vec![v4_key]);
        assert_eq!(rib.vpn_len(), 1, "v6 stale route must survive a v4 sweep");

        // Whole-table sweep purges the remaining stale route.
        let swept = rib.sweep_stale_vpn();
        assert_eq!(swept, vec![v6_key]);
        assert_eq!(rib.vpn_len(), 0);
    }

    #[test]
    fn promote_to_llgr_stale_vpn_drops_no_llgr_and_scopes_to_tuple() {
        use rustbgpd_wire::COMMUNITY_NO_LLGR;

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let keep_key = insert_vpn_with(&mut rib, vpn_nlri([10, 0, 1, 0], 24, 100), vec![]);
        let no_llgr_key = insert_vpn_with(
            &mut rib,
            vpn_nlri([10, 0, 2, 0], 24, 200),
            vec![PathAttribute::Communities(vec![COMMUNITY_NO_LLGR])],
        );
        let v6_key = insert_vpn_with(&mut rib, vpn_nlri_v6(1, 48, 300), vec![]);

        rib.mark_stale_vpn(VPN_V4);
        rib.mark_stale_vpn(VPN_V6);
        let affected =
            rib.promote_to_llgr_stale_vpn(VPN_V4, &mut crate::attr_intern::AttrInternTable::new());

        // NO_LLGR route removed entirely (RFC 9494 §4.3)
        assert!(!rib.vpn_routes.contains_key(&no_llgr_key));
        // Other v4 route promoted, community injected, local tag recorded
        assert!(rib.vpn_routes[&keep_key].is_llgr_stale);
        assert!(!rib.vpn_routes[&keep_key].is_stale);
        assert!(
            rib.vpn_routes[&keep_key]
                .communities()
                .contains(&COMMUNITY_LLGR_STALE)
        );
        assert!(rib.vpn_llgr_stale_local_tags.contains(&keep_key));
        assert!(affected.contains(&keep_key));
        assert!(affected.contains(&no_llgr_key));
        // v6 tuple untouched: still GR-stale, not promoted
        assert!(rib.vpn_routes[&v6_key].is_stale);
        assert!(!rib.vpn_routes[&v6_key].is_llgr_stale);
        assert!(!affected.contains(&v6_key));

        // LLGR expiry sweep removes only the promoted route.
        let swept = rib.sweep_llgr_stale_vpn();
        assert_eq!(swept, vec![keep_key]);
        assert_eq!(rib.vpn_len(), 1);
    }

    #[test]
    fn insert_vpn_clears_llgr_stale_local_tag_on_readvertise() {
        // Regression mirror of insert_evpn_clears_llgr_stale_local_tag_on_readvertise:
        // a re-advertised key must drop our local-injection record so a later
        // EoR does not strip a peer-originated LLGR_STALE community.
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let nlri = vpn_nlri([10, 0, 1, 0], 24, 100);
        let key = insert_vpn_with(&mut rib, nlri.clone(), vec![]);

        rib.mark_stale_vpn(VPN_V4);
        rib.promote_to_llgr_stale_vpn(VPN_V4, &mut crate::attr_intern::AttrInternTable::new());
        assert!(rib.vpn_llgr_stale_local_tags.contains(&key));

        // Peer re-advertises the same key, itself carrying LLGR_STALE.
        let readvertised = insert_vpn_with(
            &mut rib,
            nlri,
            vec![PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE])],
        );
        assert_eq!(readvertised, key);
        assert!(!rib.vpn_llgr_stale_local_tags.contains(&key));

        // EoR: the peer-originated LLGR_STALE must survive.
        rib.clear_llgr_stale_vpn(VPN_V4);
        assert!(
            rib.vpn_routes[&key]
                .communities()
                .contains(&COMMUNITY_LLGR_STALE)
        );
    }

    #[test]
    fn withdraw_vpn_clears_llgr_stale_local_tag() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let key = insert_vpn_with(&mut rib, vpn_nlri([10, 0, 1, 0], 24, 100), vec![]);
        rib.mark_stale_vpn(VPN_V4);
        rib.promote_to_llgr_stale_vpn(VPN_V4, &mut crate::attr_intern::AttrInternTable::new());
        assert!(rib.vpn_llgr_stale_local_tags.contains(&key));

        assert!(rib.withdraw_vpn(&key));
        assert!(!rib.vpn_llgr_stale_local_tags.contains(&key));
    }

    fn labeled_nlri(addr: [u8; 4], len: u8, label: u32) -> LabeledNlri {
        LabeledNlri {
            labels: vec![MplsLabelEntry::try_new(label, 0, true).unwrap()],
            prefix: rustbgpd_wire::Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(addr), len)),
        }
    }

    fn labeled_nlri_v6(seg: u16, len: u8, label: u32) -> LabeledNlri {
        LabeledNlri {
            labels: vec![MplsLabelEntry::try_new(label, 0, true).unwrap()],
            prefix: rustbgpd_wire::Prefix::V6(Ipv6Prefix::new(
                Ipv6Addr::new(0x2001, 0xdb8, seg, 0, 0, 0, 0, 0),
                len,
            )),
        }
    }

    fn make_labeled_route(nlri: LabeledNlri, peer_oct: u8) -> LabeledRibRoute {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, peer_oct));
        LabeledRibRoute {
            nlri,
            next_hop: peer,
            link_local_next_hop: None,
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

    fn insert_labeled_with(
        rib: &mut AdjRibIn,
        nlri: LabeledNlri,
        attrs: Vec<PathAttribute>,
    ) -> LabeledRibRouteKey {
        let mut route = make_labeled_route(nlri, 1);
        route.attributes = Arc::new(attrs);
        let key = route.key();
        rib.insert_labeled(route);
        key
    }

    #[test]
    fn labeled_insert_get_replace_withdraw_round_trip() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let nlri = labeled_nlri([10, 0, 1, 0], 24, 100);
        let key = LabeledRibRouteKey {
            prefix: nlri.key(),
            path_id: 0,
        };

        assert!(!rib.insert_labeled(make_labeled_route(nlri.clone(), 1)));
        assert_eq!(rib.labeled_len(), 1);
        assert_eq!(rib.iter_labeled().count(), 1);
        assert_eq!(
            rib.get_labeled(&key).unwrap().next_hop,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );

        // Same prefix with a *different label* is the same key (labels are
        // route data, not identity — RFC 8277 §2.3 implicit replace).
        let relabeled = labeled_nlri([10, 0, 1, 0], 24, 999);
        assert_eq!(
            LabeledRibRouteKey {
                prefix: relabeled.key(),
                path_id: 0
            },
            key
        );
        assert!(rib.insert_labeled(make_labeled_route(relabeled, 2)));
        assert_eq!(rib.labeled_len(), 1, "same key should replace");
        assert_eq!(
            rib.get_labeled(&key).unwrap().next_hop,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert_eq!(rib.get_labeled(&key).unwrap().nlri.labels[0].label, 999);

        assert!(rib.withdraw_labeled(&key));
        assert_eq!(rib.labeled_len(), 0);
        assert!(!rib.withdraw_labeled(&key));
    }

    #[test]
    fn labeled_path_ids_are_distinct_keys_and_iterable_per_prefix() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let nlri = labeled_nlri([10, 0, 1, 0], 24, 100);

        let mut path1 = make_labeled_route(nlri.clone(), 1);
        path1.path_id = 1;
        let mut path2 = make_labeled_route(nlri.clone(), 2);
        path2.path_id = 2;
        assert!(!rib.insert_labeled(path1));
        assert!(!rib.insert_labeled(path2), "distinct path_id is a new key");
        assert_eq!(rib.labeled_len(), 2);

        let prefix = nlri.key();
        let mut peers: Vec<_> = rib
            .iter_labeled_for_prefix(&prefix)
            .map(|r| r.peer)
            .collect();
        peers.sort();
        assert_eq!(
            peers,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            ]
        );

        // Removing one path leaves the other reachable via the index.
        assert!(rib.withdraw_labeled(&LabeledRibRouteKey { prefix, path_id: 1 }));
        assert_eq!(rib.iter_labeled_for_prefix(&prefix).count(), 1);
        assert!(rib.withdraw_labeled(&LabeledRibRouteKey { prefix, path_id: 2 }));
        assert_eq!(rib.iter_labeled_for_prefix(&prefix).count(), 0);
    }

    #[test]
    fn labeled_withdraw_all_returns_keys_and_empties_table() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let a = labeled_nlri([10, 0, 1, 0], 24, 100);
        let b = labeled_nlri([10, 0, 2, 0], 24, 200);
        rib.insert_labeled(make_labeled_route(a.clone(), 1));
        rib.insert_labeled(make_labeled_route(b.clone(), 1));
        assert_eq!(rib.labeled_len(), 2);

        let mut keys = rib.withdraw_all_labeled();
        keys.sort_by_key(|k| k.prefix.to_string());
        assert_eq!(
            keys,
            vec![
                LabeledRibRouteKey {
                    prefix: a.key(),
                    path_id: 0
                },
                LabeledRibRouteKey {
                    prefix: b.key(),
                    path_id: 0
                },
            ]
        );
        assert_eq!(rib.labeled_len(), 0);
    }

    #[test]
    fn labeled_insert_reports_replacement_for_intern_gc() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let mut intern = crate::attr_intern::AttrInternTable::new();
        let nlri = labeled_nlri([10, 0, 1, 0], 24, 100);

        let mut first = make_labeled_route(nlri.clone(), 1);
        intern.intern(&mut first.attributes);
        assert!(!rib.insert_labeled(first));
        assert_eq!(intern.len(), 1);

        let mut replacement = make_labeled_route(nlri, 2);
        replacement.attributes = Arc::new(vec![PathAttribute::Origin(Origin::Egp)]);
        intern.intern(&mut replacement.attributes);

        assert!(rib.insert_labeled(replacement));
        assert_eq!(
            intern.len(),
            2,
            "replacement strands the previous interned attribute set before GC"
        );

        intern.gc();
        assert_eq!(intern.len(), 1);
    }

    #[test]
    fn labeled_storage_is_isolated_from_unicast_and_vpn_tables() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);

        // Unicast route at the *same prefix* as the labeled route: the two
        // tables must not collide (ADR-0077 §2).
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 9, 0), 24);
        rib.insert(make_route(prefix, Ipv4Addr::new(10, 0, 0, 1)));
        rib.insert_labeled(make_labeled_route(labeled_nlri([10, 0, 9, 0], 24, 100), 1));
        rib.insert_vpn(make_vpn_route(vpn_nlri([10, 0, 9, 0], 24, 100), 1));

        assert_eq!(rib.labeled_len(), 1);
        assert_eq!(rib.len(), 1, "labeled storage must not touch unicast count");
        assert_eq!(rib.vpn_len(), 1, "labeled storage must not touch VPN count");

        // Withdrawing the labeled route leaves unicast and VPN intact.
        let key = LabeledRibRouteKey {
            prefix: rustbgpd_wire::Prefix::V4(prefix),
            path_id: 0,
        };
        assert!(rib.withdraw_labeled(&key));
        assert_eq!(rib.len(), 1);
        assert_eq!(rib.vpn_len(), 1);

        rib.clear();
        assert_eq!(rib.labeled_len(), 0);
        assert!(rib.is_empty());
    }

    #[test]
    fn mark_stale_labeled_scopes_to_family_tuple() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let v4_key = insert_labeled_with(&mut rib, labeled_nlri([10, 0, 1, 0], 24, 100), vec![]);
        let v6_key = insert_labeled_with(&mut rib, labeled_nlri_v6(1, 48, 200), vec![]);

        // Wrong SAFI: no-op
        assert!(
            rib.mark_stale_labeled((Afi::Ipv4, Safi::Unicast))
                .is_empty()
        );
        assert!(!rib.labeled_routes[&v4_key].is_stale);

        // IPv4 labeled: only the v4-tuple route becomes stale
        assert!(rib.mark_stale_labeled(LU_V4).is_empty());
        assert!(rib.labeled_routes[&v4_key].is_stale);
        assert!(
            !rib.labeled_routes[&v6_key].is_stale,
            "v6 tuple must be untouched"
        );
    }

    #[test]
    fn mark_stale_labeled_consecutive_restart_deletes_gr_stale_and_retains_llgr_stale() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);

        // First cycle: one route goes GR-stale, then promotes to LLGR-stale.
        let llgr_key = insert_labeled_with(&mut rib, labeled_nlri([10, 0, 2, 0], 24, 200), vec![]);
        rib.mark_stale_labeled(LU_V4);
        rib.promote_to_llgr_stale_labeled(LU_V4, &mut crate::attr_intern::AttrInternTable::new());

        // Reconnect advertises a second route; two more drops follow. The
        // GR-stale route is deleted (RFC 4724 §4.1), the LLGR-stale one is
        // retained unchanged (RFC 9494: original deadline governs).
        let gr_key = insert_labeled_with(&mut rib, labeled_nlri([10, 0, 1, 0], 24, 100), vec![]);
        assert!(rib.mark_stale_labeled(LU_V4).is_empty());
        let deleted = rib.mark_stale_labeled(LU_V4);
        assert_eq!(deleted, vec![gr_key]);
        assert_eq!(rib.labeled_len(), 1);
        let retained = rib.labeled_routes.get(&llgr_key).unwrap();
        assert!(retained.is_llgr_stale && !retained.is_stale);
        assert!(
            retained
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
        );
    }

    #[test]
    fn clear_stale_labeled_strips_local_llgr_community() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let key = insert_labeled_with(&mut rib, labeled_nlri([10, 0, 1, 0], 24, 100), vec![]);

        rib.mark_stale_labeled(LU_V4);
        rib.promote_to_llgr_stale_labeled(LU_V4, &mut crate::attr_intern::AttrInternTable::new());
        let promoted = &rib.labeled_routes[&key];
        assert!(promoted.is_llgr_stale);
        assert!(promoted.communities().contains(&COMMUNITY_LLGR_STALE));
        assert!(rib.labeled_llgr_stale_local_tags.contains(&key));

        rib.clear_stale_labeled(LU_V4);
        let route = &rib.labeled_routes[&key];
        assert!(!route.is_stale);
        assert!(!route.is_llgr_stale);
        assert!(!route.communities().contains(&COMMUNITY_LLGR_STALE));
    }

    #[test]
    fn clear_stale_labeled_preserves_peer_originated_llgr_community() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let peer_attrs = vec![PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE])];
        let key = insert_labeled_with(&mut rib, labeled_nlri([10, 0, 1, 0], 24, 100), peer_attrs);

        rib.mark_stale_labeled(LU_V4);
        rib.clear_stale_labeled(LU_V4);
        let route = &rib.labeled_routes[&key];
        assert!(!route.is_stale);
        assert!(route.communities().contains(&COMMUNITY_LLGR_STALE));
    }

    #[test]
    fn sweep_stale_family_labeled_sweeps_only_matching_tuple() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let v4_key = insert_labeled_with(&mut rib, labeled_nlri([10, 0, 1, 0], 24, 100), vec![]);
        let v6_key = insert_labeled_with(&mut rib, labeled_nlri_v6(1, 48, 200), vec![]);
        rib.mark_stale_labeled(LU_V4);
        rib.mark_stale_labeled(LU_V6);

        let swept = rib.sweep_stale_family_labeled(LU_V4);
        assert_eq!(swept, vec![v4_key]);
        assert_eq!(
            rib.labeled_len(),
            1,
            "v6 stale route must survive a v4 sweep"
        );

        // Whole-table sweep purges the remaining stale route.
        let swept = rib.sweep_stale_labeled();
        assert_eq!(swept, vec![v6_key]);
        assert_eq!(rib.labeled_len(), 0);
    }

    #[test]
    fn promote_to_llgr_stale_labeled_drops_no_llgr_and_scopes_to_tuple() {
        use rustbgpd_wire::COMMUNITY_NO_LLGR;

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let keep_key = insert_labeled_with(&mut rib, labeled_nlri([10, 0, 1, 0], 24, 100), vec![]);
        let no_llgr_key = insert_labeled_with(
            &mut rib,
            labeled_nlri([10, 0, 2, 0], 24, 200),
            vec![PathAttribute::Communities(vec![COMMUNITY_NO_LLGR])],
        );
        let v6_key = insert_labeled_with(&mut rib, labeled_nlri_v6(1, 48, 300), vec![]);

        rib.mark_stale_labeled(LU_V4);
        rib.mark_stale_labeled(LU_V6);
        let affected = rib
            .promote_to_llgr_stale_labeled(LU_V4, &mut crate::attr_intern::AttrInternTable::new());

        // NO_LLGR route removed entirely (RFC 9494 §4.3)
        assert!(!rib.labeled_routes.contains_key(&no_llgr_key));
        // Other v4 route promoted, community injected, local tag recorded
        assert!(rib.labeled_routes[&keep_key].is_llgr_stale);
        assert!(!rib.labeled_routes[&keep_key].is_stale);
        assert!(
            rib.labeled_routes[&keep_key]
                .communities()
                .contains(&COMMUNITY_LLGR_STALE)
        );
        assert!(rib.labeled_llgr_stale_local_tags.contains(&keep_key));
        assert!(affected.contains(&keep_key));
        assert!(affected.contains(&no_llgr_key));
        // v6 tuple untouched: still GR-stale, not promoted
        assert!(rib.labeled_routes[&v6_key].is_stale);
        assert!(!rib.labeled_routes[&v6_key].is_llgr_stale);
        assert!(!affected.contains(&v6_key));

        // LLGR expiry sweep removes only the promoted route; the family
        // variant is exercised by the EoR path below.
        let swept = rib.sweep_llgr_stale_labeled();
        assert_eq!(swept, vec![keep_key]);
        assert_eq!(rib.labeled_len(), 1);
    }

    #[test]
    fn sweep_llgr_stale_family_labeled_scopes_to_tuple() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let v4_key = insert_labeled_with(&mut rib, labeled_nlri([10, 0, 1, 0], 24, 100), vec![]);
        insert_labeled_with(&mut rib, labeled_nlri_v6(1, 48, 200), vec![]);
        rib.mark_stale_labeled(LU_V4);
        rib.mark_stale_labeled(LU_V6);
        rib.promote_to_llgr_stale_labeled(LU_V4, &mut crate::attr_intern::AttrInternTable::new());
        rib.promote_to_llgr_stale_labeled(LU_V6, &mut crate::attr_intern::AttrInternTable::new());

        let swept = rib.sweep_llgr_stale_family_labeled(LU_V4);
        assert_eq!(swept, vec![v4_key]);
        assert_eq!(
            rib.labeled_len(),
            1,
            "v6 LLGR-stale route must survive a v4 EoR sweep"
        );
    }

    #[test]
    fn insert_labeled_clears_llgr_stale_local_tag_on_readvertise() {
        // Regression mirror of insert_vpn_clears_llgr_stale_local_tag_on_readvertise:
        // a re-advertised key must drop our local-injection record so a later
        // EoR does not strip a peer-originated LLGR_STALE community.
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let nlri = labeled_nlri([10, 0, 1, 0], 24, 100);
        let key = insert_labeled_with(&mut rib, nlri.clone(), vec![]);

        rib.mark_stale_labeled(LU_V4);
        rib.promote_to_llgr_stale_labeled(LU_V4, &mut crate::attr_intern::AttrInternTable::new());
        assert!(rib.labeled_llgr_stale_local_tags.contains(&key));

        // Peer re-advertises the same key, itself carrying LLGR_STALE.
        let readvertised = insert_labeled_with(
            &mut rib,
            nlri,
            vec![PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE])],
        );
        assert_eq!(readvertised, key);
        assert!(!rib.labeled_llgr_stale_local_tags.contains(&key));

        // EoR: the peer-originated LLGR_STALE must survive.
        rib.clear_llgr_stale_labeled(LU_V4);
        assert!(
            rib.labeled_routes[&key]
                .communities()
                .contains(&COMMUNITY_LLGR_STALE)
        );
    }

    #[test]
    fn withdraw_labeled_clears_llgr_stale_local_tag() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let key = insert_labeled_with(&mut rib, labeled_nlri([10, 0, 1, 0], 24, 100), vec![]);
        rib.mark_stale_labeled(LU_V4);
        rib.promote_to_llgr_stale_labeled(LU_V4, &mut crate::attr_intern::AttrInternTable::new());
        assert!(rib.labeled_llgr_stale_local_tags.contains(&key));

        assert!(rib.withdraw_labeled(&key));
        assert!(!rib.labeled_llgr_stale_local_tags.contains(&key));
    }

    #[test]
    fn mark_stale_bgpls_scopes_to_family_tuple() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let base_key = insert_bgpls_with(&mut rib, BgpLsFamily::LinkState, bgpls_nlri(1), vec![]);
        let vpn_key = insert_bgpls_with(
            &mut rib,
            BgpLsFamily::LinkStateVpn,
            bgpls_vpn_nlri(1),
            vec![],
        );

        // Non-BGP-LS family: no-op
        assert!(rib.mark_stale_bgpls((Afi::Ipv4, Safi::Unicast)).is_empty());
        assert!(!rib.bgpls_routes[&base_key].is_stale);

        // SAFI 71: only base link-state routes become stale
        assert!(rib.mark_stale_bgpls(LS_BASE).is_empty());
        assert!(rib.bgpls_routes[&base_key].is_stale);
        assert!(
            !rib.bgpls_routes[&vpn_key].is_stale,
            "SAFI 72 tuple must be untouched"
        );
    }

    #[test]
    fn mark_stale_bgpls_consecutive_restart_deletes_gr_stale_and_retains_llgr_stale() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);

        // First cycle: one route goes GR-stale, then promotes to LLGR-stale.
        let llgr_key = insert_bgpls_with(&mut rib, BgpLsFamily::LinkState, bgpls_nlri(2), vec![]);
        rib.mark_stale_bgpls(LS_BASE);
        rib.promote_to_llgr_stale_bgpls(LS_BASE, &mut crate::attr_intern::AttrInternTable::new());

        // Reconnect advertises a second route; two more drops follow. The
        // GR-stale route is deleted (RFC 4724 §4.1), the LLGR-stale one is
        // retained unchanged (RFC 9494: original deadline governs).
        let gr_key = insert_bgpls_with(&mut rib, BgpLsFamily::LinkState, bgpls_nlri(1), vec![]);
        assert!(rib.mark_stale_bgpls(LS_BASE).is_empty());
        let deleted = rib.mark_stale_bgpls(LS_BASE);
        assert_eq!(deleted, vec![gr_key]);
        assert_eq!(rib.bgpls_len(), 1);
        let retained = rib.bgpls_routes.get(&llgr_key).unwrap();
        assert!(retained.is_llgr_stale && !retained.is_stale);
        assert!(
            retained
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
        );
    }

    #[test]
    fn clear_stale_bgpls_strips_local_llgr_community() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let key = insert_bgpls_with(&mut rib, BgpLsFamily::LinkState, bgpls_nlri(1), vec![]);

        rib.mark_stale_bgpls(LS_BASE);
        rib.promote_to_llgr_stale_bgpls(LS_BASE, &mut crate::attr_intern::AttrInternTable::new());
        assert!(rib.bgpls_routes[&key].is_llgr_stale);
        assert!(
            rib.bgpls_routes[&key]
                .communities()
                .contains(&COMMUNITY_LLGR_STALE)
        );
        assert!(rib.bgpls_llgr_stale_local_tags.contains(&key));

        rib.clear_stale_bgpls(LS_BASE);
        let route = &rib.bgpls_routes[&key];
        assert!(!route.is_stale);
        assert!(!route.is_llgr_stale);
        assert!(!route.communities().contains(&COMMUNITY_LLGR_STALE));
    }

    #[test]
    fn clear_stale_bgpls_preserves_peer_originated_llgr_community() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let peer_attrs = vec![PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE])];
        let key = insert_bgpls_with(&mut rib, BgpLsFamily::LinkState, bgpls_nlri(1), peer_attrs);

        rib.mark_stale_bgpls(LS_BASE);
        rib.clear_stale_bgpls(LS_BASE);
        let route = &rib.bgpls_routes[&key];
        assert!(!route.is_stale);
        assert!(route.communities().contains(&COMMUNITY_LLGR_STALE));
    }

    #[test]
    fn sweep_stale_family_bgpls_sweeps_only_matching_tuple() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let base_key = insert_bgpls_with(&mut rib, BgpLsFamily::LinkState, bgpls_nlri(1), vec![]);
        let vpn_key = insert_bgpls_with(
            &mut rib,
            BgpLsFamily::LinkStateVpn,
            bgpls_vpn_nlri(1),
            vec![],
        );
        rib.mark_stale_bgpls(LS_BASE);
        rib.mark_stale_bgpls(LS_VPN);

        let swept = rib.sweep_stale_family_bgpls(LS_BASE);
        assert_eq!(swept, vec![base_key]);
        assert_eq!(
            rib.bgpls_len(),
            1,
            "SAFI 72 stale route must survive a SAFI 71 sweep"
        );

        let swept = rib.sweep_stale_bgpls();
        assert_eq!(swept, vec![vpn_key]);
        assert_eq!(rib.bgpls_len(), 0);
    }

    #[test]
    fn promote_to_llgr_stale_bgpls_drops_no_llgr_and_scopes_to_tuple() {
        use rustbgpd_wire::COMMUNITY_NO_LLGR;

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let keep_key = insert_bgpls_with(&mut rib, BgpLsFamily::LinkState, bgpls_nlri(1), vec![]);
        let no_llgr_key = insert_bgpls_with(
            &mut rib,
            BgpLsFamily::LinkState,
            bgpls_nlri(2),
            vec![PathAttribute::Communities(vec![COMMUNITY_NO_LLGR])],
        );
        let vpn_key = insert_bgpls_with(
            &mut rib,
            BgpLsFamily::LinkStateVpn,
            bgpls_vpn_nlri(1),
            vec![],
        );

        rib.mark_stale_bgpls(LS_BASE);
        rib.mark_stale_bgpls(LS_VPN);
        let affected = rib
            .promote_to_llgr_stale_bgpls(LS_BASE, &mut crate::attr_intern::AttrInternTable::new());

        assert!(!rib.bgpls_routes.contains_key(&no_llgr_key));
        assert!(rib.bgpls_routes[&keep_key].is_llgr_stale);
        assert!(!rib.bgpls_routes[&keep_key].is_stale);
        assert!(
            rib.bgpls_routes[&keep_key]
                .communities()
                .contains(&COMMUNITY_LLGR_STALE)
        );
        assert!(rib.bgpls_llgr_stale_local_tags.contains(&keep_key));
        assert!(affected.contains(&keep_key));
        assert!(affected.contains(&no_llgr_key));
        // SAFI 72 tuple untouched: still GR-stale, not promoted
        assert!(rib.bgpls_routes[&vpn_key].is_stale);
        assert!(!rib.bgpls_routes[&vpn_key].is_llgr_stale);
        assert!(!affected.contains(&vpn_key));

        let swept = rib.sweep_llgr_stale_bgpls();
        assert_eq!(swept, vec![keep_key]);
        assert_eq!(rib.bgpls_len(), 1);
    }

    #[test]
    fn insert_bgpls_clears_llgr_stale_local_tag_on_readvertise() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let nlri = bgpls_nlri(1);
        let key = insert_bgpls_with(&mut rib, BgpLsFamily::LinkState, nlri.clone(), vec![]);

        rib.mark_stale_bgpls(LS_BASE);
        rib.promote_to_llgr_stale_bgpls(LS_BASE, &mut crate::attr_intern::AttrInternTable::new());
        assert!(rib.bgpls_llgr_stale_local_tags.contains(&key));

        let readvertised = insert_bgpls_with(
            &mut rib,
            BgpLsFamily::LinkState,
            nlri,
            vec![PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE])],
        );
        assert_eq!(readvertised, key);
        assert!(!rib.bgpls_llgr_stale_local_tags.contains(&key));

        rib.clear_llgr_stale_bgpls(LS_BASE);
        assert!(
            rib.bgpls_routes[&key]
                .communities()
                .contains(&COMMUNITY_LLGR_STALE)
        );
    }

    #[test]
    fn withdraw_bgpls_clears_llgr_stale_local_tag() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let key = insert_bgpls_with(&mut rib, BgpLsFamily::LinkState, bgpls_nlri(1), vec![]);
        rib.mark_stale_bgpls(LS_BASE);
        rib.promote_to_llgr_stale_bgpls(LS_BASE, &mut crate::attr_intern::AttrInternTable::new());
        assert!(rib.bgpls_llgr_stale_local_tags.contains(&key));

        assert!(rib.withdraw_bgpls(&key));
        assert!(!rib.bgpls_llgr_stale_local_tags.contains(&key));
    }

    #[test]
    fn mark_stale_rtc_scopes_to_family_tuple() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let key = insert_rtc_with(&mut rib, rtc_nlri(100), vec![]);

        // Non-RTC family: no-op
        assert!(rib.mark_stale_rtc((Afi::Ipv4, Safi::Unicast)).is_empty());
        assert!(!rib.rtc_routes[&key].is_stale);

        assert!(rib.mark_stale_rtc(RTC_FAM).is_empty());
        assert!(rib.rtc_routes[&key].is_stale);
    }

    #[test]
    fn mark_stale_rtc_consecutive_restart_deletes_gr_stale_and_retains_llgr_stale() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);

        // First cycle: one route goes GR-stale, then promotes to LLGR-stale.
        let llgr_key = insert_rtc_with(&mut rib, rtc_nlri(200), vec![]);
        rib.mark_stale_rtc(RTC_FAM);
        rib.promote_to_llgr_stale_rtc(RTC_FAM, &mut crate::attr_intern::AttrInternTable::new());

        // Reconnect advertises a second route; two more drops follow. The
        // GR-stale route is deleted (RFC 4724 §4.1), the LLGR-stale one is
        // retained unchanged (RFC 9494: original deadline governs).
        let gr_key = insert_rtc_with(&mut rib, rtc_nlri(100), vec![]);
        assert!(rib.mark_stale_rtc(RTC_FAM).is_empty());
        let deleted = rib.mark_stale_rtc(RTC_FAM);
        assert_eq!(deleted, vec![gr_key]);
        assert_eq!(rib.rtc_len(), 1);
        let retained = rib.rtc_routes.get(&llgr_key).unwrap();
        assert!(retained.is_llgr_stale && !retained.is_stale);
        assert!(
            retained
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE)
        );
    }

    #[test]
    fn clear_stale_rtc_strips_local_llgr_community() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let key = insert_rtc_with(&mut rib, rtc_nlri(100), vec![]);

        rib.mark_stale_rtc(RTC_FAM);
        rib.promote_to_llgr_stale_rtc(RTC_FAM, &mut crate::attr_intern::AttrInternTable::new());
        assert!(rib.rtc_routes[&key].is_llgr_stale);
        assert!(
            rib.rtc_routes[&key]
                .communities()
                .contains(&COMMUNITY_LLGR_STALE)
        );
        assert!(rib.rtc_llgr_stale_local_tags.contains(&key));

        rib.clear_stale_rtc(RTC_FAM);
        let route = &rib.rtc_routes[&key];
        assert!(!route.is_stale);
        assert!(!route.is_llgr_stale);
        assert!(!route.communities().contains(&COMMUNITY_LLGR_STALE));
    }

    #[test]
    fn clear_stale_rtc_preserves_peer_originated_llgr_community() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let peer_attrs = vec![PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE])];
        let key = insert_rtc_with(&mut rib, rtc_nlri(100), peer_attrs);

        rib.mark_stale_rtc(RTC_FAM);
        rib.clear_stale_rtc(RTC_FAM);
        let route = &rib.rtc_routes[&key];
        assert!(!route.is_stale);
        assert!(route.communities().contains(&COMMUNITY_LLGR_STALE));
    }

    #[test]
    fn sweep_stale_family_rtc_ignores_non_rtc_family() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let key = insert_rtc_with(&mut rib, rtc_nlri(100), vec![]);
        rib.mark_stale_rtc(RTC_FAM);

        let swept = rib.sweep_stale_family_rtc((Afi::Ipv4, Safi::Unicast));
        assert!(swept.is_empty());
        assert_eq!(rib.rtc_len(), 1);

        let swept = rib.sweep_stale_family_rtc(RTC_FAM);
        assert_eq!(swept, vec![key]);
        assert_eq!(rib.rtc_len(), 0);
    }

    #[test]
    fn promote_to_llgr_stale_rtc_drops_no_llgr_routes() {
        use rustbgpd_wire::COMMUNITY_NO_LLGR;

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let keep_key = insert_rtc_with(&mut rib, rtc_nlri(100), vec![]);
        let no_llgr_key = insert_rtc_with(
            &mut rib,
            rtc_nlri(200),
            vec![PathAttribute::Communities(vec![COMMUNITY_NO_LLGR])],
        );

        rib.mark_stale_rtc(RTC_FAM);
        let affected =
            rib.promote_to_llgr_stale_rtc(RTC_FAM, &mut crate::attr_intern::AttrInternTable::new());

        assert!(!rib.rtc_routes.contains_key(&no_llgr_key));
        assert!(rib.rtc_routes[&keep_key].is_llgr_stale);
        assert!(!rib.rtc_routes[&keep_key].is_stale);
        assert!(
            rib.rtc_routes[&keep_key]
                .communities()
                .contains(&COMMUNITY_LLGR_STALE)
        );
        assert!(rib.rtc_llgr_stale_local_tags.contains(&keep_key));
        assert!(affected.contains(&keep_key));
        assert!(affected.contains(&no_llgr_key));

        let swept = rib.sweep_llgr_stale_rtc();
        assert_eq!(swept, vec![keep_key]);
        assert_eq!(rib.rtc_len(), 0);
    }

    #[test]
    fn insert_rtc_clears_llgr_stale_local_tag_on_readvertise() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let nlri = rtc_nlri(100);
        let key = insert_rtc_with(&mut rib, nlri, vec![]);

        rib.mark_stale_rtc(RTC_FAM);
        rib.promote_to_llgr_stale_rtc(RTC_FAM, &mut crate::attr_intern::AttrInternTable::new());
        assert!(rib.rtc_llgr_stale_local_tags.contains(&key));

        let readvertised = insert_rtc_with(
            &mut rib,
            nlri,
            vec![PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE])],
        );
        assert_eq!(readvertised, key);
        assert!(!rib.rtc_llgr_stale_local_tags.contains(&key));

        rib.clear_llgr_stale_rtc(RTC_FAM);
        assert!(
            rib.rtc_routes[&key]
                .communities()
                .contains(&COMMUNITY_LLGR_STALE)
        );
    }

    #[test]
    fn withdraw_rtc_clears_llgr_stale_local_tag() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        let key = insert_rtc_with(&mut rib, rtc_nlri(100), vec![]);
        rib.mark_stale_rtc(RTC_FAM);
        rib.promote_to_llgr_stale_rtc(RTC_FAM, &mut crate::attr_intern::AttrInternTable::new());
        assert!(rib.rtc_llgr_stale_local_tags.contains(&key));

        assert!(rib.withdraw_rtc(&key));
        assert!(!rib.rtc_llgr_stale_local_tags.contains(&key));
    }

    #[test]
    fn clear_resets_llgr_stale_local_tags_for_vpn_bgpls_rtc() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        insert_vpn_with(&mut rib, vpn_nlri([10, 0, 1, 0], 24, 100), vec![]);
        insert_bgpls_with(&mut rib, BgpLsFamily::LinkState, bgpls_nlri(1), vec![]);
        insert_rtc_with(&mut rib, rtc_nlri(100), vec![]);
        insert_labeled_with(&mut rib, labeled_nlri([10, 0, 1, 0], 24, 100), vec![]);
        rib.mark_stale_vpn(VPN_V4);
        rib.mark_stale_bgpls(LS_BASE);
        rib.mark_stale_rtc(RTC_FAM);
        rib.mark_stale_labeled(LU_V4);
        rib.promote_to_llgr_stale_vpn(VPN_V4, &mut crate::attr_intern::AttrInternTable::new());
        rib.promote_to_llgr_stale_bgpls(LS_BASE, &mut crate::attr_intern::AttrInternTable::new());
        rib.promote_to_llgr_stale_rtc(RTC_FAM, &mut crate::attr_intern::AttrInternTable::new());
        rib.promote_to_llgr_stale_labeled(LU_V4, &mut crate::attr_intern::AttrInternTable::new());
        assert!(!rib.vpn_llgr_stale_local_tags.is_empty());
        assert!(!rib.bgpls_llgr_stale_local_tags.is_empty());
        assert!(!rib.rtc_llgr_stale_local_tags.is_empty());
        assert!(!rib.labeled_llgr_stale_local_tags.is_empty());

        rib.clear();
        assert!(rib.vpn_llgr_stale_local_tags.is_empty());
        assert!(rib.bgpls_llgr_stale_local_tags.is_empty());
        assert!(rib.rtc_llgr_stale_local_tags.is_empty());
        assert!(rib.labeled_llgr_stale_local_tags.is_empty());
    }

    #[test]
    fn withdraw_all_resets_llgr_stale_local_tags_per_family() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rib = AdjRibIn::new(peer);
        insert_vpn_with(&mut rib, vpn_nlri([10, 0, 1, 0], 24, 100), vec![]);
        insert_bgpls_with(&mut rib, BgpLsFamily::LinkState, bgpls_nlri(1), vec![]);
        insert_rtc_with(&mut rib, rtc_nlri(100), vec![]);
        insert_labeled_with(&mut rib, labeled_nlri([10, 0, 1, 0], 24, 100), vec![]);
        rib.mark_stale_vpn(VPN_V4);
        rib.mark_stale_bgpls(LS_BASE);
        rib.mark_stale_rtc(RTC_FAM);
        rib.mark_stale_labeled(LU_V4);
        rib.promote_to_llgr_stale_vpn(VPN_V4, &mut crate::attr_intern::AttrInternTable::new());
        rib.promote_to_llgr_stale_bgpls(LS_BASE, &mut crate::attr_intern::AttrInternTable::new());
        rib.promote_to_llgr_stale_rtc(RTC_FAM, &mut crate::attr_intern::AttrInternTable::new());
        rib.promote_to_llgr_stale_labeled(LU_V4, &mut crate::attr_intern::AttrInternTable::new());

        rib.withdraw_all_vpn();
        rib.withdraw_all_bgpls();
        rib.withdraw_all_rtc();
        rib.withdraw_all_labeled();
        assert!(rib.vpn_llgr_stale_local_tags.is_empty());
        assert!(rib.bgpls_llgr_stale_local_tags.is_empty());
        assert!(rib.rtc_llgr_stale_local_tags.is_empty());
        assert!(rib.labeled_llgr_stale_local_tags.is_empty());
    }

    /// LAN-335 slab-storage leak gate: withdraw must free the route's slab
    /// slot and re-insert must reuse it, so sustained insert/withdraw churn
    /// keeps the slot vector at the steady-state size instead of growing
    /// without bound.
    #[test]
    fn withdraw_reinsert_churn_reuses_slab_slots() {
        let mut rib = AdjRibIn::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let prefixes: Vec<Ipv4Prefix> = (0..100u8)
            .map(|i| Ipv4Prefix::new(Ipv4Addr::new(10, 1, i, 0), 24))
            .collect();

        for cycle in 0..5 {
            for p in &prefixes {
                rib.insert(make_route(*p, Ipv4Addr::new(192, 0, 2, 1)));
            }
            assert_eq!(rib.len(), prefixes.len(), "cycle {cycle}");
            assert_eq!(
                rib.routes.slot_count(),
                prefixes.len(),
                "cycle {cycle}: churn must reuse freed slots, not grow the slab"
            );
            for p in &prefixes {
                assert!(rib.withdraw(&Prefix::V4(*p), 0), "cycle {cycle}");
            }
            assert!(rib.is_empty(), "cycle {cycle}");
        }
    }
}
