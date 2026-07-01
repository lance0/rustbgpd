use std::net::IpAddr;

use rustbgpd_wire::{EvpnRouteKey, FlowSpecRule, Prefix};
// FxHash (rustc-hash) on the route-bearing maps — see `adj_rib_in` for the
// rationale (internal keys, faster hasher on the convergence hot path).
// Aliased to the std name so the storage types read unchanged.
use rustc_hash::{FxBuildHasher, FxHashMap as HashMap};
use smallvec::SmallVec;

use crate::prefix_map::FamilyPrefixMap;
use crate::route::{
    BgpLsRibRoute, BgpLsRouteKey, EvpnRibRoute, FlowSpecRoute, Route, RtcRibRoute, RtcRibRouteKey,
    VpnRibRoute, VpnRibRouteKey,
};

/// Per-peer Adj-RIB-Out: routes advertised to a specific peer.
///
/// Routes are keyed by `(Prefix, path_id)` for Add-Path (RFC 7911).
/// In single-best mode, `path_id` is always 0.
pub struct AdjRibOut {
    peer: IpAddr,
    routes: HashMap<(Prefix, u32), Route>,
    /// Secondary index: prefix → path IDs for fast per-prefix lookup, backed by
    /// a family-split prefix trie. `SmallVec<[u32; 1]>` inlines the single-best
    /// case (`path_id=0`) without heap allocation; Add-Path multi-path spills to
    /// heap transparently.
    prefix_path_ids: FamilyPrefixMap<SmallVec<[u32; 1]>>,
    /// `FlowSpec` routes advertised to this peer (always single-best, `path_id=0`).
    flowspec_routes: HashMap<FlowSpecRule, FlowSpecRoute>,
    /// EVPN routes advertised to this peer, keyed by RFC 7432 route identity.
    evpn_routes: HashMap<EvpnRouteKey, EvpnRibRoute>,
    /// BGP-LS routes advertised to this peer, keyed by opaque RFC 9552 identity.
    bgpls_routes: HashMap<BgpLsRouteKey, BgpLsRibRoute>,
    /// VPNv4/VPNv6 routes advertised to this peer, keyed by RD + prefix identity.
    vpn_routes: HashMap<VpnRibRouteKey, VpnRibRoute>,
    /// RT-Constrain routes advertised to this peer, keyed by RFC 4684 identity.
    rtc_routes: HashMap<RtcRibRouteKey, RtcRibRoute>,
}

impl AdjRibOut {
    /// Create a new empty Adj-RIB-Out for the given peer.
    #[must_use]
    pub fn new(peer: IpAddr) -> Self {
        Self::with_capacity(peer, 0)
    }

    /// Create a new Adj-RIB-Out with pre-sized capacity.
    ///
    /// Use `LocRib::len()` as a good estimate — each peer's outbound view
    /// converges to approximately the same prefix count as the best-path table.
    #[must_use]
    pub fn with_capacity(peer: IpAddr, capacity: usize) -> Self {
        Self {
            peer,
            routes: HashMap::with_capacity_and_hasher(capacity, FxBuildHasher),
            prefix_path_ids: FamilyPrefixMap::default(),
            flowspec_routes: HashMap::default(),
            evpn_routes: HashMap::default(),
            bgpls_routes: HashMap::default(),
            vpn_routes: HashMap::default(),
            rtc_routes: HashMap::default(),
        }
    }

    /// Return the peer address this RIB belongs to.
    #[must_use]
    pub fn peer(&self) -> IpAddr {
        self.peer
    }

    /// Insert or replace an advertised route.
    pub fn insert(&mut self, route: Route) {
        let prefix = route.prefix;
        let path_id = route.path_id;
        self.routes.insert((prefix, path_id), route);
        let ids = self.prefix_path_ids.entry_or_default(prefix);
        if !ids.contains(&path_id) {
            ids.push(path_id);
        }
    }

    /// Withdraw a route by prefix and path ID. Returns `true` if it existed.
    pub fn withdraw(&mut self, prefix: &Prefix, path_id: u32) -> bool {
        if self.routes.remove(&(*prefix, path_id)).is_some() {
            if let Some(ids) = self.prefix_path_ids.get_mut(prefix) {
                ids.retain(|id| *id != path_id);
                if ids.is_empty() {
                    self.prefix_path_ids.remove(prefix);
                }
            }
            true
        } else {
            false
        }
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
    pub fn iter_prefix(&self, prefix: &Prefix) -> impl Iterator<Item = &Route> + '_ {
        let prefix = *prefix;
        self.prefix_path_ids
            .get(&prefix)
            .into_iter()
            .flat_map(move |ids| {
                ids.iter()
                    .filter_map(move |&id| self.routes.get(&(prefix, id)))
            })
    }

    /// Return all path IDs currently advertised for a given prefix.
    #[must_use]
    pub fn path_ids_for_prefix(&self, prefix: &Prefix) -> &[u32] {
        self.prefix_path_ids
            .get(prefix)
            .map_or(&[], SmallVec::as_slice)
    }

    /// Remove every advertised route — unicast, `FlowSpec`, EVPN, BGP-LS,
    /// VPN, and RTC — and the secondary prefix index.
    pub fn clear(&mut self) {
        self.routes.clear();
        self.prefix_path_ids.clear();
        self.flowspec_routes.clear();
        self.evpn_routes.clear();
        self.bgpls_routes.clear();
        self.vpn_routes.clear();
        self.rtc_routes.clear();
    }

    /// Return the number of advertised routes.
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
        self.prefix_path_ids.len()
    }

    /// Return the prefix trie's structural memory, excluding stored values'
    /// own heap allocations.
    #[cfg(feature = "bench-internals")]
    #[must_use]
    pub fn bench_prefix_index_mem_size(&self) -> usize {
        self.prefix_path_ids.mem_size()
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

    // --- EVPN methods (RFC 7432) ---

    /// Insert or replace an advertised EVPN route.
    pub fn insert_evpn(&mut self, route: EvpnRibRoute) {
        self.evpn_routes.insert(route.key(), route);
    }

    /// Remove an EVPN route by key. Returns `true` if it existed.
    pub fn remove_evpn(&mut self, key: &EvpnRouteKey) -> bool {
        self.evpn_routes.remove(key).is_some()
    }

    /// Look up an EVPN route by key.
    #[must_use]
    pub fn get_evpn(&self, key: &EvpnRouteKey) -> Option<&EvpnRibRoute> {
        self.evpn_routes.get(key)
    }

    /// Iterate over all advertised EVPN routes.
    pub fn iter_evpn(&self) -> impl Iterator<Item = &EvpnRibRoute> {
        self.evpn_routes.values()
    }

    /// Return the number of advertised EVPN routes.
    #[must_use]
    pub fn evpn_len(&self) -> usize {
        self.evpn_routes.len()
    }

    // --- BGP-LS methods (ADR-0077 outbound reflection substrate) ---

    /// Insert or replace an advertised BGP-LS route.
    pub fn insert_bgpls(&mut self, route: BgpLsRibRoute) {
        self.bgpls_routes.insert(route.key(), route);
    }

    /// Remove an advertised BGP-LS route by opaque key. Returns `true` if it existed.
    pub fn remove_bgpls(&mut self, key: &BgpLsRouteKey) -> bool {
        self.bgpls_routes.remove(key).is_some()
    }

    /// Look up an advertised BGP-LS route by opaque key.
    #[must_use]
    pub fn get_bgpls(&self, key: &BgpLsRouteKey) -> Option<&BgpLsRibRoute> {
        self.bgpls_routes.get(key)
    }

    /// Iterate over all advertised BGP-LS routes.
    pub fn iter_bgpls(&self) -> impl Iterator<Item = &BgpLsRibRoute> {
        self.bgpls_routes.values()
    }

    /// Return the number of advertised BGP-LS routes.
    #[must_use]
    pub fn bgpls_len(&self) -> usize {
        self.bgpls_routes.len()
    }

    // --- VPNv4/VPNv6 methods (ADR-0077 outbound reflection substrate) ---

    /// Insert or replace an advertised VPN route.
    pub fn insert_vpn(&mut self, route: VpnRibRoute) {
        self.vpn_routes.insert(route.key(), route);
    }

    /// Remove an advertised VPN route by key. Returns `true` if it existed.
    pub fn remove_vpn(&mut self, key: &VpnRibRouteKey) -> bool {
        self.vpn_routes.remove(key).is_some()
    }

    /// Look up an advertised VPN route by key.
    #[must_use]
    pub fn get_vpn(&self, key: &VpnRibRouteKey) -> Option<&VpnRibRoute> {
        self.vpn_routes.get(key)
    }

    /// Iterate over all advertised VPN routes.
    pub fn iter_vpn(&self) -> impl Iterator<Item = &VpnRibRoute> {
        self.vpn_routes.values()
    }

    /// Return the number of advertised VPN routes.
    #[must_use]
    pub fn vpn_len(&self) -> usize {
        self.vpn_routes.len()
    }

    // --- RT-Constrain methods (RFC 4684 outbound reflection substrate) ---

    /// Insert or replace an advertised RTC route.
    pub fn insert_rtc(&mut self, route: RtcRibRoute) {
        self.rtc_routes.insert(route.key(), route);
    }

    /// Remove an advertised RTC route by key. Returns `true` if it existed.
    pub fn remove_rtc(&mut self, key: &RtcRibRouteKey) -> bool {
        self.rtc_routes.remove(key).is_some()
    }

    /// Look up an advertised RTC route by key.
    #[must_use]
    pub fn get_rtc(&self, key: &RtcRibRouteKey) -> Option<&RtcRibRoute> {
        self.rtc_routes.get(key)
    }

    /// Iterate over all advertised RTC routes.
    pub fn iter_rtc(&self) -> impl Iterator<Item = &RtcRibRoute> {
        self.rtc_routes.values()
    }

    /// Return the number of advertised RTC routes.
    #[must_use]
    pub fn rtc_len(&self) -> usize {
        self.rtc_routes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Instant;

    use rustbgpd_wire::{
        Ipv4Prefix, MplsLabelEntry, Origin, PathAttribute, Prefix, RouteDistinguisher, RtcNlri,
        VpnNlri, VpnPrefix,
    };

    use crate::route::BgpLsFamily;
    use crate::test_support::make_route_with_path_id as make_route;

    fn prefix_a() -> Prefix {
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24))
    }

    fn prefix_b() -> Prefix {
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 1, 0), 24))
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
    fn vpn_insert_remove_iter_isolated_from_unicast_index() {
        let mut rib = AdjRibOut::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let nlri = vpn_nlri([10, 0, 1, 0], 24, 100);
        let key = VpnRibRouteKey {
            nlri_key: nlri.key(),
            path_id: 0,
        };

        rib.insert_vpn(make_vpn_route(nlri.clone(), 1));
        assert_eq!(rib.vpn_len(), 1);
        assert_eq!(rib.iter_vpn().count(), 1);
        assert_eq!(rib.len(), 0);
        assert!(rib.path_ids_for_prefix(&prefix_a()).is_empty());

        // Same RD + prefix + path_id replaces in place.
        rib.insert_vpn(make_vpn_route(nlri, 2));
        assert_eq!(rib.vpn_len(), 1, "same key should replace");
        assert_eq!(
            rib.get_vpn(&key).unwrap().peer,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );

        assert!(rib.remove_vpn(&key));
        assert_eq!(rib.vpn_len(), 0);
        assert!(!rib.remove_vpn(&key));
    }

    fn make_rtc_route(local_admin: u32, peer_oct: u8) -> RtcRibRoute {
        // 2-octet-AS RT:65001:<local_admin>, origin AS 65001, full /96.
        let rt = 0x0002_FDE9_0000_0000_u64 | u64::from(local_admin);
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, peer_oct));
        RtcRibRoute {
            nlri: RtcNlri::new(65001, rt, 96).unwrap(),
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
    fn rtc_insert_remove_iter_isolated_from_unicast_index() {
        let mut rib = AdjRibOut::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let route = make_rtc_route(100, 1);
        let key = route.key();

        rib.insert_rtc(route);
        assert_eq!(rib.rtc_len(), 1);
        assert_eq!(rib.iter_rtc().count(), 1);
        assert_eq!(rib.len(), 0);
        assert_eq!(rib.vpn_len(), 0);
        assert!(rib.path_ids_for_prefix(&prefix_a()).is_empty());

        // Same NLRI + path_id replaces in place.
        rib.insert_rtc(make_rtc_route(100, 2));
        assert_eq!(rib.rtc_len(), 1, "same key should replace");
        assert_eq!(
            rib.get_rtc(&key).unwrap().peer,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );

        assert!(rib.remove_rtc(&key));
        assert_eq!(rib.rtc_len(), 0);
        assert!(!rib.remove_rtc(&key));
    }

    #[test]
    fn index_tracks_single_best_insert_withdraw() {
        let mut rib = AdjRibOut::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let p = prefix_a();

        assert!(rib.path_ids_for_prefix(&p).is_empty());
        rib.insert(make_route(p, 0));
        assert_eq!(rib.path_ids_for_prefix(&p), [0]);

        assert!(rib.withdraw(&p, 0));
        assert!(rib.path_ids_for_prefix(&p).is_empty());
        assert!(!rib.withdraw(&p, 0));
    }

    #[test]
    fn index_tracks_add_path_multiple_ids() {
        let mut rib = AdjRibOut::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let p = prefix_a();

        rib.insert(make_route(p, 1));
        rib.insert(make_route(p, 2));
        rib.insert(make_route(p, 3));

        let mut ids = rib.path_ids_for_prefix(&p).to_vec();
        ids.sort_unstable();
        assert_eq!(ids, [1, 2, 3]);

        rib.withdraw(&p, 2);
        let mut ids = rib.path_ids_for_prefix(&p).to_vec();
        ids.sort_unstable();
        assert_eq!(ids, [1, 3]);
    }

    #[test]
    fn index_handles_duplicate_insert() {
        let mut rib = AdjRibOut::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let p = prefix_a();

        rib.insert(make_route(p, 0));
        rib.insert(make_route(p, 0)); // replace, not duplicate
        assert_eq!(rib.path_ids_for_prefix(&p), [0]);
        assert_eq!(rib.len(), 1);
    }

    #[test]
    fn index_isolated_per_prefix() {
        let mut rib = AdjRibOut::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let pa = prefix_a();
        let pb = prefix_b();

        rib.insert(make_route(pa, 0));
        rib.insert(make_route(pb, 0));
        rib.insert(make_route(pb, 1));

        assert_eq!(rib.path_ids_for_prefix(&pa), [0]);
        let mut ids_b = rib.path_ids_for_prefix(&pb).to_vec();
        ids_b.sort_unstable();
        assert_eq!(ids_b, [0, 1]);

        rib.withdraw(&pa, 0);
        assert!(rib.path_ids_for_prefix(&pa).is_empty());
        assert_eq!(rib.path_ids_for_prefix(&pb).len(), 2);
    }

    #[test]
    fn clear_resets_index() {
        let mut rib = AdjRibOut::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        rib.insert(make_route(prefix_a(), 0));
        rib.insert(make_route(prefix_b(), 1));
        rib.insert_bgpls(make_bgpls_route(BgpLsFamily::LinkState, bgpls_nlri(13), 1));

        rib.clear();
        assert!(rib.path_ids_for_prefix(&prefix_a()).is_empty());
        assert!(rib.path_ids_for_prefix(&prefix_b()).is_empty());
        assert!(rib.is_empty());
        assert_eq!(rib.bgpls_len(), 0);
    }

    #[test]
    fn bgpls_insert_remove_isolated_from_unicast_index() {
        let mut rib = AdjRibOut::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let nlri = bgpls_nlri(14);
        let key = BgpLsRouteKey {
            family: BgpLsFamily::LinkState,
            nlri: nlri.key(),
            path_id: 0,
        };

        rib.insert_bgpls(make_bgpls_route(BgpLsFamily::LinkState, nlri.clone(), 1));
        assert_eq!(rib.bgpls_len(), 1);
        assert_eq!(rib.iter_bgpls().count(), 1);
        assert_eq!(rib.len(), 0);
        assert!(rib.path_ids_for_prefix(&prefix_a()).is_empty());

        rib.insert_bgpls(make_bgpls_route(BgpLsFamily::LinkState, nlri, 2));
        assert_eq!(rib.bgpls_len(), 1, "same opaque key should replace");
        assert_eq!(
            rib.get_bgpls(&key).unwrap().peer,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );

        assert!(rib.remove_bgpls(&key));
        assert_eq!(rib.bgpls_len(), 0);
        assert!(!rib.remove_bgpls(&key));
    }

    #[test]
    fn iter_prefix_uses_index() {
        let mut rib = AdjRibOut::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let pa = prefix_a();
        let pb = prefix_b();

        rib.insert(make_route(pa, 1));
        rib.insert(make_route(pa, 2));
        rib.insert(make_route(pb, 0));

        let routes_a: Vec<_> = rib.iter_prefix(&pa).collect();
        assert_eq!(routes_a.len(), 2);
        assert!(routes_a.iter().all(|r| r.prefix == pa));

        let routes_b: Vec<_> = rib.iter_prefix(&pb).collect();
        assert_eq!(routes_b.len(), 1);

        let routes_none: Vec<_> = rib
            .iter_prefix(&Prefix::V4(Ipv4Prefix::new(
                Ipv4Addr::new(192, 168, 0, 0),
                16,
            )))
            .collect();
        assert!(routes_none.is_empty());
    }
}
