//! Best-path selection per RFC 4271 §9.1.2.
//!
//! Uses deterministic MED (always-compare) for simplicity, matching `GoBGP`.

use std::cmp::Ordering;

use rustbgpd_wire::AsPath;

use crate::route::Route;

/// Compare two routes for best-path selection.
///
/// The preferred route sorts `Less`. Decision steps (RFC 4271 §9.1.2):
/// 0. Non-stale preferred over stale (RFC 4724 demotion)
/// 1. Highest `LOCAL_PREF` (default 100)
/// 2. Shortest `AS_PATH` length (default 0)
/// 3. Lowest ORIGIN — IGP < EGP < INCOMPLETE
/// 4. Lowest MED (default 0; always-compare / deterministic MED)
/// 5. eBGP over iBGP
///    5.5. Shortest `CLUSTER_LIST` length (RFC 4456 §9)
///    5.6. Lowest `ORIGINATOR_ID` (RFC 4456 §9) — only when both present
/// 6. Lowest peer address (tiebreaker)
#[must_use]
pub fn best_path_cmp(a: &Route, b: &Route) -> Ordering {
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

    // 5. eBGP over iBGP (only RouteOrigin::Ebgp gets preference here;
    //    RouteOrigin::Local sorts equal to iBGP — local routes win via
    //    LOCAL_PREF or shorter AS_PATH, not an explicit origin preference)
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
    a.peer.cmp(&b.peer)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    use rustbgpd_wire::{AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute, Prefix};

    use super::*;
    use crate::route::{Route, RouteOrigin};

    fn base_route(peer: Ipv4Addr) -> Route {
        Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            next_hop: IpAddr::V4(peer),
            peer: IpAddr::V4(peer),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65001])],
                }),
                PathAttribute::LocalPref(100),
            ],
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            path_id: 0,
        }
    }

    fn with_local_pref(mut r: Route, lp: u32) -> Route {
        r.attributes
            .retain(|a| !matches!(a, PathAttribute::LocalPref(_)));
        r.attributes.push(PathAttribute::LocalPref(lp));
        r
    }

    fn with_as_path(mut r: Route, asns: Vec<u32>) -> Route {
        r.attributes
            .retain(|a| !matches!(a, PathAttribute::AsPath(_)));
        r.attributes.push(PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(asns)],
        }));
        r
    }

    fn with_origin(mut r: Route, origin: Origin) -> Route {
        r.attributes
            .retain(|a| !matches!(a, PathAttribute::Origin(_)));
        r.attributes.push(PathAttribute::Origin(origin));
        r
    }

    fn with_med(mut r: Route, med: u32) -> Route {
        r.attributes.retain(|a| !matches!(a, PathAttribute::Med(_)));
        r.attributes.push(PathAttribute::Med(med));
        r
    }

    // --- Decision step tests ---

    #[test]
    fn higher_local_pref_wins() {
        let a = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 1)), 200);
        let b = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 2)), 100);
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
        assert_eq!(best_path_cmp(&b, &a), Ordering::Greater);
    }

    #[test]
    fn shorter_as_path_wins() {
        let a = with_as_path(base_route(Ipv4Addr::new(1, 0, 0, 1)), vec![65001]);
        let b = with_as_path(
            base_route(Ipv4Addr::new(1, 0, 0, 2)),
            vec![65001, 65002, 65003],
        );
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn lower_origin_wins() {
        let a = with_origin(base_route(Ipv4Addr::new(1, 0, 0, 1)), Origin::Igp);
        let b = with_origin(base_route(Ipv4Addr::new(1, 0, 0, 2)), Origin::Egp);
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn lower_med_wins() {
        let a = with_med(base_route(Ipv4Addr::new(1, 0, 0, 1)), 50);
        let b = with_med(base_route(Ipv4Addr::new(1, 0, 0, 2)), 100);
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn lower_peer_addr_tiebreaks() {
        let a = base_route(Ipv4Addr::new(1, 0, 0, 1));
        let b = base_route(Ipv4Addr::new(1, 0, 0, 2));
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn equal_routes_same_peer() {
        let a = base_route(Ipv4Addr::new(1, 0, 0, 1));
        let b = base_route(Ipv4Addr::new(1, 0, 0, 1));
        assert_eq!(best_path_cmp(&a, &b), Ordering::Equal);
    }

    #[test]
    fn local_pref_beats_shorter_as_path() {
        let a = with_as_path(
            with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 1)), 200),
            vec![65001, 65002, 65003],
        );
        let b = with_as_path(
            with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 2)), 100),
            vec![65001],
        );
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn default_local_pref_when_absent() {
        // Route with no LOCAL_PREF attribute should default to 100
        let mut a = base_route(Ipv4Addr::new(1, 0, 0, 1));
        a.attributes
            .retain(|a| !matches!(a, PathAttribute::LocalPref(_)));
        let b = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 2)), 100);
        // Same local_pref, same as_path, same origin, no MED → peer tiebreak
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn ebgp_beats_ibgp() {
        let mut a = base_route(Ipv4Addr::new(1, 0, 0, 1));
        a.origin_type = RouteOrigin::Ebgp;
        let mut b = base_route(Ipv4Addr::new(1, 0, 0, 2));
        b.origin_type = RouteOrigin::Ibgp;
        // eBGP route wins even though peer address is lower
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
        assert_eq!(best_path_cmp(&b, &a), Ordering::Greater);
    }

    #[test]
    fn ebgp_ibgp_same_both_ebgp_falls_through() {
        let a = base_route(Ipv4Addr::new(1, 0, 0, 1));
        let b = base_route(Ipv4Addr::new(1, 0, 0, 2));
        // Both eBGP — falls through to peer tiebreaker
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn non_stale_beats_stale() {
        let a = base_route(Ipv4Addr::new(1, 0, 0, 1));
        let mut b = base_route(Ipv4Addr::new(1, 0, 0, 1));
        b.is_stale = true;
        // Non-stale (a) preferred over stale (b)
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
        assert_eq!(best_path_cmp(&b, &a), Ordering::Greater);
    }

    #[test]
    fn stale_demotion_beats_local_pref() {
        // A stale route with higher LOCAL_PREF should lose to a non-stale route
        let mut a = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 1)), 200);
        a.is_stale = true;
        let b = with_local_pref(base_route(Ipv4Addr::new(1, 0, 0, 2)), 100);
        assert_eq!(best_path_cmp(&a, &b), Ordering::Greater);
    }

    #[test]
    fn igp_beats_incomplete() {
        let a = with_origin(base_route(Ipv4Addr::new(1, 0, 0, 1)), Origin::Igp);
        let b = with_origin(base_route(Ipv4Addr::new(1, 0, 0, 2)), Origin::Incomplete);
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
        assert_eq!(best_path_cmp(&b, &a), Ordering::Greater);
    }

    fn with_cluster_list(mut r: Route, ids: Vec<Ipv4Addr>) -> Route {
        r.attributes
            .retain(|a| !matches!(a, PathAttribute::ClusterList(_)));
        r.attributes.push(PathAttribute::ClusterList(ids));
        r
    }

    fn with_originator_id(mut r: Route, id: Ipv4Addr) -> Route {
        r.attributes
            .retain(|a| !matches!(a, PathAttribute::OriginatorId(_)));
        r.attributes.push(PathAttribute::OriginatorId(id));
        r
    }

    #[test]
    fn shorter_cluster_list_wins() {
        let a = with_cluster_list(
            base_route(Ipv4Addr::new(1, 0, 0, 2)),
            vec![Ipv4Addr::new(10, 0, 0, 1)],
        );
        let b = with_cluster_list(
            base_route(Ipv4Addr::new(1, 0, 0, 1)),
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)],
        );
        // a has shorter CLUSTER_LIST, wins despite higher peer address
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
        assert_eq!(best_path_cmp(&b, &a), Ordering::Greater);
    }

    #[test]
    fn lower_originator_id_wins() {
        let a = with_originator_id(
            base_route(Ipv4Addr::new(1, 0, 0, 2)),
            Ipv4Addr::new(10, 0, 0, 1),
        );
        let b = with_originator_id(
            base_route(Ipv4Addr::new(1, 0, 0, 1)),
            Ipv4Addr::new(10, 0, 0, 2),
        );
        // a has lower ORIGINATOR_ID, wins despite higher peer address
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
        assert_eq!(best_path_cmp(&b, &a), Ordering::Greater);
    }

    #[test]
    fn cluster_list_beats_originator_id() {
        // Shorter CLUSTER_LIST should win even if ORIGINATOR_ID is higher
        let a = with_originator_id(
            with_cluster_list(
                base_route(Ipv4Addr::new(1, 0, 0, 1)),
                vec![Ipv4Addr::new(10, 0, 0, 1)],
            ),
            Ipv4Addr::new(10, 0, 0, 99),
        );
        let b = with_originator_id(
            with_cluster_list(
                base_route(Ipv4Addr::new(1, 0, 0, 1)),
                vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)],
            ),
            Ipv4Addr::new(10, 0, 0, 1),
        );
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
    }

    #[test]
    fn originator_id_only_when_both_present() {
        // When only one route has ORIGINATOR_ID, it should fall through
        let a = with_originator_id(
            base_route(Ipv4Addr::new(1, 0, 0, 2)),
            Ipv4Addr::new(10, 0, 0, 99),
        );
        let b = base_route(Ipv4Addr::new(1, 0, 0, 1));
        // ORIGINATOR_ID tiebreaker skipped (b has none), falls to peer address
        // b has lower peer → b wins
        assert_eq!(best_path_cmp(&a, &b), Ordering::Greater);
    }
}

#[cfg(test)]
mod proptests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    use proptest::prelude::*;
    use rustbgpd_wire::{AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute, Prefix};

    use super::*;
    use crate::route::{Route, RouteOrigin};

    fn arb_origin() -> impl Strategy<Value = Origin> {
        prop_oneof![
            Just(Origin::Igp),
            Just(Origin::Egp),
            Just(Origin::Incomplete),
        ]
    }

    fn arb_route_origin() -> impl Strategy<Value = RouteOrigin> {
        prop_oneof![
            Just(RouteOrigin::Ebgp),
            Just(RouteOrigin::Ibgp),
            Just(RouteOrigin::Local),
        ]
    }

    fn arb_route() -> impl Strategy<Value = Route> {
        (
            1u8..=4,                                   // peer last octet
            0u32..=500,                                // local_pref
            prop::collection::vec(1u32..=65535, 0..5), // as_path ASNs
            arb_origin(),
            0u32..=1000,                   // MED
            arb_route_origin(),            // origin_type
            proptest::option::of(1u8..=4), // originator_id last octet
            0u8..=3,                       // cluster_list length
        )
            .prop_map(
                |(peer_oct, lp, asns, origin, med, origin_type, oid_oct, cl_len)| {
                    let peer = Ipv4Addr::new(10, 0, 0, peer_oct);
                    let mut attributes = vec![
                        PathAttribute::LocalPref(lp),
                        PathAttribute::AsPath(AsPath {
                            segments: if asns.is_empty() {
                                vec![]
                            } else {
                                vec![AsPathSegment::AsSequence(asns)]
                            },
                        }),
                        PathAttribute::Origin(origin),
                        PathAttribute::Med(med),
                    ];
                    if let Some(oct) = oid_oct {
                        attributes.push(PathAttribute::OriginatorId(Ipv4Addr::new(10, 0, 0, oct)));
                    }
                    if cl_len > 0 {
                        let ids: Vec<Ipv4Addr> =
                            (1..=cl_len).map(|i| Ipv4Addr::new(10, 0, i, 1)).collect();
                        attributes.push(PathAttribute::ClusterList(ids));
                    }
                    Route {
                        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
                        next_hop: IpAddr::V4(peer),
                        peer: IpAddr::V4(peer),
                        attributes,
                        received_at: Instant::now(),
                        origin_type,
                        peer_router_id: Ipv4Addr::UNSPECIFIED,
                        is_stale: false,
                        path_id: 0,
                    }
                },
            )
    }

    proptest! {
        #[test]
        fn antisymmetry(a in arb_route(), b in arb_route()) {
            let ab = best_path_cmp(&a, &b);
            let ba = best_path_cmp(&b, &a);
            prop_assert_eq!(ab, ba.reverse());
        }

        #[test]
        fn transitivity(a in arb_route(), b in arb_route(), c in arb_route()) {
            use std::cmp::Ordering::*;
            let ab = best_path_cmp(&a, &b);
            let bc = best_path_cmp(&b, &c);
            let ac = best_path_cmp(&a, &c);
            if ab == Less && bc == Less {
                prop_assert_eq!(ac, Less);
            }
            if ab == Greater && bc == Greater {
                prop_assert_eq!(ac, Greater);
            }
        }

        #[test]
        fn totality(a in arb_route(), b in arb_route()) {
            let result = best_path_cmp(&a, &b);
            prop_assert!(matches!(result, std::cmp::Ordering::Less | std::cmp::Ordering::Equal | std::cmp::Ordering::Greater));
        }
    }
}
