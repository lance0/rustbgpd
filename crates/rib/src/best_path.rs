//! Best-path selection per RFC 4271 §9.1.2.
//!
//! Uses deterministic MED (always-compare) for simplicity, matching `GoBGP`.

use std::cmp::Ordering;

use rustbgpd_wire::AsPath;

use crate::route::Route;

/// Compare two routes for best-path selection.
///
/// The preferred route sorts `Less`. Decision steps (RFC 4271 §9.1.2):
/// 1. Highest `LOCAL_PREF` (default 100)
/// 2. Shortest `AS_PATH` length (default 0)
/// 3. Lowest ORIGIN — IGP < EGP < INCOMPLETE
/// 4. Lowest MED (default 0; always-compare / deterministic MED)
/// 5. eBGP over iBGP
/// 6. Lowest peer address (tiebreaker)
#[must_use]
pub fn best_path_cmp(a: &Route, b: &Route) -> Ordering {
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

    // 5. eBGP over iBGP (eBGP = true sorts Less = preferred)
    let cmp = b.is_ebgp.cmp(&a.is_ebgp);
    if cmp != Ordering::Equal {
        return cmp;
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
    use crate::route::Route;

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
            is_ebgp: true,
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
        a.is_ebgp = true;
        let mut b = base_route(Ipv4Addr::new(1, 0, 0, 2));
        b.is_ebgp = false;
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
    fn igp_beats_incomplete() {
        let a = with_origin(base_route(Ipv4Addr::new(1, 0, 0, 1)), Origin::Igp);
        let b = with_origin(base_route(Ipv4Addr::new(1, 0, 0, 2)), Origin::Incomplete);
        assert_eq!(best_path_cmp(&a, &b), Ordering::Less);
        assert_eq!(best_path_cmp(&b, &a), Ordering::Greater);
    }
}

#[cfg(test)]
mod proptests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    use proptest::prelude::*;
    use rustbgpd_wire::{AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute, Prefix};

    use super::*;
    use crate::route::Route;

    fn arb_origin() -> impl Strategy<Value = Origin> {
        prop_oneof![
            Just(Origin::Igp),
            Just(Origin::Egp),
            Just(Origin::Incomplete),
        ]
    }

    fn arb_route() -> impl Strategy<Value = Route> {
        (
            1u8..=4,                                   // peer last octet
            0u32..=500,                                // local_pref
            prop::collection::vec(1u32..=65535, 0..5), // as_path ASNs
            arb_origin(),
            0u32..=1000,   // MED
            any::<bool>(), // is_ebgp
        )
            .prop_map(|(peer_oct, lp, asns, origin, med, is_ebgp)| {
                let peer = Ipv4Addr::new(10, 0, 0, peer_oct);
                Route {
                    prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
                    next_hop: IpAddr::V4(peer),
                    peer: IpAddr::V4(peer),
                    attributes: vec![
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
                    ],
                    received_at: Instant::now(),
                    is_ebgp,
                }
            })
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
