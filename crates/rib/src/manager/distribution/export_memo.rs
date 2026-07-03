//! Pass-scoped memo for the unicast export tail.
//!
//! A policy-modified export fanout used to deep-clone the route's
//! `Arc<Vec<PathAttribute>>` once per (route, peer) — 76% of live heap in
//! a modifying-chain RR fanout (2026-07-03 dhat profile, indictment #1) —
//! even though the post-modification attribute set is identical for every
//! peer whose chain evaluation produced the same `RouteModifications`.
//!
//! Soundness: [`rustbgpd_policy::apply_modifications`] is a pure function
//! of `(source attributes, RouteModifications)`. Peer context (address,
//! ASN, group) only influences chain *evaluation*, whose entire output is
//! the `RouteModifications` value itself — so keying on
//! (source-attribute identity, modifications equality) is exact, and
//! peer-varying chains simply land in separate slots.
//!
//! The memo also caches the `AS_PATH` regex-match string per source
//! attribute set (indictment #4: it was rebuilt per (prefix, peer)).
//!
//! Scope: one distribution pass (a `distribute_changes` fanout, a route
//! refresh, or an initial peer dump). The memo is a local of that pass —
//! no cross-pass interning, no lifetime questions. Source-attribute
//! identity is the `Arc` pointer; each entry pins a clone of the source
//! `Arc` so the pointer cannot be reused by a different allocation while
//! the memo is alive.

use std::sync::Arc;

use rustbgpd_policy::{NextHopAction, RouteModifications};
use rustbgpd_wire::PathAttribute;
use rustc_hash::FxHashMap;

use crate::route::Route;

/// Memoized export-tail results for one distribution pass.
#[derive(Default)]
pub(in crate::manager) struct ExportMemo {
    entries: FxHashMap<usize, MemoEntry>,
}

struct MemoEntry {
    /// Pins the source allocation so the pointer key stays unique for
    /// the memo's lifetime.
    _source: Arc<Vec<PathAttribute>>,
    /// Rendered `AS_PATH` match string (built at most once per source
    /// attribute set).
    aspath: Option<Arc<str>>,
    /// Distinct post-modification outcomes for this source attribute
    /// set. Expected tiny: one slot per distinct `RouteModifications`
    /// produced by the export chains in this pass.
    modified: Vec<(
        RouteModifications,
        Arc<Vec<PathAttribute>>,
        Option<NextHopAction>,
    )>,
}

impl ExportMemo {
    fn entry(&mut self, attrs: &Arc<Vec<PathAttribute>>) -> &mut MemoEntry {
        self.entries
            .entry(Arc::as_ptr(attrs) as usize)
            .or_insert_with(|| MemoEntry {
                _source: Arc::clone(attrs),
                aspath: None,
                modified: Vec::new(),
            })
    }

    /// `AS_PATH` string for policy regex matching, memoized per source
    /// attribute set.
    pub(in crate::manager) fn aspath_str(&mut self, route: &Route) -> Arc<str> {
        let entry = self.entry(&route.attributes);
        if entry.aspath.is_none() {
            let s = route
                .as_path()
                .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string);
            entry.aspath = Some(Arc::from(s));
        }
        entry.aspath.clone().expect("aspath populated just above")
    }

    /// Clone `route` with `mods` applied to its attributes, sharing one
    /// post-modification attribute `Arc` across every (route, peer) in
    /// this pass with the same source attribute set and equal
    /// modifications. Empty modifications keep sharing the source `Arc`
    /// exactly as before.
    pub(in crate::manager) fn apply(
        &mut self,
        route: &Route,
        mods: &RouteModifications,
    ) -> (Route, Option<NextHopAction>) {
        let mut modified = route.clone();
        if mods.is_empty() {
            return (modified, None);
        }
        let entry = self.entry(&route.attributes);
        let (attrs, nh) =
            if let Some((_, attrs, nh)) = entry.modified.iter().find(|(m, _, _)| m == mods) {
                (Arc::clone(attrs), nh.clone())
            } else {
                let mut new_attrs = (*route.attributes).clone();
                let nh = rustbgpd_policy::apply_modifications(&mut new_attrs, mods);
                let attrs = Arc::new(new_attrs);
                entry
                    .modified
                    .push((mods.clone(), Arc::clone(&attrs), nh.clone()));
                (attrs, nh)
            };
        modified.attributes = attrs;
        if let Some(NextHopAction::Specific(addr)) = &nh {
            modified.next_hop = *addr;
        }
        (modified, nh)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    use rustbgpd_wire::{
        AsPath, AsPathSegment, ExtendedCommunity, Ipv4Prefix, LargeCommunity, Origin, Prefix,
    };

    use super::*;
    use crate::route::RouteOrigin;

    fn attrs(local_pref: u32) -> Vec<PathAttribute> {
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65000, 65100, 65200])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(198, 51, 100, 1)),
            PathAttribute::LocalPref(local_pref),
            PathAttribute::Med(50),
            PathAttribute::Communities(vec![0xFDE8_0064]), // 65000:100
        ]
    }

    fn route(attributes: Arc<Vec<PathAttribute>>) -> Route {
        Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24)),
            next_hop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            attributes,
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::new(192, 0, 2, 10),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        }
    }

    /// The pre-memo export path, duplicated verbatim as the equivalence
    /// oracle: private deep clone + `apply_modifications` per call.
    fn bypass(route: &Route, mods: &RouteModifications) -> (Route, Option<NextHopAction>) {
        let mut modified = route.clone();
        let nh = if mods.is_empty() {
            None
        } else {
            let nh =
                rustbgpd_policy::apply_modifications(Arc::make_mut(&mut modified.attributes), mods);
            if let Some(NextHopAction::Specific(addr)) = &nh {
                modified.next_hop = *addr;
            }
            nh
        };
        (modified, nh)
    }

    fn mods_matrix() -> Vec<RouteModifications> {
        let ext = ExtendedCommunity::new(0x0002_fde8_0000_0007);
        let large = LargeCommunity {
            global_admin: 65000,
            local_data1: 1,
            local_data2: 2,
        };
        vec![
            RouteModifications::default(),
            RouteModifications {
                set_med: Some(200),
                ..Default::default()
            },
            RouteModifications {
                set_local_pref: Some(300),
                communities_add: vec![0xFDE8_03E7], // 65000:999
                ..Default::default()
            },
            RouteModifications {
                communities_remove: vec![0xFDE8_0064], // 65000:100
                ..Default::default()
            },
            RouteModifications {
                extended_communities_add: vec![ext],
                extended_communities_remove: vec![ext],
                large_communities_add: vec![large],
                large_communities_remove: vec![large],
                ..Default::default()
            },
            RouteModifications {
                as_path_prepend: Some((65000, 3)),
                set_med: Some(0),
                ..Default::default()
            },
            RouteModifications {
                set_next_hop: Some(NextHopAction::Specific(IpAddr::V4(Ipv4Addr::new(
                    203, 0, 113, 9,
                )))),
                ..Default::default()
            },
            RouteModifications {
                set_next_hop: Some(NextHopAction::Self_),
                communities_add: vec![1, 2, 3],
                ..Default::default()
            },
        ]
    }

    /// Every (source attrs, modifications) cell must be byte-identical
    /// to the pre-memo private-clone path, on both the miss and the hit.
    #[test]
    fn memo_matches_bypass_across_matrix() {
        for source in [
            attrs(100),
            attrs(50),
            vec![PathAttribute::Origin(Origin::Igp)],
        ] {
            let r = route(Arc::new(source));
            for mods in mods_matrix() {
                let mut memo = ExportMemo::default();
                let (expect_route, expect_nh) = bypass(&r, &mods);
                let (miss, miss_nh) = memo.apply(&r, &mods);
                let (hit, hit_nh) = memo.apply(&r, &mods);
                assert_eq!(*miss.attributes, *expect_route.attributes, "mods {mods:?}");
                assert_eq!(miss.next_hop, expect_route.next_hop, "mods {mods:?}");
                assert_eq!(miss_nh, expect_nh, "mods {mods:?}");
                assert_eq!(*hit.attributes, *expect_route.attributes, "mods {mods:?}");
                assert_eq!(hit.next_hop, expect_route.next_hop, "mods {mods:?}");
                assert_eq!(hit_nh, expect_nh, "mods {mods:?}");
                if mods.is_empty() {
                    // No-modification exports keep sharing the source Arc.
                    assert!(Arc::ptr_eq(&miss.attributes, &r.attributes));
                } else {
                    // Hits share the memoized allocation.
                    assert!(Arc::ptr_eq(&miss.attributes, &hit.attributes));
                    assert!(!Arc::ptr_eq(&miss.attributes, &r.attributes));
                }
            }
        }
    }

    /// Distinct modifications against one source attr set — the
    /// peer-varying-chain shape — must land in separate slots, and
    /// distinct source Arcs must never cross-share.
    #[test]
    fn memo_keys_by_source_identity_and_modifications_value() {
        let mut memo = ExportMemo::default();
        let r1 = route(Arc::new(attrs(100)));
        // Same content, different allocation: correctness must hold
        // (no sharing expected — identity is the Arc pointer).
        let r2 = route(Arc::new(attrs(100)));
        let med100 = RouteModifications {
            set_med: Some(100),
            ..Default::default()
        };
        let med200 = RouteModifications {
            set_med: Some(200),
            ..Default::default()
        };

        let (a, _) = memo.apply(&r1, &med100);
        let (b, _) = memo.apply(&r1, &med200);
        let (c, _) = memo.apply(&r2, &med100);
        assert!(!Arc::ptr_eq(&a.attributes, &b.attributes));
        assert!(!Arc::ptr_eq(&a.attributes, &c.attributes));
        assert_eq!(*a.attributes, *bypass(&r1, &med100).0.attributes);
        assert_eq!(*b.attributes, *bypass(&r1, &med200).0.attributes);
        assert_eq!(*c.attributes, *bypass(&r2, &med100).0.attributes);
        // Same content from the same source: shared.
        let (a2, _) = memo.apply(&r1, &med100);
        assert!(Arc::ptr_eq(&a.attributes, &a2.attributes));
    }

    #[test]
    fn aspath_str_memoized_per_source_attr_set() {
        let mut memo = ExportMemo::default();
        let r = route(Arc::new(attrs(100)));
        let s1 = memo.aspath_str(&r);
        let s2 = memo.aspath_str(&r);
        assert_eq!(&*s1, "65000 65100 65200");
        assert!(Arc::ptr_eq(&s1, &s2));

        let no_aspath = route(Arc::new(vec![PathAttribute::Origin(Origin::Igp)]));
        assert_eq!(&*memo.aspath_str(&no_aspath), "");
    }
}
