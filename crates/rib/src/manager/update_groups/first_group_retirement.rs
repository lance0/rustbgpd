use std::collections::BTreeMap;

use super::{GroupRibOut, PeerId, PolicyRows};

impl GroupRibOut {
    pub(in crate::manager) fn first_group_policy_evaluated(
        &self,
        prefix: &rustbgpd_wire::Prefix,
    ) -> bool {
        #[cfg(test)]
        crate::manager::slice_timing::record_work("first_group_evaluated_lookups", 1);
        self.table.get(prefix, 0).is_some() || self.policy_filtered.get(prefix).is_some()
    }

    /// Select bounded-growth sidecars before any staged route can enter them.
    pub(in crate::manager) fn prepare_policy_first_group(&mut self) {
        debug_assert!(self.table.is_empty());
        self.table
            .prepare_first_group_next_hops(self.export_chain.as_ref().expect("policy first group"));
        self.policy_filtered = PolicyRows::Ordered(BTreeMap::new());
        if !self.source_control_passthrough {
            self.source_attrs = PolicyRows::Ordered(BTreeMap::new());
        }
    }

    pub(in crate::manager) fn empty_first_group_table(&self) -> Self {
        let mut empty = Self::new(
            self.export_chain
                .as_ref()
                .map(rustbgpd_policy::PolicyChain::fork_for_install),
            self.is_ebgp,
            self.interpret_rfc1997,
            self.is_rr_client,
            None,
            self.sendable.clone(),
            self.llgr.clone(),
            false,
            0,
        );
        if empty.export_chain.is_some() {
            empty.prepare_policy_first_group();
        }
        empty
    }

    /// Release the counters and policy input owned by an advertised slot.
    pub(super) fn retire_first_group_slot(&mut self) -> Option<PeerId> {
        #[cfg(test)]
        crate::manager::slice_timing::record_work("first_group_retired_slots", 1);
        let (source, prefix) = self.table.retire_first_group_slot()?;
        self.dec_source(source, &prefix);
        if !self.source_control_passthrough {
            self.source_attrs.remove(&(prefix, 0));
        }
        Some(source)
    }

    /// Retire one physical slot (even a hole) or one denied prefix per unit.
    pub(in crate::manager) fn retire_first_group_page(&mut self, mut budget: usize) -> bool {
        debug_assert!(self.members.is_empty() && !self.per_client_best);
        debug_assert!(
            !crate::manager::distribution::otc_role_blocks(self.local_role)
                && self.otc_blocked.is_empty()
        );
        while !self.table.first_group_retirement_finished() {
            if budget == 0 {
                return false;
            }
            budget -= 1;
            self.retire_first_group_slot();
        }
        debug_assert!(self.source_counts.is_empty() && self.source_attrs.is_empty());
        match &mut self.policy_filtered {
            PolicyRows::Ordered(map) => PolicyRows::retire_ordered(map, &mut budget, |denials| {
                self.single_best_denials.retire_prefix(denials, &mut || {});
            }),
            PolicyRows::Sharded(map) => {
                debug_assert!(map.is_empty());
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::GroupDelta;
    use super::*;
    use crate::PeerId;
    use crate::adj_rib_out::LocalExportSource;
    use crate::route::Route;
    use crate::test_support::make_route_with_path_id;
    use rustbgpd_wire::{Afi, Ipv4Prefix, Ipv6Prefix, Prefix, Safi};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    fn delta(prefix: Prefix, route: Option<Route>) -> GroupDelta {
        GroupDelta {
            prefix,
            path_id: 0,
            local_source: route.as_ref().and_then(LocalExportSource::from_route),
            new: route.map(|route| (route, None)),
            old_source: None,
            prior_source_attrs: None,
            prior: None,
            policy_label: None,
            source_attrs: None,
            lane: None,
        }
    }

    #[test]
    fn private_staging_selects_ordered_provenance_only_on_first_local_row() {
        use crate::attr_set::AttrSet;
        use crate::manager::RibManager;
        use crate::route::RouteOrigin;
        use rustbgpd_wire::{LargeCommunity, PathAttribute};

        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let (_qtx, qrx) = tokio::sync::mpsc::channel(1);
        let mut manager =
            RibManager::new(rx, qrx, None, None, rustbgpd_telemetry::BgpMetrics::new());
        let mut group = GroupRibOut::new(
            None,
            false,
            true,
            true,
            None,
            vec![(Afi::Ipv4, Safi::Unicast)],
            vec![],
            false,
            0,
        );
        // Include named and announce-to-none controls on every row. A
        // memberless table keeps them in the route, without building RS indexes.
        for i in 1..=3u32 {
            let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(i), 32));
            let mut route = make_route_with_path_id(prefix, i);
            route.attributes = AttrSet::new(vec![
                PathAttribute::Communities(vec![64496]),
                PathAttribute::LargeCommunities(vec![LargeCommunity::new(64512, 0, 0)]),
            ]);
            if i > 1 {
                route.peer = PeerId::LOCAL;
                route.origin_type = RouteOrigin::Local;
            }
            assert!(manager.loc_rib.recompute(prefix, std::iter::once(&route)));
            group = manager.stage_first_group_page(1, group, &[prefix].into());
            assert!(group.table.get(&prefix, 0).is_some());
            assert_eq!(
                group.table.local_export_source(&prefix, 0),
                LocalExportSource::from_route(&route)
            );
            assert_eq!(group.table.uses_ordered_local_sources(), i > 1);
            assert!(
                group.rs_tagged.is_empty() && group.rs_named.is_empty() && group.rs_all.is_empty()
            );
            assert!(group.source_attrs.is_empty());
        }
        assert!(group.retire_first_group_page(3));
        assert_eq!(group.table.local_export_sources().len(), 0);
    }

    #[test]
    fn private_slab_promotes_only_when_a_new_row_needs_a_second_page() {
        use crate::loc_rib::REGISTRATION_PAGE_SIZE;
        use crate::manager::RibManager;
        use crate::slab::SEGMENT;

        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let (_qtx, qrx) = tokio::sync::mpsc::channel(1);
        let mut manager =
            RibManager::new(rx, qrx, None, None, rustbgpd_telemetry::BgpMetrics::new());
        let prefix = |slot: usize| {
            Prefix::V4(Ipv4Prefix::new(
                Ipv4Addr::from(u32::try_from(slot).unwrap()),
                32,
            ))
        };
        let page: std::collections::HashSet<_> = (0..REGISTRATION_PAGE_SIZE).map(prefix).collect();
        for &key in &page {
            let route = make_route_with_path_id(key, 0);
            assert!(manager.loc_rib.recompute(key, [&route].into_iter()));
        }
        let mut group = GroupRibOut::new(
            None,
            false,
            true,
            true,
            None,
            vec![(Afi::Ipv4, Safi::Unicast)],
            vec![],
            false,
            0,
        );
        // Both the first scan and a restart after journal overflow begin empty.
        for attempt in 0..2 {
            assert_eq!(group.table.bench_route_capacity(), 0);
            group = manager.stage_first_group_page(1, group, &page);
            assert_eq!(group.table.bench_route_capacity(), REGISTRATION_PAGE_SIZE);

            let key = prefix(0);
            let mut replacement = make_route_with_path_id(key, 0);
            replacement.next_hop = Ipv4Addr::new(192, 0, 2, 99).into();
            assert!(manager.loc_rib.recompute(key, [&replacement].into_iter()));
            for _ in 0..2 {
                // A replacement, then an unchanged repair.
                group = manager.stage_first_group_page(1, group, &[key].into());
                assert_eq!(
                    group.table.get(&key, 0).unwrap().next_hop,
                    replacement.next_hop
                );
                assert_eq!(group.table.bench_route_capacity(), REGISTRATION_PAGE_SIZE);
            }
            assert!(manager.loc_rib.recompute(key, std::iter::empty()));
            group = manager.stage_first_group_page(1, group, &[key].into());
            assert!(group.table.get(&key, 0).is_none());
            let extra = prefix(REGISTRATION_PAGE_SIZE);
            let fresh = make_route_with_path_id(extra, 0);
            assert!(manager.loc_rib.recompute(extra, [&fresh].into_iter()));
            group = manager.stage_first_group_page(1, group, &[extra].into());
            assert_eq!(group.table.len(), REGISTRATION_PAGE_SIZE);
            assert_eq!(group.table.bench_route_capacity(), REGISTRATION_PAGE_SIZE);

            let restored = make_route_with_path_id(key, 0);
            assert!(manager.loc_rib.recompute(key, [&restored].into_iter()));
            group = manager.stage_first_group_page(1, group, &[key].into());
            assert_eq!(group.table.len(), REGISTRATION_PAGE_SIZE + 1);
            assert_eq!(group.table.bench_route_capacity(), SEGMENT);
            if attempt == 0 {
                group = group.empty_first_group_table();
                assert!(manager.loc_rib.recompute(extra, std::iter::empty()));
            }
        }
    }

    #[test]
    fn retirement_charges_withdrawn_slots_and_releases_bodies_and_indexes_in_pages() {
        use crate::manager::slice_timing::take_first_group_retirement_work;

        let mut group = GroupRibOut::new(
            None,
            false,
            true,
            true,
            None,
            vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)],
            vec![],
            false,
            0,
        );
        let mut keys = Vec::new();
        for i in 0..8u32 {
            let prefix = if i % 2 == 0 {
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(i + 1), 32))
            } else {
                Prefix::V6(Ipv6Prefix::new(Ipv6Addr::from(u128::from(i + 1)), 128))
            };
            let mut route = make_route_with_path_id(prefix, 0);
            if i % 2 == 0 {
                route.peer = PeerId::LOCAL;
            }
            keys.push((prefix, Arc::downgrade(&route.attributes)));
            group.apply_delta(&delta(prefix, Some(route)));
        }
        for (prefix, _) in &keys[5..] {
            group.apply_delta(&delta(*prefix, None));
        }
        take_first_group_retirement_work();
        assert!(!group.retire_first_group_page(0));
        assert_eq!(take_first_group_retirement_work(), [0, 0, 0]);
        assert!(
            !group.retire_first_group_page(2),
            "two holes consume this page"
        );
        assert_eq!(take_first_group_retirement_work(), [2, 0, 0]);
        assert_eq!(group.table.len(), 5);
        assert!(
            !group.retire_first_group_page(2),
            "one more hole, then one body"
        );
        assert_eq!(take_first_group_retirement_work(), [2, 0, 0]);
        assert_eq!(group.table.len(), 4);
        for (index, (prefix, attrs)) in keys.iter().enumerate() {
            assert_eq!(attrs.strong_count(), usize::from(index < 4));
            assert_eq!(group.table.get(prefix, 0).is_some(), index < 4);
            assert_eq!(
                group.table.local_export_source(prefix, 0).is_some(),
                index < 4 && index % 2 == 0
            );
        }
        assert!(group.retire_first_group_page(4));
        assert_eq!(take_first_group_retirement_work(), [4, 0, 0]);
        assert!(group.retire_first_group_page(0));
        assert_eq!(take_first_group_retirement_work(), [0, 0, 0]);
        assert!(keys.iter().all(|(_, attrs)| attrs.strong_count() == 0));
        assert_eq!(group.table.local_export_sources().len(), 0);
        assert!(group.source_counts.is_empty());
        assert_eq!(group.family_totals, [0; 4]);
    }
}
