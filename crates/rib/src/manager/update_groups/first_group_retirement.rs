use super::GroupRibOut;

impl GroupRibOut {
    pub(in crate::manager) fn empty_first_group_table(&self) -> Self {
        Self::new(
            None,
            self.is_ebgp,
            self.interpret_rfc1997,
            self.is_rr_client,
            None,
            self.sendable.clone(),
            self.llgr.clone(),
            false,
            0,
        )
    }

    /// Retire an unpublished single-best unicast group with no policy, role,
    /// or members. Its only populated sidecars are keyed by route or source.
    /// Charge a slot even if a mid-build withdrawal already removed its row.
    pub(in crate::manager) fn retire_first_group_page(&mut self, budget: usize) -> bool {
        debug_assert!(self.members.is_empty() && !self.per_client_best);
        debug_assert!(self.export_chain.is_none() && self.local_role.is_none());
        debug_assert!(self.policy_filtered.is_empty() && self.otc_blocked.is_empty());
        for _ in 0..budget {
            if self.table.first_group_retirement_finished() {
                break;
            }
            if let Some((source, prefix)) = self.table.retire_first_group_slot() {
                self.dec_source(source, &prefix);
            }
        }
        let finished = self.table.first_group_retirement_finished();
        debug_assert!(!finished || self.source_counts.is_empty());
        finished
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
    fn private_staging_allocates_local_shards_only_on_first_local_row() {
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
            let shards = if i == 1 { 1 } else { crate::fast_hash::SHARDS };
            assert_eq!(group.table.local_source_shards(), shards);
            assert!(
                group.rs_tagged.is_empty() && group.rs_named.is_empty() && group.rs_all.is_empty()
            );
            assert!(group.source_attrs.is_empty());
        }
        assert!(group.retire_first_group_page(3));
        assert_eq!(group.table.local_export_sources().len(), 0);
    }

    #[test]
    fn retirement_charges_withdrawn_slots_and_releases_bodies_and_indexes_in_pages() {
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
        assert!(!group.retire_first_group_page(0));
        assert!(
            !group.retire_first_group_page(2),
            "two holes consume this page"
        );
        assert_eq!(group.table.len(), 5);
        assert!(
            !group.retire_first_group_page(2),
            "one more hole, then one body"
        );
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
        assert!(group.retire_first_group_page(0));
        assert!(keys.iter().all(|(_, attrs)| attrs.strong_count() == 0));
        assert_eq!(group.table.local_export_sources().len(), 0);
        assert!(group.source_counts.is_empty());
        assert_eq!(group.family_totals, [0; 4]);
    }
}
