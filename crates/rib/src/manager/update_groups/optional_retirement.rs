//! Retire a memberless, single-best unicast destination before reusing its slot.

use super::policy_transition::retire_inventory_vec;
use super::{
    AddrMap, BatchedMemberSupplement, BatchedTransitionCounters, FastMap, GroupRibOut,
    NextHopAction, PeerId, PolicyLabel, PolicyRows, Prefix, Route, ShardedMap,
};

/// An optional preparation can be discarded before ever gaining a member.
/// For a blocking role its OTC denials need a bucket-addressable store, as
/// they have no advertised row to find them by during retirement. The map
/// remains the group's only OTC store if the destination is adopted.
#[derive(Debug)]
pub(super) enum OtcBlocked {
    Ordinary(FastMap<Prefix, Route>),
    Optional(ShardedMap<Prefix, Route>),
}

impl OtcBlocked {
    pub(super) fn is_empty(&self) -> bool {
        match self {
            Self::Ordinary(map) => map.is_empty(),
            Self::Optional(map) => map.is_empty(),
        }
    }

    #[cfg(feature = "bench-internals")]
    pub(super) fn storage_shape(&self) -> (usize, usize) {
        match self {
            Self::Ordinary(map) => (map.len(), map.capacity()),
            Self::Optional(map) => (map.len(), map.capacity()),
        }
    }

    pub(super) fn values(&self) -> impl Iterator<Item = &Route> {
        let (ordinary, optional) = match self {
            Self::Ordinary(map) => (Some(map.values()), None),
            Self::Optional(map) => (None, Some(map.values())),
        };
        ordinary
            .into_iter()
            .flatten()
            .chain(optional.into_iter().flatten())
    }

    pub(super) fn retire_with(&mut self, checkpoint: &mut impl FnMut()) {
        match self {
            Self::Ordinary(map) => crate::adj_rib_out::release_hash_map(map, checkpoint),
            Self::Optional(map) => crate::adj_rib_out::release_sharded_map(map, checkpoint),
        }
    }

    pub(super) fn get(&self, prefix: &Prefix) -> Option<&Route> {
        match self {
            Self::Ordinary(map) => map.get(prefix),
            Self::Optional(map) => map.get(prefix),
        }
    }

    pub(super) fn capacity(&self) -> usize {
        match self {
            Self::Ordinary(map) => map.capacity(),
            Self::Optional(map) => map.capacity(),
        }
    }
}

impl GroupRibOut {
    /// Called only when an optional preparation creates a fresh table.
    pub(in crate::manager) fn prepare_optional_retirement(&mut self) {
        debug_assert!(
            self.members.is_empty() && !self.per_client_best && self.otc_blocked.is_empty()
        );
        if crate::manager::distribution::otc_role_blocks(self.local_role) {
            self.otc_blocked = OtcBlocked::Optional(ShardedMap::default());
        }
    }
}

#[derive(Default)]
struct BucketCursor {
    shard: usize,
    bucket: usize,
}

impl BucketCursor {
    /// Removal never moves neighboring buckets. Empty shards can be skipped by
    /// their count; every inspected bucket of a populated shard costs one unit.
    fn drain<K, V>(&mut self, map: &mut ShardedMap<K, V>, budget: &mut usize) -> bool {
        let shards = map.shards_mut();
        while let Some(shard) = shards.get_mut(self.shard) {
            while !shard.is_empty() {
                if *budget == 0 {
                    return false;
                }
                debug_assert!(self.bucket < shard.num_buckets());
                if let Ok(entry) = shard.get_bucket_entry(self.bucket) {
                    drop(entry.remove().0);
                }
                self.bucket += 1;
                *budget -= 1;
            }
            self.shard += 1;
            self.bucket = 0;
        }
        true
    }
}

/// A rejected single-best inventory stops during the destination walk.
/// Lane and denial counters are folded after that walk. Every partial permit
/// uses the one group permit label, and every supplement is a source-flip
/// withdrawal keyed by the source of an actual destination slot.
pub(in crate::manager) struct RejectedBatchedInventory {
    announce: Vec<Route>,
    next_hop: Vec<Option<NextHopAction>>,
    supplements: Option<AddrMap<PeerId, BatchedMemberSupplement>>,
    permit_totals: Option<FastMap<Option<PolicyLabel>, u64>>,
    permit_by_source: Option<AddrMap<PeerId, FastMap<Option<PolicyLabel>, u64>>>,
    pending_source: Option<PeerId>,
}

#[expect(
    clippy::ref_option,
    reason = "the whole Option is the borrowed hash key, including the unlabelled row"
)]
impl RejectedBatchedInventory {
    pub(super) fn new(
        announce: Vec<Route>,
        next_hop: Vec<Option<NextHopAction>>,
        supplements: AddrMap<PeerId, BatchedMemberSupplement>,
        counters: BatchedTransitionCounters,
    ) -> Self {
        debug_assert!(counters.permit_totals.len() <= 1);
        debug_assert!(counters.deny_totals.is_empty() && counters.deny_by_source.is_empty());
        debug_assert!(counters.lane_by_winner_source.is_empty());
        Self {
            announce,
            next_hop,
            // These fresh maps have only inserted rows. Keep their allocation
            // ownership explicitly until release; logical capacity can shrink
            // as removals leave tombstones.
            supplements: (!supplements.is_empty()).then_some(supplements),
            permit_totals: (!counters.permit_totals.is_empty()).then_some(counters.permit_totals),
            permit_by_source: (!counters.permit_by_source.is_empty())
                .then_some(counters.permit_by_source),
            pending_source: None,
        }
    }

    fn retire_vectors(&mut self, budget: &mut usize) -> bool {
        retire_inventory_vec(&mut self.announce, budget)
            && retire_inventory_vec(&mut self.next_hop, budget)
    }

    // The retiring table supplies the keys. Avoid a hash iterator that could
    // walk arbitrary holes between live sources or cost a second route walk.
    fn retire_source(&mut self, label: &Option<PolicyLabel>, budget: &mut usize) -> bool {
        let Some(source) = self.pending_source else {
            return true;
        };
        if let Some(permits) = &mut self.permit_by_source
            && let Some(labels) = permits.get_mut(&source)
        {
            if !Self::release_permit(labels, label, budget) || *budget == 0 {
                return false;
            }
            // Release the source's empty label-map allocation.
            *budget -= 1;
            permits.remove(&source);
        }
        if let Some(supplements) = &mut self.supplements
            && supplements.contains_key(&source)
        {
            if *budget == 0 {
                return false;
            }
            *budget -= 1;
            let supplement = supplements.remove(&source).expect("retiring source");
            debug_assert_eq!(supplement.announce.capacity(), 0);
            // The withdrawal keys are Copy, including when a large source
            // reserve was only partly filled before the cohort refused.
            drop(supplement);
        }
        self.pending_source = None;
        true
    }

    fn finish(&mut self, label: &Option<PolicyLabel>, budget: &mut usize) -> bool {
        if let Some(totals) = &mut self.permit_totals
            && !Self::release_permit(totals, label, budget)
        {
            return false;
        }
        debug_assert!(self.permit_by_source.as_ref().is_none_or(AddrMap::is_empty));
        debug_assert!(self.supplements.as_ref().is_none_or(AddrMap::is_empty));
        release_empty_map(&mut self.permit_totals, budget)
            && release_empty_map(&mut self.permit_by_source, budget)
            && release_empty_map(&mut self.supplements, budget)
    }

    // Both maps receiving permit labels are fresh and group-uniform. Remove the
    // only label by key, even if the allocation has mostly empty buckets.
    fn release_permit(
        rows: &mut FastMap<Option<PolicyLabel>, u64>,
        label: &Option<PolicyLabel>,
        budget: &mut usize,
    ) -> bool {
        if !rows.is_empty() {
            if *budget == 0 {
                return false;
            }
            *budget -= 1;
            rows.remove(label).expect("one group permit label");
            debug_assert!(rows.is_empty());
        }
        true
    }
}

fn release_empty_map<T>(map: &mut Option<T>, budget: &mut usize) -> bool {
    if map.is_some() {
        if *budget == 0 {
            return false;
        }
        *budget -= 1;
        *map = None;
    }
    true
}

pub(in crate::manager) struct OptionalGroupRetirement {
    group: GroupRibOut,
    rejected: Option<Box<RejectedBatchedInventory>>,
    denials: BucketCursor,
    otc: BucketCursor,
}

impl OptionalGroupRetirement {
    #[cfg(test)]
    pub(in crate::manager) fn new(group: GroupRibOut) -> Self {
        Self::with_refusal(group, None)
    }

    pub(in crate::manager) fn with_refusal(
        group: GroupRibOut,
        rejected: Option<Box<RejectedBatchedInventory>>,
    ) -> Self {
        debug_assert!(group.members.is_empty() && !group.per_client_best);
        debug_assert!(!group.stages_vpn() && !group.owns_evpn_routes());
        Self {
            group,
            rejected,
            denials: BucketCursor::default(),
            otc: BucketCursor::default(),
        }
    }

    #[cfg(test)]
    pub(in crate::manager) fn refused_inventory_rows_remaining(&self) -> Option<usize> {
        self.rejected.as_ref().map(|scratch| scratch.announce.len())
    }

    pub(in crate::manager) fn export_policy(&self) -> Option<&rustbgpd_policy::PolicyChain> {
        self.group.export_chain.as_ref()
    }

    /// Share the caller's budget with detached inventory and its change logs.
    /// A slab slot (including a hole or spare segment) retires the associated
    /// route, prefix index, next-hop, local provenance and source count together.
    pub(in crate::manager) fn retire_page(&mut self, budget: &mut usize) -> bool {
        if let Some(scratch) = &mut self.rejected
            && !scratch.retire_vectors(budget)
        {
            return false;
        }
        loop {
            if let Some(scratch) = &mut self.rejected
                && !scratch.retire_source(&self.group.permit_policy_label, budget)
            {
                return false;
            }
            if self.group.table.first_group_retirement_finished() {
                break;
            }
            if *budget == 0 {
                return false;
            }
            *budget -= 1;
            let source = self.group.retire_first_group_slot();
            if let Some(scratch) = &mut self.rejected {
                scratch.pending_source = source;
            }
        }
        if let Some(scratch) = &mut self.rejected {
            if !scratch.finish(&self.group.permit_policy_label, budget) || *budget == 0 {
                return false;
            }
            *budget -= 1;
            self.rejected = None;
        }
        debug_assert!(self.group.source_counts.is_empty() && self.group.source_attrs.is_empty());
        // The single-best stager replaces each prefix's entire denial map
        // with at most one (source, path ID) and its Arc<str> policy label.
        let denials_retired = match &mut self.group.policy_filtered {
            PolicyRows::Sharded(map) => self.denials.drain(map, budget),
            PolicyRows::Ordered(map) => PolicyRows::retire_ordered(map, budget),
        };
        if !denials_retired {
            return false;
        }
        match &mut self.group.otc_blocked {
            OtcBlocked::Optional(map) => self.otc.drain(map, budget),
            OtcBlocked::Ordinary(map) => {
                debug_assert!(
                    map.is_empty(),
                    "a blocking optional group must own its paged OTC map"
                );
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use super::*;
    use crate::loc_rib::REGISTRATION_PAGE_SIZE;
    use crate::manager::RibManager;
    use crate::test_support::{make_route_with_path_id, peer_v4};
    use rustbgpd_wire::{Afi, Ipv4Prefix, Safi};

    fn groups_with_late_action_change(
        winners: [PeerId; 2],
        rows: usize,
    ) -> (GroupRibOut, GroupRibOut) {
        let group = || {
            GroupRibOut::new(
                None,
                true,
                true,
                false,
                None,
                vec![(Afi::Ipv4, Safi::Unicast)],
                vec![],
                false,
                0,
            )
        };
        let (mut old, mut new) = (group(), group());
        new.permit_policy_label = Some(Arc::from("permit"));
        for index in 0..=rows {
            let prefix = Prefix::V4(Ipv4Prefix::new(
                Ipv4Addr::from(u32::try_from(index).unwrap()),
                32,
            ));
            let mut route = make_route_with_path_id(prefix, 0);
            let mut prior = route.clone();
            let action = if index == rows {
                Some(NextHopAction::Self_)
            } else {
                route.peer = winners[index % winners.len()];
                if index % 4 >= 2 {
                    prior.peer = route.peer;
                    prior.next_hop = Ipv4Addr::new(192, 0, 2, 123).into();
                }
                None
            };
            old.table.insert_with_next_hop(prior, None, &mut || {});
            new.inc_source(route.peer, &prefix);
            new.table.insert_with_next_hop(route, action, &mut || {});
        }
        (old, new)
    }

    #[test]
    fn late_source_flip_inventory_retires_by_slot_and_holds_its_last_references() {
        let winners = [
            peer_v4(Ipv4Addr::new(192, 0, 2, 10)),
            peer_v4(Ipv4Addr::new(192, 0, 2, 11)),
        ];
        let rows = REGISTRATION_PAGE_SIZE * 2;
        let (old, new) = groups_with_late_action_change(winners, rows);
        let label = Arc::downgrade(new.permit_policy_label.as_ref().unwrap());
        let mut scratch =
            RibManager::batched_transition_inventory(&old, &new, &[], true, |_| {}, &mut |_| {})
                .err()
                .flatten()
                .expect("the last action-only row refuses");
        drop(old);
        assert_eq!(scratch.announce.len(), rows);
        assert_eq!(
            scratch.permit_totals.as_ref().unwrap()[&new.permit_policy_label],
            u64::try_from(rows).unwrap()
        );
        for source in winners {
            let supplement = &mut scratch
                .supplements
                .as_mut()
                .unwrap()
                .get_mut(&source)
                .unwrap()
                .withdraw;
            assert_eq!(
                supplement.len(),
                rows / 4,
                "only half this source's winners flipped"
            );
            assert!(
                supplement.capacity() >= rows / winners.len(),
                "actual full-source reserve"
            );
            scratch
                .permit_by_source
                .as_mut()
                .unwrap()
                .get_mut(&source)
                .unwrap()
                .reserve(8 * rows);
        }
        // Even deliberately oversized reserves have no holes to traverse
        // when a source's actual row identifies the entry.
        scratch.supplements.as_mut().unwrap().reserve(8 * rows);
        scratch.permit_by_source.as_mut().unwrap().reserve(8 * rows);
        scratch.permit_totals.as_mut().unwrap().reserve(8 * rows);
        let attrs = Arc::downgrade(&scratch.announce.last().unwrap().attributes);
        assert_eq!(attrs.strong_count(), 2);
        assert_eq!(label.strong_count(), 1 + 1 + winners.len());
        let mut owner = OptionalGroupRetirement::with_refusal(new, Some(scratch));
        assert!(!owner.retire_page(&mut 0));
        assert_eq!(attrs.strong_count(), 2);
        let mut one = 1;
        assert!(!owner.retire_page(&mut one));
        assert_eq!(one, 0);
        assert_eq!(attrs.strong_count(), 1, "slab retains the announced route");
        let mut charged = 1;
        loop {
            // A one-unit remainder can always make progress, including when
            // the last slot left a singleton map and its allocation to release.
            let mut one = 1;
            let finished = owner.retire_page(&mut one);
            charged += 1 - one;
            if finished {
                break;
            }
            assert_eq!(one, 0);
        }
        // Announce rows and two vector allocations; every raw destination
        // slot; each source's label, label map and withdrawal vector;
        // one total label, three empty hash allocations and the scratch box.
        assert_eq!(
            charged,
            rows + 2 + (rows + 1) + 3 * winners.len() + 1 + 3 + 1
        );
        assert_eq!(attrs.strong_count(), 0);
        assert_eq!(
            label.strong_count(),
            1,
            "only the group owns the last label"
        );
        drop(owner);
        assert_eq!(label.strong_count(), 0);
    }
}
