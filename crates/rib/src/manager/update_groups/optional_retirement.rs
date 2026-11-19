//! Retire a memberless, single-best unicast destination before reusing its slot.

use super::{
    FastMap, FastState, GroupRibOut, HashSet, Prefix, Route, ShardedMap, merge_owned_maps,
};

/// An optional preparation can be discarded before ever gaining a member.
/// For a blocking role its OTC denials need a bucket-addressable store, as
/// they have no advertised row to find them by during retirement. The map
/// remains the group's only OTC store if the destination is adopted.
#[derive(Debug)]
pub(super) enum OtcBlocked {
    Ordinary(FastMap<(Prefix, u32), Route>),
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

    pub(super) fn replace_for<S: std::hash::BuildHasher>(
        &mut self,
        prefixes: &HashSet<Prefix, S>,
        blocked: &[Route],
        checkpoint: &mut impl FnMut(),
    ) {
        match self {
            Self::Ordinary(map) => {
                map.retain(|(prefix, _), _| {
                    checkpoint();
                    !prefixes.contains(prefix)
                });
                // Keep actor checkpoints around growth of the ordinary route map.
                let mut incoming =
                    FastMap::with_capacity_and_hasher(blocked.len(), FastState::default());
                checkpoint();
                for route in blocked {
                    checkpoint();
                    incoming.insert((route.prefix, route.path_id), route.clone());
                }
                merge_owned_maps(map, incoming, checkpoint);
            }
            Self::Optional(map) => {
                // A single-best staging pass can block only the path-0 winner.
                if !map.is_empty() {
                    for prefix in prefixes {
                        checkpoint();
                        map.remove(prefix);
                    }
                }
                for route in blocked {
                    checkpoint();
                    debug_assert_eq!(route.path_id, 0);
                    map.insert(route.prefix, route.clone());
                }
            }
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

pub(in crate::manager) struct OptionalGroupRetirement {
    group: GroupRibOut,
    denials: BucketCursor,
    otc: BucketCursor,
}

impl OptionalGroupRetirement {
    pub(in crate::manager) fn new(group: GroupRibOut) -> Self {
        debug_assert!(group.members.is_empty() && !group.per_client_best);
        debug_assert!(!group.stages_vpn() && !group.owns_evpn_routes());
        Self {
            group,
            denials: BucketCursor::default(),
            otc: BucketCursor::default(),
        }
    }

    pub(in crate::manager) fn export_policy(&self) -> Option<&rustbgpd_policy::PolicyChain> {
        self.group.export_chain.as_ref()
    }

    /// Share the caller's budget with detached inventory and its change logs.
    /// A slab slot (including a hole or spare segment) retires the associated
    /// route, prefix index, next-hop, local provenance and source count together.
    pub(in crate::manager) fn retire_page(&mut self, budget: &mut usize) -> bool {
        while !self.group.table.first_group_retirement_finished() {
            if *budget == 0 {
                return false;
            }
            *budget -= 1;
            if let Some((source, prefix)) = self.group.table.retire_first_group_slot() {
                self.group.dec_source(source, &prefix);
                if !self.group.source_control_passthrough {
                    self.group.source_attrs.remove(&(prefix, 0));
                }
            }
        }
        debug_assert!(self.group.source_counts.is_empty() && self.group.source_attrs.is_empty());
        // The single-best stager replaces each prefix's entire denial map
        // with at most one (source, path ID) and its Arc<str> policy label.
        if !self.denials.drain(&mut self.group.policy_filtered, budget) {
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
