//! Route-keyed group state. A paced first group keeps its ordered
//! tables after publication so adoption never has to rehash a full inventory.

use std::collections::BTreeMap;
use std::hash::Hash;

use crate::fast_hash::{AddrMap, ShardedMap};

use super::{PeerId, PolicyLabel};

/// Initial replay counts the group's current denials at enrollment, before
/// a live change can replace a denial whose prefix has not been replayed.
#[derive(Default)]
pub(super) struct SingleBestDenials {
    pub(super) labels: BTreeMap<Option<PolicyLabel>, (u64, BTreeMap<PeerId, u64>)>,
}

impl SingleBestDenials {
    pub(super) fn add(&mut self, source: PeerId, label: Option<PolicyLabel>) {
        let (total, sources) = self.labels.entry(label).or_default();
        *total += 1;
        *sources.entry(source).or_default() += 1;
    }

    pub(super) fn remove(&mut self, source: PeerId, label: Option<PolicyLabel>) {
        let std::collections::btree_map::Entry::Occupied(mut entry) = self.labels.entry(label)
        else {
            unreachable!("counted denial label");
        };
        let (total, sources) = entry.get_mut();
        *total -= 1;
        let own = sources.get_mut(&source).expect("counted denial source");
        *own -= 1;
        if *own == 0 {
            sources.remove(&source);
        }
        if *total == 0 {
            entry.remove();
        }
    }

    pub(super) fn retire_prefix(
        &mut self,
        denials: AddrMap<(PeerId, u32), Option<PolicyLabel>>,
        checkpoint: &mut impl FnMut(),
    ) {
        for ((source, _), label) in denials {
            checkpoint();
            self.remove(source, label);
        }
    }
}

#[derive(Debug)]
pub(super) enum PolicyRows<K, V> {
    Sharded(ShardedMap<K, V>),
    Ordered(BTreeMap<K, V>),
}

impl<K, V> Default for PolicyRows<K, V> {
    fn default() -> Self {
        Self::Sharded(ShardedMap::default())
    }
}

impl<K: Hash + Ord, V> PolicyRows<K, V> {
    #[cfg(test)]
    pub(super) fn sharded(&self) -> &ShardedMap<K, V> {
        let Self::Sharded(map) = self else {
            panic!("fixture requires ordinary storage")
        };
        map
    }

    pub(super) fn get(&self, key: &K) -> Option<&V> {
        match self {
            Self::Sharded(map) => map.get(key),
            Self::Ordered(map) => map.get(key),
        }
    }

    pub(super) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        match self {
            Self::Sharded(map) => map.get_mut(key),
            Self::Ordered(map) => map.get_mut(key),
        }
    }

    pub(super) fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    pub(super) fn get_or_default(&mut self, key: K) -> &mut V
    where
        V: Default,
    {
        match self {
            Self::Sharded(map) => map.get_or_default(key),
            Self::Ordered(map) => map.entry(key).or_default(),
        }
    }

    pub(super) fn insert(&mut self, key: K, value: V) -> Option<V> {
        match self {
            Self::Sharded(map) => map.insert(key, value),
            Self::Ordered(map) => map.insert(key, value),
        }
    }

    pub(super) fn remove(&mut self, key: &K) -> Option<V> {
        match self {
            Self::Sharded(map) => map.remove(key),
            Self::Ordered(map) => map.remove(key),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        match self {
            Self::Sharded(map) => map.is_empty(),
            Self::Ordered(map) => map.is_empty(),
        }
    }

    pub(super) fn len(&self) -> usize {
        match self {
            Self::Sharded(map) => map.len(),
            Self::Ordered(map) => map.len(),
        }
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        let (sharded, ordered) = match self {
            Self::Sharded(map) => (Some(map.iter()), None),
            Self::Ordered(map) => (None, Some(map.iter())),
        };
        sharded
            .into_iter()
            .flatten()
            .chain(ordered.into_iter().flatten())
    }

    pub(super) fn keys(&self) -> impl Iterator<Item = &K> {
        self.iter().map(|(key, _)| key)
    }

    pub(super) fn values(&self) -> impl Iterator<Item = &V> {
        self.iter().map(|(_, value)| value)
    }

    pub(super) fn release(&mut self, checkpoint: &mut impl FnMut()) {
        self.release_with(checkpoint, |entry, _| drop(entry));
    }

    pub(super) fn release_with<C: FnMut()>(
        &mut self,
        checkpoint: &mut C,
        mut retire: impl FnMut((K, V), &mut C),
    ) {
        match self {
            Self::Sharded(map) => {
                crate::adj_rib_out::release_sharded_map_values(map, checkpoint, retire);
            }
            Self::Ordered(map) => {
                for row in std::mem::take(map) {
                    checkpoint();
                    retire(row, checkpoint);
                }
                checkpoint();
            }
        }
    }

    /// A denied prefix has no advertised slot to drive its retirement.
    pub(super) fn retire_ordered(
        map: &mut BTreeMap<K, V>,
        budget: &mut usize,
        mut retire: impl FnMut(V),
    ) -> bool {
        while *budget > 0
            && let Some((_, row)) = map.pop_first()
        {
            retire(row);
            #[cfg(test)]
            crate::manager::slice_timing::record_work("first_group_retired_denials", 1);
            *budget -= 1;
        }
        map.is_empty()
    }
}

// A paced group must bound growth of each reverse-index set as well as the
// outer map. Ordinary groups keep the compact sharded representation.
impl<K: Ord + Hash, L: Ord + Hash> PolicyRows<K, PolicyRows<L, ()>> {
    #[expect(
        clippy::zero_sized_map_values,
        reason = "an ordered key set shares the PolicyRows representation of the sharded index"
    )]
    pub(super) fn insert_index_key(&mut self, key: K, value: L) {
        let set = match self {
            Self::Sharded(map) => map.get_or_default(key),
            Self::Ordered(map) => map
                .entry(key)
                .or_insert_with(|| PolicyRows::Ordered(BTreeMap::new())),
        };
        set.insert(value, ());
    }
}
