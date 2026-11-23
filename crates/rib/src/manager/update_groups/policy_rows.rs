//! Route-keyed export policy state. A paced first group keeps its ordered
//! tables after publication so adoption never has to rehash a full inventory.

use std::collections::BTreeMap;
use std::hash::Hash;

use crate::fast_hash::ShardedMap;

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

    pub(super) fn get_or_default(&mut self, key: K) -> &mut V
    where
        V: Default,
    {
        match self {
            Self::Sharded(map) => map.get_or_default(key),
            Self::Ordered(map) => map.entry(key).or_default(),
        }
    }

    pub(super) fn insert(&mut self, key: K, value: V) {
        match self {
            Self::Sharded(map) => map.insert(key, value),
            Self::Ordered(map) => map.insert(key, value),
        };
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
    pub(super) fn retire_ordered(map: &mut BTreeMap<K, V>, budget: &mut usize) -> bool {
        while *budget > 0 && map.pop_first().is_some() {
            #[cfg(test)]
            crate::manager::slice_timing::record_work("first_group_retired_denials", 1);
            *budget -= 1;
        }
        map.is_empty()
    }
}
