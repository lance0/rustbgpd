//! Ordered union of the inputs to one startup unicast family release.
//! A source parks on its next prefix, so a continuation retains neither
//! route payloads nor a second copy of the family.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};
use std::num::NonZeroU32;
use std::ops::{Bound, RangeInclusive};

use rustbgpd_wire::{Afi, Prefix, Safi};

use crate::manager::{AdjRibInEpoch, RibManager, helpers::prefix_family};
use crate::update::route_query_start_prefix;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Source {
    Deferred,
    Frozen,
    Announcer(NonZeroU32),
}

#[derive(Debug)]
pub(in crate::manager) struct UnicastReleaseInventory {
    afi: Afi,
    initial: [Option<Source>; 2],
    epochs: RangeInclusive<u32>,
    frontier: BinaryHeap<Reverse<(Prefix, Source)>>,
    last: Option<Prefix>,
    #[cfg(test)]
    pub(in crate::manager) source_steps: usize,
}

impl RibManager {
    /// Resume ordinary lazy listing-index maintenance when both startup
    /// unicast windows have closed. Dataplane index mode remains independent.
    pub(in crate::manager) fn update_selection_inventory_index(&mut self) {
        let needed = self.selection_deferral.as_ref().is_some_and(|deferral| {
            [Afi::Ipv4, Afi::Ipv6]
                .into_iter()
                .any(|afi| deferral.may_hold_family((afi, Safi::Unicast)))
        });
        self.loc_rib.set_release_index_eager(needed);
    }

    pub(in crate::manager) fn unicast_release_inventory(
        &self,
        afi: Afi,
    ) -> UnicastReleaseInventory {
        let overflow = self
            .deferred_selection_keys
            .overflowed_families
            .contains(&(afi, Safi::Unicast));
        UnicastReleaseInventory {
            afi,
            initial: [Some(Source::Deferred), overflow.then_some(Source::Frozen)],
            // Every input with a unicast route has an announcer epoch. A retired
            // epoch is a charged miss. Peers added later publish through ingest.
            epochs: 1..=self.unicast_prefix_peers.next_epoch,
            // At most one Copy entry per live source at the captured epoch,
            // plus the deferred and frozen tables. No growth or per-source
            // destruction when a replacement waiter cancels this walk.
            frontier: BinaryHeap::with_capacity(self.unicast_prefix_peers.epoch_peers.len() + 2),
            last: None,
            #[cfg(test)]
            source_steps: 0,
        }
    }

    fn next_release_prefix(
        &self,
        source: Source,
        afi: Afi,
        after: Option<Prefix>,
    ) -> Option<Prefix> {
        let start = after.or_else(|| route_query_start_prefix(None, Some(afi)));
        let prefix = match source {
            Source::Deferred => {
                let lower = after.map_or_else(
                    || start.map_or(Bound::Unbounded, Bound::Included),
                    Bound::Excluded,
                );
                self.deferred_selection_keys
                    .unicast
                    .range((lower, Bound::Unbounded))
                    .next()
                    .map(|(key, ())| *key)
            }
            Source::Frozen => self
                .loc_rib
                .release_prefixes_from(start)
                .find(|key| Some(*key) != after),
            Source::Announcer(epoch) => {
                let peer = self
                    .unicast_prefix_peers
                    .epoch_peers
                    .get(&AdjRibInEpoch(epoch))?;
                self.ribs
                    .get(peer)?
                    .release_prefixes_from(start)
                    .find(|key| Some(*key) != after)
            }
        };
        prefix.filter(|key| prefix_family(key).0 == afi)
    }

    /// Each unit initializes one source or advances one frontier entry.
    /// Duplicates, dead epochs and exhausted sources all consume a unit.
    pub(in crate::manager) fn next_unicast_release_batch(
        &self,
        inventory: &mut UnicastReleaseInventory,
        budget: usize,
    ) -> (HashSet<Prefix>, bool) {
        debug_assert!(budget != 0);
        let mut keys = HashSet::new();
        for _ in 0..budget {
            let seed = inventory
                .initial
                .iter_mut()
                .find_map(Option::take)
                .or_else(|| {
                    inventory.epochs.next().map(|epoch| {
                        Source::Announcer(
                            NonZeroU32::new(epoch).expect("announcer epochs start at one"),
                        )
                    })
                });
            let (source, after) = if let Some(source) = seed {
                (source, None)
            } else if let Some(Reverse((key, source))) = inventory.frontier.pop() {
                if inventory.last != Some(key) {
                    inventory.last = Some(key);
                    keys.insert(key);
                }
                (source, Some(key))
            } else {
                return (keys, true);
            };
            #[cfg(test)]
            {
                inventory.source_steps += 1;
            }
            if let Some(key) = self.next_release_prefix(source, inventory.afi, after) {
                inventory.frontier.push(Reverse((key, source)));
            }
        }
        (keys, false)
    }

    /// Called only once current selection and export have taken ownership.
    /// Retained-byte charges stay with the family until its full release.
    pub(in crate::manager) fn retire_unicast_release_key(&mut self, key: Prefix) {
        let ledger = &mut self.deferred_selection_keys;
        if ledger.unicast.remove(&key).is_some() {
            ledger.retired_unicast_bytes[usize::from(matches!(key, Prefix::V6(_)))] +=
                size_of::<Prefix>();
        }
    }
}
