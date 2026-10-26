//! Compact slab storage for route bodies (LAN-335).
//!
//! The route-bearing maps used to store ~130-byte route values inline in
//! hashbrown bucket arrays, paying the table's power-of-two capacity slack
//! per value (the dominant heap cost in the 2026-07 dhat re-baseline).
//! [`crate::slab::RouteSlab`] stores the bodies densely behind `u32` handles,
//! so the maps and prefix-trie indexes only carry 4-byte handles.
//!
//! `Option<T>` costs nothing for the stored route types: they all carry a
//! non-null `Arc`, so the niche optimization folds the vacancy discriminant
//! into the payload (asserted by `option_is_niche_free_for_route_types`).
//!
//! Freed slots are pushed onto a free list and reused by later inserts, so
//! sustained insert/withdraw churn does not grow the slot count.
//!
//! Slots live in fixed segments of [`SEGMENT`] slots. A single `Vec` doubled
//! by copying every route inside one insert: about 100 MiB and 50-60 ms at
//! 1M routes, a RIB actor stall no checkpoint could split. Growth now copies
//! at most one segment, and the tail slack is at most one segment instead of
//! up to the whole table.

use crate::adj_rib_out::{RetirementCheckpoint, RetirementProgress};

/// Slots per segment: 64Ki routes, about 6.5 MiB of 104-byte route bodies.
const SEGMENT: usize = 1 << 16;

/// Dense storage for route bodies addressed by `u32` handles.
///
/// Not a general-purpose slab: handles are only valid until `remove` or
/// `clear`, and the owner (a RIB table) is responsible for never holding a
/// stale handle — its map/index and this slab are mutated together.
#[derive(Debug)]
pub(crate) struct RouteSlab<T> {
    /// Slot `h` is `segments[h / SEGMENT][h % SEGMENT]`. Only the segment
    /// holding the next new slot can be partly filled; segments after it are
    /// empty preallocations. A small table keeps one segment that grows like
    /// a `Vec` up to [`SEGMENT`] slots.
    segments: Vec<Vec<Option<T>>>,
    /// Slots ever allocated (occupied + free): the next new handle.
    slots: usize,
    free: Vec<u32>,
}

impl<T> Default for RouteSlab<T> {
    fn default() -> Self {
        Self {
            segments: Vec::new(),
            slots: 0,
            free: Vec::new(),
        }
    }
}

impl<T> RouteSlab<T> {
    /// Create a slab with pre-sized slot capacity.
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        let mut slab = Self::default();
        slab.reserve_with(capacity, &mut || {});
        slab
    }

    /// Store a value, returning its handle. Reuses a freed slot when one
    /// is available.
    pub(crate) fn insert(&mut self, value: T) -> u32 {
        if let Some(handle) = self.free.pop() {
            *self.slot_mut(handle) = Some(value);
            return handle;
        }
        let handle = u32::try_from(self.slots).expect("route slab exceeds u32 handle space");
        let index = self.slots / SEGMENT;
        if index == self.segments.len() {
            self.segments.push(if index == 0 {
                Vec::new()
            } else {
                Vec::with_capacity(SEGMENT)
            });
        }
        let segment = &mut self.segments[index];
        if segment.len() == segment.capacity() {
            // Double like a `Vec`, but never past one segment.
            segment.reserve_exact(segment.capacity().max(4).min(SEGMENT - segment.len()));
        }
        segment.push(Some(value));
        self.slots += 1;
        handle
    }

    /// Ensure room for `additional` inserts. Allocates any missing segments
    /// and grows the partly filled one, copying at most one segment.
    pub(crate) fn reserve_with(&mut self, additional: usize, checkpoint: &mut impl FnMut()) {
        let target = self.slots + additional.saturating_sub(self.free.len());
        if target <= self.slots {
            return;
        }
        let last = (target - 1) / SEGMENT;
        for index in self.slots / SEGMENT..=last {
            let want = if index == last {
                target - index * SEGMENT
            } else {
                SEGMENT
            };
            if index == self.segments.len() {
                checkpoint();
                self.segments
                    .push(Vec::with_capacity(if index == 0 { want } else { SEGMENT }));
                checkpoint();
            } else if self.segments[index].capacity() < want {
                let segment = &mut self.segments[index];
                // At least double, so per-batch reserves stay amortized.
                let grown = want.max((2 * segment.capacity()).min(SEGMENT));
                checkpoint();
                segment.reserve_exact(grown - segment.len());
                checkpoint();
            }
        }
    }

    fn slot(&self, handle: u32) -> Option<&Option<T>> {
        let handle = handle as usize;
        self.segments.get(handle / SEGMENT)?.get(handle % SEGMENT)
    }

    fn slot_mut(&mut self, handle: u32) -> &mut Option<T> {
        let handle = handle as usize;
        &mut self.segments[handle / SEGMENT][handle % SEGMENT]
    }

    /// Remove and return the value at `handle`, freeing the slot for reuse.
    pub(crate) fn remove(&mut self, handle: u32) -> Option<T> {
        self.slot(handle)?;
        let value = self.slot_mut(handle).take();
        if value.is_some() {
            self.free.push(handle);
        }
        value
    }

    /// Replace the value in an occupied slot.
    pub(crate) fn set(&mut self, handle: u32, value: T) {
        let slot = self.slot_mut(handle);
        debug_assert!(slot.is_some(), "RouteSlab::set on a vacant slot");
        *slot = Some(value);
    }

    pub(crate) fn get(&self, handle: u32) -> Option<&T> {
        self.slot(handle)?.as_ref()
    }

    pub(crate) fn get_mut(&mut self, handle: u32) -> Option<&mut T> {
        self.slot(handle)?;
        self.slot_mut(handle).as_mut()
    }

    /// Number of occupied slots.
    pub(crate) fn len(&self) -> usize {
        self.slots - self.free.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Backing slot capacity (the memory-profile analog of
    /// `HashMap::capacity` on the maps this replaces).
    #[cfg(any(test, feature = "bench-internals"))]
    pub(crate) fn capacity(&self) -> usize {
        self.segments.iter().map(Vec::capacity).sum()
    }

    /// Total slots ever allocated (occupied + free): the bound of a
    /// handle-order walk. Also the tests' leak probe: steady-state churn
    /// must not grow this.
    pub(crate) fn slot_count(&self) -> usize {
        self.slots
    }

    /// Drop every value. Keeps the slot allocations, like `HashMap::clear`.
    pub(crate) fn clear(&mut self) {
        self.segments.iter_mut().for_each(Vec::clear);
        self.slots = 0;
        self.free.clear();
    }

    /// Drop every slot, including vacancies, while retaining both backing
    /// allocations for later reuse.
    pub(crate) fn retire_with(&mut self, checkpoint: &mut impl RetirementCheckpoint) {
        self.free.clear();
        while self.slots > 0 {
            self.slots -= 1;
            let slot = self.segments[self.slots / SEGMENT]
                .pop()
                .expect("slot count matches segment lengths");
            let progress = if slot.is_some() {
                RetirementProgress::Progress
            } else {
                RetirementProgress::Boundary
            };
            checkpoint.checkpoint(progress);
            drop(slot);
            checkpoint.checkpoint(progress);
        }
    }

    /// Retire every slot, then release the empty backing allocations.
    pub(crate) fn release_with(&mut self, checkpoint: &mut impl RetirementCheckpoint) {
        self.retire_with(checkpoint);

        let segments = std::mem::take(&mut self.segments);
        checkpoint.checkpoint(RetirementProgress::Boundary);
        drop(segments);
        checkpoint.checkpoint(RetirementProgress::Boundary);

        let free = std::mem::take(&mut self.free);
        checkpoint.checkpoint(RetirementProgress::Boundary);
        drop(free);
        checkpoint.checkpoint(RetirementProgress::Boundary);
    }

    /// Release only unused tail capacity while preserving logical slot
    /// indices, handles, occupancy, and the free list.
    pub(crate) fn shrink_to_fit(&mut self) {
        self.segments.truncate(self.slots.div_ceil(SEGMENT));
        if let Some(tail) = self.segments.last_mut() {
            tail.shrink_to_fit();
        }
        self.segments.shrink_to_fit();
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.segments.iter().flatten().filter_map(Option::as_ref)
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.segments
            .iter_mut()
            .flatten()
            .filter_map(Option::as_mut)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_get_remove_round_trip() {
        let mut slab: RouteSlab<String> = RouteSlab::default();
        let a = slab.insert("a".to_string());
        let b = slab.insert("b".to_string());
        assert_ne!(a, b);
        assert_eq!(slab.len(), 2);
        assert_eq!(slab.get(a).unwrap(), "a");
        assert_eq!(slab.get_mut(b).unwrap(), "b");
        assert_eq!(slab.remove(a), Some("a".to_string()));
        assert_eq!(slab.remove(a), None, "double-remove is a no-op");
        assert_eq!(slab.get(a), None);
        assert_eq!(slab.remove(99), None, "an unallocated handle is a no-op");
        assert_eq!(slab.len(), 1);
    }

    #[test]
    fn removed_slots_are_reused_so_churn_does_not_grow_the_slab() {
        let mut slab: RouteSlab<u64> = RouteSlab::default();
        let handles: Vec<u32> = (0..1000).map(|i| slab.insert(i)).collect();
        assert_eq!(slab.slot_count(), 1000);
        for h in &handles {
            slab.remove(*h);
        }
        assert!(slab.is_empty());
        for i in 0..1000 {
            slab.insert(i);
        }
        assert_eq!(slab.len(), 1000);
        assert_eq!(
            slab.slot_count(),
            1000,
            "withdraw/re-insert churn must reuse freed slots, not grow"
        );
    }

    /// A full-table slab must never copy the table to grow: each insert may
    /// add at most one segment of capacity. A single `Vec` doubles from 2
    /// segments to 4 inside one insert.
    #[test]
    fn growth_adds_at_most_one_segment_per_insert() {
        let mut slab: RouteSlab<u64> = RouteSlab::default();
        let mut before = slab.capacity();
        let mut first = None;
        for value in 0..4 * SEGMENT as u64 {
            let handle = slab.insert(value);
            let after = slab.capacity();
            assert!(
                after - before <= SEGMENT,
                "insert {value} grew capacity {before} -> {after}, copying the table"
            );
            assert_eq!(slab.get(handle), Some(&value));
            if value == SEGMENT as u64 {
                first = Some(std::ptr::from_ref(slab.get(0).unwrap()));
            }
            before = after;
        }
        assert_eq!(before, 4 * SEGMENT, "no slack beyond the last segment");
        assert!(
            std::ptr::eq(slab.get(0).unwrap(), first.unwrap()),
            "a full segment is never moved"
        );
        assert_eq!(slab.iter().count(), 4 * SEGMENT);
        assert!(slab.iter().copied().eq(0..4 * SEGMENT as u64));
    }

    #[test]
    fn small_slabs_stay_small() {
        let mut slab: RouteSlab<u64> = RouteSlab::default();
        for value in 0..5 {
            slab.insert(value);
        }
        assert!(slab.capacity() <= 8);
        assert_eq!(RouteSlab::<u64>::with_capacity(3).capacity(), 3);
    }

    #[test]
    fn shrink_to_fit_preserves_handles_occupancy_and_free_slots() {
        let mut slab = RouteSlab::with_capacity(64);
        let handles: Vec<_> = (0..8).map(|value| slab.insert(value)).collect();
        slab.remove(handles[2]);
        slab.remove(handles[5]);
        let free = slab.free.clone();
        let capacity_before = slab.capacity();

        slab.shrink_to_fit();

        let capacity_after = slab.capacity();
        assert!(capacity_after >= slab.slot_count());
        assert!(capacity_after <= capacity_before);
        assert_eq!(slab.len(), 6);
        assert_eq!(slab.free, free);
        for (index, handle) in handles.into_iter().enumerate() {
            assert_eq!(
                slab.get(handle),
                (![2, 5].contains(&index)).then_some(&index)
            );
        }
    }

    #[test]
    fn shrink_to_fit_drops_empty_tail_segments() {
        let mut slab = RouteSlab::with_capacity(3 * SEGMENT);
        let handle = slab.insert(1_u64);
        slab.shrink_to_fit();
        assert_eq!(slab.capacity(), 1);
        assert_eq!(slab.get(handle), Some(&1));
        assert_eq!(slab.insert(2), 1);
    }

    #[test]
    fn reserve_preserves_holes_handles_and_free_reuse() {
        let mut slab = RouteSlab::with_capacity(3);
        let first = slab.insert(10_u64);
        let hole = slab.insert(20);
        let last = slab.insert(30);
        assert_eq!(slab.remove(hole), Some(20));
        let free = slab.free.clone();
        let old_capacity = slab.capacity();

        slab.reserve_with(4, &mut || {});

        assert!(slab.capacity() >= 6);
        assert!(slab.capacity() > old_capacity);
        assert_eq!(slab.slot_count(), 3);
        assert_eq!(slab.free, free);
        assert_eq!(slab.get(first), Some(&10));
        assert_eq!(slab.get(hole), None);
        assert_eq!(slab.get(last), Some(&30));
        assert_eq!(slab.insert(40), hole, "the free list stays LIFO");

        assert_eq!(slab.remove(last), Some(30));
        let capacity = slab.capacity();
        let mut no_growth_checkpoints = 0;
        slab.reserve_with(1, &mut || no_growth_checkpoints += 1);
        assert_eq!(slab.capacity(), capacity, "a free slot satisfies the batch");
        assert_eq!(no_growth_checkpoints, 0);
        assert_eq!(
            slab.insert(50),
            last,
            "the existing free slot remains reusable"
        );
    }

    #[test]
    fn reserve_across_segments_then_fill_moves_nothing() {
        let mut slab: RouteSlab<u64> = RouteSlab::default();
        slab.insert(0);
        slab.reserve_with(3 * SEGMENT, &mut || {});
        let capacity = slab.capacity();
        assert!(capacity > 3 * SEGMENT);
        assert!(capacity <= 4 * SEGMENT);
        for value in 1..=3 * SEGMENT as u64 {
            slab.insert(value);
        }
        assert_eq!(slab.capacity(), capacity, "the reserve covered the batch");
    }

    #[test]
    fn small_reserves_grow_the_open_segment_geometrically() {
        let mut slab = RouteSlab::with_capacity(64);
        for value in 0..64_u64 {
            slab.insert(value);
        }
        let mut growths = 0;
        for value in 64..1024_u64 {
            let before = slab.capacity();
            slab.reserve_with(1, &mut || {});
            if slab.capacity() != before {
                growths += 1;
            }
            slab.insert(value);
        }
        assert_eq!(growths, 4, "64 -> 128 -> 256 -> 512 -> 1024");
    }

    #[test]
    fn set_replaces_in_place() {
        let mut slab: RouteSlab<u64> = RouteSlab::default();
        let h = slab.insert(1);
        slab.set(h, 2);
        assert_eq!(slab.get(h), Some(&2));
        assert_eq!(slab.len(), 1);
    }

    #[test]
    fn clear_empties_and_invalidates_handles() {
        let mut slab: RouteSlab<u64> = RouteSlab::default();
        let h = slab.insert(7);
        slab.clear();
        assert!(slab.is_empty());
        assert_eq!(slab.get(h), None);
        // Fresh inserts after clear start from slot zero again.
        assert_eq!(slab.insert(8), 0);
    }

    #[test]
    fn retire_visits_holes_and_preserves_capacity() {
        let mut slab = RouteSlab::with_capacity(8);
        let first = slab.insert(1_u64);
        slab.insert(2);
        slab.remove(first);
        let capacity = slab.capacity();
        let mut checkpoints = 0;

        slab.retire_with(&mut || checkpoints += 1);

        assert_eq!(
            checkpoints, 4,
            "both slots, including the hole, are bracketed"
        );
        assert!(slab.is_empty());
        assert_eq!(slab.slot_count(), 0);
        assert_eq!(slab.capacity(), capacity);
        assert_eq!(slab.insert(3), 0);
    }

    #[test]
    fn retire_and_refill_across_segments() {
        let mut slab: RouteSlab<u64> = RouteSlab::default();
        for value in 0..SEGMENT as u64 + 3 {
            slab.insert(value);
        }
        let capacity = slab.capacity();
        slab.retire_with(&mut || {});
        assert_eq!(slab.slot_count(), 0);
        assert_eq!(slab.capacity(), capacity);
        for value in 0..SEGMENT as u64 + 3 {
            assert_eq!(slab.insert(value), u32::try_from(value).unwrap());
        }
        assert_eq!(slab.capacity(), capacity);
    }

    /// The whole point of the slab is compactness: `Option<Route>` must not
    /// pay a discriminant word — the non-null `Arc` inside `Route` provides
    /// the niche.
    #[test]
    fn option_is_niche_free_for_route_types() {
        use crate::route::Route;
        use std::mem::size_of;
        assert_eq!(size_of::<Option<Route>>(), size_of::<Route>());
        assert_eq!(size_of::<Route>(), 104);
    }
}
