//! Compact slab storage for route bodies (LAN-335).
//!
//! The route-bearing maps used to store ~130-byte route values inline in
//! hashbrown bucket arrays, paying the table's power-of-two capacity slack
//! per value (the dominant heap cost in the 2026-07 dhat re-baseline).
//! [`RouteSlab`] stores the bodies densely in a `Vec` behind `u32` handles,
//! so the maps and prefix-trie indexes only carry 4-byte handles.
//!
//! `Option<T>` costs nothing for the stored route types: they all carry a
//! non-null `Arc`, so the niche optimization folds the vacancy discriminant
//! into the payload (asserted by `option_is_niche_free_for_route_types`).
//!
//! Freed slots are pushed onto a free list and reused by later inserts, so
//! sustained insert/withdraw churn does not grow the slot vector.

/// Dense storage for route bodies addressed by `u32` handles.
///
/// Not a general-purpose slab: handles are only valid until `remove` or
/// `clear`, and the owner (a RIB table) is responsible for never holding a
/// stale handle — its map/index and this slab are mutated together.
#[derive(Debug)]
pub(crate) struct RouteSlab<T> {
    slots: Vec<Option<T>>,
    free: Vec<u32>,
}

impl<T> Default for RouteSlab<T> {
    fn default() -> Self {
        Self::with_capacity(0)
    }
}

impl<T> RouteSlab<T> {
    /// Create a slab with pre-sized slot capacity.
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            slots: Vec::with_capacity(capacity),
            free: Vec::new(),
        }
    }

    /// Store a value, returning its handle. Reuses a freed slot when one
    /// is available.
    pub(crate) fn insert(&mut self, value: T) -> u32 {
        if let Some(handle) = self.free.pop() {
            self.slots[handle as usize] = Some(value);
            handle
        } else {
            let handle =
                u32::try_from(self.slots.len()).expect("route slab exceeds u32 handle space");
            self.slots.push(Some(value));
            handle
        }
    }

    /// Remove and return the value at `handle`, freeing the slot for reuse.
    pub(crate) fn remove(&mut self, handle: u32) -> Option<T> {
        let value = self.slots.get_mut(handle as usize)?.take();
        if value.is_some() {
            self.free.push(handle);
        }
        value
    }

    /// Replace the value in an occupied slot.
    pub(crate) fn set(&mut self, handle: u32, value: T) {
        let slot = &mut self.slots[handle as usize];
        debug_assert!(slot.is_some(), "RouteSlab::set on a vacant slot");
        *slot = Some(value);
    }

    pub(crate) fn get(&self, handle: u32) -> Option<&T> {
        self.slots.get(handle as usize)?.as_ref()
    }

    pub(crate) fn get_mut(&mut self, handle: u32) -> Option<&mut T> {
        self.slots.get_mut(handle as usize)?.as_mut()
    }

    /// Number of occupied slots.
    pub(crate) fn len(&self) -> usize {
        self.slots.len() - self.free.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Backing slot capacity (the memory-profile analog of
    /// `HashMap::capacity` on the maps this replaces).
    #[cfg(feature = "bench-internals")]
    pub(crate) fn capacity(&self) -> usize {
        self.slots.capacity()
    }

    /// Total slots ever allocated (occupied + free). Test-only leak probe:
    /// steady-state churn must not grow this.
    #[cfg(test)]
    pub(crate) fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Drop every value. Keeps the slot allocation, like `HashMap::clear`.
    pub(crate) fn clear(&mut self) {
        self.slots.clear();
        self.free.clear();
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.slots.iter().filter_map(Option::as_ref)
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.slots.iter_mut().filter_map(Option::as_mut)
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
        assert_eq!(slab.len(), 1);
    }

    #[test]
    fn removed_slots_are_reused_so_churn_does_not_grow_the_slab() {
        let mut slab: RouteSlab<u64> = RouteSlab::default();
        let handles: Vec<u32> = (0..1000).map(|i| slab.insert(i)).collect();
        assert_eq!(slab.slots.len(), 1000);
        for h in &handles {
            slab.remove(*h);
        }
        assert!(slab.is_empty());
        for i in 0..1000 {
            slab.insert(i);
        }
        assert_eq!(slab.len(), 1000);
        assert_eq!(
            slab.slots.len(),
            1000,
            "withdraw/re-insert churn must reuse freed slots, not grow"
        );
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

    /// The whole point of the slab is compactness: `Option<Route>` must not
    /// pay a discriminant word — the non-null `Arc` inside `Route` provides
    /// the niche.
    #[test]
    fn option_is_niche_free_for_route_types() {
        use crate::route::Route;
        use std::mem::size_of;
        assert_eq!(size_of::<Option<Route>>(), size_of::<Route>());
    }
}
