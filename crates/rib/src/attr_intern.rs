//! Global cross-peer path-attribute interning (LAN-336).
//!
//! One table for the whole daemon, owned by the `RibManager` actor —
//! the analog of BIRD's refcounted `rta`/`ea_list` cache and OpenBGPD's
//! attribute hash. Interning used to live per `AdjRibIn` (one table per
//! peer), which deduplicated identical attribute sets *within* a peer
//! but stored one copy *per peer* when many peers carry the same set —
//! the common route-reflector / route-server reality (reflection
//! preserves `NEXT_HOP`, so dual-fed clients advertise byte-identical
//! attribute vectors).
//!
//! Ownership makes this lock-free: the manager task is the only writer,
//! so the table is a plain field threaded by `&mut` — no `Mutex`, no
//! atomics beyond the `Arc` counters that already exist.
//!
//! Reclaim is the `Arc::strong_count` sweep the per-peer tables already
//! used: an entry whose only reference is the table itself is dropped by
//! [`AttrInternTable::gc`]. Large-table unicast UPDATE chunks amortize sweeps
//! with a displaced-route limit and an actor deadline; explicit teardown,
//! injection, other-family, GR/LLGR and refresh seams retain immediate sweeps.
//! `Arc`'s reference count *is* the refcount; there is no separate bookkeeping
//! to drift out of sync.
//
// ponytail: gc remains an O(table) sweep. Unicast hot-path frequency is bounded,
// but each sweep still visits the global table. Revisit incremental sweeping
// if a single large-table sweep exceeds the actor work budget.

use std::sync::Arc;

use rustc_hash::FxHashSet;

use crate::attr_set::AttrSet;

/// Deduplicates identical `Arc<AttrSet>` allocations across
/// all peers and route families. See the module docs for ownership and
/// reclaim rules.
#[derive(Debug, Default)]
pub struct AttrInternTable {
    set: FxHashSet<Arc<AttrSet>>,
}

impl AttrInternTable {
    /// Create an empty intern table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern `attrs` in place: if identical content is already in the
    /// table, `attrs` is rewritten to the shared allocation and the
    /// caller's copy drops; otherwise this allocation is recorded as the
    /// canonical one.
    ///
    /// Normal announce callers intern before storing a route. The one mutation
    /// exception is GR-to-LLGR promotion: it copy-on-write transforms a stored
    /// attribute set, immediately re-interns the replacement, then recomputes
    /// every affected route before distribution. That ordering invalidates any
    /// old pointer-keyed export memo before the transformed route is emitted.
    pub fn intern(&mut self, attrs: &mut Arc<AttrSet>) {
        if let Some(existing) = self.set.get(attrs) {
            *attrs = Arc::clone(existing);
        } else {
            self.set.insert(Arc::clone(attrs));
        }
    }

    /// Drop entries whose only remaining reference is the table itself
    /// (`strong_count == 1`): no route in any RIB, Loc-RIB clone, or
    /// in-flight export still uses them.
    pub fn gc(&mut self) {
        self.set.retain(|a| Arc::strong_count(a) > 1);
    }

    /// Number of unique interned attribute sets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// `true` if the table holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Backing capacity of the table, for memory-profile harnesses.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.set.capacity()
    }
}

#[cfg(test)]
mod tests {
    use rustbgpd_wire::{Origin, PathAttribute};

    use super::*;

    fn attrs(med: u32) -> Arc<AttrSet> {
        AttrSet::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::Med(med),
        ])
    }

    #[test]
    fn intern_deduplicates_identical_content() {
        let mut table = AttrInternTable::new();
        let mut a = attrs(1);
        let mut b = attrs(1);
        assert!(!Arc::ptr_eq(&a, &b));
        table.intern(&mut a);
        table.intern(&mut b);
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn intern_separates_different_content() {
        let mut table = AttrInternTable::new();
        let mut a = attrs(1);
        let mut b = attrs(2);
        table.intern(&mut a);
        table.intern(&mut b);
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn gc_removes_unreferenced_entries_only() {
        let mut table = AttrInternTable::new();
        let mut a = attrs(1);
        let mut b = attrs(2);
        table.intern(&mut a);
        table.intern(&mut b);
        drop(b);
        assert_eq!(table.len(), 2, "entries persist until gc");
        table.gc();
        assert_eq!(table.len(), 1, "unreferenced entry reclaimed");
        table.gc();
        assert_eq!(table.len(), 1, "referenced entry survives repeated gc");
        drop(a);
        table.gc();
        assert!(table.is_empty());
    }
}
