//! Nexthop ID allocator for ADR-0059 slice 3.
//!
//! Hands out tagged `u32` IDs for the kernel's nexthop table:
//!
//! - `0x3000_0000 | bitmap_id` for per-VTEP FDB nexthops.
//! - `0x4000_0000 | bitmap_id` for FDB nexthop groups.
//!
//! `bitmap_id` is in `[1, NH_ID_MAX]` (matching FRR's `EVPN_NH_ID_MAX`
//! = `0x4000`). The same bitmap backs both per-VTEP and NHG IDs — the
//! type bit is purely for `ip nexthop show` discriminability, and the
//! kernel does not enforce per-protocol ownership, so the bitmap stays
//! a single resource.
//!
//! The 0x3000 / 0x4000 tag bits are **deliberately offset** from FRR's
//! 0x1000 / 0x2000 so a host running both FRR and rustbgpd can't
//! collide on `NLM_F_REPLACE` (ADR-0059 §5 invariant 6).
//!
//! Startup adoption: when the dataplane starts, it dumps any existing
//! tagged IDs from the kernel and calls [`NhIdAllocator::reserve`] for
//! each one. This prevents the allocator from handing out an ID that
//! already exists in the kernel (which would silently `NLM_F_REPLACE`
//! the existing object — see ADR-0059 §5 invariant 6 + slice 3 review
//! callout #3).

use thiserror::Error;

/// Maximum `bitmap_id`. Inclusive. Matches FRR's `EVPN_NH_ID_MAX`.
pub const NH_ID_MAX: u32 = 0x4000;

/// Tag bits OR'd onto per-VTEP nexthop IDs.
pub const VTEP_NH_TAG: u32 = 0x3000_0000;

/// Tag bits OR'd onto FDB nexthop group IDs.
pub const NHG_TAG: u32 = 0x4000_0000;

/// Mask covering the high-nibble tag bits.
const TAG_MASK: u32 = 0xF000_0000;
/// Mask covering the bitmap-id portion (low 28 bits, but we only allocate
/// up to [`NH_ID_MAX`] = 0x4000).
const ID_MASK: u32 = 0x0FFF_FFFF;

/// `BitVec`-style allocator over `[1, NH_ID_MAX]`. Index 0 is reserved
/// (kernel rejects nexthop id 0).
#[derive(Debug, Clone)]
pub struct NhIdAllocator {
    /// `bitmap[i] == true` means `bitmap_id` `i` is in use. Index 0
    /// is reserved (kernel forbids `nh_id` 0); we leave it always `true`.
    bitmap: Vec<bool>,
}

impl Default for NhIdAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl NhIdAllocator {
    /// Build a fresh allocator with all `[1, NH_ID_MAX]` slots free
    /// and slot 0 permanently reserved.
    #[must_use]
    pub fn new() -> Self {
        let mut bitmap = vec![false; (NH_ID_MAX + 1) as usize];
        bitmap[0] = true; // 0 is permanently reserved
        Self { bitmap }
    }

    /// Allocate a per-VTEP nexthop ID. Tag bits `VTEP_NH_TAG` are
    /// OR'd onto the returned value.
    ///
    /// # Errors
    ///
    /// Returns [`NhIdError::Exhausted`] when no bitmap slot is free.
    pub fn alloc_vtep_nh(&mut self) -> Result<u32, NhIdError> {
        let bitmap_id = self.alloc_bitmap_slot()?;
        Ok(VTEP_NH_TAG | bitmap_id)
    }

    /// Allocate an FDB nexthop group ID. Tag bits `NHG_TAG` are OR'd
    /// onto the returned value.
    ///
    /// # Errors
    ///
    /// Returns [`NhIdError::Exhausted`] when no bitmap slot is free.
    pub fn alloc_nhg(&mut self) -> Result<u32, NhIdError> {
        let bitmap_id = self.alloc_bitmap_slot()?;
        Ok(NHG_TAG | bitmap_id)
    }

    /// Free a previously-allocated tagged ID. Strips the tag bits and
    /// clears the bitmap slot. No-ops on slot 0 (which stays
    /// reserved) and on IDs whose tag isn't ours.
    pub fn release(&mut self, id: u32) {
        if !Self::is_ours(id) {
            return;
        }
        let bitmap_id = (id & ID_MASK) as usize;
        if bitmap_id == 0 || bitmap_id > NH_ID_MAX as usize {
            return;
        }
        self.bitmap[bitmap_id] = false;
    }

    /// Reserve an ID seen during startup adoption (kernel already has
    /// this nexthop installed from a prior rustbgpd run). Idempotent
    /// on idempotent input.
    ///
    /// # Errors
    ///
    /// - [`NhIdError::NotOurs`] if the high-nibble tag bits don't
    ///   match either of our reservations.
    /// - [`NhIdError::OutOfRange`] if `bitmap_id` is 0 or > [`NH_ID_MAX`].
    pub fn reserve(&mut self, id: u32) -> Result<(), NhIdError> {
        if !Self::is_ours(id) {
            return Err(NhIdError::NotOurs(id));
        }
        let bitmap_id = (id & ID_MASK) as usize;
        if bitmap_id == 0 || bitmap_id > NH_ID_MAX as usize {
            return Err(NhIdError::OutOfRange(id));
        }
        self.bitmap[bitmap_id] = true;
        Ok(())
    }

    /// `true` when `id`'s high-nibble matches one of our reservations.
    /// IDs allocated by FRR (0x1000 / 0x2000) or by other agents
    /// return `false`.
    #[must_use]
    pub fn is_ours(id: u32) -> bool {
        let tag = id & TAG_MASK;
        tag == VTEP_NH_TAG || tag == NHG_TAG
    }

    /// `true` when `id` is in our per-VTEP NH tag range.
    #[must_use]
    pub fn is_vtep_nh(id: u32) -> bool {
        (id & TAG_MASK) == VTEP_NH_TAG
    }

    /// `true` when `id` is in our NHG tag range.
    #[must_use]
    pub fn is_nhg(id: u32) -> bool {
        (id & TAG_MASK) == NHG_TAG
    }

    fn alloc_bitmap_slot(&mut self) -> Result<u32, NhIdError> {
        // Skip slot 0 (always reserved); first-fit linear scan.
        for (i, used) in self.bitmap.iter_mut().enumerate().skip(1) {
            if !*used {
                *used = true;
                let slot: u32 = i.try_into().expect("bitmap size fits in u32");
                return Ok(slot);
            }
        }
        Err(NhIdError::Exhausted)
    }
}

/// Errors from [`NhIdAllocator`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NhIdError {
    /// All bitmap slots are in use; no more IDs available. Should
    /// never happen in practice — 16K IDs is far more than any
    /// operator multi-homing setup needs.
    #[error("nexthop ID allocator exhausted (NH_ID_MAX = 0x{:x})", NH_ID_MAX)]
    Exhausted,
    /// `reserve` was called with an ID whose tag doesn't match either
    /// `VTEP_NH_TAG` or `NHG_TAG`. Likely an FRR-tagged ID or other
    /// foreign agent's allocation; ignore it during adoption.
    #[error("nexthop ID 0x{0:08x} is not in a rustbgpd-owned tag range")]
    NotOurs(u32),
    /// `reserve` was called with a `bitmap_id` outside `[1, NH_ID_MAX]`.
    #[error("nexthop ID 0x{0:08x} has out-of-range bitmap_id portion")]
    OutOfRange(u32),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_first_returns_bitmap_id_one() {
        let mut a = NhIdAllocator::new();
        let id = a.alloc_vtep_nh().unwrap();
        assert_eq!(id, VTEP_NH_TAG | 1);
    }

    #[test]
    fn alloc_second_returns_bitmap_id_two() {
        let mut a = NhIdAllocator::new();
        let _ = a.alloc_vtep_nh().unwrap();
        let id = a.alloc_nhg().unwrap();
        assert_eq!(id, NHG_TAG | 2); // shared bitmap, second slot
    }

    #[test]
    fn alloc_after_release_reuses_slot() {
        let mut a = NhIdAllocator::new();
        let first = a.alloc_vtep_nh().unwrap();
        let _ = a.alloc_nhg().unwrap(); // slot 2
        a.release(first); // slot 1 now free
        let third = a.alloc_vtep_nh().unwrap();
        assert_eq!(third, VTEP_NH_TAG | 1, "should reuse freed slot 1");
    }

    #[test]
    fn release_strips_tag_and_frees_slot() {
        let mut a = NhIdAllocator::new();
        let id = a.alloc_nhg().unwrap(); // 0x4000_0001
        a.release(id);
        // Now alloc_vtep_nh should reuse slot 1 but tag it as vtep.
        let next = a.alloc_vtep_nh().unwrap();
        assert_eq!(next, VTEP_NH_TAG | 1);
    }

    #[test]
    fn release_ignores_foreign_ids() {
        let mut a = NhIdAllocator::new();
        a.release(0x1000_0001); // FRR-tagged; should be a no-op
        a.release(0x2000_0001); // FRR-tagged
        a.release(0xFFFF_FFFF); // garbage
        // Bitmap untouched; alloc still returns slot 1.
        assert_eq!(a.alloc_vtep_nh().unwrap(), VTEP_NH_TAG | 1);
    }

    #[test]
    fn release_of_unowned_slot_is_idempotent() {
        let mut a = NhIdAllocator::new();
        a.release(VTEP_NH_TAG | 0x2A); // never allocated; bitmap[0x2A] was false
        // Now alloc would still return slot 1 (first free).
        assert_eq!(a.alloc_vtep_nh().unwrap(), VTEP_NH_TAG | 1);
    }

    #[test]
    fn alloc_exhaustion_returns_error() {
        let mut a = NhIdAllocator::new();
        for _ in 1..=NH_ID_MAX {
            a.alloc_vtep_nh().unwrap();
        }
        assert!(matches!(a.alloc_vtep_nh(), Err(NhIdError::Exhausted)));
        assert!(matches!(a.alloc_nhg(), Err(NhIdError::Exhausted)));
    }

    #[test]
    fn is_ours_recognizes_both_tag_ranges() {
        assert!(NhIdAllocator::is_ours(VTEP_NH_TAG | 1));
        assert!(NhIdAllocator::is_ours(NHG_TAG | 0x4000));
        assert!(NhIdAllocator::is_vtep_nh(VTEP_NH_TAG | 1));
        assert!(NhIdAllocator::is_nhg(NHG_TAG | 1));
        assert!(!NhIdAllocator::is_nhg(VTEP_NH_TAG | 1));
        assert!(!NhIdAllocator::is_vtep_nh(NHG_TAG | 1));
    }

    #[test]
    fn is_ours_rejects_frr_range() {
        // FRR uses 0x1000 and 0x2000 — must NOT be ours.
        assert!(!NhIdAllocator::is_ours(0x1000_0001));
        assert!(!NhIdAllocator::is_ours(0x2000_0001));
        // Untagged plain IDs too.
        assert!(!NhIdAllocator::is_ours(1));
        assert!(!NhIdAllocator::is_ours(0xFFFF_FFFF));
    }

    #[test]
    fn reserve_marks_slot_used() {
        let mut a = NhIdAllocator::new();
        a.reserve(VTEP_NH_TAG | 5).unwrap();
        // Slot 5 is now used; alloc returns slot 1 (first free), then 2, 3, 4, then 6 (skips 5).
        for expected in [1, 2, 3, 4, 6] {
            assert_eq!(a.alloc_vtep_nh().unwrap(), VTEP_NH_TAG | expected);
        }
    }

    #[test]
    fn reserve_is_idempotent_on_same_id() {
        let mut a = NhIdAllocator::new();
        a.reserve(VTEP_NH_TAG | 5).unwrap();
        a.reserve(VTEP_NH_TAG | 5).unwrap(); // idempotent — no error
        // Slot 5 still used.
        assert!(a.bitmap[5]);
    }

    #[test]
    fn reserve_rejects_foreign_tag() {
        let mut a = NhIdAllocator::new();
        assert!(matches!(
            a.reserve(0x1000_0001),
            Err(NhIdError::NotOurs(0x1000_0001))
        ));
        assert!(matches!(
            a.reserve(0x2000_0001),
            Err(NhIdError::NotOurs(0x2000_0001))
        ));
    }

    #[test]
    fn reserve_rejects_out_of_range() {
        let mut a = NhIdAllocator::new();
        // bitmap_id = 0 (would be slot 0, permanently reserved by convention)
        assert!(matches!(
            a.reserve(VTEP_NH_TAG),
            Err(NhIdError::OutOfRange(_))
        ));
        // bitmap_id beyond NH_ID_MAX
        assert!(matches!(
            a.reserve(VTEP_NH_TAG | (NH_ID_MAX + 1)),
            Err(NhIdError::OutOfRange(_))
        ));
    }
}
