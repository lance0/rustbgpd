//! Nexthop ID allocator for ADR-0059 slice 3.
//!
//! Hands out tagged `u32` IDs for the kernel's nexthop table:
//!
//! - `0x3000_0000 | bitmap_id` for per-VTEP FDB nexthops.
//! - `0x4000_0000 | bitmap_id` for FDB nexthop groups.
//! - `0x5000_0000 | bitmap_id` for L3VXLAN per-VTEP nexthops.
//! - `0x6000_0000 | bitmap_id` for L3VXLAN FDB nexthop groups.
//!
//! `bitmap_id` is in `[1, NH_ID_MAX]` (matching FRR's `EVPN_NH_ID_MAX`
//! = `0x4000`). The same bitmap backs both per-VTEP and NHG IDs — the
//! type bit is purely for `ip nexthop show` discriminability, and the
//! kernel does not enforce per-protocol ownership, so the bitmap stays
//! a single resource.
//!
//! The 0x3000 / 0x4000 / 0x5000 / 0x6000 tag bits are
//! **deliberately offset** from FRR's
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

/// Tag bits OR'd onto L3VXLAN per-VTEP nexthop IDs.
pub const L3_VTEP_NH_TAG: u32 = 0x5000_0000;

/// Tag bits OR'd onto L3VXLAN FDB nexthop group IDs.
pub const L3_NHG_TAG: u32 = 0x6000_0000;

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

    /// Allocate an L3VXLAN per-VTEP nexthop ID. Tag bits
    /// [`L3_VTEP_NH_TAG`] are OR'd onto the returned value.
    ///
    /// # Errors
    ///
    /// Returns [`NhIdError::Exhausted`] when no bitmap slot is free.
    pub fn alloc_l3_vtep_nh(&mut self) -> Result<u32, NhIdError> {
        let bitmap_id = self.alloc_bitmap_slot()?;
        Ok(L3_VTEP_NH_TAG | bitmap_id)
    }

    /// Allocate an L3VXLAN FDB nexthop group ID. Tag bits
    /// [`L3_NHG_TAG`] are OR'd onto the returned value.
    ///
    /// # Errors
    ///
    /// Returns [`NhIdError::Exhausted`] when no bitmap slot is free.
    pub fn alloc_l3_nhg(&mut self) -> Result<u32, NhIdError> {
        let bitmap_id = self.alloc_bitmap_slot()?;
        Ok(L3_NHG_TAG | bitmap_id)
    }

    /// Free a previously-allocated L2 tagged ID. Strips the tag bits
    /// and clears the bitmap slot. No-ops on slot 0 (which stays
    /// reserved) and on IDs whose tag is not one of the L2 FDB-NHG
    /// ranges.
    ///
    /// This stays L2-only for ADR-0059 compatibility; use
    /// [`Self::release_l3`] for the all-active Type-5 L3 domain.
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

    /// Free a previously-allocated L3 tagged ID. Strips the tag bits
    /// and clears the bitmap slot. No-ops on slot 0 (which stays
    /// reserved) and on IDs whose tag is not one of the L3VXLAN
    /// FDB-NHG ranges.
    pub fn release_l3(&mut self, id: u32) {
        if !Self::is_l3_ours(id) {
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
    ///   match any rustbgpd nexthop-owner reservation.
    /// - [`NhIdError::OutOfRange`] if `bitmap_id` is 0 or > [`NH_ID_MAX`].
    pub fn reserve(&mut self, id: u32) -> Result<(), NhIdError> {
        if !Self::is_any_rustbgpd(id) {
            return Err(NhIdError::NotOurs(id));
        }
        let bitmap_id = (id & ID_MASK) as usize;
        if bitmap_id == 0 || bitmap_id > NH_ID_MAX as usize {
            return Err(NhIdError::OutOfRange(id));
        }
        self.bitmap[bitmap_id] = true;
        Ok(())
    }

    /// `true` when `id`'s high-nibble matches one of the existing L2
    /// FDB-NHG reservations. IDs allocated by FRR (0x1000 / 0x2000),
    /// by other agents, or by rustbgpd's L3 reservations return
    /// `false`.
    ///
    /// This method is intentionally kept as the L2 compatibility
    /// predicate because the ADR-0059 adoption/drift paths currently
    /// own only L2 FDB-NHG state. Use [`Self::is_any_rustbgpd`] for a
    /// broad ownership check and [`Self::is_l3_ours`] for the L3 class.
    #[must_use]
    pub fn is_ours(id: u32) -> bool {
        Self::is_l2_ours(id)
    }

    /// `true` when `id`'s high-nibble matches one of the existing L2
    /// FDB-NHG reservations.
    #[must_use]
    pub fn is_l2_ours(id: u32) -> bool {
        let tag = id & TAG_MASK;
        tag == VTEP_NH_TAG || tag == NHG_TAG
    }

    /// `true` when `id`'s high-nibble matches one of the L3VXLAN
    /// FDB-NHG reservations.
    #[must_use]
    pub fn is_l3_ours(id: u32) -> bool {
        let tag = id & TAG_MASK;
        tag == L3_VTEP_NH_TAG || tag == L3_NHG_TAG
    }

    /// `true` when `id`'s high-nibble matches any rustbgpd-owned
    /// nexthop tag reservation.
    #[must_use]
    pub fn is_any_rustbgpd(id: u32) -> bool {
        Self::is_l2_ours(id) || Self::is_l3_ours(id)
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

    /// `true` when `id` is in our L3VXLAN per-VTEP NH tag range.
    #[must_use]
    pub fn is_l3_vtep_nh(id: u32) -> bool {
        (id & TAG_MASK) == L3_VTEP_NH_TAG
    }

    /// `true` when `id` is in our L3VXLAN FDB-NHG tag range.
    #[must_use]
    pub fn is_l3_nhg(id: u32) -> bool {
        (id & TAG_MASK) == L3_NHG_TAG
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
    fn alloc_l3_ids_use_separate_tags_and_shared_bitmap() {
        let mut a = NhIdAllocator::new();
        let l2_member = a.alloc_vtep_nh().unwrap();
        let l2_group = a.alloc_nhg().unwrap();
        let l3_member = a.alloc_l3_vtep_nh().unwrap();
        let l3_group = a.alloc_l3_nhg().unwrap();

        assert_eq!(l2_member, VTEP_NH_TAG | 1);
        assert_eq!(l2_group, NHG_TAG | 2);
        assert_eq!(l3_member, L3_VTEP_NH_TAG | 3);
        assert_eq!(l3_group, L3_NHG_TAG | 4);
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
    fn release_strips_l2_tag_and_frees_slot() {
        let mut a = NhIdAllocator::new();
        let id = a.alloc_nhg().unwrap(); // 0x4000_0001
        a.release(id);
        // Now alloc_vtep_nh should reuse slot 1 but tag it as vtep.
        let next = a.alloc_vtep_nh().unwrap();
        assert_eq!(next, VTEP_NH_TAG | 1);
    }

    #[test]
    fn release_strips_l3_tag_and_frees_slot() {
        let mut a = NhIdAllocator::new();
        let id = a.alloc_l3_nhg().unwrap(); // 0x6000_0001
        a.release_l3(id);
        let next = a.alloc_l3_vtep_nh().unwrap();
        assert_eq!(next, L3_VTEP_NH_TAG | 1);
    }

    #[test]
    fn l2_release_ignores_l3_tagged_ids() {
        let mut a = NhIdAllocator::new();
        let id = a.alloc_l3_nhg().unwrap(); // slot 1
        a.release(id);
        let next = a.alloc_l3_vtep_nh().unwrap();
        assert_eq!(
            next,
            L3_VTEP_NH_TAG | 2,
            "L2 cleanup must not release an L3-owned slot"
        );
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
        assert!(matches!(a.alloc_l3_vtep_nh(), Err(NhIdError::Exhausted)));
        assert!(matches!(a.alloc_l3_nhg(), Err(NhIdError::Exhausted)));
    }

    #[test]
    fn is_ours_recognizes_only_l2_tag_ranges() {
        assert!(NhIdAllocator::is_ours(VTEP_NH_TAG | 1));
        assert!(NhIdAllocator::is_ours(NHG_TAG | 0x4000));
        assert!(NhIdAllocator::is_l2_ours(VTEP_NH_TAG | 1));
        assert!(NhIdAllocator::is_l2_ours(NHG_TAG | 1));
        assert!(NhIdAllocator::is_vtep_nh(VTEP_NH_TAG | 1));
        assert!(NhIdAllocator::is_nhg(NHG_TAG | 1));
        assert!(!NhIdAllocator::is_nhg(VTEP_NH_TAG | 1));
        assert!(!NhIdAllocator::is_vtep_nh(NHG_TAG | 1));
        assert!(
            !NhIdAllocator::is_ours(L3_VTEP_NH_TAG | 1),
            "legacy L2 predicate must not adopt L3 member IDs"
        );
        assert!(
            !NhIdAllocator::is_ours(L3_NHG_TAG | 1),
            "legacy L2 predicate must not adopt L3 group IDs"
        );
    }

    #[test]
    fn l3_predicates_recognize_only_l3_tag_ranges() {
        assert!(NhIdAllocator::is_l3_ours(L3_VTEP_NH_TAG | 1));
        assert!(NhIdAllocator::is_l3_ours(L3_NHG_TAG | 1));
        assert!(NhIdAllocator::is_l3_vtep_nh(L3_VTEP_NH_TAG | 1));
        assert!(NhIdAllocator::is_l3_nhg(L3_NHG_TAG | 1));
        assert!(!NhIdAllocator::is_l3_ours(VTEP_NH_TAG | 1));
        assert!(!NhIdAllocator::is_l3_ours(NHG_TAG | 1));
        assert!(!NhIdAllocator::is_l3_nhg(L3_VTEP_NH_TAG | 1));
        assert!(!NhIdAllocator::is_l3_vtep_nh(L3_NHG_TAG | 1));
    }

    #[test]
    fn broad_predicate_recognizes_all_rustbgpd_tag_ranges() {
        assert!(NhIdAllocator::is_any_rustbgpd(VTEP_NH_TAG | 1));
        assert!(NhIdAllocator::is_any_rustbgpd(NHG_TAG | 1));
        assert!(NhIdAllocator::is_any_rustbgpd(L3_VTEP_NH_TAG | 1));
        assert!(NhIdAllocator::is_any_rustbgpd(L3_NHG_TAG | 1));
        assert!(!NhIdAllocator::is_any_rustbgpd(0x1000_0001));
        assert!(!NhIdAllocator::is_any_rustbgpd(0x2000_0001));
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
    fn reserve_l3_tag_marks_slot_used() {
        let mut a = NhIdAllocator::new();
        a.reserve(L3_NHG_TAG | 5).unwrap();
        for expected in [1, 2, 3, 4, 6] {
            assert_eq!(a.alloc_l3_vtep_nh().unwrap(), L3_VTEP_NH_TAG | expected);
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
