//! Per-ESI label allocator for Gate 8b.
//!
//! Assigns one 20-bit MPLS label to each
//! [`EthernetSegmentIdentifier`] the daemon participates in, and
//! preserves the assignment across reconfiguration. The label is
//! load-bearing for split-horizon enforcement (RFC 7432 §7.5 ESI
//! Label extcomm carried on Type 1 EAD-per-ES routes), so a label
//! that drifts on every daemon restart or config edit would cause
//! peers to flap their split-horizon filter tables.
//!
//! ## Why a stateful allocator instead of a synthesizer
//!
//! Gate 8 shipped a deterministic [`synthesize_from_esi`] that
//! mapped ESI bytes `[4..7]` into the 20-bit label space. That
//! works in the single-operator case where every operator picks
//! disjoint ESI ranges, but breaks the moment two operators on
//! different fabrics happen to choose ESIs that collide on those
//! four bytes — both segments end up advertising the same ESI
//! Label, and split-horizon enforcement on a peer that imports
//! both gets confused. The allocator keeps a `(ESI -> label)`
//! map plus a free-list of returned labels, so:
//!
//! - Two distinct ESIs **always** receive distinct labels (no
//!   hash collisions in a 2^32 → 2^20 mapping).
//! - The label assignment for a given ESI is stable across
//!   `reserve` / `release` / `reserve` cycles for the same ESI,
//!   so an operator who removes and re-adds a segment in one
//!   reconfiguration window doesn't see a label flap.
//! - Labels released by removed segments are reused, so the
//!   address space doesn't bleed.
//!
//! The synthesizer remains exposed as a fallback for callers that
//! genuinely want a deterministic-from-ESI mapping (tests,
//! offline tooling) — the allocator delegates to it for the
//! initial assignment when the segment is first seen, which means
//! Gate 8b prep operators who already run with the deterministic
//! mapping observe no label change on upgrade. Subsequent
//! collisions land on the next-free-label fallback.
//!
//! ## What this module does NOT do
//!
//! - Persist allocations across daemon restarts. The allocator is
//!   in-memory only; a daemon restart re-runs first-seen ordering
//!   from `[[ethernet_segments]]`. For the deterministic-mapping
//!   path that's a no-op (same ESI → same synthesized seed); for
//!   the collision-avoidance path it could shift assignments. A
//!   future slice could persist via the runtime-state file the
//!   GR machinery already uses.
//! - Coordinate label space with operators of other label-using
//!   features in the same daemon (`FlowSpec`, MPLS labelled unicast,
//!   etc.). Today the daemon doesn't program MPLS forwarding, so
//!   the only MPLS labels in flight are EVPN-driven and live in
//!   the same allocator.

use std::collections::{BTreeMap, BTreeSet};

use crate::EthernetSegmentIdentifier;
use rustbgpd_wire::MplsLabel;

/// Smallest label this allocator will hand out. The MPLS reserved
/// range covers 0..=15 (RFC 3032 §2.1); operator-configured tunnels
/// often reach into 16..=999 too, but EVPN ESI labels traditionally
/// live above the reserved range and that's all we need to honor.
const MIN_LABEL: u32 = 16;

/// Largest label fitting in the 20-bit MPLS label field. EVPN
/// over MPLS uses the full 20 bits; EVPN over VXLAN uses the 24-bit
/// VNI shape (RFC 8365 §5.1.3) which fits the full 20 bits too. So
/// this cap is the real ceiling for either encap.
const MAX_LABEL: u32 = (1 << 20) - 1;

/// Per-ESI label allocator.
///
/// Holds a `(ESI -> label)` map plus a free-list of labels released
/// by removed segments. Reservations are idempotent: reserving an
/// ESI that already has a label returns the same label.
#[derive(Debug, Default)]
pub struct EsiLabelAllocator {
    /// Currently-assigned `(ESI -> label)`.
    by_esi: BTreeMap<EthernetSegmentIdentifier, MplsLabel>,
    /// Reverse index — needed to detect collisions cheaply.
    by_label: BTreeMap<u32, EthernetSegmentIdentifier>,
    /// Released labels available for reuse. Sorted so the next
    /// reservation gets the lowest label, keeping operator
    /// `bridge -d link show` output tidy.
    free: BTreeSet<u32>,
}

impl EsiLabelAllocator {
    /// Empty allocator with no assignments.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of currently-assigned ESI labels.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_esi.len()
    }

    /// `true` if no labels are currently assigned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_esi.is_empty()
    }

    /// Look up the label currently assigned to `esi`, if any.
    #[must_use]
    pub fn get(&self, esi: EthernetSegmentIdentifier) -> Option<MplsLabel> {
        self.by_esi.get(&esi).copied()
    }

    /// Reserve (or return the existing assignment for) `esi`.
    ///
    /// Strategy:
    /// 1. Idempotent return if `esi` already has a label.
    /// 2. Try the deterministic synthesis first — if it doesn't
    ///    collide with another assignment, use it. This preserves
    ///    Gate 8b prep behavior for operators on the upgrade path.
    /// 3. On collision, drain the free-list (lowest first).
    /// 4. Otherwise grow the assigned set into a fresh label.
    /// 5. If the entire 20-bit space is exhausted (~1M segments —
    ///    well past anything operationally realistic), return
    ///    [`AllocateError::Exhausted`].
    ///
    /// # Errors
    /// Returns [`AllocateError::Exhausted`] if no free label exists
    /// in `MIN_LABEL..=MAX_LABEL`.
    pub fn reserve(&mut self, esi: EthernetSegmentIdentifier) -> Result<MplsLabel, AllocateError> {
        if let Some(existing) = self.by_esi.get(&esi).copied() {
            return Ok(existing);
        }

        // Strategy 2: try deterministic synthesis.
        let synth = synthesize_from_esi(esi).value();
        if !self.by_label.contains_key(&synth) {
            self.commit(esi, synth);
            return Ok(MplsLabel::new(synth));
        }

        // Strategy 3: pop from the free list (lowest first).
        if let Some(&candidate) = self.free.iter().next() {
            self.free.remove(&candidate);
            self.commit(esi, candidate);
            return Ok(MplsLabel::new(candidate));
        }

        // Strategy 4: scan for the lowest unassigned label.
        for label in MIN_LABEL..=MAX_LABEL {
            if !self.by_label.contains_key(&label) {
                self.commit(esi, label);
                return Ok(MplsLabel::new(label));
            }
        }

        Err(AllocateError::Exhausted)
    }

    /// Release the label assigned to `esi`, if any. Returns the
    /// label that was released (so callers can log / metric the
    /// transition).
    pub fn release(&mut self, esi: EthernetSegmentIdentifier) -> Option<MplsLabel> {
        let label = self.by_esi.remove(&esi)?;
        self.by_label.remove(&label.value());
        self.free.insert(label.value());
        Some(label)
    }

    fn commit(&mut self, esi: EthernetSegmentIdentifier, label: u32) {
        debug_assert!((MIN_LABEL..=MAX_LABEL).contains(&label));
        self.by_esi.insert(esi, MplsLabel::new(label));
        self.by_label.insert(label, esi);
        self.free.remove(&label);
    }
}

/// Reasons [`EsiLabelAllocator::reserve`] can fail. Today there's
/// only one — exhaustion of the 20-bit label space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AllocateError {
    /// Every label in `MIN_LABEL..=MAX_LABEL` is currently
    /// assigned. The operator has configured ~1M Ethernet
    /// Segments on a single PE, which is not a realistic
    /// deployment shape; if this fires the operator's daemon
    /// log gets a `warn!` and the affected segment is reported
    /// `NotReady` until labels free up.
    #[error("ESI label space exhausted (20-bit cap reached)")]
    Exhausted,
}

/// Deterministic per-ESI label synthesis from the ESI bytes.
///
/// Maps ESI bytes `[4..7]` (the AS / value half of an LACP- or
/// preference-derived ESI) into the `MIN_LABEL..=MAX_LABEL` range.
/// This is the same function Gate 8b prep used; the
/// [`EsiLabelAllocator`] uses it as a starting hint so operators
/// upgrading from the prep release see no label change unless they
/// have an actual collision.
#[must_use]
pub fn synthesize_from_esi(esi: EthernetSegmentIdentifier) -> MplsLabel {
    let octets = esi.octets();
    let raw = u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]);
    let span = MAX_LABEL - MIN_LABEL + 1;
    let label = MIN_LABEL + (raw % span);
    MplsLabel::new(label)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn esi_with_value(seed: u32) -> EthernetSegmentIdentifier {
        let bytes = seed.to_be_bytes();
        EthernetSegmentIdentifier::new([
            0x00, 0x00, 0x00, 0x00, bytes[0], bytes[1], bytes[2], bytes[3], 0x00, 0x00,
        ])
    }

    fn esi_full(bytes: [u8; 10]) -> EthernetSegmentIdentifier {
        EthernetSegmentIdentifier::new(bytes)
    }

    #[test]
    fn synthesize_is_deterministic_and_in_range() {
        let a = synthesize_from_esi(esi_with_value(0x42));
        let b = synthesize_from_esi(esi_with_value(0x42));
        assert_eq!(a, b);
        assert!(a.value() >= MIN_LABEL && a.value() <= MAX_LABEL);
    }

    #[test]
    fn synthesize_distinct_inputs_can_collide() {
        // The whole point of the allocator: bytes [4..7] is a
        // 32-bit input mapped into a 20-bit space, so collisions
        // are mathematically guaranteed at scale. Pick an obvious
        // collision pair to assert the synth is the *source* of
        // the problem the allocator solves.
        let a = synthesize_from_esi(esi_full([
            0xff, 0xee, 0xdd, 0xcc, 0x00, 0x00, 0x00, 0x10, 0x11, 0x22,
        ]));
        // Same bytes [4..7] → identical synth output:
        let b = synthesize_from_esi(esi_full([
            0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x10, 0x99, 0x88,
        ]));
        assert_eq!(a, b, "synth-only mapping is intentionally collidable");
    }

    #[test]
    fn reserve_is_idempotent() {
        let mut a = EsiLabelAllocator::new();
        let esi = esi_with_value(1);
        let l1 = a.reserve(esi).unwrap();
        let l2 = a.reserve(esi).unwrap();
        assert_eq!(l1, l2);
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn reserve_uses_synth_when_no_collision() {
        let mut a = EsiLabelAllocator::new();
        let esi = esi_with_value(0x42);
        let synth = synthesize_from_esi(esi);
        let assigned = a.reserve(esi).unwrap();
        assert_eq!(
            assigned, synth,
            "first ESI should land on its deterministic synth label"
        );
    }

    #[test]
    fn reserve_avoids_collision_with_prior_assignment() {
        // Two distinct ESIs that synth to the same label. The
        // first reservation gets the synth label; the second must
        // get something different.
        let mut a = EsiLabelAllocator::new();
        let esi1 = esi_full([0xff, 0xee, 0xdd, 0xcc, 0x00, 0x00, 0x00, 0x10, 0x11, 0x22]);
        let esi2 = esi_full([0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x10, 0x99, 0x88]);
        assert_eq!(synthesize_from_esi(esi1), synthesize_from_esi(esi2));

        let l1 = a.reserve(esi1).unwrap();
        let l2 = a.reserve(esi2).unwrap();
        assert_ne!(l1, l2, "colliding ESIs must end up on different labels");
        assert_eq!(l1, synthesize_from_esi(esi1));
        assert_eq!(a.len(), 2);
    }

    #[test]
    fn release_returns_label_to_free_list() {
        let mut a = EsiLabelAllocator::new();
        let esi = esi_with_value(7);
        let l1 = a.reserve(esi).unwrap();
        let returned = a.release(esi).unwrap();
        assert_eq!(returned, l1);
        assert_eq!(a.len(), 0);
        // Re-reserving the same ESI re-uses the synth label, since
        // it's now free again.
        let l2 = a.reserve(esi).unwrap();
        assert_eq!(l1, l2);
    }

    #[test]
    fn release_unknown_esi_is_noop() {
        let mut a = EsiLabelAllocator::new();
        assert!(a.release(esi_with_value(99)).is_none());
    }

    #[test]
    fn freed_labels_get_reused_lowest_first() {
        let mut a = EsiLabelAllocator::new();
        // Force the synth path to place esi_a on a known label.
        let esi_a = esi_with_value(0x100);
        let label_a = a.reserve(esi_a).unwrap();
        a.release(esi_a);
        // Now reserve a *different* ESI that synths to a
        // *different* label, but force the free-list path by
        // pre-occupying the synth slot with an ESI that lands
        // there first.
        let esi_b = esi_full([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00]);
        let _label_b = a.reserve(esi_b).unwrap();
        // esi_c synths to label_a (we just freed it), so the free
        // list shouldn't be needed here. Force the free-list path
        // by picking esi_c whose synth target is occupied by esi_b.
        let esi_c = esi_full([0xff, 0xee, 0xdd, 0xcc, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00]);
        let label_c = a.reserve(esi_c).unwrap();
        // esi_c's synth label collides with esi_b, so the
        // allocator falls back. The free-list pop has the
        // previously-released `label_a` available, so esi_c lands
        // there.
        assert_eq!(
            label_c, label_a,
            "freed label should be re-used before scanning fresh space"
        );
    }

    #[test]
    fn distinct_esis_get_distinct_labels_at_scale() {
        let mut a = EsiLabelAllocator::new();
        let mut labels = std::collections::HashSet::new();
        for i in 0..1000u32 {
            // Construct ESIs that all share the same bytes [4..7]
            // value, so the synthesizer would put them all on the
            // same label. The allocator must spread them out.
            let bytes = i.to_be_bytes();
            let esi = esi_full([
                bytes[0], bytes[1], bytes[2], bytes[3], 0x00, 0x00, 0x00, 0xAA, 0x00, 0x00,
            ]);
            let label = a.reserve(esi).unwrap();
            assert!(
                labels.insert(label.value()),
                "duplicate label {} assigned at iteration {i}",
                label.value()
            );
        }
        assert_eq!(a.len(), 1000);
    }

    #[test]
    fn synth_label_is_within_min_max_bounds() {
        // Edge: ESI value bytes all-zero and all-FF.
        let zero = synthesize_from_esi(esi_full([0; 10]));
        assert!(zero.value() >= MIN_LABEL && zero.value() <= MAX_LABEL);
        let ones = synthesize_from_esi(esi_full([0xFF; 10]));
        assert!(ones.value() >= MIN_LABEL && ones.value() <= MAX_LABEL);
    }
}
