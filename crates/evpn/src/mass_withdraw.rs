//! Per-`(peer, ESI)` EAD-per-ES event tracker, the receiver-side
//! fast-convergence path for EVPN multi-homing.
//!
//! RFC 7432 §8.4 ("Aliasing and Backup-Path") names the Type 1
//! EAD-per-ES route as the per-Ethernet-Segment object on which
//! receivers do mass-MAC sweeping. When a remote PE that
//! participates in an Ethernet Segment loses its CE-side
//! connectivity (NIC down, bond fail, etc.), it would otherwise
//! have to withdraw every MAC route it had advertised on that
//! segment one-by-one — an O(MACs-on-segment) wave of
//! `MP_UNREACH_NLRI` messages. The RFC's standard fast path is
//! the **EAD-per-ES withdrawal**: when a peer withdraws its Type 1
//! EAD-per-ES route for an ESI, every receiver sweeps every MAC
//! route it had attributed to that `(peer, ESI)` pairing in one
//! operation.
//!
//! ## What this module does
//!
//! Pure-logic detector. Maintains per-`(peer, ESI)` state across
//! received EAD-per-ES events and returns
//! `MassWithdrawTrigger { peer, esi }` for events that should
//! cause the caller to sweep every Type 2 route it attributes to
//! that peer/segment.
//!
//! Three event sources:
//!
//! 1. **EAD-per-ES withdrawal** (`record_withdrawal`). The
//!    canonical RFC 7432 §8.4 mass-withdraw signal — peer's
//!    `MP_UNREACH_NLRI` for the Type 1 EAD-per-ES tells receivers
//!    "this segment is gone from my side; sweep accordingly."
//! 2. **Session teardown / peer-down** (`drop_peer`). One trigger
//!    per ESI the peer was tracking; the BGP layer's session-down
//!    path doesn't need to know about per-ESI bookkeeping
//!    explicitly.
//! 3. **`AS_PATH` change on EAD-per-ES re-advertisement**
//!    (`record_advertisement`, optional). Not in RFC 7432 itself,
//!    but adopted by FRR / Cumulus / Junos as a vendor-interop
//!    heuristic: if the peer's `AS_PATH` for the EAD-per-ES route
//!    changes between two advertisements without a Withdraw
//!    in-between, treat it as if the segment churned. Keep this
//!    path optional and document it as a heuristic, not RFC.
//!
//! ## What this module does NOT do
//!
//! - Mutate the RIB. The caller takes the returned
//!   `MassWithdrawTrigger`(s) and issues the appropriate
//!   `RibUpdate` ops in their own slice. Keeping detection pure
//!   makes the policy (which routes to sweep, in what order)
//!   explicit at the call site rather than buried here.
//! - Cache `AS_PATH`s by content. The fingerprint is a hash of
//!   the path's wire shape (segment type + segment length + ASN
//!   bytes), so two `AS_PATH`s that differ only in segment
//!   structure (e.g. `AS_SEQUENCE [1, 2]` vs two `AS_SEQUENCE`
//!   segments `[1] [2]`) produce different fingerprints. False
//!   negatives via hash collision are tolerable — they'd be a
//!   one-shot missed mass-withdraw the next 5 s reconcile pass
//!   corrects via the FDB-aging path. The fingerprint type is
//!   opaque so we can swap the hash function without touching
//!   call sites.
//! - Decide whether `AS_PATH` *should* have changed. Detection is
//!   purely "did it change vs the last advertisement we saw?" The
//!   policy contract that justifies firing on `AS_PATH` change is
//!   the originator's, not the receiver's — we trust the upstream
//!   conventions.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rustbgpd_wire::{AsPath, AsPathSegment, EthernetSegmentIdentifier};

/// Opaque fingerprint of an `AS_PATH`. Equal fingerprints → equal
/// paths (false negatives via hash collision are tolerable, see
/// the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AsPathFingerprint(u64);

impl AsPathFingerprint {
    /// Build a fingerprint from an `AS_PATH`'s wire shape:
    /// segment-type tag + segment length + ASN bytes for each
    /// segment in order. Two `AS_PATH`s that differ only in
    /// segment structure (e.g. one segment `[1, 2]` vs two
    /// segments `[1]` then `[2]`) produce different fingerprints,
    /// so a re-segmentation by an upstream peer counts as a
    /// change for mass-withdraw purposes.
    #[must_use]
    pub fn from_as_path(path: &AsPath) -> Self {
        // FNV-1a 64-bit, structure-aware. Tag bytes for segment
        // type are distinct constants so a switch from
        // `AsSequence` to `AsSet` (same ASNs) hashes differently.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for segment in &path.segments {
            let (tag, asns): (u8, &[u32]) = match segment {
                AsPathSegment::AsSequence(asns) => (0x02, asns.as_slice()),
                AsPathSegment::AsSet(asns) => (0x01, asns.as_slice()),
            };
            h = fnv1a_step(h, tag);
            // Length prefix in network order so segment boundaries
            // contribute distinct bytes — this is what makes
            // [1,2] vs [1][2] hash differently even though the
            // flat ASN sequence is identical.
            // BGP `AS_PATH` segments are at most 255 ASNs by wire shape
            // (segment-length is a u8), so the `usize -> u32` cast
            // never truncates in practice. Saturating-cast to silence
            // the clippy lint without changing semantics.
            let asn_count = u32::try_from(asns.len()).unwrap_or(u32::MAX);
            for &byte in &asn_count.to_be_bytes() {
                h = fnv1a_step(h, byte);
            }
            for asn in asns {
                for &byte in &asn.to_be_bytes() {
                    h = fnv1a_step(h, byte);
                }
            }
        }
        Self(h)
    }

    /// Build from a flat ASN list. Test/helper convenience —
    /// production callers should use [`Self::from_as_path`] so
    /// segment structure is preserved. The flat form treats every
    /// ASN as part of one synthetic `AsSequence` segment, which
    /// matches the most common single-segment shape but loses
    /// fidelity for paths with multiple segments or `AsSet`s.
    #[must_use]
    pub fn from_asns(asns: &[u32]) -> Self {
        Self::from_as_path(&AsPath {
            segments: vec![AsPathSegment::AsSequence(asns.to_vec())],
        })
    }

    /// Sentinel for "no `AS_PATH` ever recorded" — distinct from
    /// any plausible hash output (the FNV-1a basis is a different
    /// constant from the empty-input result).
    #[must_use]
    pub const fn never_seen() -> Self {
        Self(0)
    }
}

#[inline]
const fn fnv1a_step(h: u64, byte: u8) -> u64 {
    (h ^ (byte as u64)).wrapping_mul(0x100_0000_01b3)
}

/// One mass-withdraw trigger. The caller sweeps every MAC route
/// it had attributed to `peer` on `esi`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MassWithdrawTrigger {
    /// Peer that advertised the EAD-per-ES change.
    pub peer: IpAddr,
    /// Segment whose member MACs should be swept.
    pub esi: EthernetSegmentIdentifier,
}

/// Per-`(peer, esi)` `AS_PATH` tracker.
///
/// Maintains the last fingerprint seen on each `(peer, esi)` pair;
/// returns a trigger only when the new fingerprint differs from
/// the recorded one. The first-seen advertisement is *not* a
/// trigger — it's the establish event, not a flip.
#[derive(Debug, Default, Clone)]
pub struct AsPathTracker {
    by_key: BTreeMap<(IpAddr, EthernetSegmentIdentifier), AsPathFingerprint>,
}

impl AsPathTracker {
    /// Empty tracker; `record_advertisement` for the first
    /// advertisement of a given `(peer, esi)` returns `None`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an EAD-per-ES advertisement from `peer` for `esi`
    /// with the given `AS_PATH` fingerprint. Returns
    /// `Some(MassWithdrawTrigger)` iff this is a re-advertisement
    /// with a different fingerprint than the previous one.
    pub fn record_advertisement(
        &mut self,
        peer: IpAddr,
        esi: EthernetSegmentIdentifier,
        fingerprint: AsPathFingerprint,
    ) -> Option<MassWithdrawTrigger> {
        let key = (peer, esi);
        let prior = self.by_key.insert(key, fingerprint);
        match prior {
            None => None, // First-seen — establish, not a flip.
            Some(p) if p == fingerprint => None,
            Some(_) => Some(MassWithdrawTrigger { peer, esi }),
        }
    }

    /// Record an EAD-per-ES withdrawal for `(peer, esi)`. Returns
    /// `Some(MassWithdrawTrigger)` iff the tracker had previously
    /// observed an advertisement from this peer for this segment;
    /// otherwise returns `None` (a withdrawal for a `(peer, ESI)`
    /// we never saw advertise is a no-op — the RIB has nothing
    /// attributed to that pair to sweep). On success, internal
    /// state is cleared so a subsequent re-advertisement is
    /// treated as first-seen, not a fingerprint flip.
    ///
    /// Callers that need every withdrawal to surface a trigger
    /// regardless of seeding must guarantee `record_advertisement`
    /// has been called first (e.g. drive both off the same
    /// `EvpnRouteEvent` broadcast subscription so first-seen and
    /// withdrawal events arrive in order on a single stream).
    pub fn record_withdrawal(
        &mut self,
        peer: IpAddr,
        esi: EthernetSegmentIdentifier,
    ) -> Option<MassWithdrawTrigger> {
        if self.by_key.remove(&(peer, esi)).is_some() {
            Some(MassWithdrawTrigger { peer, esi })
        } else {
            None
        }
    }

    /// Drop all state for `peer` (e.g., on session teardown).
    /// Returns one trigger per ESI the peer was tracking.
    #[must_use]
    pub fn drop_peer(&mut self, peer: IpAddr) -> Vec<MassWithdrawTrigger> {
        let to_remove: Vec<_> = self
            .by_key
            .keys()
            .filter(|(p, _)| *p == peer)
            .copied()
            .collect();
        let mut out = Vec::with_capacity(to_remove.len());
        for key in to_remove {
            self.by_key.remove(&key);
            out.push(MassWithdrawTrigger {
                peer: key.0,
                esi: key.1,
            });
        }
        out
    }

    /// Number of `(peer, esi)` pairs currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// `true` if no `(peer, esi)` pairs are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn esi(seed: u8) -> EthernetSegmentIdentifier {
        EthernetSegmentIdentifier::new([seed; 10])
    }
    fn peer(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn fingerprint_is_deterministic() {
        assert_eq!(
            AsPathFingerprint::from_asns(&[64512, 64513]),
            AsPathFingerprint::from_asns(&[64512, 64513]),
        );
    }

    #[test]
    fn fingerprint_distinguishes_path_changes() {
        let a = AsPathFingerprint::from_asns(&[64512, 64513]);
        let b = AsPathFingerprint::from_asns(&[64512, 64514]);
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_distinguishes_path_order() {
        let a = AsPathFingerprint::from_asns(&[64512, 64513]);
        let b = AsPathFingerprint::from_asns(&[64513, 64512]);
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_distinguishes_segment_structure() {
        // [1, 2] in one AsSequence vs [1] [2] in two AsSequences:
        // flat ASN list is identical, but the wire shape differs,
        // so the fingerprints must too. Otherwise a peer that
        // re-segments its `AS_PATH` between advertisements (a real
        // BGP behavior under route-server / aggregation churn)
        // would silently fail to trigger mass-withdraw.
        let one_seg = AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![1, 2])],
        };
        let two_segs = AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![1]),
                AsPathSegment::AsSequence(vec![2]),
            ],
        };
        assert_ne!(
            AsPathFingerprint::from_as_path(&one_seg),
            AsPathFingerprint::from_as_path(&two_segs),
        );
    }

    #[test]
    fn fingerprint_distinguishes_segment_type() {
        // Same ASN list under AsSequence vs AsSet must hash
        // differently — the segment-type tag prefix bytes guarantee
        // that.
        let seq = AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![1, 2, 3])],
        };
        let set = AsPath {
            segments: vec![AsPathSegment::AsSet(vec![1, 2, 3])],
        };
        assert_ne!(
            AsPathFingerprint::from_as_path(&seq),
            AsPathFingerprint::from_as_path(&set),
        );
    }

    #[test]
    fn first_advertisement_is_not_a_trigger() {
        let mut t = AsPathTracker::new();
        let fp = AsPathFingerprint::from_asns(&[64512]);
        assert!(
            t.record_advertisement(peer("10.0.0.1"), esi(1), fp)
                .is_none()
        );
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn idempotent_advertisement_is_not_a_trigger() {
        let mut t = AsPathTracker::new();
        let fp = AsPathFingerprint::from_asns(&[64512]);
        assert!(
            t.record_advertisement(peer("10.0.0.1"), esi(1), fp)
                .is_none()
        );
        assert!(
            t.record_advertisement(peer("10.0.0.1"), esi(1), fp)
                .is_none()
        );
    }

    #[test]
    fn changed_fingerprint_is_a_trigger() {
        let mut t = AsPathTracker::new();
        let fp1 = AsPathFingerprint::from_asns(&[64512]);
        let fp2 = AsPathFingerprint::from_asns(&[64513]);
        let _ = t.record_advertisement(peer("10.0.0.1"), esi(1), fp1);
        let trigger = t.record_advertisement(peer("10.0.0.1"), esi(1), fp2);
        assert_eq!(
            trigger,
            Some(MassWithdrawTrigger {
                peer: peer("10.0.0.1"),
                esi: esi(1),
            })
        );
    }

    #[test]
    fn withdrawal_after_advertise_is_a_trigger() {
        let mut t = AsPathTracker::new();
        let fp = AsPathFingerprint::from_asns(&[64512]);
        let _ = t.record_advertisement(peer("10.0.0.1"), esi(1), fp);
        let trigger = t.record_withdrawal(peer("10.0.0.1"), esi(1));
        assert!(trigger.is_some());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn withdrawal_without_prior_advertise_is_noop() {
        let mut t = AsPathTracker::new();
        let trigger = t.record_withdrawal(peer("10.0.0.1"), esi(1));
        assert!(trigger.is_none());
    }

    #[test]
    fn re_advertisement_after_withdrawal_is_first_seen_again() {
        let mut t = AsPathTracker::new();
        let fp = AsPathFingerprint::from_asns(&[64512]);
        let _ = t.record_advertisement(peer("10.0.0.1"), esi(1), fp);
        let _ = t.record_withdrawal(peer("10.0.0.1"), esi(1));
        // After withdrawal, the same fingerprint reappearing is a
        // fresh establish, not a fingerprint-change trigger.
        let trigger = t.record_advertisement(peer("10.0.0.1"), esi(1), fp);
        assert!(trigger.is_none());
    }

    #[test]
    fn drop_peer_emits_one_trigger_per_tracked_esi() {
        let mut t = AsPathTracker::new();
        let fp = AsPathFingerprint::from_asns(&[64512]);
        let _ = t.record_advertisement(peer("10.0.0.1"), esi(1), fp);
        let _ = t.record_advertisement(peer("10.0.0.1"), esi(2), fp);
        let _ = t.record_advertisement(peer("10.0.0.2"), esi(1), fp);

        let triggers = t.drop_peer(peer("10.0.0.1"));
        assert_eq!(triggers.len(), 2);
        for trigger in &triggers {
            assert_eq!(trigger.peer, peer("10.0.0.1"));
        }
        // Other peer's state survives.
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn drop_peer_unknown_returns_empty() {
        let mut t = AsPathTracker::new();
        assert!(t.drop_peer(peer("10.0.0.99")).is_empty());
    }

    #[test]
    fn changed_fingerprint_for_one_esi_does_not_disturb_others() {
        let mut t = AsPathTracker::new();
        let fp1 = AsPathFingerprint::from_asns(&[64512]);
        let fp2 = AsPathFingerprint::from_asns(&[64513]);
        let _ = t.record_advertisement(peer("10.0.0.1"), esi(1), fp1);
        let _ = t.record_advertisement(peer("10.0.0.1"), esi(2), fp1);
        let trigger = t.record_advertisement(peer("10.0.0.1"), esi(1), fp2);
        assert_eq!(trigger.unwrap().esi, esi(1));
        // esi(2) state is untouched — still recorded with fp1.
        assert!(
            t.record_advertisement(peer("10.0.0.1"), esi(2), fp1)
                .is_none()
        );
    }
}
