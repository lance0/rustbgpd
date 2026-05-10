//! Mass-withdraw on `AS_PATH` change for EVPN multi-homing
//! (RFC 7432 §8.6).
//!
//! When a remote PE that participates in an Ethernet Segment loses
//! its CE-side connectivity (NIC down, bond fail, etc.), it would
//! normally have to withdraw every MAC route it had advertised on
//! that segment one-by-one — an O(MACs-on-segment) wave of
//! `MP_UNREACH_NLRI` messages that scales poorly under failure.
//! RFC 7432 §8.6 defines a fast-flip primitive: re-advertise the
//! Type 1 EAD-per-ES route with a *changed* `AS_PATH`, and every
//! receiver mass-withdraws every MAC route it had attributed to
//! that `(peer, ESI)` pairing in one operation.
//!
//! ## What this module does
//!
//! Pure-logic change detector. Tracks `(peer, ESI) ->
//! AsPathFingerprint` across received EAD-per-ES events; on an
//! advertisement whose fingerprint differs from the last recorded
//! one, returns `MassWithdrawTrigger { peer, esi }`. The caller
//! wires the trigger into the RIB to sweep matching MAC routes.
//!
//! Withdrawal of the EAD-per-ES route itself (`MP_UNREACH_NLRI` on
//! the Type 1) is *also* a mass-withdraw signal — RFC 7432 §8.6
//! treats both as equivalent. The detector exposes
//! `record_withdraw` for that path.
//!
//! ## What this module does NOT do
//!
//! - Mutate the RIB. The caller takes the returned
//!   `MassWithdrawTrigger`(s) and issues the appropriate
//!   `RibUpdate` ops in their own slice. Keeping detection pure
//!   makes the policy (which routes to sweep, in what order)
//!   explicit at the call site rather than buried here.
//! - Cache `AS_PATH`s by content. The fingerprint is a hash of
//!   the path's wire shape; equality is hash-equality. False
//!   negatives are theoretically possible (hash collisions on
//!   distinct AS paths) but RFC-wise they'd be a one-shot missed
//!   mass-withdraw the next 5 s reconcile pass corrects via the
//!   FDB-aging path. The fingerprint type is opaque so we can swap
//!   the hash function without touching call sites.
//! - Decide whether `AS_PATH` *should* have changed. Detection is
//!   purely "did it change vs the last advertisement we saw?" The
//!   RFC §8.6 contract is that the *originator* changes its
//!   `AS_PATH` only when it intends mass-withdraw; receivers like
//!   us trust that contract.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rustbgpd_wire::EthernetSegmentIdentifier;

/// Opaque fingerprint of an `AS_PATH`. Equal fingerprints → equal
/// paths (false negatives via hash collision are tolerable, see
/// the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AsPathFingerprint(u64);

impl AsPathFingerprint {
    /// Build from a slice of 4-octet ASNs in segment order.
    /// Implementation: FNV-1a over the bytes. Stable across
    /// runs and cheap enough to hash on every event.
    #[must_use]
    pub fn from_asns(asns: &[u32]) -> Self {
        // FNV-1a 64-bit
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for asn in asns {
            for &byte in &asn.to_be_bytes() {
                h ^= u64::from(byte);
                h = h.wrapping_mul(0x100_0000_01b3);
            }
        }
        Self(h)
    }

    /// Sentinel for "no `AS_PATH` ever recorded" — distinct from
    /// any plausible hash output (the FNV-1a basis is a different
    /// constant from the empty-input result of `from_asns(&[])`).
    #[must_use]
    pub const fn never_seen() -> Self {
        Self(0)
    }
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

    /// Record an EAD-per-ES withdrawal for `(peer, esi)`. Always
    /// returns a trigger (the route went away — every MAC the
    /// peer advertised on this segment must be swept). The
    /// internal state is cleared so a subsequent re-advertisement
    /// is treated as first-seen.
    pub fn record_withdrawal(
        &mut self,
        peer: IpAddr,
        esi: EthernetSegmentIdentifier,
    ) -> Option<MassWithdrawTrigger> {
        if self.by_key.remove(&(peer, esi)).is_some() {
            Some(MassWithdrawTrigger { peer, esi })
        } else {
            // Withdrawal for a peer/segment we never saw advertise
            // is a no-op rather than a spurious sweep — the RIB
            // has nothing to withdraw.
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
