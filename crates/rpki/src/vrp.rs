//! VRP (Validated ROA Payload) table and origin validation.
//!
//! The [`VrpTable`] ingests a set of [`VrpEntry`] values and implements RFC 6811
//! origin validation: given a route's prefix and origin ASN, it classifies the
//! route as `Valid`, `Invalid`, or `NotFound`.
//!
//! Internally the table is a **family-split, prefix-length-bucketed index**: one
//! bucket per possible prefix length (33 for IPv4, 129 for IPv6), each a list of
//! `(network, auths)` groups sorted by masked network address. Validation walks
//! the route's ancestor lengths `0..=route_len`, binary-searching one bucket per
//! length — at most 33 (v4) / 129 (v6) searches, versus an O(n) scan of the
//! whole table. Origin validation needs *every* covering ancestor (a
//! less-specific Valid VRP must win even when a more-specific covering VRP fails
//! ASN or maxLength), so an all-ancestors walk is required — a longest-prefix
//! match alone would misclassify.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rustbgpd_wire::{Prefix, RpkiValidation};
use smallvec::SmallVec;

/// One authorization within a `(prefix_len, network)` group: an origin ASN and
/// the maximum prefix length it may announce.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VrpAuth {
    origin_asn: u32,
    max_len: u8,
}

/// VRPs sharing one masked network at a given prefix length. The common case is
/// a single authorization, inlined by `SmallVec`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VrpGroup<N> {
    network: N,
    auths: SmallVec<[VrpAuth; 1]>,
}

/// A single Validated ROA Payload entry from an RPKI cache.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VrpEntry {
    /// Network address (IPv4 or IPv6).
    pub prefix: IpAddr,
    /// Prefix length of the ROA.
    pub prefix_len: u8,
    /// Maximum prefix length authorized by the ROA.
    pub max_len: u8,
    /// Authorized origin AS number.
    pub origin_asn: u32,
}

impl PartialOrd for VrpEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VrpEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Sort by address family, then address bytes, then prefix_len, max_len, origin_asn
        fn addr_sort_key(addr: &IpAddr) -> (u8, [u8; 16]) {
            match addr {
                IpAddr::V4(v4) => {
                    let mut buf = [0u8; 16];
                    buf[..4].copy_from_slice(&v4.octets());
                    (4, buf)
                }
                IpAddr::V6(v6) => (6, v6.octets()),
            }
        }
        let (af_a, bytes_a) = addr_sort_key(&self.prefix);
        let (af_b, bytes_b) = addr_sort_key(&other.prefix);
        af_a.cmp(&af_b)
            .then(bytes_a.cmp(&bytes_b))
            .then(self.prefix_len.cmp(&other.prefix_len))
            .then(self.max_len.cmp(&other.max_len))
            .then(self.origin_asn.cmp(&other.origin_asn))
    }
}

/// Mask an IPv4 address to its leading `len` bits (`len <= 32`).
fn mask_v4(addr: Ipv4Addr, len: u8) -> u32 {
    let bits = u32::from(addr);
    if len == 0 {
        0
    } else {
        bits & (u32::MAX << (32 - len))
    }
}

/// Mask an IPv6 address to its leading `len` bits (`len <= 128`).
fn mask_v6(addr: Ipv6Addr, len: u8) -> u128 {
    let bits = u128::from(addr);
    if len == 0 {
        0
    } else {
        bits & (u128::MAX << (128 - len))
    }
}

/// Immutable VRP table for fast RFC 6811 origin validation.
///
/// Built once from a set of entries, then shared via `Arc`. Storage is a
/// family-split, prefix-length-bucketed index (see the module docs); `v4` has 33
/// buckets (lengths `0..=32`), `v6` has 129 (`0..=128`), each sorted by network.
/// `v4_count`/`v6_count` are the exact-deduped *input* counts (the source for the
/// `rpki_vrp_count` metric); they are tracked separately from the index, which
/// compresses duplicate authorizations.
#[derive(PartialEq, Eq)]
pub struct VrpTable {
    v4_count: usize,
    v6_count: usize,
    v4: Vec<Vec<VrpGroup<u32>>>,
    v6: Vec<Vec<VrpGroup<u128>>>,
}

/// Compress sorted `(asn, max_len)` pairs for one network into `VrpAuth`s,
/// collapsing duplicate origin ASNs to the largest `max_len` (RFC 6482: a
/// shorter duplicate maxLength grants no additional authorization).
fn compress_auths(sorted: &[(u32, u8)]) -> SmallVec<[VrpAuth; 1]> {
    let mut auths: SmallVec<[VrpAuth; 1]> = SmallVec::new();
    for &(origin_asn, max_len) in sorted {
        if let Some(last) = auths.last_mut()
            && last.origin_asn == origin_asn
        {
            last.max_len = last.max_len.max(max_len);
        } else {
            auths.push(VrpAuth {
                origin_asn,
                max_len,
            });
        }
    }
    auths
}

/// Build one family's buckets from `(prefix_len, network, asn, max_len)` items.
/// `items` is sorted ascending, so each `(len, network)` run is contiguous and
/// already network-ordered within its bucket.
fn build_buckets<N: Copy + PartialEq>(
    n_buckets: usize,
    mut items: Vec<(u8, N, u32, u8)>,
) -> Vec<Vec<VrpGroup<N>>>
where
    (u8, N, u32, u8): Ord,
{
    items.sort_unstable();
    let mut buckets: Vec<Vec<VrpGroup<N>>> = vec![Vec::new(); n_buckets];
    let mut i = 0;
    while i < items.len() {
        let (len, network, ..) = items[i];
        let start = i;
        while i < items.len() && items[i].0 == len && items[i].1 == network {
            i += 1;
        }
        let pairs: SmallVec<[(u32, u8); 1]> =
            items[start..i].iter().map(|&(_, _, a, m)| (a, m)).collect();
        buckets[len as usize].push(VrpGroup {
            network,
            auths: compress_auths(&pairs),
        });
    }
    buckets
}

impl VrpTable {
    /// Build a new VRP table from a set of entries.
    ///
    /// Entries are exact-deduplicated for the count metrics; malformed entries
    /// (`prefix_len > 32` for IPv4 / `> 128` for IPv6) are skipped so bucket
    /// indexing cannot panic. The index then compresses duplicate origin ASNs
    /// per network to the largest `max_len`.
    #[must_use]
    pub fn new(mut entries: Vec<VrpEntry>) -> Self {
        entries.sort();
        entries.dedup();

        let mut v4_items: Vec<(u8, u32, u32, u8)> = Vec::new();
        let mut v6_items: Vec<(u8, u128, u32, u8)> = Vec::new();
        for e in entries {
            match e.prefix {
                IpAddr::V4(addr) if e.prefix_len <= 32 => {
                    v4_items.push((
                        e.prefix_len,
                        mask_v4(addr, e.prefix_len),
                        e.origin_asn,
                        e.max_len,
                    ));
                }
                IpAddr::V6(addr) if e.prefix_len <= 128 => {
                    v6_items.push((
                        e.prefix_len,
                        mask_v6(addr, e.prefix_len),
                        e.origin_asn,
                        e.max_len,
                    ));
                }
                _ => {} // malformed prefix length — skip
            }
        }

        Self {
            v4_count: v4_items.len(),
            v6_count: v6_items.len(),
            v4: build_buckets(33, v4_items),
            v6: build_buckets(129, v6_items),
        }
    }

    /// Validate a route prefix + origin ASN per RFC 6811 §2.
    ///
    /// A VRP *covers* the route when its prefix contains the route prefix
    /// (network containment, `vrp.prefix_len <= route_len`). `max_len` does
    /// **not** affect coverage — it only gates the `Valid` decision.
    ///
    /// 1. No covering VRP → `NotFound`.
    /// 2. A covering VRP with matching `origin_asn` and `route_len <= max_len`
    ///    → `Valid`.
    /// 3. Covering VRP(s) exist but none yields `Valid` — wrong `origin_asn`, or
    ///    the route is more specific than every covering VRP's `max_len`
    ///    → `Invalid` (NOT `NotFound`).
    ///
    /// Walks ancestor lengths `0..=route_len`, binary-searching one bucket per
    /// length; a bucket hit is itself the containment proof (mask + exact network
    /// match).
    #[must_use]
    pub fn validate(&self, prefix: &Prefix, origin_asn: u32) -> RpkiValidation {
        let mut has_covering = false;
        match prefix {
            Prefix::V4(v4) => {
                let addr = v4.addr;
                let route_len = v4.len.min(32);
                for len in 0..=route_len {
                    let network = mask_v4(addr, len);
                    let bucket = &self.v4[len as usize];
                    if let Ok(idx) = bucket.binary_search_by_key(&network, |g| g.network) {
                        has_covering = true;
                        if bucket[idx]
                            .auths
                            .iter()
                            .any(|a| a.origin_asn == origin_asn && v4.len <= a.max_len)
                        {
                            return RpkiValidation::Valid;
                        }
                    }
                }
            }
            Prefix::V6(v6) => {
                let addr = v6.addr;
                let route_len = v6.len.min(128);
                for len in 0..=route_len {
                    let network = mask_v6(addr, len);
                    let bucket = &self.v6[len as usize];
                    if let Ok(idx) = bucket.binary_search_by_key(&network, |g| g.network) {
                        has_covering = true;
                        if bucket[idx]
                            .auths
                            .iter()
                            .any(|a| a.origin_asn == origin_asn && v6.len <= a.max_len)
                        {
                            return RpkiValidation::Valid;
                        }
                    }
                }
            }
        }

        if has_covering {
            RpkiValidation::Invalid
        } else {
            RpkiValidation::NotFound
        }
    }

    /// Total number of VRP entries (exact-deduped input count).
    #[must_use]
    pub fn len(&self) -> usize {
        self.v4_count + self.v6_count
    }

    /// Whether the table has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.v4_count == 0 && self.v6_count == 0
    }

    /// Number of IPv4 VRP entries.
    #[must_use]
    pub fn v4_count(&self) -> usize {
        self.v4_count
    }

    /// Number of IPv6 VRP entries.
    #[must_use]
    pub fn v6_count(&self) -> usize {
        self.v6_count
    }
}

impl std::fmt::Debug for VrpTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VrpTable")
            .field("v4_count", &self.v4_count)
            .field("v6_count", &self.v6_count)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix};

    use super::*;

    fn v4_vrp(addr: Ipv4Addr, prefix_len: u8, max_len: u8, asn: u32) -> VrpEntry {
        VrpEntry {
            prefix: IpAddr::V4(addr),
            prefix_len,
            max_len,
            origin_asn: asn,
        }
    }

    fn v6_vrp(addr: Ipv6Addr, prefix_len: u8, max_len: u8, asn: u32) -> VrpEntry {
        VrpEntry {
            prefix: IpAddr::V6(addr),
            prefix_len,
            max_len,
            origin_asn: asn,
        }
    }

    fn v4_prefix(addr: Ipv4Addr, len: u8) -> Prefix {
        Prefix::V4(Ipv4Prefix::new(addr, len))
    }

    fn v6_prefix(addr: Ipv6Addr, len: u8) -> Prefix {
        Prefix::V6(Ipv6Prefix::new(addr, len))
    }

    // ── Basic validation ─────────────────────────────────────────

    #[test]
    fn exact_match_valid() {
        let table = VrpTable::new(vec![v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001)]);
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(10, 0, 0, 0), 24), 65001),
            RpkiValidation::Valid
        );
    }

    #[test]
    fn exact_match_origin_mismatch_invalid() {
        let table = VrpTable::new(vec![v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001)]);
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(10, 0, 0, 0), 24), 65002),
            RpkiValidation::Invalid
        );
    }

    #[test]
    fn no_coverage_not_found() {
        let table = VrpTable::new(vec![v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001)]);
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(192, 168, 0, 0), 24), 65001),
            RpkiValidation::NotFound
        );
    }

    #[test]
    fn empty_table_not_found() {
        let table = VrpTable::new(vec![]);
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(10, 0, 0, 0), 24), 65001),
            RpkiValidation::NotFound
        );
    }

    // ── Max-length coverage ──────────────────────────────────────

    #[test]
    fn max_len_covers_more_specific() {
        // VRP: 10.0.0.0/16 max_len=24 AS65001
        let table = VrpTable::new(vec![v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 16, 24, 65001)]);
        // /24 within max_len → Valid
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(10, 0, 1, 0), 24), 65001),
            RpkiValidation::Valid
        );
    }

    #[test]
    fn max_len_exceeded_invalid() {
        // VRP: 10.0.0.0/16 max_len=24 AS65001
        let table = VrpTable::new(vec![v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 16, 24, 65001)]);
        // /25 exceeds max_len=24 but IS covered by 10.0.0.0/16 → Invalid, not
        // NotFound (RFC 6811 §2: a covering VRP exists, none yields Valid). Even
        // the authorized origin AS65001 may not announce more specific than
        // max_len.
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(10, 0, 1, 0), 25), 65001),
            RpkiValidation::Invalid
        );
        // A different origin on the same over-specific covered route is likewise
        // Invalid (covered, no Valid).
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(10, 0, 1, 0), 25), 65999),
            RpkiValidation::Invalid
        );
    }

    #[test]
    fn ancestor_valid_beats_specific_mismatch() {
        // The most-specific covering VRP fails (wrong ASN), but a less-specific
        // covering VRP authorizes the route → Valid. RFC 6811: ANY covering VRP
        // that matches makes the route Valid, not only the most specific — this
        // is why origin validation needs every covering ancestor, not LPM.
        let table = VrpTable::new(vec![
            v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65002), // specific, wrong ASN
            v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 8, 24, 65001),  // general, right ASN
        ]);
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(10, 0, 0, 0), 24), 65001),
            RpkiValidation::Valid
        );
    }

    #[test]
    fn max_len_exact_boundary() {
        // VRP: 10.0.0.0/16 max_len=24 AS65001
        let table = VrpTable::new(vec![v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 16, 24, 65001)]);
        // /16 within max_len → Valid (route len == VRP prefix len)
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(10, 0, 0, 0), 16), 65001),
            RpkiValidation::Valid
        );
    }

    // ── Multiple VRPs ────────────────────────────────────────────

    #[test]
    fn multiple_vrps_any_match_valid() {
        // Two VRPs cover 10.0.0.0/24: AS65001 and AS65002
        let table = VrpTable::new(vec![
            v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001),
            v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65002),
        ]);
        // AS65002 matches one VRP → Valid
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(10, 0, 0, 0), 24), 65002),
            RpkiValidation::Valid
        );
    }

    #[test]
    fn multiple_vrps_none_match_invalid() {
        let table = VrpTable::new(vec![
            v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001),
            v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65002),
        ]);
        // AS65003 doesn't match any → Invalid (covering VRPs exist)
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(10, 0, 0, 0), 24), 65003),
            RpkiValidation::Invalid
        );
    }

    #[test]
    fn overlapping_vrps_different_max_len() {
        // VRP1: 10.0.0.0/16 max_len=20 AS65001
        // VRP2: 10.0.0.0/16 max_len=24 AS65002
        let table = VrpTable::new(vec![
            v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 16, 20, 65001),
            v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 16, 24, 65002),
        ]);
        // /24 route: only VRP2 covers (max_len=24 >= 24), AS65002 matches
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(10, 0, 1, 0), 24), 65002),
            RpkiValidation::Valid
        );
        // /24 route: AS65001 has VRP with max_len=20, doesn't cover /24
        // But VRP2 covers it with different origin → Invalid
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(10, 0, 1, 0), 24), 65001),
            RpkiValidation::Invalid
        );
    }

    // ── IPv6 ─────────────────────────────────────────────────────

    #[test]
    fn ipv6_exact_match_valid() {
        let table = VrpTable::new(vec![v6_vrp("2001:db8::".parse().unwrap(), 32, 48, 65001)]);
        assert_eq!(
            table.validate(&v6_prefix("2001:db8:1::".parse().unwrap(), 48), 65001),
            RpkiValidation::Valid
        );
    }

    #[test]
    fn ipv6_origin_mismatch_invalid() {
        let table = VrpTable::new(vec![v6_vrp("2001:db8::".parse().unwrap(), 32, 48, 65001)]);
        assert_eq!(
            table.validate(&v6_prefix("2001:db8:1::".parse().unwrap(), 48), 65002),
            RpkiValidation::Invalid
        );
    }

    #[test]
    fn ipv6_no_coverage() {
        let table = VrpTable::new(vec![v6_vrp("2001:db8::".parse().unwrap(), 32, 48, 65001)]);
        assert_eq!(
            table.validate(&v6_prefix("2001:db9::".parse().unwrap(), 32), 65001),
            RpkiValidation::NotFound
        );
    }

    #[test]
    fn ipv6_host_route_max_len() {
        // VRP covers /48 with max_len=128 — a /128 host route matches (the v6
        // shift-by-128 boundary in the masking helper must not misbehave).
        let table = VrpTable::new(vec![v6_vrp(
            "2001:db8:1::".parse().unwrap(),
            48,
            128,
            65001,
        )]);
        assert_eq!(
            table.validate(&v6_prefix("2001:db8:1::1".parse().unwrap(), 128), 65001),
            RpkiValidation::Valid
        );
    }

    #[test]
    fn ipv6_max_len_exceeded_invalid() {
        // Mirror of the v4 max-len fix on v6: /64 covered by /32 max_len=48 → Invalid.
        let table = VrpTable::new(vec![v6_vrp("2001:db8::".parse().unwrap(), 32, 48, 65001)]);
        assert_eq!(
            table.validate(&v6_prefix("2001:db8:1::".parse().unwrap(), 64), 65001),
            RpkiValidation::Invalid
        );
    }

    // ── Mixed IPv4 + IPv6 ────────────────────────────────────────

    #[test]
    fn mixed_table_validates_correct_family() {
        let table = VrpTable::new(vec![
            v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001),
            v6_vrp("2001:db8::".parse().unwrap(), 32, 48, 65002),
        ]);
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(10, 0, 0, 0), 24), 65001),
            RpkiValidation::Valid
        );
        assert_eq!(
            table.validate(&v6_prefix("2001:db8:1::".parse().unwrap(), 48), 65002),
            RpkiValidation::Valid
        );
        // Cross-family: no coverage
        assert_eq!(
            table.validate(&v6_prefix("2001:db8:1::".parse().unwrap(), 48), 65001),
            RpkiValidation::Invalid
        );
    }

    // ── Constructor ──────────────────────────────────────────────

    #[test]
    fn deduplication() {
        let table = VrpTable::new(vec![
            v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001),
            v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001),
            v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001),
        ]);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn len_and_is_empty() {
        let empty = VrpTable::new(vec![]);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let non_empty = VrpTable::new(vec![v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001)]);
        assert!(!non_empty.is_empty());
        assert_eq!(non_empty.len(), 1);
    }

    #[test]
    fn v4_v6_counts() {
        let table = VrpTable::new(vec![
            v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001),
            v4_vrp(Ipv4Addr::new(10, 1, 0, 0), 24, 24, 65001),
            v6_vrp("2001:db8::".parse().unwrap(), 32, 48, 65001),
        ]);
        assert_eq!(table.v4_count(), 2);
        assert_eq!(table.v6_count(), 1);
        assert_eq!(table.len(), 3);
    }

    // ── Prefix containment edge cases ────────────────────────────

    #[test]
    fn vrp_with_zero_prefix_len_covers_all() {
        let table = VrpTable::new(vec![v4_vrp(Ipv4Addr::UNSPECIFIED, 0, 32, 65001)]);
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(192, 168, 1, 0), 24), 65001),
            RpkiValidation::Valid
        );
    }

    #[test]
    fn host_route_max_len() {
        // VRP covers /24 with max_len=32 — a /32 host route should match
        let table = VrpTable::new(vec![v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 24, 32, 65001)]);
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(10, 0, 0, 1), 32), 65001),
            RpkiValidation::Valid
        );
    }

    #[test]
    fn route_less_specific_than_vrp_not_covered() {
        // VRP: 10.0.0.0/24 — route 10.0.0.0/16 is NOT covered (VRP is more specific)
        let table = VrpTable::new(vec![v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001)]);
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(10, 0, 0, 0), 16), 65001),
            RpkiValidation::NotFound
        );
    }

    // ── Address masking helper ───────────────────────────────────

    #[test]
    fn mask_v4_truncates_host_bits() {
        assert_eq!(
            mask_v4(Ipv4Addr::new(10, 0, 1, 5), 16),
            u32::from(Ipv4Addr::new(10, 0, 0, 0))
        );
        assert_eq!(
            mask_v4(Ipv4Addr::new(10, 0, 1, 0), 24),
            u32::from(Ipv4Addr::new(10, 0, 1, 0))
        );
        // /0 masks to 0; /32 keeps every bit (shift-boundary guards).
        assert_eq!(mask_v4(Ipv4Addr::new(192, 168, 1, 1), 0), 0);
        assert_eq!(
            mask_v4(Ipv4Addr::new(192, 168, 1, 1), 32),
            u32::from(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn mask_v6_truncates_host_bits() {
        let a: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
        assert_eq!(
            mask_v6(a, 32),
            u128::from("2001:db8::".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(mask_v6(a, 0), 0);
        assert_eq!(mask_v6(a, 128), u128::from(a));
    }

    // ── Index build behavior ─────────────────────────────────────

    #[test]
    fn maxlen_compression_keeps_largest() {
        // Two distinct deduped VRPs for the same network + origin differ only in
        // max_len. The index compresses them to the largest max_len, but the
        // count metric still reflects the deduped *input* (2), not the 1 auth.
        let table = VrpTable::new(vec![
            v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 16, 24, 65001),
            v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 16, 20, 65001),
        ]);
        assert_eq!(table.v4_count(), 2);
        // /24 is within the largest (24) max_len → Valid.
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(10, 0, 1, 0), 24), 65001),
            RpkiValidation::Valid
        );
    }

    #[test]
    fn malformed_prefix_len_skipped() {
        // prefix_len beyond the family width is dropped (no panic) and not counted.
        let table = VrpTable::new(vec![
            v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 33, 33, 65001),
            v6_vrp("2001:db8::".parse().unwrap(), 129, 129, 65002),
            v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65003), // valid, kept
        ]);
        assert_eq!(table.v4_count(), 1);
        assert_eq!(table.v6_count(), 0);
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(10, 0, 0, 0), 24), 65003),
            RpkiValidation::Valid
        );
    }
}
