//! VRP (Validated ROA Payload) table and origin validation.
//!
//! The [`VrpTable`] stores a sorted, deduplicated set of [`VrpEntry`] values
//! and implements RFC 6811 origin validation: given a route's prefix and
//! origin ASN, it classifies the route as `Valid`, `Invalid`, or `NotFound`.

use std::net::IpAddr;

use rustbgpd_wire::{Prefix, RpkiValidation};

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

/// Immutable, sorted table of VRP entries for fast origin validation.
///
/// Built once from a set of entries (deduplicating), then shared via `Arc`.
/// Validation is O(n) scan over entries of the same address family — sufficient
/// for typical VRP table sizes (hundreds of thousands of entries). A more
/// sophisticated index can be added later if needed.
#[derive(PartialEq, Eq)]
pub struct VrpTable {
    /// Sorted and deduplicated entries.
    v4_entries: Vec<VrpEntry>,
    v6_entries: Vec<VrpEntry>,
}

impl VrpTable {
    /// Build a new VRP table from a set of entries.
    ///
    /// Entries are sorted and deduplicated.
    #[must_use]
    pub fn new(mut entries: Vec<VrpEntry>) -> Self {
        entries.sort();
        entries.dedup();
        let mut v4_entries = Vec::new();
        let mut v6_entries = Vec::new();
        for e in entries {
            match e.prefix {
                IpAddr::V4(_) => v4_entries.push(e),
                IpAddr::V6(_) => v6_entries.push(e),
            }
        }
        Self {
            v4_entries,
            v6_entries,
        }
    }

    /// Validate a route prefix + origin ASN per RFC 6811.
    ///
    /// 1. Find all VRPs that *cover* the prefix: the VRP's prefix contains the
    ///    route's prefix, and the route's prefix length ≤ VRP's `max_len`.
    /// 2. If no covering VRPs → `NotFound`
    /// 3. If any covering VRP has matching `origin_asn` → `Valid`
    /// 4. Covering VRPs exist but none match → `Invalid`
    #[must_use]
    pub fn validate(&self, prefix: &Prefix, origin_asn: u32) -> RpkiValidation {
        let (route_addr, route_len) = match prefix {
            Prefix::V4(v4) => (IpAddr::V4(v4.addr), v4.len),
            Prefix::V6(v6) => (IpAddr::V6(v6.addr), v6.len),
        };

        let entries = match route_addr {
            IpAddr::V4(_) => &self.v4_entries,
            IpAddr::V6(_) => &self.v6_entries,
        };

        let mut has_covering = false;
        for vrp in entries {
            // VRP prefix length must be ≤ route prefix length (VRP covers route)
            if vrp.prefix_len > route_len {
                continue;
            }
            // Route prefix length must be ≤ VRP max_len
            if route_len > vrp.max_len {
                continue;
            }
            // Check containment: VRP prefix must contain the route prefix
            if !prefix_contains(vrp.prefix, vrp.prefix_len, route_addr, route_len) {
                continue;
            }
            // This VRP covers the route
            has_covering = true;
            if vrp.origin_asn == origin_asn {
                return RpkiValidation::Valid;
            }
        }

        if has_covering {
            RpkiValidation::Invalid
        } else {
            RpkiValidation::NotFound
        }
    }

    /// Total number of VRP entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.v4_entries.len() + self.v6_entries.len()
    }

    /// Whether the table has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.v4_entries.is_empty() && self.v6_entries.is_empty()
    }

    /// Number of IPv4 VRP entries.
    #[must_use]
    pub fn v4_count(&self) -> usize {
        self.v4_entries.len()
    }

    /// Number of IPv6 VRP entries.
    #[must_use]
    pub fn v6_count(&self) -> usize {
        self.v6_entries.len()
    }
}

impl std::fmt::Debug for VrpTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VrpTable")
            .field("v4_entries", &self.v4_entries.len())
            .field("v6_entries", &self.v6_entries.len())
            .finish()
    }
}

/// Check whether `outer` (with `outer_len`) contains `inner` (with `inner_len`).
///
/// Both addresses must be the same address family.
fn prefix_contains(outer: IpAddr, outer_len: u8, inner: IpAddr, inner_len: u8) -> bool {
    if outer_len > inner_len {
        return false;
    }
    match (outer, inner) {
        (IpAddr::V4(o), IpAddr::V4(i)) => {
            if outer_len == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - outer_len);
            (u32::from(o) & mask) == (u32::from(i) & mask)
        }
        (IpAddr::V6(o), IpAddr::V6(i)) => {
            if outer_len == 0 {
                return true;
            }
            let o_bits = u128::from(o);
            let i_bits = u128::from(i);
            let mask = u128::MAX << (128 - outer_len);
            (o_bits & mask) == (i_bits & mask)
        }
        _ => false, // different address families
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
    fn max_len_exceeded_not_found() {
        // VRP: 10.0.0.0/16 max_len=24 AS65001
        let table = VrpTable::new(vec![v4_vrp(Ipv4Addr::new(10, 0, 0, 0), 16, 24, 65001)]);
        // /25 exceeds max_len=24 → NotFound (no covering VRP)
        assert_eq!(
            table.validate(&v4_prefix(Ipv4Addr::new(10, 0, 1, 0), 25), 65001),
            RpkiValidation::NotFound
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

    // ── prefix_contains helper ───────────────────────────────────

    #[test]
    fn prefix_contains_v4() {
        assert!(prefix_contains(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            16,
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 0)),
            24,
        ));
        assert!(!prefix_contains(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            16,
            IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)),
            24,
        ));
    }

    #[test]
    fn prefix_contains_v6() {
        assert!(prefix_contains(
            IpAddr::V6("2001:db8::".parse().unwrap()),
            32,
            IpAddr::V6("2001:db8:1::".parse().unwrap()),
            48,
        ));
        assert!(!prefix_contains(
            IpAddr::V6("2001:db8::".parse().unwrap()),
            32,
            IpAddr::V6("2001:db9::".parse().unwrap()),
            48,
        ));
    }

    #[test]
    fn prefix_contains_zero_len() {
        assert!(prefix_contains(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            32,
        ));
    }

    #[test]
    fn prefix_contains_cross_family_false() {
        assert!(!prefix_contains(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            8,
            IpAddr::V6("::ffff:10.0.0.0".parse().unwrap()),
            128,
        ));
    }
}
