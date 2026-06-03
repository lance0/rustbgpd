//! Per-peer Outbound Route Filtering (ORF) state — RFC 5291 + RFC 5292.
//!
//! When a peer pushes Address-Prefix ORF entries (via ROUTE-REFRESH), the RIB
//! stores them here per `(peer, AFI, SAFI)` and consults the set as an
//! *additional* outbound filter when distributing routes to that peer — on top
//! of normal export policy, applied before it.
//!
//! Evaluation follows prefix-list semantics (FRR-compatible): entries are
//! ordered by their `Sequence` field, the first matching entry wins, and a
//! non-empty set with no match denies (implicit deny). An empty set imposes no
//! constraint (permit-all), so a peer that negotiated ORF but has not yet sent
//! entries still receives the full table once the initial-advertisement gate is
//! lifted (see the manager's `peer_orf_pending`).

use rustbgpd_wire::{AddressPrefixOrf, OrfAction, OrfMatch, Prefix};

/// One installed Address-Prefix ORF entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OrfFilterEntry {
    /// Ordering key — entries are evaluated in ascending sequence order.
    pub sequence: u32,
    /// Permit or Deny on match.
    pub match_: OrfMatch,
    /// Minimum prefix length (0 = unspecified, RFC 5292 §4).
    pub min_len: u8,
    /// Maximum prefix length (0 = unspecified, RFC 5292 §4).
    pub max_len: u8,
    /// The filtered prefix.
    pub prefix: Prefix,
}

/// A per-`(peer, AFI, SAFI)` ORF prefix filter: a sequence-ordered entry list
/// with prefix-list match semantics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct OrfFilterSet {
    /// Entries kept sorted by `sequence` (ascending). A plain `Vec`, not a
    /// trie — first-match-by-sequence ordering matters more than lookup speed,
    /// and ORF lists are small.
    entries: Vec<OrfFilterEntry>,
}

impl OrfFilterSet {
    /// Whether the set holds no entries (permit-all).
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Apply a batch of wire ORF entries (in wire order).
    ///
    /// `ADD` inserts/replaces by sequence, `REMOVE` deletes by sequence,
    /// `REMOVE-ALL` clears the set. Returns `Err(())` if any entry carries an
    /// unrecognized field value (e.g. `min_len > max_len`, or a length beyond
    /// the address family): per RFC 5291 §5.2 the previously installed list of
    /// that type is removed, so on error the set is cleared and the caller
    /// treats the family as permit-all again.
    pub(crate) fn apply(&mut self, entries: &[AddressPrefixOrf]) -> Result<(), ()> {
        for entry in entries {
            match entry.action {
                OrfAction::RemoveAll => self.entries.clear(),
                OrfAction::Remove => {
                    self.entries.retain(|e| e.sequence != entry.sequence);
                }
                OrfAction::Add => {
                    let Some(prefix) = entry.prefix else {
                        self.entries.clear();
                        return Err(());
                    };
                    if !valid_lengths(&prefix, entry.min_len, entry.max_len) {
                        self.entries.clear();
                        return Err(());
                    }
                    self.entries.retain(|e| e.sequence != entry.sequence);
                    self.entries.push(OrfFilterEntry {
                        sequence: entry.sequence,
                        match_: entry.match_,
                        min_len: entry.min_len,
                        max_len: entry.max_len,
                        prefix,
                    });
                }
            }
        }
        self.entries.sort_by_key(|e| e.sequence);
        Ok(())
    }

    /// Whether `prefix` is permitted for export under this filter.
    ///
    /// Empty set ⇒ permit-all. Otherwise the first entry (by sequence) whose
    /// prefix contains `prefix` and whose length window matches decides;
    /// no match ⇒ deny (implicit deny).
    pub(crate) fn permits(&self, prefix: &Prefix) -> bool {
        if self.entries.is_empty() {
            return true;
        }
        for entry in &self.entries {
            if entry_matches(entry, prefix) {
                return entry.match_ == OrfMatch::Permit;
            }
        }
        false
    }
}

/// Family-maximum prefix length.
fn family_max(prefix: &Prefix) -> u8 {
    match prefix {
        Prefix::V4(_) => 32,
        Prefix::V6(_) => 128,
    }
}

/// Validate the min/max length window of an ADD entry against its prefix
/// (RFC 5292 §4). `0` means unspecified.
fn valid_lengths(prefix: &Prefix, min_len: u8, max_len: u8) -> bool {
    let fam_max = family_max(prefix);
    if min_len > fam_max || max_len > fam_max {
        return false;
    }
    if min_len != 0 && max_len != 0 && min_len > max_len {
        return false;
    }
    true
}

/// Whether `entry` matches `route` per RFC 5292 §6: containment plus the
/// min/max length window (0 = unspecified; both unspecified ⇒ exact length).
fn entry_matches(entry: &OrfFilterEntry, route: &Prefix) -> bool {
    if !prefix_contains(&entry.prefix, route) {
        return false;
    }
    let entry_len = entry.prefix.prefix_len();
    let route_len = route.prefix_len();
    if entry.min_len == 0 && entry.max_len == 0 {
        return route_len == entry_len;
    }
    let lo = entry_len.max(entry.min_len);
    let hi = if entry.max_len == 0 {
        family_max(route)
    } else {
        entry.max_len
    };
    route_len >= lo && route_len <= hi
}

/// Whether `outer` (at its own prefix length) network-contains `inner`.
/// Both prefixes are canonical (host bits already zeroed by construction).
fn prefix_contains(outer: &Prefix, inner: &Prefix) -> bool {
    match (outer, inner) {
        (Prefix::V4(o), Prefix::V4(i)) => {
            o.len <= i.len && {
                let mask = if o.len == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(o.len))
                };
                (u32::from(o.addr) & mask) == (u32::from(i.addr) & mask)
            }
        }
        (Prefix::V6(o), Prefix::V6(i)) => {
            o.len <= i.len && {
                let mask = if o.len == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(o.len))
                };
                (u128::from(o.addr) & mask) == (u128::from(i.addr) & mask)
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(addr: [u8; 4], len: u8) -> Prefix {
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(addr), len))
    }

    fn add(seq: u32, m: OrfMatch, min: u8, max: u8, prefix: Prefix) -> AddressPrefixOrf {
        AddressPrefixOrf {
            action: OrfAction::Add,
            match_: m,
            sequence: seq,
            min_len: min,
            max_len: max,
            prefix: Some(prefix),
        }
    }

    #[test]
    fn empty_set_permits_all() {
        let f = OrfFilterSet::default();
        assert!(f.permits(&v4([10, 0, 0, 0], 8)));
        assert!(f.permits(&v4([192, 168, 1, 0], 24)));
    }

    #[test]
    fn exact_match_when_min_max_both_zero() {
        let mut f = OrfFilterSet::default();
        f.apply(&[add(1, OrfMatch::Permit, 0, 0, v4([10, 0, 0, 0], 8))])
            .unwrap();
        assert!(f.permits(&v4([10, 0, 0, 0], 8)), "exact /8 permitted");
        // More-specific under 10/8 does NOT match an exact /8 entry, and with a
        // non-empty list, no-match ⇒ implicit deny.
        assert!(!f.permits(&v4([10, 1, 0, 0], 16)));
    }

    #[test]
    fn min_only_is_ge() {
        let mut f = OrfFilterSet::default();
        // permit 10/8 ge 16 (min=16, max unspecified)
        f.apply(&[add(1, OrfMatch::Permit, 16, 0, v4([10, 0, 0, 0], 8))])
            .unwrap();
        assert!(!f.permits(&v4([10, 0, 0, 0], 8)), "len 8 < min 16");
        assert!(f.permits(&v4([10, 1, 0, 0], 16)));
        assert!(f.permits(&v4([10, 1, 1, 0], 24)));
        assert!(f.permits(&v4([10, 1, 1, 1], 32)));
    }

    #[test]
    fn max_only_is_le() {
        let mut f = OrfFilterSet::default();
        // permit 10/8 le 24 (max=24, min unspecified → lower bound = prefix len 8)
        f.apply(&[add(1, OrfMatch::Permit, 0, 24, v4([10, 0, 0, 0], 8))])
            .unwrap();
        assert!(f.permits(&v4([10, 0, 0, 0], 8)));
        assert!(f.permits(&v4([10, 1, 1, 0], 24)));
        assert!(!f.permits(&v4([10, 1, 1, 0], 25)), "len 25 > max 24");
    }

    #[test]
    fn min_and_max_window() {
        let mut f = OrfFilterSet::default();
        f.apply(&[add(1, OrfMatch::Permit, 16, 24, v4([10, 0, 0, 0], 8))])
            .unwrap();
        assert!(!f.permits(&v4([10, 1, 0, 0], 15)), "len 15 < min 16");
        assert!(f.permits(&v4([10, 1, 0, 0], 16)));
        assert!(f.permits(&v4([10, 1, 1, 0], 24)));
        assert!(!f.permits(&v4([10, 1, 1, 0], 25)));
    }

    #[test]
    fn first_match_by_sequence_wins() {
        let mut f = OrfFilterSet::default();
        // seq 1: deny 10.1/16 ; seq 2: permit 10/8 le 32
        f.apply(&[
            add(2, OrfMatch::Permit, 0, 32, v4([10, 0, 0, 0], 8)),
            add(1, OrfMatch::Deny, 0, 32, v4([10, 1, 0, 0], 16)),
        ])
        .unwrap();
        // 10.1.0.0/24 matches the deny (seq 1) first → denied.
        assert!(!f.permits(&v4([10, 1, 1, 0], 24)));
        // 10.2.0.0/24 only matches the permit (seq 2) → permitted.
        assert!(f.permits(&v4([10, 2, 1, 0], 24)));
    }

    #[test]
    fn implicit_deny_on_no_match() {
        let mut f = OrfFilterSet::default();
        f.apply(&[add(1, OrfMatch::Permit, 0, 0, v4([192, 168, 0, 0], 16))])
            .unwrap();
        // 10/8 matches nothing in a non-empty list ⇒ implicit deny.
        assert!(!f.permits(&v4([10, 0, 0, 0], 8)));
    }

    #[test]
    fn remove_by_sequence() {
        let mut f = OrfFilterSet::default();
        f.apply(&[add(1, OrfMatch::Permit, 0, 0, v4([10, 0, 0, 0], 8))])
            .unwrap();
        f.apply(&[AddressPrefixOrf {
            action: OrfAction::Remove,
            match_: OrfMatch::Permit,
            sequence: 1,
            min_len: 0,
            max_len: 0,
            prefix: None,
        }])
        .unwrap();
        assert!(f.is_empty());
    }

    #[test]
    fn remove_all_clears() {
        let mut f = OrfFilterSet::default();
        f.apply(&[
            add(1, OrfMatch::Permit, 0, 0, v4([10, 0, 0, 0], 8)),
            add(2, OrfMatch::Permit, 0, 0, v4([192, 168, 0, 0], 16)),
        ])
        .unwrap();
        f.apply(&[AddressPrefixOrf {
            action: OrfAction::RemoveAll,
            match_: OrfMatch::Permit,
            sequence: 0,
            min_len: 0,
            max_len: 0,
            prefix: None,
        }])
        .unwrap();
        assert!(f.is_empty());
        assert!(f.permits(&v4([10, 0, 0, 0], 8)), "cleared ⇒ permit-all");
    }

    #[test]
    fn add_replaces_same_sequence() {
        let mut f = OrfFilterSet::default();
        f.apply(&[add(1, OrfMatch::Permit, 0, 0, v4([10, 0, 0, 0], 8))])
            .unwrap();
        f.apply(&[add(1, OrfMatch::Deny, 0, 0, v4([10, 0, 0, 0], 8))])
            .unwrap();
        assert!(
            !f.permits(&v4([10, 0, 0, 0], 8)),
            "deny replaced permit at seq 1"
        );
    }

    #[test]
    fn malformed_min_gt_max_flushes_list() {
        let mut f = OrfFilterSet::default();
        f.apply(&[add(1, OrfMatch::Permit, 0, 0, v4([10, 0, 0, 0], 8))])
            .unwrap();
        // min 24 > max 16 ⇒ malformed field; previously-installed list is reset.
        let err = f.apply(&[add(2, OrfMatch::Permit, 24, 16, v4([192, 168, 0, 0], 16))]);
        assert!(err.is_err());
        assert!(f.is_empty(), "malformed entry resets the installed list");
    }

    #[test]
    fn ipv6_host_route_match() {
        let mut f = OrfFilterSet::default();
        let net = Prefix::V6(Ipv6Prefix::new(
            "2001:db8::".parse::<Ipv6Addr>().unwrap(),
            32,
        ));
        f.apply(&[add(1, OrfMatch::Permit, 0, 128, net)]).unwrap();
        let host = Prefix::V6(Ipv6Prefix::new(
            "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
            128,
        ));
        assert!(f.permits(&host));
        let other = Prefix::V6(Ipv6Prefix::new(
            "2001:dead::1".parse::<Ipv6Addr>().unwrap(),
            128,
        ));
        assert!(!f.permits(&other));
    }

    #[test]
    fn default_route_entry() {
        let mut f = OrfFilterSet::default();
        // permit 0/0 le 32 ⇒ permit everything (explicit permit-all).
        f.apply(&[add(1, OrfMatch::Permit, 0, 32, v4([0, 0, 0, 0], 0))])
            .unwrap();
        assert!(f.permits(&v4([10, 0, 0, 0], 8)));
        assert!(f.permits(&v4([192, 168, 1, 1], 32)));
    }
}
