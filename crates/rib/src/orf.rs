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

use std::collections::BTreeMap;
use std::sync::Arc;

use rustbgpd_wire::{AddressPrefixOrf, Ipv4Prefix, Ipv6Prefix, OrfAction, OrfMatch, Prefix};

use crate::fast_hash::FastMap;

/// Fixed retained-entry bound per peer and address family, including DEFER pushes.
pub(crate) const MAX_ORF_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OrfApplyError {
    Malformed,
    Capacity,
}

/// One installed Address-Prefix ORF entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OrfFilterEntry {
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
/// with prefix-list match semantics, plus a lookup index rebuilt on change.
///
/// Cloning shares the installed state, so a distribution pass can snapshot a
/// peer's filters without copying them.
#[derive(Debug, Clone, Default)]
pub(crate) struct OrfFilterSet {
    inner: Arc<OrfFilterState>,
    generation: u64,
}

#[derive(Debug, Clone, Default)]
struct OrfFilterState {
    /// Sequence order also supports replacements/removals without a list scan.
    entries: BTreeMap<u32, OrfFilterEntry>,
    index: OrfIndex,
}

impl PartialEq for OrfFilterSet {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner) || self.inner.entries == other.inner.entries
    }
}

impl Eq for OrfFilterSet {}

impl OrfFilterSet {
    /// Whether the set holds no entries (permit-all).
    pub(crate) fn is_empty(&self) -> bool {
        self.inner.entries.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.inner.entries.len()
    }

    /// Apply a batch of wire ORF entries (in wire order).
    ///
    /// `ADD` inserts/replaces by sequence, `REMOVE` deletes by sequence,
    /// `REMOVE-ALL` clears the set. Returns `Malformed` if any entry carries an
    /// unrecognized field value (e.g. `min_len > max_len`, or a length beyond
    /// the address family): per RFC 5291 §6 the previously installed list of
    /// that type is removed, so on error the set is cleared and the caller
    /// treats the family as permit-all again. An ADD exceeding the fixed cap
    /// rejects the entire batch and preserves the previously installed filter.
    pub(crate) fn apply(&mut self, entries: &[AddressPrefixOrf]) -> Result<(), OrfApplyError> {
        // RFC 5291 §6 malformed-field reset takes precedence over capacity.
        if entries.iter().any(|entry| {
            entry.action == OrfAction::Add
                && entry
                    .prefix
                    .is_none_or(|prefix| !valid_lengths(&prefix, entry.min_len, entry.max_len))
        }) {
            self.clear();
            return Err(OrfApplyError::Malformed);
        }
        // Stage the batch as per-sequence changes over the installed list, so
        // the capacity check never inserts the cap+1 entry and never copies
        // the installed list.
        let installed = &self.inner.entries;
        let mut cleared = false;
        let mut changes: BTreeMap<u32, Option<OrfFilterEntry>> = BTreeMap::new();
        let mut len = installed.len();
        for entry in entries {
            let present = changes.get(&entry.sequence).map_or_else(
                || !cleared && installed.contains_key(&entry.sequence),
                Option::is_some,
            );
            match entry.action {
                OrfAction::RemoveAll => {
                    cleared = true;
                    changes.clear();
                    len = 0;
                }
                OrfAction::Remove => {
                    len -= usize::from(present);
                    changes.insert(entry.sequence, None);
                }
                OrfAction::Add => {
                    let Some(prefix) = entry.prefix else {
                        unreachable!("an ADD without a prefix was rejected as malformed above");
                    };
                    if !present {
                        if len == MAX_ORF_ENTRIES {
                            return Err(OrfApplyError::Capacity);
                        }
                        len += 1;
                    }
                    changes.insert(
                        entry.sequence,
                        Some(OrfFilterEntry {
                            match_: entry.match_,
                            min_len: entry.min_len,
                            max_len: entry.max_len,
                            prefix,
                        }),
                    );
                }
            }
        }
        let effective = (cleared && !installed.is_empty())
            || changes.iter().any(|(sequence, change)| {
                let current = if cleared {
                    None
                } else {
                    installed.get(sequence)
                };
                current != change.as_ref()
            });
        if !effective {
            return Ok(());
        }
        let state = Arc::make_mut(&mut self.inner);
        if cleared {
            state.entries.clear();
        }
        for (sequence, change) in changes {
            match change {
                Some(entry) => {
                    state.entries.insert(sequence, entry);
                }
                None => {
                    state.entries.remove(&sequence);
                }
            }
        }
        state.index = OrfIndex::build(&state.entries);
        self.generation += 1;
        Ok(())
    }

    /// Remove every entry (RFC 5291 §6 malformed-list reset).
    fn clear(&mut self) {
        if !self.is_empty() {
            self.inner = Arc::default();
            self.generation += 1;
        }
    }

    /// Advances on every change to the installed entries, so callers can
    /// detect a change without keeping a copy of the filter.
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether `prefix` is permitted for export under this filter.
    ///
    /// Empty set ⇒ permit-all. Otherwise the first entry (by sequence) whose
    /// prefix contains `prefix` and whose length window matches decides;
    /// no match ⇒ deny (implicit deny).
    pub(crate) fn permits(&self, prefix: &Prefix) -> bool {
        self.is_empty() || self.inner.index.first_match(prefix) == Some(OrfMatch::Permit)
    }
}

/// First-match verdicts precomputed per entry prefix. Only entries whose
/// prefix contains a route can match it, and at most one such prefix exists
/// per length, so a lookup probes one key per distinct installed length up to
/// the route's own length instead of scanning every entry.
#[derive(Debug, Clone, Default)]
struct OrfIndex {
    /// Distinct installed entry-prefix lengths, ascending: `[IPv4, IPv6]`.
    lengths: [Vec<u8>; 2],
    /// Entry prefix → the lowest-sequence entry matching each route length.
    keys: FastMap<Prefix, LengthVerdicts>,
}

#[derive(Debug, Clone)]
struct LengthVerdicts {
    /// Route length that `verdicts[0]` describes.
    first_len: u8,
    /// `(sequence, action)` of the lowest-sequence entry at this prefix whose
    /// length window holds the route length, if any.
    verdicts: Box<[Option<(u32, OrfMatch)>]>,
}

impl OrfIndex {
    fn build(entries: &BTreeMap<u32, OrfFilterEntry>) -> Self {
        // Iterating in sequence order keeps each key's windows sorted by
        // sequence, so the first window to claim a length is the first match.
        let mut windows: FastMap<Prefix, Vec<(u8, u8, u32, OrfMatch)>> = FastMap::default();
        for (&sequence, entry) in entries {
            let (lo, hi) = length_window(&entry.prefix, entry.min_len, entry.max_len);
            if lo <= hi {
                windows
                    .entry(truncate(&entry.prefix, entry.prefix.prefix_len()))
                    .or_default()
                    .push((lo, hi, sequence, entry.match_));
            }
        }
        let mut index = Self::default();
        for (prefix, windows) in windows {
            let first_len = windows.iter().map(|w| w.0).min().unwrap_or(0);
            let last_len = windows.iter().map(|w| w.1).max().unwrap_or(0);
            let mut verdicts = vec![None; usize::from(last_len - first_len) + 1];
            for (lo, hi, sequence, action) in windows {
                let range = usize::from(lo - first_len)..=usize::from(hi - first_len);
                for verdict in &mut verdicts[range] {
                    verdict.get_or_insert((sequence, action));
                }
            }
            index.lengths[family_index(&prefix)].push(prefix.prefix_len());
            index.keys.insert(
                prefix,
                LengthVerdicts {
                    first_len,
                    verdicts: verdicts.into_boxed_slice(),
                },
            );
        }
        for lengths in &mut index.lengths {
            lengths.sort_unstable();
            lengths.dedup();
        }
        index
    }

    /// The action of the lowest-sequence entry matching `route`, if any.
    fn first_match(&self, route: &Prefix) -> Option<OrfMatch> {
        let route_len = route.prefix_len();
        let mut best: Option<(u32, OrfMatch)> = None;
        for &len in &self.lengths[family_index(route)] {
            if len > route_len {
                break;
            }
            let Some(key) = self.keys.get(&truncate(route, len)) else {
                continue;
            };
            let hit = route_len
                .checked_sub(key.first_len)
                .and_then(|offset| key.verdicts.get(usize::from(offset)))
                .copied()
                .flatten();
            if let Some(hit) = hit
                && best.is_none_or(|best| hit.0 < best.0)
            {
                best = Some(hit);
            }
        }
        best.map(|(_, action)| action)
    }
}

fn family_index(prefix: &Prefix) -> usize {
    match prefix {
        Prefix::V4(_) => 0,
        Prefix::V6(_) => 1,
    }
}

/// `prefix` shortened to `len` bits, host bits zeroed.
fn truncate(prefix: &Prefix, len: u8) -> Prefix {
    match prefix {
        Prefix::V4(p) => Prefix::V4(Ipv4Prefix::new(p.addr, len)),
        Prefix::V6(p) => Prefix::V6(Ipv6Prefix::new(p.addr, len)),
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

/// The inclusive route-length window `[lo, hi]` an entry with this prefix and
/// min/max matches (RFC 5292 §6; 0 = unspecified, both unspecified ⇒ exact
/// length). The lower bound is clamped to the entry's own prefix length, so a
/// `min_len` below it is harmless.
fn length_window(prefix: &Prefix, min_len: u8, max_len: u8) -> (u8, u8) {
    let entry_len = prefix.prefix_len();
    if min_len == 0 && max_len == 0 {
        return (entry_len, entry_len);
    }
    let lo = entry_len.max(min_len);
    let hi = if max_len == 0 {
        family_max(prefix)
    } else {
        max_len
    };
    (lo, hi)
}

/// Whether a well-formed ADD entry can never match any route: a non-zero
/// `max_len` below the entry's own prefix length leaves an empty window. Such
/// an entry is valid per RFC 5292 §4 and stays installed — rejecting it would
/// flush the list and fail open to permit-all — so callers only report it.
pub(crate) fn unmatchable_window(prefix: &Prefix, min_len: u8, max_len: u8) -> bool {
    let (lo, hi) = length_window(prefix, min_len, max_len);
    lo > hi
}

/// Whether `entry` matches `route` per RFC 5292 §6: containment plus the
/// min/max length window (0 = unspecified; both unspecified ⇒ exact length).
/// The linear first-match reference the index is tested against.
#[cfg(test)]
fn entry_matches(entry: &OrfFilterEntry, route: &Prefix) -> bool {
    if !prefix_contains(&entry.prefix, route) {
        return false;
    }
    let (lo, hi) = length_window(&entry.prefix, entry.min_len, entry.max_len);
    let route_len = route.prefix_len();
    route_len >= lo && route_len <= hi
}

/// Whether `outer` (at its own prefix length) network-contains `inner`.
/// Both prefixes are canonical (host bits already zeroed by construction).
#[cfg(test)]
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
    use proptest::prelude::*;
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
    fn unmatchable_max_below_prefix_len_is_installed_and_reported() {
        let mut f = OrfFilterSet::default();
        // 10/8 le 4: max 4 < prefix length 8, so no route can ever sit in the
        // window. Rejecting it would flush the list (fail-open flood), so it
        // stays installed and is only reported.
        let prefix = v4([10, 0, 0, 0], 8);
        f.apply(&[add(2, OrfMatch::Permit, 0, 4, prefix)]).unwrap();
        assert!(!f.is_empty(), "unmatchable entry is still installed");
        assert!(unmatchable_window(&prefix, 0, 4));
        assert!(
            !f.permits(&v4([10, 0, 0, 0], 8)),
            "never matches: implicit deny"
        );
        // min below the prefix length is clamped by the match, not impossible.
        assert!(!unmatchable_window(&prefix, 4, 0));
        assert!(!unmatchable_window(&prefix, 4, 8));
        assert!(!unmatchable_window(&prefix, 0, 0));
        // max equal to the prefix length still matches the exact prefix.
        assert!(!unmatchable_window(&prefix, 0, 8));
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

    /// The pre-index first-match scan: the reference the index must equal.
    fn linear_permits(set: &OrfFilterSet, prefix: &Prefix) -> bool {
        set.is_empty()
            || set
                .inner
                .entries
                .values()
                .find(|entry| entry_matches(entry, prefix))
                .is_some_and(|entry| entry.match_ == OrfMatch::Permit)
    }

    /// The pre-index staging: a full copy of the installed list, mutated in
    /// order, kept only if every ADD fits.
    fn reference_apply(
        installed: &BTreeMap<u32, OrfFilterEntry>,
        batch: &[AddressPrefixOrf],
    ) -> BTreeMap<u32, OrfFilterEntry> {
        let mut next = installed.clone();
        for entry in batch {
            match entry.action {
                OrfAction::RemoveAll => next.clear(),
                OrfAction::Remove => {
                    next.remove(&entry.sequence);
                }
                OrfAction::Add => {
                    if next.len() == MAX_ORF_ENTRIES && !next.contains_key(&entry.sequence) {
                        return installed.clone();
                    }
                    next.insert(
                        entry.sequence,
                        OrfFilterEntry {
                            match_: entry.match_,
                            min_len: entry.min_len,
                            max_len: entry.max_len,
                            prefix: entry.prefix.unwrap(),
                        },
                    );
                }
            }
        }
        next
    }

    /// A prefix near a few shared bases, so entries and routes nest often.
    fn arb_prefix() -> impl Strategy<Value = Prefix> {
        let v4 = (
            prop::sample::select(vec![
                0u32,
                0x0a00_0000,
                0x0a01_0000,
                0x0a01_0280,
                0xc0a8_0101,
            ]),
            0u8..=32,
        )
            .prop_map(|(addr, len)| Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(addr), len)));
        let v6 = (
            prop::sample::select(vec![
                0u128,
                0x2001_0db8 << 96,
                (0x2001_0db8 << 96) | (0x8000 << 64),
                (0x2001_0db8 << 96) | 1,
            ]),
            0u8..=128,
        )
            .prop_map(|(addr, len)| Prefix::V6(Ipv6Prefix::new(Ipv6Addr::from(addr), len)));
        prop_oneof![3 => v4, 2 => v6]
    }

    /// A well-formed wire entry: any action, a small sequence space so
    /// replacements and removals collide, and a valid length window
    /// (including unspecified, ge-only, le-only and unmatchable windows).
    fn arb_entry() -> impl Strategy<Value = AddressPrefixOrf> {
        (
            0u8..10,
            0u32..24,
            any::<bool>(),
            arb_prefix(),
            0u8..=128,
            0u8..=128,
        )
            .prop_map(|(kind, sequence, permit, prefix, a, b)| {
                let fam_max = family_max(&prefix);
                let (mut min_len, mut max_len) = (a.min(fam_max), b.min(fam_max));
                if min_len != 0 && max_len != 0 && min_len > max_len {
                    std::mem::swap(&mut min_len, &mut max_len);
                }
                match kind % 8 {
                    0 => min_len = 0,
                    1 => max_len = 0,
                    2 => (min_len, max_len) = (0, 0),
                    _ => {}
                }
                AddressPrefixOrf {
                    action: match kind {
                        0 => OrfAction::RemoveAll,
                        1 | 2 => OrfAction::Remove,
                        _ => OrfAction::Add,
                    },
                    match_: if permit {
                        OrfMatch::Permit
                    } else {
                        OrfMatch::Deny
                    },
                    sequence,
                    min_len,
                    max_len,
                    prefix: Some(prefix),
                }
            })
    }

    proptest::proptest! {
        /// Differential: after any sequence of well-formed batches, the
        /// installed list equals the copy-and-replay staging, and the index
        /// gives the linear first-match verdict for every probed route.
        #[test]
        fn index_matches_linear_first_match(
            batches in prop::collection::vec(prop::collection::vec(arb_entry(), 0..24), 1..6),
            routes in prop::collection::vec(arb_prefix(), 1..64),
        ) {
            let mut set = OrfFilterSet::default();
            for batch in &batches {
                let previous = set.inner.entries.clone();
                let expected = reference_apply(&previous, batch);
                let before = set.generation();
                set.apply(batch).unwrap();
                prop_assert_eq!(&set.inner.entries, &expected);
                prop_assert_eq!(set.generation() != before, expected != previous);
                for route in &routes {
                    prop_assert_eq!(set.permits(route), linear_permits(&set, route), "route {}", route);
                }
            }
        }
    }
}
