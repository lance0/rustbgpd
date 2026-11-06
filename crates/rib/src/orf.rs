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
use std::sync::{Arc, OnceLock};

use rustbgpd_wire::{AddressPrefixOrf, Ipv4Prefix, Ipv6Prefix, OrfAction, OrfMatch, Prefix};

use smallvec::SmallVec;

use crate::prefix_map::FamilyPrefixMap;

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
/// with prefix-list match semantics, plus a lookup index built on the first
/// lookup after a change.
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
    /// Built on first use, so a message that no lookup follows (a DEFER
    /// push, say) pays only its staging.
    index: OnceLock<OrfIndex>,
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
        // After REMOVE-ALL the result is exactly the staged ADDs, so it equals
        // the installed list when the count matches and no staged change
        // differs from what is installed at its sequence.
        let effective = (cleared && len != installed.len())
            || changes
                .iter()
                .any(|(sequence, change)| change.as_ref() != installed.get(sequence));
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
        state.index = OnceLock::new();
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
        self.is_empty()
            || self
                .inner
                .index
                .get_or_init(|| OrfIndex::build(&self.inner.entries))
                .first_match(prefix)
                == Some(OrfMatch::Permit)
    }
}

/// First-match verdicts precomputed per entry prefix, in a prefix trie. Only
/// entries whose prefix covers a route can match it, so a lookup walks the
/// trie path to the route and checks each covering key's verdict runs.
#[derive(Debug, Clone, Default)]
struct OrfIndex {
    keys: FamilyPrefixMap<Verdicts>,
}

/// Non-overlapping route-length runs in ascending order, each naming the
/// lowest-sequence entry at its prefix whose window holds those lengths.
/// An entry prefix usually has one run, which stays inline.
type Verdicts = SmallVec<[Run; 1]>;

#[derive(Debug, Clone, Copy)]
struct Run {
    first: u8,
    last: u8,
    sequence: u32,
    action: OrfMatch,
}

impl OrfIndex {
    fn build(entries: &BTreeMap<u32, OrfFilterEntry>) -> Self {
        // Iterating in sequence order keeps each key's windows sorted by
        // sequence, so the first window to claim a length is the first match.
        let mut windows: BTreeMap<Prefix, Vec<(u8, u8, u32, OrfMatch)>> = BTreeMap::new();
        for (&sequence, entry) in entries {
            let (lo, hi) = length_window(&entry.prefix, entry.min_len, entry.max_len);
            if lo <= hi {
                windows.entry(canonical(&entry.prefix)).or_default().push((
                    lo,
                    hi,
                    sequence,
                    entry.match_,
                ));
            }
        }
        let mut index = Self::default();
        for (prefix, windows) in windows {
            let mut painted: [Option<(u32, OrfMatch)>; 129] = [None; 129];
            for (lo, hi, sequence, action) in windows {
                for verdict in &mut painted[usize::from(lo)..=usize::from(hi)] {
                    verdict.get_or_insert((sequence, action));
                }
            }
            let runs = index.keys.entry_or_default(prefix);
            for (len, verdict) in (0u8..=128).zip(painted) {
                let Some((sequence, action)) = verdict else {
                    continue;
                };
                match runs.last_mut() {
                    Some(run) if run.last + 1 == len && run.sequence == sequence => run.last = len,
                    _ => runs.push(Run {
                        first: len,
                        last: len,
                        sequence,
                        action,
                    }),
                }
            }
        }
        index
    }

    /// The action of the lowest-sequence entry matching `route`, if any.
    fn first_match(&self, route: &Prefix) -> Option<OrfMatch> {
        let len = route.prefix_len();
        self.keys
            .cover(route)
            .filter_map(|runs| runs.iter().find(|run| run.first <= len && len <= run.last))
            .min_by_key(|run| run.sequence)
            .map(|run| run.action)
    }
}

/// `prefix` with its host bits zeroed, as the trie requires.
fn canonical(prefix: &Prefix) -> Prefix {
    match prefix {
        Prefix::V4(p) => Prefix::V4(Ipv4Prefix::new(p.addr, p.len)),
        Prefix::V6(p) => Prefix::V6(Ipv6Prefix::new(p.addr, p.len)),
    }
}

/// Build a filter from `entries` and hand it back type-erased, so memory
/// probes can measure what one installed filter retains. With `probe`, the
/// lazily built lookup index is forced by one lookup.
///
/// # Panics
///
/// Panics if `entries` is not an installable batch.
#[cfg(feature = "bench-internals")]
#[must_use]
pub fn bench_orf_filter(
    entries: &[AddressPrefixOrf],
    probe: Option<Prefix>,
) -> Box<dyn std::any::Any> {
    let mut set = OrfFilterSet::default();
    set.apply(entries).expect("benchmark ORF entries install");
    if let Some(prefix) = probe {
        let _ = set.permits(&prefix);
    }
    Box::new(set)
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

    fn remove_all() -> AddressPrefixOrf {
        AddressPrefixOrf {
            action: OrfAction::RemoveAll,
            match_: OrfMatch::Permit,
            sequence: 0,
            min_len: 0,
            max_len: 0,
            prefix: None,
        }
    }

    /// REMOVE-ALL followed by the identical installed list leaves the filter
    /// unchanged, so the generation (and any paged export walk) must not move.
    /// A different re-add, or a shorter one, does move it.
    #[test]
    fn remove_all_then_identical_readd_keeps_the_generation() {
        let entry = add(14, OrfMatch::Permit, 0, 0, v4([10, 0, 0, 0], 8));
        let mut f = OrfFilterSet::default();
        f.apply(&[entry]).unwrap();
        let installed = f.generation();
        f.apply(&[remove_all(), entry]).unwrap();
        assert_eq!(
            f.generation(),
            installed,
            "identical re-add is not a change"
        );

        let mut other = entry;
        other.match_ = OrfMatch::Deny;
        f.apply(&[remove_all(), other]).unwrap();
        assert_ne!(f.generation(), installed, "a different re-add is a change");
        let changed = f.generation();
        f.apply(&[remove_all()]).unwrap();
        assert_ne!(f.generation(), changed, "emptying the list is a change");
    }

    /// 4,096 IPv4 /32 and /31 keys whose `FxHash` agrees in the low 13 bits
    /// (bucket index) and top 7 bits (control byte): the worst case for a
    /// hash-table index keyed by entry prefix.
    fn fx_colliding_v4(n: usize) -> Vec<Prefix> {
        use std::hash::BuildHasher;
        let hash = |p: &Prefix| rustc_hash::FxBuildHasher.hash_one(p);
        let mask = |h: u64| (h & 0x1fff, h >> 57);
        let target = mask(hash(&v4([0, 0, 0, 0], 32)));
        let threads = 16u64;
        let mut out: Vec<Prefix> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..threads)
                .map(|t| {
                    s.spawn(move || {
                        let span = (1u64 << 32) / threads;
                        let mut hits = Vec::new();
                        for a in (t * span)..((t + 1) * span) {
                            let a = u32::try_from(a).expect("within the IPv4 space");
                            for len in [32, 31] {
                                let p = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(a), len));
                                if mask(hash(&p)) == target {
                                    hits.push(p);
                                }
                            }
                        }
                        hits
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().expect("search thread"))
                .collect()
        });
        out.sort_unstable();
        out.dedup();
        out.truncate(n);
        out
    }

    /// Per-message cost of a DEFER toggle (no lookup follows) and of the
    /// index rebuild the next lookup pays, for ordinary and hash-crafted keys.
    ///
    /// `cargo test -p rustbgpd-rib --release --lib -- --ignored --nocapture
    /// orf::tests::defer_and_rebuild_cost_probe`
    #[test]
    #[ignore = "manual timing receipt"]
    fn defer_and_rebuild_cost_probe() {
        let crafted = fx_colliding_v4(4096);
        assert_eq!(crafted.len(), 4096);
        let plain: Vec<Prefix> = (0..4096u32)
            .map(|i| {
                Prefix::V4(Ipv4Prefix::new(
                    Ipv4Addr::from(0xac10_0000u32.wrapping_add(i.wrapping_mul(7919))),
                    32,
                ))
            })
            .collect();
        let route = v4([10, 0, 0, 0], 24);
        for (name, keys) in [
            ("ordinary /32 keys", plain),
            ("crafted colliding keys", crafted),
        ] {
            let entries: Vec<_> = (0u32..)
                .zip(&keys)
                .map(|(seq, p)| add(seq, OrfMatch::Permit, 0, 0, *p))
                .collect();
            let mut set = OrfFilterSet::default();
            set.apply(&entries).unwrap();
            let _ = set.permits(&route);
            let rounds = 200u32;
            let mut toggle = entries[0];
            let (mut defer, mut rebuild) = (std::time::Duration::ZERO, std::time::Duration::ZERO);
            for round in 0..rounds {
                toggle.match_ = if round % 2 == 0 {
                    OrfMatch::Deny
                } else {
                    OrfMatch::Permit
                };
                let start = std::time::Instant::now();
                set.apply(std::slice::from_ref(&toggle)).unwrap();
                defer += start.elapsed();
                let start = std::time::Instant::now();
                std::hint::black_box(set.permits(&route));
                rebuild += start.elapsed();
            }
            // DEFER messages that no lookup follows: the index stays unbuilt.
            let start = std::time::Instant::now();
            for round in 0..rounds {
                toggle.match_ = if round % 2 == 0 {
                    OrfMatch::Deny
                } else {
                    OrfMatch::Permit
                };
                set.apply(std::slice::from_ref(&toggle)).unwrap();
            }
            let defer_only = start.elapsed() / rounds;
            println!(
                "{name:24} DEFER apply alone {defer_only:>8.2?}  apply after a lookup (drops the index) {:>8.2?}  first lookup after it (rebuild) {:>8.2?}",
                defer / rounds,
                rebuild / rounds
            );
        }
    }

    /// The cap counts the list after REMOVE-ALL, and a batch that would
    /// exceed it leaves the installed list untouched.
    #[test]
    fn capacity_counts_after_remove_all_and_rejects_cap_plus_one() {
        let cap = u32::try_from(MAX_ORF_ENTRIES).unwrap();
        let fill = |start: u32| -> Vec<AddressPrefixOrf> {
            (start..start + cap)
                .map(|seq| add(seq, OrfMatch::Permit, 0, 32, v4([10, 0, 0, 0], 8)))
                .collect()
        };
        let mut f = OrfFilterSet::default();
        f.apply(&fill(0)).unwrap();
        let mut replace = vec![remove_all()];
        replace.extend(fill(cap));
        f.apply(&replace).unwrap();
        assert_eq!(f.len(), MAX_ORF_ENTRIES);
        assert!(f.inner.entries.contains_key(&cap));
        let before = f.clone();
        let generation = f.generation();
        let mut over = vec![remove_all()];
        over.extend(fill(0));
        over.push(add(2 * cap, OrfMatch::Deny, 0, 32, v4([10, 0, 0, 0], 8)));
        assert_eq!(f.apply(&over), Err(OrfApplyError::Capacity));
        assert_eq!(f, before);
        assert_eq!(f.generation(), generation);
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
