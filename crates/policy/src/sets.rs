//! Indexed match-set layer for the compiled policy IR (ADR-0096).
//!
//! Match *data* compiles out of policy programs into shared indexed
//! structures: prefix sets with ge/le ranges, community hash sets, and
//! interned AS-path regexes. [`SetStore`] deduplicates them by content
//! across policies and chains — the `OpenBGPd` lesson that evaluation
//! speed lives in the set-index layer, not the expression interpreter —
//! so a thousand-entry customer list costs one hash probe per route
//! instead of a thousand-statement walk.

use std::sync::Arc;

use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix, Prefix};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::engine::{AsPathRegex, CommunityMatch, RouteContext};

/// Check a candidate prefix against an `(entry, ge, le)` triple using
/// the exact `PolicyStatement` prefix semantics: the candidate address
/// is masked at the entry's length and compared against the entry's
/// masked address, then the candidate's length must fall inside the
/// range derived from `ge`/`le`. This is the single scalar
/// implementation — the statement matcher delegates here and
/// [`PrefixSet`] is its indexed equivalent.
///
/// Range derivation (both address families):
/// - no `ge`, no `le` → exact-length match (`entry.len ..= entry.len`)
/// - `ge` only → `ge ..= address_bits`
/// - `le` only → `entry.len ..= le`
/// - both → `ge ..= le`
#[must_use]
#[inline]
pub fn prefix_entry_matches(
    entry: Prefix,
    ge: Option<u8>,
    le: Option<u8>,
    candidate: Prefix,
) -> bool {
    match (entry, candidate) {
        (Prefix::V4(entry), Prefix::V4(cand)) => matches_v4(entry, ge, le, cand),
        (Prefix::V6(entry), Prefix::V6(cand)) => matches_v6(entry, ge, le, cand),
        _ => false,
    }
}

#[inline]
fn matches_v4(entry: Ipv4Prefix, ge: Option<u8>, le: Option<u8>, candidate: Ipv4Prefix) -> bool {
    let mask = mask_v4(entry.len);
    if (u32::from(entry.addr) & mask) != (u32::from(candidate.addr) & mask) {
        return false;
    }
    let (min_len, max_len) = length_bounds(entry.len, ge, le, 32);
    candidate.len >= min_len && candidate.len <= max_len
}

#[inline]
fn matches_v6(entry: Ipv6Prefix, ge: Option<u8>, le: Option<u8>, candidate: Ipv6Prefix) -> bool {
    let mask = mask_v6(entry.len);
    if (u128::from(entry.addr) & mask) != (u128::from(candidate.addr) & mask) {
        return false;
    }
    let (min_len, max_len) = length_bounds(entry.len, ge, le, 128);
    candidate.len >= min_len && candidate.len <= max_len
}

#[inline]
fn length_bounds(entry_len: u8, ge: Option<u8>, le: Option<u8>, max_bits: u8) -> (u8, u8) {
    match (ge, le) {
        (None, None) => (entry_len, entry_len),
        (Some(ge), None) => (ge, max_bits),
        (None, Some(le)) => (entry_len, le),
        (Some(ge), Some(le)) => (ge, le),
    }
}

#[inline]
fn mask_v4(len: u8) -> u32 {
    if len == 0 {
        0
    } else if len >= 32 {
        u32::MAX
    } else {
        !((1u32 << (32 - len)) - 1)
    }
}

#[inline]
fn mask_v6(len: u8) -> u128 {
    if len == 0 {
        0
    } else if len >= 128 {
        u128::MAX
    } else {
        !((1u128 << (128 - len)) - 1)
    }
}

/// One member of a [`PrefixSet`]: a prefix plus the optional ge/le
/// length bounds, with the same semantics as a `PolicyStatement`'s
/// `prefix`/`ge`/`le` fields (see [`prefix_entry_matches`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixSetEntry {
    /// The covering prefix; candidates are masked at its length.
    pub prefix: Prefix,
    /// Minimum candidate prefix length (inclusive).
    pub ge: Option<u8>,
    /// Maximum candidate prefix length (inclusive).
    pub le: Option<u8>,
}

impl PrefixSetEntry {
    /// Canonical ordering/interning key.
    fn key(&self) -> PrefixEntryKey {
        match self.prefix {
            Prefix::V4(p) => (4, u128::from(u32::from(p.addr)), p.len, self.ge, self.le),
            Prefix::V6(p) => (6, u128::from(p.addr), p.len, self.ge, self.le),
        }
    }
}

type PrefixEntryKey = (u8, u128, u8, Option<u8>, Option<u8>);

/// Canonical ordering/interning key for a community criterion.
type CommunityKey = (u8, u32, u32, u32);

/// An indexed prefix set: membership is one hash probe per *distinct
/// member prefix length* instead of a scan over every member.
///
/// The index groups members by (address family, member length); a
/// lookup masks the candidate address at each member length, probes a
/// hash map, and checks the stored ge/le length ranges. Real-world sets
/// use a handful of distinct member lengths, so lookups are effectively
/// O(1) regardless of set size.
///
/// This deliberately is *not* a containment trie: the statement matcher
/// it replaces uses pure mask-plus-range semantics, where a member
/// *longer* than the candidate can still match when `ge` reaches below
/// the member length. The per-length mask groups reproduce that
/// exactly; a trie ancestor-walk would not.
#[derive(Debug, Clone)]
pub struct PrefixSet {
    /// Canonically sorted, deduplicated members — the set's identity.
    entries: Vec<PrefixSetEntry>,
    v4: Vec<LenGroup<u32>>,
    v6: Vec<LenGroup<u128>>,
}

#[derive(Debug, Clone)]
struct LenGroup<B> {
    member_len: u8,
    /// Masked member address → inclusive candidate-length ranges.
    buckets: FxHashMap<B, Vec<(u8, u8)>>,
}

impl PrefixSet {
    /// Build an indexed set from members. Members are canonicalized
    /// (sorted, deduplicated), so construction order does not affect
    /// identity or behavior.
    #[must_use]
    pub fn new(entries: impl IntoIterator<Item = PrefixSetEntry>) -> Self {
        let mut entries: Vec<PrefixSetEntry> = entries.into_iter().collect();
        entries.sort_unstable_by_key(PrefixSetEntry::key);
        entries.dedup();

        let mut v4: Vec<LenGroup<u32>> = Vec::new();
        let mut v6: Vec<LenGroup<u128>> = Vec::new();
        for entry in &entries {
            match entry.prefix {
                Prefix::V4(p) => {
                    let bounds = length_bounds(p.len, entry.ge, entry.le, 32);
                    let masked = u32::from(p.addr) & mask_v4(p.len);
                    push_group(&mut v4, p.len, masked, bounds);
                }
                Prefix::V6(p) => {
                    let bounds = length_bounds(p.len, entry.ge, entry.le, 128);
                    let masked = u128::from(p.addr) & mask_v6(p.len);
                    push_group(&mut v6, p.len, masked, bounds);
                }
            }
        }
        Self { entries, v4, v6 }
    }

    /// Whether any member matches the candidate — equivalent to
    /// [`prefix_entry_matches`] over every member, evaluated in
    /// O(distinct member lengths).
    #[must_use]
    #[inline]
    pub fn matches(&self, candidate: Prefix) -> bool {
        match candidate {
            Prefix::V4(c) => {
                let bits = u32::from(c.addr);
                self.v4.iter().any(|group| {
                    group
                        .buckets
                        .get(&(bits & mask_v4(group.member_len)))
                        .is_some_and(|ranges| {
                            ranges.iter().any(|&(lo, hi)| c.len >= lo && c.len <= hi)
                        })
                })
            }
            Prefix::V6(c) => {
                let bits = u128::from(c.addr);
                self.v6.iter().any(|group| {
                    group
                        .buckets
                        .get(&(bits & mask_v6(group.member_len)))
                        .is_some_and(|ranges| {
                            ranges.iter().any(|&(lo, hi)| c.len >= lo && c.len <= hi)
                        })
                })
            }
        }
    }

    /// The canonical (sorted, deduplicated) member list.
    #[must_use]
    pub fn entries(&self) -> &[PrefixSetEntry] {
        &self.entries
    }
}

impl PartialEq for PrefixSet {
    fn eq(&self, other: &Self) -> bool {
        // The index is derived deterministically from the canonical
        // member list, so members alone are the identity.
        self.entries == other.entries
    }
}

impl Eq for PrefixSet {}

fn push_group<B: std::hash::Hash + Eq>(
    groups: &mut Vec<LenGroup<B>>,
    member_len: u8,
    key: B,
    bounds: (u8, u8),
) {
    let group = if let Some(pos) = groups.iter().position(|g| g.member_len == member_len) {
        &mut groups[pos]
    } else {
        groups.push(LenGroup {
            member_len,
            buckets: FxHashMap::default(),
        });
        groups.last_mut().expect("just pushed")
    };
    group.buckets.entry(key).or_default().push(bounds);
}

/// An indexed community criteria set with the OR-any semantics of a
/// `PolicyStatement`'s `match_community` list: the set matches when any
/// route community satisfies any member criterion. Standard, RT, RO,
/// and large criteria are partitioned into hash sets so each route
/// community is one probe against its own kind.
#[derive(Debug, Clone, Default)]
pub struct CommunitySet {
    /// Canonically sorted, deduplicated criteria — the set's identity.
    criteria: Vec<CommunityMatch>,
    standard: FxHashSet<u32>,
    route_targets: FxHashSet<(u32, u32)>,
    route_origins: FxHashSet<(u32, u32)>,
    large: FxHashSet<(u32, u32, u32)>,
    exact_ext: FxHashSet<u64>,
}

impl CommunitySet {
    /// Build an indexed set from criteria. Criteria are canonicalized
    /// (sorted, deduplicated), so construction order does not affect
    /// identity or behavior.
    #[must_use]
    pub fn new(criteria: impl IntoIterator<Item = CommunityMatch>) -> Self {
        let mut criteria: Vec<CommunityMatch> = criteria.into_iter().collect();
        criteria.sort_unstable_by_key(|cm| community_key(*cm));
        criteria.dedup();

        let mut set = Self {
            criteria,
            ..Self::default()
        };
        for cm in &set.criteria {
            match *cm {
                CommunityMatch::Standard { value } => {
                    set.standard.insert(value);
                }
                CommunityMatch::RouteTarget { global, local } => {
                    set.route_targets.insert((global, local));
                }
                CommunityMatch::RouteOrigin { global, local } => {
                    set.route_origins.insert((global, local));
                }
                CommunityMatch::LargeCommunity {
                    global_admin,
                    local_data1,
                    local_data2,
                } => {
                    set.large.insert((global_admin, local_data1, local_data2));
                }
                CommunityMatch::ExactExt(raw) => {
                    set.exact_ext.insert(raw);
                }
            }
        }
        set
    }

    /// Whether any route community matches any member criterion —
    /// equivalent to `CommunityMatch::matches_route_communities` OR'd
    /// over every member.
    #[must_use]
    #[inline]
    pub fn matches(&self, ctx: &RouteContext<'_>) -> bool {
        if !self.standard.is_empty() && ctx.communities.iter().any(|c| self.standard.contains(c)) {
            return true;
        }
        if (!self.route_targets.is_empty()
            || !self.route_origins.is_empty()
            || !self.exact_ext.is_empty())
            && ctx.extended_communities.iter().any(|ec| {
                ec.route_target()
                    .is_some_and(|key| self.route_targets.contains(&key))
                    || ec
                        .route_origin()
                        .is_some_and(|key| self.route_origins.contains(&key))
                    || self.exact_ext.contains(&ec.as_u64())
            })
        {
            return true;
        }
        !self.large.is_empty()
            && ctx.large_communities.iter().any(|lc| {
                self.large
                    .contains(&(lc.global_admin, lc.local_data1, lc.local_data2))
            })
    }

    /// The canonical (sorted, deduplicated) criteria list.
    #[must_use]
    pub fn criteria(&self) -> &[CommunityMatch] {
        &self.criteria
    }
}

impl PartialEq for CommunitySet {
    fn eq(&self, other: &Self) -> bool {
        self.criteria == other.criteria
    }
}

impl Eq for CommunitySet {}

/// Canonical ordering/interning key for a community criterion.
fn community_key(cm: CommunityMatch) -> CommunityKey {
    match cm {
        CommunityMatch::Standard { value } => (0, value, 0, 0),
        CommunityMatch::RouteTarget { global, local } => (1, global, local, 0),
        CommunityMatch::RouteOrigin { global, local } => (2, global, local, 0),
        CommunityMatch::LargeCommunity {
            global_admin,
            local_data1,
            local_data2,
        } => (3, global_admin, local_data1, local_data2),
        #[expect(
            clippy::cast_possible_truncation,
            reason = "deliberate split of the raw u64 into two key halves"
        )]
        CommunityMatch::ExactExt(raw) => (4, (raw >> 32) as u32, raw as u32, 0),
    }
}

/// Content-hash interner for match sets and AS-path regexes.
///
/// Two policies — or two chains compiled through the same store —
/// referencing identical set data share one `Arc`'d indexed structure.
/// Keys are canonicalized (sorted, deduplicated) member lists, so any
/// ordering of the same data interns to the same set.
#[derive(Debug, Default)]
pub struct SetStore {
    prefix_sets: FxHashMap<Vec<PrefixEntryKey>, Arc<PrefixSet>>,
    community_sets: FxHashMap<Vec<CommunityKey>, Arc<CommunitySet>>,
    as_path_regexes: FxHashMap<String, Arc<AsPathRegex>>,
}

impl SetStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern a prefix set built from `entries`.
    #[must_use]
    pub fn prefix_set(&mut self, entries: &[PrefixSetEntry]) -> Arc<PrefixSet> {
        let mut key: Vec<PrefixEntryKey> = entries.iter().map(PrefixSetEntry::key).collect();
        key.sort_unstable();
        key.dedup();
        Arc::clone(
            self.prefix_sets
                .entry(key)
                .or_insert_with(|| Arc::new(PrefixSet::new(entries.iter().copied()))),
        )
    }

    /// Intern a community set built from `criteria`.
    #[must_use]
    pub fn community_set(&mut self, criteria: &[CommunityMatch]) -> Arc<CommunitySet> {
        let mut key: Vec<CommunityKey> = criteria.iter().map(|cm| community_key(*cm)).collect();
        key.sort_unstable();
        key.dedup();
        Arc::clone(
            self.community_sets
                .entry(key)
                .or_insert_with(|| Arc::new(CommunitySet::new(criteria.iter().copied()))),
        )
    }

    /// Intern a compiled AS-path regex by its configured pattern.
    #[must_use]
    pub fn as_path_regex(&mut self, regex: &AsPathRegex) -> Arc<AsPathRegex> {
        Arc::clone(
            self.as_path_regexes
                .entry(regex.pattern().to_string())
                .or_insert_with(|| Arc::new(regex.clone())),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn v4(addr: [u8; 4], len: u8) -> Prefix {
        Prefix::V4(Ipv4Prefix::new(
            Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]),
            len,
        ))
    }

    fn v6(len: u8) -> Prefix {
        Prefix::V6(Ipv6Prefix::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            len,
        ))
    }

    fn entry(prefix: Prefix, ge: Option<u8>, le: Option<u8>) -> PrefixSetEntry {
        PrefixSetEntry { prefix, ge, le }
    }

    /// The indexed set must agree with the scalar matcher on every
    /// (member, candidate-length) combination, including the odd
    /// mask-only corners (entry longer than candidate, len-0 entries).
    #[test]
    fn prefix_set_agrees_with_scalar_matcher() {
        let members = [
            entry(v4([10, 0, 0, 0], 8), None, None),
            entry(v4([10, 10, 0, 0], 16), Some(24), Some(28)),
            entry(v4([192, 0, 2, 0], 24), Some(8), None),
            entry(v4([0, 0, 0, 0], 0), None, None),
            entry(v4([172, 16, 0, 0], 12), None, Some(20)),
            entry(v6(32), Some(48), Some(64)),
            entry(v6(64), None, None),
        ];
        let set = PrefixSet::new(members.iter().copied());

        let mut candidates = Vec::new();
        for len in 0..=32u8 {
            candidates.push(v4([10, 10, 3, 0], len));
            candidates.push(v4([192, 0, 2, 128], len));
            candidates.push(v4([172, 16, 5, 0], len));
            candidates.push(v4([8, 8, 8, 8], len));
        }
        for len in 0..=128u8 {
            candidates.push(v6(len));
        }

        for cand in candidates {
            let scalar = members
                .iter()
                .any(|m| prefix_entry_matches(m.prefix, m.ge, m.le, cand));
            assert_eq!(
                set.matches(cand),
                scalar,
                "prefix set diverges from scalar matcher on {cand:?}"
            );
        }
    }

    #[test]
    fn community_set_agrees_with_criteria_scan() {
        let criteria = [
            CommunityMatch::Standard {
                value: (65001 << 16) | 0x64,
            },
            CommunityMatch::RouteTarget {
                global: 65001,
                local: 7,
            },
            CommunityMatch::RouteOrigin {
                global: 65002,
                local: 9,
            },
            CommunityMatch::LargeCommunity {
                global_admin: 65001,
                local_data1: 1,
                local_data2: 2,
            },
        ];
        let set = CommunitySet::new(criteria.iter().copied());

        // Route carrying only the large community.
        let large = [rustbgpd_wire::LargeCommunity {
            global_admin: 65001,
            local_data1: 1,
            local_data2: 2,
        }];
        let ctx = RouteContext {
            prefix: None,
            next_hop: None,
            extended_communities: &[],
            communities: &[(65500 << 16) | 0x01],
            large_communities: &large,
            as_path_str: "",
            as_path_len: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            peer_address: None,
            peer_asn: None,
            peer_group: None,
            route_type: None,
            evpn_route_type: None,
            local_pref: None,
            med: None,
        };
        assert!(set.matches(&ctx));

        let empty_ctx = RouteContext {
            large_communities: &[],
            ..ctx
        };
        assert!(!set.matches(&empty_ctx));
    }

    #[test]
    fn store_dedupes_by_content_regardless_of_order() {
        let mut store = SetStore::new();
        let a = [
            entry(v4([10, 0, 0, 0], 8), None, None),
            entry(v4([192, 0, 2, 0], 24), Some(24), Some(32)),
        ];
        let b = [a[1], a[0], a[0]]; // reordered + duplicated
        let first = store.prefix_set(&a);
        let second = store.prefix_set(&b);
        assert!(Arc::ptr_eq(&first, &second));

        let cm = [CommunityMatch::Standard { value: 1 }];
        assert!(Arc::ptr_eq(
            &store.community_set(&cm),
            &store.community_set(&cm)
        ));

        let re = AsPathRegex::new("_65001_").unwrap();
        assert!(Arc::ptr_eq(
            &store.as_path_regex(&re),
            &store.as_path_regex(&AsPathRegex::new("_65001_").unwrap())
        ));
    }
}
