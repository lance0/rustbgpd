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

use rustbgpd_wire::{ExtendedCommunity, Ipv4Prefix, Ipv6Prefix, LargeCommunity, Prefix};
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

/// Reject a `(prefix_len, ge, le)` triple whose derived range (see
/// [`prefix_entry_matches`]) can never contain a candidate length:
/// every present bound must satisfy `prefix_len <= ge <= le <= max_bits`.
/// Both policy frontends call this at load so a dead entry is a load
/// error instead of a silent no-match. The `Err` carries the reason
/// without location; callers add the prefix or source span.
///
/// # Errors
///
/// Returns the human-readable rule that the bounds violate.
pub fn check_length_bounds(
    prefix_len: u8,
    max_bits: u8,
    ge: Option<u8>,
    le: Option<u8>,
) -> Result<(), String> {
    if let Some(ge) = ge {
        if ge > max_bits {
            return Err(format!("ge value {ge} exceeds {max_bits}"));
        }
        if ge < prefix_len {
            return Err(format!(
                "ge value {ge} is less than prefix length {prefix_len}"
            ));
        }
    }
    if let Some(le) = le {
        if le > max_bits {
            return Err(format!("le value {le} exceeds {max_bits}"));
        }
        if le < prefix_len {
            return Err(format!(
                "le value {le} is less than prefix length {prefix_len}"
            ));
        }
    }
    if let (Some(ge), Some(le)) = (ge, le)
        && ge > le
    {
        return Err(format!("ge value {ge} exceeds le value {le}"));
    }
    Ok(())
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
    /// An exact-length entry: no `ge`, no `le`.
    #[must_use]
    pub const fn exact(prefix: Prefix) -> Self {
        Self {
            prefix,
            ge: None,
            le: None,
        }
    }

    /// Whether `candidate` matches this entry ([`prefix_entry_matches`]).
    #[must_use]
    #[inline]
    pub fn matches(&self, candidate: Prefix) -> bool {
        prefix_entry_matches(self.prefix, self.ge, self.le, candidate)
    }

    /// Canonical ordering/interning key.
    fn key(&self) -> PrefixEntryKey {
        match self.prefix {
            Prefix::V4(p) => (4, u128::from(u32::from(p.addr)), p.len, self.ge, self.le),
            Prefix::V6(p) => (6, u128::from(p.addr), p.len, self.ge, self.le),
        }
    }
}

impl std::fmt::Display for PrefixSetEntry {
    /// Prefix-list form: `10.0.0.0/8`, `10.0.0.0/8 le 24`, `10.0.0.0/8 ge 16 le 24`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.prefix)?;
        if let Some(ge) = self.ge {
            write!(f, " ge {ge}")?;
        }
        if let Some(le) = self.le {
            write!(f, " le {le}")?;
        }
        Ok(())
    }
}

type PrefixEntryKey = (u8, u128, u8, Option<u8>, Option<u8>);

/// Canonical ordering/interning key for a community criterion.
type CommunityKey = (u8, u32, u32, u32);

/// Most range comparisons one route community value may cost against a
/// community set's patterns: the largest bucket of each kind the value
/// probes, plus the patterns with no fixed field to bucket by. Source
/// sets and dataset snapshots over the bound are load errors, so an
/// `in` probe does at most this many comparisons per route community
/// on top of the exact-member hash probe.
pub const MAX_COMMUNITY_PATTERN_SCAN: usize = 64;

/// One field of a [`CommunityPattern`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CommunityField {
    /// Inclusive value range. An exact value has `lo == hi`; `*` is the
    /// field's full range (`0..=65535` for a standard-community half,
    /// `0..=u32::MAX` otherwise).
    Range {
        /// Lowest matching value.
        lo: u32,
        /// Highest matching value.
        hi: u32,
    },
    /// A private-use ASN (RFC 6996): 64512..=65534 or
    /// 4200000000..=4294967294. A 16-bit field can only hit the first
    /// range.
    PrivateAs,
}

impl CommunityField {
    /// An exact-value field.
    #[must_use]
    pub const fn exact(value: u32) -> Self {
        Self::Range {
            lo: value,
            hi: value,
        }
    }

    /// Whether `value` falls in this field.
    #[must_use]
    #[inline]
    pub fn matches(self, value: u32) -> bool {
        match self {
            Self::Range { lo, hi } => lo <= value && value <= hi,
            Self::PrivateAs => rustbgpd_wire::is_private_asn(value),
        }
    }

    /// The value when the field matches exactly one value.
    #[must_use]
    pub const fn fixed(self) -> Option<u32> {
        match self {
            Self::Range { lo, hi } if lo == hi => Some(lo),
            _ => None,
        }
    }

    /// The smallest value the field matches.
    #[must_use]
    pub const fn min(self) -> u32 {
        match self {
            Self::Range { lo, .. } => lo,
            Self::PrivateAs => 64_512,
        }
    }
}

/// A community-set member that matches a range of values (`.rpol`
/// `65000:*`, `*:666`, `65000:1..9:*`, `RT:65000:*`). Patterns are kept
/// apart from the exact [`CommunityMatch`] members so the exact members,
/// and every IR node that carries one, keep their size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CommunityPattern {
    /// A standard community whose halves fall in the fields.
    Standard {
        /// High 16 bits (the ASN half).
        asn: CommunityField,
        /// Low 16 bits.
        value: CommunityField,
    },
    /// A large community whose three parts fall in the fields.
    Large {
        /// Global administrator.
        global_admin: CommunityField,
        /// First local data part.
        local_data1: CommunityField,
        /// Second local data part.
        local_data2: CommunityField,
    },
    /// A Route Target whose decoded `(global, local)` falls in the fields
    /// (encoding-agnostic, like [`CommunityMatch::RouteTarget`]).
    RouteTarget {
        /// Global administrator (ASN, or an IPv4 address as u32).
        global: CommunityField,
        /// Local administrator.
        local: CommunityField,
    },
    /// A Route Origin whose decoded `(global, local)` falls in the fields.
    RouteOrigin {
        /// Global administrator (ASN, or an IPv4 address as u32).
        global: CommunityField,
        /// Local administrator.
        local: CommunityField,
    },
}

impl CommunityPattern {
    /// Whether a standard community matches.
    #[must_use]
    pub fn matches_standard(&self, community: u32) -> bool {
        match self {
            Self::Standard { asn, value } => {
                asn.matches(community >> 16) && value.matches(community & 0xFFFF)
            }
            _ => false,
        }
    }

    /// Whether a large community matches.
    #[must_use]
    pub fn matches_large(&self, lc: &LargeCommunity) -> bool {
        match self {
            Self::Large {
                global_admin,
                local_data1,
                local_data2,
            } => {
                global_admin.matches(lc.global_admin)
                    && local_data1.matches(lc.local_data1)
                    && local_data2.matches(lc.local_data2)
            }
            _ => false,
        }
    }

    /// Whether an extended community matches.
    #[must_use]
    pub fn matches_ec(&self, ec: &ExtendedCommunity) -> bool {
        match self {
            Self::RouteTarget { global, local } => ec
                .route_target()
                .is_some_and(|(g, l)| global.matches(g) && local.matches(l)),
            Self::RouteOrigin { global, local } => ec
                .route_origin()
                .is_some_and(|(g, l)| global.matches(g) && local.matches(l)),
            _ => false,
        }
    }
}

/// One `.rpol` community-set or dataset member: an exact criterion or a
/// pattern. The pattern is boxed so a member is no larger than an exact
/// criterion: million-record dataset files and retained set ASTs keep
/// their footprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommunityMember {
    /// An exact community value.
    Exact(CommunityMatch),
    /// A range pattern.
    Pattern(Box<CommunityPattern>),
}

/// Split members into exact criteria and patterns.
#[must_use]
pub fn split_community_members<'a>(
    members: impl IntoIterator<Item = &'a CommunityMember>,
) -> (Vec<CommunityMatch>, Vec<CommunityPattern>) {
    let mut exact = Vec::new();
    let mut patterns = Vec::new();
    for member in members {
        match member {
            CommunityMember::Exact(cm) => exact.push(*cm),
            CommunityMember::Pattern(pattern) => patterns.push(**pattern),
        }
    }
    (exact, patterns)
}

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
    /// Pattern members; `None` for a set without patterns, which then
    /// probes its exact members only.
    patterns: Option<Box<CommunityPatterns>>,
}

/// A community set's pattern members, indexed per kind.
#[derive(Debug, Clone, Default)]
struct CommunityPatterns {
    /// Canonically sorted, deduplicated patterns — part of the set's
    /// identity.
    members: Vec<CommunityPattern>,
    /// Standard patterns with a fixed ASN half, keyed by it; the
    /// unkeyed list holds the standard patterns with neither half fixed.
    standard_by_asn: PatternIndex<2>,
    /// Standard patterns with only the low half fixed, keyed by it.
    standard_by_value: PatternIndex<2>,
    /// Keyed by the global administrator.
    large: PatternIndex<3>,
    /// Keyed by the global administrator.
    route_targets: PatternIndex<2>,
    /// Keyed by the global administrator.
    route_origins: PatternIndex<2>,
}

impl CommunityPatterns {
    fn new(patterns: impl IntoIterator<Item = CommunityPattern>) -> Option<Box<Self>> {
        let mut members: Vec<CommunityPattern> = patterns.into_iter().collect();
        if members.is_empty() {
            return None;
        }
        members.sort_unstable();
        members.dedup();
        let mut index = Self::default();
        for pattern in &members {
            match *pattern {
                CommunityPattern::Standard { asn, value } => {
                    if asn.fixed().is_some() {
                        index.standard_by_asn.insert(asn.fixed(), [asn, value]);
                    } else if value.fixed().is_some() {
                        index.standard_by_value.insert(value.fixed(), [asn, value]);
                    } else {
                        index.standard_by_asn.insert(None, [asn, value]);
                    }
                }
                CommunityPattern::Large {
                    global_admin,
                    local_data1,
                    local_data2,
                } => index.large.insert(
                    global_admin.fixed(),
                    [global_admin, local_data1, local_data2],
                ),
                CommunityPattern::RouteTarget { global, local } => {
                    index.route_targets.insert(global.fixed(), [global, local]);
                }
                CommunityPattern::RouteOrigin { global, local } => {
                    index.route_origins.insert(global.fixed(), [global, local]);
                }
            }
        }
        index.members = members;
        Some(Box::new(index))
    }

    fn has_standard(&self) -> bool {
        !self.standard_by_asn.is_empty() || !self.standard_by_value.is_empty()
    }

    #[inline]
    fn matches_standard(&self, value: u32) -> bool {
        let (asn, low) = (value >> 16, value & 0xFFFF);
        self.standard_by_asn.matches(asn, [asn, low])
            || self.standard_by_value.matches(low, [asn, low])
    }

    /// Out of line, so the exact-only probe loops compile as they did
    /// before patterns existed.
    #[inline(never)]
    fn matches(&self, ctx: &RouteContext<'_>) -> bool {
        (self.has_standard() && ctx.communities.iter().any(|&c| self.matches_standard(c)))
            || ((!self.route_targets.is_empty() || !self.route_origins.is_empty())
                && ctx.extended_communities.iter().any(|ec| {
                    ec.route_target().is_some_and(|(global, local)| {
                        self.route_targets.matches(global, [global, local])
                    }) || ec.route_origin().is_some_and(|(global, local)| {
                        self.route_origins.matches(global, [global, local])
                    })
                }))
            || (!self.large.is_empty()
                && ctx.large_communities.iter().any(|lc| {
                    self.large.matches(
                        lc.global_admin,
                        [lc.global_admin, lc.local_data1, lc.local_data2],
                    )
                }))
    }

    /// A standard value probes one ASN bucket and one value bucket; the
    /// other kinds probe one bucket each.
    fn scan_bound(&self) -> usize {
        (self.standard_by_asn.scan_bound() + self.standard_by_value.scan_bound())
            .max(self.large.scan_bound())
            .max(self.route_targets.scan_bound())
            .max(self.route_origins.scan_bound())
    }
}

/// The range patterns of one community kind. A pattern with a fixed
/// field lives in that field's bucket; the rest are scanned for every
/// value.
#[derive(Debug, Clone, Default)]
struct PatternIndex<const N: usize> {
    keyed: FxHashMap<u32, Vec<[CommunityField; N]>>,
    unkeyed: Vec<[CommunityField; N]>,
    largest_bucket: usize,
}

impl<const N: usize> PatternIndex<N> {
    fn insert(&mut self, key: Option<u32>, fields: [CommunityField; N]) {
        if let Some(key) = key {
            let bucket = self.keyed.entry(key).or_default();
            bucket.push(fields);
            self.largest_bucket = self.largest_bucket.max(bucket.len());
        } else {
            self.unkeyed.push(fields);
        }
    }

    fn is_empty(&self) -> bool {
        self.keyed.is_empty() && self.unkeyed.is_empty()
    }

    /// Whether a pattern in `key`'s bucket, or an unkeyed pattern,
    /// matches every field of `values`.
    #[inline]
    fn matches(&self, key: u32, values: [u32; N]) -> bool {
        let hit = |fields: &[CommunityField; N]| {
            fields
                .iter()
                .zip(values)
                .all(|(field, value)| field.matches(value))
        };
        self.keyed
            .get(&key)
            .is_some_and(|bucket| bucket.iter().any(hit))
            || self.unkeyed.iter().any(hit)
    }

    /// Most comparisons one value costs: its bucket plus the unkeyed list.
    fn scan_bound(&self) -> usize {
        self.largest_bucket + self.unkeyed.len()
    }
}

impl CommunitySet {
    /// Build an indexed set from criteria. Criteria are canonicalized
    /// (sorted, deduplicated), so construction order does not affect
    /// identity or behavior.
    #[must_use]
    pub fn new(criteria: impl IntoIterator<Item = CommunityMatch>) -> Self {
        Self::with_patterns(criteria, [])
    }

    /// Build an indexed set from exact criteria and patterns, both
    /// canonicalized.
    #[must_use]
    pub fn with_patterns(
        criteria: impl IntoIterator<Item = CommunityMatch>,
        patterns: impl IntoIterator<Item = CommunityPattern>,
    ) -> Self {
        let mut criteria: Vec<CommunityMatch> = criteria.into_iter().collect();
        criteria.sort_unstable_by_key(|cm| community_key(*cm));
        criteria.dedup();

        let mut set = Self {
            criteria,
            patterns: CommunityPatterns::new(patterns),
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
        (!self.large.is_empty()
            && ctx.large_communities.iter().any(|lc| {
                self.large
                    .contains(&(lc.global_admin, lc.local_data1, lc.local_data2))
            }))
            || self
                .patterns
                .as_deref()
                .is_some_and(|patterns| patterns.matches(ctx))
    }

    /// Whether `value` is a **standard** (RFC 1997) member of this set
    /// — one hash probe against the standard partition, then the
    /// standard patterns if the set has any. Backs the LAN-303
    /// `<binding> in <community-set>` form, where the binding carries a
    /// standard community's raw `u32`; large/extended members are not
    /// `u32`-comparable and never match here.
    #[must_use]
    #[inline]
    pub fn contains_standard(&self, value: u32) -> bool {
        self.standard.contains(&value)
            || self
                .patterns
                .as_deref()
                .is_some_and(|patterns| patterns.has_standard() && patterns.matches_standard(value))
    }

    /// Whether `value` is an **exact** standard member; patterns are not
    /// consulted. A well-known community counts as named by a set only
    /// through an exact member.
    #[must_use]
    #[inline]
    pub fn contains_standard_exact(&self, value: u32) -> bool {
        self.standard.contains(&value)
    }

    /// Whether a large community is a member, exact or by pattern.
    #[must_use]
    #[inline]
    pub fn contains_large(&self, lc: &LargeCommunity) -> bool {
        self.large
            .contains(&(lc.global_admin, lc.local_data1, lc.local_data2))
            || self.patterns.as_deref().is_some_and(|patterns| {
                !patterns.large.is_empty()
                    && patterns.large.matches(
                        lc.global_admin,
                        [lc.global_admin, lc.local_data1, lc.local_data2],
                    )
            })
    }

    /// Whether an extended community is a member: an RT/RO member by its
    /// decoded `(global, local)`, a raw member by its wire value, or an
    /// RT/RO pattern.
    #[must_use]
    #[inline]
    pub fn contains_ext(&self, ec: &ExtendedCommunity) -> bool {
        let target = ec.route_target();
        let origin = ec.route_origin();
        target.is_some_and(|key| self.route_targets.contains(&key))
            || origin.is_some_and(|key| self.route_origins.contains(&key))
            || self.exact_ext.contains(&ec.as_u64())
            || self.patterns.as_deref().is_some_and(|patterns| {
                target.is_some_and(|(global, local)| {
                    patterns.route_targets.matches(global, [global, local])
                }) || origin.is_some_and(|(global, local)| {
                    patterns.route_origins.matches(global, [global, local])
                })
            })
    }

    /// The canonical (sorted, deduplicated) criteria list.
    #[must_use]
    pub fn criteria(&self) -> &[CommunityMatch] {
        &self.criteria
    }

    /// The canonical (sorted, deduplicated) pattern members.
    #[must_use]
    pub fn patterns(&self) -> &[CommunityPattern] {
        self.patterns
            .as_deref()
            .map_or(&[], |patterns| patterns.members.as_slice())
    }

    /// Most range comparisons one route community value can cost
    /// against this set's patterns (0 for a set without patterns); see
    /// [`MAX_COMMUNITY_PATTERN_SCAN`].
    #[must_use]
    pub fn pattern_scan_bound(&self) -> usize {
        self.patterns
            .as_deref()
            .map_or(0, CommunityPatterns::scan_bound)
    }

    /// The load-time [`MAX_COMMUNITY_PATTERN_SCAN`] check.
    ///
    /// # Errors
    ///
    /// The reason, without location, when a route community could be
    /// compared against more patterns than the bound.
    pub fn check_pattern_scan(&self) -> Result<(), String> {
        let bound = self.pattern_scan_bound();
        if bound > MAX_COMMUNITY_PATTERN_SCAN {
            return Err(format!(
                "a route community can be compared against {bound} patterns in this set, \
                 more than the limit of {MAX_COMMUNITY_PATTERN_SCAN}"
            ));
        }
        Ok(())
    }
}

impl PartialEq for CommunitySet {
    fn eq(&self, other: &Self) -> bool {
        self.criteria == other.criteria && self.patterns() == other.patterns()
    }
}

impl Eq for CommunitySet {}

/// An indexed ASN set (`asn-set` in `.rpol`): membership is one hash
/// probe regardless of member count. Probed by `route.origin-as in`
/// and `peer.asn in` guards.
#[derive(Debug, Clone, Default)]
pub struct AsnSet {
    /// Canonically sorted, deduplicated members — the set's identity.
    asns: Vec<u32>,
    set: FxHashSet<u32>,
}

impl AsnSet {
    /// Build an indexed set from members. Members are canonicalized
    /// (sorted, deduplicated), so construction order and duplicates do
    /// not affect identity or behavior.
    #[must_use]
    pub fn new(asns: impl IntoIterator<Item = u32>) -> Self {
        let mut asns: Vec<u32> = asns.into_iter().collect();
        asns.sort_unstable();
        asns.dedup();
        let set = asns.iter().copied().collect();
        Self { asns, set }
    }

    /// Whether `asn` is a member — one hash probe, no allocation.
    #[must_use]
    #[inline]
    pub fn contains(&self, asn: u32) -> bool {
        self.set.contains(&asn)
    }

    /// The canonical (sorted, deduplicated) member list.
    #[must_use]
    pub fn asns(&self) -> &[u32] {
        &self.asns
    }
}

impl PartialEq for AsnSet {
    fn eq(&self, other: &Self) -> bool {
        // The hash set is derived from the canonical member list, so
        // members alone are the identity.
        self.asns == other.asns
    }
}

impl Eq for AsnSet {}

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
    community_sets: FxHashMap<(Vec<CommunityKey>, Vec<CommunityPattern>), Arc<CommunitySet>>,
    asn_sets: FxHashMap<Vec<u32>, Arc<AsnSet>>,
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
        self.community_set_with_patterns(criteria, &[])
    }

    /// Intern a community set built from `criteria` and `patterns`.
    #[must_use]
    pub fn community_set_with_patterns(
        &mut self,
        criteria: &[CommunityMatch],
        patterns: &[CommunityPattern],
    ) -> Arc<CommunitySet> {
        let mut key: Vec<CommunityKey> = criteria.iter().map(|cm| community_key(*cm)).collect();
        key.sort_unstable();
        key.dedup();
        let mut pattern_key = patterns.to_vec();
        pattern_key.sort_unstable();
        pattern_key.dedup();
        Arc::clone(
            self.community_sets
                .entry((key, pattern_key))
                .or_insert_with(|| {
                    Arc::new(CommunitySet::with_patterns(
                        criteria.iter().copied(),
                        patterns.iter().copied(),
                    ))
                }),
        )
    }

    /// Intern an ASN set built from `asns`.
    #[must_use]
    pub fn asn_set(&mut self, asns: &[u32]) -> Arc<AsnSet> {
        let mut key: Vec<u32> = asns.to_vec();
        key.sort_unstable();
        key.dedup();
        Arc::clone(
            self.asn_sets
                .entry(key)
                .or_insert_with(|| Arc::new(AsnSet::new(asns.iter().copied()))),
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

    /// Intern an AS-path regex by its configured pattern, compiling it only
    /// when this store has not interned that pattern yet.
    ///
    /// # Errors
    /// Returns the compile error for an invalid pattern.
    pub fn as_path_regex_pattern(&mut self, pattern: &str) -> Result<Arc<AsPathRegex>, String> {
        if let Some(regex) = self.as_path_regexes.get(pattern) {
            return Ok(Arc::clone(regex));
        }
        let regex = Arc::new(AsPathRegex::new(pattern)?);
        self.as_path_regexes
            .insert(pattern.to_string(), Arc::clone(&regex));
        Ok(regex)
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
            as_path: None,
            as_path_len: 0,
            origin_asn: None,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            peer_address: None,
            peer_asn: None,
            peer_group: None,
            route_type: None,
            family: None,
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

    /// Membership over a large set with duplicates: canonicalization
    /// dedupes, hits and misses are single probes (the structure is one
    /// `FxHashSet` — O(1) by construction, no per-member scan exists).
    #[test]
    fn asn_set_large_with_duplicates() {
        let members = (0..100_000u32).map(|i| 64_512 + (i % 50_000));
        let set = AsnSet::new(members);
        assert_eq!(set.asns().len(), 50_000, "duplicates canonicalized away");
        assert!(set.contains(64_512));
        assert!(set.contains(64_512 + 49_999));
        assert!(!set.contains(64_512 + 50_000));
        assert!(!set.contains(0));
        // 4-byte ASNs are first-class members.
        let wide = AsnSet::new([4_200_000_001, 64_500]);
        assert!(wide.contains(4_200_000_001));
        assert!(!wide.contains(1));
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

        // Reordered + duplicated ASN members intern to the same set.
        assert!(Arc::ptr_eq(
            &store.asn_set(&[64_500, 64_501, 64_502]),
            &store.asn_set(&[64_502, 64_500, 64_501, 64_500])
        ));

        let re = AsPathRegex::new("_65001_").unwrap();
        let interned = store.as_path_regex(&re);
        assert!(Arc::ptr_eq(
            &interned,
            &store.as_path_regex(&AsPathRegex::new("_65001_").unwrap())
        ));
        // Pattern interning shares the same entry and compiles only on a miss.
        assert!(Arc::ptr_eq(
            &interned,
            &store.as_path_regex_pattern("_65001_").unwrap()
        ));
        let fresh = store.as_path_regex_pattern("_65002_").unwrap();
        assert!(fresh.is_match("65002") && !fresh.is_match("65001"));
        assert!(Arc::ptr_eq(
            &fresh,
            &store.as_path_regex(&AsPathRegex::new("_65002_").unwrap())
        ));
        assert!(store.as_path_regex_pattern("(").is_err());
    }

    fn range(lo: u32, hi: u32) -> CommunityField {
        CommunityField::Range { lo, hi }
    }

    /// The bucketed pattern index agrees with a linear scan of every
    /// member criterion, for values on and around every field boundary,
    /// whichever field a pattern is bucketed by.
    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one table of patterns and one boundary grid per kind read best together"
    )]
    fn community_set_patterns_agree_with_criteria_scan() {
        use rustbgpd_wire::{ExtendedCommunity, LargeCommunity};

        let any16 = range(0, 0xFFFF);
        let any32 = range(0, u32::MAX);
        let patterns = [
            // Standard: keyed by ASN, keyed by value, and unkeyed.
            CommunityPattern::Standard {
                asn: CommunityField::exact(64_496),
                value: any16,
            },
            CommunityPattern::Standard {
                asn: CommunityField::exact(64_497),
                value: range(100, 199),
            },
            CommunityPattern::Standard {
                asn: any16,
                value: CommunityField::exact(666),
            },
            CommunityPattern::Standard {
                asn: CommunityField::PrivateAs,
                value: range(7, 8),
            },
            // Large: keyed by global admin, and unkeyed.
            CommunityPattern::Large {
                global_admin: CommunityField::exact(64_496),
                local_data1: range(1, 9),
                local_data2: any32,
            },
            CommunityPattern::Large {
                global_admin: CommunityField::PrivateAs,
                local_data1: any32,
                local_data2: range(u32::MAX - 1, u32::MAX),
            },
            CommunityPattern::Large {
                global_admin: any32,
                local_data1: CommunityField::exact(7),
                local_data2: any32,
            },
            // Extended: RT keyed, RT unkeyed, RO keyed.
            CommunityPattern::RouteTarget {
                global: CommunityField::exact(64_496),
                local: any32,
            },
            CommunityPattern::RouteTarget {
                global: CommunityField::PrivateAs,
                local: range(1, 2),
            },
            CommunityPattern::RouteOrigin {
                global: CommunityField::exact(64_497),
                local: range(10, 20),
            },
        ];
        let exact = CommunityMatch::Standard {
            value: (64_499 << 16) | 1,
        };
        let set = CommunitySet::with_patterns([exact], patterns);
        let scan_standard =
            |c: u32| exact.matches_standard(c) || patterns.iter().any(|p| p.matches_standard(c));
        let scan_large = |lc: &LargeCommunity| patterns.iter().any(|p| p.matches_large(lc));
        let scan_ext = |ec: &ExtendedCommunity| patterns.iter().any(|p| p.matches_ec(ec));

        let edges = |points: &[u32]| -> Vec<u32> {
            points
                .iter()
                .flat_map(|&p| [p.saturating_sub(1), p, p.saturating_add(1)])
                .collect()
        };
        let halves = edges(&[
            0, 7, 8, 100, 199, 666, 64_496, 64_497, 64_499, 64_512, 65_534, 0xFFFF,
        ]);
        let words = edges(&[
            0,
            1,
            2,
            7,
            9,
            10,
            20,
            64_496,
            64_497,
            64_512,
            65_534,
            4_200_000_000,
            u32::MAX - 1,
            u32::MAX,
        ]);
        let mut hits = 0usize;
        for &hi in &halves {
            for &lo in &halves {
                if hi > 0xFFFF || lo > 0xFFFF {
                    continue;
                }
                let c = (hi << 16) | lo;
                assert_eq!(
                    set.contains_standard(c),
                    scan_standard(c),
                    "standard {hi}:{lo}"
                );
                hits += usize::from(scan_standard(c));
            }
        }
        for &ga in &words {
            for &l1 in &words {
                for &l2 in &[0, 1, u32::MAX - 2, u32::MAX - 1, u32::MAX] {
                    let lc = LargeCommunity::new(ga, l1, l2);
                    let ctx = RouteContext {
                        large_communities: std::slice::from_ref(&lc),
                        ..empty_ctx()
                    };
                    assert_eq!(set.matches(&ctx), scan_large(&lc), "large {ga}:{l1}:{l2}");
                    assert_eq!(set.contains_large(&lc), scan_large(&lc), "{ga}:{l1}:{l2}");
                    hits += usize::from(scan_large(&lc));
                }
            }
            for &local in &[0u32, 1, 2, 3, 9, 10, 20, 21, 0xFFFF] {
                let two_octet = |sub: u64| {
                    ExtendedCommunity::new(
                        (sub << 48) | (u64::from(ga & 0xFFFF) << 32) | u64::from(local),
                    )
                };
                let four_octet = |sub: u64| {
                    ExtendedCommunity::new(
                        (0x02 << 56) | (sub << 48) | (u64::from(ga) << 16) | u64::from(local),
                    )
                };
                for ec in [
                    two_octet(0x02),
                    two_octet(0x03),
                    four_octet(0x02),
                    four_octet(0x03),
                ] {
                    let ctx = RouteContext {
                        extended_communities: std::slice::from_ref(&ec),
                        ..empty_ctx()
                    };
                    assert_eq!(set.matches(&ctx), scan_ext(&ec), "ext {ec:?}");
                    assert_eq!(set.contains_ext(&ec), scan_ext(&ec), "ext {ec:?}");
                    hits += usize::from(scan_ext(&ec));
                }
            }
        }
        assert!(hits > 100, "the grid must exercise matches, got {hits}");
        // A standard value probes one ASN bucket (1), one value bucket (1)
        // and the unkeyed PRIVATE_AS pattern (1).
        assert_eq!(set.pattern_scan_bound(), 3);
    }

    #[test]
    fn pattern_scan_bound_counts_each_probed_bucket_once() {
        let check = |patterns: Vec<CommunityPattern>| {
            CommunitySet::with_patterns([], patterns).check_pattern_scan()
        };
        let max = u32::try_from(MAX_COMMUNITY_PATTERN_SCAN).unwrap();
        let large_bucket = |n: u32| {
            (0..n)
                .map(|i| CommunityPattern::Large {
                    global_admin: CommunityField::exact(64_496),
                    local_data1: CommunityField::exact(i),
                    local_data2: range(0, u32::MAX),
                })
                .collect::<Vec<_>>()
        };
        assert!(check(large_bucket(max)).is_ok());
        assert!(check(large_bucket(max + 1)).is_err());
        // 33 ranges under one ASN cost 33 comparisons, not 66: the value
        // bucket a community also probes is a different, empty bucket.
        let asn_ranges = |n: u32| {
            (0..n)
                .map(|i| CommunityPattern::Standard {
                    asn: CommunityField::exact(65_000),
                    value: range(2 * i, 2 * i + 1),
                })
                .collect::<Vec<_>>()
        };
        let set = CommunitySet::with_patterns([], asn_ranges(33));
        assert_eq!(set.pattern_scan_bound(), 33);
        assert!(set.check_pattern_scan().is_ok());
        // `65000:666` probes the full ASN bucket and the full value
        // bucket: 33 + 32 = 65.
        let mut both = asn_ranges(33);
        both.extend((0..32).map(|i| CommunityPattern::Standard {
            asn: range(2 * i, 2 * i + 1),
            value: CommunityField::exact(666),
        }));
        let err = check(both).expect_err("65 comparisons");
        assert!(err.contains("compared against 65 patterns"), "{err}");
        // Distinct buckets do not add up; exact members never count.
        let spread: Vec<CommunityPattern> = (0..1_000)
            .map(|asn| CommunityPattern::Standard {
                asn: CommunityField::exact(asn),
                value: range(0, 0xFFFF),
            })
            .collect();
        let exact = (0..1_000).map(|value| CommunityMatch::Standard { value });
        assert!(
            CommunitySet::with_patterns(exact, spread)
                .check_pattern_scan()
                .is_ok()
        );
        let unkeyed = |n: u32| {
            (0..n)
                .map(|i| CommunityPattern::Standard {
                    asn: range(0, i + 1),
                    value: range(0, 0xFFFF),
                })
                .collect::<Vec<_>>()
        };
        assert!(check(unkeyed(max)).is_ok());
        assert!(check(unkeyed(max + 1)).is_err());
    }

    /// Patterns live outside the exact member type, so exact members and
    /// the IR nodes carrying them keep their size.
    #[test]
    fn exact_members_and_ir_nodes_keep_their_size() {
        use std::mem::size_of;
        assert_eq!(size_of::<CommunityMatch>(), 16);
        assert_eq!(size_of::<crate::ir::MatchExpr>(), 32);
        assert_eq!(size_of::<crate::ir::Term>(), 272);
        assert_eq!(size_of::<CommunityMember>(), 16);
        // One pointer for a set's optional pattern index.
        assert_eq!(size_of::<Option<Box<CommunityPatterns>>>(), 8);
    }

    /// The per-value probes `remove <kind> in SET` uses: exact members of
    /// each kind, and the exact-only standard probe that ignores patterns.
    #[test]
    fn per_value_probes_cover_exact_members_and_skip_patterns_when_asked() {
        use rustbgpd_wire::{ExtendedCommunity, LargeCommunity};

        let set = CommunitySet::with_patterns(
            [
                CommunityMatch::Standard {
                    value: rustbgpd_wire::COMMUNITY_NO_EXPORT,
                },
                CommunityMatch::LargeCommunity {
                    global_admin: 64_496,
                    local_data1: 1,
                    local_data2: 2,
                },
                CommunityMatch::RouteTarget {
                    global: 64_496,
                    local: 7,
                },
                CommunityMatch::RouteOrigin {
                    global: 64_497,
                    local: 8,
                },
                CommunityMatch::ExactExt(ExtendedCommunity::ORIGIN_VALIDATION_INVALID.as_u64()),
            ],
            [CommunityPattern::Standard {
                asn: CommunityField::exact(0xFFFF),
                value: range(0, 0xFFFF),
            }],
        );
        let no_advertise = rustbgpd_wire::COMMUNITY_NO_ADVERTISE;
        assert!(set.contains_standard(no_advertise));
        assert!(!set.contains_standard_exact(no_advertise));
        assert!(set.contains_standard_exact(rustbgpd_wire::COMMUNITY_NO_EXPORT));
        assert!(set.contains_large(&LargeCommunity::new(64_496, 1, 2)));
        assert!(!set.contains_large(&LargeCommunity::new(64_496, 1, 3)));
        // RT 64496:7 in its 2-octet and 4-octet encodings; RO 64497:8.
        let rt2 = ExtendedCommunity::new((0x02 << 48) | (64_496 << 32) | 7);
        let rt4 = ExtendedCommunity::new((0x0202 << 48) | (64_496 << 16) | 7);
        let ro = ExtendedCommunity::new((0x03 << 48) | (64_497 << 32) | 8);
        let rt_as_ro = ExtendedCommunity::new((0x03 << 48) | (64_496 << 32) | 7);
        assert!(set.contains_ext(&rt2) && set.contains_ext(&rt4) && set.contains_ext(&ro));
        assert!(!set.contains_ext(&rt_as_ro));
        assert!(set.contains_ext(&ExtendedCommunity::ORIGIN_VALIDATION_INVALID));
        assert!(!set.contains_ext(&ExtendedCommunity::ORIGIN_VALIDATION_VALID));
    }

    fn empty_ctx() -> RouteContext<'static> {
        RouteContext {
            prefix: None,
            next_hop: None,
            extended_communities: &[],
            communities: &[],
            large_communities: &[],
            as_path_str: "",
            as_path: None,
            as_path_len: 0,
            origin_asn: None,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            peer_address: None,
            peer_asn: None,
            peer_group: None,
            route_type: None,
            family: None,
            evpn_route_type: None,
            local_pref: None,
            med: None,
        }
    }
}
