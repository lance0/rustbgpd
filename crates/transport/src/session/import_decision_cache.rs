//! Per-session import-policy decision cache (ADR-0073).
//!
//! Every import-policy evaluation in [`super::inbound`] — permit and
//! deny alike — records its decision here so an operator can later ask
//! "why didn't this prefix come in?" or "what did the chain do to this
//! one when it was accepted?" via
//! `PolicyService.ExplainImportPolicy`. The cache is deliberately
//! **not** durable: it is bounded transport-session diagnostic state
//! that resets on peer flap and on daemon restart. See ADR-0073 for
//! the contract.
//!
//! Operations:
//!
//! - [`ImportDecisionCache::insert`] — write on every eval; replaces
//!   the existing entry under the same key and refreshes its LRU
//!   position.
//! - [`ImportDecisionCache::mark_withdrawn`] — tombstone an entry on
//!   UPDATE-withdraw, keeping it visible as `WITHDRAWN` until eviction
//!   or session reset.
//! - [`ImportDecisionCache::lookup`] — the explain-side read; returns
//!   `Hit` / `Stale` / `Evicted` / `NotSeen`. STALE detection lives
//!   inside the cache so the caller's response mapping stays a single
//!   `match`.
//!
//! Bound: per-peer LRU cap configured via `[policy.explain] cache_size`
//! ([`DEFAULT_EXPLAIN_CACHE_SIZE`] = 4096). When the cap
//! is reached, the least-recently-touched entry is pushed out and its key
//! is remembered as a 64-bit fingerprint, so a later lookup returns
//! `Evicted` rather than a misleading `NotSeen` however many keys have
//! been evicted since the session came up. A write for the key removes
//! its fingerprint, and a live entry always takes precedence. The only
//! error is a 64-bit fingerprint collision between two keys, which can
//! answer `Evicted` for an unseen key or, once the colliding key is
//! re-announced, `NotSeen` for an evicted one; across `n` evicted keys a
//! collision has probability about `n² / 2^65`.
//!
//! The fingerprint memory is capped at [`EVICTED_KEY_LIMIT`] keys (see
//! that constant for its measured cost). Past the cap no new fingerprint is
//! stored and every unknown key answers `Evicted`: the cache can no longer
//! prove a key was never seen, so it never claims so.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::SystemTime;

use lru::LruCache;
use rustbgpd_policy::{PolicyAction, RouteModifications, StatementAttribution};
use rustbgpd_wire::{
    Afi, AspaValidation, ExtendedCommunity, LargeCommunity, Prefix, RpkiValidation, Safi,
};
use rustc_hash::FxHashSet;

/// Default per-peer cap. Per ADR-0073 this is a deliberate fabric /
/// partial-table starter size (hundreds–low-thousands of prefixes fully
/// observable), **not** sized for internet full-table retention — a
/// 100k-prefix peer keeps the cache saturated, so operators wanting
/// reliable full-table explain raise `[policy.explain] cache_size`
/// toward their expected retained-prefix count and own the memory.
pub const DEFAULT_EXPLAIN_CACHE_SIZE: usize = 4096;

/// Cap on remembered evicted keys per session. It covers a full
/// dual-stack table plus churn; a peer cycling through distinct prefixes
/// cannot grow the memory past it. Allocator-counted requested bytes:
/// 18.9 MB for 1M evicted `path_id` 0 keys and 37.8 MB at the cap; 27–34 B
/// per nonzero Add-Path key (ordered so an all-paths lookup can enumerate
/// them), up to 72 MB at the cap.
pub const EVICTED_KEY_LIMIT: usize = 1 << 21;

/// Identity of a cached import decision.
///
/// Per ADR-0073 the key is `(AFI, SAFI, prefix, path_id)`. `path_id` is
/// always part of the key; for sessions without Add-Path it carries the
/// RFC 7911 implicit value `0`.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ImportDecisionKey {
    pub afi: Afi,
    pub safi: Safi,
    pub prefix: Prefix,
    pub path_id: u32,
}

/// The outcome stored in a cache entry.
///
/// `Permit` and `Deny` are produced by an import-policy evaluation.
/// `Withdrawn` is produced by `ImportDecisionCache::mark_withdrawn`
/// when the peer subsequently withdraws a permitted prefix — the
/// entry is retained as a tombstone rather than dropped to `NotSeen`
/// because the operator distinction matters (see ADR-0073).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachedOutcome {
    Permit,
    Deny,
    Withdrawn,
}

impl From<PolicyAction> for CachedOutcome {
    fn from(action: PolicyAction) -> Self {
        match action {
            PolicyAction::Permit => Self::Permit,
            PolicyAction::Deny => Self::Deny,
        }
    }
}

/// Compact owned copy of the pre-policy fields the policy evaluator saw.
///
/// This is intentionally narrower than a raw `Vec<PathAttribute>`: import
/// explain only needs these fields to re-derive statement attribution, so the
/// bounded cache does not retain unrelated attributes such as `ORIGIN`,
/// `NEXT_HOP`, `ORIGINATOR_ID`, `CLUSTER_LIST`, or unknown transitive
/// attributes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CachedPolicyContext {
    pub extended_communities: Vec<ExtendedCommunity>,
    pub communities: Vec<u32>,
    pub large_communities: Vec<LargeCommunity>,
    /// Typed `AS_PATH` (owned), so an explain re-derivation of a chain
    /// with `for asn in route.as-path` loops sees the same iteration the
    /// live evaluation saw. Explain-enabled path only.
    ///
    /// The single source of truth for the `AS_PATH` surface: the
    /// `RouteContext.as_path_str` an explain query needs is rendered
    /// from this at query time via
    /// [`rustbgpd_wire::AsPath::to_aspath_string`] — the same formatter
    /// the inbound extractor uses — rather than stored alongside it.
    /// `None` renders as the empty string, exactly as the live path's
    /// `unwrap_or_default` does, so nothing is lost by not storing it.
    pub as_path: Option<rustbgpd_wire::AsPath>,
    pub as_path_len: usize,
    pub origin_asn: Option<u32>,
    pub local_pref: Option<u32>,
    pub med: Option<u32>,
}

/// A single cached decision. Carries everything required to render an
/// `ExplainImportPolicyResponse` without consulting any other subsystem.
#[derive(Debug, Clone)]
pub struct CachedDecision {
    pub outcome: CachedOutcome,
    /// Decision attribution from
    /// [`rustbgpd_policy::PolicyEvaluation::matched_policy`]. `None` =
    /// inline deny or absent / genuinely empty chain; a nonempty-chain
    /// Permit carries `chain_default_permit`.
    pub matched_policy: Option<Arc<str>>,
    /// RPKI origin-validation state at evaluation time.
    pub rpki: RpkiValidation,
    /// ASPA path-verification state at evaluation time.
    pub aspa: AspaValidation,
    /// Pre-policy context fields exactly as the policy evaluator saw them.
    /// Cloned at the eval site only when import explain is enabled; the
    /// original UPDATE path is unchanged.
    pub policy_context: CachedPolicyContext,
    /// The next-hop the evaluation context saw. Stored separately
    /// because it is not part of `policy_context`: MP-unicast routes carry it
    /// in `MP_REACH` framing, which is stripped before route attributes are
    /// stored. Needed so the statement-level explain re-derivation rebuilds
    /// the *exact* evaluation-time `RouteContext`.
    pub next_hop: Option<IpAddr>,
    /// Modifications the policy chain would apply on permit. Carried
    /// for both permit and deny entries — for a deny they describe what
    /// *would* have happened if the chain had reached its inline-deny
    /// terminator (typically empty on a hard deny).
    pub modifications: RouteModifications,
    /// Wall-clock time of the evaluation. The cache itself doesn't read
    /// this; it's solely for the explain response.
    pub evaluated_at: SystemTime,
    /// The session's import-policy generation at the time of evaluation
    /// (session-local, bumped only on this peer's import-chain hot-apply —
    /// not a global policy-registry counter). The lookup path compares this
    /// to the session's current generation to flag `Stale` entries.
    pub policy_generation: u64,
}

/// Result of a cache lookup.
///
/// `Stale` carries the cached decision so the explain response can
/// still render the *historical* state — the operator's value is
/// "here's what was decided then, against the policy as it was then,
/// noting that the policy has since changed."
#[derive(Debug, Clone)]
pub enum LookupResult {
    Hit(CachedDecision),
    Stale(CachedDecision),
    Evicted,
    NotSeen,
}

/// One resolved path for an explain query. `path_id` is echoed so an
/// all-paths (Add-Path) query can disambiguate the entries it returns.
#[derive(Debug, Clone)]
pub struct ResolvedMatch {
    pub path_id: u32,
    pub result: LookupResult,
    /// Statement-level attribution, re-derived at query time by the
    /// session command handler (not by the cache — the cache holds no
    /// policy chain). Populated only for current-generation `Hit`
    /// entries with a `Permit` / `Deny` outcome: a `Stale` entry's
    /// chain is gone (re-deriving against the current chain could
    /// contradict the recorded outcome) and a `Withdrawn` tombstone
    /// has shed the attributes the re-derivation needs. Empty
    /// otherwise.
    pub statements: Vec<StatementAttribution>,
}

/// The session's reply to an explain query. Carries the session's
/// current import-policy generation so the caller can render the
/// top-level `current_policy_generation` field and the per-match
/// staleness is internally consistent with it.
///
/// `matches` is empty only when the prefix was never seen on this
/// session (or its only record is a fingerprint collision) — the caller renders that
/// as a single synthetic `NOT_SEEN` when `cache_enabled` is set, or
/// as `CACHE_DISABLED` when it is not (a disabled cache records
/// nothing, so an empty match set says nothing about the prefix).
#[derive(Debug, Clone)]
pub struct ImportExplainReply {
    pub current_generation: u64,
    /// Whether this session records import decisions at all
    /// (`[policy.explain] enabled`, snapshotted at session build).
    /// `false` means the empty cache is a configuration fact, not an
    /// evaluated "never seen" answer (LAN-320).
    pub cache_enabled: bool,
    /// The session's configured entry cap (`[policy.explain] cache_size`).
    pub cache_size: usize,
    /// Decisions evicted by that cap since the last session reset. Zero
    /// means every decision recorded on this session is still cached.
    pub evictions_since_reset: u64,
    pub matches: Vec<ResolvedMatch>,
}

/// Bounded per-session LRU of import-policy decisions.
///
/// Not `Send`/`Sync` on its own — the session owns it; cross-task
/// readers (the explain RPC) go through an `Arc<Mutex<…>>` wrapper.
#[derive(Debug)]
pub struct ImportDecisionCache {
    /// Per-peer LRU cap, retained so `entries` can be built on demand.
    cap: NonZeroUsize,
    /// `None` until the first `insert`. `LruCache::new` eagerly
    /// allocates its index (`HashMap::with_capacity(cap)`) plus the two
    /// sigil nodes of its intrusive list, so building it at session
    /// construction charges every peer for the cache whether or not
    /// `[policy.explain] enabled` is set — and a disabled session never
    /// inserts. Deferring the build keeps a disabled session (and an
    /// enabled one that has not yet seen an UPDATE) allocation-free.
    entries: Option<LruCache<ImportDecisionKey, CachedDecision>>,
    /// Every key evicted from `entries` since the last reset and not
    /// written again. Grows on demand; empty until the first eviction.
    evicted: EvictedKeys,
    /// LRU evictions since the last reset, reported on the explain reply.
    evictions_since_reset: u64,
}

/// Fingerprints of evicted keys, split so the common case stays one
/// `u64` per key: a session without Add-Path receive only ever uses
/// `path_id` 0.
#[derive(Debug, Default)]
struct EvictedKeys {
    /// Per-cache random keys, so a peer cannot choose prefixes whose
    /// fingerprints collide.
    state: RandomState,
    /// `(afi, safi, prefix)` fingerprints whose `path_id` 0 entry was evicted.
    default_path: FxHashSet<u64>,
    /// Evicted nonzero Add-Path keys, ordered so each prefix's paths are
    /// one range an all-paths lookup can enumerate. Every operation is
    /// logarithmic, however many path identifiers one prefix cycles through.
    add_path: BTreeSet<AddPathKey>,
    len: usize,
    /// Set once `len` reached [`EVICTED_KEY_LIMIT`]; every unknown key
    /// then answers `Evicted`.
    overflowed: bool,
}

/// An evicted nonzero Add-Path key: `(afi, safi, prefix)` fingerprint, then
/// path identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AddPathKey {
    prefix: u64,
    path_id: u32,
}

impl Ord for AddPathKey {
    fn cmp(&self, other: &Self) -> Ordering {
        #[cfg(test)]
        ADD_PATH_COMPARISONS.with(|count| count.set(count.get() + 1));
        (self.prefix, self.path_id).cmp(&(other.prefix, other.path_id))
    }
}

impl PartialOrd for AddPathKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
thread_local! {
    /// `AddPathKey` comparisons on this thread, so a test can bound the
    /// work without timing it.
    static ADD_PATH_COMPARISONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl EvictedKeys {
    fn fingerprint(&self, afi: Afi, safi: Safi, prefix: &Prefix) -> u64 {
        self.state.hash_one((afi, safi, prefix))
    }

    fn insert(&mut self, key: &ImportDecisionKey) {
        if self.len >= EVICTED_KEY_LIMIT {
            self.overflowed = true;
            return;
        }
        let fp = self.fingerprint(key.afi, key.safi, &key.prefix);
        let added = if key.path_id == 0 {
            self.default_path.insert(fp)
        } else {
            self.add_path.insert(AddPathKey {
                prefix: fp,
                path_id: key.path_id,
            })
        };
        self.len += usize::from(added);
    }

    fn remove(&mut self, key: &ImportDecisionKey) {
        if self.len == 0 {
            return;
        }
        let fp = self.fingerprint(key.afi, key.safi, &key.prefix);
        let removed = if key.path_id == 0 {
            self.default_path.remove(&fp)
        } else {
            self.add_path.remove(&AddPathKey {
                prefix: fp,
                path_id: key.path_id,
            })
        };
        self.len -= usize::from(removed);
    }

    fn contains(&self, key: &ImportDecisionKey) -> bool {
        if self.overflowed {
            return true;
        }
        if self.len == 0 {
            return false;
        }
        let fp = self.fingerprint(key.afi, key.safi, &key.prefix);
        if key.path_id == 0 {
            self.default_path.contains(&fp)
        } else {
            self.add_path.contains(&AddPathKey {
                prefix: fp,
                path_id: key.path_id,
            })
        }
    }

    /// Recorded evicted path identifiers for a prefix.
    fn path_ids(&self, afi: Afi, safi: Safi, prefix: &Prefix) -> Vec<u32> {
        let mut ids = Vec::new();
        if self.len > 0 {
            let fp = self.fingerprint(afi, safi, prefix);
            if self.default_path.contains(&fp) {
                ids.push(0);
            }
            let first = AddPathKey {
                prefix: fp,
                path_id: 1,
            };
            let last = AddPathKey {
                prefix: fp,
                path_id: u32::MAX,
            };
            ids.extend(self.add_path.range(first..=last).map(|k| k.path_id));
        }
        ids
    }

    #[cfg(test)]
    fn is_unallocated(&self) -> bool {
        self.default_path.capacity() == 0 && self.add_path.is_empty()
    }
}

impl ImportDecisionCache {
    /// Create a cache with the given per-peer capacity. A zero or
    /// otherwise nonsensical input is clamped to `1` — the cache is
    /// always at least nominally usable.
    ///
    /// Allocates nothing: the LRU is built on first use and the evicted-key
    /// memory on first eviction.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            cap: NonZeroUsize::new(cap.max(1)).expect("clamped to at least 1"),
            entries: None,
            evicted: EvictedKeys::default(),
            evictions_since_reset: 0,
        }
    }

    /// The configured per-session entry cap.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.cap.get()
    }

    /// LRU evictions since the session's last reset.
    #[must_use]
    pub fn evictions_since_reset(&self) -> u64 {
        self.evictions_since_reset
    }

    /// Drop every cached decision and the evicted-key memory.
    ///
    /// Called on session reset (peer flap / `Action::SessionDown`): the
    /// cache is **per-session** diagnostic state, so decisions recorded
    /// on a prior session must not leak into an explain query on the
    /// reconnected session (ADR-0073 "resets on peer session reset").
    /// A reconnecting `PeerSession` is not reconstructed, so without this
    /// a stale decision could answer for any prefix the peer has not yet
    /// re-advertised.
    ///
    /// Drops the backing allocations too, returning the cache to the
    /// state `with_capacity` left it in — a session that is down holds
    /// no cache memory, and the next `insert` rebuilds the LRU at its
    /// full configured size.
    pub fn clear(&mut self) {
        self.entries = None;
        self.evicted = EvictedKeys::default();
        self.evictions_since_reset = 0;
    }

    /// Insert or replace an entry and return whether it evicted another
    /// key. The LRU victim's key is remembered so a subsequent `lookup`
    /// for it returns `Evicted` rather than `NotSeen`; a write for a
    /// previously evicted key forgets that record, so lookups see the
    /// fresh decision.
    pub fn insert(&mut self, key: ImportDecisionKey, decision: CachedDecision) -> bool {
        self.evicted.remove(&key);
        let cap = self.cap;
        let entries = self.entries.get_or_insert_with(|| LruCache::new(cap));
        // `push` also returns the old pair when it replaces `key` in place.
        let replaced = key.clone();
        match entries.push(key, decision) {
            Some((victim, _)) if victim != replaced => {
                self.evicted.insert(&victim);
                self.evictions_since_reset = self.evictions_since_reset.saturating_add(1);
                true
            }
            _ => false,
        }
    }

    /// Tombstone the entry under `key` as `Withdrawn`. No-op when the
    /// key is absent — withdrawing a prefix we never accepted carries
    /// no operator value.
    ///
    /// The tombstone is **lighter** than a live entry: the cached policy
    /// context and modifications are dropped, keeping only outcome,
    /// decision attribution, RPKI/ASPA state, timestamp, and generation. A
    /// peer that churns announce/withdraw/announce therefore can't fill
    /// the bounded LRU with full-payload dead entries that crowd out
    /// live decisions (ADR-0073). The withdrawn route's context is
    /// the least useful field for the "why is it gone?" question
    /// anyway.
    pub fn mark_withdrawn(&mut self, key: &ImportDecisionKey) {
        if let Some(decision) = self.entries.as_mut().and_then(|e| e.get_mut(key)) {
            decision.outcome = CachedOutcome::Withdrawn;
            decision.policy_context = CachedPolicyContext::default();
            decision.modifications = RouteModifications::default();
        }
    }

    /// Look up a single decision by exact key. Returns `Stale` when the
    /// cached entry's `policy_generation` is older than
    /// `current_generation`.
    ///
    /// Side-effect-free: uses `peek`, so an operator's explain query
    /// does **not** perturb the LRU eviction order. A diagnostic read
    /// keeping a cold entry alive (or aging a hot one) would be
    /// surprising; the hot write path is the sole owner of recency.
    #[must_use]
    pub fn lookup(&self, key: &ImportDecisionKey, current_generation: u64) -> LookupResult {
        if let Some(decision) = self.entries.as_ref().and_then(|e| e.peek(key)) {
            Self::classify(decision.clone(), current_generation)
        } else if self.evicted.contains(key) {
            LookupResult::Evicted
        } else {
            LookupResult::NotSeen
        }
    }

    /// Resolve every cached path for `(afi, safi, prefix)` — the
    /// Add-Path / "operator omitted `--path-id`" case. Returns one
    /// [`ResolvedMatch`] per live entry, ordered by `path_id` for a
    /// stable response. Evicted paths for the prefix are returned as
    /// `Evicted` so the operator isn't told `NotSeen` for something
    /// that was real. Empty only when genuinely never-seen.
    #[must_use]
    pub fn lookup_all_paths(
        &self,
        afi: Afi,
        safi: Safi,
        prefix: &Prefix,
        current_generation: u64,
    ) -> Vec<ResolvedMatch> {
        let mut matches: Vec<ResolvedMatch> = self
            .entries
            .iter()
            .flat_map(|entries| entries.iter())
            .filter(|(k, _)| k.afi == afi && k.safi == safi && &k.prefix == prefix)
            .map(|(k, decision)| ResolvedMatch {
                path_id: k.path_id,
                result: Self::classify(decision.clone(), current_generation),
                statements: Vec::new(),
            })
            .collect();
        // A key is never both live and evicted, so these cannot duplicate
        // a live path.
        let mut evicted = self.evicted.path_ids(afi, safi, prefix);
        if matches.is_empty() && evicted.is_empty() && self.evicted.overflowed {
            // Past the memory cap the evicted path identifier is unknown.
            evicted.push(0);
        }
        matches.extend(evicted.into_iter().map(|path_id| ResolvedMatch {
            path_id,
            result: LookupResult::Evicted,
            statements: Vec::new(),
        }));
        matches.sort_by_key(|m| m.path_id);
        matches
    }

    fn classify(decision: CachedDecision, current_generation: u64) -> LookupResult {
        if decision.policy_generation < current_generation {
            LookupResult::Stale(decision)
        } else {
            LookupResult::Hit(decision)
        }
    }

    /// Number of entries currently held — distinct keys, regardless of
    /// outcome. Withdrawn tombstones count. Test-only for now; promote
    /// to `pub` when a cache-occupancy metric or `PR2` consumer needs
    /// it.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.as_ref().map_or(0, LruCache::len)
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.entries.as_ref().is_none_or(LruCache::is_empty)
    }

    /// Whether the cache is holding zero heap allocation — no LRU index
    /// and no evicted-key memory. The structural fact a disabled session
    /// must satisfy: an occupancy assertion (`lookup` returns
    /// `NotSeen`) is satisfied by an eagerly-allocated empty cache too,
    /// so it cannot pin this.
    #[cfg(test)]
    pub(super) fn is_unallocated(&self) -> bool {
        self.entries.is_none() && self.evicted.is_unallocated()
    }
}

impl Default for ImportDecisionCache {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_EXPLAIN_CACHE_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rustbgpd_wire::Ipv4Prefix;

    use super::*;

    fn key(octet: u8, path_id: u32) -> ImportDecisionKey {
        ImportDecisionKey {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, octet), 32)),
            path_id,
        }
    }

    fn permit_at(generation: u64) -> CachedDecision {
        CachedDecision {
            outcome: CachedOutcome::Permit,
            matched_policy: Some("test-permit".into()),
            rpki: RpkiValidation::NotFound,
            aspa: AspaValidation::Unknown,
            policy_context: CachedPolicyContext::default(),
            next_hop: None,
            modifications: RouteModifications::default(),
            evaluated_at: SystemTime::UNIX_EPOCH,
            policy_generation: generation,
        }
    }

    fn deny_at(generation: u64) -> CachedDecision {
        CachedDecision {
            outcome: CachedOutcome::Deny,
            matched_policy: Some("test-deny".into()),
            rpki: RpkiValidation::NotFound,
            aspa: AspaValidation::Unknown,
            policy_context: CachedPolicyContext::default(),
            next_hop: None,
            modifications: RouteModifications::default(),
            evaluated_at: SystemTime::UNIX_EPOCH,
            policy_generation: generation,
        }
    }

    #[test]
    fn lookup_unseen_key_is_not_seen() {
        let cache = ImportDecisionCache::with_capacity(4);
        assert!(matches!(cache.lookup(&key(1, 0), 0), LookupResult::NotSeen));
    }

    #[test]
    fn permit_then_lookup_is_hit() {
        let mut cache = ImportDecisionCache::with_capacity(4);
        cache.insert(key(1, 0), permit_at(0));
        match cache.lookup(&key(1, 0), 0) {
            LookupResult::Hit(decision) => {
                assert_eq!(decision.outcome, CachedOutcome::Permit);
                assert_eq!(decision.matched_policy.as_deref(), Some("test-permit"));
            }
            other => panic!("expected Hit, got {other:?}"),
        }
    }

    #[test]
    fn deny_is_retained_and_explainable() {
        // Pin 1 from ADR-0073 plan: denied import is explainable even
        // though no RIB route exists.
        let mut cache = ImportDecisionCache::with_capacity(4);
        cache.insert(key(2, 0), deny_at(0));
        match cache.lookup(&key(2, 0), 0) {
            LookupResult::Hit(decision) => assert_eq!(decision.outcome, CachedOutcome::Deny),
            other => panic!("expected Hit(Deny), got {other:?}"),
        }
    }

    #[test]
    fn insert_replaces_existing_entry() {
        let mut cache = ImportDecisionCache::with_capacity(4);
        cache.insert(key(1, 0), permit_at(0));
        cache.insert(key(1, 0), deny_at(0));
        assert_eq!(cache.len(), 1);
        match cache.lookup(&key(1, 0), 0) {
            LookupResult::Hit(decision) => assert_eq!(decision.outcome, CachedOutcome::Deny),
            other => panic!("expected Hit(Deny), got {other:?}"),
        }
    }

    #[test]
    fn mark_withdrawn_converts_outcome_to_withdrawn() {
        // Pin 5 from ADR-0073 plan: withdraw → WITHDRAWN tombstone, not
        // NotSeen.
        let mut cache = ImportDecisionCache::with_capacity(4);
        cache.insert(key(3, 0), permit_at(0));
        cache.mark_withdrawn(&key(3, 0));
        match cache.lookup(&key(3, 0), 0) {
            LookupResult::Hit(decision) => assert_eq!(decision.outcome, CachedOutcome::Withdrawn),
            other => panic!("expected Hit(Withdrawn), got {other:?}"),
        }
    }

    #[test]
    fn withdraw_drops_stored_payload() {
        // ADR-0073: a WITHDRAWN tombstone must shed its attrs/mods so a
        // churny peer can't fill the LRU with full-payload dead entries.
        let mut cache = ImportDecisionCache::with_capacity(4);
        let mut decision = permit_at(0);
        decision.policy_context = CachedPolicyContext {
            communities: vec![100],
            as_path: Some(rustbgpd_wire::AsPath {
                segments: vec![rustbgpd_wire::AsPathSegment::AsSequence(vec![65002])],
            }),
            as_path_len: 1,
            ..CachedPolicyContext::default()
        };
        decision.modifications = RouteModifications {
            set_local_pref: Some(150),
            ..RouteModifications::default()
        };
        cache.insert(key(3, 0), decision);
        cache.mark_withdrawn(&key(3, 0));
        match cache.lookup(&key(3, 0), 0) {
            LookupResult::Hit(d) => {
                assert_eq!(d.outcome, CachedOutcome::Withdrawn);
                assert_eq!(
                    d.policy_context,
                    CachedPolicyContext::default(),
                    "policy context dropped on withdraw"
                );
                assert!(
                    d.modifications.set_local_pref.is_none(),
                    "modifications dropped on withdraw"
                );
                // The lightweight fields survive for the explain answer.
                assert_eq!(d.matched_policy.as_deref(), Some("test-permit"));
            }
            other => panic!("expected Hit(Withdrawn), got {other:?}"),
        }
    }

    #[test]
    fn mark_withdrawn_on_unseen_key_is_noop() {
        let mut cache = ImportDecisionCache::with_capacity(4);
        cache.mark_withdrawn(&key(4, 0));
        assert!(cache.is_empty());
        assert!(matches!(cache.lookup(&key(4, 0), 0), LookupResult::NotSeen));
    }

    #[test]
    fn stale_returned_when_entry_generation_lags() {
        // Pin 6 from ADR-0073 plan: policy reload yields STALE.
        let mut cache = ImportDecisionCache::with_capacity(4);
        cache.insert(key(1, 0), permit_at(7));
        // Generation has moved forward — the cached entry now reads stale.
        match cache.lookup(&key(1, 0), 8) {
            LookupResult::Stale(decision) => {
                assert_eq!(decision.outcome, CachedOutcome::Permit);
                assert_eq!(decision.policy_generation, 7);
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[test]
    fn same_generation_lookup_is_hit_not_stale() {
        let mut cache = ImportDecisionCache::with_capacity(4);
        cache.insert(key(1, 0), permit_at(5));
        assert!(matches!(cache.lookup(&key(1, 0), 5), LookupResult::Hit(_)));
    }

    #[test]
    fn evicted_lookup_reports_evicted_not_not_seen() {
        // Pin: EVICTED tracker distinguishes evicted from never-seen.
        let mut cache = ImportDecisionCache::with_capacity(2);
        cache.insert(key(1, 0), permit_at(0));
        cache.insert(key(2, 0), permit_at(0));
        // This third insert evicts key(1, 0) (least recently touched).
        cache.insert(key(3, 0), permit_at(0));
        assert!(matches!(cache.lookup(&key(1, 0), 0), LookupResult::Evicted));
        assert!(matches!(
            cache.lookup(&key(99, 0), 0),
            LookupResult::NotSeen
        ));
    }

    #[test]
    fn reinserting_an_evicted_key_clears_the_eviction_record() {
        // The evicted-key memory must be cleared on a write — once the
        // operator's peer re-sends the prefix, the cache must report
        // the fresh decision and never spuriously surface Evicted.
        let mut cache = ImportDecisionCache::with_capacity(2);
        cache.insert(key(1, 0), permit_at(0));
        cache.insert(key(2, 0), permit_at(0));
        cache.insert(key(3, 0), permit_at(0)); // evicts key(1)
        assert!(matches!(cache.lookup(&key(1, 0), 0), LookupResult::Evicted));
        cache.insert(key(1, 0), permit_at(0)); // peer re-advertises
        assert!(matches!(cache.lookup(&key(1, 0), 0), LookupResult::Hit(_)));
    }

    #[test]
    fn lookup_is_side_effect_free_on_eviction_order() {
        // An operator's explain query must not perturb the LRU order.
        // key(1) is the oldest; reading it repeatedly must NOT rescue
        // it from being the next eviction victim.
        let mut cache = ImportDecisionCache::with_capacity(2);
        cache.insert(key(1, 0), permit_at(0));
        cache.insert(key(2, 0), permit_at(0));
        for _ in 0..3 {
            assert!(matches!(cache.lookup(&key(1, 0), 0), LookupResult::Hit(_)));
        }
        // Inserting a third entry still evicts key(1) (the genuine LRU),
        // not key(2) — the reads above were peeks, not touches.
        cache.insert(key(3, 0), permit_at(0));
        assert!(matches!(cache.lookup(&key(1, 0), 0), LookupResult::Evicted));
        assert!(matches!(cache.lookup(&key(2, 0), 0), LookupResult::Hit(_)));
    }

    #[test]
    fn lookup_all_paths_returns_every_live_path_sorted() {
        let mut cache = ImportDecisionCache::with_capacity(8);
        cache.insert(key(1, 3), permit_at(0));
        cache.insert(key(1, 1), deny_at(0));
        cache.insert(key(1, 2), permit_at(0));
        // A different prefix that must not leak into the result.
        cache.insert(key(2, 1), permit_at(0));
        let prefix = key(1, 0).prefix;
        let matches = cache.lookup_all_paths(Afi::Ipv4, Safi::Unicast, &prefix, 0);
        let path_ids: Vec<u32> = matches.iter().map(|m| m.path_id).collect();
        assert_eq!(path_ids, vec![1, 2, 3], "sorted, prefix-scoped");
    }

    #[test]
    fn lookup_all_paths_surfaces_evicted_when_no_live_entry() {
        let mut cache = ImportDecisionCache::with_capacity(2);
        cache.insert(key(1, 7), permit_at(0));
        cache.insert(key(2, 0), permit_at(0));
        cache.insert(key(3, 0), permit_at(0)); // evicts key(1, 7)
        let prefix = key(1, 0).prefix;
        let matches = cache.lookup_all_paths(Afi::Ipv4, Safi::Unicast, &prefix, 0);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].path_id, 7);
        assert!(matches!(matches[0].result, LookupResult::Evicted));
    }

    #[test]
    fn lookup_all_paths_empty_when_never_seen() {
        let cache = ImportDecisionCache::with_capacity(4);
        let prefix = key(5, 0).prefix;
        assert!(
            cache
                .lookup_all_paths(Afi::Ipv4, Safi::Unicast, &prefix, 0)
                .is_empty()
        );
    }

    #[test]
    fn path_id_disambiguates_add_path_entries() {
        let mut cache = ImportDecisionCache::with_capacity(4);
        cache.insert(key(1, 1), permit_at(0));
        cache.insert(key(1, 2), deny_at(0));
        assert_eq!(cache.len(), 2);
        match cache.lookup(&key(1, 1), 0) {
            LookupResult::Hit(d) => assert_eq!(d.outcome, CachedOutcome::Permit),
            other => panic!("expected Hit(Permit) for path_id=1, got {other:?}"),
        }
        match cache.lookup(&key(1, 2), 0) {
            LookupResult::Hit(d) => assert_eq!(d.outcome, CachedOutcome::Deny),
            other => panic!("expected Hit(Deny) for path_id=2, got {other:?}"),
        }
    }

    #[test]
    fn zero_capacity_is_clamped_to_at_least_one() {
        let mut cache = ImportDecisionCache::with_capacity(0);
        cache.insert(key(1, 0), permit_at(0));
        assert!(matches!(cache.lookup(&key(1, 0), 0), LookupResult::Hit(_)));
    }

    #[test]
    fn cache_allocates_nothing_until_first_insert() {
        // Structural, not behavioural: an eagerly-built cache answers
        // every lookup identically, so only the allocation state can
        // distinguish the two. A session with `[policy.explain]
        // enabled = false` never inserts and must therefore cost
        // nothing.
        let mut cache = ImportDecisionCache::with_capacity(DEFAULT_EXPLAIN_CACHE_SIZE);
        assert!(
            cache.is_unallocated(),
            "a cache with no entries must hold no LRU index and no evicted-key memory",
        );
        // Reads must not allocate either.
        let _ = cache.lookup(&key(1, 0), 0);
        let _ = cache.lookup_all_paths(Afi::Ipv4, Safi::Unicast, &key(1, 0).prefix, 0);
        cache.mark_withdrawn(&key(1, 0));
        assert!(
            cache.is_unallocated(),
            "lookups and withdraws must not build the cache"
        );

        cache.insert(key(1, 0), permit_at(0));
        assert!(!cache.is_unallocated(), "the first insert builds the LRU");
        assert_eq!(cache.len(), 1);

        // A session reset returns the peer to zero resident cost.
        cache.clear();
        assert!(
            cache.is_unallocated(),
            "clear releases the backing allocations"
        );
        assert!(matches!(cache.lookup(&key(1, 0), 0), LookupResult::NotSeen));
    }

    /// A distinct /32 per index, for pushing a cache far past its cap.
    fn nth_key(i: u32, path_id: u32) -> ImportDecisionKey {
        ImportDecisionKey {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(0x0a00_0000 | i), 32)),
            path_id,
        }
    }

    /// More evictions than the 512-key ring that used to back `Evicted`.
    const MANY: u32 = 4 + 512 + 64;

    #[test]
    fn evicted_key_stays_evicted_after_many_evictions() {
        let mut cache = ImportDecisionCache::with_capacity(4);
        for i in 0..MANY {
            cache.insert(nth_key(i, 0), permit_at(0));
        }
        assert!(
            matches!(cache.lookup(&nth_key(0, 0), 0), LookupResult::Evicted),
            "the first key was announced, then evicted: it must not read as never seen",
        );
        assert!(matches!(
            cache.lookup(&nth_key(MANY, 0), 0),
            LookupResult::NotSeen
        ));
        let evicted = cache.lookup_all_paths(Afi::Ipv4, Safi::Unicast, &nth_key(0, 0).prefix, 0);
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].path_id, 0);
        assert!(matches!(evicted[0].result, LookupResult::Evicted));
        assert!(
            cache
                .lookup_all_paths(Afi::Ipv4, Safi::Unicast, &nth_key(MANY, 0).prefix, 0)
                .is_empty()
        );
        assert_eq!(cache.evictions_since_reset(), u64::from(MANY - 4));
        assert_eq!(cache.capacity(), 4);

        // Re-announcing clears the evicted record.
        cache.insert(nth_key(0, 0), deny_at(0));
        assert!(matches!(
            cache.lookup(&nth_key(0, 0), 0),
            LookupResult::Hit(_)
        ));
        let live = cache.lookup_all_paths(Afi::Ipv4, Safi::Unicast, &nth_key(0, 0).prefix, 0);
        assert_eq!(live.len(), 1);
        assert!(matches!(live[0].result, LookupResult::Hit(_)));
        // Evicted again, it reads as evicted again.
        for i in MANY..MANY + 4 {
            cache.insert(nth_key(i, 0), permit_at(0));
        }
        assert!(matches!(
            cache.lookup(&nth_key(0, 0), 0),
            LookupResult::Evicted
        ));
    }

    #[test]
    fn add_path_evictions_are_exact_per_path_id() {
        let mut cache = ImportDecisionCache::with_capacity(4);
        for path_id in 1..=3 {
            cache.insert(nth_key(0, path_id), permit_at(0));
        }
        for i in 1..MANY {
            cache.insert(nth_key(i, 1), permit_at(0));
        }
        let prefix = nth_key(0, 0).prefix;
        assert!(matches!(
            cache.lookup(&nth_key(0, 2), 0),
            LookupResult::Evicted
        ));
        assert!(matches!(
            cache.lookup(&nth_key(0, 9), 0),
            LookupResult::NotSeen
        ));
        assert!(matches!(
            cache.lookup(&nth_key(0, 0), 0),
            LookupResult::NotSeen
        ));
        let evicted = cache.lookup_all_paths(Afi::Ipv4, Safi::Unicast, &prefix, 0);
        assert_eq!(
            evicted.iter().map(|m| m.path_id).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert!(
            evicted
                .iter()
                .all(|m| matches!(m.result, LookupResult::Evicted))
        );

        // Re-announcing one path clears only that path; the all-paths
        // answer lists it live beside its still-evicted siblings.
        cache.insert(nth_key(0, 2), permit_at(0));
        let mixed = cache.lookup_all_paths(Afi::Ipv4, Safi::Unicast, &prefix, 0);
        assert_eq!(
            mixed.iter().map(|m| m.path_id).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert!(matches!(mixed[0].result, LookupResult::Evicted));
        assert!(matches!(mixed[1].result, LookupResult::Hit(_)));
        assert!(matches!(mixed[2].result, LookupResult::Evicted));
    }

    #[test]
    fn cycling_add_path_ids_on_one_prefix_stays_logarithmic() {
        // Add-Path receive is unlimited by default and decisions are
        // recorded before admission, so one prefix can cycle through any
        // number of path identifiers. Each evict, re-announce and lookup
        // must stay logarithmic in that number, not linear.
        const PATHS: u32 = 20_000;
        let mut cache = ImportDecisionCache::with_capacity(1);
        ADD_PATH_COMPARISONS.with(|count| count.set(0));
        for path_id in 1..=PATHS {
            cache.insert(nth_key(0, path_id), permit_at(0)); // evicts path_id - 1
        }
        for path_id in 1..PATHS {
            assert!(matches!(
                cache.lookup(&nth_key(0, path_id), 0),
                LookupResult::Evicted
            ));
        }
        for path_id in 1..PATHS {
            cache.insert(nth_key(0, path_id), permit_at(0)); // clears its record
        }
        let comparisons = ADD_PATH_COMPARISONS.with(std::cell::Cell::get);
        let operations = 4 * PATHS as usize;
        // Measured at about 32 comparisons per operation; a per-prefix list would
        // need about PATHS² / 2 comparisons in total.
        assert!(
            comparisons < operations * 64,
            "{comparisons} comparisons for {operations} operations",
        );
        // Re-announcing in order evicts each predecessor again.
        assert_eq!(cache.evicted.add_path.len(), PATHS as usize - 1);
        assert!(matches!(
            cache.lookup(&nth_key(0, PATHS - 1), 0),
            LookupResult::Hit(_)
        ));
    }

    #[test]
    fn replacing_a_live_entry_is_not_an_eviction() {
        let mut cache = ImportDecisionCache::with_capacity(1);
        assert!(!cache.insert(key(1, 0), permit_at(0)));
        assert!(!cache.insert(key(1, 0), deny_at(0)));
        assert_eq!(cache.evictions_since_reset(), 0);
        assert!(matches!(cache.lookup(&key(1, 0), 0), LookupResult::Hit(_)));
        assert!(cache.insert(key(2, 0), permit_at(0)));
        assert_eq!(cache.evictions_since_reset(), 1);
    }

    #[test]
    fn clear_forgets_evictions() {
        let mut cache = ImportDecisionCache::with_capacity(1);
        cache.insert(key(1, 0), permit_at(0));
        cache.insert(key(2, 0), permit_at(0));
        assert!(matches!(cache.lookup(&key(1, 0), 0), LookupResult::Evicted));
        cache.clear();
        assert!(cache.is_unallocated());
        assert_eq!(cache.evictions_since_reset(), 0);
        assert!(matches!(cache.lookup(&key(1, 0), 0), LookupResult::NotSeen));
    }

    #[test]
    fn evicted_memory_past_its_limit_never_claims_not_seen() {
        let mut cache = ImportDecisionCache::with_capacity(1);
        cache.insert(key(1, 0), permit_at(0));
        cache.insert(key(2, 0), permit_at(0)); // evicts key(1)
        // Stand in for EVICTED_KEY_LIMIT real evictions.
        cache.evicted.len = EVICTED_KEY_LIMIT;
        cache.insert(key(3, 0), permit_at(0)); // evicts key(2), unrecorded
        assert!(cache.evicted.overflowed);
        assert!(matches!(cache.lookup(&key(2, 0), 0), LookupResult::Evicted));
        assert!(
            matches!(cache.lookup(&key(99, 0), 0), LookupResult::Evicted),
            "past the limit an unknown key may have been evicted",
        );
        let unknown = cache.lookup_all_paths(Afi::Ipv4, Safi::Unicast, &key(99, 0).prefix, 0);
        assert_eq!(unknown.len(), 1);
        assert!(matches!(unknown[0].result, LookupResult::Evicted));
        assert!(matches!(cache.lookup(&key(3, 0), 0), LookupResult::Hit(_)));
        let live = cache.lookup_all_paths(Afi::Ipv4, Safi::Unicast, &key(3, 0).prefix, 0);
        assert_eq!(live.len(), 1, "a live path is not also reported evicted");
        assert!(matches!(live[0].result, LookupResult::Hit(_)));
        cache.clear();
        assert!(matches!(
            cache.lookup(&key(99, 0), 0),
            LookupResult::NotSeen
        ));
    }
}
