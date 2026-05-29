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
//! ([`super::super::DEFAULT_EXPLAIN_CACHE_SIZE`] = 4096). When the cap
//! is reached, the least-recently-touched entry is pushed out; its key
//! is recorded in a small lossy recent-eviction ring so a subsequent
//! lookup returns `Evicted` rather than misleading `NotSeen`. The ring
//! is false-positive-only — a stale eviction record cannot mask a
//! genuine entry because every write refreshes the LRU position and
//! takes precedence over the ring.

use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::time::SystemTime;

use lru::LruCache;
use rustbgpd_policy::{PolicyAction, RouteModifications};
use rustbgpd_wire::{Afi, AspaValidation, PathAttribute, Prefix, RpkiValidation, Safi};

/// Default per-peer cap. Per ADR-0073 this is a deliberate fabric /
/// partial-table starter size (hundreds–low-thousands of prefixes fully
/// observable), **not** sized for internet full-table retention — a
/// 100k-prefix peer keeps the cache saturated, so operators wanting
/// reliable full-table explain raise `[policy.explain] cache_size`
/// toward their expected retained-prefix count and own the memory.
pub const DEFAULT_EXPLAIN_CACHE_SIZE: usize = 4096;

/// Bound for the recent-eviction tracker. Small fixed cap — its job is
/// to distinguish "evicted" from "never seen" for entries that just
/// fell out of LRU, not to be an exhaustive eviction log.
const EVICTION_TRACKER_CAPACITY: usize = 512;

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

/// A single cached decision. Carries everything required to render an
/// `ExplainImportPolicyResponse` without consulting any other subsystem.
#[derive(Debug, Clone)]
pub struct CachedDecision {
    pub outcome: CachedOutcome,
    /// Terminal-decision policy name from
    /// [`rustbgpd_policy::PolicyEvaluation::matched_policy`]. `None` =
    /// inline / anonymous.
    pub matched_policy: Option<String>,
    /// RPKI origin-validation state at evaluation time.
    pub rpki: RpkiValidation,
    /// ASPA upstream-path-verification state at evaluation time.
    pub aspa: AspaValidation,
    /// Path attributes exactly as received before policy applied them.
    /// Cloned at the eval site; the original UPDATE-path is unchanged.
    pub pre_policy_attrs: Vec<PathAttribute>,
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
}

/// The session's reply to an explain query. Carries the session's
/// current import-policy generation so the caller can render the
/// top-level `current_policy_generation` field and the per-match
/// staleness is internally consistent with it.
///
/// `matches` is empty only when the prefix was never seen on this
/// session and no eviction record survives — the caller renders that
/// as a single synthetic `NOT_SEEN`.
#[derive(Debug, Clone)]
pub struct ImportExplainReply {
    pub current_generation: u64,
    pub matches: Vec<ResolvedMatch>,
}

/// Bounded per-session LRU of import-policy decisions.
///
/// Not `Send`/`Sync` on its own — the session owns it; cross-task
/// readers (the explain RPC) go through an `Arc<Mutex<…>>` wrapper.
#[derive(Debug)]
pub struct ImportDecisionCache {
    entries: LruCache<ImportDecisionKey, CachedDecision>,
    /// FIFO of recently-evicted keys. False-positive-only by
    /// construction: every `insert` for a key clears it from this ring
    /// before recording the new entry, so the ring can never mask a
    /// genuine live entry.
    recently_evicted: VecDeque<ImportDecisionKey>,
}

impl ImportDecisionCache {
    /// Create a cache with the given per-peer capacity. A zero or
    /// otherwise nonsensical input is clamped to `1` — the cache is
    /// always at least nominally usable.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        let cap = NonZeroUsize::new(cap.max(1)).expect("clamped to at least 1");
        Self {
            entries: LruCache::new(cap),
            recently_evicted: VecDeque::with_capacity(EVICTION_TRACKER_CAPACITY),
        }
    }

    /// Drop every cached decision and the recent-eviction ring.
    ///
    /// Called on session reset (peer flap / `Action::SessionDown`): the
    /// cache is **per-session** diagnostic state, so decisions recorded
    /// on a prior session must not leak into an explain query on the
    /// reconnected session (ADR-0073 "resets on peer session reset").
    /// A reconnecting `PeerSession` is not reconstructed, so without this
    /// a stale decision could answer for any prefix the peer has not yet
    /// re-advertised.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.recently_evicted.clear();
    }

    /// Insert or replace an entry. On capacity overflow the LRU victim
    /// is recorded in the recent-eviction ring so a subsequent
    /// `lookup` for it returns `Evicted` rather than `NotSeen`.
    ///
    /// If the key was previously in the recent-eviction ring, that
    /// stale record is dropped so future lookups see the fresh
    /// decision rather than spuriously reporting `Evicted`.
    pub fn insert(&mut self, key: ImportDecisionKey, decision: CachedDecision) {
        self.drop_eviction_record(&key);
        if let Some((victim_key, _)) = self.entries.push(key, decision) {
            self.record_eviction(victim_key);
        }
    }

    /// Tombstone the entry under `key` as `Withdrawn`. No-op when the
    /// key is absent — withdrawing a prefix we never accepted carries
    /// no operator value.
    ///
    /// The tombstone is **lighter** than a live entry: the pre-policy
    /// attributes and modifications are dropped, keeping only outcome,
    /// matched policy, RPKI/ASPA state, timestamp, and generation. A
    /// peer that churns announce/withdraw/announce therefore can't fill
    /// the bounded LRU with full-payload dead entries that crowd out
    /// live decisions (ADR-0073). The withdrawn route's attributes are
    /// the least useful field for the "why is it gone?" question
    /// anyway.
    pub fn mark_withdrawn(&mut self, key: &ImportDecisionKey) {
        if let Some(decision) = self.entries.get_mut(key) {
            decision.outcome = CachedOutcome::Withdrawn;
            decision.pre_policy_attrs = Vec::new();
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
        if let Some(decision) = self.entries.peek(key) {
            Self::classify(decision.clone(), current_generation)
        } else if self.recently_evicted.iter().any(|k| k == key) {
            LookupResult::Evicted
        } else {
            LookupResult::NotSeen
        }
    }

    /// Resolve every cached path for `(afi, safi, prefix)` — the
    /// Add-Path / "operator omitted `--path-id`" case. Returns one
    /// [`ResolvedMatch`] per live entry, ordered by `path_id` for a
    /// stable response. When no live entry exists but one or more
    /// matching keys are in the recent-eviction ring, returns those as
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
            .filter(|(k, _)| k.afi == afi && k.safi == safi && &k.prefix == prefix)
            .map(|(k, decision)| ResolvedMatch {
                path_id: k.path_id,
                result: Self::classify(decision.clone(), current_generation),
            })
            .collect();
        if matches.is_empty() {
            matches.extend(
                self.recently_evicted
                    .iter()
                    .filter(|k| k.afi == afi && k.safi == safi && &k.prefix == prefix)
                    .map(|k| ResolvedMatch {
                        path_id: k.path_id,
                        result: LookupResult::Evicted,
                    }),
            );
        }
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
        self.entries.len()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn record_eviction(&mut self, key: ImportDecisionKey) {
        if self.recently_evicted.len() == EVICTION_TRACKER_CAPACITY {
            self.recently_evicted.pop_front();
        }
        self.recently_evicted.push_back(key);
    }

    fn drop_eviction_record(&mut self, key: &ImportDecisionKey) {
        self.recently_evicted.retain(|k| k != key);
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
            pre_policy_attrs: Vec::new(),
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
            pre_policy_attrs: Vec::new(),
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
        decision.pre_policy_attrs = vec![PathAttribute::Origin(rustbgpd_wire::Origin::Igp)];
        decision.modifications = RouteModifications {
            set_local_pref: Some(150),
            ..RouteModifications::default()
        };
        cache.insert(key(3, 0), decision);
        cache.mark_withdrawn(&key(3, 0));
        match cache.lookup(&key(3, 0), 0) {
            LookupResult::Hit(d) => {
                assert_eq!(d.outcome, CachedOutcome::Withdrawn);
                assert!(d.pre_policy_attrs.is_empty(), "attrs dropped on withdraw");
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
        // The eviction ring must be false-positive-only — once the
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
}
