//! Bounded per-session retention of rejected inbound routes (LAN-472).
//!
//! The member-support half of the filtered-route surface: when the
//! import path rejects a unicast announcement — policy deny, OTC
//! route-leak, next-hop ownership, `AS_PATH`/RR loop, or RFC 7606
//! treat-as-withdraw — the identity is retained here together with its
//! canonical [`ImportRejectReason`] token and a compact attribute
//! summary, so `PolicyService.ListRejectedRoutes` (and through it
//! `rbgp rib received <peer> --rejected` and an Alice-LG-style looking
//! glass) can answer "why isn't my route accepted?" without the
//! operator having to know the prefix in advance.
//!
//! Deliberately a sibling of, not an extension to, the ADR-0073
//! [`super::import_decision_cache`]: that LRU mixes permits with denies
//! (a busy peer's accepted prefixes would evict the rejects this
//! surface exists to answer for) and offers only point lookups. This
//! store holds rejects exclusively and supports enumeration.
//!
//! Lifecycle: an entry is inserted (or refreshed) on rejection, removed
//! when the same `(AFI, SAFI, prefix, path_id)` identity is later
//! accepted or explicitly withdrawn, and the whole store resets on
//! session reset — the same per-session contract as the decision cache.
//!
//! Bound: per-peer LRU cap from `[policy.reject_retention] capacity`
//! ([`DEFAULT_REJECT_RETENTION_CAPACITY`] = 1024). A reject storm
//! therefore converges on "the most recent `capacity` rejects", never
//! unbounded growth. Memory math: each entry is one key (~64 B) plus
//! the reason/validation scalars, the AS-path string, and the community
//! vectors — a few hundred bytes for realistic routes, call it ≤ 512 B.
//! `1024 × 512 B ≈ 0.5 MiB` worst case per peer; a 500-peer route
//! server bounds at ~256 MiB only if *every* peer keeps a full storm
//! retained, and operators can lower the cap per deployment.

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::SystemTime;

use lru::LruCache;
use rustbgpd_telemetry::reason_labels::ImportRejectReason;
use rustbgpd_wire::{AspaValidation, LargeCommunity, RpkiValidation};

use super::import_decision_cache::ImportDecisionKey;

/// Default per-peer retention cap. Sized for the realistic
/// member-support case (an IXP member's leaked/misconfigured
/// announcements number in the tens to low thousands), not full-table
/// retention. See the module docs for the memory bound math.
pub const DEFAULT_REJECT_RETENTION_CAPACITY: usize = 1024;

/// One retained rejection: the canonical reason token plus the compact
/// attribute summary a looking glass renders.
///
/// Attribute fields are best-effort: the policy-deny path fills them
/// all; the pre-policy safety gates (loops, treat-as-withdraw) fill
/// what was decodable — the reason token is always present and is the
/// load-bearing answer.
#[derive(Debug, Clone)]
pub struct RejectedRouteEntry {
    /// Canonical rejection mechanism token.
    pub reason: ImportRejectReason,
    /// Sub-mechanism detail: the matched policy name for
    /// `policy_reject`, the canonical sub-reason token for the OTC /
    /// ownership / RR-loop gates, absent otherwise.
    pub detail: Option<String>,
    /// Wire next-hop the rejected announcement carried, when decoded.
    pub next_hop: Option<IpAddr>,
    /// Lossless `AS_PATH` rendering (`AsPath::to_aspath_string`), empty
    /// when the UPDATE carried none or the attribute was not decodable.
    pub as_path: String,
    /// Standard communities from the rejected UPDATE.
    pub communities: Vec<u32>,
    /// Large communities from the rejected UPDATE.
    pub large_communities: Vec<LargeCommunity>,
    /// RPKI origin-validation state at rejection time.
    pub rpki: RpkiValidation,
    /// ASPA path-verification state at rejection time.
    pub aspa: AspaValidation,
    /// Wall-clock time of the rejection.
    pub rejected_at: SystemTime,
}

/// The session's reply to a `ListRejectedRoutes` query.
#[derive(Debug, Clone)]
pub struct RejectedRoutesReply {
    /// Whether this session retains rejected routes at all
    /// (`[policy.reject_retention] enabled`, snapshotted at session
    /// build). `false` means an empty listing is a configuration fact,
    /// not "nothing was rejected".
    pub enabled: bool,
    /// The session's retention cap, so the caller can render "showing
    /// the most recent N" honestly when the store is full.
    pub capacity: usize,
    /// Every retained rejection, sorted by key for stable output.
    pub entries: Vec<(ImportDecisionKey, RejectedRouteEntry)>,
}

/// Bounded per-session LRU of rejected inbound routes.
///
/// Not `Send`/`Sync` on its own — the session owns it and services
/// queries on its command path, exactly like the import-decision cache.
#[derive(Debug)]
pub struct RejectedRouteStore {
    entries: LruCache<ImportDecisionKey, RejectedRouteEntry>,
    capacity: usize,
}

impl RejectedRouteStore {
    /// Create a store with the given per-peer capacity, clamped to at
    /// least 1 (same convention as the decision cache).
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        let cap = cap.max(1);
        Self {
            entries: LruCache::new(NonZeroUsize::new(cap).expect("clamped to at least 1")),
            capacity: cap,
        }
    }

    /// Insert or refresh a rejection. On overflow the least-recently
    /// rejected entry is evicted — under a storm the store converges on
    /// the most recent rejects, which is what a "why isn't my route in
    /// right now?" query wants.
    pub fn insert(&mut self, key: ImportDecisionKey, entry: RejectedRouteEntry) {
        self.entries.push(key, entry);
    }

    /// Remove the entry for an identity that was subsequently accepted
    /// or explicitly withdrawn. No-op when absent.
    pub fn remove(&mut self, key: &ImportDecisionKey) {
        self.entries.pop(key);
    }

    /// Drop everything — session reset, same contract as
    /// [`super::import_decision_cache::ImportDecisionCache::clear`].
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Number of retained rejections (the gauge value).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The configured cap, echoed on the query reply.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Clone out every retained rejection, sorted by
    /// `(AFI, SAFI, prefix, path_id)` for a stable listing. Bounded by
    /// the cap, so the clone is fine for a diagnostic query path.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(ImportDecisionKey, RejectedRouteEntry)> {
        let mut out: Vec<_> = self
            .entries
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        out.sort_by(|(a, _), (b, _)| {
            (a.afi as u16, a.safi as u8, a.prefix, a.path_id).cmp(&(
                b.afi as u16,
                b.safi as u8,
                b.prefix,
                b.path_id,
            ))
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rustbgpd_wire::{Afi, Ipv4Prefix, Prefix, Safi};

    use super::*;

    fn key(octet: u8) -> ImportDecisionKey {
        ImportDecisionKey {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, octet), 32)),
            path_id: 0,
        }
    }

    fn entry(reason: ImportRejectReason) -> RejectedRouteEntry {
        RejectedRouteEntry {
            reason,
            detail: None,
            next_hop: None,
            as_path: String::new(),
            communities: Vec::new(),
            large_communities: Vec::new(),
            rpki: RpkiValidation::NotFound,
            aspa: AspaValidation::Unknown,
            rejected_at: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn insert_then_snapshot_returns_entry() {
        let mut store = RejectedRouteStore::with_capacity(4);
        store.insert(key(1), entry(ImportRejectReason::PolicyReject));
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, key(1));
        assert_eq!(snap[0].1.reason, ImportRejectReason::PolicyReject);
    }

    #[test]
    fn cap_evicts_least_recent_reject() {
        let mut store = RejectedRouteStore::with_capacity(2);
        store.insert(key(1), entry(ImportRejectReason::PolicyReject));
        store.insert(key(2), entry(ImportRejectReason::OtcRouteLeak));
        store.insert(key(3), entry(ImportRejectReason::AsPathLoop));
        assert_eq!(store.len(), 2, "bounded at capacity");
        let keys: Vec<_> = store.snapshot().into_iter().map(|(k, _)| k).collect();
        assert!(!keys.contains(&key(1)), "oldest reject evicted");
        assert!(keys.contains(&key(2)) && keys.contains(&key(3)));
    }

    #[test]
    fn reinsert_refreshes_lru_position() {
        let mut store = RejectedRouteStore::with_capacity(2);
        store.insert(key(1), entry(ImportRejectReason::PolicyReject));
        store.insert(key(2), entry(ImportRejectReason::PolicyReject));
        // Refresh key(1); key(2) becomes the LRU victim.
        store.insert(key(1), entry(ImportRejectReason::RrLoop));
        store.insert(key(3), entry(ImportRejectReason::PolicyReject));
        let keys: Vec<_> = store.snapshot().into_iter().map(|(k, _)| k).collect();
        assert!(keys.contains(&key(1)), "refreshed entry survives");
        assert!(!keys.contains(&key(2)), "stale entry evicted");
    }

    #[test]
    fn remove_and_clear() {
        let mut store = RejectedRouteStore::with_capacity(4);
        store.insert(key(1), entry(ImportRejectReason::PolicyReject));
        store.insert(key(2), entry(ImportRejectReason::PolicyReject));
        store.remove(&key(1));
        assert_eq!(store.len(), 1);
        store.remove(&key(9)); // absent → no-op
        store.clear();
        assert!(store.is_empty());
    }

    #[test]
    fn snapshot_is_sorted_by_key() {
        let mut store = RejectedRouteStore::with_capacity(8);
        store.insert(key(9), entry(ImportRejectReason::PolicyReject));
        store.insert(key(1), entry(ImportRejectReason::PolicyReject));
        store.insert(key(5), entry(ImportRejectReason::PolicyReject));
        let keys: Vec<_> = store.snapshot().into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec![key(1), key(5), key(9)]);
    }

    #[test]
    fn zero_capacity_is_clamped_to_at_least_one() {
        let mut store = RejectedRouteStore::with_capacity(0);
        store.insert(key(1), entry(ImportRejectReason::PolicyReject));
        assert_eq!(store.len(), 1);
        assert_eq!(store.capacity(), 1);
    }
}
