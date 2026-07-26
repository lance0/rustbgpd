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
//! Bound: two independent caps, both enforced.
//!
//! Entry count: per-peer LRU cap from `[policy.reject_retention]
//! capacity` ([`DEFAULT_REJECT_RETENTION_CAPACITY`] = 1024). A reject
//! storm therefore converges on "the most recent `capacity` rejects",
//! never unbounded growth. The LRU is allocated on the first retained
//! rejection, so a healthy session with no rejected routes pays no
//! backing-store allocation.
//!
//! Entry size: [`RejectedRouteStore::insert`] truncates every entry's
//! wire-derived owned data — a hostile peer with maximal `AS_PATH` /
//! community attributes (worse under RFC 8654 Extended Messages) must
//! not be able to inflate retained entries to multiple KB across
//! hundreds of peers. The rendered AS-path and detail strings are
//! capped at [`MAX_RETAINED_AS_PATH_BYTES`] / [`MAX_RETAINED_DETAIL_BYTES`]
//! (a `…` marker replaces the tail); the community vectors are capped
//! at `MAX_RETAINED_COMMUNITIES` / `MAX_RETAINED_LARGE_COMMUNITIES`
//! with the dropped count recorded so the operator surface can render
//! "…and N more". Memory math with the caps enforced: worst-case heap
//! is 96 + 64 + 16×4 + 8×12 = 320 B, plus the inline key + entry
//! structs — ≤ 512 B per entry, pinned by the size-budget test below.
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

/// Byte cap on a retained entry's rendered `as_path` string, marker
/// included. 96 bytes shows the first ~15 hops of even an all-4-octet
/// path — the leading portion is what identifies the announcement; a
/// hostile maximal `AS_PATH` is exactly what this cap exists to shed.
pub const MAX_RETAINED_AS_PATH_BYTES: usize = 96;

/// Byte cap on a retained entry's `detail` string, marker included.
/// Policy names and gate sub-reason tokens fit comfortably.
pub const MAX_RETAINED_DETAIL_BYTES: usize = 64;

/// Cap on retained standard communities; the excess is counted in
/// [`RejectedRouteEntry::communities_dropped`].
pub const MAX_RETAINED_COMMUNITIES: usize = 16;

/// Cap on retained large communities; the excess is counted in
/// [`RejectedRouteEntry::large_communities_dropped`].
pub const MAX_RETAINED_LARGE_COMMUNITIES: usize = 8;

/// Marker appended to a string field the retention bound truncated.
pub const RETENTION_TRUNCATION_MARKER: char = '…';

/// Truncate `s` to at most `max` bytes on a char boundary, replacing
/// the tail with [`RETENTION_TRUNCATION_MARKER`]. Rebuilds the string
/// so the retained allocation is exact — `String::truncate` alone
/// would keep the original (unbounded) capacity alive.
fn truncate_marked(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    let mut end = max - RETENTION_TRUNCATION_MARKER.len_utf8();
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut bounded = String::with_capacity(end + RETENTION_TRUNCATION_MARKER.len_utf8());
    bounded.push_str(&s[..end]);
    bounded.push(RETENTION_TRUNCATION_MARKER);
    *s = bounded;
}

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
    /// Standard communities from the rejected UPDATE, capped at
    /// `MAX_RETAINED_COMMUNITIES`.
    pub communities: Vec<u32>,
    /// Count of standard communities dropped by the retention cap;
    /// 0 means `communities` is complete.
    pub communities_dropped: u32,
    /// Large communities from the rejected UPDATE, capped at
    /// `MAX_RETAINED_LARGE_COMMUNITIES`.
    pub large_communities: Vec<LargeCommunity>,
    /// Count of large communities dropped by the retention cap;
    /// 0 means `large_communities` is complete.
    pub large_communities_dropped: u32,
    /// RPKI origin-validation state at rejection time.
    pub rpki: RpkiValidation,
    /// ASPA path-verification state at rejection time.
    pub aspa: AspaValidation,
    /// Wall-clock time of the rejection.
    pub rejected_at: SystemTime,
}

impl RejectedRouteEntry {
    /// Enforce the per-entry byte bound: truncate the string fields
    /// (marker appended) and cap the community vectors, recording the
    /// dropped counts. `RejectedRouteStore::insert` applies this to
    /// every entry, so the documented ≤ 512 B budget is a property of
    /// the store, not an assumption about callers. Idempotent — an
    /// already-bounded entry is untouched. Callers that clone one
    /// summary across many rejected identities should call it once
    /// before cloning so the clones are bounded too.
    pub fn enforce_bounds(&mut self) {
        truncate_marked(&mut self.as_path, MAX_RETAINED_AS_PATH_BYTES);
        if let Some(detail) = self.detail.as_mut() {
            truncate_marked(detail, MAX_RETAINED_DETAIL_BYTES);
        }
        if self.communities.len() > MAX_RETAINED_COMMUNITIES {
            self.communities_dropped =
                u32::try_from(self.communities.len() - MAX_RETAINED_COMMUNITIES)
                    .unwrap_or(u32::MAX);
            self.communities.truncate(MAX_RETAINED_COMMUNITIES);
            self.communities.shrink_to_fit();
        }
        if self.large_communities.len() > MAX_RETAINED_LARGE_COMMUNITIES {
            self.large_communities_dropped =
                u32::try_from(self.large_communities.len() - MAX_RETAINED_LARGE_COMMUNITIES)
                    .unwrap_or(u32::MAX);
            self.large_communities
                .truncate(MAX_RETAINED_LARGE_COMMUNITIES);
            self.large_communities.shrink_to_fit();
        }
    }
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
    /// Built on first insert. `LruCache::new` eagerly reserves its hash
    /// index at `capacity`, so constructing it with the session would
    /// charge every peer even when the peer has no rejected routes.
    entries: Option<LruCache<ImportDecisionKey, RejectedRouteEntry>>,
    capacity: usize,
}

impl RejectedRouteStore {
    /// Create a store with the given per-peer capacity, clamped to at
    /// least 1 (same convention as the decision cache).
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        let cap = cap.max(1);
        Self {
            entries: None,
            capacity: cap,
        }
    }

    /// The backing LRU, built at its configured size on first use.
    fn storage(&mut self) -> &mut LruCache<ImportDecisionKey, RejectedRouteEntry> {
        let capacity = NonZeroUsize::new(self.capacity).expect("capacity is clamped to at least 1");
        self.entries.get_or_insert_with(|| LruCache::new(capacity))
    }

    /// Insert or refresh a rejection. On overflow the least-recently
    /// rejected entry is evicted — under a storm the store converges on
    /// the most recent rejects, which is what a "why isn't my route in
    /// right now?" query wants. The entry's byte bound is enforced here
    /// ([`RejectedRouteEntry::enforce_bounds`]), so nothing retained
    /// can exceed the documented per-entry budget.
    pub fn insert(&mut self, key: ImportDecisionKey, mut entry: RejectedRouteEntry) {
        entry.enforce_bounds();
        self.storage().push(key, entry);
    }

    /// Remove the entry for an identity that was subsequently accepted
    /// or explicitly withdrawn. No-op when absent.
    pub fn remove(&mut self, key: &ImportDecisionKey) {
        if let Some(entries) = self.entries.as_mut() {
            entries.pop(key);
        }
    }

    /// Drop everything — session reset, same contract as
    /// [`super::import_decision_cache::ImportDecisionCache::clear`].
    pub fn clear(&mut self) {
        self.entries = None;
    }

    /// Number of retained rejections (the gauge value).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.as_ref().map_or(0, LruCache::len)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.as_ref().is_none_or(LruCache::is_empty)
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
        let mut out: Vec<_> = self.entries.as_ref().map_or_else(Vec::new, |entries| {
            entries
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        });
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

    /// Whether the store has no backing LRU allocation. An empty-store
    /// assertion is insufficient because an eagerly allocated LRU is
    /// empty too.
    #[cfg(test)]
    pub(super) fn is_unallocated(&self) -> bool {
        self.entries.is_none()
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
            communities_dropped: 0,
            large_communities: Vec::new(),
            large_communities_dropped: 0,
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
        assert!(store.is_unallocated());
        store.insert(key(1), entry(ImportRejectReason::PolicyReject));
        store.insert(key(2), entry(ImportRejectReason::PolicyReject));
        assert!(!store.is_unallocated());
        store.remove(&key(1));
        assert_eq!(store.len(), 1);
        store.remove(&key(9)); // absent → no-op
        store.clear();
        assert!(store.is_empty());
        assert!(
            store.is_unallocated(),
            "session reset must release the backing LRU allocation"
        );
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

    /// Maximal wire-derived data is truncated at insert time: strings
    /// carry the marker, community vectors carry the dropped counts,
    /// and an already-bounded entry passes through untouched.
    #[test]
    fn insert_enforces_byte_bounds_with_truncation_markers() {
        let mut store = RejectedRouteStore::with_capacity(4);
        let mut oversized = entry(ImportRejectReason::PolicyReject);
        oversized.as_path = (0..2000).map(|_| "65001 ").collect();
        oversized.detail = Some("p".repeat(500));
        oversized.communities = (0..300).collect();
        oversized.large_communities = (0..300)
            .map(|i| LargeCommunity {
                global_admin: 65001,
                local_data1: i,
                local_data2: 0,
            })
            .collect();
        store.insert(key(1), oversized);
        let (_, bounded) = &store.snapshot()[0];
        assert!(bounded.as_path.len() <= MAX_RETAINED_AS_PATH_BYTES);
        assert!(bounded.as_path.ends_with(RETENTION_TRUNCATION_MARKER));
        let detail = bounded.detail.as_deref().unwrap();
        assert!(detail.len() <= MAX_RETAINED_DETAIL_BYTES);
        assert!(detail.ends_with(RETENTION_TRUNCATION_MARKER));
        assert_eq!(bounded.communities.len(), MAX_RETAINED_COMMUNITIES);
        assert_eq!(
            bounded.communities_dropped as usize,
            300 - MAX_RETAINED_COMMUNITIES
        );
        assert_eq!(
            bounded.large_communities.len(),
            MAX_RETAINED_LARGE_COMMUNITIES
        );
        assert_eq!(
            bounded.large_communities_dropped as usize,
            300 - MAX_RETAINED_LARGE_COMMUNITIES
        );
        assert!(
            bounded.communities.capacity() <= MAX_RETAINED_COMMUNITIES,
            "truncation must release the oversized allocation"
        );

        let mut small = entry(ImportRejectReason::OtcRouteLeak);
        small.as_path = "65001 65002".to_owned();
        small.communities = vec![1, 2, 3];
        store.insert(key(2), small);
        let snap = store.snapshot();
        let (_, kept) = snap.iter().find(|(k, _)| *k == key(2)).unwrap();
        assert_eq!(kept.as_path, "65001 65002", "under-cap fields untouched");
        assert_eq!(kept.communities_dropped, 0);
    }

    /// Pin the documented ≤ 512 B per-entry budget against the real
    /// type sizes: worst-case retained heap under the caps plus the
    /// inline key + entry structs must fit. Fails on any field or cap
    /// change that would silently break the module-doc math.
    #[test]
    fn worst_case_entry_fits_documented_byte_budget() {
        let worst_heap = MAX_RETAINED_AS_PATH_BYTES
            + MAX_RETAINED_DETAIL_BYTES
            + MAX_RETAINED_COMMUNITIES * size_of::<u32>()
            + MAX_RETAINED_LARGE_COMMUNITIES * size_of::<LargeCommunity>();
        let inline = size_of::<ImportDecisionKey>() + size_of::<RejectedRouteEntry>();
        assert!(
            worst_heap + inline <= 512,
            "worst-case entry {worst_heap} heap + {inline} inline bytes exceeds the \
             documented 512 B budget — retune the retention caps"
        );
    }
}
