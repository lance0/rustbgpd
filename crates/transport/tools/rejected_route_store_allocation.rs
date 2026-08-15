//! Sequential manual proof for rejected-route store allocation behavior.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use lru::LruCache;
use rustbgpd_telemetry::reason_labels::ImportRejectReason;
use rustbgpd_wire::{Afi, AspaValidation, Ipv4Prefix, Prefix, RpkiValidation, Safi};

#[path = "../src/session/import_decision_cache.rs"]
pub mod import_decision_cache;
#[path = "../src/session/rejected_routes.rs"]
pub mod rejected_routes;

use import_decision_cache::ImportDecisionKey;
use rejected_routes::{DEFAULT_REJECT_RETENTION_CAPACITY, RejectedRouteEntry, RejectedRouteStore};

struct RequestedAllocator;

static LIVE_REQUESTED_BYTES: AtomicUsize = AtomicUsize::new(0);
static ALLOCATION_REQUESTS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every operation delegates to `System` with the original layout and
// only updates atomics after a successful allocation or before a matching
// deallocation. The wrapper neither dereferences nor changes returned pointers.
unsafe impl GlobalAlloc for RequestedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATION_REQUESTS.fetch_add(1, Ordering::SeqCst);
        // SAFETY: delegation preserves the allocator contract and layout.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE_REQUESTED_BYTES.fetch_add(layout.size(), Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` was allocated by this wrapper's `System` delegate with
        // the same layout, as required by `GlobalAlloc`.
        unsafe { System.dealloc(ptr, layout) };
        LIVE_REQUESTED_BYTES.fetch_sub(layout.size(), Ordering::SeqCst);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATION_REQUESTS.fetch_add(1, Ordering::SeqCst);
        // SAFETY: delegation preserves the original allocation and layout and
        // passes the requested replacement size through unchanged.
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            if new_size >= layout.size() {
                LIVE_REQUESTED_BYTES.fetch_add(new_size - layout.size(), Ordering::SeqCst);
            } else {
                LIVE_REQUESTED_BYTES.fetch_sub(layout.size() - new_size, Ordering::SeqCst);
            }
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOCATOR: RequestedAllocator = RequestedAllocator;

type EagerStore = LruCache<ImportDecisionKey, RejectedRouteEntry>;

fn key(path_id: u32) -> ImportDecisionKey {
    ImportDecisionKey {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 1), 32)),
        path_id,
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
        aspa_invalid_hop: None,
        rejected_at: SystemTime::UNIX_EPOCH,
    }
}

fn eager(capacity: usize) -> EagerStore {
    LruCache::new(NonZeroUsize::new(capacity).unwrap())
}

fn insert_both(
    candidate: &mut RejectedRouteStore,
    oracle: &mut EagerStore,
    path_id: u32,
    reason: ImportRejectReason,
) {
    candidate.insert(key(path_id), entry(reason));
    oracle.push(key(path_id), entry(reason));
}

fn candidate_snapshot(store: &RejectedRouteStore) -> Vec<(ImportDecisionKey, ImportRejectReason)> {
    store
        .snapshot()
        .into_iter()
        .map(|(key, entry)| (key, entry.reason))
        .collect()
}

fn oracle_snapshot(store: &EagerStore) -> Vec<(ImportDecisionKey, ImportRejectReason)> {
    let mut snapshot: Vec<_> = store
        .iter()
        .map(|(key, entry)| (key.clone(), entry.reason))
        .collect();
    snapshot.sort_by(|(a, _), (b, _)| {
        (a.afi as u16, a.safi as u8, a.prefix, a.path_id).cmp(&(
            b.afi as u16,
            b.safi as u8,
            b.prefix,
            b.path_id,
        ))
    });
    snapshot
}

fn assert_parity(candidate: &RejectedRouteStore, oracle: &EagerStore) {
    assert_eq!(candidate.len(), oracle.len());
    assert!(candidate.len() <= candidate.capacity());
    assert_eq!(candidate_snapshot(candidate), oracle_snapshot(oracle));
}

fn lazy_store_matches_bounded_lru_semantics() {
    const CAPACITY: usize = 1024;
    let mut candidate = RejectedRouteStore::with_capacity(CAPACITY);
    let mut oracle = eager(CAPACITY);

    for path_id in 0..CAPACITY as u32 {
        insert_both(
            &mut candidate,
            &mut oracle,
            path_id,
            ImportRejectReason::PolicyReject,
        );
        assert_eq!(candidate.len(), usize::try_from(path_id).unwrap() + 1);
        assert!(candidate.len() <= CAPACITY);
    }
    assert_parity(&candidate, &oracle);

    insert_both(
        &mut candidate,
        &mut oracle,
        CAPACITY as u32,
        ImportRejectReason::AsPathLoop,
    );
    assert_parity(&candidate, &oracle);
    let keys: Vec<_> = candidate
        .snapshot()
        .into_iter()
        .map(|(key, _)| key.path_id)
        .collect();
    assert_eq!(keys.len(), CAPACITY);
    assert!(!keys.contains(&0), "the exact oldest key must be evicted");
    assert!(keys.contains(&(CAPACITY as u32)));

    insert_both(&mut candidate, &mut oracle, 1, ImportRejectReason::RrLoop);
    insert_both(
        &mut candidate,
        &mut oracle,
        CAPACITY as u32 + 1,
        ImportRejectReason::OtcRouteLeak,
    );
    assert_parity(&candidate, &oracle);
    let refreshed = candidate_snapshot(&candidate);
    assert!(
        refreshed
            .iter()
            .any(|(key, reason)| { key.path_id == 1 && *reason == ImportRejectReason::RrLoop })
    );
    assert!(
        !refreshed.iter().any(|(key, _)| key.path_id == 2),
        "refreshing key 1 must make key 2 the exact next victim"
    );

    candidate.remove(&key(500));
    oracle.pop(&key(500));
    assert_parity(&candidate, &oracle);

    candidate.clear();
    oracle.clear();
    assert_parity(&candidate, &oracle);
    assert_eq!(candidate.capacity(), CAPACITY);
    insert_both(
        &mut candidate,
        &mut oracle,
        77,
        ImportRejectReason::TreatAsWithdraw,
    );
    assert_parity(&candidate, &oracle);

    let mut one = RejectedRouteStore::with_capacity(1);
    let mut one_oracle = eager(1);
    insert_both(
        &mut one,
        &mut one_oracle,
        7,
        ImportRejectReason::PolicyReject,
    );
    insert_both(&mut one, &mut one_oracle, 7, ImportRejectReason::RrLoop);
    assert_parity(&one, &one_oracle);
    insert_both(
        &mut one,
        &mut one_oracle,
        8,
        ImportRejectReason::NextHopOwnership,
    );
    assert_parity(&one, &one_oracle);
    assert_eq!(candidate_snapshot(&one)[0].0, key(8));
    one.remove(&key(8));
    one_oracle.pop(&key(8));
    assert_parity(&one, &one_oracle);
    one.clear();
    one_oracle.clear();
    insert_both(&mut one, &mut one_oracle, 9, ImportRejectReason::AsPathLoop);
    assert_parity(&one, &one_oracle);
}

fn requested_live<T>(build: impl FnOnce() -> T) -> (T, usize) {
    let before = LIVE_REQUESTED_BYTES.load(Ordering::SeqCst);
    let value = build();
    let after = LIVE_REQUESTED_BYTES.load(Ordering::SeqCst);
    (value, after.checked_sub(before).unwrap())
}

fn saturated_candidate(capacity: usize) -> RejectedRouteStore {
    let mut store = RejectedRouteStore::with_capacity(capacity);
    for path_id in 0..capacity as u32 {
        store.insert(key(path_id), entry(ImportRejectReason::PolicyReject));
    }
    store
}

fn saturated_eager(capacity: usize) -> EagerStore {
    let mut store = eager(capacity);
    for path_id in 0..capacity as u32 {
        store.push(key(path_id), entry(ImportRejectReason::PolicyReject));
    }
    store
}

fn lazy_store_releases_default_reservation_without_saturated_allocations() {
    let (first_candidate, candidate_first_live) = requested_live(|| {
        let mut store = RejectedRouteStore::with_capacity(DEFAULT_REJECT_RETENTION_CAPACITY);
        store.insert(key(0), entry(ImportRejectReason::PolicyReject));
        store
    });
    assert_eq!(first_candidate.len(), 1);
    black_box(&first_candidate);
    drop(first_candidate);

    let (first_eager, eager_first_live) = requested_live(|| {
        let mut store = eager(DEFAULT_REJECT_RETENTION_CAPACITY);
        store.push(key(0), entry(ImportRejectReason::PolicyReject));
        store
    });
    assert_eq!(first_eager.len(), 1);
    black_box(&first_eager);
    drop(first_eager);
    assert!(
        eager_first_live >= candidate_first_live + 24_576,
        "default first entry saved only {} requested-live bytes (candidate {candidate_first_live}, eager {eager_first_live})",
        eager_first_live.saturating_sub(candidate_first_live)
    );

    for capacity in [1, 16, 128, 1024] {
        let (candidate, candidate_live) = requested_live(|| saturated_candidate(capacity));
        assert_eq!(candidate.len(), capacity);
        black_box(&candidate);
        drop(candidate);

        let (oracle, eager_live) = requested_live(|| saturated_eager(capacity));
        assert_eq!(oracle.len(), capacity);
        black_box(&oracle);
        drop(oracle);

        assert!(
            candidate_live <= eager_live,
            "capacity {capacity}: lazy saturated store retained {candidate_live} requested bytes, eager retained {eager_live}"
        );
    }

    let mut candidate = saturated_candidate(1024);
    let mut oracle = saturated_eager(1024);
    let candidate_key = key(1024);
    let candidate_entry = entry(ImportRejectReason::AsPathLoop);
    let before_candidate = ALLOCATION_REQUESTS.load(Ordering::SeqCst);
    candidate.insert(candidate_key, candidate_entry);
    let candidate_requests = ALLOCATION_REQUESTS.load(Ordering::SeqCst) - before_candidate;

    let oracle_key = key(1024);
    let oracle_entry = entry(ImportRejectReason::AsPathLoop);
    let before_oracle = ALLOCATION_REQUESTS.load(Ordering::SeqCst);
    let evicted = oracle.push(oracle_key, oracle_entry);
    let oracle_requests = ALLOCATION_REQUESTS.load(Ordering::SeqCst) - before_oracle;

    assert_eq!(
        candidate_requests, 0,
        "bounded candidate must reuse storage"
    );
    assert_eq!(
        oracle_requests, 0,
        "bounded eager oracle must reuse storage"
    );
    assert!(evicted.is_some());
    assert_parity(&candidate, &oracle);
}

fn main() {
    lazy_store_matches_bounded_lru_semantics();
    lazy_store_releases_default_reservation_without_saturated_allocations();
}
