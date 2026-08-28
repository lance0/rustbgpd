//! Import-explain cache write microbenchmarks.
//!
//! The clone component uses the real compact policy context. The cache groups
//! exercise the actual bounded `ImportDecisionCache::insert` seam after the
//! cache is full, with a fresh key and `CachedDecision` for every write. They
//! do not measure full UPDATE decoding or policy evaluation.
//!
//! Requires the off-by-default `bench-internals` feature:
//! `cargo bench -p rustbgpd-transport --features bench-internals --bench explain_snapshot`.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::SystemTime;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rustbgpd_policy::RouteModifications;
use rustbgpd_transport::{
    CachedDecision, CachedOutcome, CachedPolicyContext, ExplainSnapshotBenchCache,
    ImportDecisionKey,
};
use rustbgpd_wire::{
    Afi, AsPath, AsPathSegment, AspaValidation, ExtendedCommunity, Ipv4Prefix, LargeCommunity,
    Prefix, RpkiValidation, Safi,
};

const CACHE_CAPACITY: usize = 4_096;

fn policy_context(as_path_hops: u32, communities: usize) -> CachedPolicyContext {
    let as_path = AsPath {
        segments: vec![AsPathSegment::AsSequence(
            (0..as_path_hops).map(|i| 65_000 + i).collect(),
        )],
    };
    CachedPolicyContext {
        extended_communities: vec![ExtendedCommunity::new(0x0002_FDE8_0000_0064)],
        communities: (0..communities as u32)
            .map(|i| (65_001u32 << 16) | i)
            .collect(),
        large_communities: (0..communities as u32)
            .map(|i| LargeCommunity::new(65_001, i, i + 1))
            .collect(),
        as_path_len: as_path.len(),
        origin_asn: Some(65_000 + as_path_hops.saturating_sub(1)),
        as_path: Some(as_path),
        local_pref: Some(100),
        med: Some(50),
    }
}

fn modifications() -> RouteModifications {
    RouteModifications {
        set_local_pref: Some(200),
        communities_add: vec![(65_001u32 << 16) | 999],
        ..RouteModifications::default()
    }
}

fn decision(context: &CachedPolicyContext, matched_policy: &Arc<str>) -> CachedDecision {
    CachedDecision {
        outcome: CachedOutcome::Permit,
        matched_policy: Some(Arc::clone(matched_policy)),
        rpki: RpkiValidation::NotFound,
        aspa: AspaValidation::Unknown,
        policy_context: context.clone(),
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        modifications: modifications(),
        evaluated_at: SystemTime::now(),
        policy_generation: 1,
    }
}

fn key(path_id: u32) -> ImportDecisionKey {
    ImportDecisionKey {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)),
        path_id,
    }
}

fn full_cache(
    context: &CachedPolicyContext,
    matched_policy: &Arc<str>,
) -> ExplainSnapshotBenchCache {
    let mut cache = ExplainSnapshotBenchCache::with_capacity(CACHE_CAPACITY);
    for path_id in 0..u32::try_from(CACHE_CAPACITY).expect("cache capacity fits u32") {
        cache.insert(key(path_id), decision(context, matched_policy));
    }
    cache
}

fn bench_explain_snapshot(c: &mut Criterion) {
    let mut clones = c.benchmark_group("explain_snapshot_cached_policy_context_clone");
    for (label, hops, communities) in [("typical", 4, 4), ("heavy", 24, 64)] {
        let context = policy_context(hops, communities);
        clones.bench_with_input(
            BenchmarkId::from_parameter(label),
            &context,
            |b, context| {
                b.iter(|| std::hint::black_box(std::hint::black_box(context).clone()));
            },
        );
    }
    clones.finish();

    let mut writes = c.benchmark_group("explain_snapshot_full_cache_insert");
    for (label, hops, communities) in [("typical", 4, 4), ("heavy", 24, 64)] {
        let context = policy_context(hops, communities);
        let matched_policy: Arc<str> = Arc::from("bench-permit");
        let mut cache = full_cache(&context, &matched_policy);
        let mut path_id = u32::try_from(CACHE_CAPACITY).expect("cache capacity fits u32");
        writes.bench_function(label, |b| {
            b.iter(|| {
                cache.insert(
                    key(path_id),
                    decision(
                        std::hint::black_box(&context),
                        std::hint::black_box(&matched_policy),
                    ),
                );
                path_id = path_id.wrapping_add(1);
                std::hint::black_box(&cache);
            });
        });
    }
    writes.finish();
}

criterion_group!(benches, bench_explain_snapshot);
criterion_main!(benches);
