//! Criterion benchmark for the ADR-0073 import-explain snapshot cost.
//!
//! When `[policy.explain].enabled` is true, the transport eval site does
//! the following per accepted/denied NLRI before broadcasting the route:
//! clone the compact pre-policy policy context, clone the policy
//! `RouteModifications`, and stamp a timestamp — then insert into the
//! per-session decision cache. The `enabled = false` gate avoids exactly
//! that work. This bench measures
//! `context.clone() + mods.clone() + SystemTime::now()` over a typical
//! and a heavy route shape — a synthetic proxy for the per-NLRI
//! overhead, deliberately *not* reaching into transport internals (the
//! cache type stays private to the session).
//!
//! Empirically the cost is **allocation- and timestamp-bound, roughly
//! flat across route complexity** (the typical and heavy shapes land
//! within noise of each other): the three small `Vec` allocations and
//! the `SystemTime::now()` call dominate, and the per-element copy of
//! longer AS_PATH strings / larger community sets is in the
//! sub-nanosecond margin. The takeaway is a bounded per-NLRI figure for
//! the explain-enabled write, not a scaling curve.
//!
//! Run: `cargo bench -p rustbgpd-policy --bench explain_snapshot`.

use std::net::Ipv4Addr;
use std::time::SystemTime;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use rustbgpd_policy::RouteModifications;
use rustbgpd_wire::{AsPath, AsPathSegment, ExtendedCommunity, LargeCommunity};

#[allow(
    dead_code,
    reason = "criterion measures clone cost; fields are intentionally retained by black_box"
)]
#[derive(Clone)]
struct ExplainSnapshotContext {
    extended_communities: Vec<ExtendedCommunity>,
    communities: Vec<u32>,
    large_communities: Vec<LargeCommunity>,
    as_path_str: String,
    as_path_len: usize,
    local_pref: Option<u32>,
    med: Option<u32>,
    next_hop: Option<Ipv4Addr>,
}

/// A route's compact pre-policy context with `as_path_hops` AS_PATH hops
/// and `communities` standard/large communities — the two dimensions
/// that dominate the clone cost in practice.
fn route_context(as_path_hops: u32, communities: usize) -> ExplainSnapshotContext {
    let as_path = AsPath {
        segments: vec![AsPathSegment::AsSequence(
            (0..as_path_hops).map(|i| 65000 + i).collect(),
        )],
    };
    ExplainSnapshotContext {
        extended_communities: vec![ExtendedCommunity::new(0x0002_FDE8_0000_0064)],
        communities: (0..communities as u32)
            .map(|i| (65001u32 << 16) | i)
            .collect(),
        large_communities: (0..communities as u32)
            .map(|i| LargeCommunity::new(65001, i, i + 1))
            .collect(),
        as_path_str: as_path.to_aspath_string(),
        as_path_len: as_path.len(),
        local_pref: Some(100),
        med: Some(50),
        next_hop: Some(Ipv4Addr::new(10, 0, 0, 2)),
    }
}

/// A modest policy outcome: a couple of applied changes, the common
/// shape on an accepted route.
fn typical_mods() -> RouteModifications {
    RouteModifications {
        set_local_pref: Some(200),
        communities_add: vec![(65001u32 << 16) | 999],
        ..RouteModifications::default()
    }
}

fn bench_explain_snapshot(c: &mut Criterion) {
    let mut group = c.benchmark_group("explain_snapshot_clone");
    // (as_path_hops, communities): a typical eBGP route vs a heavy one.
    for (label, hops, comms) in [("typical", 4u32, 4usize), ("heavy", 24, 64)] {
        let context = route_context(hops, comms);
        let mods = typical_mods();
        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &(context, mods),
            |b, (context, mods)| {
                b.iter(|| {
                    // Mirror the eval-site explain write (minus the cache
                    // insert): clone the pre-policy context + modifications
                    // and stamp the time.
                    let snap_context = std::hint::black_box(context).clone();
                    let snap_mods = std::hint::black_box(mods).clone();
                    let at = SystemTime::now();
                    std::hint::black_box((snap_context, snap_mods, at));
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_explain_snapshot);
criterion_main!(benches);
