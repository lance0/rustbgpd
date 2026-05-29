//! Microbench for inbound UPDATE attribute-clone churn (PR2).
//!
//! Measures the per-NLRI attribute materialization on the inbound path.
//! Because the pre-PR2 behavior no longer exists on this branch, the
//! bench carries BOTH variants so a single run gives the before/after:
//!
//! - `legacy` — what `process_update` did before: deep-clone the canonical
//!   attribute `Vec` per accepted route and run `apply_modifications`
//!   unconditionally, then `Arc::new`.
//! - `new` — `materialize_attrs`: share the canonical `Arc` when policy made
//!   no modifications (the common case), deep-clone + apply only when it did.
//!
//! Matrix: attr richness (typical / rich) × output count (1 / 100 / 1000
//! NLRI) × modifications (none / one). The headline win is
//! `new/*/no_mods` at high NLRI counts (N `Arc` bumps vs N deep clones).
//!
//! Requires the `bench-internals` feature (exposes `RouteAttrBundle` +
//! `materialize_attrs`):
//!   cargo bench -p rustbgpd-transport --features bench-internals --bench inbound_attrs

use std::hint::black_box;
use std::net::Ipv4Addr;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use rustbgpd_policy::{RouteModifications, apply_modifications};
use rustbgpd_transport::{RouteAttrBundle, materialize_attrs};
use rustbgpd_wire::{
    AsPath, AsPathSegment, ExtendedCommunity, LargeCommunity, Origin, PathAttribute,
};

fn typical_attrs() -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65001, 65002, 65003])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
        PathAttribute::Communities(vec![100, 200]),
    ]
}

fn rich_attrs() -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65001, 65002, 65003, 65004])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
        PathAttribute::Communities(vec![100, 200, 300, 400]),
        PathAttribute::ExtendedCommunities(vec![
            ExtendedCommunity::new(1),
            ExtendedCommunity::new(2),
        ]),
        PathAttribute::LargeCommunities(vec![
            LargeCommunity::new(65001, 1, 2),
            LargeCommunity::new(65001, 3, 4),
        ]),
        PathAttribute::LocalPref(150),
        PathAttribute::Med(42),
    ]
}

fn one_mod() -> RouteModifications {
    RouteModifications {
        set_local_pref: Some(200),
        ..RouteModifications::default()
    }
}

/// New path: share the canonical `Arc` when no mods; clone + apply otherwise.
fn run_new(canonical: &Arc<Vec<PathAttribute>>, mods: &RouteModifications, count: usize) {
    for _ in 0..count {
        let (attrs, nh) = materialize_attrs(canonical, mods);
        black_box((&attrs, &nh));
    }
}

/// Legacy path: deep-clone the canonical `Vec` and apply unconditionally.
fn run_legacy(canonical: &Arc<Vec<PathAttribute>>, mods: &RouteModifications, count: usize) {
    for _ in 0..count {
        let mut attrs = (**canonical).clone();
        let nh = apply_modifications(&mut attrs, mods);
        let attrs = Arc::new(attrs);
        black_box((&attrs, &nh));
    }
}

fn bench_materialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("inbound_attr_materialize");
    for (richness, base) in [("typical", typical_attrs()), ("rich", rich_attrs())] {
        // Body-unicast canonical Arc, shared across the whole UPDATE.
        let bundle = RouteAttrBundle::new(&base, None);
        let canonical = bundle.unicast.clone();
        for (mods_name, mods) in [
            ("no_mods", RouteModifications::default()),
            ("one_mod", one_mod()),
        ] {
            for &count in &[1usize, 100, 1000] {
                group.bench_with_input(
                    BenchmarkId::new(format!("new/{richness}/{mods_name}"), count),
                    &count,
                    |b, &count| b.iter(|| run_new(&canonical, &mods, count)),
                );
                group.bench_with_input(
                    BenchmarkId::new(format!("legacy/{richness}/{mods_name}"), count),
                    &count,
                    |b, &count| b.iter(|| run_legacy(&canonical, &mods, count)),
                );
            }
        }
    }
    group.finish();
}

fn bench_bundle_new(c: &mut Criterion) {
    let mut group = c.benchmark_group("inbound_attr_bundle_new");
    for (richness, base) in [("typical", typical_attrs()), ("rich", rich_attrs())] {
        group.bench_function(BenchmarkId::new("no_otc", richness), |b| {
            b.iter(|| black_box(RouteAttrBundle::new(black_box(&base), None)));
        });
        group.bench_function(BenchmarkId::new("with_otc", richness), |b| {
            b.iter(|| black_box(RouteAttrBundle::new(black_box(&base), Some(65001))));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_materialize, bench_bundle_new);
criterion_main!(benches);
