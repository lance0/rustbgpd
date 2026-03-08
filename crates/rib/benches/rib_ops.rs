use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};

use rustbgpd_rib::adj_rib_in::AdjRibIn;
use rustbgpd_rib::adj_rib_out::AdjRibOut;
use rustbgpd_rib::best_path::best_path_cmp;
use rustbgpd_rib::loc_rib::LocRib;
use rustbgpd_rib::route::{Route, RouteOrigin};
use rustbgpd_wire::{
    AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute, Prefix, RpkiValidation,
};

fn generate_prefixes(count: usize) -> Vec<Prefix> {
    (0..count)
        .map(|i| {
            let b1 = ((i >> 8) & 0xFF) as u8;
            let b2 = (i & 0xFF) as u8;
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, b1, b2, 0), 24))
        })
        .collect()
}

fn typical_attributes(peer_idx: u32) -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![
                65000 + peer_idx,
                65100,
                65200,
            ])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, peer_idx as u8, 1)),
        PathAttribute::LocalPref(100),
        PathAttribute::Med(50),
    ]
}

fn make_route(prefix: Prefix, peer_idx: u32) -> Route {
    Route {
        prefix,
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, peer_idx as u8, 1)),
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, peer_idx as u8, 1)),
        attributes: typical_attributes(peer_idx),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::new(10, 0, peer_idx as u8, 1),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
    }
}

fn bench_best_path_cmp(c: &mut Criterion) {
    let mut group = c.benchmark_group("best_path_cmp");
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));

    // Equal routes — full tiebreak path
    let a = make_route(prefix, 1);
    let b = make_route(prefix, 1);
    group.bench_function("equal", |bench| {
        bench.iter(|| {
            for _ in 0..1000 {
                std::hint::black_box(best_path_cmp(&a, &b));
            }
        });
    });

    // LOCAL_PREF difference — early exit at step 1
    let mut b_lp = make_route(prefix, 2);
    b_lp.attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002, 65100, 65200])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 2, 1)),
        PathAttribute::LocalPref(200),
    ];
    group.bench_function("local_pref_diff", |bench| {
        bench.iter(|| {
            for _ in 0..1000 {
                std::hint::black_box(best_path_cmp(&a, &b_lp));
            }
        });
    });

    // Full tiebreak — different peer addresses
    let a2 = make_route(prefix, 1);
    let b2 = make_route(prefix, 2);
    group.bench_function("full_tiebreak", |bench| {
        bench.iter(|| {
            for _ in 0..1000 {
                std::hint::black_box(best_path_cmp(&a2, &b2));
            }
        });
    });

    group.finish();
}

fn bench_adj_rib_in_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("adj_rib_in_insert");
    group.sample_size(10);

    for count in [10_000, 100_000, 500_000] {
        let prefixes = generate_prefixes(count);
        let routes: Vec<Route> = prefixes.iter().map(|p| make_route(*p, 1)).collect();
        group.bench_with_input(BenchmarkId::from_parameter(count), &routes, |b, routes| {
            b.iter_batched(
                || AdjRibIn::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1))),
                |mut rib| {
                    for route in routes {
                        rib.insert(route.clone());
                    }
                    rib
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

fn bench_loc_rib_recompute(c: &mut Criterion) {
    let mut group = c.benchmark_group("loc_rib_recompute");
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));

    for num_candidates in [1, 2, 4, 8] {
        let candidates: Vec<Route> = (0..num_candidates)
            .map(|i| make_route(prefix, i as u32))
            .collect();
        group.bench_with_input(
            BenchmarkId::from_parameter(num_candidates),
            &candidates,
            |b, candidates| {
                b.iter_batched(
                    LocRib::new,
                    |mut rib| {
                        rib.recompute(prefix, candidates.iter());
                        rib
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_rib_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("rib_pipeline");
    group.sample_size(10);

    for count in [1_000, 10_000, 50_000] {
        let prefixes = generate_prefixes(count);
        let peer1_routes: Vec<Route> = prefixes.iter().map(|p| make_route(*p, 1)).collect();
        let peer2_routes: Vec<Route> = prefixes.iter().map(|p| make_route(*p, 2)).collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &(&prefixes, &peer1_routes, &peer2_routes),
            |b, (prefixes, p1_routes, p2_routes)| {
                b.iter_batched(
                    || {
                        (
                            AdjRibIn::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1))),
                            AdjRibIn::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1))),
                            LocRib::new(),
                            AdjRibOut::new(IpAddr::V4(Ipv4Addr::new(10, 0, 3, 1))),
                        )
                    },
                    |(mut rib1, mut rib2, mut loc, mut out)| {
                        // Insert into Adj-RIB-In from two peers
                        for route in *p1_routes {
                            rib1.insert(route.clone());
                        }
                        for route in *p2_routes {
                            rib2.insert(route.clone());
                        }
                        // Recompute best path for each prefix
                        for prefix in *prefixes {
                            let candidates =
                                rib1.iter_prefix(prefix).chain(rib2.iter_prefix(prefix));
                            if loc.recompute(*prefix, candidates)
                                && let Some(best) = loc.get(prefix)
                            {
                                out.insert(best.clone());
                            }
                        }
                        (rib1, rib2, loc, out)
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_route_churn(c: &mut Criterion) {
    let mut group = c.benchmark_group("route_churn");
    group.sample_size(10);

    let base_count = 10_000;
    let churn_count = 1_000;
    let prefixes = generate_prefixes(base_count);
    let base_routes: Vec<Route> = prefixes.iter().map(|p| make_route(*p, 1)).collect();
    let churn_routes: Vec<Route> = prefixes[..churn_count]
        .iter()
        .map(|p| make_route(*p, 2))
        .collect();

    group.bench_function("10k_base_1k_churn", |b| {
        b.iter_batched(
            || {
                let mut rib = AdjRibIn::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)));
                let rib2 = AdjRibIn::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)));
                let mut loc = LocRib::new();
                for route in &base_routes {
                    rib.insert(route.clone());
                }
                for prefix in &prefixes {
                    loc.recompute(*prefix, rib.iter_prefix(prefix));
                }
                (rib, rib2, loc)
            },
            |(rib, mut rib2, mut loc)| {
                // Announce churn routes from peer 2
                for route in &churn_routes {
                    rib2.insert(route.clone());
                }
                for prefix in &prefixes[..churn_count] {
                    let candidates = rib.iter_prefix(prefix).chain(rib2.iter_prefix(prefix));
                    loc.recompute(*prefix, candidates);
                }
                // Withdraw churn routes
                for prefix in &prefixes[..churn_count] {
                    rib2.withdraw(prefix, 0);
                }
                for prefix in &prefixes[..churn_count] {
                    loc.recompute(*prefix, rib.iter_prefix(prefix));
                }
                (rib, rib2, loc)
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_best_path_cmp,
    bench_adj_rib_in_insert,
    bench_loc_rib_recompute,
    bench_rib_pipeline,
    bench_route_churn,
);
criterion_main!(benches);
