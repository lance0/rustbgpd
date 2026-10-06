//! Session-side outbound encode: `send_route_update` grouping, UPDATE build
//! and writer-queue enqueue for one announce-only envelope, against an
//! in-memory writer queue. Only `send_route_update` is timed; draining the
//! queue happens outside the measurement.
//!
//! - `shared_arc`: every route shares one attribute allocation (the common
//!   case: interned source attributes and a pass-scoped export memo).
//! - `equal_values`: equal attribute values behind one allocation per route
//!   (a replay of routes stored across many distribution passes).
//! - `distinct_values`: a distinct MED per route (a diverse table: one
//!   UPDATE per route whatever the grouping key).
//!
//!
//! `failover_encode` times one grouped distribution pass across identical
//! update-group members sharing one encode cell: `announce_only`, and
//! `mixed` (the same announcements plus withdrawals, the shape of a member
//! failover where some prefixes have an alternate source and some do not).
//! Each cell reports the summed session time of all members.
//!
//!   cargo bench -p rustbgpd-transport --features bench-internals --bench outbound_encode

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rustbgpd_rib::AttrSet;
use rustbgpd_rib::{Route, RouteOrigin};
use rustbgpd_transport::{OutboundEncodeBench, OutboundGroupBench};
use rustbgpd_wire::{AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute, Prefix};

/// Benches link the allocator the daemon ships with, so allocation-heavy
/// paths are timed under jemalloc rather than the system allocator.
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn attrs(med: Option<u32>) -> Vec<PathAttribute> {
    let mut attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65_002, 64_600, 64_700])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::Communities(vec![0xFF78_03E8, 0xFDE8_0064]),
    ];
    if let Some(med) = med {
        attrs.push(PathAttribute::Med(med));
    }
    attrs
}

fn routes(count: u32, shape: &str) -> Arc<Vec<Route>> {
    let shared = AttrSet::new(attrs(None));
    (0..count)
        .map(|i| Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from((20 << 24) | (i << 8)), 24)),
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            attributes: match shape {
                "shared_arc" => Arc::clone(&shared),
                "equal_values" => AttrSet::new(attrs(None)),
                _ => AttrSet::new(attrs(Some(i))),
            },
            received_at: rustbgpd_rib::route::ReceivedAt::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            received_as_path: None,
            aspa_context: rustbgpd_rib::route::AspaContextId::DEFAULT,
        })
        .collect::<Vec<_>>()
        .into()
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("outbound_encode");
    for shape in ["shared_arc", "equal_values", "distinct_values"] {
        for count in [100u32, 1_000, 10_000] {
            let announce = routes(count, shape);
            let mut bench = OutboundEncodeBench::new(1 << 16);
            group.throughput(Throughput::Elements(u64::from(count)));
            group.bench_with_input(BenchmarkId::new(shape, count), &announce, |b, announce| {
                b.iter_custom(|iterations| {
                    (0..iterations)
                        .map(|_| bench.send(black_box(announce)))
                        .sum()
                });
            });
        }
    }
    group.finish();
}

/// 50 sources x 40 prefixes, one interned attribute set per source.
fn failover_announce() -> Arc<Vec<Route>> {
    let template = routes(1, "shared_arc")[0].clone();
    (1..=50u8)
        .flat_map(|s| {
            let source = Ipv4Addr::new(10, 1, 0, s);
            let mut source_attrs = attrs(None);
            source_attrs[1] = PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![64_600 + u32::from(s)])],
            });
            source_attrs[2] = PathAttribute::NextHop(source);
            let shared = AttrSet::new(source_attrs);
            let template = template.clone();
            (0..40u32).map(move |j| {
                let i = u32::from(s - 1) * 40 + j;
                Route {
                    prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from((20 << 24) | (i << 8)), 24)),
                    peer: IpAddr::V4(source),
                    next_hop: IpAddr::V4(source),
                    attributes: Arc::clone(&shared),
                    ..template.clone()
                }
            })
        })
        .collect::<Vec<_>>()
        .into()
}

fn failover(c: &mut Criterion) {
    let mut group = c.benchmark_group("failover_encode");
    let announce = failover_announce();
    let withdraw: Vec<(Prefix, u32)> = (0..1_000u32)
        .map(|i| {
            (
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from((30 << 24) | (i << 8)), 24)),
                0,
            )
        })
        .collect();
    for (shape, withdraw) in [("announce_only", &[][..]), ("mixed", &withdraw[..])] {
        for members in [8usize, 32] {
            let mut bench = OutboundGroupBench::new(members, 1 << 16);
            group.bench_function(BenchmarkId::new(shape, members), |b| {
                b.iter_custom(|iterations| {
                    (0..iterations)
                        .map(|_| bench.send(black_box(&announce), black_box(withdraw)))
                        .sum()
                });
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench, failover);
criterion_main!(benches);
