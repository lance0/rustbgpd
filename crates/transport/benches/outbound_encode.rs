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
//!   cargo bench -p rustbgpd-transport --features bench-internals --bench outbound_encode

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rustbgpd_rib::AttrSet;
use rustbgpd_rib::{Route, RouteOrigin};
use rustbgpd_transport::OutboundEncodeBench;
use rustbgpd_wire::{AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute, Prefix};

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

fn routes(count: u32, shape: &str) -> Arc<[Route]> {
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
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        })
        .collect()
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

criterion_group!(benches, bench);
criterion_main!(benches);
