//! Contested-prefix selection between two neighbors that share one IPv6
//! link-local address on different interfaces, so the scoped tie-break
//! (address, then interface name) resolves through the peer table.
//!
//! Same shape as `rib_ops`'s `contested_prefix_selection/numbered_v6`: a
//! challenger announces every prefix a holder already has, equal through
//! every step above the peer tie-break, and wins, so each prefix's best path
//! changes; only the announcement is timed. The `allocated_numbered`
//! variant is the in-tree reference: allocated handles on distinct
//! addresses, decided at the address. This bench needs generational
//! handles, so it has no pre-handle control; compare its two variants and
//! the absolute figures instead.
//!
//!   cargo bench -p rustbgpd-rib --features bench-internals --bench contested_prefix_scoped

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rustbgpd_rib::route::{Route, RouteOrigin};
use rustbgpd_rib::{AttrSet, PeerEndpoint, PeerId, RibManager};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute, Prefix, RpkiValidation,
};
use tokio::sync::mpsc;

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn prefixes(count: usize) -> Vec<Prefix> {
    (0..count)
        .map(|i| {
            let [_, b0, b1, b2] = u32::try_from(i)
                .expect("fixture index fits u32")
                .to_be_bytes();
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10 + b0, b1, b2, 0), 24))
        })
        .collect()
}

fn route(prefix: Prefix, peer: PeerId, attributes: &Arc<AttrSet>) -> Route {
    Route {
        prefix,
        next_hop: Ipv4Addr::new(10, 0, 1, 1).into(),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer,
        attributes: Arc::clone(attributes),
        received_at: rustbgpd_rib::route::ReceivedAt::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::new(10, 0, 1, 1),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        received_as_path: None,
        aspa_context: rustbgpd_rib::route::AspaContextId::DEFAULT,
    }
}

fn handle(address: &str, interface: Option<&str>) -> PeerId {
    PeerId::allocate(PeerEndpoint::new(
        address.parse().expect("fixture address"),
        interface,
    ))
}

fn bench_contested_prefix_scoped(c: &mut Criterion) {
    let mut group = c.benchmark_group("contested_prefix_selection_scoped");
    group.sample_size(10);
    let attributes = AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65001, 65100, 65200])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 1, 1)),
        PathAttribute::LocalPref(100),
        PathAttribute::Med(50),
    ]);
    // Holder and challenger, allocated holder first so handle order
    // disagrees with the winner.
    let variants = [
        (
            "scoped_same_address",
            handle("fe80::1", Some("eth1")),
            handle("fe80::1", Some("eth0")),
        ),
        (
            "allocated_numbered",
            handle("2001:db8::2", None),
            handle("2001:db8::1", None),
        ),
    ];
    for (name, holder, challenger) in variants {
        for count in [1_000, 100_000] {
            let prefixes = prefixes(count);
            let routes = |peer: PeerId| -> Vec<Route> {
                prefixes
                    .iter()
                    .map(|prefix| route(*prefix, peer, &attributes))
                    .collect()
            };
            let withdrawn: Vec<(Prefix, u32)> = prefixes.iter().map(|p| (*p, 0)).collect();
            let (_tx, rx) = mpsc::channel(8);
            let (_query_tx, query_rx) = mpsc::channel(8);
            let mut manager = RibManager::new(rx, query_rx, None, None, BgpMetrics::new());
            manager.bench_seed_loc_rib(routes(holder));
            manager.bench_seed_loc_rib(routes(challenger));
            assert_eq!(
                manager.bench_best_peer(prefixes[0]),
                Some(challenger),
                "{name}: the challenger must win the tie-break"
            );
            manager.bench_withdraw_loc_rib(challenger, withdrawn.clone());
            assert_eq!(manager.bench_best_peer(prefixes[0]), Some(holder));
            group.bench_function(BenchmarkId::new(name, count), |b| {
                b.iter_custom(|iterations| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iterations {
                        let announced = routes(challenger);
                        let start = std::time::Instant::now();
                        manager.bench_seed_loc_rib(announced);
                        elapsed += start.elapsed();
                        manager.bench_withdraw_loc_rib(challenger, withdrawn.clone());
                    }
                    elapsed
                });
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_contested_prefix_scoped);
criterion_main!(benches);
