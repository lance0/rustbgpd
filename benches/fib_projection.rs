use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use rustbgpd::bench_internals::{FibTableConfig, project_fib_intent_counts};
use rustbgpd_rib::{FibInstallCandidate, FibInstallNextHop, Route, RouteOrigin};
use rustbgpd_wire::{
    AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute, Prefix, RpkiValidation,
};

fn table(name: &str, table_id: u32, metric: u32, allowed_neighbors: &[IpAddr]) -> FibTableConfig {
    FibTableConfig {
        name: name.to_string(),
        table_id,
        metric,
        families: vec!["ipv4_unicast".to_string()],
        allowed_peer_groups: Vec::new(),
        allowed_neighbors: allowed_neighbors
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
        max_routes: None,
        maximum_paths: None,
        maximum_paths_ebgp: None,
        maximum_paths_ibgp: None,
    }
}

fn peer(idx: usize) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, (idx % 250 + 1) as u8))
}

fn prefix(idx: usize) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(
        Ipv4Addr::new(10, ((idx >> 8) & 0xff) as u8, (idx & 0xff) as u8, 0),
        24,
    ))
}

fn attrs(peer_idx: usize) -> Arc<Vec<PathAttribute>> {
    Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![
                65000 + peer_idx as u32,
                65100,
                65200,
            ])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(203, 0, 113, (peer_idx % 250 + 1) as u8)),
        PathAttribute::LocalPref(100),
        PathAttribute::Med(50),
    ])
}

fn route(idx: usize, peer_idx: usize) -> Route {
    let next_hop = IpAddr::V4(Ipv4Addr::new(203, 0, 113, (peer_idx % 250 + 1) as u8));
    Route {
        prefix: prefix(idx),
        next_hop,
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: peer(peer_idx),
        attributes: attrs(peer_idx),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::new(192, 0, 2, (peer_idx % 250 + 1) as u8),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

fn candidate(idx: usize, peer_idx: usize, ecmp_width: usize) -> FibInstallCandidate {
    let best = route(idx, peer_idx);
    let mut next_hops = Vec::with_capacity(ecmp_width.max(1));
    for offset in 0..ecmp_width.max(1) {
        let sibling_peer = peer_idx + offset;
        next_hops.push(FibInstallNextHop {
            next_hop: IpAddr::V4(Ipv4Addr::new(203, 0, 113, (sibling_peer % 250 + 1) as u8)),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: peer(sibling_peer),
            path_id: offset as u32,
            weight: 1,
        });
    }
    FibInstallCandidate { best, next_hops }
}

fn build_inputs(
    tables: usize,
    candidates: usize,
    allowed_peer_count: usize,
    ecmp_width: usize,
) -> (Vec<FibTableConfig>, Vec<FibInstallCandidate>) {
    let allowed = (0..allowed_peer_count).map(peer).collect::<Vec<_>>();
    let tables = (0..tables)
        .map(|idx| table(&format!("edge-{idx}"), 1000 + idx as u32, 200, &allowed))
        .collect::<Vec<_>>();
    let candidates = (0..candidates)
        .map(|idx| candidate(idx, idx % (allowed_peer_count * 2).max(1), ecmp_width))
        .collect::<Vec<_>>();
    (tables, candidates)
}

fn bench_fib_projection(c: &mut Criterion) {
    let peer_groups = BTreeMap::new();
    let cases = [
        ("tables1_routes1k_ecmp1", 1, 1_000, 32, 1),
        ("tables4_routes5k_ecmp1", 4, 5_000, 64, 1),
        ("tables8_routes5k_ecmp4", 8, 5_000, 64, 4),
    ];

    let mut group = c.benchmark_group("fib_projection");
    for (name, table_count, candidate_count, allowed_peer_count, ecmp_width) in cases {
        let (tables, candidates) =
            build_inputs(table_count, candidate_count, allowed_peer_count, ecmp_width);
        group.bench_with_input(BenchmarkId::from_parameter(name), &(), |b, ()| {
            b.iter(|| {
                std::hint::black_box(project_fib_intent_counts(
                    std::hint::black_box(&tables),
                    std::hint::black_box(&candidates),
                    std::hint::black_box(&peer_groups),
                ));
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_fib_projection);
criterion_main!(benches);
