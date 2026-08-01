use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};

use rustbgpd_policy::{PolicyChain, RouteContext, evaluate_chain};
use rustbgpd_rib::adj_rib_in::AdjRibIn;
use rustbgpd_rib::adj_rib_out::AdjRibOut;
use rustbgpd_rib::attr_intern::AttrInternTable;
use rustbgpd_rib::best_path::best_path_cmp;
use rustbgpd_rib::loc_rib::LocRib;
use rustbgpd_rib::route::{Route, RouteOrigin};
use rustbgpd_wire::{
    AsPath, AsPathSegment, ExtendedCommunity, Ipv4Prefix, LargeCommunity, Origin, PathAttribute,
    Prefix, RpkiValidation,
};
use rustc_hash::FxHasher;

fn generate_prefixes(count: usize) -> Vec<Prefix> {
    const PREFIXES_PER_BLOCK: usize = 1 << 16;
    const BLOCKS: usize = 256 - 10;
    assert!(
        count <= PREFIXES_PER_BLOCK * BLOCKS,
        "benchmark prefix space exhausted"
    );
    let prefixes: Vec<_> = (0..count)
        .map(|i| {
            let block =
                u8::try_from(i / PREFIXES_PER_BLOCK).expect("benchmark prefix block fits u8");
            let b1 = ((i >> 8) & 0xFF) as u8;
            let b2 = (i & 0xFF) as u8;
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10 + block, b1, b2, 0), 24))
        })
        .collect();
    assert_eq!(
        prefixes.iter().copied().collect::<HashSet<_>>().len(),
        count,
        "benchmark prefixes must remain unique beyond 65,536"
    );
    prefixes
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

fn rich_attributes(peer_idx: u32) -> Vec<PathAttribute> {
    let mut attrs = typical_attributes(peer_idx);
    attrs.push(PathAttribute::Communities(
        (0..32).map(|i| (65_000_u32 << 16) | i).collect(),
    ));
    attrs.push(PathAttribute::ExtendedCommunities(
        (0..24)
            .map(|i| ExtendedCommunity::new(0x0002_FDE8_0000_0000 | i))
            .collect(),
    ));
    attrs.push(PathAttribute::LargeCommunities(
        (0..16)
            .map(|i| LargeCommunity::new(65_000, 100 + i, 200 + i))
            .collect(),
    ));
    attrs.push(PathAttribute::OriginatorId(Ipv4Addr::new(192, 0, 2, 1)));
    attrs.push(PathAttribute::ClusterList(
        (0..16)
            .map(|i| Ipv4Addr::new(198, 51, 100, i + 1))
            .collect(),
    ));
    attrs.push(PathAttribute::OnlyToCustomer(65_000));
    attrs
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttrProfile {
    Typical,
    Rich,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttrAllocation {
    SharedArc,
    IndependentEqual,
    ManyUnique,
}

#[derive(Clone, Copy, Debug)]
struct AttrCase {
    label: &'static str,
    count: usize,
    profile: AttrProfile,
    allocation: AttrAllocation,
}

const fn attr_case(
    label: &'static str,
    count: usize,
    profile: AttrProfile,
    allocation: AttrAllocation,
) -> AttrCase {
    AttrCase {
        label,
        count,
        profile,
        allocation,
    }
}

const ATTR_CASES: [AttrCase; 7] = [
    attr_case(
        "typical_shared_arc",
        10_000,
        AttrProfile::Typical,
        AttrAllocation::SharedArc,
    ),
    attr_case(
        "typical_independent_equal",
        10_000,
        AttrProfile::Typical,
        AttrAllocation::IndependentEqual,
    ),
    attr_case(
        "rich_shared_arc",
        10_000,
        AttrProfile::Rich,
        AttrAllocation::SharedArc,
    ),
    attr_case(
        "rich_independent_equal",
        10_000,
        AttrProfile::Rich,
        AttrAllocation::IndependentEqual,
    ),
    attr_case(
        "many_unique",
        10_000,
        AttrProfile::Typical,
        AttrAllocation::ManyUnique,
    ),
    attr_case(
        "typical_shared_arc",
        100_000,
        AttrProfile::Typical,
        AttrAllocation::SharedArc,
    ),
    attr_case(
        "typical_independent_equal",
        100_000,
        AttrProfile::Typical,
        AttrAllocation::IndependentEqual,
    ),
];

fn base_attributes(profile: AttrProfile) -> Vec<PathAttribute> {
    match profile {
        AttrProfile::Typical => typical_attributes(1),
        AttrProfile::Rich => rich_attributes(1),
    }
}

fn unique_attributes(index: usize) -> Vec<PathAttribute> {
    let mut attrs = typical_attributes(1);
    let med = attrs
        .iter_mut()
        .find_map(|attr| match attr {
            PathAttribute::Med(value) => Some(value),
            _ => None,
        })
        .expect("typical benchmark attributes contain MED");
    *med = u32::try_from(index).expect("benchmark unique index fits u32");
    attrs
}

fn build_attribute_arcs(case: AttrCase, count: usize) -> Vec<Arc<Vec<PathAttribute>>> {
    match case.allocation {
        AttrAllocation::SharedArc => {
            let attrs = Arc::new(base_attributes(case.profile));
            vec![attrs; count]
        }
        AttrAllocation::IndependentEqual => {
            let attrs = base_attributes(case.profile);
            (0..count).map(|_| Arc::new(attrs.clone())).collect()
        }
        AttrAllocation::ManyUnique => (0..count)
            .map(|index| Arc::new(unique_attributes(index)))
            .collect(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HashObservation {
    digest: u64,
    writes: u64,
    bytes: u64,
}

#[derive(Default)]
struct CountingHasher {
    inner: FxHasher,
    writes: u64,
    bytes: u64,
}

macro_rules! forward_counted_write {
    ($method:ident, $ty:ty) => {
        fn $method(&mut self, value: $ty) {
            self.writes += 1;
            self.bytes += std::mem::size_of::<$ty>() as u64;
            self.inner.$method(value);
        }
    };
}

impl Hasher for CountingHasher {
    fn finish(&self) -> u64 {
        self.inner.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.writes += 1;
        self.bytes += bytes.len() as u64;
        self.inner.write(bytes);
    }

    forward_counted_write!(write_u8, u8);
    forward_counted_write!(write_u16, u16);
    forward_counted_write!(write_u32, u32);
    forward_counted_write!(write_u64, u64);
    forward_counted_write!(write_u128, u128);
    forward_counted_write!(write_usize, usize);
    forward_counted_write!(write_i8, i8);
    forward_counted_write!(write_i16, i16);
    forward_counted_write!(write_i32, i32);
    forward_counted_write!(write_i64, i64);
    forward_counted_write!(write_i128, i128);
    forward_counted_write!(write_isize, isize);
}

fn observe_hash(attrs: &[PathAttribute]) -> HashObservation {
    let mut hasher = CountingHasher::default();
    attrs.hash(&mut hasher);
    HashObservation {
        digest: hasher.finish(),
        writes: hasher.writes,
        bytes: hasher.bytes,
    }
}

fn hash_with_production_hasher(attrs: &[PathAttribute]) -> u64 {
    let mut hasher = FxHasher::default();
    attrs.hash(&mut hasher);
    hasher.finish()
}

fn validate_attr_case(case: AttrCase) {
    let mut attrs = build_attribute_arcs(case, case.count);
    let input_pointers = attrs
        .iter()
        .map(|attrs| Arc::as_ptr(attrs) as usize)
        .collect::<HashSet<_>>()
        .len();
    let input_contents = attrs.iter().map(Arc::as_ref).collect::<HashSet<_>>().len();

    match case.allocation {
        AttrAllocation::SharedArc => {
            assert_eq!(input_pointers, 1, "shared case must reuse one Arc");
            assert_eq!(input_contents, 1, "shared case must have equal content");
        }
        AttrAllocation::IndependentEqual => {
            assert_eq!(input_pointers, case.count, "equal case must start unshared");
            assert_eq!(input_contents, 1, "equal case must have equal content");
        }
        AttrAllocation::ManyUnique => {
            assert_eq!(
                input_pointers, case.count,
                "unique case must start unshared"
            );
            assert_eq!(
                input_contents, case.count,
                "unique content must not collapse"
            );
        }
    }

    let mut table = AttrInternTable::new();
    for value in &mut attrs {
        table.intern(value);
    }
    let output_pointers = attrs
        .iter()
        .map(|attrs| Arc::as_ptr(attrs) as usize)
        .collect::<HashSet<_>>()
        .len();
    let expected = if case.allocation == AttrAllocation::ManyUnique {
        case.count
    } else {
        1
    };
    assert_eq!(
        table.len(),
        expected,
        "intern table length must match content"
    );
    assert_eq!(
        output_pointers, expected,
        "interned pointer roster must match table"
    );
}

fn validate_attr_hash_measurement() {
    let typical_shared = build_attribute_arcs(ATTR_CASES[0], 1);
    let typical_equal = build_attribute_arcs(ATTR_CASES[1], 1);
    let rich_shared = build_attribute_arcs(ATTR_CASES[2], 1);
    let rich_equal = build_attribute_arcs(ATTR_CASES[3], 1);

    let typical_shared_hash = observe_hash(&typical_shared[0]);
    let typical_equal_hash = observe_hash(&typical_equal[0]);
    let rich_shared_hash = observe_hash(&rich_shared[0]);
    let rich_equal_hash = observe_hash(&rich_equal[0]);

    assert!(
        typical_shared_hash.writes > 0 && typical_shared_hash.bytes > 0,
        "attrs.hash must perform counted work"
    );
    assert_eq!(
        typical_shared_hash, typical_equal_hash,
        "shared and independently allocated equal typical attrs must hash identically"
    );
    assert_eq!(
        rich_shared_hash, rich_equal_hash,
        "shared and independently allocated equal rich attrs must hash identically"
    );
    assert_eq!(
        typical_shared_hash.digest,
        hash_with_production_hasher(&typical_shared[0]),
        "counting and timed hash helpers must agree for typical attrs"
    );
    assert_eq!(
        rich_shared_hash.digest,
        hash_with_production_hasher(&rich_shared[0]),
        "counting and timed hash helpers must agree for rich attrs"
    );
    assert!(
        rich_shared_hash.writes > typical_shared_hash.writes,
        "rich attrs must perform more hash writes"
    );
    assert!(
        rich_shared_hash.bytes > typical_shared_hash.bytes,
        "rich attrs must hash more bytes"
    );
    assert_ne!(
        hash_with_production_hasher(&unique_attributes(1)),
        hash_with_production_hasher(&unique_attributes(2)),
        "distinct attribute content must produce distinct fixture digests"
    );

    for case in ATTR_CASES {
        validate_attr_case(case);
    }
    let prefixes = generate_prefixes(100_000);
    assert_eq!(
        prefixes[0],
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24))
    );
    assert_eq!(
        prefixes[65_535],
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 255, 255, 0), 24))
    );
    assert_eq!(
        prefixes[65_536],
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(11, 0, 0, 0), 24))
    );
}

fn make_route(prefix: Prefix, peer_idx: u32) -> Route {
    make_route_with_attributes(prefix, peer_idx, Arc::new(typical_attributes(peer_idx)))
}

fn make_route_with_attributes(
    prefix: Prefix,
    peer_idx: u32,
    attributes: Arc<Vec<PathAttribute>>,
) -> Route {
    Route {
        prefix,
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, peer_idx as u8, 1)),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, peer_idx as u8, 1)),
        attributes,
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::new(10, 0, peer_idx as u8, 1),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

fn route_as_path(route: &Route) -> Option<&AsPath> {
    route.attributes.iter().find_map(|a| match a {
        PathAttribute::AsPath(p) => Some(p),
        _ => None,
    })
}

fn export_ctx(prefix: Prefix, aspath_str: &str) -> RouteContext<'_> {
    RouteContext {
        prefix: Some(prefix),
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: aspath_str,
        as_path: None,
        as_path_len: 0,
        origin_asn: None,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        family: None,
        evpn_route_type: None,
        local_pref: None,
        med: None,
    }
}

fn bench_attr_intern_hashing(c: &mut Criterion) {
    // This is deliberately outside every timed loop. Deleting the real
    // `attrs.hash(&mut hasher)` call makes the executable fail here before it
    // can publish Criterion numbers.
    validate_attr_hash_measurement();

    let mut hash_group = c.benchmark_group("attr_hash_only");
    hash_group.sample_size(10);
    for case in ATTR_CASES {
        let attrs = build_attribute_arcs(case, case.count);
        hash_group.bench_with_input(
            BenchmarkId::new(case.label, case.count),
            &attrs,
            |b, attrs| {
                b.iter(|| {
                    let mut folded = 0_u64;
                    for (index, attrs) in attrs.iter().enumerate() {
                        let digest = hash_with_production_hasher(std::hint::black_box(attrs));
                        folded = folded.rotate_left(1) ^ digest ^ index as u64;
                    }
                    std::hint::black_box(folded)
                });
            },
        );
    }
    hash_group.finish();

    let mut intern_group = c.benchmark_group("attr_intern");
    intern_group.sample_size(10);
    for case in ATTR_CASES {
        let attrs = build_attribute_arcs(case, case.count);
        intern_group.bench_with_input(
            BenchmarkId::new(case.label, case.count),
            &attrs,
            |b, attrs| {
                b.iter_batched(
                    || (attrs.clone(), AttrInternTable::new()),
                    |(mut attrs, mut table)| {
                        for value in &mut attrs {
                            table.intern(value);
                        }
                        std::hint::black_box((attrs, table))
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
    intern_group.finish();
}

fn case_routes(case: AttrCase, peer_idx: u32) -> (Vec<Prefix>, Vec<Route>) {
    let prefixes = generate_prefixes(case.count);
    let attrs = build_attribute_arcs(case, case.count);
    let routes = prefixes
        .iter()
        .zip(attrs)
        .map(|(prefix, attrs)| make_route_with_attributes(*prefix, peer_idx, attrs))
        .collect();
    (prefixes, routes)
}

fn bench_attr_hashing_adj_rib_in_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("attr_hashing_adj_rib_in_insert");
    group.sample_size(10);
    for case in ATTR_CASES {
        let (_, routes) = case_routes(case, 1);
        group.bench_with_input(
            BenchmarkId::new(case.label, case.count),
            &routes,
            |b, routes| {
                b.iter_batched(
                    || {
                        (
                            AdjRibIn::with_capacity(
                                IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
                                routes.len(),
                                0,
                            ),
                            AttrInternTable::new(),
                        )
                    },
                    |(mut rib, mut intern)| {
                        for route in routes {
                            let mut route = route.clone();
                            intern.intern(&mut route.attributes);
                            rib.insert(route);
                        }
                        std::hint::black_box((rib, intern))
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_attr_hashing_bulk_initial_load(c: &mut Criterion) {
    let mut group = c.benchmark_group("attr_hashing_bulk_initial_load");
    group.sample_size(10);
    for case in ATTR_CASES {
        let (prefixes, routes) = case_routes(case, 1);
        group.bench_with_input(
            BenchmarkId::new(case.label, case.count),
            &(&prefixes, &routes),
            |b, (prefixes, routes)| {
                b.iter_batched(
                    || {
                        (
                            AdjRibIn::with_capacity(
                                IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
                                routes.len(),
                                0,
                            ),
                            LocRib::with_capacity(routes.len()),
                            AdjRibOut::with_capacity(
                                IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
                                routes.len(),
                            ),
                            AttrInternTable::new(),
                        )
                    },
                    |(mut rib, mut loc, mut out, mut intern)| {
                        for route in *routes {
                            let mut route = route.clone();
                            intern.intern(&mut route.attributes);
                            rib.insert(route);
                        }
                        for prefix in *prefixes {
                            if loc.recompute(*prefix, rib.iter_prefix(prefix))
                                && let Some(best) = loc.get(prefix)
                            {
                                out.insert(best.clone());
                            }
                        }
                        std::hint::black_box((rib, loc, out, intern))
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_attr_hashing_route_churn(c: &mut Criterion) {
    let mut group = c.benchmark_group("attr_hashing_route_churn");
    group.sample_size(10);
    for case in ATTR_CASES {
        let churn_count = case.count / 10;
        let prefixes = generate_prefixes(case.count);
        let attrs = build_attribute_arcs(case, case.count + churn_count);
        let base_routes: Vec<_> = prefixes
            .iter()
            .zip(attrs[..case.count].iter().cloned())
            .map(|(prefix, attrs)| make_route_with_attributes(*prefix, 1, attrs))
            .collect();
        let churn_routes: Vec<_> = prefixes[..churn_count]
            .iter()
            .zip(attrs[case.count..].iter().cloned())
            .map(|(prefix, attrs)| make_route_with_attributes(*prefix, 2, attrs))
            .collect();

        group.bench_with_input(
            BenchmarkId::new(case.label, case.count),
            &(&prefixes, &base_routes, &churn_routes),
            |b, (prefixes, base_routes, churn_routes)| {
                b.iter_batched(
                    || {
                        let mut rib = AdjRibIn::with_capacity(
                            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
                            base_routes.len(),
                            0,
                        );
                        let rib2 = AdjRibIn::with_capacity(
                            IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
                            churn_routes.len(),
                            0,
                        );
                        let mut loc = LocRib::with_capacity(base_routes.len());
                        let mut intern = AttrInternTable::new();
                        for route in *base_routes {
                            let mut route = route.clone();
                            intern.intern(&mut route.attributes);
                            rib.insert(route);
                        }
                        for prefix in *prefixes {
                            loc.recompute(*prefix, rib.iter_prefix(prefix));
                        }
                        (rib, rib2, loc, intern)
                    },
                    |(rib, mut rib2, mut loc, mut intern)| {
                        for route in *churn_routes {
                            let mut route = route.clone();
                            intern.intern(&mut route.attributes);
                            rib2.insert(route);
                        }
                        for prefix in &prefixes[..churn_count] {
                            let candidates =
                                rib.iter_prefix(prefix).chain(rib2.iter_prefix(prefix));
                            loc.recompute(*prefix, candidates);
                        }
                        for prefix in &prefixes[..churn_count] {
                            rib2.withdraw(prefix, 0);
                        }
                        for prefix in &prefixes[..churn_count] {
                            loc.recompute(*prefix, rib.iter_prefix(prefix));
                        }
                        intern.gc();
                        std::hint::black_box((rib, rib2, loc, intern))
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
    group.finish();
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
    b_lp.attributes = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002, 65100, 65200])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 2, 1)),
        PathAttribute::LocalPref(200),
    ]);
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
                || {
                    (
                        AdjRibIn::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1))),
                        AttrInternTable::new(),
                    )
                },
                |(mut rib, mut intern)| {
                    for route in routes {
                        let mut route = route.clone();
                        intern.intern(&mut route.attributes);
                        rib.insert(route);
                    }
                    (rib, intern)
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
                            AttrInternTable::new(),
                        )
                    },
                    |(mut rib1, mut rib2, mut loc, mut out, mut intern)| {
                        // Insert into Adj-RIB-In from two peers
                        for route in *p1_routes {
                            let mut route = route.clone();
                            intern.intern(&mut route.attributes);
                            rib1.insert(route);
                        }
                        for route in *p2_routes {
                            let mut route = route.clone();
                            intern.intern(&mut route.attributes);
                            rib2.insert(route);
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
                        (rib1, rib2, loc, out, intern)
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_bulk_initial_load(c: &mut Criterion) {
    let mut group = c.benchmark_group("bulk_initial_load");
    group.sample_size(10);

    // Keep this CI-sized. The larger 500k cold-load shape is useful for
    // manual perf work, but 100k is enough to expose scaling regressions
    // without making routine benchmark comparisons drag.
    for count in [10_000, 100_000] {
        let prefixes = generate_prefixes(count);
        let routes: Vec<Route> = prefixes.iter().map(|p| make_route(*p, 1)).collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &(&prefixes, &routes),
            |b, (prefixes, routes)| {
                b.iter_batched(
                    || {
                        (
                            AdjRibIn::with_capacity(
                                IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
                                routes.len(),
                                0,
                            ),
                            LocRib::with_capacity(routes.len()),
                            AdjRibOut::with_capacity(
                                IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
                                routes.len(),
                            ),
                            AttrInternTable::new(),
                        )
                    },
                    |(mut rib, mut loc, mut out, mut intern)| {
                        for route in *routes {
                            let mut route = route.clone();
                            intern.intern(&mut route.attributes);
                            rib.insert(route);
                        }

                        for prefix in *prefixes {
                            if loc.recompute(*prefix, rib.iter_prefix(prefix))
                                && let Some(best) = loc.get(prefix)
                            {
                                out.insert(best.clone());
                            }
                        }

                        (rib, loc, out, intern)
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
                let mut intern = AttrInternTable::new();
                for route in &base_routes {
                    let mut route = route.clone();
                    intern.intern(&mut route.attributes);
                    rib.insert(route);
                }
                for prefix in &prefixes {
                    loc.recompute(*prefix, rib.iter_prefix(prefix));
                }
                (rib, rib2, loc, intern)
            },
            |(rib, mut rib2, mut loc, mut intern)| {
                // Announce churn routes from peer 2
                for route in &churn_routes {
                    let mut route = route.clone();
                    intern.intern(&mut route.attributes);
                    rib2.insert(route);
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
                // Reclaim the withdrawn churn attrs — the manager gc's at
                // this seam, so the benched pipeline does too.
                intern.gc();
                (rib, rib2, loc, intern)
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

// Export-path AS_PATH-string cost: eager (always render) vs lazy (skip when the
// export chain has no AS_PATH regex). The delta is the per-route allocation the
// lazy gate removes — the dominant RR/route-server fanout waste. Self-contained
// (both arms in one run) since a git A/B can't reference the new predicate on a
// pre-change baseline.
fn bench_export_policy_eval(c: &mut Criterion) {
    let mut group = c.benchmark_group("export_policy_eval");
    let routes: Vec<Route> = generate_prefixes(10_000)
        .iter()
        .map(|p| make_route(*p, 1))
        .collect();
    // Empty chain permits all and requires_as_path_string() is false.
    let chain = PolicyChain::new(vec![]);

    group.bench_function("eager_as_path_string", |b| {
        b.iter(|| {
            for route in &routes {
                // black_box the rendered string so the eager arm genuinely pays
                // the allocation even though the empty chain never reads it, and
                // black_box the chain + result so neither is constant-folded away.
                let aspath_str = std::hint::black_box(
                    route_as_path(route).map_or_else(String::new, AsPath::to_aspath_string),
                );
                let ctx = export_ctx(route.prefix, &aspath_str);
                std::hint::black_box(evaluate_chain(Some(std::hint::black_box(&chain)), &ctx));
            }
        });
    });

    group.bench_function("lazy_as_path_string", |b| {
        let needs_as_path_string = chain.requires_as_path_string();
        b.iter(|| {
            for route in &routes {
                let aspath_str = std::hint::black_box(if needs_as_path_string {
                    route_as_path(route).map_or_else(String::new, AsPath::to_aspath_string)
                } else {
                    String::new()
                });
                let ctx = export_ctx(route.prefix, &aspath_str);
                std::hint::black_box(evaluate_chain(Some(std::hint::black_box(&chain)), &ctx));
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_attr_intern_hashing,
    bench_attr_hashing_adj_rib_in_insert,
    bench_attr_hashing_bulk_initial_load,
    bench_attr_hashing_route_churn,
    bench_best_path_cmp,
    bench_adj_rib_in_insert,
    bench_loc_rib_recompute,
    bench_rib_pipeline,
    bench_bulk_initial_load,
    bench_route_churn,
    bench_export_policy_eval,
);
criterion_main!(benches);
