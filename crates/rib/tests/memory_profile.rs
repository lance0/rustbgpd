//! Memory profiling for RIB data structures.
//!
//! The high-N profile is an ignored, manual regression harness. It emits JSONL
//! rows that `bench/compare-rib-memory.sh` can compare across git refs:
//!
//! ```text
//! cargo test -p rustbgpd-rib --features bench-internals \
//!   --test memory_profile memory_profile_high_n -- --ignored --nocapture
//! ```
//!
//! A small non-ignored test keeps the profile shapes and JSON schema compiling
//! under ordinary `cargo test`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rustbgpd_rib::adj_rib_in::AdjRibIn;
use rustbgpd_rib::adj_rib_out::AdjRibOut;
use rustbgpd_rib::loc_rib::LocRib;
use rustbgpd_rib::route::{Route, RouteOrigin};
use rustbgpd_wire::{
    AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute, Prefix, RpkiValidation,
};

struct TrackingAllocator {
    inner: System,
    allocated: AtomicUsize,
    peak: AtomicUsize,
}

impl TrackingAllocator {
    const fn new() -> Self {
        Self {
            inner: System,
            allocated: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }

    fn allocated(&self) -> usize {
        self.allocated.load(Ordering::Relaxed)
    }

    fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    fn reset_peak(&self) {
        self.peak
            .store(self.allocated.load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { self.inner.alloc(layout) };
        if !ptr.is_null() {
            let current =
                self.allocated.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            self.peak.fetch_max(current, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.allocated.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { self.inner.dealloc(ptr, layout) };
    }
}

#[global_allocator]
static ALLOC: TrackingAllocator = TrackingAllocator::new();

#[derive(Debug, Clone, Copy)]
struct ComponentStats {
    adj_in_routes: usize,
    adj_in_capacity: usize,
    adj_in_prefix_index_entries: usize,
    adj_in_prefix_index_bytes: usize,
    adj_in_attr_intern_entries: usize,
    adj_in_attr_intern_capacity: usize,
    loc_routes: usize,
    loc_capacity: usize,
    adj_out_routes: usize,
    adj_out_capacity: usize,
    adj_out_prefix_index_entries: usize,
    adj_out_prefix_index_bytes: usize,
}

impl ComponentStats {
    const ZERO: Self = Self {
        adj_in_routes: 0,
        adj_in_capacity: 0,
        adj_in_prefix_index_entries: 0,
        adj_in_prefix_index_bytes: 0,
        adj_in_attr_intern_entries: 0,
        adj_in_attr_intern_capacity: 0,
        loc_routes: 0,
        loc_capacity: 0,
        adj_out_routes: 0,
        adj_out_capacity: 0,
        adj_out_prefix_index_entries: 0,
        adj_out_prefix_index_bytes: 0,
    };
}

#[derive(Debug, Clone)]
struct MemoryRow {
    profile: &'static str,
    shape: &'static str,
    prefixes: usize,
    input_peers: usize,
    output_peers: usize,
    route_copies: usize,
    live_bytes: usize,
    peak_bytes: usize,
    elapsed_ms: u128,
    stats: ComponentStats,
}

impl MemoryRow {
    fn bytes_per_prefix(&self) -> usize {
        self.live_bytes / self.prefixes.max(1)
    }

    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"kind\":\"rib_memory\",",
                "\"profile\":\"{}\",",
                "\"shape\":\"{}\",",
                "\"prefixes\":{},",
                "\"input_peers\":{},",
                "\"output_peers\":{},",
                "\"route_copies\":{},",
                "\"live_bytes\":{},",
                "\"peak_bytes\":{},",
                "\"bytes_per_prefix\":{},",
                "\"elapsed_ms\":{},",
                "\"route_size\":{},",
                "\"prefix_size\":{},",
                "\"path_attribute_size\":{},",
                "\"adj_in_routes\":{},",
                "\"adj_in_capacity\":{},",
                "\"adj_in_prefix_index_entries\":{},",
                "\"adj_in_prefix_index_bytes\":{},",
                "\"adj_in_attr_intern_entries\":{},",
                "\"adj_in_attr_intern_capacity\":{},",
                "\"loc_routes\":{},",
                "\"loc_capacity\":{},",
                "\"adj_out_routes\":{},",
                "\"adj_out_capacity\":{},",
                "\"adj_out_prefix_index_entries\":{},",
                "\"adj_out_prefix_index_bytes\":{}",
                "}}"
            ),
            self.profile,
            self.shape,
            self.prefixes,
            self.input_peers,
            self.output_peers,
            self.route_copies,
            self.live_bytes,
            self.peak_bytes,
            self.bytes_per_prefix(),
            self.elapsed_ms,
            std::mem::size_of::<Route>(),
            std::mem::size_of::<Prefix>(),
            std::mem::size_of::<PathAttribute>(),
            self.stats.adj_in_routes,
            self.stats.adj_in_capacity,
            self.stats.adj_in_prefix_index_entries,
            self.stats.adj_in_prefix_index_bytes,
            self.stats.adj_in_attr_intern_entries,
            self.stats.adj_in_attr_intern_capacity,
            self.stats.loc_routes,
            self.stats.loc_capacity,
            self.stats.adj_out_routes,
            self.stats.adj_out_capacity,
            self.stats.adj_out_prefix_index_entries,
            self.stats.adj_out_prefix_index_bytes,
        )
    }
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
        PathAttribute::Communities(vec![0xFFFF_0001, 0xFFFF_0002]),
    ]
}

fn make_route(prefix: Prefix, peer_idx: u32, attrs: &[PathAttribute]) -> Route {
    Route {
        prefix,
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, peer_idx as u8, 1)),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, peer_idx as u8, 1)),
        attributes: Arc::new(attrs.to_vec()),
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

fn generate_prefixes(count: usize) -> Vec<Prefix> {
    (0..count)
        .map(|i| {
            let b0 = ((i >> 16) & 0xFF) as u8;
            let b1 = ((i >> 8) & 0xFF) as u8;
            let b2 = (i & 0xFF) as u8;
            Prefix::V4(Ipv4Prefix::new(
                Ipv4Addr::new(b0.wrapping_add(1), b1, b2, 0),
                24,
            ))
        })
        .collect()
}

#[cfg(feature = "bench-internals")]
fn adj_in_route_capacity(rib: &AdjRibIn) -> usize {
    rib.bench_route_capacity()
}
#[cfg(not(feature = "bench-internals"))]
fn adj_in_route_capacity(_rib: &AdjRibIn) -> usize {
    0
}

#[cfg(feature = "bench-internals")]
fn adj_in_prefix_index_len(rib: &AdjRibIn) -> usize {
    rib.bench_prefix_index_len()
}
#[cfg(not(feature = "bench-internals"))]
fn adj_in_prefix_index_len(_rib: &AdjRibIn) -> usize {
    0
}

#[cfg(feature = "bench-internals")]
fn adj_in_prefix_index_mem_size(rib: &AdjRibIn) -> usize {
    rib.bench_prefix_index_mem_size()
}
#[cfg(not(feature = "bench-internals"))]
fn adj_in_prefix_index_mem_size(_rib: &AdjRibIn) -> usize {
    0
}

#[cfg(feature = "bench-internals")]
fn adj_in_attr_intern_len(rib: &AdjRibIn) -> usize {
    rib.bench_attr_intern_len()
}
#[cfg(not(feature = "bench-internals"))]
fn adj_in_attr_intern_len(_rib: &AdjRibIn) -> usize {
    0
}

#[cfg(feature = "bench-internals")]
fn adj_in_attr_intern_capacity(rib: &AdjRibIn) -> usize {
    rib.bench_attr_intern_capacity()
}
#[cfg(not(feature = "bench-internals"))]
fn adj_in_attr_intern_capacity(_rib: &AdjRibIn) -> usize {
    0
}

#[cfg(feature = "bench-internals")]
fn loc_route_capacity(rib: &LocRib) -> usize {
    rib.bench_route_capacity()
}
#[cfg(not(feature = "bench-internals"))]
fn loc_route_capacity(_rib: &LocRib) -> usize {
    0
}

#[cfg(feature = "bench-internals")]
fn adj_out_route_capacity(rib: &AdjRibOut) -> usize {
    rib.bench_route_capacity()
}
#[cfg(not(feature = "bench-internals"))]
fn adj_out_route_capacity(_rib: &AdjRibOut) -> usize {
    0
}

#[cfg(feature = "bench-internals")]
fn adj_out_prefix_index_len(rib: &AdjRibOut) -> usize {
    rib.bench_prefix_index_len()
}
#[cfg(not(feature = "bench-internals"))]
fn adj_out_prefix_index_len(_rib: &AdjRibOut) -> usize {
    0
}

#[cfg(feature = "bench-internals")]
fn adj_out_prefix_index_mem_size(rib: &AdjRibOut) -> usize {
    rib.bench_prefix_index_mem_size()
}
#[cfg(not(feature = "bench-internals"))]
fn adj_out_prefix_index_mem_size(_rib: &AdjRibOut) -> usize {
    0
}

fn adj_in_stats(ribs: &[&AdjRibIn]) -> ComponentStats {
    ribs.iter().fold(ComponentStats::ZERO, |mut stats, rib| {
        stats.adj_in_routes += rib.len();
        stats.adj_in_capacity += adj_in_route_capacity(rib);
        stats.adj_in_prefix_index_entries += adj_in_prefix_index_len(rib);
        stats.adj_in_prefix_index_bytes += adj_in_prefix_index_mem_size(rib);
        stats.adj_in_attr_intern_entries += adj_in_attr_intern_len(rib);
        stats.adj_in_attr_intern_capacity += adj_in_attr_intern_capacity(rib);
        stats
    })
}

fn loc_stats(rib: &LocRib) -> ComponentStats {
    ComponentStats {
        loc_routes: rib.len(),
        loc_capacity: loc_route_capacity(rib),
        ..ComponentStats::ZERO
    }
}

fn adj_out_stats(ribs: &[&AdjRibOut]) -> ComponentStats {
    ribs.iter().fold(ComponentStats::ZERO, |mut stats, rib| {
        stats.adj_out_routes += rib.len();
        stats.adj_out_capacity += adj_out_route_capacity(rib);
        stats.adj_out_prefix_index_entries += adj_out_prefix_index_len(rib);
        stats.adj_out_prefix_index_bytes += adj_out_prefix_index_mem_size(rib);
        stats
    })
}

fn merge_stats(parts: &[ComponentStats]) -> ComponentStats {
    parts.iter().fold(ComponentStats::ZERO, |mut total, stats| {
        total.adj_in_routes += stats.adj_in_routes;
        total.adj_in_capacity += stats.adj_in_capacity;
        total.adj_in_prefix_index_entries += stats.adj_in_prefix_index_entries;
        total.adj_in_prefix_index_bytes += stats.adj_in_prefix_index_bytes;
        total.adj_in_attr_intern_entries += stats.adj_in_attr_intern_entries;
        total.adj_in_attr_intern_capacity += stats.adj_in_attr_intern_capacity;
        total.loc_routes += stats.loc_routes;
        total.loc_capacity += stats.loc_capacity;
        total.adj_out_routes += stats.adj_out_routes;
        total.adj_out_capacity += stats.adj_out_capacity;
        total.adj_out_prefix_index_entries += stats.adj_out_prefix_index_entries;
        total.adj_out_prefix_index_bytes += stats.adj_out_prefix_index_bytes;
        total
    })
}

fn measure_adj_rib_in(profile: &'static str, prefixes: &[Prefix]) -> MemoryRow {
    let attrs = typical_attributes(1);
    let baseline = ALLOC.allocated();
    ALLOC.reset_peak();
    let start = Instant::now();

    let mut rib =
        AdjRibIn::with_capacity(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), prefixes.len(), 0);
    for prefix in prefixes {
        rib.insert(make_route(*prefix, 1, &attrs));
    }

    let elapsed_ms = start.elapsed().as_millis();
    let live_bytes = ALLOC.allocated() - baseline;
    let peak_bytes = ALLOC.peak() - baseline;
    let stats = adj_in_stats(&[&rib]);
    let route_copies = stats.adj_in_routes;
    drop(rib);

    MemoryRow {
        profile,
        shape: "adj_rib_in",
        prefixes: prefixes.len(),
        input_peers: 1,
        output_peers: 0,
        route_copies,
        live_bytes,
        peak_bytes,
        elapsed_ms,
        stats,
    }
}

fn measure_full_rib(profile: &'static str, prefixes: &[Prefix]) -> MemoryRow {
    let attrs1 = typical_attributes(1);
    let attrs2 = typical_attributes(2);
    let baseline = ALLOC.allocated();
    ALLOC.reset_peak();
    let start = Instant::now();

    let mut rib1 =
        AdjRibIn::with_capacity(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), prefixes.len(), 0);
    let mut rib2 =
        AdjRibIn::with_capacity(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)), prefixes.len(), 0);
    let mut loc = LocRib::with_capacity(prefixes.len());

    for prefix in prefixes {
        rib1.insert(make_route(*prefix, 1, &attrs1));
        rib2.insert(make_route(*prefix, 2, &attrs2));
    }
    for prefix in prefixes {
        let candidates = rib1.iter_prefix(prefix).chain(rib2.iter_prefix(prefix));
        loc.recompute(*prefix, candidates);
    }

    let elapsed_ms = start.elapsed().as_millis();
    let live_bytes = ALLOC.allocated() - baseline;
    let peak_bytes = ALLOC.peak() - baseline;
    let stats = merge_stats(&[adj_in_stats(&[&rib1, &rib2]), loc_stats(&loc)]);
    let route_copies = stats.adj_in_routes + stats.loc_routes;
    drop(loc);
    drop(rib1);
    drop(rib2);

    MemoryRow {
        profile,
        shape: "full_rib",
        prefixes: prefixes.len(),
        input_peers: 2,
        output_peers: 0,
        route_copies,
        live_bytes,
        peak_bytes,
        elapsed_ms,
        stats,
    }
}

fn measure_rr_fanout(profile: &'static str, prefixes: &[Prefix]) -> MemoryRow {
    let attrs1 = typical_attributes(1);
    let attrs2 = typical_attributes(2);
    let baseline = ALLOC.allocated();
    ALLOC.reset_peak();
    let start = Instant::now();

    let mut rib1 =
        AdjRibIn::with_capacity(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), prefixes.len(), 0);
    let mut rib2 =
        AdjRibIn::with_capacity(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)), prefixes.len(), 0);
    let mut loc = LocRib::with_capacity(prefixes.len());

    for prefix in prefixes {
        rib1.insert(make_route(*prefix, 1, &attrs1));
        rib2.insert(make_route(*prefix, 2, &attrs2));
    }
    for prefix in prefixes {
        let candidates = rib1.iter_prefix(prefix).chain(rib2.iter_prefix(prefix));
        loc.recompute(*prefix, candidates);
    }

    let mut out1 = AdjRibOut::with_capacity(IpAddr::V4(Ipv4Addr::new(10, 0, 11, 1)), loc.len());
    let mut out2 = AdjRibOut::with_capacity(IpAddr::V4(Ipv4Addr::new(10, 0, 12, 1)), loc.len());
    for prefix in prefixes {
        let Some(best) = loc.get(prefix) else {
            continue;
        };
        out1.insert(best.clone());
        out2.insert(best.clone());
    }

    let elapsed_ms = start.elapsed().as_millis();
    let live_bytes = ALLOC.allocated() - baseline;
    let peak_bytes = ALLOC.peak() - baseline;
    let stats = merge_stats(&[
        adj_in_stats(&[&rib1, &rib2]),
        loc_stats(&loc),
        adj_out_stats(&[&out1, &out2]),
    ]);
    let route_copies = stats.adj_in_routes + stats.loc_routes + stats.adj_out_routes;
    drop(out1);
    drop(out2);
    drop(loc);
    drop(rib1);
    drop(rib2);

    MemoryRow {
        profile,
        shape: "rr_fanout",
        prefixes: prefixes.len(),
        input_peers: 2,
        output_peers: 2,
        route_copies,
        live_bytes,
        peak_bytes,
        elapsed_ms,
        stats,
    }
}

fn profile_rows(profile: &'static str, sizes: &[usize]) -> Vec<MemoryRow> {
    let mut rows = Vec::with_capacity(sizes.len() * 3);
    for &size in sizes {
        let prefixes = generate_prefixes(size);
        rows.push(measure_adj_rib_in(profile, &prefixes));
        rows.push(measure_full_rib(profile, &prefixes));
        rows.push(measure_rr_fanout(profile, &prefixes));
        drop(prefixes);
    }
    rows
}

fn configured_profile() -> (&'static str, Vec<usize>) {
    if let Ok(raw) = std::env::var("RUSTBGPD_RIB_MEMORY_SIZES") {
        let sizes: Vec<usize> = raw
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(|part| {
                part.parse::<usize>()
                    .unwrap_or_else(|_| panic!("invalid RUSTBGPD_RIB_MEMORY_SIZES entry: {part}"))
            })
            .collect();
        assert!(
            !sizes.is_empty(),
            "RUSTBGPD_RIB_MEMORY_SIZES must include at least one size"
        );
        return ("custom", sizes);
    }

    match std::env::var("RUSTBGPD_RIB_MEMORY_PROFILE")
        .unwrap_or_else(|_| "full".to_string())
        .as_str()
    {
        "quick" => ("quick", vec![10_000, 100_000]),
        "full" => ("full", vec![100_000, 500_000, 900_000]),
        other => panic!("unknown RUSTBGPD_RIB_MEMORY_PROFILE: {other}"),
    }
}

#[test]
fn memory_profile_schema_quick() {
    let rows = profile_rows("schema", &[512]);
    assert_eq!(rows.len(), 3);

    let adj = rows.iter().find(|row| row.shape == "adj_rib_in").unwrap();
    assert_eq!(adj.prefixes, 512);
    assert_eq!(adj.input_peers, 1);
    assert_eq!(adj.output_peers, 0);
    assert_eq!(adj.route_copies, 512);
    assert_eq!(adj.stats.adj_in_routes, 512);
    assert!(adj.live_bytes > 0);
    assert!(adj.peak_bytes >= adj.live_bytes);
    assert!(adj.to_json().starts_with("{\"kind\":\"rib_memory\""));

    let full = rows.iter().find(|row| row.shape == "full_rib").unwrap();
    assert_eq!(full.input_peers, 2);
    assert_eq!(full.output_peers, 0);
    assert_eq!(full.route_copies, 512 * 3);
    assert_eq!(full.stats.adj_in_routes, 512 * 2);
    assert_eq!(full.stats.loc_routes, 512);

    let rr = rows.iter().find(|row| row.shape == "rr_fanout").unwrap();
    assert_eq!(rr.input_peers, 2);
    assert_eq!(rr.output_peers, 2);
    assert_eq!(rr.route_copies, 512 * 5);
    assert_eq!(rr.stats.adj_out_routes, 512 * 2);
}

#[test]
#[ignore = "manual high-N memory regression harness; use bench/compare-rib-memory.sh"]
fn memory_profile_high_n() {
    let (profile, sizes) = configured_profile();
    for row in profile_rows(profile, &sizes) {
        println!("{}", row.to_json());
    }
}
