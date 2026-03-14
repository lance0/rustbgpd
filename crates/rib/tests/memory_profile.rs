//! Memory profiling for RIB data structures.
//!
//! Measures actual heap allocation per route using a tracking allocator.
//! Run with: cargo test -p rustbgpd-rib --test memory_profile -- --nocapture

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rustbgpd_rib::adj_rib_in::AdjRibIn;
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

fn rich_attributes(peer_idx: u32) -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![65000 + peer_idx, 65100, 65200, 65300, 65400]),
                AsPathSegment::AsSet(vec![65010, 65011]),
            ],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, peer_idx as u8, 1)),
        PathAttribute::LocalPref(100),
        PathAttribute::Med(50),
        PathAttribute::Communities(vec![
            0xFFFF_0001,
            0xFFFF_0002,
            0xFFFF_0003,
            0x0001_0001,
            0x0001_0002,
        ]),
        PathAttribute::OriginatorId(Ipv4Addr::new(10, 0, 0, 1)),
        PathAttribute::ClusterList(vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]),
    ]
}

fn make_route(prefix: Prefix, peer_idx: u32, attrs: &[PathAttribute]) -> Route {
    Route {
        prefix,
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, peer_idx as u8, 1)),
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

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

#[test]
fn memory_profile() {
    println!();
    println!("=== Type Sizes (stack) ===");
    println!("  Route:          {} bytes", std::mem::size_of::<Route>());
    println!("  Prefix:         {} bytes", std::mem::size_of::<Prefix>());
    println!(
        "  PathAttribute:  {} bytes",
        std::mem::size_of::<PathAttribute>()
    );
    println!("  AsPath:         {} bytes", std::mem::size_of::<AsPath>());
    println!(
        "  AsPathSegment:  {} bytes",
        std::mem::size_of::<AsPathSegment>()
    );
    println!(
        "  AdjRibIn:       {} bytes",
        std::mem::size_of::<AdjRibIn>()
    );
    println!("  LocRib:         {} bytes", std::mem::size_of::<LocRib>());
    println!();

    // Measure single route heap allocation
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    let typical_attrs = typical_attributes(1);
    let rich_attrs = rich_attributes(1);

    let before = ALLOC.allocated();
    let _route_typical = make_route(prefix, 1, &typical_attrs);
    let after = ALLOC.allocated();
    let typical_heap = after - before;
    println!("=== Per-Route Heap Allocation ===");
    println!(
        "  Typical (6 attrs, 3-ASN path):  {} bytes heap + {} bytes stack = {} bytes total",
        typical_heap,
        std::mem::size_of::<Route>(),
        typical_heap + std::mem::size_of::<Route>()
    );

    let before = ALLOC.allocated();
    let _route_rich = make_route(prefix, 1, &rich_attrs);
    let after = ALLOC.allocated();
    let rich_heap = after - before;
    println!(
        "  Rich (8 attrs, 5-ASN+SET path): {} bytes heap + {} bytes stack = {} bytes total",
        rich_heap,
        std::mem::size_of::<Route>(),
        rich_heap + std::mem::size_of::<Route>()
    );
    drop(_route_typical);
    drop(_route_rich);
    println!();

    // Measure AdjRibIn at scale
    println!("=== AdjRibIn Memory at Scale (typical attrs) ===");
    for count in [10_000, 100_000, 500_000, 900_000] {
        let prefixes = generate_prefixes(count);

        // Force a GC-like cleanup
        let baseline = ALLOC.allocated();
        ALLOC.reset_peak();

        let mut rib = AdjRibIn::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)));
        for p in &prefixes {
            rib.insert(make_route(*p, 1, &typical_attrs));
        }

        let rib_mem = ALLOC.allocated() - baseline;
        let peak_mem = ALLOC.peak() - baseline;
        let per_route = rib_mem / count;

        println!(
            "  {:>7} routes: {} resident ({} peak), {} per route",
            count,
            format_bytes(rib_mem),
            format_bytes(peak_mem),
            format_bytes(per_route)
        );

        drop(rib);
        drop(prefixes);
    }
    println!();

    // Measure AdjRibIn + LocRib (2 peers)
    println!("=== Full RIB Memory: 2 peers + LocRib (typical attrs) ===");
    for count in [100_000, 500_000, 900_000] {
        let prefixes = generate_prefixes(count);
        let baseline = ALLOC.allocated();
        ALLOC.reset_peak();

        let mut rib1 = AdjRibIn::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)));
        let mut rib2 = AdjRibIn::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)));
        let mut loc = LocRib::new();

        for p in &prefixes {
            rib1.insert(make_route(*p, 1, &typical_attrs));
            rib2.insert(make_route(*p, 2, &typical_attrs));
        }
        for p in &prefixes {
            let candidates = rib1.iter_prefix(p).chain(rib2.iter_prefix(p));
            loc.recompute(*p, candidates);
        }

        let total_mem = ALLOC.allocated() - baseline;
        let peak_mem = ALLOC.peak() - baseline;
        let per_prefix = total_mem / count;

        println!(
            "  {:>7} prefixes x 2 peers: {} resident ({} peak), {} per prefix",
            count,
            format_bytes(total_mem),
            format_bytes(peak_mem),
            format_bytes(per_prefix)
        );

        drop(loc);
        drop(rib1);
        drop(rib2);
        drop(prefixes);
    }
    println!();

    // Comparison context
    println!("=== Comparison Context ===");
    println!("  GoBGP:  8-16+ GB for full table (~800k routes), per GitHub issues");
    println!("  BIRD:   ~325 MB for full table (30 peers x 800k), per bgperf2");
    println!("  FRR:    ~100 MB for 100k routes (10 peers), per bgperf2");
}
