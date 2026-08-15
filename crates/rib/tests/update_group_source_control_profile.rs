#![cfg(feature = "bench-internals")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustbgpd_wire::{Ipv4Prefix, PathAttribute, Prefix};
use rustc_hash::FxHashMap;

struct TrackingAllocator {
    live: AtomicUsize,
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            self.live.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.live.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }
}

#[global_allocator]
static ALLOC: TrackingAllocator = TrackingAllocator {
    live: AtomicUsize::new(0),
};

fn prefix(n: u32) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(n), 32))
}

#[test]
fn passthrough_group_avoids_historical_source_control_collection() {
    const ROUTES: usize = 100_000;
    const MIN_HISTORICAL_BYTES: usize = 3 * 1024 * 1024;

    let source = include_str!("../src/manager/update_groups.rs");
    assert!(source.contains("source_control_passthrough: bool"));
    assert!(source.contains("if !self.source_control_passthrough"));
    assert!(source.contains("source_control_for_route"));

    let safe: FxHashMap<(Prefix, u32), Arc<Vec<PathAttribute>>> = FxHashMap::default();
    assert_eq!((safe.len(), safe.capacity()), (0, 0));

    let shared_attrs = Arc::new(vec![PathAttribute::Communities(vec![1])]);
    let before = ALLOC.live.load(Ordering::Relaxed);
    let mut historical: FxHashMap<(Prefix, u32), Arc<Vec<PathAttribute>>> = FxHashMap::default();
    for n in 0..ROUTES as u32 {
        historical.insert((prefix(n), 0), Arc::clone(&shared_attrs));
    }
    let historical_map_bytes = ALLOC.live.load(Ordering::Relaxed) - before;

    println!(
        "{{\"kind\":\"update_group_source_control_profile\",\"routes\":{ROUTES},\"safe_len\":{},\"safe_capacity\":{},\"historical_capacity\":{},\"historical_map_bytes\":{historical_map_bytes}}}",
        safe.len(),
        safe.capacity(),
        historical.capacity()
    );
    assert_eq!(historical.len(), ROUTES);
    assert!(
        historical_map_bytes >= MIN_HISTORICAL_BYTES,
        "historical source-control map allocated only {historical_map_bytes} bytes"
    );
}
