#![cfg(feature = "bench-internals")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustbgpd_wire::{Ipv4Prefix, Prefix};
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
fn labelled_staged_routes_have_zero_per_route_permit_label_collection() {
    const ROUTES: usize = 100_000;
    const FOUR_MIB: usize = 4 * 1024 * 1024;

    // Structural pin: production owns one group label and neither historical
    // route-keyed Permit-label collection remains.
    let source = include_str!("../src/manager/update_groups.rs");
    assert!(source.contains("permit_policy_label: Option<PolicyLabel>"));
    assert!(!source.contains("staged_labels"));
    assert!(!source.contains("vpn_staged_labels"));

    let shared_label: Arc<str> = Arc::from("terminal-export-policy");
    let before = ALLOC.live.load(Ordering::Relaxed);
    let mut historical: FxHashMap<(Prefix, u32), Option<Arc<str>>> = FxHashMap::default();
    for n in 0..ROUTES as u32 {
        historical.insert((prefix(n), 0), Some(Arc::clone(&shared_label)));
    }
    let capacity = historical.capacity();
    let with_collection = ALLOC.live.load(Ordering::Relaxed);
    let reclaimed = with_collection - before;

    println!(
        "{{\"kind\":\"update_group_policy_label_profile\",\"routes\":{ROUTES},\"per_route_collections\":0,\"historical_capacity\":{capacity},\"reclaimed_bytes\":{reclaimed}}}"
    );
    assert_eq!(historical.len(), ROUTES);
    assert!(
        reclaimed >= FOUR_MIB,
        "route-keyed Permit-label collection used only {reclaimed} bytes"
    );
}
