#![cfg(feature = "bench-internals")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustbgpd_rib::RibManager;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Ipv4Prefix, Prefix};
use tokio::sync::mpsc;

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

#[test]
#[ignore = "manual fresh-process structural allocator receipt"]
fn unicast_prefix_peers_memory() {
    const PREFIXES: usize = 100_000;
    let announcers: usize = std::env::var("LAN1034_ANNOUNCERS")
        .expect("set LAN1034_ANNOUNCERS to 1 or 2")
        .parse()
        .expect("LAN1034_ANNOUNCERS is an integer");

    // All input/setup allocations precede the measurement baseline.
    let prefixes: Vec<_> = (0..PREFIXES as u32)
        .map(|n| Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(n), 32)))
        .collect();
    let (_tx, rx) = mpsc::channel(1);
    let (_query_tx, query_rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, query_rx, None, None, BgpMetrics::new());

    let before = ALLOC.live.load(Ordering::Relaxed);
    let receipt = manager.bench_populate_unicast_prefix_peers(&prefixes, announcers);
    let after = ALLOC.live.load(Ordering::Relaxed);
    let live_delta = after
        .checked_sub(before)
        .expect("index growth is non-negative");

    assert_eq!(receipt.entries, PREFIXES);
    assert!(receipt.capacity >= receipt.entries);
    assert_eq!(receipt.announcers_per_prefix, announcers);
    println!(
        "{{\"kind\":\"unicast_prefix_peers_memory\",\"baseline_reference_sha\":\"812770e5297f6c455e457f158d057528f6bcf4fb\",\"measured_representation\":\"epoch_inline_or_spill_slot\",\"requested_prefixes\":{PREFIXES},\"announcers_per_prefix\":{announcers},\"live_bytes_delta\":{live_delta},\"entries\":{},\"capacity\":{},\"prefix_size\":{},\"peer_address_size\":{},\"epoch_size\":{},\"primary_value_size\":{},\"spill_slots\":{}}}",
        receipt.entries,
        receipt.capacity,
        receipt.prefix_size,
        receipt.peer_address_size,
        receipt.epoch_size,
        receipt.primary_value_size,
        receipt.spill_slots,
    );
}
