#![cfg(feature = "bench-internals")]
//! Live heap retained by one installed 4,096-entry prefix-ORF filter, with
//! the entry list alone and with its lookup index built. The entry list alone
//! is the pre-index representation.
//!
//! cargo test -p rustbgpd-rib --features bench-internals --release \
//!     --test orf_index_memory -- --ignored --nocapture

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};

use rustbgpd_rib::bench_orf_filter;
use rustbgpd_wire::{AddressPrefixOrf, Ipv4Prefix, Ipv6Prefix, OrfAction, OrfMatch, Prefix};

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

fn v4(addr: u32, len: u8) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(addr), len))
}

fn v6(addr: u128, len: u8) -> Prefix {
    Prefix::V6(Ipv6Prefix::new(Ipv6Addr::from(addr), len))
}

fn add(sequence: u32, match_: OrfMatch, max_len: u8, prefix: Prefix) -> AddressPrefixOrf {
    AddressPrefixOrf {
        action: OrfAction::Add,
        match_,
        sequence,
        min_len: 0,
        max_len,
        prefix: Some(prefix),
    }
}

fn shapes() -> Vec<(&'static str, Vec<AddressPrefixOrf>, Prefix)> {
    let v6_lengths_base = 0x2001_0db8_u128 << 96;
    vec![
        (
            "v4 4095 /32 + 0/0 le 32",
            (0..4095)
                .map(|s| add(s, OrfMatch::Permit, 0, v4(0xac10_0000 + s, 32)))
                .chain([add(4095, OrfMatch::Permit, 32, v4(0, 0))])
                .collect(),
            v4(0x0a00_0000, 24),
        ),
        (
            "v4 4096 /12 le 32",
            (0..4096)
                .map(|i| add(i, OrfMatch::Permit, 32, v4(i << 20, 12)))
                .collect(),
            v4(0x0a00_0000, 24),
        ),
        (
            "v6 4096 /12 le 128",
            (0..4096)
                .map(|i| add(i, OrfMatch::Permit, 128, v6(u128::from(i) << 116, 12)))
                .collect(),
            v6(0x2a00_u128 << 112, 48),
        ),
        (
            "v6 4096 /32 le 48",
            (0..4096)
                .map(|i| {
                    add(
                        i,
                        OrfMatch::Permit,
                        48,
                        v6((0x2001_0000_u128 + u128::from(i)) << 96, 32),
                    )
                })
                .collect(),
            v6(0x2a00_u128 << 112, 48),
        ),
        (
            "v6 every len 1..=128 + ::/0",
            (1..=128u8)
                .zip(0u32..)
                .map(|(len, seq)| add(seq, OrfMatch::Deny, 0, v6(v6_lengths_base, len)))
                .chain((128..4095).map(|s| {
                    add(
                        s,
                        OrfMatch::Permit,
                        0,
                        v6((0x2001_0db9_u128 << 96) + u128::from(s), 128),
                    )
                }))
                .chain([add(4095, OrfMatch::Permit, 128, v6(0, 0))])
                .collect(),
            v6(0x2a00_u128 << 112, 48),
        ),
    ]
}

fn retained(entries: &[AddressPrefixOrf], probe: Option<Prefix>) -> usize {
    let before = ALLOC.live.load(Ordering::Relaxed);
    let filter = bench_orf_filter(entries, probe);
    let after = ALLOC.live.load(Ordering::Relaxed);
    drop(filter);
    after - before
}

#[test]
#[ignore = "manual allocator receipt"]
fn orf_index_retained_bytes_by_shape() {
    for (name, entries, probe) in shapes() {
        let list = retained(&entries, None);
        let indexed = retained(&entries, Some(probe));
        println!(
            "{name:30} entry list {list:>9} B  with index {indexed:>9} B  ratio {:.2}",
            indexed as f64 / list as f64
        );
    }
}
