//! Allocation bound for RFC 7606 §3 (g) duplicate-attribute recovery.
//!
//! An UPDATE may repeat one attribute type thousands of times. Decoding it
//! must allocate the same amount however many repeats it carries: one
//! record per duplicated type, never one per occurrence.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustbgpd_wire::attribute::decode_path_attributes_revised;

// Count only the measuring thread; libtest threads allocate concurrently.
thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

struct CountingAllocator {
    allocations: AtomicUsize,
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator {
    allocations: AtomicUsize::new(0),
};

// SAFETY: every call delegates to `System` unchanged; counting only reads
// thread-local state and bumps an atomic.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.count();
        // SAFETY: forwarded with the caller's layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `System` with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        self.count();
        // SAFETY: forwarded with the caller's pointer and layout.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

impl CountingAllocator {
    fn count(&self) {
        // `try_with`: the allocator runs in TLS destructors too.
        if COUNTING.try_with(Cell::get).unwrap_or(false) {
            self.allocations.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// ORIGIN, `AS_PATH` and `NEXT_HOP`, then `repeats` + 1 `MULTI_EXIT_DISC`.
fn duplicate_med_attributes(repeats: usize) -> Vec<u8> {
    let mut buf = vec![0x40, 1, 1, 0];
    buf.extend([0x40, 2, 6, 2, 1, 0, 0, 0xFD, 0xE9]);
    buf.extend([0x40, 3, 4, 10, 0, 0, 2]);
    for _ in 0..=repeats {
        buf.extend([0x80, 4, 4, 0, 0, 0, 5]);
    }
    buf
}

fn decode_allocations(repeats: usize) -> usize {
    let buf = duplicate_med_attributes(repeats);
    ALLOCATOR.allocations.store(0, Ordering::Relaxed);
    COUNTING.set(true);
    let decoded = decode_path_attributes_revised(&buf, true, false, &[]);
    COUNTING.set(false);
    let allocations = ALLOCATOR.allocations.load(Ordering::Relaxed);
    decoded.expect("duplicates are recoverable");
    allocations
}

/// Load-bearing: one record or detail string per repeat makes the larger
/// UPDATE allocate thousands of times more and fails here.
#[test]
fn duplicate_attribute_decode_allocations_do_not_grow_with_repeats() {
    let few = decode_allocations(2);
    // About 9,000 repeats fill a 65,535-octet Extended Message.
    let many = decode_allocations(9_000);
    assert_eq!(
        few, many,
        "allocations: 2 repeats {few}, 9000 repeats {many}"
    );
}
