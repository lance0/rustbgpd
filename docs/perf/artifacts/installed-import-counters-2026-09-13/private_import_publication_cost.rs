//! Private, source-only preparation for a one-shot ownership/cost receipt.
//! No production hooks: uses InstalledImportPolicy::new and tokio watch directly.
//! System requested bytes are not RSS, usable allocation sizes, or jemalloc cost.
//! All work is synchronous on this sole test's thread; no session/RPC latency claim.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::Instant;

use rustbgpd_policy::rpol::compile_rpol;
use rustbgpd_policy::sets::SetStore;
use rustbgpd_policy::{NamedPolicy, PolicyChain, PolicyHitCounters};
use rustbgpd_transport::handle::{InstalledImportPolicy, SessionIdentity};
use tokio::sync::watch;

const PEERS: usize = 1000;
const GENERATIONS: usize = 4;
const LONG_LABEL_BYTES: usize = 256; // Chosen diagnostic shape, not a config limit.

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

#[derive(Clone, Copy, Default)]
struct Counts {
    allocation_ops: usize,
    allocated_bytes: usize,
    deallocation_ops: usize,
    deallocated_bytes: usize,
}

struct CountingAllocator {
    inner: System,
    allocation_ops: AtomicUsize,
    allocated_bytes: AtomicUsize,
    deallocation_ops: AtomicUsize,
    deallocated_bytes: AtomicUsize,
}

impl CountingAllocator {
    const fn new() -> Self {
        Self {
            inner: System,
            allocation_ops: AtomicUsize::new(0),
            allocated_bytes: AtomicUsize::new(0),
            deallocation_ops: AtomicUsize::new(0),
            deallocated_bytes: AtomicUsize::new(0),
        }
    }

    fn begin(&self) {
        assert!(!COUNTING.get());
        self.allocation_ops.store(0, Ordering::Relaxed);
        self.allocated_bytes.store(0, Ordering::Relaxed);
        self.deallocation_ops.store(0, Ordering::Relaxed);
        self.deallocated_bytes.store(0, Ordering::Relaxed);
        COUNTING.set(true);
    }

    fn snapshot(&self) -> Counts {
        Counts {
            allocation_ops: self.allocation_ops.load(Ordering::Relaxed),
            allocated_bytes: self.allocated_bytes.load(Ordering::Relaxed),
            deallocation_ops: self.deallocation_ops.load(Ordering::Relaxed),
            deallocated_bytes: self.deallocated_bytes.load(Ordering::Relaxed),
        }
    }

    fn count_success(&self, pointer: *mut u8, bytes: usize) {
        // `try_with` (not `with`): the allocator is reachable from TLS
        // destructors on exiting threads, where key access would panic.
        if !pointer.is_null() && COUNTING.try_with(Cell::get).unwrap_or(false) {
            self.allocation_ops.fetch_add(1, Ordering::Relaxed);
            self.allocated_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    fn count_retired(&self, bytes: usize) {
        if COUNTING.try_with(Cell::get).unwrap_or(false) {
            self.deallocation_ops.fetch_add(1, Ordering::Relaxed);
            self.deallocated_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }
}

// SAFETY: every operation forwards the original pointer/layout contract to the
// same `System` allocator. The wrapper adds only allocation-free atomic
// bookkeeping after successful allocation operations.
// This extension also records retired layouts after successful realloc/dealloc;
// bookkeeping never reads the old pointer or changes the forwarded contract.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is forwarded unchanged to the wrapped allocator.
        let pointer = unsafe { self.inner.alloc(layout) };
        self.count_success(pointer, layout.size());
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is forwarded unchanged to the wrapped allocator.
        let pointer = unsafe { self.inner.alloc_zeroed(layout) };
        self.count_success(pointer, layout.size());
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller's original pointer/layout pair and requested new
        // size are forwarded unchanged to the allocator that created it.
        let resized = unsafe { self.inner.realloc(pointer, layout, new_size) };
        self.count_success(resized, new_size);
        // A successful realloc retires the old requested size even in place.
        // A failed realloc retains the old allocation and contributes neither.
        if !resized.is_null() {
            self.count_retired(layout.size());
        }
        resized
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the caller's pointer/layout pair is forwarded unchanged to
        // the allocator that created it.
        unsafe { self.inner.dealloc(pointer, layout) };
        self.count_retired(layout.size());
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator::new();

struct Measurement {
    phase: &'static str,
    generation: usize,
    elapsed_ns: u128,
    before: Counts,
    after: Counts,
}

fn record(
    rows: &mut Vec<Measurement>,
    phase: &'static str,
    generation: usize,
    operation: impl FnOnce(),
) {
    assert!(rows.len() < rows.capacity());
    let before = ALLOCATOR.snapshot();
    let start = Instant::now();
    operation();
    let elapsed_ns = start.elapsed().as_nanos();
    let after = ALLOCATOR.snapshot();
    rows.push(Measurement { phase, generation, elapsed_ns, before, after });
}

fn chain_template(long_labels: bool) -> PolicyChain {
    // Retained run-D scenario: 1000 peers, import_chain = ["member-in"].
    // This import body stays unchanged across its export-policy reloads.
    let names = if long_labels {
        ["p".repeat(LONG_LABEL_BYTES), "d".repeat(LONG_LABEL_BYTES), "a".repeat(LONG_LABEL_BYTES)]
    } else {
        ["member-in".into(), "drop-blocked".into(), "default".into()]
    };
    let source = format!(
        "policy {} {{\n term {} {{ if route.prefix == 192.0.2.0/24 {{ reject }} }}\n term {} {{ accept }}\n}}",
        names[0], names[1], names[2]
    );
    let compiled = compile_rpol(&source, &mut SetStore::new()).expect("valid one-policy fixture");
    assert_eq!(compiled.policies.len(), 1);
    assert_eq!(compiled.policies[0].terms.len(), 2);
    assert_eq!(compiled.policies[0].name.as_deref(), Some(names[0].as_str()));
    assert_eq!(compiled.policies[0].terms[0].name.as_deref(), Some(names[1].as_str()));
    assert_eq!(compiled.policies[0].terms[1].name.as_deref(), Some(names[2].as_str()));
    PolicyChain::from_named(vec![NamedPolicy::from_rpol(names[0].clone(), Arc::new(compiled))])
}

fn measure_case(long_labels: bool, warm: bool) {
    // Parser/configured rpol body and harness storage live outside accounting.
    // Keep the template alive until counting stops: its pre-existing shared body
    // cannot be freed inside the measured owned-object lifecycle.
    let template = chain_template(long_labels);
    let mut rows = Vec::with_capacity(64);
    let mut senders = Vec::with_capacity(PEERS);
    let mut receivers = Vec::with_capacity(PEERS);
    let mut current_chains = Vec::<PolicyChain>::with_capacity(PEERS);
    let mut next_chains = Vec::<PolicyChain>::with_capacity(PEERS);
    let mut descriptors = Vec::with_capacity(PEERS);
    let mut readers_a: [Vec<Arc<InstalledImportPolicy>>; GENERATIONS] =
        std::array::from_fn(|_| Vec::with_capacity(PEERS));
    let mut readers_b: [Vec<Arc<InstalledImportPolicy>>; GENERATIONS] =
        std::array::from_fn(|_| Vec::with_capacity(PEERS));
    let mut descriptor_weaks: [Vec<Weak<InstalledImportPolicy>>; GENERATIONS] =
        std::array::from_fn(|_| Vec::with_capacity(PEERS));
    let mut counter_weaks: [Vec<Weak<PolicyHitCounters>>; GENERATIONS] =
        std::array::from_fn(|_| Vec::with_capacity(PEERS));

    // One uninterrupted account scope: release-window deltas may be negative.
    // Resetting each window would misclassify prior-window allocations as foreign.
    let scope_start = Instant::now();
    ALLOCATOR.begin();
    record(&mut rows, "create_watch_channels", 0, || {
        for _ in 0..PEERS {
            let (sender, receiver) = watch::channel(None::<Arc<InstalledImportPolicy>>);
            senders.push(sender);
            receivers.push(receiver);
        }
    });

    for generation in 0..GENERATIONS {
        record(&mut rows, "clone_fresh_policy_chains", generation + 1, || {
            for _ in 0..PEERS {
                // clone() deliberately resets compiled/counter caches; share()
                // would reuse installed counters and invalidate this experiment.
                next_chains.push(template.clone());
            }
        });
        if warm {
            record(&mut rows, "initialize_compiled", generation + 1, || {
                for chain in &next_chains {
                    let _ = chain.compiled();
                }
            });
            record(&mut rows, "initialize_counters", generation + 1, || {
                for chain in &next_chains {
                    let _ = chain.hit_counters();
                }
            });
        }
        record(&mut rows, "construct_descriptors", generation + 1, || {
            for (peer, chain) in next_chains.iter().enumerate() {
                descriptors.push(Arc::new(InstalledImportPolicy::new(
                    SessionIdentity::primary(peer as u64),
                    (generation + 1) as u64,
                    Some(chain),
                )));
            }
        });
        record(&mut rows, "publish_watch_values", generation + 1, || {
            for (sender, descriptor) in senders.iter().zip(descriptors.drain(..)) {
                drop(sender.send_replace(Some(descriptor)));
            }
        });
        record(&mut rows, "retire_replaced_policy_chains", generation + 1, || {
            current_chains.clear();
            std::mem::swap(&mut current_chains, &mut next_chains);
        });
        record(&mut rows, "capture_reader_a", generation + 1, || {
            for receiver in &mut receivers {
                readers_a[generation].push(Arc::clone(receiver.borrow_and_update().as_ref().unwrap()));
            }
        });
        record(&mut rows, "capture_reader_b", generation + 1, || {
            for receiver in &mut receivers {
                readers_b[generation].push(Arc::clone(receiver.borrow_and_update().as_ref().unwrap()));
            }
        });
        record(&mut rows, "capture_weak_release_witnesses", generation + 1, || {
            for (descriptor, chain) in readers_a[generation].iter().zip(&current_chains) {
                descriptor_weaks[generation].push(Arc::downgrade(descriptor));
                counter_weaks[generation].push(Arc::downgrade(chain.hit_counters()));
            }
        });
        if generation > 0 {
            for peer in 0..PEERS {
                assert!(!Weak::ptr_eq(&descriptor_weaks[generation][peer], &descriptor_weaks[generation - 1][peer]));
                assert!(!Weak::ptr_eq(&counter_weaks[generation][peer], &counter_weaks[generation - 1][peer]));
            }
        }
    }

    record(&mut rows, "drop_current_policy_chains", 0, || current_chains.clear());
    for generation in 0..GENERATIONS {
        for peer in 0..PEERS {
            let owners = if generation + 1 == GENERATIONS { 3 } else { 2 };
            assert_eq!(descriptor_weaks[generation][peer].strong_count(), owners);
            assert_eq!(counter_weaks[generation][peer].strong_count(), 1);
        }
    }
    record(&mut rows, "drop_independent_reader_a_pins", 0, || {
        for readers in &mut readers_a { readers.clear(); }
    });
    for generation in 0..GENERATIONS {
        assert!(descriptor_weaks[generation].iter().all(|weak| weak.strong_count() > 0));
        assert!(counter_weaks[generation].iter().all(|weak| weak.strong_count() == 1));
    }
    record(&mut rows, "drop_old_reader_b_last_pins", 0, || {
        for readers in &mut readers_b[..GENERATIONS - 1] { readers.clear(); }
    });
    for generation in 0..GENERATIONS - 1 {
        assert!(descriptor_weaks[generation].iter().all(|weak| weak.upgrade().is_none()));
        assert!(counter_weaks[generation].iter().all(|weak| weak.upgrade().is_none()));
    }
    let latest = GENERATIONS - 1;
    record(&mut rows, "retire_channel_senders", 0, || senders.clear());
    assert!(receivers.iter().all(|receiver| receiver.has_changed().is_err()));
    assert!(descriptor_weaks[latest].iter().all(|weak| weak.strong_count() == 2));
    record(&mut rows, "drop_retired_channel_receivers", 0, || receivers.clear());
    assert!(descriptor_weaks[latest].iter().all(|weak| weak.strong_count() == 1));
    assert!(counter_weaks[latest].iter().all(|weak| weak.strong_count() == 1));
    record(&mut rows, "drop_current_reader_b_last_pins", 0, || readers_b[latest].clear());
    assert!(descriptor_weaks[latest].iter().all(|weak| weak.upgrade().is_none()));
    assert!(counter_weaks[latest].iter().all(|weak| weak.upgrade().is_none()));
    // Weak witnesses keep Arc control allocations alive after payload release.
    record(&mut rows, "drop_weak_control_allocations", 0, || {
        for witnesses in &mut descriptor_weaks { witnesses.clear(); }
        for witnesses in &mut counter_weaks { witnesses.clear(); }
    });
    COUNTING.set(false);
    let total = ALLOCATOR.snapshot();
    rows.push(Measurement {
        phase: "whole_account_scope",
        generation: 0,
        elapsed_ns: scope_start.elapsed().as_nanos(), // Includes ownership assertions.
        before: Counts::default(),
        after: total,
    });

    // Formatting, harness buffer disposal, and template disposal are uncounted.
    for row in rows {
        let allocated = row.after.allocated_bytes - row.before.allocated_bytes;
        let deallocated = row.after.deallocated_bytes - row.before.deallocated_bytes;
        println!(
            "shape={} warm={} peers={} generations={} phase={} generation={} elapsed_ns={} allocation_ops={} allocated_requested_bytes={} deallocation_ops={} deallocated_requested_bytes={} net_requested_bytes={}",
            if long_labels { "labels_256_bytes" } else { "native_labels_9_12_7" },
            warm, PEERS, GENERATIONS, row.phase, row.generation, row.elapsed_ns,
            row.after.allocation_ops - row.before.allocation_ops, allocated,
            row.after.deallocation_ops - row.before.deallocation_ops, deallocated,
            allocated as i128 - deallocated as i128,
        );
    }
}

#[test]
fn private_import_publication_cost() {
    for long_labels in [false, true] {
        for warm in [false, true] {
            measure_case(long_labels, warm);
        }
    }
}
