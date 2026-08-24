//! Fixed-operation allocation gate for named policy attribution.
//!
//! This is an allocation receipt, not a timing benchmark. The chain is
//! compiled and its counters are initialized before measurement; the measured
//! window contains only repeated production retention-rich single-walk
//! evaluation calls.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustbgpd_policy::{
    CHAIN_DEFAULT_PERMIT_ATTRIBUTION, NamedPolicy, Policy, PolicyAction, PolicyChain, RouteContext,
    RouteModifications, evaluate_chain_with_reject_term,
};
use rustbgpd_wire::{AspaValidation, RpkiValidation};

const VERDICTS: usize = 256;

// Counting is scoped to the measuring thread, not the process. The
// evaluation under test runs entirely on the test thread, but the test
// process also hosts libtest-harness threads whose incidental allocations
// (progress plumbing, timing) land inside the measured window when a
// loaded host stretches its wall-clock span — a handful of phantom
// "label rebuilds" that no policy code performed. A per-verdict label
// rebuild happens on this thread and still counts exactly.
thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

struct CountingAllocator {
    inner: System,
    allocations: AtomicUsize,
}

impl CountingAllocator {
    const fn new() -> Self {
        Self {
            inner: System,
            allocations: AtomicUsize::new(0),
        }
    }

    fn begin(&self) {
        self.allocations.store(0, Ordering::Relaxed);
        COUNTING.set(true);
    }

    fn end(&self) -> usize {
        COUNTING.set(false);
        self.allocations.load(Ordering::Relaxed)
    }

    fn count_success(&self, pointer: *mut u8) {
        // `try_with` (not `with`): the allocator is reachable from TLS
        // destructors on exiting threads, where key access would panic.
        if !pointer.is_null() && COUNTING.try_with(Cell::get).unwrap_or(false) {
            self.allocations.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// SAFETY: every operation forwards the original pointer/layout contract to the
// same `System` allocator. The wrapper adds only allocation-free atomic
// bookkeeping after successful allocation operations.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is forwarded unchanged to the wrapped allocator.
        let pointer = unsafe { self.inner.alloc(layout) };
        self.count_success(pointer);
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is forwarded unchanged to the wrapped allocator.
        let pointer = unsafe { self.inner.alloc_zeroed(layout) };
        self.count_success(pointer);
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller's original pointer/layout pair and requested new
        // size are forwarded unchanged to the allocator that created it.
        let resized = unsafe { self.inner.realloc(pointer, layout, new_size) };
        self.count_success(resized);
        resized
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the caller's pointer/layout pair is forwarded unchanged to
        // the allocator that created it.
        unsafe { self.inner.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator::new();

fn route_context() -> RouteContext<'static> {
    RouteContext {
        prefix: None,
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 0,
        origin_asn: None,
        validation_state: RpkiValidation::NotFound,
        aspa_state: AspaValidation::Unknown,
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

fn named_permit_chain() -> PolicyChain {
    PolicyChain::from_named(vec![NamedPolicy {
        name: Some("customer-import".to_string()),
        policy: Policy {
            entries: Vec::new(),
            default_action: PolicyAction::Permit,
        },
        rpol: None,
    }])
}

/// Mutation proof: rebuilding an owned label per verdict preserves the
/// asserted text and action but makes the allocation count non-zero.
#[test]
fn retained_permit_attribution_allocates_nothing_per_verdict() {
    let chain = named_permit_chain();
    let context = route_context();

    // Compile the chain and initialize its hit counters before measurement.
    let (warm_result, warm_evaluation, warm_term) =
        evaluate_chain_with_reject_term(Some(&chain), &context);
    assert_eq!(warm_result.action, PolicyAction::Permit);
    assert_eq!(warm_term, None);
    let expected_label = warm_evaluation
        .matched_policy
        .expect("nonempty chain must produce attributed verdicts");
    assert_eq!(expected_label.as_ref(), CHAIN_DEFAULT_PERMIT_ATTRIBUTION);

    let mut attributed_verdicts = 0;
    ALLOCATOR.begin();
    for _ in 0..VERDICTS {
        let (result, evaluation, term) = evaluate_chain_with_reject_term(Some(&chain), &context);
        let label = evaluation
            .matched_policy
            .expect("measured verdict must remain attributed");
        if result.action == PolicyAction::Permit
            && evaluation.action == PolicyAction::Permit
            && evaluation.eval_error.is_none()
            && term.is_none()
            && label.as_ref() == CHAIN_DEFAULT_PERMIT_ATTRIBUTION
        {
            attributed_verdicts += 1;
        }
    }
    let allocations = ALLOCATOR.end();

    assert_eq!(
        attributed_verdicts, VERDICTS,
        "the fixed-operation window must exercise the chain-default attributed path"
    );
    assert_eq!(
        allocations, 0,
        "chain-default attribution rebuilt {allocations} labels across {VERDICTS} verdicts"
    );

    // Keep the public result shape explicit: the allocation gate is not
    // allowed to change policy semantics to buy the count.
    assert_eq!(RouteModifications::default(), warm_result.modifications);
}
