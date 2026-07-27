//! Fixed-operation allocation gate for named policy attribution.
//!
//! This is an allocation receipt, not a timing benchmark. The chain is
//! compiled and its counters are initialized before measurement; the measured
//! window contains only repeated production
//! `PolicyChain::evaluate_with_attribution` calls.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use rustbgpd_policy::{
    NamedPolicy, Policy, PolicyAction, PolicyChain, RouteContext, RouteModifications,
};
use rustbgpd_wire::{AspaValidation, RpkiValidation};

const VERDICTS: usize = 256;

struct CountingAllocator {
    inner: System,
    enabled: AtomicBool,
    allocations: AtomicUsize,
}

impl CountingAllocator {
    const fn new() -> Self {
        Self {
            inner: System,
            enabled: AtomicBool::new(false),
            allocations: AtomicUsize::new(0),
        }
    }

    fn begin(&self) {
        self.enabled.store(false, Ordering::Relaxed);
        self.allocations.store(0, Ordering::Relaxed);
        self.enabled.store(true, Ordering::Relaxed);
    }

    fn end(&self) -> usize {
        self.enabled.store(false, Ordering::Relaxed);
        self.allocations.load(Ordering::Relaxed)
    }

    fn count_success(&self, pointer: *mut u8) {
        if !pointer.is_null() && self.enabled.load(Ordering::Relaxed) {
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

/// Red proof: changing the evaluator to rebuild an owned label per verdict
/// (for example `Arc::from(policy.name.as_deref().unwrap())`) preserves the
/// asserted text and action but makes the allocation count non-zero.
#[test]
fn named_attribution_allocates_no_label_per_verdict() {
    let chain = named_permit_chain();
    let context = route_context();

    // Compile the chain and initialize its hit counters before measurement.
    let (warm_result, warm_evaluation) = chain.evaluate_with_attribution(&context);
    assert_eq!(warm_result.action, PolicyAction::Permit);
    let expected_label = warm_evaluation
        .matched_policy
        .expect("named policy must produce attributed verdicts");
    assert_eq!(expected_label.as_ref(), "customer-import");

    let mut attributed_verdicts = 0;
    ALLOCATOR.begin();
    for _ in 0..VERDICTS {
        let (result, evaluation) = chain.evaluate_with_attribution(&context);
        let label = evaluation
            .matched_policy
            .expect("measured verdict must remain attributed");
        if result.action == PolicyAction::Permit
            && evaluation.action == PolicyAction::Permit
            && evaluation.eval_error.is_none()
            && label.as_ref() == "customer-import"
        {
            attributed_verdicts += 1;
        }
    }
    let allocations = ALLOCATOR.end();

    assert_eq!(
        attributed_verdicts, VERDICTS,
        "the fixed-operation window must exercise the named attributed path"
    );
    assert_eq!(
        allocations, 0,
        "named attribution rebuilt {allocations} labels across {VERDICTS} verdicts"
    );

    // Keep the public result shape explicit: the allocation gate is not
    // allowed to change policy semantics to buy the count.
    assert_eq!(RouteModifications::default(), warm_result.modifications);
}
