//! Real-config allocation receipt for eager `.rpol` set sharing.
//!
//! Run in release mode; the diagnostic allocator is deliberately separate
//! from the shipped jemalloc build. Its elapsed times are diagnostic evidence
//! for this implementation gate, not a shipped-allocator performance claim:
//!
//! ```console
//! cargo test -p rustbgpd --no-default-features --features bench-internals \
//!   --release --test policy_set_store_allocation -- --ignored --nocapture
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use rustbgpd::config::{Config, ResolvedNeighbor};
use rustbgpd_policy::sets::PrefixSet;

const SET_ENTRIES: usize = 10_000;
const PEER_SHAPES: [usize; 4] = [1, 10, 100, 1_000];
const EXPECTED_SET_STORE_CHUNK_SIZE: usize = 32;
const DEFAULT_RUNS: usize = 5;

struct TrackingAllocator {
    inner: System,
    enabled: AtomicBool,
    live_bytes: AtomicUsize,
    peak_live_bytes: AtomicUsize,
    calls: AtomicUsize,
    requested_bytes: AtomicUsize,
}

impl TrackingAllocator {
    const fn new() -> Self {
        Self {
            inner: System,
            enabled: AtomicBool::new(false),
            live_bytes: AtomicUsize::new(0),
            peak_live_bytes: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            requested_bytes: AtomicUsize::new(0),
        }
    }

    fn add_live(&self, bytes: usize) {
        let live = self.live_bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        if self.enabled.load(Ordering::Relaxed) {
            self.peak_live_bytes.fetch_max(live, Ordering::Relaxed);
        }
    }

    fn subtract_live(&self, bytes: usize) {
        self.live_bytes.fetch_sub(bytes, Ordering::Relaxed);
    }

    fn count(&self, bytes: usize) {
        if self.enabled.load(Ordering::Relaxed) {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.requested_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    fn begin(&self) -> usize {
        self.enabled.store(false, Ordering::Relaxed);
        self.calls.store(0, Ordering::Relaxed);
        self.requested_bytes.store(0, Ordering::Relaxed);
        let baseline = self.live_bytes.load(Ordering::Relaxed);
        self.peak_live_bytes.store(baseline, Ordering::Relaxed);
        self.enabled.store(true, Ordering::Relaxed);
        baseline
    }

    fn end(&self, baseline: usize) -> AllocationReceipt {
        self.enabled.store(false, Ordering::Relaxed);
        AllocationReceipt {
            baseline_live_bytes: baseline,
            calls: self.calls.load(Ordering::Relaxed),
            requested_bytes: self.requested_bytes.load(Ordering::Relaxed),
            peak_live_delta_bytes: self
                .peak_live_bytes
                .load(Ordering::Relaxed)
                .saturating_sub(baseline),
            live_delta_bytes: self
                .live_bytes
                .load(Ordering::Relaxed)
                .saturating_sub(baseline),
        }
    }
}

// SAFETY: every operation forwards the original pointer/layout contract to the
// same `System` allocator. The wrapper adds only allocation-free atomic
// bookkeeping after successful operations.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is forwarded unchanged to the wrapped allocator.
        let pointer = unsafe { self.inner.alloc(layout) };
        if !pointer.is_null() {
            self.add_live(layout.size());
            self.count(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is forwarded unchanged to the wrapped allocator.
        let pointer = unsafe { self.inner.alloc_zeroed(layout) };
        if !pointer.is_null() {
            self.add_live(layout.size());
            self.count(layout.size());
        }
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the original pointer/layout and requested size are forwarded
        // unchanged to the allocator that created the allocation.
        let resized = unsafe { self.inner.realloc(pointer, layout, new_size) };
        if !resized.is_null() {
            if new_size >= layout.size() {
                self.add_live(new_size - layout.size());
            } else {
                self.subtract_live(layout.size() - new_size);
            }
            self.count(new_size);
        }
        resized
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the pointer/layout pair is forwarded unchanged to the
        // allocator that created it.
        unsafe { self.inner.dealloc(pointer, layout) };
        self.subtract_live(layout.size());
    }
}

#[global_allocator]
static TRACKING_ALLOCATOR: TrackingAllocator = TrackingAllocator::new();

#[derive(Clone, Copy)]
struct AllocationReceipt {
    baseline_live_bytes: usize,
    calls: usize,
    requested_bytes: usize,
    peak_live_delta_bytes: usize,
    live_delta_bytes: usize,
}

struct Fixture {
    _dir: tempfile::TempDir,
    config: Config,
}

fn tier_security() -> &'static str {
    r#"
[global.telemetry.grpc_uds]
path = "/tmp/rustbgpd-policy-set-store.sock"
principal = "local-admin"

[security.grpc]
enforcement = "tier"

[security.grpc.roles]
local-admin = "operator"
"#
}

fn prefix_members(first_octet: u8, count: usize) -> String {
    let mut members = String::new();
    for index in 0..count {
        if index != 0 {
            members.push_str(", ");
        }
        write!(
            members,
            "{first_octet}.{}.{}.0/24",
            (index / 256) % 256,
            index % 256
        )
        .unwrap();
    }
    members
}

fn shared_fixture(peers: usize) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("policies")).expect("policy directory");
    let rpol = format!(
        "prefix-set shared {{ {} }}\n\
         policy shared-import {{ term allow {{ if route.prefix in shared {{ accept }} }} }}\n",
        prefix_members(10, SET_ENTRIES)
    );
    std::fs::write(dir.path().join("policies/shared.rpol"), rpol).expect("shared rpol");

    let mut config = format!(
        r#"
[global]
asn = 65000
router_id = "192.0.2.254"
listen_port = 1179

[global.telemetry]
log_format = "json"

{}

[policy]
rpol_files = ["policies/shared.rpol"]
"#,
        tier_security()
    );
    for peer in 0..peers {
        writeln!(
            config,
            r#"
[[neighbors]]
address = "10.0.{}.{}"
remote_asn = {}
import_policy_chain = ["shared-import"]"#,
            peer / 250,
            peer % 250 + 1,
            64_512 + peer
        )
        .unwrap();
    }
    let path = dir.path().join("config.toml");
    std::fs::write(&path, config).expect("config");
    let config =
        Config::load_with_diagnostics(path.to_str().unwrap()).expect("shared fixture loads");
    Fixture { _dir: dir, config }
}

fn unique_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("policies")).expect("policy directory");
    let rpol = format!(
        "prefix-set first {{ {} }}\n\
         prefix-set second {{ {} }}\n\
         policy first-import {{ term allow {{ if route.prefix in first {{ accept }} }} }}\n\
         policy second-import {{ term allow {{ if route.prefix in second {{ accept }} }} }}\n",
        prefix_members(10, 32),
        prefix_members(11, 32),
    );
    std::fs::write(dir.path().join("policies/unique.rpol"), rpol).expect("unique rpol");
    let config = format!(
        r#"
[global]
asn = 65000
router_id = "192.0.2.254"
listen_port = 1179

[global.telemetry]
log_format = "json"

{}

[policy]
rpol_files = ["policies/unique.rpol"]

[[neighbors]]
address = "10.0.0.1"
remote_asn = 64512
import_policy_chain = ["first-import"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 64513
import_policy_chain = ["second-import"]
"#,
        tier_security()
    );
    let path = dir.path().join("config.toml");
    std::fs::write(&path, config).expect("config");
    let config =
        Config::load_with_diagnostics(path.to_str().unwrap()).expect("unique fixture loads");
    Fixture { _dir: dir, config }
}

fn unique_large_fixture(peers: usize) -> (Fixture, usize) {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("policies")).expect("policy directory");

    let mut rpol_files = String::new();
    let mut fixture_bytes = 0;
    for peer in 0..peers {
        if peer != 0 {
            rpol_files.push_str(", ");
        }
        write!(rpol_files, "\"policies/member{peer}.rpol\"").unwrap();

        let mut members = String::new();
        for index in 0..SET_ENTRIES {
            if index != 0 {
                members.push_str(", ");
            }
            write!(members, "2001:db8:{peer:x}:{index:x}::/64").unwrap();
        }
        let rpol = format!(
            "prefix-set member{peer} {{ {members} }}\n\
             policy member{peer}-import {{ term allow {{ if route.prefix in member{peer} {{ accept }} }} }}\n"
        );
        fixture_bytes += rpol.len();
        std::fs::write(dir.path().join(format!("policies/member{peer}.rpol")), rpol)
            .expect("unique large rpol");
    }

    let mut config = format!(
        r#"
[global]
asn = 65000
router_id = "192.0.2.254"
listen_port = 1179

[global.telemetry]
log_format = "json"

{}

[policy]
rpol_files = [{rpol_files}]
"#,
        tier_security()
    );
    for peer in 0..peers {
        writeln!(
            config,
            r#"
[[neighbors]]
address = "10.1.{}.{}"
remote_asn = {}
import_policy_chain = ["member{}-import"]"#,
            peer / 250,
            peer % 250 + 1,
            64_512 + peer,
            peer
        )
        .unwrap();
    }
    fixture_bytes += config.len();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, config).expect("config");
    let config =
        Config::load_with_diagnostics(path.to_str().unwrap()).expect("unique fixture loads");
    (Fixture { _dir: dir, config }, fixture_bytes)
}

fn named_prefix_set<'a>(neighbor: &'a ResolvedNeighbor, name: &str) -> &'a Arc<PrefixSet> {
    let chain = neighbor.import_policy.as_ref().expect("import chain");
    let compiled = chain.policies[0].rpol.as_ref().expect("rpol member");
    let index = compiled
        .prefix_set_names
        .iter()
        .position(|candidate| candidate.as_deref() == Some(name))
        .expect("named prefix set");
    &compiled.prefix_sets[index]
}

fn canonical_prefix_set_count(resolved: &[ResolvedNeighbor], name: &str) -> usize {
    resolved
        .iter()
        .map(|neighbor| Arc::as_ptr(named_prefix_set(neighbor, name)))
        .collect::<std::collections::HashSet<_>>()
        .len()
}

fn measure_resolution(fixture: &Fixture) -> (AllocationReceipt, Vec<ResolvedNeighbor>) {
    let baseline = TRACKING_ALLOCATOR.begin();
    let resolved = fixture
        .config
        .resolved_neighbors()
        .expect("real neighbor batch resolves");
    let receipt = TRACKING_ALLOCATOR.end(baseline);
    (receipt, resolved)
}

/// Fixed-operation gate for the retained resolved-neighbor batch. With one
/// shared 10,000-entry set, ten peers may add neighbor shells and chain handles
/// but must not rebuild ten indexed sets.
///
/// Red proof: restoring the old local `SetStore` inside the shared-store chain
/// resolver produces 100,381 resolution allocations for ten peers, more than
/// ten times the one-peer control, and makes the bound red.
#[test]
fn shared_set_batch_allocations_do_not_scale_per_peer() {
    let one = shared_fixture(1);
    let ten = shared_fixture(10);

    let (one_resolve, _) = measure_resolution(&one);
    let (ten_resolve, resolved) = measure_resolution(&ten);
    assert!(
        ten_resolve.calls < one_resolve.calls * 2,
        "ten-peer resolution rebuilt shared sets: one={} ten={}",
        one_resolve.calls,
        ten_resolve.calls
    );
    assert!(Arc::ptr_eq(
        named_prefix_set(&resolved[0], "shared"),
        named_prefix_set(&resolved[1], "shared"),
    ));
}

/// This receipt is ignored because the 1,000-peer current-main control
/// intentionally retains repeated 10,000-entry indexes. It is a fixed real
/// config-resolution shape, not a daemon/RSS or shipped-allocator benchmark.
#[test]
#[ignore = "manual eager policy-set allocation receipt"]
fn shared_large_set_receipt() {
    let runs = std::env::var("POLICY_SET_STORE_RUNS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_RUNS);
    let expect_shared = std::env::var_os("POLICY_SET_STORE_ALLOW_UNSHARED").is_none();

    println!(
        "operation,peers,run,elapsed_us,allocation_calls,requested_bytes,live_delta_bytes,shared"
    );
    for peers in PEER_SHAPES {
        let fixture = shared_fixture(peers);
        for run in 1..=runs {
            let started = Instant::now();
            let (allocations, resolved) = measure_resolution(&fixture);
            let elapsed_us = started.elapsed().as_micros();

            assert_eq!(resolved.len(), peers);
            let shared = peers < 2
                || Arc::ptr_eq(
                    named_prefix_set(&resolved[0], "shared"),
                    named_prefix_set(&resolved[1], "shared"),
                );
            if expect_shared {
                assert!(shared, "resolved neighbors must share the common set");
            }
            let expected_copies = if expect_shared {
                peers.div_ceil(EXPECTED_SET_STORE_CHUNK_SIZE)
            } else {
                peers
            };
            assert_eq!(
                canonical_prefix_set_count(&resolved, "shared"),
                expected_copies,
                "common-set copies must match the bounded chunk contract"
            );
            println!(
                "resolve,{peers},{run},{elapsed_us},{},{},{},{shared}",
                allocations.calls, allocations.requested_bytes, allocations.live_delta_bytes
            );
            std::hint::black_box(&resolved);
        }
    }

    let unique = unique_fixture()
        .config
        .resolved_neighbors()
        .expect("unique control resolves");
    assert!(
        !Arc::ptr_eq(
            named_prefix_set(&unique[0], "first"),
            named_prefix_set(&unique[1], "second"),
        ),
        "content-distinct sets must never alias"
    );
}

/// Reviewer gate for the opposite fleet shape: every peer references a
/// distinct 10,000-entry set from its own `.rpol` file. Fixture construction
/// and config loading precede the allocator window; `baseline_live_bytes` and
/// source `fixture_bytes` disclose that retained setup cost.
#[test]
#[ignore = "manual unique policy-set peak-memory receipt"]
fn unique_large_set_peak_receipt() {
    println!(
        "peers,fixture_bytes,baseline_live_bytes,elapsed_us,allocation_calls,requested_bytes,peak_live_delta_bytes,live_delta_bytes"
    );
    for peers in [1, 10, 31, 32, 33, 95, 96, 97, 100] {
        let (fixture, fixture_bytes) = unique_large_fixture(peers);
        let started = Instant::now();
        let (allocations, resolved) = measure_resolution(&fixture);
        let elapsed_us = started.elapsed().as_micros();
        assert_eq!(resolved.len(), peers);
        if peers > 1 {
            assert!(!Arc::ptr_eq(
                named_prefix_set(&resolved[0], "member0"),
                named_prefix_set(&resolved[1], "member1"),
            ));
        }
        println!(
            "{peers},{fixture_bytes},{},{elapsed_us},{},{},{},{}",
            allocations.baseline_live_bytes,
            allocations.calls,
            allocations.requested_bytes,
            allocations.peak_live_delta_bytes,
            allocations.live_delta_bytes
        );
        std::hint::black_box(resolved);
    }
}
