//! Measurement harness for ordinary MRT snapshot allocation behavior.
//!
//! The `timing` binary uses the same bare jemalloc allocator as the shipped
//! daemon and compiles without diagnostic counters. The separately compiled
//! `diagnostic` binary counts allocator activity and top-level output growth;
//! its measurements are never reported as elapsed-time results.

#[cfg(feature = "snapshot-allocation-diagnostics")]
use std::alloc::{GlobalAlloc, Layout};
use std::error::Error;
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(feature = "snapshot-allocation-diagnostics")]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use rustbgpd_mrt::SnapshotReader;
use rustbgpd_mrt::codec::encode_snapshot;
#[cfg(feature = "snapshot-allocation-diagnostics")]
use rustbgpd_mrt::codec::encode_snapshot_with_allocation_diagnostics;
use rustbgpd_mrt::reader::{SnapshotEntry, SnapshotNlri};
use rustbgpd_rib::route::{Route, RouteOrigin};
use rustbgpd_rib::update::MrtPeerEntry;
use rustbgpd_wire::attribute::encode_path_attributes;
use rustbgpd_wire::{
    AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute, Prefix, RpkiValidation,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tikv_jemallocator::Jemalloc;

const COLLECTOR_BGP_ID: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 254);
const PEER_IPV4_BASE: u32 = 0xc612_0001;
const MRT_TIMESTAMP: u32 = 1_750_000_000;
const FIXED_ORIGINATED_TIME: u32 = 1_740_000_000;
const TIMING_SAMPLES: usize = 7;
const WARMUPS: usize = 2;

#[cfg(not(feature = "snapshot-allocation-diagnostics"))]
#[global_allocator]
static ALLOCATOR: Jemalloc = Jemalloc;

#[cfg(feature = "snapshot-allocation-diagnostics")]
struct TrackingAllocator {
    inner: Jemalloc,
    enabled: AtomicBool,
    alloc_calls: AtomicUsize,
    alloc_zeroed_calls: AtomicUsize,
    realloc_calls: AtomicUsize,
    dealloc_calls: AtomicUsize,
    requested_bytes: AtomicUsize,
    live_requested_bytes: AtomicUsize,
    peak_live_requested_bytes: AtomicUsize,
}

#[cfg(feature = "snapshot-allocation-diagnostics")]
impl TrackingAllocator {
    const fn new() -> Self {
        Self {
            inner: Jemalloc,
            enabled: AtomicBool::new(false),
            alloc_calls: AtomicUsize::new(0),
            alloc_zeroed_calls: AtomicUsize::new(0),
            realloc_calls: AtomicUsize::new(0),
            dealloc_calls: AtomicUsize::new(0),
            requested_bytes: AtomicUsize::new(0),
            live_requested_bytes: AtomicUsize::new(0),
            peak_live_requested_bytes: AtomicUsize::new(0),
        }
    }

    fn update_peak(&self, current: usize) {
        self.peak_live_requested_bytes
            .fetch_max(current, Ordering::Relaxed);
    }

    fn add_live(&self, bytes: usize) {
        let current = self
            .live_requested_bytes
            .fetch_add(bytes, Ordering::Relaxed)
            .saturating_add(bytes);
        self.update_peak(current);
    }

    fn subtract_live(&self, bytes: usize) {
        self.live_requested_bytes
            .fetch_sub(bytes, Ordering::Relaxed);
    }

    fn begin_measurement(&self) -> usize {
        self.enabled.store(false, Ordering::Relaxed);
        self.alloc_calls.store(0, Ordering::Relaxed);
        self.alloc_zeroed_calls.store(0, Ordering::Relaxed);
        self.realloc_calls.store(0, Ordering::Relaxed);
        self.dealloc_calls.store(0, Ordering::Relaxed);
        self.requested_bytes.store(0, Ordering::Relaxed);
        let baseline_live_requested_bytes = self.live_requested_bytes.load(Ordering::Relaxed);
        self.peak_live_requested_bytes
            .store(baseline_live_requested_bytes, Ordering::Relaxed);
        self.enabled.store(true, Ordering::Relaxed);
        baseline_live_requested_bytes
    }

    fn end_measurement(&self, baseline_live_requested_bytes: usize) -> AllocatorReceipt {
        self.enabled.store(false, Ordering::Relaxed);
        let final_live_requested_bytes = self.live_requested_bytes.load(Ordering::Relaxed);
        let peak_live_requested_bytes = self.peak_live_requested_bytes.load(Ordering::Relaxed);
        AllocatorReceipt {
            alloc_calls: self.alloc_calls.load(Ordering::Relaxed),
            alloc_zeroed_calls: self.alloc_zeroed_calls.load(Ordering::Relaxed),
            realloc_calls: self.realloc_calls.load(Ordering::Relaxed),
            dealloc_calls: self.dealloc_calls.load(Ordering::Relaxed),
            requested_bytes: self.requested_bytes.load(Ordering::Relaxed),
            baseline_live_requested_bytes,
            final_live_requested_bytes,
            peak_live_requested_bytes,
            peak_live_delta_bytes: peak_live_requested_bytes
                .saturating_sub(baseline_live_requested_bytes),
            peak_live_overhead_bytes: 0,
        }
    }

    fn count_request(&self, counter: &AtomicUsize, bytes: usize) {
        if self.enabled.load(Ordering::Relaxed) {
            counter.fetch_add(1, Ordering::Relaxed);
            self.requested_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }
}

#[cfg(feature = "snapshot-allocation-diagnostics")]
// SAFETY: every allocation operation is forwarded to the same `Jemalloc`
// instance without altering its pointer/layout contract. The wrapper adds only
// allocation-free atomic bookkeeping after successful operations.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplies a valid layout under `GlobalAlloc::alloc`;
        // it is forwarded unchanged to the wrapped allocator.
        let pointer = unsafe { self.inner.alloc(layout) };
        if !pointer.is_null() {
            self.add_live(layout.size());
            self.count_request(&self.alloc_calls, layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplies a valid layout under
        // `GlobalAlloc::alloc_zeroed`; it is forwarded unchanged.
        let pointer = unsafe { self.inner.alloc_zeroed(layout) };
        if !pointer.is_null() {
            self.add_live(layout.size());
            self.count_request(&self.alloc_zeroed_calls, layout.size());
        }
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller guarantees that `pointer` was allocated by this
        // wrapper with `layout`. All successful allocations come from
        // `self.inner`, so the original pointer/layout pair and new size can be
        // forwarded to that same allocator.
        let resized = unsafe { self.inner.realloc(pointer, layout, new_size) };
        if !resized.is_null() {
            if new_size >= layout.size() {
                self.add_live(new_size - layout.size());
            } else {
                self.subtract_live(layout.size() - new_size);
            }
            self.count_request(&self.realloc_calls, new_size);
        }
        resized
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the caller guarantees that `pointer` was allocated by this
        // wrapper with `layout`; this wrapper delegates all allocations to
        // `self.inner`, so the pair belongs to that allocator.
        unsafe { self.inner.dealloc(pointer, layout) };
        self.subtract_live(layout.size());
        if self.enabled.load(Ordering::Relaxed) {
            self.dealloc_calls.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(feature = "snapshot-allocation-diagnostics")]
#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator::new();

type AnyResult<T> = Result<T, Box<dyn Error>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Timing,
    Diagnostic,
}

impl Mode {
    fn parse(value: &str) -> AnyResult<Self> {
        match value {
            "timing" => Ok(Self::Timing),
            "diagnostic" => Ok(Self::Diagnostic),
            _ => Err(invalid(format!(
                "mode must be timing or diagnostic, got {value}"
            ))),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Timing => "timing",
            Self::Diagnostic => "diagnostic",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Shape {
    Ixp700,
    DualFullFeed,
}

impl Shape {
    const ALL: [Self; 2] = [Self::Ixp700, Self::DualFullFeed];

    fn parse(value: &str) -> AnyResult<Self> {
        match value {
            "ixp-700" => Ok(Self::Ixp700),
            "dual-full-feed" => Ok(Self::DualFullFeed),
            _ => Err(invalid(format!(
                "shape must be ixp-700 or dual-full-feed, got {value}"
            ))),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Ixp700 => "ixp-700",
            Self::DualFullFeed => "dual-full-feed",
        }
    }

    const fn full_counts(self) -> (usize, usize, usize) {
        match self {
            Self::Ixp700 => (400_400, 400_400, 700),
            Self::DualFullFeed => (400_400, 800_800, 2),
        }
    }

    const fn smoke_counts(self) -> (usize, usize, usize) {
        match self {
            Self::Ixp700 => (28, 28, 7),
            Self::DualFullFeed => (8, 16, 2),
        }
    }

    const fn paths_per_prefix(self) -> usize {
        match self {
            Self::Ixp700 => 1,
            Self::DualFullFeed => 2,
        }
    }
}

fn prove_shape_contract() {
    assert_eq!(Shape::Ixp700.full_counts(), (400_400, 400_400, 700));
    assert_eq!(Shape::DualFullFeed.full_counts(), (400_400, 800_800, 2));
    assert_eq!(Shape::Ixp700.smoke_counts(), (28, 28, 7));
    assert_eq!(Shape::DualFullFeed.smoke_counts(), (8, 16, 2));
}

#[derive(Debug)]
struct Args {
    mode: Mode,
    smoke: bool,
    shape: Option<Shape>,
    commit: String,
    output: Option<PathBuf>,
}

impl Args {
    fn parse() -> AnyResult<Self> {
        let mut raw = std::env::args().skip(1);
        let mut mode = None;
        let mut smoke = false;
        let mut shape = None;
        let mut commit = None;
        let mut output = None;
        while let Some(argument) = raw.next() {
            match argument.as_str() {
                // Cargo passes this libtest-compatible marker to a
                // `harness = false` bench even when invoked by `cargo test`.
                "--bench" => {}
                "timing" | "diagnostic" if mode.is_none() => {
                    mode = Some(Mode::parse(&argument)?);
                }
                "--smoke" => smoke = true,
                "--shape" => {
                    shape = Some(Shape::parse(
                        &raw.next()
                            .ok_or_else(|| invalid("--shape requires a value"))?,
                    )?);
                }
                "--commit" => {
                    commit = Some(
                        raw.next()
                            .ok_or_else(|| invalid("--commit requires a value"))?,
                    );
                }
                "--output" => {
                    output = Some(PathBuf::from(
                        raw.next()
                            .ok_or_else(|| invalid("--output requires a path"))?,
                    ));
                }
                "--help" | "-h" => {
                    println!(
                        "snapshot_allocation <timing|diagnostic> [--smoke] \
                         [--shape <ixp-700|dual-full-feed>] [--commit SHA] \
                         [--output FILE]"
                    );
                    std::process::exit(0);
                }
                _ => return Err(invalid(format!("unrecognized argument: {argument}"))),
            }
        }
        let mode = mode.ok_or_else(|| invalid("timing or diagnostic mode is required"))?;
        ensure_mode_matches_build(mode)?;
        let commit = validate_retention_args(smoke, commit, output.is_some())?;
        Ok(Self {
            mode,
            smoke,
            shape,
            commit,
            output,
        })
    }
}

fn is_exact_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_retention_args(
    smoke: bool,
    commit: Option<String>,
    has_output: bool,
) -> AnyResult<String> {
    if smoke {
        return Ok(commit.unwrap_or_else(|| "smoke".to_string()));
    }
    let commit =
        commit.ok_or_else(|| invalid("full runs require --commit with the exact git SHA"))?;
    if !is_exact_commit(&commit) {
        return Err(invalid(
            "full-run --commit must be exactly 40 lowercase hexadecimal characters",
        ));
    }
    if !has_output {
        return Err(invalid("full runs require --output for retained JSONL"));
    }
    Ok(commit)
}

fn prove_commit_contract() {
    let exact = "0123456789abcdef0123456789abcdef01234567";
    assert!(is_exact_commit(exact));
    assert!(!is_exact_commit("0123456789abcdef0123456789abcdef0123456"));
    assert!(!is_exact_commit("0123456789ABCDEF0123456789ABCDEF01234567"));
    assert!(!is_exact_commit(
        "host-or-branch-name-must-not-enter-a-receipt"
    ));
    assert_eq!(validate_retention_args(true, None, false).unwrap(), "smoke");
    assert!(validate_retention_args(false, Some(exact.to_string()), true).is_ok());
    assert!(validate_retention_args(false, Some("main".to_string()), true).is_err());
    assert!(validate_retention_args(false, Some(exact.to_string()), false).is_err());
}

fn invalid(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

fn ensure_mode_matches_build(mode: Mode) -> AnyResult<()> {
    let diagnostics = cfg!(feature = "snapshot-allocation-diagnostics");
    match (mode, diagnostics) {
        (Mode::Timing, false) | (Mode::Diagnostic, true) => Ok(()),
        (Mode::Timing, true) => Err(invalid(
            "timing mode refuses a binary compiled with allocation diagnostics",
        )),
        (Mode::Diagnostic, false) => Err(invalid(
            "diagnostic mode requires --features snapshot-allocation-diagnostics",
        )),
    }
}

fn prove_mode_contract() {
    let diagnostics = cfg!(feature = "snapshot-allocation-diagnostics");
    assert_eq!(
        ensure_mode_matches_build(Mode::Timing).is_ok(),
        !diagnostics
    );
    assert_eq!(
        ensure_mode_matches_build(Mode::Diagnostic).is_ok(),
        diagnostics
    );
}

#[derive(Debug)]
struct Fixture {
    shape: Shape,
    peers: Vec<MrtPeerEntry>,
    routes: Vec<Route>,
    expected_per_peer: Vec<u64>,
    prefix_count: usize,
}

impl Fixture {
    fn build(shape: Shape, smoke: bool) -> Self {
        let (prefix_count, path_count, source_count) = if smoke {
            shape.smoke_counts()
        } else {
            shape.full_counts()
        };
        let peers: Vec<_> = (0..source_count).map(make_peer).collect();
        let attributes: Vec<_> = peers
            .iter()
            .map(|peer| {
                Arc::new(vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath {
                        segments: vec![AsPathSegment::AsSequence(vec![
                            64_500,
                            64_501,
                            64_502,
                            peer.peer_asn,
                        ])],
                    }),
                    PathAttribute::LocalPref(100),
                    PathAttribute::Med(peer.peer_asn % 100),
                    PathAttribute::Communities(vec![(peer.peer_asn << 16) | 100]),
                ])
            })
            .collect();
        let received_at = Instant::now();
        let mut routes = Vec::with_capacity(path_count);
        let mut expected_per_peer = vec![0_u64; source_count];
        match shape {
            Shape::Ixp700 => {
                for prefix_index in 0..prefix_count {
                    let source_index = prefix_index % source_count;
                    routes.push(make_route(
                        prefix_index,
                        source_index,
                        &peers,
                        &attributes,
                        received_at,
                    ));
                    expected_per_peer[source_index] += 1;
                }
            }
            Shape::DualFullFeed => {
                for prefix_index in 0..prefix_count {
                    for (source_index, path_count) in expected_per_peer.iter_mut().enumerate() {
                        routes.push(make_route(
                            prefix_index,
                            source_index,
                            &peers,
                            &attributes,
                            received_at,
                        ));
                        *path_count += 1;
                    }
                }
            }
        }
        assert_eq!(routes.len(), path_count);
        Self {
            shape,
            peers,
            routes,
            expected_per_peer,
            prefix_count,
        }
    }
}

fn make_peer(index: usize) -> MrtPeerEntry {
    let ordinal = u32::try_from(index).expect("source count fits u32");
    let address = Ipv4Addr::from(PEER_IPV4_BASE + ordinal);
    MrtPeerEntry {
        peer_addr: IpAddr::V4(address),
        peer_bgp_id: address,
        peer_asn: 64_512 + ordinal,
    }
}

fn make_route(
    prefix_index: usize,
    source_index: usize,
    peers: &[MrtPeerEntry],
    attributes: &[Arc<Vec<PathAttribute>>],
    received_at: Instant,
) -> Route {
    let prefix_ordinal = u32::try_from(prefix_index).expect("prefix count fits u32");
    let peer = &peers[source_index];
    Route {
        prefix: Prefix::V4(Ipv4Prefix::new(
            Ipv4Addr::from(0x0a00_0000_u32 + prefix_ordinal),
            32,
        )),
        next_hop: peer.peer_addr,
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: peer.peer_addr,
        attributes: Arc::clone(&attributes[source_index]),
        received_at,
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: peer.peer_bgp_id,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

#[derive(Debug)]
struct EncodedSample {
    bytes: Vec<u8>,
    elapsed_ns: Option<u64>,
    allocator: Option<AllocatorReceipt>,
    growth: Option<GrowthReceipt>,
}

fn encode(fixture: &Fixture, mode: Mode, fixed_originated_time: u32) -> AnyResult<EncodedSample> {
    #[cfg(not(feature = "snapshot-allocation-diagnostics"))]
    let _ = fixed_originated_time;
    match mode {
        Mode::Timing => {
            let started = Instant::now();
            let bytes = encode_snapshot(
                COLLECTOR_BGP_ID,
                &fixture.peers,
                &fixture.routes,
                &[],
                MRT_TIMESTAMP,
            )?;
            let elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
            Ok(EncodedSample {
                bytes,
                elapsed_ns: Some(elapsed_ns),
                allocator: None,
                growth: None,
            })
        }
        Mode::Diagnostic => {
            #[cfg(feature = "snapshot-allocation-diagnostics")]
            {
                let baseline_live_requested_bytes = ALLOCATOR.begin_measurement();
                let result = encode_snapshot_with_allocation_diagnostics(
                    COLLECTOR_BGP_ID,
                    &fixture.peers,
                    &fixture.routes,
                    &[],
                    MRT_TIMESTAMP,
                    fixed_originated_time,
                );
                let mut allocator = ALLOCATOR.end_measurement(baseline_live_requested_bytes);
                let (bytes, diagnostics) = result?;
                assert_eq!(
                    allocator
                        .final_live_requested_bytes
                        .saturating_sub(allocator.baseline_live_requested_bytes),
                    bytes.capacity(),
                    "the single-threaded measurement window must retain only the returned output",
                );
                allocator.peak_live_overhead_bytes =
                    allocator.peak_live_delta_bytes.saturating_sub(bytes.len());
                assert_eq!(
                    allocator.peak_live_overhead_bytes,
                    allocator.peak_live_delta_bytes.saturating_sub(bytes.len()),
                    "reported peak overhead must exclude the retained output length",
                );
                assert!(
                    diagnostics.ordinary_output_growth_reservations >= fixture.routes.len() as u64,
                    "ordinary output-growth probe must execute at least once per encoded path"
                );
                Ok(EncodedSample {
                    bytes,
                    elapsed_ns: None,
                    allocator: Some(allocator),
                    growth: Some(GrowthReceipt {
                        top_level_unbounded_capacity_misses: diagnostics
                            .ordinary_output_growth_reservations,
                    }),
                })
            }
            #[cfg(not(feature = "snapshot-allocation-diagnostics"))]
            unreachable!("mode/build agreement rejects this branch")
        }
    }
}

#[derive(Debug)]
struct Validation {
    decoded_entry_count: u64,
    semantic_sha256: String,
}

fn validate_snapshot(bytes: &[u8], fixture: &Fixture) -> AnyResult<Validation> {
    let mut reader = SnapshotReader::new(bytes)?;
    if reader.collector_bgp_id() != COLLECTOR_BGP_ID || !reader.view_name().is_empty() {
        return Err(invalid(
            "decoded peer-index table identity does not match fixture",
        ));
    }
    if reader.peers().len() != fixture.peers.len() {
        return Err(invalid(
            "decoded peer inventory length does not match fixture",
        ));
    }
    for (decoded, expected) in reader.peers().iter().zip(&fixture.peers) {
        if decoded.peer_addr != expected.peer_addr
            || decoded.peer_bgp_id != expected.peer_bgp_id
            || decoded.peer_asn != expected.peer_asn
        {
            return Err(invalid("decoded peer inventory does not match fixture"));
        }
    }

    let mut semantic = Sha256::new();
    semantic.update(b"rustbgpd-mrt-snapshot-semantics-v1\0");
    hash_ipv4(&mut semantic, reader.collector_bgp_id());
    hash_bytes(&mut semantic, reader.view_name().as_bytes());
    for peer in reader.peers() {
        hash_ip(&mut semantic, peer.peer_addr);
        hash_ipv4(&mut semantic, peer.peer_bgp_id);
        semantic.update(peer.peer_asn.to_be_bytes());
    }

    let mut decoded_entry_count = 0_u64;
    let mut per_peer = vec![0_u64; fixture.peers.len()];
    let mut prefix_groups = 0_usize;
    let mut current_prefix = None;
    let mut current_prefix_paths = 0_usize;
    let mut attribute_bytes = Vec::new();
    for decoded in reader.by_ref() {
        let entry = decoded?;
        let prefix = match entry.nlri {
            SnapshotNlri::Unicast(prefix) => prefix,
            SnapshotNlri::Generic { .. } => {
                return Err(invalid("unicast fixture decoded a generic NLRI"));
            }
        };
        if entry.add_path || entry.path_id != 0 {
            return Err(invalid("non-Add-Path fixture decoded as Add-Path"));
        }
        let expected_route = fixture
            .routes
            .get(usize::try_from(decoded_entry_count).unwrap_or(usize::MAX))
            .ok_or_else(|| invalid("decoded more entries than the fixture contains"))?;
        if prefix != expected_route.prefix
            || Some(entry.peer_index) != expected_peer_index(expected_route)
            || entry.peer.peer_addr != expected_route.peer
            || entry.next_hop != Some(expected_route.next_hop)
            || entry.link_local_next_hop != expected_route.link_local_next_hop
            || !attributes_match_route(&entry.attributes, expected_route)
        {
            return Err(invalid(
                "decoded prefix, peer, next-hop, or attributes do not match fixture semantics",
            ));
        }
        match current_prefix {
            Some(previous) if previous == prefix => current_prefix_paths += 1,
            Some(_) => {
                if current_prefix_paths != fixture.shape.paths_per_prefix() {
                    return Err(invalid("decoded path multiplicity does not match shape"));
                }
                prefix_groups += 1;
                current_prefix = Some(prefix);
                current_prefix_paths = 1;
            }
            None => {
                current_prefix = Some(prefix);
                current_prefix_paths = 1;
            }
        }
        let peer_index = usize::from(entry.peer_index);
        let count = per_peer
            .get_mut(peer_index)
            .ok_or_else(|| invalid("decoded entry has an out-of-range peer index"))?;
        *count += 1;
        hash_entry(&mut semantic, &entry, prefix, &mut attribute_bytes)?;
        decoded_entry_count += 1;
    }
    if current_prefix.is_some() {
        if current_prefix_paths != fixture.shape.paths_per_prefix() {
            return Err(invalid(
                "decoded final path multiplicity does not match shape",
            ));
        }
        prefix_groups += 1;
    }
    if decoded_entry_count != fixture.routes.len() as u64
        || prefix_groups != fixture.prefix_count
        || per_peer != fixture.expected_per_peer
        || reader.skipped_records() != 0
    {
        return Err(invalid(
            "decoded snapshot cardinality does not match fixture",
        ));
    }
    Ok(Validation {
        decoded_entry_count,
        semantic_sha256: hex_digest(semantic.finalize()),
    })
}

fn expected_peer_index(route: &Route) -> Option<u16> {
    let IpAddr::V4(address) = route.peer else {
        return None;
    };
    u16::try_from(u32::from(address).checked_sub(PEER_IPV4_BASE)?).ok()
}

fn attributes_match_route(decoded: &[PathAttribute], route: &Route) -> bool {
    let expected = route.attributes.as_slice();
    let IpAddr::V4(next_hop) = route.next_hop else {
        return false;
    };
    expected.len() >= 2
        && decoded.len() == expected.len() + 1
        && decoded[..2] == expected[..2]
        && decoded[2] == PathAttribute::NextHop(next_hop)
        && decoded[3..] == expected[2..]
}

fn hash_entry(
    digest: &mut Sha256,
    entry: &SnapshotEntry,
    prefix: Prefix,
    attribute_bytes: &mut Vec<u8>,
) -> AnyResult<()> {
    hash_prefix(digest, prefix);
    digest.update(entry.peer_index.to_be_bytes());
    hash_ip(digest, entry.peer.peer_addr);
    hash_ipv4(digest, entry.peer.peer_bgp_id);
    digest.update(entry.peer.peer_asn.to_be_bytes());
    digest.update(entry.path_id.to_be_bytes());
    digest.update([u8::from(entry.add_path)]);
    attribute_bytes.clear();
    encode_path_attributes(&entry.attributes, attribute_bytes, true, false)?;
    hash_bytes(digest, attribute_bytes);
    hash_optional_ip(digest, entry.next_hop);
    match entry.link_local_next_hop {
        Some(address) => {
            digest.update([1]);
            hash_ipv6(digest, address);
        }
        None => digest.update([0]),
    }
    // `originated_time` is deliberately excluded: production derives it from
    // wall and monotonic clocks, while it is not part of route semantics.
    Ok(())
}

fn hash_prefix(digest: &mut Sha256, prefix: Prefix) {
    match prefix {
        Prefix::V4(prefix) => {
            digest.update([4, prefix.len]);
            hash_ipv4(digest, prefix.addr);
        }
        Prefix::V6(prefix) => {
            digest.update([6, prefix.len]);
            hash_ipv6(digest, prefix.addr);
        }
    }
}

fn hash_optional_ip(digest: &mut Sha256, address: Option<IpAddr>) {
    match address {
        Some(address) => {
            digest.update([1]);
            hash_ip(digest, address);
        }
        None => digest.update([0]),
    }
}

fn hash_ip(digest: &mut Sha256, address: IpAddr) {
    match address {
        IpAddr::V4(address) => {
            digest.update([4]);
            hash_ipv4(digest, address);
        }
        IpAddr::V6(address) => {
            digest.update([6]);
            hash_ipv6(digest, address);
        }
    }
}

fn hash_ipv4(digest: &mut Sha256, address: Ipv4Addr) {
    digest.update(address.octets());
}

fn hash_ipv6(digest: &mut Sha256, address: Ipv6Addr) {
    digest.update(address.octets());
}

fn hash_bytes(digest: &mut Sha256, bytes: &[u8]) {
    digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(bytes);
}

fn sha256(bytes: &[u8]) -> String {
    hex_digest(Sha256::digest(bytes))
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

fn prove_reader_rejects_truncation(bytes: &[u8], fixture: &Fixture) {
    assert!(bytes.len() > 1);
    assert!(
        validate_snapshot(&bytes[..bytes.len() - 1], fixture).is_err(),
        "streaming validation must reject a truncated final record"
    );
}

#[derive(Debug, Clone, Serialize)]
struct AllocatorReceipt {
    alloc_calls: usize,
    alloc_zeroed_calls: usize,
    realloc_calls: usize,
    dealloc_calls: usize,
    requested_bytes: usize,
    baseline_live_requested_bytes: usize,
    final_live_requested_bytes: usize,
    peak_live_requested_bytes: usize,
    peak_live_delta_bytes: usize,
    peak_live_overhead_bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
struct GrowthReceipt {
    top_level_unbounded_capacity_misses: u64,
}

#[derive(Debug, Serialize)]
struct ReceiptRow<'a> {
    schema_version: u8,
    variant: &'static str,
    commit: &'a str,
    mode: &'static str,
    shape: &'static str,
    smoke: bool,
    warmup_count: usize,
    sample_index: usize,
    path_count: usize,
    prefix_count: usize,
    source_count: usize,
    output_len_bytes: usize,
    output_capacity_bytes: usize,
    decoded_entry_count: u64,
    elapsed_ns: Option<u64>,
    raw_sha256: String,
    semantic_sha256: String,
    allocator: Option<AllocatorReceipt>,
    growth: Option<GrowthReceipt>,
}

#[cfg(feature = "snapshot-allocation-diagnostics")]
fn prove_tracker_contract() {
    let layout = Layout::from_size_align(8, 8).expect("valid tracker test layout");
    let zeroed_layout = Layout::from_size_align(16, 8).expect("valid tracker test layout");
    let shrink_layout = Layout::from_size_align(64, 8).expect("valid tracker test layout");
    let before = ALLOCATOR.live_requested_bytes.load(Ordering::Relaxed);
    let baseline = ALLOCATOR.begin_measurement();
    // SAFETY: `layout` is non-zero and valid, and the result is checked before
    // it is dereferenced or passed back to the same allocator.
    let pointer = unsafe { GlobalAlloc::alloc(&ALLOCATOR, layout) };
    assert!(!pointer.is_null());
    // SAFETY: `pointer` is non-null and valid for all `layout.size()` bytes.
    unsafe { pointer.write_bytes(0x5a, layout.size()) };
    // SAFETY: `zeroed_layout` is non-zero and valid, and the result is checked
    // before it is read or passed back to the same allocator.
    let zeroed = unsafe { GlobalAlloc::alloc_zeroed(&ALLOCATOR, zeroed_layout) };
    assert!(!zeroed.is_null());
    // SAFETY: `zeroed` is non-null and valid for `zeroed_layout.size()` bytes.
    let zeroed_is_clear = unsafe {
        std::slice::from_raw_parts(zeroed.cast_const(), zeroed_layout.size())
            .iter()
            .all(|byte| *byte == 0)
    };
    // SAFETY: `pointer` came from `ALLOCATOR` with `layout`; the new size is
    // non-zero. The result is checked before use.
    let resized = unsafe { GlobalAlloc::realloc(&ALLOCATOR, pointer, layout, 32) };
    assert!(!resized.is_null());
    // SAFETY: successful realloc returned storage valid for 32 bytes, which
    // includes the `layout.size()` preserved bytes read here.
    let realloc_preserved = unsafe {
        std::slice::from_raw_parts(resized.cast_const(), layout.size())
            .iter()
            .all(|byte| *byte == 0x5a)
    };
    // SAFETY: `shrink_layout` is non-zero and valid, and the result is checked
    // before it is dereferenced or passed back to the same allocator.
    let shrink_pointer = unsafe { GlobalAlloc::alloc(&ALLOCATOR, shrink_layout) };
    assert!(!shrink_pointer.is_null());
    // SAFETY: `shrink_pointer` is non-null and valid for all
    // `shrink_layout.size()` bytes.
    unsafe { shrink_pointer.write_bytes(0xa5, shrink_layout.size()) };
    // SAFETY: `shrink_pointer` came from `ALLOCATOR` with `shrink_layout`; the
    // new size is non-zero. The result is checked before use.
    let shrunk = unsafe { GlobalAlloc::realloc(&ALLOCATOR, shrink_pointer, shrink_layout, 16) };
    assert!(!shrunk.is_null());
    // SAFETY: successful realloc returned storage valid for the 16 bytes read.
    let shrink_preserved = unsafe {
        std::slice::from_raw_parts(shrunk.cast_const(), 16)
            .iter()
            .all(|byte| *byte == 0xa5)
    };
    // SAFETY: all three pointers came from `ALLOCATOR`, remain live, and are
    // paired with the exact layouts of their current allocations.
    unsafe {
        GlobalAlloc::dealloc(
            &ALLOCATOR,
            resized,
            Layout::from_size_align(32, 8).expect("valid resized layout"),
        );
        GlobalAlloc::dealloc(&ALLOCATOR, zeroed, zeroed_layout);
        GlobalAlloc::dealloc(
            &ALLOCATOR,
            shrunk,
            Layout::from_size_align(16, 8).expect("valid shrunk layout"),
        );
    }
    let stats = ALLOCATOR.end_measurement(baseline);
    assert!(zeroed_is_clear, "alloc_zeroed must return cleared memory");
    assert!(
        realloc_preserved,
        "native realloc must preserve the old bytes"
    );
    assert!(
        shrink_preserved,
        "native shrinking realloc must preserve retained bytes"
    );
    assert_eq!(stats.alloc_calls, 2);
    assert_eq!(stats.alloc_zeroed_calls, 1);
    assert_eq!(stats.realloc_calls, 2);
    assert_eq!(stats.dealloc_calls, 3);
    assert_eq!(stats.requested_bytes, 8 + 16 + 32 + 64 + 16);
    assert_eq!(stats.baseline_live_requested_bytes, before);
    assert_eq!(stats.final_live_requested_bytes, before);
    assert!(stats.peak_live_requested_bytes >= before.saturating_add(112));
    assert!(stats.peak_live_delta_bytes >= 112);
}

fn run_shape(args: &Args, shape: Shape, output: &mut dyn Write) -> AnyResult<()> {
    let fixture = Fixture::build(shape, args.smoke);

    let first_warmup = encode(&fixture, args.mode, FIXED_ORIGINATED_TIME)?;
    let first_validation = validate_snapshot(&first_warmup.bytes, &fixture)?;
    let first_raw = sha256(&first_warmup.bytes);
    if args.smoke {
        prove_reader_rejects_truncation(&first_warmup.bytes, &fixture);
    }
    drop(first_warmup);

    let second_fixed_time = FIXED_ORIGINATED_TIME + 1;
    let second_warmup = encode(&fixture, args.mode, second_fixed_time)?;
    let second_validation = validate_snapshot(&second_warmup.bytes, &fixture)?;
    if first_validation.semantic_sha256 != second_validation.semantic_sha256 {
        return Err(invalid("semantic digest changed across warmups"));
    }
    if args.mode == Mode::Diagnostic && first_raw == sha256(&second_warmup.bytes) {
        return Err(invalid(
            "changing the diagnostic originated time did not change the raw digest",
        ));
    }
    drop(second_warmup);

    let sample_count = if args.smoke || args.mode == Mode::Diagnostic {
        1
    } else {
        TIMING_SAMPLES
    };
    for sample_index in 1..=sample_count {
        let encoded = encode(&fixture, args.mode, FIXED_ORIGINATED_TIME)?;
        let output_len_bytes = encoded.bytes.len();
        let output_capacity_bytes = encoded.bytes.capacity();
        let validation = validate_snapshot(&encoded.bytes, &fixture)?;
        let raw_sha256 = sha256(&encoded.bytes);
        if validation.semantic_sha256 != first_validation.semantic_sha256 {
            return Err(invalid("retained sample semantic digest changed"));
        }
        if args.mode == Mode::Diagnostic && raw_sha256 != first_raw {
            return Err(invalid("fixed-time diagnostic bytes are not deterministic"));
        }
        let row = ReceiptRow {
            schema_version: 1,
            variant: "control",
            commit: &args.commit,
            mode: args.mode.as_str(),
            shape: shape.as_str(),
            smoke: args.smoke,
            warmup_count: WARMUPS,
            sample_index,
            path_count: fixture.routes.len(),
            prefix_count: fixture.prefix_count,
            source_count: fixture.peers.len(),
            output_len_bytes,
            output_capacity_bytes,
            decoded_entry_count: validation.decoded_entry_count,
            elapsed_ns: encoded.elapsed_ns,
            raw_sha256,
            semantic_sha256: validation.semantic_sha256,
            allocator: encoded.allocator,
            growth: encoded.growth,
        };
        serde_json::to_writer(&mut *output, &row)?;
        output.write_all(b"\n")?;
        output.flush()?;
        // Output destruction and allocator accounting are deliberately after
        // elapsed timing and after the diagnostic measurement window.
        drop(encoded.bytes);
    }
    Ok(())
}

fn main() -> AnyResult<()> {
    let args = Args::parse()?;
    prove_mode_contract();
    prove_shape_contract();
    prove_commit_contract();
    #[cfg(feature = "snapshot-allocation-diagnostics")]
    prove_tracker_contract();

    let mut output: Box<dyn Write> = match &args.output {
        Some(path) => Box::new(BufWriter::new(
            OpenOptions::new().create(true).append(true).open(path)?,
        )),
        None => Box::new(BufWriter::new(io::stdout().lock())),
    };
    let shapes: &[Shape] = match args.shape {
        Some(Shape::Ixp700) => &[Shape::Ixp700],
        Some(Shape::DualFullFeed) => &[Shape::DualFullFeed],
        None => &Shape::ALL,
    };
    for shape in shapes {
        run_shape(&args, *shape, &mut output)?;
    }
    Ok(())
}
