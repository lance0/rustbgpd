#[cfg(feature = "codec-allocation-diagnostics")]
use std::alloc::{GlobalAlloc, Layout, System};
use std::net::Ipv4Addr;
#[cfg(not(feature = "codec-allocation-diagnostics"))]
use std::net::{IpAddr, Ipv6Addr};
#[cfg(feature = "codec-allocation-diagnostics")]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[cfg(not(feature = "codec-allocation-diagnostics"))]
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use rustbgpd_wire::attribute::decode_path_attributes_revised;
use rustbgpd_wire::attribute::{decode_path_attributes, encode_path_attributes};
#[cfg(not(feature = "codec-allocation-diagnostics"))]
use rustbgpd_wire::nlri::{decode_nlri, encode_nlri};
use rustbgpd_wire::validate::validate_update_attributes;
#[cfg(not(feature = "codec-allocation-diagnostics"))]
use rustbgpd_wire::{
    Afi, ErrorDisposition, Ipv4NlriEntry, Ipv4Prefix, Ipv4UnicastMode, Ipv6Prefix, MpReachNlri,
    MpUnreachNlri, NlriEntry, Prefix, Safi, UpdateMessage,
};
use rustbgpd_wire::{
    Aggregator, AsPath, AsPathSegment, ExtendedCommunity, LargeCommunity, Origin, PathAttribute,
};

#[cfg(not(feature = "codec-allocation-diagnostics"))]
fn generate_ipv4_prefixes(count: usize) -> Vec<Ipv4Prefix> {
    (0..count)
        .map(|i| {
            let b1 = ((i >> 8) & 0xFF) as u8;
            let b2 = (i & 0xFF) as u8;
            Ipv4Prefix::new(Ipv4Addr::new(10, b1, b2, 0), 24)
        })
        .collect()
}

fn typical_attributes() -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65001, 65002, 65003])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
        PathAttribute::LocalPref(100),
        PathAttribute::Med(50),
        PathAttribute::Communities(vec![0xFFFF_0001, 0xFFFF_0002]),
    ]
}

/// A wider attribute set than [`typical_attributes`]: multi-segment
/// `AS_PATH`, communities of every flavor, route-reflection attributes, an
/// aggregator, and an extended-length (>255 B value) attribute.
///
/// `AS_SET` is deliberately absent — RFC 9774 §3 prohibits originating it, so
/// `encode_path_attributes` rejects it and the whole `attr_encode` group would
/// panic. Multi-segment coverage comes from a second `AS_SEQUENCE` instead;
/// received-side `AS_SET` coverage lives in [`as_set_as_path_wire`].
fn rich_attributes() -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![65001, 65002, 65003, 65004, 65005]),
                AsPathSegment::AsSequence(vec![65010, 65011]),
            ],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
        PathAttribute::LocalPref(100),
        PathAttribute::Med(50),
        // 128 communities = 512-byte value, which forces the extended-length
        // header path on both encode and decode.
        PathAttribute::Communities((0..128).map(|i| 0x0001_0000 + i).collect()),
        PathAttribute::ExtendedCommunities(vec![ExtendedCommunity::new(0x0002_FDE8_0000_0007)]),
        PathAttribute::LargeCommunities(vec![LargeCommunity {
            global_admin: 65001,
            local_data1: 7,
            local_data2: 9,
        }]),
        PathAttribute::OriginatorId(Ipv4Addr::new(10, 0, 0, 9)),
        PathAttribute::ClusterList(vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]),
        PathAttribute::Aggregator(Aggregator {
            asn: 65001,
            router_id: Ipv4Addr::new(10, 0, 0, 9),
            partial: false,
        }),
    ]
}

/// A hand-framed `AS_PATH` carrying a single `AS_SET` segment.
///
/// Framed by hand because `encode_path_attributes` refuses to originate one
/// (RFC 9774 §3). Receiving one is still a real shape with a defined RFC 7606
/// treat-as-withdraw disposition, and the raw segment scan that reaches that
/// verdict runs on every UPDATE, so it stays on the decode side of the bench.
#[cfg(not(feature = "codec-allocation-diagnostics"))]
fn as_set_as_path_wire() -> Vec<u8> {
    let asns: [u32; 2] = [65010, 65011];
    let count = u8::try_from(asns.len()).expect("fixture segment fits one octet");
    let mut buf = vec![
        0x40,          // flags: well-known transitive
        2,             // type: AS_PATH
        2 + count * 4, // value length: segment header + 4-octet ASNs
        1,             // segment type: AS_SET
        count,
    ];
    for asn in asns {
        buf.extend_from_slice(&asn.to_be_bytes());
    }
    buf
}

#[cfg(not(feature = "codec-allocation-diagnostics"))]
fn ipv6_mp_add_path_update() -> (
    UpdateMessage,
    Vec<PathAttribute>,
    NlriEntry,
    NlriEntry,
    IpAddr,
) {
    let announced = NlriEntry {
        path_id: 7,
        prefix: Prefix::V6(Ipv6Prefix::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0x100, 0, 0, 0, 0, 0),
            48,
        )),
    };
    let withdrawn = NlriEntry {
        path_id: 11,
        prefix: Prefix::V6(Ipv6Prefix::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0x200, 0, 0, 0, 0, 0),
            48,
        )),
    };
    let next_hop = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65001])],
        }),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop,
            link_local_next_hop: None,
            announced: vec![announced],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            vpn_announced: vec![],
            labeled_announced: vec![],
            rtc_announced: vec![],
        }),
        PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            withdrawn: vec![withdrawn],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: vec![],
            bgpls_withdrawn: vec![],
            vpn_withdrawn: vec![],
            labeled_withdrawn: vec![],
            rtc_withdrawn: vec![],
        }),
    ];
    let msg = UpdateMessage::build(&[], &[], &attrs, true, true, Ipv4UnicastMode::Body);
    (msg, attrs, announced, withdrawn, next_hop)
}

#[cfg(not(feature = "codec-allocation-diagnostics"))]
fn assert_ipv6_mp_add_path_update(
    msg: &UpdateMessage,
    attrs: &[PathAttribute],
    announced: NlriEntry,
    withdrawn: NlriEntry,
    next_hop: IpAddr,
) {
    let add_path_families = [(Afi::Ipv6, Safi::Unicast)];
    let decoded = msg
        .parse_revised(true, false, false, &add_path_families)
        .expect("clean IPv6 MP-BGP Add-Path UPDATE must parse");
    assert!(
        decoded.malformed.is_empty(),
        "clean fixture must not exercise malformed recovery"
    );
    assert!(decoded.update.announced.is_empty());
    assert!(decoded.update.withdrawn.is_empty());
    assert_eq!(decoded.update.attributes, attrs);
    assert_eq!(decoded.update.bgpls_nlri_discarded, 0);

    let reach = decoded
        .update
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("fixture must decode MP_REACH_NLRI");
    assert_eq!((reach.afi, reach.safi), (Afi::Ipv6, Safi::Unicast));
    assert_eq!(reach.next_hop, next_hop);
    assert_eq!(reach.announced, vec![announced]);
    assert_ne!(reach.announced[0].path_id, 0);

    let unreach = decoded
        .update
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::MpUnreachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("fixture must decode MP_UNREACH_NLRI");
    assert_eq!((unreach.afi, unreach.safi), (Afi::Ipv6, Safi::Unicast));
    assert_eq!(unreach.withdrawn, vec![withdrawn]);
    assert_ne!(unreach.withdrawn[0].path_id, 0);
}

#[cfg(not(feature = "codec-allocation-diagnostics"))]
fn bench_nlri_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("nlri_decode");
    for count in [1, 10, 100, 500] {
        let prefixes = generate_ipv4_prefixes(count);
        let mut buf = Vec::new();
        encode_nlri(&prefixes, &mut buf);
        group.bench_with_input(BenchmarkId::from_parameter(count), &buf, |b, buf| {
            b.iter(|| decode_nlri(buf).unwrap());
        });
    }
    group.finish();
}

#[cfg(not(feature = "codec-allocation-diagnostics"))]
fn bench_nlri_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("nlri_encode");
    for count in [1, 10, 100, 500] {
        let prefixes = generate_ipv4_prefixes(count);
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &prefixes,
            |b, prefixes| {
                b.iter(|| {
                    let mut buf = Vec::with_capacity(prefixes.len() * 4);
                    encode_nlri(prefixes, &mut buf);
                    buf
                });
            },
        );
    }
    group.finish();
}

#[cfg(not(feature = "codec-allocation-diagnostics"))]
fn bench_update_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("update_build");
    let attrs = typical_attributes();
    for count in [1, 10, 100, 500] {
        let entries: Vec<Ipv4NlriEntry> = generate_ipv4_prefixes(count)
            .into_iter()
            .map(|p| Ipv4NlriEntry {
                path_id: 0,
                prefix: p,
            })
            .collect();
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &entries,
            |b, entries| {
                b.iter(|| {
                    UpdateMessage::build(entries, &[], &attrs, true, false, Ipv4UnicastMode::Body)
                });
            },
        );
    }

    let (msg, attrs, announced, withdrawn, next_hop) = ipv6_mp_add_path_update();
    assert_ipv6_mp_add_path_update(&msg, &attrs, announced, withdrawn, next_hop);
    group.bench_function("ipv6_mp_add_path", |b| {
        b.iter(|| UpdateMessage::build(&[], &[], &attrs, true, true, Ipv4UnicastMode::Body));
    });
    group.finish();
}

#[cfg(not(feature = "codec-allocation-diagnostics"))]
fn bench_update_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("update_parse");
    let attrs = typical_attributes();
    for count in [1, 10, 100, 500] {
        let entries: Vec<Ipv4NlriEntry> = generate_ipv4_prefixes(count)
            .into_iter()
            .map(|p| Ipv4NlriEntry {
                path_id: 0,
                prefix: p,
            })
            .collect();
        let msg = UpdateMessage::build(&entries, &[], &attrs, true, false, Ipv4UnicastMode::Body);
        group.bench_with_input(BenchmarkId::from_parameter(count), &msg, |b, msg| {
            b.iter(|| msg.parse(true, false, &[]).unwrap());
        });
    }
    group.finish();
}

#[cfg(not(feature = "codec-allocation-diagnostics"))]
fn bench_update_parse_revised(c: &mut Criterion) {
    let mut group = c.benchmark_group("update_parse_revised");
    let attrs = typical_attributes();
    for count in [1, 10, 100, 500] {
        let entries: Vec<Ipv4NlriEntry> = generate_ipv4_prefixes(count)
            .into_iter()
            .map(|prefix| Ipv4NlriEntry { path_id: 0, prefix })
            .collect();
        let msg = UpdateMessage::build(&entries, &[], &attrs, true, false, Ipv4UnicastMode::Body);
        let decoded = msg
            .parse_revised(true, false, false, &[])
            .expect("clean eBGP UPDATE must parse through the production path");
        assert!(
            decoded.malformed.is_empty(),
            "clean fixture must not exercise malformed recovery"
        );
        assert_eq!(decoded.update.announced, entries);
        assert!(decoded.update.withdrawn.is_empty());
        assert_eq!(decoded.update.attributes, attrs);
        assert_eq!(decoded.update.bgpls_nlri_discarded, 0);

        group.bench_with_input(BenchmarkId::from_parameter(count), &msg, |b, msg| {
            b.iter(|| msg.parse_revised(true, false, false, &[]).unwrap());
        });
    }

    let (msg, attrs, announced, withdrawn, next_hop) = ipv6_mp_add_path_update();
    let add_path_families = [(Afi::Ipv6, Safi::Unicast)];
    assert_ipv6_mp_add_path_update(&msg, &attrs, announced, withdrawn, next_hop);

    group.bench_function("ipv6_mp_add_path", |b| {
        b.iter(|| {
            msg.parse_revised(true, false, false, &add_path_families)
                .unwrap()
        });
    });
    group.finish();
}

#[cfg(not(feature = "codec-allocation-diagnostics"))]
fn bench_attr_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("attr_decode");

    let typical = typical_attributes();
    let mut typical_buf = Vec::new();
    encode_path_attributes(&typical, &mut typical_buf, true, false).unwrap();
    group.bench_with_input(
        BenchmarkId::new("typical", typical.len()),
        &typical_buf,
        |b, buf| {
            b.iter(|| decode_path_attributes(buf, true, &[]).unwrap());
        },
    );

    let rich = rich_attributes();
    let mut rich_buf = Vec::new();
    encode_path_attributes(&rich, &mut rich_buf, true, false).unwrap();
    group.bench_with_input(BenchmarkId::new("rich", rich.len()), &rich_buf, |b, buf| {
        b.iter(|| decode_path_attributes(buf, true, &[]).unwrap());
    });

    // RFC 9774 §3 leaves `AS_SET` un-originatable but still receivable, so the
    // revised decoder is the only side that can carry the shape. The RFC 7606
    // treat-as-withdraw verdict is what makes the fixture load-bearing; assert
    // it once outside the measurement so a silently-clean decode cannot pass
    // for coverage.
    let as_set_buf = as_set_as_path_wire();
    let verdict = decode_path_attributes_revised(&as_set_buf, true, false, &[])
        .expect("AS_SET in AS_PATH is recoverable, not session-reset");
    assert!(
        verdict
            .malformed
            .iter()
            .any(|m| m.disposition == ErrorDisposition::TreatAsWithdraw),
        "AS_SET fixture must keep its RFC 7606 treat-as-withdraw disposition"
    );
    group.bench_with_input(
        BenchmarkId::new("as_set_revised", 1),
        &as_set_buf,
        |b, buf| {
            b.iter(|| decode_path_attributes_revised(buf, true, false, &[]).unwrap());
        },
    );

    group.finish();
}

#[cfg(not(feature = "codec-allocation-diagnostics"))]
fn bench_attr_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("attr_encode");

    let typical = typical_attributes();
    group.bench_with_input(
        BenchmarkId::new("typical", typical.len()),
        &typical,
        |b, attrs| {
            b.iter(|| {
                let mut buf = Vec::with_capacity(128);
                encode_path_attributes(attrs, &mut buf, true, false).unwrap();
                buf
            });
        },
    );

    let rich = rich_attributes();
    group.bench_with_input(BenchmarkId::new("rich", rich.len()), &rich, |b, attrs| {
        b.iter(|| {
            let mut buf = Vec::with_capacity(256);
            encode_path_attributes(attrs, &mut buf, true, false).unwrap();
            buf
        });
    });

    group.finish();
}

#[cfg(not(feature = "codec-allocation-diagnostics"))]
fn bench_validate_update(c: &mut Criterion) {
    let attrs = typical_attributes();
    c.bench_function("validate_update", |b| {
        b.iter(|| validate_update_attributes(&attrs, true, true, true).unwrap());
    });
}

#[cfg(feature = "codec-allocation-diagnostics")]
const DIAGNOSTIC_OPERATIONS: usize = 10_000;

#[cfg(feature = "codec-allocation-diagnostics")]
struct TrackingAllocator {
    enabled: AtomicBool,
    alloc_calls: AtomicUsize,
    alloc_zeroed_calls: AtomicUsize,
    realloc_calls: AtomicUsize,
    requested_bytes: AtomicUsize,
}

#[cfg(feature = "codec-allocation-diagnostics")]
impl TrackingAllocator {
    const fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            alloc_calls: AtomicUsize::new(0),
            alloc_zeroed_calls: AtomicUsize::new(0),
            realloc_calls: AtomicUsize::new(0),
            requested_bytes: AtomicUsize::new(0),
        }
    }

    fn reset(&self) {
        self.enabled.store(false, Ordering::Relaxed);
        self.alloc_calls.store(0, Ordering::Relaxed);
        self.alloc_zeroed_calls.store(0, Ordering::Relaxed);
        self.realloc_calls.store(0, Ordering::Relaxed);
        self.requested_bytes.store(0, Ordering::Relaxed);
    }

    fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
    }

    fn disable(&self) {
        self.enabled.store(false, Ordering::Relaxed);
    }

    fn count(&self, counter: &AtomicUsize, requested_bytes: usize) {
        if self.enabled.load(Ordering::Relaxed) {
            counter.fetch_add(1, Ordering::Relaxed);
            self.requested_bytes
                .fetch_add(requested_bytes, Ordering::Relaxed);
        }
    }

    fn receipt(&self) -> AllocationReceipt {
        assert!(
            !self.enabled.load(Ordering::Relaxed),
            "allocation counters must be disabled before reading a receipt"
        );
        let alloc_calls = self.alloc_calls.load(Ordering::Relaxed);
        let alloc_zeroed_calls = self.alloc_zeroed_calls.load(Ordering::Relaxed);
        let realloc_calls = self.realloc_calls.load(Ordering::Relaxed);
        AllocationReceipt {
            alloc_calls,
            alloc_zeroed_calls,
            realloc_calls,
            allocation_calls: alloc_calls
                .saturating_add(alloc_zeroed_calls)
                .saturating_add(realloc_calls),
            requested_bytes: self.requested_bytes.load(Ordering::Relaxed),
        }
    }
}

#[cfg(feature = "codec-allocation-diagnostics")]
// SAFETY: every operation is forwarded unchanged to `System`; the wrapper
// performs only allocation-free atomic bookkeeping around successful requests.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's `GlobalAlloc` contract provides a valid layout,
        // which is forwarded unchanged to the wrapped allocator.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            self.count(&self.alloc_calls, layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's `GlobalAlloc` contract provides a valid layout,
        // which is forwarded unchanged to the wrapped allocator.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            self.count(&self.alloc_zeroed_calls, layout.size());
        }
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller guarantees the pointer/layout pair came from this
        // allocator. All allocations are delegated to `System`, so forwarding
        // the pair and requested new size preserves that contract.
        let resized = unsafe { System.realloc(pointer, layout, new_size) };
        if !resized.is_null() {
            self.count(&self.realloc_calls, new_size);
        }
        resized
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: every successful allocation came from `System`, and the
        // caller supplies the matching pointer/layout pair.
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[cfg(feature = "codec-allocation-diagnostics")]
#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator::new();

#[cfg(feature = "codec-allocation-diagnostics")]
#[derive(Clone, Copy)]
struct AllocationReceipt {
    alloc_calls: usize,
    alloc_zeroed_calls: usize,
    realloc_calls: usize,
    allocation_calls: usize,
    requested_bytes: usize,
}

#[cfg(feature = "codec-allocation-diagnostics")]
struct DiagnosticRow {
    benchmark: &'static str,
    fixture_attributes: usize,
    fixture_len_bytes: usize,
    fixture_digest: u64,
    allocation: AllocationReceipt,
}

#[cfg(feature = "codec-allocation-diagnostics")]
impl DiagnosticRow {
    fn write_json(&self) {
        assert_eq!(
            self.allocation.allocation_calls,
            self.allocation
                .alloc_calls
                .saturating_add(self.allocation.alloc_zeroed_calls)
                .saturating_add(self.allocation.realloc_calls)
        );
        println!(
            concat!(
                "{{\"schema_version\":1,",
                "\"benchmark\":\"{}\",",
                "\"operations\":{},",
                "\"fixture_attributes\":{},",
                "\"fixture_len_bytes\":{},",
                "\"fixture_digest\":\"fnv1a64:{:016x}\",",
                "\"alloc_calls\":{},",
                "\"alloc_zeroed_calls\":{},",
                "\"realloc_calls\":{},",
                "\"allocation_calls\":{},",
                "\"requested_bytes\":{}}}"
            ),
            self.benchmark,
            DIAGNOSTIC_OPERATIONS,
            self.fixture_attributes,
            self.fixture_len_bytes,
            self.fixture_digest,
            self.allocation.alloc_calls,
            self.allocation.alloc_zeroed_calls,
            self.allocation.realloc_calls,
            self.allocation.allocation_calls,
            self.allocation.requested_bytes,
        );
    }
}

#[cfg(feature = "codec-allocation-diagnostics")]
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        digest ^= u64::from(*byte);
        digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
    }
    digest
}

#[cfg(feature = "codec-allocation-diagnostics")]
fn run_attr_encode_diagnostic() -> DiagnosticRow {
    let attrs = rich_attributes();
    assert_eq!(
        attrs.len(),
        11,
        "diagnostic must retain the Criterion rich/11 fixture"
    );

    let mut expected = Vec::with_capacity(1024);
    encode_path_attributes(&attrs, &mut expected, true, false)
        .expect("rich attributes must encode before measurement");
    assert!(
        expected.len() <= 1024,
        "the caller output must fit its preallocated diagnostic buffer"
    );
    let decoded = decode_path_attributes(&expected, true, &[])
        .expect("rich diagnostic output must round-trip");
    assert_eq!(
        decoded, attrs,
        "rich diagnostic output must round-trip exactly"
    );

    let mut output = Vec::with_capacity(1024);
    assert!(output.capacity() >= 1024);
    ALLOCATOR.reset();
    for _ in 0..DIAGNOSTIC_OPERATIONS {
        output.clear();
        ALLOCATOR.enable();
        let result = encode_path_attributes(&attrs, &mut output, true, false);
        ALLOCATOR.disable();
        result.expect("rich attributes must encode during measurement");
        assert_eq!(
            output, expected,
            "every measured encode must produce the exact fixture bytes"
        );
    }
    let allocation = ALLOCATOR.receipt();
    assert_eq!(
        output, expected,
        "the final measured output must remain exact"
    );

    DiagnosticRow {
        benchmark: "attr_encode/rich/11",
        fixture_attributes: attrs.len(),
        fixture_len_bytes: expected.len(),
        fixture_digest: fnv1a64(&expected),
        allocation,
    }
}

#[cfg(feature = "codec-allocation-diagnostics")]
fn run_validate_update_diagnostic() -> DiagnosticRow {
    let attrs = typical_attributes();
    validate_update_attributes(&attrs, true, true, true)
        .expect("Criterion validation fixture must be valid before measurement");

    let mut encoded_fixture = Vec::with_capacity(1024);
    encode_path_attributes(&attrs, &mut encoded_fixture, true, false)
        .expect("validation fixture must have a stable wire representation");

    ALLOCATOR.reset();
    for _ in 0..DIAGNOSTIC_OPERATIONS {
        ALLOCATOR.enable();
        let result = validate_update_attributes(&attrs, true, true, true);
        ALLOCATOR.disable();
        result.expect("every measured validation must accept the fixture");
    }
    let allocation = ALLOCATOR.receipt();
    validate_update_attributes(&attrs, true, true, true)
        .expect("validation fixture must remain valid after measurement");

    DiagnosticRow {
        benchmark: "validate_update",
        fixture_attributes: attrs.len(),
        fixture_len_bytes: encoded_fixture.len(),
        fixture_digest: fnv1a64(&encoded_fixture),
        allocation,
    }
}

#[cfg(feature = "codec-allocation-diagnostics")]
fn run_attr_decode_revised_diagnostic() -> DiagnosticRow {
    let attrs = typical_attributes();
    assert_eq!(
        attrs.len(),
        6,
        "diagnostic must retain the Criterion typical/6 fixture"
    );

    let mut encoded_fixture = Vec::with_capacity(128);
    encode_path_attributes(&attrs, &mut encoded_fixture, true, false)
        .expect("revised decode fixture must have a stable wire representation");
    let decoded = decode_path_attributes_revised(&encoded_fixture, true, false, &[])
        .expect("revised decode fixture must decode before measurement");
    assert_eq!(
        decoded.attributes, attrs,
        "revised decode fixture must preserve every attribute"
    );
    assert!(
        decoded.malformed.is_empty(),
        "revised decode fixture must not exercise recovery"
    );
    assert_eq!(
        decoded.bgpls_nlri_discarded, 0,
        "revised decode fixture must not discard BGP-LS NLRI"
    );

    ALLOCATOR.reset();
    for _ in 0..DIAGNOSTIC_OPERATIONS {
        ALLOCATOR.enable();
        let result = decode_path_attributes_revised(&encoded_fixture, true, false, &[]);
        ALLOCATOR.disable();
        let decoded = result.expect("every measured revised decode must accept the fixture");
        assert_eq!(
            decoded.attributes, attrs,
            "every measured revised decode must preserve every attribute"
        );
        assert!(
            decoded.malformed.is_empty(),
            "measured revised decode must not exercise recovery"
        );
        assert_eq!(
            decoded.bgpls_nlri_discarded, 0,
            "measured revised decode must not discard BGP-LS NLRI"
        );
    }
    let allocation = ALLOCATOR.receipt();

    DiagnosticRow {
        benchmark: "attr_decode_revised/typical/6",
        fixture_attributes: attrs.len(),
        fixture_len_bytes: encoded_fixture.len(),
        fixture_digest: fnv1a64(&encoded_fixture),
        allocation,
    }
}

#[cfg(feature = "codec-allocation-diagnostics")]
fn main() {
    let attr_encode = run_attr_encode_diagnostic();
    let attr_decode_revised = run_attr_decode_revised_diagnostic();
    let validate_update = run_validate_update_diagnostic();
    assert_ne!(
        attr_encode.fixture_digest, validate_update.fixture_digest,
        "the two diagnostic fixtures must retain distinct digests"
    );
    assert_eq!(
        attr_decode_revised.fixture_digest, validate_update.fixture_digest,
        "revised decode and validation must retain the same typical/6 fixture"
    );
    attr_encode.write_json();
    attr_decode_revised.write_json();
    validate_update.write_json();
}

#[cfg(not(feature = "codec-allocation-diagnostics"))]
criterion_group!(
    benches,
    bench_nlri_decode,
    bench_nlri_encode,
    bench_update_build,
    bench_update_parse,
    bench_update_parse_revised,
    bench_attr_decode,
    bench_attr_encode,
    bench_validate_update,
);
#[cfg(not(feature = "codec-allocation-diagnostics"))]
criterion_main!(benches);
