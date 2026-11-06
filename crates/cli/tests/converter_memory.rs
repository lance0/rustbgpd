//! Heap bounds for `rbgp diff snapshot from-bmp`.
//!
//! A snapshot repeats every route's attributes, so a small capture can
//! render to a large output. The converter must not hold that output, or
//! one attribute copy per NLRI, in memory: peak heap stays near one record
//! however many routes the input carries.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::time::UNIX_EPOCH;

use rustbgpctl::ribsnap_bmp;
use rustbgpd_bmp::codec::{encode_initiation, encode_peer_up, encode_route_monitoring};
use rustbgpd_bmp::{BmpPeerInfo, BmpPeerType, BmpVersion};
use rustbgpd_wire::{Capability, OpenMessage};

// Live heap bytes on the measuring thread only; libtest threads allocate
// concurrently.
thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static LIVE: Cell<i64> = const { Cell::new(0) };
    static PEAK: Cell<i64> = const { Cell::new(0) };
}

struct PeakAllocator;

#[global_allocator]
static ALLOCATOR: PeakAllocator = PeakAllocator;

fn track(delta: i64) {
    // `try_with`: the allocator runs in TLS destructors too.
    if COUNTING.try_with(Cell::get).unwrap_or(false) {
        let live = LIVE.with(Cell::get) + delta;
        LIVE.with(|cell| cell.set(live));
        PEAK.with(|cell| cell.set(cell.get().max(live)));
    }
}

fn size(layout: Layout) -> i64 {
    i64::try_from(layout.size()).expect("allocation size fits i64")
}

// SAFETY: every call delegates to `System` unchanged; tracking only
// touches thread-local counters.
unsafe impl GlobalAlloc for PeakAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        track(size(layout));
        // SAFETY: forwarded with the caller's layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        track(-size(layout));
        // SAFETY: `ptr` came from `System` with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        track(i64::try_from(new_size).expect("allocation size fits i64") - size(layout));
        // SAFETY: forwarded with the caller's pointer and layout.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// Counts written bytes and discards them.
struct CountingSink(u64);

impl Write for CountingSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Run `convert` and return (exit code, output bytes, peak live heap bytes).
fn measure(convert: impl FnOnce(&mut CountingSink) -> i32) -> (i32, u64, i64) {
    let mut sink = CountingSink(0);
    LIVE.with(|cell| cell.set(0));
    PEAK.with(|cell| cell.set(0));
    COUNTING.with(|cell| cell.set(true));
    let code = convert(&mut sink);
    COUNTING.with(|cell| cell.set(false));
    let peak = PEAK.with(Cell::get);
    eprintln!(
        "exit {code}, {} output bytes, peak heap {peak} bytes",
        sink.0
    );
    (code, sink.0, peak)
}

fn update(attrs: &[u8], nlri: &[u8]) -> Vec<u8> {
    let mut bytes = vec![255; 16];
    bytes.extend_from_slice(
        &u16::try_from(23 + attrs.len() + nlri.len())
            .unwrap()
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&[2, 0, 0]);
    bytes.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(attrs);
    bytes.extend_from_slice(nlri);
    bytes
}

/// One post-policy Adj-RIB-Out UPDATE whose `routes` NLRIs share a
/// COMMUNITIES attribute of `communities` values, then End-of-RIB.
fn amplifying_capture(communities: u16, routes: u16) -> Vec<u8> {
    let info = BmpPeerInfo {
        peer_addr: "192.0.2.30".parse().unwrap(),
        neighbor: 1,
        peer_asn: 65001,
        peer_bgp_id: Ipv4Addr::new(192, 0, 2, 30),
        peer_type: BmpPeerType::Global,
        is_ipv6: false,
        is_post_policy: true,
        is_rib_out: true,
        is_as4: true,
        timestamp: UNIX_EPOCH,
    };
    let mut open = Vec::new();
    OpenMessage {
        version: 4,
        my_as: 65001,
        hold_time: 90,
        bgp_identifier: Ipv4Addr::new(192, 0, 2, 1),
        capabilities: vec![Capability::FourOctetAs { asn: 65001 }],
    }
    .encode(&mut open)
    .unwrap();
    let mut bytes = encode_initiation("rs", "amplification fixture", BmpVersion::V3).to_vec();
    bytes.extend(encode_peer_up(
        &info,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        179,
        40000,
        &open,
        &open,
        BmpVersion::V3,
    ));
    let mut attrs = vec![64, 1, 1, 0, 64, 2, 0, 64, 3, 4, 192, 0, 2, 20];
    attrs.extend_from_slice(&[0xD0, 8]); // optional transitive, extended length
    attrs.extend_from_slice(&(communities * 4).to_be_bytes());
    for community in 0..communities {
        attrs.extend_from_slice(&(0xFDE9_0000_u32 | u32::from(community)).to_be_bytes());
    }
    let mut nlri = Vec::new();
    for route in 0..routes {
        let [high, low] = route.to_be_bytes();
        nlri.extend_from_slice(&[24, 10, high, low]);
    }
    bytes.extend(encode_route_monitoring(
        &info,
        &update(&attrs, &nlri),
        None,
        BmpVersion::V3,
    ));
    bytes.extend(encode_route_monitoring(
        &info,
        &update(&[], &[]),
        None,
        BmpVersion::V3,
    ));
    bytes
}

/// Load-bearing: cloning the attribute set per NLRI holds 4 MiB of
/// communities, and buffering the rendered snapshot holds about 11 MB.
#[test]
fn from_bmp_peak_heap_stays_near_one_record() {
    let capture = amplifying_capture(1024, 1024);
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&capture).unwrap();
    let opts = ribsnap_bmp::FromBmpOpts {
        file: file.path(),
        peers: &[],
        source: None,
        generation: 0,
    };
    let (code, output, peak) = measure(|sink| ribsnap_bmp::from_bmp_to(&opts, sink));
    assert_eq!(code, 0);
    assert!(output > 10_000_000, "{output} output bytes");
    assert!(
        peak < 2 << 20,
        "peak heap {peak} bytes for {output} output bytes"
    );
}
