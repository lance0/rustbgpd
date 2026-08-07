//! Occupancy and timing receipt for the production VPN RIB query path.

#[cfg(feature = "vpn-query-allocation")]
use std::alloc::{GlobalAlloc, Layout};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
#[cfg(feature = "vpn-query-allocation")]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustbgpd_api::proto;
use rustbgpd_api::proto::rib_service_server::RibService as RibServiceTrait;
use rustbgpd_api::rib_service::{RibService, VpnQueryServiceReceipt};
use rustbgpd_rib::{RibManager, RibUpdate, RouteOrigin, VpnRibRoute};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    AsPath, AsPathSegment, ExtendedCommunity, MplsLabelEntry, Origin, PathAttribute,
    RouteDistinguisher, VpnNlri, VpnPrefix,
};
use serde_json::json;
use tokio::sync::{mpsc, oneshot};
use tonic::Request;

#[cfg(feature = "vpn-query-allocation")]
const ALLOC: usize = 0;
#[cfg(feature = "vpn-query-allocation")]
const ALLOC_ZEROED: usize = 1;
#[cfg(feature = "vpn-query-allocation")]
const REALLOC: usize = 2;
#[cfg(feature = "vpn-query-allocation")]
const DEALLOC: usize = 3;

#[cfg(not(feature = "vpn-query-allocation"))]
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(feature = "vpn-query-allocation")]
struct TrackingAllocator {
    inner: tikv_jemallocator::Jemalloc,
    locked: AtomicBool,
    enabled: AtomicBool,
    live: AtomicUsize,
    baseline: AtomicUsize,
    peak: AtomicUsize,
    calls: [AtomicUsize; 4],
    requested_bytes: [AtomicUsize; 4],
}

#[cfg(feature = "vpn-query-allocation")]
impl TrackingAllocator {
    const fn new() -> Self {
        Self {
            inner: tikv_jemallocator::Jemalloc,
            locked: AtomicBool::new(false),
            enabled: AtomicBool::new(false),
            live: AtomicUsize::new(0),
            baseline: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            calls: [const { AtomicUsize::new(0) }; 4],
            requested_bytes: [const { AtomicUsize::new(0) }; 4],
        }
    }

    fn begin(&self) {
        let _guard = self.guard();
        let live = self.live.load(Ordering::Relaxed);
        self.baseline.store(live, Ordering::Relaxed);
        self.peak.store(live, Ordering::Relaxed);
        for counter in self.calls.iter().chain(&self.requested_bytes) {
            counter.store(0, Ordering::Relaxed);
        }
        self.enabled.store(true, Ordering::Relaxed);
    }

    fn end(&self) -> AllocationSnapshot {
        let _guard = self.guard();
        self.enabled.store(false, Ordering::Relaxed);
        let baseline = self.baseline.load(Ordering::Relaxed);
        let peak = self.peak.load(Ordering::Relaxed);
        AllocationSnapshot {
            calls: std::array::from_fn(|index| self.calls[index].load(Ordering::Relaxed)),
            requested_bytes: std::array::from_fn(|index| {
                self.requested_bytes[index].load(Ordering::Relaxed)
            }),
            baseline_live_requested_bytes: baseline,
            final_live_requested_bytes: self.live.load(Ordering::Relaxed),
            peak_live_requested_bytes: peak,
            peak_delta_requested_bytes: peak
                .checked_sub(baseline)
                .expect("allocator peak fell below query baseline"),
        }
    }

    fn guard(&self) -> AllocationGuard<'_> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::hint::spin_loop();
        }
        AllocationGuard(self)
    }

    fn add(&self, bytes: usize) {
        let live = self.live.fetch_add(bytes, Ordering::Relaxed) + bytes;
        if self.enabled.load(Ordering::Relaxed) {
            self.peak.fetch_max(live, Ordering::Relaxed);
        }
    }

    fn record_request(&self, operation: usize, requested: usize) {
        if self.enabled.load(Ordering::Relaxed) {
            self.calls[operation].fetch_add(1, Ordering::Relaxed);
            self.requested_bytes[operation].fetch_add(requested, Ordering::Relaxed);
        }
    }
}

#[cfg(feature = "vpn-query-allocation")]
#[derive(Debug)]
struct AllocationSnapshot {
    calls: [usize; 4],
    requested_bytes: [usize; 4],
    baseline_live_requested_bytes: usize,
    final_live_requested_bytes: usize,
    peak_live_requested_bytes: usize,
    peak_delta_requested_bytes: usize,
}

#[cfg(feature = "vpn-query-allocation")]
struct AllocationGuard<'a>(&'a TrackingAllocator);

#[cfg(feature = "vpn-query-allocation")]
impl Drop for AllocationGuard<'_> {
    fn drop(&mut self) {
        self.0.locked.store(false, Ordering::Release);
    }
}

#[cfg(feature = "vpn-query-allocation")]
// SAFETY: all operations are forwarded unchanged to one jemalloc instance;
// atomic accounting does not alter pointer or layout contracts.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _guard = self.guard();
        self.record_request(ALLOC, layout.size());
        let ptr = unsafe { self.inner.alloc(layout) };
        if !ptr.is_null() {
            self.add(layout.size());
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let _guard = self.guard();
        self.record_request(ALLOC_ZEROED, layout.size());
        let ptr = unsafe { self.inner.alloc_zeroed(layout) };
        if !ptr.is_null() {
            self.add(layout.size());
        }
        ptr
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _guard = self.guard();
        self.record_request(REALLOC, new_size);
        let resized = unsafe { self.inner.realloc(ptr, layout, new_size) };
        if !resized.is_null() {
            if new_size >= layout.size() {
                self.add(new_size - layout.size());
            } else {
                self.live
                    .fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        resized
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _guard = self.guard();
        self.record_request(DEALLOC, layout.size());
        unsafe { self.inner.dealloc(ptr, layout) };
        self.live.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[cfg(feature = "vpn-query-allocation")]
#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator::new();

const PEERS: usize = 16;
const SMOKE_ROUTES: usize = 256;
const BATCH: usize = 4_096;

#[derive(Debug)]
struct QueryReceipt {
    actor_ns: u64,
    service_method_ns: u64,
    post_actor_ns: u64,
    actor_rows: usize,
    actor_capacity: usize,
    actor_snapshot_lower_bound_bytes: usize,
    returned_rows: usize,
    dispatch: u64,
    checksum: u64,
}

fn actor_snapshot_lower_bound_bytes(rows: usize, capacity: usize) -> usize {
    capacity
        .checked_mul(std::mem::size_of::<VpnRibRoute>())
        .and_then(|route_bytes| {
            rows.checked_mul(std::mem::size_of::<MplsLabelEntry>())
                .and_then(|label_bytes| route_bytes.checked_add(label_bytes))
        })
        .expect("VPN RIB actor snapshot lower bound overflow")
}

#[derive(Debug)]
struct CapacityCensored(&'static str);

fn mix(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

fn semantic_hash(rd: &[u8], prefix: &str, peer: &str, label: u32) -> u64 {
    let hash = mix(0xcbf2_9ce4_8422_2325, rd);
    let hash = mix(hash, prefix.as_bytes());
    let hash = mix(hash, peer.as_bytes());
    mix(hash, &label.to_be_bytes())
}

fn route(index: usize, attributes: &Arc<Vec<PathAttribute>>) -> VpnRibRoute {
    let peer_octet = u8::try_from(index % PEERS + 1).unwrap();
    let peer = Ipv4Addr::new(10, 0, 0, peer_octet);
    let prefix = Ipv4Addr::from(0x0b00_0000_u32 + u32::try_from(index).unwrap());
    VpnRibRoute {
        nlri: VpnNlri {
            labels: vec![MplsLabelEntry::try_new(300, 0, true).unwrap()],
            route_distinguisher: RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 100]),
            prefix: VpnPrefix::v4(prefix, 32).unwrap(),
        },
        next_hop: Ipv4Addr::new(192, 0, 2, 1).into(),
        link_local_next_hop: None,
        peer: peer.into(),
        attributes: Arc::clone(attributes),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: peer,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    }
}

fn expected_checksum(routes: usize, filtered: bool) -> u64 {
    let rd = [0, 0, 0xfd, 0xe8, 0, 0, 0, 100];
    (0..routes)
        .filter(|index| !filtered || index % PEERS == 0)
        .fold(0_u64, |sum, index| {
            let peer = format!("10.0.0.{}", index % PEERS + 1);
            let prefix = format!("{}/32", Ipv4Addr::from(0x0b00_0000_u32 + index as u32));
            sum.wrapping_add(semantic_hash(&rd, &prefix, &peer, 300))
        })
}

async fn query(
    service: &RibService,
    actor_rx: &mut mpsc::Receiver<(u64, usize, usize, u64)>,
    service_rx: &mut mpsc::Receiver<VpnQueryServiceReceipt>,
    peer_filter: &str,
    timeout: Duration,
) -> Result<QueryReceipt, CapacityCensored> {
    let deadline = tokio::time::Instant::now() + timeout;
    let started = Instant::now();
    let response = tokio::time::timeout_at(
        deadline,
        service.list_vpn_routes(Request::new(proto::ListVpnRoutesRequest {
            afi_safi: String::new(),
            peer_filter: peer_filter.to_string(),
        })),
    )
    .await
    .map_err(|_| CapacityCensored("service_query"))?
    .unwrap()
    .into_inner();
    let service_method_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    if !peer_filter.is_empty() {
        assert!(
            response
                .routes
                .iter()
                .all(|route| route.peer_address == peer_filter),
            "filtered VPN query returned a route from another peer"
        );
    }
    let (actor_ns, actor_rows, actor_capacity, dispatch) =
        tokio::time::timeout_at(deadline, actor_rx.recv())
            .await
            .map_err(|_| CapacityCensored("actor_receipt"))?
            .expect("VPN RIB actor receipt channel closed");
    let actor_snapshot_lower_bound_bytes =
        actor_snapshot_lower_bound_bytes(actor_rows, actor_capacity);
    let service_receipt = tokio::time::timeout_at(deadline, service_rx.recv())
        .await
        .map_err(|_| CapacityCensored("service_receipt"))?
        .expect("VPN RIB service receipt channel closed");
    assert_eq!(service_receipt.returned_rows, response.routes.len());
    let checksum = response.routes.iter().fold(0_u64, |sum, row| {
        sum.wrapping_add(semantic_hash(
            &row.route_distinguisher,
            &row.prefix,
            &row.peer_address,
            row.labels[0],
        ))
    });
    Ok(QueryReceipt {
        actor_ns,
        service_method_ns,
        post_actor_ns: service_method_ns
            .checked_sub(actor_ns)
            .expect("service_method_ns underflowed actor_handler_ns"),
        actor_rows,
        actor_capacity,
        actor_snapshot_lower_bound_bytes,
        returned_rows: service_receipt.returned_rows,
        dispatch,
        checksum,
    })
}

fn verify(receipt: &QueryReceipt, routes: usize, filtered: bool, dispatch: u64) {
    let expected_rows = if filtered { routes / PEERS } else { routes };
    // The peer filter is evaluated inside the RIB task, so the actor's
    // snapshot is the matching rows — not the whole family table the
    // service would then discard.
    assert_eq!(receipt.actor_rows, expected_rows);
    assert!(receipt.actor_capacity >= expected_rows);
    assert_eq!(
        receipt.actor_snapshot_lower_bound_bytes,
        actor_snapshot_lower_bound_bytes(receipt.actor_rows, receipt.actor_capacity)
    );
    assert_eq!(receipt.returned_rows, expected_rows);
    assert_eq!(receipt.dispatch, dispatch);
    assert_eq!(receipt.checksum, expected_checksum(routes, filtered));
    assert!(receipt.actor_ns > 0);
    assert!(receipt.service_method_ns > 0);
    assert_eq!(
        receipt.post_actor_ns,
        receipt.service_method_ns - receipt.actor_ns
    );
}

async fn run(
    routes: usize,
    case: &str,
    output: &str,
    timeout: Duration,
    declared_cpu: usize,
    linux_affinity: &str,
) -> Result<(), CapacityCensored> {
    let (primary_tx, primary_rx) = mpsc::channel(32);
    let (query_tx, query_rx) = mpsc::channel(8);
    let (actor_tx, mut actor_rx) = mpsc::channel(4);
    let manager = RibManager::new(primary_rx, query_rx, None, None, BgpMetrics::new())
        .with_vpn_query_bench_receipts(actor_tx);
    let manager_task = tokio::spawn(manager.run());
    let attributes = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![64512, 64513])],
        }),
        PathAttribute::LocalPref(100),
        PathAttribute::ExtendedCommunities(vec![ExtendedCommunity::new(0x0002_fde8_0000_0064)]),
    ]);
    let setup_deadline = tokio::time::Instant::now() + timeout;
    for peer_index in 0..PEERS {
        let peer = IpAddr::V4(Ipv4Addr::new(
            10,
            0,
            0,
            u8::try_from(peer_index + 1).unwrap(),
        ));
        let mut indices = (peer_index..routes).step_by(PEERS);
        loop {
            let announced: Vec<_> = indices
                .by_ref()
                .take(BATCH)
                .map(|index| route(index, &attributes))
                .collect();
            if announced.is_empty() {
                break;
            }
            let update = RibUpdate::VpnRoutesReceived {
                peer,
                session_id: 0,
                announced,
                withdrawn: Vec::new(),
            };
            let RibUpdate::VpnRoutesReceived {
                peer: envelope_peer,
                announced,
                ..
            } = &update
            else {
                unreachable!("constructed VPN seed update changed variant");
            };
            assert!(
                announced.iter().all(|route| route.peer == *envelope_peer),
                "VPN seed route ownership differs from its update envelope"
            );
            tokio::time::timeout_at(setup_deadline, primary_tx.send(update))
                .await
                .map_err(|_| CapacityCensored("seed_send"))?
                .expect("VPN RIB primary channel closed during setup");
        }
    }
    let (barrier_tx, barrier_rx) = oneshot::channel();
    tokio::time::timeout_at(
        setup_deadline,
        primary_tx.send(RibUpdate::QueryLocRibCount { reply: barrier_tx }),
    )
    .await
    .map_err(|_| CapacityCensored("barrier_send"))?
    .expect("VPN RIB primary channel closed before the setup barrier");
    let _ = tokio::time::timeout_at(setup_deadline, barrier_rx)
        .await
        .map_err(|_| CapacityCensored("barrier_reply"))?
        .expect("VPN RIB manager dropped the setup barrier reply");

    let (service_tx, mut service_rx) = mpsc::channel(4);
    let service = RibService::new(query_tx).with_vpn_query_bench_receipts(service_tx);
    #[cfg(feature = "vpn-query-allocation")]
    ALLOCATOR.begin();
    let filtered = case == "F";
    let query_result = query(
        &service,
        &mut actor_rx,
        &mut service_rx,
        if filtered { "10.0.0.1" } else { "" },
        timeout,
    )
    .await;
    let allocation = allocation_snapshot();
    let receipt = query_result?;
    verify(&receipt, routes, filtered, 1);
    let (allocation_json, peak_live_requested_bytes) = allocation_evidence(
        allocation.as_ref(),
        receipt.actor_snapshot_lower_bound_bytes,
    );
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let document = json!({
        "schema": 2,
        "allocator": "tikv-jemallocator",
        "mode": if cfg!(feature = "vpn-query-allocation") { "allocation" } else { "timing" },
        "timestamp_unix": timestamp,
        "declared_cpu": declared_cpu,
        "linux_affinity": linux_affinity,
        "routes": routes,
        "peers": PEERS,
        "case": case,
        "query": receipt_json(&receipt),
        "allocation": allocation_json,
        "peak_live_requested_bytes": peak_live_requested_bytes,
        "vmrss_bytes": read_status_kib("VmRSS").map(|value| value * 1024),
        "vmhwm_bytes": read_status_kib("VmHWM").map(|value| value * 1024),
    });
    std::fs::write(output, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    manager_task.abort();
    Ok(())
}

#[cfg(feature = "vpn-query-allocation")]
fn allocation_snapshot() -> Option<AllocationSnapshot> {
    Some(ALLOCATOR.end())
}

#[cfg(not(feature = "vpn-query-allocation"))]
fn allocation_snapshot() -> Option<()> {
    None
}

#[cfg(feature = "vpn-query-allocation")]
fn allocation_evidence(
    value: Option<&AllocationSnapshot>,
    lower_bound: usize,
) -> (serde_json::Value, Option<usize>) {
    let value = value.expect("allocation snapshot missing");
    assert!(
        value.peak_delta_requested_bytes >= lower_bound,
        "query peak delta did not retain the actor snapshot lower bound"
    );
    (
        json!({
            "alloc_calls": value.calls[ALLOC],
            "alloc_requested_bytes": value.requested_bytes[ALLOC],
            "alloc_zeroed_calls": value.calls[ALLOC_ZEROED],
            "alloc_zeroed_requested_bytes": value.requested_bytes[ALLOC_ZEROED],
            "realloc_calls": value.calls[REALLOC],
            "realloc_requested_bytes": value.requested_bytes[REALLOC],
            "dealloc_calls": value.calls[DEALLOC],
            "dealloc_requested_bytes": value.requested_bytes[DEALLOC],
            "baseline_live_requested_bytes": value.baseline_live_requested_bytes,
            "final_live_requested_bytes": value.final_live_requested_bytes,
            "peak_live_requested_bytes": value.peak_live_requested_bytes,
            "peak_delta_requested_bytes": value.peak_delta_requested_bytes,
        }),
        Some(value.peak_live_requested_bytes),
    )
}

#[cfg(not(feature = "vpn-query-allocation"))]
fn allocation_evidence(
    _value: Option<&()>,
    _lower_bound: usize,
) -> (serde_json::Value, Option<usize>) {
    (serde_json::Value::Null, None)
}

fn read_status_kib(field: &str) -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|line| line.starts_with(field))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn read_linux_affinity() -> Option<String> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|line| line.starts_with("Cpus_allowed_list:"))?
        .split_whitespace()
        .nth(1)
        .map(str::to_owned)
}

fn receipt_json(value: &QueryReceipt) -> serde_json::Value {
    json!({
        "actor_handler_ns": value.actor_ns,
        "service_method_ns": value.service_method_ns,
        "post_actor_ns": value.post_actor_ns,
        "actor_rows": value.actor_rows,
        "actor_capacity": value.actor_capacity,
        "vpn_rib_route_size_bytes": std::mem::size_of::<VpnRibRoute>(),
        "mpls_label_entry_size_bytes": std::mem::size_of::<MplsLabelEntry>(),
        "actor_snapshot_lower_bound_bytes": value.actor_snapshot_lower_bound_bytes,
        "returned_rows": value.returned_rows,
        "dispatch": value.dispatch,
        "checksum": value.checksum,
    })
}

fn main() {
    let args: Vec<_> = std::env::args().filter(|arg| arg != "--bench").collect();
    let (routes, case, output, timeout, declared_cpu) = match args.as_slice() {
        [_, mode, case, output, cpu] if mode == "smoke" && (case == "U" || case == "F") => (
            SMOKE_ROUTES,
            case.as_str(),
            output.as_str(),
            Duration::from_secs(10),
            cpu.parse::<usize>()
                .expect("declared CPU must be an integer"),
        ),
        [_, mode, count, case, output, cpu] if mode == "cell" && (case == "U" || case == "F") => {
            let routes = count.parse::<usize>().unwrap();
            assert!([10_000, 100_000, 1_000_000].contains(&routes));
            (
                routes,
                case.as_str(),
                output.as_str(),
                Duration::from_secs(120),
                cpu.parse::<usize>()
                    .expect("declared CPU must be an integer"),
            )
        }
        _ => {
            panic!(
                "usage: vpn_query smoke U|F OUTPUT CPU | vpn_query cell 10000|100000|1000000 U|F OUTPUT CPU"
            )
        }
    };
    let linux_affinity = read_linux_affinity().expect("Linux CPU affinity is unavailable");
    assert_eq!(
        linux_affinity,
        declared_cpu.to_string(),
        "Linux affinity differs from the declared CPU"
    );
    let result = if std::env::var_os("RUSTBGPD_VPN_QUERY_FORCE_CENSOR").is_some() {
        Err(CapacityCensored("forced_fixture"))
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(run(
                routes,
                case,
                output,
                timeout,
                declared_cpu,
                &linux_affinity,
            ))
    };
    if let Err(CapacityCensored(phase)) = result {
        let document = json!({
            "schema": 2,
            "mode": if cfg!(feature = "vpn-query-allocation") { "allocation" } else { "timing" },
            "declared_cpu": declared_cpu,
            "linux_affinity": linux_affinity,
            "routes": routes,
            "case": case,
            "outcome": "capacity_censored",
            "censor_phase": phase,
        });
        std::fs::write(output, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
        std::process::exit(75);
    }
}
