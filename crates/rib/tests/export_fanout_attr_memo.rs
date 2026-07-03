//! Live-heap receipt for the export-fanout attribute memo (2026-07-03 dhat
//! profile, indictment #1): a modifying export chain used to deep-clone the
//! attribute set per (route, peer) — 5.5x the no-policy RR-fanout footprint
//! at 256 peers x 10k prefixes. With the pass-scoped `ExportMemo`, the
//! with-policy live heap must sit near the no-policy baseline.
//!
//! Reduced reproduction of the profile's `fanout_policy` scenario:
//! 64 RR clients x 2k prefixes, one shared inbound attribute set, and a
//! tagging chain (AS_PATH regex guard + med-set + community-add) so every
//! permitted route carries modifications.
//!
//! Run: `cargo test -p rustbgpd-rib --test export_fanout_attr_memo -- --ignored --nocapture`
//! `#[ignore]`d — a sizing receipt, not a regression test: it allocates
//! ~100 MB transiently and its bound is a heap ratio, not exact bytes. Still
//! compiled by a normal `cargo test` run, so it cannot bit-rot.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rustbgpd_policy::{
    AsPathRegex, Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications,
};
use rustbgpd_rib::RibManager;
use rustbgpd_rib::route::{Route, RouteOrigin};
use rustbgpd_rib::update::RibUpdate;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Afi, AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute, Prefix, Safi};
use tokio::sync::{mpsc, oneshot};

struct TrackingAllocator {
    inner: System,
    live: AtomicUsize,
    total_allocs: AtomicUsize,
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { self.inner.alloc(layout) };
        if !p.is_null() {
            self.live.fetch_add(layout.size(), Ordering::Relaxed);
            self.total_allocs.fetch_add(1, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { self.inner.dealloc(ptr, layout) };
        self.live.fetch_sub(layout.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { self.inner.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            self.live.fetch_add(new_size, Ordering::Relaxed);
            self.live.fetch_sub(layout.size(), Ordering::Relaxed);
            self.total_allocs.fetch_add(1, Ordering::Relaxed);
        }
        p
    }
}

#[global_allocator]
static ALLOC: TrackingAllocator = TrackingAllocator {
    inner: System,
    live: AtomicUsize::new(0),
    total_allocs: AtomicUsize::new(0),
};

/// Tagging export chain in the shape of the profile's M80 fixture:
/// AS_PATH regex guard + med-set + community-add, so modifications are
/// non-empty for every permitted route.
fn tagging_chain() -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Permit,
            match_community: vec![],
            match_as_path: Some(AsPathRegex::new("_65100_").unwrap()),
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications {
                set_med: Some(200),
                communities_add: vec![(65000 << 16) | 999],
                ..Default::default()
            },
        }],
        default_action: PolicyAction::Permit,
    }])
}

fn route(prefix: Prefix, peer: IpAddr, attributes: Arc<Vec<PathAttribute>>) -> Route {
    Route {
        prefix,
        next_hop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer,
        attributes,
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::new(192, 0, 2, 99),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

async fn barrier(tx: &mpsc::Sender<RibUpdate>) -> usize {
    let (reply, rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply })
        .await
        .unwrap();
    rx.await.unwrap()
}

/// RR fanout through the real `RibManager::run()` loop. Returns
/// (steady-state live-heap delta in bytes, total allocation count) for
/// the scenario. Outbound channels are sized to hold the full flood, so
/// steady state is deterministic — no sleeps.
fn run_fanout(n_peers: usize, n_prefixes: u32, with_policy: bool) -> (usize, usize) {
    let live_before = ALLOC.live.load(Ordering::Relaxed);
    let allocs_before = ALLOC.total_allocs.load(Ordering::Relaxed);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let live_steady = rt.block_on(async {
        let (tx, rx) = mpsc::channel(4096);
        let (_qtx, qrx) = mpsc::channel::<RibUpdate>(64);
        let manager = RibManager::new(
            rx,
            qrx,
            None,
            Some(Ipv4Addr::new(192, 0, 2, 1)),
            BgpMetrics::new(),
        );
        let handle = tokio::spawn(manager.run());

        let chain = with_policy.then(tagging_chain);
        let mut receivers = Vec::with_capacity(n_peers);
        for i in 0..n_peers {
            let [_, b1, b2, b3] = (i as u32).to_be_bytes();
            let (out_tx, out_rx) = mpsc::channel(n_prefixes as usize + 64);
            tx.send(RibUpdate::PeerUp {
                per_client_best: false,
                session_id: 1 + i as u64,
                peer: IpAddr::V4(Ipv4Addr::new(10, b1, b2, b3.wrapping_add(1))),
                peer_asn: 64_512,
                peer_router_id: Ipv4Addr::new(192, 0, 2, 200),
                outbound_tx: out_tx,
                export_policy: chain.clone(),
                sendable_families: vec![(Afi::Ipv4, Safi::Unicast)],
                is_ebgp: false,
                route_reflector_client: true,
                orr_vantage: None,
                add_path_send_families: vec![],
                add_path_send_max: 0,
                negotiated_orf_recv: Vec::new(),
                negotiated_llgr_families: Vec::new(),
            })
            .await
            .unwrap();
            receivers.push(out_rx);
        }
        barrier(&tx).await;

        // One source floods n_prefixes sharing a single attribute set
        // (the profile harness shape: attrs maximally Arc-shared at
        // ingest; per-peer structural fanout is what is measured).
        let src = IpAddr::V4(Ipv4Addr::new(172, 20, 0, 10));
        let shared: Arc<Vec<PathAttribute>> = Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65000, 65100, 65200])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(198, 51, 100, 1)),
            PathAttribute::LocalPref(100),
            PathAttribute::Med(50),
            PathAttribute::Communities(vec![(65000 << 16) | 100]),
        ]);
        let mut i = 0u32;
        while i < n_prefixes {
            let hi = (i + 1000).min(n_prefixes);
            let batch: Vec<Route> = (i..hi)
                .map(|j| {
                    let p = Prefix::V4(Ipv4Prefix::new(
                        Ipv4Addr::new(20 + (j >> 16) as u8, (j >> 8) as u8, j as u8, 0),
                        24,
                    ));
                    route(p, src, Arc::clone(&shared))
                })
                .collect();
            i = hi;
            tx.send(RibUpdate::RoutesReceived {
                session_id: 0,
                peer: src,
                announced: batch,
                withdrawn: vec![],
                flowspec_announced: vec![],
                flowspec_withdrawn: vec![],
                evpn_announced: vec![],
                evpn_withdrawn: vec![],
            })
            .await
            .unwrap();
        }
        let count = barrier(&tx).await;
        assert_eq!(count, n_prefixes as usize);

        // Steady state: flood ingested + distributed; every per-peer copy
        // is retained (Adj-RIB-Out + the undrained outbound buffers).
        let live = ALLOC.live.load(Ordering::Relaxed) - live_before;

        drop(tx);
        handle.await.unwrap();
        drop(receivers);
        live
    });
    drop(rt);
    (
        live_steady,
        ALLOC.total_allocs.load(Ordering::Relaxed) - allocs_before,
    )
}

#[test]
#[ignore = "sizing receipt, not a regression test; run on demand with --ignored --nocapture"]
fn policy_fanout_live_heap_near_no_policy_baseline() {
    const PEERS: usize = 64;
    const PREFIXES: u32 = 2000;

    let (base_live, base_allocs) = run_fanout(PEERS, PREFIXES, false);
    let (policy_live, policy_allocs) = run_fanout(PEERS, PREFIXES, true);

    #[allow(clippy::cast_precision_loss)]
    let ratio = policy_live as f64 / base_live as f64;
    println!(
        "no-policy: {:.1} MB live / {} allocs; tagging-policy: {:.1} MB live / {} allocs; ratio {ratio:.2}x",
        base_live as f64 / 1e6,
        base_allocs,
        policy_live as f64 / 1e6,
        policy_allocs,
    );

    // Pre-memo this ratio was ~4-5x at this shape (5.5x at the profile's
    // 256x10k). The memo shares one modified attribute set across all
    // (route, peer) pairs, so with-policy must sit near the baseline.
    assert!(
        ratio < 1.5,
        "policy fanout live heap {policy_live} B is {ratio:.2}x the no-policy {base_live} B"
    );
}
