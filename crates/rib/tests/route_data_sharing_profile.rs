//! Decision harness for the shared-`RouteData` refactor — **measured and
//! REJECTED**. The proposal was to split `Route` into a shared immutable
//! `RouteData` (referenced from each RIB) plus a thin per-RIB wrapper, to stop
//! triplicating the route *shell* across Adj-RIB-In / Loc-RIB / Adj-RIB-Out in
//! the route-reflector / route-server fanout shape (where Adj-RIB-Out clones,
//! one per advertised peer, dominate). This harness sized the win against a
//! `>=25%`-of-RR-heap gate; the realistic design clears only 5–13%, so the
//! refactor was **not shipped**. Kept as the reproducible evidence behind that
//! call — see `docs/BENCHMARKS.md` and the sprint plan's gate-decision entry.
//!
//! Run: `cargo test -p rustbgpd-rib --test route_data_sharing_profile -- --ignored --nocapture`
//! `#[ignore]`d — a sizing harness, not a regression test: it allocates a few
//! hundred MB transiently and prints a report. It is still **compiled by a
//! normal `cargo test` run**, so it cannot silently bit-rot against the `Route`
//! / RIB APIs.
//!
//! ## Results (50k prefixes per RIB; `size_of::<Route>()` = 120 B)
//!
//! | shape | P=2 | P=8 |
//! |---|---|---|
//! | realistic split, light policy (transparent RR) | 11.0% | 13.4% |
//! | realistic split, heavy policy (per-client rewrite) — FLOOR | 4.8% | 5.5% |
//! | `Arc<Route>` whole-shell — UNACHIEVABLE upper bound | 36.5% | 31.0% |
//!
//! **The `Arc<Route>` whole-shell row is an unachievable upper bound**, kept
//! only to reconcile with the original (mistaken) gate reading that flipped the
//! decision. It would collapse the entire 120 B `Route` to an 8 B pointer — but
//! `is_stale` / `is_llgr_stale` (Adj-RIB-In graceful restart) and
//! `validation_state` / `aspa_state` (RPKI / ASPA cache updates) **mutate per
//! RIB**, so the full shell can never be shared. The realistic split can share
//! only the 64 B identity record while every copy keeps a 64 B per-RIB wrapper,
//! recovering only ~40% of that upper bound — hence 5–13%, not 31–37%.
//!
//! ## Method
//!
//! A tracking global allocator (the repo's `memory_profile` methodology — exact
//! live-heap bytes, equivalent to dhat's core metric) reads the real RR-shape
//! heap (P Adj-RIB-In + Loc-RIB + P Adj-RIB-Out) as the denominator, then
//! measures the owned-`Route` vs split (`Arc<RouteData>` identity + per-RIB
//! wrapper) storage difference for the Loc-RIB + Adj-RIB-Out clone set.
//!
//! Two denominators are reported per peer-count:
//!   * **light policy** — every Adj-RIB-Out client advertises the route
//!     unchanged, so all egress copies share one attributes `Arc`. This is the
//!     shape the original gate measured.
//!   * **heavy policy** — every client rewrites communities + next-hop, so the
//!     attributes `Arc` can no longer be shared across clients; each egress
//!     copy carries a distinct attribute set. This inflates total heap, so the
//!     same identity-sharing saving becomes a smaller fraction of it. This is
//!     the conservative floor: does the win survive per-client export policy?
//!
//! The split models the **real** refactor (`RouteData` = identity fields only;
//! attributes + next-hop deliberately stay on the per-RIB wrapper so per-client
//! policy still shares the identity), so the saving here is attribute-
//! independent: it is the same bytes whether egress attributes are shared or
//! distinct. Only the denominator moves between light and heavy.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rustbgpd_rib::adj_rib_in::AdjRibIn;
use rustbgpd_rib::adj_rib_out::AdjRibOut;
use rustbgpd_rib::loc_rib::LocRib;
use rustbgpd_rib::route::{NextHopScope, Route, RouteOrigin};
use rustbgpd_wire::{
    AsPath, AsPathSegment, AspaValidation, Ipv4Prefix, Origin, PathAttribute, Prefix,
    RpkiValidation,
};

struct TrackingAllocator {
    inner: System,
    allocated: AtomicUsize,
}
impl TrackingAllocator {
    const fn new() -> Self {
        Self {
            inner: System,
            allocated: AtomicUsize::new(0),
        }
    }
    fn allocated(&self) -> usize {
        self.allocated.load(Ordering::Relaxed)
    }
}
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { self.inner.alloc(l) };
        if !p.is_null() {
            self.allocated.fetch_add(l.size(), Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        self.allocated.fetch_sub(l.size(), Ordering::Relaxed);
        unsafe { self.inner.dealloc(p, l) };
    }
}
#[global_allocator]
static ALLOC: TrackingAllocator = TrackingAllocator::new();

/// Shared immutable identity record under the proposed split. Attributes and
/// next-hop are deliberately NOT here — they stay on the per-RIB wrapper so
/// per-client export policy (which rewrites them) still shares this record.
#[allow(dead_code)]
struct RouteData {
    prefix: Prefix,
    peer: IpAddr,
    received_at: Instant,
    origin_type: RouteOrigin,
    peer_router_id: Ipv4Addr,
    path_id: u32,
}

/// Per-RIB / per-client wrapper: shares identity via `Arc<RouteData>`, owns the
/// policy-mutable surface (attributes, next-hop) + the per-RIB mutable flags
/// (`is_stale`/`is_llgr_stale`, RPKI/ASPA validation) that today force a full
/// `Route` copy per RIB.
#[allow(dead_code)]
struct SplitRoute {
    data: Arc<RouteData>,
    next_hop: IpAddr,
    link_local_next_hop: Option<Ipv6Addr>,
    next_hop_scope: Option<Box<NextHopScope>>,
    attributes: Arc<Vec<PathAttribute>>,
    is_stale: bool,
    is_llgr_stale: bool,
    validation_state: RpkiValidation,
    aspa_state: AspaValidation,
}

/// Ingress attributes for source peer `i` — one `Arc` shared across all its
/// prefixes (the natural Adj-RIB-In shape).
fn attrs(i: u32) -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65000 + i, 65100, 65200])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, i as u8, 1)),
        PathAttribute::LocalPref(100),
        PathAttribute::Med(50),
        PathAttribute::Communities(vec![0xFFFF_0001, 0xFFFF_0002]),
    ]
}

/// Post-policy egress attributes for `client` advertising prefix index `idx`:
/// distinct communities + AS_PATH tail so the attribute set cannot be shared
/// across clients (the heavy-policy shape). A fresh `Arc` per call.
fn client_attrs(client: u32, idx: u32) -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![
                65000 + (idx % 64000),
                65100 + client,
                65200,
            ])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, (client & 0xFF) as u8, 1, 1)),
        PathAttribute::LocalPref(100),
        PathAttribute::Med(50),
        PathAttribute::Communities(vec![0xFFFF_0000 | client, 0xFFFF_0001, idx & 0xFFFF]),
    ]
}

fn make_route(prefix: Prefix, i: u32, a: &Arc<Vec<PathAttribute>>) -> Route {
    Route {
        prefix,
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, i as u8, 1)),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, i as u8, 1)),
        attributes: a.clone(),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::new(10, 0, i as u8, 1),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

/// A post-policy egress route for `client`/`idx` with its own (unshared)
/// attribute set and next-hop — the heavy-policy egress shape.
fn make_client_route(prefix: Prefix, client: u32, idx: u32) -> Route {
    let a = Arc::new(client_attrs(client, idx));
    Route {
        prefix,
        next_hop: IpAddr::V4(Ipv4Addr::new(10, (client & 0xFF) as u8, 1, 1)),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        attributes: a,
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::new(10, 0, 1, 1),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

fn prefixes(n: usize) -> Vec<Prefix> {
    (0..n)
        .map(|i| {
            let b0 = ((i >> 16) & 0xFF) as u8;
            let b1 = ((i >> 8) & 0xFF) as u8;
            let b2 = (i & 0xFF) as u8;
            Prefix::V4(Ipv4Prefix::new(
                Ipv4Addr::new(b0.wrapping_add(1), b1, b2, 0),
                24,
            ))
        })
        .collect()
}

/// Build the RR fanout shape (P Adj-RIB-In + Loc-RIB + P Adj-RIB-Out) and
/// return the live-heap bytes it occupies. `heavy_policy` controls whether each
/// Adj-RIB-Out client gets its own (unshared) post-policy attribute set.
fn rr_shape_heap(pfx: &[Prefix], p: usize, heavy_policy: bool) -> (usize, Vec<Route>) {
    let base = ALLOC.allocated();
    let ribs: Vec<AdjRibIn> = (0..p)
        .map(|i| {
            let mut r = AdjRibIn::new(IpAddr::V4(Ipv4Addr::new(10, 0, i as u8 + 1, 1)));
            let a = Arc::new(attrs(i as u32 + 1));
            for x in pfx {
                r.insert(make_route(*x, i as u32 + 1, &a));
            }
            r
        })
        .collect();
    let mut loc = LocRib::new();
    for x in pfx {
        loc.recompute(*x, ribs.iter().flat_map(|r| r.iter_prefix(x)));
    }
    let mut outs: Vec<AdjRibOut> = (0..p)
        .map(|i| AdjRibOut::new(IpAddr::V4(Ipv4Addr::new(10, 0, i as u8 + 1, 1))))
        .collect();
    for (client, o) in outs.iter_mut().enumerate() {
        for (idx, x) in pfx.iter().enumerate() {
            if heavy_policy {
                o.insert(make_client_route(*x, client as u32, idx as u32));
            } else if let Some(b) = loc.get(x) {
                // light: every client advertises the winner unchanged, sharing
                // its attributes Arc.
                o.insert(b.clone());
            }
        }
    }
    let total = ALLOC.allocated() - base;
    let winners: Vec<Route> = loc.iter().cloned().collect();
    (total, winners)
}

fn mb(b: usize) -> String {
    format!("{:.1} MB", b as f64 / 1_048_576.0)
}

#[test]
#[ignore = "sizing harness, not a regression test; run on demand with --ignored"]
fn route_data_sharing_profile() {
    let rs = std::mem::size_of::<Route>();
    let ds = std::mem::size_of::<RouteData>();
    let ws = std::mem::size_of::<SplitRoute>();
    println!();
    println!("=== Route-data sharing potential: identity-shell duplication in RR fanout ===");
    println!(
        "    size_of::<Route>() = {rs} B  |  proposed RouteData = {ds} B  |  wrapper = {ws} B"
    );
    let n = 50_000usize;
    let pfx = prefixes(n);
    println!("    prefixes per RIB = {n}");

    for p in [2usize, 8usize] {
        // Two denominators: light (egress attrs shared) and heavy (per-client
        // distinct egress attrs). Heavy is the conservative floor.
        let (light_total, winners) = rr_shape_heap(&pfx, p, false);
        let (heavy_total, _) = rr_shape_heap(&pfx, p, true);

        // Numerator: realistic RouteData split saving for the (p+1)-copy clone
        // set (Loc-RIB winner + p Adj-RIB-Out copies). The saving is the shared
        // identity fields; it is attribute-independent (attributes live on the
        // wrapper in both forms and cancel), so it is valid for both denominators.
        let b_owned = ALLOC.allocated();
        let owned: Vec<HashMap<Prefix, Route>> = (0..=p)
            .map(|_| winners.iter().map(|r| (r.prefix, r.clone())).collect())
            .collect();
        let owned_mem = ALLOC.allocated() - b_owned;
        drop(owned);

        let b_split = ALLOC.allocated();
        // One shared identity record per prefix; every copy points at it.
        let datas: Vec<Arc<RouteData>> = winners
            .iter()
            .map(|r| {
                Arc::new(RouteData {
                    prefix: r.prefix,
                    peer: r.peer,
                    received_at: r.received_at,
                    origin_type: r.origin_type,
                    peer_router_id: r.peer_router_id,
                    path_id: r.path_id,
                })
            })
            .collect();
        let split: Vec<HashMap<Prefix, SplitRoute>> = (0..=p)
            .map(|_| {
                winners
                    .iter()
                    .zip(&datas)
                    .map(|(r, d)| {
                        (
                            r.prefix,
                            SplitRoute {
                                data: d.clone(),
                                next_hop: r.next_hop,
                                link_local_next_hop: r.link_local_next_hop,
                                next_hop_scope: r.next_hop_scope.clone(),
                                attributes: r.attributes.clone(),
                                is_stale: r.is_stale,
                                is_llgr_stale: r.is_llgr_stale,
                                validation_state: r.validation_state,
                                aspa_state: r.aspa_state,
                            },
                        )
                    })
                    .collect()
            })
            .collect();
        let split_mem = ALLOC.allocated() - b_split;
        drop(split);
        drop(datas);

        // Reconciliation: the DEAD `Arc<Route>` whole-shell upper bound the
        // original gate measured. Shares the entire 120 B shell (incl. the
        // per-RIB-mutable flags it must not), so it overstates the achievable
        // win — kept here only to show why the prior gate read ~31-37%.
        let arc_winners: Vec<Arc<Route>> = winners.iter().map(|r| Arc::new(r.clone())).collect();
        let b_arc = ALLOC.allocated();
        let arc_shared: Vec<HashMap<Prefix, Arc<Route>>> = (0..=p)
            .map(|_| arc_winners.iter().map(|r| (r.prefix, r.clone())).collect())
            .collect();
        let arc_mem = ALLOC.allocated() - b_arc;
        drop(arc_shared);
        drop(arc_winners);
        drop(winners);
        let arc_saving = owned_mem.saturating_sub(arc_mem);
        let pct_arc_light = 100.0 * arc_saving as f64 / light_total as f64;

        let saving = owned_mem.saturating_sub(split_mem);
        let pct_light = 100.0 * saving as f64 / light_total as f64;
        let pct_heavy = 100.0 * saving as f64 / heavy_total as f64;
        println!();
        println!("  P={p} ({} Adj-RIB-Out clients):", p);
        println!(
            "    clone-set storage: owned {:>9}  ->  RouteData-split {:>9}  =  saving {:>9}",
            mb(owned_mem),
            mb(split_mem),
            mb(saving),
        );
        println!(
            "    light-policy heap {:>9}  ->  saving is {:.1}% of RR heap",
            mb(light_total),
            pct_light,
        );
        println!(
            "    heavy-policy heap {:>9}  ->  saving is {:.1}% of RR heap   <-- per-client-policy FLOOR",
            mb(heavy_total),
            pct_heavy,
        );
        println!(
            "    [reconcile] DEAD Arc<Route> whole-shell upper bound: saving {:>9} = {:.1}% (light) — unachievable",
            mb(arc_saving),
            pct_arc_light,
        );
    }
    println!();
    println!("  RouteData split shares ONLY the identity fields (prefix/peer/path_id/origin/");
    println!("  router_id/received_at); attributes + next-hop stay per-copy, so the saving is");
    println!("  the same under light and heavy policy. Heavy policy only enlarges the heap the");
    println!("  saving is measured against (distinct egress attribute sets), lowering the %.");
}
