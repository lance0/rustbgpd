//! Differential proof for the incremental best-path recompute and the
//! announcing-peers reverse index (`UnicastPrefixPeers`).
//!
//! Random operation sequences — announces (incl. same-peer attr changes,
//! Add-Path ties, refresh-style replays), withdrawals, session teardown,
//! GR stale marking, LLGR promotion, and `EoR` sweeps/clears — are applied
//! through the same seams production uses. After every step:
//!
//! 1. the Loc-RIB best for every prefix must be IDENTICAL to a
//!    from-scratch full-scan recompute over every peer's Adj-RIB-In (the
//!    pre-index reference semantics), and
//! 2. the reverse index must satisfy its never-under-count contract:
//!    every (prefix, peer) pair present in an Adj-RIB-In is indexed
//!    (over-counting is allowed — stale entries are pruned lazily).

use std::time::Instant;

use proptest::prelude::*;

use super::*;
use crate::loc_rib::LocRib;
use crate::route::RouteOrigin;

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const PEERS: u8 = 4;
const PREFIXES: u8 = 6;

fn peer_addr(peer: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10 + peer))
}

fn prefix_of(index: u8) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 100 + index, 0, 0), 16))
}

/// Deterministic route for (peer, prefix, `path_id`, variant). `variant`
/// selects the attribute payload; it deliberately does NOT depend on
/// `path_id`, so one peer announcing the same variant on two path IDs
/// produces full-tie candidates (`best_path_cmp` Equal) — the case the
/// announce fast path must hand to the full rescan.
fn build_route(peer: u8, prefix: u8, path_id: u8, variant: u8, received_at: Instant) -> Route {
    Route {
        prefix: prefix_of(prefix),
        next_hop: peer_addr(peer),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: peer_addr(peer),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001])],
            }),
            PathAttribute::LocalPref(100 + u32::from(variant % 2) * 10),
            PathAttribute::Med(u32::from(variant)),
        ]),
        received_at,
        origin_type: if peer < 2 {
            RouteOrigin::Ebgp
        } else {
            RouteOrigin::Ibgp
        },
        peer_router_id: Ipv4Addr::new(192, 0, 2, peer),
        is_stale: false,
        is_llgr_stale: false,
        path_id: u32::from(path_id),
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

#[derive(Debug, Clone)]
enum Op {
    /// Real announce path: `enqueue_routes_received` → chunk drain →
    /// `recompute_best_after_announce`. Re-announcing an existing
    /// (prefix, `path_id`) with a new variant is the same-peer attr-change /
    /// refresh-replay case.
    Announce { peer: u8, routes: Vec<(u8, u8, u8)> },
    /// Real withdraw path → `recompute_best_after_withdraw`.
    Withdraw { peer: u8, keys: Vec<(u8, u8)> },
    /// Session teardown seam: Adj-RIB-In dropped whole, then a full
    /// recompute of its prefixes (`clear_peer_adj_rib_in` shape).
    SessionDown { peer: u8 },
    /// RFC 4724 GR entry seam: mark the family stale (consecutive-restart
    /// re-mark deletes already-stale routes), then recompute.
    MarkStale { peer: u8 },
    /// RFC 9494 promotion seam: GR-stale → LLGR-stale with in-place
    /// `LLGR_STALE` community injection, then recompute.
    PromoteLlgr { peer: u8 },
    /// `EoR` seam: sweep still-stale + still-LLGR-stale routes, clear flags
    /// on the retained ones, then recompute retained ∪ swept.
    EorClear { peer: u8 },
}

fn op_strategy() -> impl Strategy<Value = Op> {
    let route = (0..PREFIXES, 0u8..2, 0u8..3);
    prop_oneof![
        5 => (0..PEERS, proptest::collection::vec(route, 1..5))
            .prop_map(|(peer, routes)| Op::Announce { peer, routes }),
        3 => (0..PEERS, proptest::collection::vec((0..PREFIXES, 0u8..2), 1..5))
            .prop_map(|(peer, keys)| Op::Withdraw { peer, keys }),
        1 => (0..PEERS).prop_map(|peer| Op::SessionDown { peer }),
        1 => (0..PEERS).prop_map(|peer| Op::MarkStale { peer }),
        1 => (0..PEERS).prop_map(|peer| Op::PromoteLlgr { peer }),
        1 => (0..PEERS).prop_map(|peer| Op::EorClear { peer }),
    ]
}

fn apply(manager: &mut RibManager, op: &Op, received_at: Instant) {
    match op {
        Op::Announce { peer, routes } => {
            let announced = routes
                .iter()
                .map(|&(prefix, path_id, variant)| {
                    build_route(*peer, prefix, path_id, variant, received_at)
                })
                .collect();
            manager.enqueue_routes_received(
                peer_addr(*peer),
                announced,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
            );
            drain_route_chunks(manager);
        }
        Op::Withdraw { peer, keys } => {
            let withdrawn = keys
                .iter()
                .map(|&(prefix, path_id)| (prefix_of(prefix), u32::from(path_id)))
                .collect();
            manager.enqueue_routes_received(
                peer_addr(*peer),
                vec![],
                withdrawn,
                vec![],
                vec![],
                vec![],
                vec![],
            );
            drain_route_chunks(manager);
        }
        Op::SessionDown { peer } => {
            if let Some(rib) = manager.ribs.remove(&peer_addr(*peer)) {
                let affected: HashSet<Prefix> = rib.iter().map(|r| r.prefix).collect();
                manager.recompute_best(&affected);
            }
        }
        Op::MarkStale { peer } => {
            if let Some(rib) = manager.ribs.get_mut(&peer_addr(*peer)) {
                let mut affected: HashSet<Prefix> = rib.iter().map(|r| r.prefix).collect();
                affected.extend(rib.mark_stale(FAMILY));
                manager.recompute_best(&affected);
            }
        }
        Op::PromoteLlgr { peer } => {
            if let Some(rib) = manager.ribs.get_mut(&peer_addr(*peer)) {
                let affected: HashSet<Prefix> =
                    rib.promote_to_llgr_stale(FAMILY).into_iter().collect();
                manager.recompute_best(&affected);
            }
        }
        Op::EorClear { peer } => {
            if let Some(rib) = manager.ribs.get_mut(&peer_addr(*peer)) {
                let mut swept = rib.sweep_stale_family(FAMILY);
                swept.extend(rib.sweep_llgr_stale_family(FAMILY));
                rib.clear_stale(FAMILY);
                let mut affected: HashSet<Prefix> = rib.iter().map(|r| r.prefix).collect();
                affected.extend(swept);
                manager.recompute_best(&affected);
            }
        }
    }
}

/// Payload-identity comparison mirroring everything `LocRib::recompute`'s
/// change detection can observe, minus `received_at` (an unchanged best is
/// deliberately not reinstalled, so its clone keeps the older timestamp).
fn same_route(a: &Route, b: &Route) -> bool {
    a.prefix == b.prefix
        && a.peer == b.peer
        && a.path_id == b.path_id
        && a.next_hop == b.next_hop
        && a.link_local_next_hop == b.link_local_next_hop
        && a.next_hop_scope == b.next_hop_scope
        && a.peer_router_id == b.peer_router_id
        && a.is_stale == b.is_stale
        && a.is_llgr_stale == b.is_llgr_stale
        && a.origin_type == b.origin_type
        && a.validation_state == b.validation_state
        && a.aspa_state == b.aspa_state
        && a.attributes == b.attributes
}

fn check_invariants(manager: &RibManager, step: usize) {
    // Index contract: never under-count. Every (prefix, peer) actually
    // present in an Adj-RIB-In must be indexed.
    for (peer, rib) in &manager.ribs {
        for route in rib.iter() {
            assert!(
                manager
                    .unicast_prefix_peers
                    .get(&route.prefix)
                    .is_some_and(|peers| peers.contains(peer)),
                "step {step}: index under-counts: peer {peer} holds {} but is not indexed",
                route.prefix,
            );
        }
    }

    // Loc-RIB equivalence: from-scratch full scan over every peer's
    // Adj-RIB-In (the pre-index reference collection) must select a best
    // identical to what the incremental/indexed path installed.
    let mut reference = LocRib::new();
    for index in 0..PREFIXES {
        let prefix = prefix_of(index);
        reference.recompute(
            prefix,
            manager
                .ribs
                .values()
                .flat_map(|rib| rib.iter_prefix(&prefix)),
        );
        match (reference.get(&prefix), manager.loc_rib.get(&prefix)) {
            (None, None) => {}
            (Some(expected), Some(actual)) => assert!(
                same_route(expected, actual),
                "step {step}: best mismatch for {prefix}:\n expected {expected:?}\n actual {actual:?}",
            ),
            (expected, actual) => panic!(
                "step {step}: best presence mismatch for {prefix}: \
                 expected {expected:?}, actual {actual:?}",
            ),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        ..ProptestConfig::default()
    })]

    #[test]
    fn incremental_best_path_matches_full_rescan(
        ops in proptest::collection::vec(op_strategy(), 1..80)
    ) {
        let (_tx, rx) = mpsc::channel(8);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
        let received_at = Instant::now();
        for (step, op) in ops.iter().enumerate() {
            apply(&mut manager, op, received_at);
            check_invariants(&manager, step);
        }
    }
}
