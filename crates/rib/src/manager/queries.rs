//! Read-only RIB query, export-explain, and snapshot handlers.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use rustbgpd_policy::PolicyChain;
use rustbgpd_wire::{Afi, Prefix, Safi};
use tokio::sync::broadcast;
use tracing::{debug, warn};

use super::helpers::{prefix_family, unicast_route_family};
use super::{
    EVPN_ROUTE_EVENT_HISTORY_CAPACITY, ROUTE_EVENT_HISTORY_CAPACITY, ROUTE_QUERY_MAX_PAGE_SIZE,
    RibManager, distribution, update_groups,
};
use crate::adj_rib_in::AdjRibIn;
use crate::adj_rib_out::AdjRibOut;
use crate::best_path::best_path_cmp_with_reason;
use crate::event::{RouteEvent, RouteEventType};
use crate::update::{
    BestPathCandidate, ExactExportKey, ExplainAdvertisedRoute, ExplainAdvertisedRouteError,
    ExplainBestPath, MrtPeerEntry, MrtSnapshotData, NeighborPolicyStats, NeighborRibSnapshot,
    NeighborRibSnapshotResponse, RoutePage, RoutePageError, RoutePageVersion, RouteQueryFilter,
    RouteQueryKey, RouteQueryScope, UpdateGroupPeerComparison, WarmMrtSnapshotBudget,
    WarmMrtSnapshotView, route_query_key,
};

pub(super) fn send_mrt_snapshot(
    reply: tokio::sync::oneshot::Sender<MrtSnapshotData>,
    build: impl FnOnce() -> MrtSnapshotData,
) {
    // A canceled on-demand dump drops this receiver while the query waits in
    // the actor mailbox. Check before cloning any peer or route state.
    if reply.is_closed() {
        debug!("MRT snapshot query canceled before materialization");
        return;
    }

    let snapshot = build();
    if reply.send(snapshot).is_err() {
        warn!("MRT snapshot query caller dropped before receiving response");
    }
}

fn materialize_neighbor_rib_snapshot(
    peers: Vec<IpAddr>,
    comparison: Option<(IpAddr, IpAddr)>,
    mut is_canceled: impl FnMut() -> bool,
    mut build_row: impl FnMut(IpAddr) -> NeighborRibSnapshot,
    build_comparison: impl FnOnce(IpAddr, IpAddr) -> UpdateGroupPeerComparison,
) -> Option<NeighborRibSnapshotResponse> {
    let mut snapshots = Vec::with_capacity(peers.len());
    for peer in peers {
        if is_canceled() {
            return None;
        }
        snapshots.push(build_row(peer));
    }
    if is_canceled() {
        return None;
    }
    let comparison = comparison.map(|(primary, comparison)| build_comparison(primary, comparison));
    if is_canceled() {
        return None;
    }
    Some(NeighborRibSnapshotResponse {
        snapshots,
        comparison,
    })
}

fn send_neighbor_rib_snapshot(
    reply: tokio::sync::oneshot::Sender<NeighborRibSnapshotResponse>,
    peers: Vec<IpAddr>,
    comparison: Option<(IpAddr, IpAddr)>,
    build_row: impl FnMut(IpAddr) -> NeighborRibSnapshot,
    build_comparison: impl FnOnce(IpAddr, IpAddr) -> UpdateGroupPeerComparison,
) {
    let Some(snapshot) = materialize_neighbor_rib_snapshot(
        peers,
        comparison,
        || reply.is_closed(),
        build_row,
        build_comparison,
    ) else {
        debug!("neighbor RIB snapshot query canceled during materialization");
        return;
    };
    let _ = reply.send(snapshot);
}

/// Synthesized messages per RFC 9069 Loc-RIB dump chunk — the
/// per-request allocation bound of the resumable dump (the final chunk
/// additionally carries one End-of-RIB marker per streamed family).
pub(super) const BMP_DUMP_CHUNK_SIZE: usize = 256;
/// The `n` smallest keys strictly greater than `after`, ascending,
/// selected in one pass over an unordered key iterator with a max-heap
/// capped at `n` — the mutation-robust cursor step of the resumable
/// BMP Loc-RIB dump. Returns fewer than `n` keys iff the walk past
/// `after` is exhausted.
fn smallest_keys_after<K: Ord + Copy>(
    keys: impl Iterator<Item = K>,
    after: Option<K>,
    n: usize,
) -> Vec<K> {
    let mut heap = std::collections::BinaryHeap::with_capacity(n + 1);
    for key in keys {
        if after.is_some_and(|a| key <= a) {
            continue;
        }
        if heap.len() < n {
            heap.push(key);
        } else if heap.peek().is_some_and(|&top| key < top) {
            heap.pop();
            heap.push(key);
        }
    }
    heap.into_sorted_vec()
}
/// One bounded page over an unordered route iterator: the filter-matching
/// routes with the `page_size` smallest identity keys strictly greater
/// than `after`, ascending, plus the scope's total matching count.
/// Single pass, O(page) allocation — the same mutation-robust cursor
/// step as [`smallest_keys_after`], carrying the routes alongside the
/// keys so no per-key re-lookup is needed.
pub(super) fn page_routes<'a>(
    routes: impl Iterator<Item = &'a crate::route::Route>,
    filter: Option<&RouteQueryFilter>,
    after: Option<RouteQueryKey>,
    page_size: usize,
) -> RoutePage {
    /// Max-heap entry ordered by identity key only.
    struct Entry<'a>(RouteQueryKey, &'a crate::route::Route);
    impl PartialEq for Entry<'_> {
        fn eq(&self, other: &Self) -> bool {
            self.0 == other.0
        }
    }
    impl Eq for Entry<'_> {}
    impl PartialOrd for Entry<'_> {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }
    impl Ord for Entry<'_> {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.0.cmp(&other.0)
        }
    }

    let n = page_size.clamp(1, ROUTE_QUERY_MAX_PAGE_SIZE);
    let mut heap = std::collections::BinaryHeap::with_capacity(n + 1);
    let mut total: u64 = 0;
    // Matching routes strictly past the cursor — tells whether routes
    // remain beyond this page.
    let mut remaining: u64 = 0;
    for route in routes {
        if let Some(filter) = filter
            && !filter(route)
        {
            continue;
        }
        total += 1;
        let key = route_query_key(route);
        if after.is_some_and(|a| key <= a) {
            continue;
        }
        remaining += 1;
        if heap.len() < n {
            heap.push(Entry(key, route));
        } else if heap.peek().is_some_and(|top| key < top.0) {
            heap.pop();
            heap.push(Entry(key, route));
        }
    }
    let routes: Vec<_> = heap
        .into_sorted_vec()
        .into_iter()
        .map(|entry| entry.1.clone())
        .collect();
    let has_more = remaining > routes.len() as u64;
    RoutePage {
        routes,
        total,
        has_more,
        version: RoutePageVersion::default(),
    }
}
/// One bounded page over rows yielded in order strictly after the cursor.
/// At most `page_size + 1` yielded rows are cloned: the extra row proves
/// `has_more` without restarting the ordered iterator. Callers whose iterator
/// applies member-local filters may inspect additional underlying index rows
/// before yielding those rows.
fn page_ordered_routes<'a>(
    routes: impl Iterator<Item = &'a crate::route::Route>,
    total: usize,
    page_size: usize,
) -> RoutePage {
    let n = page_size.clamp(1, ROUTE_QUERY_MAX_PAGE_SIZE);
    let mut routes: Vec<_> = routes.take(n + 1).cloned().collect();
    let has_more = routes.len() > n;
    routes.truncate(n);
    RoutePage {
        routes,
        total: u64::try_from(total).unwrap_or(u64::MAX),
        has_more,
        version: RoutePageVersion::default(),
    }
}
/// Merge multiple individually ordered Adj-RIB-In iterators into one route
/// page. The heap retains one key per peer and the output retains at most one
/// page, so a Received(all) request is bounded by O(peers + page) rather than
/// the route-table size.
fn page_merged_ordered_routes<'a, I>(
    mut iterators: Vec<I>,
    total: usize,
    page_size: usize,
) -> RoutePage
where
    I: Iterator<Item = &'a crate::route::Route>,
{
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;

    let n = page_size.clamp(1, ROUTE_QUERY_MAX_PAGE_SIZE);
    let mut current = Vec::with_capacity(iterators.len());
    let mut heap = BinaryHeap::with_capacity(iterators.len());
    for (index, iterator) in iterators.iter_mut().enumerate() {
        let route = iterator.next();
        if let Some(route) = route {
            heap.push(Reverse((route_query_key(route), index)));
        }
        current.push(route);
    }

    let mut routes = Vec::with_capacity(n + 1);
    while routes.len() <= n {
        let Some(Reverse((_, index))) = heap.pop() else {
            break;
        };
        let route = current[index]
            .take()
            .expect("heap entry always owns one current route");
        routes.push(route.clone());
        let next = iterators[index].next();
        if let Some(route) = next {
            heap.push(Reverse((route_query_key(route), index)));
        }
        current[index] = next;
    }
    let has_more = routes.len() > n;
    routes.truncate(n);
    RoutePage {
        routes,
        total: u64::try_from(total).unwrap_or(u64::MAX),
        has_more,
        version: RoutePageVersion::default(),
    }
}

impl RibManager {
    /// One bounded chunk of the RFC 9069 Loc-RIB table dump: synthesize
    /// at most [`BMP_DUMP_CHUNK_SIZE`] UPDATE PDUs (unicast bests, then
    /// VPN bests) resuming after `cursor`, and reply with the next
    /// resume position. The BMP dump forwarder drives the loop, so the
    /// full table is never materialized at once and every other RIB
    /// command interleaves between chunk requests.
    ///
    /// Cursor semantics: each chunk is "the `N` smallest keys strictly
    /// greater than the cursor" in the key's total order, selected in
    /// one pass over the unordered Loc-RIB map. That makes the cursor
    /// robust to mutations between chunks — a route that survives the
    /// dump is emitted exactly once, a removed route simply stops
    /// matching, and any route installed after `started_at` (behind
    /// *or ahead of* the cursor) reaches the collector only via the
    /// live stream, which the BMP manager holds back until the dump's
    /// End-of-RIB — so no post-generation-start update can precede the
    /// `EoR` on the wire (LAN-885). A phase yielding fewer than `N`
    /// keys is exhausted:
    /// unicast hands over to VPN, VPN closes the dump with one
    /// End-of-RIB per streamed family (dump→EoR→live ordering).
    // ponytail: each chunk re-scans the family's key set (O(table) per
    // chunk, O(table²/N) per dump) — swap the scan for a sorted index
    // or key snapshot if dump CPU at DFZ scale ever bites; allocation
    // is already bounded per chunk.
    pub(super) fn handle_query_bmp_loc_rib_dump(
        &self,
        cursor: Option<rustbgpd_bmp::BmpDumpCursor>,
        started_at: std::time::SystemTime,
        reply: tokio::sync::oneshot::Sender<rustbgpd_bmp::BmpDumpChunk>,
    ) {
        use crate::bmp_sync;
        use rustbgpd_bmp::BmpDumpCursor as Cursor;
        let now = std::time::SystemTime::now();
        // Dump entries carry the Path Marking status bits (Best +
        // stale flags) but no reason code — deriving one would mean a
        // full best-path re-comparison per prefix; live emissions
        // attach it where the comparison already ran.
        let mut messages: Vec<(
            bytes::Bytes,
            std::time::SystemTime,
            Option<rustbgpd_bmp::BmpPathStatus>,
        )> = Vec::with_capacity(BMP_DUMP_CHUNK_SIZE);
        let next = match cursor {
            None | Some(Cursor::Unicast(_)) => {
                let after = match cursor {
                    Some(Cursor::Unicast(prefix)) => Some(prefix),
                    _ => None,
                };
                let keys = smallest_keys_after(
                    self.loc_rib.iter().map(|r| r.prefix),
                    after,
                    BMP_DUMP_CHUNK_SIZE,
                );
                for key in &keys {
                    // Stored wall-clock install time (RFC 9069 per-peer
                    // header timestamp) — identical to the live tap's
                    // emission timestamp for the same install, immune to
                    // clock steps between install and dump (LAN-193).
                    let Some((route, installed_at)) = self.loc_rib.get_with_install_time(key)
                    else {
                        continue;
                    };
                    // LAN-885: the walk reads the live table, so a route
                    // admitted after the collector's generation began must
                    // not become dump content — its held-back live delta
                    // replays after End-of-RIB instead. Emitting it here
                    // would leak a post-generation-start update across the
                    // dump/live boundary. (Stored wall-clock install times:
                    // a backward clock step mid-dump could readmit such a
                    // route — accepted; a monotonic install sequence is the
                    // upgrade path.)
                    if installed_at > started_at {
                        continue;
                    }
                    if let Some(pdu) = bmp_sync::synthesize_unicast_announce(route) {
                        let status = bmp_sync::loc_rib_path_status(
                            route.is_stale || route.is_llgr_stale,
                            None,
                        );
                        messages.push((pdu, installed_at, Some(status)));
                    }
                }
                match keys.last() {
                    Some(&last) if keys.len() == BMP_DUMP_CHUNK_SIZE => Some(Cursor::Unicast(last)),
                    _ => Some(Cursor::Vpn(None)),
                }
            }
            Some(Cursor::Vpn(after)) => {
                let keys = smallest_keys_after(
                    self.loc_rib.iter_vpn().map(|r| r.nlri.key()),
                    after,
                    BMP_DUMP_CHUNK_SIZE,
                );
                for key in &keys {
                    let Some((route, installed_at)) = self.loc_rib.get_vpn_with_install_time(key)
                    else {
                        continue;
                    };
                    // LAN-885: same post-generation-start exclusion as the
                    // unicast phase above.
                    if installed_at > started_at {
                        continue;
                    }
                    if let Some(pdu) = bmp_sync::synthesize_vpn_announce(route) {
                        let status = bmp_sync::loc_rib_path_status(
                            route.is_stale || route.is_llgr_stale,
                            None,
                        );
                        messages.push((pdu, installed_at, Some(status)));
                    }
                }
                match keys.last() {
                    Some(&last) if keys.len() == BMP_DUMP_CHUNK_SIZE => {
                        Some(Cursor::Vpn(Some(last)))
                    }
                    _ => {
                        // End-of-RIB per family closes the dump; live
                        // emission continues seamlessly after (dump→EoR→
                        // live). EoR markers announce no path — nothing
                        // to mark.
                        for (afi, safi) in bmp_sync::LOC_RIB_FAMILIES {
                            if let Some(pdu) = bmp_sync::synthesize_end_of_rib(afi, safi) {
                                messages.push((pdu, now, None));
                            }
                        }
                        None
                    }
                }
            }
        };
        if reply
            .send(rustbgpd_bmp::BmpDumpChunk { messages, next })
            .is_err()
        {
            debug!("BMP Loc-RIB dump consumer dropped, aborting dump");
        }
    }
    /// Per-AFI/SAFI Loc-RIB route counts for the RFC 9069 BMP stats
    /// report (stat type 10; type 8 is the sum). Scoped to the streamed
    /// Loc-RIB families — counting families absent from the fabricated
    /// OPEN would advertise routes the collector can never receive.
    pub(super) fn handle_query_bmp_loc_rib_stats(
        &self,
        reply: tokio::sync::oneshot::Sender<Vec<(u16, u8, u64)>>,
    ) {
        let (mut v4, mut v6) = (0u64, 0u64);
        for route in self.loc_rib.iter() {
            match route.prefix {
                Prefix::V4(_) => v4 += 1,
                Prefix::V6(_) => v6 += 1,
            }
        }
        let (mut vpnv4, mut vpnv6) = (0u64, 0u64);
        for route in self.loc_rib.iter_vpn() {
            match route.family() {
                rustbgpd_wire::VpnAddressFamily::V4 => vpnv4 += 1,
                rustbgpd_wire::VpnAddressFamily::V6 => vpnv6 += 1,
            }
        }
        let _ = reply.send(vec![
            (Afi::Ipv4 as u16, Safi::Unicast as u8, v4),
            (Afi::Ipv6 as u16, Safi::Unicast as u8, v6),
            (Afi::Ipv4 as u16, Safi::MplsVpn as u8, vpnv4),
            (Afi::Ipv6 as u16, Safi::MplsVpn as u8, vpnv6),
        ]);
    }
    pub(super) fn handle_query_received_routes(
        &mut self,
        peer: Option<IpAddr>,
        reply: tokio::sync::oneshot::Sender<Vec<crate::route::Route>>,
    ) {
        let routes: Vec<_> = match peer {
            Some(peer_addr) => self
                .ribs
                .get(&peer_addr)
                .map(|rib| rib.iter().cloned().collect())
                .unwrap_or_default(),
            None => self
                .ribs
                .values()
                .flat_map(|rib| rib.iter().cloned())
                .collect(),
        };

        if reply.send(routes).is_err() {
            warn!("query caller dropped before receiving response");
        }
    }
    /// One bounded page of a resumable route listing. The reply channel
    /// doubles as the cancellation token: an abandoned caller (dropped
    /// receiver — e.g. a canceled gRPC request whose page query was
    /// already enqueued) skips the scan entirely, so abandoned
    /// pagination stops costing the RIB task anything.
    pub(super) fn handle_query_routes_page_versioned(
        &mut self,
        scope: RouteQueryScope,
        filter: Option<&RouteQueryFilter>,
        after: Option<RouteQueryKey>,
        expected_version: Option<RoutePageVersion>,
        page_size: usize,
        reply: tokio::sync::oneshot::Sender<Result<RoutePage, RoutePageError>>,
    ) {
        if reply.is_closed() {
            debug!("route page query canceled before scan; skipping");
            return;
        }
        let version = match self.route_page_version(scope) {
            Ok(version) => version,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        if after.is_some() != expected_version.is_some() {
            let _ = reply.send(Err(RoutePageError::Invalidated));
            return;
        }
        if expected_version.is_some_and(|expected| expected != version) {
            let _ = reply.send(Err(RoutePageError::Invalidated));
            return;
        }
        // Arbitrary API route predicates still need the full scope to preserve
        // the cursor-independent filtered total. Unfiltered listings resume
        // through persistent ordered indices and clone only one page plus a
        // lookahead row. A grouped advertised view may inspect extra index rows
        // while applying member-local split horizon and exact-rejection filters.
        let page = if filter.is_some() {
            match scope {
                RouteQueryScope::Received { peer: Some(peer) } => page_routes(
                    self.ribs.get(&peer).into_iter().flat_map(AdjRibIn::iter),
                    filter,
                    after,
                    page_size,
                ),
                RouteQueryScope::Received { peer: None } => page_routes(
                    self.ribs.values().flat_map(AdjRibIn::iter),
                    filter,
                    after,
                    page_size,
                ),
                RouteQueryScope::Best => page_routes(self.loc_rib.iter(), filter, after, page_size),
                RouteQueryScope::Advertised { peer } => {
                    match self.grouped_advertised_routes_iter(peer) {
                        Some(routes) => page_routes(routes, filter, after, page_size),
                        None => page_routes(
                            self.adj_ribs_out
                                .get(&peer)
                                .into_iter()
                                .flat_map(AdjRibOut::iter),
                            filter,
                            after,
                            page_size,
                        ),
                    }
                }
            }
        } else {
            match scope {
                RouteQueryScope::Received { peer: Some(peer) } => {
                    self.ribs.get(&peer).map_or_else(RoutePage::default, |rib| {
                        page_ordered_routes(rib.iter_ordered_from(after), rib.len(), page_size)
                    })
                }
                RouteQueryScope::Received { peer: None } => {
                    let total = self.ribs.values().map(AdjRibIn::len).sum();
                    let iterators = self
                        .ribs
                        .values()
                        .map(|rib| rib.iter_ordered_from(after))
                        .collect();
                    page_merged_ordered_routes(iterators, total, page_size)
                }
                RouteQueryScope::Best => {
                    let total = self.loc_rib.len();
                    page_ordered_routes(self.loc_rib.iter_ordered_from(after), total, page_size)
                }
                RouteQueryScope::Advertised { peer } => {
                    // A grouped member holds no per-peer unicast Adj-RIB-Out;
                    // its view is group table − own-sourced − exact-export
                    // rejections. Both branches resume through their table's
                    // compact prefix index without materializing the scope.
                    let grouped_total = self.grouped_advertised_count(peer);
                    match self.grouped_advertised_routes_ordered_iter(peer, after) {
                        Some(routes) => page_ordered_routes(
                            routes,
                            grouped_total.unwrap_or_default(),
                            page_size,
                        ),
                        None => {
                            self.adj_ribs_out
                                .get(&peer)
                                .map_or_else(RoutePage::default, |rib| {
                                    page_ordered_routes(
                                        rib.iter_ordered_from(after),
                                        rib.len(),
                                        page_size,
                                    )
                                })
                        }
                    }
                }
            }
        };
        let page = RoutePage { version, ..page };
        if reply.send(Ok(page)).is_err() {
            warn!("query caller dropped before receiving response");
        }
    }
    /// Compatibility boundary for the retained ordered route-paging benchmark.
    ///
    /// The canonical bench-support source is overlaid byte-for-byte onto the
    /// pre-continuation baseline, whose handler had this signature. A stable
    /// wrapper keeps that measurement honest while production callers use the
    /// versioned handler above. The wrapper supplies the current version for a
    /// continuation because the benchmark performs no concurrent mutation.
    #[cfg(feature = "bench-internals")]
    pub(super) fn handle_query_routes_page(
        &mut self,
        scope: RouteQueryScope,
        filter: Option<&RouteQueryFilter>,
        after: Option<RouteQueryKey>,
        page_size: usize,
        reply: tokio::sync::oneshot::Sender<RoutePage>,
    ) {
        let expected_version = after.and_then(|_| self.route_page_version(scope).ok());
        let (versioned_reply, mut versioned_response) = tokio::sync::oneshot::channel();
        self.handle_query_routes_page_versioned(
            scope,
            filter,
            after,
            expected_version,
            page_size,
            versioned_reply,
        );
        let page = versioned_response
            .try_recv()
            .expect("route page handler replies synchronously")
            .expect("benchmark route-page generation remains available");
        let _ = reply.send(page);
    }
    pub(super) fn handle_query_best_routes(
        &mut self,
        reply: tokio::sync::oneshot::Sender<Vec<crate::route::Route>>,
    ) {
        let routes: Vec<_> = self.loc_rib.iter().cloned().collect();
        if reply.send(routes).is_err() {
            warn!("query caller dropped before receiving response");
        }
    }
    /// Build the per-prefix FIB install-candidate view: each Loc-RIB best plus
    /// the equal-cost (ECMP) next-hop set, bounded by `max_paths`. Loc-RIB holds
    /// only the single best per prefix, so the equal-cost siblings are gathered
    /// from the Adj-RIB-In snapshots (the same source `distribute_multipath_prefix`
    /// scans for Add-Path), filtered by `multipath_equal`. Output ordering: the
    /// best route's next-hop is always index 0; the remaining equal-cost siblings
    /// follow ordered by `(next_hop, peer, path_id)`. Deduped by next-hop *before*
    /// the `max_paths` cap.
    pub(super) fn handle_query_fib_install_candidates(
        &mut self,
        max_paths: u32,
        relax: bool,
        weighted: bool,
        reply: tokio::sync::oneshot::Sender<Vec<crate::route::FibInstallCandidate>>,
    ) {
        use crate::best_path::{link_bandwidth_weights, multipath_equal};
        use crate::route::{FibInstallCandidate, FibInstallNextHop};

        let cap = max_paths.max(1) as usize;
        let mut out = Vec::with_capacity(self.loc_rib.len());
        for best in self.loc_rib.iter() {
            let mut next_hops: Vec<FibInstallNextHop> = Vec::new();
            if cap <= 1 {
                // ECMP off (the default `maximum_paths` of 1): skip the
                // equal-cost sibling scan + sort entirely and program just the
                // best next-hop. This keeps default FIB deployments off the new
                // multipath query cost — they pay nothing for sibling gathering.
                next_hops.push(FibInstallNextHop {
                    next_hop: best.next_hop,
                    link_local_next_hop: best.link_local_next_hop,
                    next_hop_scope: best.next_hop_scope.as_deref().cloned(),
                    peer: best.peer,
                    path_id: best.path_id,
                    weight: 1,
                });
            } else {
                let mut siblings: Vec<&crate::route::Route> = self
                    .ribs
                    .values()
                    .flat_map(|rib| rib.iter_prefix(&best.prefix))
                    .filter(|r| multipath_equal(best, r, relax))
                    .collect();
                siblings.sort_by(|a, b| {
                    a.next_hop
                        .cmp(&b.next_hop)
                        .then(a.peer.cmp(&b.peer))
                        .then(a.path_id.cmp(&b.path_id))
                });

                let mut seen: std::collections::BTreeSet<(IpAddr, Option<u32>)> =
                    std::collections::BTreeSet::new();
                // Gather (next-hop, link-bandwidth) best-first, deduped by
                // (next-hop, egress ifindex), capped. The ifindex is part of the
                // key so two equal `fe80::/10` gateways reached over different
                // interfaces stay distinct and both install as ECMP (ADR-0069);
                // a same-family next-hop carries no scope, so this collapses to
                // plain next-hop dedup for the common case. Bandwidth is held
                // alongside so weights can be normalized over exactly the
                // installed set below.
                let mut bandwidths: Vec<Option<f32>> = Vec::new();
                for r in std::iter::once(best).chain(siblings.iter().copied()) {
                    if next_hops.len() >= cap {
                        break;
                    }
                    let scope_ifindex = r.next_hop_scope.as_ref().map(|scope| scope.ifindex);
                    if seen.insert((r.next_hop, scope_ifindex)) {
                        next_hops.push(FibInstallNextHop {
                            next_hop: r.next_hop,
                            link_local_next_hop: r.link_local_next_hop,
                            next_hop_scope: r.next_hop_scope.as_deref().cloned(),
                            peer: r.peer,
                            path_id: r.path_id,
                            weight: 1,
                        });
                        bandwidths.push(r.link_bandwidth());
                    }
                }
                for (next_hop, weight) in next_hops
                    .iter_mut()
                    .zip(link_bandwidth_weights(weighted, &bandwidths))
                {
                    next_hop.weight = weight;
                }
            }
            out.push(FibInstallCandidate {
                best: best.clone(),
                next_hops,
            });
        }
        if reply.send(out).is_err() {
            warn!("query caller dropped before receiving response");
        }
    }
    pub(super) fn handle_query_peer_groups(
        &mut self,
        reply: tokio::sync::oneshot::Sender<std::collections::HashMap<IpAddr, String>>,
    ) {
        if reply.send(self.peer_group.clone()).is_err() {
            warn!("query caller dropped before receiving peer-group map");
        }
    }
    pub(super) fn handle_query_advertised_routes(
        &mut self,
        peer: IpAddr,
        reply: tokio::sync::oneshot::Sender<Vec<crate::route::Route>>,
    ) {
        // A grouped member holds no per-peer unicast Adj-RIB-Out; its
        // advertised set is synthesized: group table − own-sourced.
        let routes: Vec<_> = self.grouped_advertised_routes(peer).unwrap_or_else(|| {
            self.adj_ribs_out
                .get(&peer)
                .map(|rib| rib.iter().cloned().collect())
                .unwrap_or_default()
        });

        if reply.send(routes).is_err() {
            warn!("query caller dropped before receiving response");
        }
    }
    pub(super) fn handle_explain_advertised_route(
        &mut self,
        peer: IpAddr,
        prefix: Prefix,
        rd: Option<rustbgpd_wire::RouteDistinguisher>,
        labeled: bool,
        source: Option<crate::update::RouteSourceIdentity>,
        reply: tokio::sync::oneshot::Sender<
            Result<ExplainAdvertisedRoute, ExplainAdvertisedRouteError>,
        >,
    ) {
        if !self.peer_sendable_families.contains_key(&peer) {
            let _ = reply.send(Err(ExplainAdvertisedRouteError::NotFound(
                "peer not registered for outbound updates".to_string(),
            )));
            return;
        }
        if source.is_some() && (rd.is_some() || labeled) {
            let _ = reply.send(Err(ExplainAdvertisedRouteError::FailedPrecondition(
                "source selection is supported only for unicast Add-Path export explain"
                    .to_string(),
            )));
            return;
        }
        if let Some(source) = source {
            if self.add_path_send_max_for_prefix(peer, &prefix) == 0 {
                let _ = reply.send(Err(ExplainAdvertisedRouteError::FailedPrecondition(
                    format!("peer {peer} did not negotiate Add-Path send for this prefix family"),
                )));
                return;
            }
            let exists = self.ribs.get(&source.peer).is_some_and(|rib| {
                rib.iter_prefix(&prefix)
                    .any(|route| route.path_id == source.path_id)
            });
            if !exists {
                let _ = reply.send(Err(ExplainAdvertisedRouteError::NotFound(format!(
                    "source path {}/{} from {} with path ID {} not found in Adj-RIB-In",
                    prefix.addr_string(),
                    prefix.prefix_len(),
                    source.peer,
                    source.path_id
                ))));
                return;
            }
        }
        let explanation = match (rd, labeled) {
            (Some(rd), _) => self.explain_vpn_export(peer, prefix, rd),
            (None, true) => self.explain_labeled_export(peer, prefix),
            (None, false) => self.explain_unicast_export(peer, prefix, source),
        };
        if reply.send(Ok(explanation)).is_err() {
            warn!("query caller dropped before receiving response");
        }
    }
    /// A gate-ladder explanation for a family whose advertisement is
    /// still held by the RFC 5291 §6 initial-ORF gate — live staging
    /// skips the family wholesale, before any per-prefix work.
    fn orf_gated_explain(
        peer: IpAddr,
        prefix: Prefix,
        rd: Option<rustbgpd_wire::RouteDistinguisher>,
    ) -> ExplainAdvertisedRoute {
        let mut trace = distribution::ExportGateTrace::default();
        trace.gates.push(crate::update::ExportGateStep {
            gate: "orf_gate",
            code: "orf_pending",
            verdict: crate::update::ExportGateVerdict::Stop,
            detail: "peer negotiated ORF for this family; advertisement is deferred until \
                     its first ROUTE-REFRESH lifts the gate (RFC 5291 §6)"
                .to_string(),
        });
        trace.into_explain(peer, prefix, rd, None)
    }
    fn apply_exact_export_overlay_to_explain(
        &self,
        peer: IpAddr,
        key: &ExactExportKey,
        mut explanation: ExplainAdvertisedRoute,
    ) -> ExplainAdvertisedRoute {
        if explanation.decision != crate::update::ExplainDecision::Advertise
            || !self
                .peer_unexportable
                .get(&peer)
                .is_some_and(|rejected| rejected.contains(key))
        {
            return explanation;
        }
        let detail =
            "the active session's exact wire encoder rejected this post-policy route".to_string();
        explanation.decision = crate::update::ExplainDecision::Deny;
        explanation.already_advertised = false;
        explanation.reasons = vec![crate::update::ExplainReason {
            code: "exact_export_rejected",
            message: detail.clone(),
        }];
        explanation.gates.push(crate::update::ExportGateStep {
            gate: "exact_export",
            code: "exact_export_rejected",
            verdict: crate::update::ExportGateVerdict::Stop,
            detail,
        });
        explanation
    }
    /// Materialize the member-specific wire view used to explain a grouped
    /// unicast export. Rejected rows remain absent until an exact encoder
    /// accepts them again, just as they do in live group projections.
    fn grouped_unicast_explain_view(&self, peer: IpAddr) -> Option<AdjRibOut> {
        let group = self
            .grouped_member_of(peer)
            .and_then(|gid| self.group_ribs.get(&gid))?;
        let rejected = self.peer_unexportable.get(&peer);
        let mut view = AdjRibOut::new(peer);
        for route in group.table.iter().filter(|route| {
            let key = ExactExportKey::Unicast(route.prefix, route.path_id);
            route.peer != peer && !rejected.is_some_and(|keys| keys.contains(&key))
        }) {
            view.insert(route.clone());
        }
        Some(view)
    }
    /// Explain the unicast export ladder for `(prefix, peer)`.
    ///
    /// Truthfulness mechanism: for the single-best shapes — per-peer
    /// AND update-grouped — this dry-runs the very staging body live
    /// distribution executes (`distribute_single_best_prefix`) with an
    /// explain-only `ExportTarget` that records the gate ladder and
    /// counts nothing; a grouped member is explained against its group
    /// table (its real advertised state) with split horizon applied
    /// against the member, exactly like the source-flip matrix does at
    /// emit time. ORR-vantage, Add-Path-send, and per-client-best peers
    /// (never grouped — all three disqualify) take the dedicated explain
    /// that shares its candidate collection and gate helpers with the
    /// live ORR/multipath bodies — a per-client-best peer's explain
    /// ranks the same filtered-best candidate walk live staging
    /// performs, so it reports the advertised runner-up (not a false
    /// "denied") when the Loc-RIB best is policy-denied.
    #[expect(
        clippy::too_many_lines,
        reason = "the explain path mirrors the complete live unicast gate ladder"
    )]
    fn explain_unicast_export(
        &mut self,
        peer: IpAddr,
        prefix: Prefix,
        source: Option<crate::update::RouteSourceIdentity>,
    ) -> ExplainAdvertisedRoute {
        let family = prefix_family(&prefix);
        if self
            .peer_orf_pending
            .get(&peer)
            .is_some_and(|gated| gated.contains(&family))
        {
            let mut explanation = Self::orf_gated_explain(peer, prefix, None);
            explanation.source = source;
            return explanation;
        }

        let sendable = self.peer_sendable_families.get(&peer);
        let llgr = self.peer_advertised_llgr_families.get(&peer);
        let orf = self
            .peer_orf_filters
            .get(&peer)
            .and_then(|filters| filters.get(&family));
        let target_is_ebgp = self.peer_is_ebgp.get(&peer).copied().unwrap_or(true);
        let interpret_rfc1997 = self.peer_interpret_rfc1997.contains(&peer);
        let target_is_rr_client = self.peer_is_rr_client.get(&peer).copied().unwrap_or(false);
        let peer_asn = self.peer_asn.get(&peer).copied();
        let peer_group = self.peer_group.get(&peer).map(String::as_str);

        // Same resolved-vantage gate as live distribution: an ORR peer
        // whose vantage did not resolve falls back to the standard
        // Loc-RIB-best explain, exactly like the distribution loop.
        let orr_ctx = self.peer_orr_vantage.get(&peer).and_then(|vantage| {
            self.orr
                .spf
                .get(vantage)
                .map(|spf| (&self.orr.topology, spf, *vantage))
        });
        let add_path_send_max = self.add_path_send_max_for_prefix(peer, &prefix);
        let per_client_best = self.peer_per_client_best.contains(&peer);

        if orr_ctx.is_some() || add_path_send_max > 0 || per_client_best {
            let explanation = Self::explain_single_best_prefix(
                &self.loc_rib,
                &self.ribs,
                &self.unicast_prefix_peers,
                &self.peer_is_rr_client,
                self.adj_ribs_out.get(&peer),
                prefix,
                peer,
                peer_asn,
                peer_group,
                target_is_ebgp,
                interpret_rfc1997,
                self.peer_rs_control.get(&peer).copied(),
                target_is_rr_client,
                self.peer_local_roles.get(&peer).copied().flatten(),
                self.cluster_id,
                sendable,
                llgr,
                orf,
                add_path_send_max,
                self.export_policy_for(peer),
                orr_ctx,
                per_client_best,
                source,
            );
            return self.apply_exact_export_overlay_to_explain(
                peer,
                &ExactExportKey::Unicast(prefix, explanation.path_id),
                explanation,
            );
        }

        // Dry run of the live single-best staging body. A grouped member has
        // no private unicast Adj-RIB-Out, so materialize its exact wire view:
        // shared table minus own-sourced and member-local unexportable rows.
        let member_of = self.grouped_member_of(peer);
        let empty_rib_out;
        let grouped_rib_out = self.grouped_unicast_explain_view(peer);
        let rib_out = if let Some(grouped) = grouped_rib_out.as_ref() {
            grouped
        } else if let Some(out) = self.adj_ribs_out.get(&peer) {
            out
        } else {
            empty_rib_out = AdjRibOut::new(peer);
            &empty_rib_out
        };

        let mut trace = distribution::ExportGateTrace::default();
        let mut target = distribution::ExportTarget::Explain {
            peer,
            peer_asn,
            peer_group,
            local_role: self.peer_local_roles.get(&peer).copied().flatten(),
            trace: &mut trace,
        };
        let mut memo = distribution::ExportMemo::default();
        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        let mut nh_override_flags = Vec::new();
        let mut policy_filtered = Vec::new();
        Self::distribute_single_best_prefix(
            &self.loc_rib,
            rib_out,
            &self.peer_is_rr_client,
            &prefix,
            &mut target,
            target_is_ebgp,
            interpret_rfc1997,
            self.peer_rs_control.get(&peer).copied(),
            target_is_rr_client,
            self.cluster_id,
            sendable,
            llgr,
            self.export_policy_for(peer),
            orf,
            &mut memo,
            &mut announce,
            &mut withdraw,
            &mut nh_override_flags,
            &mut policy_filtered,
            false,
        );
        let explanation = trace.into_explain(peer, prefix, None, member_of.map(|gid| gid as u64));
        self.apply_exact_export_overlay_to_explain(
            peer,
            &ExactExportKey::Unicast(prefix, explanation.path_id),
            explanation,
        )
    }
    /// Explain the VPNv4/VPNv6 (SAFI 128) export ladder for
    /// `(rd, prefix, peer)` by dry-running the live VPN staging body
    /// (`stage_vpn_routes`) over the singleton identity with an
    /// explain-only target — the RT-Constrain membership gate, RR
    /// suppression, LLGR restriction, export policy, and the
    /// advertised-state diff all come from the same code live
    /// reflection runs. A VPN-staging group member is diffed against
    /// its group table under its own RT filter `Φ_m`, matching the
    /// emit-time matrix.
    #[expect(
        clippy::too_many_lines,
        reason = "the explain path mirrors the complete live VPN gate ladder"
    )]
    fn explain_vpn_export(
        &mut self,
        peer: IpAddr,
        prefix: Prefix,
        rd: rustbgpd_wire::RouteDistinguisher,
    ) -> ExplainAdvertisedRoute {
        let vpn_prefix = match prefix {
            Prefix::V4(p) => rustbgpd_wire::VpnPrefix::V4 {
                addr: p.addr,
                len: p.len,
            },
            Prefix::V6(p) => rustbgpd_wire::VpnPrefix::V6 {
                addr: p.addr,
                len: p.len,
            },
        };
        let key = rustbgpd_wire::VpnRouteKey {
            route_distinguisher: rd,
            prefix: vpn_prefix,
        };
        let family = match key.prefix {
            rustbgpd_wire::VpnPrefix::V4 { .. } => (Afi::Ipv4, Safi::MplsVpn),
            rustbgpd_wire::VpnPrefix::V6 { .. } => (Afi::Ipv6, Safi::MplsVpn),
        };
        if self
            .peer_orf_pending
            .get(&peer)
            .is_some_and(|gated| gated.contains(&family))
        {
            return Self::orf_gated_explain(peer, prefix, Some(rd));
        }

        let sendable = self.peer_sendable_families.get(&peer);
        let llgr = self.peer_advertised_llgr_families.get(&peer);
        let target_is_ebgp = self.peer_is_ebgp.get(&peer).copied().unwrap_or(true);
        let interpret_rfc1997 = self.peer_interpret_rfc1997.contains(&peer);
        let target_is_rr_client = self.peer_is_rr_client.get(&peer).copied().unwrap_or(false);
        let peer_asn = self.peer_asn.get(&peer).copied();
        let peer_group = self.peer_group.get(&peer).map(String::as_str);
        let rtc_filter = self.rtc_vpn_filter(peer, sendable);
        let orr_ctx = self
            .peer_orr_vantage
            .get(&peer)
            .and_then(|vantage| self.orr.spf.get(vantage))
            .map(|spf| (&self.orr.topology, spf));
        let add_path_send_max = self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0);
        let add_path_send_families = self
            .peer_add_path_send_families
            .get(&peer)
            .cloned()
            .unwrap_or_default();

        let vpn_grouped = self.vpn_grouped_member_of(peer);
        let empty_rib_out;
        let grouped_rib_out;
        let rib_out = if let Some(group) = vpn_grouped.and_then(|gid| self.group_ribs.get(&gid)) {
            let rejected = self.peer_unexportable.get(&peer);
            let mut view = AdjRibOut::new(peer);
            for route in group.table.iter_vpn().filter(|route| {
                let key = ExactExportKey::Vpn(route.key());
                route.peer != peer
                    && update_groups::rt_passes(rtc_filter.as_ref(), route)
                    && !rejected.is_some_and(|keys| keys.contains(&key))
            }) {
                view.insert_vpn(route.clone());
            }
            grouped_rib_out = view;
            &grouped_rib_out
        } else if let Some(out) = self.adj_ribs_out.get(&peer) {
            out
        } else {
            empty_rib_out = AdjRibOut::new(peer);
            &empty_rib_out
        };

        let mut trace = distribution::ExportGateTrace::default();
        let mut target = distribution::ExportTarget::Explain {
            peer,
            peer_asn,
            peer_group,
            local_role: self.peer_local_roles.get(&peer).copied().flatten(),
            trace: &mut trace,
        };
        let mut keys = HashSet::new();
        keys.insert(key);
        let mut vpn_announce = Vec::new();
        let mut vpn_withdraw = Vec::new();
        Self::stage_vpn_routes(
            &self.loc_rib,
            &self.ribs,
            rib_out,
            &self.peer_is_rr_client,
            &keys,
            &mut target,
            target_is_ebgp,
            interpret_rfc1997,
            target_is_rr_client,
            self.cluster_id,
            sendable,
            llgr,
            rtc_filter.as_ref(),
            orr_ctx,
            add_path_send_max,
            self.peer_add_path_send_limits.get(&peer),
            &add_path_send_families,
            self.export_policy_for(peer),
            &mut vpn_announce,
            &mut vpn_withdraw,
            false,
        );
        let explanation =
            trace.into_explain(peer, prefix, Some(rd), vpn_grouped.map(|gid| gid as u64));
        self.apply_exact_export_overlay_to_explain(
            peer,
            &ExactExportKey::Vpn(crate::route::VpnRibRouteKey {
                nlri_key: key,
                path_id: explanation.path_id,
            }),
            explanation,
        )
    }
    /// Explain the labeled-unicast (SAFI 4, RFC 8277) export ladder for
    /// `(prefix, peer)` by dry-running the live labeled staging body
    /// (`stage_labeled_routes`) over the singleton identity with an
    /// explain-only target — RR suppression, the LLGR restriction,
    /// RFC 1997 community suppression, export policy, and the
    /// advertised-state diff all come from the same code live
    /// reflection runs. Labeled-unicast has no update-group staging,
    /// so the explain always diffs the peer's private Adj-RIB-Out.
    fn explain_labeled_export(&mut self, peer: IpAddr, prefix: Prefix) -> ExplainAdvertisedRoute {
        let family = match prefix {
            Prefix::V4(_) => (Afi::Ipv4, Safi::LabeledUnicast),
            Prefix::V6(_) => (Afi::Ipv6, Safi::LabeledUnicast),
        };
        if self
            .peer_orf_pending
            .get(&peer)
            .is_some_and(|gated| gated.contains(&family))
        {
            return Self::orf_gated_explain(peer, prefix, None);
        }

        let sendable = self.peer_sendable_families.get(&peer);
        let llgr = self.peer_advertised_llgr_families.get(&peer);
        let target_is_ebgp = self.peer_is_ebgp.get(&peer).copied().unwrap_or(true);
        let interpret_rfc1997 = self.peer_interpret_rfc1997.contains(&peer);
        let target_is_rr_client = self.peer_is_rr_client.get(&peer).copied().unwrap_or(false);
        let peer_asn = self.peer_asn.get(&peer).copied();
        let peer_group = self.peer_group.get(&peer).map(String::as_str);
        let orr_ctx = self
            .peer_orr_vantage
            .get(&peer)
            .and_then(|vantage| self.orr.spf.get(vantage))
            .map(|spf| (&self.orr.topology, spf));
        let add_path_send_max = self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0);
        let add_path_send_families = self
            .peer_add_path_send_families
            .get(&peer)
            .cloned()
            .unwrap_or_default();

        let empty_rib_out;
        let rib_out = if let Some(out) = self.adj_ribs_out.get(&peer) {
            out
        } else {
            empty_rib_out = AdjRibOut::new(peer);
            &empty_rib_out
        };

        let mut trace = distribution::ExportGateTrace::default();
        let mut target = distribution::ExportTarget::Explain {
            peer,
            peer_asn,
            peer_group,
            local_role: self.peer_local_roles.get(&peer).copied().flatten(),
            trace: &mut trace,
        };
        let mut keys = HashSet::new();
        keys.insert(prefix);
        let mut labeled_announce = Vec::new();
        let mut labeled_withdraw = Vec::new();
        Self::stage_labeled_routes(
            &self.loc_rib,
            &self.ribs,
            rib_out,
            &self.peer_is_rr_client,
            &keys,
            &mut target,
            target_is_ebgp,
            interpret_rfc1997,
            target_is_rr_client,
            self.cluster_id,
            sendable,
            llgr,
            orr_ctx,
            add_path_send_max,
            self.peer_add_path_send_limits.get(&peer),
            &add_path_send_families,
            self.export_policy_for(peer),
            &mut labeled_announce,
            &mut labeled_withdraw,
            false,
        );
        let explanation = trace.into_explain(peer, prefix, None, None);
        self.apply_exact_export_overlay_to_explain(
            peer,
            &ExactExportKey::Labeled(crate::route::LabeledRibRouteKey {
                prefix,
                path_id: explanation.path_id,
            }),
            explanation,
        )
    }
    #[expect(
        clippy::too_many_lines,
        reason = "best-path explain assembles route, policy, and attribution in one snapshot"
    )]
    pub(super) fn handle_explain_best_path(
        &mut self,
        prefix: Prefix,
        peer: Option<IpAddr>,
        reply: tokio::sync::oneshot::Sender<Option<ExplainBestPath>>,
    ) {
        use crate::best_path::best_path_cmp;
        use crate::manager::helpers::should_suppress_ibgp_inner;
        use rustbgpd_policy::{PolicyAction, RouteContext, RouteType, evaluate_chain};

        // Mirrors `distribution::route_type`. Local copy because that
        // helper is private to the distribution module and lifting it
        // up would be a wider surgery than this slice warrants.
        fn route_type_for(origin: crate::route::RouteOrigin) -> RouteType {
            match origin {
                crate::route::RouteOrigin::Local => RouteType::Local,
                crate::route::RouteOrigin::Ibgp => RouteType::Internal,
                crate::route::RouteOrigin::Ebgp => RouteType::External,
            }
        }

        // Peer-scoped: reject the call before any work if the peer
        // isn't registered. Mirrors handle_explain_advertised_route's
        // not-found semantics so the CLI can give the operator a
        // clear "unknown peer" error instead of a silently-empty
        // response.
        if let Some(peer_addr) = peer
            && !self.peer_sendable_families.contains_key(&peer_addr)
        {
            let _ = reply.send(None);
            return;
        }

        // Collect all candidates from all Adj-RIB-In tables.
        let mut all_candidates: Vec<crate::route::Route> = self
            .ribs
            .values()
            .flat_map(|rib| rib.iter_prefix(&prefix).cloned())
            .collect();

        // Best by RFC 4271 best-path comparison — independent of
        // peer scope, and used as the reference point for every
        // candidate's `vs_best_reason`.
        let best = all_candidates
            .iter()
            .min_by(|a, b| best_path_cmp(a, b))
            .cloned();

        // For the peer-aware path, build the ranked advertised set so
        // each candidate can be tagged with its `advertised_path_id`.
        // The selection mirrors `distribute_multipath_prefix` exactly:
        // family check → split-horizon → iBGP/RR suppression → export
        // eligibility (including source `NO_ADVERTISE`) → export policy →
        // modified-route `NO_ADVERTISE` → top-N by best-path. Mirroring the
        // contract is deliberate — operators trust explain only if it
        // produces the same selection that distribution would, modulo state
        // changes between the two calls.
        let mut advertised: Vec<(IpAddr, u32, u32)> = Vec::new();
        let mut add_path_send_max: u32 = 0;
        if let Some(peer_addr) = peer {
            let target_is_ebgp = self.peer_is_ebgp.get(&peer_addr).copied().unwrap_or(true);
            let interpret_rfc1997 = self.peer_interpret_rfc1997.contains(&peer_addr);
            let target_is_rr_client = self
                .peer_is_rr_client
                .get(&peer_addr)
                .copied()
                .unwrap_or(false);
            let target_peer_asn = self.peer_asn.get(&peer_addr).copied();
            let target_peer_group = self.peer_group.get(&peer_addr).map(String::as_str);
            let cluster_id = self.cluster_id;
            let sendable = self.peer_sendable_families.get(&peer_addr);
            let family = match prefix {
                Prefix::V4(_) => (Afi::Ipv4, Safi::Unicast),
                Prefix::V6(_) => (Afi::Ipv6, Safi::Unicast),
            };
            // `add_path_send_max_for_prefix()` already returns 0 if
            // the peer's `add_path_send_families` doesn't cover this
            // prefix's AFI/SAFI; we additionally zero it out when the
            // sendable-family check fails so the response always
            // reflects the *effective* cap. A peer with
            // `add_path_send_max=4` for IPv4 unicast but no IPv6
            // unicast sendable will see `add_path_send_max=0` here
            // for an IPv6 prefix — same answer distribution would
            // produce.
            //
            // Single-best peers (`effective send_max == 0`) skip the
            // ranking loop entirely — `distribute_single_best_prefix`
            // only ever advertises the Loc-RIB best with
            // `path_id = 0`, never falls back to the next-best
            // candidate. Marking a non-best candidate as "advertised"
            // because it sorts first in the export-filtered set would
            // lie to the operator about what distribution would
            // actually do (e.g. when the global best is suppressed by
            // split-horizon). In that mode the operator infers
            // winner-advertisement from `best_route` plus the export
            // policy state visible elsewhere; the candidates list
            // still surfaces the alternatives with
            // `advertised_path_id = 0`.
            let family_sendable = sendable.is_some_and(|f| f.contains(&family));
            add_path_send_max = if family_sendable {
                self.add_path_send_max_for_prefix(peer_addr, &prefix)
            } else {
                0
            };
            if add_path_send_max > 0 {
                let export_pol = self.export_policy_for(peer_addr);
                let mut filtered: Vec<&crate::route::Route> = all_candidates
                    .iter()
                    .filter(|route| {
                        if route.peer == peer_addr {
                            return false; // split horizon
                        }
                        if should_suppress_ibgp_inner(
                            route,
                            target_is_ebgp,
                            target_is_rr_client,
                            cluster_id,
                            &self.peer_is_rr_client,
                        ) {
                            return false;
                        }
                        true
                    })
                    .collect();
                filtered.sort_by(|a, b| best_path_cmp(a, b));

                let limit = if add_path_send_max == u32::MAX {
                    usize::MAX
                } else {
                    add_path_send_max as usize
                };

                let needs_as_path_string =
                    export_pol.is_some_and(PolicyChain::requires_as_path_string);
                let mut next_rank: u32 = 1;
                let mut export_memo = distribution::ExportMemo::default();
                for cand in &filtered {
                    if (next_rank as usize) > limit {
                        break;
                    }
                    let aspath_str = if needs_as_path_string {
                        cand.as_path()
                            .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string)
                    } else {
                        String::new()
                    };
                    let aspath_len = cand.as_path().map_or(0, rustbgpd_wire::AsPath::len);
                    let origin_asn = cand.as_path().and_then(rustbgpd_wire::AsPath::origin_asn);
                    let ctx = RouteContext {
                        prefix: Some(prefix),
                        next_hop: Some(cand.next_hop),
                        extended_communities: cand.extended_communities(),
                        communities: cand.communities(),
                        large_communities: cand.large_communities(),
                        as_path_str: &aspath_str,
                        as_path: cand.as_path(),
                        as_path_len: aspath_len,
                        origin_asn,
                        validation_state: cand.validation_state,
                        aspa_state: cand.aspa_state,
                        peer_address: Some(peer_addr),
                        peer_asn: target_peer_asn,
                        peer_group: target_peer_group,
                        route_type: Some(route_type_for(cand.origin_type)),
                        family: Some(unicast_route_family(&prefix)),
                        evpn_route_type: None,
                        local_pref: cand.local_pref_attr(),
                        med: cand.med_attr(),
                    };
                    // Pre-policy source-route gates: NO_ADVERTISE, then the
                    // eBGP-only NO_EXPORT/NO_EXPORT_SUBCONFED form. Kept in
                    // lockstep with live staging so this candidate walk and
                    // apply agree (plan-vs-apply equivalence).
                    if distribution::no_export_export_suppressed(
                        cand.communities(),
                        target_is_ebgp,
                        interpret_rfc1997,
                    ) {
                        continue;
                    }
                    if distribution::no_advertise_export_suppressed(cand.communities()) {
                        continue;
                    }
                    let result = evaluate_chain(export_pol, &ctx);
                    if result.action != PolicyAction::Permit {
                        continue;
                    }
                    let (modified, _) = export_memo.apply(cand, &result.modifications);
                    if distribution::no_advertise_export_suppressed(modified.communities()) {
                        continue;
                    }
                    let outbound_rank = next_rank;
                    next_rank += 1;
                    if self
                        .peer_unexportable
                        .get(&peer_addr)
                        .is_some_and(|rejected| {
                            rejected.contains(&ExactExportKey::Unicast(prefix, outbound_rank))
                        })
                    {
                        continue;
                    }
                    advertised.push((cand.peer, cand.path_id, outbound_rank));
                }
            }
        }

        // Build the advertised-rank index once (O(N) build, O(1)
        // lookup) so the per-candidate tagging below stays linear in
        // candidate count rather than quadratic. With Add-Path
        // peers commonly carrying tens of paths per prefix this is
        // a meaningful difference at scale.
        let advertised_rank: HashMap<(IpAddr, u32), u32> = advertised
            .into_iter()
            .map(|(peer, inbound_path_id, outbound_rank)| ((peer, inbound_path_id), outbound_rank))
            .collect();

        let candidates: Vec<BestPathCandidate> = if let Some(ref best_route) = best {
            all_candidates
                .drain(..)
                .filter(|c| !(c.peer == best_route.peer && c.path_id == best_route.path_id))
                .map(|candidate| {
                    let (ordering, reason) = best_path_cmp_with_reason(&candidate, best_route);
                    let vs_best_detail =
                        crate::best_path::best_path_reason_detail(reason, &candidate, best_route);
                    let multipath = crate::best_path::multipath_eligibility(best_route, &candidate);
                    let advertised_path_id = advertised_rank
                        .get(&(candidate.peer, candidate.path_id))
                        .copied()
                        .unwrap_or(0);
                    BestPathCandidate {
                        route: candidate,
                        vs_best_reason: reason,
                        vs_best_ordering: ordering,
                        advertised_path_id,
                        vs_best_detail,
                        multipath,
                    }
                })
                .collect()
        } else {
            vec![]
        };

        // The step that *won*: the comparison against the runner-up —
        // the closest competitor by best-path order — is the last
        // decision the winner had to survive. Re-derived on demand from
        // the same explain-only ladder (`best_path_cmp_with_reason`);
        // the hot-path comparator never records anything.
        let (best_reason, best_reason_detail) = match (&best, candidates.is_empty()) {
            (Some(best_route), false) => {
                let runner_up = candidates
                    .iter()
                    .map(|c| &c.route)
                    .min_by(|a, b| best_path_cmp(a, b))
                    .expect("non-empty candidate list has a minimum");
                let (_, reason) = best_path_cmp_with_reason(best_route, runner_up);
                let detail =
                    crate::best_path::best_path_reason_detail(reason, best_route, runner_up);
                (Some(reason), detail)
            }
            // Single-path trivial winner or no best route at all.
            _ => (None, String::new()),
        };

        let explanation = ExplainBestPath {
            prefix,
            best,
            candidates,
            peer,
            add_path_send_max,
            best_reason,
            best_reason_detail,
        };

        if reply.send(Some(explanation)).is_err() {
            warn!("query caller dropped before receiving best-path explanation");
        }
    }
    pub(super) fn handle_subscribe_route_events(
        &mut self,
        reply: tokio::sync::oneshot::Sender<broadcast::Receiver<RouteEvent>>,
    ) {
        let rx = self.route_events_tx.subscribe();
        let _ = reply.send(rx);
    }
    pub(super) fn handle_query_route_event_history(
        &mut self,
        peer: Option<IpAddr>,
        afi: Option<Afi>,
        prefix: Option<Prefix>,
        limit: usize,
        reply: tokio::sync::oneshot::Sender<Vec<RouteEvent>>,
    ) {
        let limit = if limit == 0 {
            ROUTE_EVENT_HISTORY_CAPACITY
        } else {
            limit.min(ROUTE_EVENT_HISTORY_CAPACITY)
        };

        let mut events: Vec<RouteEvent> = self
            .route_event_history
            .iter()
            .rev()
            .filter(|event| match afi {
                Some(Afi::Ipv4) => matches!(event.prefix, Prefix::V4(_)),
                Some(Afi::Ipv6) => matches!(event.prefix, Prefix::V6(_)),
                Some(_) => false,
                None => true,
            })
            .filter(|event| match peer {
                Some(peer) => {
                    event.peer == Some(peer)
                        || event.previous_peer == Some(peer)
                        || event.target_peer == Some(peer)
                }
                None => true,
            })
            .filter(|event| match prefix {
                Some(prefix) => event.prefix == prefix,
                None => true,
            })
            .take(limit)
            .cloned()
            .collect();
        events.reverse();
        let _ = reply.send(events);
    }
    pub(super) fn handle_subscribe_evpn_route_events(
        &mut self,
        reply: tokio::sync::oneshot::Sender<broadcast::Receiver<crate::event::EvpnRouteEvent>>,
    ) {
        let rx = self.evpn_events_tx.subscribe();
        let _ = reply.send(rx);
    }
    pub(super) fn handle_query_evpn_route_event_history(
        &mut self,
        peer: Option<IpAddr>,
        route_type: Option<u8>,
        rd: Option<rustbgpd_wire::RouteDistinguisher>,
        event_types: &std::collections::BTreeSet<RouteEventType>,
        limit: usize,
        reply: tokio::sync::oneshot::Sender<Vec<crate::event::EvpnRouteEvent>>,
    ) {
        let limit = if limit == 0 {
            EVPN_ROUTE_EVENT_HISTORY_CAPACITY
        } else {
            limit.min(EVPN_ROUTE_EVENT_HISTORY_CAPACITY)
        };

        let mut events: Vec<crate::event::EvpnRouteEvent> = self
            .evpn_route_event_history
            .iter()
            .rev()
            .filter(|event| {
                route_type.is_none_or(|route_type| event.key.route_type() == route_type)
            })
            .filter(|event| rd.is_none_or(|rd| crate::event::evpn_key_rd(&event.key) == Some(rd)))
            .filter(|event| event_types.is_empty() || event_types.contains(&event.event_type))
            .filter(|event| match peer {
                Some(peer) => event.peer == Some(peer) || event.previous_peer == Some(peer),
                None => true,
            })
            .take(limit)
            .cloned()
            .collect();
        events.reverse();
        let _ = reply.send(events);
    }
    pub(super) fn handle_query_loc_rib_count(
        &mut self,
        reply: tokio::sync::oneshot::Sender<usize>,
    ) {
        let _ = reply.send(self.loc_rib.len());
    }
    pub(super) fn handle_query_advertised_count(
        &mut self,
        peer: IpAddr,
        reply: tokio::sync::oneshot::Sender<usize>,
    ) {
        // Grouped members synthesize: group table len − own-sourced.
        let count = self
            .grouped_advertised_count(peer)
            .unwrap_or_else(|| self.adj_ribs_out.get(&peer).map_or(0, AdjRibOut::len));
        let _ = reply.send(count);
    }
    /// ADR-0112: routes this peer's Adj-RIB-In still retains as GR or LLGR
    /// stale. Counted over every family the RIB stores, because one directional
    /// RFC 8212 verdict governs all of a neighbor's families — a retained
    /// EVPN or VPN route is as much prior-policy state as a retained unicast
    /// one.
    pub(super) fn handle_query_peer_retained_stale(
        &mut self,
        peer: IpAddr,
        reply: tokio::sync::oneshot::Sender<usize>,
    ) {
        let retained = self.ribs.get(&peer).map_or(0, |rib| {
            let stale = |stale: bool, llgr_stale: bool| stale || llgr_stale;
            rib.iter()
                .filter(|r| stale(r.is_stale, r.is_llgr_stale))
                .count()
                + rib
                    .iter_flowspec()
                    .filter(|r| stale(r.is_stale, r.is_llgr_stale))
                    .count()
                + rib
                    .iter_evpn()
                    .filter(|r| stale(r.is_stale, r.is_llgr_stale))
                    .count()
                + rib
                    .iter_vpn()
                    .filter(|r| stale(r.is_stale, r.is_llgr_stale))
                    .count()
                + rib
                    .iter_labeled()
                    .filter(|r| stale(r.is_stale, r.is_llgr_stale))
                    .count()
                + rib
                    .iter_bgpls()
                    .filter(|r| stale(r.is_stale, r.is_llgr_stale))
                    .count()
                + rib
                    .iter_rtc()
                    .filter(|r| stale(r.is_stale, r.is_llgr_stale))
                    .count()
        });
        let _ = reply.send(retained);
    }
    pub(super) fn handle_query_adj_rib_out_counts(
        &mut self,
        reply: tokio::sync::oneshot::Sender<crate::update::AdjRibOutCounts>,
    ) {
        let mut counts: crate::update::AdjRibOutCounts = self
            .adj_ribs_out
            .iter()
            .map(|(peer, rib)| (*peer, rib.family_counts()))
            .collect();
        // Grouped members hold no per-peer unicast entries: synthesize
        // their unicast family counts from the group tables (BMP RFC
        // 8671 stat type 17 must not report zero for them).
        for (&peer, membership) in &self.update_groups.members {
            let update_groups::GroupMembership::Grouped(_) = membership else {
                continue;
            };
            let Some(synthesized) = self.grouped_family_counts(peer) else {
                continue;
            };
            if synthesized.is_empty() {
                continue;
            }
            counts.entry(peer).or_default().extend(synthesized);
        }
        let _ = reply.send(counts);
    }
    pub(super) fn handle_query_neighbor_policy_stats(
        &mut self,
        peer: IpAddr,
        reply: tokio::sync::oneshot::Sender<NeighborPolicyStats>,
    ) {
        let stats = self
            .export_policy_stats
            .get(&peer)
            .copied()
            .unwrap_or_default();
        let _ = reply.send(stats);
    }
    /// Answer `NeighborService`'s aggregate read in one actor turn.  Keep this
    /// adjacent to the individual count/counter handlers so their semantics
    /// cannot drift: the aggregate is deliberately their one-turn projection,
    /// not a second notion of neighbor state.
    pub(super) fn handle_query_neighbor_rib_snapshots(
        &self,
        peers: Vec<IpAddr>,
        comparison: Option<(IpAddr, IpAddr)>,
        reply: tokio::sync::oneshot::Sender<NeighborRibSnapshotResponse>,
    ) {
        send_neighbor_rib_snapshot(
            reply,
            peers,
            comparison,
            |peer| NeighborRibSnapshot {
                peer,
                advertised_count: self
                    .grouped_advertised_count(peer)
                    .unwrap_or_else(|| self.adj_ribs_out.get(&peer).map_or(0, AdjRibOut::len)),
                policy_stats: self
                    .export_policy_stats
                    .get(&peer)
                    .copied()
                    .unwrap_or_default(),
                outbound: self.peer_outbound_state(peer),
            },
            |primary, comparison| self.update_group_comparison(primary, comparison),
        );
    }
    /// Snapshot the live per-term hit counters of installed export
    /// chains (ADR-0096 Decision 3.3): one entry per peer with an
    /// installed chain, plus the shared global fallback instance for
    /// peers evaluated before any per-peer install. Read-only — no
    /// counter is touched.
    pub(super) fn handle_query_export_policy_term_hits(
        &mut self,
        peer: Option<IpAddr>,
        reply: tokio::sync::oneshot::Sender<Vec<crate::update::ExportPolicyTermHits>>,
    ) {
        let snapshot = |owner: Option<IpAddr>,
                        chain: &rustbgpd_policy::PolicyChain|
         -> crate::update::ExportPolicyTermHits {
            crate::update::ExportPolicyTermHits {
                peer: owner,
                evals: chain.hit_counters().evals(),
                eval_errors: chain.hit_counters().eval_errors(),
                last_error: chain
                    .hit_counters()
                    .last_error()
                    .map(|error| error.to_string()),
                terms: chain.term_hit_rows(),
            }
        };
        let mut out = Vec::new();
        if let Some(peer) = peer {
            if let Some(chain) = self.export_policy_for(peer) {
                out.push(snapshot(Some(peer), chain));
            }
        } else {
            let mut peers: Vec<IpAddr> = self
                .peer_export_policies
                .iter()
                .filter_map(|(peer, chain)| chain.as_ref().map(|_| *peer))
                .collect();
            peers.sort_unstable();
            for peer in peers {
                if let Some(Some(chain)) = self.peer_export_policies.get(&peer) {
                    out.push(snapshot(Some(peer), chain));
                }
            }
            if let Some(chain) = self.export_policy.as_ref() {
                out.push(snapshot(None, chain));
            }
        }
        let _ = reply.send(out);
    }
    pub(super) fn handle_query_flowspec_routes(
        &mut self,
        reply: tokio::sync::oneshot::Sender<Vec<crate::route::FlowSpecRoute>>,
    ) {
        let routes: Vec<_> = self.loc_rib.iter_flowspec().cloned().collect();
        if reply.send(routes).is_err() {
            warn!("FlowSpec query caller dropped before receiving response");
        }
    }
    /// Serve `QueryOrrStatus`: per-vantage resolution/SPF/bound-peer
    /// status plus topology totals, from the cached `OrrState` (fresh by
    /// construction while any vantage is configured; empty otherwise).
    pub(super) fn handle_query_orr_status(
        &self,
        reply: tokio::sync::oneshot::Sender<crate::orr::OrrStatusSnapshot>,
    ) {
        let mut vantages: Vec<crate::orr::OrrVantageStatus> = self
            .orr
            .resolved
            .iter()
            .map(|(&vantage, &resolved)| {
                let node = self
                    .orr
                    .topology
                    .resolve_node(vantage)
                    .and_then(|ix| self.orr.topology.node_key(ix));
                let descriptors = node.map(crate::orr::NodeDescriptors::parse);
                let mut peers: Vec<IpAddr> = self
                    .peer_orr_vantage
                    .iter()
                    .filter(|&(_, &bound)| bound == vantage)
                    .map(|(&peer, _)| peer)
                    .collect();
                peers.sort();
                crate::orr::OrrVantageStatus {
                    vantage,
                    resolved,
                    node_key_hex: node
                        .map(|key| crate::orr::hex(key.as_bytes()))
                        .unwrap_or_default(),
                    asn: descriptors.as_ref().and_then(|d| d.asn),
                    bgp_ls_id: descriptors.as_ref().and_then(|d| d.bgp_ls_id),
                    router_id_hex: descriptors
                        .and_then(|d| d.router_id.as_deref().map(crate::orr::hex))
                        .unwrap_or_default(),
                    reachable_nodes: self.orr.spf.get(&vantage).map_or(0, |spf| {
                        u32::try_from(spf.reachable_count()).unwrap_or(u32::MAX)
                    }),
                    peers,
                }
            })
            .collect();
        vantages.sort_by_key(|status| status.vantage);
        let _ = reply.send(crate::orr::OrrStatusSnapshot {
            vantages,
            topology_nodes: u32::try_from(self.orr.topology.node_count()).unwrap_or(u32::MAX),
            topology_links: u32::try_from(self.orr.topology.link_count()).unwrap_or(u32::MAX),
            input_diagnostics: self.orr.topology.input_diagnostics(),
        });
    }
    pub(super) fn handle_query_mrt_snapshot(
        &mut self,
        reply: tokio::sync::oneshot::Sender<MrtSnapshotData>,
    ) {
        send_mrt_snapshot(reply, || {
            let peers: Vec<MrtPeerEntry> = self
                .peer_asn
                .iter()
                .map(|(&addr, &asn)| MrtPeerEntry {
                    peer_addr: addr,
                    peer_bgp_id: self
                        .peer_bgp_id
                        .get(&addr)
                        .copied()
                        .unwrap_or(Ipv4Addr::UNSPECIFIED),
                    peer_asn: asn,
                })
                .collect();

            let routes: Vec<_> = self
                .ribs
                .values()
                .flat_map(|rib| rib.iter().cloned())
                .collect();

            let evpn_routes: Vec<_> = self
                .ribs
                .values()
                .flat_map(|rib| rib.iter_evpn().cloned())
                .collect();

            MrtSnapshotData {
                peers,
                routes,
                evpn_routes,
            }
        });
    }
    pub(super) fn handle_query_warm_mrt_snapshot(
        &mut self,
        views: &[WarmMrtSnapshotView],
        budget: &WarmMrtSnapshotBudget,
        reply: tokio::sync::oneshot::Sender<Result<MrtSnapshotData, String>>,
    ) {
        let result = self.build_warm_mrt_snapshot(views, budget);
        if reply.send(result).is_err() {
            warn!("warm MRT snapshot query caller dropped before receiving response");
        }
    }
    /// Build a route snapshot and verify the exact active session inventory in
    /// one RIB-actor turn. The supplied views came from the peer-manager actor;
    /// session generation/ASN/router-ID checks close replacement races between
    /// those two captures. Any mismatch rejects the complete checkpoint.
    ///
    /// This is an actor-ordered snapshot, not a global transport quiescence
    /// barrier: UPDATEs the RIB actor processes before this query are included;
    /// UPDATEs arriving later are not. On a later restore tranche, ordinary GR
    /// stale-route reconciliation remains authoritative for that bounded edge.
    #[expect(
        clippy::too_many_lines,
        reason = "one actor turn validates the complete identity fence and captures every supported route view"
    )]
    fn build_warm_mrt_snapshot(
        &self,
        views: &[WarmMrtSnapshotView],
        budget: &WarmMrtSnapshotBudget,
    ) -> Result<MrtSnapshotData, String> {
        budget.check()?;
        if views.is_empty() {
            return Err("warm checkpoint has no eligible peer/family views".to_string());
        }
        if views
            .windows(2)
            .any(|pair| pair[0].sort_key() >= pair[1].sort_key())
        {
            return Err(
                "warm checkpoint views must be strictly sorted and duplicate-free".to_string(),
            );
        }

        let mut peer_identity = HashMap::<IpAddr, (u64, u32, Ipv4Addr)>::new();
        let mut families = HashMap::<IpAddr, HashSet<(Afi, Safi)>>::new();
        for view in views {
            budget.check()?;
            if !matches!(
                (view.afi, view.safi),
                (Afi::Ipv4 | Afi::Ipv6, Safi::Unicast) | (Afi::L2Vpn, Safi::Evpn)
            ) {
                return Err(format!(
                    "warm checkpoint view for {} uses unsupported family {:?}/{:?}",
                    view.peer, view.afi, view.safi
                ));
            }
            let identity = (view.session_id, view.peer_asn, view.peer_router_id);
            if peer_identity
                .insert(view.peer, identity)
                .is_some_and(|prior| prior != identity)
            {
                return Err(format!(
                    "warm checkpoint views disagree on identity for peer {}",
                    view.peer
                ));
            }
            if !families
                .entry(view.peer)
                .or_default()
                .insert((view.afi, view.safi))
            {
                return Err(format!(
                    "warm checkpoint repeats family {:?}/{:?} for peer {}",
                    view.afi, view.safi, view.peer
                ));
            }
        }

        for (&peer, &(session_id, peer_asn, peer_router_id)) in &peer_identity {
            budget.check()?;
            if self.outbound_session_ids.get(&peer).copied() != Some(session_id) {
                return Err(format!(
                    "peer {peer} changed active session during warm checkpoint"
                ));
            }
            if self.peer_asn.get(&peer).copied() != Some(peer_asn) {
                return Err(format!(
                    "peer {peer} changed negotiated ASN during warm checkpoint"
                ));
            }
            if self.peer_bgp_id.get(&peer).copied() != Some(peer_router_id) {
                return Err(format!(
                    "peer {peer} changed BGP identifier during warm checkpoint"
                ));
            }
        }

        let mut peers: Vec<_> = peer_identity
            .iter()
            .map(|(&peer_addr, &(_, peer_asn, peer_bgp_id))| MrtPeerEntry {
                peer_addr,
                peer_bgp_id,
                peer_asn,
            })
            .collect();
        peers.sort_by_key(|peer| peer.peer_addr);

        let route_is_allowed = |route: &crate::route::Route| {
            let family = match route.prefix {
                Prefix::V4(_) => (Afi::Ipv4, Safi::Unicast),
                Prefix::V6(_) => (Afi::Ipv6, Safi::Unicast),
            };
            families
                .get(&route.peer)
                .is_some_and(|allowed| allowed.contains(&family))
        };
        let evpn_is_allowed = |route: &crate::route::EvpnRibRoute| {
            families
                .get(&route.peer)
                .is_some_and(|allowed| allowed.contains(&(Afi::L2Vpn, Safi::Evpn)))
        };

        // Count and bound every owned allocation before cloning even one
        // route. Route attributes and interface names are Arc-backed; the
        // only clone-side allocation outside the Vec buffers is the optional
        // boxed next-hop scope, accounted explicitly below.
        let mut route_count = 0usize;
        let mut boxed_scope_count = 0usize;
        let mut evpn_count = 0usize;
        for rib in self.ribs.values() {
            for route in rib.iter() {
                budget.check()?;
                if route_is_allowed(route) {
                    route_count = route_count
                        .checked_add(1)
                        .ok_or_else(|| "warm checkpoint route count overflow".to_string())?;
                    boxed_scope_count = boxed_scope_count
                        .checked_add(usize::from(route.next_hop_scope.is_some()))
                        .ok_or_else(|| "warm checkpoint route scope count overflow".to_string())?;
                }
            }
            for route in rib.iter_evpn() {
                budget.check()?;
                if evpn_is_allowed(route) {
                    evpn_count = evpn_count
                        .checked_add(1)
                        .ok_or_else(|| "warm checkpoint EVPN route count overflow".to_string())?;
                }
            }
        }
        let materialized_bytes = peers
            .len()
            .checked_mul(std::mem::size_of::<MrtPeerEntry>())
            .and_then(|bytes| {
                route_count
                    .checked_mul(std::mem::size_of::<crate::route::Route>())
                    .and_then(|routes| bytes.checked_add(routes))
            })
            .and_then(|bytes| {
                boxed_scope_count
                    .checked_mul(std::mem::size_of::<crate::route::NextHopScope>())
                    .and_then(|scopes| bytes.checked_add(scopes))
            })
            .and_then(|bytes| {
                evpn_count
                    .checked_mul(std::mem::size_of::<crate::route::EvpnRibRoute>())
                    .and_then(|routes| bytes.checked_add(routes))
            })
            .ok_or_else(|| "warm checkpoint materialized size overflow".to_string())?;
        if materialized_bytes > budget.max_materialized_bytes {
            return Err(format!(
                "warm checkpoint needs {materialized_bytes} materialized bytes, exceeding the {}-byte cap",
                budget.max_materialized_bytes
            ));
        }

        let mut routes = Vec::new();
        routes.try_reserve_exact(route_count).map_err(|_| {
            format!("failed to reserve {route_count} warm checkpoint unicast routes")
        })?;
        let mut evpn_routes = Vec::new();
        evpn_routes
            .try_reserve_exact(evpn_count)
            .map_err(|_| format!("failed to reserve {evpn_count} warm checkpoint EVPN routes"))?;
        for rib in self.ribs.values() {
            for route in rib.iter() {
                budget.check()?;
                if route_is_allowed(route) {
                    routes.push(route.clone());
                }
            }
            for route in rib.iter_evpn() {
                budget.check()?;
                if evpn_is_allowed(route) {
                    evpn_routes.push(route.clone());
                }
            }
        }

        Ok(MrtSnapshotData {
            peers,
            routes,
            evpn_routes,
        })
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;

    #[test]
    fn canceled_neighbor_rib_snapshot_does_not_invoke_builder() {
        let (reply, receiver) = tokio::sync::oneshot::channel();
        drop(receiver);
        send_neighbor_rib_snapshot(
            reply,
            vec!["192.0.2.1".parse().unwrap()],
            None,
            |_| panic!("canceled query materialized"),
            |_, _| panic!("canceled query compared"),
        );
    }

    /// Load-bearing mid-materialization cancellation proof: removing the
    /// per-row closure check visits K+1 and continues building an
    /// undeliverable response; removing the pre-comparison check invokes the
    /// comparison after the Kth row cancels the request.
    #[test]
    fn canceled_neighbor_rib_snapshot_stops_at_exact_row_boundary() {
        use std::cell::RefCell;
        use std::rc::Rc;

        const PEERS: usize = 32;
        const CLOSE_AFTER: usize = 7;
        let canceled = Rc::new(std::cell::Cell::new(false));
        let visited = Rc::new(RefCell::new(Vec::new()));
        let peers: Vec<IpAddr> = (1..=PEERS)
            .map(|octet| IpAddr::V4(Ipv4Addr::new(192, 0, 2, u8::try_from(octet).unwrap())))
            .collect();

        let response = materialize_neighbor_rib_snapshot(
            peers.clone(),
            Some((peers[0], peers[1])),
            {
                let canceled = Rc::clone(&canceled);
                move || canceled.get()
            },
            {
                let canceled = Rc::clone(&canceled);
                let visited = Rc::clone(&visited);
                move |peer| {
                    visited.borrow_mut().push(peer);
                    if visited.borrow().len() == CLOSE_AFTER {
                        canceled.set(true);
                    }
                    NeighborRibSnapshot {
                        peer,
                        advertised_count: 0,
                        policy_stats: NeighborPolicyStats::default(),
                        outbound: crate::update::PeerOutboundState {
                            update_group: String::new(),
                            effective_distribution_mode:
                                crate::update::EffectiveDistributionMode::Unknown,
                            selection_deferral: Vec::new(),
                            outbound_prefix_limits: Vec::new(),
                        },
                    }
                }
            },
            |_, _| panic!("comparison must not be built after cancellation"),
        );

        assert!(response.is_none(), "canceled snapshot is never publishable");
        assert_eq!(&*visited.borrow(), &peers[..CLOSE_AFTER]);
    }

    /// Load-bearing pre-comparison fence: removing the check immediately
    /// after the final row invokes comparison construction for a request that
    /// was canceled while that row was materialized.
    #[test]
    fn canceled_neighbor_rib_snapshot_skips_comparison_after_last_row() {
        let canceled = std::cell::Cell::new(false);
        let response = materialize_neighbor_rib_snapshot(
            vec!["192.0.2.1".parse().unwrap()],
            Some(("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap())),
            || canceled.get(),
            |peer| {
                canceled.set(true);
                NeighborRibSnapshot {
                    peer,
                    advertised_count: 0,
                    policy_stats: NeighborPolicyStats::default(),
                    outbound: crate::update::PeerOutboundState {
                        update_group: String::new(),
                        effective_distribution_mode:
                            crate::update::EffectiveDistributionMode::Unknown,
                        selection_deferral: Vec::new(),
                        outbound_prefix_limits: Vec::new(),
                    },
                }
            },
            |_, _| panic!("comparison must not be built after the final row canceled"),
        );
        assert!(response.is_none());
    }

    /// Load-bearing final fence: removing the post-comparison cancellation
    /// check returns `Some`, which makes the caller enter its send path after
    /// the request was canceled during comparison construction.
    #[test]
    fn canceled_neighbor_rib_snapshot_skips_send_after_comparison() {
        let canceled = std::cell::Cell::new(false);
        let response = materialize_neighbor_rib_snapshot(
            Vec::new(),
            Some(("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap())),
            || canceled.get(),
            |_| unreachable!("no rows requested"),
            |_, _| {
                canceled.set(true);
                UpdateGroupPeerComparison {
                    primary_update_group: String::new(),
                    verdict: crate::update::UpdateGroupComparisonVerdict::Unknown,
                    primary_membership: crate::update::UpdateGroupComparisonMembership::Unknown,
                    comparison_membership: crate::update::UpdateGroupComparisonMembership::Unknown,
                    differences: Vec::new(),
                }
            },
        );
        assert!(response.is_none(), "send path must remain unreachable");
    }
}
