#[cfg(feature = "bench-internals")]
mod bench_support;
mod distribution;
mod graceful_restart;
mod helpers;
mod peer_lifecycle;
mod route_refresh;
mod update_groups;

#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use rustbgpd_policy::PolicyChain;
use rustbgpd_rpki::VrpTable;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Afi, FlowSpecRule, Prefix, Safi};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info, warn};

use crate::adj_rib_in::AdjRibIn;
use crate::adj_rib_out::AdjRibOut;
use crate::best_path::best_path_cmp_with_reason;
use crate::event::{RouteEvent, RouteEventType};
use crate::loc_rib::LocRib;
use crate::update::{
    BestPathCandidate, ExplainAdvertisedRoute, ExplainBestPath, MrtPeerEntry, MrtSnapshotData,
    NeighborPolicyStats, OutboundRouteUpdate, RibUpdate, RoutePage, RouteQueryFilter,
    RouteQueryKey, RouteQueryScope, route_query_key,
};

use helpers::{
    DIRTY_RESYNC_INTERVAL, LlgrPeerConfig, gauge_val, prefix_family, unicast_route_family,
};

/// Reverse index of unicast announcing peers: prefix → the peers whose
/// Adj-RIB-In currently holds at least one route for it. `FxHash` +
/// peer-fed keys: same deliberate `HashDoS` tradeoff as the route maps (see the
/// rationale block at the top of `adj_rib_in.rs`).
///
/// Maintenance contract (load-bearing): the index may OVER-count but must
/// never UNDER-count — `recompute_best` collects candidates only from the
/// indexed peers, so a missing entry would silently drop a live candidate
/// from best-path selection. Every seam that inserts a unicast route into
/// an Adj-RIB-In must call [`RibManager::register_unicast_announcer`]
/// (announce chunks, local injection, bench seeding — the only three
/// insert sites). Removal seams (withdraw, session down, GR/LLGR sweeps,
/// `EoR` clears, max-prefix teardown) need no hook: a peer that no longer
/// holds the prefix is pruned lazily by the next `recompute_best` probe,
/// costing one wasted Adj-RIB-In lookup until then.
type UnicastPrefixPeers = rustc_hash::FxHashMap<Prefix, smallvec::SmallVec<[IpAddr; 1]>>;

#[cfg(test)]
use helpers::{ERR_REFRESH_TIMEOUT, LOCAL_PEER, validate_route_rpki};

/// A peer's RT-Constrain membership (RFC 4684): the Route Targets the peer
/// declared interest in via SAFI-132 NLRI. Rebuilt whole from the peer's OWN
/// Adj-RIB-In (all paths — never the Loc-RIB best, whose tiebreak winner may
/// belong to a different peer) whenever that Adj-RIB-In mutates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RtcMembership {
    /// Peer advertised the zero-length default NLRI: interest in every RT.
    has_default: bool,
    /// Non-default membership NLRI, sorted + deduped so rebuilds of the
    /// same set compare equal regardless of `HashMap` iteration order.
    entries: Vec<rustbgpd_wire::RtcNlri>,
}

impl RtcMembership {
    /// Whether any of `rts` falls inside this membership. An empty
    /// membership (SAFI 132 negotiated, no interest received yet) matches
    /// nothing — the strict RFC 4684 rule, so a route with no Route Target
    /// at all only passes via the default NLRI.
    fn matches_any(&self, rts: &[rustbgpd_wire::ExtendedCommunity]) -> bool {
        if self.has_default {
            return true;
        }
        rts.iter()
            .any(|&rt| self.entries.iter().any(|nlri| nlri.matches(rt)))
    }
}

/// Central RIB manager that owns all Adj-RIB-In, Loc-RIB, and Adj-RIB-Out state.
///
/// Runs as a single tokio task, receiving updates via an mpsc channel.
/// No `Arc<RwLock>` — all state is owned by this task.
pub struct RibManager {
    ribs: HashMap<IpAddr, AdjRibIn>,
    /// Global cross-peer attribute intern table (LAN-336). Owned by this
    /// task like everything else — lock-free by construction. Every route
    /// insertion seam interns `route.attributes` here BEFORE storing the
    /// route; every removal seam runs [`RibManager::gc_attr_intern`]
    /// afterwards (see `crate::attr_intern` for the reclaim rules).
    attr_intern: crate::attr_intern::AttrInternTable,
    /// See [`UnicastPrefixPeers`] for the maintenance contract.
    unicast_prefix_peers: UnicastPrefixPeers,
    loc_rib: LocRib,
    adj_ribs_out: HashMap<IpAddr, AdjRibOut>,
    outbound_peers: HashMap<IpAddr, mpsc::Sender<OutboundRouteUpdate>>,
    /// Transport session identity recorded at `PeerUp` registration,
    /// keyed like `outbound_peers`. `handle_peer_down` /
    /// `handle_peer_graceful_restart` discard a teardown whose stamped id
    /// doesn't match, so a stale collision-loser `PeerDown` (RFC 4271
    /// §6.8 overlap, processed after the winner's `PeerUp`) cannot
    /// destroy the surviving session's state. Invariant: equals the
    /// `session_id` of the LAST entry in `live_sessions[peer]` whenever a
    /// registration exists.
    outbound_session_ids: HashMap<IpAddr, u64>,
    /// Every live transport session known for a peer address, in `PeerUp`
    /// arrival order (last = the active registration), bounded by
    /// [`MAX_LIVE_SESSIONS_PER_PEER`]. During the RFC 4271 §6.8 collision
    /// window two session tasks can be Established for one address and
    /// their `PeerUp`/`PeerDown` events interleave arbitrarily across the
    /// shared mpsc (per-sender FIFO only). Keeping the superseded-but-
    /// still-live session's registration material lets the manager FAIL
    /// OVER to it when the active session goes down (the symmetric
    /// interleaving `PeerUp(winner)` → `PeerUp(loser)` →
    /// `PeerDown(loser)`) instead of tearing down a peer that still has
    /// an Established session. Entries are removed by their session's own
    /// `PeerDown`/GR-down or by full peer teardown.
    live_sessions: HashMap<IpAddr, Vec<LiveSessionRecord>>,
    export_policy: Option<PolicyChain>,
    peer_export_policies: HashMap<IpAddr, Option<PolicyChain>>,
    /// Families the transport can actually serialize per peer.
    peer_sendable_families: HashMap<IpAddr, Vec<(Afi, Safi)>>,
    /// Families for which each registered outbound peer advertised the
    /// Long-Lived Graceful Restart capability (RFC 9494). Gates the
    /// export of LLGR-stale routes: absent family + eBGP target =
    /// suppress (§4.4); absent family + iBGP target = advertise with
    /// `NO_EXPORT` and `LOCAL_PREF` 0, rewritten in transport (§4.6).
    peer_advertised_llgr_families: HashMap<IpAddr, Vec<(Afi, Safi)>>,
    /// Whether each registered outbound peer is eBGP (true) or iBGP (false).
    peer_is_ebgp: HashMap<IpAddr, bool>,
    /// Whether each registered outbound peer is a route reflector client.
    peer_is_rr_client: HashMap<IpAddr, bool>,
    /// RFC 9107 ORR vantage per registered outbound peer (RR clients
    /// configured with `orr_vantage` only).
    peer_orr_vantage: HashMap<IpAddr, IpAddr>,
    /// Cached ORR topology + per-vantage SPF state (RFC 9107), rebuilt
    /// by [`Self::recompute_orr`] at every BGP-LS mutation seam. Empty
    /// while `peer_orr_vantage` is empty (zero non-ORR cost).
    orr: crate::orr::OrrState,
    /// Local cluster ID for route reflection (RFC 4456). `None` = not an RR.
    cluster_id: Option<Ipv4Addr>,
    /// Peers that failed a `try_send()` and need a full export resync.
    dirty_peers: HashSet<IpAddr>,
    /// Peers whose next `distribute_changes` pass must bypass the
    /// `AdjRibOut`-already-matches suppression for currently-
    /// advertised routes. Used by `RibUpdate::RefreshPeerOutbound`
    /// when an *outbound attribute surface* changes that the RIB
    /// itself cannot see — RFC 8326 `GShut` community attach toggle
    /// is the canonical case: the toggle lives on `PeerSession` and
    /// gets applied in transport's `attach_graceful_shutdown_if_enabled`,
    /// AFTER the RIB-side equality check, so the diff sees no change
    /// and would otherwise skip re-emit. The set is consumed (cleared
    /// per peer) at the end of each `distribute_changes` pass so the
    /// force is one-shot and doesn't leak into unrelated subsequent
    /// passes.
    force_outbound_peers: HashSet<IpAddr>,
    /// `EoR` markers that failed to enqueue and must be retried.
    pending_eor: HashMap<IpAddr, HashSet<(Afi, Safi)>>,
    /// Families with an outstanding enhanced route refresh response retry.
    pending_refresh: HashMap<IpAddr, HashSet<(Afi, Safi)>>,
    /// Active inbound enhanced route refresh windows by peer/family.
    refresh_in_progress: HashMap<IpAddr, HashSet<(Afi, Safi)>>,
    /// Per-peer/per-family deadlines for active enhanced route refresh windows.
    refresh_deadlines: HashMap<(IpAddr, Afi, Safi), tokio::time::Instant>,
    /// Unicast routes still awaiting replacement during an inbound refresh.
    refresh_stale_routes: HashMap<IpAddr, HashSet<(Prefix, u32)>>,
    /// `FlowSpec` routes still awaiting replacement during an inbound refresh.
    refresh_stale_flowspec: HashMap<IpAddr, HashSet<(Afi, FlowSpecRule, u32)>>,
    /// EVPN routes still awaiting replacement during an inbound refresh.
    refresh_stale_evpn: HashMap<IpAddr, HashSet<rustbgpd_wire::EvpnRouteKey>>,
    /// BGP-LS routes still awaiting replacement during an inbound refresh.
    refresh_stale_bgpls: HashMap<IpAddr, HashSet<crate::route::BgpLsRouteKey>>,
    /// VPNv4/VPNv6 routes still awaiting replacement during an inbound refresh.
    refresh_stale_vpn: HashMap<IpAddr, HashSet<crate::route::VpnRibRouteKey>>,
    /// Labeled-unicast route keys marked stale by an in-progress RFC 7313
    /// enhanced route refresh (the SAFI 4 sibling of `refresh_stale_vpn`).
    refresh_stale_labeled: HashMap<IpAddr, HashSet<crate::route::LabeledRibRouteKey>>,
    /// RT-Constrain routes still awaiting replacement during an inbound refresh.
    refresh_stale_rtc: HashMap<IpAddr, HashSet<crate::route::RtcRibRouteKey>>,
    /// O(1) per-peer/per-family stale-entry counts for refresh observability.
    refresh_stale_counts: HashMap<(IpAddr, Afi, Safi), usize>,
    /// Peers currently undergoing graceful restart, keyed by peer address.
    /// Value is the set of (AFI, SAFI) families still awaiting End-of-RIB.
    gr_peers: HashMap<IpAddr, HashSet<(Afi, Safi)>>,
    /// Deadlines for sweeping stale routes per GR peer.
    gr_stale_deadlines: HashMap<IpAddr, tokio::time::Instant>,
    /// Configured stale-routes-time per GR peer (seconds), used to reset
    /// the timer on `PeerUp` during graceful restart.
    gr_stale_routes_time: HashMap<IpAddr, u64>,
    /// Peers currently in LLGR stale phase (RFC 9494), keyed by peer address.
    /// Value is the set of (AFI, SAFI) families in LLGR.
    llgr_peers: HashMap<IpAddr, HashSet<(Afi, Safi)>>,
    /// Deadlines for sweeping LLGR-stale routes, per (peer, AFI, SAFI) —
    /// RFC 9494 §4.3 stale time is negotiated per family. An entry is
    /// stamped ONCE when the family enters the LLGR stale phase and
    /// deliberately survives re-establishment while routes remain
    /// LLGR-stale: the ORIGINAL Long-Lived Stale Time bounds total
    /// retention, so a reconnect-then-down never restarts the timer.
    llgr_stale_deadlines: HashMap<(IpAddr, Afi, Safi), tokio::time::Instant>,
    /// Configured per-peer LLGR parameters, stored on `PeerGracefulRestart`.
    llgr_peer_config: HashMap<IpAddr, LlgrPeerConfig>,
    /// Maximum Add-Path paths per prefix per peer (0 = single-best only).
    peer_add_path_send_max: HashMap<IpAddr, u32>,
    /// Effective family-local Add-Path caps, including peer Paths-Limit.
    peer_add_path_send_limits: HashMap<IpAddr, HashMap<(Afi, Safi), u32>>,
    /// Route-server clients with RFC 7947 §2.3.2 per-client best-path
    /// enabled: unicast export stages the first export-policy-permitted
    /// candidate (path-hiding mitigation) at `path_id 0` instead of the
    /// Loc-RIB best. Families with negotiated Add-Path send take the
    /// multipath path instead.
    peer_per_client_best: HashSet<IpAddr>,
    /// Peer ASN, tracked for MRT `PEER_INDEX_TABLE`.
    peer_asn: HashMap<IpAddr, u32>,
    /// Peer-group membership used for export policy neighbor-set matching.
    peer_group: HashMap<IpAddr, String>,
    /// Peer BGP router ID, tracked for MRT `PEER_INDEX_TABLE`.
    peer_bgp_id: HashMap<IpAddr, Ipv4Addr>,
    /// Families for which Add-Path Send/Both was negotiated per peer.
    peer_add_path_send_families: HashMap<IpAddr, Vec<(Afi, Safi)>>,
    /// Per-peer Address-Prefix ORF filters (RFC 5291/5292), keyed by
    /// `(AFI, SAFI)`. Consulted as an additional outbound filter before export
    /// policy when distributing to the peer. Absent ⇒ no ORF constraint.
    peer_orf_filters: HashMap<IpAddr, HashMap<(Afi, Safi), crate::orf::OrfFilterSet>>,
    /// Per-peer RT-Constrain membership (RFC 4684) gating VPNv4/VPNv6
    /// distribution. Present (possibly empty = advertise NO VPN routes,
    /// the strict rule) from peer-up for every peer that negotiated
    /// `(IPv4, RtConstrain)`; absent ⇒ no RTC constraint. Per-session
    /// state: cleared with the rest of the outbound teardown, so a GR
    /// re-establish starts strict until the peer's interest re-arrives.
    peer_rt_membership: HashMap<IpAddr, RtcMembership>,
    /// Families whose initial advertisement is gated pending the peer's first
    /// ROUTE-REFRESH (RFC 5291 §6). While a `(peer, AFI, SAFI)` is here, the
    /// initial table dump skips it; the gate is lifted on the first refresh.
    peer_orf_pending: HashMap<IpAddr, HashSet<(Afi, Safi)>>,
    /// Families whose initial-table `EoR` is withheld because the peer came
    /// back as a graceful-restart RESTARTER (RFC 4724) while the family was
    /// still behind the RFC 5291 §6 ORF initial-advertisement gate. An
    /// immediate `EoR` would tell the restarter our initial update is
    /// complete and trigger its stale-route sweep BEFORE the gated flood
    /// arrives — a self-inflicted blackhole window. The `EoR` is emitted
    /// after the gate lifts and the gated flood is sent. Non-GR ORF peers
    /// keep the immediate `EoR`: a client that never sends ROUTE-REFRESH
    /// would otherwise never see `EoR` at all.
    gr_deferred_eor: HashMap<IpAddr, HashSet<(Afi, Safi)>>,
    /// Current RPKI VRP table for origin validation. `None` = no RPKI data.
    vrp_table: Option<Arc<VrpTable>>,
    /// Current ASPA table for path verification. `None` = no ASPA data.
    aspa_table: Option<Arc<rustbgpd_rpki::AspaTable>>,
    route_events_tx: broadcast::Sender<RouteEvent>,
    /// Currently surfaced unicast export-policy denials. This keeps
    /// route-level policy-filtered events transition-based instead of
    /// re-emitting on every dirty or forced outbound resync.
    policy_filtered_routes: HashMap<IpAddr, HashSet<PolicyFilteredRouteKey>>,
    /// Aggregate export-policy evaluation counters keyed by target peer.
    export_policy_stats: HashMap<IpAddr, NeighborPolicyStats>,
    /// Bounded recent route-event history for after-the-fact operator
    /// timeline queries. Live streaming still uses `route_events_tx`.
    route_event_history: VecDeque<RouteEvent>,
    /// Monotonic process-local id assigned before route events are recorded in
    /// history and broadcast to live subscribers.
    next_route_event_id: u64,
    /// True after the process-local route-event id reaches `u64::MAX`.
    /// Further events keep publishing with the saturated id instead of
    /// panicking the RIB manager. This is a defense-in-depth branch: hitting
    /// it would require exhausting the entire 64-bit event space in one
    /// daemon lifetime.
    route_event_id_exhausted: bool,
    /// EVPN best-path change broadcast. Separate from
    /// `route_events_tx` because `RouteEvent` is keyed by `Prefix`
    /// (unicast-only) and EVPN consumers (the daemon's local-MAC
    /// originator) need an `EvpnRouteKey`-shaped event with the full
    /// new best path attached. ADR-0055 §5 — Gate 7c.
    evpn_events_tx: broadcast::Sender<crate::event::EvpnRouteEvent>,
    /// Bounded recent EVPN best-path event history for after-the-fact
    /// operator timeline queries. Live streaming still uses
    /// `evpn_events_tx`.
    evpn_route_event_history: VecDeque<crate::event::EvpnRouteEvent>,
    /// Sink for the durable event outbox (ADR-0072). Fires AFTER the
    /// process-local ring + broadcast at every publish site. Defaults
    /// to [`crate::event_sink::NoopRibEventSink`] so callers that
    /// don't care about durable history (tests, daemons with
    /// `[event_history].enabled = false`) need not change anything.
    /// The binary installs an EHM-backed sink via
    /// [`Self::with_event_sink`] when `[event_history]` is enabled.
    event_sink: std::sync::Arc<dyn crate::event_sink::RibEventSink>,
    /// RFC 9069 Loc-RIB BMP tap. When set, every Loc-RIB best-path
    /// change on a streamed family (unicast + VPN) is synthesized into
    /// an UPDATE PDU and sent as a `LocRibRouteMonitoring` event; `None`
    /// (no collector monitors `loc_rib`) costs one `is_some()` check
    /// per recompute.
    bmp_tx: Option<mpsc::Sender<rustbgpd_bmp::BmpEvent>>,
    metrics: BgpMetrics,
    rx: mpsc::Receiver<RibUpdate>,
    /// Priority channel for read-only queries (gRPC).
    query_rx: mpsc::Receiver<RibUpdate>,
    /// Large route batches that are being processed in chunks.
    pending_route_batches: VecDeque<PendingRoutesReceived>,
    /// Best-path changes accumulated across the chunks of the
    /// currently-draining route batch and distributed in a single
    /// `distribute_changes` call when the batch is exhausted. Deferring
    /// only the *distribution* coalesces a multi-chunk initial-load flood
    /// into one outbound batch per peer instead of one per 1024-route
    /// chunk. `recompute_best` still runs per chunk, so Loc-RIB, route
    /// events, and partial-progress Loc-RIB queries stay live mid-batch.
    ///
    /// Flush boundary, precisely: the run loop processes new primary-channel
    /// *updates* (`PeerUp` / `PeerDown`, further `RoutesReceived`, `EoR` —
    /// anything that mutates the RIB) only once all pending chunks drain (see
    /// `process_next_route_chunk`), so the accumulator is always fully
    /// flushed before any mutation observes Adj-RIB-Out, and is empty
    /// between batches. Priority read-only *queries* DO still interleave
    /// between chunks (`drain_queries`): a `QueryAdvertised*` reading
    /// Adj-RIB-Out mid-flood correctly sees pre-flush advertised state —
    /// those routes have not been advertised yet — even though Loc-RIB has
    /// advanced. That is an accurate, eventually-consistent intermediate
    /// view, not stale data: Adj-RIB-Out is "what we have sent", and we have
    /// not sent the deferred batch yet.
    pending_distribute_changed: HashSet<Prefix>,
    pending_distribute_affected: HashSet<Prefix>,
    /// Test-only ingest stall (ADR-0078 fault injection). When set via
    /// [`TEST_INGEST_STALL_ENV`], the run loop sleeps this long before
    /// handling each `RoutesReceived` batch popped from the primary
    /// channel, so the channel's remaining capacity stays occupied by
    /// the session tasks' sends and the inbound backpressure path
    /// (block-never-drop, writer-owned keepalives, pending-input hold
    /// re-arm) becomes deterministically observable. `None` in
    /// production — the only cost when unset is an `is_some()` check.
    test_ingest_stall: Option<std::time::Duration>,
    /// Update-group fingerprint registry (slice 1): membership (group
    /// id or ungrouped reason) per registered peer. Since slice 2 the
    /// distribution path reads it: grouped peers share the staged
    /// tables in `group_ribs`; ungrouped peers keep the per-peer path.
    update_groups: update_groups::UpdateGroupRegistry,
    /// Group-owned staged outbound tables, keyed by group id. One per
    /// non-empty group; created (and built with a single shared staging
    /// pass) at the first member's join, dropped at the last member's
    /// leave. See [`update_groups::GroupRibOut`].
    group_ribs: HashMap<usize, update_groups::GroupRibOut>,
    /// A regrouped member's previously-advertised view (old group table
    /// minus own-sourced, or the per-peer Adj-RIB-Out) — unicast plus
    /// group-owned VPN — held until its one-shot resync diff succeeds.
    /// Transient — regroups are config-time events.
    pending_regroup_baseline: HashMap<IpAddr, update_groups::RegroupBaseline>,
    /// Extra (over-)withdraw keys a member must emit on its next
    /// resync: tombstones carried across a regroup by a member that was
    /// dirty when it moved (its missed withdrawals are unknown —
    /// over-withdraw is the safe direction). Cleared on resync success.
    pending_extra_withdraws: HashMap<IpAddr, update_groups::ExtraWithdraws>,
    /// Differential-oracle test hook: disqualify every peer from
    /// grouping so identical scenarios can be driven through the
    /// per-peer path (the correctness oracle) and compared against a
    /// grouped run.
    #[cfg(test)]
    test_force_ungrouped: bool,
}

/// Bound on `live_sessions` entries per peer address. The RFC 4271 §6.8
/// collision window realistically holds two concurrent sessions (one per
/// connection direction); the bound only guards against a pathological
/// emitter. When exceeded, the OLDEST (most-superseded) record is dropped
/// — its eventual `PeerDown` is then discarded as stale.
const MAX_LIVE_SESSIONS_PER_PEER: usize = 2;

/// Registration material for one live transport session of a peer
/// address, captured at `PeerUp`. Held in `RibManager::live_sessions` so
/// an outbound-registration failover can re-register a surviving session
/// (channel + negotiated metadata + initial table dump) after the active
/// session goes down during the collision window.
pub(super) struct LiveSessionRecord {
    session_id: u64,
    outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
    peer_asn: u32,
    peer_router_id: Ipv4Addr,
    export_policy: Option<PolicyChain>,
    sendable_families: Vec<(Afi, Safi)>,
    is_ebgp: bool,
    route_reflector_client: bool,
    orr_vantage: Option<IpAddr>,
    per_client_best: bool,
    add_path_send_families: Vec<(Afi, Safi)>,
    add_path_send_max: u32,
    negotiated_orf_recv: Vec<(Afi, Safi)>,
    negotiated_llgr_families: Vec<(Afi, Safi)>,
}

const ROUTES_RECEIVED_CHUNK_SIZE: usize = 1024;
/// Synthesized messages per RFC 9069 Loc-RIB dump chunk — the
/// per-request allocation bound of the resumable dump (the final chunk
/// additionally carries one End-of-RIB marker per streamed family).
const BMP_DUMP_CHUNK_SIZE: usize = 256;

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

/// Server-side hard cap on a paged route-query page — bounds per-page
/// allocation regardless of the client-requested size.
pub(crate) const ROUTE_QUERY_MAX_PAGE_SIZE: usize = 1000;

/// One bounded page over an unordered route iterator: the filter-matching
/// routes with the `page_size` smallest identity keys strictly greater
/// than `after`, ascending, plus the scope's total matching count.
/// Single pass, O(page) allocation — the same mutation-robust cursor
/// step as [`smallest_keys_after`], carrying the routes alongside the
/// keys so no per-key re-lookup is needed.
fn page_routes<'a>(
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
    }
}
const QUERY_BUDGET_PER_CHUNK: usize = 8;
const ROUTE_EVENT_HISTORY_CAPACITY: usize = 4096;
const EVPN_ROUTE_EVENT_HISTORY_CAPACITY: usize = 4096;

/// Test-only fault injection for the ADR-0078 inbound backpressure
/// contract: milliseconds the RIB manager sleeps before handling each
/// `RoutesReceived` batch. Used by the M63 interop smoke to stall the
/// RIB against a real peer so the inbound channel fills, the session
/// task parks, and hold-timer survival is provable. Never set this in
/// production. Read once at RIB-manager construction; unset, empty,
/// zero, or unparseable values disable the stall.
const TEST_INGEST_STALL_ENV: &str = "RUSTBGPD_TEST_RIB_INGEST_STALL_MS";

/// Pure core of the [`TEST_INGEST_STALL_ENV`] override with the
/// environment value injected, so the parse rule (positive u64
/// milliseconds → stall, anything else → no stall) is unit-testable
/// without touching process-global env state.
fn test_ingest_stall_override(env: Option<&str>) -> Option<std::time::Duration> {
    let raw = env?;
    match raw.trim().parse::<u64>() {
        Ok(ms) if ms > 0 => Some(std::time::Duration::from_millis(ms)),
        Ok(_) => None,
        Err(_) => {
            warn!(
                value = %raw,
                "ignoring invalid {TEST_INGEST_STALL_ENV} (expected milliseconds as a u64)"
            );
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct PolicyFilteredRouteKey {
    pub(super) target_peer: IpAddr,
    pub(super) source_peer: IpAddr,
    pub(super) prefix: Prefix,
    pub(super) path_id: u32,
}

enum PendingRouteChunk {
    Withdrawn(Vec<(Prefix, u32)>),
    Announced(Vec<crate::route::Route>),
    FlowSpecWithdrawn(Vec<FlowSpecRule>),
    FlowSpecAnnounced(Vec<crate::route::FlowSpecRoute>),
    EvpnWithdrawn(Vec<rustbgpd_wire::EvpnRouteKey>),
    EvpnAnnounced(Vec<crate::route::EvpnRibRoute>),
}

enum PendingRoutePhase {
    Withdrawn,
    Announced,
    FlowSpecWithdrawn,
    FlowSpecAnnounced,
    EvpnWithdrawn,
    EvpnAnnounced,
    Done,
}

struct PendingRoutesReceived {
    peer: IpAddr,
    route_capacity_hint: usize,
    flowspec_capacity_hint: usize,
    withdrawn: std::vec::IntoIter<(Prefix, u32)>,
    announced: std::vec::IntoIter<crate::route::Route>,
    flowspec_withdrawn: std::vec::IntoIter<FlowSpecRule>,
    flowspec_announced: std::vec::IntoIter<crate::route::FlowSpecRoute>,
    evpn_withdrawn: std::vec::IntoIter<rustbgpd_wire::EvpnRouteKey>,
    evpn_announced: std::vec::IntoIter<crate::route::EvpnRibRoute>,
    phase: PendingRoutePhase,
}

impl PendingRoutesReceived {
    fn new(
        peer: IpAddr,
        announced: Vec<crate::route::Route>,
        withdrawn: Vec<(Prefix, u32)>,
        flowspec_announced: Vec<crate::route::FlowSpecRoute>,
        flowspec_withdrawn: Vec<FlowSpecRule>,
        evpn_announced: Vec<crate::route::EvpnRibRoute>,
        evpn_withdrawn: Vec<rustbgpd_wire::EvpnRouteKey>,
    ) -> Self {
        let route_capacity_hint = (announced.len() + withdrawn.len()).max(16);
        let flowspec_capacity_hint = (flowspec_announced.len() + flowspec_withdrawn.len()).max(4);
        Self {
            peer,
            route_capacity_hint,
            flowspec_capacity_hint,
            withdrawn: withdrawn.into_iter(),
            announced: announced.into_iter(),
            flowspec_withdrawn: flowspec_withdrawn.into_iter(),
            flowspec_announced: flowspec_announced.into_iter(),
            evpn_withdrawn: evpn_withdrawn.into_iter(),
            evpn_announced: evpn_announced.into_iter(),
            phase: PendingRoutePhase::Withdrawn,
        }
    }

    fn route_capacity_hint(&self) -> usize {
        self.route_capacity_hint
    }

    fn flowspec_capacity_hint(&self) -> usize {
        self.flowspec_capacity_hint
    }

    fn peer(&self) -> IpAddr {
        self.peer
    }

    fn next_chunk(&mut self) -> Option<PendingRouteChunk> {
        loop {
            match self.phase {
                PendingRoutePhase::Withdrawn => {
                    let chunk: Vec<_> = self
                        .withdrawn
                        .by_ref()
                        .take(ROUTES_RECEIVED_CHUNK_SIZE)
                        .collect();
                    if chunk.is_empty() {
                        self.phase = PendingRoutePhase::Announced;
                        continue;
                    }
                    return Some(PendingRouteChunk::Withdrawn(chunk));
                }
                PendingRoutePhase::Announced => {
                    let chunk: Vec<_> = self
                        .announced
                        .by_ref()
                        .take(ROUTES_RECEIVED_CHUNK_SIZE)
                        .collect();
                    if chunk.is_empty() {
                        self.phase = PendingRoutePhase::FlowSpecWithdrawn;
                        continue;
                    }
                    return Some(PendingRouteChunk::Announced(chunk));
                }
                PendingRoutePhase::FlowSpecWithdrawn => {
                    let chunk: Vec<_> = self
                        .flowspec_withdrawn
                        .by_ref()
                        .take(ROUTES_RECEIVED_CHUNK_SIZE)
                        .collect();
                    if chunk.is_empty() {
                        self.phase = PendingRoutePhase::FlowSpecAnnounced;
                        continue;
                    }
                    return Some(PendingRouteChunk::FlowSpecWithdrawn(chunk));
                }
                PendingRoutePhase::FlowSpecAnnounced => {
                    let chunk: Vec<_> = self
                        .flowspec_announced
                        .by_ref()
                        .take(ROUTES_RECEIVED_CHUNK_SIZE)
                        .collect();
                    if chunk.is_empty() {
                        self.phase = PendingRoutePhase::EvpnWithdrawn;
                        continue;
                    }
                    return Some(PendingRouteChunk::FlowSpecAnnounced(chunk));
                }
                PendingRoutePhase::EvpnWithdrawn => {
                    let chunk: Vec<_> = self
                        .evpn_withdrawn
                        .by_ref()
                        .take(ROUTES_RECEIVED_CHUNK_SIZE)
                        .collect();
                    if chunk.is_empty() {
                        self.phase = PendingRoutePhase::EvpnAnnounced;
                        continue;
                    }
                    return Some(PendingRouteChunk::EvpnWithdrawn(chunk));
                }
                PendingRoutePhase::EvpnAnnounced => {
                    let chunk: Vec<_> = self
                        .evpn_announced
                        .by_ref()
                        .take(ROUTES_RECEIVED_CHUNK_SIZE)
                        .collect();
                    if chunk.is_empty() {
                        self.phase = PendingRoutePhase::Done;
                        continue;
                    }
                    return Some(PendingRouteChunk::EvpnAnnounced(chunk));
                }
                PendingRoutePhase::Done => return None,
            }
        }
    }

    fn has_more(&self) -> bool {
        !self.withdrawn.as_slice().is_empty()
            || !self.announced.as_slice().is_empty()
            || !self.flowspec_withdrawn.as_slice().is_empty()
            || !self.flowspec_announced.as_slice().is_empty()
            || !self.evpn_withdrawn.as_slice().is_empty()
            || !self.evpn_announced.as_slice().is_empty()
    }
}

impl RibManager {
    /// Sweep the global attribute intern table (drop entries no route
    /// references any more) and refresh its gauge. Run after any batch
    /// that removed or replaced routes — the same seams that swept the
    /// per-peer tables before LAN-336.
    fn gc_attr_intern(&mut self) {
        self.attr_intern.gc();
        self.sync_attr_intern_gauge();
    }

    /// Refresh the global intern-table gauge without sweeping. Run after
    /// insert-only batches so growth is visible at every mutation seam
    /// (a gauge a scenario never updates cannot gate anything).
    fn sync_attr_intern_gauge(&self) {
        self.metrics
            .set_rib_attr_intern_global_size(gauge_val(self.attr_intern.len()));
    }
}

impl RibManager {
    /// Create a new RIB manager with the given update channel and optional export policy.
    #[must_use]
    pub fn new(
        rx: mpsc::Receiver<RibUpdate>,
        query_rx: mpsc::Receiver<RibUpdate>,
        export_policy: Option<PolicyChain>,
        cluster_id: Option<Ipv4Addr>,
        metrics: BgpMetrics,
    ) -> Self {
        let (route_events_tx, _) = broadcast::channel(4096);
        metrics.set_route_event_history_capacity(
            i64::try_from(ROUTE_EVENT_HISTORY_CAPACITY).unwrap_or(i64::MAX),
        );
        metrics.set_route_event_history_depth(0);
        // EVPN broadcast — same capacity as the unicast channel.
        // Slow EVPN subscribers receive `Lagged(_)`; the daemon's
        // originator falls back to `repoll_rib` per ADR-0054 §6's
        // level-triggered model. Capacity here only needs to ride
        // through transient bursts (mobility storms, FRR-side
        // re-advertisement on session up).
        let (evpn_events_tx, _) = broadcast::channel(4096);
        // Read the test-only ingest stall once at construction
        // (RIB-manager startup); unset in production.
        let test_ingest_stall_env = match std::env::var(TEST_INGEST_STALL_ENV) {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                warn!("ignoring non-unicode {TEST_INGEST_STALL_ENV}");
                None
            }
        };
        let test_ingest_stall = test_ingest_stall_override(test_ingest_stall_env.as_deref());
        if let Some(stall) = test_ingest_stall {
            warn!(
                stall_ms = u64::try_from(stall.as_millis()).unwrap_or(u64::MAX),
                "{TEST_INGEST_STALL_ENV} active: stalling every RoutesReceived batch \
                 (ADR-0078 fault injection — test use only, never set in production)"
            );
        }
        Self {
            ribs: HashMap::new(),
            attr_intern: crate::attr_intern::AttrInternTable::new(),
            unicast_prefix_peers: UnicastPrefixPeers::default(),
            loc_rib: LocRib::new(),
            adj_ribs_out: HashMap::new(),
            outbound_peers: HashMap::new(),
            outbound_session_ids: HashMap::new(),
            live_sessions: HashMap::new(),
            export_policy,
            peer_export_policies: HashMap::new(),
            peer_sendable_families: HashMap::new(),
            peer_advertised_llgr_families: HashMap::new(),
            peer_is_ebgp: HashMap::new(),
            peer_is_rr_client: HashMap::new(),
            peer_orr_vantage: HashMap::new(),
            orr: crate::orr::OrrState::default(),
            cluster_id,
            dirty_peers: HashSet::new(),
            force_outbound_peers: HashSet::new(),
            pending_eor: HashMap::new(),
            pending_refresh: HashMap::new(),
            refresh_in_progress: HashMap::new(),
            refresh_deadlines: HashMap::new(),
            refresh_stale_routes: HashMap::new(),
            refresh_stale_flowspec: HashMap::new(),
            refresh_stale_evpn: HashMap::new(),
            refresh_stale_bgpls: HashMap::new(),
            refresh_stale_vpn: HashMap::new(),
            refresh_stale_labeled: HashMap::new(),
            refresh_stale_rtc: HashMap::new(),
            refresh_stale_counts: HashMap::new(),
            gr_peers: HashMap::new(),
            gr_stale_deadlines: HashMap::new(),
            gr_stale_routes_time: HashMap::new(),
            llgr_peers: HashMap::new(),
            llgr_stale_deadlines: HashMap::new(),
            llgr_peer_config: HashMap::new(),
            peer_add_path_send_max: HashMap::new(),
            peer_add_path_send_limits: HashMap::new(),
            peer_per_client_best: HashSet::new(),
            peer_add_path_send_families: HashMap::new(),
            peer_orf_filters: HashMap::new(),
            peer_rt_membership: HashMap::new(),
            peer_orf_pending: HashMap::new(),
            gr_deferred_eor: HashMap::new(),
            peer_asn: HashMap::new(),
            peer_group: HashMap::new(),
            peer_bgp_id: HashMap::new(),
            update_groups: update_groups::UpdateGroupRegistry::default(),
            group_ribs: HashMap::new(),
            pending_regroup_baseline: HashMap::new(),
            pending_extra_withdraws: HashMap::new(),
            #[cfg(test)]
            test_force_ungrouped: false,
            vrp_table: None,
            aspa_table: None,
            route_events_tx,
            policy_filtered_routes: HashMap::new(),
            export_policy_stats: HashMap::new(),
            route_event_history: VecDeque::with_capacity(ROUTE_EVENT_HISTORY_CAPACITY),
            next_route_event_id: 1,
            route_event_id_exhausted: false,
            evpn_events_tx,
            evpn_route_event_history: VecDeque::with_capacity(EVPN_ROUTE_EVENT_HISTORY_CAPACITY),
            event_sink: std::sync::Arc::new(crate::event_sink::NoopRibEventSink),
            bmp_tx: None,
            metrics,
            rx,
            query_rx,
            pending_route_batches: VecDeque::new(),
            pending_distribute_changed: HashSet::new(),
            pending_distribute_affected: HashSet::new(),
            test_ingest_stall,
        }
    }

    /// Test-only ADR-0078 fault injection: sleep before handling a
    /// `RoutesReceived` batch popped from the primary channel. The
    /// sleep happens *after* the recv and *before* `handle_update`, so
    /// the channel's remaining slots stay occupied by session-task
    /// sends for the whole stall — exactly the saturation shape the
    /// M63 interop smoke needs. No-op (one `is_some()` check) unless
    /// [`TEST_INGEST_STALL_ENV`] was set at construction.
    async fn maybe_stall_test_ingest(&self, update: &RibUpdate) {
        if let Some(stall) = self.test_ingest_stall
            && matches!(update, RibUpdate::RoutesReceived { .. })
        {
            debug!(
                stall_ms = u64::try_from(stall.as_millis()).unwrap_or(u64::MAX),
                "test ingest stall before RoutesReceived batch"
            );
            tokio::time::sleep(stall).await;
        }
    }

    /// Install an out-of-crate event sink. Called once at startup by
    /// the daemon binary when `[event_history].enabled = true`. The
    /// sink fires from the route and EVPN publish helpers alongside
    /// the existing process-local rings and legacy broadcasts. The
    /// durable cursor contract is owned by `SubscribeFromEvent`; the
    /// legacy watch/list surfaces keep their pre-existing behavior.
    #[must_use]
    pub fn with_event_sink(
        mut self,
        sink: std::sync::Arc<dyn crate::event_sink::RibEventSink>,
    ) -> Self {
        self.event_sink = sink;
        self
    }

    /// Install the RFC 9069 Loc-RIB BMP tap. Called at startup by the
    /// daemon binary when at least one BMP collector monitors the
    /// `loc_rib` view; left `None` otherwise so non-monitored
    /// deployments pay nothing for PDU synthesis.
    #[must_use]
    pub fn with_bmp_tx(mut self, bmp_tx: mpsc::Sender<rustbgpd_bmp::BmpEvent>) -> Self {
        self.bmp_tx = Some(bmp_tx);
        self
    }

    /// Emit an RFC 9069 Loc-RIB Route Monitoring event. `pdu = None`
    /// (synthesis failure, already warned) is a no-op. `path_status`
    /// carries the Path Marking payload for announcements (`None` on
    /// withdrawals — a gone path has no status). Uses `try_send`
    /// — monitoring must never backpressure the RIB task; drops are
    /// surfaced with a warning.
    fn emit_bmp_loc_rib(
        &self,
        pdu: Option<bytes::Bytes>,
        path_status: Option<rustbgpd_bmp::BmpPathStatus>,
        timestamp: std::time::SystemTime,
    ) {
        let (Some(tx), Some(update_pdu)) = (self.bmp_tx.as_ref(), pdu) else {
            return;
        };
        if let Err(e) = tx.try_send(rustbgpd_bmp::BmpEvent::LocRibRouteMonitoring {
            update_pdu,
            timestamp,
            path_status,
        }) {
            warn!(error = %e, "BMP event channel full or closed, dropping Loc-RIB route monitoring");
        }
    }

    #[must_use]
    fn peer_has_any_add_path_send(&self, peer: IpAddr) -> bool {
        self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0) > 0
            && self
                .peer_add_path_send_families
                .get(&peer)
                .is_some_and(|families| !families.is_empty())
    }

    #[must_use]
    fn add_path_send_max_for_prefix(&self, peer: IpAddr, prefix: &Prefix) -> u32 {
        let send_max = self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0);
        if send_max == 0 {
            return 0;
        }
        let family = prefix_family(prefix);
        if let Some(limit) = self
            .peer_add_path_send_limits
            .get(&peer)
            .and_then(|limits| limits.get(&family))
        {
            return *limit;
        }
        if self
            .peer_add_path_send_families
            .get(&peer)
            .is_some_and(|families| families.contains(&family))
        {
            send_max
        } else {
            0
        }
    }

    /// Resolve the export policy for a peer: per-peer if set, else global.
    fn export_policy_for(&self, peer: IpAddr) -> Option<&PolicyChain> {
        match self.peer_export_policies.get(&peer) {
            Some(policy) => policy.as_ref(),
            None => self.export_policy.as_ref(),
        }
    }

    /// Clear all enhanced route refresh state for a peer.
    fn clear_peer_refresh_state(&mut self, peer: IpAddr) {
        self.pending_refresh.remove(&peer);
        self.refresh_in_progress.remove(&peer);
        self.refresh_stale_routes.remove(&peer);
        self.refresh_stale_flowspec.remove(&peer);
        self.refresh_stale_evpn.remove(&peer);
        self.refresh_stale_bgpls.remove(&peer);
        self.refresh_stale_vpn.remove(&peer);
        self.refresh_stale_labeled.remove(&peer);
        self.refresh_stale_rtc.remove(&peer);
        self.refresh_stale_counts
            .retain(|(stale_peer, _, _), _| *stale_peer != peer);
        self.refresh_deadlines
            .retain(|(stale_peer, _, _), _| *stale_peer != peer);
    }

    /// Drain a bounded number of pending queries from the priority channel.
    fn drain_queries(&mut self, limit: usize) {
        for _ in 0..limit {
            let Ok(query) = self.query_rx.try_recv() else {
                break;
            };
            self.handle_update(query);
        }
    }

    fn drain_ready_updates(&mut self) -> bool {
        let mut drained = false;
        while let Ok(update) = self.rx.try_recv() {
            drained = true;
            self.handle_update(update);
        }
        drained
    }

    /// Process a single `RibUpdate` message.
    #[expect(
        clippy::too_many_lines,
        reason = "dispatcher needs one arm per RibUpdate variant"
    )]
    fn handle_update(&mut self, update: RibUpdate) {
        match update {
            RibUpdate::RoutesReceived {
                peer,
                session_id,
                announced,
                withdrawn,
                flowspec_announced,
                flowspec_withdrawn,
                evpn_announced,
                evpn_withdrawn,
            } => {
                if !self.stale_session_message(peer, session_id, "RoutesReceived", "routes") {
                    self.enqueue_routes_received(
                        peer,
                        announced,
                        withdrawn,
                        flowspec_announced,
                        flowspec_withdrawn,
                        evpn_announced,
                        evpn_withdrawn,
                    );
                }
            }
            RibUpdate::BgpLsRoutesReceived {
                peer,
                session_id,
                announced,
                withdrawn,
            } => {
                if !self.stale_session_message(peer, session_id, "BgpLsRoutesReceived", "bgpls") {
                    self.handle_bgpls_routes_received(peer, announced, withdrawn);
                }
            }
            RibUpdate::VpnRoutesReceived {
                peer,
                session_id,
                announced,
                withdrawn,
            } => {
                if !self.stale_session_message(peer, session_id, "VpnRoutesReceived", "vpn") {
                    self.handle_vpn_routes_received(peer, announced, withdrawn);
                }
            }
            RibUpdate::LabeledRoutesReceived {
                peer,
                session_id,
                announced,
                withdrawn,
            } => {
                if !self.stale_session_message(peer, session_id, "LabeledRoutesReceived", "labeled")
                {
                    self.handle_labeled_routes_received(peer, announced, withdrawn);
                }
            }
            RibUpdate::RtcRoutesReceived {
                peer,
                session_id,
                announced,
                withdrawn,
            } => {
                if !self.stale_session_message(peer, session_id, "RtcRoutesReceived", "rtc") {
                    self.handle_rtc_routes_received(peer, announced, withdrawn);
                }
            }
            RibUpdate::PeerDown { peer, session_id } => self.handle_peer_down(peer, session_id),
            RibUpdate::PeerDeleted { peer } => self.handle_peer_deleted(peer),
            RibUpdate::PeerUp {
                peer,
                session_id,
                peer_asn,
                peer_router_id,
                outbound_tx,
                export_policy,
                sendable_families,
                is_ebgp,
                route_reflector_client,
                orr_vantage,
                per_client_best,
                add_path_send_families,
                add_path_send_max,
                negotiated_orf_recv,
                negotiated_llgr_families,
            } => self.handle_peer_up(
                peer,
                session_id,
                peer_asn,
                peer_router_id,
                outbound_tx,
                export_policy,
                sendable_families,
                is_ebgp,
                route_reflector_client,
                orr_vantage,
                per_client_best,
                add_path_send_families,
                add_path_send_max,
                negotiated_orf_recv,
                negotiated_llgr_families,
            ),
            RibUpdate::PeerAddPathLimits {
                peer,
                session_id,
                limits,
            } => {
                if self.outbound_session_ids.get(&peer).copied() == Some(session_id) {
                    self.peer_add_path_send_limits
                        .insert(peer, limits.into_iter().collect());
                    self.send_initial_table(peer);
                }
            }
            RibUpdate::PeerOrfUpdate {
                peer,
                session_id,
                afi,
                safi,
                when,
                entries,
                reply,
            } => {
                if self.stale_session_message(peer, session_id, "PeerOrfUpdate", "orf") {
                    let _ = reply.send(Err(format!(
                        "stale ORF update from superseded session {session_id} discarded"
                    )));
                } else {
                    self.handle_peer_orf_update(peer, afi, safi, when, &entries, reply);
                }
            }
            RibUpdate::SetPeerPolicyContext {
                peer,
                session_id,
                peer_group,
            } => {
                if !self.stale_session_message(
                    peer,
                    session_id,
                    "SetPeerPolicyContext",
                    "policy_context",
                ) {
                    self.handle_set_peer_policy_context(peer, peer_group);
                }
            }
            RibUpdate::InjectRoute { route, reply } => self.handle_inject_route(route, reply),
            RibUpdate::WithdrawInjected {
                prefix,
                path_id,
                reply,
            } => self.handle_withdraw_injected(prefix, path_id, reply),
            RibUpdate::QueryReceivedRoutes { peer, reply } => {
                self.handle_query_received_routes(peer, reply);
            }
            RibUpdate::QueryRoutesPage {
                scope,
                filter,
                after,
                page_size,
                reply,
            } => {
                self.handle_query_routes_page(scope, filter.as_ref(), after, page_size, reply);
            }
            RibUpdate::QueryBestRoutes { reply } => self.handle_query_best_routes(reply),
            RibUpdate::QueryFibInstallCandidates {
                max_paths,
                relax,
                weighted,
                reply,
            } => {
                self.handle_query_fib_install_candidates(max_paths, relax, weighted, reply);
            }
            RibUpdate::QueryPeerGroups { reply } => self.handle_query_peer_groups(reply),
            RibUpdate::QueryAdvertisedRoutes { peer, reply } => {
                self.handle_query_advertised_routes(peer, reply);
            }
            RibUpdate::ExplainBestPath {
                prefix,
                peer,
                reply,
            } => {
                self.handle_explain_best_path(prefix, peer, reply);
            }
            RibUpdate::ExplainAdvertisedRoute {
                peer,
                prefix,
                rd,
                reply,
            } => self.handle_explain_advertised_route(peer, prefix, rd, reply),
            RibUpdate::SubscribeRouteEvents { reply } => {
                self.handle_subscribe_route_events(reply);
            }
            RibUpdate::QueryRouteEventHistory {
                peer,
                afi,
                prefix,
                limit,
                reply,
            } => {
                self.handle_query_route_event_history(peer, afi, prefix, limit, reply);
            }
            RibUpdate::SubscribeEvpnRouteEvents { reply } => {
                self.handle_subscribe_evpn_route_events(reply);
            }
            RibUpdate::QueryEvpnRouteEventHistory {
                peer,
                route_type,
                rd,
                event_types,
                limit,
                reply,
            } => {
                self.handle_query_evpn_route_event_history(
                    peer,
                    route_type,
                    rd,
                    &event_types,
                    limit,
                    reply,
                );
            }
            RibUpdate::QueryLocRibCount { reply } => self.handle_query_loc_rib_count(reply),
            RibUpdate::QueryAdjRibOutCounts { reply } => {
                self.handle_query_adj_rib_out_counts(reply);
            }
            RibUpdate::QueryAdvertisedCount { peer, reply } => {
                self.handle_query_advertised_count(peer, reply);
            }
            RibUpdate::QueryNeighborPolicyStats { peer, reply } => {
                self.handle_query_neighbor_policy_stats(peer, reply);
            }
            RibUpdate::QueryPeerUpdateGroup { peer, reply } => {
                self.handle_query_peer_update_group(peer, reply);
            }
            #[cfg(test)]
            RibUpdate::TestQueryVpnAdvertised { peer, reply } => {
                self.handle_test_query_vpn_advertised(peer, reply);
            }
            #[cfg(test)]
            RibUpdate::TestQueryOutboundHealth { reply } => {
                let group_dirty = self
                    .group_ribs
                    .values()
                    .map(|group| group.dirty_members.len())
                    .sum();
                let group_tombstones = self
                    .group_ribs
                    .values()
                    .map(|group| group.tombstones.len() + group.vpn_tombstones.len())
                    .sum();
                let _ = reply.send((
                    self.dirty_peers.len(),
                    self.force_outbound_peers.len(),
                    group_dirty,
                    group_tombstones,
                    self.pending_regroup_baseline.len(),
                    self.pending_extra_withdraws.len(),
                ));
            }
            RibUpdate::QueryExportPolicyTermHits { peer, reply } => {
                self.handle_query_export_policy_term_hits(peer, reply);
            }
            RibUpdate::ReplacePeerExportPolicy {
                peer,
                export_policy,
                reply,
            } => self.handle_replace_peer_export_policy(peer, export_policy, reply),
            RibUpdate::RefreshPeerOutbound { peer, reply } => {
                self.handle_refresh_peer_outbound(peer, reply);
            }
            RibUpdate::EndOfRib {
                peer,
                session_id,
                afi,
                safi,
            } => {
                if !self.stale_session_message(peer, session_id, "EndOfRib", "eor") {
                    self.handle_end_of_rib(peer, afi, safi);
                }
            }
            RibUpdate::RouteRefreshRequest {
                peer,
                session_id,
                afi,
                safi,
            } => {
                if !self.stale_session_message(peer, session_id, "RouteRefreshRequest", "refresh") {
                    self.handle_route_refresh_request(peer, afi, safi);
                }
            }
            RibUpdate::BeginRouteRefresh {
                peer,
                session_id,
                afi,
                safi,
            } => {
                if !self.stale_session_message(peer, session_id, "BeginRouteRefresh", "refresh") {
                    self.handle_begin_route_refresh(peer, afi, safi);
                }
            }
            RibUpdate::EndRouteRefresh {
                peer,
                session_id,
                afi,
                safi,
            } => {
                if !self.stale_session_message(peer, session_id, "EndRouteRefresh", "refresh") {
                    self.handle_end_route_refresh(peer, afi, safi);
                }
            }
            RibUpdate::PeerGracefulRestart {
                peer,
                session_id,
                restart_time,
                stale_routes_time,
                gr_families,
                peer_llgr_capable,
                peer_llgr_families,
                llgr_stale_time,
            } => self.handle_peer_graceful_restart(
                peer,
                session_id,
                restart_time,
                stale_routes_time,
                gr_families,
                peer_llgr_capable,
                peer_llgr_families,
                llgr_stale_time,
            ),
            RibUpdate::RpkiCacheUpdate { table } => self.handle_rpki_cache_update(table),
            RibUpdate::AspaTableUpdate { table } => self.handle_aspa_cache_update(table),
            RibUpdate::InjectFlowSpec { route, reply } => self.handle_inject_flowspec(route, reply),
            RibUpdate::WithdrawFlowSpec { rule, reply } => {
                self.handle_withdraw_flowspec(rule, reply);
            }
            RibUpdate::InjectEvpn { route, reply } => self.handle_inject_evpn(route, reply),
            RibUpdate::WithdrawEvpn { key, reply } => self.handle_withdraw_evpn(key, reply),
            RibUpdate::QueryFlowSpecRoutes { reply } => {
                self.handle_query_flowspec_routes(reply);
            }
            RibUpdate::QueryEvpnRoutes { reply } => {
                let routes: Vec<crate::route::EvpnRibRoute> =
                    self.loc_rib.iter_evpn().cloned().collect();
                let _ = reply.send(routes);
            }
            RibUpdate::QueryBgpLsRoutes { reply } => {
                let routes: Vec<crate::route::BgpLsRibRoute> =
                    self.loc_rib.iter_bgpls().cloned().collect();
                let _ = reply.send(routes);
            }
            RibUpdate::QueryLabeledRoutes { reply } => {
                let routes: Vec<crate::route::LabeledRibRoute> =
                    self.loc_rib.iter_labeled().cloned().collect();
                let _ = reply.send(routes);
            }
            RibUpdate::QueryVpnRoutes { reply } => {
                let routes: Vec<crate::route::VpnRibRoute> =
                    self.loc_rib.iter_vpn().cloned().collect();
                let _ = reply.send(routes);
            }
            RibUpdate::QueryRtcRoutes { reply } => {
                let routes: Vec<crate::route::RtcRibRoute> =
                    self.loc_rib.iter_rtc().cloned().collect();
                let _ = reply.send(routes);
            }
            RibUpdate::QueryOrrTopology { reply } => {
                // With vantages configured the cached topology is fresh
                // by construction (rebuilt at every BGP-LS mutation
                // seam); without them the cache is intentionally empty,
                // so build on demand as before.
                let snapshot = if self.peer_orr_vantage.is_empty() {
                    crate::orr::OrrTopology::build(
                        self.ribs
                            .values()
                            .flat_map(crate::adj_rib_in::AdjRibIn::iter_bgpls),
                    )
                    .snapshot()
                } else {
                    self.orr.topology.snapshot()
                };
                let _ = reply.send(snapshot);
            }
            RibUpdate::QueryOrrStatus { reply } => self.handle_query_orr_status(reply),
            RibUpdate::QueryMrtSnapshot { reply } => self.handle_query_mrt_snapshot(reply),
            RibUpdate::QueryBmpLocRibDump { cursor, reply } => {
                self.handle_query_bmp_loc_rib_dump(cursor, reply);
            }
            RibUpdate::QueryBmpLocRibStats { reply } => {
                self.handle_query_bmp_loc_rib_stats(reply);
            }
        }
    }

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
    /// matching, and an insertion behind the cursor reaches the
    /// collector via the live stream (which the BMP manager holds back
    /// until the dump's End-of-RIB, so deltas always follow the
    /// snapshot rows on the wire). A phase yielding fewer than `N`
    /// keys is exhausted:
    /// unicast hands over to VPN, VPN closes the dump with one
    /// End-of-RIB per streamed family (dump→EoR→live ordering).
    // ponytail: each chunk re-scans the family's key set (O(table) per
    // chunk, O(table²/N) per dump) — swap the scan for a sorted index
    // or key snapshot if dump CPU at DFZ scale ever bites; allocation
    // is already bounded per chunk.
    fn handle_query_bmp_loc_rib_dump(
        &self,
        cursor: Option<rustbgpd_bmp::BmpDumpCursor>,
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
    fn handle_query_bmp_loc_rib_stats(
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

    fn handle_query_received_routes(
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
    // ponytail: each page re-scans the scope (O(table) per page, like
    // the BMP Loc-RIB dump) — allocation is bounded per page; swap in a
    // sorted index if paging CPU at DFZ scale ever bites.
    fn handle_query_routes_page(
        &mut self,
        scope: RouteQueryScope,
        filter: Option<&RouteQueryFilter>,
        after: Option<RouteQueryKey>,
        page_size: usize,
        reply: tokio::sync::oneshot::Sender<RoutePage>,
    ) {
        if reply.is_closed() {
            debug!("route page query canceled before scan; skipping");
            return;
        }
        let page = match scope {
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
                // A grouped member holds no per-peer unicast Adj-RIB-Out;
                // its advertised set is synthesized (group table − own-
                // sourced) — materialized by that synthesis, then paged
                // so the reply stays bounded either way.
                match self.grouped_advertised_routes(peer) {
                    Some(routes) => page_routes(routes.iter(), filter, after, page_size),
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
        };
        if reply.send(page).is_err() {
            warn!("query caller dropped before receiving response");
        }
    }

    fn handle_query_best_routes(
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
    fn handle_query_fib_install_candidates(
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

    fn handle_query_peer_groups(
        &mut self,
        reply: tokio::sync::oneshot::Sender<std::collections::HashMap<IpAddr, String>>,
    ) {
        if reply.send(self.peer_group.clone()).is_err() {
            warn!("query caller dropped before receiving peer-group map");
        }
    }

    fn handle_query_advertised_routes(
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

    fn handle_explain_advertised_route(
        &mut self,
        peer: IpAddr,
        prefix: Prefix,
        rd: Option<rustbgpd_wire::RouteDistinguisher>,
        reply: tokio::sync::oneshot::Sender<Option<ExplainAdvertisedRoute>>,
    ) {
        if !self.peer_sendable_families.contains_key(&peer) {
            let _ = reply.send(None);
            return;
        }
        let explanation = match rd {
            Some(rd) => self.explain_vpn_export(peer, prefix, rd),
            None => self.explain_unicast_export(peer, prefix),
        };
        if reply.send(Some(explanation)).is_err() {
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
    fn explain_unicast_export(&mut self, peer: IpAddr, prefix: Prefix) -> ExplainAdvertisedRoute {
        let family = prefix_family(&prefix);
        if self
            .peer_orf_pending
            .get(&peer)
            .is_some_and(|gated| gated.contains(&family))
        {
            return Self::orf_gated_explain(peer, prefix, None);
        }

        let sendable = self.peer_sendable_families.get(&peer);
        let llgr = self.peer_advertised_llgr_families.get(&peer);
        let orf = self
            .peer_orf_filters
            .get(&peer)
            .and_then(|filters| filters.get(&family));
        let target_is_ebgp = self.peer_is_ebgp.get(&peer).copied().unwrap_or(true);
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
            return Self::explain_single_best_prefix(
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
                target_is_rr_client,
                self.cluster_id,
                sendable,
                llgr,
                orf,
                add_path_send_max,
                self.export_policy_for(peer),
                orr_ctx,
                per_client_best,
            );
        }

        // Dry run of the live single-best staging body. A grouped
        // member's advertised state is the group table (update-groups
        // design §2: members hold no per-peer unicast Adj-RIB-Out).
        //
        // Limitation: the group table still holds routes this member
        // itself sourced, which split-horizon excludes from the live
        // emit but which the dry-run's `already_advertised` gate does
        // not filter. A member-scoped AdjRibOut view (`route.peer !=
        // peer`) is not synthesized here, so for a member's own-sourced
        // prefixes the dry-run may show them as already-advertised.
        let member_of = self.grouped_member_of(peer);
        let empty_rib_out;
        let rib_out = if let Some(group) = member_of.and_then(|gid| self.group_ribs.get(&gid)) {
            &group.table
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
        trace.into_explain(peer, prefix, None, member_of.map(|gid| gid as u64))
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
        let rib_out = if let Some(group) = vpn_grouped.and_then(|gid| self.group_ribs.get(&gid)) {
            &group.table
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
            target_is_rr_client,
            self.cluster_id,
            sendable,
            llgr,
            rtc_filter.as_ref(),
            orr_ctx,
            add_path_send_max,
            &add_path_send_families,
            self.export_policy_for(peer),
            &mut vpn_announce,
            &mut vpn_withdraw,
            false,
        );
        trace.into_explain(peer, prefix, Some(rd), vpn_grouped.map(|gid| gid as u64))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "best-path explain assembles route, policy, and attribution in one snapshot"
    )]
    fn handle_explain_best_path(
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
        // policy → top-N by best-path. Mirroring the contract is
        // deliberate — operators trust explain only if it produces
        // the same selection that distribution would, modulo state
        // changes between the two calls.
        let mut advertised: Vec<(IpAddr, u32)> = Vec::new();
        let mut add_path_send_max: u32 = 0;
        if let Some(peer_addr) = peer {
            let target_is_ebgp = self.peer_is_ebgp.get(&peer_addr).copied().unwrap_or(true);
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
                    if evaluate_chain(export_pol, &ctx).action != PolicyAction::Permit {
                        continue;
                    }
                    advertised.push((cand.peer, cand.path_id));
                    next_rank += 1;
                }
            }
        }

        // Build the advertised-rank index once (O(N) build, O(1)
        // lookup) so the per-candidate tagging below stays linear in
        // candidate count rather than quadratic. With Add-Path
        // peers commonly carrying tens of paths per prefix this is
        // a meaningful difference at scale.
        let advertised_rank: HashMap<(IpAddr, u32), u32> = advertised
            .iter()
            .enumerate()
            .filter_map(|(idx, key)| u32::try_from(idx + 1).ok().map(|rank| (*key, rank)))
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

    fn handle_subscribe_route_events(
        &mut self,
        reply: tokio::sync::oneshot::Sender<broadcast::Receiver<RouteEvent>>,
    ) {
        let rx = self.route_events_tx.subscribe();
        let _ = reply.send(rx);
    }

    fn publish_route_event(&mut self, mut event: RouteEvent) {
        event.event_id = self.next_route_event_id;
        if let Some(next) = self.next_route_event_id.checked_add(1) {
            self.next_route_event_id = next;
        } else if !self.route_event_id_exhausted {
            self.route_event_id_exhausted = true;
            warn!(
                event_id = self.next_route_event_id,
                "route event id space exhausted; publishing future route events with \
                 the saturated id instead of panicking"
            );
        }
        if self.route_event_history.len() == ROUTE_EVENT_HISTORY_CAPACITY {
            self.route_event_history.pop_front();
        }
        self.route_event_history.push_back(event.clone());
        self.metrics.set_route_event_history_depth(
            i64::try_from(self.route_event_history.len()).unwrap_or(i64::MAX),
        );
        // Hand a snapshot to the durable outbox sink BEFORE the
        // legacy broadcast send. The legacy broadcast consumes
        // `event`, so the sink call has to happen first; ADR-0072
        // explicitly does NOT claim "no-live-without-durable" for
        // the legacy live surface (`WatchEvents`, `WatchRoutes`),
        // only for the EHM-owned broadcast that backs
        // `SubscribeFromEvent`. The order at this site is therefore
        // not load-bearing for correctness; pick the order that
        // avoids the second clone (sink first, then move into
        // broadcast).
        self.event_sink.publish_route_event(&event);
        let _ = self.route_events_tx.send(event);
    }

    pub(super) fn update_policy_filtered_routes_for_prefixes(
        &mut self,
        target_peer: IpAddr,
        prefixes: &HashSet<Prefix>,
        current: &HashSet<PolicyFilteredRouteKey>,
    ) {
        let peer_routes = self.policy_filtered_routes.entry(target_peer).or_default();
        let previous = peer_routes
            .iter()
            .copied()
            .filter(|key| prefixes.contains(&key.prefix))
            .collect::<Vec<_>>();

        for key in previous {
            if !current.contains(&key) {
                peer_routes.remove(&key);
            }
        }

        let mut newly_filtered = Vec::new();
        for key in current.iter().copied() {
            if peer_routes.insert(key) {
                newly_filtered.push(key);
            }
        }

        if peer_routes.is_empty() {
            self.policy_filtered_routes.remove(&target_peer);
        }

        for key in newly_filtered {
            self.publish_route_event(RouteEvent {
                event_id: 0,
                event_type: RouteEventType::PolicyFiltered,
                prefix: key.prefix,
                peer: Some(key.source_peer),
                previous_peer: None,
                target_peer: Some(key.target_peer),
                timestamp: crate::event::unix_timestamp_now(),
                path_id: key.path_id,
                reason: "policy_denied".to_string(),
            });
        }
    }

    pub(super) fn clear_policy_filtered_routes_for_peer(&mut self, target_peer: IpAddr) {
        self.policy_filtered_routes.remove(&target_peer);
    }

    fn handle_query_route_event_history(
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

    fn handle_subscribe_evpn_route_events(
        &mut self,
        reply: tokio::sync::oneshot::Sender<broadcast::Receiver<crate::event::EvpnRouteEvent>>,
    ) {
        let rx = self.evpn_events_tx.subscribe();
        let _ = reply.send(rx);
    }

    fn publish_evpn_route_event(&mut self, event: crate::event::EvpnRouteEvent) {
        if self.evpn_route_event_history.len() == EVPN_ROUTE_EVENT_HISTORY_CAPACITY {
            self.evpn_route_event_history.pop_front();
        }
        self.evpn_route_event_history.push_back(event.clone());
        // ADR-0072: durable outbox sink fires alongside the legacy
        // broadcast. See `publish_route_event` for the ordering note.
        self.event_sink.publish_evpn_event(&event);
        let _ = self.evpn_events_tx.send(event);
    }

    fn handle_query_evpn_route_event_history(
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
            .filter(|event| rd.is_none_or(|rd| crate::event::evpn_key_rd(&event.key) == rd))
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

    fn handle_query_loc_rib_count(&mut self, reply: tokio::sync::oneshot::Sender<usize>) {
        let _ = reply.send(self.loc_rib.len());
    }

    fn handle_query_advertised_count(
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

    fn handle_query_adj_rib_out_counts(
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
            let update_groups::GroupMembership::Grouped(gid) = membership else {
                continue;
            };
            let Some(group) = self.group_ribs.get(gid) else {
                continue;
            };
            let synthesized = group.family_counts_for(peer);
            if synthesized.is_empty() {
                continue;
            }
            counts.entry(peer).or_default().extend(synthesized);
        }
        let _ = reply.send(counts);
    }

    fn handle_query_neighbor_policy_stats(
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

    /// Snapshot the live per-term hit counters of installed export
    /// chains (ADR-0096 Decision 3.3): one entry per peer with an
    /// installed chain, plus the shared global fallback instance for
    /// peers evaluated before any per-peer install. Read-only — no
    /// counter is touched.
    fn handle_query_export_policy_term_hits(
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

    fn handle_query_flowspec_routes(
        &mut self,
        reply: tokio::sync::oneshot::Sender<Vec<crate::route::FlowSpecRoute>>,
    ) {
        let routes: Vec<_> = self.loc_rib.iter_flowspec().cloned().collect();
        if reply.send(routes).is_err() {
            warn!("FlowSpec query caller dropped before receiving response");
        }
    }

    fn handle_bgpls_routes_received(
        &mut self,
        peer: IpAddr,
        announced: Vec<crate::route::BgpLsRibRoute>,
        withdrawn: Vec<crate::route::BgpLsRouteKey>,
    ) {
        let active_refresh = self
            .refresh_in_progress
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        let mut affected: HashSet<crate::route::BgpLsRouteKey> = HashSet::new();
        let mut removed_stale_counts: HashMap<(Afi, Safi), usize> = HashMap::new();
        let mut needs_intern_gc = false;

        {
            let rib = self.ribs.entry(peer).or_insert_with(|| AdjRibIn::new(peer));
            for key in withdrawn {
                let family = key.family.to_afi_safi();
                if rib.withdraw_bgpls(&key) {
                    needs_intern_gc = true;
                    affected.insert(key.clone());
                }
                if active_refresh.contains(&family)
                    && let Some(stale) = self.refresh_stale_bgpls.get_mut(&peer)
                    && stale.remove(&key)
                {
                    *removed_stale_counts.entry(family).or_default() += 1;
                }
            }

            for mut route in announced {
                let key = route.key();
                let family = route.family.to_afi_safi();
                self.attr_intern.intern(&mut route.attributes);
                needs_intern_gc |= rib.insert_bgpls(route);
                affected.insert(key.clone());
                if active_refresh.contains(&family)
                    && let Some(stale) = self.refresh_stale_bgpls.get_mut(&peer)
                    && stale.remove(&key)
                {
                    *removed_stale_counts.entry(family).or_default() += 1;
                }
            }
        }

        for ((afi, safi), count) in removed_stale_counts {
            self.decrement_refresh_stale_count(peer, afi, safi, count);
        }
        self.update_peer_refresh_metrics(peer);
        self.recompute_bgpls_keys(&affected);
        if !affected.is_empty() {
            if needs_intern_gc {
                self.attr_intern.gc();
            }
            self.sync_attr_intern_gauge();
        }
    }

    fn handle_vpn_routes_received(
        &mut self,
        peer: IpAddr,
        announced: Vec<crate::route::VpnRibRoute>,
        withdrawn: Vec<crate::route::VpnRibRouteKey>,
    ) {
        let active_refresh = self
            .refresh_in_progress
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        let mut affected: HashSet<crate::route::VpnRibRouteKey> = HashSet::new();
        let mut removed_stale_counts: HashMap<(Afi, Safi), usize> = HashMap::new();
        let mut needs_intern_gc = false;

        {
            let rib = self.ribs.entry(peer).or_insert_with(|| AdjRibIn::new(peer));
            for key in withdrawn {
                let family = key.afi_safi();
                if rib.withdraw_vpn(&key) {
                    needs_intern_gc = true;
                    affected.insert(key.clone());
                }
                if active_refresh.contains(&family)
                    && let Some(stale) = self.refresh_stale_vpn.get_mut(&peer)
                    && stale.remove(&key)
                {
                    *removed_stale_counts.entry(family).or_default() += 1;
                }
            }

            for mut route in announced {
                let key = route.key();
                let family = route.afi_safi();
                self.attr_intern.intern(&mut route.attributes);
                needs_intern_gc |= rib.insert_vpn(route);
                affected.insert(key.clone());
                if active_refresh.contains(&family)
                    && let Some(stale) = self.refresh_stale_vpn.get_mut(&peer)
                    && stale.remove(&key)
                {
                    *removed_stale_counts.entry(family).or_default() += 1;
                }
            }
        }

        for ((afi, safi), count) in removed_stale_counts {
            self.decrement_refresh_stale_count(peer, afi, safi, count);
        }
        self.update_peer_refresh_metrics(peer);
        self.recompute_vpn_keys(&affected);
        if !affected.is_empty() {
            if needs_intern_gc {
                self.attr_intern.gc();
            }
            self.sync_attr_intern_gauge();
        }
    }

    /// Recompute the Loc-RIB VPN selection for each affected key across the
    /// current set of peer Adj-RIB-Ins, then distribute the changes to
    /// eligible peers. Shared by the receive path, peer teardown, and the
    /// GR-entry conservative withdraw so a departed peer's routes fall back
    /// to the next-best candidate (or are withdrawn downstream), mirroring
    /// the unicast/FlowSpec/EVPN/BGP-LS recompute + distribution pattern.
    fn recompute_vpn_keys(&mut self, affected: &HashSet<crate::route::VpnRibRouteKey>) {
        self.recompute_and_distribute_vpn(affected);
    }

    fn handle_labeled_routes_received(
        &mut self,
        peer: IpAddr,
        announced: Vec<crate::route::LabeledRibRoute>,
        withdrawn: Vec<crate::route::LabeledRibRouteKey>,
    ) {
        let active_refresh = self
            .refresh_in_progress
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        let mut affected: HashSet<crate::route::LabeledRibRouteKey> = HashSet::new();
        let mut removed_stale_counts: HashMap<(Afi, Safi), usize> = HashMap::new();
        let mut needs_intern_gc = false;

        {
            let rib = self.ribs.entry(peer).or_insert_with(|| AdjRibIn::new(peer));
            for key in withdrawn {
                let family = key.afi_safi();
                if rib.withdraw_labeled(&key) {
                    needs_intern_gc = true;
                    affected.insert(key);
                }
                if active_refresh.contains(&family)
                    && let Some(stale) = self.refresh_stale_labeled.get_mut(&peer)
                    && stale.remove(&key)
                {
                    *removed_stale_counts.entry(family).or_default() += 1;
                }
            }

            for mut route in announced {
                let key = route.key();
                let family = route.afi_safi();
                self.attr_intern.intern(&mut route.attributes);
                needs_intern_gc |= rib.insert_labeled(route);
                affected.insert(key);
                if active_refresh.contains(&family)
                    && let Some(stale) = self.refresh_stale_labeled.get_mut(&peer)
                    && stale.remove(&key)
                {
                    *removed_stale_counts.entry(family).or_default() += 1;
                }
            }
        }

        for ((afi, safi), count) in removed_stale_counts {
            self.decrement_refresh_stale_count(peer, afi, safi, count);
        }
        self.update_peer_refresh_metrics(peer);
        self.recompute_labeled_keys(&affected);
        if !affected.is_empty() {
            if needs_intern_gc {
                self.attr_intern.gc();
            }
            self.sync_attr_intern_gauge();
        }
    }

    /// Recompute the Loc-RIB labeled selection for each affected key across
    /// the current set of peer Adj-RIB-Ins, then distribute the changes to
    /// eligible peers, mirroring [`Self::recompute_vpn_keys`].
    fn recompute_labeled_keys(&mut self, affected: &HashSet<crate::route::LabeledRibRouteKey>) {
        self.recompute_and_distribute_labeled(affected);
    }

    /// RT-Constrain ingest (RFC 4684). Mirrors the VPN receive path; after
    /// the Adj-RIB-In mutation the peer's RT membership is rebuilt so the
    /// VPNv4/VPNv6 Adj-RIB-Out restages under the new filter.
    fn handle_rtc_routes_received(
        &mut self,
        peer: IpAddr,
        announced: Vec<crate::route::RtcRibRoute>,
        withdrawn: Vec<crate::route::RtcRibRouteKey>,
    ) {
        let family = crate::route::RtcRibRouteKey::afi_safi();
        let active_refresh = self
            .refresh_in_progress
            .get(&peer)
            .is_some_and(|families| families.contains(&family));
        let mut affected: HashSet<crate::route::RtcRibRouteKey> = HashSet::new();
        let mut removed_stale = 0usize;
        let mut needs_intern_gc = false;

        {
            let rib = self.ribs.entry(peer).or_insert_with(|| AdjRibIn::new(peer));
            for key in withdrawn {
                if rib.withdraw_rtc(&key) {
                    needs_intern_gc = true;
                    affected.insert(key.clone());
                }
                if active_refresh
                    && let Some(stale) = self.refresh_stale_rtc.get_mut(&peer)
                    && stale.remove(&key)
                {
                    removed_stale += 1;
                }
            }
            for mut route in announced {
                let key = route.key();
                self.attr_intern.intern(&mut route.attributes);
                needs_intern_gc |= rib.insert_rtc(route);
                if active_refresh
                    && let Some(stale) = self.refresh_stale_rtc.get_mut(&peer)
                    && stale.remove(&key)
                {
                    removed_stale += 1;
                }
                affected.insert(key);
            }
        }

        self.decrement_refresh_stale_count(peer, family.0, family.1, removed_stale);
        self.update_peer_refresh_metrics(peer);
        self.recompute_rtc_keys(&affected);
        if !affected.is_empty() {
            if needs_intern_gc {
                self.attr_intern.gc();
            }
            self.sync_attr_intern_gauge();
        }
        self.rebuild_rtc_membership_and_restage_vpn(peer);
    }

    /// Rebuild `peer`'s RT-Constrain membership from its Adj-RIB-In (all
    /// paths) and route the result through [`Self::set_rt_membership`] —
    /// the corrective emit (grouped delta walk or per-peer restage) fires
    /// there iff the membership actually changed.
    fn rebuild_rtc_membership_and_restage_vpn(&mut self, peer: IpAddr) {
        let membership = self.rtc_membership_from_rib(peer);
        self.set_rt_membership(peer, Some(membership));
    }

    /// THE single Φ-write function (design §2.3 / risk 1): EVERY mutation
    /// of `peer_rt_membership` routes through here, so a membership
    /// change can never be split from its corrective emit. Sites:
    ///
    /// - `rebuild_rtc_membership_and_restage_vpn` (RTC routes received,
    ///   RFC 7313 stale sweeps, GR/LLGR sweeps) → `Some(derived)`;
    /// - `register_active_session` at `PeerUp` → `Some` (empty-strict,
    ///   or GR-re-derived) / `None` (family not negotiated) — both run
    ///   BEFORE the outbound registration, so no corrective emit fires
    ///   and the Φ-filtered initial-dump replay covers delivery;
    /// - `clear_outbound_peer_state` teardown → `None` (the outbound
    ///   registration is going away; nothing to correct).
    ///
    /// Corrective emit for a changed Φ on a live registration: a member
    /// of a VPN-staging group takes the membership-delta table walk
    /// (zero policy evals, table untouched — design §2.3); everyone else
    /// keeps the per-peer dirty restage (the Adj-RIB-Out equality
    /// machinery yields the RFC 4684 minimal update set, no session
    /// reset). An unchanged membership is a strict no-op.
    fn set_rt_membership(&mut self, peer: IpAddr, membership: Option<RtcMembership>) {
        // Removing Φ is valid only before outbound registration (a new
        // session that did not negotiate RTC) or after deregistration during
        // teardown. On a live registration it would silently change the peer
        // from RT-filtered to unfiltered without a corrective VPN emission.
        // Keep this before the equality early-return so an already-absent
        // entry cannot conceal an invalid live call.
        debug_assert!(
            membership.is_some() || !self.outbound_peers.contains_key(&peer),
            "RT membership may be cleared only before outbound registration or after deregistration"
        );
        // Capture BEFORE the write (design §2.3): under the invariant
        // adv(m) = Φ-filtered group table, `old` is the true prior
        // advertised state.
        let old = self.peer_rt_membership.get(&peer).cloned();
        if old == membership {
            return;
        }
        let Some(new) = membership else {
            self.peer_rt_membership.remove(&peer);
            return;
        };
        self.peer_rt_membership.insert(peer, new.clone());
        if !self.outbound_peers.contains_key(&peer) {
            return;
        }
        if let Some(gid) = self.vpn_grouped_member_of(peer) {
            // Absent prior membership on a live RTC registration
            // resolves to strict empty — the `rtc_vpn_filter` rule.
            let old = old.unwrap_or_default();
            self.apply_rtc_membership_delta_to_grouped_member(peer, gid, &old, &new);
        } else {
            self.mark_outbound_dirty(peer);
            self.distribute_changes(&HashSet::new(), &HashSet::new());
        }
    }

    /// Derive `peer`'s RT-Constrain membership from its Adj-RIB-In (all
    /// paths, stale included — GR-preserved interest keeps filtering VPN
    /// advertisements through the restart window). Shared by the rebuild
    /// seam above and the GR re-establish path in
    /// `register_active_session`.
    fn rtc_membership_from_rib(&self, peer: IpAddr) -> RtcMembership {
        let mut has_default = false;
        let mut entries: Vec<rustbgpd_wire::RtcNlri> = Vec::new();
        if let Some(rib) = self.ribs.get(&peer) {
            for route in rib.iter_rtc() {
                if route.nlri.is_default() {
                    has_default = true;
                } else {
                    entries.push(route.nlri);
                }
            }
        }
        entries.sort_unstable();
        entries.dedup();
        RtcMembership {
            has_default,
            entries,
        }
    }

    /// Recompute the Loc-RIB RT-Constrain selection for each affected key
    /// and distribute the changes, mirroring [`Self::recompute_vpn_keys`].
    fn recompute_rtc_keys(&mut self, affected: &HashSet<crate::route::RtcRibRouteKey>) {
        self.recompute_and_distribute_rtc(affected);
    }

    /// Recompute the Loc-RIB BGP-LS selection for each affected key across the
    /// current set of peer Adj-RIB-Ins.
    ///
    /// Shared by the receive path and the peer-teardown cleanup so a departed
    /// peer's routes fall back to the next-best remaining candidate (or are
    /// removed when no peer still advertises the key), mirroring the
    /// unicast/FlowSpec/EVPN recompute + distribution pattern.
    fn recompute_bgpls_keys(&mut self, affected: &HashSet<crate::route::BgpLsRouteKey>) {
        self.recompute_and_distribute_bgpls(affected);
        // An empty affected set means no BGP-LS route actually changed
        // (e.g. a withdraw of a key not held, or an empty batch), so the
        // Adj-RIB-In topology union is byte-identical and the SPF surface
        // cannot have moved — skip the topology rebuild + per-vantage SPF
        // (LAN-189). Vantage-config changes take the direct
        // `recompute_orr()` path in peer_lifecycle, not this seam, so
        // they are unaffected by this guard.
        if affected.is_empty() {
            return;
        }
        // Every BGP-LS mutation seam routes through here — receive
        // (`handle_bgpls_routes_received`), the enhanced-refresh EoRR
        // sweep (`finish_route_refresh`), the GR entry sweep
        // (`handle_peer_graceful_restart`, recompute-then-GC ordering),
        // and BGP-LS-bearing peer teardown (`clear_peer_adj_rib_in`) —
        // so the ORR cache rebuild needs exactly one call site.
        let changed = self.recompute_orr();
        self.resync_orr_bound_peers(&changed);
    }

    /// Resync every established peer bound to a changed ORR vantage: a
    /// changed SPF surface (metric shift, vantage resolution flip) can
    /// move those peers' per-vantage bests without any unicast RIB
    /// change, so nothing else would re-stage them. Dirty + empty-set
    /// `distribute_changes` is the `ReplacePeerExportPolicy` precedent —
    /// the Adj-RIB-Out equality machinery reduces the full restage to
    /// the minimal announce/withdraw delta per peer (unaffected peers
    /// see zero messages).
    fn resync_orr_bound_peers(&mut self, changed: &HashSet<IpAddr>) {
        if changed.is_empty() {
            return;
        }
        let bound: Vec<IpAddr> = self
            .peer_orr_vantage
            .iter()
            .filter(|(peer, vantage)| {
                changed.contains(*vantage) && self.outbound_peers.contains_key(*peer)
            })
            .map(|(peer, _)| *peer)
            .collect();
        if bound.is_empty() {
            return;
        }
        // Preserve the single dirty-marking seam: ORR currently disqualifies
        // grouping, but routing through the helper also marks group state if
        // that eligibility rule changes later.
        for peer in bound {
            self.mark_outbound_dirty(peer);
        }
        self.distribute_changes(&HashSet::new(), &HashSet::new());
    }

    /// Rebuild the cached RFC 9107 ORR state: one topology from the
    /// BGP-LS Adj-RIB-In union, one SPF per DISTINCT configured vantage
    /// IP. Returns the vantages whose SPF distance surface changed
    /// (consumed by [`Self::resync_orr_bound_peers`] to dirty their
    /// bound peers). Early-outs with no
    /// topology build and no SPF while `peer_orr_vantage` is empty, so
    /// non-ORR deployments pay nothing on BGP-LS churn.
    pub(super) fn recompute_orr(&mut self) -> HashSet<IpAddr> {
        if self.peer_orr_vantage.is_empty() {
            if !self.orr.is_empty() {
                self.orr = crate::orr::OrrState::default();
                self.metrics.set_orr_topology_nodes(0);
                self.metrics.set_orr_topology_links(0);
                self.metrics.set_orr_unresolved_vantages(0);
            }
            return HashSet::new();
        }

        let topology = crate::orr::OrrTopology::build(
            self.ribs
                .values()
                .flat_map(crate::adj_rib_in::AdjRibIn::iter_bgpls),
        );
        let vantages: HashSet<IpAddr> = self.peer_orr_vantage.values().copied().collect();
        let mut changed = HashSet::new();
        let mut spf = HashMap::new();
        let mut resolved = HashMap::new();
        let mut signatures = HashMap::new();
        for vantage in vantages {
            let node = topology.resolve_node(vantage);
            let was_resolved = self.orr.resolved.get(&vantage).copied();
            // Log once per transition (a fresh vantage counts as one).
            match (was_resolved, node.is_some()) {
                (Some(true) | None, false) => warn!(
                    %vantage,
                    "ORR vantage does not resolve to a BGP-LS topology node — \
                     bound peers fall back to the standard best path"
                ),
                (Some(false) | None, true) => {
                    info!(%vantage, "ORR vantage resolved to a BGP-LS topology node");
                }
                (Some(true), true) | (Some(false), false) => {}
            }
            resolved.insert(vantage, node.is_some());
            if let Some(node) = node {
                let result = topology.spf(node);
                self.metrics.record_orr_spf_run();
                let signature = topology.spf_signature(&result);
                if self.orr.signatures.get(&vantage) != Some(&signature) {
                    changed.insert(vantage);
                }
                spf.insert(vantage, result);
                signatures.insert(vantage, signature);
            } else if self.orr.spf.contains_key(&vantage) {
                // Resolved → unresolved is a change too: bound peers
                // revert to the standard best path (PR-4).
                changed.insert(vantage);
            }
        }

        let unresolved = resolved.values().filter(|resolved| !**resolved).count();
        self.metrics
            .set_orr_topology_nodes(i64::try_from(topology.node_count()).unwrap_or(i64::MAX));
        self.metrics
            .set_orr_topology_links(i64::try_from(topology.link_count()).unwrap_or(i64::MAX));
        self.metrics
            .set_orr_unresolved_vantages(i64::try_from(unresolved).unwrap_or(i64::MAX));
        self.orr = crate::orr::OrrState {
            topology,
            spf,
            resolved,
            signatures,
        };
        changed
    }

    /// Serve `QueryOrrStatus`: per-vantage resolution/SPF/bound-peer
    /// status plus topology totals, from the cached `OrrState` (fresh by
    /// construction while any vantage is configured; empty otherwise).
    fn handle_query_orr_status(
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
        });
    }

    fn handle_query_mrt_snapshot(&mut self, reply: tokio::sync::oneshot::Sender<MrtSnapshotData>) {
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

        let snapshot = MrtSnapshotData {
            peers,
            routes,
            evpn_routes,
        };
        if reply.send(snapshot).is_err() {
            warn!("MRT snapshot query caller dropped before receiving response");
        }
    }

    /// Run the RIB manager event loop until the channel is closed.
    ///
    /// When dirty peers exist (from failed outbound sends), a persistent
    /// resync timer fires to retry distribution independently of both
    /// incoming mutations and non-mutating query traffic. The timer is
    /// started when `dirty_peers` transitions from empty to non-empty and
    /// reset after each retry tick; it is not recreated per loop iteration,
    /// so incoming messages cannot starve it.
    #[expect(
        clippy::too_many_lines,
        reason = "event loop with timer arms and query draining"
    )]
    pub async fn run(mut self) {
        // Persistent timer: starts far in the future (disabled). Reset to
        // DIRTY_RESYNC_INTERVAL when dirty_peers becomes non-empty.
        let resync_sleep = tokio::time::sleep(DIRTY_RESYNC_INTERVAL);
        tokio::pin!(resync_sleep);
        let mut resync_armed = false;
        let mut query_rx_open = true;

        // GR stale sweep timer — reset each iteration to the nearest deadline.
        let gr_sleep = tokio::time::sleep(std::time::Duration::from_hours(24));
        tokio::pin!(gr_sleep);

        // LLGR stale sweep timer — reset each iteration to the nearest deadline.
        let llgr_sleep = tokio::time::sleep(std::time::Duration::from_hours(24));
        tokio::pin!(llgr_sleep);

        // Enhanced route refresh timer — reset each iteration to the nearest
        // active refresh deadline.
        let refresh_sleep = tokio::time::sleep(std::time::Duration::from_hours(24));
        tokio::pin!(refresh_sleep);

        loop {
            // Sample ingest-channel depth once per iteration — a gauge
            // pegged at the channel capacity on scrape means producers
            // (sessions, local originators) are parked on backpressure.
            self.metrics
                .set_rib_ingest_channel_depth(i64::try_from(self.rx.len()).unwrap_or(i64::MAX));

            // Arm the resync timer when dirty_peers transitions empty → non-empty.
            if !self.dirty_peers.is_empty() && !resync_armed {
                resync_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + DIRTY_RESYNC_INTERVAL);
                resync_armed = true;
            }

            // Arm the GR timer to the nearest stale deadline.
            let has_gr_timers = if let Some(deadline) = self.next_gr_deadline() {
                gr_sleep.as_mut().reset(deadline);
                true
            } else {
                false
            };

            // Arm the LLGR timer to the nearest stale deadline.
            let has_llgr_timers = if let Some(deadline) = self.next_llgr_deadline() {
                llgr_sleep.as_mut().reset(deadline);
                true
            } else {
                false
            };

            let has_refresh_timers = if let Some(deadline) = self.next_refresh_deadline() {
                refresh_sleep.as_mut().reset(deadline);
                true
            } else {
                false
            };

            let needs_timers =
                resync_armed || has_gr_timers || has_llgr_timers || has_refresh_timers;

            if query_rx_open && self.query_rx.is_closed() {
                query_rx_open = false;
            }

            let now = tokio::time::Instant::now();
            if resync_armed && resync_sleep.deadline() <= now {
                debug!(
                    count = self.dirty_peers.len(),
                    "resync timer fired for dirty peers"
                );
                self.distribute_changes(&HashSet::new(), &HashSet::new());
                if self.dirty_peers.is_empty() {
                    self.metrics.record_rib_dirty_resync("cleared");
                    resync_armed = false;
                } else {
                    self.metrics.record_rib_dirty_resync("still_dirty");
                    resync_sleep
                        .as_mut()
                        .reset(tokio::time::Instant::now() + DIRTY_RESYNC_INTERVAL);
                }
                continue;
            }
            if has_gr_timers && gr_sleep.deadline() <= now {
                if self.drain_ready_updates() {
                    continue;
                }
                let expired: Vec<IpAddr> = self
                    .gr_stale_deadlines
                    .iter()
                    .filter(|&(_, &deadline)| deadline <= now)
                    .map(|(&peer, _)| peer)
                    .collect();
                for peer in expired {
                    self.sweep_gr_stale(peer);
                }
                continue;
            }
            if has_llgr_timers && llgr_sleep.deadline() <= now {
                if self.drain_ready_updates() {
                    continue;
                }
                self.sweep_expired_llgr_stale();
                continue;
            }
            if has_refresh_timers && refresh_sleep.deadline() <= now {
                if self.drain_ready_updates() {
                    continue;
                }
                self.expire_refresh_windows();
                continue;
            }

            if self.process_next_route_chunk() {
                self.drain_queries(QUERY_BUDGET_PER_CHUNK);
                tokio::task::yield_now().await;
            } else if needs_timers {
                tokio::select! {
                    query = self.query_rx.recv(), if query_rx_open => {
                        match query {
                            Some(q) => self.handle_update(q),
                            None => query_rx_open = false,
                        }
                    }
                    update = self.rx.recv() => {
                        match update {
                            Some(update) => {
                                self.maybe_stall_test_ingest(&update).await;
                                self.handle_update(update);
                                self.drain_queries(QUERY_BUDGET_PER_CHUNK);
                            }
                            None => break,
                        }
                    }
                    () = resync_sleep.as_mut(), if resync_armed => {
                        debug!(
                            count = self.dirty_peers.len(),
                            "resync timer fired for dirty peers"
                        );
                        self.distribute_changes(&HashSet::new(), &HashSet::new());

                        // Reset for next tick if still dirty, otherwise disarm.
                        if self.dirty_peers.is_empty() {
                            self.metrics.record_rib_dirty_resync("cleared");
                            resync_armed = false;
                        } else {
                            self.metrics.record_rib_dirty_resync("still_dirty");
                            resync_sleep.as_mut().reset(
                                tokio::time::Instant::now() + DIRTY_RESYNC_INTERVAL,
                            );
                        }
                    }
                    () = gr_sleep.as_mut(), if has_gr_timers => {
                        if self.drain_ready_updates() {
                            continue;
                        }
                        // Find all peers whose GR deadline has expired
                        let now = tokio::time::Instant::now();
                        let expired: Vec<IpAddr> = self
                            .gr_stale_deadlines
                            .iter()
                            .filter(|&(_, &deadline)| deadline <= now)
                            .map(|(&peer, _)| peer)
                            .collect();
                        for peer in expired {
                            self.sweep_gr_stale(peer);
                        }
                    }
                    () = llgr_sleep.as_mut(), if has_llgr_timers => {
                        if self.drain_ready_updates() {
                            continue;
                        }
                        self.sweep_expired_llgr_stale();
                    }
                    () = refresh_sleep.as_mut(), if has_refresh_timers => {
                        if self.drain_ready_updates() {
                            continue;
                        }
                        self.expire_refresh_windows();
                    }
                }
            } else {
                // No timers needed — wait for a route update or query.
                tokio::select! {
                    query = self.query_rx.recv(), if query_rx_open => {
                        match query {
                            Some(q) => self.handle_update(q),
                            None => query_rx_open = false,
                        }
                    }
                    update = self.rx.recv() => {
                        match update {
                            Some(update) => {
                                self.maybe_stall_test_ingest(&update).await;
                                self.handle_update(update);
                                self.drain_queries(QUERY_BUDGET_PER_CHUNK);
                            }
                            None => break,
                        }
                    }
                }
            }

            // Disarm if dirty_peers was cleared by a message handler (e.g. PeerDown).
            if self.dirty_peers.is_empty() {
                resync_armed = false;
            }
        }

        debug!("rib manager shutting down");
    }
}
