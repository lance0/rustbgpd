#[cfg(feature = "bench-internals")]
mod bench_support;
mod distribution;
mod graceful_restart;
mod helpers;
mod peer_lifecycle;
mod route_refresh;

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
    NeighborPolicyStats, OutboundRouteUpdate, RibUpdate,
};

use helpers::{DIRTY_RESYNC_INTERVAL, LlgrPeerConfig, prefix_family};

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
    /// Deadlines for sweeping LLGR-stale routes per peer.
    llgr_stale_deadlines: HashMap<IpAddr, tokio::time::Instant>,
    /// Configured per-peer LLGR parameters, stored on `PeerGracefulRestart`.
    llgr_peer_config: HashMap<IpAddr, LlgrPeerConfig>,
    /// Maximum Add-Path paths per prefix per peer (0 = single-best only).
    peer_add_path_send_max: HashMap<IpAddr, u32>,
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
    add_path_send_families: Vec<(Afi, Safi)>,
    add_path_send_max: u32,
    negotiated_orf_recv: Vec<(Afi, Safi)>,
    negotiated_llgr_families: Vec<(Afi, Safi)>,
}

const ROUTES_RECEIVED_CHUNK_SIZE: usize = 1024;
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
            refresh_stale_rtc: HashMap::new(),
            refresh_stale_counts: HashMap::new(),
            gr_peers: HashMap::new(),
            gr_stale_deadlines: HashMap::new(),
            gr_stale_routes_time: HashMap::new(),
            llgr_peers: HashMap::new(),
            llgr_stale_deadlines: HashMap::new(),
            llgr_peer_config: HashMap::new(),
            peer_add_path_send_max: HashMap::new(),
            peer_add_path_send_families: HashMap::new(),
            peer_orf_filters: HashMap::new(),
            peer_rt_membership: HashMap::new(),
            peer_orf_pending: HashMap::new(),
            gr_deferred_eor: HashMap::new(),
            peer_asn: HashMap::new(),
            peer_group: HashMap::new(),
            peer_bgp_id: HashMap::new(),
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
                add_path_send_families,
                add_path_send_max,
                negotiated_orf_recv,
                negotiated_llgr_families,
            ),
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
                reply,
            } => self.handle_explain_advertised_route(peer, prefix, reply),
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
            RibUpdate::QueryAdvertisedCount { peer, reply } => {
                self.handle_query_advertised_count(peer, reply);
            }
            RibUpdate::QueryNeighborPolicyStats { peer, reply } => {
                self.handle_query_neighbor_policy_stats(peer, reply);
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
        }
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
        let routes: Vec<_> = self
            .adj_ribs_out
            .get(&peer)
            .map(|rib| rib.iter().cloned().collect())
            .unwrap_or_default();

        if reply.send(routes).is_err() {
            warn!("query caller dropped before receiving response");
        }
    }

    fn handle_explain_advertised_route(
        &mut self,
        peer: IpAddr,
        prefix: Prefix,
        reply: tokio::sync::oneshot::Sender<Option<ExplainAdvertisedRoute>>,
    ) {
        let Some(sendable) = self.peer_sendable_families.get(&peer) else {
            let _ = reply.send(None);
            return;
        };

        // Same resolved-vantage gate as live distribution: an ORR peer
        // whose vantage did not resolve falls back to the standard
        // Loc-RIB-best explain, exactly like `flush_pending_distribution`.
        let orr_ctx = self.peer_orr_vantage.get(&peer).and_then(|vantage| {
            self.orr
                .spf
                .get(vantage)
                .map(|spf| (&self.orr.topology, spf, *vantage))
        });

        let explanation = Self::explain_single_best_prefix(
            &self.loc_rib,
            &self.ribs,
            &self.peer_is_rr_client,
            prefix,
            peer,
            self.peer_asn.get(&peer).copied(),
            self.peer_group.get(&peer).map(String::as_str),
            self.peer_is_ebgp.get(&peer).copied().unwrap_or(true),
            self.peer_is_rr_client.get(&peer).copied().unwrap_or(false),
            self.cluster_id,
            Some(sendable),
            self.export_policy_for(peer),
            orr_ctx,
        );

        if reply.send(Some(explanation)).is_err() {
            warn!("query caller dropped before receiving response");
        }
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
                    let ctx = RouteContext {
                        prefix: Some(prefix),
                        next_hop: Some(cand.next_hop),
                        extended_communities: cand.extended_communities(),
                        communities: cand.communities(),
                        large_communities: cand.large_communities(),
                        as_path_str: &aspath_str,
                        as_path_len: aspath_len,
                        validation_state: cand.validation_state,
                        aspa_state: cand.aspa_state,
                        peer_address: Some(peer_addr),
                        peer_asn: target_peer_asn,
                        peer_group: target_peer_group,
                        route_type: Some(route_type_for(cand.origin_type)),
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
        let count = self.adj_ribs_out.get(&peer).map_or(0, AdjRibOut::len);
        let _ = reply.send(count);
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

            for route in announced {
                let key = route.key();
                let family = route.family.to_afi_safi();
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
        if needs_intern_gc && let Some(rib) = self.ribs.get_mut(&peer) {
            rib.gc_intern_table();
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

            for route in announced {
                let key = route.key();
                let family = route.afi_safi();
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
        if needs_intern_gc && let Some(rib) = self.ribs.get_mut(&peer) {
            rib.gc_intern_table();
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
            for route in announced {
                let key = route.key();
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
        if needs_intern_gc && let Some(rib) = self.ribs.get_mut(&peer) {
            rib.gc_intern_table();
        }
        self.rebuild_rtc_membership_and_restage_vpn(peer);
    }

    /// Rebuild `peer`'s RT-Constrain membership from its Adj-RIB-In (all
    /// paths) and, when it changed, mark the peer dirty and run a resync so
    /// the VPN Adj-RIB-Out restages under the new filter (the
    /// `handle_replace_peer_export_policy` precedent — the Adj-RIB-Out
    /// equality machinery yields the RFC 4684 minimal update set, no
    /// session reset). An unchanged membership skips the restage entirely.
    fn rebuild_rtc_membership_and_restage_vpn(&mut self, peer: IpAddr) {
        let membership = self.rtc_membership_from_rib(peer);
        if self.peer_rt_membership.get(&peer) == Some(&membership) {
            return;
        }
        self.peer_rt_membership.insert(peer, membership);
        if self.outbound_peers.contains_key(&peer) {
            self.dirty_peers.insert(peer);
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
        self.dirty_peers.extend(bound);
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
                let expired: Vec<IpAddr> = self
                    .llgr_stale_deadlines
                    .iter()
                    .filter(|&(_, &deadline)| deadline <= now)
                    .map(|(&peer, _)| peer)
                    .collect();
                for peer in expired {
                    self.sweep_llgr_stale(peer);
                }
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
                        // Find all peers whose LLGR deadline has expired
                        let now = tokio::time::Instant::now();
                        let expired: Vec<IpAddr> = self
                            .llgr_stale_deadlines
                            .iter()
                            .filter(|&(_, &deadline)| deadline <= now)
                            .map(|(&peer, _)| peer)
                            .collect();
                        for peer in expired {
                            self.sweep_llgr_stale(peer);
                        }
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
