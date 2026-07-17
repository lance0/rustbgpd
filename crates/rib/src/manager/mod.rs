#[cfg(feature = "bench-internals")]
mod bench_support;
#[cfg(feature = "bench-internals")]
pub use bench_support::PolicyTransitionBenchReceipt;
mod distribution;
mod graceful_restart;
mod helpers;
mod peer_lifecycle;
mod route_refresh;
mod selection_deferral;
mod update_groups;

#[cfg(test)]
mod tests;

#[cfg(test)]
use crate::ERR_REFRESH_TIMEOUT;

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use rustbgpd_policy::PolicyChain;
use rustbgpd_rpki::VrpTable;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Afi, BgpRole, Prefix, Safi};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info, warn};

use crate::adj_rib_in::AdjRibIn;
use crate::adj_rib_out::AdjRibOut;
use crate::best_path::best_path_cmp_with_reason;
use crate::event::{RouteEvent, RouteEventType};
use crate::loc_rib::LocRib;
use crate::update::{
    BestPathCandidate, ExactExportEncoder, ExactExportKey, ExplainAdvertisedRoute, ExplainBestPath,
    MrtPeerEntry, MrtSnapshotData, NeighborPolicyStats, OutboundRouteUpdate, RibReadinessError,
    RibReadinessQuery, RibUpdate, RoutePage, RoutePageError, RoutePageVersion, RouteQueryFilter,
    RouteQueryKey, RouteQueryScope, WarmMrtSnapshotBudget, WarmMrtSnapshotView, route_query_key,
};

use helpers::{
    DIRTY_RESYNC_INTERVAL, LlgrPeerConfig, gauge_val, prefix_family, unicast_route_family,
};
pub use selection_deferral::{SelectionDeferralConfig, SelectionDeferralWaiterConfig};

#[cfg(any(test, feature = "bench-internals"))]
#[derive(Clone, Copy, Debug, Default)]
struct PolicyTransitionStats {
    plan_builds: usize,
    full_exact_probes: usize,
    route_shell_materializations: usize,
    actor_polls: usize,
    max_actor_slice: std::time::Duration,
    max_prefix_snapshot_poll: std::time::Duration,
    max_finalize_poll: std::time::Duration,
    max_commit_poll: std::time::Duration,
    #[cfg(feature = "bench-internals")]
    authoritative_peer_applies: usize,
    #[cfg(feature = "bench-internals")]
    max_authoritative_peer_apply: std::time::Duration,
}

#[cfg(test)]
struct PermissiveTestExactExport;

#[cfg(test)]
impl crate::update::ExactExportSnapshot for PermissiveTestExactExport {
    fn owner_id(&self) -> u64 {
        0
    }

    fn generation(&self) -> u64 {
        0
    }

    fn probe_announcement(
        &self,
        _candidate: crate::update::ExactExportCandidate<'_>,
    ) -> Result<crate::update::ExactExportResult, crate::update::ExactExportError> {
        Ok(crate::update::ExactExportResult {
            encoded_len: 0,
            max_len: usize::MAX,
            generation: 0,
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
impl ExactExportEncoder for PermissiveTestExactExport {
    fn owner_id(&self) -> u64 {
        0
    }

    fn snapshot(&self) -> Arc<dyn crate::update::ExactExportSnapshot> {
        Arc::new(Self)
    }
}

#[cfg(test)]
fn permissive_test_exact_export_encoder() -> Arc<dyn ExactExportEncoder> {
    Arc::new(PermissiveTestExactExport)
}

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
use helpers::{LOCAL_PEER, validate_route_rpki};

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
    /// Session-stamped local role staged before `PeerUp`, so the initial
    /// Adj-RIB-Out build can enforce RFC 9234 OTC egress rules.
    pending_peer_export_context: HashMap<(IpAddr, u64), Option<BgpRole>>,
    /// Session-stamped exact encoder staged immediately before `PeerUp`.
    /// Keeping the handle separate from the legacy registration payload
    /// avoids making every non-transport `PeerUp` producer construct a fake
    /// wire encoder while still fencing collision losers by session id.
    pending_peer_export_encoders: HashMap<(IpAddr, u64), Arc<dyn ExactExportEncoder>>,
    /// Session-stamped peer GR capability context staged immediately before
    /// `PeerUp`, used only by the process-start RFC 4724 selection gate.
    pending_peer_gr_context: HashMap<(IpAddr, u64), PeerSelectionDeferralContext>,
    /// Exact encoder owned by the active outbound registration. Every
    /// precommit pass captures one immutable snapshot from this handle and
    /// attaches that same snapshot to the outbound envelope.
    peer_export_encoders: HashMap<IpAddr, Arc<dyn ExactExportEncoder>>,
    /// Sparse per-peer identities rejected by exact wire preparation. For
    /// update-group members this is the member-local overlay over the shared
    /// group table; for private peers it suppresses repeated diagnostics and
    /// withdrawals for routes that were never advertised.
    peer_unexportable: HashMap<IpAddr, HashSet<ExactExportKey>>,
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
    /// Local RFC 9234 role for the active outbound registration.
    peer_local_roles: HashMap<IpAddr, Option<BgpRole>>,
    /// OTC rejections waiting to ride the next reserved outbound envelope to
    /// transport's existing metric/event publisher.
    pending_otc_blocked: HashMap<IpAddr, HashMap<(Prefix, u32), crate::route::Route>>,
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
    /// Ordered (`BTreeSet`) so the resync tick can round-robin fairly via
    /// [`Self::dirty_resync_cursor`] instead of re-drawing an arbitrary
    /// subset each tick.
    dirty_peers: BTreeSet<IpAddr>,
    /// Ring position of the dirty-resync round-robin: the last peer
    /// attempted. Selection resumes strictly after it (wrapping), so peers
    /// whose sends keep failing cannot monopolize every tick while
    /// drainable peers starve.
    dirty_resync_cursor: Option<IpAddr>,
    /// Wall-clock budget one actor poll may spend flushing paced work —
    /// commit-kind transition polls and dirty-resync ticks — before parking
    /// for the readiness seam. A unit of paced work is cheap-to-moderate,
    /// but ~10 ms of interleaved actor work elapses between polls, so a
    /// fixed per-poll item count makes throughput scale inversely with
    /// fleet size (measured ~0.88 s of emission stagger at 700 members).
    /// Tests override this to force deterministic per-stride parking.
    flush_poll_budget: std::time::Duration,
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
    refresh_stale_flowspec: HashMap<IpAddr, HashSet<crate::route::FlowSpecRouteKey>>,
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
    /// Peers with RFC 1997 `NO_EXPORT`/`NO_EXPORT_SUBCONFED` egress
    /// enforcement enabled (config `interpret_rfc1997`, default
    /// `!route_server_client`). Source routes carrying either community
    /// are suppressed at staging toward these peers when they are eBGP.
    peer_interpret_rfc1997: HashSet<IpAddr>,
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
    /// Peers currently isolated from shared update-groups because their
    /// transport flagged them slow (LAN-470, `slow_peer_isolation`).
    /// Membership recomputes classify these as
    /// `GroupMembership::SlowPeer` (per-peer fallback path). Per-session
    /// state: cleared on session teardown like the ORF gate above.
    slow_isolated_peers: HashSet<IpAddr>,
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
    /// Process-start RFC 4724 route-selection gates. `None` on cold starts.
    selection_deferral: Option<selection_deferral::SelectionDeferral>,
    /// Route identities touched while their family's Loc-RIB was frozen.
    /// Includes withdrawals so restored rows absent from Adj-RIB-In are
    /// still removed when the gate releases.
    deferred_selection_keys: selection_deferral::DeferredSelectionKeys,
    /// Route-refresh responses received while family convergence and `EoR`
    /// remain held. Replayed after the convergence `EoR` is queued.
    selection_deferred_refresh: HashMap<IpAddr, HashSet<(Afi, Safi)>>,
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
    /// Dedicated type-narrow lane used only by core readiness.
    readiness_rx: Option<mpsc::Receiver<RibReadinessQuery>>,
    /// Large route batches that are being processed in chunks.
    pending_route_batches: VecDeque<PendingRoutesReceived>,
    /// One explicit shared policy transition advanced by the actor itself.
    /// While present, only the dedicated type-narrow readiness lane may
    /// interleave; general queries, primary mutations, and timers remain
    /// ordered behind the final commit or fail-closed fallback handoff.
    pending_clean_policy_transition: Option<distribution::PendingCleanPolicyTransition>,
    /// In-progress unfenced staging of a prospective clean-transition
    /// destination group (`RibUpdate::PrepareExportPolicyDestination`).
    /// Advanced one budgeted slice at a time only when no ordinary
    /// mutation traffic is queued — churn keeps flowing, and keeps the
    /// staged table current, while this walk covers the snapshot.
    pending_destination_prestage: Option<distribution::DestinationPrestage>,
    /// The exact group id a COMPLETED prestage staged, recorded so every
    /// discard removes the group that was actually built (never a
    /// re-derivation from current attributes, which can drift) and so a
    /// committing cohort that resolves a different destination discards
    /// the unadopted group instead of leaking it.
    prepared_destination: Option<usize>,
    /// Withdrawn NLRI identities accumulated across the currently-draining
    /// batch. Retired only after distribution so the exact overlay can
    /// suppress any rejected-only wire withdrawal first.
    pending_exact_export_withdrawals: HashSet<ExactExportKey>,
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
    /// Process-local mutation versions bound into opaque route-page tokens.
    /// A successful continuation must match the requested scope's current
    /// version; no server-side snapshots are retained.
    route_page_received_version: Option<RoutePageVersion>,
    route_page_best_version: Option<RoutePageVersion>,
    route_page_advertised_version: Option<RoutePageVersion>,
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
    #[cfg(test)]
    test_force_exact_export_slow_path: bool,
    #[cfg(test)]
    test_exact_export_fast_path_hits: u64,
    /// Test/benchmark-only evidence for the explicit clean policy transition.
    #[cfg(any(test, feature = "bench-internals"))]
    policy_transition_stats: PolicyTransitionStats,
}

/// Bound on `live_sessions` entries per peer address. The RFC 4271 §6.8
/// collision window realistically holds two concurrent sessions (one per
/// connection direction); the bound only guards against a pathological
/// emitter. When exceeded, the OLDEST (most-superseded) record is dropped
/// — its eventual `PeerDown` is then discarded as stale.
const MAX_LIVE_SESSIONS_PER_PEER: usize = 2;

/// A transition exceeding the former cohort wait budget is still allowed to
/// complete, but deserves an operator-visible warning and metric investigation.
const SLOW_POLICY_TRANSITION: std::time::Duration = std::time::Duration::from_secs(5);

/// Readiness stays live during bounded transition progress, but fails closed
/// once ownership is far beyond any legitimate transition receipt.
const MAX_HEALTHY_POLICY_TRANSITION_AGE: std::time::Duration = std::time::Duration::from_secs(30);

/// Registration material for one live transport session of a peer
/// address, captured at `PeerUp`. Held in `RibManager::live_sessions` so
/// an outbound-registration failover can re-register a surviving session
/// (channel + negotiated metadata + initial table dump) after the active
/// session goes down during the collision window.
#[expect(
    clippy::struct_excessive_bools,
    reason = "mirrors the independent PeerUp registration booleans"
)]
pub(super) struct LiveSessionRecord {
    session_id: u64,
    outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
    peer_asn: u32,
    peer_router_id: Ipv4Addr,
    export_policy: Option<PolicyChain>,
    sendable_families: Vec<(Afi, Safi)>,
    is_ebgp: bool,
    route_reflector_client: bool,
    local_role: Option<BgpRole>,
    orr_vantage: Option<IpAddr>,
    per_client_best: bool,
    interpret_rfc1997: bool,
    add_path_send_families: Vec<(Afi, Safi)>,
    add_path_send_max: u32,
    /// Per-family Paths-Limit caps (RFC-draft Paths-Limit), filtered to the
    /// negotiated send families. Empty at `PeerUp`; the session emits its
    /// `PeerAddPathLimits` exactly once, and the handler mirrors the accepted
    /// map here so a collision failback replays it instead of clamping every
    /// family back to the scalar `add_path_send_max`.
    add_path_send_limits: HashMap<(Afi, Safi), u32>,
    negotiated_orf_recv: Vec<(Afi, Safi)>,
    negotiated_llgr_families: Vec<(Afi, Safi)>,
    gr_context: Option<PeerSelectionDeferralContext>,
    exact_export_encoder: Option<Arc<dyn ExactExportEncoder>>,
}

#[derive(Clone, Debug, Default)]
#[expect(
    clippy::struct_field_names,
    reason = "fields mirror the RibUpdate::SetPeerGracefulRestartContext wire names"
)]
struct PeerSelectionDeferralContext {
    peer_restart_state: bool,
    peer_gr_families: Vec<(Afi, Safi)>,
    /// Peer negotiated enhanced route refresh (RFC 7313). Collision
    /// failback only arms a `BoRR`/`EoRR` convergence wait when the
    /// survivor can actually produce the pair.
    peer_enhanced_refresh: bool,
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
const QUERY_BUDGET_PER_CHUNK: usize = 8;
/// Production stride of probed routes between wall-clock checks inside one
/// strict shared-policy actor poll; the poll keeps striding until
/// [`FLUSH_POLL_BUDGET`] elapses.
pub(in crate::manager) const POLICY_TRANSITION_PRODUCTION_ROUTE_SLICE: usize = 1_024;
/// Maximum route identities processed by one strict shared-policy actor poll.
#[cfg(not(test))]
pub(in crate::manager) const POLICY_TRANSITION_ROUTE_SLICE: usize =
    POLICY_TRANSITION_PRODUCTION_ROUTE_SLICE;
/// Tiny deterministic unit used to prove multi-poll ordering in tests.
#[cfg(test)]
pub(in crate::manager) const POLICY_TRANSITION_ROUTE_SLICE: usize = 1;

pub(in crate::manager) fn policy_transition_slice_end(
    cursor: usize,
    len: usize,
    budget: usize,
) -> usize {
    (cursor + budget).min(len)
}
/// Maximum members classified by one strict shared-policy actor poll.
pub(in crate::manager) const POLICY_TRANSITION_MEMBER_SLICE: usize = 8;
/// Stride of validated members committed between wall-clock checks inside
/// one commit-kind actor poll (matches `QUERY_BUDGET_PER_CHUNK`). The poll
/// keeps flushing strides until [`COMMIT_FLUSH_POLL_BUDGET`] elapses, then
/// parks so the readiness lane gets its seam.
pub(in crate::manager) const COMMIT_MEMBERS_PER_POLL: usize = 8;
/// Wall-clock budget for one paced actor poll — a commit-kind member flush
/// or a dirty-resync tick. Bounds the readiness-seam latency (well under
/// the 200 ms readiness deadline) while decoupling paced throughput from
/// fleet size — a fixed 8-item poll at ~10 ms of interleaved actor work per
/// poll seam cost ~0.88 s of staggered emission at 700 members.
const FLUSH_POLL_BUDGET: std::time::Duration = std::time::Duration::from_millis(25);
/// Stride of dirty peers handed to one `distribute_changes` pass between
/// wall-clock checks inside a resync-timer tick. Each dirty peer costs
/// O(table) enumeration and staging, so an unbounded pass stalls the actor
/// for the whole backlog; the tick keeps taking strides until
/// [`FLUSH_POLL_BUDGET`] elapses, then a withheld remainder re-arms the
/// timer at [`DIRTY_RESYNC_BACKLOG_INTERVAL`].
const RESYNC_PEERS_PER_TICK: usize = 8;
/// Re-arm interval while a withheld dirty-resync backlog remains. Short by
/// design: the backlog is work the actor already owes, so the next slice
/// should run as soon as queued updates and queries have had a turn.
const DIRTY_RESYNC_BACKLOG_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);
const ROUTE_EVENT_HISTORY_CAPACITY: usize = 4096;
const EVPN_ROUTE_EVENT_HISTORY_CAPACITY: usize = 4096;

fn initial_route_page_version() -> RoutePageVersion {
    let state = std::collections::hash_map::RandomState::new();
    let mut hasher = state.build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| {
                u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
            }),
    );
    RoutePageVersion {
        epoch: hasher.finish(),
        generation: 0,
    }
}

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
    FlowSpecWithdrawn(Vec<crate::route::FlowSpecKey>),
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
    flowspec_withdrawn: std::vec::IntoIter<crate::route::FlowSpecKey>,
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
        flowspec_withdrawn: Vec<crate::route::FlowSpecKey>,
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

fn log_orr_input_transition(
    previous: crate::orr::OrrInputDiagnostics,
    current: crate::orr::OrrInputDiagnostics,
) {
    match crate::orr::input_diagnostics_transition(previous, current) {
        Some(crate::orr::OrrInputTransition::ExclusionsActivated) => warn!(
            included_default = current.included_default,
            excluded_nondefault = current.excluded_nondefault,
            malformed_topology = current.malformed_topology,
            malformed_attribute_29 = current.malformed_attribute_29,
            default_with_ignored_flex_algo = current.default_with_ignored_flex_algo,
            "ORR BGP-LS exclusions became active for the supported default topology"
        ),
        Some(crate::orr::OrrInputTransition::ExclusionsCleared) => info!(
            included_default = current.included_default,
            excluded_nondefault = current.excluded_nondefault,
            malformed_topology = current.malformed_topology,
            malformed_attribute_29 = current.malformed_attribute_29,
            default_with_ignored_flex_algo = current.default_with_ignored_flex_algo,
            "one or more ORR BGP-LS exclusion categories cleared; other diagnostics remain active"
        ),
        Some(crate::orr::OrrInputTransition::FlexChanged) => info!(
            included_default = current.included_default,
            excluded_nondefault = current.excluded_nondefault,
            malformed_topology = current.malformed_topology,
            malformed_attribute_29 = current.malformed_attribute_29,
            default_with_ignored_flex_algo = current.default_with_ignored_flex_algo,
            "ORR ignored Flex-Algorithm input changed; classic default-topology metrics remain active"
        ),
        Some(crate::orr::OrrInputTransition::Cleared) => {
            info!("ORR BGP-LS input filtering is no longer active");
        }
        None => {}
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
    #[expect(
        clippy::too_many_lines,
        reason = "constructor initializes the manager's deliberately centralized actor state"
    )]
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
            flush_poll_budget: FLUSH_POLL_BUDGET,
            outbound_session_ids: HashMap::new(),
            live_sessions: HashMap::new(),
            pending_peer_export_context: HashMap::new(),
            pending_peer_export_encoders: HashMap::new(),
            pending_peer_gr_context: HashMap::new(),
            peer_export_encoders: HashMap::new(),
            peer_unexportable: HashMap::new(),
            export_policy,
            peer_export_policies: HashMap::new(),
            peer_sendable_families: HashMap::new(),
            peer_advertised_llgr_families: HashMap::new(),
            peer_is_ebgp: HashMap::new(),
            peer_is_rr_client: HashMap::new(),
            peer_local_roles: HashMap::new(),
            pending_otc_blocked: HashMap::new(),
            peer_orr_vantage: HashMap::new(),
            orr: crate::orr::OrrState::default(),
            cluster_id,
            dirty_peers: BTreeSet::new(),
            dirty_resync_cursor: None,
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
            peer_interpret_rfc1997: HashSet::new(),
            peer_add_path_send_families: HashMap::new(),
            peer_orf_filters: HashMap::new(),
            slow_isolated_peers: HashSet::new(),
            peer_rt_membership: HashMap::new(),
            peer_orf_pending: HashMap::new(),
            gr_deferred_eor: HashMap::new(),
            selection_deferral: None,
            deferred_selection_keys: selection_deferral::DeferredSelectionKeys::default(),
            selection_deferred_refresh: HashMap::new(),
            peer_asn: HashMap::new(),
            peer_group: HashMap::new(),
            peer_bgp_id: HashMap::new(),
            update_groups: update_groups::UpdateGroupRegistry::default(),
            group_ribs: HashMap::new(),
            pending_regroup_baseline: HashMap::new(),
            pending_extra_withdraws: HashMap::new(),
            #[cfg(test)]
            test_force_ungrouped: false,
            #[cfg(test)]
            test_force_exact_export_slow_path: false,
            #[cfg(test)]
            test_exact_export_fast_path_hits: 0,
            #[cfg(any(test, feature = "bench-internals"))]
            policy_transition_stats: PolicyTransitionStats::default(),
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
            readiness_rx: None,
            pending_route_batches: VecDeque::new(),
            pending_clean_policy_transition: None,
            pending_destination_prestage: None,
            prepared_destination: None,
            pending_exact_export_withdrawals: HashSet::new(),
            pending_distribute_changed: HashSet::new(),
            pending_distribute_affected: HashSet::new(),
            route_page_received_version: Some(initial_route_page_version()),
            route_page_best_version: Some(initial_route_page_version()),
            route_page_advertised_version: Some(initial_route_page_version()),
            test_ingest_stall,
        }
    }

    /// Install the dedicated type-narrow RIB readiness-query receiver.
    #[must_use]
    pub fn with_readiness_queries(
        mut self,
        readiness_rx: mpsc::Receiver<RibReadinessQuery>,
    ) -> Self {
        self.readiness_rx = Some(readiness_rx);
        self
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

    /// Install the startup-frozen RFC 4724 restarting-speaker waiter roster.
    /// Called before the actor starts; cold starts leave the gate absent.
    #[must_use]
    pub fn with_selection_deferral(mut self, config: SelectionDeferralConfig) -> Self {
        self.selection_deferral = selection_deferral::SelectionDeferral::new(config, &self.metrics);
        self
    }

    #[must_use]
    pub(super) fn selection_deferred(&self, family: (Afi, Safi)) -> bool {
        self.selection_deferral
            .as_ref()
            .is_some_and(|state| state.selection_deferred(family))
    }

    #[must_use]
    pub(super) fn selection_convergence_held(&self, family: (Afi, Safi)) -> bool {
        self.selection_deferral
            .as_ref()
            .is_some_and(|state| state.is_gated(family))
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
        // The exact family map is subordinate to the negotiated Add-Path
        // send set. Keep this check ahead of the map lookup so a malformed
        // cross-crate payload can never enable Add-Path for an unnegotiated
        // family in release builds.
        if !self
            .peer_add_path_send_families
            .get(&peer)
            .is_some_and(|families| families.contains(&family))
        {
            return 0;
        }
        if let Some(limit) = self
            .peer_add_path_send_limits
            .get(&peer)
            .and_then(|limits| limits.get(&family))
        {
            return *limit;
        }
        send_max
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

    /// Advance one scope version without ever reusing a process-local value.
    /// Generation rollover increments the epoch; exhausting both words leaves
    /// the scope disabled so continuation fails closed.
    fn advance_route_page_version(version: &mut Option<RoutePageVersion>) {
        let Some(current) = version.as_mut() else {
            return;
        };
        if let Some(next) = current.generation.checked_add(1) {
            current.generation = next;
        } else if let Some(next_epoch) = current.epoch.checked_add(1) {
            current.epoch = next_epoch;
            current.generation = 0;
        } else {
            *version = None;
        }
    }

    fn advance_received_pages(&mut self) {
        Self::advance_route_page_version(&mut self.route_page_received_version);
    }

    fn advance_best_pages(&mut self) {
        Self::advance_route_page_version(&mut self.route_page_best_version);
    }

    pub(super) fn advance_advertised_pages(&mut self) {
        Self::advance_route_page_version(&mut self.route_page_advertised_version);
    }

    fn advance_all_route_pages(&mut self) {
        self.advance_received_pages();
        self.advance_best_pages();
        self.advance_advertised_pages();
    }

    fn route_page_version(
        &self,
        scope: RouteQueryScope,
    ) -> Result<RoutePageVersion, RoutePageError> {
        let version = match scope {
            RouteQueryScope::Received { .. } => self.route_page_received_version,
            RouteQueryScope::Best => self.route_page_best_version,
            RouteQueryScope::Advertised { .. } => self.route_page_advertised_version,
        };
        version.ok_or(RoutePageError::GenerationExhausted)
    }

    fn advance_route_pages_for_update(&mut self, update: &RibUpdate) {
        match update {
            // `ReplacePeerExportPolicies` stages a multi-iteration clean
            // transition whose `Finalize` flips group memberships and export
            // overlays; general queries stay fenced out until it is terminal,
            // so advancing here at acceptance covers the whole transaction.
            RibUpdate::PeerAddPathLimits { .. }
            | RibUpdate::PeerOrfUpdate { .. }
            | RibUpdate::PeerSlowState { .. }
            | RibUpdate::SetPeerPolicyContext { .. }
            | RibUpdate::ReplacePeerExportPolicy { .. }
            | RibUpdate::ReplacePeerExportPolicies { .. }
            | RibUpdate::RefreshPeerOutbound { .. }
            | RibUpdate::RouteRefreshRequest { .. } => self.advance_advertised_pages(),
            RibUpdate::PeerUp { .. }
            | RibUpdate::PeerDown { .. }
            | RibUpdate::PeerDeleted { .. }
            | RibUpdate::InjectRoute { .. }
            | RibUpdate::WithdrawInjected { .. }
            | RibUpdate::EndOfRib { .. }
            | RibUpdate::PeerGracefulRestart { .. }
            | RibUpdate::BeginRouteRefresh { .. }
            | RibUpdate::EndRouteRefresh { .. }
            | RibUpdate::RpkiCacheUpdate { .. }
            | RibUpdate::AspaTableUpdate { .. } => self.advance_all_route_pages(),
            _ => {}
        }
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

    /// Preserve the policy-transition ownership fence when a primary update
    /// acquires it: the post-update fairness drain must not admit general
    /// queries until that transition is terminal.
    fn drain_general_queries_if_unfenced(&mut self) {
        if self.pending_clean_policy_transition.is_none() {
            self.drain_queries(QUERY_BUDGET_PER_CHUNK);
        }
    }

    fn handle_readiness_query(
        &self,
        query: RibReadinessQuery,
        policy_transition_elapsed: Option<std::time::Duration>,
    ) {
        match query {
            RibReadinessQuery::LocRibCount { reply } => {
                let result = match policy_transition_elapsed {
                    Some(elapsed) if elapsed >= MAX_HEALTHY_POLICY_TRANSITION_AGE => {
                        Err(RibReadinessError::PolicyTransitionStalled)
                    }
                    _ => Ok(self.loc_rib.len()),
                };
                let _ = reply.send(result);
            }
        }
    }

    /// Service a bounded number of type-narrow readiness probes at an actor
    /// seam without admitting any ordinary query or mutation.
    fn drain_readiness_queries(&mut self, policy_transition_elapsed: Option<std::time::Duration>) {
        for _ in 0..QUERY_BUDGET_PER_CHUNK {
            let query = match self.readiness_rx.as_mut() {
                Some(rx) => match rx.try_recv() {
                    Ok(query) => query,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        self.readiness_rx = None;
                        break;
                    }
                },
                None => break,
            };
            self.handle_readiness_query(query, policy_transition_elapsed);
        }
    }

    /// One bounded resync-timer tick: hand [`RESYNC_PEERS_PER_TICK`]-sized
    /// slices of dirty peers to `distribute_changes` until the poll's
    /// wall-clock budget elapses, withholding the remainder so the actor
    /// yields between polls. Selection round-robins from
    /// [`Self::dirty_resync_cursor`] and never re-attempts a peer within
    /// the same tick, so peers whose sends keep failing cannot spin the
    /// budget loop or monopolize successive ticks. Returns whether a
    /// withheld (not-yet-attempted) backlog remains — distinct from peers
    /// that stayed dirty because their send failed; those wait for the
    /// ordinary retry interval.
    ///
    /// Safe to run partially: per-peer resync is idempotent — Adj-RIB-Out
    /// state and the dirty flag are committed/cleared only after a
    /// successful send, and withheld peers are not touched at all.
    fn resync_dirty_peers_bounded(&mut self) -> bool {
        // Peers whose outbound channel is gone can never resync: drop them
        // before selecting the slice, so a backlog of dead sessions (e.g.
        // after shutdown tore the TCP sessions down) quiesces in one cheap
        // tick — instead of burning an O(table) export pass per dead peer
        // and re-arming forever, starving the shutdown observation.
        let gone: Vec<IpAddr> = self
            .dirty_peers
            .iter()
            .copied()
            .filter(|&peer| self.outbound_channel_gone(peer))
            .collect();
        for peer in gone {
            debug!(%peer, "dropping dirty peer whose outbound channel closed");
            self.drop_gone_dirty_peer(peer);
        }
        let poll_start = std::time::Instant::now();
        let mut attempted: HashSet<IpAddr> = HashSet::new();
        loop {
            // Ring selection: up to RESYNC_PEERS_PER_TICK unattempted peers,
            // starting strictly after the cursor and wrapping. Ring order is
            // preserved so the cursor lands on the last peer actually
            // attempted, not the numerically largest.
            let ring: Vec<IpAddr> = {
                let after = self
                    .dirty_peers
                    .iter()
                    .filter(|peer| match self.dirty_resync_cursor {
                        Some(cursor) => **peer > cursor,
                        None => true,
                    });
                let wrapped = self.dirty_peers.iter().filter(|peer| {
                    self.dirty_resync_cursor
                        .is_some_and(|cursor| **peer <= cursor)
                });
                after
                    .chain(wrapped)
                    .filter(|peer| !attempted.contains(*peer))
                    .take(RESYNC_PEERS_PER_TICK)
                    .copied()
                    .collect()
            };
            let Some(&last) = ring.last() else {
                // Nothing unattempted remains: any peers still dirty failed
                // their send this tick and wait for the ordinary retry.
                return false;
            };
            self.dirty_resync_cursor = Some(last);
            attempted.extend(ring.iter().copied());
            let selected: BTreeSet<IpAddr> = ring.into_iter().collect();
            let withheld: Vec<IpAddr> = self.dirty_peers.difference(&selected).copied().collect();
            self.dirty_peers = selected;
            self.distribute_changes(&HashSet::new(), &HashSet::new());
            self.dirty_peers.extend(withheld);
            let unattempted_remain = self
                .dirty_peers
                .iter()
                .any(|peer| !attempted.contains(peer));
            if !unattempted_remain {
                return false;
            }
            if poll_start.elapsed() >= self.flush_poll_budget {
                return true;
            }
        }
    }

    async fn receive_readiness_query(
        readiness_rx: &mut Option<mpsc::Receiver<RibReadinessQuery>>,
    ) -> Option<RibReadinessQuery> {
        match readiness_rx {
            Some(rx) => rx.recv().await,
            None => std::future::pending().await,
        }
    }

    /// Record one real state-machine poll. Production yields immediately after
    /// each call; the benchmark driver invokes the same advance seam
    /// synchronously and records identical phase boundaries.
    pub(in crate::manager) fn record_policy_transition_poll(
        &mut self,
        kind: distribution::CleanPolicyTransitionPollKind,
        elapsed: std::time::Duration,
    ) {
        self.metrics
            .observe_rib_policy_transition_actor_poll(kind.as_str(), elapsed);
        #[cfg(any(test, feature = "bench-internals"))]
        {
            self.policy_transition_stats.actor_polls =
                self.policy_transition_stats.actor_polls.saturating_add(1);
            self.policy_transition_stats.max_actor_slice =
                self.policy_transition_stats.max_actor_slice.max(elapsed);
            match kind {
                distribution::CleanPolicyTransitionPollKind::PrefixSnapshot => {
                    self.policy_transition_stats.max_prefix_snapshot_poll = self
                        .policy_transition_stats
                        .max_prefix_snapshot_poll
                        .max(elapsed);
                }
                distribution::CleanPolicyTransitionPollKind::Finalize => {
                    self.policy_transition_stats.max_finalize_poll =
                        self.policy_transition_stats.max_finalize_poll.max(elapsed);
                }
                distribution::CleanPolicyTransitionPollKind::Commit => {
                    self.policy_transition_stats.max_commit_poll =
                        self.policy_transition_stats.max_commit_poll.max(elapsed);
                }
                distribution::CleanPolicyTransitionPollKind::Bounded => {}
            }
        }
    }

    fn finish_policy_transition_observability(
        &self,
        outcome: &'static str,
        member_count: usize,
        elapsed: std::time::Duration,
    ) {
        self.metrics.set_rib_policy_transition_in_progress(false);
        self.metrics
            .set_rib_policy_transition_last_duration(elapsed);
        let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        info!(
            outcome,
            member_count, elapsed_ms, "RIB export-policy transition completed"
        );
    }

    fn warn_if_policy_transition_slow(
        pending: &mut distribution::PendingCleanPolicyTransition,
        member_count: usize,
    ) {
        if let Some(elapsed) = pending.take_slow_warning(SLOW_POLICY_TRANSITION) {
            warn!(
                member_count,
                elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                "RIB export-policy transition remains in progress"
            );
        }
    }

    fn drain_ready_updates(&mut self) -> bool {
        let mut drained = false;
        // Route batches are actor-deferred for fairness. During a timer race,
        // however, preserve channel order: an EoR or timeout must not release
        // selection before route payloads accepted ahead of it are applied.
        while self.process_next_route_chunk() {
            drained = true;
        }
        while let Ok(update) = self.rx.try_recv() {
            drained = true;
            self.handle_update(update);
            if self.pending_clean_policy_transition.is_some() {
                // The accepted cohort command now owns FIFO. Leave every
                // later primary update queued until its atomic finalize or
                // fail-closed fallback handoff completes.
                break;
            }
            while self.process_next_route_chunk() {
                drained = true;
            }
        }
        drained
    }

    /// Process a single `RibUpdate` message.
    #[expect(
        clippy::too_many_lines,
        reason = "dispatcher needs one arm per RibUpdate variant"
    )]
    fn handle_update(&mut self, update: RibUpdate) {
        self.advance_route_pages_for_update(&update);
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
                    let retired = withdrawn
                        .iter()
                        .cloned()
                        .map(ExactExportKey::BgpLs)
                        .collect::<Vec<_>>();
                    self.handle_bgpls_routes_received(peer, announced, withdrawn);
                    self.retire_exact_export_rejections(retired);
                }
            }
            RibUpdate::VpnRoutesReceived {
                peer,
                session_id,
                announced,
                withdrawn,
            } => {
                if !self.stale_session_message(peer, session_id, "VpnRoutesReceived", "vpn") {
                    let retired = withdrawn
                        .iter()
                        .cloned()
                        .map(ExactExportKey::Vpn)
                        .collect::<Vec<_>>();
                    self.handle_vpn_routes_received(peer, announced, withdrawn);
                    self.retire_exact_export_rejections(retired);
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
                    let retired = withdrawn
                        .iter()
                        .copied()
                        .map(ExactExportKey::Labeled)
                        .collect::<Vec<_>>();
                    self.handle_labeled_routes_received(peer, announced, withdrawn);
                    self.retire_exact_export_rejections(retired);
                }
            }
            RibUpdate::RtcRoutesReceived {
                peer,
                session_id,
                announced,
                withdrawn,
            } => {
                if !self.stale_session_message(peer, session_id, "RtcRoutesReceived", "rtc") {
                    let retired = withdrawn
                        .iter()
                        .cloned()
                        .map(ExactExportKey::Rtc)
                        .collect::<Vec<_>>();
                    self.handle_rtc_routes_received(peer, announced, withdrawn);
                    self.retire_exact_export_rejections(retired);
                }
            }
            RibUpdate::PeerDown { peer, session_id } => {
                self.handle_peer_down(peer, session_id);
                self.prune_exact_export_rejections();
            }
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
                interpret_rfc1997,
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
                interpret_rfc1997,
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
                // Transport emits this once per session from the immutable
                // OPEN negotiation, immediately after PeerUp. Idempotency
                // suppresses duplicate delivery; this is not a runtime cap
                // reconfiguration surface (a decrease requires a new session
                // so excess advertised path IDs are withdrawn by teardown).
                if self.outbound_session_ids.get(&peer).copied() == Some(session_id) {
                    let send_families = self
                        .peer_add_path_send_families
                        .get(&peer)
                        .cloned()
                        .unwrap_or_default();
                    let mut rejected_families = Vec::new();
                    let new_limits: HashMap<_, _> = limits
                        .into_iter()
                        .filter(|(family, _)| {
                            let accepted = send_families.contains(family);
                            if !accepted {
                                rejected_families.push(*family);
                            }
                            accepted
                        })
                        .collect();
                    if !rejected_families.is_empty() {
                        rejected_families.sort_by_key(|(afi, safi)| (*afi as u16, *safi as u8));
                        rejected_families.dedup();
                        warn!(
                            %peer,
                            ?rejected_families,
                            "ignoring Paths-Limit entries outside the negotiated Add-Path send families"
                        );
                    }
                    let scalar_limit = self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0);
                    let effective_limit_changed = self
                        .peer_add_path_send_families
                        .get(&peer)
                        .is_some_and(|families| {
                            families.iter().any(|family| {
                                let old = self
                                    .peer_add_path_send_limits
                                    .get(&peer)
                                    .and_then(|limits| limits.get(family))
                                    .copied()
                                    .unwrap_or(scalar_limit);
                                let new = new_limits.get(family).copied().unwrap_or(scalar_limit);
                                old != new
                            })
                        });
                    // Mirror the accepted map into the live-session record —
                    // the single registration truth an outbound failover
                    // replays from. Without this, a collision failback would
                    // permanently clamp every family to the scalar limit.
                    if let Some(record) = self.live_sessions.get_mut(&peer).and_then(|sessions| {
                        sessions.iter_mut().find(|s| s.session_id == session_id)
                    }) {
                        record.add_path_send_limits.clone_from(&new_limits);
                    }
                    self.peer_add_path_send_limits.insert(peer, new_limits);
                    if effective_limit_changed {
                        self.send_initial_table(peer);
                    }
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
            RibUpdate::PeerSlowState {
                peer,
                session_id,
                slow,
            } => {
                if !self.stale_session_message(peer, session_id, "PeerSlowState", "slow_peer") {
                    self.handle_peer_slow_state(peer, slow);
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
            RibUpdate::SetPeerExportContext {
                peer,
                session_id,
                local_role,
            } => {
                // This context intentionally precedes `PeerUp` so the initial
                // table build cannot race RFC 9234 enforcement. Key by session
                // id because collision-window senders can interleave.
                self.pending_peer_export_context
                    .insert((peer, session_id), local_role);
            }
            RibUpdate::SetPeerExportEncoder {
                peer,
                session_id,
                encoder,
            } => {
                // Like the role context above, this is deliberately staged
                // before PeerUp. Collision-window senders can interleave, so
                // only the matching session consumes the handle.
                self.pending_peer_export_encoders
                    .insert((peer, session_id), encoder);
            }
            RibUpdate::SetPeerGracefulRestartContext {
                peer,
                session_id,
                peer_restart_state,
                peer_gr_families,
                peer_enhanced_refresh,
            } => {
                self.pending_peer_gr_context.insert(
                    (peer, session_id),
                    PeerSelectionDeferralContext {
                        peer_restart_state,
                        peer_gr_families,
                        peer_enhanced_refresh,
                    },
                );
            }
            RibUpdate::InjectRoute { route, reply } => self.handle_inject_route(route, reply),
            RibUpdate::WithdrawInjected {
                prefix,
                path_id,
                reply,
            } => {
                self.handle_withdraw_injected(prefix, path_id, reply);
                self.retire_exact_export_rejections([ExactExportKey::Unicast(prefix, path_id)]);
            }
            RibUpdate::QueryReceivedRoutes { peer, reply } => {
                self.handle_query_received_routes(peer, reply);
            }
            RibUpdate::QueryRoutesPage {
                scope,
                filter,
                after,
                expected_version,
                page_size,
                reply,
            } => {
                self.handle_query_routes_page_versioned(
                    scope,
                    filter.as_ref(),
                    after,
                    expected_version,
                    page_size,
                    reply,
                );
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
                labeled,
                reply,
            } => self.handle_explain_advertised_route(peer, prefix, rd, labeled, reply),
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
            RibUpdate::QueryPeerOutboundState { peer, reply } => {
                self.handle_query_peer_outbound_state(peer, reply);
            }
            RibUpdate::QueryUpdateGroupSnapshot { reply } => {
                self.handle_query_update_group_snapshot(reply);
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
            #[cfg(test)]
            RibUpdate::TestQueryPolicyTransitionStats { reply } => {
                let stats = self.policy_transition_stats;
                let _ = reply.send((
                    stats.plan_builds,
                    stats.full_exact_probes,
                    stats.route_shell_materializations,
                    stats.max_actor_slice.as_nanos(),
                    stats.actor_polls,
                ));
            }
            #[cfg(test)]
            RibUpdate::TestQueryUncommittedPolicyTransitionGroups { reply } => {
                let count = self
                    .group_ribs
                    .values()
                    .filter(|group| group.members.is_empty())
                    .count();
                let _ = reply.send(count);
            }
            RibUpdate::QueryExportPolicyTermHits { peer, reply } => {
                self.handle_query_export_policy_term_hits(peer, reply);
            }
            RibUpdate::ReplacePeerExportPolicy {
                peer,
                export_policy,
                reply,
            } => self.handle_replace_peer_export_policy(peer, export_policy, reply),
            RibUpdate::ReplacePeerExportPolicies {
                replacements,
                reply,
            } => self.handle_replace_peer_export_policies(replacements, reply),
            RibUpdate::PrepareExportPolicyDestination {
                peer,
                export_policy,
                reply,
            } => self.begin_destination_prestage(peer, export_policy.as_ref(), reply),
            RibUpdate::DiscardPreparedExportPolicyDestination { .. } => {
                self.discard_prepared_export_destination();
            }
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
                    let selection_transition =
                        self.selection_deferral_end_of_rib(peer, session_id, (afi, safi));
                    self.handle_end_of_rib(peer, afi, safi);
                    if let Some(transition) = selection_transition {
                        self.apply_selection_deferral_transitions(
                            [transition],
                            "all current-session End-of-RIB markers received",
                        );
                    }
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
                    if let Some(transition) =
                        self.selection_deferral_begin_route_refresh(peer, session_id, (afi, safi))
                    {
                        self.apply_selection_deferral_transitions(
                            [transition],
                            "collision-failback refresh began",
                        );
                    }
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
                    if let Some(transition) =
                        self.selection_deferral_end_route_refresh(peer, session_id, (afi, safi))
                    {
                        self.apply_selection_deferral_transitions(
                            [transition],
                            "collision-failback survivor refresh completed",
                        );
                    }
                }
            }
            RibUpdate::RouteRefreshTimeout {
                peer,
                session_id,
                afi,
                safi,
            } => {
                if !self.stale_session_message(peer, session_id, "RouteRefreshTimeout", "refresh") {
                    self.finish_route_refresh(peer, afi, safi, true);
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
            RibUpdate::WithdrawFlowSpec { key, reply } => {
                let retired = ExactExportKey::FlowSpec(key.clone());
                self.handle_withdraw_flowspec(key, reply);
                self.retire_exact_export_rejections([retired]);
            }
            RibUpdate::InjectEvpn { route, reply } => self.handle_inject_evpn(route, reply),
            RibUpdate::WithdrawEvpn { key, reply } => {
                self.handle_withdraw_evpn(key, reply);
                self.retire_exact_export_rejections([ExactExportKey::Evpn(key)]);
            }
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
            RibUpdate::QueryWarmMrtSnapshot {
                views,
                budget,
                reply,
            } => {
                self.handle_query_warm_mrt_snapshot(&views, &budget, reply);
            }
            RibUpdate::QueryBmpLocRibDump { cursor, reply } => {
                self.handle_query_bmp_loc_rib_dump(cursor, reply);
            }
            RibUpdate::QueryBmpLocRibStats { reply } => {
                self.handle_query_bmp_loc_rib_stats(reply);
            }
        }
    }

    /// Remove sparse rejection-overlay keys whose NLRI identity no longer
    /// exists in any Adj-RIB-In. This full live-set rebuild is reserved for
    /// infrequent bulk lifecycle sweeps; the UPDATE hot path uses targeted
    /// withdrawal cleanup instead.
    fn prune_exact_export_rejections(&mut self) {
        if self.peer_unexportable.is_empty() {
            return;
        }
        let live = self.live_exact_export_nlri();
        self.peer_unexportable.retain(|_, rejected| {
            rejected.retain(|key| live.contains(&key.nlri_identity()));
            !rejected.is_empty()
        });
    }

    fn live_exact_export_nlri(&self) -> HashSet<ExactExportKey> {
        self.ribs
            .values()
            .flat_map(|rib| {
                rib.iter()
                    // Invariant: unicast is keyed at path_id 0 here because
                    // lookups go through ExactExportKey::nlri_identity()
                    // (crates/rib/src/update.rs), which normalizes the
                    // unicast Add-Path rank to 0. Changing either side's
                    // keying requires changing the other.
                    .map(|route| ExactExportKey::Unicast(route.prefix, 0))
                    .chain(
                        rib.iter_flowspec()
                            .map(|route| ExactExportKey::FlowSpec(route.selection_key())),
                    )
                    .chain(
                        rib.iter_evpn()
                            .map(|route| ExactExportKey::Evpn(route.key())),
                    )
                    .chain(
                        rib.iter_bgpls()
                            .map(|route| ExactExportKey::BgpLs(route.key()).nlri_identity()),
                    )
                    .chain(
                        rib.iter_vpn()
                            .map(|route| ExactExportKey::Vpn(route.key()).nlri_identity()),
                    )
                    .chain(
                        rib.iter_labeled()
                            .map(|route| ExactExportKey::Labeled(route.key()).nlri_identity()),
                    )
                    .chain(
                        rib.iter_rtc()
                            .map(|route| ExactExportKey::Rtc(route.key()).nlri_identity()),
                    )
            })
            .collect()
    }

    fn exact_export_nlri_is_live(&self, key: &ExactExportKey) -> bool {
        match key {
            ExactExportKey::Unicast(prefix, _) => {
                self.unicast_prefix_peers.get(prefix).is_some_and(|peers| {
                    peers.iter().any(|peer| {
                        self.ribs
                            .get(peer)
                            .is_some_and(|rib| rib.iter_prefix(prefix).next().is_some())
                    })
                })
            }
            ExactExportKey::FlowSpec(key) => self.ribs.values().any(|rib| {
                rib.iter_flowspec()
                    .any(|route| route.selection_key() == *key)
            }),
            ExactExportKey::Evpn(key) => self
                .ribs
                .values()
                .any(|rib| rib.iter_evpn().any(|route| route.key() == *key)),
            ExactExportKey::BgpLs(key) => self.ribs.values().any(|rib| {
                rib.iter_bgpls().any(|route| {
                    ExactExportKey::BgpLs(route.key()).nlri_identity()
                        == ExactExportKey::BgpLs(key.clone()).nlri_identity()
                })
            }),
            ExactExportKey::Vpn(key) => self
                .ribs
                .values()
                .any(|rib| rib.iter_vpn_for_nlri(&key.nlri_key).next().is_some()),
            ExactExportKey::Labeled(key) => self
                .ribs
                .values()
                .any(|rib| rib.iter_labeled_for_prefix(&key.prefix).next().is_some()),
            ExactExportKey::Rtc(key) => self.ribs.values().any(|rib| {
                rib.iter_rtc().any(|route| {
                    ExactExportKey::Rtc(route.key()).nlri_identity()
                        == ExactExportKey::Rtc(key.clone()).nlri_identity()
                })
            }),
        }
    }

    /// Retire withdrawn overlay identities after distribution had the first
    /// chance to suppress a rejected-only wire withdrawal. A surviving source
    /// path keeps the overlay; the distribution pass has already refreshed its
    /// exact accept/reject state.
    fn retire_exact_export_rejections(
        &mut self,
        withdrawn: impl IntoIterator<Item = ExactExportKey>,
    ) {
        if self.peer_unexportable.is_empty() {
            return;
        }
        let withdrawn = withdrawn
            .into_iter()
            .map(|key| key.nlri_identity())
            .collect::<HashSet<_>>();
        if withdrawn.is_empty() {
            return;
        }
        let rejected_withdrawn = self
            .peer_unexportable
            .values()
            .flat_map(|rejected| rejected.iter().map(ExactExportKey::nlri_identity))
            .filter(|identity| withdrawn.contains(identity))
            .collect::<HashSet<_>>();
        if rejected_withdrawn.is_empty() {
            return;
        }
        let live = rejected_withdrawn
            .iter()
            .filter(|key| self.exact_export_nlri_is_live(key))
            .cloned()
            .collect::<HashSet<_>>();
        self.peer_unexportable.retain(|_, rejected| {
            rejected.retain(|key| {
                let identity = key.nlri_identity();
                !rejected_withdrawn.contains(&identity) || live.contains(&identity)
            });
            !rejected.is_empty()
        });
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
    fn handle_query_routes_page_versioned(
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
                RouteQueryScope::Best => page_ordered_routes(
                    self.loc_rib.iter_ordered_from(after),
                    self.loc_rib.len(),
                    page_size,
                ),
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
    fn handle_query_routes_page(
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
        labeled: bool,
        reply: tokio::sync::oneshot::Sender<Option<ExplainAdvertisedRoute>>,
    ) {
        if !self.peer_sendable_families.contains_key(&peer) {
            let _ = reply.send(None);
            return;
        }
        let explanation = match (rd, labeled) {
            (Some(rd), _) => self.explain_vpn_export(peer, prefix, rd),
            (None, true) => self.explain_labeled_export(peer, prefix),
            (None, false) => self.explain_unicast_export(peer, prefix),
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
        if !self.selection_deferred(family) {
            self.rebuild_rtc_membership_and_restage_vpn(peer);
        }
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
                log_orr_input_transition(
                    self.orr.topology.input_diagnostics(),
                    crate::orr::OrrInputDiagnostics::default(),
                );
                self.orr = crate::orr::OrrState::default();
            }
            self.metrics.set_orr_topology_nodes(0);
            self.metrics.set_orr_topology_links(0);
            self.metrics.set_orr_unresolved_vantages(0);
            self.metrics
                .set_orr_input_diagnostics(crate::orr::OrrInputDiagnostics::default().values());
            return HashSet::new();
        }

        let topology = crate::orr::OrrTopology::build(
            self.ribs
                .values()
                .flat_map(crate::adj_rib_in::AdjRibIn::iter_bgpls)
                .filter(|route| !self.selection_deferred(route.family.to_afi_safi())),
        );
        let input_diagnostics = topology.input_diagnostics();
        log_orr_input_transition(self.orr.topology.input_diagnostics(), input_diagnostics);
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
        self.metrics
            .set_orr_input_diagnostics(input_diagnostics.values());
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
            input_diagnostics: self.orr.topology.input_diagnostics(),
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

    fn handle_query_warm_mrt_snapshot(
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

        // RFC 4724 restarting-speaker selection-deferral timer. The roster
        // and deadline are frozen before this actor starts.
        let selection_sleep = tokio::time::sleep(std::time::Duration::from_hours(24));
        tokio::pin!(selection_sleep);

        loop {
            // Sample ingest-channel depth once per iteration — a gauge
            // pegged at the channel capacity on scrape means producers
            // (sessions, local originators) are parked on backpressure.
            self.metrics
                .set_rib_ingest_channel_depth(i64::try_from(self.rx.len()).unwrap_or(i64::MAX));

            if let Some(mut pending) = self.pending_clean_policy_transition.take() {
                // Only the type-narrow readiness lane may interleave here.
                // General queries, primary updates, route chunks, timers, and
                // resync work remain queued until terminal commit or the
                // fail-closed fallback handoff.
                let member_count = pending.member_count();
                Self::warn_if_policy_transition_slow(&mut pending, member_count);
                self.drain_readiness_queries(Some(pending.elapsed()));
                let kind = pending.poll_kind();
                let started = std::time::Instant::now();
                let policy_transition_elapsed = match self.advance_clean_policy_transition(pending)
                {
                    distribution::CleanPolicyTransitionAdvance::Continue(mut next) => {
                        self.record_policy_transition_poll(kind, started.elapsed());
                        let member_count = next.member_count();
                        Self::warn_if_policy_transition_slow(&mut next, member_count);
                        let elapsed = next.elapsed();
                        self.pending_clean_policy_transition = Some(next);
                        Some(elapsed)
                    }
                    distribution::CleanPolicyTransitionAdvance::Committed(mut done) => {
                        self.record_policy_transition_poll(kind, started.elapsed());
                        let member_count = done.member_count();
                        Self::warn_if_policy_transition_slow(&mut done, member_count);
                        self.finish_policy_transition_observability(
                            "committed",
                            done.member_count(),
                            done.elapsed(),
                        );
                        drop(done);
                        None
                    }
                    distribution::CleanPolicyTransitionAdvance::Fallback(mut failed) => {
                        let cleanup = failed.discard_uncommitted_transition(&mut self);
                        self.record_policy_transition_poll(kind, started.elapsed());
                        let member_count = failed.member_count();
                        Self::warn_if_policy_transition_slow(&mut failed, member_count);
                        let outcome = if cleanup.is_ok() {
                            "fallback_handoff"
                        } else {
                            "fallback_cleanup_error"
                        };
                        self.finish_policy_transition_observability(
                            outcome,
                            member_count,
                            failed.elapsed(),
                        );
                        if let Some(reply) = failed.take_reply() {
                            let result = cleanup.map(|()| {
                                crate::update::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply
                            });
                            let _ = reply.send(result);
                        }
                        None
                    }
                };
                self.drain_readiness_queries(policy_transition_elapsed);
                tokio::task::yield_now().await;
                continue;
            }

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

            let has_selection_timer =
                if let Some(deadline) = self.next_selection_deferral_deadline() {
                    selection_sleep.as_mut().reset(deadline);
                    true
                } else {
                    false
                };

            let needs_timers = resync_armed
                || has_gr_timers
                || has_llgr_timers
                || has_refresh_timers
                || has_selection_timer;

            if query_rx_open && self.query_rx.is_closed() {
                query_rx_open = false;
            }

            let now = tokio::time::Instant::now();
            if resync_armed && resync_sleep.deadline() <= now {
                debug!(
                    count = self.dirty_peers.len(),
                    "resync timer fired for dirty peers"
                );
                let backlog = self.resync_dirty_peers_bounded();
                if self.dirty_peers.is_empty() {
                    self.metrics.record_rib_dirty_resync("cleared");
                    resync_armed = false;
                } else {
                    self.metrics.record_rib_dirty_resync("still_dirty");
                    let interval = if backlog {
                        DIRTY_RESYNC_BACKLOG_INTERVAL
                    } else {
                        DIRTY_RESYNC_INTERVAL
                    };
                    resync_sleep
                        .as_mut()
                        .reset(tokio::time::Instant::now() + interval);
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
            if has_selection_timer && selection_sleep.deadline() <= now {
                // A queued current-session EoR wins the all-EoR release race
                // over a simultaneously ready timer.
                if self.drain_ready_updates() {
                    continue;
                }
                self.expire_selection_deferral();
                continue;
            }

            // Unfenced destination pre-staging: advance one budgeted slice
            // only when no ordinary mutation traffic is queued, so churn
            // keeps flowing (and keeps already-staged prefixes current)
            // between slices. Readiness and a bounded query budget are
            // served every iteration, mirroring the paced-flush seams.
            if self.pending_destination_prestage.is_some() {
                if self.drain_ready_updates() {
                    self.drain_readiness_queries(None);
                    continue;
                }
                self.drain_readiness_queries(None);
                self.advance_destination_prestage();
                self.drain_queries(QUERY_BUDGET_PER_CHUNK);
                tokio::task::yield_now().await;
                continue;
            }

            if self.process_next_route_chunk() {
                self.drain_readiness_queries(None);
                self.drain_queries(QUERY_BUDGET_PER_CHUNK);
                tokio::task::yield_now().await;
            } else if needs_timers {
                tokio::select! {
                    readiness = Self::receive_readiness_query(&mut self.readiness_rx) => {
                        match readiness {
                            Some(query) => self.handle_readiness_query(query, None),
                            None => self.readiness_rx = None,
                        }
                    }
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
                                self.drain_general_queries_if_unfenced();
                            }
                            None => break,
                        }
                    }
                    () = resync_sleep.as_mut(), if resync_armed => {
                        debug!(
                            count = self.dirty_peers.len(),
                            "resync timer fired for dirty peers"
                        );
                        let backlog = self.resync_dirty_peers_bounded();

                        // Reset for next tick if still dirty, otherwise disarm.
                        if self.dirty_peers.is_empty() {
                            self.metrics.record_rib_dirty_resync("cleared");
                            resync_armed = false;
                        } else {
                            self.metrics.record_rib_dirty_resync("still_dirty");
                            let interval = if backlog {
                                DIRTY_RESYNC_BACKLOG_INTERVAL
                            } else {
                                DIRTY_RESYNC_INTERVAL
                            };
                            resync_sleep.as_mut().reset(
                                tokio::time::Instant::now() + interval,
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
                    () = selection_sleep.as_mut(), if has_selection_timer => {
                        if self.drain_ready_updates() {
                            continue;
                        }
                        self.expire_selection_deferral();
                    }
                }
            } else {
                // No timers needed — wait for a route update or query.
                tokio::select! {
                    readiness = Self::receive_readiness_query(&mut self.readiness_rx) => {
                        match readiness {
                            Some(query) => self.handle_readiness_query(query, None),
                            None => self.readiness_rx = None,
                        }
                    }
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
                                self.drain_general_queries_if_unfenced();
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
