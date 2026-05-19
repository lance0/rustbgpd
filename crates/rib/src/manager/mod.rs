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
use tracing::{debug, warn};

use crate::adj_rib_in::AdjRibIn;
use crate::adj_rib_out::AdjRibOut;
use crate::best_path::best_path_cmp_with_reason;
use crate::event::{RouteEvent, RouteEventType};
use crate::loc_rib::LocRib;
use crate::update::{
    BestPathCandidate, ExplainAdvertisedRoute, ExplainBestPath, MrtPeerEntry, MrtSnapshotData,
    OutboundRouteUpdate, RibUpdate,
};

use helpers::{DIRTY_RESYNC_INTERVAL, LlgrPeerConfig, prefix_family};

#[cfg(test)]
use helpers::{ERR_REFRESH_TIMEOUT, LOCAL_PEER, validate_route_rpki};

/// Central RIB manager that owns all Adj-RIB-In, Loc-RIB, and Adj-RIB-Out state.
///
/// Runs as a single tokio task, receiving updates via an mpsc channel.
/// No `Arc<RwLock>` — all state is owned by this task.
pub struct RibManager {
    ribs: HashMap<IpAddr, AdjRibIn>,
    loc_rib: LocRib,
    adj_ribs_out: HashMap<IpAddr, AdjRibOut>,
    outbound_peers: HashMap<IpAddr, mpsc::Sender<OutboundRouteUpdate>>,
    export_policy: Option<PolicyChain>,
    peer_export_policies: HashMap<IpAddr, Option<PolicyChain>>,
    /// Families the transport can actually serialize per peer.
    peer_sendable_families: HashMap<IpAddr, Vec<(Afi, Safi)>>,
    /// Whether each registered outbound peer is eBGP (true) or iBGP (false).
    peer_is_ebgp: HashMap<IpAddr, bool>,
    /// Whether each registered outbound peer is a route reflector client.
    peer_is_rr_client: HashMap<IpAddr, bool>,
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
    /// Current RPKI VRP table for origin validation. `None` = no RPKI data.
    vrp_table: Option<Arc<VrpTable>>,
    /// Current ASPA table for upstream path verification. `None` = no ASPA data.
    aspa_table: Option<Arc<rustbgpd_rpki::AspaTable>>,
    route_events_tx: broadcast::Sender<RouteEvent>,
    /// Bounded recent route-event history for after-the-fact operator
    /// timeline queries. Live streaming still uses `route_events_tx`.
    route_event_history: VecDeque<RouteEvent>,
    /// Monotonic process-local id assigned before route events are recorded in
    /// history and broadcast to live subscribers.
    next_route_event_id: u64,
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
    metrics: BgpMetrics,
    rx: mpsc::Receiver<RibUpdate>,
    /// Priority channel for read-only queries (gRPC).
    query_rx: mpsc::Receiver<RibUpdate>,
    /// Large route batches that are being processed in chunks.
    pending_route_batches: VecDeque<PendingRoutesReceived>,
}

const ROUTES_RECEIVED_CHUNK_SIZE: usize = 1024;
const QUERY_BUDGET_PER_CHUNK: usize = 8;
const ROUTE_EVENT_HISTORY_CAPACITY: usize = 4096;
const EVPN_ROUTE_EVENT_HISTORY_CAPACITY: usize = 4096;

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
        Self {
            ribs: HashMap::new(),
            loc_rib: LocRib::new(),
            adj_ribs_out: HashMap::new(),
            outbound_peers: HashMap::new(),
            export_policy,
            peer_export_policies: HashMap::new(),
            peer_sendable_families: HashMap::new(),
            peer_is_ebgp: HashMap::new(),
            peer_is_rr_client: HashMap::new(),
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
            gr_peers: HashMap::new(),
            gr_stale_deadlines: HashMap::new(),
            gr_stale_routes_time: HashMap::new(),
            llgr_peers: HashMap::new(),
            llgr_stale_deadlines: HashMap::new(),
            llgr_peer_config: HashMap::new(),
            peer_add_path_send_max: HashMap::new(),
            peer_add_path_send_families: HashMap::new(),
            peer_asn: HashMap::new(),
            peer_group: HashMap::new(),
            peer_bgp_id: HashMap::new(),
            vrp_table: None,
            aspa_table: None,
            route_events_tx,
            route_event_history: VecDeque::with_capacity(ROUTE_EVENT_HISTORY_CAPACITY),
            next_route_event_id: 1,
            evpn_events_tx,
            evpn_route_event_history: VecDeque::with_capacity(EVPN_ROUTE_EVENT_HISTORY_CAPACITY),
            metrics,
            rx,
            query_rx,
            pending_route_batches: VecDeque::new(),
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
                announced,
                withdrawn,
                flowspec_announced,
                flowspec_withdrawn,
                evpn_announced,
                evpn_withdrawn,
            } => self.enqueue_routes_received(
                peer,
                announced,
                withdrawn,
                flowspec_announced,
                flowspec_withdrawn,
                evpn_announced,
                evpn_withdrawn,
            ),
            RibUpdate::PeerDown { peer } => self.handle_peer_down(peer),
            RibUpdate::PeerUp {
                peer,
                peer_asn,
                peer_router_id,
                outbound_tx,
                export_policy,
                sendable_families,
                is_ebgp,
                route_reflector_client,
                add_path_send_families,
                add_path_send_max,
            } => self.handle_peer_up(
                peer,
                peer_asn,
                peer_router_id,
                outbound_tx,
                export_policy,
                sendable_families,
                is_ebgp,
                route_reflector_client,
                add_path_send_families,
                add_path_send_max,
            ),
            RibUpdate::SetPeerPolicyContext { peer, peer_group } => {
                self.handle_set_peer_policy_context(peer, peer_group);
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
            RibUpdate::ReplacePeerExportPolicy {
                peer,
                export_policy,
                reply,
            } => self.handle_replace_peer_export_policy(peer, export_policy, reply),
            RibUpdate::RefreshPeerOutbound { peer, reply } => {
                self.handle_refresh_peer_outbound(peer, reply);
            }
            RibUpdate::EndOfRib { peer, afi, safi } => self.handle_end_of_rib(peer, afi, safi),
            RibUpdate::RouteRefreshRequest { peer, afi, safi } => {
                self.handle_route_refresh_request(peer, afi, safi);
            }
            RibUpdate::BeginRouteRefresh { peer, afi, safi } => {
                self.handle_begin_route_refresh(peer, afi, safi);
            }
            RibUpdate::EndRouteRefresh { peer, afi, safi } => {
                self.handle_end_route_refresh(peer, afi, safi);
            }
            RibUpdate::PeerGracefulRestart {
                peer,
                restart_time,
                stale_routes_time,
                gr_families,
                peer_llgr_capable,
                peer_llgr_families,
                llgr_stale_time,
            } => self.handle_peer_graceful_restart(
                peer,
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

        let explanation = Self::explain_single_best_prefix(
            &self.loc_rib,
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
        );

        if reply.send(Some(explanation)).is_err() {
            warn!("query caller dropped before receiving response");
        }
    }

    #[expect(clippy::too_many_lines)]
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

                let mut next_rank: u32 = 1;
                for cand in &filtered {
                    if (next_rank as usize) > limit {
                        break;
                    }
                    let aspath_str = cand
                        .as_path()
                        .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string);
                    let aspath_len = cand.as_path().map_or(0, rustbgpd_wire::AsPath::len);
                    let ctx = RouteContext {
                        prefix,
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

        let candidates = if let Some(ref best_route) = best {
            all_candidates
                .drain(..)
                .filter(|c| !(c.peer == best_route.peer && c.path_id == best_route.path_id))
                .map(|candidate| {
                    let (ordering, reason) = best_path_cmp_with_reason(&candidate, best_route);
                    let advertised_path_id = advertised_rank
                        .get(&(candidate.peer, candidate.path_id))
                        .copied()
                        .unwrap_or(0);
                    BestPathCandidate {
                        route: candidate,
                        vs_best_reason: reason,
                        vs_best_ordering: ordering,
                        advertised_path_id,
                    }
                })
                .collect()
        } else {
            vec![]
        };

        let explanation = ExplainBestPath {
            prefix,
            best,
            candidates,
            peer,
            add_path_send_max,
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
        self.next_route_event_id = self
            .next_route_event_id
            .checked_add(1)
            .expect("route event id space exhausted");
        if self.route_event_history.len() == ROUTE_EVENT_HISTORY_CAPACITY {
            self.route_event_history.pop_front();
        }
        self.route_event_history.push_back(event.clone());
        self.metrics.set_route_event_history_depth(
            i64::try_from(self.route_event_history.len()).unwrap_or(i64::MAX),
        );
        let _ = self.route_events_tx.send(event);
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
                Some(peer) => event.peer == Some(peer) || event.previous_peer == Some(peer),
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

    fn handle_query_flowspec_routes(
        &mut self,
        reply: tokio::sync::oneshot::Sender<Vec<crate::route::FlowSpecRoute>>,
    ) {
        let routes: Vec<_> = self.loc_rib.iter_flowspec().cloned().collect();
        if reply.send(routes).is_err() {
            warn!("FlowSpec query caller dropped before receiving response");
        }
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
                    resync_armed = false;
                } else {
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
                            resync_armed = false;
                        } else {
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
