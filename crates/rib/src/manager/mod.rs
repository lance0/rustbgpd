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
use crate::event::RouteEvent;
use crate::loc_rib::LocRib;
use crate::update::{MrtPeerEntry, MrtSnapshotData, OutboundRouteUpdate, RibUpdate};

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
    /// `EoR` markers that failed to enqueue and must be retried.
    pending_eor: HashMap<IpAddr, HashSet<(Afi, Safi)>>,
    /// Families still in the initial table-load phase per peer.
    initial_load_awaiting: HashMap<IpAddr, HashSet<(Afi, Safi)>>,
    /// Prefixes whose outbound distribution is deferred until initial-load `EoR`.
    initial_load_affected: HashMap<IpAddr, HashSet<Prefix>>,
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
    route_events_tx: broadcast::Sender<RouteEvent>,
    metrics: BgpMetrics,
    rx: mpsc::Receiver<RibUpdate>,
    /// Priority channel for read-only queries (gRPC).
    query_rx: mpsc::Receiver<RibUpdate>,
    /// Large route batches that are being processed in chunks.
    pending_route_batches: VecDeque<PendingRoutesReceived>,
}

const ROUTES_RECEIVED_CHUNK_SIZE: usize = 1024;
const QUERY_BUDGET_PER_CHUNK: usize = 8;

enum PendingRouteChunk {
    Withdrawn(Vec<(Prefix, u32)>),
    Announced(Vec<crate::route::Route>),
    FlowSpecWithdrawn(Vec<FlowSpecRule>),
    FlowSpecAnnounced(Vec<crate::route::FlowSpecRoute>),
}

enum PendingRoutePhase {
    Withdrawn,
    Announced,
    FlowSpecWithdrawn,
    FlowSpecAnnounced,
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
    phase: PendingRoutePhase,
}

impl PendingRoutesReceived {
    fn new(
        peer: IpAddr,
        announced: Vec<crate::route::Route>,
        withdrawn: Vec<(Prefix, u32)>,
        flowspec_announced: Vec<crate::route::FlowSpecRoute>,
        flowspec_withdrawn: Vec<FlowSpecRule>,
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
                        self.phase = PendingRoutePhase::Done;
                        continue;
                    }
                    return Some(PendingRouteChunk::FlowSpecAnnounced(chunk));
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
            pending_eor: HashMap::new(),
            initial_load_awaiting: HashMap::new(),
            initial_load_affected: HashMap::new(),
            pending_refresh: HashMap::new(),
            refresh_in_progress: HashMap::new(),
            refresh_deadlines: HashMap::new(),
            refresh_stale_routes: HashMap::new(),
            refresh_stale_flowspec: HashMap::new(),
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
            route_events_tx,
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
            } => self.enqueue_routes_received(
                peer,
                announced,
                withdrawn,
                flowspec_announced,
                flowspec_withdrawn,
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
                peer_gr_capable,
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
                peer_gr_capable,
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
            RibUpdate::QueryAdvertisedRoutes { peer, reply } => {
                self.handle_query_advertised_routes(peer, reply);
            }
            RibUpdate::SubscribeRouteEvents { reply } => {
                self.handle_subscribe_route_events(reply);
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
            RibUpdate::InjectFlowSpec { route, reply } => self.handle_inject_flowspec(route, reply),
            RibUpdate::WithdrawFlowSpec { rule, reply } => {
                self.handle_withdraw_flowspec(rule, reply);
            }
            RibUpdate::QueryFlowSpecRoutes { reply } => {
                self.handle_query_flowspec_routes(reply);
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

    fn handle_subscribe_route_events(
        &mut self,
        reply: tokio::sync::oneshot::Sender<broadcast::Receiver<RouteEvent>>,
    ) {
        let rx = self.route_events_tx.subscribe();
        let _ = reply.send(rx);
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

        let snapshot = MrtSnapshotData { peers, routes };
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
        let gr_sleep = tokio::time::sleep(std::time::Duration::from_secs(86400));
        tokio::pin!(gr_sleep);

        // LLGR stale sweep timer — reset each iteration to the nearest deadline.
        let llgr_sleep = tokio::time::sleep(std::time::Duration::from_secs(86400));
        tokio::pin!(llgr_sleep);

        // Enhanced route refresh timer — reset each iteration to the nearest
        // active refresh deadline.
        let refresh_sleep = tokio::time::sleep(std::time::Duration::from_secs(86400));
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
