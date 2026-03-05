mod distribution;
mod graceful_restart;
mod helpers;
mod peer_lifecycle;
mod route_refresh;

#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
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
use crate::event::RouteEvent;
use crate::loc_rib::LocRib;
use crate::update::{OutboundRouteUpdate, RibUpdate};

use helpers::{
    DIRTY_RESYNC_INTERVAL, ERR_REFRESH_TIMEOUT, LOCAL_PEER, LlgrPeerConfig, gauge_val,
    prefix_family, validate_route_rpki,
};

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
    /// Peer BGP router ID, tracked for MRT `PEER_INDEX_TABLE`.
    peer_bgp_id: HashMap<IpAddr, Ipv4Addr>,
    /// Families for which Add-Path Send/Both was negotiated per peer.
    peer_add_path_send_families: HashMap<IpAddr, Vec<(Afi, Safi)>>,
    /// Current RPKI VRP table for origin validation. `None` = no RPKI data.
    vrp_table: Option<Arc<VrpTable>>,
    route_events_tx: broadcast::Sender<RouteEvent>,
    metrics: BgpMetrics,
    rx: mpsc::Receiver<RibUpdate>,
}

impl RibManager {
    #[must_use]
    pub fn new(
        rx: mpsc::Receiver<RibUpdate>,
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
            peer_bgp_id: HashMap::new(),
            vrp_table: None,
            route_events_tx,
            metrics,
            rx,
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
        self.peer_export_policies
            .get(&peer)
            .and_then(|p| p.as_ref())
            .or(self.export_policy.as_ref())
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

    /// Process a single `RibUpdate` message.
    #[expect(clippy::too_many_lines)]
    fn handle_update(&mut self, update: RibUpdate) {
        match update {
            RibUpdate::RoutesReceived {
                peer,
                announced,
                withdrawn,
                flowspec_announced,
                flowspec_withdrawn,
            } => {
                let active_refresh = self
                    .refresh_in_progress
                    .get(&peer)
                    .cloned()
                    .unwrap_or_default();
                let rib = self.ribs.entry(peer).or_insert_with(|| AdjRibIn::new(peer));
                let mut affected = HashSet::new();

                for &(prefix, path_id) in &withdrawn {
                    if rib.withdraw(&prefix, path_id) {
                        debug!(%peer, %prefix, path_id, "withdrawn");
                        affected.insert(prefix);
                    }
                    if active_refresh.contains(&prefix_family(&prefix))
                        && let Some(stale) = self.refresh_stale_routes.get_mut(&peer)
                    {
                        stale.remove(&(prefix, path_id));
                    }
                }

                for mut route in announced {
                    if let Some(ref table) = self.vrp_table {
                        route.validation_state = validate_route_rpki(&route, table);
                    }
                    debug!(%peer, prefix = %route.prefix, "announced");
                    affected.insert(route.prefix);
                    let prefix = route.prefix;
                    let path_id = route.path_id;
                    rib.insert(route);
                    if active_refresh.contains(&prefix_family(&prefix))
                        && let Some(stale) = self.refresh_stale_routes.get_mut(&peer)
                    {
                        stale.remove(&(prefix, path_id));
                    }
                }

                // FlowSpec routes
                let mut fs_affected: HashSet<rustbgpd_wire::FlowSpecRule> = HashSet::new();
                for rule in &flowspec_withdrawn {
                    if rib.withdraw_flowspec(rule, 0) {
                        debug!(%peer, rule = %rule, "flowspec withdrawn");
                        fs_affected.insert(rule.clone());
                    }
                    if active_refresh.iter().any(|(afi, safi)| {
                        *safi == Safi::FlowSpec && matches!(afi, Afi::Ipv4 | Afi::Ipv6)
                    }) && let Some(stale) = self.refresh_stale_flowspec.get_mut(&peer)
                    {
                        stale.retain(|(_, stale_rule, _)| stale_rule != rule);
                    }
                }
                for route in flowspec_announced {
                    debug!(%peer, rule = %route.rule, "flowspec announced");
                    let stale_key = (route.afi, route.rule.clone(), route.path_id);
                    fs_affected.insert(route.rule.clone());
                    rib.insert_flowspec(route);
                    if active_refresh.contains(&(stale_key.0, Safi::FlowSpec))
                        && let Some(stale) = self.refresh_stale_flowspec.get_mut(&peer)
                    {
                        stale.remove(&stale_key);
                    }
                }

                debug!(%peer, routes = rib.len(), "rib updated");
                let peer_label = peer.to_string();
                self.metrics
                    .set_rib_prefixes(&peer_label, "all", gauge_val(rib.len()));
                self.metrics.set_rib_prefixes(
                    &peer_label,
                    "flowspec",
                    gauge_val(rib.flowspec_len()),
                );
                let changed = self.recompute_best(&affected);
                self.distribute_changes(&changed, &affected);

                if !fs_affected.is_empty() {
                    self.recompute_and_distribute_flowspec(&fs_affected);
                }
            }

            RibUpdate::PeerDown { peer } => {
                // If GR was active for this peer, abort it and sweep stale routes
                if self.gr_peers.remove(&peer).is_some() {
                    self.gr_stale_deadlines.remove(&peer);
                    self.gr_stale_routes_time.remove(&peer);
                    self.llgr_peer_config.remove(&peer);
                    info!(%peer, "peer down during graceful restart — aborting GR");
                    let peer_label = peer.to_string();
                    self.metrics.set_gr_active(&peer_label, false);
                    self.metrics.set_gr_stale_routes(&peer_label, 0);
                }

                // If LLGR was active for this peer, abort it
                if self.llgr_peers.remove(&peer).is_some() {
                    self.llgr_stale_deadlines.remove(&peer);
                    info!(%peer, "peer down during LLGR — aborting LLGR");
                    let peer_label = peer.to_string();
                    self.metrics.set_gr_active(&peer_label, false);
                    self.metrics.set_gr_stale_routes(&peer_label, 0);
                }

                if let Some(rib) = self.ribs.get_mut(&peer) {
                    let affected: HashSet<Prefix> = rib.iter().map(|r| r.prefix).collect();
                    let count = rib.len();
                    // Collect FlowSpec rules before clearing
                    let fs_affected: HashSet<rustbgpd_wire::FlowSpecRule> =
                        rib.iter_flowspec().map(|r| r.rule.clone()).collect();
                    rib.clear();
                    rib.clear_flowspec();
                    debug!(%peer, cleared = count, "peer down — rib cleared");
                    self.metrics.set_rib_prefixes(&peer.to_string(), "all", 0);
                    let changed = self.recompute_best(&affected);
                    self.distribute_changes(&changed, &affected);
                    if !fs_affected.is_empty() {
                        self.recompute_and_distribute_flowspec(&fs_affected);
                    }
                }
                // Clean up outbound state
                self.adj_ribs_out.remove(&peer);
                self.metrics
                    .set_adj_rib_out_prefixes(&peer.to_string(), "all", 0);
                self.outbound_peers.remove(&peer);
                self.peer_export_policies.remove(&peer);
                self.peer_sendable_families.remove(&peer);
                self.peer_is_ebgp.remove(&peer);
                self.peer_is_rr_client.remove(&peer);
                self.peer_add_path_send_max.remove(&peer);
                self.peer_add_path_send_families.remove(&peer);
                self.peer_asn.remove(&peer);
                self.peer_bgp_id.remove(&peer);
                self.dirty_peers.remove(&peer);
                self.pending_eor.remove(&peer);
                self.clear_peer_refresh_state(peer);
            }

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
            } => {
                self.peer_asn.insert(peer, peer_asn);
                self.peer_bgp_id.insert(peer, peer_router_id);
                // If the peer re-establishes during graceful restart, keep
                // routes stale and wait for End-of-RIB per family (RFC 4724
                // §4.2).  Reset the timer from restart_time (session window)
                // to stale_routes_time (EoR window).
                if self.gr_peers.contains_key(&peer) {
                    if let Some(&srt) = self.gr_stale_routes_time.get(&peer) {
                        let deadline =
                            tokio::time::Instant::now() + std::time::Duration::from_secs(srt);
                        self.gr_stale_deadlines.insert(peer, deadline);
                    }
                    info!(%peer, "peer re-established during GR — waiting for End-of-RIB");
                } else if self.llgr_peers.contains_key(&peer) {
                    // Peer re-established during LLGR — promote LLGR families
                    // back to GR-awaiting-EoR so EndOfRib clears the stale flag.
                    if let Some(llgr_families) = self.llgr_peers.remove(&peer) {
                        self.llgr_stale_deadlines.remove(&peer);
                        // Recover configured stale_routes_time from LLGR config
                        let srt = self
                            .llgr_peer_config
                            .get(&peer)
                            .map_or(360, |c| c.stale_routes_time);
                        self.gr_stale_routes_time.insert(peer, srt);
                        self.gr_peers.insert(peer, llgr_families);
                        let deadline =
                            tokio::time::Instant::now() + std::time::Duration::from_secs(srt);
                        self.gr_stale_deadlines.insert(peer, deadline);
                        info!(%peer, stale_routes_time = srt, "peer re-established during LLGR — waiting for End-of-RIB");
                    }
                }

                debug!(%peer, "peer up — registering for outbound updates");
                let peer_label = peer.to_string();
                self.metrics.set_rib_prefixes(&peer_label, "all", 0);
                self.metrics.set_adj_rib_out_prefixes(&peer_label, "all", 0);
                self.outbound_peers.insert(peer, outbound_tx);
                self.peer_export_policies.insert(peer, export_policy);
                self.peer_sendable_families.insert(peer, sendable_families);
                self.peer_is_ebgp.insert(peer, is_ebgp);
                self.peer_is_rr_client.insert(peer, route_reflector_client);
                self.peer_add_path_send_families
                    .insert(peer, add_path_send_families);
                self.peer_add_path_send_max.insert(peer, add_path_send_max);
                self.send_initial_table(peer);
            }

            RibUpdate::InjectRoute { route, reply } => {
                let prefix = route.prefix;
                let rib = self
                    .ribs
                    .entry(LOCAL_PEER)
                    .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
                rib.insert(route);
                debug!(%prefix, "injected local route");
                self.metrics
                    .set_rib_prefixes(&LOCAL_PEER.to_string(), "all", gauge_val(rib.len()));

                let mut affected = HashSet::new();
                affected.insert(prefix);
                let changed = self.recompute_best(&affected);
                self.distribute_changes(&changed, &affected);

                let _ = reply.send(Ok(()));
            }

            RibUpdate::WithdrawInjected {
                prefix,
                path_id,
                reply,
            } => {
                let rib = self
                    .ribs
                    .entry(LOCAL_PEER)
                    .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
                if rib.withdraw(&prefix, path_id) {
                    debug!(%prefix, "withdrawn injected route");
                    self.metrics.set_rib_prefixes(
                        &LOCAL_PEER.to_string(),
                        "all",
                        gauge_val(rib.len()),
                    );
                    let mut affected = HashSet::new();
                    affected.insert(prefix);
                    let changed = self.recompute_best(&affected);
                    self.distribute_changes(&changed, &affected);
                    let _ = reply.send(Ok(()));
                } else {
                    let _ = reply.send(Err(format!("prefix {prefix} not found")));
                }
            }

            RibUpdate::QueryReceivedRoutes { peer, reply } => {
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

            RibUpdate::QueryBestRoutes { reply } => {
                let routes: Vec<_> = self.loc_rib.iter().cloned().collect();
                if reply.send(routes).is_err() {
                    warn!("query caller dropped before receiving response");
                }
            }

            RibUpdate::QueryAdvertisedRoutes { peer, reply } => {
                let routes: Vec<_> = self
                    .adj_ribs_out
                    .get(&peer)
                    .map(|rib| rib.iter().cloned().collect())
                    .unwrap_or_default();

                if reply.send(routes).is_err() {
                    warn!("query caller dropped before receiving response");
                }
            }

            RibUpdate::SubscribeRouteEvents { reply } => {
                let rx = self.route_events_tx.subscribe();
                let _ = reply.send(rx);
            }

            RibUpdate::QueryLocRibCount { reply } => {
                let _ = reply.send(self.loc_rib.len());
            }

            RibUpdate::QueryAdvertisedCount { peer, reply } => {
                let count = self.adj_ribs_out.get(&peer).map_or(0, AdjRibOut::len);
                let _ = reply.send(count);
            }

            RibUpdate::EndOfRib { peer, afi, safi } => {
                info!(%peer, ?afi, ?safi, "received End-of-RIB");
                let is_gr_peer = self.gr_peers.contains_key(&peer);
                let is_llgr_peer = self.llgr_peers.contains_key(&peer);
                if !is_gr_peer && !is_llgr_peer {
                    debug!(%peer, ?afi, ?safi, "End-of-RIB received without active GR/LLGR state, ignoring");
                }
                if is_gr_peer {
                    // Remove family from awaiting set
                    if let Some(awaiting) = self.gr_peers.get_mut(&peer) {
                        awaiting.remove(&(afi, safi));
                    }

                    // Clear stale flag on this family's routes
                    if let Some(rib) = self.ribs.get_mut(&peer) {
                        rib.clear_stale((afi, safi));
                    }

                    // Recompute best paths — routes are no longer demoted
                    let affected: HashSet<Prefix> = self
                        .ribs
                        .get(&peer)
                        .map(|rib| rib.iter().map(|r| r.prefix).collect())
                        .unwrap_or_default();
                    let changed = self.recompute_best(&affected);
                    self.distribute_changes(&changed, &affected);

                    // Update stale routes metric after partial clear
                    let peer_label = peer.to_string();
                    let stale_count = self
                        .ribs
                        .get(&peer)
                        .map_or(0, |rib| rib.iter().filter(|r| r.is_stale).count());
                    self.metrics
                        .set_gr_stale_routes(&peer_label, gauge_val(stale_count));

                    // If all families received EoR, GR is complete
                    let all_done = self.gr_peers.get(&peer).is_some_and(HashSet::is_empty);
                    if all_done {
                        info!(%peer, "graceful restart complete — all End-of-RIB received");
                        self.gr_peers.remove(&peer);
                        self.gr_stale_deadlines.remove(&peer);
                        self.gr_stale_routes_time.remove(&peer);
                        self.llgr_peer_config.remove(&peer);
                        self.metrics.set_gr_active(&peer_label, false);
                        self.metrics.set_gr_stale_routes(&peer_label, 0);
                    }
                } else if is_llgr_peer {
                    // EoR during LLGR phase — clear LLGR-stale flag for this family
                    if let Some(awaiting) = self.llgr_peers.get_mut(&peer) {
                        awaiting.remove(&(afi, safi));
                    }

                    // Clear LLGR-stale flag on this family's routes
                    if let Some(rib) = self.ribs.get_mut(&peer) {
                        rib.clear_llgr_stale((afi, safi));
                    }

                    // Recompute best paths — routes are no longer demoted
                    let affected: HashSet<Prefix> = self
                        .ribs
                        .get(&peer)
                        .map(|rib| rib.iter().map(|r| r.prefix).collect())
                        .unwrap_or_default();
                    let changed = self.recompute_best(&affected);
                    self.distribute_changes(&changed, &affected);

                    let peer_label = peer.to_string();
                    let llgr_stale_count = self
                        .ribs
                        .get(&peer)
                        .map_or(0, |rib| rib.iter().filter(|r| r.is_llgr_stale).count());
                    self.metrics
                        .set_gr_stale_routes(&peer_label, gauge_val(llgr_stale_count));

                    // If all LLGR families received EoR, LLGR is complete
                    let all_done = self.llgr_peers.get(&peer).is_some_and(HashSet::is_empty);
                    if all_done {
                        info!(%peer, "LLGR complete — all End-of-RIB received");
                        self.llgr_peers.remove(&peer);
                        self.llgr_stale_deadlines.remove(&peer);
                        self.metrics.set_gr_active(&peer_label, false);
                        self.metrics.set_gr_stale_routes(&peer_label, 0);
                    }
                }
            }

            RibUpdate::RouteRefreshRequest { peer, afi, safi } => {
                info!(%peer, ?afi, ?safi, "handling route refresh request");
                self.send_route_refresh_response(peer, afi, safi);
            }

            RibUpdate::BeginRouteRefresh { peer, afi, safi } => {
                info!(%peer, ?afi, ?safi, "beginning enhanced route refresh");
                self.refresh_in_progress
                    .entry(peer)
                    .or_default()
                    .insert((afi, safi));
                self.refresh_deadlines.insert(
                    (peer, afi, safi),
                    tokio::time::Instant::now() + ERR_REFRESH_TIMEOUT,
                );
                if let Some(rib) = self.ribs.get(&peer) {
                    if safi == Safi::FlowSpec {
                        let stale = self.refresh_stale_flowspec.entry(peer).or_default();
                        stale.retain(|(stale_afi, _, _)| *stale_afi != afi);
                        for route in rib.iter_flowspec().filter(|route| route.afi == afi) {
                            stale.insert((route.afi, route.rule.clone(), route.path_id));
                        }
                    } else {
                        let stale = self.refresh_stale_routes.entry(peer).or_default();
                        stale.retain(|(prefix, _)| prefix_family(prefix) != (afi, safi));
                        for route in rib
                            .iter()
                            .filter(|route| prefix_family(&route.prefix) == (afi, safi))
                        {
                            stale.insert((route.prefix, route.path_id));
                        }
                    }
                }
            }

            RibUpdate::EndRouteRefresh { peer, afi, safi } => {
                self.finish_route_refresh(peer, afi, safi, false);
            }

            RibUpdate::PeerGracefulRestart {
                peer,
                restart_time,
                stale_routes_time,
                gr_families,
                peer_llgr_capable,
                peer_llgr_families,
                llgr_stale_time,
            } => {
                info!(%peer, restart_time, stale_routes_time, llgr_stale_time, "peer entered graceful restart");

                let mut affected = HashSet::new();

                if let Some(rib) = self.ribs.get_mut(&peer) {
                    // Mark routes stale for families in the GR capability
                    for &family in &gr_families {
                        rib.mark_stale(family);
                    }
                    // Withdraw routes for families NOT in the GR capability
                    let withdrawn = rib.withdraw_families_except(&gr_families);
                    if !withdrawn.is_empty() {
                        info!(%peer, count = withdrawn.len(), "withdrew non-GR family routes");
                    }
                    for prefix in withdrawn {
                        affected.insert(prefix);
                    }
                }

                // Include stale routes in affected set for best-path recompute
                if let Some(rib) = self.ribs.get(&peer) {
                    for route in rib.iter() {
                        affected.insert(route.prefix);
                    }
                    self.metrics
                        .set_rib_prefixes(&peer.to_string(), "all", gauge_val(rib.len()));
                }

                let changed = self.recompute_best(&affected);
                self.distribute_changes(&changed, &affected);

                // Clean up outbound state — peer is down, dead channel would
                // cause wasteful dirty-peer resync attempts.
                self.outbound_peers.remove(&peer);
                self.adj_ribs_out.remove(&peer);
                self.peer_export_policies.remove(&peer);
                self.peer_sendable_families.remove(&peer);
                self.peer_is_ebgp.remove(&peer);
                self.peer_is_rr_client.remove(&peer);
                self.peer_add_path_send_max.remove(&peer);
                self.peer_add_path_send_families.remove(&peer);
                self.dirty_peers.remove(&peer);
                self.pending_eor.remove(&peer);
                self.clear_peer_refresh_state(peer);

                // Initial timer = restart_time (window for session re-establishment).
                // On PeerUp, this is reset to stale_routes_time for EoR.
                let deadline = tokio::time::Instant::now()
                    + std::time::Duration::from_secs(u64::from(restart_time));
                self.gr_stale_deadlines.insert(peer, deadline);
                self.gr_stale_routes_time.insert(peer, stale_routes_time);

                // Record awaiting families
                self.gr_peers
                    .insert(peer, gr_families.into_iter().collect());

                // Store LLGR config for two-phase timer
                if peer_llgr_capable && llgr_stale_time > 0 {
                    self.llgr_peer_config.insert(
                        peer,
                        LlgrPeerConfig {
                            peer_llgr_capable,
                            peer_llgr_families,
                            local_llgr_stale_time: llgr_stale_time,
                            stale_routes_time,
                        },
                    );
                }

                // Metrics
                let peer_label = peer.to_string();
                self.metrics.set_gr_active(&peer_label, true);
                let stale_count = self
                    .ribs
                    .get(&peer)
                    .map_or(0, |rib| rib.iter().filter(|r| r.is_stale).count());
                self.metrics
                    .set_gr_stale_routes(&peer_label, gauge_val(stale_count));
            }

            RibUpdate::RpkiCacheUpdate { table } => {
                info!(
                    vrps = table.len(),
                    "RPKI cache update — re-validating routes"
                );
                self.vrp_table = Some(Arc::clone(&table));
                self.metrics
                    .set_rpki_vrp_count("ipv4", gauge_val(table.v4_count()));
                self.metrics
                    .set_rpki_vrp_count("ipv6", gauge_val(table.v6_count()));

                // Re-validate all routes in all Adj-RIB-Ins.
                let mut affected = HashSet::new();
                for rib in self.ribs.values_mut() {
                    for route in rib.iter_mut() {
                        let new_state = validate_route_rpki(route, &table);
                        if route.validation_state != new_state {
                            route.validation_state = new_state;
                            affected.insert(route.prefix);
                        }
                    }
                }

                if !affected.is_empty() {
                    info!(
                        changed = affected.len(),
                        "RPKI re-validation changed routes"
                    );
                    let changed = self.recompute_best(&affected);
                    self.distribute_changes(&changed, &affected);
                }
            }

            RibUpdate::InjectFlowSpec { route, reply } => {
                let rule = route.rule.clone();
                let rib = self
                    .ribs
                    .entry(LOCAL_PEER)
                    .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
                rib.insert_flowspec(route);
                debug!(rule = %rule, "injected local FlowSpec route");
                let mut fs_affected = HashSet::new();
                fs_affected.insert(rule);
                self.recompute_and_distribute_flowspec(&fs_affected);
                let _ = reply.send(Ok(()));
            }

            RibUpdate::WithdrawFlowSpec { rule, reply } => {
                let rib = self
                    .ribs
                    .entry(LOCAL_PEER)
                    .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
                if rib.withdraw_flowspec(&rule, 0) {
                    debug!(rule = %rule, "withdrawn injected FlowSpec route");
                    let mut fs_affected = HashSet::new();
                    fs_affected.insert(rule);
                    self.recompute_and_distribute_flowspec(&fs_affected);
                    let _ = reply.send(Ok(()));
                } else {
                    let _ = reply.send(Err(format!("FlowSpec rule {rule} not found")));
                }
            }

            RibUpdate::QueryFlowSpecRoutes { reply } => {
                let routes: Vec<_> = self.loc_rib.iter_flowspec().cloned().collect();
                if reply.send(routes).is_err() {
                    warn!("FlowSpec query caller dropped before receiving response");
                }
            }

            RibUpdate::QueryMrtSnapshot { reply } => {
                use crate::update::{MrtPeerEntry, MrtSnapshotData};

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

                // TABLE_DUMP_V2 is built from Adj-RIB-In routes per peer.
                // Avoid mixing Loc-RIB winners to prevent duplicate entries.
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
    pub async fn run(mut self) {
        // Persistent timer: starts far in the future (disabled). Reset to
        // DIRTY_RESYNC_INTERVAL when dirty_peers becomes non-empty.
        let resync_sleep = tokio::time::sleep(DIRTY_RESYNC_INTERVAL);
        tokio::pin!(resync_sleep);
        let mut resync_armed = false;

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

            if needs_timers {
                tokio::select! {
                    update = self.rx.recv() => {
                        match update {
                            Some(update) => self.handle_update(update),
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
                // No timers needed — just wait for the next message.
                match self.rx.recv().await {
                    Some(update) => self.handle_update(update),
                    None => break,
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
