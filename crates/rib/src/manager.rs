use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use rustbgpd_policy::{PrefixList, check_prefix_list};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Afi, Prefix, Safi};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info, warn};

use crate::event::{RouteEvent, RouteEventType};

use crate::adj_rib_in::AdjRibIn;
use crate::adj_rib_out::AdjRibOut;
use crate::loc_rib::LocRib;
use crate::update::{OutboundRouteUpdate, RibUpdate};

/// Sentinel peer address for locally-injected routes.
const LOCAL_PEER: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// How long to wait before retrying distribution to dirty peers.
const DIRTY_RESYNC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Safe cast from usize to i64 for gauge metrics.
#[expect(clippy::cast_possible_wrap)]
fn gauge_val(n: usize) -> i64 {
    n as i64
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
    export_policy: Option<PrefixList>,
    peer_export_policies: HashMap<IpAddr, Option<PrefixList>>,
    /// Families the transport can actually serialize per peer.
    peer_sendable_families: HashMap<IpAddr, Vec<(Afi, Safi)>>,
    /// Peers that failed a `try_send()` and need a full export resync.
    dirty_peers: HashSet<IpAddr>,
    /// Peers currently undergoing graceful restart, keyed by peer address.
    /// Value is the set of (AFI, SAFI) families still awaiting End-of-RIB.
    gr_peers: HashMap<IpAddr, HashSet<(Afi, Safi)>>,
    /// Deadlines for sweeping stale routes per GR peer.
    gr_stale_deadlines: HashMap<IpAddr, tokio::time::Instant>,
    /// Configured stale-routes-time per GR peer (seconds), used to reset
    /// the timer on `PeerUp` during graceful restart.
    gr_stale_routes_time: HashMap<IpAddr, u64>,
    route_events_tx: broadcast::Sender<RouteEvent>,
    metrics: BgpMetrics,
    rx: mpsc::Receiver<RibUpdate>,
}

impl RibManager {
    #[must_use]
    pub fn new(
        rx: mpsc::Receiver<RibUpdate>,
        export_policy: Option<PrefixList>,
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
            dirty_peers: HashSet::new(),
            gr_peers: HashMap::new(),
            gr_stale_deadlines: HashMap::new(),
            gr_stale_routes_time: HashMap::new(),
            route_events_tx,
            metrics,
            rx,
        }
    }

    /// Resolve the export policy for a peer: per-peer if set, else global.
    fn export_policy_for(&self, peer: IpAddr) -> Option<&PrefixList> {
        self.peer_export_policies
            .get(&peer)
            .and_then(|p| p.as_ref())
            .or(self.export_policy.as_ref())
    }

    /// Check whether a prefix's AFI is sendable for a given peer.
    fn is_prefix_sendable(&self, peer: IpAddr, prefix: &Prefix) -> bool {
        let family = match prefix {
            Prefix::V4(_) => (Afi::Ipv4, Safi::Unicast),
            Prefix::V6(_) => (Afi::Ipv6, Safi::Unicast),
        };
        self.peer_sendable_families
            .get(&peer)
            .is_some_and(|fams| fams.contains(&family))
    }

    /// Recompute Loc-RIB best path for a set of affected prefixes.
    /// Returns the set of prefixes that actually changed.
    /// Also emits route events to the broadcast channel.
    fn recompute_best(&mut self, affected: &HashSet<Prefix>) -> HashSet<Prefix> {
        let mut changed = HashSet::new();
        for prefix in affected {
            let previous_best_peer = self.loc_rib.get(prefix).map(|r| r.peer);
            let candidates: Vec<_> = self
                .ribs
                .values()
                .filter_map(|rib| rib.get(prefix))
                .collect();
            let did_change = self.loc_rib.recompute(*prefix, candidates.into_iter());
            if did_change {
                changed.insert(*prefix);
                let current_best = self.loc_rib.get(prefix);
                match (previous_best_peer, current_best) {
                    (None, Some(best)) => {
                        debug!(%prefix, peer = %best.peer, "best path added");
                        let _ = self.route_events_tx.send(RouteEvent {
                            event_type: RouteEventType::Added,
                            prefix: *prefix,
                            peer: Some(best.peer),
                            previous_peer: None,
                            timestamp: crate::event::unix_timestamp_now(),
                        });
                    }
                    (Some(old_peer), None) => {
                        debug!(%prefix, "best path removed");
                        let _ = self.route_events_tx.send(RouteEvent {
                            event_type: RouteEventType::Withdrawn,
                            prefix: *prefix,
                            peer: None,
                            previous_peer: Some(old_peer),
                            timestamp: crate::event::unix_timestamp_now(),
                        });
                    }
                    (Some(old_peer), Some(best)) => {
                        debug!(%prefix, peer = %best.peer, "best path changed");
                        let _ = self.route_events_tx.send(RouteEvent {
                            event_type: RouteEventType::BestChanged,
                            prefix: *prefix,
                            peer: Some(best.peer),
                            previous_peer: Some(old_peer),
                            timestamp: crate::event::unix_timestamp_now(),
                        });
                    }
                    (None, None) => {}
                }
            }
        }
        self.metrics
            .set_loc_rib_prefixes("all", gauge_val(self.loc_rib.len()));
        changed
    }

    /// Distribute Loc-RIB changes to all registered outbound peers.
    ///
    /// For clean peers, only `changed_prefixes` are evaluated. Dirty peers
    /// (those that failed a previous `try_send()`) get a full export resync:
    /// all Loc-RIB and `AdjRibOut` prefixes are diffed to bring the peer's
    /// view back in sync. `AdjRibOut` is only committed after a successful
    /// channel send; on failure the peer stays dirty for retry via the
    /// resync timer.
    ///
    /// Routes are filtered by `sendable_families` (set at `PeerUp` time)
    /// so that Adj-RIB-Out only contains routes the transport can actually
    /// serialize for this peer. The transport retains `is_family_negotiated`
    /// as a safety net.
    fn distribute_changes(&mut self, changed_prefixes: &HashSet<Prefix>) {
        if changed_prefixes.is_empty() && self.dirty_peers.is_empty() {
            return;
        }

        let peers: Vec<IpAddr> = self.outbound_peers.keys().copied().collect();
        for peer in peers {
            // For dirty peers, compute full prefix set from Loc-RIB + AdjRibOut
            let is_dirty = self.dirty_peers.contains(&peer);
            let effective_prefixes: HashSet<Prefix> = if is_dirty {
                let mut all: HashSet<Prefix> = self.loc_rib.iter().map(|r| r.prefix).collect();
                if let Some(rib_out) = self.adj_ribs_out.get(&peer) {
                    all.extend(rib_out.iter().map(|r| r.prefix));
                }
                all
            } else if changed_prefixes.is_empty() {
                continue;
            } else {
                changed_prefixes.clone()
            };

            let mut announce = Vec::new();
            let mut withdraw = Vec::new();

            // Resolve export policy and sendable families before borrowing rib_out
            let export_pol = self.export_policy_for(peer).cloned();
            let sendable = self.peer_sendable_families.get(&peer).cloned();

            let rib_out = self
                .adj_ribs_out
                .entry(peer)
                .or_insert_with(|| AdjRibOut::new(peer));

            // Stage: compute delta without mutating AdjRibOut
            for prefix in &effective_prefixes {
                if let Some(best) = self.loc_rib.get(prefix) {
                    // Split horizon: don't send route back to its source
                    if best.peer == peer {
                        if rib_out.get(prefix).is_some() {
                            withdraw.push(*prefix);
                        }
                        continue;
                    }

                    // Sendable family check: skip routes whose AFI the
                    // transport cannot serialize for this peer.
                    let family = match prefix {
                        Prefix::V4(_) => (Afi::Ipv4, Safi::Unicast),
                        Prefix::V6(_) => (Afi::Ipv6, Safi::Unicast),
                    };
                    if !sendable.as_ref().is_some_and(|f| f.contains(&family)) {
                        if rib_out.get(prefix).is_some() {
                            withdraw.push(*prefix);
                        }
                        continue;
                    }

                    // Export policy check (per-peer or global)
                    if check_prefix_list(export_pol.as_ref(), *prefix)
                        != rustbgpd_policy::PolicyAction::Permit
                    {
                        if rib_out.get(prefix).is_some() {
                            withdraw.push(*prefix);
                        }
                        continue;
                    }

                    // Advertise (or re-advertise if already in Adj-RIB-Out)
                    announce.push(best.clone());
                } else {
                    // Best path removed — withdraw if previously advertised
                    if rib_out.get(prefix).is_some() {
                        withdraw.push(*prefix);
                    }
                }
            }

            if (!announce.is_empty() || !withdraw.is_empty())
                && let Some(tx) = self.outbound_peers.get(&peer)
            {
                let update = OutboundRouteUpdate {
                    announce: announce.clone(),
                    withdraw: withdraw.clone(),
                    end_of_rib: vec![],
                };
                if tx.try_send(update).is_err() {
                    warn!(%peer, "outbound channel full or closed — marking dirty for resync");
                    self.metrics.record_outbound_route_drop(&peer.to_string());
                    self.dirty_peers.insert(peer);
                } else {
                    // Commit: apply staged mutations to AdjRibOut
                    let rib_out = self
                        .adj_ribs_out
                        .get_mut(&peer)
                        .expect("rib_out just accessed");
                    for route in &announce {
                        rib_out.insert(route.clone());
                    }
                    for prefix in &withdraw {
                        rib_out.withdraw(prefix);
                    }
                    self.metrics.set_adj_rib_out_prefixes(
                        &peer.to_string(),
                        "all",
                        gauge_val(rib_out.len()),
                    );
                    if is_dirty {
                        self.dirty_peers.remove(&peer);
                    }
                }
            } else if is_dirty && announce.is_empty() && withdraw.is_empty() {
                // Dirty peer with no diff — already in sync
                self.dirty_peers.remove(&peer);
            }
        }
    }

    /// Send the full Loc-RIB to a newly established peer (initial table dump).
    ///
    /// `AdjRibOut` is only populated after a successful channel send. On
    /// failure the peer is marked dirty so `distribute_changes()` will
    /// retry a full resync via the resync timer.
    fn send_initial_table(&mut self, peer: IpAddr) {
        let mut announce = Vec::new();
        let export_pol = self.export_policy_for(peer).cloned();

        // Stage: collect eligible routes without mutating AdjRibOut
        for route in self.loc_rib.iter() {
            // Split horizon
            if route.peer == peer {
                continue;
            }
            // Sendable family check
            if !self.is_prefix_sendable(peer, &route.prefix) {
                continue;
            }
            // Export policy (per-peer or global)
            if check_prefix_list(export_pol.as_ref(), route.prefix)
                != rustbgpd_policy::PolicyAction::Permit
            {
                continue;
            }
            announce.push(route.clone());
        }

        // Determine EoR families from this peer's sendable families
        let eor_families = self
            .peer_sendable_families
            .get(&peer)
            .cloned()
            .unwrap_or_default();

        if let Some(tx) = self.outbound_peers.get(&peer) {
            if !announce.is_empty() {
                let update = OutboundRouteUpdate {
                    announce: announce.clone(),
                    withdraw: vec![],
                    end_of_rib: vec![],
                };
                if tx.try_send(update).is_err() {
                    warn!(%peer, "outbound channel full or closed during initial dump — marking dirty");
                    self.metrics.record_outbound_route_drop(&peer.to_string());
                    self.dirty_peers.insert(peer);
                    return;
                }
                // Commit: populate AdjRibOut with what was actually sent
                let rib_out = self
                    .adj_ribs_out
                    .entry(peer)
                    .or_insert_with(|| AdjRibOut::new(peer));
                for route in &announce {
                    rib_out.insert(route.clone());
                }
                self.metrics.set_adj_rib_out_prefixes(
                    &peer.to_string(),
                    "all",
                    gauge_val(rib_out.len()),
                );
            }

            // Send End-of-RIB markers for all sendable families
            if !eor_families.is_empty() {
                let eor = OutboundRouteUpdate {
                    announce: vec![],
                    withdraw: vec![],
                    end_of_rib: eor_families,
                };
                if tx.try_send(eor).is_err() {
                    debug!(%peer, "outbound channel full — EoR will be sent on resync");
                }
            }
        }
    }

    /// Process a single `RibUpdate` message.
    #[expect(clippy::too_many_lines)]
    fn handle_update(&mut self, update: RibUpdate) {
        match update {
            RibUpdate::RoutesReceived {
                peer,
                announced,
                withdrawn,
            } => {
                let rib = self.ribs.entry(peer).or_insert_with(|| AdjRibIn::new(peer));
                let mut affected = HashSet::new();

                for prefix in &withdrawn {
                    if rib.withdraw(prefix) {
                        debug!(%peer, %prefix, "withdrawn");
                        affected.insert(*prefix);
                    }
                }

                for route in announced {
                    debug!(%peer, prefix = %route.prefix, "announced");
                    affected.insert(route.prefix);
                    rib.insert(route);
                }

                debug!(%peer, routes = rib.len(), "rib updated");
                self.metrics
                    .set_rib_prefixes(&peer.to_string(), "all", gauge_val(rib.len()));
                let changed = self.recompute_best(&affected);
                self.distribute_changes(&changed);
            }

            RibUpdate::PeerDown { peer } => {
                // If GR was active for this peer, abort it and sweep stale routes
                if self.gr_peers.remove(&peer).is_some() {
                    self.gr_stale_deadlines.remove(&peer);
                    self.gr_stale_routes_time.remove(&peer);
                    info!(%peer, "peer down during graceful restart — aborting GR");
                    let peer_label = peer.to_string();
                    self.metrics.set_gr_active(&peer_label, false);
                    self.metrics.set_gr_stale_routes(&peer_label, 0);
                }

                if let Some(rib) = self.ribs.get_mut(&peer) {
                    let affected: HashSet<Prefix> = rib.iter().map(|r| r.prefix).collect();
                    let count = rib.len();
                    rib.clear();
                    debug!(%peer, cleared = count, "peer down — rib cleared");
                    self.metrics.set_rib_prefixes(&peer.to_string(), "all", 0);
                    let changed = self.recompute_best(&affected);
                    self.distribute_changes(&changed);
                }
                // Clean up outbound state
                self.adj_ribs_out.remove(&peer);
                self.metrics
                    .set_adj_rib_out_prefixes(&peer.to_string(), "all", 0);
                self.outbound_peers.remove(&peer);
                self.peer_export_policies.remove(&peer);
                self.peer_sendable_families.remove(&peer);
                self.dirty_peers.remove(&peer);
            }

            RibUpdate::PeerUp {
                peer,
                outbound_tx,
                export_policy,
                sendable_families,
            } => {
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
                }

                debug!(%peer, "peer up — registering for outbound updates");
                let peer_label = peer.to_string();
                self.metrics.set_rib_prefixes(&peer_label, "all", 0);
                self.metrics.set_adj_rib_out_prefixes(&peer_label, "all", 0);
                self.outbound_peers.insert(peer, outbound_tx);
                self.peer_export_policies.insert(peer, export_policy);
                self.peer_sendable_families.insert(peer, sendable_families);
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
                self.distribute_changes(&changed);

                let _ = reply.send(Ok(()));
            }

            RibUpdate::WithdrawInjected { prefix, reply } => {
                let rib = self
                    .ribs
                    .entry(LOCAL_PEER)
                    .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
                if rib.withdraw(&prefix) {
                    debug!(%prefix, "withdrawn injected route");
                    self.metrics.set_rib_prefixes(
                        &LOCAL_PEER.to_string(),
                        "all",
                        gauge_val(rib.len()),
                    );
                    let mut affected = HashSet::new();
                    affected.insert(prefix);
                    let changed = self.recompute_best(&affected);
                    self.distribute_changes(&changed);
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
                    self.distribute_changes(&changed);

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
                        self.metrics.set_gr_active(&peer_label, false);
                        self.metrics.set_gr_stale_routes(&peer_label, 0);
                    }
                }
            }

            RibUpdate::PeerGracefulRestart {
                peer,
                restart_time,
                stale_routes_time,
                gr_families,
            } => {
                info!(%peer, restart_time, stale_routes_time, "peer entered graceful restart");

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
                self.distribute_changes(&changed);

                // Clean up outbound state — peer is down, dead channel would
                // cause wasteful dirty-peer resync attempts.
                self.outbound_peers.remove(&peer);
                self.adj_ribs_out.remove(&peer);
                self.peer_export_policies.remove(&peer);
                self.peer_sendable_families.remove(&peer);
                self.dirty_peers.remove(&peer);

                // Initial timer = restart_time (window for session re-establishment).
                // On PeerUp, this is reset to stale_routes_time for EoR.
                let deadline = tokio::time::Instant::now()
                    + std::time::Duration::from_secs(u64::from(restart_time));
                self.gr_stale_deadlines.insert(peer, deadline);
                self.gr_stale_routes_time.insert(peer, stale_routes_time);

                // Record awaiting families
                self.gr_peers
                    .insert(peer, gr_families.into_iter().collect());

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
        }
    }

    /// Sweep stale routes for a peer whose GR timer has expired.
    fn sweep_gr_stale(&mut self, peer: IpAddr) {
        info!(%peer, "graceful restart timer expired — sweeping stale routes");
        self.gr_peers.remove(&peer);
        self.gr_stale_deadlines.remove(&peer);
        self.gr_stale_routes_time.remove(&peer);
        let peer_label = peer.to_string();
        self.metrics.record_gr_timer_expired(&peer_label);
        self.metrics.set_gr_active(&peer_label, false);
        self.metrics.set_gr_stale_routes(&peer_label, 0);

        if let Some(rib) = self.ribs.get_mut(&peer) {
            let swept = rib.sweep_stale();
            if !swept.is_empty() {
                info!(%peer, count = swept.len(), "swept stale routes");
                let affected: HashSet<Prefix> = swept.into_iter().collect();
                self.metrics
                    .set_rib_prefixes(&peer.to_string(), "all", gauge_val(rib.len()));
                let changed = self.recompute_best(&affected);
                self.distribute_changes(&changed);
            }
        }
    }

    /// Find the nearest GR stale deadline, if any.
    fn next_gr_deadline(&self) -> Option<tokio::time::Instant> {
        self.gr_stale_deadlines.values().copied().min()
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

            let needs_timers = resync_armed || has_gr_timers;

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
                        self.distribute_changes(&HashSet::new());

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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    use rustbgpd_wire::{
        Afi, AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute, Prefix, Safi,
    };
    use tokio::sync::oneshot;

    use super::*;
    use crate::route::Route;

    /// Default sendable families for IPv4-only test peers.
    fn ipv4_sendable() -> Vec<(Afi, Safi)> {
        vec![(Afi::Ipv4, Safi::Unicast)]
    }

    /// Sendable families for dual-stack test peers.
    fn dual_stack_sendable() -> Vec<(Afi, Safi)> {
        vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)]
    }

    /// Drain the initial End-of-RIB marker sent at `PeerUp` time.
    async fn drain_eor(out_rx: &mut mpsc::Receiver<OutboundRouteUpdate>) {
        let eor = out_rx.recv().await.unwrap();
        assert!(eor.announce.is_empty());
        assert!(eor.withdraw.is_empty());
        assert!(!eor.end_of_rib.is_empty());
    }

    fn make_route(prefix: Ipv4Prefix, next_hop: Ipv4Addr) -> Route {
        Route {
            prefix: Prefix::V4(prefix),
            next_hop: IpAddr::V4(next_hop),
            peer: IpAddr::V4(next_hop),
            attributes: vec![],
            received_at: Instant::now(),
            is_ebgp: true,
            is_stale: false,
        }
    }

    fn make_route_with_lp(prefix: Ipv4Prefix, peer: Ipv4Addr, local_pref: u32) -> Route {
        Route {
            prefix: Prefix::V4(prefix),
            next_hop: IpAddr::V4(peer),
            peer: IpAddr::V4(peer),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65001])],
                }),
                PathAttribute::LocalPref(local_pref),
            ],
            received_at: Instant::now(),
            is_ebgp: true,
            is_stale: false,
        }
    }

    #[tokio::test]
    async fn routes_received_and_queried() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();

        let routes = reply_rx.await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, Prefix::V4(prefix));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn peer_down_clears_routes() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::PeerDown { peer }).await.unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();

        let routes = reply_rx.await.unwrap();
        assert!(routes.is_empty());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn withdrawal_removes_route() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![
                make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1)),
                make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1)),
            ],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![],
            withdrawn: vec![Prefix::V4(prefix1)],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();

        let routes = reply_rx.await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, Prefix::V4(prefix2));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn query_all_peers() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_route(
                Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24),
                Ipv4Addr::new(10, 0, 0, 1),
            )],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_route(
                Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24),
                Ipv4Addr::new(10, 0, 0, 2),
            )],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryReceivedRoutes {
            peer: None,
            reply: reply_tx,
        })
        .await
        .unwrap();

        let routes = reply_rx.await.unwrap();
        assert_eq!(routes.len(), 2);

        drop(tx);
        handle.await.unwrap();
    }

    // --- Loc-RIB integration tests ---

    #[tokio::test]
    async fn best_routes_returns_winner() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

        // Peer1: local_pref 100
        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Peer2: local_pref 200 — should win
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();

        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].peer, peer2);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn peer_down_promotes_second_best() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Peer2 goes down — peer1 should be promoted
        tx.send(RibUpdate::PeerDown { peer: peer2 }).await.unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();

        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].peer, peer1);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn withdrawal_updates_best() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Peer2 withdraws the prefix
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![],
            withdrawn: vec![Prefix::V4(prefix)],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();

        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].peer, peer1);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn different_best_per_prefix() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let prefix_a = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let prefix_b = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
        let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

        // Peer1 wins prefix_a (higher LP), peer2 wins prefix_b (higher LP)
        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![
                make_route_with_lp(prefix_a, Ipv4Addr::new(1, 0, 0, 1), 200),
                make_route_with_lp(prefix_b, Ipv4Addr::new(1, 0, 0, 1), 100),
            ],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![
                make_route_with_lp(prefix_a, Ipv4Addr::new(1, 0, 0, 2), 100),
                make_route_with_lp(prefix_b, Ipv4Addr::new(1, 0, 0, 2), 200),
            ],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();

        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 2);

        let best_a = best
            .iter()
            .find(|r| r.prefix == Prefix::V4(prefix_a))
            .unwrap();
        let best_b = best
            .iter()
            .find(|r| r.prefix == Prefix::V4(prefix_b))
            .unwrap();
        assert_eq!(best_a.peer, peer1);
        assert_eq!(best_b.peer, peer2);

        drop(tx);
        handle.await.unwrap();
    }

    // --- M3 outbound distribution tests ---

    #[tokio::test]
    async fn peer_up_triggers_initial_table_dump() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Inject a route from source
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Register target for outbound
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();

        // Should receive initial table dump
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));
        assert!(update.withdraw.is_empty());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn route_change_distributes_to_peer() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn split_horizon_prevents_echo() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        // The route is FROM this peer — should not be sent back
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Force a query to serialize the event loop
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        // Channel should be empty (no outbound update sent)
        assert!(out_rx.try_recv().is_err());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn peer_down_cleans_up_outbound() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let (out_tx, _out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();

        tx.send(RibUpdate::PeerDown { peer }).await.unwrap();

        // Query advertised routes — should be empty after PeerDown
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer,
            reply: reply_tx,
        })
        .await
        .unwrap();

        let routes = reply_rx.await.unwrap();
        assert!(routes.is_empty());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn inject_route_enters_loc_rib_and_distributes() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
        let route = Route {
            prefix: Prefix::V4(prefix),
            next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            peer: LOCAL_PEER,
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
            ],
            received_at: Instant::now(),
            is_ebgp: false,
            is_stale: false,
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::InjectRoute {
            route,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        // Should be in Loc-RIB
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].prefix, Prefix::V4(prefix));

        // Should have been distributed
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn withdraw_injected_removes_and_distributes() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
        let route = Route {
            prefix: Prefix::V4(prefix),
            next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            peer: LOCAL_PEER,
            attributes: vec![PathAttribute::Origin(Origin::Igp)],
            received_at: Instant::now(),
            is_ebgp: false,
            is_stale: false,
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::InjectRoute {
            route,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let _ = reply_rx.await;

        // Consume the inject announcement
        let _ = out_rx.recv().await;

        // Now withdraw
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::WithdrawInjected {
            prefix: Prefix::V4(prefix),
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        // Should receive withdrawal
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.withdraw.len(), 1);
        assert_eq!(update.withdraw[0], Prefix::V4(prefix));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn export_policy_blocks_denied() {
        use rustbgpd_policy::{PolicyAction, PrefixList, PrefixListEntry};

        let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
        let export_policy = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: Prefix::V4(denied_prefix),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
            }],
            default_action: PolicyAction::Permit,
        };

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, Some(export_policy), BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        // This route matches the deny entry
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(denied_prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Force serialization
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        // Should NOT have received the denied route
        assert!(out_rx.try_recv().is_err());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn query_advertised_routes() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut _out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Wait for distribution
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();

        let routes = reply_rx.await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, Prefix::V4(prefix));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn per_peer_export_policy() {
        use rustbgpd_policy::{PolicyAction, PrefixList, PrefixListEntry};

        let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
        let allowed_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Peer1 gets a deny policy on 10.0.0.0/8, peer2 has no per-peer policy
        let peer1_export = Some(PrefixList {
            entries: vec![PrefixListEntry {
                prefix: Prefix::V4(denied_prefix),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
            }],
            default_action: PolicyAction::Permit,
        });

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

        let (send_filtered, mut recv_filtered) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: peer1,
            outbound_tx: send_filtered,
            export_policy: peer1_export,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();
        drain_eor(&mut recv_filtered).await;

        let (send_unfiltered, mut recv_unfiltered) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: peer2,
            outbound_tx: send_unfiltered,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();
        drain_eor(&mut recv_unfiltered).await;

        // Source peer sends both prefixes
        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![
                make_route(denied_prefix, Ipv4Addr::new(10, 0, 0, 1)),
                make_route(allowed_prefix, Ipv4Addr::new(10, 0, 0, 1)),
            ],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Peer1: should get only the allowed prefix (denied_prefix blocked)
        let filtered = recv_filtered.recv().await.unwrap();
        assert_eq!(filtered.announce.len(), 1);
        assert_eq!(filtered.announce[0].prefix, Prefix::V4(allowed_prefix));

        // Peer2: should get both (no per-peer policy, no global policy)
        let unfiltered = recv_unfiltered.recv().await.unwrap();
        assert_eq!(unfiltered.announce.len(), 2);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn peer_down_cleans_up_export_policy() {
        use rustbgpd_policy::{PolicyAction, PrefixList, PrefixListEntry};

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let (out_tx, _out_rx) = mpsc::channel(64);
        let policy = Some(PrefixList {
            entries: vec![PrefixListEntry {
                prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8)),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
            }],
            default_action: PolicyAction::Permit,
        });

        tx.send(RibUpdate::PeerUp {
            peer,
            outbound_tx: out_tx,
            export_policy: policy,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();

        tx.send(RibUpdate::PeerDown { peer }).await.unwrap();

        // Query to confirm loop processed PeerDown
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let routes = reply_rx.await.unwrap();
        assert!(routes.is_empty());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn channel_full_marks_dirty_and_resyncs() {
        tokio::time::pause();

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

        // Channel capacity 1: fills after one send
        let (out_tx, mut out_rx) = mpsc::channel(1);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        // First route: should succeed (channel empty → fits)
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Drain the successful send so we can verify AdjRibOut
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);

        // Verify AdjRibOut has the route
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let advertised = reply_rx.await.unwrap();
        assert_eq!(advertised.len(), 1);

        // Send prefix2 — fills the channel (capacity 1)
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // DON'T drain — channel is now full. Withdraw prefix1 to trigger
        // another distribute_changes that will fail on try_send.
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![],
            withdrawn: vec![Prefix::V4(prefix1)],
        })
        .await
        .unwrap();

        // Force serialization
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        // After channel-full failure, AdjRibOut preserves last successfully
        // sent state: both prefix1 and prefix2 were sent before the failure.
        // The withdrawal of prefix1 was lost because the channel was full.
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let advertised = reply_rx.await.unwrap();
        assert_eq!(
            advertised.len(),
            2,
            "AdjRibOut preserves last successfully sent state (prefix1+prefix2)"
        );

        // Now drain the channel to allow resync
        let _ = out_rx.recv().await.unwrap();

        // Advance time to trigger the dirty-peer resync timer — no external
        // route mutation needed; the timer fires independently.
        tokio::time::advance(Duration::from_secs(2)).await;

        // Drain the resync update
        let resync = out_rx.recv().await.unwrap();

        // The resync should withdraw prefix1 (no longer in Loc-RIB) and
        // re-announce prefix2 (current Loc-RIB state)
        assert!(
            resync.withdraw.contains(&Prefix::V4(prefix1)),
            "resync should withdraw prefix1 (no longer in Loc-RIB)"
        );
        let announced_prefixes: Vec<_> = resync.announce.iter().map(|r| r.prefix).collect();
        assert!(
            announced_prefixes.contains(&Prefix::V4(prefix2)),
            "resync should re-announce prefix2"
        );

        // After successful resync, AdjRibOut should match Loc-RIB
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let advertised = reply_rx.await.unwrap();
        assert_eq!(
            advertised.len(),
            1,
            "AdjRibOut matches Loc-RIB after resync (only prefix2)"
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn dirty_resync_not_starved_by_query_traffic() {
        tokio::time::pause();

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        let (out_tx, mut out_rx) = mpsc::channel(1);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();

        // Announce prefix1
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();
        let _ = out_rx.recv().await.unwrap(); // drain

        // Withdraw prefix1 — channel is empty so this fills it
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![],
            withdrawn: vec![Prefix::V4(prefix1)],
        })
        .await
        .unwrap();

        // That send succeeded (channel was empty). Now announce again to fill.
        let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Don't drain — channel full. Send another route to trigger a failed
        // distribute_changes, marking the peer dirty.
        let prefix3 = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12);
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix3, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Force serialization
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        // Drain the outbound channel to allow resync
        let _ = out_rx.recv().await.unwrap();

        // Advance 500ms — not enough for the 1s timer
        tokio::time::advance(Duration::from_millis(500)).await;

        // Send several queries to exercise the "message churn" path.
        // With the old code (sleep recreated each iteration), each query
        // would reset the 1s countdown, starving the timer.
        for _ in 0..5 {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
                .await
                .unwrap();
            let _ = reply_rx.await;
        }

        // Advance the remaining 600ms — total 1100ms, past the 1s deadline
        // that was set before the query churn.
        tokio::time::advance(Duration::from_millis(600)).await;

        // The resync should fire despite the intervening queries.
        let resync = out_rx.recv().await.unwrap();
        assert!(
            !resync.announce.is_empty() || !resync.withdraw.is_empty(),
            "resync should produce updates despite query churn"
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn initial_dump_failure_leaves_adjribout_empty() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Pre-populate Loc-RIB
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Use a closed channel (drop rx side immediately) to guarantee send failure
        let (out_tx, out_rx) = mpsc::channel(1);
        drop(out_rx);

        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();

        // AdjRibOut should be empty since initial dump send failed
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let advertised = reply_rx.await.unwrap();
        assert!(
            advertised.is_empty(),
            "AdjRibOut should be empty when initial dump send fails"
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn initial_dump_failure_resyncs_via_timer() {
        tokio::time::pause();

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Pre-populate Loc-RIB
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Use a full channel (capacity 1, pre-filled) to fail the initial dump
        // but keep the channel recoverable (unlike closed).
        let (out_tx, mut out_rx) = mpsc::channel(1);
        // Fill the channel so send_initial_table's try_send fails
        out_tx
            .send(OutboundRouteUpdate {
                announce: vec![],
                withdraw: vec![],
                end_of_rib: vec![],
            })
            .await
            .unwrap();

        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();

        // Force serialization — initial dump should have failed (channel full)
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let advertised = reply_rx.await.unwrap();
        assert!(
            advertised.is_empty(),
            "AdjRibOut should be empty after failed initial dump"
        );

        // Drain the channel to make room for the resync
        let _ = out_rx.recv().await.unwrap();

        // Advance time to trigger the resync timer
        tokio::time::advance(Duration::from_secs(2)).await;

        // The resync should deliver the initial table
        let resync = out_rx.recv().await.unwrap();
        assert_eq!(
            resync.announce.len(),
            1,
            "resync should announce the route from Loc-RIB"
        );
        assert_eq!(resync.announce[0].prefix, Prefix::V4(prefix));
        assert!(resync.withdraw.is_empty());

        // AdjRibOut should now reflect Loc-RIB
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let advertised = reply_rx.await.unwrap();
        assert_eq!(
            advertised.len(),
            1,
            "AdjRibOut should match Loc-RIB after resync"
        );

        drop(tx);
        handle.await.unwrap();
    }

    // --- Route event streaming tests ---

    async fn subscribe_events(
        tx: &mpsc::Sender<RibUpdate>,
    ) -> tokio::sync::broadcast::Receiver<crate::event::RouteEvent> {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::SubscribeRouteEvents { reply: reply_tx })
            .await
            .unwrap();
        reply_rx.await.unwrap()
    }

    #[tokio::test]
    async fn route_event_added_on_new_best() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let mut events_rx = subscribe_events(&tx).await;

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let event = events_rx.recv().await.unwrap();
        assert_eq!(event.event_type, crate::event::RouteEventType::Added);
        assert_eq!(event.prefix, Prefix::V4(prefix));
        assert_eq!(event.peer, Some(peer));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn route_event_withdrawn_on_last_removed() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Subscribe after route is added
        let mut events_rx = subscribe_events(&tx).await;

        // Withdraw the route
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![],
            withdrawn: vec![Prefix::V4(prefix)],
        })
        .await
        .unwrap();

        let event = events_rx.recv().await.unwrap();
        assert_eq!(event.event_type, crate::event::RouteEventType::Withdrawn);
        assert_eq!(event.prefix, Prefix::V4(prefix));
        assert!(event.peer.is_none());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn route_event_best_changed_on_better_path() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

        // Peer1 announces first
        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Subscribe after first route is installed
        let mut events_rx = subscribe_events(&tx).await;

        // Peer2 announces with higher local-pref — best changes
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let event = events_rx.recv().await.unwrap();
        assert_eq!(event.event_type, crate::event::RouteEventType::BestChanged);
        assert_eq!(event.prefix, Prefix::V4(prefix));
        assert_eq!(event.peer, Some(peer2));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn multiple_subscribers_receive_same_events() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let mut sub1 = subscribe_events(&tx).await;
        let mut sub2 = subscribe_events(&tx).await;

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let e1 = sub1.recv().await.unwrap();
        let e2 = sub2.recv().await.unwrap();
        assert_eq!(e1.prefix, Prefix::V4(prefix));
        assert_eq!(e2.prefix, Prefix::V4(prefix));
        assert_eq!(e1.event_type, e2.event_type);

        drop(tx);
        handle.await.unwrap();
    }

    // --- WatchRoutes event tests ---

    #[tokio::test]
    async fn route_event_withdrawn_carries_previous_peer() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let mut events_rx = subscribe_events(&tx).await;

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![],
            withdrawn: vec![Prefix::V4(prefix)],
        })
        .await
        .unwrap();

        let event = events_rx.recv().await.unwrap();
        assert_eq!(event.event_type, RouteEventType::Withdrawn);
        assert!(event.peer.is_none());
        assert_eq!(event.previous_peer, Some(peer));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn route_event_best_changed_carries_both_peers() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let mut events_rx = subscribe_events(&tx).await;

        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let event = events_rx.recv().await.unwrap();
        assert_eq!(event.event_type, RouteEventType::BestChanged);
        assert_eq!(event.peer, Some(peer2));
        assert_eq!(event.previous_peer, Some(peer1));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn route_event_has_timestamp() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let mut events_rx = subscribe_events(&tx).await;

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let event = events_rx.recv().await.unwrap();
        assert!(!event.timestamp.is_empty());
        // Should be a valid integer (Unix seconds)
        let ts: u64 = event
            .timestamp
            .parse()
            .expect("timestamp should be numeric");
        assert!(ts > 0);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn route_event_added_has_no_previous_peer() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let mut events_rx = subscribe_events(&tx).await;

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let event = events_rx.recv().await.unwrap();
        assert_eq!(event.event_type, RouteEventType::Added);
        assert_eq!(event.peer, Some(peer));
        assert!(event.previous_peer.is_none());

        drop(tx);
        handle.await.unwrap();
    }

    // --- Prometheus gauge tests ---

    #[tokio::test]
    #[expect(clippy::cast_possible_truncation)]
    async fn rib_prefixes_gauge_tracks_adjribin() {
        let metrics = BgpMetrics::new();
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, metrics.clone());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Serialize
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        let families = metrics.registry().gather();
        let rib_gauge = families
            .iter()
            .find(|f| f.get_name() == "bgp_rib_prefixes")
            .expect("bgp_rib_prefixes metric not found");
        let sample = rib_gauge.get_metric()[0].get_gauge().get_value();
        assert_eq!(sample as i64, 1);

        // PeerDown should zero the gauge
        tx.send(RibUpdate::PeerDown { peer }).await.unwrap();
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        let families = metrics.registry().gather();
        let rib_gauge = families
            .iter()
            .find(|f| f.get_name() == "bgp_rib_prefixes")
            .expect("bgp_rib_prefixes metric not found");
        let sample = rib_gauge.get_metric()[0].get_gauge().get_value();
        assert_eq!(sample as i64, 0);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    #[expect(clippy::cast_possible_truncation)]
    async fn loc_rib_gauge_tracks_best() {
        let metrics = BgpMetrics::new();
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, metrics.clone());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        let families = metrics.registry().gather();
        let loc_gauge = families
            .iter()
            .find(|f| f.get_name() == "bgp_rib_loc_prefixes")
            .expect("bgp_loc_rib_prefixes metric not found");
        let sample = loc_gauge.get_metric()[0].get_gauge().get_value();
        assert_eq!(sample as i64, 1);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    #[expect(clippy::cast_possible_truncation)]
    async fn adj_rib_out_gauge_tracks_advertised() {
        let metrics = BgpMetrics::new();
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, metrics.clone());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        let (out_tx, mut _out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();

        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        let families = metrics.registry().gather();
        let out_gauge = families
            .iter()
            .find(|f| f.get_name() == "bgp_rib_adj_out_prefixes")
            .expect("bgp_adj_rib_out_prefixes metric not found");
        let sample = out_gauge.get_metric()[0].get_gauge().get_value();
        assert_eq!(sample as i64, 1);

        drop(tx);
        handle.await.unwrap();
    }

    // --- Query count tests ---

    #[tokio::test]
    async fn query_loc_rib_count() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![
                make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1)),
                make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1)),
            ],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryLocRibCount { reply: reply_tx })
            .await
            .unwrap();
        let count = reply_rx.await.unwrap();
        assert_eq!(count, 2);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn query_advertised_count() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        let (out_tx, mut _out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();

        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Serialize
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedCount {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let count = reply_rx.await.unwrap();
        assert_eq!(count, 1);

        // Unknown peer returns 0
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedCount {
            peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
            reply: reply_tx,
        })
        .await
        .unwrap();
        let count = reply_rx.await.unwrap();
        assert_eq!(count, 0);

        drop(tx);
        handle.await.unwrap();
    }

    // --- Sendable families filtering tests ---

    #[tokio::test]
    async fn distribute_changes_filters_unsendable_families() {
        use rustbgpd_wire::Ipv6Prefix;

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);

        // Register peer with IPv4-only sendable families
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

        let v4_route = make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1));
        let v6_route = Route {
            prefix: Prefix::V6(v6_prefix),
            next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
            peer: source,
            attributes: vec![],
            received_at: Instant::now(),
            is_ebgp: true,
            is_stale: false,
        };

        // Send both IPv4 and IPv6 routes
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![v4_route, v6_route],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Should only receive IPv4 route
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].prefix, Prefix::V4(v4_prefix));
        assert!(update.withdraw.is_empty());

        // Adj-RIB-Out should only contain IPv4
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let advertised = reply_rx.await.unwrap();
        assert_eq!(advertised.len(), 1);
        assert_eq!(advertised[0].prefix, Prefix::V4(v4_prefix));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn send_initial_table_filters_unsendable_families() {
        use rustbgpd_wire::Ipv6Prefix;

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

        let v4_route = make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1));
        let v6_route = Route {
            prefix: Prefix::V6(v6_prefix),
            next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
            peer: source,
            attributes: vec![],
            received_at: Instant::now(),
            is_ebgp: true,
            is_stale: false,
        };

        // Pre-populate Loc-RIB with both IPv4 and IPv6 routes
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![v4_route, v6_route],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Register peer with IPv4-only sendable families — initial dump
        // should filter out the IPv6 route
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();

        // Initial table dump should only contain IPv4
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].prefix, Prefix::V4(v4_prefix));
        assert!(update.withdraw.is_empty());

        // Adj-RIB-Out should only contain IPv4
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let advertised = reply_rx.await.unwrap();
        assert_eq!(advertised.len(), 1);
        assert_eq!(advertised[0].prefix, Prefix::V4(v4_prefix));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn dual_stack_peer_receives_both_families() {
        use rustbgpd_wire::Ipv6Prefix;

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

        let v4_route = make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1));
        let v6_route = Route {
            prefix: Prefix::V6(v6_prefix),
            next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
            peer: source,
            attributes: vec![],
            received_at: Instant::now(),
            is_ebgp: true,
            is_stale: false,
        };

        // Pre-populate Loc-RIB
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![v4_route, v6_route],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Register peer with dual-stack sendable families
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: dual_stack_sendable(),
        })
        .await
        .unwrap();

        // Should receive both routes in initial dump
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 2);

        drop(tx);
        handle.await.unwrap();
    }

    // --- Graceful Restart tests ---

    #[tokio::test]
    async fn gr_marks_stale_and_demotes_routes() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        // Source sends a route
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);

        // Source enters graceful restart
        tx.send(RibUpdate::PeerGracefulRestart {
            peer: source,
            restart_time: 120,
            stale_routes_time: 360,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        })
        .await
        .unwrap();

        // Route should still be in Loc-RIB (stale but present)
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert!(best[0].is_stale, "route should be marked stale");

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn gr_eor_clears_stale() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Source sends a route
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Source enters graceful restart
        tx.send(RibUpdate::PeerGracefulRestart {
            peer: source,
            restart_time: 120,
            stale_routes_time: 360,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        })
        .await
        .unwrap();

        // Verify stale
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert!(best[0].is_stale);

        // Send End-of-RIB
        tx.send(RibUpdate::EndOfRib {
            peer: source,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();

        // Route should no longer be stale
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert!(
            !best[0].is_stale,
            "route should no longer be stale after EoR"
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn gr_timer_sweeps_stale_routes() {
        tokio::time::pause();

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Source sends a route
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Source enters graceful restart with short timer
        tx.send(RibUpdate::PeerGracefulRestart {
            peer: source,
            restart_time: 5,
            stale_routes_time: 10,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        })
        .await
        .unwrap();

        // Route is stale but still in Loc-RIB
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert!(best[0].is_stale);

        // Advance past the GR timer (min(5, 10) = 5 seconds)
        tokio::time::advance(Duration::from_secs(6)).await;
        // Yield to let the manager process the expired GR timer
        tokio::task::yield_now().await;

        // Route should have been swept
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert!(best.is_empty(), "stale routes should be swept after timer");

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn gr_peer_up_defers_stale_to_eor() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Source sends a route
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Source enters graceful restart
        tx.send(RibUpdate::PeerGracefulRestart {
            peer: source,
            restart_time: 120,
            stale_routes_time: 360,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        })
        .await
        .unwrap();

        // Verify route is stale
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert!(best[0].is_stale);

        // Source re-establishes — route should STILL be stale
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: source,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert!(best[0].is_stale, "route should still be stale after PeerUp");

        // End-of-RIB clears stale and completes GR
        tx.send(RibUpdate::EndOfRib {
            peer: source,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert!(
            !best[0].is_stale,
            "route should be non-stale after End-of-RIB"
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn gr_peer_up_timer_expires_sweeps_stale() {
        tokio::time::pause();

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Source sends a route
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Source enters GR with short restart_time
        tx.send(RibUpdate::PeerGracefulRestart {
            peer: source,
            restart_time: 5,
            stale_routes_time: 10,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        })
        .await
        .unwrap();

        // Advance past restart_time but before stale_routes_time
        tokio::time::advance(Duration::from_secs(3)).await;
        tokio::task::yield_now().await;

        // Source re-establishes — timer resets to stale_routes_time (10s)
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: source,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        // Route still stale (no EoR yet)
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert!(best[0].is_stale);

        // Advance past stale_routes_time — timer should sweep
        tokio::time::advance(Duration::from_secs(11)).await;
        tokio::task::yield_now().await;

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert!(best.is_empty(), "stale routes should be swept after timer");

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn gr_peer_down_aborts_gr() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Source sends a route
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Source enters graceful restart
        tx.send(RibUpdate::PeerGracefulRestart {
            peer: source,
            restart_time: 120,
            stale_routes_time: 360,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        })
        .await
        .unwrap();

        // Source goes fully down during GR — aborts GR, clears all routes
        tx.send(RibUpdate::PeerDown { peer: source }).await.unwrap();

        // Routes should be gone
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert!(best.is_empty(), "routes cleared after PeerDown aborts GR");

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn gr_withdraws_non_gr_family_routes() {
        use rustbgpd_wire::Ipv6Prefix;

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source: IpAddr = "10.0.0.1".parse().unwrap();
        let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

        // Source sends both IPv4 and IPv6 routes
        let v6_route = Route {
            prefix: Prefix::V6(v6_prefix),
            next_hop: "2001:db8::1".parse().unwrap(),
            peer: source,
            attributes: vec![],
            received_at: Instant::now(),
            is_ebgp: true,
            is_stale: false,
        };
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1)), v6_route],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Verify both routes present
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 2);

        // GR with only IPv4 in GR capability — IPv6 should be withdrawn
        tx.send(RibUpdate::PeerGracefulRestart {
            peer: source,
            restart_time: 120,
            stale_routes_time: 360,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        })
        .await
        .unwrap();

        // IPv4 route should be stale, IPv6 route should be gone
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1, "only IPv4 route should remain");
        assert!(
            matches!(best[0].prefix, Prefix::V4(_)),
            "remaining route should be IPv4"
        );
        assert!(best[0].is_stale, "IPv4 route should be stale");

        drop(tx);
        handle.await.unwrap();
    }
}
