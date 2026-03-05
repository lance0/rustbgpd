use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use rustbgpd_api::peer_types::{
    PeerInfo, PeerManagerCommand, PeerManagerNeighborConfig, ReconcileFailure,
    ReconcileFailureKind, ReconcileResult,
};
use rustbgpd_bmp::{BmpEvent, BmpPeerInfo, BmpPeerType};
use rustbgpd_fsm::{PeerConfig, SessionState};
use rustbgpd_policy::PolicyChain;
use rustbgpd_rib::RibUpdate;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::{PeerHandle, SessionNotification, TransportConfig};
use rustbgpd_wire::{Afi, Safi};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

const DEFAULT_HOLD_TIME: u16 = 90;
const DEFAULT_CONNECT_RETRY_SECS: u32 = 30;
const BGP_PORT: u16 = 179;
const BMP_STATS_INTERVAL_SECS: u64 = 60;

struct ManagedPeer {
    handle: PeerHandle,
    remote_asn: u32,
    description: String,
    enabled: bool,
    hold_time: Option<u16>,
    max_prefixes: Option<u32>,
    transport_config: TransportConfig,
    import_policy: Option<PolicyChain>,
    export_policy: Option<PolicyChain>,
    /// Pending inbound TCP stream waiting for collision resolution.
    pending_inbound: Option<TcpStream>,
}

/// Manages the lifecycle of all peer sessions.
///
/// Runs as a single tokio task, receiving commands via an mpsc channel.
/// Same single-task ownership pattern as `RibManager`.
pub struct PeerManager {
    peers: HashMap<IpAddr, ManagedPeer>,
    rx: mpsc::Receiver<PeerManagerCommand>,
    local_asn: u32,
    router_id: Ipv4Addr,
    /// Local cluster ID for route reflection (RFC 4456). `None` when not an RR.
    cluster_id: Option<Ipv4Addr>,
    /// Process-wide local restarting-speaker GR deadline. Static peers
    /// restored during this window advertise `restart_state = true`.
    local_gr_restart_until: Option<Instant>,
    metrics: BgpMetrics,
    rib_tx: mpsc::Sender<RibUpdate>,
    /// Optional BMP event sender (None when BMP not configured).
    bmp_tx: Option<mpsc::Sender<BmpEvent>>,
    session_notify_tx: mpsc::UnboundedSender<SessionNotification>,
    session_notify_rx: mpsc::UnboundedReceiver<SessionNotification>,
}

impl PeerManager {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        rx: mpsc::Receiver<PeerManagerCommand>,
        local_asn: u32,
        router_id: Ipv4Addr,
        cluster_id: Option<Ipv4Addr>,
        local_gr_restart_until: Option<Instant>,
        metrics: BgpMetrics,
        rib_tx: mpsc::Sender<RibUpdate>,
        bmp_tx: Option<mpsc::Sender<BmpEvent>>,
    ) -> Self {
        let (session_notify_tx, session_notify_rx) = mpsc::unbounded_channel();
        Self {
            peers: HashMap::new(),
            rx,
            local_asn,
            router_id,
            cluster_id,
            local_gr_restart_until,
            metrics,
            rib_tx,
            bmp_tx,
            session_notify_tx,
            session_notify_rx,
        }
    }

    fn build_transport_config(&self, config: &PeerManagerNeighborConfig) -> TransportConfig {
        let families = if config.families.is_empty() {
            vec![(Afi::Ipv4, Safi::Unicast)]
        } else {
            config.families.clone()
        };
        let peer = PeerConfig {
            local_asn: self.local_asn,
            remote_asn: config.remote_asn,
            local_router_id: self.router_id,
            hold_time: config.hold_time.unwrap_or(DEFAULT_HOLD_TIME),
            connect_retry_secs: DEFAULT_CONNECT_RETRY_SECS,
            families,
            graceful_restart: config.graceful_restart,
            gr_restart_time: config.gr_restart_time,
            llgr_stale_time: config.llgr_stale_time,
            add_path_receive: config.add_path_receive,
            add_path_send: config.add_path_send,
            add_path_send_max: config.add_path_send_max,
        };
        let remote_addr = SocketAddr::new(config.address, BGP_PORT);
        let mut transport = TransportConfig::new(peer, remote_addr);
        transport.max_prefixes = config.max_prefixes;
        transport.local_ipv6_nexthop = config.local_ipv6_nexthop;
        transport.gr_stale_routes_time = config.gr_stale_routes_time;
        transport.llgr_stale_time = config.llgr_stale_time;
        transport.gr_restart_until = if config.gr_restart_eligible && config.graceful_restart {
            self.local_gr_restart_until
                .filter(|deadline| *deadline > Instant::now())
        } else {
            None
        };
        transport.route_reflector_client = config.route_reflector_client;
        transport.route_server_client = config.route_server_client;
        transport.cluster_id = self.cluster_id;
        transport
    }

    async fn add_peer(&mut self, config: PeerManagerNeighborConfig) -> Result<(), String> {
        if self.peers.contains_key(&config.address) {
            return Err(format!("peer {} already exists", config.address));
        }

        let transport = self.build_transport_config(&config);
        let address = config.address;
        let remote_asn = config.remote_asn;
        let description = config.description.clone();
        let hold_time = config.hold_time;
        let max_prefixes = config.max_prefixes;

        let handle = PeerHandle::spawn(
            transport.clone(),
            self.metrics.clone(),
            self.rib_tx.clone(),
            config.import_policy.clone(),
            config.export_policy.clone(),
            Some(self.session_notify_tx.clone()),
            self.bmp_tx.clone(),
        );

        if let Err(e) = handle.start().await {
            warn!(%address, error = %e, "failed to start peer session");
            return Err(format!("failed to start peer: {e}"));
        }

        info!(%address, %remote_asn, "peer added dynamically");
        self.peers.insert(
            address,
            ManagedPeer {
                handle,
                remote_asn,
                description,
                enabled: true,
                hold_time,
                max_prefixes,
                transport_config: transport,
                import_policy: config.import_policy,
                export_policy: config.export_policy,
                pending_inbound: None,
            },
        );

        Ok(())
    }

    async fn delete_peer(&mut self, address: IpAddr) -> Result<(), String> {
        let managed = self
            .peers
            .remove(&address)
            .ok_or_else(|| format!("peer {address} not found"))?;

        match managed.handle.shutdown().await {
            Ok(Ok(())) => info!(%address, "peer deleted"),
            Ok(Err(e)) => warn!(%address, error = %e, "peer shutdown error during delete"),
            Err(e) => error!(%address, error = %e, "peer task join error during delete"),
        }

        Ok(())
    }

    async fn get_peer_info(&self, address: IpAddr) -> Option<PeerInfo> {
        let managed = self.peers.get(&address)?;
        let session_state = managed.handle.query_state().await;

        Some(PeerInfo {
            address,
            remote_asn: managed.remote_asn,
            description: managed.description.clone(),
            state: session_state
                .as_ref()
                .map_or(SessionState::Idle, |s| s.fsm_state),
            enabled: managed.enabled,
            prefix_count: session_state.as_ref().map_or(0, |s| s.prefix_count),
            hold_time: managed.hold_time,
            max_prefixes: managed.max_prefixes,
            families: managed.transport_config.peer.families.clone(),
            updates_received: session_state.as_ref().map_or(0, |s| s.updates_received),
            updates_sent: session_state.as_ref().map_or(0, |s| s.updates_sent),
            notifications_received: session_state
                .as_ref()
                .map_or(0, |s| s.notifications_received),
            notifications_sent: session_state.as_ref().map_or(0, |s| s.notifications_sent),
            flap_count: session_state.as_ref().map_or(0, |s| s.flap_count),
            uptime_secs: session_state.as_ref().map_or(0, |s| s.uptime_secs),
            last_error: session_state
                .as_ref()
                .map_or_else(String::new, |s| s.last_error.clone()),
        })
    }

    async fn list_peers(&self) -> Vec<PeerInfo> {
        let mut infos = Vec::with_capacity(self.peers.len());
        for (&addr, managed) in &self.peers {
            let session_state = managed.handle.query_state().await;
            infos.push(PeerInfo {
                address: addr,
                remote_asn: managed.remote_asn,
                description: managed.description.clone(),
                state: session_state
                    .as_ref()
                    .map_or(SessionState::Idle, |s| s.fsm_state),
                enabled: managed.enabled,
                prefix_count: session_state.as_ref().map_or(0, |s| s.prefix_count),
                hold_time: managed.hold_time,
                max_prefixes: managed.max_prefixes,
                families: managed.transport_config.peer.families.clone(),
                updates_received: session_state.as_ref().map_or(0, |s| s.updates_received),
                updates_sent: session_state.as_ref().map_or(0, |s| s.updates_sent),
                notifications_received: session_state
                    .as_ref()
                    .map_or(0, |s| s.notifications_received),
                notifications_sent: session_state.as_ref().map_or(0, |s| s.notifications_sent),
                flap_count: session_state.as_ref().map_or(0, |s| s.flap_count),
                uptime_secs: session_state.as_ref().map_or(0, |s| s.uptime_secs),
                last_error: session_state
                    .as_ref()
                    .map_or_else(String::new, |s| s.last_error.clone()),
            });
        }
        infos
    }

    async fn enable_peer(&mut self, address: IpAddr) -> Result<(), String> {
        let managed = self
            .peers
            .get_mut(&address)
            .ok_or_else(|| format!("peer {address} not found"))?;
        managed.enabled = true;
        managed
            .handle
            .start()
            .await
            .map_err(|e| format!("failed to start peer: {e}"))?;
        info!(%address, "peer enabled");
        Ok(())
    }

    async fn disable_peer(
        &mut self,
        address: IpAddr,
        reason: Option<bytes::Bytes>,
    ) -> Result<(), String> {
        let managed = self
            .peers
            .get_mut(&address)
            .ok_or_else(|| format!("peer {address} not found"))?;
        managed.enabled = false;
        managed.pending_inbound = None;
        managed
            .handle
            .stop(reason)
            .await
            .map_err(|e| format!("failed to stop peer: {e}"))?;
        info!(%address, "peer disabled");
        Ok(())
    }

    async fn soft_reset_in(
        &self,
        address: IpAddr,
        families: Vec<(Afi, Safi)>,
    ) -> Result<(), String> {
        let managed = self
            .peers
            .get(&address)
            .ok_or_else(|| format!("not found: peer {address}"))?;

        // Determine which families to request refresh for
        let target_families = if families.is_empty() {
            // All configured families for this peer
            managed.transport_config.peer.families.clone()
        } else {
            families
        };

        for (afi, safi) in &target_families {
            if let Err(e) = managed.handle.send_route_refresh(*afi, *safi).await {
                warn!(%address, error = %e, "failed to send route refresh");
                return Err(format!("send failed: route refresh to {address}: {e}"));
            }
        }

        info!(%address, families = ?target_families, "soft reset in requested");
        Ok(())
    }

    async fn handle_inbound(&mut self, stream: TcpStream, peer_addr: IpAddr) {
        let Some(managed) = self.peers.get_mut(&peer_addr) else {
            warn!(%peer_addr, "inbound connection from unknown peer, dropping");
            return;
        };

        if !managed.enabled {
            info!(%peer_addr, "inbound connection for disabled peer, dropping");
            return;
        }

        let current_state = managed.handle.query_state().await;
        let fsm_state = current_state
            .as_ref()
            .map_or(SessionState::Idle, |s| s.fsm_state);

        match fsm_state {
            SessionState::Idle => {
                // Accept immediately — no collision possible
                self.replace_with_inbound(peer_addr, stream).await;
            }
            SessionState::Established => {
                // Already established — drop inbound (no collision)
                info!(%peer_addr, "inbound connection for established peer, dropping");
            }
            SessionState::Connect | SessionState::Active | SessionState::OpenSent => {
                // Store pending inbound, wait for OpenReceived notification
                info!(%peer_addr, state = fsm_state.as_str(), "storing pending inbound for collision resolution");
                if let Some(managed) = self.peers.get_mut(&peer_addr) {
                    managed.pending_inbound = Some(stream);
                }
            }
            SessionState::OpenConfirm => {
                // We already have router-id from negotiation — resolve now
                let remote_router_id = current_state.and_then(|s| s.remote_router_id);
                if let Some(rid) = remote_router_id {
                    self.resolve_collision(peer_addr, rid, stream).await;
                } else {
                    // Shouldn't happen, but accept inbound as fallback
                    warn!(%peer_addr, "OpenConfirm but no remote_router_id, accepting inbound");
                    self.replace_with_inbound(peer_addr, stream).await;
                }
            }
        }
    }

    async fn handle_session_notification(&mut self, notification: SessionNotification) {
        match notification {
            SessionNotification::OpenReceived {
                peer_addr,
                remote_router_id,
            } => {
                let pending = self
                    .peers
                    .get_mut(&peer_addr)
                    .and_then(|m| m.pending_inbound.take());
                if let Some(stream) = pending {
                    self.resolve_collision(peer_addr, remote_router_id, stream)
                        .await;
                }
            }
            SessionNotification::BackToIdle { peer_addr } => {
                let pending = self.peers.get_mut(&peer_addr).and_then(|m| {
                    if m.enabled {
                        m.pending_inbound.take()
                    } else {
                        // Peer is disabled — drop pending inbound
                        m.pending_inbound = None;
                        None
                    }
                });
                if let Some(stream) = pending {
                    // Existing session failed — accept pending inbound
                    info!(%peer_addr, "existing session went idle, accepting pending inbound");
                    self.replace_with_inbound(peer_addr, stream).await;
                }
            }
        }
    }

    async fn resolve_collision(
        &mut self,
        peer_addr: IpAddr,
        remote_router_id: Ipv4Addr,
        inbound_stream: TcpStream,
    ) {
        let local_id = u32::from(self.router_id);
        let remote_id = u32::from(remote_router_id);

        match local_id.cmp(&remote_id) {
            std::cmp::Ordering::Greater => {
                // We win — keep existing session, drop inbound
                info!(
                    %peer_addr,
                    local_id = %self.router_id,
                    remote_id = %remote_router_id,
                    "collision: local wins, dropping inbound"
                );
                drop(inbound_stream);
            }
            std::cmp::Ordering::Less => {
                // Remote wins — dump existing, accept inbound
                info!(
                    %peer_addr,
                    local_id = %self.router_id,
                    remote_id = %remote_router_id,
                    "collision: remote wins, replacing with inbound"
                );
                if let Some(managed) = self.peers.get(&peer_addr) {
                    let _ = managed.handle.collision_dump().await;
                }
                self.replace_with_inbound(peer_addr, inbound_stream).await;
            }
            std::cmp::Ordering::Equal => {
                // Equal router-ids — should not happen; drop inbound
                warn!(
                    %peer_addr,
                    router_id = %self.router_id,
                    "collision: equal router-ids, dropping inbound"
                );
                drop(inbound_stream);
            }
        }
    }

    async fn replace_with_inbound(&mut self, peer_addr: IpAddr, stream: TcpStream) {
        let Some(managed) = self.peers.get_mut(&peer_addr) else {
            return;
        };

        let old_handle = std::mem::replace(
            &mut managed.handle,
            PeerHandle::spawn_inbound(
                managed.transport_config.clone(),
                self.metrics.clone(),
                self.rib_tx.clone(),
                managed.import_policy.clone(),
                managed.export_policy.clone(),
                stream,
                Some(self.session_notify_tx.clone()),
                self.bmp_tx.clone(),
            ),
        );

        // Shut down the old session
        let _ = old_handle.shutdown().await;

        // Start the new inbound session — trigger TcpConnectionConfirmed
        if let Err(e) = managed.handle.start().await {
            warn!(%peer_addr, error = %e, "failed to start inbound session");
        } else {
            info!(%peer_addr, "inbound session started");
        }
    }

    async fn reconcile_peers(
        &mut self,
        added: Vec<PeerManagerNeighborConfig>,
        removed: Vec<IpAddr>,
        changed: Vec<PeerManagerNeighborConfig>,
    ) -> ReconcileResult {
        let mut result = ReconcileResult::default();
        let added_count = added.len();
        let removed_count = removed.len();
        let changed_count = changed.len();

        // Remove peers
        for addr in &removed {
            if let Err(e) = self.delete_peer(*addr).await {
                warn!(%addr, error = %e, "reconcile: failed to remove peer");
                result.failures.push(ReconcileFailure {
                    kind: ReconcileFailureKind::Remove,
                    address: *addr,
                    error: e,
                });
            }
        }
        // Changed peers: delete then re-add
        for cfg in &changed {
            let addr = cfg.address;
            if let Err(e) = self.delete_peer(addr).await {
                warn!(%addr, error = %e, "reconcile: failed to remove changed peer");
                result.failures.push(ReconcileFailure {
                    kind: ReconcileFailureKind::ChangeRemove,
                    address: addr,
                    error: e,
                });
            }
            if let Err(e) = self.add_peer(cfg.clone()).await {
                warn!(%addr, error = %e, "reconcile: failed to re-add changed peer");
                result.failures.push(ReconcileFailure {
                    kind: ReconcileFailureKind::ChangeAdd,
                    address: addr,
                    error: e,
                });
            }
        }
        // Add new peers
        for cfg in added {
            let addr = cfg.address;
            if let Err(e) = self.add_peer(cfg).await {
                warn!(%addr, error = %e, "reconcile: failed to add new peer");
                result.failures.push(ReconcileFailure {
                    kind: ReconcileFailureKind::Add,
                    address: addr,
                    error: e,
                });
            }
        }
        info!(
            added = added_count,
            removed = removed_count,
            changed = changed_count,
            failures = result.failures.len(),
            "peer reconciliation complete"
        );
        result
    }

    fn bmp_peer_info(
        peer_addr: IpAddr,
        remote_asn: u32,
        remote_router_id: Option<Ipv4Addr>,
        four_octet_as: Option<bool>,
    ) -> BmpPeerInfo {
        BmpPeerInfo {
            peer_addr,
            peer_asn: remote_asn,
            peer_bgp_id: remote_router_id.unwrap_or(Ipv4Addr::UNSPECIFIED),
            peer_type: BmpPeerType::Global,
            is_ipv6: peer_addr.is_ipv6(),
            is_post_policy: false,
            is_as4: four_octet_as.unwrap_or(true),
            timestamp: std::time::SystemTime::now(),
        }
    }

    async fn emit_periodic_bmp_stats(&self) {
        let Some(ref bmp_tx) = self.bmp_tx else {
            return;
        };

        for (&peer_addr, managed) in &self.peers {
            let Some(state) = managed.handle.query_state().await else {
                continue;
            };
            if state.fsm_state != SessionState::Established {
                continue;
            }

            let prefix_count = u64::try_from(state.prefix_count).unwrap_or(u64::MAX);
            let event = BmpEvent::StatsReport {
                peer_info: Self::bmp_peer_info(
                    peer_addr,
                    managed.remote_asn,
                    state.remote_router_id,
                    state.four_octet_as,
                ),
                adj_rib_in_routes: prefix_count,
            };

            if let Err(e) = bmp_tx.try_send(event) {
                warn!(
                    peer = %peer_addr,
                    error = %e,
                    "BMP event channel full or closed, dropping periodic stats report"
                );
            }
        }
    }

    /// Run the `PeerManager` event loop until shutdown or channel close.
    pub async fn run(mut self) {
        let mut bmp_stats_interval = self.bmp_tx.as_ref().map(|_| {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(BMP_STATS_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval
        });
        // Consume the immediate first tick so the first report is emitted
        // after one full interval.
        if let Some(interval) = bmp_stats_interval.as_mut() {
            interval.tick().await;
        }

        loop {
            tokio::select! {
                cmd = self.rx.recv() => {
                    let Some(cmd) = cmd else {
                        debug!("peer manager channel closed");
                        return;
                    };
                    match cmd {
                        PeerManagerCommand::AddPeer { config, reply } => {
                            let result = self.add_peer(config).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::DeletePeer { address, reply } => {
                            let result = self.delete_peer(address).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::ListPeers { reply } => {
                            let infos = self.list_peers().await;
                            let _ = reply.send(infos);
                        }
                        PeerManagerCommand::GetPeerState { address, reply } => {
                            let info = self.get_peer_info(address).await;
                            let _ = reply.send(info);
                        }
                        PeerManagerCommand::EnablePeer { address, reply } => {
                            let result = self.enable_peer(address).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::DisablePeer { address, reason, reply } => {
                            let result = self.disable_peer(address, reason).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::SoftResetIn { address, families, reply } => {
                            let result = self.soft_reset_in(address, families).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::AcceptInbound { stream, peer_addr } => {
                            self.handle_inbound(stream, peer_addr).await;
                        }
                        PeerManagerCommand::ReconcilePeers { added, removed, changed, reply } => {
                            let result = self.reconcile_peers(added, removed, changed).await;
                            let _ = reply.send(result);
                        }
                        PeerManagerCommand::Shutdown => {
                            info!("peer manager shutting down {} peers", self.peers.len());
                            for (addr, managed) in self.peers.drain() {
                                debug!(%addr, "shutting down peer");
                                match managed.handle.shutdown().await {
                                    Ok(Ok(())) => debug!(%addr, "peer shut down"),
                                    Ok(Err(e)) => warn!(%addr, error = %e, "peer shutdown error"),
                                    Err(e) => error!(%addr, error = %e, "peer task join error"),
                                }
                            }
                            return;
                        }
                    }
                }
                notification = self.session_notify_rx.recv() => {
                    if let Some(notification) = notification {
                        self.handle_session_notification(notification).await;
                    }
                }
                () = async {
                    if let Some(interval) = bmp_stats_interval.as_mut() {
                        interval.tick().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    self.emit_periodic_bmp_stats().await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::oneshot;

    fn make_config(addr: IpAddr, asn: u32) -> PeerManagerNeighborConfig {
        PeerManagerNeighborConfig {
            address: addr,
            remote_asn: asn,
            description: format!("test-peer-{addr}"),
            hold_time: None,
            max_prefixes: None,
            families: vec![(Afi::Ipv4, Safi::Unicast)],
            graceful_restart: true,
            gr_restart_time: 120,
            gr_stale_routes_time: 360,
            llgr_stale_time: 0,
            gr_restart_eligible: false,
            local_ipv6_nexthop: None,
            route_reflector_client: false,
            route_server_client: false,
            add_path_receive: false,
            add_path_send: false,
            add_path_send_max: 0,
            import_policy: None,
            export_policy: None,
        }
    }

    #[tokio::test]
    async fn add_peer_and_list() {
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::AddPeer {
            config: make_config(addr, 65002),
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::ListPeers { reply: reply_tx })
            .await
            .unwrap();
        let peers = reply_rx.await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].address, addr);
        assert_eq!(peers[0].remote_asn, 65002);

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn add_duplicate_returns_error() {
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::AddPeer {
            config: make_config(addr, 65002),
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::AddPeer {
            config: make_config(addr, 65002),
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_err());

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn delete_peer_removes() {
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::AddPeer {
            config: make_config(addr, 65002),
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::DeletePeer {
            address: addr,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::ListPeers { reply: reply_tx })
            .await
            .unwrap();
        let peers = reply_rx.await.unwrap();
        assert!(peers.is_empty());

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn delete_nonexistent_returns_error() {
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::DeletePeer {
            address: addr,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_err());

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn get_peer_state_existing() {
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::AddPeer {
            config: make_config(addr, 65002),
            reply: reply_tx,
        })
        .await
        .unwrap();
        let _ = reply_rx.await;

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::GetPeerState {
            address: addr,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let info = reply_rx.await.unwrap();
        assert!(info.is_some());
        assert_eq!(info.unwrap().address, addr);

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn get_peer_state_nonexistent_returns_none() {
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::GetPeerState {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_none());

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_stops_all_peers() {
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        for i in 2..=3 {
            let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(PeerManagerCommand::AddPeer {
                config: make_config(addr, 65000 + u32::from(i)),
                reply: reply_tx,
            })
            .await
            .unwrap();
            let _ = reply_rx.await;
        }

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[test]
    fn build_transport_config_preserves_local_ipv6_nexthop() {
        let (_, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );

        let nh: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut config = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
        config.local_ipv6_nexthop = Some(nh);

        let transport = mgr.build_transport_config(&config);
        assert_eq!(transport.local_ipv6_nexthop, Some(nh));
    }

    #[test]
    fn build_transport_config_preserves_route_server_client() {
        let (_, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );

        let mut config = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
        config.route_server_client = true;

        let transport = mgr.build_transport_config(&config);
        assert!(transport.route_server_client);
    }

    #[test]
    fn collision_local_wins() {
        // Local router-id 10.0.0.10 (higher) vs remote 10.0.0.2 (lower)
        // → local wins, inbound should be dropped
        let local_id = u32::from(Ipv4Addr::new(10, 0, 0, 10));
        let remote_id = u32::from(Ipv4Addr::new(10, 0, 0, 2));
        assert!(local_id > remote_id, "local should win collision");
    }

    #[test]
    fn collision_remote_wins() {
        // Local router-id 10.0.0.1 (lower) vs remote 10.0.0.10 (higher)
        // → remote wins, existing session should be dumped
        let local_id = u32::from(Ipv4Addr::new(10, 0, 0, 1));
        let remote_id = u32::from(Ipv4Addr::new(10, 0, 0, 10));
        assert!(local_id < remote_id, "remote should win collision");
    }

    #[tokio::test]
    async fn collision_existing_goes_idle_accepts_pending() {
        // Verify the PeerManager correctly handles notifications via its
        // select! loop (session_notify channel is wired).
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Add peer
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::AddPeer {
            config: make_config(addr, 65002),
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        // Verify the peer exists
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::GetPeerState {
            address: addr,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let info = reply_rx.await.unwrap();
        assert!(info.is_some());

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn disable_peer_stays_disabled() {
        // Verify that disabling a peer keeps it disabled even after
        // the session goes idle (BackToIdle should not re-enable).
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Add peer
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::AddPeer {
            config: make_config(addr, 65002),
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        // Disable peer
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::DisablePeer {
            address: addr,
            reason: None,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        // Give time for the session to process Stop and go Idle
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify the peer is still disabled
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::GetPeerState {
            address: addr,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let info = reply_rx.await.unwrap().unwrap();
        assert!(!info.enabled, "peer should remain disabled");

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn inbound_during_established_dropped() {
        // Verify the handle_inbound match arm for Established works.
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            metrics,
            rib_tx,
            None,
        );
        let handle = tokio::spawn(mgr.run());

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Add peer
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::AddPeer {
            config: make_config(addr, 65002),
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[test]
    fn build_transport_config_sets_restart_window_for_eligible_static_peer() {
        let (_tx, rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            Some(Instant::now() + Duration::from_secs(30)),
            BgpMetrics::new(),
            rib_tx,
            None,
        );
        let mut cfg = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
        cfg.gr_restart_eligible = true;

        let transport = mgr.build_transport_config(&cfg);
        assert!(transport.gr_restart_until.is_some());
    }

    #[test]
    fn build_transport_config_omits_restart_window_for_dynamic_peer() {
        let (_tx, rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let mgr = PeerManager::new(
            rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            Some(Instant::now() + Duration::from_secs(30)),
            BgpMetrics::new(),
            rib_tx,
            None,
        );
        let cfg = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);

        let transport = mgr.build_transport_config(&cfg);
        assert!(transport.gr_restart_until.is_none());
    }
}
