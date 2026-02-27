use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use rustbgpd_api::peer_types::{PeerInfo, PeerManagerCommand, PeerManagerNeighborConfig};
use rustbgpd_fsm::{PeerConfig, SessionState};
use rustbgpd_rib::RibUpdate;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::{PeerHandle, TransportConfig};
use rustbgpd_wire::{Afi, Safi};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

const DEFAULT_HOLD_TIME: u16 = 90;
const DEFAULT_CONNECT_RETRY_SECS: u32 = 30;
const BGP_PORT: u16 = 179;

struct ManagedPeer {
    handle: PeerHandle,
    remote_asn: u32,
    description: String,
    enabled: bool,
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
    metrics: BgpMetrics,
    rib_tx: mpsc::Sender<RibUpdate>,
}

impl PeerManager {
    pub fn new(
        rx: mpsc::Receiver<PeerManagerCommand>,
        local_asn: u32,
        router_id: Ipv4Addr,
        metrics: BgpMetrics,
        rib_tx: mpsc::Sender<RibUpdate>,
    ) -> Self {
        Self {
            peers: HashMap::new(),
            rx,
            local_asn,
            router_id,
            metrics,
            rib_tx,
        }
    }

    fn build_transport_config(&self, config: &PeerManagerNeighborConfig) -> TransportConfig {
        let peer = PeerConfig {
            local_asn: self.local_asn,
            remote_asn: config.remote_asn,
            local_router_id: self.router_id,
            hold_time: config.hold_time.unwrap_or(DEFAULT_HOLD_TIME),
            connect_retry_secs: DEFAULT_CONNECT_RETRY_SECS,
            families: vec![(Afi::Ipv4, Safi::Unicast)],
        };
        let remote_addr = SocketAddr::new(config.address, BGP_PORT);
        let mut transport = TransportConfig::new(peer, remote_addr);
        transport.max_prefixes = config.max_prefixes;
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

        let handle = PeerHandle::spawn(
            transport,
            self.metrics.clone(),
            self.rib_tx.clone(),
            config.import_policy,
            config.export_policy,
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
        let (state, prefix_count) = match managed.handle.query_state().await {
            Some(s) => (s.fsm_state, s.prefix_count),
            None => (SessionState::Idle, 0),
        };

        Some(PeerInfo {
            address,
            remote_asn: managed.remote_asn,
            description: managed.description.clone(),
            state,
            enabled: managed.enabled,
            prefix_count,
        })
    }

    async fn list_peers(&self) -> Vec<PeerInfo> {
        let mut infos = Vec::with_capacity(self.peers.len());
        for (&addr, managed) in &self.peers {
            let (state, prefix_count) = match managed.handle.query_state().await {
                Some(s) => (s.fsm_state, s.prefix_count),
                None => (SessionState::Idle, 0),
            };
            infos.push(PeerInfo {
                address: addr,
                remote_asn: managed.remote_asn,
                description: managed.description.clone(),
                state,
                enabled: managed.enabled,
                prefix_count,
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

    async fn disable_peer(&mut self, address: IpAddr) -> Result<(), String> {
        let managed = self
            .peers
            .get_mut(&address)
            .ok_or_else(|| format!("peer {address} not found"))?;
        managed.enabled = false;
        managed
            .handle
            .stop()
            .await
            .map_err(|e| format!("failed to stop peer: {e}"))?;
        info!(%address, "peer disabled");
        Ok(())
    }

    /// Run the `PeerManager` event loop until shutdown or channel close.
    pub async fn run(mut self) {
        while let Some(cmd) = self.rx.recv().await {
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
                PeerManagerCommand::DisablePeer { address, reply } => {
                    let result = self.disable_peer(address).await;
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

        debug!("peer manager channel closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    fn make_config(addr: IpAddr, asn: u32) -> PeerManagerNeighborConfig {
        PeerManagerNeighborConfig {
            address: addr,
            remote_asn: asn,
            description: format!("test-peer-{addr}"),
            hold_time: None,
            max_prefixes: None,
            import_policy: None,
            export_policy: None,
        }
    }

    #[tokio::test]
    async fn add_peer_and_list() {
        let (tx, rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let metrics = BgpMetrics::new();
        let mgr = PeerManager::new(rx, 65001, Ipv4Addr::new(10, 0, 0, 1), metrics, rib_tx);
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
        let mgr = PeerManager::new(rx, 65001, Ipv4Addr::new(10, 0, 0, 1), metrics, rib_tx);
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
        let mgr = PeerManager::new(rx, 65001, Ipv4Addr::new(10, 0, 0, 1), metrics, rib_tx);
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
        let mgr = PeerManager::new(rx, 65001, Ipv4Addr::new(10, 0, 0, 1), metrics, rib_tx);
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
        let mgr = PeerManager::new(rx, 65001, Ipv4Addr::new(10, 0, 0, 1), metrics, rib_tx);
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
        let mgr = PeerManager::new(rx, 65001, Ipv4Addr::new(10, 0, 0, 1), metrics, rib_tx);
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
        let mgr = PeerManager::new(rx, 65001, Ipv4Addr::new(10, 0, 0, 1), metrics, rib_tx);
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
}
