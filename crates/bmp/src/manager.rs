//! BMP fan-out manager.
//!
//! Receives `BmpEvent`s from transport, encodes them into BMP wire
//! format, and distributes the encoded bytes to all collector channels.

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::codec;
use crate::types::{BmpControlEvent, BmpEvent};

/// BMP manager that fans out encoded messages to all collectors.
pub struct BmpManager {
    event_rx: mpsc::Receiver<BmpEvent>,
    control_rx: mpsc::Receiver<BmpControlEvent>,
    collectors: Vec<mpsc::Sender<Bytes>>,
    /// Latest encoded PeerUp message per peer address.
    peer_up_cache: std::collections::HashMap<std::net::IpAddr, Bytes>,
}

impl BmpManager {
    #[must_use]
    pub fn new(
        event_rx: mpsc::Receiver<BmpEvent>,
        control_rx: mpsc::Receiver<BmpControlEvent>,
        collectors: Vec<mpsc::Sender<Bytes>>,
    ) -> Self {
        Self {
            event_rx,
            control_rx,
            collectors,
            peer_up_cache: std::collections::HashMap::new(),
        }
    }

    /// Run the manager loop. Receives events, encodes, and fans out.
    /// Returns when both event and control channels are closed.
    pub async fn run(mut self) {
        let mut events_open = true;
        let mut control_open = true;

        while events_open || control_open {
            tokio::select! {
                maybe_event = self.event_rx.recv(), if events_open => {
                    match maybe_event {
                        Some(event) => self.handle_event(event),
                        None => {
                            events_open = false;
                            debug!("BMP event channel closed");
                        }
                    }
                }
                maybe_control = self.control_rx.recv(), if control_open => {
                    match maybe_control {
                        Some(control) => self.handle_control(control),
                        None => {
                            control_open = false;
                            debug!("BMP control channel closed");
                        }
                    }
                }
            }
        }
        debug!("BMP manager shutting down");
    }

    fn encode_event(event: &BmpEvent) -> Bytes {
        match event {
            BmpEvent::PeerUp {
                peer_info,
                local_open,
                remote_open,
                local_addr,
                local_port,
                remote_port,
            } => codec::encode_peer_up(
                peer_info,
                *local_addr,
                *local_port,
                *remote_port,
                local_open,
                remote_open,
            ),
            BmpEvent::PeerDown { peer_info, reason } => codec::encode_peer_down(peer_info, reason),
            BmpEvent::RouteMonitoring {
                peer_info,
                update_pdu,
            } => codec::encode_route_monitoring(peer_info, update_pdu),
            BmpEvent::StatsReport {
                peer_info,
                adj_rib_in_routes,
            } => codec::encode_stats_report(
                peer_info,
                &[codec::StatCounter {
                    stat_type: 7,
                    value: *adj_rib_in_routes,
                }],
                &[],
            ),
        }
    }

    fn handle_event(&mut self, event: BmpEvent) {
        match &event {
            BmpEvent::PeerUp { peer_info, .. } => {
                let encoded = Self::encode_event(&event);
                self.peer_up_cache.insert(peer_info.peer_addr, encoded.clone());
                self.fan_out(&encoded);
            }
            BmpEvent::PeerDown { peer_info, .. } => {
                self.peer_up_cache.remove(&peer_info.peer_addr);
                let encoded = Self::encode_event(&event);
                self.fan_out(&encoded);
            }
            BmpEvent::RouteMonitoring { .. } | BmpEvent::StatsReport { .. } => {
                let encoded = Self::encode_event(&event);
                self.fan_out(&encoded);
            }
        }
    }

    fn handle_control(&self, control: BmpControlEvent) {
        match control {
            BmpControlEvent::CollectorConnected {
                collector_id,
                collector_addr,
            } => {
                info!(
                    collector_id,
                    collector = %collector_addr,
                    peer_count = self.peer_up_cache.len(),
                    "BMP collector connected, replaying current PeerUp state"
                );
                self.replay_peer_up_to_collector(collector_id);
            }
            BmpControlEvent::CollectorDisconnected {
                collector_id,
                collector_addr,
            } => {
                debug!(
                    collector_id,
                    collector = %collector_addr,
                    "BMP collector disconnected"
                );
            }
        }
    }

    fn replay_peer_up_to_collector(&self, collector_id: usize) {
        let Some(tx) = self.collectors.get(collector_id) else {
            warn!(
                collector_id,
                "BMP replay target collector index out of range, skipping"
            );
            return;
        };

        for msg in self.peer_up_cache.values() {
            if let Err(e) = tx.try_send(msg.clone()) {
                warn!(
                    collector_id,
                    error = %e,
                    "BMP collector channel full or closed during replay"
                );
                break;
            }
        }
    }

    fn fan_out(&self, msg: &Bytes) {
        for tx in &self.collectors {
            if let Err(e) = tx.try_send(msg.clone()) {
                warn!(error = %e, "BMP collector channel full or closed, dropping message");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::UNIX_EPOCH;

    use super::*;
    use crate::types::{BmpPeerInfo, BmpPeerType, PeerDownReason};

    fn sample_peer_info() -> BmpPeerInfo {
        BmpPeerInfo {
            peer_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            peer_asn: 65002,
            peer_bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            peer_type: BmpPeerType::Global,
            is_ipv6: false,
            is_post_policy: false,
            is_as4: true,
            timestamp: UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
        }
    }

    #[tokio::test]
    async fn manager_fans_out_to_all_collectors() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (c1_tx, mut c1_rx) = mpsc::channel(16);
        let (c2_tx, mut c2_rx) = mpsc::channel(16);

        let mgr = BmpManager::new(event_rx, control_rx, vec![c1_tx, c2_tx]);
        let handle = tokio::spawn(mgr.run());

        // Send a RouteMonitoring event
        let info = sample_peer_info();
        let update = Bytes::from_static(&[0xAA; 23]);
        event_tx
            .send(BmpEvent::RouteMonitoring {
                peer_info: info,
                update_pdu: update,
            })
            .await
            .unwrap();

        // Both collectors should receive the encoded message
        let msg1 = c1_rx.recv().await.unwrap();
        let msg2 = c2_rx.recv().await.unwrap();
        assert_eq!(msg1, msg2);
        assert!(!msg1.is_empty());

        // Verify BMP common header
        assert_eq!(msg1[0], 3); // BMP version
        assert_eq!(msg1[5], 0); // Route Monitoring type

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn manager_handles_peer_up() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (c_tx, mut c_rx) = mpsc::channel(16);

        let mgr = BmpManager::new(event_rx, control_rx, vec![c_tx]);
        let handle = tokio::spawn(mgr.run());

        event_tx
            .send(BmpEvent::PeerUp {
                peer_info: sample_peer_info(),
                local_open: Bytes::from_static(&[0xFF; 29]),
                remote_open: Bytes::from_static(&[0xFE; 29]),
                local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                local_port: 179,
                remote_port: 54321,
            })
            .await
            .unwrap();

        let msg = c_rx.recv().await.unwrap();
        assert_eq!(msg[5], 3); // Peer Up type

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn manager_handles_peer_down() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (c_tx, mut c_rx) = mpsc::channel(16);

        let mgr = BmpManager::new(event_rx, control_rx, vec![c_tx]);
        let handle = tokio::spawn(mgr.run());

        event_tx
            .send(BmpEvent::PeerDown {
                peer_info: sample_peer_info(),
                reason: PeerDownReason::RemoteNoNotification,
            })
            .await
            .unwrap();

        let msg = c_rx.recv().await.unwrap();
        assert_eq!(msg[5], 2); // Peer Down type

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn manager_handles_stats_report() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (c_tx, mut c_rx) = mpsc::channel(16);

        let mgr = BmpManager::new(event_rx, control_rx, vec![c_tx]);
        let handle = tokio::spawn(mgr.run());

        event_tx
            .send(BmpEvent::StatsReport {
                peer_info: sample_peer_info(),
                adj_rib_in_routes: 42,
            })
            .await
            .unwrap();

        let msg = c_rx.recv().await.unwrap();
        assert_eq!(msg[5], 1); // Stats Report type

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn manager_exits_on_channel_close() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (c_tx, _c_rx) = mpsc::channel(16);

        let mgr = BmpManager::new(event_rx, control_rx, vec![c_tx]);
        let handle = tokio::spawn(mgr.run());

        drop(event_tx);
        drop(control_tx);
        // Manager should exit cleanly
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn collector_connected_replays_peer_up_only_to_target_collector() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (c1_tx, mut c1_rx) = mpsc::channel(16);
        let (c2_tx, mut c2_rx) = mpsc::channel(16);

        let mgr = BmpManager::new(event_rx, control_rx, vec![c1_tx, c2_tx]);
        let handle = tokio::spawn(mgr.run());

        // First, learn one established peer via normal PeerUp event.
        event_tx
            .send(BmpEvent::PeerUp {
                peer_info: sample_peer_info(),
                local_open: Bytes::from_static(&[0xFF; 29]),
                remote_open: Bytes::from_static(&[0xFE; 29]),
                local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                local_port: 179,
                remote_port: 54321,
            })
            .await
            .unwrap();

        // Drain the original fan-out message from both collectors.
        let _ = c1_rx.recv().await.unwrap();
        let _ = c2_rx.recv().await.unwrap();

        // Simulate collector #0 reconnect.
        control_tx
            .send(BmpControlEvent::CollectorConnected {
                collector_id: 0,
                collector_addr: "127.0.0.1:11019".parse().unwrap(),
            })
            .await
            .unwrap();

        // Collector 0 should get replay.
        let replay = c1_rx.recv().await.unwrap();
        assert_eq!(replay[0], 3); // BMP version
        assert_eq!(replay[5], 3); // PeerUp message type

        // Collector 1 should not receive replay from collector 0 reconnect.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), c2_rx.recv())
                .await
                .is_err()
        );

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();
    }
}
