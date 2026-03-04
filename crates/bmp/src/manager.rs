//! BMP fan-out manager.
//!
//! Receives `BmpEvent`s from transport, encodes them into BMP wire
//! format, and distributes the encoded bytes to all collector channels.

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::codec;
use crate::types::BmpEvent;

/// BMP manager that fans out encoded messages to all collectors.
pub struct BmpManager {
    event_rx: mpsc::Receiver<BmpEvent>,
    collectors: Vec<mpsc::Sender<Bytes>>,
}

impl BmpManager {
    #[must_use]
    pub fn new(event_rx: mpsc::Receiver<BmpEvent>, collectors: Vec<mpsc::Sender<Bytes>>) -> Self {
        Self {
            event_rx,
            collectors,
        }
    }

    /// Run the manager loop. Receives events, encodes, and fans out.
    /// Returns when the event channel is closed (daemon shutdown).
    pub async fn run(mut self) {
        while let Some(event) = self.event_rx.recv().await {
            let encoded = Self::encode_event(&event);
            self.fan_out(&encoded);
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
            BmpEvent::PeerDown { peer_info, reason } => {
                codec::encode_peer_down(peer_info, reason)
            }
            BmpEvent::RouteMonitoring {
                peer_info,
                update_pdu,
            } => codec::encode_route_monitoring(peer_info, update_pdu),
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
        let (c1_tx, mut c1_rx) = mpsc::channel(16);
        let (c2_tx, mut c2_rx) = mpsc::channel(16);

        let mgr = BmpManager::new(event_rx, vec![c1_tx, c2_tx]);
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
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn manager_handles_peer_up() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (c_tx, mut c_rx) = mpsc::channel(16);

        let mgr = BmpManager::new(event_rx, vec![c_tx]);
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
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn manager_handles_peer_down() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (c_tx, mut c_rx) = mpsc::channel(16);

        let mgr = BmpManager::new(event_rx, vec![c_tx]);
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
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn manager_exits_on_channel_close() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (c_tx, _c_rx) = mpsc::channel(16);

        let mgr = BmpManager::new(event_rx, vec![c_tx]);
        let handle = tokio::spawn(mgr.run());

        drop(event_tx);
        // Manager should exit cleanly
        handle.await.unwrap();
    }
}
