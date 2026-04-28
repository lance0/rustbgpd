//! BMP fan-out manager.
//!
//! Receives `BmpEvent`s from transport, encodes them into BMP wire
//! format, and distributes the encoded bytes to all collector channels.

use std::net::SocketAddr;

use bytes::Bytes;
use rustbgpd_telemetry::BgpMetrics;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::codec;
use crate::types::{BmpControlEvent, BmpEvent};

/// BMP manager that fans out encoded messages to all collectors.
pub struct BmpManager {
    event_rx: mpsc::Receiver<BmpEvent>,
    control_rx: mpsc::Receiver<BmpControlEvent>,
    /// Per-collector address + sender, paired by index. The address is
    /// the operator-facing identifier used as the `collector` label on
    /// `bmp_*` Prometheus counters.
    collectors: Vec<(SocketAddr, mpsc::Sender<Bytes>)>,
    /// Latest encoded `PeerUp` message per peer address.
    peer_up_cache: std::collections::HashMap<std::net::IpAddr, Bytes>,
    metrics: BgpMetrics,
}

impl BmpManager {
    /// Create a new BMP manager with the given event/control channels and collectors.
    #[must_use]
    pub fn new(
        event_rx: mpsc::Receiver<BmpEvent>,
        control_rx: mpsc::Receiver<BmpControlEvent>,
        collectors: Vec<(SocketAddr, mpsc::Sender<Bytes>)>,
        metrics: BgpMetrics,
    ) -> Self {
        Self {
            event_rx,
            control_rx,
            collectors,
            peer_up_cache: std::collections::HashMap::new(),
            metrics,
        }
    }

    /// Run the manager loop. Receives events, encodes, and fans out.
    /// Returns when both channels are closed or an explicit shutdown is
    /// requested.
    pub async fn run(mut self) {
        let mut events_open = true;
        let mut control_open = true;

        while events_open || control_open {
            tokio::select! {
                maybe_event = self.event_rx.recv(), if events_open => {
                    if let Some(event) = maybe_event {
                        self.handle_event(&event);
                    } else {
                        events_open = false;
                        debug!("BMP event channel closed");
                    }
                }
                maybe_control = self.control_rx.recv(), if control_open => {
                    if let Some(control) = maybe_control {
                        if self.handle_control(control) {
                            break;
                        }
                    } else {
                        control_open = false;
                        debug!("BMP control channel closed");
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

    fn handle_event(&mut self, event: &BmpEvent) {
        match event {
            BmpEvent::PeerUp { peer_info, .. } => {
                let encoded = Self::encode_event(event);
                self.peer_up_cache
                    .insert(peer_info.peer_addr, encoded.clone());
                self.fan_out(&encoded);
            }
            BmpEvent::PeerDown { peer_info, .. } => {
                self.peer_up_cache.remove(&peer_info.peer_addr);
                let encoded = Self::encode_event(event);
                self.fan_out(&encoded);
            }
            BmpEvent::RouteMonitoring { .. } | BmpEvent::StatsReport { .. } => {
                let encoded = Self::encode_event(event);
                self.fan_out(&encoded);
            }
        }
    }

    /// Returns true when manager should exit.
    fn handle_control(&mut self, control: BmpControlEvent) -> bool {
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
                false
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
                false
            }
            BmpControlEvent::Shutdown => {
                info!("BMP manager received shutdown request");
                true
            }
        }
    }

    fn replay_peer_up_to_collector(&self, collector_id: usize) {
        let Some((addr, tx)) = self.collectors.get(collector_id) else {
            warn!(
                collector_id,
                "BMP replay target collector index out of range, skipping"
            );
            return;
        };
        let addr_label = addr.to_string();
        self.metrics.record_bmp_replay_attempt(&addr_label);

        // Iterate via a counted index so an abort can attribute every
        // remaining cached-PeerUp message as dropped — otherwise a
        // single saturation event under-reports thousands of skipped
        // peers as one drop.
        let cache_values: Vec<&Bytes> = self.peer_up_cache.values().collect();
        for (idx, msg) in cache_values.iter().enumerate() {
            if let Err(e) = tx.try_send((*msg).clone()) {
                let reason = trysend_reason(&e);
                let remaining = u64::try_from(cache_values.len() - idx).unwrap_or(u64::MAX);
                self.metrics
                    .record_bmp_collector_drop(&addr_label, "replay", reason, remaining);
                warn!(
                    collector_id,
                    collector = %addr,
                    error = %e,
                    skipped = remaining,
                    "BMP collector channel full or closed during replay; remaining PeerUp messages dropped"
                );
                break;
            }
        }
    }

    fn fan_out(&self, msg: &Bytes) {
        for (addr, tx) in &self.collectors {
            if let Err(e) = tx.try_send(msg.clone()) {
                let reason = trysend_reason(&e);
                self.metrics
                    .record_bmp_collector_drop(&addr.to_string(), "fan_out", reason, 1);
                warn!(
                    collector = %addr,
                    error = %e,
                    "BMP collector channel full or closed, dropping message"
                );
            }
        }
    }
}

/// Classify a `tokio::sync::mpsc::error::TrySendError` into the
/// `reason` label used on `bmp_*_drops_total` counters.
fn trysend_reason<T>(err: &mpsc::error::TrySendError<T>) -> &'static str {
    match err {
        mpsc::error::TrySendError::Full(_) => "channel_full",
        mpsc::error::TrySendError::Closed(_) => "channel_closed",
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::UNIX_EPOCH;

    use super::*;
    use crate::types::{BmpPeerInfo, BmpPeerType, PeerDownReason};

    fn collector_addr(id: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 11000 + id))
    }

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

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), c1_tx), (collector_addr(1), c2_tx)],
            BgpMetrics::new(),
        );
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

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), c_tx)],
            BgpMetrics::new(),
        );
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

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), c_tx)],
            BgpMetrics::new(),
        );
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

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), c_tx)],
            BgpMetrics::new(),
        );
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

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), c_tx)],
            BgpMetrics::new(),
        );
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

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), c1_tx), (collector_addr(1), c2_tx)],
            BgpMetrics::new(),
        );
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

    /// Sum the values of all metrics in the family with `name`.
    /// Returns `0` if the family is absent. Counters are always
    /// integer-valued so `as u64` is exact (no float-cmp drama).
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "Prometheus counters are monotonic non-negative integers exposed as f64"
    )]
    fn metric_family_sum(metrics: &BgpMetrics, name: &str) -> u64 {
        metrics
            .registry()
            .gather()
            .iter()
            .find(|f| f.get_name() == name)
            .map_or(0, |f| {
                f.get_metric()
                    .iter()
                    .map(|m| m.get_counter().get_value() as u64)
                    .sum()
            })
    }

    /// Find a counter sample in the family `name` whose label set
    /// matches every (key, value) pair in `match_labels`.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "Prometheus counters are monotonic non-negative integers exposed as f64"
    )]
    fn metric_value_with_labels(
        metrics: &BgpMetrics,
        name: &str,
        match_labels: &[(&str, &str)],
    ) -> u64 {
        metrics
            .registry()
            .gather()
            .into_iter()
            .find(|f| f.get_name() == name)
            .and_then(|mut f| {
                f.take_metric().into_iter().find(|m| {
                    match_labels.iter().all(|(k, v)| {
                        m.get_label()
                            .iter()
                            .any(|l| l.get_name() == *k && l.get_value() == *v)
                    })
                })
            })
            .map_or(0, |m| m.get_counter().get_value() as u64)
    }

    /// Collector channel saturates during regular fan-out → manager
    /// records a `bmp_collector_drops_total{phase=fan_out}` increment.
    ///
    /// We pre-fill a 1-deep channel before constructing the manager so
    /// the next `try_send` in `fan_out` is guaranteed to fail with
    /// `Full`.
    #[tokio::test]
    async fn fan_out_drop_increments_collector_drop_counter() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (c_tx, _c_rx) = mpsc::channel::<Bytes>(1);
        // Pre-fill the collector channel so the manager's first
        // try_send hits Full.
        c_tx.try_send(Bytes::from_static(b"prefill")).unwrap();
        let addr = collector_addr(7);

        let metrics = BgpMetrics::new();
        let mgr = BmpManager::new(event_rx, control_rx, vec![(addr, c_tx)], metrics.clone());
        let handle = tokio::spawn(mgr.run());

        event_tx
            .send(BmpEvent::RouteMonitoring {
                peer_info: sample_peer_info(),
                update_pdu: Bytes::from_static(&[0xAA; 23]),
            })
            .await
            .unwrap();

        // Give the manager a moment to process and bump the counter.
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            if metric_family_sum(&metrics, "bmp_collector_drops_total") >= 1 {
                break;
            }
        }

        let dropped = metric_value_with_labels(
            &metrics,
            "bmp_collector_drops_total",
            &[("phase", "fan_out")],
        );
        assert_eq!(dropped, 1, "fan-out drop should have incremented counter");

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();
    }

    /// Replay aborts after the first `try_send` failure, so it must
    /// attribute every remaining cached-PeerUp message as dropped. Otherwise
    /// a saturated reconnect on a fabric with many peers under-reports the
    /// loss as a single drop and operators see "1 drop" while thousands of
    /// peers are missing from the collector's view.
    ///
    /// Builds a 5-deep `PeerUp` cache via 5 distinct `PeerUp` events, then
    /// replays into a 1-deep collector channel pre-filled with one byte
    /// so every replay `try_send` hits Full. Asserts the replay-phase
    /// drop counter equals the cache size, not 1.
    #[tokio::test]
    async fn replay_drop_counts_every_skipped_cached_peer() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        // 5-deep collector channel: enough to absorb 5 PeerUp fan-outs
        // during cache build, then we'll saturate it before triggering replay.
        let (c_tx, mut c_rx) = mpsc::channel::<Bytes>(5);
        let addr = collector_addr(9);

        let metrics = BgpMetrics::new();
        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(addr, c_tx.clone())],
            metrics.clone(),
        );
        let handle = tokio::spawn(mgr.run());

        // Build a 5-peer PeerUp cache. Each PeerUp also fan-outs to the
        // collector, so we drain those as they arrive.
        for octet in 1..=5u8 {
            let mut info = sample_peer_info();
            info.peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet));
            info.peer_bgp_id = Ipv4Addr::new(10, 0, 0, octet);
            event_tx
                .send(BmpEvent::PeerUp {
                    peer_info: info,
                    local_open: Bytes::from_static(&[0xFF; 29]),
                    remote_open: Bytes::from_static(&[0xFE; 29]),
                    local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    local_port: 179,
                    remote_port: 54321,
                })
                .await
                .unwrap();
            // Drain the fan-out so the channel is empty before replay.
            let _ = c_rx.recv().await.unwrap();
        }

        // Saturate the collector channel — every replay try_send will hit Full.
        for _ in 0..5 {
            c_tx.try_send(Bytes::from_static(b"x")).unwrap();
        }

        // Trigger replay.
        control_tx
            .send(BmpControlEvent::CollectorConnected {
                collector_id: 0,
                collector_addr: addr,
            })
            .await
            .unwrap();

        // Wait for the counter to reflect at least the full cache size.
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            if metric_family_sum(&metrics, "bmp_collector_drops_total") >= 5 {
                break;
            }
        }

        let dropped = metric_value_with_labels(
            &metrics,
            "bmp_collector_drops_total",
            &[("phase", "replay")],
        );
        assert_eq!(
            dropped, 5,
            "replay abort should attribute every skipped cached PeerUp (5), \
             not just the first try_send failure"
        );

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();
    }

    /// Collector reconnect (`CollectorConnected`) → manager records a
    /// `bmp_replay_attempts_total{collector=...}` increment, even if
    /// the `PeerUp` cache is empty.
    #[tokio::test]
    async fn collector_connected_increments_replay_attempts() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (c_tx, _c_rx) = mpsc::channel(16);
        let addr = collector_addr(3);

        let metrics = BgpMetrics::new();
        let mgr = BmpManager::new(event_rx, control_rx, vec![(addr, c_tx)], metrics.clone());
        let handle = tokio::spawn(mgr.run());

        control_tx
            .send(BmpControlEvent::CollectorConnected {
                collector_id: 0,
                collector_addr: addr,
            })
            .await
            .unwrap();

        // Allow the manager to process the control event.
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            if metric_family_sum(&metrics, "bmp_replay_attempts_total") >= 1 {
                break;
            }
        }

        let attempts = metric_value_with_labels(
            &metrics,
            "bmp_replay_attempts_total",
            &[("collector", &addr.to_string())],
        );
        assert_eq!(
            attempts, 1,
            "replay attempt should have incremented counter"
        );

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn manager_exits_on_explicit_shutdown() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (c_tx, _c_rx) = mpsc::channel(16);

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), c_tx)],
            BgpMetrics::new(),
        );
        let mut handle = tokio::spawn(mgr.run());

        control_tx.send(BmpControlEvent::Shutdown).await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), &mut handle)
            .await
            .expect("BMP manager did not exit after explicit shutdown")
            .unwrap();

        // Keep sender alive until after manager exits to prove explicit
        // shutdown does not depend on event channel closure.
        drop(event_tx);
    }
}
