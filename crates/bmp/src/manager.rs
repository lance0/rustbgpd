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
use crate::types::{
    BmpControlEvent, BmpDumpChunk, BmpDumpRequest, BmpEvent, BmpLocRibConfig, BmpMonitorFilter,
};

/// Per-message send timeout for a Loc-RIB dump forwarder. Paces the dump
/// to the collector's TCP drain rate via the bounded collector channel;
/// a collector that stalls longer than this aborts the dump (the next
/// reconnect triggers a fresh one).
const LOC_RIB_DUMP_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// BMP manager that fans out encoded messages to all collectors.
pub struct BmpManager {
    event_rx: mpsc::Receiver<BmpEvent>,
    control_rx: mpsc::Receiver<BmpControlEvent>,
    /// Per-collector address + sender + monitoring filter, paired by
    /// index. The address is the operator-facing identifier used as the
    /// `collector` label on `bmp_*` Prometheus counters.
    collectors: Vec<(SocketAddr, mpsc::Sender<Bytes>, BmpMonitorFilter)>,
    /// Latest encoded `PeerUp` message per peer address.
    peer_up_cache: std::collections::HashMap<std::net::IpAddr, Bytes>,
    /// RFC 9069 Loc-RIB instance-peer identity. `None` = no collector
    /// monitors `loc_rib`; Loc-RIB events are dropped.
    loc_rib: Option<BmpLocRibConfig>,
    /// Loc-RIB table-dump request channel toward the RIB manager, used
    /// on collector (re)connect to synthesize the initial table sync.
    dump_tx: Option<mpsc::Sender<BmpDumpRequest>>,
    metrics: BgpMetrics,
}

impl BmpManager {
    /// Create a new BMP manager with the given event/control channels and collectors.
    #[must_use]
    pub fn new(
        event_rx: mpsc::Receiver<BmpEvent>,
        control_rx: mpsc::Receiver<BmpControlEvent>,
        collectors: Vec<(SocketAddr, mpsc::Sender<Bytes>, BmpMonitorFilter)>,
        metrics: BgpMetrics,
    ) -> Self {
        Self {
            event_rx,
            control_rx,
            collectors,
            peer_up_cache: std::collections::HashMap::new(),
            loc_rib: None,
            dump_tx: None,
            metrics,
        }
    }

    /// Enable RFC 9069 Loc-RIB monitoring: the emulated Loc-RIB instance
    /// peer identity plus the table-dump request channel used to
    /// synchronize a (re)connecting collector with the current Loc-RIB.
    #[must_use]
    pub fn with_loc_rib(
        mut self,
        cfg: BmpLocRibConfig,
        dump_tx: mpsc::Sender<BmpDumpRequest>,
    ) -> Self {
        self.loc_rib = Some(cfg);
        self.dump_tx = Some(dump_tx);
        self
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
            BmpEvent::LocRibRouteMonitoring { .. } | BmpEvent::LocRibStats { .. } => {
                unreachable!("Loc-RIB events are encoded in handle_loc_rib_event")
            }
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
                adj_rib_out_post,
            } => {
                let mut counters = vec![codec::StatCounter {
                    stat_type: 7,
                    value: *adj_rib_in_routes,
                }];
                let mut afi_counters = Vec::new();
                // RFC 8671: type 15 = post-policy Adj-RIB-Out total,
                // type 17 = its per-AFI/SAFI breakdown. Omitted when
                // the counts were unavailable this tick.
                if let Some(per_family) = adj_rib_out_post {
                    counters.push(codec::StatCounter {
                        stat_type: 15,
                        value: per_family.iter().map(|(_, _, count)| count).sum(),
                    });
                    for &(afi, safi, value) in per_family {
                        afi_counters.push(codec::AfiStatCounter {
                            stat_type: 17,
                            afi,
                            safi,
                            value,
                        });
                    }
                }
                codec::encode_stats_report(peer_info, &counters, &afi_counters)
            }
        }
    }

    /// Encode and fan out an RFC 9069 Loc-RIB event to `loc_rib`
    /// collectors. Dropped silently when Loc-RIB monitoring is not
    /// configured (no collector monitors the view).
    fn handle_loc_rib_event(&self, event: &BmpEvent) {
        let Some(ref cfg) = self.loc_rib else {
            return;
        };
        let encoded = match event {
            BmpEvent::LocRibRouteMonitoring {
                update_pdu,
                timestamp,
            } => codec::encode_route_monitoring(&cfg.peer_info(*timestamp), update_pdu),
            BmpEvent::LocRibStats { per_family } => {
                // RFC 9069 stat type 8 = Loc-RIB total (64-bit gauge),
                // type 10 = its per-AFI/SAFI breakdown.
                let counters = vec![codec::StatCounter {
                    stat_type: 8,
                    value: per_family.iter().map(|(_, _, count)| count).sum(),
                }];
                let afi_counters: Vec<codec::AfiStatCounter> = per_family
                    .iter()
                    .map(|&(afi, safi, value)| codec::AfiStatCounter {
                        stat_type: 10,
                        afi,
                        safi,
                        value,
                    })
                    .collect();
                codec::encode_stats_report(
                    &cfg.peer_info(std::time::SystemTime::now()),
                    &counters,
                    &afi_counters,
                )
            }
            _ => return,
        };
        self.fan_out_filtered(&encoded, |f| f.loc_rib);
    }

    fn handle_event(&mut self, event: &BmpEvent) {
        match event {
            BmpEvent::LocRibRouteMonitoring { .. } | BmpEvent::LocRibStats { .. } => {
                self.handle_loc_rib_event(event);
            }
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
            // Route monitoring is the only per-collector-filtered
            // message: rib-in RM only to `rib_in_pre` collectors,
            // rib-out RM only to `rib_out_post` collectors.
            BmpEvent::RouteMonitoring { peer_info, .. } => {
                let encoded = Self::encode_event(event);
                let rib_out = peer_info.is_rib_out;
                self.fan_out_filtered(&encoded, |f| {
                    if rib_out {
                        f.rib_out_post
                    } else {
                        f.rib_in_pre
                    }
                });
            }
            BmpEvent::StatsReport { .. } => {
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
                self.start_loc_rib_sync(collector_id);
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
                // RFC 9069 §5.3: the Loc-RIB instance peer goes down with
                // reason 6 + the VRF/Table Name TLV when monitoring stops.
                if let Some(ref cfg) = self.loc_rib {
                    let down = codec::encode_loc_rib_peer_down(cfg, std::time::SystemTime::now());
                    self.fan_out_filtered(&down, |f| f.loc_rib);
                }
                true
            }
        }
    }

    fn replay_peer_up_to_collector(&self, collector_id: usize) {
        let Some((addr, tx, _)) = self.collectors.get(collector_id) else {
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

    /// RFC 9069 table sync for a (re)connected collector that monitors
    /// `loc_rib`: replay the Loc-RIB instance Peer Up, then request a
    /// Loc-RIB dump from the RIB manager and forward its chunks —
    /// synthesized Route Monitoring PDUs ending with per-AFI/SAFI
    /// End-of-RIB markers — to this collector only.
    ///
    /// The forwarder runs as its own task so the manager loop never
    /// blocks on a slow collector; live Loc-RIB events keep fanning out
    /// concurrently and may overlap the dump (the standard BMP
    /// dump-vs-live race — collectors reconcile by prefix).
    fn start_loc_rib_sync(&self, collector_id: usize) {
        let Some(ref cfg) = self.loc_rib else {
            return;
        };
        let Some((addr, collector_tx, filter)) = self.collectors.get(collector_id) else {
            return;
        };
        if !filter.loc_rib {
            return;
        }

        let addr_label = addr.to_string();
        let peer_up = codec::encode_loc_rib_peer_up(cfg, std::time::SystemTime::now());
        if let Err(e) = collector_tx.try_send(peer_up) {
            let reason = trysend_reason(&e);
            self.metrics
                .record_bmp_collector_drop(&addr_label, "loc_rib_dump", reason, 1);
            warn!(
                collector = %addr,
                error = %e,
                "BMP collector channel full or closed for Loc-RIB PeerUp; skipping dump"
            );
            return;
        }

        let Some(ref dump_tx) = self.dump_tx else {
            return;
        };
        let (chunk_tx, chunk_rx) = mpsc::channel::<BmpDumpChunk>(4);
        if let Err(e) = dump_tx.try_send(BmpDumpRequest { reply: chunk_tx }) {
            let reason = trysend_reason(&e);
            self.metrics
                .record_bmp_collector_drop(&addr_label, "loc_rib_dump", reason, 1);
            warn!(
                collector = %addr,
                error = %e,
                "Loc-RIB dump request channel full or closed; collector starts live-only"
            );
            return;
        }

        let cfg = cfg.clone();
        let collector_tx = collector_tx.clone();
        let metrics = self.metrics.clone();
        tokio::spawn(forward_loc_rib_dump(
            chunk_rx,
            collector_tx,
            cfg,
            metrics,
            addr_label,
        ));
    }

    fn fan_out(&self, msg: &Bytes) {
        self.fan_out_filtered(msg, |_| true);
    }

    fn fan_out_filtered(&self, msg: &Bytes, want: impl Fn(&BmpMonitorFilter) -> bool) {
        for (addr, tx, filter) in &self.collectors {
            if !want(filter) {
                continue;
            }
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

/// Forward one Loc-RIB dump — chunks of `(synthesized UPDATE PDU,
/// install time)` from the RIB manager — to a single collector as
/// Route Monitoring messages. The bounded collector channel plus a
/// per-message send timeout pace the dump at the collector's drain
/// rate; a timeout or closed channel aborts the dump (a fresh one runs
/// on the next reconnect).
async fn forward_loc_rib_dump(
    mut chunk_rx: mpsc::Receiver<BmpDumpChunk>,
    collector_tx: mpsc::Sender<Bytes>,
    cfg: BmpLocRibConfig,
    metrics: BgpMetrics,
    addr_label: String,
) {
    let mut sent: u64 = 0;
    while let Some(chunk) = chunk_rx.recv().await {
        for (pdu, timestamp) in chunk.messages {
            let msg = codec::encode_route_monitoring(&cfg.peer_info(timestamp), &pdu);
            match tokio::time::timeout(LOC_RIB_DUMP_SEND_TIMEOUT, collector_tx.send(msg)).await {
                Ok(Ok(())) => sent += 1,
                Ok(Err(_)) => {
                    metrics.record_bmp_collector_drop(
                        &addr_label,
                        "loc_rib_dump",
                        "channel_closed",
                        1,
                    );
                    warn!(collector = %addr_label, "collector channel closed mid Loc-RIB dump, aborting");
                    return;
                }
                Err(_) => {
                    metrics.record_bmp_collector_drop(
                        &addr_label,
                        "loc_rib_dump",
                        "send_timeout",
                        1,
                    );
                    warn!(collector = %addr_label, "collector stalled during Loc-RIB dump, aborting");
                    return;
                }
            }
        }
    }
    debug!(collector = %addr_label, messages = sent, "Loc-RIB dump forwarded");
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
            is_rib_out: false,
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
            vec![
                (collector_addr(0), c1_tx, BmpMonitorFilter::default()),
                (collector_addr(1), c2_tx, BmpMonitorFilter::default()),
            ],
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

    /// Per-collector monitor filtering: collector A monitors rib-in
    /// only (default), collector B monitors both. A rib-in RM reaches
    /// both; a rib-out RM reaches only B. Non-RM messages (stats)
    /// reach both regardless.
    #[tokio::test]
    async fn route_monitoring_filtered_per_collector_monitor_selection() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (a_tx, mut a_rx) = mpsc::channel(16);
        let (b_tx, mut b_rx) = mpsc::channel(16);

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![
                (collector_addr(0), a_tx, BmpMonitorFilter::default()),
                (
                    collector_addr(1),
                    b_tx,
                    BmpMonitorFilter {
                        rib_in_pre: true,
                        rib_out_post: true,
                        loc_rib: false,
                    },
                ),
            ],
            BgpMetrics::new(),
        );
        let handle = tokio::spawn(mgr.run());

        // Rib-out RM: only collector B.
        let mut rib_out_info = sample_peer_info();
        rib_out_info.is_rib_out = true;
        rib_out_info.is_post_policy = true;
        event_tx
            .send(BmpEvent::RouteMonitoring {
                peer_info: rib_out_info,
                update_pdu: Bytes::from_static(&[0xBB; 23]),
            })
            .await
            .unwrap();

        // Rib-in RM: both collectors.
        event_tx
            .send(BmpEvent::RouteMonitoring {
                peer_info: sample_peer_info(),
                update_pdu: Bytes::from_static(&[0xAA; 23]),
            })
            .await
            .unwrap();

        // B sees rib-out first (O flag set), then rib-in.
        let b_first = b_rx.recv().await.unwrap();
        assert_eq!(b_first[5], 0, "route monitoring type");
        assert_ne!(b_first[6 + 1] & 0x10, 0, "O flag set on rib-out RM");
        assert_ne!(b_first[6 + 1] & 0x40, 0, "L flag set on rib-out RM");
        let b_second = b_rx.recv().await.unwrap();
        assert_eq!(b_second[6 + 1] & 0x10, 0, "O flag clear on rib-in RM");

        // A sees only the rib-in RM — the rib-out one was filtered.
        let a_first = a_rx.recv().await.unwrap();
        assert_eq!(a_first[5], 0);
        assert_eq!(a_first[6 + 1] & 0x10, 0, "collector A must not see rib-out");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), a_rx.recv())
                .await
                .is_err(),
            "collector A (rib-in only) must not receive the rib-out RM"
        );

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
            vec![(collector_addr(0), c_tx, BmpMonitorFilter::default())],
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
            vec![(collector_addr(0), c_tx, BmpMonitorFilter::default())],
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
            vec![(collector_addr(0), c_tx, BmpMonitorFilter::default())],
            BgpMetrics::new(),
        );
        let handle = tokio::spawn(mgr.run());

        event_tx
            .send(BmpEvent::StatsReport {
                peer_info: sample_peer_info(),
                adj_rib_in_routes: 42,
                adj_rib_out_post: Some(vec![(1, 1, 10), (2, 1, 5)]),
            })
            .await
            .unwrap();

        let msg = c_rx.recv().await.unwrap();
        assert_eq!(msg[5], 1); // Stats Report type
        // Stats count at offset 6 (common hdr) + 42 (per-peer hdr):
        // type 7 + type 15 + two type-17 entries = 4.
        let count = u32::from_be_bytes(msg[48..52].try_into().unwrap());
        assert_eq!(count, 4);
        // First: type 7 (len 8, value 42). Second: type 15 = sum 15.
        assert_eq!(u16::from_be_bytes([msg[52], msg[53]]), 7);
        assert_eq!(u64::from_be_bytes(msg[56..64].try_into().unwrap()), 42);
        assert_eq!(u16::from_be_bytes([msg[64], msg[65]]), 15);
        assert_eq!(u64::from_be_bytes(msg[68..76].try_into().unwrap()), 15);
        // Then the two AFI/SAFI-qualified type-17 entries.
        assert_eq!(u16::from_be_bytes([msg[76], msg[77]]), 17);
        assert_eq!(u16::from_be_bytes([msg[91], msg[92]]), 17);

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
            vec![(collector_addr(0), c_tx, BmpMonitorFilter::default())],
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
            vec![
                (collector_addr(0), c1_tx, BmpMonitorFilter::default()),
                (collector_addr(1), c2_tx, BmpMonitorFilter::default()),
            ],
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
            .find(|f| f.name() == name)
            .map_or(0, |f| {
                f.metric.iter().map(|m| m.counter.value() as u64).sum()
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
            .find(|f| f.name() == name)
            .and_then(|mut f| {
                f.take_metric().into_iter().find(|m| {
                    match_labels
                        .iter()
                        .all(|(k, v)| m.label.iter().any(|l| l.name() == *k && l.value() == *v))
                })
            })
            .map_or(0, |m| m.counter.value() as u64)
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
        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(addr, c_tx, BmpMonitorFilter::default())],
            metrics.clone(),
        );
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
            vec![(addr, c_tx.clone(), BmpMonitorFilter::default())],
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
        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(addr, c_tx, BmpMonitorFilter::default())],
            metrics.clone(),
        );
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

    fn loc_rib_config() -> crate::types::BmpLocRibConfig {
        crate::types::BmpLocRibConfig {
            local_asn: 65001,
            router_id: Ipv4Addr::new(10, 0, 0, 1),
            open_pdu: Bytes::from_static(&[0xAB; 29]),
        }
    }

    fn loc_rib_filter() -> BmpMonitorFilter {
        BmpMonitorFilter {
            rib_in_pre: false,
            rib_out_post: false,
            loc_rib: true,
        }
    }

    /// Loc-RIB RM events reach only `loc_rib` collectors (peer type 3 in
    /// the header); rib-in RM events do NOT reach a loc_rib-only
    /// collector.
    #[tokio::test]
    async fn loc_rib_route_monitoring_filtered_per_collector() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (rib_in_tx, mut rib_in_rx) = mpsc::channel(16);
        let (loc_rib_tx, mut loc_rib_rx) = mpsc::channel(16);
        let (dump_tx, _dump_rx) = mpsc::channel(4);

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![
                (collector_addr(0), rib_in_tx, BmpMonitorFilter::default()),
                (collector_addr(1), loc_rib_tx, loc_rib_filter()),
            ],
            BgpMetrics::new(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let handle = tokio::spawn(mgr.run());

        event_tx
            .send(BmpEvent::LocRibRouteMonitoring {
                update_pdu: Bytes::from_static(&[0xCC; 23]),
                timestamp: UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
            })
            .await
            .unwrap();
        event_tx
            .send(BmpEvent::RouteMonitoring {
                peer_info: sample_peer_info(),
                update_pdu: Bytes::from_static(&[0xAA; 23]),
            })
            .await
            .unwrap();

        // loc_rib collector: exactly the Loc-RIB RM, peer type 3, flags 0.
        let msg = loc_rib_rx.recv().await.unwrap();
        assert_eq!(msg[5], 0, "route monitoring type");
        assert_eq!(msg[6], 3, "peer type 3 (Loc-RIB instance)");
        assert_eq!(msg[7], 0, "loc-rib flags always 0");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), loc_rib_rx.recv())
                .await
                .is_err(),
            "loc_rib-only collector must not receive the rib-in RM"
        );

        // rib-in collector: only the rib-in RM (peer type 0).
        let msg = rib_in_rx.recv().await.unwrap();
        assert_eq!(msg[6], 0, "peer type 0 (global instance peer)");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), rib_in_rx.recv())
                .await
                .is_err(),
            "rib-in collector must not receive the Loc-RIB RM"
        );

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();
    }

    /// RFC 9069 stats (types 8 + 10) fan out to `loc_rib` collectors only.
    #[tokio::test]
    async fn loc_rib_stats_reach_only_loc_rib_collectors() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (rib_in_tx, mut rib_in_rx) = mpsc::channel(16);
        let (loc_rib_tx, mut loc_rib_rx) = mpsc::channel(16);
        let (dump_tx, _dump_rx) = mpsc::channel(4);

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![
                (collector_addr(0), rib_in_tx, BmpMonitorFilter::default()),
                (collector_addr(1), loc_rib_tx, loc_rib_filter()),
            ],
            BgpMetrics::new(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let handle = tokio::spawn(mgr.run());

        event_tx
            .send(BmpEvent::LocRibStats {
                per_family: vec![(1, 1, 10), (2, 1, 5)],
            })
            .await
            .unwrap();

        let msg = loc_rib_rx.recv().await.unwrap();
        assert_eq!(msg[5], 1, "stats report type");
        assert_eq!(msg[6], 3, "peer type 3");
        // count(4) at offset 48: type 8 + two type-10 entries = 3.
        assert_eq!(u32::from_be_bytes(msg[48..52].try_into().unwrap()), 3);
        // First: type 8, len 8, value = 15 (sum).
        assert_eq!(u16::from_be_bytes([msg[52], msg[53]]), 8);
        assert_eq!(u64::from_be_bytes(msg[56..64].try_into().unwrap()), 15);
        // Then the per-family type-10 entries.
        assert_eq!(u16::from_be_bytes([msg[64], msg[65]]), 10);

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), rib_in_rx.recv())
                .await
                .is_err(),
            "non-loc_rib collector must not receive Loc-RIB stats"
        );

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();
    }

    /// Collector connect triggers the RFC 9069 table sync: Loc-RIB Peer
    /// Up first, then the dump chunks as RM messages (install-time
    /// headers), then live Loc-RIB events keep flowing — and the dump
    /// request goes out for `loc_rib` collectors only.
    #[tokio::test]
    async fn collector_connect_triggers_loc_rib_peer_up_then_dump_then_live() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (c_tx, mut c_rx) = mpsc::channel(16);
        let (dump_tx, mut dump_rx) = mpsc::channel(4);

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), c_tx, loc_rib_filter())],
            BgpMetrics::new(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let handle = tokio::spawn(mgr.run());

        control_tx
            .send(BmpControlEvent::CollectorConnected {
                collector_id: 0,
                collector_addr: collector_addr(0),
            })
            .await
            .unwrap();

        // 1. Loc-RIB Peer Up replay (peer type 3, fabricated OPEN twice,
        // table-name TLV at the tail).
        let peer_up = c_rx.recv().await.unwrap();
        assert_eq!(peer_up[5], 3, "PeerUp message type");
        assert_eq!(peer_up[6], 3, "peer type 3");
        assert_eq!(&peer_up[peer_up.len() - 6..], b"global");

        // 2. The manager requested a dump; answer with two chunks
        // playing the RIB manager's role (2 routes + 1 "EoR" PDU).
        let request = tokio::time::timeout(std::time::Duration::from_secs(2), dump_rx.recv())
            .await
            .expect("dump requested on connect")
            .expect("dump channel open");
        let install = UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
        request
            .reply
            .send(crate::types::BmpDumpChunk {
                messages: vec![
                    (Bytes::from_static(&[0xD1; 23]), install),
                    (Bytes::from_static(&[0xD2; 23]), install),
                ],
            })
            .await
            .unwrap();
        request
            .reply
            .send(crate::types::BmpDumpChunk {
                messages: vec![(Bytes::from_static(&[0xE0; 23]), install)],
            })
            .await
            .unwrap();
        drop(request);

        for expected in [0xD1u8, 0xD2, 0xE0] {
            let msg = c_rx.recv().await.unwrap();
            assert_eq!(msg[5], 0, "route monitoring type");
            assert_eq!(msg[6], 3, "peer type 3");
            let ts = u32::from_be_bytes(msg[40..44].try_into().unwrap());
            assert_eq!(ts, 1_600_000_000, "per-message install timestamp");
            assert_eq!(msg[48], expected, "dump PDU order preserved");
        }

        // 3. Live emission continues seamlessly after the dump.
        event_tx
            .send(BmpEvent::LocRibRouteMonitoring {
                update_pdu: Bytes::from_static(&[0xF7; 23]),
                timestamp: UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
            })
            .await
            .unwrap();
        let live = c_rx.recv().await.unwrap();
        assert_eq!(live[48], 0xF7);

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();
    }

    /// A collector that does not monitor `loc_rib` gets neither the
    /// Loc-RIB Peer Up nor a dump request on connect.
    #[tokio::test]
    async fn non_loc_rib_collector_connect_skips_dump() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (c_tx, mut c_rx) = mpsc::channel(16);
        let (dump_tx, mut dump_rx) = mpsc::channel(4);

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), c_tx, BmpMonitorFilter::default())],
            BgpMetrics::new(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let handle = tokio::spawn(mgr.run());

        control_tx
            .send(BmpControlEvent::CollectorConnected {
                collector_id: 0,
                collector_addr: collector_addr(0),
            })
            .await
            .unwrap();

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), c_rx.recv())
                .await
                .is_err(),
            "no Loc-RIB PeerUp for a non-loc_rib collector (empty PeerUp cache)"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), dump_rx.recv())
                .await
                .is_err(),
            "no dump request for a non-loc_rib collector"
        );

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();
    }

    /// Shutdown sends the Loc-RIB Peer Down (reason 6 + table-name TLV)
    /// to `loc_rib` collectors before the manager exits.
    #[tokio::test]
    async fn shutdown_emits_loc_rib_peer_down_reason_6() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (c_tx, mut c_rx) = mpsc::channel(16);
        let (dump_tx, _dump_rx) = mpsc::channel(4);

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), c_tx, loc_rib_filter())],
            BgpMetrics::new(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let handle = tokio::spawn(mgr.run());

        control_tx.send(BmpControlEvent::Shutdown).await.unwrap();
        handle.await.unwrap();

        let msg = c_rx.recv().await.unwrap();
        assert_eq!(msg[5], 2, "PeerDown message type");
        assert_eq!(msg[6], 3, "peer type 3");
        assert_eq!(msg[48], 6, "reason 6: local system closed, TLV follows");
        assert_eq!(&msg[msg.len() - 6..], b"global");

        drop(event_tx);
    }

    #[tokio::test]
    async fn manager_exits_on_explicit_shutdown() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (c_tx, _c_rx) = mpsc::channel(16);

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), c_tx, BmpMonitorFilter::default())],
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
