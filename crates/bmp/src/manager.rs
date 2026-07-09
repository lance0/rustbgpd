//! BMP fan-out manager.
//!
//! Receives `BmpEvent`s from transport, encodes them into BMP wire
//! format, and distributes the encoded bytes to all collector channels.
//!
//! Internal events are version-agnostic (raw PDU + peer metadata);
//! framing happens per collector at fan-out time — each collector is
//! configured v3 or v4 ([`BmpVersion`]) and an event is encoded at
//! most once per version actually in use.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use rustbgpd_telemetry::BgpMetrics;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::codec;
use crate::types::{
    BmpControlEvent, BmpDumpRequest, BmpEvent, BmpLocRibConfig, BmpMonitorFilter, BmpVersion,
};

/// Per-message send timeout for a Loc-RIB dump forwarder. Paces the dump
/// to the collector's TCP drain rate via the bounded collector channel;
/// a collector that stalls longer than this aborts the dump (the next
/// reconnect triggers a fresh one).
const LOC_RIB_DUMP_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Bound on live Loc-RIB messages held back per collector while its
/// initial table dump streams. Overflow drops the newest message
/// (counted on `bmp_collector_drops_total`) — the same lossy posture as
/// a full collector channel; the collector's next reconnect resyncs.
const LOC_RIB_DUMP_LIVE_BUFFER_CAP: usize = 8192;

/// One in-flight Loc-RIB dump for a collector connection generation.
struct ActiveDump {
    /// Connection generation the dump was started for.
    generation: u64,
    /// The forwarder task, aborted when the connection is superseded.
    task: tokio::task::JoinHandle<()>,
    /// Live Loc-RIB messages held back while the dump streams, flushed
    /// in arrival order after the dump's End-of-RIB so the collector
    /// sees a strict dump rows → `EoR` → live deltas order — an older
    /// dump row can never follow a newer live withdrawal for a key.
    buffered: Vec<Bytes>,
}

/// Sent by a dump forwarder when it finishes (complete or aborted) so
/// the manager flushes the held-back live messages and stops buffering.
struct DumpDone {
    collector_id: usize,
    generation: u64,
}

/// BMP manager that fans out encoded messages to all collectors.
pub struct BmpManager {
    event_rx: mpsc::Receiver<BmpEvent>,
    control_rx: mpsc::Receiver<BmpControlEvent>,
    /// Per-collector address + sender + monitoring filter + BMP wire
    /// version, paired by index. The address is the operator-facing
    /// identifier used as the `collector` label on `bmp_*` Prometheus
    /// counters.
    collectors: Vec<(
        SocketAddr,
        mpsc::Sender<Bytes>,
        BmpMonitorFilter,
        BmpVersion,
    )>,
    /// Latest encoded `PeerUp` message per peer address, one encoding
    /// per BMP version (indexed by [`BmpVersion::idx`]).
    peer_up_cache: std::collections::HashMap<std::net::IpAddr, [Bytes; 2]>,
    /// RFC 9069 Loc-RIB instance-peer identity. `None` = no collector
    /// monitors `loc_rib`; Loc-RIB events are dropped.
    loc_rib: Option<BmpLocRibConfig>,
    /// Loc-RIB table-dump request channel toward the RIB manager, used
    /// on collector (re)connect to synthesize the initial table sync.
    dump_tx: Option<mpsc::Sender<BmpDumpRequest>>,
    /// Collector indices whose most recent connect-time Loc-RIB `PeerUp`
    /// was dropped on a full channel (LAN-200). Live Loc-RIB Route
    /// Monitoring is suppressed for these collectors so none ever sees an
    /// RFC 9069 RM without a preceding Loc-RIB `PeerUp`. Cleared when a
    /// later reconnect's [`Self::start_loc_rib_sync`] lands the `PeerUp`.
    loc_rib_suppressed: std::collections::HashSet<usize>,
    /// Per-collector connection generation, parallel to `collectors`.
    /// Bumped on every connect and disconnect; a dump forwarder
    /// snapshots the value at spawn and fences every send against the
    /// current one, so a dump started for a previous connection can
    /// never emit into a newer connection's stream (LAN-289).
    generations: Vec<Arc<AtomicU64>>,
    /// In-flight Loc-RIB dump (plus its held-back live messages) per
    /// collector index. Present from dump spawn until its [`DumpDone`].
    active_dumps: std::collections::HashMap<usize, ActiveDump>,
    /// Cloned into each spawned dump forwarder; completions come back
    /// on `dump_done_rx` in the manager loop.
    dump_done_tx: mpsc::Sender<DumpDone>,
    dump_done_rx: mpsc::Receiver<DumpDone>,
    metrics: BgpMetrics,
}

impl BmpManager {
    /// Create a new BMP manager with the given event/control channels and collectors.
    #[must_use]
    pub fn new(
        event_rx: mpsc::Receiver<BmpEvent>,
        control_rx: mpsc::Receiver<BmpControlEvent>,
        collectors: Vec<(
            SocketAddr,
            mpsc::Sender<Bytes>,
            BmpMonitorFilter,
            BmpVersion,
        )>,
        metrics: BgpMetrics,
    ) -> Self {
        // At most one in-flight dump (and thus one pending completion)
        // per collector.
        let (dump_done_tx, dump_done_rx) = mpsc::channel(collectors.len().max(1));
        let generations = collectors
            .iter()
            .map(|_| Arc::new(AtomicU64::new(0)))
            .collect();
        Self {
            event_rx,
            control_rx,
            collectors,
            peer_up_cache: std::collections::HashMap::new(),
            loc_rib: None,
            dump_tx: None,
            loc_rib_suppressed: std::collections::HashSet::new(),
            generations,
            active_dumps: std::collections::HashMap::new(),
            dump_done_tx,
            dump_done_rx,
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
                maybe_done = self.dump_done_rx.recv() => {
                    // Never `None`: the manager holds a `dump_done_tx`.
                    if let Some(done) = maybe_done {
                        self.handle_dump_done(&done);
                    }
                }
            }
        }
        debug!("BMP manager shutting down");
    }

    fn encode_event(event: &BmpEvent, version: BmpVersion) -> Bytes {
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
                version,
            ),
            BmpEvent::PeerDown { peer_info, reason } => {
                codec::encode_peer_down(peer_info, reason, version)
            }
            BmpEvent::RouteMonitoring {
                peer_info,
                update_pdu,
                // Path marking is Loc-RIB-only: the rib-in tap fires at
                // receive time (before best-path selection) and rib-out
                // is per-peer staged output — neither has an honest
                // local decision status to mark.
            } => codec::encode_route_monitoring(peer_info, update_pdu, None, version),
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
                codec::encode_stats_report(peer_info, &counters, &afi_counters, version)
            }
        }
    }

    /// Encode and fan out an RFC 9069 Loc-RIB event to `loc_rib`
    /// collectors. Dropped silently when Loc-RIB monitoring is not
    /// configured (no collector monitors the view).
    ///
    /// A collector with an in-flight initial dump does not receive the
    /// message directly: it is held back in the dump's buffer and
    /// flushed after the dump's End-of-RIB ([`Self::handle_dump_done`]),
    /// so the collector-facing order is always dump rows (point-in-time
    /// snapshot) → `EoR` → live deltas from that point.
    fn handle_loc_rib_event(&mut self, event: &BmpEvent) {
        let Some(ref cfg) = self.loc_rib else {
            return;
        };
        if !matches!(
            event,
            BmpEvent::LocRibRouteMonitoring { .. } | BmpEvent::LocRibStats { .. }
        ) {
            return;
        }
        let now = std::time::SystemTime::now();
        let encode = |version: BmpVersion| match event {
            BmpEvent::LocRibRouteMonitoring {
                update_pdu,
                timestamp,
                path_status,
            } => codec::encode_route_monitoring(
                &cfg.peer_info(*timestamp),
                update_pdu,
                *path_status,
                version,
            ),
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
                codec::encode_stats_report(&cfg.peer_info(now), &counters, &afi_counters, version)
            }
            _ => unreachable!("guarded above"),
        };
        let mut memo: [Option<Bytes>; 2] = [None, None];
        for (idx, (addr, tx, filter, version)) in self.collectors.iter().enumerate() {
            // Suppress live RM for any collector whose connect-time
            // Loc-RIB PeerUp was dropped (LAN-200) — RFC 9069 RM must
            // never precede the Loc-RIB PeerUp on the wire.
            if !filter.loc_rib || self.loc_rib_suppressed.contains(&idx) {
                continue;
            }
            let msg = memo[version.idx()]
                .get_or_insert_with(|| encode(*version))
                .clone();
            if let Some(dump) = self.active_dumps.get_mut(&idx) {
                if dump.buffered.len() < LOC_RIB_DUMP_LIVE_BUFFER_CAP {
                    dump.buffered.push(msg);
                } else {
                    self.metrics.record_bmp_collector_drop(
                        &addr.to_string(),
                        "loc_rib_dump",
                        "live_buffer_full",
                        1,
                    );
                    warn!(
                        collector = %addr,
                        "live Loc-RIB buffer full during initial dump, dropping message"
                    );
                }
                continue;
            }
            if let Err(e) = tx.try_send(msg) {
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

    fn handle_event(&mut self, event: &BmpEvent) {
        match event {
            BmpEvent::LocRibRouteMonitoring { .. } | BmpEvent::LocRibStats { .. } => {
                self.handle_loc_rib_event(event);
            }
            BmpEvent::PeerUp { peer_info, .. } => {
                // Encode both versions eagerly: the cache must be able
                // to replay to any collector version on reconnect.
                let encoded = [
                    Self::encode_event(event, BmpVersion::V3),
                    Self::encode_event(event, BmpVersion::V4),
                ];
                self.fan_out(|version| encoded[version.idx()].clone());
                self.peer_up_cache.insert(peer_info.peer_addr, encoded);
            }
            BmpEvent::PeerDown { peer_info, .. } => {
                self.peer_up_cache.remove(&peer_info.peer_addr);
                self.fan_out(|version| Self::encode_event(event, version));
            }
            // Route monitoring is the only per-collector-filtered
            // message: rib-in RM only to `rib_in_pre` collectors,
            // rib-out RM only to `rib_out_post` collectors.
            BmpEvent::RouteMonitoring { peer_info, .. } => {
                let rib_out = peer_info.is_rib_out;
                self.fan_out_filtered(
                    |_, f| {
                        if rib_out {
                            f.rib_out_post
                        } else {
                            f.rib_in_pre
                        }
                    },
                    |version| Self::encode_event(event, version),
                );
            }
            BmpEvent::StatsReport { .. } => {
                self.fan_out(|version| Self::encode_event(event, version));
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
                self.bump_generation_and_cancel_dump(collector_id);
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
                self.bump_generation_and_cancel_dump(collector_id);
                false
            }
            BmpControlEvent::Shutdown => {
                info!("BMP manager received shutdown request");
                for (_, dump) in self.active_dumps.drain() {
                    dump.task.abort();
                }
                // RFC 9069 §5.3: the Loc-RIB instance peer goes down with
                // reason 6 + the VRF/Table Name TLV when monitoring stops.
                if let Some(ref cfg) = self.loc_rib {
                    let now = std::time::SystemTime::now();
                    self.fan_out_filtered(
                        |_, f| f.loc_rib,
                        |version| codec::encode_loc_rib_peer_down(cfg, now, version),
                    );
                }
                true
            }
        }
    }

    /// Advance the collector's connection generation and cancel any
    /// in-flight Loc-RIB dump from the previous generation (LAN-289).
    /// The abort covers a forwarder parked in a blocked send; the
    /// forwarder's own generation fence covers the abort/send race —
    /// it re-checks the generation before every send, and the bump
    /// here happens before anything for the new connection is
    /// enqueued, so a racing stale row can only land ahead of the new
    /// generation's Loc-RIB `PeerUp` (which resets collector state).
    fn bump_generation_and_cancel_dump(&mut self, collector_id: usize) {
        if let Some(generation) = self.generations.get(collector_id) {
            generation.fetch_add(1, Ordering::SeqCst);
        }
        if let Some(dump) = self.active_dumps.remove(&collector_id) {
            dump.task.abort();
            debug!(
                collector_id,
                "cancelled stale Loc-RIB dump from superseded collector connection"
            );
        }
    }

    /// A dump forwarder finished (complete or aborted): flush the live
    /// Loc-RIB messages held back for it — preserving the dump rows →
    /// `EoR` → live deltas order — and resume direct live fan-out.
    /// A completion from a superseded generation is ignored: its state
    /// was already discarded by [`Self::bump_generation_and_cancel_dump`].
    fn handle_dump_done(&mut self, done: &DumpDone) {
        match self.active_dumps.get(&done.collector_id) {
            Some(dump) if dump.generation == done.generation => {}
            _ => return,
        }
        let Some(dump) = self.active_dumps.remove(&done.collector_id) else {
            return;
        };
        let Some((addr, tx, _, _)) = self.collectors.get(done.collector_id) else {
            return;
        };
        let addr_label = addr.to_string();
        let total = dump.buffered.len();
        for (idx, msg) in dump.buffered.into_iter().enumerate() {
            if let Err(e) = tx.try_send(msg) {
                let reason = trysend_reason(&e);
                let remaining = u64::try_from(total - idx).unwrap_or(u64::MAX);
                self.metrics.record_bmp_collector_drop(
                    &addr_label,
                    "loc_rib_dump",
                    reason,
                    remaining,
                );
                warn!(
                    collector = %addr,
                    error = %e,
                    skipped = remaining,
                    "BMP collector channel full or closed flushing post-dump live \
                     Loc-RIB messages; remaining messages dropped"
                );
                break;
            }
        }
    }

    fn replay_peer_up_to_collector(&self, collector_id: usize) {
        let Some((addr, tx, _, version)) = self.collectors.get(collector_id) else {
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
        let cache_values: Vec<&Bytes> = self
            .peer_up_cache
            .values()
            .map(|encoded| &encoded[version.idx()])
            .collect();
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
    /// blocks on a slow collector. While it runs, live Loc-RIB events
    /// for this collector are held back and flushed after the dump's
    /// End-of-RIB ([`Self::handle_loc_rib_event`]), and the task is
    /// fenced by the collector's connection generation so a reconnect
    /// mid-dump can never leak stale dump rows into the new
    /// connection's stream (LAN-289).
    fn start_loc_rib_sync(&mut self, collector_id: usize) {
        let Some(ref cfg) = self.loc_rib else {
            return;
        };
        let Some((addr, collector_tx, filter, version)) = self.collectors.get(collector_id) else {
            return;
        };
        if !filter.loc_rib {
            return;
        }

        let addr_label = addr.to_string();
        let version = *version;
        // Clone out of `self` up front so the mutable `loc_rib_suppressed`
        // bookkeeping below doesn't collide with the collector/config
        // borrows.
        let cfg = cfg.clone();
        let collector_tx = collector_tx.clone();
        let peer_up = codec::encode_loc_rib_peer_up(&cfg, std::time::SystemTime::now(), version);
        if let Err(e) = collector_tx.try_send(peer_up) {
            let reason = trysend_reason(&e);
            self.metrics
                .record_bmp_collector_drop(&addr_label, "loc_rib_dump", reason, 1);
            warn!(
                collector = %addr_label,
                error = %e,
                "BMP collector channel full or closed for Loc-RIB PeerUp; skipping dump \
                 and suppressing live Loc-RIB RM until reconnect"
            );
            // A dropped PeerUp must not be followed by live RM (LAN-200):
            // gate live Loc-RIB fan-out for this collector until a later
            // reconnect lands the PeerUp.
            self.loc_rib_suppressed.insert(collector_id);
            return;
        }
        // PeerUp is on the wire ahead of any RM — live fan-out may resume.
        self.loc_rib_suppressed.remove(&collector_id);

        let Some(ref dump_tx) = self.dump_tx else {
            return;
        };
        let Some(generation) = self.generations.get(collector_id) else {
            return;
        };
        let dump_generation = generation.load(Ordering::SeqCst);
        let metrics = self.metrics.clone();
        let task = tokio::spawn(forward_loc_rib_dump(
            DumpForwarder {
                dump_tx: dump_tx.clone(),
                collector_tx,
                cfg,
                version,
                metrics,
                addr_label,
                generation: Arc::clone(generation),
                dump_generation,
            },
            self.dump_done_tx.clone(),
            collector_id,
        ));
        self.active_dumps.insert(
            collector_id,
            ActiveDump {
                generation: dump_generation,
                task,
                buffered: Vec::new(),
            },
        );
    }

    fn fan_out(&self, encode: impl Fn(BmpVersion) -> Bytes) {
        self.fan_out_filtered(|_, _| true, encode);
    }

    /// Fan out one event, framing per collector version. `want` receives
    /// the collector index and filter; `encode` is called at most once
    /// per BMP version in use (two-slot memo).
    fn fan_out_filtered(
        &self,
        want: impl Fn(usize, &BmpMonitorFilter) -> bool,
        encode: impl Fn(BmpVersion) -> Bytes,
    ) {
        let mut memo: [Option<Bytes>; 2] = [None, None];
        for (idx, (addr, tx, filter, version)) in self.collectors.iter().enumerate() {
            if !want(idx, filter) {
                continue;
            }
            let msg = memo[version.idx()]
                .get_or_insert_with(|| encode(*version))
                .clone();
            if let Err(e) = tx.try_send(msg) {
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

/// Everything one Loc-RIB dump forwarder task needs, bundled so the
/// spawn site stays readable.
struct DumpForwarder {
    dump_tx: mpsc::Sender<BmpDumpRequest>,
    collector_tx: mpsc::Sender<Bytes>,
    cfg: BmpLocRibConfig,
    version: BmpVersion,
    metrics: BgpMetrics,
    addr_label: String,
    /// Live connection generation of the collector (shared with the
    /// manager, which bumps it on every connect/disconnect).
    generation: Arc<AtomicU64>,
    /// The generation this dump was started for; the forwarder aborts
    /// as soon as the live value moves past it.
    dump_generation: u64,
}

impl DumpForwarder {
    /// LAN-289 generation fence: `true` when the collector connection
    /// this dump was started for has been superseded. Checked before
    /// every send — a stale dump row must never enter a newer
    /// connection's stream (an older announce after a newer withdrawal
    /// would leave the collector with a route that no longer exists).
    fn superseded(&self) -> bool {
        self.generation.load(Ordering::SeqCst) != self.dump_generation
    }
}

/// Forward one Loc-RIB dump to a single collector as Route Monitoring
/// messages, driving the resumable chunk loop against the RIB manager
/// (see [`stream_loc_rib_dump`]), then report completion — success or
/// abort — so the manager flushes the live messages it held back.
async fn forward_loc_rib_dump(
    forwarder: DumpForwarder,
    done_tx: mpsc::Sender<DumpDone>,
    collector_id: usize,
) {
    let generation = forwarder.dump_generation;
    stream_loc_rib_dump(forwarder).await;
    let _ = done_tx
        .send(DumpDone {
            collector_id,
            generation,
        })
        .await;
}

/// The dump chunk loop: request one bounded chunk from the RIB
/// manager, forward it, then request the next from the returned
/// cursor. The RIB manager synthesizes at most one chunk per request,
/// so live route processing interleaves between chunks and no
/// full-table dump vector ever materializes.
///
/// The bounded collector channel plus a per-message send timeout pace
/// the dump at the collector's drain rate; a timeout or closed channel
/// aborts the dump (a fresh one runs on the next reconnect), and the
/// connection-generation fence aborts it the moment the collector
/// reconnects or drops (LAN-289).
async fn stream_loc_rib_dump(f: DumpForwarder) {
    let mut cursor = None;
    let mut sent: u64 = 0;
    loop {
        if f.superseded() {
            debug!(collector = %f.addr_label, "collector connection superseded, aborting stale Loc-RIB dump");
            return;
        }
        let (reply, chunk_rx) = tokio::sync::oneshot::channel();
        if f.dump_tx
            .send(BmpDumpRequest { cursor, reply })
            .await
            .is_err()
        {
            f.metrics
                .record_bmp_collector_drop(&f.addr_label, "loc_rib_dump", "channel_closed", 1);
            warn!(collector = %f.addr_label, "Loc-RIB dump request channel closed, aborting dump");
            return;
        }
        let Ok(chunk) = chunk_rx.await else {
            f.metrics
                .record_bmp_collector_drop(&f.addr_label, "loc_rib_dump", "channel_closed", 1);
            warn!(collector = %f.addr_label, "RIB manager dropped Loc-RIB dump chunk reply, aborting dump");
            return;
        };
        for (pdu, timestamp, path_status) in chunk.messages {
            if f.superseded() {
                debug!(collector = %f.addr_label, "collector connection superseded, aborting stale Loc-RIB dump");
                return;
            }
            let msg = codec::encode_route_monitoring(
                &f.cfg.peer_info(timestamp),
                &pdu,
                path_status,
                f.version,
            );
            match tokio::time::timeout(LOC_RIB_DUMP_SEND_TIMEOUT, f.collector_tx.send(msg)).await {
                Ok(Ok(())) => sent += 1,
                Ok(Err(_)) => {
                    f.metrics.record_bmp_collector_drop(
                        &f.addr_label,
                        "loc_rib_dump",
                        "channel_closed",
                        1,
                    );
                    warn!(collector = %f.addr_label, "collector channel closed mid Loc-RIB dump, aborting");
                    return;
                }
                Err(_) => {
                    f.metrics.record_bmp_collector_drop(
                        &f.addr_label,
                        "loc_rib_dump",
                        "send_timeout",
                        1,
                    );
                    warn!(collector = %f.addr_label, "collector stalled during Loc-RIB dump, aborting");
                    return;
                }
            }
        }
        match chunk.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    debug!(collector = %f.addr_label, messages = sent, "Loc-RIB dump forwarded");
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
                (
                    collector_addr(0),
                    c1_tx,
                    BmpMonitorFilter::default(),
                    BmpVersion::V3,
                ),
                (
                    collector_addr(1),
                    c2_tx,
                    BmpMonitorFilter::default(),
                    BmpVersion::V3,
                ),
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

    /// Mixed-version fan-out (draft-ietf-grow-bmp-tlv-20): one v3 and
    /// one v4 collector receive the same events, each framed at its
    /// configured version. Route Monitoring: bare PDU for v3, BGP
    /// Message TLV (type 7, index 0) for v4. Peer Up (TLV-provisioned
    /// already in v3) differs only in the version byte — including the
    /// cached copy replayed on reconnect.
    #[tokio::test]
    async fn mixed_version_collectors_get_version_correct_framing() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (v3_tx, mut v3_rx) = mpsc::channel(16);
        let (v4_tx, mut v4_rx) = mpsc::channel(16);

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![
                (
                    collector_addr(0),
                    v3_tx,
                    BmpMonitorFilter::default(),
                    BmpVersion::V3,
                ),
                (
                    collector_addr(1),
                    v4_tx,
                    BmpMonitorFilter::default(),
                    BmpVersion::V4,
                ),
            ],
            BgpMetrics::new(),
        );
        let handle = tokio::spawn(mgr.run());

        // Peer Up: same bytes except the version byte.
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
        let up3 = v3_rx.recv().await.unwrap();
        let up4 = v4_rx.recv().await.unwrap();
        assert_eq!(up3[0], 3);
        assert_eq!(up4[0], 4);
        assert_eq!(up3[1..], up4[1..], "Peer Up: version byte only");

        // Route Monitoring: v3 bare PDU, v4 BGP Message TLV wrap.
        let pdu = [0xAA; 23];
        event_tx
            .send(BmpEvent::RouteMonitoring {
                peer_info: sample_peer_info(),
                update_pdu: Bytes::copy_from_slice(&pdu),
            })
            .await
            .unwrap();
        let rm3 = v3_rx.recv().await.unwrap();
        let rm4 = v4_rx.recv().await.unwrap();
        assert_eq!(rm3[0], 3);
        assert_eq!(&rm3[6 + 42..], &pdu, "v3: bare PDU after per-peer header");
        assert_eq!(rm4[0], 4);
        let tlv = &rm4[6 + 42..];
        assert_eq!(u16::from_be_bytes([tlv[0], tlv[1]]), 7, "BGP Message TLV");
        assert_eq!(u16::from_be_bytes([tlv[2], tlv[3]]) as usize, pdu.len());
        assert_eq!(u16::from_be_bytes([tlv[4], tlv[5]]), 0, "index 0");
        assert_eq!(&tlv[6..], &pdu);

        // Stats Report: v4 wraps in the Stats TLV (code point 1).
        event_tx
            .send(BmpEvent::StatsReport {
                peer_info: sample_peer_info(),
                adj_rib_in_routes: 42,
                adj_rib_out_post: None,
            })
            .await
            .unwrap();
        let st3 = v3_rx.recv().await.unwrap();
        let st4 = v4_rx.recv().await.unwrap();
        assert_eq!(st3[0], 3);
        assert_eq!(st4[0], 4);
        let tlv = &st4[6 + 42..];
        assert_eq!(u16::from_be_bytes([tlv[0], tlv[1]]), 1, "Stats TLV");
        assert_eq!(&tlv[4..], &st3[6 + 42..], "value = v3 count + stats bytes");

        // Reconnect of the v4 collector replays the v4-framed Peer Up.
        control_tx
            .send(BmpControlEvent::CollectorConnected {
                collector_id: 1,
                collector_addr: collector_addr(1),
            })
            .await
            .unwrap();
        let replay = v4_rx.recv().await.unwrap();
        assert_eq!(replay[0], 4, "replayed Peer Up framed at collector version");
        assert_eq!(replay[..], up4[..], "replay = original v4 Peer Up");

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
                (
                    collector_addr(0),
                    a_tx,
                    BmpMonitorFilter::default(),
                    BmpVersion::V3,
                ),
                (
                    collector_addr(1),
                    b_tx,
                    BmpMonitorFilter {
                        rib_in_pre: true,
                        rib_out_post: true,
                        loc_rib: false,
                    },
                    BmpVersion::V3,
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
            vec![(
                collector_addr(0),
                c_tx,
                BmpMonitorFilter::default(),
                BmpVersion::V3,
            )],
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
            vec![(
                collector_addr(0),
                c_tx,
                BmpMonitorFilter::default(),
                BmpVersion::V3,
            )],
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
            vec![(
                collector_addr(0),
                c_tx,
                BmpMonitorFilter::default(),
                BmpVersion::V3,
            )],
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
            vec![(
                collector_addr(0),
                c_tx,
                BmpMonitorFilter::default(),
                BmpVersion::V3,
            )],
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
                (
                    collector_addr(0),
                    c1_tx,
                    BmpMonitorFilter::default(),
                    BmpVersion::V3,
                ),
                (
                    collector_addr(1),
                    c2_tx,
                    BmpMonitorFilter::default(),
                    BmpVersion::V3,
                ),
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
            vec![(addr, c_tx, BmpMonitorFilter::default(), BmpVersion::V3)],
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
            vec![(
                addr,
                c_tx.clone(),
                BmpMonitorFilter::default(),
                BmpVersion::V3,
            )],
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
            vec![(addr, c_tx, BmpMonitorFilter::default(), BmpVersion::V3)],
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
                (
                    collector_addr(0),
                    rib_in_tx,
                    BmpMonitorFilter::default(),
                    BmpVersion::V3,
                ),
                (
                    collector_addr(1),
                    loc_rib_tx,
                    loc_rib_filter(),
                    BmpVersion::V3,
                ),
            ],
            BgpMetrics::new(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let handle = tokio::spawn(mgr.run());

        event_tx
            .send(BmpEvent::LocRibRouteMonitoring {
                update_pdu: Bytes::from_static(&[0xCC; 23]),
                timestamp: UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
                path_status: None,
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
                (
                    collector_addr(0),
                    rib_in_tx,
                    BmpMonitorFilter::default(),
                    BmpVersion::V3,
                ),
                (
                    collector_addr(1),
                    loc_rib_tx,
                    loc_rib_filter(),
                    BmpVersion::V3,
                ),
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
            vec![(collector_addr(0), c_tx, loc_rib_filter(), BmpVersion::V3)],
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

        // 2. The manager requested the first dump chunk (fresh cursor);
        // answer with a resumable chunk playing the RIB manager's role,
        // then serve the follow-up request from the returned cursor
        // (1 route + 1 "EoR" PDU) — proving the forwarder drives the
        // request→forward→request-next loop and round-trips the cursor.
        let request = tokio::time::timeout(std::time::Duration::from_secs(2), dump_rx.recv())
            .await
            .expect("dump requested on connect")
            .expect("dump channel open");
        assert!(request.cursor.is_none(), "fresh dump starts cursor-less");
        let install = UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
        let resume = rustbgpd_wire::Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
            std::net::Ipv4Addr::new(10, 2, 0, 0),
            16,
        ));
        request
            .reply
            .send(crate::types::BmpDumpChunk {
                messages: vec![
                    (Bytes::from_static(&[0xD1; 23]), install, None),
                    (Bytes::from_static(&[0xD2; 23]), install, None),
                ],
                next: Some(crate::types::BmpDumpCursor::Unicast(resume)),
            })
            .unwrap();
        let request = tokio::time::timeout(std::time::Duration::from_secs(2), dump_rx.recv())
            .await
            .expect("follow-up chunk requested")
            .expect("dump channel open");
        match request.cursor {
            Some(crate::types::BmpDumpCursor::Unicast(p)) => {
                assert_eq!(p, resume, "cursor round-trips verbatim");
            }
            other => panic!("expected the returned cursor back, got {other:?}"),
        }
        request
            .reply
            .send(crate::types::BmpDumpChunk {
                messages: vec![(Bytes::from_static(&[0xE0; 23]), install, None)],
                next: None,
            })
            .unwrap();

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
                path_status: None,
            })
            .await
            .unwrap();
        let live = c_rx.recv().await.unwrap();
        assert_eq!(live[48], 0xF7);

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();
    }

    /// LAN-289 generation fence: a Loc-RIB dump task started for a
    /// previous collector connection stops on reconnect — nothing from
    /// the stale dump may interleave after the new generation's stream
    /// (`PeerUp` + fresh dump) starts.
    #[tokio::test]
    async fn reconnect_fences_stale_loc_rib_dump_task() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (c_tx, mut c_rx) = mpsc::channel(64);
        let (dump_tx, mut dump_rx) = mpsc::channel(4);

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), c_tx, loc_rib_filter(), BmpVersion::V3)],
            BgpMetrics::new(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let handle = tokio::spawn(mgr.run());

        let install = UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
        let chunk = |octet: u8, next| crate::types::BmpDumpChunk {
            messages: vec![(
                Bytes::from_static(match octet {
                    0xA1 => &[0xA1; 23],
                    0xBB => &[0xBB; 23],
                    _ => &[0xC1; 23],
                }),
                install,
                None,
            )],
            next,
        };

        // Generation 1: connect → PeerUp, opening dump request.
        control_tx
            .send(BmpControlEvent::CollectorConnected {
                collector_id: 0,
                collector_addr: collector_addr(0),
            })
            .await
            .unwrap();
        let peer_up = c_rx.recv().await.unwrap();
        assert_eq!(peer_up[5], 3, "gen-1 Loc-RIB PeerUp");
        let req1 = tokio::time::timeout(std::time::Duration::from_secs(2), dump_rx.recv())
            .await
            .expect("gen-1 dump requested")
            .expect("dump channel open");
        assert!(req1.cursor.is_none());
        let resume = rustbgpd_wire::Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
            std::net::Ipv4Addr::new(10, 1, 0, 0),
            16,
        ));
        req1.reply
            .send(chunk(
                0xA1,
                Some(crate::types::BmpDumpCursor::Unicast(resume)),
            ))
            .unwrap();
        let row = c_rx.recv().await.unwrap();
        assert_eq!(row[48], 0xA1, "gen-1 dump row before the reconnect flows");
        // The gen-1 task asks for its next chunk; hold the reply.
        let stale_req = tokio::time::timeout(std::time::Duration::from_secs(2), dump_rx.recv())
            .await
            .expect("gen-1 follow-up requested")
            .expect("dump channel open");
        assert!(stale_req.cursor.is_some(), "gen-1 resume cursor");

        // Reconnect → generation 2: the manager cancels the gen-1 task
        // and starts a fresh dump (cursor-less request).
        control_tx
            .send(BmpControlEvent::CollectorConnected {
                collector_id: 0,
                collector_addr: collector_addr(0),
            })
            .await
            .unwrap();
        let peer_up2 = c_rx.recv().await.unwrap();
        assert_eq!(peer_up2[5], 3, "gen-2 Loc-RIB PeerUp");
        let req2 = tokio::time::timeout(std::time::Duration::from_secs(2), dump_rx.recv())
            .await
            .expect("gen-2 dump requested")
            .expect("dump channel open");
        assert!(req2.cursor.is_none(), "fresh dump for the new generation");

        // Answer the STALE gen-1 request — its rows must never reach
        // the collector (task aborted and generation-fenced).
        let _ = stale_req.reply.send(chunk(0xBB, None));
        // Complete the gen-2 dump.
        req2.reply.send(chunk(0xC1, None)).unwrap();

        let row = c_rx.recv().await.unwrap();
        assert_eq!(
            row[48], 0xC1,
            "only the new generation's dump rows reach the collector"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), c_rx.recv())
                .await
                .is_err(),
            "stale gen-1 dump row must never interleave into the gen-2 stream"
        );

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();
    }

    /// Dump-vs-live serialization (LAN-289/LAN-193): a live Loc-RIB
    /// event arriving while the initial dump streams is held back and
    /// delivered after the dump's final chunk, so a collector never
    /// sees an older dump announcement after a newer live withdrawal
    /// for the same key — the wire order is dump rows → `EoR` → live
    /// deltas.
    #[tokio::test]
    async fn live_loc_rib_events_flush_after_dump_completes() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (c_tx, mut c_rx) = mpsc::channel(16);
        let (dump_tx, mut dump_rx) = mpsc::channel(4);

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), c_tx, loc_rib_filter(), BmpVersion::V3)],
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
        let peer_up = c_rx.recv().await.unwrap();
        assert_eq!(peer_up[5], 3);
        let request = tokio::time::timeout(std::time::Duration::from_secs(2), dump_rx.recv())
            .await
            .expect("dump requested on connect")
            .expect("dump channel open");

        // A live withdrawal for a key the in-flight dump also carries
        // lands while the dump is mid-stream.
        event_tx
            .send(BmpEvent::LocRibRouteMonitoring {
                update_pdu: Bytes::from_static(&[0xEE; 23]),
                timestamp: UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
                path_status: None,
            })
            .await
            .unwrap();
        // Held back: nothing may reach the collector before the dump.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), c_rx.recv())
                .await
                .is_err(),
            "live Loc-RIB RM must be held back while the dump streams"
        );

        // The dump completes: its (older) announcement for the key,
        // then EoR, in the final chunk.
        let install = UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
        request
            .reply
            .send(crate::types::BmpDumpChunk {
                messages: vec![(Bytes::from_static(&[0xD1; 23]), install, None)],
                next: None,
            })
            .unwrap();

        // Wire order: dump row first, THEN the buffered live
        // withdrawal — the collector ends without the route.
        let first = c_rx.recv().await.unwrap();
        assert_eq!(first[48], 0xD1, "dump row precedes the held-back delta");
        let second = c_rx.recv().await.unwrap();
        assert_eq!(second[48], 0xEE, "live withdrawal flushes after the dump");

        // Post-dump live events flow directly again.
        event_tx
            .send(BmpEvent::LocRibRouteMonitoring {
                update_pdu: Bytes::from_static(&[0xF7; 23]),
                timestamp: UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_111),
                path_status: None,
            })
            .await
            .unwrap();
        let third = c_rx.recv().await.unwrap();
        assert_eq!(third[48], 0xF7);

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();
    }

    /// Mixed v3/v4 collectors, one marked Loc-RIB RM event: the v3
    /// collector's message carries no TLV bytes at all (bare PDU after
    /// the per-peer header) while the v4 collector gets the BGP
    /// Message TLV followed by the Path Marking TLV with the event's
    /// status bitmap and reason code.
    #[tokio::test]
    async fn mixed_version_collectors_loc_rib_path_marking() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (v3_tx, mut v3_rx) = mpsc::channel(16);
        let (v4_tx, mut v4_rx) = mpsc::channel(16);
        let (dump_tx, _dump_rx) = mpsc::channel(4);

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![
                (collector_addr(0), v3_tx, loc_rib_filter(), BmpVersion::V3),
                (collector_addr(1), v4_tx, loc_rib_filter(), BmpVersion::V4),
            ],
            BgpMetrics::new(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let handle = tokio::spawn(mgr.run());

        let pdu = [0xCC; 23];
        event_tx
            .send(BmpEvent::LocRibRouteMonitoring {
                update_pdu: Bytes::copy_from_slice(&pdu),
                timestamp: UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
                path_status: Some(crate::types::BmpPathStatus {
                    status: crate::tlv::PATH_STATUS_BEST,
                    reason: Some(crate::tlv::REASON_LOCAL_PREF),
                }),
            })
            .await
            .unwrap();

        // v3: bare PDU right after the per-peer header — no TLVs.
        let msg = v3_rx.recv().await.unwrap();
        assert_eq!(msg[0], 3);
        assert_eq!(&msg[6 + 42..], &pdu, "v3 carries the bare PDU, no TLVs");

        // v4: BGP Message TLV then the Path Marking TLV.
        let msg = v4_rx.recv().await.unwrap();
        assert_eq!(msg[0], 4);
        let tlvs = &msg[6 + 42..];
        assert_eq!(u16::from_be_bytes([tlvs[0], tlvs[1]]), 7, "BGP Message");
        let pm = &tlvs[6 + pdu.len()..];
        assert_eq!(
            pm,
            &[
                0x00, 0x05, // Path Marking TLV (type 5)
                0x00, 0x06, // status(4) + reason(2)
                0x00, 0x00, // index 0
                0x00, 0x00, 0x00, 0x02, // Best
                0x00, 0x03, // local preference
            ]
        );

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
            vec![(
                collector_addr(0),
                c_tx,
                BmpMonitorFilter::default(),
                BmpVersion::V3,
            )],
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

    /// LAN-200: a Loc-RIB `PeerUp` dropped on a full channel at connect
    /// suppresses subsequent live Loc-RIB Route Monitoring for that
    /// collector, so it never sees an RFC 9069 RM without a preceding
    /// Loc-RIB `PeerUp`. A later reconnect (channel drained) heals it.
    #[tokio::test]
    async fn dropped_loc_rib_peer_up_suppresses_live_route_monitoring() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        // Capacity-1 collector channel so a single backlog message fills
        // it and the connect-time Loc-RIB PeerUp cannot enqueue.
        let (c_tx, mut c_rx) = mpsc::channel(1);
        let (dump_tx, mut dump_rx) = mpsc::channel(4);

        let metrics = BgpMetrics::new();
        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(
                collector_addr(0),
                c_tx.clone(),
                loc_rib_filter(),
                BmpVersion::V3,
            )],
            metrics.clone(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let handle = tokio::spawn(mgr.run());

        let live_rm = || BmpEvent::LocRibRouteMonitoring {
            update_pdu: Bytes::from_static(&[0xCC; 23]),
            timestamp: UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
            path_status: None,
        };

        // Saturate the channel, then connect: the PeerUp try_send hits
        // Full and is dropped → this collector is suppressed. The drop
        // counter is the observable signal that the connect (and the
        // failed PeerUp) was processed — only then is it safe to drain
        // the backlog without the PeerUp sneaking into the freed slot.
        c_tx.try_send(Bytes::from_static(b"backlog")).unwrap();
        control_tx
            .send(BmpControlEvent::CollectorConnected {
                collector_id: 0,
                collector_addr: collector_addr(0),
            })
            .await
            .unwrap();
        for _ in 0..40 {
            if metric_family_sum(&metrics, "bmp_collector_drops_total") >= 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            metric_family_sum(&metrics, "bmp_collector_drops_total") >= 1,
            "connect-time Loc-RIB PeerUp drop must be counted"
        );
        event_tx.send(live_rm()).await.unwrap();

        // Only the pre-existing backlog is queued — no PeerUp, no RM,
        // and no dump was requested for the failed sync.
        let msg = c_rx.recv().await.unwrap();
        assert_eq!(msg, Bytes::from_static(b"backlog"));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), c_rx.recv())
                .await
                .is_err(),
            "suppressed: no live Loc-RIB RM without a preceding PeerUp"
        );
        assert!(
            dump_rx.try_recv().is_err(),
            "no dump for a collector whose Loc-RIB PeerUp was dropped"
        );

        // Reconnect with the channel drained heals it: PeerUp lands, the
        // dump runs (empty table here), then live RM flows again.
        control_tx
            .send(BmpControlEvent::CollectorConnected {
                collector_id: 0,
                collector_addr: collector_addr(0),
            })
            .await
            .unwrap();
        let peer_up = c_rx.recv().await.unwrap();
        assert_eq!(
            peer_up[6], 3,
            "Loc-RIB PeerUp (peer type 3) delivered on reconnect"
        );
        let request = tokio::time::timeout(std::time::Duration::from_secs(2), dump_rx.recv())
            .await
            .expect("dump requested on the healing reconnect")
            .expect("dump channel open");
        request
            .reply
            .send(crate::types::BmpDumpChunk {
                messages: vec![],
                next: None,
            })
            .unwrap();
        event_tx.send(live_rm()).await.unwrap();
        let rm = c_rx.recv().await.unwrap();
        assert_eq!(rm[5], 0, "route monitoring type");
        assert_eq!(rm[6], 3, "live Loc-RIB RM resumes after the PeerUp");

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
            vec![(collector_addr(0), c_tx, loc_rib_filter(), BmpVersion::V3)],
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
            vec![(
                collector_addr(0),
                c_tx,
                BmpMonitorFilter::default(),
                BmpVersion::V3,
            )],
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
