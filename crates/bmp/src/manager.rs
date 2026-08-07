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
    BmpCollectorBootstrap, BmpControlEvent, BmpDumpRequest, BmpEvent, BmpLocRibConfig,
    BmpMonitorFilter, BmpVersion,
};

/// Maximum time a dump request may wait for admission to the bounded
/// RIB-manager request channel.
const LOC_RIB_DUMP_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Maximum time the RIB manager may hold one admitted chunk request
/// before replying. This is deliberately separate from admission:
/// saturation and a wedged request handler are different failures.
const LOC_RIB_DUMP_REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Per-message send timeout for a Loc-RIB dump forwarder. Paces the dump
/// to the collector's TCP drain rate via the bounded collector channel;
/// a collector that stalls longer than this aborts the dump (the next
/// reconnect triggers a fresh one).
const LOC_RIB_DUMP_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Maximum live Loc-RIB rows held behind bootstrap or an in-flight dump.
/// Exceeding the cap fails that collector generation closed rather than
/// certifying a snapshot that omitted live deltas.
const LOC_RIB_DUMP_LIVE_BUFFER_CAP: usize = 8192;

/// One in-flight Loc-RIB dump — or a post-dump flush round of its
/// held-back live messages — for a collector connection generation.
struct ActiveDump {
    /// Connection generation the dump was started for.
    generation: u64,
    /// The forwarder or flush task, aborted when the connection is
    /// superseded.
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
    outcome: DumpOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DumpOutcome {
    /// The terminal RIB-owned chunk, including its End-of-RIB closure,
    /// was forwarded in full.
    Complete,
    /// The dump ended before its terminal RIB-owned End-of-RIB closure.
    Failed(DumpFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DumpFailure {
    RequestTimeout,
    RequestClosed,
    ReplyTimeout,
    ReplyClosed,
    ChannelTimeout,
    ChannelClosed,
    /// The post-dump flush of held-back live messages stalled past
    /// [`LOC_RIB_DUMP_SEND_TIMEOUT`] with this many messages undelivered.
    FlushTimeout(u64),
    /// The collector channel closed mid-flush with this many messages
    /// undelivered.
    FlushClosed(u64),
}

impl DumpFailure {
    const fn reason(self) -> &'static str {
        match self {
            Self::RequestTimeout => "request_timeout",
            Self::RequestClosed => "request_closed",
            Self::ReplyTimeout => "reply_timeout",
            Self::ReplyClosed => "reply_closed",
            Self::ChannelTimeout => "channel_timeout",
            Self::ChannelClosed => "channel_closed",
            Self::FlushTimeout(_) => "flush_timeout",
            Self::FlushClosed(_) => "flush_closed",
        }
    }

    /// Messages irrecoverably lost by the failure itself. Dump failures
    /// count as one dropped stream; a flush failure knows exactly how
    /// many held-back live messages it left undelivered.
    const fn dropped(self) -> u64 {
        match self {
            Self::FlushTimeout(n) | Self::FlushClosed(n) => n,
            _ => 1,
        }
    }
}

/// Connection-local resources. The sender is absent while disconnected
/// and is never reused across TCP connections.
enum CollectorPhase {
    Disconnected,
    BootstrapPending {
        generation: u64,
        sender: mpsc::Sender<Bytes>,
        loc_rib_peer_up: bool,
        /// Loc-RIB deltas accepted after the finite bootstrap snapshot but
        /// before the client confirms it reached TCP. They must follow the
        /// initial dump's terminal End-of-RIB, never precede it.
        loc_rib_buffer: Vec<Bytes>,
        /// When this generation began holding live deltas back. Carried
        /// on every dump chunk request so the RIB walk excludes routes
        /// installed after it — those must arrive only via the post-EoR
        /// replay of the buffer (LAN-885).
        started_at: std::time::SystemTime,
    },
    Active {
        generation: u64,
        sender: mpsc::Sender<Bytes>,
        loc_rib_peer_up: bool,
    },
}

impl CollectorPhase {
    fn sender(&self) -> Option<&mpsc::Sender<Bytes>> {
        match self {
            Self::Disconnected => None,
            Self::BootstrapPending { sender, .. } | Self::Active { sender, .. } => Some(sender),
        }
    }

    const fn generation(&self) -> Option<u64> {
        match self {
            Self::Disconnected => None,
            Self::BootstrapPending { generation, .. } | Self::Active { generation, .. } => {
                Some(*generation)
            }
        }
    }

    const fn loc_rib_peer_up(&self) -> bool {
        match self {
            Self::BootstrapPending {
                loc_rib_peer_up, ..
            }
            | Self::Active {
                loc_rib_peer_up, ..
            } => *loc_rib_peer_up,
            Self::Disconnected => false,
        }
    }
}

struct Collector {
    addr: SocketAddr,
    addr_label: String,
    filter: BmpMonitorFilter,
    version: BmpVersion,
    phase: CollectorPhase,
    /// Shared solely with this collector's dump task. The manager is
    /// the only writer and advances it before replacing connection state.
    generation: Arc<AtomicU64>,
}

/// BMP manager that fans out encoded messages to all collectors.
pub struct BmpManager {
    event_rx: mpsc::Receiver<BmpEvent>,
    control_rx: mpsc::Receiver<BmpControlEvent>,
    /// Per-collector immutable metadata plus generation-local connection
    /// state. The address is the operator-facing
    /// identifier used as the `collector` label on `bmp_*` Prometheus
    /// counters.
    collectors: Vec<Collector>,
    /// Latest encoded `PeerUp` message per peer address, one encoding
    /// per BMP version (indexed by [`BmpVersion::idx`]).
    peer_up_cache: std::collections::HashMap<std::net::IpAddr, [Bytes; 2]>,
    /// RFC 9069 Loc-RIB instance-peer identity. `None` = no collector
    /// monitors `loc_rib`; Loc-RIB events are dropped.
    loc_rib: Option<BmpLocRibConfig>,
    /// Loc-RIB table-dump request channel toward the RIB manager, used
    /// on collector (re)connect to synthesize the initial table sync.
    dump_tx: Option<mpsc::Sender<BmpDumpRequest>>,
    /// Collector indices whose current generation's Loc-RIB dump failed
    /// before its RIB-owned End-of-RIB closure. Live Loc-RIB output is
    /// suppressed for the rest of that generation; a later connection
    /// generation starts clean and heals the suppression.
    loc_rib_suppressed: std::collections::HashSet<usize>,
    /// In-flight Loc-RIB dump (plus its held-back live messages) per
    /// collector index. Present from dump spawn until the dump and
    /// every follow-up flush round report [`DumpDone`] with nothing
    /// left held back.
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
        collectors: Vec<(SocketAddr, BmpMonitorFilter, BmpVersion)>,
        metrics: BgpMetrics,
    ) -> Self {
        Self::from_collectors(
            event_rx,
            control_rx,
            collectors
                .into_iter()
                .map(|(addr, filter, version)| Collector {
                    addr,
                    addr_label: addr.to_string(),
                    filter,
                    version,
                    phase: CollectorPhase::Disconnected,
                    generation: Arc::new(AtomicU64::new(0)),
                })
                .collect(),
            metrics,
        )
    }

    /// Explicit active-state fixture for legacy fan-out tests. Generation and
    /// bootstrap tests use [`Self::new`] so this seam cannot make them green.
    #[cfg(test)]
    fn new_connected_for_test(
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
        Self::from_collectors(
            event_rx,
            control_rx,
            collectors
                .into_iter()
                .map(|(addr, sender, filter, version)| {
                    let loc_rib_peer_up = filter.loc_rib;
                    Collector {
                        addr,
                        addr_label: addr.to_string(),
                        filter,
                        version,
                        phase: CollectorPhase::Active {
                            generation: 1,
                            sender,
                            loc_rib_peer_up,
                        },
                        generation: Arc::new(AtomicU64::new(1)),
                    }
                })
                .collect(),
            metrics,
        )
    }

    fn from_collectors(
        event_rx: mpsc::Receiver<BmpEvent>,
        control_rx: mpsc::Receiver<BmpControlEvent>,
        collectors: Vec<Collector>,
        metrics: BgpMetrics,
    ) -> Self {
        // At most one in-flight dump (and thus one pending completion)
        // per collector.
        let (dump_done_tx, dump_done_rx) = mpsc::channel(collectors.len().max(1));
        Self {
            event_rx,
            control_rx,
            collectors,
            peer_up_cache: std::collections::HashMap::new(),
            loc_rib: None,
            dump_tx: None,
            loc_rib_suppressed: std::collections::HashSet::new(),
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
                        self.handle_event(&event).await;
                    } else {
                        events_open = false;
                        debug!("BMP event channel closed");
                    }
                }
                maybe_control = self.control_rx.recv(), if control_open => {
                    if let Some(control) = maybe_control {
                        if self.handle_control(control).await {
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
        self.fence_and_abort_dumps().await;
        for collector in &mut self.collectors {
            collector.phase = CollectorPhase::Disconnected;
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
    #[expect(
        clippy::too_many_lines,
        reason = "encoding, fan-out, and fail-closed fencing form one actor transaction"
    )]
    async fn handle_loc_rib_event(&mut self, event: &BmpEvent) {
        let Some(cfg) = self.loc_rib.clone() else {
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
        let mut overflowed = Vec::new();
        for idx in 0..self.collectors.len() {
            if !self.collectors[idx].filter.loc_rib || self.loc_rib_suppressed.contains(&idx) {
                continue;
            }
            let version = self.collectors[idx].version;
            let msg = memo[version.idx()]
                .get_or_insert_with(|| encode(version))
                .clone();
            let collector = &mut self.collectors[idx];
            let addr = collector.addr;
            let addr_label = collector.addr_label.as_str();
            match &mut collector.phase {
                CollectorPhase::Disconnected => {}
                CollectorPhase::BootstrapPending { loc_rib_buffer, .. } => {
                    let overflow = buffer_loc_rib_message(loc_rib_buffer, msg);
                    self.metrics
                        .observe_bmp_loc_rib_dump_live_buffer(addr_label, loc_rib_buffer.len());
                    if overflow {
                        overflowed.push(idx);
                    }
                }
                CollectorPhase::Active {
                    generation, sender, ..
                } => {
                    if let Some(dump) = self.active_dumps.get_mut(&idx) {
                        if *generation == dump.generation {
                            let overflow = buffer_loc_rib_message(&mut dump.buffered, msg);
                            self.metrics.observe_bmp_loc_rib_dump_live_buffer(
                                addr_label,
                                dump.buffered.len(),
                            );
                            if overflow {
                                overflowed.push(idx);
                            }
                        }
                    } else if let Err(e) = sender.try_send(msg) {
                        let reason = trysend_reason(&e);
                        self.metrics
                            .record_bmp_collector_drop(addr_label, "fan_out", reason, 1);
                        warn!(collector = %addr, error = %e, "BMP collector channel full or closed, dropping message");
                    }
                }
            }
        }
        if overflowed.is_empty() {
            return;
        }

        // Fence every affected generation before awaiting any forwarder. TCP
        // EOF invalidates all rows already observed for that BMP session.
        let mut tasks = Vec::new();
        for idx in overflowed {
            self.collectors[idx]
                .generation
                .fetch_add(1, Ordering::SeqCst);
            let phase = std::mem::replace(
                &mut self.collectors[idx].phase,
                CollectorPhase::Disconnected,
            );
            let discarded = match phase {
                CollectorPhase::BootstrapPending { loc_rib_buffer, .. } => loc_rib_buffer.len(),
                CollectorPhase::Active { .. } => {
                    let dump = self.active_dumps.remove(&idx).unwrap();
                    let len = dump.buffered.len();
                    tasks.push(dump.task);
                    len
                }
                CollectorPhase::Disconnected => unreachable!("validated connected phase"),
            };
            self.metrics.record_bmp_collector_drop(
                &self.collectors[idx].addr.to_string(),
                "loc_rib_dump",
                "live_buffer_full",
                u64::try_from(discarded).unwrap_or(u64::MAX),
            );
            self.metrics
                .clear_bmp_loc_rib_dump_live_buffer(&self.collectors[idx].addr.to_string());
            warn!(collector = %self.collectors[idx].addr, discarded, "live Loc-RIB buffer exceeded its bound; closing incomplete BMP generation");
        }
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
    }

    async fn handle_event(&mut self, event: &BmpEvent) {
        match event {
            BmpEvent::LocRibRouteMonitoring { .. } | BmpEvent::LocRibStats { .. } => {
                self.handle_loc_rib_event(event).await;
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
    async fn handle_control(&mut self, control: BmpControlEvent) -> bool {
        match control {
            BmpControlEvent::CollectorConnected {
                collector_id,
                collector_addr,
                sender,
                bootstrap,
            } => {
                self.handle_collector_connected(collector_id, collector_addr, sender, bootstrap);
                false
            }
            BmpControlEvent::CollectorDisconnected {
                collector_id,
                collector_addr,
                generation,
            } => {
                self.handle_collector_disconnected(collector_id, collector_addr, generation);
                false
            }
            BmpControlEvent::CollectorBootstrapComplete {
                collector_id,
                generation,
            } => {
                self.handle_bootstrap_complete(collector_id, generation);
                false
            }
            BmpControlEvent::Shutdown => {
                info!("BMP manager received shutdown request");
                // Control and data use distinct channels. Drain every data
                // event already accepted before fencing generations so its
                // wire message precedes the terminal Loc-RIB Peer Down.
                while let Ok(event) = self.event_rx.try_recv() {
                    self.handle_event(&event).await;
                }
                self.fence_and_abort_dumps().await;
                // RFC 9069 §5.3: emit Peer Down only on a generation whose
                // bootstrap actually carried the matching Loc-RIB Peer Up.
                if let Some(cfg) = self.loc_rib.clone() {
                    let now = std::time::SystemTime::now();
                    let mut memo: [Option<Bytes>; 2] = [None, None];
                    for collector in &self.collectors {
                        let (sender, loc_rib_peer_up) = match &collector.phase {
                            CollectorPhase::Active {
                                sender,
                                loc_rib_peer_up,
                                ..
                            } => (sender, *loc_rib_peer_up),
                            CollectorPhase::Disconnected
                            | CollectorPhase::BootstrapPending { .. } => continue,
                        };
                        if !loc_rib_peer_up {
                            continue;
                        }
                        let msg = memo[collector.version.idx()]
                            .get_or_insert_with(|| {
                                codec::encode_loc_rib_peer_down(&cfg, now, collector.version)
                            })
                            .clone();
                        if let Err(e) = sender.try_send(msg) {
                            self.metrics.record_bmp_collector_drop(
                                &collector.addr.to_string(),
                                "fan_out",
                                trysend_reason(&e),
                                1,
                            );
                            warn!(collector = %collector.addr, error = %e, "failed to enqueue shutdown Loc-RIB Peer Down");
                        }
                    }
                }
                // Dropping the last sender for every active generation lets
                // clients drain Peer Down before emitting Termination.
                for collector in &mut self.collectors {
                    if collector.phase.loc_rib_peer_up() {
                        self.metrics
                            .clear_bmp_loc_rib_dump_live_buffer(&collector.addr.to_string());
                    }
                    collector.phase = CollectorPhase::Disconnected;
                }
                true
            }
        }
    }

    /// Fence every connection generation and wait until all dump forwarders
    /// have observed cancellation. Awaiting is load-bearing: a task that is
    /// merely told to abort can still enqueue one final row after Peer Down.
    async fn fence_and_abort_dumps(&mut self) {
        for collector in &self.collectors {
            collector.generation.fetch_add(1, Ordering::SeqCst);
            if collector.phase.loc_rib_peer_up() {
                self.metrics
                    .clear_bmp_loc_rib_dump_live_buffer(&collector.addr.to_string());
            }
        }
        let tasks: Vec<_> = self
            .active_dumps
            .drain()
            .map(|(_, dump)| dump.task)
            .collect();
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
    }

    fn cancel_dump(&mut self, collector_id: usize) {
        if let Some(dump) = self.active_dumps.remove(&collector_id) {
            dump.task.abort();
            debug!(
                collector_id,
                "cancelled stale Loc-RIB dump from superseded collector connection"
            );
        }
    }

    fn handle_collector_connected(
        &mut self,
        collector_id: usize,
        collector_addr: SocketAddr,
        sender: mpsc::Sender<Bytes>,
        bootstrap: tokio::sync::oneshot::Sender<BmpCollectorBootstrap>,
    ) {
        let Some(collector) = self.collectors.get(collector_id) else {
            warn!(collector_id, collector = %collector_addr, "BMP connect target index out of range, rejecting connection");
            return;
        };
        if collector.addr != collector_addr {
            warn!(collector_id, configured = %collector.addr, reported = %collector_addr, "BMP connect address mismatch, rejecting connection");
            return;
        }

        self.cancel_dump(collector_id);
        let collector = &mut self.collectors[collector_id];
        let generation = collector.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let addr_label = collector.addr.to_string();
        self.metrics.record_bmp_replay_attempt(&addr_label);

        // Stable ordering makes reconnect behavior deterministic without
        // retaining any history beyond the current Peer Up cache.
        let mut peers: Vec<_> = self.peer_up_cache.iter().collect();
        peers.sort_unstable_by_key(|(addr, _)| **addr);
        let mut messages = Vec::with_capacity(peers.len() + usize::from(collector.filter.loc_rib));
        messages.extend(
            peers
                .into_iter()
                .map(|(_, encoded)| encoded[collector.version.idx()].clone()),
        );
        let loc_rib_peer_up = collector.filter.loc_rib && self.loc_rib.is_some();
        if loc_rib_peer_up {
            self.metrics.reset_bmp_loc_rib_dump_live_buffer(&addr_label);
        }
        if let Some(cfg) = self.loc_rib.as_ref().filter(|_| loc_rib_peer_up) {
            messages.push(codec::encode_loc_rib_peer_up(
                cfg,
                std::time::SystemTime::now(),
                collector.version,
            ));
        }

        collector.phase = CollectorPhase::BootstrapPending {
            generation,
            sender,
            loc_rib_peer_up,
            loc_rib_buffer: Vec::new(),
            started_at: std::time::SystemTime::now(),
        };
        self.loc_rib_suppressed.remove(&collector_id);
        info!(
            collector_id,
            collector = %collector_addr,
            generation,
            peer_count = self.peer_up_cache.len(),
            loc_rib_peer_up,
            "BMP collector connected, returning ordered bootstrap"
        );
        if bootstrap
            .send(BmpCollectorBootstrap {
                generation,
                messages,
            })
            .is_err()
        {
            warn!(collector_id, collector = %collector_addr, generation, "BMP client dropped bootstrap acknowledgement receiver");
            self.disconnect_current(collector_id, generation);
        }
    }

    fn handle_bootstrap_complete(&mut self, collector_id: usize, generation: u64) {
        let Some(collector) = self.collectors.get_mut(collector_id) else {
            warn!(
                collector_id,
                generation, "BMP bootstrap completion target out of range, ignoring"
            );
            return;
        };
        let old_phase = std::mem::replace(&mut collector.phase, CollectorPhase::Disconnected);
        let (loc_rib_buffer, started_at) = match old_phase {
            CollectorPhase::BootstrapPending {
                generation: current,
                sender,
                loc_rib_peer_up,
                loc_rib_buffer,
                started_at,
            } if current == generation => {
                collector.phase = CollectorPhase::Active {
                    generation,
                    sender,
                    loc_rib_peer_up,
                };
                (loc_rib_buffer, started_at)
            }
            other => {
                collector.phase = other;
                debug!(collector_id, generation, current = ?collector.phase.generation(), "stale BMP bootstrap completion ignored");
                return;
            }
        };
        debug!(
            collector_id,
            generation, "BMP collector bootstrap completed"
        );
        self.start_loc_rib_dump(collector_id, generation, loc_rib_buffer, started_at);
    }

    fn handle_collector_disconnected(
        &mut self,
        collector_id: usize,
        collector_addr: SocketAddr,
        generation: u64,
    ) {
        let Some(collector) = self.collectors.get(collector_id) else {
            warn!(collector_id, collector = %collector_addr, generation, "BMP disconnect target out of range, ignoring");
            return;
        };
        if collector.addr != collector_addr || collector.phase.generation() != Some(generation) {
            debug!(collector_id, collector = %collector_addr, generation, current = ?collector.phase.generation(), "stale or mismatched BMP disconnect ignored");
            return;
        }
        debug!(collector_id, collector = %collector_addr, generation, "BMP collector disconnected");
        self.disconnect_current(collector_id, generation);
    }

    fn disconnect_current(&mut self, collector_id: usize, generation: u64) {
        self.cancel_dump(collector_id);
        let collector = &mut self.collectors[collector_id];
        if collector.phase.generation() == Some(generation) {
            if collector.filter.loc_rib && self.loc_rib.is_some() {
                self.metrics
                    .clear_bmp_loc_rib_dump_live_buffer(&collector.addr.to_string());
            }
            collector.generation.fetch_add(1, Ordering::SeqCst);
            collector.phase = CollectorPhase::Disconnected;
        }
    }

    /// Apply a generation-current dump outcome. Only a complete terminal
    /// RIB chunk flushes buffered deltas. Failure discards them and
    /// suppresses this Loc-RIB view until a later connection generation.
    ///
    /// The flush runs as a follow-up task registered in
    /// [`Self::active_dumps`]: the held-back buffer (up to
    /// [`LOC_RIB_DUMP_LIVE_BUFFER_CAP`] messages) can exceed the
    /// collector channel's free capacity, so delivery must await
    /// capacity at the collector's drain rate ([`flush_held_loc_rib`])
    /// instead of dropping whatever the burst could not fit. While a
    /// round flushes, live events keep buffering behind it; each round's
    /// completion arrives back here and flushes what accumulated
    /// meanwhile, and the collector goes live once a round completes
    /// with nothing held.
    fn handle_dump_done(&mut self, done: &DumpDone) {
        match self.active_dumps.get(&done.collector_id) {
            Some(dump) if dump.generation == done.generation => {}
            _ => return,
        }
        let Some(dump) = self.active_dumps.remove(&done.collector_id) else {
            return;
        };
        let Some(collector) = self.collectors.get(done.collector_id) else {
            return;
        };
        if collector.phase.generation() != Some(done.generation) {
            return;
        }
        let Some(tx) = collector.phase.sender() else {
            return;
        };
        let addr_label = collector.addr.to_string();
        self.metrics.clear_bmp_loc_rib_dump_live_buffer(&addr_label);
        if let DumpOutcome::Failed(failure) = done.outcome {
            self.loc_rib_suppressed.insert(done.collector_id);
            // The discarded held-back live messages are real drops too:
            // count them alongside what the failure itself lost.
            let buffered_dropped = u64::try_from(dump.buffered.len()).unwrap_or(u64::MAX);
            self.metrics.record_bmp_collector_drop(
                &addr_label,
                "loc_rib_dump",
                failure.reason(),
                failure.dropped().saturating_add(buffered_dropped),
            );
            warn!(
                collector = %collector.addr,
                generation = done.generation,
                reason = failure.reason(),
                buffered_dropped = dump.buffered.len(),
                "Loc-RIB dump or post-dump flush failed; suppressing this view until reconnect"
            );
            return;
        }
        if dump.buffered.is_empty() {
            return;
        }

        let flush = FlushForwarder {
            collector_tx: tx.clone(),
            addr_label,
            generation: Arc::clone(&collector.generation),
            dump_generation: done.generation,
        };
        let task = tokio::spawn(flush_held_loc_rib(
            flush,
            dump.buffered,
            self.dump_done_tx.clone(),
            done.collector_id,
        ));
        self.active_dumps.insert(
            done.collector_id,
            ActiveDump {
                generation: done.generation,
                task,
                buffered: Vec::new(),
            },
        );
    }

    /// RFC 9069 table sync for a (re)connected collector that monitors
    /// `loc_rib`: after its finite bootstrap reaches TCP, request a
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
    fn start_loc_rib_dump(
        &mut self,
        collector_id: usize,
        generation: u64,
        buffered: Vec<Bytes>,
        started_at: std::time::SystemTime,
    ) {
        let Some(ref cfg) = self.loc_rib else {
            return;
        };
        let Some(collector) = self.collectors.get(collector_id) else {
            return;
        };
        if !collector.filter.loc_rib
            || collector.phase.generation() != Some(generation)
            || !matches!(collector.phase, CollectorPhase::Active { .. })
        {
            return;
        }
        let Some(collector_tx) = collector.phase.sender().cloned() else {
            return;
        };
        let addr_label = collector.addr.to_string();
        let version = collector.version;
        let cfg = cfg.clone();

        let Some(ref dump_tx) = self.dump_tx else {
            return;
        };
        let generation_fence = Arc::clone(&collector.generation);
        let task = tokio::spawn(forward_loc_rib_dump(
            DumpForwarder {
                dump_tx: dump_tx.clone(),
                collector_tx,
                cfg,
                version,
                addr_label,
                generation: generation_fence,
                dump_generation: generation,
                started_at,
            },
            self.dump_done_tx.clone(),
            collector_id,
        ));
        self.active_dumps.insert(
            collector_id,
            ActiveDump {
                generation,
                task,
                buffered,
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
        for (idx, collector) in self.collectors.iter().enumerate() {
            if !want(idx, &collector.filter) {
                continue;
            }
            let Some(tx) = collector.phase.sender() else {
                continue;
            };
            let msg = memo[collector.version.idx()]
                .get_or_insert_with(|| encode(collector.version))
                .clone();
            if let Err(e) = tx.try_send(msg) {
                let reason = trysend_reason(&e);
                self.metrics.record_bmp_collector_drop(
                    &collector.addr.to_string(),
                    "fan_out",
                    reason,
                    1,
                );
                warn!(
                    collector = %collector.addr,
                    error = %e,
                    "BMP collector channel full or closed, dropping message"
                );
            }
        }
    }
}

impl Drop for BmpManager {
    fn drop(&mut self) {
        for collector in &self.collectors {
            let addr_label = collector.addr.to_string();
            self.metrics.reap_bmp_loc_rib_dump_live_buffer(&addr_label);
            self.metrics.reap_bmp_collector_series(&addr_label);
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
    addr_label: String,
    /// Live connection generation of the collector (shared with the
    /// manager, which bumps it on every connect/disconnect).
    generation: Arc<AtomicU64>,
    /// The generation this dump was started for; the forwarder aborts
    /// as soon as the live value moves past it.
    dump_generation: u64,
    /// When the generation began holding live Loc-RIB deltas back;
    /// carried on every chunk request so the RIB walk never emits a
    /// route installed after it as dump content (LAN-885).
    started_at: std::time::SystemTime,
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

/// Forward one generation's Loc-RIB dump and report only a terminal
/// success or failure. Superseded tasks are silently fenced; their
/// manager-owned state was already discarded.
async fn forward_loc_rib_dump(
    forwarder: DumpForwarder,
    done_tx: mpsc::Sender<DumpDone>,
    collector_id: usize,
) {
    let generation = forwarder.dump_generation;
    if let Some(outcome) = stream_loc_rib_dump(forwarder).await {
        let _ = done_tx
            .send(DumpDone {
                collector_id,
                generation,
                outcome,
            })
            .await;
    }
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
async fn stream_loc_rib_dump(f: DumpForwarder) -> Option<DumpOutcome> {
    let mut cursor = None;
    let mut sent: u64 = 0;
    loop {
        if f.superseded() {
            debug!(collector = %f.addr_label, "collector connection superseded, aborting stale Loc-RIB dump");
            return None;
        }
        let (reply, chunk_rx) = tokio::sync::oneshot::channel();
        match tokio::time::timeout(
            LOC_RIB_DUMP_REQUEST_TIMEOUT,
            f.dump_tx.send(BmpDumpRequest {
                cursor,
                started_at: f.started_at,
                reply,
            }),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                return (!f.superseded())
                    .then_some(DumpOutcome::Failed(DumpFailure::RequestClosed));
            }
            Err(_) => {
                return (!f.superseded())
                    .then_some(DumpOutcome::Failed(DumpFailure::RequestTimeout));
            }
        }
        let chunk = match tokio::time::timeout(LOC_RIB_DUMP_REPLY_TIMEOUT, chunk_rx).await {
            Ok(Ok(chunk)) => chunk,
            Ok(Err(_)) => {
                return (!f.superseded()).then_some(DumpOutcome::Failed(DumpFailure::ReplyClosed));
            }
            Err(_) => {
                return (!f.superseded()).then_some(DumpOutcome::Failed(DumpFailure::ReplyTimeout));
            }
        };
        for (pdu, timestamp, path_status) in chunk.messages {
            if f.superseded() {
                debug!(collector = %f.addr_label, "collector connection superseded, aborting stale Loc-RIB dump");
                return None;
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
                    return (!f.superseded())
                        .then_some(DumpOutcome::Failed(DumpFailure::ChannelClosed));
                }
                Err(_) => {
                    return (!f.superseded())
                        .then_some(DumpOutcome::Failed(DumpFailure::ChannelTimeout));
                }
            }
        }
        if let Some(next) = chunk.next {
            cursor = Some(next);
        } else {
            debug!(collector = %f.addr_label, messages = sent, "Loc-RIB dump forwarded through RIB-owned End-of-RIB closure");
            return Some(DumpOutcome::Complete);
        }
    }
}

/// Everything one post-dump flush task needs, mirroring
/// [`DumpForwarder`] for the flush leg.
struct FlushForwarder {
    collector_tx: mpsc::Sender<Bytes>,
    addr_label: String,
    /// Live connection generation shared with the manager; same fencing
    /// contract as [`DumpForwarder::generation`].
    generation: Arc<AtomicU64>,
    dump_generation: u64,
}

impl FlushForwarder {
    fn superseded(&self) -> bool {
        self.generation.load(Ordering::SeqCst) != self.dump_generation
    }
}

/// Deliver one completed dump's held-back live Loc-RIB messages,
/// awaiting collector-channel capacity instead of dropping: the source
/// is bounded (at most [`LOC_RIB_DUMP_LIVE_BUFFER_CAP`] messages) and
/// the writer drains to a TCP socket, so a healthy collector always
/// absorbs the burst even when it briefly outpaces the writer.
/// [`LOC_RIB_DUMP_SEND_TIMEOUT`] per message remains the last resort
/// for a genuinely dead or stalled collector, and the generation fence
/// stops the task the moment the connection is superseded.
///
/// Runs as the collector's registered dump task so one collector's
/// flush never blocks the manager loop, other collectors, or the churn
/// fan-out path.
async fn flush_held_loc_rib(
    f: FlushForwarder,
    buffered: Vec<Bytes>,
    done_tx: mpsc::Sender<DumpDone>,
    collector_id: usize,
) {
    let total = buffered.len();
    let mut outcome = DumpOutcome::Complete;
    for (idx, msg) in buffered.into_iter().enumerate() {
        if f.superseded() {
            return;
        }
        let remaining = u64::try_from(total - idx).unwrap_or(u64::MAX);
        let failure =
            match tokio::time::timeout(LOC_RIB_DUMP_SEND_TIMEOUT, f.collector_tx.send(msg)).await {
                Ok(Ok(())) => continue,
                Ok(Err(_)) => DumpFailure::FlushClosed(remaining),
                Err(_) => DumpFailure::FlushTimeout(remaining),
            };
        if f.superseded() {
            return;
        }
        warn!(
            collector = %f.addr_label,
            reason = failure.reason(),
            skipped = remaining,
            "BMP collector stalled or closed flushing post-dump live Loc-RIB \
             messages; remaining messages dropped"
        );
        outcome = DumpOutcome::Failed(failure);
        break;
    }
    let _ = done_tx
        .send(DumpDone {
            collector_id,
            generation: f.dump_generation,
            outcome,
        })
        .await;
}

fn buffer_loc_rib_message(buffer: &mut Vec<Bytes>, message: Bytes) -> bool {
    buffer.push(message);
    buffer.len() > LOC_RIB_DUMP_LIVE_BUFFER_CAP
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

    async fn connect_collector(
        control_tx: &mpsc::Sender<BmpControlEvent>,
        collector_id: usize,
        collector_addr: SocketAddr,
        capacity: usize,
    ) -> (BmpCollectorBootstrap, mpsc::Receiver<Bytes>) {
        let (sender, receiver) = mpsc::channel(capacity);
        let (bootstrap, bootstrap_rx) = tokio::sync::oneshot::channel();
        control_tx
            .send(BmpControlEvent::CollectorConnected {
                collector_id,
                collector_addr,
                sender,
                bootstrap,
            })
            .await
            .unwrap();
        (bootstrap_rx.await.unwrap(), receiver)
    }

    async fn complete_bootstrap(
        control_tx: &mpsc::Sender<BmpControlEvent>,
        collector_id: usize,
        generation: u64,
    ) {
        control_tx
            .send(BmpControlEvent::CollectorBootstrapComplete {
                collector_id,
                generation,
            })
            .await
            .unwrap();
    }

    async fn wait_until_received<T>(sender: &mpsc::Sender<T>, capacity: usize) {
        while sender.capacity() != capacity {
            tokio::task::yield_now().await;
        }
    }

    fn dump_forwarder(
        dump_tx: mpsc::Sender<BmpDumpRequest>,
        collector_tx: mpsc::Sender<Bytes>,
    ) -> DumpForwarder {
        DumpForwarder {
            dump_tx,
            collector_tx,
            cfg: loc_rib_config(),
            version: BmpVersion::V3,
            addr_label: collector_addr(0).to_string(),
            generation: Arc::new(AtomicU64::new(1)),
            dump_generation: 1,
            started_at: std::time::SystemTime::now(),
        }
    }

    #[tokio::test]
    async fn manager_fans_out_to_all_collectors() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (c1_tx, mut c1_rx) = mpsc::channel(16);
        let (c2_tx, mut c2_rx) = mpsc::channel(16);

        let mgr = BmpManager::new_connected_for_test(
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

        let mgr = BmpManager::new_connected_for_test(
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
        let (bootstrap, _new_v4_rx) =
            connect_collector(&control_tx, 1, collector_addr(1), 16).await;
        let replay = &bootstrap.messages[0];
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

        let mgr = BmpManager::new_connected_for_test(
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

        let mgr = BmpManager::new_connected_for_test(
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

        let mgr = BmpManager::new_connected_for_test(
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

        let mgr = BmpManager::new_connected_for_test(
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

        let mgr = BmpManager::new_connected_for_test(
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

    /// Production mutation: retaining a sender while disconnected, or caching
    /// ordinary Route Monitoring, makes the 0xAA backlog appear on reconnect;
    /// removing Peer Up cache maintenance makes the bootstrap empty instead.
    #[tokio::test]
    async fn disconnected_backlog_is_skipped_while_peer_up_cache_stays_current() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![
                (
                    collector_addr(0),
                    BmpMonitorFilter::default(),
                    BmpVersion::V3,
                ),
                (
                    collector_addr(1),
                    BmpMonitorFilter::default(),
                    BmpVersion::V3,
                ),
            ],
            BgpMetrics::new(),
        );
        let handle = tokio::spawn(mgr.run());

        event_tx
            .send(BmpEvent::RouteMonitoring {
                peer_info: sample_peer_info(),
                update_pdu: Bytes::from_static(&[0xAA; 23]),
            })
            .await
            .unwrap();
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
        wait_until_received(&event_tx, 16).await;

        let (bootstrap, mut live_rx) =
            connect_collector(&control_tx, 0, collector_addr(0), 16).await;
        assert_eq!(
            bootstrap.messages.len(),
            1,
            "only current Peer Up is replayable"
        );
        let replay = &bootstrap.messages[0];
        assert_eq!(replay[0], 3); // BMP version
        assert_eq!(replay[5], 3); // PeerUp message type
        assert!(
            live_rx.try_recv().is_err(),
            "disconnected RM has no backlog"
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

    #[expect(
        clippy::cast_possible_truncation,
        reason = "test gauges use small exact integer values"
    )]
    fn gauge_value(metrics: &BgpMetrics, name: &str, collector: SocketAddr) -> i64 {
        metrics
            .registry()
            .gather()
            .into_iter()
            .find(|f| f.name() == name)
            .and_then(|mut f| {
                f.take_metric().into_iter().find(|m| {
                    m.label
                        .iter()
                        .any(|l| l.name() == "collector" && l.value() == collector.to_string())
                })
            })
            .map_or(0, |m| m.gauge.value() as i64)
    }

    fn collector_series_exists(metrics: &BgpMetrics, name: &str, collector: SocketAddr) -> bool {
        metrics.registry().gather().into_iter().any(|f| {
            f.name() == name
                && f.metric.iter().any(|m| {
                    m.label
                        .iter()
                        .any(|l| l.name() == "collector" && l.value() == collector.to_string())
                })
        })
    }

    fn assert_live_buffer_gauges(
        metrics: &BgpMetrics,
        collector: SocketAddr,
        depth: i64,
        hwm: i64,
    ) {
        assert_eq!(
            gauge_value(metrics, "bmp_loc_rib_dump_live_buffer_depth", collector),
            depth
        );
        assert_eq!(
            gauge_value(
                metrics,
                "bmp_loc_rib_dump_live_buffer_high_watermark",
                collector
            ),
            hwm
        );
    }

    #[tokio::test]
    async fn loc_rib_live_buffer_metrics_follow_generation_storage_lifecycle() {
        let (_event_tx, event_rx) = mpsc::channel(1);
        let (_control_tx, control_rx) = mpsc::channel(1);
        let (dump_tx, _dump_rx) = mpsc::channel(1);
        let metrics = BgpMetrics::new();
        let addr = collector_addr(0);
        let mut manager = BmpManager::new(
            event_rx,
            control_rx,
            vec![(addr, loc_rib_filter(), BmpVersion::V3)],
            metrics.clone(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let (bad_sender, _bad_receiver) = mpsc::channel(1);
        let (bad_bootstrap, _bad_bootstrap_rx) = tokio::sync::oneshot::channel();
        manager.handle_collector_connected(0, collector_addr(1), bad_sender, bad_bootstrap);
        assert!(!collector_series_exists(
            &metrics,
            "bmp_loc_rib_dump_live_buffer_depth",
            addr
        ));
        let (sender, _receiver) = mpsc::channel(4);
        let (bootstrap_tx, bootstrap_rx) = tokio::sync::oneshot::channel();
        manager.handle_collector_connected(0, addr, sender, bootstrap_tx);
        let generation = bootstrap_rx.await.unwrap().generation;
        assert_live_buffer_gauges(&metrics, addr, 0, 0);

        manager
            .handle_loc_rib_event(&BmpEvent::LocRibStats { per_family: vec![] })
            .await;
        assert_live_buffer_gauges(&metrics, addr, 1, 1);
        manager.handle_bootstrap_complete(0, generation);
        assert_eq!(
            gauge_value(&metrics, "bmp_loc_rib_dump_live_buffer_depth", addr),
            1
        );
        manager.handle_collector_disconnected(0, addr, generation + 1);
        assert_eq!(
            gauge_value(&metrics, "bmp_loc_rib_dump_live_buffer_depth", addr),
            1
        );

        manager.handle_dump_done(&DumpDone {
            collector_id: 0,
            generation,
            outcome: DumpOutcome::Complete,
        });
        assert_live_buffer_gauges(&metrics, addr, 0, 1);
    }

    #[test]
    fn manager_drop_reaps_only_its_exact_collector_series() {
        let metrics = BgpMetrics::new();
        let addr0 = collector_addr(0);
        let addr1 = collector_addr(1);
        metrics.reset_bmp_loc_rib_dump_live_buffer(&addr0.to_string());
        metrics.reset_bmp_loc_rib_dump_live_buffer(&addr1.to_string());
        metrics.observe_bmp_loc_rib_dump_live_buffer(&addr0.to_string(), 3);
        metrics.observe_bmp_loc_rib_dump_live_buffer(&addr1.to_string(), 5);
        for addr in [addr0, addr1] {
            let label = addr.to_string();
            metrics.record_bmp_collector_drop(&label, "fan_out", "channel_full", 1);
            metrics.record_bmp_replay_attempt(&label);
            metrics.record_bmp_control_event_drop(&label, "collector_connected", "channel_full");
        }
        let (_event_tx, event_rx) = mpsc::channel(1);
        let (_control_tx, control_rx) = mpsc::channel(1);
        let manager = BmpManager::new(
            event_rx,
            control_rx,
            vec![(addr0, loc_rib_filter(), BmpVersion::V3)],
            metrics.clone(),
        );

        drop(manager);

        for name in [
            "bmp_loc_rib_dump_live_buffer_depth",
            "bmp_loc_rib_dump_live_buffer_high_watermark",
            "bmp_collector_drops_total",
            "bmp_replay_attempts_total",
            "bmp_control_event_drops_total",
        ] {
            assert!(!collector_series_exists(&metrics, name, addr0), "{name}");
            assert!(collector_series_exists(&metrics, name, addr1), "{name}");
        }
        assert_eq!(
            gauge_value(&metrics, "bmp_loc_rib_dump_live_buffer_depth", addr1),
            5
        );
    }

    #[test]
    fn manager_drop_does_not_materialize_never_connected_series() {
        let metrics = BgpMetrics::new();
        let addr = collector_addr(0);
        let (_event_tx, event_rx) = mpsc::channel(1);
        let (_control_tx, control_rx) = mpsc::channel(1);
        drop(BmpManager::new(
            event_rx,
            control_rx,
            vec![(addr, loc_rib_filter(), BmpVersion::V3)],
            metrics.clone(),
        ));
        assert!(!collector_series_exists(
            &metrics,
            "bmp_loc_rib_dump_live_buffer_depth",
            addr
        ));
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
        let mgr = BmpManager::new_connected_for_test(
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

    /// Production mutation: replaying cached Peer Ups through the one-deep
    /// live sender truncates this six-message bootstrap at the first entry.
    #[tokio::test]
    async fn capacity_one_sender_gets_complete_finite_bootstrap() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let addr = collector_addr(9);
        let (dump_tx, _dump_rx) = mpsc::channel(1);
        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(addr, loc_rib_filter(), BmpVersion::V3)],
            BgpMetrics::new(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let handle = tokio::spawn(mgr.run());

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
        }
        wait_until_received(&event_tx, 16).await;

        let (bootstrap, mut live_rx) = connect_collector(&control_tx, 0, addr, 1).await;
        assert_eq!(
            bootstrap.messages.len(),
            6,
            "five ordinary plus Loc-RIB Peer Up"
        );
        assert!(
            bootstrap.messages[..5]
                .iter()
                .all(|message| message[5] == 3)
        );
        assert_eq!(bootstrap.messages[5][6], 3, "Loc-RIB instance Peer Up last");
        assert!(
            live_rx.try_recv().is_err(),
            "bootstrap bypasses bounded live sender"
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
        let addr = collector_addr(3);

        let metrics = BgpMetrics::new();
        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(addr, BmpMonitorFilter::default(), BmpVersion::V3)],
            metrics.clone(),
        );
        let handle = tokio::spawn(mgr.run());

        let (_bootstrap, _new_rx) = connect_collector(&control_tx, 0, addr, 16).await;

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

    /// Production mutation: omitting either generation comparison lets an old
    /// Complete start gen-2's dump or an old Disconnect close gen-2's sender.
    #[tokio::test]
    async fn stale_generation_control_events_are_ignored() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (dump_tx, mut dump_rx) = mpsc::channel(4);
        let addr = collector_addr(0);
        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(addr, loc_rib_filter(), BmpVersion::V3)],
            BgpMetrics::new(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let handle = tokio::spawn(mgr.run());

        let (first, _first_rx) = connect_collector(&control_tx, 0, addr, 8).await;
        let (second, mut second_rx) = connect_collector(&control_tx, 0, addr, 8).await;
        complete_bootstrap(&control_tx, 0, first.generation).await;
        control_tx
            .send(BmpControlEvent::CollectorDisconnected {
                collector_id: 0,
                collector_addr: addr,
                generation: first.generation,
            })
            .await
            .unwrap();
        assert!(
            dump_rx.try_recv().is_err(),
            "stale Complete cannot start a dump"
        );

        complete_bootstrap(&control_tx, 0, second.generation).await;
        let request = tokio::time::timeout(std::time::Duration::from_secs(2), dump_rx.recv())
            .await
            .expect("current generation did not start dump")
            .unwrap();
        request
            .reply
            .send(crate::types::BmpDumpChunk {
                messages: vec![],
                next: None,
            })
            .unwrap();
        event_tx
            .send(BmpEvent::StatsReport {
                peer_info: sample_peer_info(),
                adj_rib_in_routes: 1,
                adj_rib_out_post: None,
            })
            .await
            .unwrap();
        assert_eq!(second_rx.recv().await.unwrap()[5], 1);

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();
    }

    /// Production mutation: collapsing admission/reply/send errors into one
    /// path, or treating any of them as Complete, changes these bounded
    /// outcomes and can flush an unterminated Loc-RIB view.
    #[tokio::test(start_paused = true)]
    async fn every_loc_rib_dump_failure_has_a_bounded_outcome() {
        let (dump_tx, dump_rx) = mpsc::channel(1);
        drop(dump_rx);
        let (collector_tx, _collector_rx) = mpsc::channel(1);
        assert_eq!(
            stream_loc_rib_dump(dump_forwarder(dump_tx, collector_tx)).await,
            Some(DumpOutcome::Failed(DumpFailure::RequestClosed))
        );

        let (dump_tx, mut dump_rx) = mpsc::channel(1);
        let (reply, _reply_rx) = tokio::sync::oneshot::channel();
        dump_tx
            .try_send(BmpDumpRequest {
                cursor: None,
                started_at: std::time::SystemTime::now(),
                reply,
            })
            .unwrap();
        let (collector_tx, _collector_rx) = mpsc::channel(1);
        let task = tokio::spawn(stream_loc_rib_dump(dump_forwarder(dump_tx, collector_tx)));
        tokio::task::yield_now().await;
        tokio::time::advance(LOC_RIB_DUMP_REQUEST_TIMEOUT).await;
        assert_eq!(
            task.await.unwrap(),
            Some(DumpOutcome::Failed(DumpFailure::RequestTimeout))
        );
        drop(dump_rx.recv().await);

        let (dump_tx, mut dump_rx) = mpsc::channel(1);
        let (collector_tx, _collector_rx) = mpsc::channel(1);
        let task = tokio::spawn(stream_loc_rib_dump(dump_forwarder(dump_tx, collector_tx)));
        drop(dump_rx.recv().await.unwrap().reply);
        assert_eq!(
            task.await.unwrap(),
            Some(DumpOutcome::Failed(DumpFailure::ReplyClosed))
        );

        let (dump_tx, mut dump_rx) = mpsc::channel(1);
        let (collector_tx, _collector_rx) = mpsc::channel(1);
        let task = tokio::spawn(stream_loc_rib_dump(dump_forwarder(dump_tx, collector_tx)));
        let held_request = dump_rx.recv().await.unwrap();
        tokio::time::advance(LOC_RIB_DUMP_REPLY_TIMEOUT).await;
        assert_eq!(
            task.await.unwrap(),
            Some(DumpOutcome::Failed(DumpFailure::ReplyTimeout))
        );
        drop(held_request);

        let terminal_chunk = || crate::types::BmpDumpChunk {
            messages: vec![(Bytes::from_static(&[0xE0; 23]), UNIX_EPOCH, None)],
            next: None,
        };
        let (dump_tx, mut dump_rx) = mpsc::channel(1);
        let (collector_tx, collector_rx) = mpsc::channel(1);
        drop(collector_rx);
        let task = tokio::spawn(stream_loc_rib_dump(dump_forwarder(dump_tx, collector_tx)));
        dump_rx
            .recv()
            .await
            .unwrap()
            .reply
            .send(terminal_chunk())
            .unwrap();
        assert_eq!(
            task.await.unwrap(),
            Some(DumpOutcome::Failed(DumpFailure::ChannelClosed))
        );

        let (dump_tx, mut dump_rx) = mpsc::channel(1);
        let (collector_tx, _collector_rx) = mpsc::channel(1);
        collector_tx.try_send(Bytes::from_static(b"full")).unwrap();
        let task = tokio::spawn(stream_loc_rib_dump(dump_forwarder(dump_tx, collector_tx)));
        dump_rx
            .recv()
            .await
            .unwrap()
            .reply
            .send(terminal_chunk())
            .unwrap();
        tokio::time::advance(LOC_RIB_DUMP_SEND_TIMEOUT).await;
        assert_eq!(
            task.await.unwrap(),
            Some(DumpOutcome::Failed(DumpFailure::ChannelTimeout))
        );
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

        let mgr = BmpManager::new_connected_for_test(
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

        let mgr = BmpManager::new_connected_for_test(
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

    /// Production mutation: starting the dump in `CollectorConnected`
    /// makes this test observe a request before bootstrap completion.
    /// Collector connect triggers the RFC 9069 table sync: Loc-RIB Peer
    /// Up first, then the dump chunks as RM messages (install-time
    /// headers), then live Loc-RIB events keep flowing — and the dump
    /// request goes out for `loc_rib` collectors only.
    #[tokio::test]
    async fn collector_connect_triggers_loc_rib_peer_up_then_dump_then_live() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (dump_tx, mut dump_rx) = mpsc::channel(4);

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), loc_rib_filter(), BmpVersion::V3)],
            BgpMetrics::new(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let handle = tokio::spawn(mgr.run());

        let (bootstrap, mut c_rx) = connect_collector(&control_tx, 0, collector_addr(0), 16).await;

        // 1. Loc-RIB Peer Up replay (peer type 3, fabricated OPEN twice,
        // table-name TLV at the tail).
        let peer_up = &bootstrap.messages[0];
        assert_eq!(peer_up[5], 3, "PeerUp message type");
        assert_eq!(peer_up[6], 3, "peer type 3");
        assert_eq!(&peer_up[peer_up.len() - 6..], b"global");
        event_tx
            .send(BmpEvent::LocRibRouteMonitoring {
                update_pdu: Bytes::from_static(&[0xCC; 23]),
                timestamp: UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
                path_status: None,
            })
            .await
            .unwrap();
        wait_until_received(&event_tx, 16).await;
        assert!(
            dump_rx.try_recv().is_err(),
            "dump admission must wait for matching bootstrap completion"
        );
        assert!(
            c_rx.try_recv().is_err(),
            "pending Loc-RIB delta must wait behind dump and End-of-RIB"
        );
        complete_bootstrap(&control_tx, 0, bootstrap.generation).await;

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
        assert_eq!(
            c_rx.recv().await.unwrap()[48],
            0xCC,
            "delta accepted before Complete flushes after terminal EoR"
        );

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

    /// Production mutation: accepting completion/disconnect events without
    /// comparing generations lets the held stale request leak into gen 2.
    /// LAN-289 generation fence: a Loc-RIB dump task started for a
    /// previous collector connection stops on reconnect — nothing from
    /// the stale dump may interleave after the new generation's stream
    /// (`PeerUp` + fresh dump) starts.
    #[tokio::test]
    async fn reconnect_fences_stale_loc_rib_dump_task() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (dump_tx, mut dump_rx) = mpsc::channel(4);

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), loc_rib_filter(), BmpVersion::V3)],
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
        let (bootstrap1, mut c_rx) = connect_collector(&control_tx, 0, collector_addr(0), 64).await;
        let peer_up = &bootstrap1.messages[0];
        assert_eq!(peer_up[5], 3, "gen-1 Loc-RIB PeerUp");
        complete_bootstrap(&control_tx, 0, bootstrap1.generation).await;
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
        let (bootstrap2, mut c_rx2) =
            connect_collector(&control_tx, 0, collector_addr(0), 64).await;
        let peer_up2 = &bootstrap2.messages[0];
        assert_eq!(peer_up2[5], 3, "gen-2 Loc-RIB PeerUp");
        complete_bootstrap(&control_tx, 0, bootstrap2.generation).await;
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

        let row = c_rx2.recv().await.unwrap();
        assert_eq!(
            row[48], 0xC1,
            "only the new generation's dump rows reach the collector"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), c_rx2.recv())
                .await
                .is_err(),
            "stale gen-1 dump row must never interleave into the gen-2 stream"
        );

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();
    }

    /// Production mutation: flushing buffered live rows on any dump outcome,
    /// or before terminal completion, makes the 0xEE row arrive before `EoR`.
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
        let (dump_tx, mut dump_rx) = mpsc::channel(4);

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), loc_rib_filter(), BmpVersion::V3)],
            BgpMetrics::new(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let handle = tokio::spawn(mgr.run());

        let (bootstrap, mut c_rx) = connect_collector(&control_tx, 0, collector_addr(0), 16).await;
        let peer_up = &bootstrap.messages[0];
        assert_eq!(peer_up[5], 3);
        complete_bootstrap(&control_tx, 0, bootstrap.generation).await;
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

        let mgr = BmpManager::new_connected_for_test(
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

    /// Production mutation: starting every collector's Loc-RIB dump without
    /// checking its filter makes this test receive a request.
    /// A collector that does not monitor `loc_rib` gets neither the
    /// Loc-RIB Peer Up nor a dump request on connect.
    #[tokio::test]
    async fn non_loc_rib_collector_connect_skips_dump() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (dump_tx, mut dump_rx) = mpsc::channel(4);

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(
                collector_addr(0),
                BmpMonitorFilter::default(),
                BmpVersion::V3,
            )],
            BgpMetrics::new(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let handle = tokio::spawn(mgr.run());

        let (bootstrap, mut c_rx) = connect_collector(&control_tx, 0, collector_addr(0), 16).await;
        assert!(bootstrap.messages.is_empty());
        complete_bootstrap(&control_tx, 0, bootstrap.generation).await;

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

    /// Production mutation: treating `ReplyClosed` as completion flushes the
    /// buffered 0xCC row, while failing to clear suppression on reconnect
    /// prevents the later 0xDD row. Ordinary stats must survive both cases.
    #[tokio::test]
    async fn failed_dump_suppresses_loc_rib_until_reconnect_but_not_ordinary_views() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (dump_tx, mut dump_rx) = mpsc::channel(4);

        let metrics = BgpMetrics::new();
        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), loc_rib_filter(), BmpVersion::V3)],
            metrics.clone(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let handle = tokio::spawn(mgr.run());

        let (bootstrap1, mut c_rx1) =
            connect_collector(&control_tx, 0, collector_addr(0), 16).await;
        complete_bootstrap(&control_tx, 0, bootstrap1.generation).await;
        let request = dump_rx.recv().await.unwrap();
        event_tx
            .send(BmpEvent::LocRibRouteMonitoring {
                update_pdu: Bytes::from_static(&[0xCC; 23]),
                timestamp: UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
                path_status: None,
            })
            .await
            .unwrap();
        wait_until_received(&event_tx, 16).await;
        drop(request.reply);
        // One dropped dump stream plus one discarded held-back live message.
        let dump_drops = || {
            metric_value_with_labels(
                &metrics,
                "bmp_collector_drops_total",
                &[("phase", "loc_rib_dump"), ("reason", "reply_closed")],
            )
        };
        for _ in 0..40 {
            if dump_drops() == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(dump_drops(), 2);
        assert_live_buffer_gauges(&metrics, collector_addr(0), 0, 1);
        event_tx
            .send(BmpEvent::LocRibRouteMonitoring {
                update_pdu: Bytes::from_static(&[0xCF; 23]),
                timestamp: UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_001),
                path_status: None,
            })
            .await
            .unwrap();
        event_tx
            .send(BmpEvent::StatsReport {
                peer_info: sample_peer_info(),
                adj_rib_in_routes: 7,
                adj_rib_out_post: None,
            })
            .await
            .unwrap();
        assert_eq!(
            c_rx1.recv().await.unwrap()[5],
            1,
            "failed Loc-RIB stays suppressed while ordinary view continues"
        );

        let (bootstrap2, mut c_rx2) =
            connect_collector(&control_tx, 0, collector_addr(0), 16).await;
        assert_live_buffer_gauges(&metrics, collector_addr(0), 0, 0);
        complete_bootstrap(&control_tx, 0, bootstrap2.generation).await;
        let request = dump_rx.recv().await.unwrap();
        request
            .reply
            .send(crate::types::BmpDumpChunk {
                messages: vec![(
                    Bytes::from_static(&[0xE0; 23]),
                    UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000),
                    None,
                )],
                next: None,
            })
            .unwrap();
        event_tx
            .send(BmpEvent::LocRibRouteMonitoring {
                update_pdu: Bytes::from_static(&[0xDD; 23]),
                timestamp: UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_001),
                path_status: None,
            })
            .await
            .unwrap();
        assert_eq!(c_rx2.recv().await.unwrap()[48], 0xE0);
        assert_eq!(
            c_rx2.recv().await.unwrap()[48],
            0xDD,
            "reconnect heals suppression"
        );

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();
    }

    /// Production mutation: closing senders before queuing Peer Down, or
    /// emitting it for a generation without a bootstrap Peer Up, makes this
    /// test miss or spuriously receive the shutdown message.
    #[tokio::test]
    async fn shutdown_emits_loc_rib_peer_down_reason_6() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (dump_tx, _dump_rx) = mpsc::channel(4);

        let mgr = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), loc_rib_filter(), BmpVersion::V3)],
            BgpMetrics::new(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let handle = tokio::spawn(mgr.run());

        let (bootstrap, mut c_rx) = connect_collector(&control_tx, 0, collector_addr(0), 16).await;
        assert_eq!(bootstrap.messages[0][5], 3);
        complete_bootstrap(&control_tx, 0, bootstrap.generation).await;
        event_tx
            .send(BmpEvent::StatsReport {
                peer_info: sample_peer_info(),
                adj_rib_in_routes: 9,
                adj_rib_out_post: None,
            })
            .await
            .unwrap();
        control_tx.send(BmpControlEvent::Shutdown).await.unwrap();
        handle.await.unwrap();

        assert_eq!(
            c_rx.recv().await.unwrap()[5],
            1,
            "accepted event drains first"
        );
        let msg = c_rx.recv().await.unwrap();
        assert_eq!(msg[5], 2, "PeerDown message type");
        assert_eq!(msg[6], 3, "peer type 3");
        assert_eq!(msg[48], 6, "reason 6: local system closed, TLV follows");
        assert_eq!(&msg[msg.len() - 6..], b"global");
        assert!(c_rx.recv().await.is_none(), "sender closes after Peer Down");

        drop(event_tx);
    }

    /// Load-bearing proof: removing the await from dump cancellation queues
    /// Peer Down before the dump task's cancellation sentinel. That models a
    /// forwarder winning one last send after shutdown fencing.
    #[tokio::test]
    async fn shutdown_awaits_dump_cancellation_before_peer_down() {
        struct CancellationSentinel(mpsc::Sender<Bytes>);

        impl Drop for CancellationSentinel {
            fn drop(&mut self) {
                let _ = self.0.try_send(Bytes::from_static(b"dump-cancelled"));
            }
        }

        let (_event_tx, event_rx) = mpsc::channel(1);
        let (_control_tx, control_rx) = mpsc::channel(1);
        let (collector_tx, mut collector_rx) = mpsc::channel(16);
        let (dump_tx, _dump_rx) = mpsc::channel(1);
        let mut manager = BmpManager::new_connected_for_test(
            event_rx,
            control_rx,
            vec![(
                collector_addr(0),
                collector_tx.clone(),
                loc_rib_filter(),
                BmpVersion::V3,
            )],
            BgpMetrics::new(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _sentinel = CancellationSentinel(collector_tx);
            started_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();
        manager.active_dumps.insert(
            0,
            ActiveDump {
                generation: 1,
                task,
                buffered: Vec::new(),
            },
        );

        assert!(manager.handle_control(BmpControlEvent::Shutdown).await);
        assert_eq!(
            collector_rx.recv().await.unwrap(),
            Bytes::from_static(b"dump-cancelled"),
            "dump cancellation completes before Peer Down is queued"
        );
        assert_eq!(
            collector_rx.recv().await.unwrap()[5],
            2,
            "Loc-RIB Peer Down follows cancellation"
        );
    }

    /// Load-bearing proof: dropping an active dump task handle without
    /// aborting and awaiting it leaves both its RIB reply and collector sender
    /// alive after the manager exits on natural channel closure.
    #[tokio::test]
    async fn channel_close_cancels_active_dump_and_closes_generation() {
        let (event_tx, event_rx) = mpsc::channel(4);
        let (control_tx, control_rx) = mpsc::channel(4);
        let (dump_tx, mut dump_rx) = mpsc::channel(1);
        let manager = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), loc_rib_filter(), BmpVersion::V3)],
            BgpMetrics::new(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let handle = tokio::spawn(manager.run());
        let (bootstrap, mut collector_rx) =
            connect_collector(&control_tx, 0, collector_addr(0), 8).await;
        complete_bootstrap(&control_tx, 0, bootstrap.generation).await;
        let request = dump_rx.recv().await.unwrap();

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();

        assert!(
            request.reply.is_closed(),
            "manager exit left the dump reply receiver alive"
        );
        assert!(
            collector_rx.recv().await.is_none(),
            "detached dump retained the generation sender"
        );
    }

    /// Production mutation: restoring the `len < CAP` drop-newest branch
    /// leaves the generation connected and records one drop instead of all
    /// CAP+1 rows invalidated by the now-incomplete TCP session.
    #[tokio::test]
    async fn bootstrap_live_buffer_overflow_closes_generation_and_counts_all_rows() {
        let (_event_tx, event_rx) = mpsc::channel(1);
        let (_control_tx, control_rx) = mpsc::channel(1);
        let (dump_tx, _dump_rx) = mpsc::channel(1);
        let metrics = BgpMetrics::new();
        let mut manager = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), loc_rib_filter(), BmpVersion::V3)],
            metrics.clone(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let (sender, mut receiver) = mpsc::channel(1);
        manager.collectors[0].generation.store(7, Ordering::SeqCst);
        manager.collectors[0].phase = CollectorPhase::BootstrapPending {
            generation: 7,
            sender,
            loc_rib_peer_up: true,
            loc_rib_buffer: vec![Bytes::new(); LOC_RIB_DUMP_LIVE_BUFFER_CAP],
            started_at: std::time::SystemTime::now(),
        };
        assert_eq!(manager.collectors[0].phase.generation(), Some(7));
        assert!(!receiver.is_closed(), "CAP rows keep the generation live");

        manager
            .handle_event(&BmpEvent::LocRibStats { per_family: vec![] })
            .await;

        assert!(matches!(
            manager.collectors[0].phase,
            CollectorPhase::Disconnected
        ));
        assert!(receiver.recv().await.is_none(), "CAP+1 closes the sender");
        assert_eq!(
            metric_value_with_labels(
                &metrics,
                "bmp_collector_drops_total",
                &[
                    ("collector", &collector_addr(0).to_string()),
                    ("phase", "loc_rib_dump"),
                    ("reason", "live_buffer_full"),
                ],
            ),
            (LOC_RIB_DUMP_LIVE_BUFFER_CAP + 1) as u64
        );
        assert_live_buffer_gauges(&metrics, collector_addr(0), 0, 8193);
        assert_eq!(LOC_RIB_DUMP_LIVE_BUFFER_CAP, 8192);
    }

    /// Production mutations: awaiting one task before fencing collector 1
    /// makes the first sentinel report false; omitting abort-or-await leaves a
    /// sentinel/reply live; fencing all collectors closes the unaffected third.
    #[expect(
        clippy::too_many_lines,
        reason = "one fixture proves fencing, cancellation, accounting, and isolation"
    )]
    #[tokio::test]
    async fn active_dump_overflow_fences_all_then_awaits_with_isolation() {
        struct FenceSentinel {
            other: Arc<AtomicU64>,
            result: Option<tokio::sync::oneshot::Sender<bool>>,
        }
        impl Drop for FenceSentinel {
            fn drop(&mut self) {
                let _ = self
                    .result
                    .take()
                    .unwrap()
                    .send(self.other.load(Ordering::SeqCst) != 9);
            }
        }

        let (_event_tx, event_rx) = mpsc::channel(1);
        let (_control_tx, control_rx) = mpsc::channel(1);
        let (dump_tx, _dump_rx) = mpsc::channel(1);
        let metrics = BgpMetrics::new();
        let mut manager = BmpManager::new(
            event_rx,
            control_rx,
            (0..3)
                .map(|id| (collector_addr(id), loc_rib_filter(), BmpVersion::V3))
                .collect(),
            metrics.clone(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let mut receivers = Vec::new();
        let mut task_senders = Vec::new();
        for collector in &mut manager.collectors {
            let (sender, receiver) = mpsc::channel(1);
            task_senders.push(sender.clone());
            collector.generation.store(9, Ordering::SeqCst);
            collector.phase = CollectorPhase::Active {
                generation: 9,
                sender,
                loc_rib_peer_up: true,
            };
            receivers.push(receiver);
        }
        let other = Arc::clone(&manager.collectors[1].generation);
        let (fenced_tx, fenced_rx) = tokio::sync::oneshot::channel();
        let held0 = task_senders.remove(0);
        let task0 = tokio::spawn(async move {
            let _held = held0;
            let _sentinel = FenceSentinel {
                other,
                result: Some(fenced_tx),
            };
            std::future::pending::<()>().await;
        });
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel::<()>();
        let held1 = task_senders.remove(0);
        let task1 = tokio::spawn(async move {
            let _held = held1;
            let _ = reply_rx.await;
        });
        tokio::task::yield_now().await;
        manager.active_dumps.insert(
            0,
            ActiveDump {
                generation: 9,
                task: task0,
                buffered: vec![Bytes::new(); LOC_RIB_DUMP_LIVE_BUFFER_CAP],
            },
        );
        manager.active_dumps.insert(
            1,
            ActiveDump {
                generation: 9,
                task: task1,
                buffered: vec![Bytes::new(); LOC_RIB_DUMP_LIVE_BUFFER_CAP],
            },
        );

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            manager.handle_event(&BmpEvent::LocRibStats { per_family: vec![] }),
        )
        .await
        .expect("overflow handler did not abort and await every dump");

        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), fenced_rx)
                .await
                .expect("cancellation sentinel was not dropped")
                .unwrap(),
            "all generations fence before await"
        );
        assert!(reply_tx.is_closed(), "dump reply closed before resume");
        assert!(!manager.active_dumps.contains_key(&0));
        assert!(!manager.active_dumps.contains_key(&1));
        assert!(matches!(
            manager.collectors[0].phase,
            CollectorPhase::Disconnected
        ));
        assert!(matches!(
            manager.collectors[1].phase,
            CollectorPhase::Disconnected
        ));
        assert_eq!(manager.collectors[2].phase.generation(), Some(9));
        for receiver in &mut receivers[..2] {
            assert!(
                tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
                    .await
                    .expect("affected generation sender remained live")
                    .is_none()
            );
        }
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), receivers[2].recv())
                .await
                .expect("unaffected collector stopped receiving")
                .unwrap()[5],
            1,
            "third stays live"
        );
        for id in 0..2 {
            assert_eq!(
                metric_value_with_labels(
                    &metrics,
                    "bmp_collector_drops_total",
                    &[
                        ("collector", &collector_addr(id).to_string()),
                        ("reason", "live_buffer_full"),
                    ],
                ),
                (LOC_RIB_DUMP_LIVE_BUFFER_CAP + 1) as u64
            );
        }
    }

    /// Production mutation: omitting the `ActiveDump` generation comparison
    /// lets an overflow left by generation 4 fence its generation 5 replacement.
    #[tokio::test]
    async fn stale_active_dump_overflow_cannot_fence_replacement() {
        let (_event_tx, event_rx) = mpsc::channel(1);
        let (_control_tx, control_rx) = mpsc::channel(1);
        let (dump_tx, _dump_rx) = mpsc::channel(1);
        let mut manager = BmpManager::new(
            event_rx,
            control_rx,
            vec![(collector_addr(0), loc_rib_filter(), BmpVersion::V3)],
            BgpMetrics::new(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        let (sender, receiver) = mpsc::channel(1);
        manager.collectors[0].generation.store(5, Ordering::SeqCst);
        manager.collectors[0].phase = CollectorPhase::Active {
            generation: 5,
            sender,
            loc_rib_peer_up: true,
        };
        manager.active_dumps.insert(
            0,
            ActiveDump {
                generation: 4,
                task: tokio::spawn(std::future::pending()),
                buffered: vec![Bytes::new(); LOC_RIB_DUMP_LIVE_BUFFER_CAP],
            },
        );

        manager
            .handle_event(&BmpEvent::LocRibStats { per_family: vec![] })
            .await;

        assert_eq!(manager.collectors[0].phase.generation(), Some(5));
        assert!(!receiver.is_closed(), "replacement remains connected");
        manager.active_dumps.remove(&0).unwrap().task.abort();
    }

    /// Load-bearing proof that the post-dump flush awaits collector-channel
    /// capacity: the held-back buffer exceeds the channel and churn keeps
    /// arriving while nothing drains, so a `try_send` flush cannot deliver.
    /// Every message must arrive, held-back before churn, with zero drops.
    #[tokio::test]
    async fn post_dump_flush_with_concurrent_churn_delivers_everything() {
        const HELD: usize = 64;
        const CHURN: usize = 64;
        // Far smaller than HELD so the flush burst can never fit at once.
        const CHANNEL: usize = 8;

        let (event_tx, event_rx) = mpsc::channel(CHURN);
        let (control_tx, control_rx) = mpsc::channel(1);
        let (dump_tx, _dump_rx) = mpsc::channel(1);
        let (collector_tx, mut collector_rx) = mpsc::channel::<Bytes>(CHANNEL);
        let metrics = BgpMetrics::new();
        let addr = collector_addr(0);
        let mut manager = BmpManager::new_connected_for_test(
            event_rx,
            control_rx,
            vec![(addr, collector_tx, loc_rib_filter(), BmpVersion::V3)],
            metrics.clone(),
        )
        .with_loc_rib(loc_rib_config(), dump_tx);
        manager.active_dumps.insert(
            0,
            ActiveDump {
                generation: 1,
                task: tokio::spawn(async {}),
                buffered: vec![Bytes::from_static(b"held"); HELD],
            },
        );
        let done_tx = manager.dump_done_tx.clone();
        let handle = tokio::spawn(manager.run());

        done_tx
            .send(DumpDone {
                collector_id: 0,
                generation: 1,
                outcome: DumpOutcome::Complete,
            })
            .await
            .unwrap();
        // Concurrent churn: accepted by the manager while the flush is
        // still blocked on the full channel (nothing drains yet).
        for _ in 0..CHURN {
            event_tx
                .send(BmpEvent::LocRibStats { per_family: vec![] })
                .await
                .unwrap();
        }
        wait_until_received(&event_tx, CHURN).await;

        let drops = |phase: &str| {
            metric_value_with_labels(
                &metrics,
                "bmp_collector_drops_total",
                &[("collector", &addr.to_string()), ("phase", phase)],
            )
        };
        let total = HELD + CHURN;
        let mut held_seen = 0_usize;
        let mut churn_seen = 0_usize;
        for _ in 0..total {
            let Ok(Some(msg)) =
                tokio::time::timeout(std::time::Duration::from_secs(10), collector_rx.recv()).await
            else {
                panic!(
                    "delivery stalled after {} of {total} messages \
                     (drops: loc_rib_dump={}, fan_out={})",
                    held_seen + churn_seen,
                    drops("loc_rib_dump"),
                    drops("fan_out"),
                )
            };
            if msg == Bytes::from_static(b"held") {
                assert_eq!(churn_seen, 0, "held-back message delivered after churn");
                held_seen += 1;
            } else {
                churn_seen += 1;
            }
        }
        assert_eq!(held_seen, HELD);
        assert_eq!(churn_seen, CHURN);
        assert_eq!(drops("loc_rib_dump"), 0);
        assert_eq!(drops("fan_out"), 0);

        drop(event_tx);
        drop(control_tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn manager_exits_on_explicit_shutdown() {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        let (c_tx, _c_rx) = mpsc::channel(16);

        let mgr = BmpManager::new_connected_for_test(
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
