//! EHM-backed implementations of the RIB / peer-manager event sinks
//! (ADR-0072 PR5).
//!
//! `crates/rib` defines [`rustbgpd_rib::RibEventSink`] as an
//! object-safe trait so the producer-side hot path stays free of any
//! proto / event-history dependency cycle. The binary plugs in a
//! concrete implementation that owns:
//!
//! - a bounded snapshot channel into the off-actor conversion stage,
//! - the cloneable [`EventHistoryHandle`] (`try_send` + degraded state),
//! - the proto-conversion helpers from `crate::event_service::convert`,
//! - the workspace [`BgpMetrics`] for drop counters.
//!
//! The RIB sink's on-actor publish is clone + producer timestamp +
//! bounded `try_send` of the owned event snapshot. Proto conversion,
//! prost encoding, and envelope string construction run in the
//! conversion stage task spawned by [`make_rib_event_sink`], which
//! forwards finished envelopes into EHM. One FIFO channel from the
//! single RIB-actor producer preserves publish order; cursor IDs stay
//! EHM-assigned at commit.
//!
//! All publishes are non-blocking. On a full or closed queue, the sink increments
//! `bgp_event_outbox_dropped_total{category, reason=…}` and flips
//! the degraded gauge for queue-full drops.
//!
//! See `docs/adr/0072-durable-event-history.md` for the contract
//! split: producer `try_send` is **not** a durability claim. EHM
//! itself increments `bgp_event_outbox_committed_total` after the
//! `SQLite` transaction commits. This module never touches that
//! metric.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message;
use rustbgpd_event_history::{
    Category, EhmState, EnvelopePeers, EventEnvelope, EventHistoryHandle, PayloadCodec, Severity,
};
use rustbgpd_rib::{EvpnRouteEvent, RibEventSink, RouteEvent};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::{OtcRouteBlockedEvent, TransportEventSink};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::warn;

use crate::event_service::convert;
use crate::proto;

/// One RIB event captured on the RIB actor at publish time, before any
/// proto conversion. `timestamp_ns` is stamped at publish so envelope
/// timestamps stay producer-side; route events additionally carry
/// their already-assigned process-local `event_id` inside the event
/// itself. No proto message, payload bytes, or envelope strings cross
/// this channel.
#[allow(
    clippy::large_enum_variant,
    reason = "the EVPN variant is several hundred bytes larger than the route \
              variant, but boxing it would put a heap allocation back on the \
              RIB actor's publish path — the exact cost this offload removes — \
              so the enum stays by-value"
)]
enum RibEventSnapshot {
    Route {
        event: RouteEvent,
        timestamp_ns: i64,
    },
    Evpn {
        event: EvpnRouteEvent,
        timestamp_ns: i64,
    },
}

impl RibEventSnapshot {
    const fn category(&self) -> Category {
        match self {
            Self::Route { .. } => Category::Route,
            Self::Evpn { .. } => Category::Evpn,
        }
    }
}

/// Concrete sink installed on the RIB actor. Publish is a clone, a
/// timestamp stamp, and a bounded `try_send`; proto conversion, prost
/// encoding, and envelope string construction all run off-actor in
/// the conversion stage spawned by [`make_rib_event_sink`].
struct EhmRibSink {
    snapshot_tx: mpsc::Sender<RibEventSnapshot>,
    state: Arc<EhmState>,
    metrics: BgpMetrics,
}

impl EhmRibSink {
    fn enqueue(&self, snapshot: RibEventSnapshot) {
        let category = snapshot.category();
        match self.snapshot_tx.try_send(snapshot) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.metrics
                    .record_event_outbox_drop(category.as_str(), "queue_full");
                self.metrics.mark_event_outbox_degraded();
                self.state.flip_degraded();
                warn!(
                    category = category.as_str(),
                    "event outbox producer queue full; dropping event"
                );
            }
            Err(TrySendError::Closed(_)) => {
                // Conversion stage exited (shutdown in progress, or
                // post-shutdown). Don't flip degraded — this is the
                // expected late-publish race during daemon teardown.
                self.metrics
                    .record_event_outbox_drop(category.as_str(), "closed");
            }
        }
    }
}

impl RibEventSink for EhmRibSink {
    fn publish_route_event(&self, event: &RouteEvent) {
        self.enqueue(RibEventSnapshot::Route {
            event: event.clone(),
            timestamp_ns: timestamp_ns_now(),
        });
    }

    fn publish_evpn_event(&self, event: &EvpnRouteEvent) {
        self.enqueue(RibEventSnapshot::Evpn {
            event: event.clone(),
            timestamp_ns: timestamp_ns_now(),
        });
    }
}

/// Handle for the off-actor conversion stage spawned by
/// [`make_rib_event_sink`].
///
/// The binary shuts this down BEFORE
/// [`rustbgpd_event_history::EventHistoryManager::shutdown`] so
/// snapshots accepted before shutdown are converted and forwarded in
/// time for EHM's own drain-then-commit shutdown.
pub struct RibEventConversionStage {
    shutdown_tx: watch::Sender<bool>,
    join: JoinHandle<()>,
}

impl RibEventConversionStage {
    /// Signal the stage, drain its inbound snapshot queue into EHM,
    /// and wait for the task to exit. Publishes arriving after the
    /// drain see `TrySendError::Closed` on the snapshot channel — the
    /// same teardown semantics the direct EHM enqueue had before the
    /// offload.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.join.await;
    }
}

async fn run_conversion_stage(
    mut rx: mpsc::Receiver<RibEventSnapshot>,
    mut shutdown_rx: watch::Receiver<bool>,
    handle: EventHistoryHandle,
    metrics: BgpMetrics,
) {
    loop {
        tokio::select! {
            maybe = rx.recv() => match maybe {
                Some(snapshot) => convert_and_forward(&handle, &metrics, snapshot),
                // Every sink clone dropped — nothing left to drain.
                None => return,
            },
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }
    // Shutdown: close the channel so late publishes take the `Closed`
    // path, then drain snapshots accepted before the signal so they
    // still reach EHM's drain-then-commit shutdown.
    rx.close();
    while let Ok(snapshot) = rx.try_recv() {
        convert_and_forward(&handle, &metrics, snapshot);
    }
}

fn convert_and_forward(
    handle: &EventHistoryHandle,
    metrics: &BgpMetrics,
    snapshot: RibEventSnapshot,
) {
    let envelope = match snapshot {
        RibEventSnapshot::Route {
            event,
            timestamp_ns,
        } => route_event_envelope(event, timestamp_ns),
        RibEventSnapshot::Evpn {
            event,
            timestamp_ns,
        } => evpn_event_envelope(event, timestamp_ns),
    };
    try_send_envelope(handle, metrics, envelope);
}

/// Build the durable envelope for a route event. Pure function of the
/// event and the producer-captured `timestamp_ns`, so payload bytes
/// are identical to the pre-offload on-actor conversion (pinned by
/// `snapshot_envelopes_match_direct_conversion`).
fn route_event_envelope(event: RouteEvent, timestamp_ns: i64) -> EventEnvelope {
    let peers = EnvelopePeers {
        peer: event.peer,
        previous_peer: event.previous_peer,
        target_peer: event.target_peer,
    };
    let proto_event = convert::route_event_to_bgp_event(event);
    EventEnvelope {
        timestamp_ns,
        category: Category::Route,
        event_type: event_type_label(&proto_event),
        peers,
        afi_safi: afi_safi_label(proto_event.afi_safi),
        prefix: prefix_with_length(&proto_event),
        rd: None,
        evpn_route_type: None,
        severity: Severity::Info,
        payload_codec: PayloadCodec::Proto,
        payload: proto_event.encode_to_vec(),
    }
}

/// Build the durable envelope for an EVPN best-path event. Same purity
/// contract as [`route_event_envelope`].
fn evpn_event_envelope(event: EvpnRouteEvent, timestamp_ns: i64) -> EventEnvelope {
    let peers = EnvelopePeers {
        peer: event.peer,
        previous_peer: event.previous_peer,
        target_peer: None,
    };
    let rd = rustbgpd_rib::event::evpn_key_rd(&event.key).to_string();
    let evpn_route_type = Some(i32::from(event.key.route_type()));
    let proto_event = convert::evpn_event_to_bgp_event(event);
    EventEnvelope {
        timestamp_ns,
        category: Category::Evpn,
        event_type: event_type_label(&proto_event),
        peers,
        afi_safi: None,
        prefix: None,
        rd: Some(rd),
        evpn_route_type,
        severity: Severity::Info,
        payload_codec: PayloadCodec::Proto,
        payload: proto_event.encode_to_vec(),
    }
}

/// Construct an EHM-backed RIB event sink for installation on
/// `RibManager` via [`rustbgpd_rib::manager::RibManager::with_event_sink`],
/// plus its off-actor conversion stage.
///
/// The sink's publish path runs synchronously on the RIB actor and is
/// deliberately minimal: clone the event, stamp `timestamp_ns`,
/// bounded `try_send`. Proto conversion, prost encoding, and envelope
/// construction run in the returned stage's task, in publish order
/// (single producer, one FIFO channel). The snapshot channel is sized
/// to the EHM producer queue so the operator's `queue_capacity`
/// governs both seams; overload sheds work before conversion instead
/// of after.
///
/// Must be called from within a tokio runtime (spawns the stage task).
/// The returned `Arc<dyn RibEventSink>` is `Clone` and `Send + Sync`.
/// [`RibEventConversionStage::shutdown`] must run before EHM shutdown
/// so events accepted before shutdown still commit.
#[must_use]
pub fn make_rib_event_sink(
    handle: EventHistoryHandle,
    metrics: BgpMetrics,
) -> (Arc<dyn RibEventSink>, RibEventConversionStage) {
    let capacity = handle.sender().max_capacity();
    let (snapshot_tx, snapshot_rx) = mpsc::channel(capacity);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let state = handle.state().clone();
    let join = tokio::spawn(run_conversion_stage(
        snapshot_rx,
        shutdown_rx,
        handle,
        metrics.clone(),
    ));
    (
        Arc::new(EhmRibSink {
            snapshot_tx,
            state,
            metrics,
        }),
        RibEventConversionStage { shutdown_tx, join },
    )
}

/// Concrete sink that encodes transport-layer OTC decisions to proto
/// and enqueues them into the local event outbox under
/// [`Category::Policy`].
struct EhmTransportSink {
    handle: EventHistoryHandle,
    metrics: BgpMetrics,
}

impl TransportEventSink for EhmTransportSink {
    fn publish_otc_route_blocked(&self, event: &OtcRouteBlockedEvent) {
        let proto_event = convert::otc_route_blocked_event_to_bgp_event(event);
        let envelope =
            envelope_from_bgp_event(&proto_event, Category::Policy, Some(event.peer), None);
        try_send_envelope(&self.handle, &self.metrics, envelope);
    }
}

/// Construct an EHM-backed transport event sink for installation on
/// `PeerManager` via the binary's wiring layer. The returned
/// `Arc<dyn TransportEventSink>` is `Clone` and `Send + Sync`.
///
/// All publishes are non-blocking and category-tagged `policy` — the
/// OTC route-leak rule is policy enforcement at session ingress /
/// egress (ADR-0071), so it shares the existing policy storage
/// bucket and authz tier rather than requiring a fresh category.
#[must_use]
pub fn make_transport_event_sink(
    handle: EventHistoryHandle,
    metrics: BgpMetrics,
) -> Arc<dyn TransportEventSink> {
    Arc::new(EhmTransportSink { handle, metrics })
}

/// Build an [`EventEnvelope`] from a fully-formed proto [`proto::BgpEvent`]
/// payload. Used by the peer-manager and BFD bridge wiring, where
/// the producer already constructs the proto event itself (vs. RIB
/// which uses `convert::*` helpers).
///
/// `category` and `event_type_for_label` carry the operator-facing
/// metric labels; the byte payload is the prost-encoded `BgpEvent`
/// (codec `Proto`).
#[must_use]
pub fn envelope_from_bgp_event(
    proto_event: &proto::BgpEvent,
    category: Category,
    peer: Option<std::net::IpAddr>,
    previous_peer: Option<std::net::IpAddr>,
) -> EventEnvelope {
    EventEnvelope {
        timestamp_ns: timestamp_ns_now(),
        category,
        event_type: event_type_label(proto_event),
        peers: EnvelopePeers {
            peer,
            previous_peer,
            target_peer: None,
        },
        afi_safi: afi_safi_label(proto_event.afi_safi),
        prefix: prefix_with_length(proto_event),
        rd: None,
        evpn_route_type: None,
        severity: Severity::Info,
        payload_codec: PayloadCodec::Proto,
        payload: proto_event.encode_to_vec(),
    }
}

/// Record that an upstream broadcast source lost `missed` events
/// before a durable producer could enqueue them. Today this is
/// called from the FIB and BFD bridges when `fib_events.recv()` or
/// `bfd_events.recv()` returns `RecvError::Lagged(missed)` — those
/// missed events never reach the bridge body and therefore never
/// reach EHM. Mirrors the bookkeeping the queue-full path in
/// `try_send_envelope` does: the bounded drop counter, the
/// Prometheus degraded gauge, AND EHM's in-process degraded state
/// are all flipped, so a health probe reading either signal sees
/// the degradation. The previous draft of this PR set only the
/// Prometheus side, which left
/// `EventHistoryHandle::state().degraded()` reading `false` even
/// after a real durable-cursor gap.
pub fn record_source_lag(
    handle: &EventHistoryHandle,
    metrics: &BgpMetrics,
    category: &str,
    missed: u64,
) {
    metrics.record_event_outbox_drops_by(category, "source_lagged", missed);
    metrics.mark_event_outbox_degraded();
    handle.state().flip_degraded();
}

/// Try-send convenience for producers that already have a built
/// envelope. Increments the matching drop metric on failure.
pub fn try_send_envelope(
    handle: &EventHistoryHandle,
    metrics: &BgpMetrics,
    envelope: EventEnvelope,
) {
    let category = envelope.category;
    match handle.sender().try_send(envelope) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            metrics.record_event_outbox_drop(category.as_str(), "queue_full");
            metrics.mark_event_outbox_degraded();
            handle.state().flip_degraded();
            warn!(
                category = category.as_str(),
                "event outbox producer queue full; dropping event"
            );
        }
        Err(TrySendError::Closed(_)) => {
            metrics.record_event_outbox_drop(category.as_str(), "closed");
        }
    }
}

fn timestamp_ns_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_nanos()).ok())
        .unwrap_or(0)
}

fn event_type_label(e: &proto::BgpEvent) -> String {
    // Use the well-known proto enum name when we can; falls back to
    // the integer for unknown values (forward-compat).
    proto::BgpEventType::try_from(e.event_type).map_or_else(
        |_| format!("type_{}", e.event_type),
        |t| t.as_str_name().to_string(),
    )
}

/// Map the proto [`proto::AddressFamily`] enum into the operator-
/// facing string the durable outbox stores in `afi_safi`. Returns
/// `None` for the unspecified value so `EventEnvelope.afi_safi`
/// stays absent rather than carrying `"unspecified"`.
fn afi_safi_label(v: i32) -> Option<String> {
    match proto::AddressFamily::try_from(v).ok()? {
        proto::AddressFamily::Unspecified => None,
        af => Some(af.as_str_name().to_lowercase()),
    }
}

fn prefix_with_length(e: &proto::BgpEvent) -> Option<String> {
    if e.prefix.is_empty() {
        None
    } else {
        Some(format!("{}/{}", e.prefix, e.prefix_length))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Encoder as _;
    use rustbgpd_event_history::{EventHistoryConfig, EventHistoryManager, SynchronousMode};
    use rustbgpd_rib::{EvpnRibRoute, RouteEventType, RouteOrigin};
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, Ipv4Prefix, MacAddress,
        MplsLabel, Prefix, RouteDistinguisher,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    fn sample_route_event(event_type: RouteEventType, path_id: u32) -> RouteEvent {
        let policy_filtered = event_type == RouteEventType::PolicyFiltered;
        RouteEvent {
            event_id: 41,
            event_type,
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24)),
            peer: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            previous_peer: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3))),
            target_peer: policy_filtered.then_some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254))),
            timestamp: "1783915200".to_string(),
            path_id,
            reason: if policy_filtered {
                "policy_denied".to_string()
            } else {
                String::new()
            },
        }
    }

    fn sample_evpn_event() -> EvpnRouteEvent {
        let peer = Ipv4Addr::new(192, 0, 2, 2);
        let best = EvpnRibRoute {
            route: EvpnRoute::MacIp(EvpnMacIp {
                rd: RouteDistinguisher::new([0, 0, 0xfd, 0xe8, 0, 0, 0, 7]),
                esi: EthernetSegmentIdentifier::ZERO,
                ethernet_tag: EthernetTagId(100),
                mac: MacAddress::new([0x02, 0, 0, 0, 0, 7]),
                ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))),
                label1: MplsLabel::new(10_007),
                label2: None,
            }),
            next_hop: IpAddr::V4(peer),
            link_local_next_hop: None,
            peer: IpAddr::V4(peer),
            attributes: Arc::new(Vec::new()),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ibgp,
            peer_router_id: peer,
            is_stale: false,
            is_llgr_stale: false,
        };
        EvpnRouteEvent {
            event_type: RouteEventType::Added,
            key: best.key(),
            best: Some(best),
            previous_best: None,
            peer: Some(IpAddr::V4(peer)),
            previous_peer: None,
            timestamp: "1783915200".to_string(),
        }
    }

    fn small_ehm_config(dir: &tempfile::TempDir, metrics: &BgpMetrics) -> EventHistoryConfig {
        EventHistoryConfig {
            path: dir.path().join("events.db"),
            max_events: 10_000,
            max_bytes: 100_000_000,
            synchronous: SynchronousMode::Full,
            required: true,
            queue_capacity: 256,
            batch_size: 1,
            batch_interval: Duration::from_millis(5),
            broadcast_capacity: 256,
            retention_interval: Duration::from_mins(1),
            sidecar_flush_interval_batches: 100,
            metrics: Some(metrics.clone()),
        }
    }

    fn drop_counter(metrics: &BgpMetrics, category: &str, reason: &str) -> u64 {
        let encoder = prometheus::TextEncoder::new();
        let mut out = Vec::new();
        encoder
            .encode(&metrics.registry().gather(), &mut out)
            .expect("encode metrics");
        let needle = format!(
            "bgp_event_outbox_dropped_total{{category=\"{category}\",reason=\"{reason}\"}}"
        );
        String::from_utf8(out)
            .expect("metrics text is UTF-8")
            .lines()
            .find_map(|line| line.strip_prefix(&needle))
            .map_or(0, |value| {
                value.trim().parse().expect("drop counter is integral")
            })
    }

    /// Payload-byte stability pin (LAN-393): the off-actor envelope
    /// builders must produce byte-identical prost payloads and
    /// identical envelope fields to constructing them directly from
    /// the `convert` helpers, for every route-event shape and for
    /// EVPN. `timestamp_ns` must pass through unchanged.
    #[test]
    fn snapshot_envelopes_match_direct_conversion() {
        let ts = 1_234_567_890_123_456_789_i64;
        for event_type in [
            RouteEventType::Added,
            RouteEventType::Withdrawn,
            RouteEventType::BestChanged,
            RouteEventType::PolicyFiltered,
        ] {
            let event = sample_route_event(event_type, 9);
            let envelope = route_event_envelope(event.clone(), ts);
            let proto_event = convert::route_event_to_bgp_event(event.clone());
            assert_eq!(envelope.payload, proto_event.encode_to_vec());
            assert_eq!(envelope.timestamp_ns, ts);
            assert_eq!(envelope.category, Category::Route);
            assert_eq!(envelope.event_type, event_type_label(&proto_event));
            assert_eq!(envelope.afi_safi, afi_safi_label(proto_event.afi_safi));
            assert_eq!(envelope.prefix, prefix_with_length(&proto_event));
            assert_eq!(envelope.peers.peer, event.peer);
            assert_eq!(envelope.peers.previous_peer, event.previous_peer);
            assert_eq!(envelope.peers.target_peer, event.target_peer);
            assert_eq!(envelope.rd, None);
            assert_eq!(envelope.evpn_route_type, None);
            assert_eq!(envelope.payload_codec, PayloadCodec::Proto);
        }

        let event = sample_evpn_event();
        let envelope = evpn_event_envelope(event.clone(), ts);
        let proto_event = convert::evpn_event_to_bgp_event(event.clone());
        assert_eq!(envelope.payload, proto_event.encode_to_vec());
        assert_eq!(envelope.timestamp_ns, ts);
        assert_eq!(envelope.category, Category::Evpn);
        assert_eq!(envelope.event_type, event_type_label(&proto_event));
        assert_eq!(envelope.afi_safi, None);
        assert_eq!(envelope.prefix, None);
        assert_eq!(envelope.peers.peer, event.peer);
        assert_eq!(envelope.peers.previous_peer, event.previous_peer);
        assert_eq!(envelope.peers.target_peer, None);
        assert_eq!(
            envelope.rd,
            Some(rustbgpd_rib::event::evpn_key_rd(&event.key).to_string())
        );
        assert_eq!(
            envelope.evpn_route_type,
            Some(i32::from(event.key.route_type()))
        );
    }

    /// Order + cursor-contiguity pin: events published through the
    /// offloaded sink commit in publish order (route and EVPN
    /// interleaved on the one snapshot channel) with contiguous
    /// EHM-assigned cursor IDs and unchanged payload bytes.
    #[tokio::test]
    async fn offloaded_sink_preserves_order_and_cursor_contiguity() {
        let dir = tempfile::tempdir().unwrap();
        let metrics = BgpMetrics::new();
        let manager = EventHistoryManager::start(small_ehm_config(&dir, &metrics))
            .await
            .expect("EHM start");
        let handle = manager.handle();
        let mut committed_rx = handle.subscribe_live();
        let (sink, stage) = make_rib_event_sink(handle.clone(), metrics.clone());

        let mut expected_payloads = Vec::new();
        let before_ns = timestamp_ns_now();
        for index in 0..8u32 {
            let event = sample_route_event(RouteEventType::Added, index);
            expected_payloads
                .push(convert::route_event_to_bgp_event(event.clone()).encode_to_vec());
            sink.publish_route_event(&event);
            if index == 3 {
                let evpn = sample_evpn_event();
                expected_payloads
                    .push(convert::evpn_event_to_bgp_event(evpn.clone()).encode_to_vec());
                sink.publish_evpn_event(&evpn);
            }
        }
        let after_ns = timestamp_ns_now();

        for (index, expected_payload) in expected_payloads.iter().enumerate() {
            let committed = tokio::time::timeout(Duration::from_secs(5), committed_rx.recv())
                .await
                .expect("commit within 5s")
                .expect("broadcast open");
            assert_eq!(
                committed.event_id,
                u64::try_from(index).unwrap() + 1,
                "cursor IDs must stay contiguous and EHM-assigned"
            );
            assert_eq!(
                &committed.envelope.payload, expected_payload,
                "publish order and payload bytes must be preserved"
            );
            assert!(
                committed.envelope.timestamp_ns >= before_ns
                    && committed.envelope.timestamp_ns <= after_ns,
                "timestamp_ns must come from the publish window"
            );
        }

        assert!(!handle.state().degraded());
        stage.shutdown().await;
        manager.shutdown().await;
    }

    /// Producer-timestamp pin, deterministic form: stamp at publish,
    /// then start the conversion stage 150ms later. The committed
    /// envelope timestamp must fall inside the publish window, not
    /// the conversion window.
    #[tokio::test]
    async fn timestamps_are_captured_at_publish_not_conversion() {
        let dir = tempfile::tempdir().unwrap();
        let metrics = BgpMetrics::new();
        let manager = EventHistoryManager::start(small_ehm_config(&dir, &metrics))
            .await
            .expect("EHM start");
        let handle = manager.handle();
        let mut committed_rx = handle.subscribe_live();

        let (snapshot_tx, snapshot_rx) = mpsc::channel(8);
        let sink = EhmRibSink {
            snapshot_tx,
            state: handle.state().clone(),
            metrics: metrics.clone(),
        };
        let before_ns = timestamp_ns_now();
        sink.publish_route_event(&sample_route_event(RouteEventType::Added, 0));
        let after_ns = timestamp_ns_now();

        tokio::time::sleep(Duration::from_millis(150)).await;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let join = tokio::spawn(run_conversion_stage(
            snapshot_rx,
            shutdown_rx,
            handle.clone(),
            metrics.clone(),
        ));

        let committed = tokio::time::timeout(Duration::from_secs(5), committed_rx.recv())
            .await
            .expect("commit within 5s")
            .expect("broadcast open");
        assert!(
            committed.envelope.timestamp_ns >= before_ns
                && committed.envelope.timestamp_ns <= after_ns,
            "timestamp_ns {} outside publish window [{before_ns}, {after_ns}]; \
             it must be captured at publish, not at conversion",
            committed.envelope.timestamp_ns
        );

        let _ = shutdown_tx.send(true);
        let _ = join.await;
        manager.shutdown().await;
    }

    /// Queue-full pin: a full snapshot channel drops with the same
    /// counters and degraded flips the direct EHM enqueue had.
    #[test]
    fn snapshot_queue_full_drops_and_degrades() {
        let state = Arc::new(EhmState::default());
        let metrics = BgpMetrics::new();
        let (snapshot_tx, _snapshot_rx) = mpsc::channel(1);
        let sink = EhmRibSink {
            snapshot_tx,
            state: state.clone(),
            metrics: metrics.clone(),
        };

        sink.publish_route_event(&sample_route_event(RouteEventType::Added, 0));
        assert!(!state.degraded(), "accepted publish must not degrade");
        assert_eq!(drop_counter(&metrics, "route", "queue_full"), 0);

        sink.publish_route_event(&sample_route_event(RouteEventType::Added, 1));
        assert!(state.degraded(), "queue-full drop must flip EHM state");
        assert!(
            metrics.event_outbox_degraded(),
            "queue-full drop must flip the Prometheus gauge"
        );
        assert_eq!(drop_counter(&metrics, "route", "queue_full"), 1);
    }

    /// Closed pin: a closed snapshot channel (teardown) records the
    /// drop under `closed` WITHOUT flipping degraded — same as the
    /// pre-offload late-publish race against EHM shutdown.
    #[test]
    fn snapshot_channel_closed_records_drop_without_degraded() {
        let state = Arc::new(EhmState::default());
        let metrics = BgpMetrics::new();
        let (snapshot_tx, snapshot_rx) = mpsc::channel(1);
        drop(snapshot_rx);
        let sink = EhmRibSink {
            snapshot_tx,
            state: state.clone(),
            metrics: metrics.clone(),
        };

        sink.publish_evpn_event(&sample_evpn_event());
        assert!(!state.degraded(), "closed drop must not flip EHM state");
        assert!(
            !metrics.event_outbox_degraded(),
            "closed drop must not flip the Prometheus gauge"
        );
        assert_eq!(drop_counter(&metrics, "evpn", "closed"), 1);
    }

    /// Shutdown-drain pin: snapshots accepted before stage shutdown
    /// are converted and still commit; publishes after stage shutdown
    /// take the closed path.
    #[tokio::test]
    async fn stage_shutdown_drains_accepted_events_then_closes() {
        let dir = tempfile::tempdir().unwrap();
        let metrics = BgpMetrics::new();
        let manager = EventHistoryManager::start(small_ehm_config(&dir, &metrics))
            .await
            .expect("EHM start");
        let handle = manager.handle();
        let mut committed_rx = handle.subscribe_live();
        let (sink, stage) = make_rib_event_sink(handle.clone(), metrics.clone());

        for index in 0..16u32 {
            sink.publish_route_event(&sample_route_event(RouteEventType::Added, index));
        }
        stage.shutdown().await;

        for index in 0..16u64 {
            let committed = tokio::time::timeout(Duration::from_secs(5), committed_rx.recv())
                .await
                .expect("accepted-before-shutdown event commits within 5s")
                .expect("broadcast open");
            assert_eq!(committed.event_id, index + 1);
        }

        sink.publish_route_event(&sample_route_event(RouteEventType::Added, 99));
        assert_eq!(drop_counter(&metrics, "route", "closed"), 1);
        assert!(
            !handle.state().degraded(),
            "late publish after stage shutdown must not degrade"
        );

        manager.shutdown().await;
        assert_eq!(handle.state().latest_event_id(), 16);
    }

    #[tokio::test]
    async fn record_source_lag_flips_metric_and_in_process_state() {
        // Regression for the dual-signal bug the PR #291 second
        // review pass caught: `mark_event_outbox_degraded()` was
        // called but `handle.state().flip_degraded()` was not, so
        // any health probe reading the in-process EHM state would
        // see `degraded() == false` even after a real source lag.
        let dir = tempfile::tempdir().unwrap();
        let manager = EventHistoryManager::start(EventHistoryConfig {
            path: dir.path().join("events.db"),
            max_events: 100,
            max_bytes: 1_000_000,
            synchronous: SynchronousMode::Full,
            required: false,
            queue_capacity: 64,
            batch_size: 1,
            batch_interval: Duration::from_millis(10),
            broadcast_capacity: 64,
            retention_interval: Duration::from_mins(1),
            sidecar_flush_interval_batches: 100,
            metrics: None,
        })
        .await
        .expect("EHM start");
        let handle = manager.handle();
        let metrics = BgpMetrics::new();

        // Baseline: nothing is degraded, no drops recorded.
        assert!(
            !handle.state().degraded(),
            "EHM state must not start degraded"
        );
        assert!(
            !metrics.event_outbox_degraded(),
            "metric must not start degraded"
        );

        // Simulate one source lag of 7 missed events on the
        // dataplane category. Both the metric and the in-process
        // state must flip; the drop counter must increment by
        // exactly `missed`.
        record_source_lag(&handle, &metrics, "dataplane", 7);

        assert!(
            handle.state().degraded(),
            "EHM in-process state must flip on source_lagged drop"
        );
        assert!(
            metrics.event_outbox_degraded(),
            "Prometheus degraded gauge must flip on source_lagged drop"
        );

        manager.shutdown().await;
    }

    #[tokio::test]
    async fn make_transport_event_sink_enqueues_under_policy_category() {
        // End-to-end smoke for the EHM-backed transport sink. An
        // OTC ingress decision feeds the sink; the durable broadcast
        // receiver should observe one envelope under
        // `Category::Policy` with the expected event_type label and
        // a non-empty payload. This is the only test that exercises
        // the conversion + enqueue path against a real EHM actor.
        let dir = tempfile::tempdir().unwrap();
        let manager = EventHistoryManager::start(EventHistoryConfig {
            path: dir.path().join("events.db"),
            max_events: 100,
            max_bytes: 1_000_000,
            synchronous: SynchronousMode::Full,
            required: false,
            queue_capacity: 64,
            batch_size: 1,
            batch_interval: Duration::from_millis(10),
            broadcast_capacity: 64,
            retention_interval: Duration::from_mins(1),
            sidecar_flush_interval_batches: 100,
            metrics: None,
        })
        .await
        .expect("EHM start");
        let handle = manager.handle();
        let metrics = BgpMetrics::new();
        let sink = make_transport_event_sink(handle.clone(), metrics);

        let mut broadcast_rx = handle.subscribe_live();

        let event = OtcRouteBlockedEvent {
            peer: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
            direction: rustbgpd_transport::OtcDirection::Ingress,
            reason: rustbgpd_telemetry::reason_labels::OtcBlockReason::IngressFromCustomerRsclient,
            prefixes: vec!["203.0.113.0/24".to_string()],
            local_role: Some(rustbgpd_wire::BgpRole::Provider),
            remote_role: Some(rustbgpd_wire::BgpRole::Customer),
            otc_value: Some(65002),
            as_path: "65002".to_string(),
        };
        sink.publish_otc_route_blocked(&event);

        // The EHM actor commits in batches of 1 with a 10ms interval;
        // wait for the first event to land on the broadcast.
        let committed = tokio::time::timeout(Duration::from_secs(2), broadcast_rx.recv())
            .await
            .expect("EHM broadcast did not deliver within 2s")
            .expect("EHM broadcast closed before delivery");

        assert_eq!(committed.envelope.category, Category::Policy);
        assert!(
            committed.envelope.event_type.contains("OTC_ROUTE_BLOCKED"),
            "event_type label should name the new variant, got {:?}",
            committed.envelope.event_type
        );
        assert!(
            !committed.envelope.payload.is_empty(),
            "payload must round-trip the prost-encoded BgpEvent"
        );

        manager.shutdown().await;
    }
}
