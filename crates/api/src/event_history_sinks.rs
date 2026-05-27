//! EHM-backed implementations of the RIB / peer-manager event sinks
//! (ADR-0072 PR5).
//!
//! `crates/rib` defines [`rustbgpd_rib::RibEventSink`] as an
//! object-safe trait so the producer-side hot path stays free of any
//! proto / event-history dependency cycle. The binary plugs in a
//! concrete implementation that owns:
//!
//! - the cloneable [`EventHistoryHandle`] (`try_send` + degraded state),
//! - the proto-conversion helpers from `crate::event_service::convert`,
//! - the workspace [`BgpMetrics`] for drop counters.
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
    Category, EnvelopePeers, EventEnvelope, EventHistoryHandle, PayloadCodec, Severity,
};
use rustbgpd_rib::{EvpnRouteEvent, RibEventSink, RouteEvent};
use rustbgpd_telemetry::BgpMetrics;
use tokio::sync::mpsc::error::TrySendError;
use tracing::warn;

use crate::event_service::convert;
use crate::proto;

/// Concrete sink that encodes RIB events to proto and enqueues them
/// into the local event outbox.
struct EhmRibSink {
    handle: EventHistoryHandle,
    metrics: BgpMetrics,
}

impl EhmRibSink {
    fn enqueue(&self, category: Category, event: &proto::BgpEvent, envelope: EventEnvelope) {
        match self.handle.sender().try_send(envelope) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.metrics
                    .record_event_outbox_drop(category.as_str(), "queue_full");
                self.metrics.mark_event_outbox_degraded();
                self.handle.state().flip_degraded();
                warn!(
                    category = category.as_str(),
                    event_type = event.event_type,
                    "event outbox producer queue full; dropping event"
                );
            }
            Err(TrySendError::Closed(_)) => {
                // EHM actor exited (shutdown in progress, or
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
        let proto_event = convert::route_event_to_bgp_event(event.clone());
        let payload = proto_event.encode_to_vec();
        let envelope = EventEnvelope {
            timestamp_ns: timestamp_ns_now(),
            category: Category::Route,
            event_type: event_type_label(&proto_event),
            peers: EnvelopePeers {
                peer: event.peer,
                previous_peer: event.previous_peer,
                target_peer: event.target_peer,
            },
            afi_safi: afi_safi_label(proto_event.afi_safi),
            prefix: prefix_with_length(&proto_event),
            rd: None,
            evpn_route_type: None,
            severity: Severity::Info,
            payload_codec: PayloadCodec::Proto,
            payload,
        };
        self.enqueue(Category::Route, &proto_event, envelope);
    }

    fn publish_evpn_event(&self, event: &EvpnRouteEvent) {
        let proto_event = convert::evpn_event_to_bgp_event(event.clone());
        let payload = proto_event.encode_to_vec();
        let rd = rustbgpd_rib::event::evpn_key_rd(&event.key).to_string();
        let envelope = EventEnvelope {
            timestamp_ns: timestamp_ns_now(),
            category: Category::Evpn,
            event_type: event_type_label(&proto_event),
            peers: EnvelopePeers {
                peer: event.peer,
                previous_peer: event.previous_peer,
                target_peer: None,
            },
            afi_safi: None,
            prefix: None,
            rd: Some(rd),
            evpn_route_type: Some(i32::from(event.key.route_type())),
            severity: Severity::Info,
            payload_codec: PayloadCodec::Proto,
            payload,
        };
        self.enqueue(Category::Evpn, &proto_event, envelope);
    }
}

/// Construct an EHM-backed RIB event sink for installation on
/// `RibManager` via [`rustbgpd_rib::manager::RibManager::with_event_sink`].
///
/// The returned `Arc<dyn RibEventSink>` is `Clone` and `Send + Sync`;
/// it holds a cloneable [`EventHistoryHandle`] that survives any
/// number of clones without affecting EHM shutdown semantics.
#[must_use]
pub fn make_rib_event_sink(
    handle: EventHistoryHandle,
    metrics: BgpMetrics,
) -> Arc<dyn RibEventSink> {
    Arc::new(EhmRibSink { handle, metrics })
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
    use rustbgpd_event_history::{EventHistoryConfig, EventHistoryManager, SynchronousMode};
    use std::time::Duration;

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
}
