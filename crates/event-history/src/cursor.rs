//! Cursor API — `SubscribeFromEvent` actor-ordered handoff (ADR-0072 PR3).
//!
//! See "Cursor API — `SubscribeFromEvent` with actor-ordered handoff"
//! in `docs/adr/0072-durable-event-history.md` for the contract.
//!
//! The three-step handoff:
//!
//! 1. Subscribe to the live broadcast first, BEFORE reading the
//!    high-watermark. Because EHM's actor stores `latest_event_id`
//!    *before* it calls `broadcast::send`, any event whose `event_id`
//!    is `> high_watermark` is guaranteed to have arrived on the
//!    live receiver after we registered unless that per-subscriber
//!    broadcast receiver later lags.
//! 2. Capture the high-watermark — the durable
//!    [`crate::EhmState::latest_event_id`] value. Drives the
//!    replay-query upper bound.
//! 3. Spawn a replay task that drains SQLite for
//!    `from_event_id < event_id <= high_watermark`, then forwards
//!    live events with `event_id` above both the captured high-watermark
//!    and the caller cursor.
//!
//! Live subscribers may briefly receive events in the
//! `(from_event_id, high_watermark]` range from BOTH the replay and
//! the live path — between step 1 and step 2 the actor may have
//! committed and broadcast new events. The live lower-bound check
//! suppresses that overlap before forwarding to the caller.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{broadcast, mpsc};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tracing::{debug, warn};

use crate::storage::QueryFilter;
use crate::{Category, CommittedEvent, EventHistoryError, EventHistoryManager, PayloadCodec};

/// Filter applied to both replay and live segments of a
/// [`EventHistoryManager::subscribe_from_event`] stream. Mirrors
/// the indexable surface on [`crate::EventEnvelope`]; PR4's gRPC
/// `SubscribeFromEventRequest` proto maps onto this struct.
#[derive(Debug, Default, Clone)]
pub struct SubscribeFilter {
    pub category: Option<Category>,
    /// Match against any of `peer` / `previous_peer` / `target_peer`
    /// (the "any-role" semantics that the existing route history
    /// query uses).
    pub peer: Option<IpAddr>,
    pub prefix: Option<String>,
    pub rd: Option<String>,
}

impl SubscribeFilter {
    /// Returns true if the supplied committed event satisfies every
    /// `Some(...)` field on this filter. `None` fields are wildcards.
    #[must_use]
    pub fn matches(&self, evt: &CommittedEvent) -> bool {
        if let Some(want) = self.category
            && evt.envelope.category != want
        {
            return false;
        }
        if let Some(want) = self.peer {
            let any = [
                evt.envelope.peers.peer,
                evt.envelope.peers.previous_peer,
                evt.envelope.peers.target_peer,
            ]
            .into_iter()
            .flatten()
            .any(|p| p == want);
            if !any {
                return false;
            }
        }
        if let Some(want) = &self.prefix
            && evt.envelope.prefix.as_deref() != Some(want.as_str())
        {
            return false;
        }
        if let Some(want) = &self.rd
            && evt.envelope.rd.as_deref() != Some(want.as_str())
        {
            return false;
        }
        true
    }
}

/// Request shape for [`EventHistoryManager::subscribe_from_event`].
///
/// `from_event_id` semantics (matches the proto3 `optional uint64`
/// the gRPC layer will use in PR4):
///
/// - `None` — **live-only** subscription, no replay. Streams events
///   committed after the live subscription is registered.
/// - `Some(0)` — **replay everything** retained in the outbox from
///   the earliest `event_id`, then transition to live. Used by a
///   fresh collector that has no `last_seen_event_id`.
/// - `Some(N)` for `N > 0` — replay events with `event_id > N`,
///   then live. The normal reconnect case.
#[derive(Debug, Clone)]
pub struct SubscribeRequest {
    pub from_event_id: Option<u64>,
    pub filter: SubscribeFilter,
    /// Capacity of the output channel handed back to the caller.
    /// Slow consumers cause `try_send` failures on the replay+live
    /// drain task, which then logs and drops; the cursor contract
    /// is "no gaps from the daemon side" — consumer slowness shows
    /// up as a per-consumer drop, not a daemon-wide degraded state.
    pub output_capacity: usize,
}

impl Default for SubscribeRequest {
    fn default() -> Self {
        Self {
            from_event_id: None,
            filter: SubscribeFilter::default(),
            output_capacity: 4096,
        }
    }
}

/// Per-subscription drop counter surfaced to the caller. PR4's gRPC
/// layer surfaces this via `StreamLagEvent` so external collectors
/// know they fell behind.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SubscribeStatsSnapshot {
    pub broadcast_lagged: u64,
    pub output_full: u64,
}

#[derive(Debug, Default)]
pub struct SubscribeStats {
    broadcast_lagged: AtomicU64,
    output_full: AtomicU64,
}

impl SubscribeStats {
    #[must_use]
    pub fn snapshot(&self) -> SubscribeStatsSnapshot {
        SubscribeStatsSnapshot {
            broadcast_lagged: self.broadcast_lagged.load(Ordering::Acquire),
            output_full: self.output_full.load(Ordering::Acquire),
        }
    }

    fn record_broadcast_lagged(&self, n: u64) {
        self.broadcast_lagged.fetch_add(n, Ordering::AcqRel);
    }

    fn record_output_full(&self) {
        self.output_full.fetch_add(1, Ordering::AcqRel);
    }
}

/// Handle returned by [`EventHistoryManager::subscribe_from_event`].
pub struct EventSubscription {
    receiver: mpsc::Receiver<CommittedEvent>,
    stats: Arc<SubscribeStats>,
}

impl EventSubscription {
    #[must_use]
    pub fn into_receiver(self) -> mpsc::Receiver<CommittedEvent> {
        self.receiver
    }

    #[must_use]
    pub fn stats(&self) -> Arc<SubscribeStats> {
        self.stats.clone()
    }
}

impl EventHistoryManager {
    /// Subscribe to the committed event stream with optional cursor
    /// replay. See [`SubscribeRequest`] for the cursor semantics.
    ///
    /// The returned [`EventSubscription`] contains the output receiver
    /// plus observable per-subscription stats. Close the receiver to
    /// cancel the subscription. The spawned drain task exits when the
    /// receiver is dropped.
    ///
    /// # Errors
    ///
    /// Returns [`EventHistoryError::PassThrough`] when EHM is in
    /// pass-through mode (no durable backing). Live-only is still
    /// possible by calling [`Self::subscribe`] directly.
    pub async fn subscribe_from_event(
        &self,
        req: SubscribeRequest,
    ) -> Result<EventSubscription, EventHistoryError> {
        if self.state().pass_through() {
            return Err(EventHistoryError::PassThrough);
        }

        // STEP 1: subscribe to the live broadcast FIRST. Any event
        // committed-and-broadcast from this point forward arrives on
        // `live_rx`, even if its `event_id` is `<= high_watermark`.
        let live_rx = self.broadcast_tx_for_cursor();

        // STEP 2: capture the high-watermark. The actor's
        // `latest_event_id.store(...)` happens BEFORE
        // `broadcast.send(...)`, so any event with id > this value is
        // guaranteed to be on the live stream we just attached.
        let high_watermark = self.state().latest_event_id();

        let output_capacity = req.output_capacity.max(1);
        let (out_tx, out_rx) = mpsc::channel(output_capacity);
        let stats = Arc::new(SubscribeStats::default());

        // STEP 3: spawn the replay-then-live drain task.
        let storage = self.storage_handle_for_cursor();
        let req_clone = req.clone();
        let stats_for_task = stats.clone();
        tokio::spawn(async move {
            run_subscription(
                req_clone,
                high_watermark,
                storage,
                live_rx,
                out_tx,
                stats_for_task,
            )
            .await;
        });

        Ok(EventSubscription {
            receiver: out_rx,
            stats,
        })
    }
}

async fn run_subscription(
    req: SubscribeRequest,
    high_watermark: u64,
    storage: crate::storage::StoreHandle,
    live_rx: broadcast::Receiver<CommittedEvent>,
    out_tx: mpsc::Sender<CommittedEvent>,
    stats: Arc<SubscribeStats>,
) {
    let cursor_floor = req.from_event_id.unwrap_or(high_watermark);
    let live_min_id = high_watermark.max(cursor_floor);

    // ── Replay phase ────────────────────────────────────────────
    if let Some(from_id) = req.from_event_id {
        // Drain SQLite in chunks. The storage query filters category /
        // peer / prefix / rd on indexed columns; we still re-check on
        // the receiving side as a defensive boundary around storage.
        let chunk_size = req.output_capacity.max(64);
        let mut next_from = from_id;
        loop {
            let query_filter = QueryFilter {
                category: req.filter.category,
                peer: req.filter.peer.map(|p| p.to_string()),
                prefix: req.filter.prefix.clone(),
                rd: req.filter.rd.clone(),
            };
            let rows = match storage
                .query(next_from, high_watermark, chunk_size, query_filter)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = %e, "replay chunk query failed; aborting subscription");
                    return;
                }
            };
            if rows.is_empty() {
                break;
            }
            let last_id = rows.last().map(|r| r.event_id).unwrap_or(high_watermark);
            for row in rows {
                // Reconstruct a CommittedEvent from PersistedEvent.
                let envelope = crate::EventEnvelope {
                    timestamp_ns: row.timestamp_ns,
                    category: row.category,
                    event_type: row.event_type,
                    peers: crate::EnvelopePeers {
                        peer: row.peer.as_ref().and_then(|s| s.parse().ok()),
                        previous_peer: row.previous_peer.as_ref().and_then(|s| s.parse().ok()),
                        target_peer: row.target_peer.as_ref().and_then(|s| s.parse().ok()),
                    },
                    afi_safi: row.afi_safi,
                    prefix: row.prefix,
                    rd: row.rd,
                    evpn_route_type: row.evpn_route_type,
                    severity: row.severity,
                    payload_codec: PayloadCodec::parse(&row.payload_codec)
                        .unwrap_or(PayloadCodec::Opaque),
                    payload: row.payload,
                };
                let committed = CommittedEvent {
                    event_id: row.event_id,
                    daemon_boot_id: row.daemon_boot_id.into(),
                    envelope: envelope.into(),
                };
                if !req.filter.matches(&committed) {
                    continue;
                }
                if !try_emit(&out_tx, &stats, committed, "replay") {
                    return;
                }
            }
            if last_id >= high_watermark {
                break;
            }
            next_from = last_id;
        }
    }

    // ── Live phase ──────────────────────────────────────────────
    // Wrap the broadcast receiver in a Stream so we can use the
    // standard tokio_stream combinators for lag handling.
    let mut live = BroadcastStream::new(live_rx);
    while let Some(item) = live.next().await {
        let committed = match item {
            Ok(c) => c,
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                stats.record_broadcast_lagged(n);
                warn!(
                    missed = n,
                    "subscribe_from_event live stream lagged; consumer too slow"
                );
                continue;
            }
        };

        // Boundary + cursor floor: events at or below the larger of the
        // captured high-watermark and caller cursor are never delivered
        // from the live path. Replay is authoritative for <= high-water,
        // and a caller cursor beyond current latest means old live tail
        // from an in-flight batch must not leak through.
        if committed.event_id <= live_min_id {
            continue;
        }

        if !req.filter.matches(&committed) {
            continue;
        }

        if !try_emit(&out_tx, &stats, committed, "live") {
            return;
        }
    }
    let snapshot = stats.snapshot();
    debug!(
        broadcast_lagged = snapshot.broadcast_lagged,
        output_full = snapshot.output_full,
        "subscribe_from_event drain task exiting"
    );
}

fn try_emit(
    out_tx: &mpsc::Sender<CommittedEvent>,
    stats: &SubscribeStats,
    committed: CommittedEvent,
    phase: &'static str,
) -> bool {
    match out_tx.try_send(committed) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Closed(_)) => {
            debug!(phase, "subscription output closed");
            false
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            stats.record_output_full();
            warn!(
                phase,
                "subscription output full; dropping event for this subscriber"
            );
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Category, Severity};

    fn make_committed(event_id: u64, category: Category) -> CommittedEvent {
        make_committed_with_peers(event_id, category, crate::EnvelopePeers::default())
    }

    fn make_committed_with_peers(
        event_id: u64,
        category: Category,
        peers: crate::EnvelopePeers,
    ) -> CommittedEvent {
        CommittedEvent {
            event_id,
            daemon_boot_id: "test-boot".into(),
            envelope: crate::EventEnvelope {
                timestamp_ns: 0,
                category,
                event_type: "added".into(),
                peers,
                afi_safi: None,
                prefix: None,
                rd: None,
                evpn_route_type: None,
                severity: Severity::Info,
                payload_codec: crate::PayloadCodec::Opaque,
                payload: vec![],
            }
            .into(),
        }
    }

    #[test]
    fn filter_wildcard_matches_everything() {
        let f = SubscribeFilter::default();
        assert!(f.matches(&make_committed(1, Category::Route)));
        assert!(f.matches(&make_committed(2, Category::Session)));
    }

    #[test]
    fn filter_by_category_excludes_others() {
        let f = SubscribeFilter {
            category: Some(Category::Route),
            ..SubscribeFilter::default()
        };
        assert!(f.matches(&make_committed(1, Category::Route)));
        assert!(!f.matches(&make_committed(2, Category::Session)));
    }

    #[test]
    fn filter_by_peer_matches_any_role() {
        let peer: IpAddr = "192.0.2.1".parse().unwrap();
        let f = SubscribeFilter {
            peer: Some(peer),
            ..SubscribeFilter::default()
        };

        // No peers set → no match.
        assert!(!f.matches(&make_committed(1, Category::Route)));

        assert!(f.matches(&make_committed_with_peers(
            1,
            Category::Route,
            crate::EnvelopePeers {
                peer: Some(peer),
                previous_peer: None,
                target_peer: None,
            },
        )));
        assert!(f.matches(&make_committed_with_peers(
            1,
            Category::Route,
            crate::EnvelopePeers {
                peer: None,
                previous_peer: Some(peer),
                target_peer: None,
            },
        )));
        assert!(f.matches(&make_committed_with_peers(
            1,
            Category::Route,
            crate::EnvelopePeers {
                peer: None,
                previous_peer: None,
                target_peer: Some(peer),
            },
        )));

        // Different peer in all roles.
        let other: IpAddr = "192.0.2.99".parse().unwrap();
        assert!(!f.matches(&make_committed_with_peers(
            1,
            Category::Route,
            crate::EnvelopePeers {
                peer: Some(other),
                previous_peer: Some(other),
                target_peer: Some(other),
            },
        )));
    }
}
