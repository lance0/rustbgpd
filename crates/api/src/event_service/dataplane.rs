use rustbgpd_event_history::{Category, EventHistoryHandle};
use rustbgpd_telemetry::BgpMetrics;
use tokio::sync::broadcast;

use crate::event_history_sinks::{envelope_from_bgp_event, try_send_envelope};
use crate::proto;
use crate::rib_service::{BlackholeDiscardSnapshotFn, FibRouteSnapshotFn};

use super::{DATAPLANE_EVENT_POLL_INTERVAL, DataplaneEventBroadcaster};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DataplaneSummary {
    pub(super) source: &'static str,
    pub(super) installed: u64,
    pub(super) rejected: u64,
    pub(super) failed: u64,
}

impl DataplaneSummary {
    fn changed_from(self, previous: Self) -> bool {
        self.installed != previous.installed
            || self.rejected != previous.rejected
            || self.failed != previous.failed
    }
}

fn count_blackhole_statuses(rows: &[proto::BlackholeDiscard]) -> DataplaneSummary {
    let mut summary = DataplaneSummary {
        source: "blackhole",
        installed: 0,
        rejected: 0,
        failed: 0,
    };
    for row in rows {
        match proto::BlackholeDiscardState::try_from(row.state) {
            Ok(proto::BlackholeDiscardState::Installed) => summary.installed += 1,
            Ok(proto::BlackholeDiscardState::Rejected) => summary.rejected += 1,
            Ok(proto::BlackholeDiscardState::Failed) => summary.failed += 1,
            Ok(proto::BlackholeDiscardState::Unspecified) | Err(_) => {}
        }
    }
    summary
}

fn count_fib_statuses(rows: &[proto::FibRouteStatus]) -> DataplaneSummary {
    let mut summary = DataplaneSummary {
        source: "fib",
        installed: 0,
        rejected: 0,
        failed: 0,
    };
    for row in rows {
        match proto::FibRouteState::try_from(row.state) {
            Ok(proto::FibRouteState::Installed) => summary.installed += 1,
            Ok(proto::FibRouteState::Rejected) => summary.rejected += 1,
            Ok(proto::FibRouteState::Failed) => summary.failed += 1,
            Ok(proto::FibRouteState::Unspecified) | Err(_) => {}
        }
    }
    summary
}

pub(super) fn dataplane_summaries(
    blackholes: &[proto::BlackholeDiscard],
    fib_routes: &[proto::FibRouteStatus],
) -> Vec<DataplaneSummary> {
    vec![
        count_blackhole_statuses(blackholes),
        count_fib_statuses(fib_routes),
    ]
}

fn changed_dataplane_summaries(
    previous: &[DataplaneSummary],
    current: &[DataplaneSummary],
) -> Vec<DataplaneSummary> {
    current
        .iter()
        .copied()
        .filter(|summary| {
            previous
                .iter()
                .find(|candidate| candidate.source == summary.source)
                .is_none_or(|previous| summary.changed_from(*previous))
        })
        .collect()
}

/// Spawn the periodic dataplane summary poller.
///
/// Lifetime behavior depends on `event_history`:
///
/// - **`None` (EHM disabled / `[event_history].enabled = false`):**
///   the poller self-terminates when the `WatchEvents` subscriber
///   count drops to zero, mirroring pre-ADR-0072 behavior. The
///   broadcaster's `Option` is reset to `None` so the next
///   `WatchEvents` subscriber lazy-respawns the poller.
///
/// - **`Some(handle)`:** the poller is daemon-lifetime. The
///   receiver-count-zero exit is suppressed because
///   `SubscribeFromEvent` collectors need durable dataplane
///   summaries even when no live `WatchEvents` subscriber is
///   attached. On every diff tick the poller also calls
///   `try_send_envelope(...)` against the EHM handle alongside
///   the existing broadcast send, so the cursor stream sees the
///   same proto `BgpEvent` the live stream sees.
pub(crate) fn spawn_dataplane_poller(
    tx: broadcast::Sender<proto::BgpEvent>,
    shared_tx: DataplaneEventBroadcaster,
    blackhole_snapshot: BlackholeDiscardSnapshotFn,
    fib_snapshot: FibRouteSnapshotFn,
    event_history: Option<EventHistoryHandle>,
    metrics: BgpMetrics,
) {
    tokio::spawn(async move {
        let mut previous = dataplane_summaries(&blackhole_snapshot(), &fib_snapshot());
        let mut interval = tokio::time::interval(DATAPLANE_EVENT_POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            // EHM-disabled path: exit when no `WatchEvents`
            // subscriber remains so the broadcaster Option resets
            // and a future subscriber lazy-respawns. EHM-enabled
            // path: stay daemon-lifetime — durable cursor needs
            // events whether or not anyone is on the live stream.
            if event_history.is_none() && tx.receiver_count() == 0 {
                let mut guard = shared_tx
                    .lock()
                    .expect("dataplane event broadcaster mutex poisoned");
                if tx.receiver_count() == 0 {
                    *guard = None;
                    return;
                }
            }

            let current = dataplane_summaries(&blackhole_snapshot(), &fib_snapshot());
            for summary in changed_dataplane_summaries(&previous, &current) {
                let proto_event = super::convert::dataplane_summary_to_bgp_event(summary);
                // ADR-0072 PR-FU1: durable outbox enqueue.
                // Dataplane summaries carry no addressable peer or
                // prefix — operators filter by category +
                // event_type only.
                if let Some(handle) = &event_history {
                    let envelope =
                        envelope_from_bgp_event(&proto_event, Category::Dataplane, None, None);
                    try_send_envelope(handle, &metrics, envelope);
                }
                let _ = tx.send(proto_event);
            }
            previous = current;
        }
    });
}
