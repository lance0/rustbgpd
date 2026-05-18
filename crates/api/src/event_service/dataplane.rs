use tokio::sync::broadcast;

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

pub(super) fn spawn_dataplane_poller(
    tx: broadcast::Sender<proto::BgpEvent>,
    shared_tx: DataplaneEventBroadcaster,
    blackhole_snapshot: BlackholeDiscardSnapshotFn,
    fib_snapshot: FibRouteSnapshotFn,
) {
    tokio::spawn(async move {
        let mut previous = dataplane_summaries(&blackhole_snapshot(), &fib_snapshot());
        let mut interval = tokio::time::interval(DATAPLANE_EVENT_POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if tx.receiver_count() == 0 {
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
                let _ = tx.send(super::convert::dataplane_summary_to_bgp_event(summary));
            }
            previous = current;
        }
    });
}
