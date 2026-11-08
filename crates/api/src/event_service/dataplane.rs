use tokio::sync::broadcast;

use crate::proto;
use crate::rib_service::{BlackholeDiscardSnapshotFn, FibRouteSnapshotReader};

use super::{DATAPLANE_EVENT_POLL_INTERVAL, DataplaneEventBroadcaster};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DataplaneSummary {
    pub(crate) source: &'static str,
    pub(crate) installed: u64,
    pub(crate) rejected: u64,
    pub(crate) failed: u64,
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

pub(crate) fn count_fib_statuses(rows: &[proto::FibRouteStatus]) -> DataplaneSummary {
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
            // The legacy dataplane summary intentionally remains a stable
            // three-bucket installed/rejected/failed surface. Operators use
            // ListFibRoutes and bgp_fib_routes_unresolved for held rows.
            Ok(proto::FibRouteState::Unresolved | proto::FibRouteState::Unspecified) | Err(_) => {}
        }
    }
    summary
}

#[cfg(test)]
pub(super) fn dataplane_summaries(
    blackholes: &[proto::BlackholeDiscard],
    fib_routes: &[proto::FibRouteStatus],
) -> Vec<DataplaneSummary> {
    vec![
        count_blackhole_statuses(blackholes),
        count_fib_statuses(fib_routes),
    ]
}

fn read_dataplane_summaries(
    blackhole_snapshot: &BlackholeDiscardSnapshotFn,
    fib_snapshot: &FibRouteSnapshotReader,
) -> Vec<DataplaneSummary> {
    let fib = fib_snapshot.with_snapshot(crate::rib_service::FibRouteSnapshot::summary);
    // This provider can project an unrelated table. Do not pin the FIB
    // publication while it runs or while counting its rows.
    vec![count_blackhole_statuses(&blackhole_snapshot()), fib]
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
/// The poller self-terminates when the `WatchEvents` subscriber count drops
/// to zero. The broadcaster's `Option` is reset to `None` so the next
/// `WatchEvents` subscriber lazy-respawns the poller.
pub(crate) fn spawn_dataplane_poller(
    tx: broadcast::Sender<proto::BgpEvent>,
    shared_tx: DataplaneEventBroadcaster,
    blackhole_snapshot: BlackholeDiscardSnapshotFn,
    fib_snapshot: FibRouteSnapshotReader,
) {
    tokio::spawn(async move {
        let mut previous = read_dataplane_summaries(&blackhole_snapshot, &fib_snapshot);
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

            let current = read_dataplane_summaries(&blackhole_snapshot, &fib_snapshot);
            for summary in changed_dataplane_summaries(&previous, &current) {
                let _ = tx.send(super::convert::dataplane_summary_to_bgp_event(summary));
            }
            previous = current;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blackhole_projection_does_not_pin_fib_publication() {
        use crate::rib_service::FibRouteSnapshot;
        use std::sync::{Arc, Mutex, mpsc};
        let (tx, rx) = tokio::sync::watch::channel(FibRouteSnapshot::default());
        let reader = FibRouteSnapshotReader::new(rx);
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let (publish_tx, publish_rx) = mpsc::channel();
        let publisher = std::thread::spawn(move || {
            publish_rx.recv().unwrap();
            started_tx.send(()).unwrap();
            tx.send_replace(FibRouteSnapshot::default());
            finished_tx.send(()).unwrap();
        });
        let receivers = Mutex::new((started_rx, finished_rx));
        let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = completed.clone();
        let blackhole: BlackholeDiscardSnapshotFn = Arc::new(move || {
            publish_tx.send(()).unwrap();
            let receivers = receivers.lock().unwrap();
            receivers.0.recv().unwrap();
            observed.store(
                receivers
                    .1
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .is_ok(),
                std::sync::atomic::Ordering::SeqCst,
            );
            Vec::new()
        });
        read_dataplane_summaries(&blackhole, &reader);
        publisher.join().unwrap();
        assert!(
            completed.load(std::sync::atomic::Ordering::SeqCst),
            "blackhole conversion held the FIB publication borrow"
        );
    }

    #[test]
    fn legacy_three_bucket_summary_ignores_unresolved_rows() {
        let summary = count_fib_statuses(&[
            proto::FibRouteStatus {
                state: proto::FibRouteState::Installed as i32,
                ..Default::default()
            },
            proto::FibRouteStatus {
                state: proto::FibRouteState::Unresolved as i32,
                reason: "next_hop_unresolved".to_string(),
                ..Default::default()
            },
        ]);

        assert_eq!(summary.installed, 1);
        assert_eq!(summary.rejected, 0);
        assert_eq!(summary.failed, 0);
    }
}
