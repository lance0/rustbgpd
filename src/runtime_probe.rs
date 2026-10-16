//! Tokio scheduler lateness and worker busy time, measured in process.
//!
//! A 10 ms interval task records how late each tick is polled. When every
//! runtime worker is busy or blocked, every ready task waits the same way, so
//! lateness is a direct signal of worker starvation, independent of which
//! task holds the workers. The same task refreshes the per-worker busy-time
//! counters from tokio's stable runtime metrics.

use std::time::Duration;

use rustbgpd_telemetry::BgpMetrics;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tracing::warn;

const PROBE_PERIOD: Duration = Duration::from_millis(10);

pub(crate) struct RuntimeProbe {
    shutdown: CancellationToken,
    handle: JoinHandle<()>,
}

impl RuntimeProbe {
    /// Start the probe on the current runtime. Its series exist on return.
    pub(crate) fn spawn(metrics: &BgpMetrics) -> Self {
        let runtime = tokio::runtime::Handle::current().metrics();
        let busy = metrics.runtime_worker_busy_counters(runtime.num_workers());
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn(run(metrics.clone(), busy, shutdown.clone()));
        Self { shutdown, handle }
    }

    /// Stop the probe and join it, unless a further termination signal
    /// cancels `stop_waiting` first.
    pub(crate) async fn shutdown(self, stop_waiting: &CancellationToken) {
        self.shutdown.cancel();
        match crate::shutdown_wait(None, stop_waiting, self.handle).await {
            crate::ShutdownWait::Completed(Ok(())) => {}
            crate::ShutdownWait::Completed(Err(error)) => {
                warn!(%error, "runtime probe task failed");
            }
            abandoned => warn!(
                reason = abandoned.abandoned(),
                "stopped waiting for the runtime probe"
            ),
        }
    }
}

async fn run(metrics: BgpMetrics, busy: Vec<prometheus::IntCounter>, shutdown: CancellationToken) {
    let runtime = tokio::runtime::Handle::current().metrics();
    let mut reported = vec![0_u128; busy.len()];
    let mut interval = tokio::time::interval(PROBE_PERIOD);
    // Delay re-bases the schedule after a late tick, so each sample is the
    // delay of one wake rather than a backlog of burst ticks.
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        let scheduled = tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            scheduled = interval.tick() => scheduled,
        };
        metrics.observe_runtime_scheduler_lateness(scheduled.elapsed());
        for (worker, (counter, reported)) in busy.iter().zip(&mut reported).enumerate() {
            let total = runtime.worker_total_busy_duration(worker).as_micros();
            counter.inc_by(u64::try_from(total.saturating_sub(*reported)).unwrap_or(u64::MAX));
            *reported = total;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::gather_metrics_text;

    fn lateness_above_50ms(text: &str) -> f64 {
        let value = |le: &str| -> f64 {
            let prefix = format!("bgp_runtime_scheduler_lateness_seconds_bucket{{le=\"{le}\"}} ");
            text.lines()
                .find_map(|line| line.strip_prefix(&prefix))
                .unwrap_or_else(|| panic!("missing lateness bucket {le}"))
                .parse()
                .unwrap()
        };
        value("+Inf") - value("0.05")
    }

    fn worker_busy_seconds(text: &str) -> f64 {
        let micros: f64 = text
            .lines()
            .find_map(|line| {
                line.strip_prefix("bgp_runtime_worker_busy_microseconds_total{worker=\"0\"} ")
            })
            .expect("worker 0 busy series")
            .parse()
            .unwrap();
        micros / 1e6
    }

    /// A task that blocks the only worker delays the probe's next wake by
    /// about the blocked time, and the worker's busy time grows by as much.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn blocked_worker_moves_lateness_and_busy_time() {
        let metrics = BgpMetrics::new();
        let probe = RuntimeProbe::spawn(&metrics);
        let before = gather_metrics_text(&metrics);
        assert_eq!(lateness_above_50ms(&before), 0.0);
        let busy_before = worker_busy_seconds(&before);

        tokio::time::sleep(Duration::from_millis(30)).await;
        tokio::spawn(async { std::thread::sleep(Duration::from_millis(120)) })
            .await
            .unwrap();
        // Let the late tick run and the next tick refresh busy time.
        tokio::time::sleep(Duration::from_millis(40)).await;

        let after = gather_metrics_text(&metrics);
        assert!(
            lateness_above_50ms(&after) >= 1.0,
            "a 120 ms blocked worker must record a lateness sample above 50 ms"
        );
        assert!(
            worker_busy_seconds(&after) - busy_before >= 0.1,
            "the blocked worker's busy time must include the 120 ms block"
        );
        probe.shutdown(&CancellationToken::new()).await;
    }

    /// A probe join that cannot complete must not hold shutdown once a
    /// further signal cancels the waits.
    #[tokio::test]
    async fn second_signal_skips_a_probe_join_that_cannot_finish() {
        let probe = RuntimeProbe {
            shutdown: CancellationToken::new(),
            handle: tokio::spawn(std::future::pending()),
        };
        let stop_waiting = CancellationToken::new();
        let second_signal = stop_waiting.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            second_signal.cancel();
        });
        tokio::time::timeout(Duration::from_secs(10), probe.shutdown(&stop_waiting))
            .await
            .expect("a second signal did not end the runtime probe join");
    }
}
