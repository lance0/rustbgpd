//! In-place restart of the management servers.
//!
//! A failure of the metrics/readiness HTTP server or of the gRPC server is
//! not evidence about routing state, so the daemon restarts that server
//! instead of ending BGP. [`RestartBackoff`] paces both restarts;
//! [`supervise_grpc_server`] is the gRPC restart loop.

use std::future::Future;
use std::time::Duration;

use rustbgpd_telemetry::BgpMetrics;
use tokio::sync::oneshot;
use tokio::time::Instant;
use tracing::{error, info, warn};

use crate::health_probe::DaemonGate;

/// First delay before restarting a server; a single crash then costs a
/// probe less than its usual timeout.
pub const RESTART_BACKOFF_INITIAL: Duration = Duration::from_millis(100);
/// Longest delay. It stays under the shipped Kubernetes liveness probe's
/// failure window (three failures, 10 seconds apart), so a restart gap alone
/// does not get the daemon killed for a management-plane fault.
pub const RESTART_BACKOFF_CAP: Duration = Duration::from_secs(10);
/// A run at least this long starts the next backoff from the initial delay.
pub const RESTART_BACKOFF_RESET_AFTER: Duration = Duration::from_secs(60);

/// Delay before the next restart: doubles per restart up to the cap, and
/// starts over after a run that stayed up.
#[derive(Debug)]
pub struct RestartBackoff(Duration);

impl Default for RestartBackoff {
    fn default() -> Self {
        Self(RESTART_BACKOFF_INITIAL)
    }
}

impl RestartBackoff {
    /// The delay before the next restart, after a run that lasted `ran_for`.
    pub fn next_delay(&mut self, ran_for: Duration) -> Duration {
        if ran_for >= RESTART_BACKOFF_RESET_AFTER {
            self.0 = RESTART_BACKOFF_INITIAL;
        }
        let delay = self.0;
        self.0 = (delay * 2).min(RESTART_BACKOFF_CAP);
        delay
    }
}

/// The two ends one run of the gRPC server needs from its supervisor.
#[derive(Debug)]
pub struct ServerRun {
    /// Resolves when the daemon asks this run to stop.
    pub stop: oneshot::Receiver<()>,
    /// Reports whether every configured listener started.
    pub started: oneshot::Sender<Result<(), String>>,
}

/// Keep the gRPC server running until `stop` resolves or its sender drops,
/// restarting it in place when a run ends on its own.
///
/// `run_server` starts one run (in the daemon, [`crate::server::serve`] with
/// cloned inputs); a run that returns before it was asked to stop is an
/// unexpected exit. The first run's startup result goes to `first_startup`,
/// and a first run that cannot start is not retried: a listener that cannot
/// bind at startup still fails startup. Every later exit or failed start is
/// logged, counted and retried with capped backoff for as long as it takes.
///
/// While the server is down the gate holds `/readyz` red
/// ([`DaemonGate::set_grpc_server_down`]); it clears when the next run reports
/// its listeners started. No restart begins once the gate reports shutdown:
/// it is checked when a run ends and again last before each run starts. The
/// caller's stop ends a backoff at once and waits for a running server to
/// finish its own bounded drain.
///
/// A run that ends stops accepting, but the connections it already accepted
/// are separate tasks: they are told to finish (HTTP/2 GOAWAY) and a request
/// in flight on one runs to its own answer. A caller whose connection does
/// die sees a transport error. Either way an owned runtime-config mutation
/// is shielded from its caller and runs on to settlement under the
/// settlement watchdog, so no caller is told of a success that did not
/// settle.
pub async fn supervise_grpc_server<F, Fut>(
    mut run_server: F,
    first_startup: oneshot::Sender<Result<(), String>>,
    metrics: BgpMetrics,
    gate: DaemonGate,
    mut stop: oneshot::Receiver<()>,
) where
    F: FnMut(ServerRun) -> Fut,
    Fut: Future<Output = ()>,
{
    let mut first_startup = Some(first_startup);
    let mut backoff = RestartBackoff::default();
    loop {
        // Last before the run starts, so shutdown that began during a backoff
        // cancels the restart.
        if gate.is_shutting_down() {
            warn!("gRPC server not restarted: the daemon is shutting down");
            return;
        }
        let started_at = Instant::now();
        let (run_stop, run_stop_rx) = oneshot::channel();
        let (started, mut started_rx) = oneshot::channel();
        let run = run_server(ServerRun {
            stop: run_stop_rx,
            started,
        });
        tokio::pin!(run);
        let mut startup_seen = false;
        let mut startup_error = None;
        loop {
            tokio::select! {
                biased;
                _ = &mut stop => {
                    let _ = run_stop.send(());
                    run.await;
                    return;
                }
                startup = &mut started_rx, if !startup_seen => {
                    startup_seen = true;
                    let startup = startup.unwrap_or_else(|_| {
                        Err("gRPC server exited before reporting listener startup".to_string())
                    });
                    if let Some(first_startup) = first_startup.take() {
                        let failed = startup.is_err();
                        let _ = first_startup.send(startup);
                        if failed {
                            run.await;
                            return;
                        }
                    } else {
                        match startup {
                            Ok(()) => {
                                gate.set_grpc_server_down(false);
                                info!("gRPC server restarted");
                            }
                            Err(error) => startup_error = Some(error),
                        }
                    }
                }
                () = &mut run => break,
            }
        }
        metrics.record_grpc_server_crash();
        if gate.is_shutting_down() {
            warn!("gRPC server not restarted: the daemon is shutting down");
            return;
        }
        gate.set_grpc_server_down(true);
        let delay = backoff.next_delay(started_at.elapsed());
        error!(
            ?startup_error,
            restart_in_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            "gRPC server exited unexpectedly; restarting it in place"
        );
        tokio::select! {
            biased;
            _ = &mut stop => return,
            () = tokio::time::sleep(delay) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn restart_backoff_doubles_to_the_cap_and_resets_after_a_stable_run() {
        let mut backoff = RestartBackoff::default();
        let delays: Vec<_> = (0..10)
            .map(|_| backoff.next_delay(Duration::ZERO))
            .collect();
        assert_eq!(
            delays[..3],
            [
                Duration::from_millis(100),
                Duration::from_millis(200),
                Duration::from_millis(400)
            ]
        );
        assert_eq!(delays[6], Duration::from_millis(6_400));
        assert_eq!(delays[7], Duration::from_secs(10));
        assert_eq!(delays[9], RESTART_BACKOFF_CAP);
        let almost_stable = RESTART_BACKOFF_RESET_AFTER
            .checked_sub(Duration::from_millis(1))
            .unwrap();
        assert_eq!(backoff.next_delay(almost_stable), RESTART_BACKOFF_CAP);
        assert_eq!(
            backoff.next_delay(RESTART_BACKOFF_RESET_AFTER),
            RESTART_BACKOFF_INITIAL
        );
    }

    /// One run of the fake server, as the test sees it: the supervisor's
    /// ends, and the sender whose drop (or send) ends the run.
    struct FakeRun {
        run: ServerRun,
        end: oneshot::Sender<()>,
    }

    struct Harness {
        runs: mpsc::UnboundedReceiver<FakeRun>,
        first_startup: oneshot::Receiver<Result<(), String>>,
        stop: oneshot::Sender<()>,
        metrics: BgpMetrics,
        gate: DaemonGate,
        supervisor: tokio::task::JoinHandle<()>,
    }

    /// Spawn the supervisor over a fake server whose runs the test drives.
    fn harness() -> Harness {
        let (runs_tx, runs) = mpsc::unbounded_channel();
        let (first_startup_tx, first_startup) = oneshot::channel();
        let (stop, stop_rx) = oneshot::channel();
        let metrics = BgpMetrics::new();
        let gate = DaemonGate::new();
        let supervisor = tokio::spawn(supervise_grpc_server(
            move |run| {
                let (end, ended) = oneshot::channel();
                let _ = runs_tx.send(FakeRun { run, end });
                async move {
                    let _ = ended.await;
                }
            },
            first_startup_tx,
            metrics.clone(),
            gate.clone(),
            stop_rx,
        ));
        Harness {
            runs,
            first_startup,
            stop,
            metrics,
            gate,
            supervisor,
        }
    }

    fn grpc_crashes(metrics: &BgpMetrics) -> u64 {
        let families = metrics.registry().gather();
        let row = families
            .iter()
            .find(|family| family.name() == "bgp_management_server_crashes_total")
            .unwrap()
            .get_metric()
            .iter()
            .find(|row| row.get_label()[0].value() == "grpc")
            .unwrap();
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "a small whole counter value"
        )]
        let crashes = row.get_counter().get_value() as u64;
        crashes
    }

    /// Failure bound in paused time, far past any backoff: a supervisor that
    /// started a run it should not have would wait on that run forever.
    const GUARD: Duration = Duration::from_secs(3600);

    /// The crash is counted on the way into the backoff, with no await
    /// between the two, so the supervisor is in its backoff once this
    /// returns. Time is paused, so the backoff has not ended either.
    async fn in_backoff_after(metrics: &BgpMetrics, crashes: u64) {
        yield_until(|| grpc_crashes(metrics) >= crashes).await;
    }

    /// Let the supervisor run until `reached`. It never waits on a timer to
    /// get there, so a bounded number of yields is a failure bound, not a
    /// wait.
    async fn yield_until(reached: impl Fn() -> bool) {
        for _ in 0..10_000 {
            if reached() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("the supervisor never reached the expected state");
    }

    /// A supervisor that should have returned, bounded in paused time.
    async fn ended(supervisor: tokio::task::JoinHandle<()>) {
        tokio::time::timeout(GUARD, supervisor)
            .await
            .expect("the supervisor must return")
            .unwrap();
    }

    /// The stop a run receives from the supervisor, bounded in paused time.
    async fn stop_received(stop: oneshot::Receiver<()>) -> Result<(), oneshot::error::RecvError> {
        tokio::time::timeout(GUARD, stop)
            .await
            .expect("the run must be told to stop")
    }

    #[tokio::test(start_paused = true)]
    async fn a_first_run_that_cannot_start_is_reported_and_not_retried() {
        let mut h = harness();
        let first = h.runs.recv().await.unwrap();
        first.run.started.send(Err("bind failed".into())).unwrap();
        assert_eq!(h.first_startup.await, Ok(Err("bind failed".into())));
        drop(first.end);
        ended(h.supervisor).await;
        assert!(h.runs.recv().await.is_none(), "no second run");
        assert_eq!(grpc_crashes(&h.metrics), 0);
        assert!(!h.gate.grpc_server_down());
    }

    /// The whole restart: readiness goes red when the run ends, stays red
    /// through the backoff, and clears only when the next run reports its
    /// listeners started.
    #[tokio::test(start_paused = true)]
    async fn an_unexpected_exit_holds_readiness_red_until_the_restart_started() {
        let mut h = harness();
        let first = h.runs.recv().await.unwrap();
        first.run.started.send(Ok(())).unwrap();
        assert_eq!(h.first_startup.await, Ok(Ok(())));
        assert!(!h.gate.grpc_server_down());
        assert_eq!(grpc_crashes(&h.metrics), 0);

        drop(first.end);
        in_backoff_after(&h.metrics, 1).await;
        assert!(h.gate.grpc_server_down());

        let before = Instant::now();
        let second = h.runs.recv().await.unwrap();
        assert_eq!(before.elapsed(), RESTART_BACKOFF_INITIAL);
        assert!(
            h.gate.grpc_server_down(),
            "a run that has not reported its listeners is not serving"
        );
        second.run.started.send(Ok(())).unwrap();
        yield_until(|| !h.gate.grpc_server_down()).await;
        assert_eq!(grpc_crashes(&h.metrics), 1);

        drop(h.stop);
        assert_eq!(stop_received(second.run.stop).await, Ok(()));
        drop(second.end);
        ended(h.supervisor).await;
    }

    /// A restart whose listeners cannot start is one more crash: readiness
    /// stays red and the next attempt waits twice as long.
    #[tokio::test(start_paused = true)]
    async fn a_restart_that_cannot_start_is_counted_and_retried() {
        let mut h = harness();
        let first = h.runs.recv().await.unwrap();
        first.run.started.send(Ok(())).unwrap();
        drop(first.end);

        let second = h.runs.recv().await.unwrap();
        second
            .run
            .started
            .send(Err("address in use".into()))
            .unwrap();
        drop(second.end);
        in_backoff_after(&h.metrics, 2).await;
        assert!(h.gate.grpc_server_down());

        let before = Instant::now();
        let third = h.runs.recv().await.unwrap();
        assert_eq!(before.elapsed(), RESTART_BACKOFF_INITIAL * 2);
        third.run.started.send(Ok(())).unwrap();
        yield_until(|| !h.gate.grpc_server_down()).await;
        assert_eq!(grpc_crashes(&h.metrics), 2);
        h.supervisor.abort();
    }

    /// The daemon's stop reaches the running server, and the supervisor
    /// returns only after that run finished its drain.
    #[tokio::test(start_paused = true)]
    async fn stop_is_forwarded_and_waits_for_the_run_to_finish() {
        let mut h = harness();
        let first = h.runs.recv().await.unwrap();
        first.run.started.send(Ok(())).unwrap();
        h.stop.send(()).unwrap();
        assert_eq!(stop_received(first.run.stop).await, Ok(()));
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(!h.supervisor.is_finished(), "the run is still draining");
        drop(first.end);
        ended(h.supervisor).await;
        assert_eq!(grpc_crashes(&h.metrics), 0);
        assert!(h.runs.recv().await.is_none(), "no run after the stop");
    }

    /// Time is paused and only an idle runtime advances it, so a supervisor
    /// that waited its backoff out would start a second run before it saw
    /// the stop.
    #[tokio::test(start_paused = true)]
    async fn stop_ends_a_restart_backoff_without_another_run() {
        let mut h = harness();
        let first = h.runs.recv().await.unwrap();
        first.run.started.send(Ok(())).unwrap();
        drop(first.end);
        in_backoff_after(&h.metrics, 1).await;
        drop(h.stop);
        ended(h.supervisor).await;
        assert!(h.runs.recv().await.is_none(), "no run after the stop");
    }

    /// A server that ends after coordinated shutdown began stays down. The
    /// crash is counted, but no backoff runs: paused time does not advance.
    #[tokio::test(start_paused = true)]
    async fn an_exit_during_shutdown_is_counted_and_not_restarted() {
        let mut h = harness();
        let first = h.runs.recv().await.unwrap();
        first.run.started.send(Ok(())).unwrap();
        let before = Instant::now();
        h.gate.begin_shutdown();
        drop(first.end);
        ended(h.supervisor).await;
        assert_eq!(before.elapsed(), Duration::ZERO);
        assert_eq!(grpc_crashes(&h.metrics), 1);
        assert!(h.runs.recv().await.is_none(), "no run during shutdown");
    }

    /// Shutdown that begins during a backoff cancels the restart it was
    /// waiting for.
    #[tokio::test(start_paused = true)]
    async fn shutdown_during_a_restart_backoff_cancels_the_restart() {
        let mut h = harness();
        let first = h.runs.recv().await.unwrap();
        first.run.started.send(Ok(())).unwrap();
        drop(first.end);
        in_backoff_after(&h.metrics, 1).await;
        h.gate.begin_shutdown();
        ended(h.supervisor).await;
        assert!(h.runs.recv().await.is_none(), "no run during shutdown");
        drop(h.stop);
    }
}
