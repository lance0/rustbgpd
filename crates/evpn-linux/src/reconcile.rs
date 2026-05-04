//! [`ReconcileActor`] — the level-triggered reconciliation loop.
//!
//! The actor owns one [`crate::Dataplane`] implementation by value and
//! drives reconcile passes whenever any of these inputs fire:
//!
//! - new [`rustbgpd_evpn::DataplaneIntent`] arrives on the watch channel,
//! - a [`crate::KernelEvent`] arrives via [`crate::Dataplane::next_event`],
//! - the periodic full-dump timer fires (60 s default per ADR-0054 §6),
//! - the per-op retry timer fires for one or more failed-op keys,
//! - shutdown is requested via the cancellation token.
//!
//! Each fire schedules the same reconcile pass:
//!
//! ```text
//!   intent + probe + dump -> compute_diff -> apply ops, record outcomes
//! ```
//!
//! The pass is idempotent: re-running it without input changes is a
//! no-op. ADR-0054 §6 requires this property so we can safely react
//! to noisy notifications without amplifying their cost.
//!
//! ## Generic over the dataplane
//!
//! The actor is generic over `D: Dataplane` so the same code drives
//! both the [`crate::InMemoryDataplane`] fake (used by Phase 3 tests)
//! and the future `LinuxDataplane` real impl (Phase 4). The trait's
//! native `async fn` means no `dyn Dataplane` boxing.
//!
//! ## Reference
//!
//! - ADR-0054 §6 (reconcile-on-event plus periodic full resync)
//! - ADR-0054 §7 (shutdown leaves host topology intact)
//! - ADR-0054 §8 (failures surface as status, not domain mutation)

use std::sync::Arc;
use std::time::Duration;

use rustbgpd_evpn::{
    AppliedOp, DataplaneIntent, DataplaneOpKind, DataplaneReport, EvpnInstanceTable, FailedOp,
    InstanceDataplaneStatus, InstanceState, RemoteMacTable,
};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, MissedTickBehavior, sleep_until};
use tokio_util::sync::CancellationToken;

use crate::backoff::RetrySchedule;
use crate::dataplane::{Dataplane, DataplaneOp, KernelEvent};
use crate::diff::{Plan, compute_diff};
use crate::error::FailureClass;
use crate::snapshot::{InstanceProbe, InstanceProbes, KernelSnapshot, OwnedEntry, OwnedSet};

/// Tunable cadence for the reconcile loop. Production values come from
/// ADR-0054 §6; tests construct `Self::for_tests()` for a tighter
/// rhythm under `tokio::time::pause()`.
#[derive(Debug, Clone, Copy)]
pub struct ReconcileActorConfig {
    /// Periodic full-dump cadence. ADR default 60 s.
    pub periodic_dump: Duration,
    /// Coalescing window after a watch / event wake — additional
    /// signals received inside this window are folded into the same
    /// reconcile pass. Defaults to 50 ms; tests can set 0 for
    /// determinism.
    pub coalesce_window: Duration,
    /// Bounded shutdown drain timeout. ADR default 5 s.
    pub drain_timeout: Duration,
    /// Initial dump skipped — used by tests that want to drive dumps
    /// purely through events.
    pub skip_initial_dump: bool,
}

impl ReconcileActorConfig {
    /// Production defaults (ADR-0054 §6/§7).
    #[must_use]
    pub const fn production() -> Self {
        Self {
            periodic_dump: Duration::from_secs(60),
            coalesce_window: Duration::from_millis(50),
            drain_timeout: Duration::from_secs(5),
            skip_initial_dump: false,
        }
    }

    /// Test-friendly defaults — everything compressed so paused-time
    /// tests don't need to advance virtual time by minutes.
    #[must_use]
    pub const fn for_tests() -> Self {
        Self {
            periodic_dump: Duration::from_secs(60), // explicit advance in tests
            coalesce_window: Duration::from_millis(0),
            drain_timeout: Duration::from_secs(5),
            skip_initial_dump: false,
        }
    }
}

impl Default for ReconcileActorConfig {
    fn default() -> Self {
        Self::production()
    }
}

/// The actor.
///
/// Constructed once at daemon startup; the daemon spawns
/// [`ReconcileActor::run`] on a dedicated tokio task. The actor exits
/// cleanly when the cancellation token fires, draining owned remote
/// FDB entries within `drain_timeout`.
pub struct ReconcileActor<D: Dataplane> {
    dataplane: D,
    intent_rx: watch::Receiver<Arc<DataplaneIntent>>,
    report_tx: mpsc::Sender<DataplaneReport>,
    shutdown: CancellationToken,
    config: ReconcileActorConfig,
    state: ActorState,
}

/// Internal mutable state — separated so [`ReconcileActor::reconcile_once`]
/// borrows it disjointly from `dataplane`.
#[derive(Debug)]
struct ActorState {
    owned: OwnedSet,
    retry: RetrySchedule,
    /// Last `intent_generation` we successfully reconciled against.
    /// Reports echo this so the daemon can correlate.
    last_intent_generation: u64,
    /// Monotonic reconcile-pass counter for telemetry / debugging.
    reconcile_generation: u64,
    /// Anchor for retry-schedule millisecond timestamps. The schedule
    /// is purely about *relative* delays, so the anchor doesn't have
    /// to be wall-clock — `Instant` since `start` works.
    epoch: Instant,
}

impl ActorState {
    fn new() -> Self {
        Self {
            owned: OwnedSet::new(),
            retry: RetrySchedule::new(),
            last_intent_generation: 0,
            reconcile_generation: 0,
            epoch: Instant::now(),
        }
    }

    fn now_ms(&self) -> u64 {
        // Duration::as_millis returns u128; the actor epoch is set
        // at startup so the elapsed window stays well inside u64
        // even at multi-decade uptimes (u64 ms ≈ 584 million years).
        u64::try_from(
            Instant::now()
                .saturating_duration_since(self.epoch)
                .as_millis(),
        )
        .unwrap_or(u64::MAX)
    }
}

impl<D: Dataplane> ReconcileActor<D> {
    /// Build a new actor.
    pub fn new(
        config: ReconcileActorConfig,
        dataplane: D,
        intent_rx: watch::Receiver<Arc<DataplaneIntent>>,
        report_tx: mpsc::Sender<DataplaneReport>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            dataplane,
            intent_rx,
            report_tx,
            shutdown,
            config,
            state: ActorState::new(),
        }
    }

    /// Run the actor loop until shutdown.
    ///
    /// The future returned does not need to be `Send` itself; the
    /// daemon spawns it onto a tokio task with `tokio::spawn`, so the
    /// `D: Dataplane + Send` bound on the impl is what allows that.
    pub async fn run(mut self) {
        let mut periodic = tokio::time::interval(self.config.periodic_dump);
        // The first tick fires immediately; we use `Skip` so the
        // initial-dump path (run_once below) handles it instead of
        // double-reconciling.
        periodic.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // Consume the immediate tick so subsequent ticks fire after
        // `periodic_dump` of *real* time.
        periodic.tick().await;

        // Initial reconcile pass. The watch channel always has a
        // current value (the producer sets it on construction, even
        // if it's `DataplaneIntent::empty()`), so borrow() is safe
        // before any `changed()` await.
        if !self.config.skip_initial_dump {
            self.reconcile_once().await;
        }

        loop {
            // Compute the next retry deadline, if any.
            let retry_due = self
                .state
                .retry
                .earliest_due()
                .map(|due_ms| self.state.epoch + Duration::from_millis(due_ms));

            tokio::select! {
                biased;
                () = self.shutdown.cancelled() => {
                    self.drain().await;
                    return;
                }
                changed = self.intent_rx.changed() => {
                    if changed.is_err() {
                        // Watch sender closed — the daemon is going
                        // away. Drain on shutdown signal; if we don't
                        // get one, exit anyway.
                        self.shutdown.cancel();
                        continue;
                    }
                    self.coalesce_and_reconcile().await;
                }
                evt = self.dataplane.next_event() => {
                    if let Some(KernelEvent::KernelStateChanged) = evt {
                        self.coalesce_and_reconcile().await;
                    } else if evt.is_none() {
                        // Implementation closed its event stream.
                        // Fall through to periodic + retry only.
                    }
                    // Other event variants (LocalMacObservation) are
                    // not consumed here yet; Phase 5 routes them up.
                }
                _ = periodic.tick() => {
                    self.reconcile_once().await;
                }
                () = wait_until(retry_due) => {
                    self.reconcile_once().await;
                }
            }
        }
    }

    /// Wait the coalesce window, then reconcile. Drains any stacked
    /// intent updates inside the window so we apply just the latest.
    async fn coalesce_and_reconcile(&mut self) {
        if !self.config.coalesce_window.is_zero() {
            tokio::time::sleep(self.config.coalesce_window).await;
            // Mark watch as seen; subsequent intents inside the window
            // get folded into the upcoming pass automatically because
            // the actor reads `intent_rx.borrow()` at reconcile time.
            // Drain `try_recv()` on the kernel-event channel via a
            // few quick polls — but since we don't own that channel
            // (the dataplane impl does), we rely on the level-
            // triggered reconcile to handle it.
            let _ = self.intent_rx.has_changed();
        }
        self.reconcile_once().await;
    }

    /// One reconcile pass: probe → dump → diff → apply → emit report.
    async fn reconcile_once(&mut self) {
        self.state.reconcile_generation = self.state.reconcile_generation.saturating_add(1);

        // Snapshot the current intent (via `borrow_and_update` so the
        // next `changed()` fires only on subsequent publishes).
        let intent: Arc<DataplaneIntent> = self.intent_rx.borrow_and_update().clone();
        self.state.last_intent_generation = intent.generation;

        let probes = self.dataplane.probe(&intent.instances).await;
        let snapshot = match self.dataplane.dump_snapshot().await {
            Ok(s) => s,
            Err(e) => {
                // Dump failed — emit a report with no applied/failed
                // ops but instance_status echoing what we know, then
                // bail out and let the next event/timer trigger a
                // retry.
                tracing::warn!(error = %e, "kernel snapshot dump failed");
                let status = build_instance_status(&intent.instances, &probes);
                self.emit_report(status, vec![], vec![]).await;
                return;
            }
        };

        let plan = compute_diff(
            intent.remote_macs.as_ref(),
            &snapshot,
            &self.state.owned,
            &probes,
        );

        let (applied, failed) = self.apply_plan(&plan, intent.remote_macs.as_ref()).await;

        let status = build_instance_status(&intent.instances, &probes);
        self.emit_report(status, applied, failed).await;
    }

    /// Apply each op in the plan, recording successes in `owned` and
    /// failures in the retry schedule. Returns `(applied, failed)` for
    /// inclusion in the report.
    async fn apply_plan(
        &mut self,
        plan: &Plan,
        desired: &RemoteMacTable,
    ) -> (Vec<AppliedOp>, Vec<FailedOp>) {
        let mut applied = Vec::with_capacity(plan.len());
        let mut failed = Vec::new();
        let now_ms = self.state.now_ms();

        for op in &plan.ops {
            let res = self.dataplane.apply(op).await;
            match res {
                Ok(()) => {
                    self.record_success(op, desired);
                    applied.push(op_to_applied(op));
                }
                Err(err) => {
                    let class = err.class();
                    let next_due_ms = match class {
                        FailureClass::Transient | FailureClass::Conflict => self
                            .state
                            .retry
                            .record_failure(op_vni(op), op_mac(op), now_ms),
                        FailureClass::Permanent => {
                            // Don't re-attempt; the next intent /
                            // event will reset the schedule when the
                            // operator fixes the underlying state.
                            // Record it for visibility.
                            self.state
                                .retry
                                .record_failure(op_vni(op), op_mac(op), now_ms)
                        }
                    };
                    let retry_in_ms =
                        u32::try_from(next_due_ms.saturating_sub(now_ms)).unwrap_or(u32::MAX);
                    failed.push(FailedOp {
                        vni: op_vni(op),
                        kind: op_to_kind(op),
                        error: err.to_string(),
                        retry_in_ms,
                    });
                    tracing::debug!(
                        ?class,
                        retry_in_ms,
                        ?op,
                        error = %err,
                        "dataplane op failed"
                    );
                }
            }
        }

        (applied, failed)
    }

    /// On successful apply, mirror state into `owned` so the next
    /// diff pass treats the entry as ours and the next failure
    /// schedule resets.
    fn record_success(&mut self, op: &DataplaneOp, desired: &RemoteMacTable) {
        match op {
            DataplaneOp::AddRemoteFdb { vni, mac, dst }
            | DataplaneOp::UpdateRemoteFdb { vni, mac, dst } => {
                let seq = desired.get(*vni, *mac).and_then(|e| e.mobility_sequence);
                self.state.owned.record_applied(
                    *vni,
                    *mac,
                    OwnedEntry {
                        last_applied_dst: *dst,
                        last_applied_seq: seq,
                    },
                );
            }
            DataplaneOp::RemoveRemoteFdb { vni, mac } => {
                self.state.owned.record_withdrawn(*vni, *mac);
            }
        }
        self.state.retry.record_success(op_vni(op), op_mac(op));
    }

    /// Send a report, dropping it if the daemon-side receiver has gone
    /// away (it shouldn't during normal operation, but it's not worth
    /// crashing the actor over).
    async fn emit_report(
        &self,
        instance_status: Vec<InstanceDataplaneStatus>,
        applied: Vec<AppliedOp>,
        failed: Vec<FailedOp>,
    ) {
        let report = DataplaneReport {
            intent_generation: self.state.last_intent_generation,
            reconcile_generation: self.state.reconcile_generation,
            instance_status,
            applied,
            failed,
        };
        if let Err(e) = self.report_tx.send(report).await {
            tracing::trace!(error = %e, "report receiver gone; report dropped");
        }
    }

    /// Shutdown drain (ADR-0054 §7). Withdraw every owned remote FDB
    /// entry within `drain_timeout`; if the timeout fires, exit
    /// without finishing — the next startup's reconcile cleans up.
    async fn drain(&mut self) {
        if self.state.owned.is_empty() {
            return;
        }

        let drain_fut = async {
            let owned_keys: Vec<_> = self.state.owned.keys().into_iter().collect();
            for (vni, mac) in owned_keys {
                let op = DataplaneOp::RemoveRemoteFdb { vni, mac };
                if let Err(e) = self.dataplane.apply(&op).await {
                    tracing::debug!(error = %e, ?op, "drain apply failed");
                    // Best-effort — keep going. Foreign entries in
                    // the kernel are never touched by `apply` for
                    // RemoveRemoteFdb in either the real or fake
                    // impl.
                } else {
                    self.state.owned.record_withdrawn(vni, mac);
                }
            }
        };

        if tokio::time::timeout(self.config.drain_timeout, drain_fut)
            .await
            .is_err()
        {
            tracing::warn!(
                remaining = self.state.owned.len(),
                "drain timeout exceeded; remaining owned FDB entries left for next startup"
            );
        }
    }
}

/// Helper — async sleep until an optional `Instant`. If `None`, sleeps
/// forever (`tokio::select!` with this branch effectively disables it).
async fn wait_until(deadline: Option<Instant>) {
    match deadline {
        Some(when) => sleep_until(when).await,
        None => std::future::pending::<()>().await,
    }
}

/// Build the per-instance status block for a [`DataplaneReport`].
fn build_instance_status(
    instances: &EvpnInstanceTable,
    probes: &InstanceProbes,
) -> Vec<InstanceDataplaneStatus> {
    let mut rows: Vec<InstanceDataplaneStatus> = instances
        .iter()
        .map(|inst| {
            let (state, message) = match probes.get(inst.id) {
                Some(InstanceProbe::Ready) => (InstanceState::Ready, None),
                Some(InstanceProbe::NotReady { reason }) => {
                    (InstanceState::NotReady, Some(reason.clone()))
                }
                Some(InstanceProbe::Unbound) => (InstanceState::Unbound, None),
                None => {
                    if inst.bridge.is_none() {
                        (InstanceState::Unbound, None)
                    } else {
                        (InstanceState::NotReady, Some("not yet probed".into()))
                    }
                }
            };
            InstanceDataplaneStatus {
                vni: inst.id,
                state,
                message,
            }
        })
        .collect();
    rows.sort_by_key(|r| r.vni);
    rows
}

fn op_vni(op: &DataplaneOp) -> rustbgpd_evpn::EvpnInstanceId {
    match op {
        DataplaneOp::AddRemoteFdb { vni, .. }
        | DataplaneOp::UpdateRemoteFdb { vni, .. }
        | DataplaneOp::RemoveRemoteFdb { vni, .. } => *vni,
    }
}

fn op_mac(op: &DataplaneOp) -> rustbgpd_evpn::MacAddress {
    match op {
        DataplaneOp::AddRemoteFdb { mac, .. }
        | DataplaneOp::UpdateRemoteFdb { mac, .. }
        | DataplaneOp::RemoveRemoteFdb { mac, .. } => *mac,
    }
}

fn op_to_kind(op: &DataplaneOp) -> DataplaneOpKind {
    match op {
        DataplaneOp::AddRemoteFdb { mac, dst, .. } => DataplaneOpKind::AddRemoteFdb {
            mac: *mac,
            dst: *dst,
        },
        DataplaneOp::UpdateRemoteFdb { mac, dst, .. } => DataplaneOpKind::UpdateRemoteFdb {
            mac: *mac,
            dst: *dst,
        },
        DataplaneOp::RemoveRemoteFdb { mac, .. } => DataplaneOpKind::RemoveRemoteFdb { mac: *mac },
    }
}

fn op_to_applied(op: &DataplaneOp) -> AppliedOp {
    AppliedOp {
        vni: op_vni(op),
        kind: op_to_kind(op),
    }
}

// Suppress dead-code on a potentially-unused snapshot return-path
// helper used only when the dump errors.
#[allow(dead_code)]
fn empty_snapshot() -> KernelSnapshot {
    KernelSnapshot::new()
}
