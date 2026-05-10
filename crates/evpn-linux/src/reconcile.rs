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
//! both the [`crate::InMemoryDataplane`] fake and the `LinuxDataplane`
//! real impl. The trait's native `async fn` means no `dyn Dataplane`
//! boxing.
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

use std::collections::BTreeMap;

use rustbgpd_evpn::{EvpnInstanceId, MacAddress};

use crate::backoff::RetrySchedule;
use crate::dataplane::{Dataplane, DataplaneOp, KernelEvent};
use crate::diff::{Plan, compute_diff};
use crate::enforcement::build_bum_enforcement_status;
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
    /// Apply `SetBumPortFlags` ops to the kernel (Gate 8b). When
    /// `false` (default), the actor still computes the resolved
    /// `BumPortFlagPlan` and surfaces it via `DataplaneReport.
    /// bum_enforcement` for operator visibility, but never emits the
    /// kernel-mutation ops — same observe-only posture Gate 8 ships.
    /// Operators flip this to `true` once the privileged-runner soak
    /// validates enforcement on their kernel.
    pub apply_bum_enforcement: bool,
}

impl ReconcileActorConfig {
    /// Production defaults (ADR-0054 §6/§7).
    #[must_use]
    pub const fn production() -> Self {
        Self {
            periodic_dump: Duration::from_mins(1),
            coalesce_window: Duration::from_millis(50),
            drain_timeout: Duration::from_secs(5),
            skip_initial_dump: false,
            apply_bum_enforcement: false,
        }
    }

    /// Test-friendly defaults — everything compressed so paused-time
    /// tests don't need to advance virtual time by minutes.
    #[must_use]
    pub const fn for_tests() -> Self {
        Self {
            periodic_dump: Duration::from_mins(1), // explicit advance in tests
            coalesce_window: Duration::from_millis(0),
            drain_timeout: Duration::from_secs(5),
            skip_initial_dump: false,
            apply_bum_enforcement: false,
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
    /// Retry schedule for FDB ops, keyed by `(VNI, MAC)`.
    retry: RetrySchedule<(EvpnInstanceId, MacAddress)>,
    /// Per-op-fingerprint suppression for permanent FDB failures.
    /// Keyed by `(VNI, MAC)`; the value is the exact [`DataplaneOp`]
    /// that hit the permanent failure (e.g.,
    /// `AddRemoteFdb { dst: X }`).
    ///
    /// The actor consults this in apply: if the *current* op for
    /// `(VNI, MAC)` equals the recorded op, suppress the apply.
    /// When the operator changes the route — different remote VTEP
    /// after MAC mobility, different op kind because the entry
    /// transitioned add→update→remove — the equality fails and the
    /// op is re-attempted. This is per-key, fingerprint-based: an
    /// unrelated `RemoteMacTable` change for *other* keys does not
    /// clear suppression on the failed key, which is what
    /// generation-wide clearing would do.
    permanent_failures: BTreeMap<(EvpnInstanceId, MacAddress), DataplaneOp>,
    /// Retry schedule for Gate 8b BUM port-flag ops, keyed by
    /// CE-port ifindex. Independent from the FDB schedule so the
    /// two op shapes never collide on the key space.
    bum_retry: RetrySchedule<u32>,
    /// Per-ifindex permanent-failure suppression for BUM port-flag
    /// ops. Same fingerprint-equality semantics as the FDB map: a
    /// new flag triplet for the same ifindex clears the suppression.
    bum_permanent_failures: BTreeMap<u32, DataplaneOp>,
    /// Last `intent_generation` we successfully reconciled against.
    /// Reports echo this so the daemon can correlate.
    last_intent_generation: u64,
    /// Monotonic reconcile-pass counter for telemetry / debugging.
    reconcile_generation: u64,
    /// Anchor for retry-schedule millisecond timestamps. The schedule
    /// is purely about *relative* delays, so the anchor doesn't have
    /// to be wall-clock — `Instant` since `start` works.
    epoch: Instant,
    /// Last `BumPortFlagPlan` snapshot we believe is in the kernel,
    /// keyed by ifindex. Updated **per-port on apply success** so a
    /// failed port keeps its prior value and the next reconcile pass
    /// re-emits the op via `diff_flag_plans`. With
    /// `apply_bum_enforcement = false` the map tracks the
    /// last-resolved plan as the observe-only baseline so repeated
    /// reports do not emit would-have-applied diffs. Enabling kernel
    /// mutation is restart-required; a fresh actor starts with an
    /// empty baseline.
    last_bum_plan: BTreeMap<u32, crate::bum_filter::BumPortFlags>,
}

impl ActorState {
    fn new() -> Self {
        Self {
            owned: OwnedSet::new(),
            retry: RetrySchedule::new(),
            permanent_failures: BTreeMap::new(),
            bum_retry: RetrySchedule::new(),
            bum_permanent_failures: BTreeMap::new(),
            last_intent_generation: 0,
            reconcile_generation: 0,
            epoch: Instant::now(),
            last_bum_plan: BTreeMap::new(),
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
            // Compute the next retry deadline across both retry
            // schedules — FDB ops keyed by `(VNI, MAC)` and BUM ops
            // keyed by ifindex. The earlier of the two wakes the
            // actor.
            let next_fdb = self.state.retry.earliest_due();
            let next_bum = self.state.bum_retry.earliest_due();
            let retry_due = match (next_fdb, next_bum) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(x), None) | (None, Some(x)) => Some(x),
                (None, None) => None,
            }
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
                    // `LocalMacObservation` flows on the dedicated
                    // channel surfaced by [`Dataplane::take_local_mac_rx`]
                    // — it bypasses this actor entirely. Keeping the
                    // two upward flows split avoids coupling the
                    // reconcile actor's lifetime to the originator's
                    // channel layout (ADR-0054 §1).
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
        // Permanent-failure suppression is per-op-fingerprint and
        // cleared lazily in apply_plan when the op shape for a
        // suppressed key changes — there's no generation-wide clear
        // here because that would let unrelated RemoteMacTable
        // churn re-arm permanent failures on other keys.
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
                let bum_enforcement =
                    build_bum_enforcement_status(&intent.bum_enforcement, &KernelSnapshot::new());
                self.emit_report(status, vec![], vec![], bum_enforcement)
                    .await;
                return;
            }
        };

        let mut plan = compute_diff(
            intent.remote_macs.as_ref(),
            &snapshot,
            &self.state.owned,
            &probes,
        );

        // Resolve the BUM-enforcement plan early so the same row set
        // both feeds report observability and (when enabled) drives
        // kernel mutation. Diffed against last_bum_plan so we only
        // emit ops for ifindexes whose desired flag triplet actually
        // changed — idempotent at the netlink boundary.
        let bum_enforcement = build_bum_enforcement_status(&intent.bum_enforcement, &snapshot);
        let new_bum_plan = crate::bum_filter::compute_flag_plan(&bum_enforcement);
        let prior_bum_plan: Vec<crate::bum_filter::BumPortFlagPlan> = self
            .state
            .last_bum_plan
            .iter()
            .map(|(&ifindex, &flags)| crate::bum_filter::BumPortFlagPlan { ifindex, flags })
            .collect();
        let bum_changes = crate::bum_filter::diff_flag_plans(&prior_bum_plan, &new_bum_plan);
        if self.config.apply_bum_enforcement {
            // Append the BUM ops to the same plan so the existing
            // apply_plan loop dispatches them through Dataplane::apply
            // alongside FDB ops — same retry-state framework (with a
            // separate, ifindex-keyed retry map), same report
            // accounting.
            for change in &bum_changes {
                plan.ops.push(DataplaneOp::SetBumPortFlags {
                    ifindex: change.ifindex,
                    flags: change.flags,
                });
            }
        }

        let (applied, failed) = self.apply_plan(&plan, intent.remote_macs.as_ref()).await;

        // Update the last-applied BUM plan **per port**:
        // - With `apply_bum_enforcement = false` no kernel mutation
        //   happens; record `new_bum_plan` directly as the
        //   observe-only baseline.
        // - With apply enabled, only update the entry for ports
        //   whose op succeeded. Failed ports keep their prior
        //   recorded state so the next reconcile pass re-runs the
        //   diff against the right baseline and re-emits the op.
        if self.config.apply_bum_enforcement {
            // Build the set of ifindexes whose op succeeded this pass.
            let succeeded: std::collections::BTreeSet<u32> = applied
                .iter()
                .filter_map(|a| match a.kind {
                    DataplaneOpKind::SetBumPortFlags { ifindex } => Some(ifindex),
                    _ => None,
                })
                .collect();
            for change in &bum_changes {
                if succeeded.contains(&change.ifindex) {
                    if change.flags == crate::bum_filter::BumPortFlags::allow_all()
                        && !new_bum_plan.iter().any(|p| p.ifindex == change.ifindex)
                    {
                        // The change was a "restore disappeared port
                        // to allow_all" path — drop the entry so the
                        // map mirrors the new desired plan exactly.
                        self.state.last_bum_plan.remove(&change.ifindex);
                    } else {
                        self.state
                            .last_bum_plan
                            .insert(change.ifindex, change.flags);
                    }
                }
                // else: failed → leave last_bum_plan[ifindex] as-is
                // so the next pass's diff still produces the op.
            }
        } else {
            // Observe-only mode: record the would-have-applied plan
            // verbatim so repeated reports remain stable. Runtime
            // apply-mode flips are restart-required; the next daemon
            // start builds a fresh actor with an empty applied-state
            // baseline.
            self.state.last_bum_plan = new_bum_plan.iter().map(|p| (p.ifindex, p.flags)).collect();
        }

        let status = build_instance_status(&intent.instances, &probes);
        self.emit_report(status, applied, failed, bum_enforcement)
            .await;
    }

    /// Apply each op in the plan, recording successes in `owned` and
    /// failures in the retry schedule. Returns `(applied, failed)` for
    /// inclusion in the report.
    ///
    /// Two gating layers run before each apply:
    ///
    /// 1. **Per-op-fingerprint permanent suppression.** If the
    ///    current op for `(VNI, MAC)` equals the op recorded in
    ///    `permanent_failures` for that key, skip — repeating a
    ///    permanent failure (`PermissionDenied` / `KernelTooOld` /
    ///    `InvalidArgument`) won't help. If the op shape *differs*
    ///    (e.g., the operator changed the remote VTEP after MAC
    ///    mobility, or transitioned add → remove), the suppression
    ///    is cleared inline and the op runs.
    /// 2. **Per-op transient backoff.** Ops whose `(VNI, MAC)` key
    ///    is in the retry schedule and not yet due are skipped; the
    ///    actor's outer `tokio::select!` re-fires on the retry timer
    ///    so a deferred op runs as soon as its backoff elapses.
    #[allow(clippy::too_many_lines)] // per-op-shape dispatch is naturally long; further extraction hurts readability
    async fn apply_plan(
        &mut self,
        plan: &Plan,
        desired: &RemoteMacTable,
    ) -> (Vec<AppliedOp>, Vec<FailedOp>) {
        let mut applied = Vec::with_capacity(plan.len());
        let mut failed = Vec::new();
        let now_ms = self.state.now_ms();

        for op in &plan.ops {
            // Permanent-failure suppression — dispatched per op shape
            // so BUM port-flag ops use their ifindex-keyed map and
            // FDB ops use their (VNI, MAC) map. No sentinel-key
            // collision risk.
            let permanently_suppressed = if let DataplaneOp::SetBumPortFlags { ifindex, .. } = op {
                if let Some(recorded) = self.state.bum_permanent_failures.get(ifindex) {
                    if recorded == op {
                        tracing::trace!(
                            ?op,
                            "suppressed (permanent BUM failure, op shape unchanged)"
                        );
                        true
                    } else {
                        tracing::debug!(
                            ?op,
                            recorded = ?recorded,
                            "BUM op shape changed since permanent failure; clearing suppression"
                        );
                        self.state.bum_permanent_failures.remove(ifindex);
                        false
                    }
                } else {
                    false
                }
            } else {
                let fdb_key = (fdb_op_vni(op), fdb_op_mac(op));
                if let Some(recorded) = self.state.permanent_failures.get(&fdb_key) {
                    if recorded == op {
                        tracing::trace!(
                            ?op,
                            "suppressed (permanent FDB failure, op shape unchanged)"
                        );
                        true
                    } else {
                        tracing::debug!(
                            ?op,
                            recorded = ?recorded,
                            "FDB op shape changed since permanent failure; clearing suppression"
                        );
                        self.state.permanent_failures.remove(&fdb_key);
                        false
                    }
                } else {
                    false
                }
            };
            if permanently_suppressed {
                continue;
            }

            // Transient retry gating — skip until the per-op
            // exponential-backoff deadline passes. Same per-shape
            // dispatch as permanent suppression.
            let next_due_ms_opt = match op {
                DataplaneOp::SetBumPortFlags { ifindex, .. } => {
                    self.state.bum_retry.next_due_for(*ifindex)
                }
                _ => self
                    .state
                    .retry
                    .next_due_for((fdb_op_vni(op), fdb_op_mac(op))),
            };
            if let Some(next_due_ms) = next_due_ms_opt
                && next_due_ms > now_ms
            {
                let retry_in_ms =
                    u32::try_from(next_due_ms.saturating_sub(now_ms)).unwrap_or(u32::MAX);
                tracing::trace!(?op, retry_in_ms, "deferred (backoff not elapsed)");
                continue;
            }

            let res = self.dataplane.apply(op).await;
            match res {
                Ok(()) => {
                    self.record_success(op, desired);
                    applied.push(op_to_applied(op));
                }
                Err(err) => {
                    let class = err.class();
                    let fdb_key_for_failed = (fdb_op_vni(op), fdb_op_mac(op));
                    match class {
                        FailureClass::Transient | FailureClass::Conflict => {
                            let next_due_ms = match op {
                                DataplaneOp::SetBumPortFlags { ifindex, .. } => {
                                    self.state.bum_retry.record_failure(*ifindex, now_ms)
                                }
                                _ => self.state.retry.record_failure(fdb_key_for_failed, now_ms),
                            };
                            let retry_in_ms = u32::try_from(next_due_ms.saturating_sub(now_ms))
                                .unwrap_or(u32::MAX);
                            failed.push(FailedOp {
                                vni: fdb_key_for_failed.0,
                                kind: op_to_kind(op),
                                error: err.to_string(),
                                retry_in_ms,
                            });
                            tracing::debug!(
                                ?class,
                                retry_in_ms,
                                ?op,
                                error = %err,
                                "dataplane op failed; will retry"
                            );
                        }
                        FailureClass::Permanent => {
                            // Record the *exact op shape* under its
                            // op-shape-aware key. Subsequent passes
                            // suppress only when the shape matches; a
                            // mobility move (different dst) or
                            // op-kind change clears the suppression
                            // automatically. Drop from the transient
                            // retry schedule so we don't double-tick.
                            if let DataplaneOp::SetBumPortFlags { ifindex, .. } = op {
                                self.state.bum_retry.record_success(*ifindex);
                                self.state
                                    .bum_permanent_failures
                                    .insert(*ifindex, op.clone());
                            } else {
                                self.state.retry.record_success(fdb_key_for_failed);
                                self.state
                                    .permanent_failures
                                    .insert(fdb_key_for_failed, op.clone());
                            }
                            failed.push(FailedOp {
                                vni: fdb_key_for_failed.0,
                                kind: op_to_kind(op),
                                error: err.to_string(),
                                retry_in_ms: 0,
                            });
                            tracing::warn!(
                                ?op,
                                error = %err,
                                "dataplane op failed permanently; suppressed until op shape changes"
                            );
                        }
                    }
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
                self.state.retry.record_success((*vni, *mac));
            }
            DataplaneOp::RemoveRemoteFdb { vni, mac } => {
                self.state.owned.record_withdrawn(*vni, *mac);
                self.state.retry.record_success((*vni, *mac));
            }
            DataplaneOp::SetBumPortFlags { ifindex, .. } => {
                // BUM-port-flag ops do not interact with the FDB
                // OwnedSet — they program a different kernel surface
                // (bridge port `IFLA_PROTINFO` rather than FDB).
                // Clear the BUM-side retry schedule for the ifindex.
                self.state.bum_retry.record_success(*ifindex);
            }
        }
    }

    /// Send a report, dropping it if the daemon-side receiver has gone
    /// away (it shouldn't during normal operation, but it's not worth
    /// crashing the actor over).
    async fn emit_report(
        &self,
        instance_status: Vec<InstanceDataplaneStatus>,
        applied: Vec<AppliedOp>,
        failed: Vec<FailedOp>,
        bum_enforcement: Vec<rustbgpd_evpn::BumEnforcementStatus>,
    ) {
        let report = DataplaneReport {
            intent_generation: self.state.last_intent_generation,
            reconcile_generation: self.state.reconcile_generation,
            instance_status,
            applied,
            failed,
            bum_enforcement,
        };
        if let Err(e) = self.report_tx.send(report).await {
            tracing::trace!(error = %e, "report receiver gone; report dropped");
        }
    }

    /// Shutdown drain (ADR-0054 §7). Restore every BUM-suppressed CE
    /// port to `allow_all` and withdraw every owned remote FDB entry
    /// within `drain_timeout`; if the timeout fires, exit without
    /// finishing — the next startup's reconcile cleans up stale FDB
    /// entries. BUM restoration is best-effort because leaving a CE
    /// port suppressed after the daemon exits is more operator-hostile
    /// than a redundant allow-all write.
    async fn drain(&mut self) {
        let bum_restore_ops: Vec<_> = if self.config.apply_bum_enforcement {
            self.state
                .last_bum_plan
                .iter()
                .filter_map(|(&ifindex, &flags)| {
                    (flags != crate::bum_filter::BumPortFlags::allow_all()).then_some(
                        DataplaneOp::SetBumPortFlags {
                            ifindex,
                            flags: crate::bum_filter::BumPortFlags::allow_all(),
                        },
                    )
                })
                .collect()
        } else {
            Vec::new()
        };

        if self.state.owned.is_empty() && bum_restore_ops.is_empty() {
            return;
        }

        let drain_fut = async {
            for op in bum_restore_ops {
                let DataplaneOp::SetBumPortFlags { ifindex, .. } = op else {
                    unreachable!("BUM restore ops are always SetBumPortFlags")
                };
                if let Err(e) = self.dataplane.apply(&op).await {
                    tracing::debug!(error = %e, ?op, "BUM restore during drain failed");
                    // Best-effort — keep going so one stale ifindex
                    // doesn't prevent FDB drain.
                } else {
                    self.state.last_bum_plan.remove(&ifindex);
                    self.state.bum_retry.record_success(ifindex);
                    self.state.bum_permanent_failures.remove(&ifindex);
                }
            }

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
            // Bridge MAC is only meaningful when the bridge is Ready
            // and the kernel reported a six-octet link-layer address.
            // For NotReady / Unbound rows, leave it `None` — the SVI
            // task uses `state == Ready && bridge_mac == Some(_)` as
            // the precondition for origination.
            let bridge_mac = if matches!(state, InstanceState::Ready) {
                probes.bridge_mac(inst.id)
            } else {
                None
            };
            InstanceDataplaneStatus {
                vni: inst.id,
                state,
                message,
                bridge_mac,
            }
        })
        .collect();
    rows.sort_by_key(|r| r.vni);
    rows
}

/// VNI carried by an FDB op. BUM ops have no VNI surface — the
/// operator-facing key for BUM reports is the `kind` field, which
/// carries the ifindex. The placeholder VNI is only present because
/// `AppliedOp` / `FailedOp` predate BUM-port operations.
fn fdb_op_vni(op: &DataplaneOp) -> rustbgpd_evpn::EvpnInstanceId {
    match op {
        DataplaneOp::AddRemoteFdb { vni, .. }
        | DataplaneOp::UpdateRemoteFdb { vni, .. }
        | DataplaneOp::RemoveRemoteFdb { vni, .. } => *vni,
        DataplaneOp::SetBumPortFlags { .. } => {
            // VNI 0 is invalid in the domain type, so VNI 1 is the
            // harmless report placeholder.
            rustbgpd_evpn::EvpnInstanceId::new(1).expect("VNI 1 is always valid")
        }
    }
}

/// MAC carried by an FDB op. BUM ops have no MAC surface — the
/// report placeholder keeps the legacy `DataplaneOpKind` shape
/// harmless for BUM rows.
fn fdb_op_mac(op: &DataplaneOp) -> rustbgpd_evpn::MacAddress {
    match op {
        DataplaneOp::AddRemoteFdb { mac, .. }
        | DataplaneOp::UpdateRemoteFdb { mac, .. }
        | DataplaneOp::RemoveRemoteFdb { mac, .. } => *mac,
        DataplaneOp::SetBumPortFlags { .. } => rustbgpd_evpn::MacAddress::new([0; 6]),
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
        DataplaneOp::SetBumPortFlags { ifindex, .. } => {
            DataplaneOpKind::SetBumPortFlags { ifindex: *ifindex }
        }
    }
}

fn op_to_applied(op: &DataplaneOp) -> AppliedOp {
    AppliedOp {
        vni: fdb_op_vni(op),
        kind: op_to_kind(op),
    }
}

// Suppress dead-code on a potentially-unused snapshot return-path
// helper used only when the dump errors.
#[allow(dead_code)]
fn empty_snapshot() -> KernelSnapshot {
    KernelSnapshot::new()
}
