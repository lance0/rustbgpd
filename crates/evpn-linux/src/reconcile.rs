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

use rustbgpd_evpn::ip_vrf::IpVrfStatus;
use rustbgpd_evpn::{EvpnInstanceId, IpVrfId, MacAddress};

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
    /// Last `IpVrfStatus` we observed for each configured IP-VRF, used
    /// to detect transitions (`Ready` ↔ `NotReady`, or a change in the
    /// failing-predicate set) so the per-pass `probe_ip_vrfs` call
    /// only logs when state actually changes. An IP-VRF that drops out
    /// of the intent (operator removed the `[[evpn_ip_vrfs]]` entry)
    /// is removed from this map on the next pass.
    last_ip_vrf_status: BTreeMap<IpVrfId, IpVrfStatus>,
    /// L3 owned set: installed routes, refcounted neighbor entries,
    /// refcounted L3VXLAN FDB entries (Gate 9 slice 6c). Updated
    /// only on successful kernel apply; a failed op leaves the
    /// in-memory state unchanged so the next reconcile pass retries.
    l3_owned: crate::l3_diff::L3OwnedState,
    /// ADR-0059 slice 3b: NHID allocator + per-group refcount state
    /// for FDB nexthop groups. Constructed empty; populated during
    /// the first reconcile pass by the startup-adoption helper, then
    /// by `record_success` as `InstallFdbNhg` / `UpdateFdbNhgMembers`
    /// / `RemoveFdbNhg` ops land.
    nh_id_alloc: crate::nh_id_alloc::NhIdAllocator,
    /// FDB nexthop group + per-VTEP NH refcount map (ADR-0059 slice 3b).
    /// Coordinator updates this on every apply; `compute_diff` reads it
    /// to decide whether a `UpdateFdbNhgMembers` is needed.
    groups: crate::group_state::GroupOwnedMap,
    /// IDs the startup-adoption pass reserved from the kernel dump but
    /// has not yet matched against a `GroupOwnedMap` entry. After the
    /// first successful reconcile, the cleanup phase walks this set
    /// and deletes anything still here (true stale state from a prior
    /// crashed daemon). Drained as the coordinator records groups.
    adopted_unreferenced: BTreeMap<u32, crate::dataplane::KernelNexthop>,
    /// `true` once the first reconcile pass has completed adoption +
    /// stale cleanup. Gates the one-shot adoption/cleanup phase so
    /// subsequent passes skip the dump + sweep.
    adoption_done: bool,
    /// Tracks whether [`Dataplane::next_event`] is still expected to
    /// yield events. `true` at startup; flipped to `false` the first
    /// time `next_event()` resolves to `None`. While `false` the
    /// outer `tokio::select!` disables its `next_event` arm via an
    /// `if` guard — without the gate, a future that always resolves
    /// to `None` (the natural shape for a closed `mpsc::Receiver`)
    /// would spin the biased select branch and starve the
    /// periodic / retry / shutdown work that follows it.
    event_stream_open: bool,
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
            last_ip_vrf_status: BTreeMap::new(),
            l3_owned: crate::l3_diff::L3OwnedState::default(),
            event_stream_open: true,
            nh_id_alloc: crate::nh_id_alloc::NhIdAllocator::new(),
            groups: crate::group_state::GroupOwnedMap::new(),
            adopted_unreferenced: BTreeMap::new(),
            adoption_done: false,
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

impl<D: Dataplane + crate::dataplane::NexthopOps> ReconcileActor<D> {
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
                evt = self.dataplane.next_event(), if self.state.event_stream_open => {
                    match evt {
                        Some(KernelEvent::KernelStateChanged) => {
                            self.coalesce_and_reconcile().await;
                        }
                        Some(KernelEvent::LocalMacObservation(_)) => {
                            // Routed via `take_local_mac_rx` directly
                            // to the daemon's local-MAC originator
                            // task; the reconcile actor doesn't act on
                            // it. If an alternate `Dataplane` impl
                            // ever surfaces a `LocalMacObservation`
                            // here (the trait permits it), silently
                            // drop — re-running `coalesce_and_reconcile`
                            // wouldn't help, and waking would conflict
                            // with the originator task's own watch
                            // channel.
                        }
                        None => {
                            // Implementation closed its event stream
                            // (`LinuxDataplane`'s notify task exited
                            // and dropped the `kernel_event_tx`, or a
                            // test impl reached end-of-stream). Flip
                            // the guard so the next iteration's
                            // `tokio::select!` disables this arm —
                            // without that gate, `next_event()` keeps
                            // resolving to `None` immediately on every
                            // poll (the closed-channel `recv()`
                            // shape), and because the select is
                            // `biased` and this arm sits before the
                            // periodic / retry / shutdown arms, the
                            // actor would spin and starve the rest
                            // of the work.
                            self.state.event_stream_open = false;
                            tracing::warn!(
                                "kernel-event stream closed; reconcile actor will rely on periodic dump + retry only"
                            );
                        }
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
    #[allow(clippy::too_many_lines)]
    async fn reconcile_once(&mut self) {
        self.state.reconcile_generation = self.state.reconcile_generation.saturating_add(1);

        // ADR-0059 slice 3b: one-shot startup adoption. Dump tagged
        // nexthops from the kernel and reserve their IDs in the
        // allocator before any `compute_diff` Pass 1b emission, so
        // a fresh `InstallFdbNhg` can't collide with an ID left
        // behind by a prior daemon instance. The adopted set is
        // cleared as the coordinator records each ID in `groups`;
        // whatever remains after `apply_plan` is true stale state
        // and gets GC'd by `cleanup_unreferenced_adoptions` below.
        //
        // `dump_succeeded` carries to the post-apply gate so a failed
        // dump (which leaves the allocator without reservations for
        // any pre-existing kernel NHIDs) does NOT flip `adoption_done`
        // to true. Without this, a dump failure on the first pass would
        // permanently strand collision risk: future passes would emit
        // `InstallFdbNhg` against an under-reserved allocator and the
        // re-dump path would never run.
        let mut dump_succeeded = true;
        if !self.state.adoption_done {
            match self.dataplane.dump_owned_nexthops().await {
                Ok(adopted) => {
                    for nh in adopted {
                        match self.state.nh_id_alloc.reserve(nh.id) {
                            Ok(()) => {
                                self.state.adopted_unreferenced.insert(nh.id, nh);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    ?e,
                                    id = nh.id,
                                    "adoption: reserve failed; ignoring"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    // Dump failed — log + leave adoption_done false so
                    // the next reconcile pass re-attempts the dump
                    // before any FDB-NHG ops are applied against an
                    // under-reserved allocator.
                    tracing::warn!(error = %e, "adoption: dump_owned_nexthops failed");
                    dump_succeeded = false;
                }
            }
        }

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

        // Gate 9 IP-VRF readiness pass. `probe_ip_vrfs` short-circuits
        // when the intent's `IpVrfTable` is empty (Gate 9 opt-in via
        // `[[evpn_ip_vrfs]]`), so L2-only and RR-only deployments
        // never pay the netlink dump cost. Transitions are logged at
        // info / warn; steady-state is silent.
        let ip_vrf_status_map = self.dataplane.probe_ip_vrfs(&intent.ip_vrfs).await;
        Self::log_ip_vrf_transitions(&mut self.state.last_ip_vrf_status, &ip_vrf_status_map);
        let ip_vrf_status = build_ip_vrf_status(&intent.ip_vrfs, &ip_vrf_status_map);

        // Gate 9 slice 6a: dump kernel routes per IP-VRF's `table_id`
        // and emit per-VRF observations on the report. Short-circuits
        // when the intent's `IpVrfTable` is empty (Gate 9 opt-in via
        // `[[evpn_ip_vrfs]]`), so L2-only and RR-only deployments
        // never pay the netlink dump cost.
        let ip_vrf_routes = self.dataplane.dump_ip_vrf_routes(&intent.ip_vrfs).await;

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
                self.emit_report(
                    status,
                    vec![],
                    vec![],
                    bum_enforcement,
                    ip_vrf_status,
                    ip_vrf_routes,
                )
                .await;
                return;
            }
        };

        let mut plan = compute_diff(
            intent.remote_macs.as_ref(),
            &snapshot,
            &self.state.owned,
            &probes,
            &self.state.groups,
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

        // ADR-0059 slice 3b: one-shot stale-NHID cleanup. Anything
        // still in `adopted_unreferenced` after the first reconcile's
        // apply phase is owned by us (tag bits + FDB-NHG kind) but
        // not referenced by any MAC in `groups` — i.e., true stale
        // state from a prior daemon instance. Delete + release.
        //
        // Only mark adoption complete when the pass had no apply
        // failures, the dump succeeded, and every staged stale-delete
        // succeeded — if any of those is false, `adopted_unreferenced`
        // is incomplete OR the allocator hasn't fully reserved
        // pre-existing kernel IDs. Defer cleanup to the next reconcile
        // so a fresh dump can re-seed reservations before we
        // accidentally delete a not-yet-adopted ID, or release an
        // allocator slot whose ID is still live in the kernel.
        if !self.state.adoption_done && failed.is_empty() && dump_succeeded {
            let cleanup_ok = self.cleanup_unreferenced_adoptions().await;
            if cleanup_ok {
                self.state.adoption_done = true;
            }
        }

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

        // Gate 9 slice 6c: drive the L3 install pipeline. Pure-
        // function diff computes the ops from
        // `intent.remote_ip_prefixes` vs the actor's `l3_owned`
        // refcounted set; we then apply them sequentially and
        // record successes back into the owned state. Failures
        // leave the owned state unchanged so the next reconcile
        // pass retries with the same shape.
        //
        // Skip the whole loop only when **both** the intent and
        // the owned state are empty — the zero-cost RR-only
        // deployment path. If config reload (or SIGHUP-driven
        // removal of every `[[evpn_ip_vrfs]]` entry) leaves
        // `intent.ip_vrfs` empty but `l3_owned` non-empty, the
        // diff still has work to do: it must drain every owned
        // route / neighbor / FDB row, otherwise the kernel keeps
        // forwarding through L3VXLAN devices whose IP-VRF
        // configuration is gone. The diff handles empty intent
        // naturally — `desired_*` sets evaluate empty and Phase D
        // removals fire for every kernel row.
        if !intent.ip_vrfs.is_empty() || !self.state.l3_owned.is_empty() {
            let ready_l3vxlan_ifindex: std::collections::BTreeMap<IpVrfId, u32> = ip_vrf_status_map
                .iter()
                .filter_map(|(id, status)| match status {
                    rustbgpd_evpn::ip_vrf::IpVrfStatus::Ready {
                        l3vxlan_ifindex, ..
                    } => Some((*id, *l3vxlan_ifindex)),
                    rustbgpd_evpn::ip_vrf::IpVrfStatus::NotReady { .. } => None,
                })
                .collect();
            let l3_plan = crate::l3_diff::compute_l3_diff(
                intent.remote_ip_prefixes.as_ref(),
                &self.state.l3_owned,
                &ready_l3vxlan_ifindex,
                intent.ip_vrfs.as_ref(),
            );
            for drop in &l3_plan.drops {
                tracing::debug!(?drop, "L3 install drop");
            }
            // Apply-time fail-stop: an `AddRemoteIpRoute` whose
            // prerequisite `AddL3Neighbor` or `AddL3VxlanFdb` failed
            // earlier in this pass MUST NOT proceed — otherwise the
            // kernel ends up with a `proto bgp / onlink` route
            // pointing at an unresolved L3VXLAN path, and operators
            // see `installed_routes_count` incremented even though
            // forwarding is broken. The diff's phase ordering
            // (resolution adds in phase B, route adds in phase C)
            // guarantees that by the time we reach an
            // `AddRemoteIpRoute`, every prerequisite resolution add
            // in *this* plan has already been attempted, so the
            // failed-key sets are complete. Prerequisites already
            // present in `l3_owned` from a prior pass are not in
            // these sets — those routes are free to install.
            let mut failed_neighbor_keys: std::collections::HashSet<(u32, std::net::IpAddr)> =
                std::collections::HashSet::new();
            let mut failed_fdb_keys: std::collections::HashSet<(u32, MacAddress)> =
                std::collections::HashSet::new();
            for op in &l3_plan.ops {
                if let crate::dataplane::DataplaneOp::AddRemoteIpRoute {
                    l3vxlan_ifindex,
                    next_hop,
                    router_mac,
                    ..
                } = op
                {
                    let neigh_failed =
                        failed_neighbor_keys.contains(&(*l3vxlan_ifindex, *next_hop));
                    let fdb_failed = failed_fdb_keys.contains(&(*l3vxlan_ifindex, *router_mac));
                    if neigh_failed || fdb_failed {
                        tracing::warn!(
                            ?op,
                            neigh_failed,
                            fdb_failed,
                            "skipping AddRemoteIpRoute — prerequisite L3 resolution add failed in this pass; next reconcile will retry"
                        );
                        continue;
                    }
                }
                match self.dataplane.apply(op).await {
                    Ok(()) => {
                        crate::l3_diff::record_l3_success(
                            &mut self.state.l3_owned,
                            op,
                            &ready_l3vxlan_ifindex,
                            intent.ip_vrfs.as_ref(),
                            intent.remote_ip_prefixes.as_ref(),
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            ?op,
                            "L3 op failed; preserving owned state for next reconcile retry"
                        );
                        match op {
                            crate::dataplane::DataplaneOp::AddL3Neighbor {
                                l3vxlan_ifindex,
                                next_hop,
                                ..
                            } => {
                                failed_neighbor_keys.insert((*l3vxlan_ifindex, *next_hop));
                            }
                            crate::dataplane::DataplaneOp::AddL3VxlanFdb {
                                l3vxlan_ifindex,
                                router_mac,
                                ..
                            } => {
                                failed_fdb_keys.insert((*l3vxlan_ifindex, *router_mac));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        let status = build_instance_status(&intent.instances, &probes);
        self.emit_report(
            status,
            applied,
            failed,
            bum_enforcement,
            ip_vrf_status,
            ip_vrf_routes,
        )
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

            // ADR-0059 slice 3b: FDB-NHG ops require allocator +
            // refcount state owned by the actor. Route them through
            // the coordinator helper instead of `Dataplane::apply`,
            // which would reject them with `InvalidArgument`.
            let res = match op {
                DataplaneOp::InstallFdbNhg { .. }
                | DataplaneOp::UpdateFdbNhgMembers { .. }
                | DataplaneOp::RemoveFdbNhg { .. } => {
                    apply_nhg_op(&mut self.dataplane, &mut self.state, op).await
                }
                _ => self.dataplane.apply(op).await,
            };
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

    /// ADR-0059 slice 3b cleanup helper: walk `adopted_unreferenced`
    /// after the first reconcile's apply phase and delete any
    /// rustbgpd-tagged kernel nexthop that didn't get claimed by a
    /// MAC's group during apply. These are stale state from a prior
    /// daemon instance.
    ///
    /// Returns `true` only when every staged delete succeeded. On
    /// per-ID failure the allocator slot stays reserved and the entry
    /// stays in `adopted_unreferenced` so the next reconcile pass can
    /// retry — releasing the slot on a transient netlink failure would
    /// let a future `alloc_vtep_nh` / `alloc_nhg` hand out an ID that
    /// still exists in the kernel, exactly the collision adoption is
    /// supposed to prevent.
    async fn cleanup_unreferenced_adoptions(&mut self) -> bool {
        // Drain to avoid holding the borrow across the await.
        let stale: Vec<u32> = self.state.adopted_unreferenced.keys().copied().collect();
        let mut all_ok = true;
        for id in stale {
            // del_nexthop is idempotent on ENOENT (slice 2). Only
            // release + drop tracking on Ok — on Err, leave the slot
            // reserved + the entry in the map so the next reconcile
            // pass retries.
            match self.dataplane.del_nexthop(id).await {
                Ok(()) => {
                    self.state.nh_id_alloc.release(id);
                    self.state.adopted_unreferenced.remove(&id);
                }
                Err(e) => {
                    tracing::warn!(
                        ?e,
                        id,
                        "adoption cleanup: del_nexthop failed; leaving reserved for next pass"
                    );
                    all_ok = false;
                }
            }
        }
        all_ok
    }

    /// On successful apply, mirror state into `owned` so the next
    /// diff pass treats the entry as ours and the next failure
    /// schedule resets.
    fn record_success(&mut self, op: &DataplaneOp, desired: &RemoteMacTable) {
        match op {
            DataplaneOp::AddRemoteFdb { vni, mac, dst }
            | DataplaneOp::UpdateRemoteFdb { vni, mac, dst } => {
                let seq = desired.get(*vni, *mac).and_then(|e| e.mobility_sequence);
                self.state
                    .owned
                    .record_applied(*vni, *mac, OwnedEntry::single_dst(*dst, seq));
                self.state.retry.record_success((*vni, *mac));
            }
            DataplaneOp::RemoveRemoteFdb { vni, mac }
            | DataplaneOp::RemoveFdbNhg { vni, mac, .. } => {
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
            DataplaneOp::InstallFdbNhg {
                vni,
                mac,
                group_key,
                ..
            } => {
                // Record FDB-row ownership via the new group-aware kind.
                self.state
                    .owned
                    .record_applied(*vni, *mac, OwnedEntry::fdb_nhg(*group_key));
                self.state.retry.record_success((*vni, *mac));
            }
            // Gate 9 slice 6c L3 ops have their own owned-set and retry
            // tracking inside the L3 diff loop, handled by
            // `record_success_l3`. ADR-0059 slice 3 `UpdateFdbNhgMembers`
            // is a group-level update with no per-`(VNI, MAC)` owned-set
            // delta — the slice 3b coordinator updates `group_state`
            // separately. Both arms share the no-op body.
            DataplaneOp::AddRemoteIpRoute { .. }
            | DataplaneOp::RemoveRemoteIpRoute { .. }
            | DataplaneOp::AddL3Neighbor { .. }
            | DataplaneOp::RemoveL3Neighbor { .. }
            | DataplaneOp::AddL3VxlanFdb { .. }
            | DataplaneOp::RemoveL3VxlanFdb { .. }
            | DataplaneOp::UpdateFdbNhgMembers { .. } => {}
        }
    }

    /// Diff `current` IP-VRF readiness against `last` and emit one
    /// log line per VRF whose status changed. `last` is updated in
    /// place to reflect the new state. Steady-state is silent — this
    /// is structured-log output for an operator, not a metric.
    fn log_ip_vrf_transitions(
        last: &mut BTreeMap<IpVrfId, IpVrfStatus>,
        current: &std::collections::HashMap<IpVrfId, IpVrfStatus>,
    ) {
        for (id, status) in current {
            let changed = match last.get(id) {
                Some(prev) => prev != status,
                None => true,
            };
            if !changed {
                continue;
            }
            match status {
                IpVrfStatus::Ready {
                    vrf_ifindex,
                    l3vxlan_ifindex,
                    table_id,
                    ..
                } => {
                    tracing::info!(
                        vrf_id = id.as_u32(),
                        vrf_ifindex,
                        l3vxlan_ifindex,
                        table_id,
                        "IP-VRF ready"
                    );
                }
                IpVrfStatus::NotReady { reasons } => {
                    tracing::warn!(vrf_id = id.as_u32(), ?reasons, "IP-VRF not ready");
                }
            }
            last.insert(*id, status.clone());
        }
        // Drop entries for IP-VRFs no longer in the intent. Operator
        // removed `[[evpn_ip_vrfs]]` for them; future re-add must log
        // the transition fresh, not as a delta against stale state.
        last.retain(|id, _| current.contains_key(id));
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
        ip_vrf_status: Vec<rustbgpd_evpn::IpVrfDataplaneStatus>,
        ip_vrf_routes: Option<rustbgpd_evpn::ip_vrf::IpVrfRouteDump>,
    ) {
        // Gate 9 slice 6c: snapshot installed-route counts per VRF
        // for the gRPC `IpVrfState.installed_routes_count` surface
        // and the Prometheus `evpn_ip_vrf_installed_routes` gauge.
        // Only routes whose `route_installed` flag is true contribute
        // — kernel-resolution rows (neighbor / FDB) are shared
        // across prefixes and tracked separately.
        //
        // **Pre-populate every configured VRF at 0** before the
        // incrementing pass: downstream consumers (notably the
        // Prometheus gauge publisher) drive `set(label, value)` from
        // this map, so a VRF whose count transitions from N → 0 must
        // appear here as `(vrf_id, 0)` for the gauge to converge to
        // zero. Without this pre-population, a VRF that drained
        // would never reappear in the map and the gauge would retain
        // a stale non-zero value until daemon restart.
        let mut ip_vrf_installed_routes: std::collections::HashMap<IpVrfId, u32> =
            ip_vrf_status.iter().map(|row| (row.vrf_id, 0)).collect();
        for ((vrf_id, _prefix), install) in &self.state.l3_owned.installs {
            if install.route_installed {
                *ip_vrf_installed_routes.entry(*vrf_id).or_insert(0) += 1;
            }
        }

        let report = DataplaneReport {
            intent_generation: self.state.last_intent_generation,
            reconcile_generation: self.state.reconcile_generation,
            instance_status,
            applied,
            failed,
            bum_enforcement,
            ip_vrf_status,
            ip_vrf_routes,
            ip_vrf_installed_routes,
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

        // Compute the L3 drain plan up front so the early-return
        // guard below also gates on Gate 9 owned state. Drain is
        // built by running the diff against an empty intent — the
        // standard remove-everything path through `compute_l3_diff`.
        // We use the actor's current `intent_rx` ip_vrfs view so the
        // cached identities on installs still resolve correctly even
        // if the upstream supervisor has cleared its own table.
        let l3_drain_plan = if self.state.l3_owned.is_empty() {
            crate::l3_diff::L3Plan::default()
        } else {
            let intent_snapshot = self.intent_rx.borrow().clone();
            crate::l3_diff::compute_l3_diff(
                &rustbgpd_evpn::ip_vrf::RemoteIpPrefixTable::new(),
                &self.state.l3_owned,
                &std::collections::BTreeMap::new(),
                intent_snapshot.ip_vrfs.as_ref(),
            )
        };

        if self.state.owned.is_empty() && bum_restore_ops.is_empty() && l3_drain_plan.ops.is_empty()
        {
            return;
        }

        let intent_for_l3 = self.intent_rx.borrow().clone();
        let l3_intent = intent_for_l3.remote_ip_prefixes.clone();
        let l3_ip_vrfs = intent_for_l3.ip_vrfs.clone();
        let ready_l3vxlan_empty: std::collections::BTreeMap<IpVrfId, u32> =
            std::collections::BTreeMap::new();

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

            // Gate 9 slice 6c L3 drain. Withdraw every owned route
            // + tear down the kernel resolution rows. Failed ops are
            // best-effort like the L2 path; the next startup's diff
            // re-converges against whatever the kernel still has.
            for op in &l3_drain_plan.ops {
                if let Err(e) = self.dataplane.apply(op).await {
                    tracing::debug!(error = %e, ?op, "L3 drain op failed");
                } else {
                    crate::l3_diff::record_l3_success(
                        &mut self.state.l3_owned,
                        op,
                        &ready_l3vxlan_empty,
                        l3_ip_vrfs.as_ref(),
                        l3_intent.as_ref(),
                    );
                }
            }
        };

        if tokio::time::timeout(self.config.drain_timeout, drain_fut)
            .await
            .is_err()
        {
            tracing::warn!(
                remaining = self.state.owned.len(),
                l3_remaining = self.state.l3_owned.installs.len(),
                l3_neighbors_remaining = self.state.l3_owned.kernel_neighbors.len(),
                l3_fdb_remaining = self.state.l3_owned.kernel_fdb.len(),
                "drain timeout exceeded; remaining owned entries left for next startup"
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

/// Build the per-IP-VRF status block for a [`DataplaneReport`] (Gate 9).
///
/// Joins the operator-facing handle from the [`IpVrfTable`] with the
/// live [`IpVrfStatus`] verdict from the reconcile actor's per-pass
/// `probe_ip_vrfs` call. Empty when no IP-VRFs are configured —
/// `probe_ip_vrfs` short-circuits without a netlink dump in that case.
fn build_ip_vrf_status(
    ip_vrfs: &rustbgpd_evpn::IpVrfTable,
    statuses: &std::collections::HashMap<IpVrfId, IpVrfStatus>,
) -> Vec<rustbgpd_evpn::IpVrfDataplaneStatus> {
    let mut rows: Vec<rustbgpd_evpn::IpVrfDataplaneStatus> = ip_vrfs
        .iter()
        .map(|vrf| {
            // If the probe didn't return a status for this VRF (e.g.,
            // the netlink dump failed before this row was populated),
            // synthesize `NotReady{VrfDeviceMissing}` so subscribers
            // see a deterministic verdict on every report.
            let status = statuses
                .get(&vrf.id)
                .cloned()
                .unwrap_or_else(|| IpVrfStatus::NotReady {
                    reasons: vec![rustbgpd_evpn::ip_vrf::IpVrfNotReady::VrfDeviceMissing],
                });
            rustbgpd_evpn::IpVrfDataplaneStatus {
                vrf_id: vrf.id,
                vrf_name: vrf.name.clone(),
                status,
            }
        })
        .collect();
    rows.sort_by_key(|r| r.vrf_id);
    rows
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
/// ADR-0059 slice 3b coordinator: apply an FDB-NHG op by calling
/// [`NexthopOps`] methods in ADR §5 invariant 1+2 order, updating
/// the allocator + [`GroupOwnedMap`] state.
///
/// Free function (not a method) so it can borrow `dataplane` and
/// `state` mutably from disjoint fields of the actor.
///
/// On install: per-VTEP members → group (replace if exists) → FDB row.
/// On update: per-VTEP members (added) → group REPLACE → GC removed members.
/// On remove: FDB row → group (if last ref) → members (each if last ref).
#[allow(clippy::too_many_lines)] // the per-op orchestration is sequential and reads top-to-bottom
async fn apply_nhg_op<D>(
    dataplane: &mut D,
    state: &mut ActorState,
    op: &DataplaneOp,
) -> Result<(), crate::error::DataplaneError>
where
    D: crate::dataplane::NexthopOps,
{
    use crate::group_state::RefDelta;
    use std::collections::BTreeSet;

    match op {
        DataplaneOp::InstallFdbNhg {
            vni,
            mac,
            group_key,
            members,
        } => {
            // Step 1: install any per-VTEP members not yet present.
            // Allocator slot reserved up front; if the netlink call
            // fails, release the slot before returning so we don't
            // leak allocator capacity. The actor's retry schedule
            // will re-attempt on the next pass with a fresh alloc.
            for ip in members {
                if state.groups.vtep_nh(ip).is_none() {
                    let id = state.nh_id_alloc.alloc_vtep_nh().map_err(|e| {
                        crate::error::DataplaneError::Other(format!(
                            "ADR-0059: vtep NH alloc failed: {e}"
                        ))
                    })?;
                    if let Err(e) = dataplane.add_nexthop_member(id, *ip).await {
                        state.nh_id_alloc.release(id);
                        return Err(e);
                    }
                    state.groups.record_member_install(*ip, id);
                    state.adopted_unreferenced.remove(&id);
                }
            }
            // Step 2: ensure group exists with the desired member set.
            let member_ids: Vec<u32> = members
                .iter()
                .map(|ip| state.groups.vtep_nh(ip).expect("just installed").id)
                .collect();
            // Snapshot the existing group ID + member set before
            // the mutable replace call (which re-borrows `state.groups`).
            let existing = state
                .groups
                .group(group_key)
                .map(|g| (g.id, g.members.iter().copied().collect::<Vec<_>>()));
            let group_id = if let Some((g_id, existing_members)) = existing {
                if existing_members != *members {
                    // Member set drifted (e.g., re-install after
                    // partial-failure recovery). Atomic REPLACE, then
                    // GC any per-VTEP members whose last group-ref
                    // dropped — mirrors the `UpdateFdbNhgMembers`
                    // path. Without this, members removed by the
                    // drift heal stay orphaned in `vtep_nhs` and
                    // in-kernel.
                    dataplane.add_nexthop_group(g_id, &member_ids).await?;
                    let new_members: BTreeSet<_> = members.iter().copied().collect();
                    let removed = state
                        .groups
                        .record_group_member_change(*group_key, new_members);
                    for ip in removed {
                        if let Some(vtep_id) = state.groups.record_member_unref(ip, *group_key) {
                            let _ = dataplane.del_nexthop(vtep_id).await;
                            state.nh_id_alloc.release(vtep_id);
                        }
                    }
                }
                g_id
            } else {
                let id = state.nh_id_alloc.alloc_nhg().map_err(|e| {
                    crate::error::DataplaneError::Other(format!("ADR-0059: nhg alloc failed: {e}"))
                })?;
                if let Err(e) = dataplane.add_nexthop_group(id, &member_ids).await {
                    state.nh_id_alloc.release(id);
                    return Err(e);
                }
                let members_set: BTreeSet<_> = members.iter().copied().collect();
                state
                    .groups
                    .record_group_install(*group_key, id, members_set);
                state.adopted_unreferenced.remove(&id);
                id
            };
            // Step 3: install the FDB row pointing at the group.
            // Failure here leaves the group + members installed in
            // `state.groups` — they're refcounted, so the next pass's
            // Install/Update for any MAC sharing this `group_key`
            // will reuse them. Per-VTEP members not yet ref'd by any
            // MAC stay tracked in `groups.vtep_nhs`; the GC happens
            // on the corresponding RemoveFdbNhg path's last-ref unref.
            dataplane.install_fdb_nhg_row(*vni, *mac, group_id).await?;
            state.groups.record_mac_ref(*group_key, *vni, *mac);
            Ok(())
        }

        DataplaneOp::UpdateFdbNhgMembers { group_key, members } => {
            // Add any new per-VTEP members first; release allocator
            // slot on netlink failure (same rollback as Install).
            for ip in members {
                if state.groups.vtep_nh(ip).is_none() {
                    let id = state.nh_id_alloc.alloc_vtep_nh().map_err(|e| {
                        crate::error::DataplaneError::Other(format!(
                            "ADR-0059: vtep NH alloc failed: {e}"
                        ))
                    })?;
                    if let Err(e) = dataplane.add_nexthop_member(id, *ip).await {
                        state.nh_id_alloc.release(id);
                        return Err(e);
                    }
                    state.groups.record_member_install(*ip, id);
                    state.adopted_unreferenced.remove(&id);
                }
            }
            // Compute new member-id list and REPLACE the group.
            let member_ids: Vec<u32> = members
                .iter()
                .map(|ip| state.groups.vtep_nh(ip).expect("just installed").id)
                .collect();
            let Some(g_id) = state.groups.group(group_key).map(|g| g.id) else {
                // `compute_diff` Pass 1b only emits `UpdateFdbNhgMembers`
                // when the group exists in `GroupOwnedMap`, so hitting
                // this branch means `owned` and `groups` have drifted
                // out of sync — an internal state inconsistency.
                // Surface it as a transient error (classified `Other`
                // → retried) so it shows up in metrics rather than
                // silently clearing retry state.
                return Err(crate::error::DataplaneError::Other(format!(
                    "ADR-0059: UpdateFdbNhgMembers for {group_key:?} but group missing \
                     from GroupOwnedMap (owned/groups state drift)",
                )));
            };
            dataplane.add_nexthop_group(g_id, &member_ids).await?;
            let new_members: BTreeSet<_> = members.iter().copied().collect();
            let removed = state
                .groups
                .record_group_member_change(*group_key, new_members);
            // GC per-VTEP members whose last group-ref dropped.
            for ip in removed {
                if let Some(vtep_id) = state.groups.record_member_unref(ip, *group_key) {
                    let _ = dataplane.del_nexthop(vtep_id).await;
                    state.nh_id_alloc.release(vtep_id);
                }
            }
            Ok(())
        }

        DataplaneOp::RemoveFdbNhg {
            vni,
            mac,
            group_key,
        } => {
            // FDB row first (ADR §5 invariant 2).
            dataplane.remove_fdb_nhg_row(*vni, *mac).await?;
            match state.groups.record_mac_unref(*group_key, *vni, *mac) {
                RefDelta::GroupStillReferenced => Ok(()),
                RefDelta::GroupShouldDelete { id, members } => {
                    let _ = dataplane.del_nexthop(id).await;
                    state.nh_id_alloc.release(id);
                    for ip in members {
                        if let Some(vtep_id) = state.groups.record_member_unref(ip, *group_key) {
                            let _ = dataplane.del_nexthop(vtep_id).await;
                            state.nh_id_alloc.release(vtep_id);
                        }
                    }
                    Ok(())
                }
            }
        }

        _ => unreachable!("apply_nhg_op called for non-FDB-NHG op"),
    }
}

fn fdb_op_vni(op: &DataplaneOp) -> rustbgpd_evpn::EvpnInstanceId {
    match op {
        DataplaneOp::AddRemoteFdb { vni, .. }
        | DataplaneOp::UpdateRemoteFdb { vni, .. }
        | DataplaneOp::RemoveRemoteFdb { vni, .. }
        | DataplaneOp::InstallFdbNhg { vni, .. }
        | DataplaneOp::RemoveFdbNhg { vni, .. } => *vni,
        DataplaneOp::UpdateFdbNhgMembers { group_key, .. } => group_key.vni,
        DataplaneOp::SetBumPortFlags { .. }
        | DataplaneOp::AddRemoteIpRoute { .. }
        | DataplaneOp::RemoveRemoteIpRoute { .. }
        | DataplaneOp::AddL3Neighbor { .. }
        | DataplaneOp::RemoveL3Neighbor { .. }
        | DataplaneOp::AddL3VxlanFdb { .. }
        | DataplaneOp::RemoveL3VxlanFdb { .. } => {
            // VNI 0 is invalid in the domain type, so VNI 1 is the
            // harmless report placeholder for non-L2-FDB ops.
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
        | DataplaneOp::RemoveRemoteFdb { mac, .. }
        | DataplaneOp::InstallFdbNhg { mac, .. }
        | DataplaneOp::RemoveFdbNhg { mac, .. } => *mac,
        DataplaneOp::UpdateFdbNhgMembers { .. }
        | DataplaneOp::SetBumPortFlags { .. }
        | DataplaneOp::AddRemoteIpRoute { .. }
        | DataplaneOp::RemoveRemoteIpRoute { .. }
        | DataplaneOp::AddL3Neighbor { .. }
        | DataplaneOp::RemoveL3Neighbor { .. }
        | DataplaneOp::AddL3VxlanFdb { .. }
        | DataplaneOp::RemoveL3VxlanFdb { .. } => rustbgpd_evpn::MacAddress::new([0; 6]),
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
        // Gate 9 L3 ops use a parallel accounting surface
        // (`AppliedL3Op` lands with the reconciler diff loop). They
        // never reach the L2 `op_to_kind` path under the current
        // apply_plan, so this arm is structurally unreachable.
        DataplaneOp::AddRemoteIpRoute { .. }
        | DataplaneOp::RemoveRemoteIpRoute { .. }
        | DataplaneOp::AddL3Neighbor { .. }
        | DataplaneOp::RemoveL3Neighbor { .. }
        | DataplaneOp::AddL3VxlanFdb { .. }
        | DataplaneOp::RemoveL3VxlanFdb { .. } => {
            unreachable!("L3 ops use a separate AppliedL3Op accounting path")
        }
        // ADR-0059 slice 3 FDB-NHG ops have their own kind variants
        // so the report layer never relies on sentinel MAC/dst values
        // (which would collide in `permanent_failures` keyed by
        // `(VNI, MAC)` and confuse operators reading the failed-op
        // list).
        DataplaneOp::InstallFdbNhg { mac, .. } => DataplaneOpKind::InstallFdbNhg { mac: *mac },
        DataplaneOp::UpdateFdbNhgMembers { group_key, .. } => {
            DataplaneOpKind::UpdateFdbNhgMembers {
                esi: group_key.esi,
                ethernet_tag: group_key.ethernet_tag,
            }
        }
        DataplaneOp::RemoveFdbNhg { mac, .. } => DataplaneOpKind::RemoveFdbNhg { mac: *mac },
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
