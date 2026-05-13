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

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustbgpd_evpn::{
    AppliedOp, DataplaneIntent, DataplaneOpKind, DataplaneReport, EvpnInstanceTable, FailedOp,
    FdbNexthopDataplaneStatus, FdbNexthopGroupStatus, FdbNexthopMemberStatus, FdbNhgDriftCounters,
    InstanceDataplaneStatus, InstanceState, RemoteMacTable,
};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, MissedTickBehavior, sleep_until};
use tokio_util::sync::CancellationToken;

use std::collections::{BTreeMap, BTreeSet};

use rustbgpd_evpn::ip_vrf::IpVrfStatus;
use rustbgpd_evpn::{EvpnInstanceId, IpVrfId, MacAddress};

use crate::backoff::RetrySchedule;
use crate::dataplane::{Dataplane, DataplaneOp, KernelEvent};
use crate::diff::{Plan, compute_diff};
use crate::enforcement::build_bum_enforcement_status;
use crate::error::FailureClass;
use crate::snapshot::{
    InstanceProbe, InstanceProbes, KernelSnapshot, OwnedEntry, OwnedEntryKind, OwnedSet,
};

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
    /// Retry schedule for ADR-0059 slice 3b `UpdateFdbNhgMembers`
    /// ops, keyed by [`AliasGroupKey`]. Group-level ops have no
    /// natural `(VNI, MAC)` identity, so they need their own key
    /// space — without it, every group update within the same VNI
    /// would collide on a placeholder all-zeros MAC.
    nhg_retry: RetrySchedule<crate::group_state::AliasGroupKey>,
    /// Per-group permanent-failure suppression for
    /// `UpdateFdbNhgMembers`. Same fingerprint-equality semantics as
    /// the FDB / BUM maps: a different member set on the same
    /// `AliasGroupKey` clears the suppression.
    nhg_permanent_failures: BTreeMap<crate::group_state::AliasGroupKey, DataplaneOp>,
    /// IDs whose kernel `del_nexthop` failed during steady-state
    /// FDB-NHG GC (Install drift heal, `UpdateFdbNhgMembers`,
    /// `RemoveFdbNhg` group teardown). The allocator slot is *not*
    /// released until the delete actually lands, so a future
    /// `alloc_vtep_nh` / `alloc_nhg` can't hand out an ID that's
    /// still live in the kernel. Drained once per reconcile pass
    /// after the apply phase — successes release the slot + drop
    /// from the set, persistent failures keep retrying.
    pending_deletes: BTreeSet<u32>,
    /// `(VNI, MAC)` keys we've already warned about for the
    /// ADR-0059 IPv6-alias fallback. The diff pass emits the set of
    /// keys *currently* in fallback on every reconcile; the actor
    /// only logs the warn for keys that newly entered fallback this
    /// pass. Keys that drop out of fallback (entry went v4-only, or
    /// was withdrawn) are also pruned so a future re-entry produces
    /// a fresh warn.
    warned_ipv6_fallback: BTreeSet<(EvpnInstanceId, MacAddress)>,
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
    /// Last time the steady-state drift-recovery pass ran. ADR-0059
    /// slice 3.5 PR 2: every `periodic_dump` interval (≥ 60 s by
    /// default) after `adoption_done`, the actor re-dumps tagged
    /// kernel NHIDs and heals four shapes of drift:
    ///
    /// 1. **Missing per-VTEP members** — re-add via
    ///    `add_nexthop_member` at the same kernel ID we already
    ///    tracked in `groups`.
    /// 2. **Missing or member-set-drifted groups** — re-add via
    ///    `add_nexthop_group` (which is `NLM_F_CREATE | REPLACE`).
    /// 3. **Stale tagged FDB rows from a prior daemon instance**
    ///    (the PR 1 cold-start gap) — emit `remove_fdb_nhg_row`
    ///    when a kernel FDB row points at a tagged NHID we don't
    ///    track and never recorded under `owned`.
    /// 4. **Stale tagged NHIDs in kernel with no local tracking** —
    ///    fold into `adopted_unreferenced` so the existing
    ///    `cleanup_unreferenced_adoptions` pass (now eligible to
    ///    re-run on every reconcile via the same `adoption_done`
    ///    gate path) processes them with the retention-set logic.
    last_drift_check: Option<Instant>,
    /// Permanent shut-down latch for the slice 3.5 drift-recovery
    /// cycle. Flipped to `true` when `dump_owned_nexthops` returns a
    /// permanent failure (`KernelTooOld`, `PermissionDenied`,
    /// `InvalidArgument`) — the same error classes the one-shot
    /// startup-adoption block uses to decide whether to give up.
    /// Once latched, the drift gate skips entirely so the actor
    /// stops re-attempting the dump (and emitting a warn) on every
    /// reconcile trigger. Transient/conflict failures leave this
    /// false; the next reconcile pass retries.
    drift_disabled: bool,
    /// Drift / orphan-cleanup deltas accumulated since the last
    /// [`DataplaneReport`]. Drained into the report so the daemon can
    /// increment Prometheus counters without coupling this crate to
    /// the telemetry crate.
    fdb_nhg_drift_since_report: FdbNhgDriftCounters,
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
            nhg_retry: RetrySchedule::new(),
            nhg_permanent_failures: BTreeMap::new(),
            pending_deletes: BTreeSet::new(),
            warned_ipv6_fallback: BTreeSet::new(),
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
            last_drift_check: None,
            drift_disabled: false,
            fdb_nhg_drift_since_report: FdbNhgDriftCounters::default(),
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
            // Compute the next retry deadline across the three retry
            // schedules — FDB ops keyed by `(VNI, MAC)`, BUM ops keyed
            // by ifindex, and FDB-NHG group-level ops keyed by
            // `AliasGroupKey`. The earliest wakes the actor.
            let next_fdb = self.state.retry.earliest_due();
            let next_bum = self.state.bum_retry.earliest_due();
            let next_nhg = self.state.nhg_retry.earliest_due();
            let retry_due = [next_fdb, next_bum, next_nhg]
                .into_iter()
                .flatten()
                .min()
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

        // ADR-0059 slice 3b: one-shot startup adoption. Dump tagged
        // nexthops from the kernel and reserve their IDs in the
        // allocator before any `compute_diff` Pass 1b emission, so a
        // fresh `InstallFdbNhg` can't collide with an ID left behind
        // by a prior daemon instance (RTM_NEWNEXTHOP uses
        // NLM_F_REPLACE semantics). On dump failure we short-circuit
        // the reconcile pass entirely — proceeding would risk the
        // allocator handing out an ID that's still live in the
        // kernel. The actor will re-attempt on the next event /
        // intent change / retry-timer tick.
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
                Err(e) => match e.class() {
                    crate::error::FailureClass::Permanent => {
                        // Permanent dump failure — `KernelTooOld` (kernel
                        // < 5.8, no `NDA_NH_ID`), `PermissionDenied` (no
                        // `CAP_NET_ADMIN`), or `InvalidArgument` (our
                        // message shape is wrong). Mark adoption done
                        // so the next pass doesn't re-attempt the dump,
                        // and keep going with the rest of reconcile —
                        // single-dst FDB, BUM enforcement, L3 ops don't
                        // need the nexthop allocator and should still
                        // work on unsupported kernels. FDB-NHG ops that
                        // hit Pass 1b will fail with the same permanent
                        // error at apply time and get permanently
                        // suppressed per-op-shape.
                        tracing::warn!(
                            error = %e,
                            "adoption: dump_owned_nexthops permanently failed; \
                             FDB-NHG (slice 3b ECMP) disabled for this daemon instance, \
                             other reconcile paths continue normally"
                        );
                        self.state.adoption_done = true;
                    }
                    crate::error::FailureClass::Transient
                    | crate::error::FailureClass::Conflict => {
                        tracing::warn!(
                            error = %e,
                            "adoption: dump_owned_nexthops failed transiently; deferring this reconcile pass to avoid allocator collisions"
                        );
                        let status = build_instance_status(&intent.instances, &probes);
                        // `dump_snapshot` already succeeded — use the real
                        // snapshot so BUM enforcement reflects actual link
                        // state, not "no links exist".
                        let bum_enforcement =
                            build_bum_enforcement_status(&intent.bum_enforcement, &snapshot);
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
                },
            }
        }

        let mut plan = compute_diff(
            intent.remote_macs.as_ref(),
            &snapshot,
            &self.state.owned,
            &probes,
            &self.state.groups,
            intent.instances.as_ref(),
        );

        // ADR-0059 mixed-family alias fallback warn: log only for
        // `(VNI, MAC)` keys that newly entered the fallback this pass.
        // The diff produces the *currently in fallback* set; we warn
        // for new entries and prune keys that left the set so a future
        // re-entry produces a fresh warn.
        for key in plan
            .ipv6_alias_fallback_keys
            .difference(&self.state.warned_ipv6_fallback)
        {
            tracing::warn!(
                vni = ?key.0,
                mac = %key.1,
                "ADR-0059 mixed address-family alias members cannot share one FDB nexthop group; \
                 falling back to single-dst FDB row at primary VTEP",
            );
        }
        self.state
            .warned_ipv6_fallback
            .clone_from(&plan.ipv6_alias_fallback_keys);

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

        // Retry any kernel-nexthop deletes left over from steady-state
        // FDB-NHG GC failures (see `try_del_and_release_alloc`). Runs
        // every pass — the queue is empty in steady state, so this is
        // a no-op cost most of the time. Independent of the one-shot
        // adoption cleanup below: that one walks `adopted_unreferenced`
        // (set populated at first-dump), this one walks
        // `pending_deletes` (set populated as apply-time deletes fail).
        self.drain_pending_deletes().await;

        // ADR-0059 slice 3b: one-shot stale-NHID cleanup. Anything
        // still in `adopted_unreferenced` after the first reconcile's
        // apply phase is *potentially* stale state from a prior
        // daemon instance — but only "potentially" because:
        //   1. Permanently-suppressed FDB-NHG ops `continue` out of
        //      `apply_plan` and never land in `failed`, so once any
        //      InstallFdbNhg has been recorded permanent, the next
        //      pass sees `failed.is_empty()` even though the desired
        //      Install never executed. A future operator config
        //      change (or kernel upgrade) could clear the
        //      suppression, at which point those NHIDs would have
        //      been claimed. Cleanup must therefore block when any
        //      FDB-NHG op is permanently suppressed.
        //   2. Even with no suppression, the kernel snapshot may
        //      still hold FDB rows referencing adopted NHIDs (e.g.,
        //      a MAC whose Install hasn't been emitted yet because
        //      its instance is NotReady). `cleanup_unreferenced_adoptions`
        //      reads `snapshot.iter_fdb()` to compute a retention
        //      set: any adopted ID a kernel FDB row points at, plus
        //      its group members.
        //
        // Marks `adoption_done` only on a fully-clean cleanup: no
        // apply failures, no NHG suppression, every staged
        // stale-delete succeeded. Otherwise next pass retries.
        // Track whether adoption flipped to `true` *this* pass — the
        // first drift cycle has to wait one full `periodic_dump`
        // interval after that, otherwise we'd issue a second
        // `dump_owned_nexthops()` netlink call on top of the startup
        // adoption dump in the same reconcile pass.
        let adoption_flipped_this_pass = !self.state.adoption_done && failed.is_empty() && {
            let cleanup_ok = self.cleanup_unreferenced_adoptions(&snapshot).await;
            if cleanup_ok {
                self.state.adoption_done = true;
            }
            cleanup_ok
        };
        if adoption_flipped_this_pass {
            // Seed `last_drift_check` so the gate (elapsed >=
            // periodic_dump) defers the first drift cycle by one
            // interval instead of firing immediately on top of the
            // startup dump.
            self.state.last_drift_check = Some(Instant::now());
        }

        // ADR-0059 slice 3.5 PR 2: steady-state drift recovery.
        // Re-dumps tagged NHIDs ≥ `periodic_dump` after the last check
        // and heals four shapes of drift between rustbgpd's tracked
        // state and the kernel:
        //   1. Missing per-VTEP members (out-of-band `ip nexthop del`).
        //   2. Missing or member-set-drifted groups.
        //   3. Stale tagged FDB rows from a prior daemon instance
        //      (closes the slice 3.5 PR 1 cold-start gap).
        //   4. Stale tagged NHIDs in kernel that we don't track —
        //      folded into `adopted_unreferenced` so the next pass's
        //      `cleanup_unreferenced_adoptions` runs the retention-set
        //      logic over them.
        //
        // Only runs after `adoption_done` to avoid colliding with
        // startup adoption + cleanup. Gated by an elapsed-time check
        // so unrelated reconcile triggers (intent change, kernel
        // event) don't push extra netlink dumps onto the actor.
        // `last_drift_check` advances only when the dump succeeds —
        // a transient `dump_owned_nexthops` failure must not
        // postpone the next attempt by a full interval.
        if self.state.adoption_done && !adoption_flipped_this_pass && !self.state.drift_disabled {
            let due = self
                .state
                .last_drift_check
                .is_none_or(|t| t.elapsed() >= self.config.periodic_dump);
            if due
                && self
                    .reconcile_drift(&snapshot, intent.remote_macs.as_ref())
                    .await
            {
                self.state.last_drift_check = Some(Instant::now());
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
            // across three key spaces: BUM (ifindex), FDB-NHG group
            // ops (`AliasGroupKey`), and per-MAC FDB ops (`(VNI, MAC)`).
            // No sentinel-key collision risk.
            let permanently_suppressed = match op {
                DataplaneOp::SetBumPortFlags { ifindex, .. } => check_permanent_suppression(
                    &mut self.state.bum_permanent_failures,
                    ifindex,
                    op,
                    "BUM",
                ),
                DataplaneOp::UpdateFdbNhgMembers { group_key, .. } => check_permanent_suppression(
                    &mut self.state.nhg_permanent_failures,
                    group_key,
                    op,
                    "FDB-NHG group",
                ),
                _ => check_permanent_suppression(
                    &mut self.state.permanent_failures,
                    &(fdb_op_vni(op), fdb_op_mac(op)),
                    op,
                    "FDB",
                ),
            };
            if permanently_suppressed {
                continue;
            }

            // Transient retry gating — skip until the per-op
            // exponential-backoff deadline passes. Same three-way
            // dispatch as permanent suppression.
            let next_due_ms_opt = match op {
                DataplaneOp::SetBumPortFlags { ifindex, .. } => {
                    self.state.bum_retry.next_due_for(*ifindex)
                }
                DataplaneOp::UpdateFdbNhgMembers { group_key, .. } => {
                    self.state.nhg_retry.next_due_for(*group_key)
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
                                DataplaneOp::UpdateFdbNhgMembers { group_key, .. } => {
                                    self.state.nhg_retry.record_failure(*group_key, now_ms)
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
                            match op {
                                DataplaneOp::SetBumPortFlags { ifindex, .. } => {
                                    self.state.bum_retry.record_success(*ifindex);
                                    self.state
                                        .bum_permanent_failures
                                        .insert(*ifindex, op.clone());
                                }
                                DataplaneOp::UpdateFdbNhgMembers { group_key, .. } => {
                                    self.state.nhg_retry.record_success(*group_key);
                                    self.state
                                        .nhg_permanent_failures
                                        .insert(*group_key, op.clone());
                                }
                                _ => {
                                    self.state.retry.record_success(fdb_key_for_failed);
                                    self.state
                                        .permanent_failures
                                        .insert(fdb_key_for_failed, op.clone());
                                }
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

    /// Retry any kernel-nexthop deletes that failed during this or a
    /// previous reconcile pass's steady-state GC. Successes release
    /// the allocator slot + drop from the queue; persistent failures
    /// stay queued for the next pass. Bounded by the count of
    /// distinct IDs that have ever hit a transient `del_nexthop`
    /// failure — usually empty in steady state.
    async fn drain_pending_deletes(&mut self) {
        // Drain in dependency order: NHG IDs first, then VTEP member
        // IDs. `BTreeSet<u32>` iterates ascending, and our tag scheme
        // puts members at `0x3000_xxxx` and groups at `0x4000_xxxx`
        // — naive iteration would delete members before their parent
        // group, which the kernel can reject with `EINVAL` and which
        // also defeats ADR-0059 §5 invariant 2 (FDB row → group →
        // members). Partition by `is_nhg` first.
        let (groups, members): (Vec<u32>, Vec<u32>) = self
            .state
            .pending_deletes
            .iter()
            .copied()
            .partition(|id| crate::nh_id_alloc::NhIdAllocator::is_nhg(*id));
        for id in groups.into_iter().chain(members) {
            match self.dataplane.del_nexthop(id).await {
                Ok(()) => {
                    self.state.nh_id_alloc.release(id);
                    self.state.pending_deletes.remove(&id);
                    tracing::debug!(id, "pending_deletes: drained on retry");
                }
                Err(e) => {
                    tracing::trace!(?e, id, "pending_deletes: still failing");
                }
            }
        }
    }

    /// ADR-0059 slice 3b cleanup helper: walk `adopted_unreferenced`
    /// after the first reconcile's apply phase and delete any
    /// rustbgpd-tagged kernel nexthop that's *both* unclaimed by a
    /// MAC in `groups` *and* unreferenced by any FDB row in the
    /// kernel snapshot.
    ///
    /// Two-layer safety against deleting live state:
    ///
    /// 1. **Suppression gate** — if any FDB-NHG op is permanently
    ///    suppressed (`nhg_permanent_failures` non-empty, or
    ///    `permanent_failures` contains any of `InstallFdbNhg` /
    ///    `UpdateFdbNhgMembers` / `RemoveFdbNhg`), block cleanup
    ///    entirely. Permanently-suppressed ops `continue` out of
    ///    `apply_plan` without joining `failed`, so the outer
    ///    `failed.is_empty()` gate alone can't detect this case;
    ///    a future config change could clear the suppression and
    ///    those NHIDs would have been claimed if Install had
    ///    succeeded, so we mustn't pre-emptively delete them.
    ///
    /// 2. **Retention set** — even without suppression, scan
    ///    `snapshot.iter_fdb()` for FDB rows whose `nh_id` is in
    ///    `adopted_unreferenced`. Retain those IDs *and* recursively
    ///    the member IDs of retained groups (a kernel FDB row
    ///    pointing at a group implies all its member NHs are still
    ///    in use even though we don't track them in `groups` yet).
    ///
    /// Returns `true` only when (a) the suppression gate let
    /// cleanup proceed, and (b) every staged delete succeeded. On
    /// per-ID failure the allocator slot stays reserved and the
    /// entry stays in `adopted_unreferenced` so the next reconcile
    /// pass retries — releasing the slot on a transient netlink
    /// failure would let a future `alloc_vtep_nh` / `alloc_nhg`
    /// hand out an ID still live in the kernel, exactly the
    /// collision adoption is supposed to prevent.
    async fn cleanup_unreferenced_adoptions(&mut self, snapshot: &KernelSnapshot) -> bool {
        // (1) Suppression gate.
        let any_fdb_nhg_perm_failure = !self.state.nhg_permanent_failures.is_empty()
            || self.state.permanent_failures.values().any(|op| {
                matches!(
                    op,
                    DataplaneOp::InstallFdbNhg { .. }
                        | DataplaneOp::UpdateFdbNhgMembers { .. }
                        | DataplaneOp::RemoveFdbNhg { .. }
                )
            });
        if any_fdb_nhg_perm_failure {
            tracing::warn!(
                adopted = self.state.adopted_unreferenced.len(),
                "adoption cleanup blocked: FDB-NHG op(s) permanently suppressed; \
                 adopted IDs retained until suppression clears (op-shape change \
                 or daemon restart)"
            );
            return false;
        }

        // (2) Retention set from kernel snapshot. Walk every FDB row;
        //     if its `nh_id` is one we adopted, retain it. For each
        //     retained group, recursively retain its members (a
        //     kernel row pointing at the group keeps every member NH
        //     in use even before we record the group locally).
        let mut retain: BTreeSet<u32> = BTreeSet::new();
        for (_, entry) in snapshot.iter_fdb() {
            let Some(nh_id) = entry.nh_id else { continue };
            if !self.state.adopted_unreferenced.contains_key(&nh_id) {
                continue;
            }
            retain.insert(nh_id);
            if let Some(adopted) = self.state.adopted_unreferenced.get(&nh_id)
                && let crate::dataplane::KernelNexthopKind::Group { member_ids } = &adopted.kind
            {
                for mid in member_ids {
                    retain.insert(*mid);
                }
            }
        }

        // Drain in dependency order: NHG IDs before per-VTEP members
        // (Copilot finding — `BTreeSet<u32>` ascending iteration plus
        // our tag scheme would delete members first and let the
        // kernel reject the group del with `EINVAL`).
        let (stale_groups, stale_members): (Vec<u32>, Vec<u32>) = self
            .state
            .adopted_unreferenced
            .keys()
            .copied()
            .filter(|id| !retain.contains(id))
            .partition(|id| crate::nh_id_alloc::NhIdAllocator::is_nhg(*id));

        let mut all_ok = true;
        for id in stale_groups.into_iter().chain(stale_members) {
            // `del_nexthop` is idempotent on `ENOENT` (slice 2). Only
            // release + drop tracking on `Ok` — on `Err`, leave the
            // slot reserved + the entry in the map so the next
            // reconcile pass retries.
            match self.dataplane.del_nexthop(id).await {
                Ok(()) => {
                    self.state.nh_id_alloc.release(id);
                    self.state.adopted_unreferenced.remove(&id);
                    self.state.fdb_nhg_drift_since_report.orphans_cleaned += 1;
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
        // Retained IDs stay in `adopted_unreferenced` so the next
        // pass re-evaluates them — if a kernel FDB row gets removed
        // or replaced, they become deletable; if a MAC's Install
        // succeeds, `apply_nhg_op` removes them at record time.
        all_ok
    }

    /// ADR-0059 slice 3.5 PR 2 — steady-state drift recovery.
    ///
    /// Walks the rustbgpd-tagged nexthop space (`VTEP_NH_TAG` /
    /// `NHG_TAG` ID ranges) and reconciles four shapes of drift
    /// between rustbgpd's `GroupOwnedMap` + `OwnedSet` and the
    /// kernel:
    ///
    /// 1. **Missing or mis-shaped per-VTEP members.** A tracked
    ///    member ID is absent from the kernel dump, has the wrong
    ///    gateway, or has been overwritten with a group object.
    ///    Re-add at the same kernel ID via `add_nexthop_member`
    ///    (`NLM_F_CREATE | NLM_F_REPLACE`). Slot stays reserved;
    ///    no allocator churn.
    /// 2. **Missing or member-set-drifted groups.** A tracked group
    ///    ID is either absent or has a different member set than
    ///    `GroupOwnedMap` expects. `add_nexthop_group` is
    ///    `NLM_F_CREATE | NLM_F_REPLACE`, so the same call serves
    ///    create-from-missing and replace-on-drift.
    /// 3. **Stale tagged FDB rows from a prior daemon.** A kernel
    ///    FDB row's `nh_id` is in our tag space but neither tracked
    ///    in `GroupOwnedMap` nor recorded in `OwnedSet`. Emits
    ///    `remove_fdb_nhg_row` — but only when the `(VNI, MAC)` is
    ///    *also not in the current desired intent*: an apply
    ///    failure on a desired MAC must not cause the row to
    ///    disappear underneath the eventual install. Closes the
    ///    slice 3.5 PR 1 cold-start gap (restart-with-disable
    ///    leaves orphan rows).
    /// 4. **Untracked tagged NHIDs in the kernel.** Folded into
    ///    `adopted_unreferenced`, then `cleanup_unreferenced_adoptions`
    ///    runs **in-line** against the snapshot we already have.
    ///    The cleanup may retain the orphan this pass (the snapshot
    ///    pre-dates step (3) FDB-row removals); the next drift
    ///    cycle deletes it cleanly with a fresh snapshot. Keeping
    ///    `adoption_done` sticky avoids reopening the startup
    ///    adoption-dump path on the next reconcile pass, which
    ///    would issue an extra `dump_owned_nexthops` and warn for
    ///    every ID we just reserved here.
    ///
    /// All failures are non-fatal: logged + deferred. Allocator
    /// integrity is preserved end-to-end — we never release a slot
    /// before the kernel confirms the delete (the
    /// `try_del_and_release_alloc` invariant from slice 3b).
    ///
    /// Returns `true` when the dump succeeded (caller advances
    /// `last_drift_check`), `false` on dump failure. On a
    /// **permanent** dump failure class (kernel too old, no
    /// `CAP_NET_ADMIN`, malformed message) we latch the
    /// `drift_disabled` flag so subsequent reconcile passes skip
    /// the drift gate entirely — mirrors the startup-adoption
    /// permanent-failure semantics. Transient / conflict failures
    /// leave drift enabled; the next reconcile pass retries.
    #[allow(clippy::too_many_lines)]
    async fn reconcile_drift(
        &mut self,
        snapshot: &KernelSnapshot,
        desired: &RemoteMacTable,
    ) -> bool {
        use crate::dataplane::KernelNexthopKind;
        use crate::nh_id_alloc::NhIdAllocator;

        // (0) Re-dump tagged NHIDs. Mirror the startup-adoption
        //     error-class dispatch: permanent failures (kernel too
        //     old, no `CAP_NET_ADMIN`, message-shape rejection)
        //     latch `drift_disabled` so subsequent reconcile passes
        //     stop attempting the dump entirely. Transient /
        //     conflict failures leave drift enabled — the next
        //     reconcile pass will retry.
        let actual = match self.dataplane.dump_owned_nexthops().await {
            Ok(v) => v,
            Err(e) => {
                match e.class() {
                    crate::error::FailureClass::Permanent => {
                        tracing::warn!(
                            error = %e,
                            "drift: dump_owned_nexthops permanently failed; \
                             disabling drift recovery for this daemon instance \
                             (matches startup-adoption permanent-failure semantics)"
                        );
                        self.state.drift_disabled = true;
                        self.state.fdb_nhg_drift_since_report.drift_disabled += 1;
                    }
                    crate::error::FailureClass::Transient
                    | crate::error::FailureClass::Conflict => {
                        tracing::warn!(
                            error = %e,
                            "drift: dump_owned_nexthops failed transiently; \
                             deferring this drift cycle"
                        );
                    }
                }
                return false;
            }
        };
        let actual_by_id: BTreeMap<u32, crate::dataplane::KernelNexthop> =
            actual.into_iter().map(|nh| (nh.id, nh)).collect();

        // Snapshot tracked state so the &mut self loops below can call
        // dataplane methods without holding a borrow across .await.
        let tracked_vteps: Vec<(IpAddr, u32)> = self
            .state
            .groups
            .iter_vtep_nhs()
            .map(|(ip, nh)| (*ip, nh.id))
            .collect();
        let tracked_groups: Vec<(crate::group_state::AliasGroupKey, u32, BTreeSet<IpAddr>)> = self
            .state
            .groups
            .iter_groups()
            .map(|(k, g)| (*k, g.id, g.members.clone()))
            .collect();
        let tracked_ids: BTreeSet<u32> = tracked_vteps
            .iter()
            .map(|(_, id)| *id)
            .chain(tracked_groups.iter().map(|(_, id, _)| *id))
            .collect();

        // (1) Missing or mis-shaped per-VTEP members — re-add at
        //     the same ID via `add_nexthop_member` (which is
        //     `NLM_F_CREATE | NLM_F_REPLACE`, so it heals "wrong
        //     gateway / wrong kind at our ID" with the same call
        //     that creates a fresh one). "Healthy" requires:
        //       - kernel kind is `Member` (not `Group` — pathological
        //         re-use of our ID slot as a group object),
        //       - kernel gateway matches the tracked IP exactly.
        //     An external actor replacing `0x3000_xxxx` with a wrong
        //     gateway or a group object would otherwise look healthy
        //     to a `contains_key` check and never get repaired.
        for (ip, id) in &tracked_vteps {
            let needs_action = match actual_by_id.get(id) {
                None => true,
                Some(nh) => match &nh.kind {
                    KernelNexthopKind::Member { gateway } => gateway != ip,
                    KernelNexthopKind::Group { .. } => true,
                },
            };
            if !needs_action {
                continue;
            }
            match self.dataplane.add_nexthop_member(*id, *ip).await {
                Ok(()) => {
                    self.state.fdb_nhg_drift_since_report.members_repaired += 1;
                    tracing::info!(
                        id = *id,
                        gateway = %ip,
                        "drift: re-installed FDB nexthop member (missing or kind/gateway drift)"
                    );
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    id = *id,
                    gateway = %ip,
                    "drift: re-add member failed; deferring"
                ),
            }
        }

        // (2) Missing or member-set-drifted groups — re-add (REPLACE).
        for (key, g_id, members) in &tracked_groups {
            // Resolve expected kernel-side member IDs through the
            // current `groups` map (post step 1 re-adds, in case the
            // group depended on a member we just re-installed).
            let expected_member_ids: Vec<u32> = members
                .iter()
                .filter_map(|ip| self.state.groups.vtep_nh(ip).map(|nh| nh.id))
                .collect();
            let needs_action = match actual_by_id.get(g_id) {
                None => true,
                Some(nh) => match &nh.kind {
                    KernelNexthopKind::Group { member_ids } => {
                        let kset: BTreeSet<u32> = member_ids.iter().copied().collect();
                        let eset: BTreeSet<u32> = expected_member_ids.iter().copied().collect();
                        kset != eset
                    }
                    KernelNexthopKind::Member { .. } => true,
                },
            };
            if !needs_action {
                continue;
            }
            match self
                .dataplane
                .add_nexthop_group(*g_id, &expected_member_ids)
                .await
            {
                Ok(()) => {
                    self.state.fdb_nhg_drift_since_report.groups_replaced += 1;
                    tracing::info!(
                        id = *g_id,
                        ?key,
                        members = expected_member_ids.len(),
                        "drift: re-added/replaced FDB nexthop group"
                    );
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    id = *g_id,
                    ?key,
                    "drift: re-add group failed; deferring"
                ),
            }
        }

        // (3) Stale tagged FDB rows from a prior daemon — emit
        //     `remove_fdb_nhg_row` for any FDB row whose `nh_id` is
        //     in our tag space but neither tracked nor owned **and
        //     not currently desired**. The `desired` guard is the
        //     safety net for a `(VNI, MAC)` whose install hasn't
        //     succeeded yet (apply failure, race window between
        //     intent arrival and the first reconcile, or a stuck
        //     permanent failure on an op we're still retrying):
        //     deleting the row would temporarily remove forwarding
        //     state for a MAC we intend to program. Skipping it
        //     here lets the next reconcile pass re-emit the install
        //     op naturally; if the row is *also* genuinely stale,
        //     the install path's REPLACE semantics will overwrite
        //     the `nh_id` cleanly.
        let stale_rows: Vec<(EvpnInstanceId, MacAddress)> = snapshot
            .iter_fdb()
            .filter_map(|(&(vni, mac), entry)| {
                let nh_id = entry.nh_id?;
                if !NhIdAllocator::is_ours(nh_id) {
                    return None;
                }
                if tracked_ids.contains(&nh_id) {
                    return None;
                }
                if self.state.owned.contains(vni, mac) {
                    return None;
                }
                if desired.get(vni, mac).is_some() {
                    return None;
                }
                Some((vni, mac))
            })
            .collect();
        for (vni, mac) in stale_rows {
            match self.dataplane.remove_fdb_nhg_row(vni, mac).await {
                Ok(()) => tracing::info!(
                    ?vni,
                    %mac,
                    "drift: removed stale tagged FDB row left over from prior daemon"
                ),
                Err(e) => tracing::warn!(
                    error = %e,
                    ?vni,
                    %mac,
                    "drift: stale FDB row remove failed; deferring"
                ),
            }
        }

        // (4) Untracked tagged NHIDs — fold into adopted_unreferenced
        //     and run `cleanup_unreferenced_adoptions` IN-LINE below.
        //     We don't clear `adoption_done`: doing so would reopen
        //     the startup-adoption `dump_owned_nexthops` block on the
        //     next reconcile pass and warn for every ID we just
        //     reserved here. See the in-line cleanup call after this
        //     loop.
        let mut adopted_any = false;
        for (id, nh) in actual_by_id {
            if tracked_ids.contains(&id) {
                continue;
            }
            if self.state.adopted_unreferenced.contains_key(&id) {
                continue;
            }
            match self.state.nh_id_alloc.reserve(id) {
                Ok(()) => {
                    self.state.adopted_unreferenced.insert(id, nh);
                    adopted_any = true;
                }
                Err(e) => {
                    // Allocator rejected: the ID's high-nibble
                    // doesn't match our tag space (foreign tag), or
                    // its bitmap slot is outside `NH_ID_MAX`, or a
                    // prior pass already reserved it. The first two
                    // cases are operator-visible drift that we can't
                    // adopt-and-cleanup ourselves; log so they
                    // surface in operator runs instead of silently
                    // hanging around in the kernel forever.
                    tracing::warn!(
                        ?e,
                        id,
                        "drift: untracked tagged NHID could not be reserved; \
                         operator intervention may be required (rustbgpd cannot \
                         take ownership of kernel-orphaned IDs outside its \
                         reservable range)"
                    );
                }
            }
        }
        if adopted_any {
            tracing::info!(
                adopted = self.state.adopted_unreferenced.len(),
                "drift: discovered untracked tagged NHIDs; running adoption cleanup in-line"
            );
            // Run cleanup directly with the snapshot we already have
            // rather than clearing `adoption_done`. Clearing it would
            // reopen the startup-adoption `dump_owned_nexthops` path
            // on the next reconcile pass (a second netlink dump, plus
            // `reserve()` warnings for IDs we already reserved here)
            // AND defer the actual delete by up to another
            // `periodic_dump` interval. The retention set is built
            // from the current snapshot; any FDB row drift's step (3)
            // removed earlier this pass is still listed there (the
            // snapshot was taken before our removes), so the orphan
            // NHID may retain this pass and clean up cleanly on the
            // next drift cycle when the snapshot is fresh.
            let _ = self.cleanup_unreferenced_adoptions(snapshot).await;
        }
        true
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
            DataplaneOp::UpdateFdbNhgMembers { group_key, .. } => {
                // Group-level op — no per-MAC owned-set delta; the
                // slice 3b coordinator updates `group_state`
                // separately. Clear the NHG-keyed retry schedule on
                // success so subsequent failures get a fresh backoff.
                self.state.nhg_retry.record_success(*group_key);
            }
            // Gate 9 slice 6c L3 ops have their own owned-set and retry
            // tracking inside the L3 diff loop, handled by
            // `record_success_l3`.
            DataplaneOp::AddRemoteIpRoute { .. }
            | DataplaneOp::RemoveRemoteIpRoute { .. }
            | DataplaneOp::AddL3Neighbor { .. }
            | DataplaneOp::RemoveL3Neighbor { .. }
            | DataplaneOp::AddL3VxlanFdb { .. }
            | DataplaneOp::RemoveL3VxlanFdb { .. } => {}
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
        &mut self,
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
        let fdb_nhg_drift_counters = std::mem::take(&mut self.state.fdb_nhg_drift_since_report);

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
            fdb_nexthops: build_fdb_nexthop_status(&self.state),
            fdb_nhg_drift_counters,
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
    #[allow(clippy::too_many_lines)]
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

            // Snapshot the owned set with kind info — for FdbNhg
            // entries we route through `apply_nhg_op` (so the FDB
            // row → group → members teardown sequence runs and the
            // refcount state stays consistent for sibling MACs that
            // share the group). Without this, drain would issue
            // `RemoveRemoteFdb` for FdbNhg-owned MACs — which
            // `Dataplane::apply` rejects with `InvalidArgument` and
            // the kernel group/members stay orphaned across restart.
            let owned_drain: Vec<(EvpnInstanceId, MacAddress, OwnedEntryKind)> = self
                .state
                .owned
                .iter()
                .map(|(&(vni, mac), entry)| (vni, mac, entry.kind.clone()))
                .collect();
            for (vni, mac, kind) in owned_drain {
                let op = match kind {
                    OwnedEntryKind::SingleDst { .. } => DataplaneOp::RemoveRemoteFdb { vni, mac },
                    OwnedEntryKind::FdbNhg { group_key } => DataplaneOp::RemoveFdbNhg {
                        vni,
                        mac,
                        group_key,
                    },
                };
                let res = match &op {
                    DataplaneOp::RemoveFdbNhg { .. } => {
                        apply_nhg_op(&mut self.dataplane, &mut self.state, &op).await
                    }
                    _ => self.dataplane.apply(&op).await,
                };
                if let Err(e) = res {
                    tracing::debug!(error = %e, ?op, "drain apply failed");
                    // Best-effort — keep going. Foreign entries in
                    // the kernel are never touched by `apply` for
                    // RemoveRemoteFdb in either the real or fake
                    // impl; `apply_nhg_op` GC is also best-effort
                    // for the group/member teardown.
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

/// Build the operator-facing FDB-NHG snapshot for a
/// [`DataplaneReport`].
///
/// This is a projection of the actor-owned allocator/refcount state,
/// not a raw kernel dump. The fields are the pieces operators need
/// when comparing rustbgpd's view against `ip nexthop show` and
/// `bridge fdb show`: group ID, per-VTEP member IDs, MAC refs, and
/// counts for orphan / retry cleanup state.
fn build_fdb_nexthop_status(state: &ActorState) -> FdbNexthopDataplaneStatus {
    let mut groups: Vec<FdbNexthopGroupStatus> = state
        .groups
        .iter_groups()
        .map(|(key, group)| {
            let members: Vec<FdbNexthopMemberStatus> = group
                .members
                .iter()
                .map(|gateway| FdbNexthopMemberStatus {
                    gateway: *gateway,
                    nexthop_id: state.groups.vtep_nh(gateway).map_or(0, |nh| nh.id),
                })
                .collect();
            let ref_macs: Vec<MacAddress> = group.ref_macs.iter().map(|(_, mac)| *mac).collect();
            FdbNexthopGroupStatus {
                vni: key.vni,
                esi: key.esi,
                ethernet_tag: key.ethernet_tag,
                group_id: group.id,
                members,
                ref_macs,
            }
        })
        .collect();
    groups.sort_by_key(|g| (g.vni, g.esi, g.ethernet_tag, g.group_id));

    FdbNexthopDataplaneStatus {
        groups,
        orphan_nexthops_count: u32::try_from(state.adopted_unreferenced.len()).unwrap_or(u32::MAX),
        pending_delete_count: u32::try_from(state.pending_deletes.len()).unwrap_or(u32::MAX),
        drift_recovery_disabled: state.drift_disabled,
    }
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
            // Track resources newly created in this op so a later
            // step's failure can roll them back rather than leak.
            let mut new_members: Vec<(std::net::IpAddr, u32)> = Vec::new();
            let mut new_group: Option<(crate::group_state::AliasGroupKey, u32)> = None;

            // Step 1: install any per-VTEP members not yet present.
            for ip in members {
                if state.groups.vtep_nh(ip).is_none() {
                    let id = match state.nh_id_alloc.alloc_vtep_nh() {
                        Ok(id) => id,
                        Err(e) => {
                            rollback_partial_install(
                                dataplane,
                                state,
                                &new_members,
                                new_group,
                                "install_step1_alloc",
                            )
                            .await;
                            // Allocator failure (exhaustion or
                            // tag-bit collision) won't heal on
                            // retry — surface as permanent so the
                            // actor suppresses + flags the op
                            // rather than spin forever.
                            return Err(crate::error::DataplaneError::InvalidArgument(format!(
                                "ADR-0059: vtep NH alloc failed: {e}"
                            )));
                        }
                    };
                    if let Err(e) = dataplane.add_nexthop_member(id, *ip).await {
                        state.nh_id_alloc.release(id);
                        rollback_partial_install(
                            dataplane,
                            state,
                            &new_members,
                            new_group,
                            "install_step1_add",
                        )
                        .await;
                        return Err(e);
                    }
                    state.groups.record_member_install(*ip, id);
                    state.adopted_unreferenced.remove(&id);
                    new_members.push((*ip, id));
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
                if existing_members.as_slice() != members.as_slice() {
                    // Member set drifted (e.g., re-install after
                    // partial-failure recovery). Atomic REPLACE, then
                    // GC any per-VTEP members whose last group-ref
                    // dropped — mirrors the `UpdateFdbNhgMembers`
                    // path. Without this, members removed by the
                    // drift heal stay orphaned in `vtep_nhs` and
                    // in-kernel.
                    if let Err(e) = dataplane.add_nexthop_group(g_id, &member_ids).await {
                        rollback_partial_install(
                            dataplane,
                            state,
                            &new_members,
                            new_group,
                            "install_step2_replace",
                        )
                        .await;
                        return Err(e);
                    }
                    let new_members_set: BTreeSet<_> = members.iter().copied().collect();
                    let removed = state
                        .groups
                        .record_group_member_change(*group_key, new_members_set);
                    for ip in removed {
                        if let Some(vtep_id) = state.groups.record_member_unref(ip, *group_key) {
                            try_del_and_release_alloc(dataplane, state, vtep_id, "install_drift")
                                .await;
                        }
                    }
                }
                g_id
            } else {
                let id = match state.nh_id_alloc.alloc_nhg() {
                    Ok(id) => id,
                    Err(e) => {
                        rollback_partial_install(
                            dataplane,
                            state,
                            &new_members,
                            new_group,
                            "install_step2_alloc",
                        )
                        .await;
                        // Permanent for the same reason as the
                        // vtep_nh path above — allocator failure
                        // doesn't heal on retry.
                        return Err(crate::error::DataplaneError::InvalidArgument(format!(
                            "ADR-0059: nhg alloc failed: {e}"
                        )));
                    }
                };
                if let Err(e) = dataplane.add_nexthop_group(id, &member_ids).await {
                    state.nh_id_alloc.release(id);
                    rollback_partial_install(
                        dataplane,
                        state,
                        &new_members,
                        new_group,
                        "install_step2_add",
                    )
                    .await;
                    return Err(e);
                }
                let members_set: BTreeSet<_> = members.iter().copied().collect();
                state
                    .groups
                    .record_group_install(*group_key, id, members_set);
                state.adopted_unreferenced.remove(&id);
                new_group = Some((*group_key, id));
                id
            };
            // Step 3: install the FDB row pointing at the group. On
            // failure, roll back the newly-created group (if any) and
            // members — they have no MAC ref yet, so they're true
            // orphans without rollback.
            if let Err(e) = dataplane.install_fdb_nhg_row(*vni, *mac, group_id).await {
                rollback_partial_install(
                    dataplane,
                    state,
                    &new_members,
                    new_group,
                    "install_step3",
                )
                .await;
                return Err(e);
            }
            state.groups.record_mac_ref(*group_key, *vni, *mac);
            Ok(())
        }

        DataplaneOp::UpdateFdbNhgMembers { group_key, members } => {
            // Track newly-created per-VTEP members so Step 2 failure
            // can roll them back; the group itself pre-exists (the
            // op-name says "Update", not "Install") so it never
            // appears in the rollback's `new_group` slot.
            let mut new_members: Vec<(std::net::IpAddr, u32)> = Vec::new();
            for ip in members {
                if state.groups.vtep_nh(ip).is_none() {
                    let id = match state.nh_id_alloc.alloc_vtep_nh() {
                        Ok(id) => id,
                        Err(e) => {
                            rollback_partial_install(
                                dataplane,
                                state,
                                &new_members,
                                None,
                                "update_step1_alloc",
                            )
                            .await;
                            // Allocator failure (exhaustion or
                            // tag-bit collision) won't heal on
                            // retry — surface as permanent so the
                            // actor suppresses + flags the op
                            // rather than spin forever.
                            return Err(crate::error::DataplaneError::InvalidArgument(format!(
                                "ADR-0059: vtep NH alloc failed: {e}"
                            )));
                        }
                    };
                    if let Err(e) = dataplane.add_nexthop_member(id, *ip).await {
                        state.nh_id_alloc.release(id);
                        rollback_partial_install(
                            dataplane,
                            state,
                            &new_members,
                            None,
                            "update_step1_add",
                        )
                        .await;
                        return Err(e);
                    }
                    state.groups.record_member_install(*ip, id);
                    state.adopted_unreferenced.remove(&id);
                    new_members.push((*ip, id));
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
                // out of sync — an internal state inconsistency that
                // won't heal on retry. Surface as permanent so the
                // actor suppresses + flags it rather than spinning
                // indefinitely on a bug/invariant violation.
                rollback_partial_install(dataplane, state, &new_members, None, "update_no_group")
                    .await;
                return Err(crate::error::DataplaneError::InvalidArgument(format!(
                    "ADR-0059: UpdateFdbNhgMembers for {group_key:?} but group missing \
                     from GroupOwnedMap (owned/groups state drift)",
                )));
            };
            if let Err(e) = dataplane.add_nexthop_group(g_id, &member_ids).await {
                rollback_partial_install(dataplane, state, &new_members, None, "update_step2")
                    .await;
                return Err(e);
            }
            let new_members_set: BTreeSet<_> = members.iter().copied().collect();
            let removed = state
                .groups
                .record_group_member_change(*group_key, new_members_set);
            // GC per-VTEP members whose last group-ref dropped.
            for ip in removed {
                if let Some(vtep_id) = state.groups.record_member_unref(ip, *group_key) {
                    try_del_and_release_alloc(dataplane, state, vtep_id, "update_members").await;
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
                    try_del_and_release_alloc(dataplane, state, id, "remove_group").await;
                    for ip in members {
                        if let Some(vtep_id) = state.groups.record_member_unref(ip, *group_key) {
                            try_del_and_release_alloc(dataplane, state, vtep_id, "remove_member")
                                .await;
                        }
                    }
                    Ok(())
                }
            }
        }

        _ => unreachable!("apply_nhg_op called for non-FDB-NHG op"),
    }
}

/// Op-shape-aware permanent-failure check. Returns `true` if the
/// op should be skipped (recorded shape unchanged), `false` if it
/// should run (no record, or the shape changed since the failure
/// — in which case the suppression is cleared as a side effect).
fn check_permanent_suppression<K: Ord>(
    map: &mut BTreeMap<K, DataplaneOp>,
    key: &K,
    op: &DataplaneOp,
    surface: &'static str,
) -> bool {
    let Some(recorded) = map.get(key) else {
        return false;
    };
    if recorded == op {
        tracing::trace!(
            ?op,
            surface,
            "suppressed (permanent failure, op shape unchanged)"
        );
        true
    } else {
        tracing::debug!(
            ?op,
            recorded = ?recorded,
            surface,
            "op shape changed since permanent failure; clearing suppression"
        );
        map.remove(key);
        false
    }
}

/// Roll back per-VTEP members and (optionally) a group that were
/// newly created during a partial `InstallFdbNhg` /
/// `UpdateFdbNhgMembers` execution. Called when a later step fails
/// — without this, the surrounding op would return `Err` and the
/// actor would drop the `(VNI, MAC)` retry state on permanent
/// failures, leaving the in-flight members + group permanently
/// orphaned in the kernel + allocator. Each delete attempt routes
/// through `try_del_and_release_alloc`, which keeps the allocator
/// slot reserved when the kernel delete fails (transient → queued
/// for retry; permanent → operator intervention).
async fn rollback_partial_install<D: crate::dataplane::NexthopOps>(
    dataplane: &mut D,
    state: &mut ActorState,
    new_members: &[(std::net::IpAddr, u32)],
    new_group: Option<(crate::group_state::AliasGroupKey, u32)>,
    site: &'static str,
) {
    // Group first (no FDB row exists at this point, so the ADR §5
    // invariant-2 order reduces to group → members). Delete the ID
    // returned by `drop_unreferenced_group` rather than the caller-
    // supplied one — they're expected to match (debug-asserted), but
    // if state ever drifts, the map's ID is what we actually tracked
    // and is the safer kernel reference.
    if let Some((group_key, expected_id)) = new_group
        && let Some((tracked_id, _members)) = state.groups.drop_unreferenced_group(&group_key)
    {
        debug_assert_eq!(tracked_id, expected_id, "rollback ID mismatch");
        try_del_and_release_alloc(dataplane, state, tracked_id, site).await;
    }
    // Members in reverse-creation order. Skip members that a still-
    // installed group now references — this happens on the
    // existing-group drift-heal path when Step 2's REPLACE succeeded
    // and attached the new members to the (already-live) group, and
    // Step 3 then failed: the members are no longer "newly-orphaned
    // by this op", they're legitimate group members, and deleting
    // them would leave the surviving group's `members` set pointing
    // at gone kernel state. The next reconcile will re-emit Install
    // for the failed MAC and heal the missing FDB row.
    for (ip, id) in new_members.iter().rev() {
        if state.groups.vtep_nh_is_orphan(ip) {
            state.groups.drop_vtep_nh(ip);
            try_del_and_release_alloc(dataplane, state, *id, site).await;
        } else {
            tracing::debug!(
                ?ip,
                id,
                site,
                "rollback: member now referenced by surviving group; retaining"
            );
        }
    }
}

/// Best-effort delete of a tagged kernel nexthop, releasing the
/// allocator slot only if the delete succeeded. On `Err` the slot
/// stays reserved (so a future `alloc_vtep_nh` / `alloc_nhg` cannot
/// hand out an ID still live in the kernel). Transient failures get
/// queued into `state.pending_deletes` for retry on the next
/// reconcile pass — permanent failures (e.g., `PermissionDenied`,
/// `KernelTooOld`) are NOT queued because retrying can't help; they
/// log once at warn and the kernel orphan stays until operator
/// intervention. See `drain_pending_deletes`.
async fn try_del_and_release_alloc<D: crate::dataplane::NexthopOps>(
    dataplane: &mut D,
    state: &mut ActorState,
    id: u32,
    site: &'static str,
) {
    use crate::error::FailureClass;
    match dataplane.del_nexthop(id).await {
        Ok(()) => {
            state.nh_id_alloc.release(id);
            // Clear any stale retry queue entry for this ID — if a
            // prior pass enqueued it after a transient failure and
            // the current pass succeeded via the steady-state path,
            // `drain_pending_deletes` would otherwise re-attempt the
            // delete (kernel returns ENOENT → success per slice 2's
            // idempotent ACK, but spams the log on every pass).
            state.pending_deletes.remove(&id);
        }
        Err(e) => match e.class() {
            FailureClass::Permanent => {
                tracing::warn!(
                    error = %e,
                    id,
                    site,
                    "FDB-NHG GC: del_nexthop permanently failed; allocator slot retained, kernel orphan needs operator intervention"
                );
            }
            FailureClass::Transient | FailureClass::Conflict => {
                tracing::warn!(
                    error = %e,
                    id,
                    site,
                    "FDB-NHG GC: del_nexthop failed transiently; queued for retry, allocator slot retained"
                );
                state.pending_deletes.insert(id);
            }
        },
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
