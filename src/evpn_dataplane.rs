//! Daemon-side glue between the RIB's EVPN best-path table and the
//! Linux dataplane reconciler.
//!
//! ADR-0054 §1 forbids `rustbgpd-evpn-linux` from depending on
//! `rustbgpd-rib` or `rustbgpd-transport`. The daemon binary owns the
//! coordination between the two: it queries the RIB for current
//! best-path EVPN Type 2 routes, projects them into a portable
//! [`RemoteMacTable`] via [`rustbgpd_evpn::project_evpn_routes`],
//! wraps the result in a [`DataplaneIntent`], and publishes via a
//! `tokio::sync::watch::Sender<Arc<DataplaneIntent>>` that the
//! [`ReconcileActor`] consumes.
//!
//! ## Polling vs. push
//!
//! Phase 5b uses a fixed-cadence polling supervisor that re-projects
//! every [`SupervisorConfig::poll_interval`] (default 5 s). The
//! reconcile actor's 60 s periodic dump backstop and the
//! 100ms→5s op retry already handle kernel drift at finer
//! granularity. The Gate 7c push notification (`EvpnRouteEvent`
//! broadcast added in v0.17, see `crates/rib`) is consumed by the
//! local-MAC originator only; the dataplane supervisor stays
//! poll-driven because 5 s is acceptable for FDB programming, while
//! the originator's mobility window must be sub-second.
//!
//! ## Report broadcast
//!
//! Each [`DataplaneReport`] from the reconcile actor is forwarded
//! through a [`broadcast::Sender<DataplaneReport>`] so multiple
//! daemon-side subscribers can react to the same stream without
//! contending. The existing log-only consumer is one such
//! subscriber; the SVI-MAC origination task added by
//! `advertise_svi_mac` is another.
//!
//! ## RR-only deployments
//!
//! When `[[evpn_instances]]` is empty, [`spawn`] returns `None` and no
//! background tasks are created. Route-reflector deployments incur
//! zero cost from this module.
//!
//! ## Reference
//!
//! - ADR-0054 §1 (dependency direction)
//! - ADR-0054 §2 (snapshot/watch input)
//! - ADR-0054 §6 (level-triggered reconcile)

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use rustbgpd_evpn::ip_vrf::{IpVrfTable, RemoteIpPrefixTable};
use rustbgpd_evpn::{
    BumEnforcementTable, DataplaneIntent, DataplaneReport, DuplicateMacKey, EvpnInstanceTable,
    FdbNhgDriftCounters, L3AdoptionCounters, LocalMacObservation, ProjectedEvpnEadPerEvi,
    ProjectedEvpnRoute, RemoteMacTable,
};
use rustbgpd_evpn_linux::{Dataplane, ReconcileActor, ReconcileActorConfig};
use rustbgpd_rib::{RibUpdate, route::EvpnRibRoute};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{EvpnRoute, ExtendedCommunity, PathAttribute};
use tokio::sync::{broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

pub(crate) type RemoteIpPrefixDropCounts = BTreeMap<(String, String), u64>;

/// Defaults for the daemon-side supervisor.
#[derive(Debug, Clone, Copy)]
pub struct SupervisorConfig {
    /// How often to re-project from the RIB. Higher = lower CPU
    /// during MAC churn at the cost of slower convergence on the
    /// dataplane side. The reconcile actor's 60 s periodic dump
    /// repairs any missed transitions, so this can be tuned freely
    /// without correctness impact.
    pub poll_interval: Duration,
    /// Reconcile-actor configuration forwarded to the spawned actor.
    pub actor_config: ReconcileActorConfig,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        let mut actor_config = ReconcileActorConfig::production();
        let env = match std::env::var(ADOPTION_REAP_DEFERRAL_ENV) {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                warn!("ignoring non-unicode {ADOPTION_REAP_DEFERRAL_ENV}");
                None
            }
        };
        if let Some(deferral) = adoption_reap_deferral_override(env.as_deref()) {
            info!(
                deferral_secs = deferral.as_secs(),
                "{ADOPTION_REAP_DEFERRAL_ENV} overrides the ADR-0079 adoption-reap deferrals"
            );
            actor_config.fdb_adoption_reap_deferral = deferral;
            actor_config.l3_adoption_reap_deferral = deferral;
        }
        Self {
            poll_interval: Duration::from_secs(5),
            actor_config,
        }
    }
}

/// Test / operational escape hatch for the ADR-0079 adoption-reap
/// deferrals. When set to a valid `u64` number of seconds, BOTH
/// `fdb_adoption_reap_deferral` and `l3_adoption_reap_deferral` are
/// overridden at supervisor construction — the M60 kill-and-restart
/// interop proof needs a deferral short enough to observe the reap
/// inside a CI job. Unset or invalid values keep the production
/// default of 500 s (FRR zebra `-K` parity).
const ADOPTION_REAP_DEFERRAL_ENV: &str = "RUSTBGPD_EVPN_ADOPTION_REAP_DEFERRAL_SECS";

/// Pure core of the [`ADOPTION_REAP_DEFERRAL_ENV`] override with the
/// environment value injected, so the parse rule (valid u64 seconds →
/// override, anything else → keep defaults) is unit-testable without
/// touching process-global env state.
fn adoption_reap_deferral_override(env: Option<&str>) -> Option<Duration> {
    let raw = env?;
    if let Ok(secs) = raw.trim().parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    warn!(
        value = %raw,
        "ignoring invalid {ADOPTION_REAP_DEFERRAL_ENV} (expected seconds as a u64)"
    );
    None
}

/// Cloneable ADR-0063 runtime control surface for daemon apply
/// wiring. The full handle remains owned by coordinated shutdown.
#[derive(Clone, Debug)]
pub(crate) struct EvpnDataplaneRuntimeControl {
    evpn_instances_tx: watch::Sender<Arc<EvpnInstanceTable>>,
    ip_vrfs_tx: watch::Sender<Arc<IpVrfTable>>,
}

impl EvpnDataplaneRuntimeControl {
    /// Whether the dataplane supervisor can still receive runtime
    /// model snapshots.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.evpn_instances_tx.is_closed() && !self.ip_vrfs_tx.is_closed()
    }

    /// Replace the effective L2VNI table consumed by the supervisor.
    ///
    /// ADR-0063 runtime commits publish complete snapshots rather than
    /// mutating the startup table in place. Returns `false` if the
    /// dataplane supervisor has already exited.
    #[must_use]
    pub fn replace_evpn_instances(&self, instances: Arc<EvpnInstanceTable>) -> bool {
        if self.evpn_instances_tx.is_closed() {
            return false;
        }
        self.evpn_instances_tx.send_replace(instances);
        true
    }

    /// Replace the effective IP-VRF table consumed by the supervisor.
    ///
    /// Returns `false` if the dataplane supervisor has already exited.
    #[must_use]
    pub fn replace_ip_vrfs(&self, ip_vrfs: Arc<IpVrfTable>) -> bool {
        if self.ip_vrfs_tx.is_closed() {
            return false;
        }
        self.ip_vrfs_tx.send_replace(ip_vrfs);
        true
    }
}

#[derive(Debug)]
pub struct EvpnDataplaneHandle {
    pub(crate) shutdown: CancellationToken,
    pub(crate) supervisor_join: tokio::task::JoinHandle<()>,
    pub(crate) actor_join: tokio::task::JoinHandle<()>,
    /// Upward `LocalMacObservation` receiver, taken once from the
    /// dataplane at construction time. Phase E moves this into the
    /// originator actor; if the daemon never spawns the originator
    /// (e.g., during testing) it can drop the receiver and observations
    /// will fall on the floor.
    pub local_mac_rx: Option<mpsc::Receiver<LocalMacObservation>>,
    /// Broadcast handle for [`DataplaneReport`] subscribers. The
    /// log-only consumer attached at spawn time is one subscriber;
    /// the SVI-MAC origination task gated by `advertise_svi_mac` is
    /// another. Late subscribers do not see historical reports — the
    /// reconcile actor re-emits a fresh `instance_status` row on
    /// every report (including no-op passes), so a fresh subscriber
    /// converges on the next reconcile pass without missed state.
    pub(crate) report_tx: broadcast::Sender<DataplaneReport>,
    /// Gate 8b enforcement-intent input. The segment orchestrator
    /// publishes the latest `(ESI, VNI) -> DF role` table here; the
    /// supervisor folds it into the same [`DataplaneIntent`] watch
    /// stream as remote-MAC programming.
    pub(crate) bum_enforcement_tx: watch::Sender<Arc<BumEnforcementTable>>,
    /// ADR-0063 effective L2VNI table input. Future runtime commits
    /// publish complete table snapshots here; the supervisor folds
    /// the latest table into [`DataplaneIntent`] without mutating a
    /// shared `Arc` in place.
    pub(crate) evpn_instances_tx: watch::Sender<Arc<EvpnInstanceTable>>,
    /// ADR-0063 effective IP-VRF table input. Same snapshot-watch
    /// shape as [`Self::evpn_instances_tx`], kept separate because
    /// L2VNI and IP-VRF commits can be staged independently.
    pub(crate) ip_vrfs_tx: watch::Sender<Arc<IpVrfTable>>,
    /// Current remote Type 5 projection drops by bounded `(vrf,
    /// reason)` labels. Fed from the same projection summary used by
    /// Prometheus.
    pub(crate) remote_prefix_drop_counts_rx: watch::Receiver<Arc<RemoteIpPrefixDropCounts>>,
}

impl EvpnDataplaneHandle {
    /// Subscribe to the [`DataplaneReport`] broadcast. Returns a
    /// receiver that will yield every future report from the
    /// reconcile actor, plus a `Lagged` error if the subscriber falls
    /// behind the broadcast's bounded buffer.
    #[must_use]
    pub fn subscribe_reports(&self) -> broadcast::Receiver<DataplaneReport> {
        self.report_tx.subscribe()
    }

    /// Clone the Gate 8b enforcement publisher. Consumers publish a
    /// complete table snapshot; intermediates may be coalesced by the
    /// watch channel.
    #[must_use]
    pub fn bum_enforcement_sender(&self) -> watch::Sender<Arc<BumEnforcementTable>> {
        self.bum_enforcement_tx.clone()
    }

    /// Cloneable ADR-0063 runtime control surface for daemon apply
    /// wiring. The full handle remains owned by coordinated shutdown.
    #[must_use]
    pub(crate) fn runtime_control(&self) -> EvpnDataplaneRuntimeControl {
        EvpnDataplaneRuntimeControl {
            evpn_instances_tx: self.evpn_instances_tx.clone(),
            ip_vrfs_tx: self.ip_vrfs_tx.clone(),
        }
    }

    /// Subscribe to the latest remote Type 5 projection-drop count
    /// snapshot for API/CLI status surfaces.
    #[must_use]
    pub(crate) fn remote_prefix_drop_counts_receiver(
        &self,
    ) -> watch::Receiver<Arc<RemoteIpPrefixDropCounts>> {
        self.remote_prefix_drop_counts_rx.clone()
    }

    /// Replace the effective L2VNI table consumed by the supervisor.
    ///
    /// ADR-0063 runtime commits publish complete snapshots rather than
    /// mutating the startup table in place. Returns `false` if the
    /// dataplane supervisor has already exited.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "ADR-0063 coordinator wiring will call this command; this slice adds the actor command surface first"
        )
    )]
    #[must_use]
    pub fn replace_evpn_instances(&self, instances: Arc<EvpnInstanceTable>) -> bool {
        self.runtime_control().replace_evpn_instances(instances)
    }

    /// Cancel the shutdown token, which causes the reconcile actor to
    /// drain owned remote FDB entries and exit. The supervisor
    /// follows once the watch sender is dropped. Awaits both tasks
    /// under a bounded 10 s timeout — longer than the actor's
    /// internal 5 s drain (ADR-0054 §7) but short enough that a
    /// stuck task can't wedge the daemon's exit.
    pub async fn shutdown(self) {
        let Self {
            shutdown,
            supervisor_join,
            actor_join,
            local_mac_rx: _,
            report_tx: _,
            bum_enforcement_tx: _,
            evpn_instances_tx,
            ip_vrfs_tx,
            remote_prefix_drop_counts_rx: _,
        } = self;
        shutdown.cancel();
        drop((evpn_instances_tx, ip_vrfs_tx));
        // Bound the wait — the actor's drain timeout is internal, but
        // a stuck task should not wedge the daemon's shutdown
        // forever.
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let _ = supervisor_join.await;
            let _ = actor_join.await;
        })
        .await;
    }
}

/// Spawn the EVPN dataplane stack. Returns `None` if
/// `evpn_instances` is empty (RR-only deployments take this path —
/// no netlink socket is opened, no background task is spawned).
///
/// Otherwise spawns:
///
/// 1. The polling supervisor task that periodically queries the RIB
///    via `rib_tx`, projects best-path Type 2 routes into a
///    [`RemoteMacTable`], and publishes a [`DataplaneIntent`].
/// 2. The [`ReconcileActor`] consuming intents, driving the
///    [`rustbgpd_evpn_linux::Dataplane`] implementation. On Linux
///    this is the real `LinuxDataplane` (rtnetlink-backed FDB
///    program/withdraw against the bridge/master path); on other
///    platforms the function returns `None` because the dataplane
///    is meaningless.
#[must_use = "drop the handle to shut down the EVPN dataplane stack"]
#[allow(dead_code)]
pub async fn spawn(
    config: SupervisorConfig,
    evpn_instances: &Arc<EvpnInstanceTable>,
    ip_vrfs: &Arc<IpVrfTable>,
    rib_tx: mpsc::Sender<RibUpdate>,
    metrics: BgpMetrics,
    daemon_shutdown: CancellationToken,
) -> Option<EvpnDataplaneHandle> {
    let (_, duplicate_mac_quarantine_rx) = watch::channel(Arc::new(BTreeSet::new()));
    spawn_with_quarantine(
        config,
        evpn_instances,
        ip_vrfs,
        rib_tx,
        metrics,
        daemon_shutdown,
        duplicate_mac_quarantine_rx,
    )
    .await
}

/// Spawn the EVPN dataplane stack with an external duplicate-MAC
/// quarantine feed from the local originator.
///
/// Quarantined `(VNI, MAC)` keys are excluded from remote-FDB intent while
/// preserving RIB and route-reflector visibility.
#[allow(clippy::too_many_arguments)]
pub async fn spawn_with_quarantine(
    config: SupervisorConfig,
    evpn_instances: &Arc<EvpnInstanceTable>,
    ip_vrfs: &Arc<IpVrfTable>,
    rib_tx: mpsc::Sender<RibUpdate>,
    metrics: BgpMetrics,
    daemon_shutdown: CancellationToken,
    duplicate_mac_quarantine_rx: watch::Receiver<Arc<BTreeSet<DuplicateMacKey>>>,
) -> Option<EvpnDataplaneHandle> {
    if evpn_instances.is_empty() && ip_vrfs.is_empty() {
        info!(
            "no EVPN L2 instances or IP-VRFs configured — dataplane actor not spawned \
             (RR-only deployment)"
        );
        return None;
    }

    #[cfg(target_os = "linux")]
    {
        let observation_drop_metrics = metrics.clone();
        match rustbgpd_evpn_linux::LinuxDataplane::connect_with_observation_drop_hook(
            move |reason| {
                observation_drop_metrics.record_evpn_local_observation_drop(reason);
            },
        )
        .await
        {
            Ok(mut dataplane) => {
                let local_mac_rx = dataplane.take_local_mac_rx();
                let mut handle = spawn_with_dataplane_and_quarantine(
                    config,
                    evpn_instances,
                    ip_vrfs,
                    rib_tx,
                    &metrics,
                    daemon_shutdown,
                    dataplane,
                    duplicate_mac_quarantine_rx,
                );
                handle.local_mac_rx = local_mac_rx;
                Some(handle)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not open netlink socket — EVPN dataplane disabled \
                     (CAP_NET_ADMIN missing or kernel unsupported)"
                );
                None
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            config,
            rib_tx,
            metrics,
            daemon_shutdown,
            duplicate_mac_quarantine_rx,
        );
        info!(
            target = std::env::consts::OS,
            "EVPN Linux dataplane not available on this platform; \
             skipping reconciler spawn"
        );
        None
    }
}

/// Generic spawn shared by the production path and the integration
/// tests (which inject [`rustbgpd_evpn_linux::InMemoryDataplane`]).
///
/// On the production path, [`spawn`] takes ownership of the dataplane,
/// extracts the local-MAC observation receiver via
/// [`rustbgpd_evpn_linux::Dataplane::take_local_mac_rx`], and stamps
/// it onto the returned handle. Tests calling this function directly
/// receive a handle with `local_mac_rx = None`; tests that need
/// observations should call `take_local_mac_rx` themselves before
/// passing the dataplane in.
#[allow(dead_code)]
pub fn spawn_with_dataplane<D>(
    config: SupervisorConfig,
    evpn_instances: &Arc<EvpnInstanceTable>,
    ip_vrfs: &Arc<IpVrfTable>,
    rib_tx: mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    daemon_shutdown: CancellationToken,
    dataplane: D,
) -> EvpnDataplaneHandle
where
    D: Dataplane + rustbgpd_evpn_linux::dataplane::NexthopOps + Send + Sync + 'static,
{
    let (_, duplicate_mac_quarantine_rx) = watch::channel(Arc::new(BTreeSet::new()));
    spawn_with_dataplane_and_quarantine(
        config,
        evpn_instances,
        ip_vrfs,
        rib_tx,
        metrics,
        daemon_shutdown,
        dataplane,
        duplicate_mac_quarantine_rx,
    )
}

/// Test/production helper that injects a dataplane implementation and an
/// external duplicate-MAC quarantine feed.
#[allow(clippy::too_many_arguments)]
pub fn spawn_with_dataplane_and_quarantine<D>(
    config: SupervisorConfig,
    evpn_instances: &Arc<EvpnInstanceTable>,
    ip_vrfs: &Arc<IpVrfTable>,
    rib_tx: mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    daemon_shutdown: CancellationToken,
    dataplane: D,
    duplicate_mac_quarantine_rx: watch::Receiver<Arc<BTreeSet<DuplicateMacKey>>>,
) -> EvpnDataplaneHandle
where
    D: Dataplane + rustbgpd_evpn_linux::dataplane::NexthopOps + Send + Sync + 'static,
{
    let (intent_tx, intent_rx) = watch::channel(Arc::new(DataplaneIntent::empty()));
    let (bum_enforcement_tx, bum_enforcement_rx) =
        watch::channel(Arc::new(BumEnforcementTable::new()));
    let (evpn_instances_tx, evpn_instances_rx) = watch::channel(evpn_instances.clone());
    let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(ip_vrfs.clone());
    let (remote_prefix_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(RemoteIpPrefixDropCounts::new()));

    // Reconcile actor sends reports through a bounded mpsc; a
    // forwarder task drains it and republishes through a broadcast
    // channel so multiple daemon-side subscribers (logger, SVI-MAC
    // origination, future BMP exporter) can react in parallel without
    // contending. Capacity 64 matches the previous mpsc bound — the
    // reconcile actor emits at most one report per pass (5 s default
    // poll), so 64 buffers ~5 minutes of unread reports per
    // subscriber.
    let (report_mpsc_tx, mut report_mpsc_rx) = mpsc::channel::<DataplaneReport>(64);
    let (report_broadcast_tx, _) = broadcast::channel::<DataplaneReport>(64);

    // Forwarder task: mpsc -> broadcast + structured log. Replaces
    // the previous log-only consumer; logging stays here so the
    // existing operator-visible warn/debug surface is unchanged.
    {
        let report_tx = report_broadcast_tx.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            while let Some(report) = report_mpsc_rx.recv().await {
                record_fdb_nhg_drift_metrics(&metrics, report.fdb_nhg_drift_counters);
                record_l3_adoption_metrics(&metrics, report.l3_adoption_counters);
                record_single_active_metrics(&metrics, report.single_active_counters);
                if !report.failed.is_empty() {
                    warn!(
                        intent_generation = report.intent_generation,
                        failed = report.failed.len(),
                        applied = report.applied.len(),
                        "EVPN dataplane apply failures"
                    );
                } else if !report.applied.is_empty() {
                    debug!(
                        intent_generation = report.intent_generation,
                        applied = report.applied.len(),
                        "EVPN dataplane reconcile applied"
                    );
                }
                // `send` returns Err only when there are no
                // subscribers — common at startup, harmless. Not a
                // signal to log.
                let _ = report_tx.send(report);
            }
        });
    }

    let supervisor_shutdown = daemon_shutdown.clone();
    let supervisor_join = tokio::spawn(supervisor_loop(
        config.poll_interval,
        evpn_instances_rx,
        ip_vrfs_rx,
        rib_tx,
        intent_tx,
        bum_enforcement_rx,
        duplicate_mac_quarantine_rx,
        remote_prefix_drop_counts_tx,
        metrics.clone(),
        supervisor_shutdown,
    ));

    let actor = ReconcileActor::new(
        config.actor_config,
        dataplane,
        intent_rx,
        report_mpsc_tx,
        daemon_shutdown.clone(),
    );
    let actor_join = tokio::spawn(actor.run());

    EvpnDataplaneHandle {
        shutdown: daemon_shutdown,
        supervisor_join,
        actor_join,
        local_mac_rx: None,
        report_tx: report_broadcast_tx,
        bum_enforcement_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    }
}

fn record_fdb_nhg_drift_metrics(metrics: &BgpMetrics, counters: FdbNhgDriftCounters) {
    metrics.add_evpn_fdb_nhg_drift_members_repaired(counters.members_repaired);
    metrics.add_evpn_fdb_nhg_drift_groups_replaced(counters.groups_replaced);
    metrics.add_evpn_fdb_nhg_orphans_cleaned(counters.orphans_cleaned);
    metrics.add_evpn_fdb_nhg_drift_disabled(counters.drift_disabled);
    metrics.add_evpn_fdb_single_dst_adopted(counters.single_dst_adopted);
    metrics.add_evpn_fdb_single_dst_reaped(counters.single_dst_reaped);
}

fn record_single_active_metrics(
    metrics: &BgpMetrics,
    counters: rustbgpd_evpn::SingleActiveCounters,
) {
    metrics.add_evpn_single_active_backup_swaps(counters.backup_swaps);
    metrics.add_evpn_single_active_teardowns(counters.teardowns);
}

fn record_l3_adoption_metrics(metrics: &BgpMetrics, counters: L3AdoptionCounters) {
    metrics.add_evpn_l3_route_adopted(counters.routes_adopted);
    metrics.add_evpn_l3_route_reaped(counters.routes_reaped);
    metrics.add_evpn_l3_neighbor_adopted(counters.neighbors_adopted);
    metrics.add_evpn_l3_neighbor_reaped(counters.neighbors_reaped);
    metrics.add_evpn_l3vxlan_fdb_adopted(counters.l3vxlan_fdb_adopted);
    metrics.add_evpn_l3vxlan_fdb_reaped(counters.l3vxlan_fdb_reaped);
}

/// Returns `true` when the drop-count set changed since the last pass
/// (so the caller can skip re-publishing an identical status snapshot).
fn record_remote_prefix_drop_metrics(
    metrics: &BgpMetrics,
    previous: &mut BTreeMap<(String, &'static str), u64>,
    current: BTreeMap<(String, &'static str), u64>,
) -> bool {
    if *previous == current {
        return false;
    }

    let stale: Vec<(String, &'static str)> = previous
        .keys()
        .filter(|key| !current.contains_key(*key))
        .cloned()
        .collect();
    for (vrf, reason) in stale {
        metrics.set_evpn_ip_vrf_remote_prefix_drops(&vrf, reason, 0);
    }
    for ((vrf, reason), count) in &current {
        metrics.set_evpn_ip_vrf_remote_prefix_drops(
            vrf,
            reason,
            i64::try_from(*count).unwrap_or(i64::MAX),
        );
    }
    *previous = current;
    true
}

fn publish_remote_prefix_drop_counts(
    tx: &watch::Sender<Arc<RemoteIpPrefixDropCounts>>,
    current: &BTreeMap<(String, &'static str), u64>,
) {
    let snapshot = current
        .iter()
        .map(|((vrf, reason), count)| ((vrf.clone(), (*reason).to_string()), *count))
        .collect();
    tx.send_replace(Arc::new(snapshot));
}

#[derive(Debug)]
struct SupervisorIntentState {
    generation: u64,
    last_instances: Arc<EvpnInstanceTable>,
    last_ip_vrfs: Arc<IpVrfTable>,
    last_table: Arc<RemoteMacTable>,
    last_ip_prefixes: Arc<RemoteIpPrefixTable>,
    last_ip_prefix_drop_counts: BTreeMap<(String, &'static str), u64>,
    last_bum_enforcement: BumEnforcementTable,
}

impl Default for SupervisorIntentState {
    fn default() -> Self {
        Self {
            generation: 0,
            last_instances: Arc::new(EvpnInstanceTable::new()),
            last_ip_vrfs: Arc::new(IpVrfTable::new()),
            last_table: Arc::new(RemoteMacTable::new()),
            last_ip_prefixes: Arc::new(RemoteIpPrefixTable::new()),
            last_ip_prefix_drop_counts: BTreeMap::new(),
            last_bum_enforcement: BumEnforcementTable::new(),
        }
    }
}

impl SupervisorIntentState {
    fn has_cached_projection_for(
        &self,
        instances: &EvpnInstanceTable,
        ip_vrfs: &IpVrfTable,
    ) -> bool {
        self.generation > 0
            && instances == self.last_instances.as_ref()
            && ip_vrfs == self.last_ip_vrfs.as_ref()
    }
}

#[allow(clippy::too_many_arguments)]
async fn publish_dataplane_intent(
    rib_tx: &mpsc::Sender<RibUpdate>,
    intent_tx: &watch::Sender<Arc<DataplaneIntent>>,
    instances: Arc<EvpnInstanceTable>,
    ip_vrfs: Arc<IpVrfTable>,
    bum_enforcement: BumEnforcementTable,
    quarantined_macs: &BTreeSet<DuplicateMacKey>,
    metrics: &BgpMetrics,
    state: &mut SupervisorIntentState,
    remote_prefix_drop_counts_tx: &watch::Sender<Arc<RemoteIpPrefixDropCounts>>,
) -> Result<bool, RibQueryError> {
    let tables = build_intent_tables(
        rib_tx,
        instances.as_ref(),
        ip_vrfs.as_ref(),
        quarantined_macs,
    )
    .await?;
    // ADR-0083 slice 3: refresh the backup-window gauge on every
    // successful projection, BEFORE the unchanged-table early return —
    // the gauge derives from the same RIB snapshot and must converge
    // back to zero once the new active PE's re-advertisements land.
    metrics.set_evpn_single_active_backup_active(
        i64::try_from(tables.single_active_backup_active).unwrap_or(i64::MAX),
    );
    if state.generation > 0
        && instances.as_ref() == state.last_instances.as_ref()
        && ip_vrfs.as_ref() == state.last_ip_vrfs.as_ref()
        && tables.remote_macs == *state.last_table
        && tables.remote_ip_prefixes == *state.last_ip_prefixes
        && bum_enforcement == state.last_bum_enforcement
    {
        // No semantic change since the last publish. Skipping the
        // watch send keeps the reconcile actor's permanent-suppression
        // set alive across periodic polls, so an EPERM / EOPNOTSUPP
        // on op N doesn't get retried every 5 s tick.
        return Ok(true);
    }

    let drop_counts = tables.remote_ip_prefixes.drop_counts_by_vrf_reason();
    if record_remote_prefix_drop_metrics(
        metrics,
        &mut state.last_ip_prefix_drop_counts,
        drop_counts,
    ) {
        // On change the recorder moved the new set into
        // `last_ip_prefix_drop_counts`, so publish from there instead
        // of cloning.
        publish_remote_prefix_drop_counts(
            remote_prefix_drop_counts_tx,
            &state.last_ip_prefix_drop_counts,
        );
    }

    state.generation = state.generation.saturating_add(1);
    state.last_instances = instances.clone();
    state.last_ip_vrfs = ip_vrfs.clone();
    let remote_macs = Arc::new(tables.remote_macs);
    let remote_ip_prefixes = Arc::new(tables.remote_ip_prefixes);
    state.last_table = remote_macs.clone();
    state.last_ip_prefixes = remote_ip_prefixes.clone();
    state.last_bum_enforcement = bum_enforcement.clone();

    let intent = Arc::new(DataplaneIntent {
        generation: state.generation,
        instances,
        remote_macs,
        bum_enforcement: Arc::new(bum_enforcement),
        ip_vrfs,
        remote_ip_prefixes,
    });
    if intent_tx.send(intent).is_err() {
        debug!("intent receiver gone; supervisor exiting");
        return Ok(false);
    }
    Ok(true)
}

fn publish_cached_dataplane_intent(
    intent_tx: &watch::Sender<Arc<DataplaneIntent>>,
    bum_enforcement: BumEnforcementTable,
    state: &mut SupervisorIntentState,
) -> bool {
    if state.generation > 0 && bum_enforcement == state.last_bum_enforcement {
        return true;
    }

    state.generation = state.generation.saturating_add(1);
    state.last_bum_enforcement = bum_enforcement.clone();

    let intent = Arc::new(DataplaneIntent {
        generation: state.generation,
        instances: state.last_instances.clone(),
        remote_macs: state.last_table.clone(),
        bum_enforcement: Arc::new(bum_enforcement),
        ip_vrfs: state.last_ip_vrfs.clone(),
        remote_ip_prefixes: state.last_ip_prefixes.clone(),
    });
    if intent_tx.send(intent).is_err() {
        debug!("intent receiver gone; supervisor exiting");
        return false;
    }
    true
}

/// Periodic supervisor loop: query the RIB, project, publish.
///
/// Generation only advances when the effective EVPN tables, projected
/// `RemoteMacTable`, projected Type 5 prefix table, or BUM-enforcement
/// table differ from the previously-published intent. The reconcile
/// actor uses generation as the trigger to clear permanent-failure
/// suppression; incrementing on every poll regardless of content change
/// would defeat that suppression and hammer the kernel every 5 s.
///
/// ADR-0063 table inputs are watch channels rather than mutable shared
/// tables. A future coordinator commit can publish a complete effective
/// L2VNI/IP-VRF snapshot, and the supervisor will re-project
/// immediately without waiting for the next poll interval.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Supervisor wiring intentionally keeps actor dependencies explicit.
async fn supervisor_loop(
    poll_interval: Duration,
    mut instances_rx: watch::Receiver<Arc<EvpnInstanceTable>>,
    mut ip_vrfs_rx: watch::Receiver<Arc<IpVrfTable>>,
    rib_tx: mpsc::Sender<RibUpdate>,
    intent_tx: watch::Sender<Arc<DataplaneIntent>>,
    mut bum_enforcement_rx: watch::Receiver<Arc<BumEnforcementTable>>,
    mut duplicate_mac_quarantine_rx: watch::Receiver<Arc<BTreeSet<DuplicateMacKey>>>,
    remote_prefix_drop_counts_tx: watch::Sender<Arc<RemoteIpPrefixDropCounts>>,
    metrics: BgpMetrics,
    shutdown: CancellationToken,
) {
    let mut state = SupervisorIntentState::default();
    let mut duplicate_mac_quarantine_updates_open = true;
    let mut tick = tokio::time::interval(poll_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                debug!("EVPN dataplane supervisor shutting down");
                return;
            }
            _ = tick.tick() => {
                let instances = instances_rx.borrow().clone();
                let ip_vrfs = ip_vrfs_rx.borrow().clone();
                let bum_enforcement = bum_enforcement_rx.borrow().as_ref().clone();
                let quarantined = duplicate_mac_quarantine_rx.borrow().clone();
                match publish_dataplane_intent(
                    &rib_tx,
                    &intent_tx,
                    instances,
                    ip_vrfs,
                    bum_enforcement,
                    quarantined.as_ref(),
                    &metrics,
                    &mut state,
                    &remote_prefix_drop_counts_tx,
                ).await {
                    Ok(true) => {}
                    Ok(false) => return,
                    Err(e) => {
                        warn!(error = %e, "EVPN dataplane supervisor: RIB query failed");
                    },
                }
            }
            changed = bum_enforcement_rx.changed() => {
                if changed.is_err() {
                    debug!("BUM enforcement publisher gone; supervisor exiting");
                    return;
                }
                let bum_enforcement = bum_enforcement_rx.borrow_and_update().as_ref().clone();
                let instances = instances_rx.borrow().clone();
                let ip_vrfs = ip_vrfs_rx.borrow().clone();
                if state.has_cached_projection_for(instances.as_ref(), ip_vrfs.as_ref()) {
                    if !publish_cached_dataplane_intent(
                        &intent_tx,
                        bum_enforcement,
                        &mut state,
                    ) {
                        return;
                    }
                } else {
                    let quarantined = duplicate_mac_quarantine_rx.borrow().clone();
                    match publish_dataplane_intent(
                        &rib_tx,
                        &intent_tx,
                        instances,
                        ip_vrfs,
                        bum_enforcement,
                        quarantined.as_ref(),
                        &metrics,
                        &mut state,
                        &remote_prefix_drop_counts_tx,
                    ).await {
                        Ok(true) => {}
                        Ok(false) => return,
                        Err(e) => {
                            warn!(error = %e, "EVPN dataplane supervisor: RIB query failed");
                        },
                    }
                }
            }
            changed = duplicate_mac_quarantine_rx.changed(), if duplicate_mac_quarantine_updates_open => {
                if changed.is_err() {
                    debug!("duplicate-MAC quarantine publisher gone; continuing with periodic polls");
                    duplicate_mac_quarantine_updates_open = false;
                    continue;
                }
                let instances = instances_rx.borrow().clone();
                let ip_vrfs = ip_vrfs_rx.borrow().clone();
                let bum_enforcement = bum_enforcement_rx.borrow().as_ref().clone();
                let quarantined = duplicate_mac_quarantine_rx.borrow_and_update().clone();
                match publish_dataplane_intent(
                    &rib_tx,
                    &intent_tx,
                    instances,
                    ip_vrfs,
                    bum_enforcement,
                    quarantined.as_ref(),
                    &metrics,
                    &mut state,
                    &remote_prefix_drop_counts_tx,
                ).await {
                    Ok(true) => {}
                    Ok(false) => return,
                    Err(e) => {
                        warn!(error = %e, "EVPN dataplane supervisor: RIB query failed");
                    },
                }
            }
            changed = instances_rx.changed() => {
                if changed.is_err() {
                    debug!("EVPN instance model publisher gone; supervisor exiting");
                    return;
                }
                let instances = instances_rx.borrow_and_update().clone();
                let ip_vrfs = ip_vrfs_rx.borrow().clone();
                let bum_enforcement = bum_enforcement_rx.borrow().as_ref().clone();
                let quarantined = duplicate_mac_quarantine_rx.borrow().clone();
                match publish_dataplane_intent(
                    &rib_tx,
                    &intent_tx,
                    instances,
                    ip_vrfs,
                    bum_enforcement,
                    quarantined.as_ref(),
                    &metrics,
                    &mut state,
                    &remote_prefix_drop_counts_tx,
                ).await {
                    Ok(true) => {}
                    Ok(false) => return,
                    Err(e) => {
                        warn!(error = %e, "EVPN dataplane supervisor: RIB query failed");
                    },
                }
            }
            changed = ip_vrfs_rx.changed() => {
                if changed.is_err() {
                    debug!("EVPN IP-VRF model publisher gone; supervisor exiting");
                    return;
                }
                let instances = instances_rx.borrow().clone();
                let ip_vrfs = ip_vrfs_rx.borrow_and_update().clone();
                let bum_enforcement = bum_enforcement_rx.borrow().as_ref().clone();
                let quarantined = duplicate_mac_quarantine_rx.borrow().clone();
                match publish_dataplane_intent(
                    &rib_tx,
                    &intent_tx,
                    instances,
                    ip_vrfs,
                    bum_enforcement,
                    quarantined.as_ref(),
                    &metrics,
                    &mut state,
                    &remote_prefix_drop_counts_tx,
                ).await {
                    Ok(true) => {}
                    Ok(false) => return,
                    Err(e) => {
                        warn!(error = %e, "EVPN dataplane supervisor: RIB query failed");
                    },
                }
            }
        }
    }
}

/// Query the RIB for current best-path EVPN routes and project Type 2
/// MAC/IP routes through
/// [`rustbgpd_evpn::project_evpn_routes_with_backup_paths`]. Type 1
/// EAD-per-EVI routes are projected as aliasing inputs so multi-homed
/// MACs surface their alternative VTEPs in
/// [`rustbgpd_evpn::RemoteMacEntry::alias_vtep_ips`]. Type 1 EAD-per-ES
/// routes drive the receiver-side mass-withdraw filter (RFC 7432 §8.4):
/// a Type 2 with non-zero ESI is dropped from the projection if the
/// originating peer does not currently advertise an EAD-per-ES route
/// for the same ESI. Active duplicate-MAC quarantine keys are also
/// dropped from the remote-FDB intent so the dataplane stops forwarding
/// toward a quarantined remote MAC while the RIB/RR surfaces remain
/// visible. Other route types (Type 3 IMET, Type 4 ES, Type 5
/// IP-Prefix) are ignored for Gate 7b — they're carried by the RR but
/// the L2VNI dataplane boundary only programs Type 2 MACs.
/// Outcome of one RIB query: the L2 (Type 2) remote-MAC table plus
/// the L3 (Type 5) remote-IP-prefix table, projected from the same
/// `QueryEvpnRoutes` snapshot. Single function so both tables come
/// from a consistent best-path view.
struct IntentTables {
    remote_macs: rustbgpd_evpn::RemoteMacTable,
    remote_ip_prefixes: rustbgpd_evpn::ip_vrf::RemoteIpPrefixTable,
    /// ADR-0083 slice 3: number of `(ESI, EthernetTag)` single-active
    /// groups currently retargeted at their backup PE (origin VTEP
    /// withdrew its EAD-per-ES; eligible survivors remain). Mirrored
    /// onto the `evpn_single_active_backup_active` gauge.
    single_active_backup_active: usize,
}

async fn build_intent_tables(
    rib_tx: &mpsc::Sender<RibUpdate>,
    instances: &EvpnInstanceTable,
    ip_vrfs: &rustbgpd_evpn::ip_vrf::IpVrfTable,
    quarantined_macs: &BTreeSet<DuplicateMacKey>,
) -> Result<IntentTables, RibQueryError> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    rib_tx
        .send(RibUpdate::QueryEvpnRoutes { reply: reply_tx })
        .await
        .map_err(|_| RibQueryError::SendFailed)?;
    let routes = reply_rx.await.map_err(|_| RibQueryError::ReplyDropped)?;

    // Build a quick lookup of local VTEP IPs so the EAD-per-EVI
    // self-filter doesn't require a per-route instance-table scan.
    let local_vtep_ips: std::collections::BTreeSet<std::net::IpAddr> =
        instances.iter().map(|inst| inst.local_vtep_ip).collect();

    // Build the receiver-side mass-withdraw filter set from the
    // current EAD-per-ES snapshot. A VTEP that has at least one
    // EAD-per-ES route for an ESI claims segment reachability;
    // VTEPs without one fail the §8.4 reachability precondition
    // for any Type 2 they advertise on that ESI. Key by EVPN
    // next-hop, not BGP session peer: behind a route reflector,
    // many origin VTEPs can arrive through the same BGP peer.
    // Fold duplicates deterministically: if any EAD-per-ES for a given
    // (next-hop, ESI) advertises single-active, treat the pair as
    // single-active (suppress all-active aliasing ECMP). A last-wins
    // `.collect()` would make this nondeterministic across duplicate or
    // transient (e.g. RD-changing) EAD-per-ES rows for the same key.
    let ead_per_es_modes = fold_ead_per_es_modes(&routes);
    let active_ead_per_es: std::collections::BTreeSet<(
        std::net::IpAddr,
        rustbgpd_wire::EthernetSegmentIdentifier,
    )> = ead_per_es_modes.keys().copied().collect();

    // ADR-0083: derive the single-active eligible-set index from the
    // same RIB snapshot — EAD-per-ES modes (the OR-fold above) plus
    // the FULL self-filtered EAD-per-EVI stream (the index keeps only
    // rows whose pair folds single-active; the all-active aliasing
    // feed below keeps the complement). The projection uses it to
    // give single-active MAC entries a one-member group key + the
    // pre-create-backup intent instead of bypassing the FDB-NHG
    // machinery, and (slice 3) the `project_one` mass-withdraw gate
    // uses it to keep — rather than flush — Type 2 routes whose
    // origin withdrew its EAD-per-ES while eligible survivors remain.
    // Built BEFORE the Type 2 projection because the gate consumes it.
    let single_active_index = rustbgpd_evpn::SingleActiveEligibleIndex::build(
        ead_per_es_modes
            .iter()
            .map(
                |(&(vtep_ip, esi), &single_active)| rustbgpd_evpn::EadPerEsMode {
                    esi,
                    vtep_ip,
                    single_active,
                },
            ),
        routes
            .iter()
            .filter_map(|r| project_ead_per_evi_unfiltered(r, &local_vtep_ips)),
    );

    let projected: Vec<ProjectedEvpnRoute> = routes
        .iter()
        .filter_map(|r| project_one(r, &active_ead_per_es, &single_active_index))
        .filter(|route| !projected_route_is_quarantined(route, quarantined_macs))
        .collect();
    let ead_per_evi: Vec<ProjectedEvpnEadPerEvi> = routes
        .iter()
        .filter_map(|r| project_ead_per_evi(r, &local_vtep_ips, &ead_per_es_modes))
        .collect();

    // ADR-0083 slice 3 observability: the number of (ESI, EthernetTag)
    // groups currently in the post-failover backup window — i.e. with
    // at least one locally-relevant Type 2 kept by the swap arm of
    // the mass-withdraw gate. Drives the
    // `evpn_single_active_backup_active` gauge so operators can tell
    // "expected egress DF wait" apart from "repair failed".
    let single_active_backup_active = routes
        .iter()
        .filter_map(|r| {
            let key = single_active_swap_window_key(r, &active_ead_per_es, &single_active_index)?;
            let EvpnRoute::MacIp(macip) = &r.route else {
                return None;
            };
            let vni = rustbgpd_evpn::EvpnInstanceId::new(macip.label1.as_vni()).ok()?;
            instances.get(vni)?;
            Some(key)
        })
        .collect::<BTreeSet<_>>()
        .len();

    // Gate 9 slice 6c: project Type 5 (`EvpnRoute::IpPrefix`) routes
    // through the pure helper. Skip when no IP-VRFs are configured
    // so RR-only / L2-only deployments incur no per-pass cost.
    let remote_ip_prefixes = if ip_vrfs.is_empty() {
        rustbgpd_evpn::ip_vrf::RemoteIpPrefixTable::new()
    } else {
        let projected_t5: Vec<rustbgpd_evpn::ip_vrf::ProjectedIpPrefixRoute> =
            routes.iter().filter_map(project_type5).collect();
        let overlay_index_t2: Vec<rustbgpd_evpn::ip_vrf::ProjectedOverlayIndexRoute> = projected
            .iter()
            .filter_map(|route| project_overlay_index(route, instances))
            .collect();
        rustbgpd_evpn::ip_vrf::project_ip_prefix_routes_with_overlay_index(
            ip_vrfs,
            projected_t5,
            overlay_index_t2,
        )
    };
    let remote_macs = rustbgpd_evpn::project_evpn_routes_with_backup_paths(
        instances,
        projected,
        ead_per_evi,
        &single_active_index,
    );

    Ok(IntentTables {
        remote_macs,
        remote_ip_prefixes,
        single_active_backup_active,
    })
}

/// ADR-0083 slice 3: returns the `(ESI, EthernetTag)` group key when
/// `route` is a Type 2 in the post-failover swap window — its origin
/// VTEP advertises NO EAD-per-ES for the segment (the RFC 7432 §8.2
/// mass-withdraw condition that used to flush the MAC) but the
/// segment's single-active eligible set still has a survivor to
/// retarget at. `None` for every other route shape. This is the
/// keep-vs-flush decision of the reinterpreted mass-withdraw gate;
/// [`project_one`] consults it and the supervisor counts distinct
/// keys for the `evpn_single_active_backup_active` gauge.
fn single_active_swap_window_key(
    route: &EvpnRibRoute,
    active_ead_per_es: &std::collections::BTreeSet<(
        std::net::IpAddr,
        rustbgpd_wire::EthernetSegmentIdentifier,
    )>,
    single_active_index: &rustbgpd_evpn::SingleActiveEligibleIndex,
) -> Option<(
    rustbgpd_wire::EthernetSegmentIdentifier,
    rustbgpd_wire::EthernetTagId,
)> {
    let EvpnRoute::MacIp(macip) = &route.route else {
        return None;
    };
    if macip.esi == rustbgpd_wire::EthernetSegmentIdentifier::ZERO
        || active_ead_per_es.contains(&(route.next_hop, macip.esi))
    {
        return None;
    }
    single_active_index
        .backup_pe(macip.esi, macip.ethernet_tag, route.next_hop)
        .map(|_| (macip.esi, macip.ethernet_tag))
}

fn projected_route_is_quarantined(
    route: &ProjectedEvpnRoute,
    quarantined_macs: &BTreeSet<DuplicateMacKey>,
) -> bool {
    let raw_vni = route.label1.as_vni();
    if raw_vni == 0 {
        return false;
    }
    let Ok(vni) = rustbgpd_evpn::EvpnInstanceId::new(raw_vni) else {
        return false;
    };
    quarantined_macs.contains(&DuplicateMacKey::new(vni, route.mac))
}

/// Translate a projected Type 2 MAC/IP route into an overlay-index
/// resolver input for Type 5 recursion. The caller already applied
/// mass-withdraw and quarantine gates; this helper adds host-IP,
/// local-instance, and self-originated filtering.
fn project_overlay_index(
    route: &ProjectedEvpnRoute,
    instances: &EvpnInstanceTable,
) -> Option<rustbgpd_evpn::ip_vrf::ProjectedOverlayIndexRoute> {
    let host_ip = route.host_ip?;
    let raw_vni = route.label1.as_vni();
    let vni = rustbgpd_evpn::EvpnInstanceId::new(raw_vni).ok()?;
    let local_instance = instances.get(vni)?;
    if route.next_hop == local_instance.local_vtep_ip {
        return None;
    }
    Some(rustbgpd_evpn::ip_vrf::ProjectedOverlayIndexRoute {
        vni,
        host_ip,
        mac: route.mac,
        next_hop: route.next_hop,
        mobility_sequence: route.mobility_sequence,
    })
}

/// Translate an `EvpnRibRoute` carrying a Type 5 NLRI into the
/// projection's `ProjectedIpPrefixRoute` shape (Gate 9 slice 6c).
/// Returns `None` for non-Type-5 routes. Pulls the RT list and the
/// optional Router MAC extended community from the route's
/// `ExtendedCommunities` attribute in one pass via the helper on
/// `ProjectedIpPrefixRoute`.
fn project_type5(route: &EvpnRibRoute) -> Option<rustbgpd_evpn::ip_vrf::ProjectedIpPrefixRoute> {
    let EvpnRoute::IpPrefix(prefix_route) = &route.route else {
        return None;
    };
    let ext_comms: Vec<rustbgpd_wire::ExtendedCommunity> = route
        .attributes
        .iter()
        .find_map(|a| match a {
            rustbgpd_wire::PathAttribute::ExtendedCommunities(v) => Some(v.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let (route_targets, router_mac) =
        rustbgpd_evpn::ip_vrf::ProjectedIpPrefixRoute::extcomms_to_fields(&ext_comms);
    Some(rustbgpd_evpn::ip_vrf::ProjectedIpPrefixRoute {
        rd: prefix_route.rd,
        prefix: prefix_route.prefix,
        next_hop: route.next_hop,
        gateway: prefix_route.gateway,
        l3vni: prefix_route.label.as_vni(),
        route_targets,
        router_mac,
    })
}

/// Fold the EAD-per-ES reachability snapshot into a per-`(next-hop, ESI)`
/// single-active map. If ANY EAD-per-ES route for a key advertises
/// single-active, the pair is single-active (OR-fold). This is deterministic
/// across duplicate or transient (e.g. RD-changing) EAD-per-ES rows for the
/// same key, unlike a last-wins `.collect()`.
fn fold_ead_per_es_modes(
    routes: &[EvpnRibRoute],
) -> std::collections::BTreeMap<(std::net::IpAddr, rustbgpd_wire::EthernetSegmentIdentifier), bool>
{
    let mut modes = std::collections::BTreeMap::new();
    for (key, single_active) in routes.iter().filter_map(project_ead_per_es_reachability) {
        let entry = modes.entry(key).or_insert(false);
        *entry = *entry || single_active;
    }
    modes
}

fn project_ead_per_es_reachability(
    route: &EvpnRibRoute,
) -> Option<(
    (std::net::IpAddr, rustbgpd_wire::EthernetSegmentIdentifier),
    bool,
)> {
    let EvpnRoute::EadPerEs(ead) = &route.route else {
        return None;
    };
    Some((
        (route.next_hop, ead.esi),
        ead_per_es_is_single_active(&route.attributes),
    ))
}

fn ead_per_es_is_single_active(attrs: &[PathAttribute]) -> bool {
    attrs.iter().any(|attr| {
        let PathAttribute::ExtendedCommunities(ecs) = attr else {
            return false;
        };
        ecs.iter().copied().any(|ec| {
            ec.as_esi_label()
                .is_some_and(|(single_active, _)| single_active)
        })
    })
}

/// Translate a Type 1 EAD-per-EVI [`EvpnRibRoute`] into the
/// projection's aliasing input shape. Returns `None` for non-EAD
/// routes and for self-originated EAD-per-EVI rows whose next-hop
/// matches one of our local VTEP IPs (we shouldn't surface ourselves
/// as an aliasing alternative). Single-active remote EAD-per-ES rows
/// suppress all-active aliasing ECMP for the same `(next-hop, ESI)`.
fn project_ead_per_evi(
    route: &EvpnRibRoute,
    local_vtep_ips: &std::collections::BTreeSet<std::net::IpAddr>,
    ead_per_es_modes: &std::collections::BTreeMap<
        (std::net::IpAddr, rustbgpd_wire::EthernetSegmentIdentifier),
        bool,
    >,
) -> Option<ProjectedEvpnEadPerEvi> {
    let EvpnRoute::EadPerEvi(ead) = &route.route else {
        return None;
    };
    if local_vtep_ips.contains(&route.next_hop) {
        return None;
    }
    let single_active = ead_per_es_modes.get(&(route.next_hop, ead.esi)).copied()?;
    if single_active {
        return None;
    }
    Some(ProjectedEvpnEadPerEvi {
        esi: ead.esi,
        ethernet_tag: ead.ethernet_tag,
        next_hop: route.next_hop,
    })
}

/// Translate a Type 1 EAD-per-EVI [`EvpnRibRoute`] into the ADR-0083
/// single-active eligibility input shape. Unlike
/// [`project_ead_per_evi`], this does NOT filter by EAD-per-ES mode —
/// the `SingleActiveEligibleIndex` build performs the
/// "single-active EAD-per-ES AND EAD-per-EVI" join itself (decision
/// 2's both-route-types rule). Self-originated rows are still
/// filtered: we are never our own backup path.
fn project_ead_per_evi_unfiltered(
    route: &EvpnRibRoute,
    local_vtep_ips: &std::collections::BTreeSet<std::net::IpAddr>,
) -> Option<rustbgpd_evpn::AliasEadPerEvi> {
    let EvpnRoute::EadPerEvi(ead) = &route.route else {
        return None;
    };
    if local_vtep_ips.contains(&route.next_hop) {
        return None;
    }
    Some(rustbgpd_evpn::AliasEadPerEvi {
        esi: ead.esi,
        ethernet_tag: ead.ethernet_tag,
        vtep_ip: route.next_hop,
    })
}

/// Translate a single [`EvpnRibRoute`] into the projection input
/// shape, returning `None` for non-Type-2 routes (Gate 7b L2VNI
/// dataplane only programs MAC/IP entries) and for Type 2 routes
/// that fail the RFC 7432 §8.4 mass-withdraw reachability gate
/// (non-zero ESI without a matching EAD-per-ES from the same
/// origin VTEP next-hop). ADR-0083 slice 3 reinterprets that gate
/// for single-active segments: a Type 2 whose origin VTEP lost its
/// EAD-per-ES STAYS projected iff the segment's single-active
/// eligible set is non-empty (decision 5) — the projection then
/// retargets the entry's one-member group at the derived backup,
/// and the reconcile actor realizes the retarget as one atomic
/// `NLM_F_REPLACE` per `(ESI, EthernetTag)` group with the MAC rows
/// untouched. With no eligible survivor, today's flush applies.
fn project_one(
    route: &EvpnRibRoute,
    active_ead_per_es: &std::collections::BTreeSet<(
        std::net::IpAddr,
        rustbgpd_wire::EthernetSegmentIdentifier,
    )>,
    single_active_index: &rustbgpd_evpn::SingleActiveEligibleIndex,
) -> Option<ProjectedEvpnRoute> {
    let EvpnRoute::MacIp(macip) = &route.route else {
        return None;
    };

    // Mass-withdraw filter: a Type 2 with non-zero ESI is only
    // valid if the originating VTEP also advertises an EAD-per-ES
    // for the same segment. Without that, the segment is
    // unreachable from the peer's side and we shouldn't program
    // the MAC — UNLESS the segment is single-active with a
    // surviving eligible PE, in which case the withdrawal means
    // "swap to the backup", not "flush" (ADR-0083 decision 3).
    // ESI=0 routes (single-homed) bypass the filter.
    if macip.esi != rustbgpd_wire::EthernetSegmentIdentifier::ZERO
        && !active_ead_per_es.contains(&(route.next_hop, macip.esi))
        && single_active_swap_window_key(route, active_ead_per_es, single_active_index).is_none()
    {
        return None;
    }

    let mobility_sequence = extract_mac_mobility_sequence(&route.attributes);
    Some(ProjectedEvpnRoute {
        rd: macip.rd,
        mac: macip.mac,
        host_ip: macip.ip,
        label1: macip.label1,
        next_hop: route.next_hop,
        mobility_sequence,
        esi: macip.esi,
        ethernet_tag: macip.ethernet_tag,
    })
}

/// Extract the MAC mobility sequence number from path attributes per
/// RFC 7432 §15. Returns `None` if no MAC Mobility extended
/// community is present (the absence is itself meaningful — the
/// projection's tie-break treats `None` as "older than any sequence").
fn extract_mac_mobility_sequence(attrs: &[PathAttribute]) -> Option<u32> {
    for attr in attrs {
        let PathAttribute::ExtendedCommunities(ecs) = attr else {
            continue;
        };
        for ec in ecs {
            if let Some((_sticky, seq)) = ec.as_mac_mobility() {
                return Some(seq);
            }
        }
    }
    None
}

#[derive(Debug, thiserror::Error)]
enum RibQueryError {
    #[error("RIB channel send failed")]
    SendFailed,
    #[error("RIB query reply channel dropped")]
    ReplyDropped,
}

// Suppress dead-code on a helper that may be unused on platforms
// where the dataplane spawn returns None.
#[allow(dead_code)]
const fn _force_link() -> &'static dyn Fn(&[ExtendedCommunity]) -> Option<u32> {
    &|_ecs| None
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::{IpAddr, Ipv4Addr};

    use prometheus::Encoder;
    use rustbgpd_evpn::ip_vrf::{IpVrf, IpVrfId};
    use rustbgpd_evpn::{
        BumEnforcementReadiness, BumEnforcementTable, DfRole, EvpnInstance, EvpnInstanceId,
        EvpnInstanceTable, FdbNhgDriftCounters, MacAddress, RouteDistinguisher, RouteTarget,
    };
    use rustbgpd_evpn_linux::{
        InMemoryDataplane, InstanceProbe, KernelLinkInfo, snapshot::KernelVxlanInfo,
    };
    use rustbgpd_rib::route::EvpnRibRoute;
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnEadPerEs, EvpnEadPerEvi, EvpnIpPrefixRoute,
        EvpnIpPrefixValue, EvpnMacIp, EvpnRoute, ExtendedCommunity, Ipv4Prefix, MplsLabel,
        PathAttribute,
    };

    use super::*;

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).unwrap()
    }
    fn mac(b: u8) -> MacAddress {
        MacAddress::new([b; 6])
    }
    fn ipa(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Empty single-active index: `project_one`'s ADR-0083 swap arm
    /// never fires, so the mass-withdraw gate behaves exactly as it
    /// did pre-slice-3 (flush) in the tests that pin that baseline.
    fn empty_sa_index() -> rustbgpd_evpn::SingleActiveEligibleIndex {
        rustbgpd_evpn::SingleActiveEligibleIndex::new()
    }

    fn gather_metrics_text(metrics: &BgpMetrics) -> String {
        let encoder = prometheus::TextEncoder::new();
        let families = metrics.registry().gather();
        let mut buf = Vec::new();
        encoder.encode(&families, &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn local_instance(v: u32, bridge: Option<&str>) -> EvpnInstance {
        let mut bytes = [0u8; 8];
        bytes[2..4].copy_from_slice(&65001u16.to_be_bytes());
        bytes[4..8].copy_from_slice(&v.to_be_bytes());
        EvpnInstance::new(
            vni(v),
            RouteDistinguisher::new(bytes),
            vec![RouteTarget::TwoOctetAs {
                asn: 65001,
                value: v,
            }],
            ipa("10.0.0.1"),
            bridge.map(String::from),
            false,
        )
        .unwrap()
    }

    fn local_instance_table(v: u32, bridge: Option<&str>) -> EvpnInstanceTable {
        let mut t = EvpnInstanceTable::new();
        t.insert(local_instance(v, bridge)).unwrap();
        t
    }

    fn local_instance_table_many(instances: &[(u32, Option<&str>)]) -> EvpnInstanceTable {
        let mut t = EvpnInstanceTable::new();
        for (v, bridge) in instances {
            t.insert(local_instance(*v, *bridge)).unwrap();
        }
        t
    }

    fn local_ip_vrf(name: &str, v: u32, table_id: u32) -> IpVrf {
        let mut bytes = [0u8; 8];
        bytes[2..4].copy_from_slice(&65001u16.to_be_bytes());
        bytes[4..8].copy_from_slice(&v.to_be_bytes());
        IpVrf::new(
            name.to_string(),
            IpVrfId::new(v).unwrap(),
            RouteDistinguisher::new(bytes),
            vec![RouteTarget::TwoOctetAs {
                asn: 65001,
                value: v,
            }],
            ipa("10.0.0.1"),
            MacAddress::new([0x02, 0, 0, 0, 0, (v & 0xff) as u8]),
            format!("vrf-{name}"),
            format!("l3vni-{v}"),
            table_id,
        )
        .unwrap()
    }

    fn ip_vrf_table_one(name: &str, v: u32, table_id: u32) -> IpVrfTable {
        let mut t = IpVrfTable::new();
        t.insert(local_ip_vrf(name, v, table_id)).unwrap();
        t
    }

    fn evpn_macip_route(v: u32, m: u8, dst: &str, seq: Option<u32>) -> EvpnRibRoute {
        evpn_macip_route_with_host_ip(v, m, None, dst, seq)
    }

    fn evpn_macip_route_with_host_ip(
        v: u32,
        m: u8,
        host_ip: Option<&str>,
        dst: &str,
        seq: Option<u32>,
    ) -> EvpnRibRoute {
        let macip = EvpnMacIp {
            rd: RouteDistinguisher::ZERO,
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            mac: MacAddress::new([m; 6]),
            ip: host_ip.map(ipa),
            label1: MplsLabel::new(v),
            label2: None,
        };
        let mut attrs: Vec<PathAttribute> = Vec::new();
        if let Some(seq) = seq {
            attrs.push(PathAttribute::ExtendedCommunities(vec![
                ExtendedCommunity::mac_mobility(false, seq),
            ]));
        }
        EvpnRibRoute {
            route: EvpnRoute::MacIp(macip),
            next_hop: ipa(dst),
            link_local_next_hop: None,
            peer: ipa("10.0.0.99"),
            attributes: Arc::new(attrs),
            received_at: std::time::Instant::now(),
            origin_type: rustbgpd_rib::route::RouteOrigin::Ebgp,
            peer_router_id: std::net::Ipv4Addr::new(10, 0, 0, 99),
            is_stale: false,
            is_llgr_stale: false,
        }
    }

    fn evpn_ip_prefix_route(
        prefix: &str,
        gateway: &str,
        next_hop: &str,
        l3vni: u32,
    ) -> EvpnRibRoute {
        let (addr, len) = prefix.split_once('/').unwrap();
        let prefix = EvpnIpPrefixValue::V4(Ipv4Prefix::new(
            addr.parse::<Ipv4Addr>().unwrap(),
            len.parse().unwrap(),
        ));
        EvpnRibRoute {
            route: EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
                rd: RouteDistinguisher::ZERO,
                esi: EthernetSegmentIdentifier::ZERO,
                ethernet_tag: EthernetTagId(0),
                prefix,
                gateway: gateway.parse().unwrap(),
                label: MplsLabel::new(l3vni),
            }),
            next_hop: ipa(next_hop),
            link_local_next_hop: None,
            peer: ipa("10.0.0.99"),
            attributes: Arc::new(vec![PathAttribute::ExtendedCommunities(vec![
                RouteTarget::TwoOctetAs {
                    asn: 65001,
                    value: l3vni,
                }
                .to_extended_community(),
            ])]),
            received_at: std::time::Instant::now(),
            origin_type: rustbgpd_rib::route::RouteOrigin::Ebgp,
            peer_router_id: std::net::Ipv4Addr::new(10, 0, 0, 99),
            is_stale: false,
            is_llgr_stale: false,
        }
    }

    fn evpn_ead_per_es_route(
        esi: EthernetSegmentIdentifier,
        next_hop: &str,
        single_active: bool,
    ) -> EvpnRibRoute {
        EvpnRibRoute {
            route: EvpnRoute::EadPerEs(EvpnEadPerEs {
                rd: RouteDistinguisher::ZERO,
                esi,
                ethernet_tag: EthernetTagId::MAX_ET,
                label: MplsLabel::new(123),
            }),
            next_hop: ipa(next_hop),
            link_local_next_hop: None,
            peer: ipa("10.0.0.99"),
            attributes: Arc::new(vec![PathAttribute::ExtendedCommunities(vec![
                ExtendedCommunity::esi_label(single_active, 123),
            ])]),
            received_at: std::time::Instant::now(),
            origin_type: rustbgpd_rib::route::RouteOrigin::Ebgp,
            peer_router_id: std::net::Ipv4Addr::new(10, 0, 0, 99),
            is_stale: false,
            is_llgr_stale: false,
        }
    }

    fn evpn_ead_per_evi_route(
        esi: EthernetSegmentIdentifier,
        ethernet_tag: u32,
        next_hop: &str,
    ) -> EvpnRibRoute {
        EvpnRibRoute {
            route: EvpnRoute::EadPerEvi(EvpnEadPerEvi {
                rd: RouteDistinguisher::ZERO,
                esi,
                ethernet_tag: EthernetTagId(ethernet_tag),
                label: MplsLabel::new(ethernet_tag),
            }),
            next_hop: ipa(next_hop),
            link_local_next_hop: None,
            peer: ipa("10.0.0.99"),
            attributes: Arc::new(vec![]),
            received_at: std::time::Instant::now(),
            origin_type: rustbgpd_rib::route::RouteOrigin::Ebgp,
            peer_router_id: std::net::Ipv4Addr::new(10, 0, 0, 99),
            is_stale: false,
            is_llgr_stale: false,
        }
    }

    #[test]
    fn fdb_nhg_drift_report_deltas_feed_metrics() {
        let metrics = BgpMetrics::new();
        record_fdb_nhg_drift_metrics(
            &metrics,
            FdbNhgDriftCounters {
                members_repaired: 2,
                groups_replaced: 3,
                orphans_cleaned: 4,
                drift_disabled: 1,
                single_dst_adopted: 5,
                single_dst_reaped: 6,
            },
        );

        let text = gather_metrics_text(&metrics);
        assert!(text.contains("evpn_fdb_nhg_drift_members_repaired_total 2"));
        assert!(text.contains("evpn_fdb_nhg_drift_groups_replaced_total 3"));
        assert!(text.contains("evpn_fdb_nhg_orphans_cleaned_total 4"));
        assert!(text.contains("evpn_fdb_nhg_drift_disabled_total 1"));
        assert!(text.contains("evpn_fdb_single_dst_adopted_total 5"));
        assert!(text.contains("evpn_fdb_single_dst_reaped_total 6"));
    }

    #[test]
    fn l3_adoption_report_deltas_feed_metrics() {
        let metrics = BgpMetrics::new();
        record_l3_adoption_metrics(
            &metrics,
            rustbgpd_evpn::L3AdoptionCounters {
                routes_adopted: 1,
                routes_reaped: 2,
                neighbors_adopted: 3,
                neighbors_reaped: 4,
                l3vxlan_fdb_adopted: 5,
                l3vxlan_fdb_reaped: 6,
            },
        );

        let text = gather_metrics_text(&metrics);
        assert!(text.contains("evpn_l3_route_adopted_total 1"));
        assert!(text.contains("evpn_l3_route_reaped_total 2"));
        assert!(text.contains("evpn_l3_neighbor_adopted_total 3"));
        assert!(text.contains("evpn_l3_neighbor_reaped_total 4"));
        assert!(text.contains("evpn_l3vxlan_fdb_adopted_total 5"));
        assert!(text.contains("evpn_l3vxlan_fdb_reaped_total 6"));
    }

    #[tokio::test]
    async fn remote_type5_projection_drop_metrics_track_current_snapshot() {
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(2);
        let _rib_responder = tokio::spawn(async move {
            if let Some(RibUpdate::QueryEvpnRoutes { reply }) = rib_rx.recv().await {
                let route = evpn_ip_prefix_route("10.1.0.0/24", "192.0.2.10", "10.0.0.9", 5000);
                let _ = reply.send(vec![route]);
            }
            if let Some(RibUpdate::QueryEvpnRoutes { reply }) = rib_rx.recv().await {
                let _ = reply.send(vec![]);
            }
        });
        let metrics = BgpMetrics::new();
        let instances = Arc::new(EvpnInstanceTable::new());
        let ip_vrfs = Arc::new(ip_vrf_table_one("blue", 5000, 5000));
        let (intent_tx, _intent_rx) = watch::channel(Arc::new(DataplaneIntent::empty()));
        let (drop_counts_tx, drop_counts_rx) =
            watch::channel(Arc::new(RemoteIpPrefixDropCounts::new()));
        let mut state = SupervisorIntentState::default();

        assert!(
            publish_dataplane_intent(
                &rib_tx,
                &intent_tx,
                instances.clone(),
                ip_vrfs.clone(),
                BumEnforcementTable::new(),
                &BTreeSet::new(),
                &metrics,
                &mut state,
                &drop_counts_tx,
            )
            .await
            .unwrap()
        );
        assert_eq!(
            drop_counts_rx
                .borrow()
                .get(&(
                    "blue".to_string(),
                    "overlay_index_no_linked_l2vni".to_string()
                ))
                .copied(),
            Some(1)
        );
        let text = gather_metrics_text(&metrics);
        assert!(
            text.contains(
                "evpn_ip_vrf_remote_prefix_drops{reason=\"overlay_index_no_linked_l2vni\",vrf=\"blue\"} 1"
            ) || text.contains(
                "evpn_ip_vrf_remote_prefix_drops{vrf=\"blue\",reason=\"overlay_index_no_linked_l2vni\"} 1"
            ),
            "missing current drop gauge in metrics text: {text}"
        );

        assert!(
            publish_dataplane_intent(
                &rib_tx,
                &intent_tx,
                instances,
                ip_vrfs,
                BumEnforcementTable::new(),
                &BTreeSet::new(),
                &metrics,
                &mut state,
                &drop_counts_tx,
            )
            .await
            .unwrap()
        );
        assert!(drop_counts_rx.borrow().is_empty());
        let text = gather_metrics_text(&metrics);
        assert!(
            text.contains(
                "evpn_ip_vrf_remote_prefix_drops{reason=\"overlay_index_no_linked_l2vni\",vrf=\"blue\"} 0"
            ) || text.contains(
                "evpn_ip_vrf_remote_prefix_drops{vrf=\"blue\",reason=\"overlay_index_no_linked_l2vni\"} 0"
            ),
            "stale drop gauge should be reset in metrics text: {text}"
        );
    }

    #[tokio::test]
    async fn handle_replace_evpn_instances_updates_effective_table_watch() {
        let initial = Arc::new(local_instance_table(100, Some("br100")));
        let replacement = Arc::new(local_instance_table_many(&[
            (100, Some("br100")),
            (200, Some("br200")),
        ]));
        let (evpn_instances_tx, evpn_instances_rx) = watch::channel(initial);
        let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(Arc::new(IpVrfTable::new()));
        let (bum_enforcement_tx, _bum_rx) = watch::channel(Arc::new(BumEnforcementTable::new()));
        let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
            watch::channel(Arc::new(RemoteIpPrefixDropCounts::new()));
        let (report_tx, _) = broadcast::channel::<DataplaneReport>(1);

        let handle = EvpnDataplaneHandle {
            shutdown: CancellationToken::new(),
            supervisor_join: tokio::spawn(async {}),
            actor_join: tokio::spawn(async {}),
            local_mac_rx: None,
            report_tx,
            bum_enforcement_tx,
            evpn_instances_tx,
            ip_vrfs_tx,
            remote_prefix_drop_counts_rx,
        };

        assert!(handle.replace_evpn_instances(replacement));
        assert_eq!(evpn_instances_rx.borrow().len(), 2);
        handle.shutdown().await;
    }

    #[test]
    fn project_one_picks_macip_with_mobility_seq() {
        let route = evpn_macip_route(100, 1, "10.0.0.2", Some(7));
        // ESI=0 → bypasses the mass-withdraw filter regardless of
        // the active set's contents.
        let active = std::collections::BTreeSet::new();
        let projected = project_one(&route, &active, &empty_sa_index()).unwrap();
        assert_eq!(projected.mac.octets(), [1; 6]);
        assert_eq!(projected.next_hop, ipa("10.0.0.2"));
        assert_eq!(projected.mobility_sequence, Some(7));
    }

    #[test]
    fn project_one_drops_non_macip() {
        let imet = EvpnRibRoute {
            route: EvpnRoute::Imet(rustbgpd_wire::EvpnImet {
                rd: RouteDistinguisher::ZERO,
                ethernet_tag: EthernetTagId(0),
                originator_ip: ipa("10.0.0.1"),
            }),
            next_hop: ipa("10.0.0.2"),
            link_local_next_hop: None,
            peer: ipa("10.0.0.99"),
            attributes: Arc::new(vec![]),
            received_at: std::time::Instant::now(),
            origin_type: rustbgpd_rib::route::RouteOrigin::Ebgp,
            peer_router_id: std::net::Ipv4Addr::new(10, 0, 0, 99),
            is_stale: false,
            is_llgr_stale: false,
        };
        let active = std::collections::BTreeSet::new();
        assert!(project_one(&imet, &active, &empty_sa_index()).is_none());
    }

    #[test]
    fn project_one_drops_non_zero_esi_macip_without_active_ead_per_es() {
        // RFC 7432 §8.4 mass-withdraw gate: a route whose origin VTEP
        // advertises a Type 2 with non-zero ESI but doesn't claim
        // segment reachability (no current EAD-per-ES from the same
        // origin VTEP for the same ESI) fails the receiver-side
        // reachability precondition and is dropped from projection.
        use rustbgpd_wire::{EthernetSegmentIdentifier, EvpnMacIp, MplsLabel};
        let esi = EthernetSegmentIdentifier::new([1; 10]);
        let route = EvpnRibRoute {
            route: EvpnRoute::MacIp(EvpnMacIp {
                rd: RouteDistinguisher::ZERO,
                esi,
                ethernet_tag: EthernetTagId(0),
                mac: rustbgpd_wire::MacAddress::new([2; 6]),
                ip: None,
                label1: MplsLabel::new(100),
                label2: None,
            }),
            next_hop: ipa("10.0.0.2"),
            link_local_next_hop: None,
            peer: ipa("10.0.0.99"),
            attributes: Arc::new(vec![]),
            received_at: std::time::Instant::now(),
            origin_type: rustbgpd_rib::route::RouteOrigin::Ebgp,
            peer_router_id: std::net::Ipv4Addr::new(10, 0, 0, 99),
            is_stale: false,
            is_llgr_stale: false,
        };
        // No EAD-per-ES from VTEP 10.0.0.2 for this ESI → filter.
        let empty = std::collections::BTreeSet::new();
        assert!(project_one(&route, &empty, &empty_sa_index()).is_none());
        // Same route with the active set populated → route survives.
        let mut active = std::collections::BTreeSet::new();
        active.insert((ipa("10.0.0.2"), esi));
        assert!(project_one(&route, &active, &empty_sa_index()).is_some());
        // Different VTEP in the active set doesn't satisfy the gate.
        let mut wrong_vtep = std::collections::BTreeSet::new();
        wrong_vtep.insert((ipa("10.0.0.55"), esi));
        assert!(project_one(&route, &wrong_vtep, &empty_sa_index()).is_none());
    }

    #[test]
    fn project_one_mass_withdraw_filter_keys_by_next_hop_not_bgp_peer() {
        // Route-reflector topology regression: two origin VTEPs can
        // arrive through the same BGP session peer. An active EAD-per-ES
        // from VTEP A must not keep VTEP B's Type 2 route alive.
        let esi = EthernetSegmentIdentifier::new([7; 10]);
        let mut from_vtep_a = evpn_macip_route(100, 7, "10.0.0.2", None);
        let mut from_vtep_b = from_vtep_a.clone();
        from_vtep_b.next_hop = ipa("10.0.0.3");

        if let EvpnRoute::MacIp(macip) = &mut from_vtep_a.route {
            macip.esi = esi;
        }
        if let EvpnRoute::MacIp(macip) = &mut from_vtep_b.route {
            macip.esi = esi;
        }

        assert_eq!(
            from_vtep_a.peer, from_vtep_b.peer,
            "test requires both routes to arrive through the same RR peer"
        );

        let mut active = std::collections::BTreeSet::new();
        active.insert((ipa("10.0.0.2"), esi));

        assert!(project_one(&from_vtep_a, &active, &empty_sa_index()).is_some());
        assert!(
            project_one(&from_vtep_b, &active, &empty_sa_index()).is_none(),
            "EAD-per-ES from VTEP A must not satisfy VTEP B"
        );
    }

    #[test]
    fn project_ead_per_evi_requires_all_active_ead_per_es_reachability() {
        let esi = EthernetSegmentIdentifier::new([8; 10]);
        let local_vteps = BTreeSet::new();
        let ead = evpn_ead_per_evi_route(esi, 100, "10.0.0.2");

        let no_ead_per_es = BTreeMap::new();
        assert!(
            project_ead_per_evi(&ead, &local_vteps, &no_ead_per_es).is_none(),
            "EAD-per-EVI without EAD-per-ES reachability must not create aliasing input"
        );

        let all_active = BTreeMap::from([((ipa("10.0.0.2"), esi), false)]);
        assert!(
            project_ead_per_evi(&ead, &local_vteps, &all_active).is_some(),
            "all-active EAD-per-ES reachability allows aliasing input"
        );

        let single_active = BTreeMap::from([((ipa("10.0.0.2"), esi), true)]);
        assert!(
            project_ead_per_evi(&ead, &local_vteps, &single_active).is_none(),
            "single-active EAD-per-ES reachability must suppress all-active alias ECMP"
        );
    }

    #[test]
    fn project_ead_per_es_reachability_decodes_single_active_flag() {
        let esi = EthernetSegmentIdentifier::new([9; 10]);
        let all_active = evpn_ead_per_es_route(esi, "10.0.0.2", false);
        let single_active = evpn_ead_per_es_route(esi, "10.0.0.3", true);

        assert_eq!(
            project_ead_per_es_reachability(&all_active),
            Some(((ipa("10.0.0.2"), esi), false))
        );
        assert_eq!(
            project_ead_per_es_reachability(&single_active),
            Some(((ipa("10.0.0.3"), esi), true))
        );
    }

    #[test]
    fn fold_ead_per_es_modes_or_folds_single_active_across_duplicates() {
        // Two EAD-per-ES rows for the SAME (next-hop, ESI): one all-active, one
        // single-active (e.g. a transient RD-changing duplicate). The OR-fold
        // must yield single-active regardless of arrival order, so the receiver
        // deterministically suppresses all-active aliasing ECMP.
        let esi = EthernetSegmentIdentifier::new([9; 10]);
        let nh = ipa("10.0.0.2");
        let all_active = evpn_ead_per_es_route(esi, "10.0.0.2", false);
        let single_active = evpn_ead_per_es_route(esi, "10.0.0.2", true);

        for routes in [
            vec![all_active.clone(), single_active.clone()],
            vec![single_active, all_active],
        ] {
            let modes = fold_ead_per_es_modes(&routes);
            assert_eq!(
                modes.get(&(nh, esi)),
                Some(&true),
                "single-active must win the (next-hop, ESI) fold"
            );
        }
    }

    #[tokio::test]
    async fn build_intent_tables_filters_quarantined_remote_macs() {
        let instances = local_instance_table(100, Some("br100"));
        let ip_vrfs = IpVrfTable::new();
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(1);
        let _responder = tokio::spawn(async move {
            if let Some(RibUpdate::QueryEvpnRoutes { reply }) = rib_rx.recv().await {
                let routes = vec![
                    evpn_macip_route(100, 1, "10.0.0.2", Some(7)),
                    evpn_macip_route(100, 2, "10.0.0.3", Some(7)),
                ];
                let _ = reply.send(routes);
            }
        });

        let mut quarantined = BTreeSet::new();
        quarantined.insert(DuplicateMacKey::new(vni(100), mac(1)));

        let tables = build_intent_tables(&rib_tx, &instances, &ip_vrfs, &quarantined)
            .await
            .unwrap();
        assert!(
            tables.remote_macs.get(vni(100), mac(1)).is_none(),
            "quarantined MAC must be excluded from remote-FDB intent"
        );
        assert_eq!(
            tables
                .remote_macs
                .get(vni(100), mac(2))
                .unwrap()
                .remote_vtep_ip,
            ipa("10.0.0.3")
        );
    }

    fn evpn_macip_route_with_esi(
        v: u32,
        m: u8,
        dst: &str,
        esi: EthernetSegmentIdentifier,
    ) -> EvpnRibRoute {
        let mut route = evpn_macip_route(v, m, dst, None);
        if let EvpnRoute::MacIp(macip) = &mut route.route {
            macip.esi = esi;
        }
        route
    }

    // ─── ADR-0083 slice 2: single-active projection wiring ───

    #[tokio::test]
    async fn build_intent_tables_single_active_entry_carries_backup_intent() {
        // Two PEs advertise single-active EAD-per-ES + EAD-per-EVI
        // for the segment; the MAC's origin is 10.0.0.2 → the entry
        // must carry the one-member group key (empty alias list) and
        // backup = 10.0.0.3 (lowest non-primary eligible).
        let instances = local_instance_table(100, Some("br100"));
        let ip_vrfs = IpVrfTable::new();
        let esi = EthernetSegmentIdentifier::new([7; 10]);
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(1);
        let _responder = tokio::spawn(async move {
            if let Some(RibUpdate::QueryEvpnRoutes { reply }) = rib_rx.recv().await {
                let routes = vec![
                    evpn_macip_route_with_esi(100, 1, "10.0.0.2", esi),
                    evpn_ead_per_es_route(esi, "10.0.0.2", true),
                    evpn_ead_per_es_route(esi, "10.0.0.3", true),
                    evpn_ead_per_evi_route(esi, 0, "10.0.0.2"),
                    evpn_ead_per_evi_route(esi, 0, "10.0.0.3"),
                ];
                let _ = reply.send(routes);
            }
        });

        let tables = build_intent_tables(&rib_tx, &instances, &ip_vrfs, &BTreeSet::new())
            .await
            .unwrap();
        let entry = tables.remote_macs.get(vni(100), mac(1)).unwrap();
        assert_eq!(entry.remote_vtep_ip, ipa("10.0.0.2"));
        assert!(
            entry.alias_vtep_ips.is_empty(),
            "single-active never carries ECMP aliases"
        );
        assert_eq!(entry.alias_group_key, Some((esi, EthernetTagId(0))));
        assert_eq!(entry.single_active_backup_vtep_ip, Some(ipa("10.0.0.3")));
    }

    #[tokio::test]
    async fn build_intent_tables_single_active_sole_pe_keeps_plain_dst_shape() {
        // ADR-0083 decision 1 no-backup fallback: the segment is
        // single-active but only the primary is eligible → de-facto
        // single-homed, no group key, no backup intent.
        let instances = local_instance_table(100, Some("br100"));
        let ip_vrfs = IpVrfTable::new();
        let esi = EthernetSegmentIdentifier::new([7; 10]);
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(1);
        let _responder = tokio::spawn(async move {
            if let Some(RibUpdate::QueryEvpnRoutes { reply }) = rib_rx.recv().await {
                let routes = vec![
                    evpn_macip_route_with_esi(100, 1, "10.0.0.2", esi),
                    evpn_ead_per_es_route(esi, "10.0.0.2", true),
                    evpn_ead_per_evi_route(esi, 0, "10.0.0.2"),
                ];
                let _ = reply.send(routes);
            }
        });

        let tables = build_intent_tables(&rib_tx, &instances, &ip_vrfs, &BTreeSet::new())
            .await
            .unwrap();
        let entry = tables.remote_macs.get(vni(100), mac(1)).unwrap();
        assert_eq!(entry.remote_vtep_ip, ipa("10.0.0.2"));
        assert!(entry.alias_group_key.is_none());
        assert!(entry.single_active_backup_vtep_ip.is_none());
    }

    // ─── ADR-0083 slice 3: the mass-withdraw swap window ───
    //
    // These replace the slice-2 boundary pin
    // `build_intent_tables_single_active_mass_withdraw_still_flushes_slice2`:
    // the EAD-per-ES withdrawal is reinterpreted per decision 3 — with
    // eligible survivors the MAC stays projected, retargeted at the
    // group's backup member; with none, today's flush applies.

    #[tokio::test]
    async fn build_intent_tables_single_active_mass_withdraw_swaps_to_backup() {
        // The MAC's origin VTEP (10.0.0.2) has NO EAD-per-ES — the
        // RFC 7432 §8.2 mass-withdraw condition. Two single-active
        // survivors remain eligible: the entry stays projected with
        // the one-member group retargeted at the lowest survivor
        // (10.0.0.3) and the standby re-derived as the next-lowest
        // (10.0.0.4). MAC rows are untouched downstream — the diff
        // realizes this as one membership REPLACE per group.
        let instances = local_instance_table(100, Some("br100"));
        let ip_vrfs = IpVrfTable::new();
        let esi = EthernetSegmentIdentifier::new([7; 10]);
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(1);
        let _responder = tokio::spawn(async move {
            if let Some(RibUpdate::QueryEvpnRoutes { reply }) = rib_rx.recv().await {
                let routes = vec![
                    evpn_macip_route_with_esi(100, 1, "10.0.0.2", esi),
                    evpn_ead_per_es_route(esi, "10.0.0.3", true),
                    evpn_ead_per_es_route(esi, "10.0.0.4", true),
                    evpn_ead_per_evi_route(esi, 0, "10.0.0.3"),
                    evpn_ead_per_evi_route(esi, 0, "10.0.0.4"),
                ];
                let _ = reply.send(routes);
            }
        });

        let tables = build_intent_tables(&rib_tx, &instances, &ip_vrfs, &BTreeSet::new())
            .await
            .unwrap();
        let entry = tables
            .remote_macs
            .get(vni(100), mac(1))
            .expect("withdrawal with survivors must swap, not flush (ADR-0083 decision 3)");
        assert_eq!(
            entry.remote_vtep_ip,
            ipa("10.0.0.3"),
            "group member retargets to the lowest eligible survivor"
        );
        assert!(entry.alias_vtep_ips.is_empty());
        assert_eq!(entry.alias_group_key, Some((esi, EthernetTagId(0))));
        assert_eq!(
            entry.single_active_backup_vtep_ip,
            Some(ipa("10.0.0.4")),
            "standby re-pins to the next-lowest survivor"
        );
        assert_eq!(
            tables.single_active_backup_active, 1,
            "the backup-window gauge counts this (ESI, EthTag) group"
        );
    }

    #[tokio::test]
    async fn build_intent_tables_single_active_mass_withdraw_no_survivors_flushes() {
        // Eligible set empty after the withdrawal: the existing flush
        // semantics apply (the dataplane's ordered teardown removes
        // MAC rows before the group — never-through-empty).
        let instances = local_instance_table(100, Some("br100"));
        let ip_vrfs = IpVrfTable::new();
        let esi = EthernetSegmentIdentifier::new([7; 10]);
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(1);
        let _responder = tokio::spawn(async move {
            if let Some(RibUpdate::QueryEvpnRoutes { reply }) = rib_rx.recv().await {
                let routes = vec![evpn_macip_route_with_esi(100, 1, "10.0.0.2", esi)];
                let _ = reply.send(routes);
            }
        });

        let tables = build_intent_tables(&rib_tx, &instances, &ip_vrfs, &BTreeSet::new())
            .await
            .unwrap();
        assert!(
            tables.remote_macs.get(vni(100), mac(1)).is_none(),
            "no eligible survivor → today's mass-withdraw flush"
        );
        assert_eq!(tables.single_active_backup_active, 0);
    }

    #[tokio::test]
    async fn build_intent_tables_single_active_swap_is_independent_per_ethernet_tag() {
        // Groups are keyed per (ESI, EthernetTag): an ES spanning two
        // tags takes one retarget each, derived from each tag's own
        // eligible set.
        let instances = local_instance_table(100, Some("br100"));
        let ip_vrfs = IpVrfTable::new();
        let esi = EthernetSegmentIdentifier::new([7; 10]);
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(1);
        let _responder = tokio::spawn(async move {
            if let Some(RibUpdate::QueryEvpnRoutes { reply }) = rib_rx.recv().await {
                let mut tag1_route = evpn_macip_route_with_esi(100, 2, "10.0.0.2", esi);
                if let EvpnRoute::MacIp(macip) = &mut tag1_route.route {
                    macip.ethernet_tag = EthernetTagId(1);
                }
                let routes = vec![
                    evpn_macip_route_with_esi(100, 1, "10.0.0.2", esi), // tag 0
                    tag1_route,                                         // tag 1
                    evpn_ead_per_es_route(esi, "10.0.0.3", true),
                    evpn_ead_per_es_route(esi, "10.0.0.4", true),
                    // Tag 0 survivors: .3 + .4; tag 1 survivor: .4 only.
                    evpn_ead_per_evi_route(esi, 0, "10.0.0.3"),
                    evpn_ead_per_evi_route(esi, 0, "10.0.0.4"),
                    evpn_ead_per_evi_route(esi, 1, "10.0.0.4"),
                ];
                let _ = reply.send(routes);
            }
        });

        let tables = build_intent_tables(&rib_tx, &instances, &ip_vrfs, &BTreeSet::new())
            .await
            .unwrap();
        let tag0 = tables.remote_macs.get(vni(100), mac(1)).unwrap();
        assert_eq!(tag0.remote_vtep_ip, ipa("10.0.0.3"));
        assert_eq!(tag0.alias_group_key, Some((esi, EthernetTagId(0))));
        assert_eq!(tag0.single_active_backup_vtep_ip, Some(ipa("10.0.0.4")));
        let tag1 = tables.remote_macs.get(vni(100), mac(2)).unwrap();
        assert_eq!(
            tag1.remote_vtep_ip,
            ipa("10.0.0.4"),
            "tag 1 retargets from its own eligible set"
        );
        assert_eq!(tag1.alias_group_key, Some((esi, EthernetTagId(1))));
        assert!(tag1.single_active_backup_vtep_ip.is_none());
        assert_eq!(
            tables.single_active_backup_active, 2,
            "two (ESI, EthTag) groups in the backup window"
        );
    }

    #[tokio::test]
    async fn build_intent_tables_swap_window_matches_post_readvertisement() {
        // The desired-state-as-pure-function-of-RIB property (decision
        // 5): the swap-window snapshot (dead PE's MAC routes still in
        // the RIB) and the reconverged snapshot (the new active
        // re-advertised the MAC with itself as next-hop) project the
        // IDENTICAL remote-MAC table — the post-reconverge state is
        // the same whether or not the swap fired.
        let instances = local_instance_table(100, Some("br100"));
        let ip_vrfs = IpVrfTable::new();
        let esi = EthernetSegmentIdentifier::new([7; 10]);
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(2);
        let _responder = tokio::spawn(async move {
            // Snapshot 1: the window — MAC still from dead 10.0.0.2.
            if let Some(RibUpdate::QueryEvpnRoutes { reply }) = rib_rx.recv().await {
                let routes = vec![
                    evpn_macip_route_with_esi(100, 1, "10.0.0.2", esi),
                    evpn_ead_per_es_route(esi, "10.0.0.3", true),
                    evpn_ead_per_es_route(esi, "10.0.0.4", true),
                    evpn_ead_per_evi_route(esi, 0, "10.0.0.3"),
                    evpn_ead_per_evi_route(esi, 0, "10.0.0.4"),
                ];
                let _ = reply.send(routes);
            }
            // Snapshot 2: reconverged — new active 10.0.0.3
            // re-advertised the MAC; the dead PE's route aged out.
            if let Some(RibUpdate::QueryEvpnRoutes { reply }) = rib_rx.recv().await {
                let routes = vec![
                    evpn_macip_route_with_esi(100, 1, "10.0.0.3", esi),
                    evpn_ead_per_es_route(esi, "10.0.0.3", true),
                    evpn_ead_per_es_route(esi, "10.0.0.4", true),
                    evpn_ead_per_evi_route(esi, 0, "10.0.0.3"),
                    evpn_ead_per_evi_route(esi, 0, "10.0.0.4"),
                ];
                let _ = reply.send(routes);
            }
        });

        let window = build_intent_tables(&rib_tx, &instances, &ip_vrfs, &BTreeSet::new())
            .await
            .unwrap();
        let reconverged = build_intent_tables(&rib_tx, &instances, &ip_vrfs, &BTreeSet::new())
            .await
            .unwrap();
        assert_eq!(
            window.remote_macs, reconverged.remote_macs,
            "swap-window and post-readvertisement intents must be identical"
        );
        // The gauge, however, closes with the window.
        assert_eq!(window.single_active_backup_active, 1);
        assert_eq!(reconverged.single_active_backup_active, 0);
    }

    #[tokio::test]
    async fn publish_dataplane_intent_drives_single_active_backup_gauge() {
        // The `evpn_single_active_backup_active` gauge follows the
        // projected window: 1 while the swap-kept route is in the RIB,
        // back to 0 once the new active's re-advertisement replaces it.
        let instances = Arc::new(local_instance_table(100, Some("br100")));
        let ip_vrfs = Arc::new(IpVrfTable::new());
        let esi = EthernetSegmentIdentifier::new([7; 10]);
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(2);
        let _responder = tokio::spawn(async move {
            if let Some(RibUpdate::QueryEvpnRoutes { reply }) = rib_rx.recv().await {
                let routes = vec![
                    evpn_macip_route_with_esi(100, 1, "10.0.0.2", esi),
                    evpn_ead_per_es_route(esi, "10.0.0.3", true),
                    evpn_ead_per_evi_route(esi, 0, "10.0.0.3"),
                ];
                let _ = reply.send(routes);
            }
            if let Some(RibUpdate::QueryEvpnRoutes { reply }) = rib_rx.recv().await {
                let routes = vec![
                    evpn_macip_route_with_esi(100, 1, "10.0.0.3", esi),
                    evpn_ead_per_es_route(esi, "10.0.0.3", true),
                    evpn_ead_per_evi_route(esi, 0, "10.0.0.3"),
                ];
                let _ = reply.send(routes);
            }
        });
        let metrics = BgpMetrics::new();
        let (intent_tx, _intent_rx) = watch::channel(Arc::new(DataplaneIntent::empty()));
        let (drop_counts_tx, _drop_counts_rx) =
            watch::channel(Arc::new(RemoteIpPrefixDropCounts::new()));
        let mut state = SupervisorIntentState::default();

        assert!(
            publish_dataplane_intent(
                &rib_tx,
                &intent_tx,
                instances.clone(),
                ip_vrfs.clone(),
                BumEnforcementTable::new(),
                &BTreeSet::new(),
                &metrics,
                &mut state,
                &drop_counts_tx,
            )
            .await
            .unwrap()
        );
        let text = gather_metrics_text(&metrics);
        assert!(
            text.contains("evpn_single_active_backup_active 1"),
            "gauge must show the open backup window: {text}"
        );

        assert!(
            publish_dataplane_intent(
                &rib_tx,
                &intent_tx,
                instances,
                ip_vrfs,
                BumEnforcementTable::new(),
                &BTreeSet::new(),
                &metrics,
                &mut state,
                &drop_counts_tx,
            )
            .await
            .unwrap()
        );
        let text = gather_metrics_text(&metrics);
        assert!(
            text.contains("evpn_single_active_backup_active 0"),
            "gauge must close once the new active re-advertised: {text}"
        );
    }

    #[test]
    fn single_active_report_counters_feed_metrics() {
        let metrics = BgpMetrics::new();
        record_single_active_metrics(
            &metrics,
            rustbgpd_evpn::SingleActiveCounters {
                backup_swaps: 2,
                teardowns: 1,
            },
        );
        let text = gather_metrics_text(&metrics);
        assert!(text.contains("evpn_single_active_backup_swaps_total 2"));
        assert!(text.contains("evpn_single_active_teardowns_total 1"));
    }

    #[tokio::test]
    async fn build_intent_tables_all_active_aliasing_unchanged() {
        // All-active behavior must be bit-identical with the
        // single-active index in the pipeline: ECMP aliases populate,
        // no backup intent.
        let instances = local_instance_table(100, Some("br100"));
        let ip_vrfs = IpVrfTable::new();
        let esi = EthernetSegmentIdentifier::new([7; 10]);
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(1);
        let _responder = tokio::spawn(async move {
            if let Some(RibUpdate::QueryEvpnRoutes { reply }) = rib_rx.recv().await {
                let routes = vec![
                    evpn_macip_route_with_esi(100, 1, "10.0.0.2", esi),
                    evpn_ead_per_es_route(esi, "10.0.0.2", false),
                    evpn_ead_per_es_route(esi, "10.0.0.3", false),
                    evpn_ead_per_evi_route(esi, 0, "10.0.0.2"),
                    evpn_ead_per_evi_route(esi, 0, "10.0.0.3"),
                ];
                let _ = reply.send(routes);
            }
        });

        let tables = build_intent_tables(&rib_tx, &instances, &ip_vrfs, &BTreeSet::new())
            .await
            .unwrap();
        let entry = tables.remote_macs.get(vni(100), mac(1)).unwrap();
        assert_eq!(entry.alias_vtep_ips, vec![ipa("10.0.0.3")]);
        assert_eq!(entry.alias_group_key, Some((esi, EthernetTagId(0))));
        assert!(
            entry.single_active_backup_vtep_ip.is_none(),
            "all-active entries never carry the backup intent"
        );
    }

    #[tokio::test]
    async fn build_intent_tables_resolves_overlay_index_type5_through_type2() {
        let instances = local_instance_table(100, Some("br100"));
        let mut ip_vrfs = ip_vrf_table_one("blue", 5000, 5000);
        ip_vrfs.mark_referenced_by_l2vni("blue".to_string(), vni(100));
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(1);
        let _responder = tokio::spawn(async move {
            if let Some(RibUpdate::QueryEvpnRoutes { reply }) = rib_rx.recv().await {
                let routes = vec![
                    evpn_macip_route_with_host_ip(
                        100,
                        0xaa,
                        Some("192.0.2.10"),
                        "10.0.0.2",
                        Some(7),
                    ),
                    evpn_ip_prefix_route("10.1.0.0/24", "192.0.2.10", "10.0.0.9", 5000),
                ];
                let _ = reply.send(routes);
            }
        });

        let tables = build_intent_tables(&rib_tx, &instances, &ip_vrfs, &BTreeSet::new())
            .await
            .unwrap();
        assert!(tables.remote_ip_prefixes.drops().is_empty());
        let entries: Vec<_> = tables
            .remote_ip_prefixes
            .for_vrf(IpVrfId::new(5000).unwrap())
            .collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.next_hop, ipa("10.0.0.2"));
        assert_eq!(entries[0].1.router_mac, MacAddress::new([0xaa; 6]));
    }

    #[test]
    fn extract_seq_returns_none_without_extcomm() {
        let attrs: Vec<PathAttribute> = vec![];
        assert_eq!(extract_mac_mobility_sequence(&attrs), None);
    }

    #[test]
    fn adoption_reap_deferral_override_parses_valid_seconds() {
        assert_eq!(
            adoption_reap_deferral_override(Some("5")),
            Some(Duration::from_secs(5))
        );
        // Zero is meaningful (reap on the first eligible pass), not
        // "unset" — the reconcile actor's tests rely on a zero
        // deferral, so the escape hatch must be able to express it.
        assert_eq!(
            adoption_reap_deferral_override(Some("0")),
            Some(Duration::from_secs(0))
        );
        // Surrounding whitespace is tolerated, matching the
        // RUSTBGPD_WORKER_THREADS precedent.
        assert_eq!(
            adoption_reap_deferral_override(Some(" 500 ")),
            Some(Duration::from_secs(500))
        );
    }

    #[test]
    fn adoption_reap_deferral_override_rejects_invalid_and_unset() {
        assert_eq!(adoption_reap_deferral_override(None), None);
        assert_eq!(adoption_reap_deferral_override(Some("")), None);
        assert_eq!(adoption_reap_deferral_override(Some("abc")), None);
        assert_eq!(adoption_reap_deferral_override(Some("-1")), None);
        assert_eq!(adoption_reap_deferral_override(Some("5s")), None);
        assert_eq!(adoption_reap_deferral_override(Some("1.5")), None);
    }

    #[tokio::test]
    async fn spawn_returns_none_for_empty_instance_table() {
        let instances = Arc::new(EvpnInstanceTable::new());
        let ip_vrfs = Arc::new(IpVrfTable::new());
        let (rib_tx, _rib_rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let h = spawn(
            SupervisorConfig::default(),
            &instances,
            &ip_vrfs,
            rib_tx,
            BgpMetrics::new(),
            shutdown,
        )
        .await;
        assert!(h.is_none(), "RR-only path should not spawn the actor");
    }

    #[tokio::test]
    async fn supervisor_publishes_intent_built_from_rib_query() {
        let instances = Arc::new(local_instance_table(100, Some("br100")));
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
        let shutdown = CancellationToken::new();

        // Stub RIB responder: answer one QueryEvpnRoutes with a fake
        // MacIp route, then close. The supervisor will keep polling
        // but get no further data.
        let _rib_responder = tokio::spawn({
            let route = evpn_macip_route(100, 1, "10.0.0.2", Some(3));
            async move {
                if let Some(RibUpdate::QueryEvpnRoutes { reply }) = rib_rx.recv().await {
                    let _ = reply.send(vec![route]);
                }
                // Drain subsequent queries.
                while let Some(msg) = rib_rx.recv().await {
                    if let RibUpdate::QueryEvpnRoutes { reply } = msg {
                        let _ = reply.send(vec![]);
                    }
                }
            }
        });

        let dp = InMemoryDataplane::new();
        let dp_handle = dp.handle();
        dp_handle.set_probe(vni(100), InstanceProbe::Ready);

        let cfg = SupervisorConfig {
            poll_interval: Duration::from_millis(20),
            actor_config: ReconcileActorConfig::for_tests(),
        };
        let ip_vrfs = Arc::new(IpVrfTable::new());
        let h = spawn_with_dataplane(
            cfg,
            &instances,
            &ip_vrfs,
            rib_tx,
            &BgpMetrics::new(),
            shutdown.clone(),
            dp,
        );

        // Wait for the supervisor's first tick + actor reconcile to
        // populate the kernel snapshot with the projected MAC.
        for _ in 0..50 {
            if dp_handle.kernel_has_fdb(vni(100), MacAddress::new([1; 6])) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            dp_handle.kernel_has_fdb(vni(100), MacAddress::new([1; 6])),
            "supervisor never produced a successful reconcile"
        );

        h.shutdown().await;
    }

    #[tokio::test]
    async fn supervisor_republishes_when_bum_enforcement_changes() {
        let instances = Arc::new(local_instance_table(100, Some("br100")));
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
        let shutdown = CancellationToken::new();
        let _rib_responder = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                if let RibUpdate::QueryEvpnRoutes { reply } = msg {
                    let _ = reply.send(vec![]);
                }
            }
        });

        let dp = InMemoryDataplane::new();
        let dp_handle = dp.handle();
        dp_handle.set_probe(vni(100), InstanceProbe::Ready);
        let mut links = BTreeMap::new();
        links.insert(
            "br100".to_string(),
            KernelLinkInfo {
                bridge_name: "br100".to_string(),
                vlan_filtering: false,
                vxlan: Some(KernelVxlanInfo {
                    ifindex: 200,
                    vni: 100,
                    local_ip: ipa("10.0.0.1"),
                    learning_disabled: Some(true),
                }),
                ce_port_ifindexes: vec![10],
            },
        );
        dp_handle.set_links(links);

        let cfg = SupervisorConfig {
            poll_interval: Duration::from_mins(1),
            actor_config: ReconcileActorConfig::for_tests(),
        };
        let ip_vrfs = Arc::new(IpVrfTable::new());
        let h = spawn_with_dataplane(
            cfg,
            &instances,
            &ip_vrfs,
            rib_tx,
            &BgpMetrics::new(),
            shutdown.clone(),
            dp,
        );
        let mut reports = h.subscribe_reports();

        let mut table = BumEnforcementTable::new();
        let esi = EthernetSegmentIdentifier::new([3; 10]);
        table.insert(esi, vni(100), DfRole::NonDf, "br100".to_string());
        h.bum_enforcement_sender()
            .send(Arc::new(table))
            .expect("supervisor is alive");

        let mut seen = None;
        for _ in 0..20 {
            let report = tokio::time::timeout(Duration::from_millis(100), reports.recv())
                .await
                .expect("report timeout")
                .expect("report channel open");
            if !report.bum_enforcement.is_empty() {
                seen = Some(report);
                break;
            }
        }
        let report = seen.expect("BUM enforcement report never arrived");
        assert_eq!(report.bum_enforcement[0].esi, esi);
        assert_eq!(report.bum_enforcement[0].role, DfRole::NonDf);
        assert_eq!(
            report.bum_enforcement[0].readiness,
            BumEnforcementReadiness::Ready
        );

        h.shutdown().await;
    }

    /// The supervisor must NOT bump the intent generation on every
    /// poll when the projected `RemoteMacTable` is unchanged. The
    /// reconcile actor uses the generation to clear permanent-
    /// failure suppression; bumping every 5 s would let an `EPERM` /
    /// `EOPNOTSUPP` keep retrying indefinitely.
    #[tokio::test]
    async fn supervisor_does_not_bump_generation_on_stable_table() {
        let instances = Arc::new(local_instance_table(100, Some("br100")));
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
        let shutdown = CancellationToken::new();

        // Stub RIB responder: every QueryEvpnRoutes returns the
        // same single route. The projection result is therefore
        // identical across polls.
        let _rib_responder = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                if let RibUpdate::QueryEvpnRoutes { reply } = msg {
                    let route = evpn_macip_route(100, 1, "10.0.0.2", Some(1));
                    let _ = reply.send(vec![route]);
                }
            }
        });

        // Use the watch directly so we can count actual sends. The
        // actor isn't spawned for this test — we only validate the
        // supervisor's deduplication logic.
        let (intent_tx, mut intent_rx) = watch::channel(Arc::new(DataplaneIntent::empty()));
        let (_bum_tx, bum_rx) = watch::channel(Arc::new(BumEnforcementTable::new()));
        let (_quarantine_tx, quarantine_rx) = watch::channel(Arc::new(BTreeSet::new()));
        let (drop_counts_tx, _drop_counts_rx) =
            watch::channel(Arc::new(RemoteIpPrefixDropCounts::new()));
        let supervisor_shutdown = shutdown.clone();
        let (_instances_tx, instances_rx) = watch::channel(instances);
        let (_ip_vrfs_tx, ip_vrfs_rx) = watch::channel(Arc::new(IpVrfTable::new()));
        let join = tokio::spawn(super::supervisor_loop(
            Duration::from_millis(15),
            instances_rx,
            ip_vrfs_rx,
            rib_tx,
            intent_tx,
            bum_rx,
            quarantine_rx,
            drop_counts_tx,
            BgpMetrics::new(),
            supervisor_shutdown,
        ));

        // Let the supervisor poll several times. Watch only fires
        // `changed()` when the value is replaced, so we count
        // changed-events.
        let mut observed_generations: Vec<u64> = Vec::new();
        // Capture the cold-start (gen=0).
        observed_generations.push(intent_rx.borrow().generation);
        for _ in 0..6 {
            if tokio::time::timeout(Duration::from_millis(80), intent_rx.changed())
                .await
                .is_ok()
            {
                let g = intent_rx.borrow_and_update().generation;
                if observed_generations.last().is_none_or(|&prev| prev != g) {
                    observed_generations.push(g);
                }
            }
        }

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_millis(200), join).await;

        // We expect at most: gen=0 (cold-start) + gen=1 (first
        // publish on stable table). A second publish would mean the
        // supervisor bumped generation despite an unchanged table.
        assert!(
            observed_generations.len() <= 2,
            "supervisor bumped generation on stable table: {observed_generations:?}"
        );
    }

    #[tokio::test]
    async fn supervisor_reprojects_on_runtime_instance_table_change() {
        let initial_instances = Arc::new(local_instance_table(100, Some("br100")));
        let expanded_instances = Arc::new(local_instance_table_many(&[
            (100, Some("br100")),
            (200, Some("br200")),
        ]));
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
        let shutdown = CancellationToken::new();

        let _rib_responder = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                if let RibUpdate::QueryEvpnRoutes { reply } = msg {
                    let routes = vec![
                        evpn_macip_route(100, 1, "10.0.0.2", Some(1)),
                        evpn_macip_route(200, 2, "10.0.0.3", Some(1)),
                    ];
                    let _ = reply.send(routes);
                }
            }
        });

        let (intent_tx, mut intent_rx) = watch::channel(Arc::new(DataplaneIntent::empty()));
        let (_bum_tx, bum_rx) = watch::channel(Arc::new(BumEnforcementTable::new()));
        let (_quarantine_tx, quarantine_rx) = watch::channel(Arc::new(BTreeSet::new()));
        let (drop_counts_tx, _drop_counts_rx) =
            watch::channel(Arc::new(RemoteIpPrefixDropCounts::new()));
        let (instances_tx, instances_rx) = watch::channel(initial_instances);
        let (_ip_vrfs_tx, ip_vrfs_rx) = watch::channel(Arc::new(IpVrfTable::new()));
        let supervisor_shutdown = shutdown.clone();
        let join = tokio::spawn(super::supervisor_loop(
            Duration::from_mins(1),
            instances_rx,
            ip_vrfs_rx,
            rib_tx,
            intent_tx,
            bum_rx,
            quarantine_rx,
            drop_counts_tx,
            BgpMetrics::new(),
            supervisor_shutdown,
        ));

        tokio::time::timeout(Duration::from_millis(200), intent_rx.changed())
            .await
            .unwrap()
            .unwrap();
        let initial = intent_rx.borrow_and_update().clone();
        assert!(initial.remote_macs.get(vni(100), mac(1)).is_some());
        assert!(
            initial.remote_macs.get(vni(200), mac(2)).is_none(),
            "VNI 200 must be filtered before the effective table update"
        );

        instances_tx.send_replace(expanded_instances);
        tokio::time::timeout(Duration::from_millis(200), intent_rx.changed())
            .await
            .unwrap()
            .unwrap();
        let updated = intent_rx.borrow_and_update().clone();
        assert!(updated.generation > initial.generation);
        assert_eq!(updated.instances.len(), 2);
        assert!(
            updated.remote_macs.get(vni(200), mac(2)).is_some(),
            "runtime table update should re-project before the next long poll"
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_millis(200), join).await;
    }

    #[tokio::test]
    async fn supervisor_republishes_on_runtime_ip_vrf_table_change() {
        let instances = Arc::new(EvpnInstanceTable::new());
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
        let shutdown = CancellationToken::new();

        let _rib_responder = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                if let RibUpdate::QueryEvpnRoutes { reply } = msg {
                    let _ = reply.send(vec![]);
                }
            }
        });

        let (intent_tx, mut intent_rx) = watch::channel(Arc::new(DataplaneIntent::empty()));
        let (_bum_tx, bum_rx) = watch::channel(Arc::new(BumEnforcementTable::new()));
        let (_quarantine_tx, quarantine_rx) = watch::channel(Arc::new(BTreeSet::new()));
        let (drop_counts_tx, _drop_counts_rx) =
            watch::channel(Arc::new(RemoteIpPrefixDropCounts::new()));
        let (_instances_tx, instances_rx) = watch::channel(instances);
        let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(Arc::new(IpVrfTable::new()));
        let supervisor_shutdown = shutdown.clone();
        let join = tokio::spawn(super::supervisor_loop(
            Duration::from_mins(1),
            instances_rx,
            ip_vrfs_rx,
            rib_tx,
            intent_tx,
            bum_rx,
            quarantine_rx,
            drop_counts_tx,
            BgpMetrics::new(),
            supervisor_shutdown,
        ));

        tokio::time::timeout(Duration::from_millis(200), intent_rx.changed())
            .await
            .unwrap()
            .unwrap();
        let initial = intent_rx.borrow_and_update().clone();
        assert!(initial.ip_vrfs.is_empty());

        ip_vrfs_tx.send_replace(Arc::new(ip_vrf_table_one("blue", 100, 1000)));
        tokio::time::timeout(Duration::from_millis(200), intent_rx.changed())
            .await
            .unwrap()
            .unwrap();
        let updated = intent_rx.borrow_and_update().clone();
        assert!(updated.generation > initial.generation);
        assert_eq!(updated.ip_vrfs.len(), 1);
        assert!(
            updated.remote_ip_prefixes.is_empty(),
            "stable empty RIB should still republish the changed IP-VRF table"
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_millis(200), join).await;
    }

    #[tokio::test]
    async fn supervisor_bum_enforcement_change_uses_cached_projection() {
        let instances = Arc::new(local_instance_table(100, Some("br100")));
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
        let shutdown = CancellationToken::new();

        let _rib_responder = tokio::spawn(async move {
            if let Some(RibUpdate::QueryEvpnRoutes { reply }) = rib_rx.recv().await {
                let _ = reply.send(vec![evpn_macip_route(100, 1, "10.0.0.2", Some(1))]);
            }
            // Drop the receiver after the initial projection. A BUM
            // update must republish cached route projection instead
            // of depending on another RIB query.
        });

        let (intent_tx, mut intent_rx) = watch::channel(Arc::new(DataplaneIntent::empty()));
        let (bum_tx, bum_rx) = watch::channel(Arc::new(BumEnforcementTable::new()));
        let (_quarantine_tx, quarantine_rx) = watch::channel(Arc::new(BTreeSet::new()));
        let (drop_counts_tx, _drop_counts_rx) =
            watch::channel(Arc::new(RemoteIpPrefixDropCounts::new()));
        let (_instances_tx, instances_rx) = watch::channel(instances);
        let (_ip_vrfs_tx, ip_vrfs_rx) = watch::channel(Arc::new(IpVrfTable::new()));
        let supervisor_shutdown = shutdown.clone();
        let join = tokio::spawn(super::supervisor_loop(
            Duration::from_mins(1),
            instances_rx,
            ip_vrfs_rx,
            rib_tx,
            intent_tx,
            bum_rx,
            quarantine_rx,
            drop_counts_tx,
            BgpMetrics::new(),
            supervisor_shutdown,
        ));

        tokio::time::timeout(Duration::from_millis(200), intent_rx.changed())
            .await
            .unwrap()
            .unwrap();
        let initial = intent_rx.borrow_and_update().clone();
        assert!(initial.remote_macs.get(vni(100), mac(1)).is_some());

        let mut table = BumEnforcementTable::new();
        let esi = EthernetSegmentIdentifier::new([9; 10]);
        table.insert(esi, vni(100), DfRole::NonDf, "br100".to_string());
        bum_tx.send_replace(Arc::new(table));

        tokio::time::timeout(Duration::from_millis(200), intent_rx.changed())
            .await
            .unwrap()
            .unwrap();
        let updated = intent_rx.borrow_and_update().clone();
        assert!(updated.generation > initial.generation);
        assert!(updated.remote_macs.get(vni(100), mac(1)).is_some());
        assert_eq!(
            updated
                .bum_enforcement
                .get(esi, vni(100))
                .map(|row| row.role),
            Some(DfRole::NonDf)
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_millis(200), join).await;
    }

    #[test]
    fn cached_bum_republish_uses_cached_effective_tables() {
        let cached_instances = Arc::new(local_instance_table(100, Some("br100")));
        let (intent_tx, mut intent_rx) = watch::channel(Arc::new(DataplaneIntent::empty()));
        let mut state = SupervisorIntentState {
            generation: 1,
            last_instances: cached_instances.clone(),
            last_ip_vrfs: Arc::new(IpVrfTable::new()),
            last_table: Arc::new(RemoteMacTable::new()),
            last_ip_prefixes: Arc::new(RemoteIpPrefixTable::new()),
            last_ip_prefix_drop_counts: BTreeMap::new(),
            last_bum_enforcement: BumEnforcementTable::new(),
        };
        let mut table = BumEnforcementTable::new();
        let esi = EthernetSegmentIdentifier::new([9; 10]);
        table.insert(esi, vni(100), DfRole::NonDf, "br100".to_string());

        assert!(publish_cached_dataplane_intent(
            &intent_tx, table, &mut state
        ));

        let updated = intent_rx.borrow_and_update().clone();
        assert_eq!(
            updated.instances.as_ref(),
            cached_instances.as_ref(),
            "cached BUM republish must use the effective tables that produced the cached projection"
        );
        assert_eq!(updated.ip_vrfs.len(), 0);
        assert_eq!(updated.generation, 2);
        assert!(Arc::ptr_eq(&updated.remote_macs, &state.last_table));
        assert!(Arc::ptr_eq(
            &updated.remote_ip_prefixes,
            &state.last_ip_prefixes
        ));
    }

    #[tokio::test]
    async fn supervisor_reprojects_on_duplicate_mac_quarantine_change() {
        let instances = Arc::new(local_instance_table(100, Some("br100")));
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
        let shutdown = CancellationToken::new();

        let _rib_responder = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                if let RibUpdate::QueryEvpnRoutes { reply } = msg {
                    let route = evpn_macip_route(100, 1, "10.0.0.2", Some(1));
                    let _ = reply.send(vec![route]);
                }
            }
        });

        let (intent_tx, mut intent_rx) = watch::channel(Arc::new(DataplaneIntent::empty()));
        let (_bum_tx, bum_rx) = watch::channel(Arc::new(BumEnforcementTable::new()));
        let (quarantine_tx, quarantine_rx) = watch::channel(Arc::new(BTreeSet::new()));
        let (drop_counts_tx, _drop_counts_rx) =
            watch::channel(Arc::new(RemoteIpPrefixDropCounts::new()));
        let supervisor_shutdown = shutdown.clone();
        let (_instances_tx, instances_rx) = watch::channel(instances);
        let (_ip_vrfs_tx, ip_vrfs_rx) = watch::channel(Arc::new(IpVrfTable::new()));
        let join = tokio::spawn(super::supervisor_loop(
            Duration::from_mins(1),
            instances_rx,
            ip_vrfs_rx,
            rib_tx,
            intent_tx,
            bum_rx,
            quarantine_rx,
            drop_counts_tx,
            BgpMetrics::new(),
            supervisor_shutdown,
        ));

        tokio::time::timeout(Duration::from_millis(200), intent_rx.changed())
            .await
            .unwrap()
            .unwrap();
        let initial = intent_rx.borrow_and_update().clone();
        assert!(
            initial.remote_macs.get(vni(100), mac(1)).is_some(),
            "initial projection should include the remote MAC"
        );

        let mut quarantined = BTreeSet::new();
        quarantined.insert(DuplicateMacKey::new(vni(100), mac(1)));
        quarantine_tx.send_replace(Arc::new(quarantined));

        tokio::time::timeout(Duration::from_millis(200), intent_rx.changed())
            .await
            .unwrap()
            .unwrap();
        let updated = intent_rx.borrow_and_update().clone();
        assert!(
            updated.remote_macs.get(vni(100), mac(1)).is_none(),
            "quarantine update should re-project before the next long poll interval"
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_millis(200), join).await;
    }
}
