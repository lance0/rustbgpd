//! ADR-0061 general unicast Linux FIB reconciler.
//!
//! This actor is deliberately separate from the EVPN dataplane crates:
//! it consumes ordinary unicast Loc-RIB best routes and writes only the
//! explicit `[[fib_tables]]` route tables the operator configured. RIB
//! events are wakeups; every pass re-queries the full best-route view
//! and runs the pure [`crate::fib`] projection/diff model.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use rustbgpd_rib::{FibInstallCandidate, RibUpdate, RouteOrigin};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix, Prefix};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::FibTableConfig;
use crate::fib::{
    FibDrop, FibIntent, FibKernelProtocol, FibKernelRoute, FibKernelSnapshot, FibOp, FibOwnedState,
    FibPlan, FibRoute, FibRouteKey, FibRouteTarget, FibTableKey, compute_fib_diff,
    project_fib_intent_with_peer_groups, record_fib_success,
};
use crate::fib_common::{prefix_and_nexthop_same_family, table_allows_prefix};

const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
const ROUTE_EVENT_DEBOUNCE: Duration = Duration::from_millis(200);
const RIB_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Runtime config resolved from `[[fib_tables]]`.
#[derive(Debug, Clone, PartialEq)]
pub struct FibRuntimeConfig {
    /// Explicit tables the daemon may write.
    pub tables: Vec<FibTableConfig>,
    /// Optional persisted owned-state file used to recover exact route
    /// ownership after an ungraceful process restart.
    pub owned_state_path: Option<PathBuf>,
}

impl FibRuntimeConfig {
    /// Returns true when the actor should run.
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.tables.is_empty()
    }
}

/// Operator-visible state for one projected FIB row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FibRuntimeStatus {
    pub table_name: String,
    pub table_id: u32,
    pub metric: u32,
    pub prefix: Prefix,
    pub next_hop: Option<IpAddr>,
    pub peer: Option<IpAddr>,
    pub state: FibRuntimeState,
    pub reason: String,
    pub sampling: Option<FibRuntimeSampling>,
}

/// Sampling metadata for high-cardinality FIB status reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FibRuntimeSampling {
    pub sampled_rows: u64,
    pub suppressed_rows: u64,
    pub total_rows: u64,
    pub max_routes: u32,
    pub sample_limit: u32,
}

/// High-level install state surfaced through gRPC/CLI and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FibRuntimeState {
    Installed,
    Rejected,
    Failed,
}

/// Per-route FIB dataplane outcome emitted by the reconciler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FibRuntimeEvent {
    pub kind: FibRuntimeEventKind,
    pub table_name: String,
    pub table_id: u32,
    pub metric: u32,
    pub prefix: Prefix,
    pub next_hop: Option<IpAddr>,
    pub peer: Option<IpAddr>,
    pub timestamp: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FibRuntimeEventKind {
    Installed,
    Withdrawn,
    Failed,
}

/// Join handle wrapper used by main shutdown.
pub struct FibRuntimeHandle {
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl FibRuntimeHandle {
    /// Request shutdown and wait for bounded cleanup of owned routes.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        match tokio::time::timeout(SHUTDOWN_TIMEOUT, self.task).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                warn!(error = %e, "general FIB task panicked during shutdown");
            }
            Err(_) => {
                warn!(
                    timeout_ms = SHUTDOWN_TIMEOUT.as_millis(),
                    "general FIB task did not finish before shutdown timeout"
                );
            }
        }
    }
}

/// Spawn the Linux-backed general FIB reconciler. Returns `None`
/// when no `[[fib_tables]]` are configured or the platform has no
/// Linux route primitive.
#[must_use]
pub fn spawn(
    config: FibRuntimeConfig,
    rib_tx: mpsc::Sender<RibUpdate>,
    rib_query_tx: mpsc::Sender<RibUpdate>,
    metrics: BgpMetrics,
    status_tx: watch::Sender<Vec<FibRuntimeStatus>>,
    event_tx: broadcast::Sender<FibRuntimeEvent>,
    shutdown: CancellationToken,
) -> Option<FibRuntimeHandle> {
    if !config.enabled() {
        return None;
    }

    #[cfg(target_os = "linux")]
    {
        match LinuxUnicastFib::connect() {
            Ok(fib) => Some(spawn_with_fib(
                config,
                rib_tx,
                rib_query_tx,
                fib,
                metrics,
                status_tx,
                event_tx,
                shutdown,
            )),
            Err(e) => {
                metrics.record_fib_kernel_failure("setup");
                warn!(error = %e, "general FIB install requested, but netlink setup failed");
                None
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (rib_tx, rib_query_tx, status_tx, event_tx, shutdown);
        metrics.record_fib_kernel_failure("unsupported_platform");
        warn!("general FIB install requested, but kernel route programming is Linux-only");
        None
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "testable actor startup wiring includes event and status channels"
)]
fn spawn_with_fib<F>(
    config: FibRuntimeConfig,
    rib_tx: mpsc::Sender<RibUpdate>,
    rib_query_tx: mpsc::Sender<RibUpdate>,
    fib: F,
    metrics: BgpMetrics,
    status_tx: watch::Sender<Vec<FibRuntimeStatus>>,
    event_tx: broadcast::Sender<FibRuntimeEvent>,
    shutdown: CancellationToken,
) -> FibRuntimeHandle
where
    F: UnicastFib + Send + 'static,
{
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move {
        run_loop(
            config,
            rib_tx,
            rib_query_tx,
            fib,
            metrics,
            status_tx,
            event_tx,
            task_shutdown,
        )
        .await;
    });
    FibRuntimeHandle { shutdown, task }
}

#[expect(
    clippy::too_many_arguments,
    reason = "actor loop owns resolved runtime channels and shutdown handles"
)]
async fn run_loop<F>(
    config: FibRuntimeConfig,
    rib_tx: mpsc::Sender<RibUpdate>,
    rib_query_tx: mpsc::Sender<RibUpdate>,
    mut fib: F,
    metrics: BgpMetrics,
    status_tx: watch::Sender<Vec<FibRuntimeStatus>>,
    event_tx: broadcast::Sender<FibRuntimeEvent>,
    shutdown: CancellationToken,
) where
    F: UnicastFib,
{
    let mut owned = load_owned_state(&config);
    let mut interval = tokio::time::interval(RECONCILE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    let mut event_debounce = Box::pin(tokio::time::sleep(ROUTE_EVENT_DEBOUNCE));
    let mut route_event_dirty = false;

    let mut route_events = subscribe_route_events(&rib_tx).await;
    reconcile_once_with_events(
        &config,
        &rib_query_tx,
        &mut fib,
        &metrics,
        &status_tx,
        &event_tx,
        &mut owned,
        &shutdown,
    )
    .await;

    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                drain_owned_with_events(
                    &config,
                    &mut fib,
                    &metrics,
                    &status_tx,
                    &event_tx,
                    &mut owned,
                )
                .await;
                return;
            }
            _ = interval.tick() => {
                reconcile_once_with_events(
                    &config,
                    &rib_query_tx,
                    &mut fib,
                    &metrics,
                    &status_tx,
                    &event_tx,
                    &mut owned,
                    &shutdown,
                ).await;
            }
            () = &mut event_debounce, if route_event_dirty => {
                route_event_dirty = false;
                reconcile_once_with_events(
                    &config,
                    &rib_query_tx,
                    &mut fib,
                    &metrics,
                    &status_tx,
                    &event_tx,
                    &mut owned,
                    &shutdown,
                ).await;
            }
            maybe_event = recv_route_event(&mut route_events) => {
                match maybe_event {
                    Some(()) => {
                        route_event_dirty = true;
                        event_debounce
                            .as_mut()
                            .reset(tokio::time::Instant::now() + ROUTE_EVENT_DEBOUNCE);
                    }
                    None => route_events = subscribe_route_events(&rib_tx).await,
                }
            }
        }
    }
}

async fn subscribe_route_events(
    rib_tx: &mpsc::Sender<RibUpdate>,
) -> Option<broadcast::Receiver<rustbgpd_rib::RouteEvent>> {
    let (reply, rx) = oneshot::channel();
    if rib_tx
        .send(RibUpdate::SubscribeRouteEvents { reply })
        .await
        .is_err()
    {
        warn!("general FIB task could not subscribe to RIB events");
        return None;
    }
    if let Ok(events) = rx.await {
        Some(events)
    } else {
        warn!("general FIB task subscription reply dropped");
        None
    }
}

async fn recv_route_event(
    rx: &mut Option<broadcast::Receiver<rustbgpd_rib::RouteEvent>>,
) -> Option<()> {
    let Some(rx) = rx.as_mut() else {
        std::future::pending::<()>().await;
        return None;
    };
    match rx.recv().await {
        Ok(_event) => Some(()),
        Err(broadcast::error::RecvError::Lagged(n)) => {
            debug!(
                lagged = n,
                "general FIB task lagged RIB event stream; full reconcile follows"
            );
            Some(())
        }
        Err(broadcast::error::RecvError::Closed) => None,
    }
}

async fn query_fib_install_candidates(
    rib_tx: &mpsc::Sender<RibUpdate>,
    max_paths: u32,
) -> Result<Vec<FibInstallCandidate>, &'static str> {
    let (reply, rx) = oneshot::channel();
    if rib_tx
        .send(RibUpdate::QueryFibInstallCandidates { max_paths, reply })
        .await
        .is_err()
    {
        warn!("general FIB task could not query install candidates");
        return Err("send_failed");
    }
    match tokio::time::timeout(RIB_QUERY_TIMEOUT, rx).await {
        Ok(Ok(candidates)) => Ok(candidates),
        Ok(Err(_)) => {
            warn!("general FIB task install-candidate reply dropped");
            Err("reply_dropped")
        }
        Err(_) => {
            warn!("general FIB task install-candidate query timed out");
            Err("timeout")
        }
    }
}

/// Widest ECMP fan-out any configured table wants. The RIB returns candidates
/// capped at this width; projection re-caps per table. Unset / 1 ⇒ today's
/// single-next-hop behavior, so a default config never pays for sibling
/// gathering.
fn max_install_paths(config: &FibRuntimeConfig) -> u32 {
    config
        .tables
        .iter()
        .map(|table| table.maximum_paths.unwrap_or(1).max(1))
        .max()
        .unwrap_or(1)
}

async fn query_peer_groups(
    rib_tx: &mpsc::Sender<RibUpdate>,
) -> Result<BTreeMap<IpAddr, String>, &'static str> {
    let (reply, rx) = oneshot::channel();
    if rib_tx
        .send(RibUpdate::QueryPeerGroups { reply })
        .await
        .is_err()
    {
        warn!("general FIB task could not query peer-group map");
        return Err("send_failed");
    }
    match tokio::time::timeout(RIB_QUERY_TIMEOUT, rx).await {
        Ok(Ok(groups)) => Ok(groups.into_iter().collect()),
        Ok(Err(_)) => {
            warn!("general FIB task peer-group reply dropped");
            Err("reply_dropped")
        }
        Err(_) => {
            warn!("general FIB task peer-group query timed out");
            Err("timeout")
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "single reconcile pass needs snapshots, metrics, status, events, and cancellation"
)]
async fn reconcile_once_with_events<F>(
    config: &FibRuntimeConfig,
    rib_query_tx: &mpsc::Sender<RibUpdate>,
    fib: &mut F,
    metrics: &BgpMetrics,
    status_tx: &watch::Sender<Vec<FibRuntimeStatus>>,
    event_tx: &broadcast::Sender<FibRuntimeEvent>,
    owned: &mut FibOwnedState,
    shutdown: &CancellationToken,
) where
    F: UnicastFib,
{
    let candidates = tokio::select! {
        biased;
        () = shutdown.cancelled() => return,
        result = query_fib_install_candidates(rib_query_tx, max_install_paths(config)) => match result {
            Ok(candidates) => candidates,
            Err(reason) => {
                status_tx.send_replace(failed_rib_query_statuses(owned, reason));
                return;
            }
        },
    };
    let peer_groups = if config
        .tables
        .iter()
        .any(|table| !table.allowed_peer_groups.is_empty())
    {
        match tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            result = query_peer_groups(rib_query_tx) => result,
        } {
            Ok(groups) => groups,
            Err(reason) => {
                status_tx.send_replace(failed_rib_query_statuses(owned, reason));
                return;
            }
        }
    } else {
        BTreeMap::new()
    };
    let intent = project_fib_intent_with_peer_groups(&config.tables, &candidates, &peer_groups);
    let kernel = tokio::select! {
        biased;
        () = shutdown.cancelled() => return,
        result = fib.dump(&config.tables) => match result {
            Ok(snapshot) => snapshot,
            Err(e) => {
                metrics.record_fib_kernel_failure("dump");
                warn!(error = %e, "failed to dump configured FIB tables");
                status_tx.send_replace(failed_dump_statuses(&intent, owned, &e));
                return;
            }
        }
    };

    let plan = compute_fib_diff(&intent, owned, &kernel);
    for drop in &plan.drops {
        metrics.record_fib_route_rejected(drop_reason(drop));
    }
    let before_owned = owned.clone();
    let (failures, failed_keys) = apply_plan(fib, metrics, owned, &plan, event_tx, shutdown).await;
    if *owned != before_owned {
        persist_owned_state(config, owned);
    }
    let mut statuses = build_statuses(config, &intent, owned, &plan, &failed_keys);
    statuses.extend(failures);
    status_tx.send_replace(statuses);
}

#[cfg(test)]
async fn reconcile_once<F>(
    config: &FibRuntimeConfig,
    rib_query_tx: &mpsc::Sender<RibUpdate>,
    fib: &mut F,
    metrics: &BgpMetrics,
    status_tx: &watch::Sender<Vec<FibRuntimeStatus>>,
    owned: &mut FibOwnedState,
    shutdown: &CancellationToken,
) where
    F: UnicastFib,
{
    let (event_tx, _) = broadcast::channel(16);
    reconcile_once_with_events(
        config,
        rib_query_tx,
        fib,
        metrics,
        status_tx,
        &event_tx,
        owned,
        shutdown,
    )
    .await;
}

#[expect(
    clippy::too_many_lines,
    reason = "keeps success/failure handling for one FIB diff plan in one place"
)]
async fn apply_plan<F>(
    fib: &mut F,
    metrics: &BgpMetrics,
    owned: &mut FibOwnedState,
    plan: &FibPlan,
    event_tx: &broadcast::Sender<FibRuntimeEvent>,
    shutdown: &CancellationToken,
) -> (Vec<FibRuntimeStatus>, BTreeSet<FibRouteKey>)
where
    F: UnicastFib,
{
    let mut failures = Vec::new();
    let mut failed_keys = BTreeSet::new();
    for op in &plan.ops {
        if shutdown.is_cancelled() {
            break;
        }
        if let FibOp::Adopt(route) = op {
            record_fib_success(owned, op);
            info!(
                table = %route.table_name,
                table_id = route.key.table_id,
                metric = route.key.metric,
                prefix = %route.key.prefix,
                next_hop = %route.target.primary(),
                "refreshed general FIB route metadata"
            );
            continue;
        }
        if let FibOp::Forget(key) = op {
            record_fib_success(owned, op);
            info!(
                table_id = key.table_id,
                metric = key.metric,
                prefix = %key.prefix,
                "released general FIB route ownership after kernel drift"
            );
            continue;
        }
        let result = tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            result = fib.apply(op) => result,
        };
        match result {
            Ok(()) => {
                match op {
                    FibOp::Add(route) => {
                        metrics.record_fib_route_installed();
                        emit_fib_event(
                            event_tx,
                            FibRuntimeEventKind::Installed,
                            route,
                            "installed",
                        );
                        info!(
                            table = %route.table_name,
                            table_id = route.key.table_id,
                            metric = route.key.metric,
                            prefix = %route.key.prefix,
                            next_hop = %route.target.primary(),
                            "installed general FIB route"
                        );
                    }
                    FibOp::Adopt(_) => unreachable!("adopt handled before kernel apply"),
                    FibOp::Forget(_) => unreachable!("forget handled before kernel apply"),
                    FibOp::Replace { desired, .. } => {
                        metrics.record_fib_route_installed();
                        emit_fib_event(
                            event_tx,
                            FibRuntimeEventKind::Installed,
                            desired,
                            "replaced",
                        );
                        info!(
                            table = %desired.table_name,
                            table_id = desired.key.table_id,
                            metric = desired.key.metric,
                            prefix = %desired.key.prefix,
                            next_hop = %desired.target.primary(),
                            "replaced general FIB route"
                        );
                    }
                    FibOp::Remove(route) => {
                        metrics.record_fib_route_withdrawn();
                        emit_fib_event(
                            event_tx,
                            FibRuntimeEventKind::Withdrawn,
                            route,
                            "withdrawn",
                        );
                        info!(
                            table = %route.table_name,
                            table_id = route.key.table_id,
                            metric = route.key.metric,
                            prefix = %route.key.prefix,
                            "removed general FIB route"
                        );
                    }
                }
                record_fib_success(owned, op);
            }
            Err(e) => {
                let action = op_action(op);
                metrics.record_fib_kernel_failure(action);
                warn!(action, error = %e, "failed to apply general FIB route op");
                failed_keys.insert(op_route(op).key);
                emit_fib_event(
                    event_tx,
                    FibRuntimeEventKind::Failed,
                    op_route(op),
                    format!("{action}_failed:{e}"),
                );
                failures.push(status_for_route(
                    op_route(op),
                    FibRuntimeState::Failed,
                    format!("{action}_failed:{e}"),
                ));
            }
        }
    }
    (failures, failed_keys)
}

async fn drain_owned_with_events<F>(
    config: &FibRuntimeConfig,
    fib: &mut F,
    metrics: &BgpMetrics,
    status_tx: &watch::Sender<Vec<FibRuntimeStatus>>,
    event_tx: &broadcast::Sender<FibRuntimeEvent>,
    owned: &mut FibOwnedState,
) where
    F: UnicastFib,
{
    let before_owned = owned.clone();
    let snapshot = match fib.dump(&config.tables).await {
        Ok(snapshot) => snapshot,
        Err(e) => {
            metrics.record_fib_kernel_failure("dump");
            warn!(error = %e, "failed to dump configured FIB tables before shutdown drain");
            status_tx.send_replace(failed_dump_statuses(&FibIntent::default(), owned, &e));
            return;
        }
    };
    let routes = owned.routes.values().cloned().collect::<Vec<_>>();
    for route in routes {
        match snapshot.routes.get(&route.key) {
            None => {
                owned.routes.remove(&route.key);
                continue;
            }
            Some(kernel_route)
                if kernel_route.protocol == FibKernelProtocol::Bgp
                    && kernel_route.target == route.target => {}
            Some(kernel_route) => {
                warn!(
                    table = %route.table_name,
                    table_id = route.key.table_id,
                    metric = route.key.metric,
                    prefix = %route.key.prefix,
                    owned_next_hop = %route.target.primary(),
                    kernel_next_hop = %kernel_route.target.primary(),
                    "preserving foreign general FIB route during shutdown drain"
                );
                owned.routes.remove(&route.key);
                continue;
            }
        }
        let op = FibOp::Remove(route.clone());
        match fib.apply(&op).await {
            Ok(()) => {
                metrics.record_fib_route_withdrawn();
                emit_fib_event(
                    event_tx,
                    FibRuntimeEventKind::Withdrawn,
                    &route,
                    "shutdown_drain",
                );
                record_fib_success(owned, &op);
            }
            Err(e) => {
                metrics.record_fib_kernel_failure("remove");
                warn!(
                    table = %route.table_name,
                    table_id = route.key.table_id,
                    metric = route.key.metric,
                    prefix = %route.key.prefix,
                    error = %e,
                    "failed to drain general FIB route"
                );
            }
        }
    }
    if *owned != before_owned {
        persist_owned_state(config, owned);
    }
    status_tx.send_replace(Vec::new());
}

#[cfg(test)]
async fn drain_owned<F>(
    config: &FibRuntimeConfig,
    fib: &mut F,
    metrics: &BgpMetrics,
    status_tx: &watch::Sender<Vec<FibRuntimeStatus>>,
    owned: &mut FibOwnedState,
) where
    F: UnicastFib,
{
    let (event_tx, _) = broadcast::channel(16);
    drain_owned_with_events(config, fib, metrics, status_tx, &event_tx, owned).await;
}

fn emit_fib_event(
    event_tx: &broadcast::Sender<FibRuntimeEvent>,
    kind: FibRuntimeEventKind,
    route: &FibRoute,
    reason: impl Into<String>,
) {
    let _ = event_tx.send(FibRuntimeEvent {
        kind,
        table_name: route.table_name.clone(),
        table_id: route.key.table_id,
        metric: route.key.metric,
        prefix: route.key.prefix,
        next_hop: Some(route.target.primary()),
        peer: Some(route.peer),
        timestamp: rustbgpd_rib::event::unix_timestamp_now(),
        reason: reason.into(),
    });
}

/// Current owned-state envelope version. v2 persists the equal-cost
/// `next_hops` set; v1 persisted a single `next_hop` scalar.
const OWNED_STATE_VERSION: u32 = 2;
/// Oldest owned-state version this build can still load (and upgrade).
const OWNED_STATE_MIN_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct PersistedFibOwnedState {
    version: u32,
    tables: Vec<PersistedFibTableSignature>,
    routes: Vec<PersistedFibRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedFibTableSignature {
    name: String,
    table_id: u32,
    metric: u32,
    families: Vec<String>,
    allowed_peer_groups: Vec<String>,
    allowed_neighbors: Vec<String>,
    max_routes: Option<u32>,
    /// ECMP width. `#[serde(default)]` so a v1 file (which lacked the field)
    /// deserializes as `None`, matching a config with `maximum_paths` unset —
    /// preserving crash-restart owned-state across the v1→v2 upgrade. Changing
    /// `maximum_paths` changes this signature and forces a clean re-projection.
    #[serde(default)]
    maximum_paths: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedFibRoute {
    table_name: String,
    table_id: u32,
    metric: u32,
    prefix_addr: IpAddr,
    prefix_len: u8,
    /// Legacy v1 single next-hop. Read for back-compat; not written by v2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_hop: Option<IpAddr>,
    /// v2 equal-cost next-hop set. Empty on a v1 file (upgraded from
    /// `next_hop` in `into_route`).
    #[serde(default)]
    next_hops: Vec<IpAddr>,
    peer: IpAddr,
    origin_type: PersistedRouteOrigin,
    path_id: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PersistedRouteOrigin {
    Ebgp,
    Ibgp,
    Local,
}

impl From<RouteOrigin> for PersistedRouteOrigin {
    fn from(origin: RouteOrigin) -> Self {
        match origin {
            RouteOrigin::Ebgp => Self::Ebgp,
            RouteOrigin::Ibgp => Self::Ibgp,
            RouteOrigin::Local => Self::Local,
        }
    }
}

impl From<PersistedRouteOrigin> for RouteOrigin {
    fn from(origin: PersistedRouteOrigin) -> Self {
        match origin {
            PersistedRouteOrigin::Ebgp => Self::Ebgp,
            PersistedRouteOrigin::Ibgp => Self::Ibgp,
            PersistedRouteOrigin::Local => Self::Local,
        }
    }
}

impl From<&FibRoute> for PersistedFibRoute {
    fn from(route: &FibRoute) -> Self {
        Self {
            table_name: route.table_name.clone(),
            table_id: route.key.table_id,
            metric: route.key.metric,
            prefix_addr: prefix_addr(route.key.prefix),
            prefix_len: route.key.prefix.prefix_len(),
            next_hop: None,
            next_hops: route.target.next_hops.clone(),
            peer: route.peer,
            origin_type: route.origin_type.into(),
            path_id: route.path_id,
        }
    }
}

impl From<&FibTableConfig> for PersistedFibTableSignature {
    fn from(table: &FibTableConfig) -> Self {
        Self {
            name: table.name.clone(),
            table_id: table.table_id,
            metric: table.metric,
            families: table.families.clone(),
            allowed_peer_groups: table.allowed_peer_groups.clone(),
            allowed_neighbors: table.allowed_neighbors.clone(),
            max_routes: table.max_routes,
            maximum_paths: table.maximum_paths,
        }
    }
}

impl PersistedFibRoute {
    fn into_route(self) -> Option<FibRoute> {
        let prefix = prefix_from_addr_len(self.prefix_addr, self.prefix_len)?;
        // v2 carries `next_hops`; a v1 file carried a single scalar `next_hop`.
        // Upgrade v1 to a one-element set, then drop any next-hop whose family
        // disagrees with the prefix. If that empties the set, the row is
        // unusable.
        let next_hops: Vec<IpAddr> = if self.next_hops.is_empty() {
            self.next_hop.into_iter().collect()
        } else {
            self.next_hops
        }
        .into_iter()
        .filter(|next_hop| prefix_and_nexthop_same_family(prefix, *next_hop))
        .collect();
        if next_hops.is_empty() {
            return None;
        }
        let key = FibRouteKey {
            table_id: self.table_id,
            metric: self.metric,
            prefix,
        };
        Some(FibRoute {
            table_name: self.table_name,
            key,
            target: FibRouteTarget::from_next_hops(next_hops),
            peer: self.peer,
            origin_type: self.origin_type.into(),
            path_id: self.path_id,
        })
    }
}

fn load_owned_state(config: &FibRuntimeConfig) -> FibOwnedState {
    let Some(path) = &config.owned_state_path else {
        return FibOwnedState::default();
    };
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return FibOwnedState::default(),
        Err(e) => {
            warn!(path = %path.display(), error = %e, "failed to read general FIB owned-state file");
            return FibOwnedState::default();
        }
    };
    let persisted = match serde_json::from_slice::<PersistedFibOwnedState>(&bytes) {
        Ok(persisted) => persisted,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "failed to parse general FIB owned-state file");
            return FibOwnedState::default();
        }
    };
    // Accept every owned-state version this build understands. v1 (single
    // `next_hop` scalar) and v2 (`next_hops` set) are both upgraded on load by
    // `into_route`. A hard reject would orphan crash-restart state and turn
    // our own rows into a foreign-route storm, so only quarantine versions
    // newer than we can parse.
    if !(OWNED_STATE_MIN_VERSION..=OWNED_STATE_VERSION).contains(&persisted.version) {
        warn!(
            path = %path.display(),
            version = persisted.version,
            supported_max = OWNED_STATE_VERSION,
            "ignoring unsupported general FIB owned-state version"
        );
        quarantine_owned_state_file(config, "unsupported_version");
        return FibOwnedState::default();
    }
    if persisted.tables != table_signatures(&config.tables) {
        warn!(
            path = %path.display(),
            "ignoring general FIB owned-state because [[fib_tables]] changed"
        );
        quarantine_owned_state_file(config, "config_mismatch");
        return FibOwnedState::default();
    }

    let allowed_tables = config
        .tables
        .iter()
        .map(|table| FibTableKey {
            table_id: table.table_id,
            metric: table.metric,
        })
        .collect::<BTreeSet<_>>();
    let mut owned = FibOwnedState::default();
    for route in persisted.routes {
        let Some(route) = route.into_route() else {
            warn!(
                path = %path.display(),
                "skipping invalid general FIB owned-state route"
            );
            continue;
        };
        if !allowed_tables.contains(&route.key.table_key()) {
            warn!(
                path = %path.display(),
                table_id = route.key.table_id,
                metric = route.key.metric,
                "skipping general FIB owned-state route outside configured table set"
            );
            continue;
        }
        owned.routes.insert(route.key, route);
    }
    if !owned.routes.is_empty() {
        info!(
            path = %path.display(),
            routes = owned.routes.len(),
            "loaded persisted general FIB owned-state"
        );
    }
    owned
}

fn persist_owned_state(config: &FibRuntimeConfig, owned: &FibOwnedState) {
    let Some(path) = &config.owned_state_path else {
        return;
    };
    if let Err(e) = write_owned_state(path, &config.tables, owned) {
        warn!(
            path = %path.display(),
            error = %e,
            "failed to persist general FIB owned-state"
        );
    }
}

fn quarantine_owned_state_file(config: &FibRuntimeConfig, reason: &'static str) {
    let Some(path) = &config.owned_state_path else {
        return;
    };
    let stale_path = stale_owned_state_path(path);
    let _ = std::fs::remove_file(&stale_path);
    if let Err(e) = std::fs::rename(path, &stale_path) {
        warn!(
            path = %path.display(),
            stale_path = %stale_path.display(),
            reason,
            error = %e,
            "failed to quarantine stale general FIB owned-state"
        );
    } else {
        warn!(
            path = %path.display(),
            stale_path = %stale_path.display(),
            reason,
            "quarantined stale general FIB owned-state"
        );
    }
}

fn stale_owned_state_path(path: &Path) -> PathBuf {
    path.with_extension("json.stale")
}

fn write_owned_state(
    path: &Path,
    tables: &[FibTableConfig],
    owned: &FibOwnedState,
) -> Result<(), String> {
    let persisted = PersistedFibOwnedState {
        version: OWNED_STATE_VERSION,
        tables: table_signatures(tables),
        routes: owned.routes.values().map(PersistedFibRoute::from).collect(),
    };
    let bytes =
        serde_json::to_vec_pretty(&persisted).map_err(|e| format!("serialize owned-state: {e}"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create state dir: {e}"))?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("write temp state file: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename temp state file: {e}"))?;
    Ok(())
}

fn table_signatures(tables: &[FibTableConfig]) -> Vec<PersistedFibTableSignature> {
    tables
        .iter()
        .map(PersistedFibTableSignature::from)
        .collect()
}

fn op_action(op: &FibOp) -> &'static str {
    match op {
        FibOp::Add(_) => "install",
        FibOp::Adopt(_) => "adopt",
        FibOp::Replace { .. } => "replace",
        FibOp::Remove(_) => "remove",
        FibOp::Forget(_) => "forget",
    }
}

fn op_route(op: &FibOp) -> &FibRoute {
    match op {
        FibOp::Add(route) | FibOp::Adopt(route) | FibOp::Remove(route) => route,
        FibOp::Forget(_) => unreachable!("forget handled before kernel apply"),
        FibOp::Replace { desired, .. } => desired,
    }
}

fn drop_reason(drop: &FibDrop) -> &'static str {
    match drop {
        FibDrop::NextHopFamilyUnsupported { .. } => "next_hop_family_unsupported",
        FibDrop::ForeignRouteExists { .. } => "foreign_route_exists",
        FibDrop::OwnedRouteDrifted { .. } => "owned_route_drifted",
        FibDrop::PeerNotAllowed { .. } => "peer_not_allowed",
        FibDrop::RouteLimitExceeded { .. } => "route_limit_exceeded",
    }
}

fn build_statuses(
    config: &FibRuntimeConfig,
    intent: &FibIntent,
    owned: &FibOwnedState,
    plan: &FibPlan,
    failed_keys: &BTreeSet<FibRouteKey>,
) -> Vec<FibRuntimeStatus> {
    let mut out = Vec::new();
    let dropped_keys = plan
        .drops
        .iter()
        .filter_map(|drop| match drop {
            FibDrop::ForeignRouteExists { key } => Some(*key),
            FibDrop::OwnedRouteDrifted { route } => Some(route.key),
            FibDrop::NextHopFamilyUnsupported { .. }
            | FibDrop::PeerNotAllowed { .. }
            | FibDrop::RouteLimitExceeded { .. } => None,
        })
        .collect::<BTreeSet<_>>();
    for drop in &plan.drops {
        out.push(status_for_drop(config, intent, owned, drop));
    }
    for route in owned.routes.values() {
        if (intent.routes.contains_key(&route.key)
            || intent.frozen_tables.contains(&route.key.table_key()))
            && !failed_keys.contains(&route.key)
            && !dropped_keys.contains(&route.key)
        {
            out.push(status_for_route(
                route,
                FibRuntimeState::Installed,
                "owned".to_string(),
            ));
        }
    }
    out
}

fn status_for_drop(
    config: &FibRuntimeConfig,
    intent: &FibIntent,
    owned: &FibOwnedState,
    drop: &FibDrop,
) -> FibRuntimeStatus {
    match drop {
        FibDrop::NextHopFamilyUnsupported {
            table_name,
            prefix,
            next_hop,
        } => {
            let table = config.tables.iter().find(|table| table.name == *table_name);
            FibRuntimeStatus {
                table_name: table_name.clone(),
                table_id: table.map_or(0, |table| table.table_id),
                metric: table.map_or(0, |table| table.metric),
                prefix: *prefix,
                next_hop: Some(*next_hop),
                peer: None,
                state: FibRuntimeState::Rejected,
                reason: "next_hop_family_unsupported".to_string(),
                sampling: None,
            }
        }
        FibDrop::ForeignRouteExists { key } => {
            let route = intent.routes.get(key).or_else(|| owned.routes.get(key));
            if let Some(route) = route {
                FibRuntimeStatus {
                    reason: "foreign_route_exists".to_string(),
                    ..status_for_route(route, FibRuntimeState::Rejected, String::new())
                }
            } else {
                FibRuntimeStatus {
                    table_name: table_name_for_key(config, *key),
                    table_id: key.table_id,
                    metric: key.metric,
                    prefix: key.prefix,
                    next_hop: None,
                    peer: None,
                    state: FibRuntimeState::Rejected,
                    reason: "foreign_route_exists".to_string(),
                    sampling: None,
                }
            }
        }
        FibDrop::OwnedRouteDrifted { route } => FibRuntimeStatus {
            reason: "owned_route_drifted".to_string(),
            ..status_for_route(route, FibRuntimeState::Rejected, String::new())
        },
        FibDrop::PeerNotAllowed {
            table_name,
            prefix,
            peer,
        } => {
            let table = config.tables.iter().find(|table| table.name == *table_name);
            FibRuntimeStatus {
                table_name: table_name.clone(),
                table_id: table.map_or(0, |table| table.table_id),
                metric: table.map_or(0, |table| table.metric),
                prefix: *prefix,
                next_hop: None,
                peer: Some(*peer),
                state: FibRuntimeState::Rejected,
                reason: "peer_not_allowed".to_string(),
                sampling: None,
            }
        }
        FibDrop::RouteLimitExceeded {
            table_name,
            key,
            next_hop,
            peer,
            ..
        } => FibRuntimeStatus {
            table_name: table_name.clone(),
            table_id: key.table_id,
            metric: key.metric,
            prefix: key.prefix,
            next_hop: Some(*next_hop),
            peer: Some(*peer),
            state: FibRuntimeState::Rejected,
            reason: "route_limit_exceeded".to_string(),
            sampling: route_limit_sampling(drop),
        },
    }
}

fn route_limit_sampling(drop: &FibDrop) -> Option<FibRuntimeSampling> {
    let FibDrop::RouteLimitExceeded {
        limit,
        sampled_rows,
        suppressed_rows,
        total_rows,
        sample_limit,
        ..
    } = drop
    else {
        return None;
    };
    Some(FibRuntimeSampling {
        sampled_rows: *sampled_rows,
        suppressed_rows: *suppressed_rows,
        total_rows: *total_rows,
        max_routes: *limit,
        sample_limit: *sample_limit,
    })
}

fn table_name_for_key(config: &FibRuntimeConfig, key: FibRouteKey) -> String {
    config
        .tables
        .iter()
        .find(|table| table.table_id == key.table_id && table.metric == key.metric)
        .map_or_else(
            || format!("table-{}", key.table_id),
            |table| table.name.clone(),
        )
}

fn failed_dump_statuses(
    intent: &FibIntent,
    owned: &FibOwnedState,
    error: &str,
) -> Vec<FibRuntimeStatus> {
    let reason = format!("dump_failed:{error}");
    let mut out = Vec::new();
    // Owned rows the current intent no longer covers — and, during a
    // shutdown drain, every owned row, since `intent` is empty there.
    for (key, route) in &owned.routes {
        if !intent.routes.contains_key(key) {
            out.push(status_for_route(
                route,
                FibRuntimeState::Failed,
                reason.clone(),
            ));
        }
    }
    // Every desired route. Without this, a dump failure on the first
    // reconcile — or for any best route not yet installed — would leave
    // `ListFibRoutes` empty instead of surfacing the promised
    // `dump_failed:*` per-route status.
    for route in intent.routes.values() {
        out.push(status_for_route(
            route,
            FibRuntimeState::Failed,
            reason.clone(),
        ));
    }
    out
}

fn failed_rib_query_statuses(owned: &FibOwnedState, reason: &str) -> Vec<FibRuntimeStatus> {
    owned
        .routes
        .values()
        .map(|route| {
            status_for_route(
                route,
                FibRuntimeState::Failed,
                format!("rib_query_failed:{reason}"),
            )
        })
        .collect()
}

fn status_for_route(route: &FibRoute, state: FibRuntimeState, reason: String) -> FibRuntimeStatus {
    FibRuntimeStatus {
        table_name: route.table_name.clone(),
        table_id: route.key.table_id,
        metric: route.key.metric,
        prefix: route.key.prefix,
        next_hop: Some(route.target.primary()),
        peer: Some(route.peer),
        state,
        reason,
        sampling: None,
    }
}

trait UnicastFib {
    fn dump<'a>(
        &'a mut self,
        tables: &'a [FibTableConfig],
    ) -> Pin<Box<dyn Future<Output = Result<FibKernelSnapshot, String>> + Send + 'a>>;

    fn apply<'a>(
        &'a mut self,
        op: &'a FibOp,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

#[cfg(target_os = "linux")]
struct LinuxUnicastFib {
    handle: rtnetlink::Handle,
}

#[cfg(target_os = "linux")]
impl LinuxUnicastFib {
    fn connect() -> Result<Self, String> {
        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(|e| format!("open NETLINK_ROUTE: {e}"))?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }
}

#[cfg(target_os = "linux")]
impl UnicastFib for LinuxUnicastFib {
    fn dump<'a>(
        &'a mut self,
        tables: &'a [FibTableConfig],
    ) -> Pin<Box<dyn Future<Output = Result<FibKernelSnapshot, String>> + Send + 'a>> {
        Box::pin(async move { dump_configured_routes(&self.handle, tables).await })
    }

    fn apply<'a>(
        &'a mut self,
        op: &'a FibOp,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move { apply_linux_op(&self.handle, op).await })
    }
}

#[cfg(target_os = "linux")]
async fn apply_linux_op(handle: &rtnetlink::Handle, op: &FibOp) -> Result<(), String> {
    match op {
        FibOp::Add(route) => {
            let msg = build_route_message(route, RouteMessageGateway::Include)?;
            handle
                .route()
                .add(msg)
                .execute()
                .await
                .map_err(|e| format!("kernel route add: {e}"))
        }
        FibOp::Adopt(_) | FibOp::Forget(_) => Ok(()),
        FibOp::Replace { desired: route, .. } => {
            let msg = build_route_message(route, RouteMessageGateway::Include)?;
            handle
                .route()
                .add(msg)
                .replace()
                .execute()
                .await
                .map_err(|e| format!("kernel route replace: {e}"))
        }
        FibOp::Remove(route) => {
            let msg = build_route_message(route, RouteMessageGateway::Omit)?;
            match handle.route().del(msg).execute().await {
                Ok(()) => Ok(()),
                Err(e) if is_idempotent_route_delete(&e) => Ok(()),
                Err(e) => Err(format!("kernel route del: {e}")),
            }
        }
    }
}

#[cfg(target_os = "linux")]
async fn dump_configured_routes(
    handle: &rtnetlink::Handle,
    tables: &[FibTableConfig],
) -> Result<FibKernelSnapshot, String> {
    use futures::TryStreamExt;
    use rtnetlink::RouteMessageBuilder;

    let mut snapshot = FibKernelSnapshot::default();

    let v4_query = RouteMessageBuilder::<std::net::Ipv4Addr>::new().build();
    let mut v4 = handle.route().get(v4_query).execute();
    while let Some(msg) = v4
        .try_next()
        .await
        .map_err(|e| format!("kernel IPv4 route dump: {e}"))?
    {
        ingest_route_message(&msg, tables, &mut snapshot);
    }

    let v6_query = RouteMessageBuilder::<std::net::Ipv6Addr>::new().build();
    let mut v6 = handle.route().get(v6_query).execute();
    while let Some(msg) = v6
        .try_next()
        .await
        .map_err(|e| format!("kernel IPv6 route dump: {e}"))?
    {
        ingest_route_message(&msg, tables, &mut snapshot);
    }

    Ok(snapshot)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum RouteMessageGateway {
    Include,
    Omit,
}

#[cfg(target_os = "linux")]
fn build_route_message(
    route: &FibRoute,
    gateway: RouteMessageGateway,
) -> Result<netlink_packet_route::route::RouteMessage, String> {
    use netlink_packet_route::AddressFamily;
    use netlink_packet_route::route::{
        RouteAttribute, RouteFlags, RouteHeader, RouteNextHop, RouteProtocol, RouteScope, RouteType,
    };

    let family = match route.key.prefix {
        Prefix::V4(_) => AddressFamily::Inet,
        Prefix::V6(_) => AddressFamily::Inet6,
    };
    if let Some(next_hop) = route
        .target
        .next_hops
        .iter()
        .find(|next_hop| !prefix_and_nexthop_same_family(route.key.prefix, **next_hop))
    {
        return Err(format!(
            "prefix family does not match next-hop family for {} via {next_hop}",
            route.key.prefix
        ));
    }

    let mut msg = netlink_packet_route::route::RouteMessage::default();
    msg.header = RouteHeader {
        address_family: family,
        destination_prefix_length: route.key.prefix.prefix_len(),
        source_prefix_length: 0,
        tos: 0,
        table: u8::try_from(route.key.table_id).unwrap_or(0),
        protocol: RouteProtocol::Bgp,
        scope: RouteScope::Universe,
        kind: RouteType::Unicast,
        flags: RouteFlags::empty(),
    };
    msg.attributes
        .push(RouteAttribute::Table(route.key.table_id));
    msg.attributes
        .push(RouteAttribute::Priority(route.key.metric));
    if route.key.prefix.prefix_len() != 0 {
        msg.attributes
            .push(RouteAttribute::Destination(prefix_to_route_address(
                route.key.prefix,
            )));
    }
    if matches!(gateway, RouteMessageGateway::Include) {
        match route.target.next_hops.as_slice() {
            // A single next-hop stays a plain RTA_GATEWAY — byte-for-byte
            // today's shape, so default (`maximum_paths` unset/1) is unchanged.
            [next_hop] => {
                msg.attributes
                    .push(RouteAttribute::Gateway(ip_to_route_address(*next_hop)));
            }
            // Two or more program a kernel RTA_MULTIPATH (ECMP). Each hop
            // carries only a gateway; `hops = 0` ⇒ equal weight, and the
            // kernel resolves the output interface from the gateway's route.
            next_hops => {
                let hops = next_hops
                    .iter()
                    .map(|next_hop| {
                        let mut hop = RouteNextHop::default();
                        hop.attributes
                            .push(RouteAttribute::Gateway(ip_to_route_address(*next_hop)));
                        hop
                    })
                    .collect();
                msg.attributes.push(RouteAttribute::MultiPath(hops));
            }
        }
    }
    Ok(msg)
}

#[cfg(target_os = "linux")]
fn ingest_route_message(
    msg: &netlink_packet_route::route::RouteMessage,
    tables: &[FibTableConfig],
    snapshot: &mut FibKernelSnapshot,
) {
    let Some(prefix) = extract_prefix(msg) else {
        return;
    };
    let table_id = extract_table_id(msg);
    let metric = extract_metric(msg);
    let Some(_table) = tables.iter().find(|table| {
        table.table_id == table_id && table.metric == metric && table_allows_prefix(table, prefix)
    }) else {
        return;
    };

    let key = FibRouteKey {
        table_id,
        metric,
        prefix,
    };
    let protocol = if msg.header.protocol == netlink_packet_route::route::RouteProtocol::Bgp {
        FibKernelProtocol::Bgp
    } else {
        FibKernelProtocol::Other
    };
    let target = extract_gateway(msg)
        .unwrap_or_else(|| FibRouteTarget::single(unspecified_for_prefix(prefix)));
    snapshot
        .routes
        .insert(key, FibKernelRoute { target, protocol });
}

#[cfg(target_os = "linux")]
fn extract_table_id(msg: &netlink_packet_route::route::RouteMessage) -> u32 {
    use netlink_packet_route::route::RouteAttribute;
    msg.attributes
        .iter()
        .find_map(|attr| match attr {
            RouteAttribute::Table(id) => Some(*id),
            _ => None,
        })
        .unwrap_or(u32::from(msg.header.table))
}

#[cfg(target_os = "linux")]
fn extract_metric(msg: &netlink_packet_route::route::RouteMessage) -> u32 {
    use netlink_packet_route::route::RouteAttribute;
    msg.attributes
        .iter()
        .find_map(|attr| match attr {
            RouteAttribute::Priority(metric) => Some(*metric),
            _ => None,
        })
        .unwrap_or(0)
}

#[cfg(target_os = "linux")]
fn extract_prefix(msg: &netlink_packet_route::route::RouteMessage) -> Option<Prefix> {
    use netlink_packet_route::AddressFamily;
    use netlink_packet_route::route::{RouteAddress, RouteAttribute};
    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix};

    let destination = msg.attributes.iter().find_map(|attr| match attr {
        RouteAttribute::Destination(addr) => Some(addr),
        _ => None,
    });
    let len = msg.header.destination_prefix_length;
    match (msg.header.address_family, destination) {
        (AddressFamily::Inet, Some(RouteAddress::Inet(addr))) if len <= 32 => {
            Some(Prefix::V4(Ipv4Prefix::new(*addr, len)))
        }
        (AddressFamily::Inet6, Some(RouteAddress::Inet6(addr))) if len <= 128 => {
            Some(Prefix::V6(Ipv6Prefix::new(*addr, len)))
        }
        (AddressFamily::Inet, None) if len == 0 => Some(Prefix::V4(Ipv4Prefix::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            0,
        ))),
        (AddressFamily::Inet6, None) if len == 0 => Some(Prefix::V6(Ipv6Prefix::new(
            std::net::Ipv6Addr::UNSPECIFIED,
            0,
        ))),
        _ => None,
    }
}

/// Read the kernel forwarding value of a route message as a canonical
/// next-hop set. Both a single `RTA_GATEWAY` and an `RTA_MULTIPATH` (ECMP)
/// reduce to a sorted/deduped set, so `Gateway(x)` and `MultiPath([x])` compare
/// equal and the diff never flaps when the kernel echoes a different-but-
/// equivalent representation than we emitted.
#[cfg(target_os = "linux")]
fn extract_gateway(msg: &netlink_packet_route::route::RouteMessage) -> Option<FibRouteTarget> {
    use netlink_packet_route::route::RouteAttribute;
    for attr in &msg.attributes {
        match attr {
            RouteAttribute::MultiPath(next_hops) => {
                let gateways: Vec<IpAddr> = next_hops.iter().filter_map(next_hop_gateway).collect();
                if !gateways.is_empty() {
                    return Some(FibRouteTarget::from_next_hops(gateways));
                }
            }
            RouteAttribute::Gateway(addr) => {
                if let Some(next_hop) = route_address_ip(addr) {
                    return Some(FibRouteTarget::single(next_hop));
                }
            }
            _ => {}
        }
    }
    None
}

/// Pull the gateway IP out of one multipath next-hop's attributes.
#[cfg(target_os = "linux")]
fn next_hop_gateway(hop: &netlink_packet_route::route::RouteNextHop) -> Option<IpAddr> {
    use netlink_packet_route::route::RouteAttribute;
    hop.attributes.iter().find_map(|attr| match attr {
        RouteAttribute::Gateway(addr) => route_address_ip(addr),
        _ => None,
    })
}

#[cfg(target_os = "linux")]
fn route_address_ip(addr: &netlink_packet_route::route::RouteAddress) -> Option<IpAddr> {
    use netlink_packet_route::route::RouteAddress;
    match addr {
        RouteAddress::Inet(addr) => Some(IpAddr::V4(*addr)),
        RouteAddress::Inet6(addr) => Some(IpAddr::V6(*addr)),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn prefix_to_route_address(prefix: Prefix) -> netlink_packet_route::route::RouteAddress {
    use netlink_packet_route::route::RouteAddress;
    match prefix {
        Prefix::V4(p) => RouteAddress::Inet(p.addr),
        Prefix::V6(p) => RouteAddress::Inet6(p.addr),
    }
}

#[cfg(target_os = "linux")]
fn ip_to_route_address(ip: IpAddr) -> netlink_packet_route::route::RouteAddress {
    use netlink_packet_route::route::RouteAddress;
    match ip {
        IpAddr::V4(a) => RouteAddress::Inet(a),
        IpAddr::V6(a) => RouteAddress::Inet6(a),
    }
}

fn prefix_addr(prefix: Prefix) -> IpAddr {
    match prefix {
        Prefix::V4(prefix) => IpAddr::V4(prefix.addr),
        Prefix::V6(prefix) => IpAddr::V6(prefix.addr),
    }
}

fn prefix_from_addr_len(addr: IpAddr, len: u8) -> Option<Prefix> {
    match addr {
        IpAddr::V4(addr) if len <= 32 => Some(Prefix::V4(Ipv4Prefix::new(addr, len))),
        IpAddr::V6(addr) if len <= 128 => Some(Prefix::V6(Ipv6Prefix::new(addr, len))),
        IpAddr::V4(_) | IpAddr::V6(_) => None,
    }
}

fn unspecified_for_prefix(prefix: Prefix) -> IpAddr {
    match prefix {
        Prefix::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        Prefix::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    }
}

#[cfg(target_os = "linux")]
fn is_idempotent_route_delete(err: &rtnetlink::Error) -> bool {
    matches!(netlink_errno(err), Some(code) if code == libc::ENOENT || code == libc::ESRCH)
}

#[cfg(target_os = "linux")]
fn netlink_errno(err: &rtnetlink::Error) -> Option<i32> {
    match err {
        rtnetlink::Error::NetlinkError(msg) => Some(msg.raw_code().unsigned_abs().cast_signed()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Registry;
    use rustbgpd_rib::{FibInstallNextHop, Route, RouteEvent, RouteEventType, RouteOrigin};
    use rustbgpd_wire::{AsPath, Ipv4Prefix, Ipv6Prefix, Origin, PathAttribute, RpkiValidation};
    use std::collections::BTreeMap;
    use std::net::{Ipv4Addr, Ipv6Addr};
    #[cfg(target_os = "linux")]
    use std::process::Command;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Instant;

    #[derive(Default)]
    struct FakeFib {
        kernel: FibKernelSnapshot,
        fail_dump: Option<String>,
        fail_apply: Vec<String>,
        applied: Vec<FibOp>,
    }

    impl UnicastFib for FakeFib {
        fn dump<'a>(
            &'a mut self,
            _tables: &'a [FibTableConfig],
        ) -> Pin<Box<dyn Future<Output = Result<FibKernelSnapshot, String>> + Send + 'a>> {
            Box::pin(async move {
                if let Some(error) = &self.fail_dump {
                    Err(error.clone())
                } else {
                    Ok(self.kernel.clone())
                }
            })
        }

        fn apply<'a>(
            &'a mut self,
            op: &'a FibOp,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            self.applied.push(op.clone());
            Box::pin(async move {
                if let Some(error) = self.fail_apply.pop() {
                    return Err(error);
                }
                match op {
                    FibOp::Add(route) | FibOp::Adopt(route) => {
                        self.kernel.routes.insert(
                            route.key,
                            FibKernelRoute {
                                target: route.target.clone(),
                                protocol: FibKernelProtocol::Bgp,
                            },
                        );
                    }
                    FibOp::Replace { desired, .. } => {
                        self.kernel.routes.insert(
                            desired.key,
                            FibKernelRoute {
                                target: desired.target.clone(),
                                protocol: FibKernelProtocol::Bgp,
                            },
                        );
                    }
                    FibOp::Remove(route) => {
                        self.kernel.routes.remove(&route.key);
                    }
                    FibOp::Forget(_) => {}
                }
                Ok(())
            })
        }
    }

    fn table(name: &str, table_id: u32, metric: u32, families: &[&str]) -> FibTableConfig {
        FibTableConfig {
            name: name.to_string(),
            table_id,
            metric,
            families: families.iter().map(|f| (*f).to_string()).collect(),
            allowed_peer_groups: Vec::new(),
            allowed_neighbors: Vec::new(),
            max_routes: None,
            maximum_paths: None,
        }
    }

    fn config() -> FibRuntimeConfig {
        FibRuntimeConfig {
            tables: vec![table("edge", 1000, 200, &["ipv4_unicast", "ipv6_unicast"])],
            owned_state_path: None,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn v4(len: u8) -> Prefix {
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), len))
    }

    fn v6(len: u8) -> Prefix {
        Prefix::V6(Ipv6Prefix::new(
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0),
            len,
        ))
    }

    fn route(prefix: Prefix, next_hop: IpAddr) -> Route {
        Route {
            prefix,
            next_hop,
            link_local_next_hop: None,
            peer: ip("198.51.100.1"),
            attributes: Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath { segments: vec![] }),
            ]),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::new(192, 0, 2, 1),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        }
    }

    fn key(prefix: Prefix) -> FibRouteKey {
        FibRouteKey {
            table_id: 1000,
            metric: 200,
            prefix,
        }
    }

    fn fib_route(prefix: Prefix, next_hop: IpAddr) -> FibRoute {
        FibRoute {
            table_name: "edge".to_string(),
            key: key(prefix),
            target: FibRouteTarget::single(next_hop),
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        }
    }

    /// Stand-in for the RIB's install-candidate handler: group best routes by
    /// prefix (first-seen is the best, index 0), append same-prefix routes as
    /// equal-cost siblings deduped by next-hop, capped at `max_paths`.
    fn routes_to_candidates(routes: &[Route], max_paths: u32) -> Vec<FibInstallCandidate> {
        let cap = max_paths.max(1) as usize;
        let mut candidates: Vec<FibInstallCandidate> = Vec::new();
        for route in routes {
            let next_hop = FibInstallNextHop {
                next_hop: route.next_hop,
                link_local_next_hop: route.link_local_next_hop,
                peer: route.peer,
                path_id: route.path_id,
            };
            if let Some(existing) = candidates
                .iter_mut()
                .find(|candidate| candidate.best.prefix == route.prefix)
            {
                if existing.next_hops.len() < cap
                    && existing
                        .next_hops
                        .iter()
                        .all(|hop| hop.next_hop != route.next_hop)
                {
                    existing.next_hops.push(next_hop);
                }
            } else {
                candidates.push(FibInstallCandidate {
                    best: route.clone(),
                    next_hops: vec![next_hop],
                });
            }
        }
        candidates
    }

    fn rib_with_routes(routes: Vec<Route>) -> mpsc::Sender<RibUpdate> {
        let (tx, mut rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(update) = rx.recv().await {
                if let RibUpdate::QueryFibInstallCandidates { max_paths, reply } = update {
                    let _ = reply.send(routes_to_candidates(&routes, max_paths));
                }
            }
        });
        tx
    }

    fn rib_with_routes_and_peer_groups(
        routes: Vec<Route>,
        peer_groups: BTreeMap<IpAddr, String>,
    ) -> mpsc::Sender<RibUpdate> {
        let (tx, mut rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(update) = rx.recv().await {
                match update {
                    RibUpdate::QueryFibInstallCandidates { max_paths, reply } => {
                        let _ = reply.send(routes_to_candidates(&routes, max_paths));
                    }
                    RibUpdate::QueryPeerGroups { reply } => {
                        let _ = reply.send(peer_groups.clone().into_iter().collect());
                    }
                    _ => {}
                }
            }
        });
        tx
    }

    fn rib_with_events(
        routes: Vec<Route>,
    ) -> (
        mpsc::Sender<RibUpdate>,
        Arc<AtomicUsize>,
        broadcast::Sender<RouteEvent>,
    ) {
        let (tx, mut rx) = mpsc::channel(8);
        let query_count = Arc::new(AtomicUsize::new(0));
        let query_count_task = Arc::clone(&query_count);
        let (events_tx, _) = broadcast::channel(16);
        let events_task = events_tx.clone();
        tokio::spawn(async move {
            while let Some(update) = rx.recv().await {
                match update {
                    RibUpdate::QueryFibInstallCandidates { max_paths, reply } => {
                        query_count_task.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(routes_to_candidates(&routes, max_paths));
                    }
                    RibUpdate::SubscribeRouteEvents { reply } => {
                        let _ = reply.send(events_task.subscribe());
                    }
                    _ => {}
                }
            }
        });
        (tx, query_count, events_tx)
    }

    fn route_event(prefix: Prefix) -> RouteEvent {
        RouteEvent {
            event_id: 0,
            event_type: RouteEventType::BestChanged,
            prefix,
            peer: Some(ip("198.51.100.1")),
            previous_peer: None,
            target_peer: None,
            timestamp: "0".to_string(),
            path_id: 0,
            reason: String::new(),
        }
    }

    fn metrics() -> BgpMetrics {
        BgpMetrics::with_registry(Registry::new())
    }

    #[cfg(target_os = "linux")]
    fn netns_gate() -> bool {
        std::env::var("EVPN_LINUX_NETNS").as_deref() == Ok("1")
    }

    #[cfg(target_os = "linux")]
    fn run(cmd: &str, args: &[&str]) -> std::process::Output {
        let out = Command::new(cmd).args(args).output().expect("spawn");
        assert!(
            out.status.success(),
            "{cmd} {args:?} failed: status={} stdout={} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        out
    }

    #[cfg(target_os = "linux")]
    fn try_run(cmd: &str, args: &[&str]) {
        let _ = Command::new(cmd).args(args).output();
    }

    #[cfg(target_os = "linux")]
    struct NetnsFixture {
        name: String,
    }

    #[cfg(target_os = "linux")]
    impl NetnsFixture {
        fn create(test_name: &str) -> Self {
            let name = format!("rustbgpd-fib-{test_name}-{}", std::process::id());
            try_run("ip", &["netns", "delete", &name]);
            run("ip", &["netns", "add", &name]);
            run("ip", &["-n", &name, "link", "set", "lo", "up"]);
            Self { name }
        }

        fn exec(&self, cmd: &str, args: &[&str]) -> String {
            let mut full = vec!["netns", "exec", self.name.as_str(), cmd];
            full.extend(args);
            let out = run("ip", &full);
            String::from_utf8_lossy(&out.stdout).into_owned()
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for NetnsFixture {
        fn drop(&mut self) {
            try_run("ip", &["netns", "delete", &self.name]);
        }
    }

    #[cfg(target_os = "linux")]
    fn run_inner_netns(ns: &NetnsFixture, test_name: &str) {
        let exe = std::env::current_exe().expect("self-exe");
        let full_name = format!("fib_runtime::tests::{test_name}");
        let status = Command::new("ip")
            .args(["netns", "exec", &ns.name])
            .arg(&exe)
            .args(["--exact", "--nocapture", &full_name])
            .env("RUSTBGPD_FIB_NETNS_INNER", "1")
            .env("EVPN_LINUX_NETNS", "1")
            .status()
            .expect("spawn inner");
        assert!(status.success(), "inner test invocation failed");
    }

    #[cfg(target_os = "linux")]
    fn is_inner_netns() -> bool {
        std::env::var("RUSTBGPD_FIB_NETNS_INNER").is_ok()
    }

    #[cfg(target_os = "linux")]
    fn setup_unicast_netns(ns: &NetnsFixture) {
        ns.exec(
            "ip",
            &[
                "link", "add", "fib0", "type", "veth", "peer", "name", "fib-peer",
            ],
        );
        ns.exec("ip", &["addr", "add", "192.0.2.2/24", "dev", "fib0"]);
        ns.exec("ip", &["link", "set", "fib0", "up"]);
        ns.exec("ip", &["link", "set", "fib-peer", "up"]);
    }

    #[cfg(target_os = "linux")]
    fn route_show(table_id: u32, prefix: &str) -> String {
        let table = table_id.to_string();
        let args = ["route", "show", "table", &table, "exact", prefix];
        let out = Command::new("ip").args(args).output().expect("spawn");
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains("FIB table does not exist") {
                return String::new();
            }
            panic!(
                "ip {args:?} failed: status={} stdout={} stderr={}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                stderr,
            );
        }
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[cfg(target_os = "linux")]
    fn add_static_route(table_id: u32, prefix: &str) {
        let table = table_id.to_string();
        run(
            "ip",
            &[
                "route",
                "add",
                "table",
                &table,
                prefix,
                "via",
                "192.0.2.1",
                "metric",
                "200",
                "proto",
                "static",
            ],
        );
    }

    #[cfg(target_os = "linux")]
    fn replace_static_route(table_id: u32, prefix: &str, next_hop: &str) {
        let table = table_id.to_string();
        run(
            "ip",
            &[
                "route", "replace", "table", &table, prefix, "via", next_hop, "metric", "200",
                "proto", "static",
            ],
        );
    }

    #[cfg(target_os = "linux")]
    fn delete_route_any(table_id: u32, prefix: &str) {
        let table = table_id.to_string();
        try_run(
            "ip",
            &["route", "del", "table", &table, prefix, "metric", "200"],
        );
    }

    #[cfg(target_os = "linux")]
    fn delete_route(table_id: u32, prefix: &str) {
        let table = table_id.to_string();
        try_run(
            "ip",
            &[
                "route",
                "del",
                "table",
                &table,
                prefix,
                "via",
                "192.0.2.1",
                "metric",
                "200",
            ],
        );
    }

    async fn reconcile_for_test(
        routes: Vec<Route>,
        fib: &mut FakeFib,
        owned: &mut FibOwnedState,
    ) -> Vec<FibRuntimeStatus> {
        let rib_tx = rib_with_routes(routes);
        let (status_tx, status_rx) = watch::channel(Vec::new());
        reconcile_once(
            &config(),
            &rib_tx,
            fib,
            &metrics(),
            &status_tx,
            owned,
            &CancellationToken::new(),
        )
        .await;
        status_rx.borrow().clone()
    }

    async fn reconcile_for_test_with_events(
        routes: Vec<Route>,
        fib: &mut FakeFib,
        owned: &mut FibOwnedState,
    ) -> (Vec<FibRuntimeStatus>, Vec<FibRuntimeEvent>) {
        let rib_tx = rib_with_routes(routes);
        let (status_tx, status_rx) = watch::channel(Vec::new());
        let (event_tx, mut event_rx) = broadcast::channel(16);
        reconcile_once_with_events(
            &config(),
            &rib_tx,
            fib,
            &metrics(),
            &status_tx,
            &event_tx,
            owned,
            &CancellationToken::new(),
        )
        .await;
        let mut events = Vec::new();
        while let Ok(event) = event_rx.try_recv() {
            events.push(event);
        }
        (status_rx.borrow().clone(), events)
    }

    async fn reconcile_config_for_test(
        config: FibRuntimeConfig,
        rib_tx: mpsc::Sender<RibUpdate>,
        fib: &mut FakeFib,
        owned: &mut FibOwnedState,
    ) -> Vec<FibRuntimeStatus> {
        let (status_tx, status_rx) = watch::channel(Vec::new());
        reconcile_once(
            &config,
            &rib_tx,
            fib,
            &metrics(),
            &status_tx,
            owned,
            &CancellationToken::new(),
        )
        .await;
        status_rx.borrow().clone()
    }

    #[test]
    fn default_off_config_is_disabled() {
        assert!(
            !FibRuntimeConfig {
                tables: vec![],
                owned_state_path: None
            }
            .enabled()
        );
    }

    #[test]
    fn spawn_returns_none_when_fib_tables_empty() {
        let (rib_tx, _rx) = mpsc::channel(1);
        let (rib_query_tx, _query_rx) = mpsc::channel(1);
        let (status_tx, _status_rx) = watch::channel(Vec::new());
        let (event_tx, _) = broadcast::channel(16);
        let handle = spawn(
            FibRuntimeConfig {
                tables: vec![],
                owned_state_path: None,
            },
            rib_tx,
            rib_query_tx,
            metrics(),
            status_tx,
            event_tx,
            CancellationToken::new(),
        );
        assert!(handle.is_none());
    }

    #[tokio::test]
    async fn initial_reconcile_installs_desired_route_and_publishes_status() {
        let mut fib = FakeFib::default();
        let mut owned = FibOwnedState::default();
        let statuses =
            reconcile_for_test(vec![route(v4(24), ip("192.0.2.1"))], &mut fib, &mut owned).await;

        assert_eq!(fib.applied.len(), 1);
        assert!(matches!(fib.applied[0], FibOp::Add(_)));
        assert_eq!(owned.routes.len(), 1);
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, FibRuntimeState::Installed);
        assert_eq!(statuses[0].reason, "owned");
    }

    #[tokio::test]
    async fn successful_install_publishes_dataplane_route_event() {
        let mut fib = FakeFib::default();
        let mut owned = FibOwnedState::default();

        let (_statuses, events) = reconcile_for_test_with_events(
            vec![route(v4(24), ip("192.0.2.1"))],
            &mut fib,
            &mut owned,
        )
        .await;

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, FibRuntimeEventKind::Installed);
        assert_eq!(events[0].table_name, "edge");
        assert_eq!(events[0].table_id, 1000);
        assert_eq!(events[0].metric, 200);
        assert_eq!(events[0].prefix, v4(24));
        assert_eq!(events[0].next_hop, Some(ip("192.0.2.1")));
        assert_eq!(events[0].peer, Some(ip("198.51.100.1")));
        assert_eq!(events[0].reason, "installed");
    }

    #[test]
    fn owned_state_persistence_round_trips_and_ignores_config_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fib-owned.json");
        let mut config = config();
        config.owned_state_path = Some(path.clone());
        let route = fib_route(v4(24), ip("192.0.2.1"));
        let mut owned = FibOwnedState::default();
        owned.routes.insert(route.key, route.clone());

        write_owned_state(&path, &config.tables, &owned).unwrap();
        assert_eq!(load_owned_state(&config), owned);

        let mut changed = config.clone();
        changed.tables[0].metric = 201;
        assert!(load_owned_state(&changed).routes.is_empty());
        assert!(!path.exists());
        assert!(stale_owned_state_path(&path).exists());
        assert!(load_owned_state(&config).routes.is_empty());
    }

    #[test]
    fn owned_state_v1_scalar_next_hop_loads_and_upgrades() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fib-owned.json");
        let mut config = config();
        config.owned_state_path = Some(path.clone());
        // A v1 file: envelope version 1, a table signature without the
        // `maximum_paths` field, and a route carrying the legacy scalar
        // `next_hop` (no `next_hops`). It must load and upgrade, not quarantine.
        let v1 = r#"{
          "version": 1,
          "tables": [
            {
              "name": "edge",
              "table_id": 1000,
              "metric": 200,
              "families": ["ipv4_unicast", "ipv6_unicast"],
              "allowed_peer_groups": [],
              "allowed_neighbors": [],
              "max_routes": null
            }
          ],
          "routes": [
            {
              "table_name": "edge",
              "table_id": 1000,
              "metric": 200,
              "prefix_addr": "203.0.113.0",
              "prefix_len": 24,
              "next_hop": "192.0.2.1",
              "peer": "198.51.100.1",
              "origin_type": "ebgp",
              "path_id": 0
            }
          ]
        }"#;
        std::fs::write(&path, v1).unwrap();

        let owned = load_owned_state(&config);

        let expected = fib_route(v4(24), ip("192.0.2.1"));
        assert_eq!(owned.routes.len(), 1);
        assert_eq!(owned.routes.get(&expected.key), Some(&expected));
        // Accepted in place, not quarantined.
        assert!(path.exists());
        assert!(!stale_owned_state_path(&path).exists());
    }

    #[test]
    fn owned_state_round_trips_multipath_next_hops() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fib-owned.json");
        let mut config = config();
        config.owned_state_path = Some(path.clone());
        let mut route = fib_route(v4(24), ip("192.0.2.1"));
        route.target = FibRouteTarget::from_next_hops([ip("192.0.2.1"), ip("192.0.2.2")]);
        let mut owned = FibOwnedState::default();
        owned.routes.insert(route.key, route);

        write_owned_state(&path, &config.tables, &owned).unwrap();

        assert_eq!(load_owned_state(&config), owned);
    }

    #[test]
    fn changing_maximum_paths_invalidates_owned_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fib-owned.json");
        let mut config = config();
        config.owned_state_path = Some(path.clone());
        let route = fib_route(v4(24), ip("192.0.2.1"));
        let mut owned = FibOwnedState::default();
        owned.routes.insert(route.key, route);
        write_owned_state(&path, &config.tables, &owned).unwrap();
        assert_eq!(load_owned_state(&config), owned);

        // Flipping `maximum_paths` changes the table signature, so the prior
        // owned-state is treated as foreign config and quarantined.
        let mut changed = config.clone();
        changed.tables[0].maximum_paths = Some(2);
        assert!(load_owned_state(&changed).routes.is_empty());
    }

    #[test]
    fn loaded_owned_state_allows_crash_restart_replace_when_kernel_still_matches() {
        let previous = fib_route(v4(24), ip("192.0.2.1"));
        let desired = fib_route(v4(24), ip("192.0.2.2"));
        let mut owned = FibOwnedState::default();
        owned.routes.insert(previous.key, previous.clone());
        let intent = FibIntent {
            routes: BTreeMap::from([(desired.key, desired.clone())]),
            ..FibIntent::default()
        };
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(
                previous.key,
                FibKernelRoute {
                    target: previous.target.clone(),
                    protocol: FibKernelProtocol::Bgp,
                },
            )]),
        };

        let plan = compute_fib_diff(&intent, &owned, &kernel);

        assert_eq!(plan.ops, vec![FibOp::Replace { previous, desired }]);
        assert!(plan.drops.is_empty());
    }

    #[test]
    fn loaded_owned_state_still_preserves_kernel_drift_after_restart() {
        let previous = fib_route(v4(24), ip("192.0.2.1"));
        let desired = fib_route(v4(24), ip("192.0.2.2"));
        let mut owned = FibOwnedState::default();
        owned.routes.insert(previous.key, previous.clone());
        let intent = FibIntent {
            routes: BTreeMap::from([(desired.key, desired)]),
            ..FibIntent::default()
        };
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(
                previous.key,
                FibKernelRoute {
                    target: FibRouteTarget::single(ip("192.0.2.99")),
                    protocol: FibKernelProtocol::Bgp,
                },
            )]),
        };

        let plan = compute_fib_diff(&intent, &owned, &kernel);

        assert_eq!(plan.ops, vec![FibOp::Forget(previous.key)]);
        assert_eq!(
            plan.drops,
            vec![FibDrop::OwnedRouteDrifted { route: previous }]
        );
    }

    #[tokio::test]
    async fn reconcile_persists_owned_state_after_successful_install() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = config();
        config.owned_state_path = Some(dir.path().join("fib-owned.json"));
        let mut fib = FakeFib::default();
        let mut owned = FibOwnedState::default();
        let rib_tx = rib_with_routes(vec![route(v4(24), ip("192.0.2.1"))]);

        let statuses =
            reconcile_config_for_test(config.clone(), rib_tx, &mut fib, &mut owned).await;

        assert_eq!(statuses[0].state, FibRuntimeState::Installed);
        assert_eq!(load_owned_state(&config), owned);
    }

    #[tokio::test]
    async fn route_event_wakes_actor_before_periodic_interval() {
        let (rib_tx, query_count, events_tx) =
            rib_with_events(vec![route(v4(24), ip("192.0.2.1"))]);
        let (status_tx, _status_rx) = watch::channel(Vec::new());
        let (event_tx, _) = broadcast::channel(16);
        let shutdown = CancellationToken::new();
        let handle = spawn_with_fib(
            config(),
            rib_tx.clone(),
            rib_tx,
            FakeFib::default(),
            metrics(),
            status_tx,
            event_tx,
            shutdown.clone(),
        );

        tokio::task::yield_now().await;
        for _ in 0..20 {
            if events_tx.receiver_count() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let initial = query_count.load(Ordering::SeqCst);
        events_tx.send(route_event(v4(24))).unwrap();
        tokio::time::sleep(ROUTE_EVENT_DEBOUNCE + Duration::from_millis(50)).await;
        tokio::task::yield_now().await;

        assert!(query_count.load(Ordering::SeqCst) > initial);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn route_event_debounce_waits_after_idle() {
        let (rib_tx, query_count, events_tx) =
            rib_with_events(vec![route(v4(24), ip("192.0.2.1"))]);
        let (status_tx, _status_rx) = watch::channel(Vec::new());
        let (event_tx, _) = broadcast::channel(16);
        let shutdown = CancellationToken::new();
        let handle = spawn_with_fib(
            config(),
            rib_tx.clone(),
            rib_tx,
            FakeFib::default(),
            metrics(),
            status_tx,
            event_tx,
            shutdown.clone(),
        );

        tokio::task::yield_now().await;
        for _ in 0..20 {
            if events_tx.receiver_count() > 0 && query_count.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(query_count.load(Ordering::SeqCst), 1);

        tokio::time::sleep(ROUTE_EVENT_DEBOUNCE + Duration::from_millis(50)).await;
        events_tx.send(route_event(v4(24))).unwrap();
        tokio::time::sleep(ROUTE_EVENT_DEBOUNCE / 2).await;
        tokio::task::yield_now().await;

        assert_eq!(
            query_count.load(Ordering::SeqCst),
            1,
            "first route event after idle should wait for the debounce window"
        );

        tokio::time::sleep(ROUTE_EVENT_DEBOUNCE).await;
        tokio::task::yield_now().await;
        assert_eq!(query_count.load(Ordering::SeqCst), 2);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn foreign_kernel_row_prevents_install() {
        let mut fib = FakeFib::default();
        fib.kernel.routes.insert(
            key(v4(24)),
            FibKernelRoute {
                target: FibRouteTarget::single(ip("192.0.2.99")),
                protocol: FibKernelProtocol::Other,
            },
        );
        let mut owned = FibOwnedState::default();
        let statuses =
            reconcile_for_test(vec![route(v4(24), ip("192.0.2.1"))], &mut fib, &mut owned).await;

        assert!(fib.applied.is_empty());
        assert!(owned.routes.is_empty());
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, FibRuntimeState::Rejected);
        assert_eq!(statuses[0].reason, "foreign_route_exists");
    }

    #[tokio::test]
    async fn preexisting_bgp_kernel_row_is_foreign_without_owned_state() {
        let mut fib = FakeFib::default();
        fib.kernel.routes.insert(
            key(v4(24)),
            FibKernelRoute {
                target: FibRouteTarget::single(ip("192.0.2.1")),
                protocol: FibKernelProtocol::Bgp,
            },
        );
        let mut owned = FibOwnedState::default();

        let statuses =
            reconcile_for_test(vec![route(v4(24), ip("192.0.2.1"))], &mut fib, &mut owned).await;

        assert!(fib.applied.is_empty());
        assert!(owned.routes.is_empty());
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, FibRuntimeState::Rejected);
        assert_eq!(statuses[0].reason, "foreign_route_exists");
    }

    #[tokio::test]
    async fn failed_install_is_visible_in_status() {
        let mut fib = FakeFib {
            fail_apply: vec!["permission denied".to_string()],
            ..FakeFib::default()
        };
        let mut owned = FibOwnedState::default();

        let statuses =
            reconcile_for_test(vec![route(v4(24), ip("192.0.2.1"))], &mut fib, &mut owned).await;

        assert!(owned.routes.is_empty());
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, FibRuntimeState::Failed);
        assert!(statuses[0].reason.contains("install_failed"));
    }

    #[tokio::test]
    async fn failed_install_publishes_dataplane_route_event() {
        let mut fib = FakeFib {
            fail_apply: vec!["permission denied".to_string()],
            ..FakeFib::default()
        };
        let mut owned = FibOwnedState::default();

        let (_statuses, events) = reconcile_for_test_with_events(
            vec![route(v4(24), ip("192.0.2.1"))],
            &mut fib,
            &mut owned,
        )
        .await;

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, FibRuntimeEventKind::Failed);
        assert_eq!(events[0].prefix, v4(24));
        assert_eq!(events[0].reason, "install_failed:permission denied");
    }

    #[tokio::test]
    async fn dump_failure_reports_failed_status_for_desired_routes_with_empty_owned() {
        // First reconcile: owned is empty. A dump failure must still
        // surface the promised `dump_failed:*` per-route status for the
        // desired route rather than leaving `ListFibRoutes` empty.
        let mut fib = FakeFib {
            fail_dump: Some("netlink unavailable".to_string()),
            ..FakeFib::default()
        };
        let mut owned = FibOwnedState::default();

        let statuses =
            reconcile_for_test(vec![route(v4(24), ip("192.0.2.1"))], &mut fib, &mut owned).await;

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, FibRuntimeState::Failed);
        assert!(statuses[0].reason.starts_with("dump_failed:"));
        assert!(owned.routes.is_empty());
    }

    #[tokio::test]
    async fn rib_query_failure_marks_owned_status_failed() {
        let (rib_tx, rib_rx) = mpsc::channel(1);
        drop(rib_rx);
        let mut fib = FakeFib::default();
        let existing = FibRoute {
            table_name: "edge".to_string(),
            key: key(v4(24)),
            target: FibRouteTarget::single(ip("192.0.2.1")),
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        };
        let mut owned = FibOwnedState {
            routes: BTreeMap::from([(existing.key, existing)]),
        };
        let (status_tx, status_rx) = watch::channel(Vec::new());

        reconcile_once(
            &config(),
            &rib_tx,
            &mut fib,
            &metrics(),
            &status_tx,
            &mut owned,
            &CancellationToken::new(),
        )
        .await;

        let statuses = status_rx.borrow().clone();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, FibRuntimeState::Failed);
        assert_eq!(statuses[0].reason, "rib_query_failed:send_failed");
    }

    #[tokio::test]
    async fn failed_replace_does_not_emit_duplicate_installed_status() {
        let prefix = v4(24);
        let previous = FibRoute {
            table_name: "edge".to_string(),
            key: key(prefix),
            target: FibRouteTarget::single(ip("192.0.2.1")),
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        };
        let mut fib = FakeFib {
            fail_apply: vec!["replace rejected".to_string()],
            ..FakeFib::default()
        };
        fib.kernel.routes.insert(
            previous.key,
            FibKernelRoute {
                target: previous.target.clone(),
                protocol: FibKernelProtocol::Bgp,
            },
        );
        let mut owned = FibOwnedState {
            routes: BTreeMap::from([(previous.key, previous)]),
        };

        let statuses =
            reconcile_for_test(vec![route(prefix, ip("192.0.2.2"))], &mut fib, &mut owned).await;

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, FibRuntimeState::Failed);
        assert!(statuses[0].reason.contains("replace_failed"));
    }

    #[tokio::test]
    async fn drifted_owned_route_does_not_emit_duplicate_installed_status() {
        let prefix = v4(24);
        let owned_route = FibRoute {
            table_name: "edge".to_string(),
            key: key(prefix),
            target: FibRouteTarget::single(ip("192.0.2.1")),
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        };
        let mut fib = FakeFib::default();
        fib.kernel.routes.insert(
            owned_route.key,
            FibKernelRoute {
                target: FibRouteTarget::single(ip("192.0.2.99")),
                protocol: FibKernelProtocol::Other,
            },
        );
        let mut owned = FibOwnedState {
            routes: BTreeMap::from([(owned_route.key, owned_route)]),
        };

        let statuses =
            reconcile_for_test(vec![route(prefix, ip("192.0.2.1"))], &mut fib, &mut owned).await;

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, FibRuntimeState::Rejected);
        assert_eq!(statuses[0].reason, "owned_route_drifted");
        assert!(owned.routes.is_empty());
    }

    #[tokio::test]
    async fn owned_route_missing_from_desired_is_removed() {
        let prefix = v4(24);
        let route = FibRoute {
            table_name: "edge".to_string(),
            key: key(prefix),
            target: FibRouteTarget::single(ip("192.0.2.1")),
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        };
        let mut fib = FakeFib::default();
        fib.kernel.routes.insert(
            route.key,
            FibKernelRoute {
                target: route.target.clone(),
                protocol: FibKernelProtocol::Bgp,
            },
        );
        let mut owned = FibOwnedState {
            routes: BTreeMap::from([(route.key, route)]),
        };

        let statuses = reconcile_for_test(Vec::new(), &mut fib, &mut owned).await;

        assert!(matches!(fib.applied.as_slice(), [FibOp::Remove(_)]));
        assert!(owned.routes.is_empty());
        assert!(statuses.is_empty());
    }

    #[tokio::test]
    async fn successful_withdraw_publishes_dataplane_route_event() {
        let prefix = v4(24);
        let route = FibRoute {
            table_name: "edge".to_string(),
            key: key(prefix),
            target: FibRouteTarget::single(ip("192.0.2.1")),
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        };
        let mut fib = FakeFib::default();
        fib.kernel.routes.insert(
            route.key,
            FibKernelRoute {
                target: route.target.clone(),
                protocol: FibKernelProtocol::Bgp,
            },
        );
        let mut owned = FibOwnedState {
            routes: BTreeMap::from([(route.key, route)]),
        };

        let (_statuses, events) =
            reconcile_for_test_with_events(Vec::new(), &mut fib, &mut owned).await;

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, FibRuntimeEventKind::Withdrawn);
        assert_eq!(events[0].prefix, prefix);
        assert_eq!(events[0].reason, "withdrawn");
    }

    #[tokio::test]
    async fn drifted_owned_route_missing_from_desired_is_preserved_and_forgotten() {
        let prefix = v4(24);
        let route = FibRoute {
            table_name: "edge".to_string(),
            key: key(prefix),
            target: FibRouteTarget::single(ip("192.0.2.1")),
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        };
        let mut fib = FakeFib::default();
        fib.kernel.routes.insert(
            route.key,
            FibKernelRoute {
                target: FibRouteTarget::single(ip("192.0.2.99")),
                protocol: FibKernelProtocol::Bgp,
            },
        );
        let mut owned = FibOwnedState {
            routes: BTreeMap::from([(route.key, route)]),
        };

        let statuses = reconcile_for_test(Vec::new(), &mut fib, &mut owned).await;

        assert!(fib.applied.is_empty());
        assert!(owned.routes.is_empty());
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, FibRuntimeState::Rejected);
        assert_eq!(statuses[0].reason, "owned_route_drifted");
    }

    #[tokio::test]
    async fn missing_kernel_route_on_remove_still_advances_owned_state() {
        let prefix = v4(24);
        let route = FibRoute {
            table_name: "edge".to_string(),
            key: key(prefix),
            target: FibRouteTarget::single(ip("192.0.2.1")),
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        };
        let mut fib = FakeFib::default();
        let mut owned = FibOwnedState {
            routes: BTreeMap::from([(route.key, route)]),
        };

        let statuses = reconcile_for_test(Vec::new(), &mut fib, &mut owned).await;

        assert!(matches!(fib.applied.as_slice(), [FibOp::Remove(_)]));
        assert!(owned.routes.is_empty());
        assert!(statuses.is_empty());
    }

    #[tokio::test]
    async fn shutdown_drain_removes_owned_rows_and_clears_status() {
        let prefix = v4(24);
        let route = FibRoute {
            table_name: "edge".to_string(),
            key: key(prefix),
            target: FibRouteTarget::single(ip("192.0.2.1")),
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        };
        let mut fib = FakeFib::default();
        fib.kernel.routes.insert(
            route.key,
            FibKernelRoute {
                target: route.target.clone(),
                protocol: FibKernelProtocol::Bgp,
            },
        );
        let mut owned = FibOwnedState {
            routes: BTreeMap::from([(route.key, route)]),
        };
        let (status_tx, status_rx) = watch::channel(vec![FibRuntimeStatus {
            table_name: "edge".to_string(),
            table_id: 1000,
            metric: 200,
            prefix,
            next_hop: Some(ip("192.0.2.1")),
            peer: Some(ip("198.51.100.1")),
            state: FibRuntimeState::Installed,
            reason: "owned".to_string(),
            sampling: None,
        }]);

        drain_owned(&config(), &mut fib, &metrics(), &status_tx, &mut owned).await;

        assert!(owned.routes.is_empty());
        assert!(status_rx.borrow().is_empty());
    }

    #[tokio::test]
    async fn shutdown_drain_preserves_drifted_bgp_route() {
        let prefix = v4(24);
        let route = FibRoute {
            table_name: "edge".to_string(),
            key: key(prefix),
            target: FibRouteTarget::single(ip("192.0.2.1")),
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        };
        let mut fib = FakeFib::default();
        fib.kernel.routes.insert(
            route.key,
            FibKernelRoute {
                target: FibRouteTarget::single(ip("192.0.2.99")),
                protocol: FibKernelProtocol::Bgp,
            },
        );
        let mut owned = FibOwnedState {
            routes: BTreeMap::from([(route.key, route.clone())]),
        };
        let (status_tx, status_rx) = watch::channel(vec![FibRuntimeStatus {
            table_name: "edge".to_string(),
            table_id: 1000,
            metric: 200,
            prefix,
            next_hop: Some(ip("192.0.2.1")),
            peer: Some(ip("198.51.100.1")),
            state: FibRuntimeState::Installed,
            reason: "owned".to_string(),
            sampling: None,
        }]);

        drain_owned(&config(), &mut fib, &metrics(), &status_tx, &mut owned).await;

        assert!(fib.applied.is_empty());
        assert!(owned.routes.is_empty());
        assert!(status_rx.borrow().is_empty());
        assert_eq!(
            fib.kernel
                .routes
                .get(&route.key)
                .map(|route| route.target.clone()),
            Some(FibRouteTarget::single(ip("192.0.2.99")))
        );
    }

    #[tokio::test]
    async fn unsupported_next_hop_family_is_rejected() {
        let mut fib = FakeFib::default();
        let mut owned = FibOwnedState::default();
        let statuses =
            reconcile_for_test(vec![route(v4(24), ip("2001:db8::1"))], &mut fib, &mut owned).await;

        assert!(fib.applied.is_empty());
        assert!(owned.routes.is_empty());
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, FibRuntimeState::Rejected);
        assert_eq!(statuses[0].reason, "next_hop_family_unsupported");
    }

    #[tokio::test]
    async fn peer_group_allow_list_rejects_non_matching_best_route_before_apply() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.allowed_peer_groups = vec!["transit".to_string()];
        let config = FibRuntimeConfig {
            tables: vec![table],
            owned_state_path: None,
        };
        let rib_tx = rib_with_routes_and_peer_groups(
            vec![route(v4(24), ip("192.0.2.1"))],
            BTreeMap::from([(ip("198.51.100.1"), "ix".to_string())]),
        );
        let mut fib = FakeFib::default();
        let mut owned = FibOwnedState::default();

        let statuses = reconcile_config_for_test(config, rib_tx, &mut fib, &mut owned).await;

        assert!(fib.applied.is_empty());
        assert!(owned.routes.is_empty());
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, FibRuntimeState::Rejected);
        assert_eq!(statuses[0].reason, "peer_not_allowed");
    }

    #[tokio::test]
    async fn max_routes_rejects_table_before_kernel_apply() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.max_routes = Some(1);
        let config = FibRuntimeConfig {
            tables: vec![table],
            owned_state_path: None,
        };
        let rib_tx = rib_with_routes(vec![
            route(v4(24), ip("192.0.2.1")),
            route(
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 114, 0), 24)),
                ip("192.0.2.2"),
            ),
        ]);
        let mut fib = FakeFib::default();
        let mut owned = FibOwnedState::default();

        let statuses = reconcile_config_for_test(config, rib_tx, &mut fib, &mut owned).await;

        assert!(fib.applied.is_empty());
        assert!(owned.routes.is_empty());
        assert_eq!(statuses.len(), 2);
        assert!(statuses.iter().all(|status| {
            status.state == FibRuntimeState::Rejected && status.reason == "route_limit_exceeded"
        }));
        let sampling = statuses[0]
            .sampling
            .as_ref()
            .expect("route_limit_exceeded status should carry sampling metadata");
        assert_eq!(sampling.sampled_rows, 2);
        assert_eq!(sampling.suppressed_rows, 0);
        assert_eq!(sampling.total_rows, 2);
        assert_eq!(sampling.max_routes, 1);
    }

    #[tokio::test]
    async fn max_routes_over_cap_freezes_owned_rows_instead_of_draining_table() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.max_routes = Some(1);
        let config = FibRuntimeConfig {
            tables: vec![table],
            owned_state_path: None,
        };
        let existing = FibRoute {
            table_name: "edge".to_string(),
            key: key(v4(24)),
            target: FibRouteTarget::single(ip("192.0.2.1")),
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        };
        let mut fib = FakeFib::default();
        fib.kernel.routes.insert(
            existing.key,
            FibKernelRoute {
                target: existing.target.clone(),
                protocol: FibKernelProtocol::Bgp,
            },
        );
        let mut owned = FibOwnedState {
            routes: BTreeMap::from([(existing.key, existing)]),
        };
        let rib_tx = rib_with_routes(vec![
            route(v4(24), ip("192.0.2.1")),
            route(
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 114, 0), 24)),
                ip("192.0.2.2"),
            ),
        ]);

        let statuses = reconcile_config_for_test(config, rib_tx, &mut fib, &mut owned).await;

        assert!(fib.applied.is_empty());
        assert_eq!(owned.routes.len(), 1);
        assert_eq!(statuses.len(), 2);
        assert!(statuses.iter().any(|status| {
            status.state == FibRuntimeState::Installed && status.reason == "owned"
        }));
        assert!(statuses.iter().any(|status| {
            status.state == FibRuntimeState::Rejected && status.reason == "route_limit_exceeded"
        }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_route_message_uses_configured_table_metric_gateway_and_no_onlink() {
        use netlink_packet_route::route::{
            RouteAddress, RouteAttribute, RouteFlags, RouteProtocol,
        };
        let route = FibRoute {
            table_name: "edge".to_string(),
            key: key(v6(64)),
            target: FibRouteTarget::single(ip("2001:db8:ffff::1")),
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        };

        let msg = build_route_message(&route, RouteMessageGateway::Include).unwrap();

        assert_eq!(msg.header.table, 0);
        assert_eq!(msg.header.protocol, RouteProtocol::Bgp);
        assert!(!msg.header.flags.contains(RouteFlags::Onlink));
        assert!(
            msg.attributes
                .iter()
                .any(|attr| matches!(attr, RouteAttribute::Table(1000)))
        );
        assert!(
            msg.attributes
                .iter()
                .any(|attr| matches!(attr, RouteAttribute::Priority(200)))
        );
        assert!(msg.attributes.iter().any(|attr| {
            matches!(attr, RouteAttribute::Gateway(RouteAddress::Inet6(addr)) if *addr == "2001:db8:ffff::1".parse::<Ipv6Addr>().unwrap())
        }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn remove_route_message_is_key_only() {
        use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteProtocol};
        let route = FibRoute {
            table_name: "edge".to_string(),
            key: key(v4(32)),
            target: FibRouteTarget::single(ip("192.0.2.1")),
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        };

        let msg = build_route_message(&route, RouteMessageGateway::Omit).unwrap();

        assert_eq!(msg.header.protocol, RouteProtocol::Bgp);
        assert!(
            msg.attributes
                .iter()
                .any(|attr| matches!(attr, RouteAttribute::Table(1000)))
        );
        assert!(
            msg.attributes
                .iter()
                .any(|attr| matches!(attr, RouteAttribute::Priority(200)))
        );
        assert!(msg.attributes.iter().any(|attr| {
            matches!(attr, RouteAttribute::Destination(RouteAddress::Inet(addr)) if *addr == "203.0.113.0".parse::<Ipv4Addr>().unwrap())
        }));
        assert!(
            !msg.attributes
                .iter()
                .any(|attr| matches!(attr, RouteAttribute::Gateway(_))),
            "delete messages must not include stale next-hop value"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_route_message_single_next_hop_uses_gateway_not_multipath() {
        use netlink_packet_route::route::{RouteAddress, RouteAttribute};
        let route = FibRoute {
            table_name: "edge".to_string(),
            key: key(v4(24)),
            target: FibRouteTarget::single(ip("192.0.2.1")),
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        };

        let msg = build_route_message(&route, RouteMessageGateway::Include).unwrap();

        assert!(msg.attributes.iter().any(|attr| matches!(
            attr,
            RouteAttribute::Gateway(RouteAddress::Inet(addr))
                if *addr == "192.0.2.1".parse::<Ipv4Addr>().unwrap()
        )));
        assert!(
            !msg.attributes
                .iter()
                .any(|attr| matches!(attr, RouteAttribute::MultiPath(_))),
            "a single next-hop must stay RTA_GATEWAY, never RTA_MULTIPATH"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_route_message_multi_next_hop_emits_equal_weight_multipath() {
        use netlink_packet_route::route::RouteAttribute;
        let route = FibRoute {
            table_name: "edge".to_string(),
            key: key(v4(24)),
            target: FibRouteTarget::from_next_hops([ip("192.0.2.1"), ip("192.0.2.2")]),
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        };

        let msg = build_route_message(&route, RouteMessageGateway::Include).unwrap();

        let hops = msg
            .attributes
            .iter()
            .find_map(|attr| match attr {
                RouteAttribute::MultiPath(hops) => Some(hops),
                _ => None,
            })
            .expect("expected RTA_MULTIPATH");
        let gateways: Vec<IpAddr> = hops.iter().filter_map(next_hop_gateway).collect();
        assert_eq!(gateways, vec![ip("192.0.2.1"), ip("192.0.2.2")]);
        // hops == 0 ⇒ equal weight; no explicit oif for via-only ECMP.
        assert!(
            hops.iter()
                .all(|hop| hop.hops == 0 && hop.interface_index == 0)
        );
        assert!(
            !msg.attributes
                .iter()
                .any(|attr| matches!(attr, RouteAttribute::Gateway(_))),
            "a multipath route must not also carry a plain RTA_GATEWAY"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_then_extract_round_trips_multipath_set() {
        let route = FibRoute {
            table_name: "edge".to_string(),
            key: key(v4(24)),
            target: FibRouteTarget::from_next_hops([ip("192.0.2.2"), ip("192.0.2.1")]),
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        };

        let msg = build_route_message(&route, RouteMessageGateway::Include).unwrap();

        assert_eq!(extract_gateway(&msg), Some(route.target));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gateway_and_singleton_multipath_canonicalize_equal() {
        use netlink_packet_route::route::{RouteAttribute, RouteNextHop};
        // A one-hop RTA_MULTIPATH and a plain RTA_GATEWAY for the same address
        // must extract to the same canonical target, so the kernel echoing one
        // form when we emitted the other never flaps the diff.
        let gateway_route = FibRoute {
            table_name: "edge".to_string(),
            key: key(v4(24)),
            target: FibRouteTarget::single(ip("192.0.2.1")),
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        };
        let gateway_msg =
            build_route_message(&gateway_route, RouteMessageGateway::Include).unwrap();

        let mut multipath_msg = gateway_msg.clone();
        multipath_msg
            .attributes
            .retain(|attr| !matches!(attr, RouteAttribute::Gateway(_)));
        let mut hop = RouteNextHop::default();
        hop.attributes
            .push(RouteAttribute::Gateway(ip_to_route_address(ip(
                "192.0.2.1",
            ))));
        multipath_msg
            .attributes
            .push(RouteAttribute::MultiPath(vec![hop]));

        assert_eq!(
            extract_gateway(&gateway_msg),
            extract_gateway(&multipath_msg)
        );
        assert_eq!(
            extract_gateway(&multipath_msg),
            Some(FibRouteTarget::single(ip("192.0.2.1")))
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn netns_general_unicast_fib_runtime_round_trip() {
        if !netns_gate() {
            eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged general FIB netns test");
            return;
        }

        if !is_inner_netns() {
            let ns = NetnsFixture::create("general");
            setup_unicast_netns(&ns);
            run_inner_netns(&ns, "netns_general_unicast_fib_runtime_round_trip");
            return;
        }

        let prefix = v4(24);
        let prefix_text = "203.0.113.0/24";
        let foreign_prefix = "198.51.100.0/24";
        let mut fib = LinuxUnicastFib::connect().expect("LinuxUnicastFib::connect");
        let mut owned = FibOwnedState::default();
        let metrics = metrics();
        let (status_tx, status_rx) = watch::channel(Vec::new());

        // Empty [[fib_tables]] means no kernel install even when the
        // RIB has a best route.
        reconcile_once(
            &FibRuntimeConfig {
                tables: vec![],
                owned_state_path: None,
            },
            &rib_with_routes(vec![route(prefix, ip("192.0.2.1"))]),
            &mut fib,
            &metrics,
            &status_tx,
            &mut owned,
            &CancellationToken::new(),
        )
        .await;
        assert!(
            route_show(1000, prefix_text).trim().is_empty(),
            "disabled config should not install {prefix_text}"
        );

        // A foreign route at the target key is preserved and surfaced
        // as a rejected row instead of being overwritten.
        add_static_route(1000, prefix_text);
        reconcile_once(
            &config(),
            &rib_with_routes(vec![route(prefix, ip("192.0.2.1"))]),
            &mut fib,
            &metrics,
            &status_tx,
            &mut owned,
            &CancellationToken::new(),
        )
        .await;
        let foreign = route_show(1000, prefix_text);
        assert!(
            foreign.contains("proto static"),
            "foreign route changed: {foreign}"
        );
        assert!(owned.routes.is_empty());
        let statuses = status_rx.borrow().clone();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, FibRuntimeState::Rejected);
        assert_eq!(statuses[0].reason, "foreign_route_exists");
        delete_route(1000, prefix_text);
        assert!(
            route_show(1000, prefix_text).trim().is_empty(),
            "foreign setup route was not removed before install phase"
        );

        // Configured table receives the BGP-selected best route with
        // table id, metric, prefix, gateway, and proto bgp.
        reconcile_once(
            &config(),
            &rib_with_routes(vec![route(prefix, ip("192.0.2.1"))]),
            &mut fib,
            &metrics,
            &status_tx,
            &mut owned,
            &CancellationToken::new(),
        )
        .await;
        let installed = route_show(1000, prefix_text);
        assert!(
            installed.contains(prefix_text),
            "route missing: {installed}"
        );
        assert!(
            installed.contains("via 192.0.2.1"),
            "gateway missing: {installed}"
        );
        assert!(
            installed.contains("proto bgp"),
            "proto bgp missing: {installed}"
        );
        assert!(
            installed.contains("metric 200"),
            "metric missing: {installed}"
        );
        let dumped = dump_configured_routes(&fib.handle, &config().tables)
            .await
            .expect("dump_configured_routes");
        let key = key(prefix);
        assert_eq!(
            dumped.routes.get(&key).map(|r| r.target.primary()),
            Some(ip("192.0.2.1"))
        );
        assert_eq!(
            dumped.routes.get(&key).map(|r| r.protocol),
            Some(FibKernelProtocol::Bgp)
        );

        // Withdraw removes owned rows only; unrelated foreign rows survive.
        add_static_route(1000, foreign_prefix);
        reconcile_once(
            &config(),
            &rib_with_routes(Vec::new()),
            &mut fib,
            &metrics,
            &status_tx,
            &mut owned,
            &CancellationToken::new(),
        )
        .await;
        assert!(
            route_show(1000, prefix_text).trim().is_empty(),
            "withdraw left owned route installed"
        );
        let foreign_still_present = route_show(1000, foreign_prefix);
        assert!(
            foreign_still_present.contains("proto static"),
            "foreign route was not preserved: {foreign_still_present}"
        );

        // Missing external delete is idempotent and must not wedge owned state.
        reconcile_once(
            &config(),
            &rib_with_routes(vec![route(prefix, ip("192.0.2.1"))]),
            &mut fib,
            &metrics,
            &status_tx,
            &mut owned,
            &CancellationToken::new(),
        )
        .await;
        delete_route(1000, prefix_text);
        reconcile_once(
            &config(),
            &rib_with_routes(Vec::new()),
            &mut fib,
            &metrics,
            &status_tx,
            &mut owned,
            &CancellationToken::new(),
        )
        .await;
        assert!(owned.routes.is_empty());

        // External replacement of an owned row releases rustbgpd ownership
        // without deleting the replacement, and a later BGP withdraw must
        // leave that foreign route untouched.
        reconcile_once(
            &config(),
            &rib_with_routes(vec![route(prefix, ip("192.0.2.1"))]),
            &mut fib,
            &metrics,
            &status_tx,
            &mut owned,
            &CancellationToken::new(),
        )
        .await;
        replace_static_route(1000, prefix_text, "192.0.2.99");
        reconcile_once(
            &config(),
            &rib_with_routes(vec![route(prefix, ip("192.0.2.1"))]),
            &mut fib,
            &metrics,
            &status_tx,
            &mut owned,
            &CancellationToken::new(),
        )
        .await;
        assert!(owned.routes.is_empty());
        let drifted = route_show(1000, prefix_text);
        assert!(
            drifted.contains("via 192.0.2.99") && drifted.contains("proto static"),
            "drifted route was not preserved: {drifted}"
        );
        let statuses = status_rx.borrow().clone();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, FibRuntimeState::Rejected);
        assert_eq!(statuses[0].reason, "owned_route_drifted");
        reconcile_once(
            &config(),
            &rib_with_routes(Vec::new()),
            &mut fib,
            &metrics,
            &status_tx,
            &mut owned,
            &CancellationToken::new(),
        )
        .await;
        let drifted_after_withdraw = route_show(1000, prefix_text);
        assert!(
            drifted_after_withdraw.contains("via 192.0.2.99")
                && drifted_after_withdraw.contains("proto static"),
            "withdraw deleted drifted foreign route: {drifted_after_withdraw}"
        );
        delete_route_any(1000, prefix_text);
        assert!(
            route_show(1000, prefix_text).trim().is_empty(),
            "drift cleanup route remained installed"
        );

        // Shutdown drain removes daemon-owned routes and clears status.
        reconcile_once(
            &config(),
            &rib_with_routes(vec![route(prefix, ip("192.0.2.1"))]),
            &mut fib,
            &metrics,
            &status_tx,
            &mut owned,
            &CancellationToken::new(),
        )
        .await;
        drain_owned(&config(), &mut fib, &metrics, &status_tx, &mut owned).await;
        assert!(owned.routes.is_empty());
        assert!(status_rx.borrow().is_empty());
        assert!(
            route_show(1000, prefix_text).trim().is_empty(),
            "shutdown drain left owned route installed"
        );
        let foreign_after_drain = route_show(1000, foreign_prefix);
        assert!(
            foreign_after_drain.contains("proto static"),
            "shutdown drain removed foreign route: {foreign_after_drain}"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn netns_general_unicast_fib_ecmp_round_trip() {
        if !netns_gate() {
            eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run privileged ECMP FIB netns test");
            return;
        }
        if !is_inner_netns() {
            let ns = NetnsFixture::create("ecmp");
            setup_unicast_netns(&ns);
            run_inner_netns(&ns, "netns_general_unicast_fib_ecmp_round_trip");
            return;
        }

        let prefix = v4(24);
        let prefix_text = "203.0.113.0/24";
        let mut fib = LinuxUnicastFib::connect().expect("LinuxUnicastFib::connect");
        let mut owned = FibOwnedState::default();
        let metrics = metrics();
        let (status_tx, _status_rx) = watch::channel(Vec::new());
        let config = FibRuntimeConfig {
            tables: vec![{
                let mut table = table("edge", 1000, 200, &["ipv4_unicast", "ipv6_unicast"]);
                table.maximum_paths = Some(2);
                table
            }],
            owned_state_path: None,
        };
        // Both gateways are on-link in 192.0.2.0/24 (fib0), so the kernel can
        // resolve a via-only multipath route.
        let two_paths = || {
            vec![
                route(prefix, ip("192.0.2.1")),
                route(prefix, ip("192.0.2.3")),
            ]
        };

        // Install two equal-cost next-hops → kernel RTA_MULTIPATH route.
        reconcile_once(
            &config,
            &rib_with_routes(two_paths()),
            &mut fib,
            &metrics,
            &status_tx,
            &mut owned,
            &CancellationToken::new(),
        )
        .await;
        let installed = route_show(1000, prefix_text);
        assert!(
            installed.contains("nexthop via 192.0.2.1"),
            "first ECMP nexthop missing: {installed}"
        );
        assert!(
            installed.contains("nexthop via 192.0.2.3"),
            "second ECMP nexthop missing: {installed}"
        );
        assert!(
            installed.contains("proto bgp"),
            "proto bgp missing: {installed}"
        );

        // Failover: drop one path → collapses to the survivor as a single
        // RTA_GATEWAY (no `nexthop` stanzas).
        reconcile_once(
            &config,
            &rib_with_routes(vec![route(prefix, ip("192.0.2.1"))]),
            &mut fib,
            &metrics,
            &status_tx,
            &mut owned,
            &CancellationToken::new(),
        )
        .await;
        let survivor = route_show(1000, prefix_text);
        assert!(
            survivor.contains("via 192.0.2.1"),
            "survivor nexthop missing: {survivor}"
        );
        assert!(
            !survivor.contains("nexthop"),
            "shrunk route should not be multipath: {survivor}"
        );

        // Widen back to two paths.
        reconcile_once(
            &config,
            &rib_with_routes(two_paths()),
            &mut fib,
            &metrics,
            &status_tx,
            &mut owned,
            &CancellationToken::new(),
        )
        .await;
        let widened = route_show(1000, prefix_text);
        assert!(
            widened.contains("nexthop via 192.0.2.1") && widened.contains("nexthop via 192.0.2.3"),
            "widen back to ECMP failed: {widened}"
        );

        // Withdraw removes the owned multipath route.
        reconcile_once(
            &config,
            &rib_with_routes(Vec::new()),
            &mut fib,
            &metrics,
            &status_tx,
            &mut owned,
            &CancellationToken::new(),
        )
        .await;
        assert!(
            route_show(1000, prefix_text).trim().is_empty(),
            "withdraw left ECMP route installed"
        );
        assert!(owned.routes.is_empty());
    }
}
