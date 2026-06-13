//! RFC 7999 BLACKHOLE kernel-discard reconciler.
//!
//! This module is deliberately daemon-owned rather than folded into
//! `crates/evpn-linux`: RTBH is a unicast/RIB feature, not part of the
//! EVPN dataplane boundary. The actor subscribes to unicast best-route
//! events, periodically re-queries the Loc-RIB as a level-triggered
//! backstop, and owns the kernel blackhole routes it installed during
//! this daemon lifetime plus marker-matching rows it adopted at startup.
//!
//! Crash-restart reconciliation follows ADR-0079: the first reconcile
//! pass sweeps the kernel dump for rows carrying our ownership marker
//! (`RTPROT_BGP` + `RTN_BLACKHOLE` in the main table) and adopts them —
//! they keep discarding traffic and no longer block re-installation as
//! foreign. A desired prefix re-claims its adopted row implicitly; rows
//! still unclaimed after a deferral window (FRR zebra's `-K` analog) are
//! reaped, so a discard route left behind by a crashed daemon can no
//! longer blackhole traffic forever.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

use rustbgpd_rib::{RibUpdate, Route, RouteOrigin};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{PathAttribute, Prefix};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::kernel_route_notify::{
    KernelRouteEvent, KernelRouteEventKind, KernelRouteType, recv_kernel_route_event,
};

/// Linux `RT_TABLE_MAIN` — the only table this actor writes (the
/// ADR-0079 ownership marker is scoped to it).
const RT_TABLE_MAIN: u32 = 254;

const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
const ROUTE_EVENT_DEBOUNCE: Duration = Duration::from_millis(200);
const RIB_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
// How long adopted-but-unclaimed rows keep discarding before the reap
// (ADR-0079 rule 3: reap only after reconvergence). There is no explicit
// converged-intent signal in this actor, so the bound matches FRR
// zebra's graceful-restart route-sweep deferral default (`-K`, 500 s) —
// long enough for peers to re-establish and re-announce a still-desired
// blackhole, which re-claims the row and exempts it.
const ADOPTION_REAP_DEFERRAL: Duration = Duration::from_secs(500);

/// Test / operational escape hatch for the ADR-0079 blackhole
/// adoption-reap deferral. When set to a valid `u64` number of
/// seconds, the deferral is overridden at actor startup — the M62
/// kill-and-restart interop proof needs a deferral short enough to
/// observe the reap inside a CI job. Unset or invalid values keep
/// the production default of 500 s (FRR zebra `-K` parity).
const ADOPTION_REAP_DEFERRAL_ENV: &str = "RUSTBGPD_BLACKHOLE_ADOPTION_REAP_DEFERRAL_SECS";

/// Pure core of the [`ADOPTION_REAP_DEFERRAL_ENV`] override with the
/// environment value injected, so the parse rule (valid u64 seconds →
/// override, anything else → keep the default) is unit-testable
/// without touching process-global env state.
fn blackhole_reap_deferral_override(env: Option<&str>) -> Option<Duration> {
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

/// Resolve the effective adoption-reap deferral, reading
/// [`ADOPTION_REAP_DEFERRAL_ENV`] once at actor startup.
fn adoption_reap_deferral() -> Duration {
    let env = match std::env::var(ADOPTION_REAP_DEFERRAL_ENV) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            warn!("ignoring non-unicode {ADOPTION_REAP_DEFERRAL_ENV}");
            None
        }
    };
    if let Some(deferral) = blackhole_reap_deferral_override(env.as_deref()) {
        warn!(
            deferral_secs = deferral.as_secs(),
            "{ADOPTION_REAP_DEFERRAL_ENV} overrides the ADR-0079 blackhole adoption-reap deferral"
        );
        return deferral;
    }
    ADOPTION_REAP_DEFERRAL
}

/// Runtime knobs resolved from `[global]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlackholeConfig {
    /// Whether the BLACKHOLE FIB reconciler should run. The daemon
    /// passes `honor_blackhole && install_blackhole_discard` here so
    /// this runtime field represents the effective opt-in, not just
    /// the raw TOML value.
    pub enabled: bool,
    /// Permit non-host prefixes. When false, only IPv4 `/32` and IPv6
    /// `/128` are eligible.
    pub allow_broad_prefixes: bool,
}

impl BlackholeConfig {
    /// Returns true when the actor should be started.
    #[must_use]
    pub fn enabled(self) -> bool {
        self.enabled
    }
}

/// Operator-visible state for one BLACKHOLE-marked best route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlackholeStatus {
    pub prefix: Prefix,
    pub peer: IpAddr,
    pub state: BlackholeState,
    pub reason: String,
}

/// High-level install state surfaced through gRPC/CLI and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlackholeState {
    Installed,
    Rejected,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OwnedBlackhole {
    peer: IpAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RejectedBlackhole {
    prefix: Prefix,
    reason: &'static str,
}

/// What the per-pass kernel dump says about one prefix in the main table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KernelRoutePresence {
    Absent,
    /// Only rows carrying our ownership marker (`RTPROT_BGP` +
    /// `RTN_BLACKHOLE`) match the prefix. Whether the row is *owned* is
    /// the reconciler's call, not the kernel's — a marker row may be
    /// ours from this lifetime, a crash leftover, or operator-installed
    /// `proto bgp` state (indistinguishable by design, ADR-0079).
    Marker,
    /// At least one non-marker row matches the prefix.
    Foreign,
}

/// One main-table kernel route, as parsed from the per-pass dump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KernelRouteEntry {
    prefix: Prefix,
    /// True when the row carries the ownership marker.
    marker: bool,
}

/// ADR-0079 startup adoption sweep state.
struct AdoptionSweep {
    /// Whether the one-shot sweep over the first successful kernel dump
    /// has run. Never reset within a process lifetime — marker rows
    /// appearing later are claimed only if desired, never queued for
    /// reaping (sweeps must not depend on prior-process state, and a
    /// co-resident writer's rows are not ours to expire).
    swept: bool,
    /// Adopted marker rows not yet re-claimed by a desired prefix.
    pending: HashSet<Prefix>,
    /// When adopted-but-unclaimed rows become reapable.
    reap_after: tokio::time::Instant,
}

impl AdoptionSweep {
    fn new(reap_after: tokio::time::Instant) -> Self {
        Self {
            swept: false,
            pending: HashSet::new(),
            reap_after,
        }
    }
}

/// The reconciler's mutable per-lifetime state, threaded through every
/// pass together.
struct ReconcilerState {
    owned: HashMap<Prefix, OwnedBlackhole>,
    rejected: HashSet<RejectedBlackhole>,
    adoption: AdoptionSweep,
}

impl ReconcilerState {
    fn new(reap_after: tokio::time::Instant) -> Self {
        Self {
            owned: HashMap::new(),
            rejected: HashSet::new(),
            adoption: AdoptionSweep::new(reap_after),
        }
    }
}

/// Collapse the dump into per-prefix presence. A foreign row dominates:
/// the kernel can hold several routes for one prefix (different
/// metrics), and any non-marker row makes the prefix unsafe to claim.
fn presence_by_prefix(entries: &[KernelRouteEntry]) -> HashMap<Prefix, KernelRoutePresence> {
    let mut map = HashMap::with_capacity(entries.len());
    for entry in entries {
        let presence = if entry.marker {
            KernelRoutePresence::Marker
        } else {
            KernelRoutePresence::Foreign
        };
        map.entry(entry.prefix)
            .and_modify(|existing| {
                if presence == KernelRoutePresence::Foreign {
                    *existing = KernelRoutePresence::Foreign;
                }
            })
            .or_insert(presence);
    }
    map
}

/// Join handle wrapper used by main shutdown.
pub struct BlackholeHandle {
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl BlackholeHandle {
    /// Request shutdown and wait for bounded cleanup of owned routes.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        match tokio::time::timeout(SHUTDOWN_TIMEOUT, self.task).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                warn!(error = %e, "BLACKHOLE discard task panicked during shutdown");
            }
            Err(_) => {
                warn!(
                    timeout_ms = SHUTDOWN_TIMEOUT.as_millis(),
                    "BLACKHOLE discard task did not finish before shutdown timeout"
                );
            }
        }
    }
}

/// Spawn the Linux-backed BLACKHOLE discard reconciler. Returns `None`
/// when disabled or when the platform has no Linux route primitive.
#[must_use]
pub fn spawn(
    config: BlackholeConfig,
    rib_tx: mpsc::Sender<RibUpdate>,
    metrics: BgpMetrics,
    status_tx: watch::Sender<Vec<BlackholeStatus>>,
    shutdown: CancellationToken,
) -> Option<BlackholeHandle> {
    if !config.enabled() {
        return None;
    }

    #[cfg(target_os = "linux")]
    {
        match LinuxBlackholeFib::connect(metrics.clone()) {
            Ok(fib) => Some(spawn_with_fib(
                config, rib_tx, fib, metrics, status_tx, shutdown,
            )),
            Err(e) => {
                metrics.record_blackhole_discard_kernel_failure("setup");
                warn!(error = %e, "BLACKHOLE discard install requested, but netlink setup failed");
                None
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (rib_tx, status_tx, shutdown);
        metrics.record_blackhole_discard_kernel_failure("unsupported_platform");
        warn!("BLACKHOLE discard install requested, but kernel FIB programming is Linux-only");
        None
    }
}

fn spawn_with_fib<F>(
    config: BlackholeConfig,
    rib_tx: mpsc::Sender<RibUpdate>,
    fib: F,
    metrics: BgpMetrics,
    status_tx: watch::Sender<Vec<BlackholeStatus>>,
    shutdown: CancellationToken,
) -> BlackholeHandle
where
    F: BlackholeFib + Send + 'static,
{
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move {
        run_loop(config, rib_tx, fib, metrics, status_tx, task_shutdown).await;
    });
    BlackholeHandle { shutdown, task }
}

async fn run_loop<F>(
    config: BlackholeConfig,
    rib_tx: mpsc::Sender<RibUpdate>,
    mut fib: F,
    metrics: BgpMetrics,
    status_tx: watch::Sender<Vec<BlackholeStatus>>,
    shutdown: CancellationToken,
) where
    F: BlackholeFib,
{
    let mut state = ReconcilerState::new(tokio::time::Instant::now() + adoption_reap_deferral());
    let mut interval = tokio::time::interval(RECONCILE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    let mut event_debounce = Box::pin(tokio::time::sleep(ROUTE_EVENT_DEBOUNCE));
    let mut route_event_dirty = false;

    let mut route_events = subscribe_route_events(&rib_tx).await;
    let mut kernel_route_events = fib.take_kernel_route_events();
    reconcile_once(config, &rib_tx, &mut fib, &metrics, &status_tx, &mut state).await;

    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                // Adopted-but-unclaimed rows are deliberately left in
                // place: a clean shutdown inside the deferral window must
                // not reap rows BGP never got the chance to re-claim. The
                // next start re-adopts them (ADR-0079 rule 4).
                drain_owned(&mut fib, &metrics, &mut state.owned).await;
                status_tx.send_replace(Vec::new());
                return;
            }
            _ = interval.tick() => {
                reconcile_once(config, &rib_tx, &mut fib, &metrics, &status_tx, &mut state).await;
            }
            () = &mut event_debounce, if route_event_dirty => {
                route_event_dirty = false;
                reconcile_once(config, &rib_tx, &mut fib, &metrics, &status_tx, &mut state).await;
            }
            maybe_event = recv_route_event(&mut route_events) => {
                match maybe_event {
                    Some(()) => {
                        route_event_dirty = true;
                        event_debounce
                            .as_mut()
                            .reset(tokio::time::Instant::now() + ROUTE_EVENT_DEBOUNCE);
                    }
                    None => {
                        route_events = subscribe_route_events(&rib_tx).await;
                    }
                }
            }
            maybe_drift = recv_kernel_route_event(&mut kernel_route_events) => {
                match maybe_drift {
                    Some(event) => {
                        if kernel_route_drift_wakes(&event, &state.owned) {
                            debug!(
                                prefix = ?event.prefix,
                                "kernel route drift on the BLACKHOLE discard surface; \
                                 coalesced reconcile follows"
                            );
                            route_event_dirty = true;
                            event_debounce
                                .as_mut()
                                .reset(tokio::time::Instant::now() + ROUTE_EVENT_DEBOUNCE);
                        }
                    }
                    // Notification stream closed (connection teardown);
                    // retire the arm — the periodic backstop still
                    // repairs kernel drift, as before eventing.
                    None => kernel_route_events = None,
                }
            }
        }
    }
}

/// Kernel route-event drift classifier — should this
/// `RTNLGRP_IPV4_ROUTE` / `RTNLGRP_IPV6_ROUTE` notification wake the
/// reconciler ahead of the 30 s periodic backstop?
///
/// The actor's ownership marker is `RTPROT_BGP` + `RTN_BLACKHOLE` in
/// the main table (ADR-0079), so:
///
/// - **`RTM_DELROUTE`** of a marker row wakes — external interference
///   (`ip route del` / a flush) swept a discard row, whether owned or
///   an adopted-but-unclaimed crash leftover; the pass re-diffs both.
///   Our own withdraw echoes the same message and costs one coalesced
///   no-op pass.
/// - **`RTM_NEWROUTE`** wakes only when a *non*-marker row lands on an
///   owned prefix — an `ip route replace` clobbering a discard row
///   emits exactly this (the kernel sends no `DELROUTE` for the
///   replaced row). Marker-row `NEWROUTE`s never wake: every install
///   echoes one. A foreign row at a different metric does not actually
///   displace the discard row, but owned prefixes are RTBH host routes
///   so a colliding foreign add is rare enough that the extra
///   coalesced pass is cheaper than tracking kernel metrics here.
///
/// Everything outside the main table, and all unrelated main-table
/// churn (connected/static/host routes on non-owned prefixes), must
/// not wake the actor.
fn kernel_route_drift_wakes(
    event: &KernelRouteEvent,
    owned: &HashMap<Prefix, OwnedBlackhole>,
) -> bool {
    if event.table_id != RT_TABLE_MAIN {
        return false;
    }
    let marker = event.protocol_is_bgp && event.route_type == KernelRouteType::BlackHole;
    match event.kind {
        KernelRouteEventKind::Del => marker,
        KernelRouteEventKind::New => {
            !marker
                && event
                    .prefix
                    .is_some_and(|prefix| owned.contains_key(&prefix))
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
        warn!("BLACKHOLE discard task could not subscribe to RIB events");
        return None;
    }
    if let Ok(events) = rx.await {
        Some(events)
    } else {
        warn!("BLACKHOLE discard task subscription reply dropped");
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
                "BLACKHOLE discard task lagged RIB event stream; full reconcile follows"
            );
            Some(())
        }
        Err(broadcast::error::RecvError::Closed) => None,
    }
}

async fn query_best_routes(rib_tx: &mpsc::Sender<RibUpdate>) -> Option<Vec<Route>> {
    let (reply, rx) = oneshot::channel();
    if rib_tx
        .send(RibUpdate::QueryBestRoutes { reply })
        .await
        .is_err()
    {
        warn!("BLACKHOLE discard task could not query best routes");
        return None;
    }
    match tokio::time::timeout(RIB_QUERY_TIMEOUT, rx).await {
        Ok(Ok(routes)) => Some(routes),
        Ok(Err(_)) => {
            warn!("BLACKHOLE discard task best-route reply dropped");
            None
        }
        Err(_) => {
            warn!("BLACKHOLE discard task best-route query timed out");
            None
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "single level-triggered reconcile pass keeps owned-status publication, install preflight, adoption claim/reap, and counter transition accounting in one auditable order"
)]
async fn reconcile_once<F>(
    config: BlackholeConfig,
    rib_tx: &mpsc::Sender<RibUpdate>,
    fib: &mut F,
    metrics: &BgpMetrics,
    status_tx: &watch::Sender<Vec<BlackholeStatus>>,
    state: &mut ReconcilerState,
) where
    F: BlackholeFib,
{
    let Some(routes) = query_best_routes(rib_tx).await else {
        return;
    };
    let derived = derive_desired(config, &routes);
    let desired: HashMap<Prefix, &Route> = derived
        .iter()
        .filter_map(|candidate| {
            candidate
                .installable
                .then_some((candidate.prefix, candidate.route))
        })
        .collect();

    let ReconcilerState {
        owned,
        rejected,
        adoption,
    } = state;
    let mut statuses = Vec::with_capacity(derived.len() + owned.len());
    let mut current_rejected = HashSet::new();

    // One kernel dump per pass replaces the previous per-candidate
    // full-table lookups: presence for every candidate, the adoption
    // sweep, and the reap all read this snapshot.
    let presences = match fib.dump().await {
        Ok(entries) => presence_by_prefix(&entries),
        Err(e) => {
            metrics.record_blackhole_discard_kernel_failure("dump");
            warn!(
                error = %e,
                "failed to dump kernel routes for BLACKHOLE reconcile; pass degraded to removals only"
            );
            degraded_pass_without_dump(fib, metrics, status_tx, owned, rejected, derived).await;
            return;
        }
    };

    if !adoption.swept {
        adoption.swept = true;
        for (prefix, presence) in &presences {
            if *presence == KernelRoutePresence::Marker && !owned.contains_key(prefix) {
                adoption.pending.insert(*prefix);
                metrics.record_blackhole_discard_adopted();
                info!(
                    %prefix,
                    "adopted marker-matching BLACKHOLE discard route from a previous daemon lifetime"
                );
            }
        }
    }

    for (prefix, installed) in owned.clone() {
        if desired.contains_key(&prefix) {
            continue;
        }
        match fib.remove(prefix).await {
            Ok(()) => {
                owned.remove(&prefix);
                metrics.record_blackhole_discard_withdrawn();
                info!(%prefix, "removed BLACKHOLE discard route");
            }
            Err(e) => {
                metrics.record_blackhole_discard_kernel_failure("remove");
                warn!(%prefix, error = %e, "failed to remove BLACKHOLE discard route");
                statuses.push(BlackholeStatus {
                    prefix,
                    peer: installed.peer,
                    state: BlackholeState::Failed,
                    reason: "remove_failed".to_string(),
                });
            }
        }
    }

    for candidate in derived {
        if !candidate.installable {
            let rejected_key = RejectedBlackhole {
                prefix: candidate.prefix,
                reason: candidate.reason,
            };
            current_rejected.insert(rejected_key);
            if !rejected.contains(&rejected_key) {
                metrics.record_blackhole_discard_rejected(candidate.reason);
            }
            statuses.push(BlackholeStatus {
                prefix: candidate.prefix,
                peer: candidate.route.peer,
                state: BlackholeState::Rejected,
                reason: candidate.reason.to_string(),
            });
            continue;
        }

        let presence = presences
            .get(&candidate.prefix)
            .copied()
            .unwrap_or(KernelRoutePresence::Absent);

        if owned.contains_key(&candidate.prefix) {
            match presence {
                KernelRoutePresence::Marker => {
                    statuses.push(BlackholeStatus {
                        prefix: candidate.prefix,
                        peer: candidate.route.peer,
                        state: BlackholeState::Installed,
                        reason: "owned".to_string(),
                    });
                    continue;
                }
                KernelRoutePresence::Absent => {
                    owned.remove(&candidate.prefix);
                    warn!(
                        prefix = %candidate.prefix,
                        peer = %candidate.route.peer,
                        "daemon-owned BLACKHOLE discard route disappeared from kernel; reinstalling"
                    );
                }
                KernelRoutePresence::Foreign => {
                    owned.remove(&candidate.prefix);
                    warn!(
                        prefix = %candidate.prefix,
                        peer = %candidate.route.peer,
                        "daemon-owned BLACKHOLE discard route was replaced by a foreign kernel route"
                    );
                    statuses.push(BlackholeStatus {
                        prefix: candidate.prefix,
                        peer: candidate.route.peer,
                        state: BlackholeState::Failed,
                        reason: "foreign_route_exists".to_string(),
                    });
                    continue;
                }
            }
        }

        match presence {
            KernelRoutePresence::Marker => {
                // Implicit re-claim (ADR-0079 rule 2): the kernel row is
                // byte-identical to what we would install, so a desired
                // prefix claims it instead of failing as foreign. This
                // covers crash leftovers (the adoption sweep) and any
                // marker row the owned map lost track of.
                adoption.pending.remove(&candidate.prefix);
                owned.insert(
                    candidate.prefix,
                    OwnedBlackhole {
                        peer: candidate.route.peer,
                    },
                );
                info!(
                    prefix = %candidate.prefix,
                    peer = %candidate.route.peer,
                    "claimed adopted BLACKHOLE discard route for desired prefix"
                );
                statuses.push(BlackholeStatus {
                    prefix: candidate.prefix,
                    peer: candidate.route.peer,
                    state: BlackholeState::Installed,
                    reason: "adopted".to_string(),
                });
                continue;
            }
            KernelRoutePresence::Foreign => {
                statuses.push(BlackholeStatus {
                    prefix: candidate.prefix,
                    peer: candidate.route.peer,
                    state: BlackholeState::Failed,
                    reason: "foreign_route_exists".to_string(),
                });
                continue;
            }
            KernelRoutePresence::Absent => {
                // The adopted row is gone from the kernel; nothing left
                // to claim or reap — fall through to a fresh install.
                adoption.pending.remove(&candidate.prefix);
            }
        }

        match fib.install(candidate.prefix).await {
            Ok(()) => {
                owned.insert(
                    candidate.prefix,
                    OwnedBlackhole {
                        peer: candidate.route.peer,
                    },
                );
                metrics.record_blackhole_discard_installed();
                info!(
                    prefix = %candidate.prefix,
                    peer = %candidate.route.peer,
                    "installed BLACKHOLE discard route"
                );
                statuses.push(BlackholeStatus {
                    prefix: candidate.prefix,
                    peer: candidate.route.peer,
                    state: BlackholeState::Installed,
                    reason: "installed".to_string(),
                });
            }
            Err(e) => {
                metrics.record_blackhole_discard_kernel_failure("install");
                warn!(
                    prefix = %candidate.prefix,
                    peer = %candidate.route.peer,
                    error = %e,
                    "failed to install BLACKHOLE discard route"
                );
                statuses.push(BlackholeStatus {
                    prefix: candidate.prefix,
                    peer: candidate.route.peer,
                    state: BlackholeState::Failed,
                    reason: e,
                });
            }
        }
    }

    reap_or_report_adopted(
        fib,
        metrics,
        owned,
        adoption,
        &desired,
        &presences,
        &mut statuses,
    )
    .await;

    *rejected = current_rejected;
    status_tx.send_replace(statuses);
}

/// Reap adopted-but-unclaimed rows after the deferral, or surface them
/// as pending so a crash leftover is never invisible to the status
/// surfaces while it keeps discarding traffic.
async fn reap_or_report_adopted<F>(
    fib: &mut F,
    metrics: &BgpMetrics,
    owned: &HashMap<Prefix, OwnedBlackhole>,
    adoption: &mut AdoptionSweep,
    desired: &HashMap<Prefix, &Route>,
    presences: &HashMap<Prefix, KernelRoutePresence>,
    statuses: &mut Vec<BlackholeStatus>,
) where
    F: BlackholeFib,
{
    if adoption.pending.is_empty() {
        return;
    }
    let reapable = tokio::time::Instant::now() >= adoption.reap_after;
    for prefix in adoption.pending.clone() {
        if desired.contains_key(&prefix) || owned.contains_key(&prefix) {
            // Claimed (or about to be) — never reap a desired prefix.
            adoption.pending.remove(&prefix);
            continue;
        }
        match presences
            .get(&prefix)
            .copied()
            .unwrap_or(KernelRoutePresence::Absent)
        {
            KernelRoutePresence::Marker => {}
            KernelRoutePresence::Absent | KernelRoutePresence::Foreign => {
                // The row vanished or a non-marker route now occupies the
                // prefix. Either way, the adopted marker is no longer ours
                // to report or reap.
                adoption.pending.remove(&prefix);
                continue;
            }
        }
        if !reapable {
            upsert_blackhole_status(
                statuses,
                BlackholeStatus {
                    prefix,
                    peer: unspecified_peer(prefix),
                    state: BlackholeState::Installed,
                    reason: "adopted_pending_reap".to_string(),
                },
            );
            continue;
        }
        match fib.remove(prefix).await {
            Ok(()) => {
                adoption.pending.remove(&prefix);
                metrics.record_blackhole_discard_reaped();
                info!(
                    %prefix,
                    "reaped adopted BLACKHOLE discard route that no BGP route re-claimed"
                );
            }
            Err(e) => {
                metrics.record_blackhole_discard_kernel_failure("remove");
                warn!(%prefix, error = %e, "failed to reap adopted BLACKHOLE discard route");
                upsert_blackhole_status(
                    statuses,
                    BlackholeStatus {
                        prefix,
                        peer: unspecified_peer(prefix),
                        state: BlackholeState::Failed,
                        reason: "reap_failed".to_string(),
                    },
                );
            }
        }
    }
}

fn upsert_blackhole_status(statuses: &mut Vec<BlackholeStatus>, status: BlackholeStatus) {
    if let Some(existing) = statuses
        .iter_mut()
        .find(|existing| existing.prefix == status.prefix)
    {
        *existing = status;
    } else {
        statuses.push(status);
    }
}

/// Adopted rows have no announcing peer; status rows use the
/// family-matching unspecified address.
fn unspecified_peer(prefix: Prefix) -> IpAddr {
    match prefix {
        Prefix::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        Prefix::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    }
}

/// Fallback pass when the kernel dump failed: removals of no-longer-
/// desired owned routes still run (`remove` is idempotent and needs no
/// presence data), but installs, claims, and reaping are skipped and
/// every installable candidate is surfaced as degraded.
async fn degraded_pass_without_dump<F>(
    fib: &mut F,
    metrics: &BgpMetrics,
    status_tx: &watch::Sender<Vec<BlackholeStatus>>,
    owned: &mut HashMap<Prefix, OwnedBlackhole>,
    rejected: &mut HashSet<RejectedBlackhole>,
    derived: Vec<Candidate<'_>>,
) where
    F: BlackholeFib,
{
    let desired: HashSet<Prefix> = derived
        .iter()
        .filter_map(|candidate| candidate.installable.then_some(candidate.prefix))
        .collect();
    let mut statuses = Vec::with_capacity(derived.len() + owned.len());
    let mut current_rejected = HashSet::new();

    for (prefix, installed) in owned.clone() {
        if desired.contains(&prefix) {
            continue;
        }
        match fib.remove(prefix).await {
            Ok(()) => {
                owned.remove(&prefix);
                metrics.record_blackhole_discard_withdrawn();
                info!(%prefix, "removed BLACKHOLE discard route");
            }
            Err(e) => {
                metrics.record_blackhole_discard_kernel_failure("remove");
                warn!(%prefix, error = %e, "failed to remove BLACKHOLE discard route");
                statuses.push(BlackholeStatus {
                    prefix,
                    peer: installed.peer,
                    state: BlackholeState::Failed,
                    reason: "remove_failed".to_string(),
                });
            }
        }
    }

    for candidate in derived {
        if candidate.installable {
            statuses.push(BlackholeStatus {
                prefix: candidate.prefix,
                peer: candidate.route.peer,
                state: BlackholeState::Failed,
                reason: "dump_failed".to_string(),
            });
        } else {
            let rejected_key = RejectedBlackhole {
                prefix: candidate.prefix,
                reason: candidate.reason,
            };
            current_rejected.insert(rejected_key);
            if !rejected.contains(&rejected_key) {
                metrics.record_blackhole_discard_rejected(candidate.reason);
            }
            statuses.push(BlackholeStatus {
                prefix: candidate.prefix,
                peer: candidate.route.peer,
                state: BlackholeState::Rejected,
                reason: candidate.reason.to_string(),
            });
        }
    }

    *rejected = current_rejected;
    status_tx.send_replace(statuses);
}

async fn drain_owned<F>(
    fib: &mut F,
    metrics: &BgpMetrics,
    owned: &mut HashMap<Prefix, OwnedBlackhole>,
) where
    F: BlackholeFib,
{
    for prefix in owned.keys().copied().collect::<Vec<_>>() {
        match fib.remove(prefix).await {
            Ok(()) => {
                owned.remove(&prefix);
                metrics.record_blackhole_discard_withdrawn();
            }
            Err(e) => {
                metrics.record_blackhole_discard_kernel_failure("remove");
                warn!(%prefix, error = %e, "failed to drain BLACKHOLE discard route");
            }
        }
    }
}

#[derive(Debug)]
struct Candidate<'a> {
    prefix: Prefix,
    route: &'a Route,
    installable: bool,
    reason: &'static str,
}

fn derive_desired(config: BlackholeConfig, routes: &[Route]) -> Vec<Candidate<'_>> {
    let mut out = Vec::new();
    for route in routes {
        if !has_blackhole_community(route) {
            continue;
        }
        let mut installable = true;
        let mut reason = "eligible";
        if route.origin_type != RouteOrigin::Ebgp {
            installable = false;
            reason = "not_ebgp";
        } else if !config.allow_broad_prefixes && !is_host_prefix(route.prefix) {
            installable = false;
            reason = "broad_prefix";
        }
        out.push(Candidate {
            prefix: route.prefix,
            route,
            installable,
            reason,
        });
    }
    out
}

fn has_blackhole_community(route: &Route) -> bool {
    route.attributes.iter().any(|attr| {
        matches!(
            attr,
            PathAttribute::Communities(values)
                if values.contains(&rustbgpd_wire::COMMUNITY_BLACKHOLE)
        )
    })
}

fn is_host_prefix(prefix: Prefix) -> bool {
    match prefix {
        Prefix::V4(p) => p.len == 32,
        Prefix::V6(p) => p.len == 128,
    }
}

trait BlackholeFib {
    /// Dump every main-table kernel route once per reconcile pass.
    fn dump(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<KernelRouteEntry>, String>> + Send + '_>>;
    fn install(
        &mut self,
        prefix: Prefix,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>>;
    fn remove(
        &mut self,
        prefix: Prefix,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>>;

    /// Take the kernel route-change notification stream, if the
    /// backing can surface one. Called once at actor startup; `None`
    /// (fakes, non-Linux, subscription unavailable) leaves kernel-side
    /// drift repair to the periodic reconcile backstop.
    fn take_kernel_route_events(&mut self) -> Option<mpsc::Receiver<KernelRouteEvent>> {
        None
    }
}

#[cfg(target_os = "linux")]
struct LinuxBlackholeFib {
    handle: rtnetlink::Handle,
    kernel_route_events: Option<mpsc::Receiver<KernelRouteEvent>>,
}

#[cfg(target_os = "linux")]
impl LinuxBlackholeFib {
    fn connect(metrics: BgpMetrics) -> Result<Self, String> {
        let (handle, events) = crate::kernel_route_notify::connect_with_route_notifications(
            "blackhole_discard",
            metrics,
        )?;
        Ok(Self {
            handle,
            kernel_route_events: Some(events),
        })
    }
}

#[cfg(target_os = "linux")]
impl BlackholeFib for LinuxBlackholeFib {
    fn dump(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<KernelRouteEntry>, String>> + Send + '_>> {
        Box::pin(async move { dump_main_table_routes(&self.handle).await })
    }

    fn install(
        &mut self,
        prefix: Prefix,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            let msg = build_blackhole_route(prefix);
            self.handle
                .route()
                .add(msg)
                .execute()
                .await
                .map_err(|e| format!("kernel route add: {e}"))
        })
    }

    fn remove(
        &mut self,
        prefix: Prefix,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            let msg = build_blackhole_route(prefix);
            match self.handle.route().del(msg).execute().await {
                Ok(()) => Ok(()),
                Err(e) => {
                    if matches!(netlink_errno(&e), Some(code) if is_idempotent_route_delete_errno(code))
                    {
                        Ok(())
                    } else {
                        Err(format!("kernel route del: {e}"))
                    }
                }
            }
        })
    }

    fn take_kernel_route_events(&mut self) -> Option<mpsc::Receiver<KernelRouteEvent>> {
        self.kernel_route_events.take()
    }
}

/// One v4 + one v6 netlink dump per pass, parsed into main-table
/// entries. This replaces the previous per-candidate full-table scans —
/// the route count parsed per pass is now independent of how many
/// blackhole candidates exist.
#[cfg(target_os = "linux")]
async fn dump_main_table_routes(
    handle: &rtnetlink::Handle,
) -> Result<Vec<KernelRouteEntry>, String> {
    use futures::TryStreamExt;
    use rtnetlink::RouteMessageBuilder;

    let mut entries = Vec::new();
    let queries = [
        RouteMessageBuilder::<std::net::Ipv4Addr>::new().build(),
        RouteMessageBuilder::<std::net::Ipv6Addr>::new().build(),
    ];
    for query in queries {
        let mut stream = handle.route().get(query).execute();
        while let Some(route) = stream
            .try_next()
            .await
            .map_err(|e| format!("kernel route dump: {e}"))?
        {
            if let Some(entry) = kernel_route_entry(&route) {
                entries.push(entry);
            }
        }
    }
    Ok(entries)
}

#[cfg(target_os = "linux")]
fn build_blackhole_route(prefix: Prefix) -> netlink_packet_route::route::RouteMessage {
    use netlink_packet_route::AddressFamily;
    use netlink_packet_route::route::{
        RouteAddress, RouteAttribute, RouteFlags, RouteHeader, RouteProtocol, RouteScope, RouteType,
    };

    let mut msg = netlink_packet_route::route::RouteMessage::default();
    msg.header = RouteHeader {
        address_family: match prefix {
            Prefix::V4(_) => AddressFamily::Inet,
            Prefix::V6(_) => AddressFamily::Inet6,
        },
        destination_prefix_length: prefix.prefix_len(),
        source_prefix_length: 0,
        tos: 0,
        table: 254, // RT_TABLE_MAIN
        protocol: RouteProtocol::Bgp,
        scope: RouteScope::Universe,
        kind: RouteType::BlackHole,
        flags: RouteFlags::default(),
    };
    msg.attributes
        .push(RouteAttribute::Destination(match prefix {
            Prefix::V4(p) => RouteAddress::Inet(p.addr),
            Prefix::V6(p) => RouteAddress::Inet6(p.addr),
        }));
    msg
}

/// Parse one dumped kernel route into a main-table entry. Returns
/// `None` for routes in other tables and for messages whose destination
/// cannot be reconstructed (a missing `Destination` attribute is only
/// valid for the default route).
#[cfg(target_os = "linux")]
fn kernel_route_entry(msg: &netlink_packet_route::route::RouteMessage) -> Option<KernelRouteEntry> {
    use netlink_packet_route::AddressFamily;
    use netlink_packet_route::route::{RouteAddress, RouteAttribute};
    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix};

    let table = msg
        .attributes
        .iter()
        .find_map(|attr| match attr {
            RouteAttribute::Table(id) => Some(*id),
            _ => None,
        })
        .unwrap_or(u32::from(msg.header.table));
    if table != RT_TABLE_MAIN {
        return None;
    }

    let len = msg.header.destination_prefix_length;
    let destination = msg.attributes.iter().find_map(|attr| match attr {
        RouteAttribute::Destination(addr) => Some(addr),
        _ => None,
    });
    let prefix = match (msg.header.address_family, destination) {
        (AddressFamily::Inet, Some(RouteAddress::Inet(addr))) => {
            Prefix::V4(Ipv4Prefix::new(*addr, len))
        }
        (AddressFamily::Inet6, Some(RouteAddress::Inet6(addr))) => {
            Prefix::V6(Ipv6Prefix::new(*addr, len))
        }
        (AddressFamily::Inet, None) if len == 0 => {
            Prefix::V4(Ipv4Prefix::new(std::net::Ipv4Addr::UNSPECIFIED, 0))
        }
        (AddressFamily::Inet6, None) if len == 0 => {
            Prefix::V6(Ipv6Prefix::new(std::net::Ipv6Addr::UNSPECIFIED, 0))
        }
        _ => return None,
    };
    Some(KernelRouteEntry {
        prefix,
        marker: route_has_ownership_marker(msg),
    })
}

#[cfg(target_os = "linux")]
fn route_has_ownership_marker(msg: &netlink_packet_route::route::RouteMessage) -> bool {
    use netlink_packet_route::route::{RouteProtocol, RouteType};

    msg.header.protocol == RouteProtocol::Bgp && msg.header.kind == RouteType::BlackHole
}

#[cfg(target_os = "linux")]
fn is_idempotent_route_delete_errno(code: i32) -> bool {
    code == libc::ENOENT || code == libc::ESRCH
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
    use rustbgpd_rib::RouteEvent;
    use rustbgpd_rib::route::RouteOrigin;
    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix, Origin};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Instant;

    /// Fake kernel: `installed` holds marker rows (ours or crash
    /// leftovers — the dump cannot tell), `foreign` holds non-marker
    /// rows for the same table.
    #[derive(Default)]
    struct FakeFib {
        installed: HashSet<Prefix>,
        foreign: HashSet<Prefix>,
        fail_install: HashMap<Prefix, String>,
        fail_remove: HashMap<Prefix, String>,
        fail_dump: Option<String>,
        install_calls: Vec<Prefix>,
        remove_calls: Vec<Prefix>,
        dump_calls: usize,
        kernel_events: Option<mpsc::Receiver<KernelRouteEvent>>,
    }

    impl BlackholeFib for FakeFib {
        fn dump(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<KernelRouteEntry>, String>> + Send + '_>>
        {
            self.dump_calls += 1;
            Box::pin(async move {
                if let Some(error) = &self.fail_dump {
                    return Err(error.clone());
                }
                let mut entries: Vec<KernelRouteEntry> = self
                    .installed
                    .iter()
                    .map(|prefix| KernelRouteEntry {
                        prefix: *prefix,
                        marker: true,
                    })
                    .collect();
                entries.extend(self.foreign.iter().map(|prefix| KernelRouteEntry {
                    prefix: *prefix,
                    marker: false,
                }));
                Ok(entries)
            })
        }

        fn install(
            &mut self,
            prefix: Prefix,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
            self.install_calls.push(prefix);
            Box::pin(async move {
                if let Some(error) = self.fail_install.get(&prefix) {
                    return Err(error.clone());
                }
                self.installed.insert(prefix);
                Ok(())
            })
        }

        fn remove(
            &mut self,
            prefix: Prefix,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
            self.remove_calls.push(prefix);
            Box::pin(async move {
                if let Some(error) = self.fail_remove.get(&prefix) {
                    return Err(error.clone());
                }
                self.installed.remove(&prefix);
                Ok(())
            })
        }

        fn take_kernel_route_events(&mut self) -> Option<mpsc::Receiver<KernelRouteEvent>> {
            self.kernel_events.take()
        }
    }

    fn rib_with_routes(routes: Vec<Route>) -> mpsc::Sender<RibUpdate> {
        let (tx, mut rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(update) = rx.recv().await {
                if let RibUpdate::QueryBestRoutes { reply } = update {
                    let _ = reply.send(routes.clone());
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
                    RibUpdate::QueryBestRoutes { reply } => {
                        query_count_task.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(routes.clone());
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

    /// Adoption state whose reap deadline is far in the future — the
    /// default for tests not exercising the reap.
    fn deferred_adoption() -> AdoptionSweep {
        AdoptionSweep::new(tokio::time::Instant::now() + Duration::from_hours(1))
    }

    /// Adoption state whose reap deadline has already passed.
    fn reapable_adoption() -> AdoptionSweep {
        AdoptionSweep::new(tokio::time::Instant::now())
    }

    async fn reconcile_for_test_with_adoption(
        routes: Vec<Route>,
        fib: &mut FakeFib,
        owned: &mut HashMap<Prefix, OwnedBlackhole>,
        rejected: &mut HashSet<RejectedBlackhole>,
        metrics: &BgpMetrics,
        adoption: &mut AdoptionSweep,
    ) -> Vec<BlackholeStatus> {
        let rib_tx = rib_with_routes(routes);
        let (status_tx, status_rx) = watch::channel(Vec::new());
        let mut state = ReconcilerState {
            owned: std::mem::take(owned),
            rejected: std::mem::take(rejected),
            adoption: std::mem::replace(adoption, reapable_adoption()),
        };
        reconcile_once(
            BlackholeConfig {
                enabled: true,
                allow_broad_prefixes: false,
            },
            &rib_tx,
            fib,
            metrics,
            &status_tx,
            &mut state,
        )
        .await;
        *owned = state.owned;
        *rejected = state.rejected;
        *adoption = state.adoption;
        status_rx.borrow().clone()
    }

    async fn reconcile_for_test(
        routes: Vec<Route>,
        fib: &mut FakeFib,
        owned: &mut HashMap<Prefix, OwnedBlackhole>,
        rejected: &mut HashSet<RejectedBlackhole>,
        metrics: &BgpMetrics,
    ) -> Vec<BlackholeStatus> {
        let mut adoption = deferred_adoption();
        reconcile_for_test_with_adoption(routes, fib, owned, rejected, metrics, &mut adoption).await
    }

    fn counter_value(metrics: &BgpMetrics, name: &str, label_name: &str, label_value: &str) -> f64 {
        metrics
            .registry()
            .gather()
            .into_iter()
            .find(|family| family.name() == name)
            .and_then(|family| {
                family.get_metric().iter().find_map(|metric| {
                    metric
                        .get_label()
                        .iter()
                        .any(|label| label.name() == label_name && label.value() == label_value)
                        .then(|| {
                            metric
                                .get_counter()
                                .as_ref()
                                .map_or(0.0, prometheus::proto::Counter::value)
                        })
                })
            })
            .unwrap_or(0.0)
    }

    fn route(prefix: Prefix, origin_type: RouteOrigin, communities: Vec<u32>) -> Route {
        Route {
            prefix,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            attributes: Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::Communities(communities),
            ]),
            received_at: Instant::now(),
            origin_type,
            peer_router_id: Ipv4Addr::new(203, 0, 113, 1),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        }
    }

    fn route_event(prefix: Prefix) -> RouteEvent {
        crate::test_support::route_event(prefix, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)))
    }

    fn v4(len: u8) -> Prefix {
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 66), len))
    }

    fn v6(len: u8) -> Prefix {
        Prefix::V6(Ipv6Prefix::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x66),
            len,
        ))
    }

    #[test]
    fn derive_desired_accepts_ebgp_host_routes() {
        let routes = vec![route(
            v4(32),
            RouteOrigin::Ebgp,
            vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
        )];
        let got = derive_desired(
            BlackholeConfig {
                enabled: true,
                allow_broad_prefixes: false,
            },
            &routes,
        );
        assert_eq!(got.len(), 1);
        assert!(got[0].installable);
        assert_eq!(got[0].reason, "eligible");
    }

    #[test]
    fn derive_desired_rejects_broad_prefix_by_default() {
        let routes = vec![route(
            v4(24),
            RouteOrigin::Ebgp,
            vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
        )];
        let got = derive_desired(
            BlackholeConfig {
                enabled: true,
                allow_broad_prefixes: false,
            },
            &routes,
        );
        assert_eq!(got.len(), 1);
        assert!(!got[0].installable);
        assert_eq!(got[0].reason, "broad_prefix");
    }

    #[test]
    fn derive_desired_accepts_broad_prefix_when_enabled() {
        let routes = vec![route(
            v6(64),
            RouteOrigin::Ebgp,
            vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
        )];
        let got = derive_desired(
            BlackholeConfig {
                enabled: true,
                allow_broad_prefixes: true,
            },
            &routes,
        );
        assert!(got[0].installable);
    }

    #[test]
    fn derive_desired_rejects_non_ebgp() {
        let routes = vec![route(
            v4(32),
            RouteOrigin::Ibgp,
            vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
        )];
        let got = derive_desired(
            BlackholeConfig {
                enabled: true,
                allow_broad_prefixes: false,
            },
            &routes,
        );
        assert!(!got[0].installable);
        assert_eq!(got[0].reason, "not_ebgp");
    }

    #[test]
    fn derive_desired_ignores_untagged_routes() {
        let routes = vec![route(v4(32), RouteOrigin::Ebgp, vec![])];
        let got = derive_desired(
            BlackholeConfig {
                enabled: true,
                allow_broad_prefixes: false,
            },
            &routes,
        );
        assert!(got.is_empty());
    }

    #[test]
    fn blackhole_reap_deferral_override_parses_valid_seconds() {
        assert_eq!(
            blackhole_reap_deferral_override(Some("5")),
            Some(Duration::from_secs(5))
        );
        // Zero is meaningful (reap on the first eligible pass), not
        // "unset" — the escape hatch must be able to express it.
        assert_eq!(
            blackhole_reap_deferral_override(Some("0")),
            Some(Duration::from_secs(0))
        );
        // Surrounding whitespace is tolerated, matching the
        // RUSTBGPD_EVPN_ADOPTION_REAP_DEFERRAL_SECS precedent.
        assert_eq!(
            blackhole_reap_deferral_override(Some(" 500 ")),
            Some(Duration::from_secs(500))
        );
    }

    #[test]
    fn blackhole_reap_deferral_override_rejects_invalid_and_unset() {
        assert_eq!(blackhole_reap_deferral_override(None), None);
        assert_eq!(blackhole_reap_deferral_override(Some("")), None);
        assert_eq!(blackhole_reap_deferral_override(Some("abc")), None);
        assert_eq!(blackhole_reap_deferral_override(Some("-1")), None);
        assert_eq!(blackhole_reap_deferral_override(Some("5s")), None);
        assert_eq!(blackhole_reap_deferral_override(Some("1.5")), None);
    }

    #[test]
    fn host_prefix_detection_handles_v4_and_v6() {
        assert!(is_host_prefix(v4(32)));
        assert!(is_host_prefix(v6(128)));
        assert!(!is_host_prefix(v4(31)));
        assert!(!is_host_prefix(v6(127)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_route_entry_parses_marker_and_default_routes() {
        // A row built by our own install path parses back as a marker
        // entry for the same prefix.
        let host_v4 = v4(32);
        let msg = build_blackhole_route(host_v4);
        let entry = kernel_route_entry(&msg).expect("main-table route should parse");
        assert_eq!(entry.prefix, host_v4);
        assert!(entry.marker);

        // A default route without a Destination attribute parses as the
        // unspecified /0 of its family; a non-zero length without a
        // Destination attribute is unparseable and skipped.
        let default_v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0));
        let mut default_route = build_blackhole_route(default_v4);
        default_route.attributes.clear();
        let entry = kernel_route_entry(&default_route).expect("default route should parse");
        assert_eq!(entry.prefix, default_v4);

        let default_v6 = Prefix::V6(Ipv6Prefix::new(Ipv6Addr::UNSPECIFIED, 0));
        let mut default_route = build_blackhole_route(default_v6);
        default_route.attributes.clear();
        let entry = kernel_route_entry(&default_route).expect("v6 default route should parse");
        assert_eq!(entry.prefix, default_v6);

        let mut headless_host = build_blackhole_route(host_v4);
        headless_host.attributes.clear();
        assert!(kernel_route_entry(&headless_host).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_route_entry_skips_other_tables_and_flags_foreign_rows() {
        use netlink_packet_route::route::{RouteProtocol, RouteType};

        let host_v4 = v4(32);
        let mut other_table = build_blackhole_route(host_v4);
        other_table.header.table = 100;
        assert!(kernel_route_entry(&other_table).is_none());

        let mut unicast = build_blackhole_route(host_v4);
        unicast.header.kind = RouteType::Unicast;
        let entry = kernel_route_entry(&unicast).expect("foreign row should still parse");
        assert!(!entry.marker);

        let mut static_blackhole = build_blackhole_route(host_v4);
        static_blackhole.header.protocol = RouteProtocol::Static;
        let entry = kernel_route_entry(&static_blackhole).expect("foreign row should still parse");
        assert!(!entry.marker);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn route_delete_idempotent_errno_set_includes_absent_route_codes() {
        assert!(is_idempotent_route_delete_errno(libc::ENOENT));
        assert!(is_idempotent_route_delete_errno(libc::ESRCH));
        assert!(!is_idempotent_route_delete_errno(libc::EPERM));
    }

    #[tokio::test]
    async fn route_events_are_debounced_before_rib_query() {
        let prefix = v4(32);
        let (rib_tx, query_count, events_tx) = rib_with_events(vec![route(
            prefix,
            RouteOrigin::Ebgp,
            vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
        )]);
        let metrics = BgpMetrics::with_registry(Registry::new());
        let (status_tx, _status_rx) = watch::channel(Vec::new());
        let shutdown = CancellationToken::new();
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            run_loop(
                BlackholeConfig {
                    enabled: true,
                    allow_broad_prefixes: false,
                },
                rib_tx,
                FakeFib::default(),
                metrics,
                status_tx,
                task_shutdown,
            )
            .await;
        });

        for _ in 0..20 {
            if events_tx.receiver_count() > 0 && query_count.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            query_count.load(Ordering::SeqCst),
            1,
            "startup should perform exactly one initial RIB query"
        );

        for _ in 0..5 {
            events_tx.send(route_event(prefix)).unwrap();
        }
        tokio::task::yield_now().await;
        assert_eq!(
            query_count.load(Ordering::SeqCst),
            1,
            "route events should mark the actor dirty without querying immediately"
        );

        tokio::time::sleep(ROUTE_EVENT_DEBOUNCE + Duration::from_millis(50)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            query_count.load(Ordering::SeqCst),
            2,
            "a burst of route events should coalesce into one follow-up RIB query"
        );

        shutdown.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn route_event_debounce_waits_after_idle() {
        let prefix = v4(32);
        let (rib_tx, query_count, events_tx) = rib_with_events(vec![route(
            prefix,
            RouteOrigin::Ebgp,
            vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
        )]);
        let metrics = BgpMetrics::with_registry(Registry::new());
        let (status_tx, _status_rx) = watch::channel(Vec::new());
        let shutdown = CancellationToken::new();
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            run_loop(
                BlackholeConfig {
                    enabled: true,
                    allow_broad_prefixes: false,
                },
                rib_tx,
                FakeFib::default(),
                metrics,
                status_tx,
                task_shutdown,
            )
            .await;
        });

        for _ in 0..20 {
            if events_tx.receiver_count() > 0 && query_count.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(query_count.load(Ordering::SeqCst), 1);

        tokio::time::sleep(ROUTE_EVENT_DEBOUNCE + Duration::from_millis(50)).await;
        events_tx.send(route_event(prefix)).unwrap();
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

        shutdown.cancel();
        task.await.unwrap();
    }

    // --- Kernel route-drift classifier (`kernel_route_drift_wakes`) ---

    fn drift_event(
        kind: KernelRouteEventKind,
        table_id: u32,
        prefix: Option<Prefix>,
        protocol_is_bgp: bool,
        route_type: KernelRouteType,
    ) -> KernelRouteEvent {
        KernelRouteEvent {
            kind,
            table_id,
            metric: 0,
            prefix,
            protocol_is_bgp,
            route_type,
        }
    }

    fn owned_with(prefix: Prefix) -> HashMap<Prefix, OwnedBlackhole> {
        HashMap::from([(
            prefix,
            OwnedBlackhole {
                peer: "198.51.100.1".parse().unwrap(),
            },
        )])
    }

    #[test]
    fn drift_del_of_marker_row_in_main_wakes() {
        let event = drift_event(
            KernelRouteEventKind::Del,
            RT_TABLE_MAIN,
            Some(v4(32)),
            true,
            KernelRouteType::BlackHole,
        );
        // Marker-based, not owned-based: an adopted-but-unclaimed crash
        // leftover being swept must wake too.
        assert!(kernel_route_drift_wakes(&event, &HashMap::new()));
    }

    #[test]
    fn drift_del_outside_main_table_does_not_wake() {
        let event = drift_event(
            KernelRouteEventKind::Del,
            1000,
            Some(v4(32)),
            true,
            KernelRouteType::BlackHole,
        );
        assert!(!kernel_route_drift_wakes(&event, &owned_with(v4(32))));
    }

    #[test]
    fn drift_del_of_non_marker_row_does_not_wake() {
        // Host churn in main: wrong protocol or wrong route type.
        for event in [
            drift_event(
                KernelRouteEventKind::Del,
                RT_TABLE_MAIN,
                Some(v4(32)),
                false,
                KernelRouteType::BlackHole,
            ),
            drift_event(
                KernelRouteEventKind::Del,
                RT_TABLE_MAIN,
                Some(v4(32)),
                true,
                KernelRouteType::Unicast,
            ),
        ] {
            assert!(!kernel_route_drift_wakes(&event, &owned_with(v4(32))));
        }
    }

    #[test]
    fn drift_new_foreign_row_on_owned_prefix_wakes() {
        // `ip route replace` clobbering a discard row.
        let event = drift_event(
            KernelRouteEventKind::New,
            RT_TABLE_MAIN,
            Some(v4(32)),
            false,
            KernelRouteType::Unicast,
        );
        assert!(kernel_route_drift_wakes(&event, &owned_with(v4(32))));
    }

    #[test]
    fn drift_new_foreign_row_off_owned_prefix_does_not_wake() {
        let owned = owned_with(v4(32));
        for event in [
            drift_event(
                KernelRouteEventKind::New,
                RT_TABLE_MAIN,
                Some(v4(24)),
                false,
                KernelRouteType::Unicast,
            ),
            drift_event(
                KernelRouteEventKind::New,
                RT_TABLE_MAIN,
                None,
                false,
                KernelRouteType::Unicast,
            ),
        ] {
            assert!(!kernel_route_drift_wakes(&event, &owned));
        }
    }

    #[test]
    fn drift_new_marker_row_does_not_wake() {
        // Our own install echo.
        let event = drift_event(
            KernelRouteEventKind::New,
            RT_TABLE_MAIN,
            Some(v4(32)),
            true,
            KernelRouteType::BlackHole,
        );
        assert!(!kernel_route_drift_wakes(&event, &owned_with(v4(32))));
    }

    #[tokio::test]
    async fn kernel_drift_event_wakes_actor_before_periodic_interval() {
        let prefix = v4(32);
        let (rib_tx, query_count, _events_tx) = rib_with_events(vec![route(
            prefix,
            RouteOrigin::Ebgp,
            vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
        )]);
        let metrics = BgpMetrics::with_registry(Registry::new());
        let (status_tx, _status_rx) = watch::channel(Vec::new());
        let (drift_tx, drift_rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            run_loop(
                BlackholeConfig {
                    enabled: true,
                    allow_broad_prefixes: false,
                },
                rib_tx,
                FakeFib {
                    kernel_events: Some(drift_rx),
                    ..FakeFib::default()
                },
                metrics,
                status_tx,
                task_shutdown,
            )
            .await;
        });

        for _ in 0..20 {
            if query_count.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(query_count.load(Ordering::SeqCst), 1);

        // A burst of marker-row deletes coalesces into one reconcile
        // after the debounce window — no 30 s wait.
        for _ in 0..5 {
            drift_tx
                .send(drift_event(
                    KernelRouteEventKind::Del,
                    RT_TABLE_MAIN,
                    Some(prefix),
                    true,
                    KernelRouteType::BlackHole,
                ))
                .await
                .unwrap();
        }
        tokio::time::sleep(ROUTE_EVENT_DEBOUNCE + Duration::from_millis(50)).await;
        tokio::task::yield_now().await;
        assert_eq!(query_count.load(Ordering::SeqCst), 2);

        // Unrelated main-table churn does not wake the actor.
        drift_tx
            .send(drift_event(
                KernelRouteEventKind::Del,
                RT_TABLE_MAIN,
                Some(prefix),
                false,
                KernelRouteType::Unicast,
            ))
            .await
            .unwrap();
        tokio::time::sleep(ROUTE_EVENT_DEBOUNCE + Duration::from_millis(50)).await;
        tokio::task::yield_now().await;
        assert_eq!(query_count.load(Ordering::SeqCst), 2);

        shutdown.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn reconcile_installs_eligible_route_once() {
        let prefix = v4(32);
        let mut fib = FakeFib::default();
        let metrics = BgpMetrics::with_registry(Registry::new());
        let mut owned = HashMap::new();
        let mut rejected = HashSet::new();

        let statuses = reconcile_for_test(
            vec![route(
                prefix,
                RouteOrigin::Ebgp,
                vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
            )],
            &mut fib,
            &mut owned,
            &mut rejected,
            &metrics,
        )
        .await;

        assert_eq!(fib.install_calls, vec![prefix]);
        assert!(owned.contains_key(&prefix));
        assert_eq!(statuses[0].state, BlackholeState::Installed);
        assert_eq!(statuses[0].reason, "installed");
    }

    #[tokio::test]
    async fn reconcile_failed_remove_stays_visible() {
        let prefix = v4(32);
        let mut fib = FakeFib::default();
        fib.installed.insert(prefix);
        fib.fail_remove.insert(prefix, "busy".to_string());
        let metrics = BgpMetrics::with_registry(Registry::new());
        let mut owned = HashMap::from([(
            prefix,
            OwnedBlackhole {
                peer: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            },
        )]);
        let mut rejected = HashSet::new();

        let statuses =
            reconcile_for_test(Vec::new(), &mut fib, &mut owned, &mut rejected, &metrics).await;

        assert_eq!(fib.remove_calls, vec![prefix]);
        assert!(owned.contains_key(&prefix));
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, BlackholeState::Failed);
        assert_eq!(statuses[0].reason, "remove_failed");
    }

    #[tokio::test]
    async fn reconcile_rejection_counter_counts_transitions_only() {
        let prefix = v4(24);
        let routes = vec![route(
            prefix,
            RouteOrigin::Ebgp,
            vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
        )];
        let mut fib = FakeFib::default();
        let metrics = BgpMetrics::with_registry(Registry::new());
        let mut owned = HashMap::new();
        let mut rejected = HashSet::new();

        let _ = reconcile_for_test(
            routes.clone(),
            &mut fib,
            &mut owned,
            &mut rejected,
            &metrics,
        )
        .await;
        let _ = reconcile_for_test(routes, &mut fib, &mut owned, &mut rejected, &metrics).await;

        let rejected_total = counter_value(
            &metrics,
            "bgp_blackhole_discard_rejected_total",
            "reason",
            "broad_prefix",
        );
        assert!(
            (rejected_total - 1.0).abs() < f64::EPSILON,
            "expected one broad_prefix rejection transition, got {rejected_total}"
        );
    }

    #[tokio::test]
    async fn reconcile_preserves_foreign_existing_route() {
        let prefix = v4(32);
        let mut fib = FakeFib::default();
        fib.foreign.insert(prefix);
        let metrics = BgpMetrics::with_registry(Registry::new());
        let mut owned = HashMap::new();
        let mut rejected = HashSet::new();

        let statuses = reconcile_for_test(
            vec![route(
                prefix,
                RouteOrigin::Ebgp,
                vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
            )],
            &mut fib,
            &mut owned,
            &mut rejected,
            &metrics,
        )
        .await;

        assert!(fib.install_calls.is_empty());
        assert!(owned.is_empty());
        assert_eq!(statuses[0].state, BlackholeState::Failed);
        assert_eq!(statuses[0].reason, "foreign_route_exists");
    }

    #[tokio::test]
    async fn reconcile_marks_owned_route_replaced_by_foreign_as_failed() {
        let prefix = v4(32);
        let mut fib = FakeFib::default();
        fib.foreign.insert(prefix);
        let metrics = BgpMetrics::with_registry(Registry::new());
        let mut owned = HashMap::from([(
            prefix,
            OwnedBlackhole {
                peer: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            },
        )]);
        let mut rejected = HashSet::new();

        let statuses = reconcile_for_test(
            vec![route(
                prefix,
                RouteOrigin::Ebgp,
                vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
            )],
            &mut fib,
            &mut owned,
            &mut rejected,
            &metrics,
        )
        .await;

        assert!(owned.is_empty());
        assert!(fib.install_calls.is_empty());
        assert_eq!(statuses[0].state, BlackholeState::Failed);
        assert_eq!(statuses[0].reason, "foreign_route_exists");
    }

    #[tokio::test]
    async fn reconcile_reinstalls_owned_route_missing_from_kernel() {
        let prefix = v4(32);
        let mut fib = FakeFib::default();
        let metrics = BgpMetrics::with_registry(Registry::new());
        let mut owned = HashMap::from([(
            prefix,
            OwnedBlackhole {
                peer: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            },
        )]);
        let mut rejected = HashSet::new();

        let statuses = reconcile_for_test(
            vec![route(
                prefix,
                RouteOrigin::Ebgp,
                vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
            )],
            &mut fib,
            &mut owned,
            &mut rejected,
            &metrics,
        )
        .await;

        assert_eq!(fib.install_calls, vec![prefix]);
        assert!(owned.contains_key(&prefix));
        assert_eq!(statuses[0].state, BlackholeState::Installed);
        assert_eq!(statuses[0].reason, "installed");
    }

    fn plain_counter_value(metrics: &BgpMetrics, name: &str) -> f64 {
        metrics
            .registry()
            .gather()
            .into_iter()
            .find(|family| family.name() == name)
            .and_then(|family| {
                family.get_metric().first().map(|metric| {
                    metric
                        .get_counter()
                        .as_ref()
                        .map_or(0.0, prometheus::proto::Counter::value)
                })
            })
            .unwrap_or(0.0)
    }

    /// ADR-0079: a crash-leftover marker row for a still-desired prefix
    /// is claimed instead of blocking re-installation as foreign.
    #[tokio::test]
    async fn adoption_claims_marker_row_for_desired_prefix() {
        let prefix = v4(32);
        let mut fib = FakeFib::default();
        fib.installed.insert(prefix); // crash leftover with our marker
        let metrics = BgpMetrics::with_registry(Registry::new());
        let mut owned = HashMap::new();
        let mut rejected = HashSet::new();

        let statuses = reconcile_for_test(
            vec![route(
                prefix,
                RouteOrigin::Ebgp,
                vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
            )],
            &mut fib,
            &mut owned,
            &mut rejected,
            &metrics,
        )
        .await;

        assert!(
            fib.install_calls.is_empty(),
            "claiming must not re-write the identical kernel row"
        );
        assert!(owned.contains_key(&prefix));
        assert_eq!(statuses[0].state, BlackholeState::Installed);
        assert_eq!(statuses[0].reason, "adopted");
        let adopted = plain_counter_value(&metrics, "bgp_blackhole_discard_adopted_total");
        assert!((adopted - 1.0).abs() < f64::EPSILON, "got {adopted}");
    }

    /// ADR-0079: a claimed adopted row is owned like any other — a later
    /// BGP withdraw removes it from the kernel.
    #[tokio::test]
    async fn claimed_adopted_route_is_removed_when_withdrawn() {
        let prefix = v4(32);
        let mut fib = FakeFib::default();
        fib.installed.insert(prefix);
        let metrics = BgpMetrics::with_registry(Registry::new());
        let mut owned = HashMap::new();
        let mut rejected = HashSet::new();
        let mut adoption = deferred_adoption();

        let _ = reconcile_for_test_with_adoption(
            vec![route(
                prefix,
                RouteOrigin::Ebgp,
                vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
            )],
            &mut fib,
            &mut owned,
            &mut rejected,
            &metrics,
            &mut adoption,
        )
        .await;
        assert!(owned.contains_key(&prefix));

        let statuses = reconcile_for_test_with_adoption(
            Vec::new(),
            &mut fib,
            &mut owned,
            &mut rejected,
            &metrics,
            &mut adoption,
        )
        .await;

        assert_eq!(fib.remove_calls, vec![prefix]);
        assert!(owned.is_empty());
        assert!(!fib.installed.contains(&prefix));
        assert!(statuses.is_empty());
    }

    /// ADR-0079 rule 3: an adopted-but-unclaimed row keeps discarding
    /// (and stays visible on the status surface) until the deferral
    /// deadline passes.
    #[tokio::test]
    async fn adopted_unclaimed_row_is_kept_and_visible_before_deadline() {
        let prefix = v4(32);
        let mut fib = FakeFib::default();
        fib.installed.insert(prefix);
        let metrics = BgpMetrics::with_registry(Registry::new());
        let mut owned = HashMap::new();
        let mut rejected = HashSet::new();
        let mut adoption = deferred_adoption();

        let statuses = reconcile_for_test_with_adoption(
            Vec::new(),
            &mut fib,
            &mut owned,
            &mut rejected,
            &metrics,
            &mut adoption,
        )
        .await;

        assert!(fib.remove_calls.is_empty(), "must not reap before deadline");
        assert!(fib.installed.contains(&prefix));
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, BlackholeState::Installed);
        assert_eq!(statuses[0].reason, "adopted_pending_reap");
        assert!(adoption.pending.contains(&prefix));
    }

    /// ADR-0079 rule 3: once the deferral passes, an adopted row no BGP
    /// route re-claimed is reaped from the kernel.
    #[tokio::test]
    async fn adopted_unclaimed_row_is_reaped_after_deadline() {
        let prefix = v4(32);
        let mut fib = FakeFib::default();
        fib.installed.insert(prefix);
        let metrics = BgpMetrics::with_registry(Registry::new());
        let mut owned = HashMap::new();
        let mut rejected = HashSet::new();
        let mut adoption = reapable_adoption();

        let statuses = reconcile_for_test_with_adoption(
            Vec::new(),
            &mut fib,
            &mut owned,
            &mut rejected,
            &metrics,
            &mut adoption,
        )
        .await;

        assert_eq!(fib.remove_calls, vec![prefix]);
        assert!(!fib.installed.contains(&prefix));
        assert!(adoption.pending.is_empty());
        assert!(statuses.is_empty());
        let reaped = plain_counter_value(&metrics, "bgp_blackhole_discard_reaped_total");
        assert!((reaped - 1.0).abs() < f64::EPSILON, "got {reaped}");
    }

    /// If a crash-leftover row matches a route that is currently
    /// rejected by the BLACKHOLE preflight, publish one status row for
    /// the prefix. While the marker exists, the kernel reality wins:
    /// traffic is still being discarded until the deferral reaps it.
    #[tokio::test]
    async fn adopted_pending_replaces_rejected_status_for_same_prefix() {
        let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24));
        let mut fib = FakeFib::default();
        fib.installed.insert(prefix);
        let metrics = BgpMetrics::with_registry(Registry::new());
        let mut owned = HashMap::new();
        let mut rejected = HashSet::new();
        let mut adoption = deferred_adoption();

        let statuses = reconcile_for_test_with_adoption(
            vec![route(
                prefix,
                RouteOrigin::Ebgp,
                vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
            )],
            &mut fib,
            &mut owned,
            &mut rejected,
            &metrics,
            &mut adoption,
        )
        .await;

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].prefix, prefix);
        assert_eq!(statuses[0].state, BlackholeState::Installed);
        assert_eq!(statuses[0].reason, "adopted_pending_reap");
        assert!(adoption.pending.contains(&prefix));
        let rejected_total = counter_value(
            &metrics,
            "bgp_blackhole_discard_rejected_total",
            "reason",
            "broad_prefix",
        );
        assert!(
            (rejected_total - 1.0).abs() < f64::EPSILON,
            "got {rejected_total}"
        );
    }

    /// After the deferral expires, the same rejected route keeps its
    /// normal rejected status if the adopted marker is reaped cleanly.
    #[tokio::test]
    async fn reaped_rejected_prefix_keeps_rejected_status() {
        let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24));
        let mut fib = FakeFib::default();
        fib.installed.insert(prefix);
        let metrics = BgpMetrics::with_registry(Registry::new());
        let mut owned = HashMap::new();
        let mut rejected = HashSet::new();
        let mut adoption = reapable_adoption();

        let statuses = reconcile_for_test_with_adoption(
            vec![route(
                prefix,
                RouteOrigin::Ebgp,
                vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
            )],
            &mut fib,
            &mut owned,
            &mut rejected,
            &metrics,
            &mut adoption,
        )
        .await;

        assert_eq!(fib.remove_calls, vec![prefix]);
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].prefix, prefix);
        assert_eq!(statuses[0].state, BlackholeState::Rejected);
        assert_eq!(statuses[0].reason, "broad_prefix");
        assert!(adoption.pending.is_empty());
    }

    /// If an adopted row disappears before the reap deadline expires,
    /// the pending adoption record is stale and must be cleared without
    /// issuing a delete for a row the dump no longer shows.
    #[tokio::test]
    async fn adopted_pending_row_disappearing_clears_without_reap() {
        let prefix = v4(32);
        let mut fib = FakeFib::default();
        fib.installed.insert(prefix);
        let metrics = BgpMetrics::with_registry(Registry::new());
        let mut owned = HashMap::new();
        let mut rejected = HashSet::new();
        let mut adoption = deferred_adoption();

        let statuses = reconcile_for_test_with_adoption(
            Vec::new(),
            &mut fib,
            &mut owned,
            &mut rejected,
            &metrics,
            &mut adoption,
        )
        .await;
        assert_eq!(statuses[0].reason, "adopted_pending_reap");
        assert!(adoption.pending.contains(&prefix));

        fib.installed.remove(&prefix);
        adoption.reap_after = tokio::time::Instant::now();
        let statuses = reconcile_for_test_with_adoption(
            Vec::new(),
            &mut fib,
            &mut owned,
            &mut rejected,
            &metrics,
            &mut adoption,
        )
        .await;

        assert!(fib.remove_calls.is_empty());
        assert!(adoption.pending.is_empty());
        assert!(statuses.is_empty());
        let reaped = plain_counter_value(&metrics, "bgp_blackhole_discard_reaped_total");
        assert!(reaped.abs() < f64::EPSILON, "got {reaped}");
    }

    /// If a foreign row replaces an adopted marker before the reap
    /// deadline, foreign ownership dominates and the daemon must forget
    /// the pending adoption instead of deleting the replacement.
    #[tokio::test]
    async fn adopted_pending_row_replaced_by_foreign_clears_without_reap() {
        let prefix = v4(32);
        let mut fib = FakeFib::default();
        fib.installed.insert(prefix);
        let metrics = BgpMetrics::with_registry(Registry::new());
        let mut owned = HashMap::new();
        let mut rejected = HashSet::new();
        let mut adoption = deferred_adoption();

        let statuses = reconcile_for_test_with_adoption(
            Vec::new(),
            &mut fib,
            &mut owned,
            &mut rejected,
            &metrics,
            &mut adoption,
        )
        .await;
        assert_eq!(statuses[0].reason, "adopted_pending_reap");
        assert!(adoption.pending.contains(&prefix));

        fib.installed.remove(&prefix);
        fib.foreign.insert(prefix);
        adoption.reap_after = tokio::time::Instant::now();
        let statuses = reconcile_for_test_with_adoption(
            Vec::new(),
            &mut fib,
            &mut owned,
            &mut rejected,
            &metrics,
            &mut adoption,
        )
        .await;

        assert!(fib.remove_calls.is_empty());
        assert!(adoption.pending.is_empty());
        assert!(statuses.is_empty());
        let reaped = plain_counter_value(&metrics, "bgp_blackhole_discard_reaped_total");
        assert!(reaped.abs() < f64::EPSILON, "got {reaped}");
    }

    /// Foreign (non-marker) kernel rows are never adopted, never reaped,
    /// and still block installs for their prefix.
    #[tokio::test]
    async fn foreign_rows_are_never_adopted_or_reaped() {
        let foreign_only = v4(32);
        let mut fib = FakeFib::default();
        fib.foreign.insert(foreign_only);
        let metrics = BgpMetrics::with_registry(Registry::new());
        let mut owned = HashMap::new();
        let mut rejected = HashSet::new();
        let mut adoption = reapable_adoption();

        let _ = reconcile_for_test_with_adoption(
            Vec::new(),
            &mut fib,
            &mut owned,
            &mut rejected,
            &metrics,
            &mut adoption,
        )
        .await;

        assert!(fib.remove_calls.is_empty());
        assert!(adoption.pending.is_empty());
        let adopted = plain_counter_value(&metrics, "bgp_blackhole_discard_adopted_total");
        assert!(adopted.abs() < f64::EPSILON, "got {adopted}");
    }

    /// A prefix with both a marker row and a foreign row is unsafe to
    /// claim — foreign presence dominates.
    #[tokio::test]
    async fn marker_row_shadowed_by_foreign_row_is_not_claimed() {
        let prefix = v4(32);
        let mut fib = FakeFib::default();
        fib.installed.insert(prefix);
        fib.foreign.insert(prefix);
        let metrics = BgpMetrics::with_registry(Registry::new());
        let mut owned = HashMap::new();
        let mut rejected = HashSet::new();

        let statuses = reconcile_for_test(
            vec![route(
                prefix,
                RouteOrigin::Ebgp,
                vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
            )],
            &mut fib,
            &mut owned,
            &mut rejected,
            &metrics,
        )
        .await;

        assert!(owned.is_empty());
        assert!(fib.install_calls.is_empty());
        assert_eq!(statuses[0].state, BlackholeState::Failed);
        assert_eq!(statuses[0].reason, "foreign_route_exists");
    }

    /// The batching contract: one reconcile pass performs exactly one
    /// kernel dump regardless of candidate count.
    #[tokio::test]
    async fn reconcile_performs_one_dump_per_pass() {
        let mut fib = FakeFib::default();
        fib.installed.insert(Prefix::V4(Ipv4Prefix::new(
            Ipv4Addr::new(203, 0, 113, 9),
            32,
        )));
        let metrics = BgpMetrics::with_registry(Registry::new());
        let mut owned = HashMap::new();
        let mut rejected = HashSet::new();

        let routes = vec![
            route(
                v4(32),
                RouteOrigin::Ebgp,
                vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
            ),
            route(
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 7), 32)),
                RouteOrigin::Ebgp,
                vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
            ),
            route(
                v6(128),
                RouteOrigin::Ebgp,
                vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
            ),
        ];
        let _ = reconcile_for_test(routes, &mut fib, &mut owned, &mut rejected, &metrics).await;

        assert_eq!(fib.dump_calls, 1);
        assert_eq!(owned.len(), 3);
    }

    /// A failed kernel dump degrades the pass: stale owned routes are
    /// still removed, but installs/claims/reaps are skipped and every
    /// installable candidate is surfaced as failed.
    #[tokio::test]
    async fn dump_failure_degrades_pass_without_unowning() {
        let desired = v4(32);
        let stale = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 9), 32));
        let mut fib = FakeFib {
            fail_dump: Some("netlink down".to_string()),
            ..Default::default()
        };
        fib.installed.insert(desired);
        fib.installed.insert(stale);
        let metrics = BgpMetrics::with_registry(Registry::new());
        let peer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let mut owned = HashMap::from([
            (desired, OwnedBlackhole { peer }),
            (stale, OwnedBlackhole { peer }),
        ]);
        let mut rejected = HashSet::new();
        let mut adoption = deferred_adoption();

        let statuses = reconcile_for_test_with_adoption(
            vec![route(
                desired,
                RouteOrigin::Ebgp,
                vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
            )],
            &mut fib,
            &mut owned,
            &mut rejected,
            &metrics,
            &mut adoption,
        )
        .await;

        assert_eq!(fib.remove_calls, vec![stale], "stale removal still runs");
        assert!(owned.contains_key(&desired), "owned state must not churn");
        assert!(fib.install_calls.is_empty());
        assert!(!adoption.swept, "sweep must wait for a successful dump");
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, BlackholeState::Failed);
        assert_eq!(statuses[0].reason, "dump_failed");
        let failures = counter_value(
            &metrics,
            "bgp_blackhole_discard_kernel_failures_total",
            "action",
            "dump",
        );
        assert!((failures - 1.0).abs() < f64::EPSILON, "got {failures}");
    }

    /// ADR-0079 rule 4: a second sweep over the same kernel state (the
    /// double-crash case) adopts the same rows again without harm.
    #[tokio::test]
    async fn repeated_adoption_sweep_is_idempotent() {
        let prefix = v4(32);
        let mut fib = FakeFib::default();
        fib.installed.insert(prefix);
        let metrics = BgpMetrics::with_registry(Registry::new());
        let mut owned = HashMap::new();
        let mut rejected = HashSet::new();

        // Two fresh AdoptionSweep instances over identical kernel state
        // model two consecutive crashed processes.
        for _ in 0..2 {
            let mut adoption = deferred_adoption();
            let statuses = reconcile_for_test_with_adoption(
                Vec::new(),
                &mut fib,
                &mut owned,
                &mut rejected,
                &metrics,
                &mut adoption,
            )
            .await;
            assert!(fib.installed.contains(&prefix));
            assert_eq!(statuses[0].reason, "adopted_pending_reap");
        }
        assert!(fib.remove_calls.is_empty());
    }
}
