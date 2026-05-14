//! RFC 7999 BLACKHOLE kernel-discard reconciler.
//!
//! This module is deliberately daemon-owned rather than folded into
//! `crates/evpn-linux`: RTBH is a unicast/RIB feature, not part of the
//! EVPN dataplane boundary. The actor subscribes to unicast best-route
//! events, periodically re-queries the Loc-RIB as a level-triggered
//! backstop, and owns only the kernel blackhole routes it successfully
//! installed during this daemon lifetime.

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

const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
const ROUTE_EVENT_DEBOUNCE: Duration = Duration::from_millis(200);
const RIB_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KernelRoutePresence {
    Absent,
    Owned,
    Foreign,
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
        match LinuxBlackholeFib::connect() {
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
    let mut owned = HashMap::<Prefix, OwnedBlackhole>::new();
    let mut rejected = HashSet::<RejectedBlackhole>::new();
    let mut interval = tokio::time::interval(RECONCILE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    let mut event_debounce = tokio::time::interval(ROUTE_EVENT_DEBOUNCE);
    event_debounce.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    event_debounce.tick().await;
    let mut route_event_dirty = false;

    let mut route_events = subscribe_route_events(&rib_tx).await;
    reconcile_once(
        config,
        &rib_tx,
        &mut fib,
        &metrics,
        &status_tx,
        &mut owned,
        &mut rejected,
    )
    .await;

    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                drain_owned(&mut fib, &metrics, &mut owned).await;
                status_tx.send_replace(Vec::new());
                return;
            }
            _ = interval.tick() => {
                reconcile_once(
                    config,
                    &rib_tx,
                    &mut fib,
                    &metrics,
                    &status_tx,
                    &mut owned,
                    &mut rejected,
                ).await;
            }
            _ = event_debounce.tick(), if route_event_dirty => {
                route_event_dirty = false;
                reconcile_once(
                    config,
                    &rib_tx,
                    &mut fib,
                    &metrics,
                    &status_tx,
                    &mut owned,
                    &mut rejected,
                ).await;
            }
            maybe_event = recv_route_event(&mut route_events) => {
                match maybe_event {
                    Some(()) => {
                        route_event_dirty = true;
                    }
                    None => {
                        route_events = subscribe_route_events(&rib_tx).await;
                    }
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
    reason = "single level-triggered reconcile pass keeps owned-status publication, install preflight, and counter transition accounting in one auditable order"
)]
async fn reconcile_once<F>(
    config: BlackholeConfig,
    rib_tx: &mpsc::Sender<RibUpdate>,
    fib: &mut F,
    metrics: &BgpMetrics,
    status_tx: &watch::Sender<Vec<BlackholeStatus>>,
    owned: &mut HashMap<Prefix, OwnedBlackhole>,
    rejected: &mut HashSet<RejectedBlackhole>,
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

    let mut statuses = Vec::with_capacity(derived.len() + owned.len());
    let mut current_rejected = HashSet::new();

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

        if owned.contains_key(&candidate.prefix) {
            match fib.lookup(candidate.prefix).await {
                Ok(KernelRoutePresence::Owned) => {
                    statuses.push(BlackholeStatus {
                        prefix: candidate.prefix,
                        peer: candidate.route.peer,
                        state: BlackholeState::Installed,
                        reason: "owned".to_string(),
                    });
                    continue;
                }
                Ok(KernelRoutePresence::Absent) => {
                    owned.remove(&candidate.prefix);
                    warn!(
                        prefix = %candidate.prefix,
                        peer = %candidate.route.peer,
                        "daemon-owned BLACKHOLE discard route disappeared from kernel; reinstalling"
                    );
                }
                Ok(KernelRoutePresence::Foreign) => {
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
                Err(e) => {
                    metrics.record_blackhole_discard_kernel_failure("lookup");
                    warn!(
                        prefix = %candidate.prefix,
                        peer = %candidate.route.peer,
                        error = %e,
                        "failed to verify BLACKHOLE discard route liveness"
                    );
                    statuses.push(BlackholeStatus {
                        prefix: candidate.prefix,
                        peer: candidate.route.peer,
                        state: BlackholeState::Failed,
                        reason: "lookup_failed".to_string(),
                    });
                    continue;
                }
            }
        }

        match fib.lookup(candidate.prefix).await {
            Ok(KernelRoutePresence::Absent) => {}
            Ok(KernelRoutePresence::Owned | KernelRoutePresence::Foreign) => {
                statuses.push(BlackholeStatus {
                    prefix: candidate.prefix,
                    peer: candidate.route.peer,
                    state: BlackholeState::Failed,
                    reason: "foreign_route_exists".to_string(),
                });
                continue;
            }
            Err(e) => {
                metrics.record_blackhole_discard_kernel_failure("lookup");
                warn!(
                    prefix = %candidate.prefix,
                    peer = %candidate.route.peer,
                    error = %e,
                    "failed to preflight BLACKHOLE discard route install"
                );
                statuses.push(BlackholeStatus {
                    prefix: candidate.prefix,
                    peer: candidate.route.peer,
                    state: BlackholeState::Failed,
                    reason: "lookup_failed".to_string(),
                });
                continue;
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
    fn lookup(
        &mut self,
        prefix: Prefix,
    ) -> Pin<Box<dyn Future<Output = Result<KernelRoutePresence, String>> + Send + '_>>;
    fn install(
        &mut self,
        prefix: Prefix,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>>;
    fn remove(
        &mut self,
        prefix: Prefix,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>>;
}

#[cfg(target_os = "linux")]
struct LinuxBlackholeFib {
    handle: rtnetlink::Handle,
}

#[cfg(target_os = "linux")]
impl LinuxBlackholeFib {
    fn connect() -> Result<Self, String> {
        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(|e| format!("open NETLINK_ROUTE: {e}"))?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }
}

#[cfg(target_os = "linux")]
impl BlackholeFib for LinuxBlackholeFib {
    fn lookup(
        &mut self,
        prefix: Prefix,
    ) -> Pin<Box<dyn Future<Output = Result<KernelRoutePresence, String>> + Send + '_>> {
        Box::pin(async move { exact_route_presence(&self.handle, prefix).await })
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
}

#[cfg(target_os = "linux")]
async fn exact_route_presence(
    handle: &rtnetlink::Handle,
    prefix: Prefix,
) -> Result<KernelRoutePresence, String> {
    use futures::TryStreamExt;
    use rtnetlink::RouteMessageBuilder;

    let query = match prefix {
        Prefix::V4(_) => RouteMessageBuilder::<std::net::Ipv4Addr>::new().build(),
        Prefix::V6(_) => RouteMessageBuilder::<std::net::Ipv6Addr>::new().build(),
    };
    let mut stream = handle.route().get(query).execute();
    let mut found_owned = false;
    while let Some(route) = stream
        .try_next()
        .await
        .map_err(|e| format!("kernel route lookup: {e}"))?
    {
        if route_matches_prefix(&route, prefix) {
            if route_is_owned_blackhole(&route) {
                found_owned = true;
            } else {
                return Ok(KernelRoutePresence::Foreign);
            }
        }
    }
    Ok(if found_owned {
        KernelRoutePresence::Owned
    } else {
        KernelRoutePresence::Absent
    })
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

#[cfg(target_os = "linux")]
fn route_matches_prefix(msg: &netlink_packet_route::route::RouteMessage, prefix: Prefix) -> bool {
    use netlink_packet_route::AddressFamily;
    use netlink_packet_route::route::{RouteAddress, RouteAttribute};

    const RT_TABLE_MAIN: u32 = 254;

    let table = msg
        .attributes
        .iter()
        .find_map(|attr| match attr {
            RouteAttribute::Table(id) => Some(*id),
            _ => None,
        })
        .unwrap_or(u32::from(msg.header.table));
    if table != RT_TABLE_MAIN || msg.header.destination_prefix_length != prefix.prefix_len() {
        return false;
    }

    match prefix {
        Prefix::V4(prefix) => {
            if msg.header.address_family != AddressFamily::Inet {
                return false;
            }
            let has_destination = msg.attributes.iter().any(|attr| {
                matches!(
                    attr,
                    RouteAttribute::Destination(RouteAddress::Inet(addr)) if *addr == prefix.addr
                )
            });
            has_destination
                || (prefix.len == 0
                    && prefix.addr.is_unspecified()
                    && msg
                        .attributes
                        .iter()
                        .all(|attr| !matches!(attr, RouteAttribute::Destination(_))))
        }
        Prefix::V6(prefix) => {
            if msg.header.address_family != AddressFamily::Inet6 {
                return false;
            }
            let has_destination = msg.attributes.iter().any(|attr| {
                matches!(
                    attr,
                    RouteAttribute::Destination(RouteAddress::Inet6(addr)) if *addr == prefix.addr
                )
            });
            has_destination
                || (prefix.len == 0
                    && prefix.addr.is_unspecified()
                    && msg
                        .attributes
                        .iter()
                        .all(|attr| !matches!(attr, RouteAttribute::Destination(_))))
        }
    }
}

#[cfg(target_os = "linux")]
fn route_is_owned_blackhole(msg: &netlink_packet_route::route::RouteMessage) -> bool {
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
    use rustbgpd_rib::route::RouteOrigin;
    use rustbgpd_rib::{RouteEvent, RouteEventType};
    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix, Origin};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Instant;

    #[derive(Default)]
    struct FakeFib {
        installed: HashSet<Prefix>,
        foreign: HashSet<Prefix>,
        fail_install: HashMap<Prefix, String>,
        fail_remove: HashMap<Prefix, String>,
        fail_exists: HashMap<Prefix, String>,
        install_calls: Vec<Prefix>,
        remove_calls: Vec<Prefix>,
        exists_calls: Vec<Prefix>,
    }

    impl BlackholeFib for FakeFib {
        fn lookup(
            &mut self,
            prefix: Prefix,
        ) -> Pin<Box<dyn Future<Output = Result<KernelRoutePresence, String>> + Send + '_>>
        {
            self.exists_calls.push(prefix);
            Box::pin(async move {
                if let Some(error) = self.fail_exists.get(&prefix) {
                    return Err(error.clone());
                }
                if self.foreign.contains(&prefix) {
                    Ok(KernelRoutePresence::Foreign)
                } else if self.installed.contains(&prefix) {
                    Ok(KernelRoutePresence::Owned)
                } else {
                    Ok(KernelRoutePresence::Absent)
                }
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

    async fn reconcile_for_test(
        routes: Vec<Route>,
        fib: &mut FakeFib,
        owned: &mut HashMap<Prefix, OwnedBlackhole>,
        rejected: &mut HashSet<RejectedBlackhole>,
        metrics: &BgpMetrics,
    ) -> Vec<BlackholeStatus> {
        let rib_tx = rib_with_routes(routes);
        let (status_tx, status_rx) = watch::channel(Vec::new());
        reconcile_once(
            BlackholeConfig {
                enabled: true,
                allow_broad_prefixes: false,
            },
            &rib_tx,
            fib,
            metrics,
            &status_tx,
            owned,
            rejected,
        )
        .await;
        status_rx.borrow().clone()
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
        }
    }

    fn route_event(prefix: Prefix) -> RouteEvent {
        RouteEvent {
            event_type: RouteEventType::BestChanged,
            prefix,
            peer: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
            previous_peer: None,
            timestamp: "0".to_string(),
            path_id: 0,
        }
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
    fn host_prefix_detection_handles_v4_and_v6() {
        assert!(is_host_prefix(v4(32)));
        assert!(is_host_prefix(v6(128)));
        assert!(!is_host_prefix(v4(31)));
        assert!(!is_host_prefix(v6(127)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn route_match_treats_missing_destination_as_default_prefix_only() {
        let default_v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0));
        let host_v4 = v4(32);
        let mut default_route = build_blackhole_route(default_v4);
        default_route.attributes.clear();

        assert!(route_matches_prefix(&default_route, default_v4));
        assert!(!route_matches_prefix(&default_route, host_v4));

        let default_v6 = Prefix::V6(Ipv6Prefix::new(Ipv6Addr::UNSPECIFIED, 0));
        let mut default_route = build_blackhole_route(default_v6);
        default_route.attributes.clear();

        assert!(route_matches_prefix(&default_route, default_v6));
        assert!(!route_matches_prefix(&default_route, v6(128)));
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
            if query_count.load(Ordering::SeqCst) == 1 {
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
            let _ = events_tx.send(route_event(prefix));
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
}
