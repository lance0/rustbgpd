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
const RIB_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

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

impl BlackholeState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
        }
    }
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
        if let Err(e) = self.task.await {
            warn!(error = %e, "BLACKHOLE discard task panicked during shutdown");
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
                warn!(error = %e, "BLACKHOLE discard install requested, but netlink setup failed");
                None
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (rib_tx, metrics, status_tx, shutdown);
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
    let mut owned = HashSet::<Prefix>::new();
    let mut interval = tokio::time::interval(RECONCILE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut route_events = subscribe_route_events(&rib_tx).await;
    reconcile_once(config, &rib_tx, &mut fib, &metrics, &status_tx, &mut owned).await;

    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                drain_owned(&mut fib, &metrics, &mut owned).await;
                status_tx.send_replace(Vec::new());
                return;
            }
            _ = interval.tick() => {
                reconcile_once(config, &rib_tx, &mut fib, &metrics, &status_tx, &mut owned).await;
            }
            maybe_event = recv_route_event(&mut route_events) => {
                match maybe_event {
                    Some(()) => {
                        reconcile_once(config, &rib_tx, &mut fib, &metrics, &status_tx, &mut owned).await;
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

async fn reconcile_once<F>(
    config: BlackholeConfig,
    rib_tx: &mpsc::Sender<RibUpdate>,
    fib: &mut F,
    metrics: &BgpMetrics,
    status_tx: &watch::Sender<Vec<BlackholeStatus>>,
    owned: &mut HashSet<Prefix>,
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

    let mut statuses = Vec::with_capacity(derived.len());

    for prefix in owned.clone() {
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
            }
        }
    }

    for candidate in derived {
        if !candidate.installable {
            metrics.record_blackhole_discard_rejected(candidate.reason);
            statuses.push(BlackholeStatus {
                prefix: candidate.prefix,
                peer: candidate.route.peer,
                state: BlackholeState::Rejected,
                reason: candidate.reason.to_string(),
            });
            continue;
        }

        if owned.contains(&candidate.prefix) {
            statuses.push(BlackholeStatus {
                prefix: candidate.prefix,
                peer: candidate.route.peer,
                state: BlackholeState::Installed,
                reason: "owned".to_string(),
            });
            continue;
        }

        match fib.install(candidate.prefix).await {
            Ok(()) => {
                owned.insert(candidate.prefix);
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

    status_tx.send_replace(statuses);
}

async fn drain_owned<F>(fib: &mut F, metrics: &BgpMetrics, owned: &mut HashSet<Prefix>)
where
    F: BlackholeFib,
{
    for prefix in owned.clone() {
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
                    if netlink_errno(&e) == Some(libc::ENOENT) {
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
fn netlink_errno(err: &rtnetlink::Error) -> Option<i32> {
    match err {
        rtnetlink::Error::NetlinkError(msg) => Some(msg.raw_code().unsigned_abs().cast_signed()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbgpd_rib::route::RouteOrigin;
    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix, Origin};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::time::Instant;

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
}
