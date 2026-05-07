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
//! every [`SupervisorConfig::poll_interval`] (default 5 s). This is intentionally
//! simple — adding a broadcast channel of EVPN best-path changes into
//! `crates/rib` is a deeper invasive change that the operator-driven
//! `[[evpn_instances]]` flow can do without. The reconcile actor's
//! 60 s periodic dump backstop and the 100ms→5s op retry already
//! handle kernel drift at finer granularity.
//!
//! When operator demand pushes for sub-second MAC convergence, the
//! follow-up is to add a `tokio::sync::Notify` that the RIB's EVPN
//! best-path apply path pings, and have this supervisor `select!` on
//! the notify in addition to the periodic timer. That landing point
//! is documented in `docs/evpn-enablement.md` Gate 7c.
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

use std::sync::Arc;
use std::time::Duration;

use rustbgpd_evpn::{
    DataplaneIntent, EvpnInstanceTable, LocalMacObservation, ProjectedEvpnRoute, RemoteMacTable,
    project_evpn_routes,
};
use rustbgpd_evpn_linux::{Dataplane, ReconcileActor, ReconcileActorConfig};
use rustbgpd_rib::{RibUpdate, route::EvpnRibRoute};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{EvpnRoute, ExtendedCommunity, PathAttribute};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

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
        Self {
            poll_interval: Duration::from_secs(5),
            actor_config: ReconcileActorConfig::production(),
        }
    }
}

/// Handle returned to the daemon for shutdown coordination.
///
/// Holding this type alive keeps both the supervisor and the
/// reconcile actor running. Call [`Self::shutdown`] from the
/// daemon's coordinated shutdown path to cancel the actor and await
/// its bounded drain — *dropping* the handle does not run async
/// code, so a plain `drop()` would detach the tasks rather than
/// drain. The daemon binary moves the handle into the coordinated-
/// shutdown block in `main.rs` and calls `shutdown().await` there.
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
}

impl EvpnDataplaneHandle {
    /// Cancel the shutdown token, which causes the reconcile actor to
    /// drain owned remote FDB entries and exit. The supervisor
    /// follows once the watch sender is dropped. Awaits both tasks
    /// under a bounded 10 s timeout — longer than the actor's
    /// internal 5 s drain (ADR-0054 §7) but short enough that a
    /// stuck task can't wedge the daemon's exit.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        // Bound the wait — the actor's drain timeout is internal, but
        // a stuck task should not wedge the daemon's shutdown
        // forever.
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let _ = self.supervisor_join.await;
            let _ = self.actor_join.await;
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
pub async fn spawn(
    config: SupervisorConfig,
    evpn_instances: &Arc<EvpnInstanceTable>,
    rib_tx: mpsc::Sender<RibUpdate>,
    metrics: BgpMetrics,
    daemon_shutdown: CancellationToken,
) -> Option<EvpnDataplaneHandle> {
    if evpn_instances.is_empty() {
        info!("no EVPN instances configured — dataplane actor not spawned (RR-only deployment)");
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
                let mut handle = spawn_with_dataplane(
                    config,
                    evpn_instances,
                    rib_tx,
                    daemon_shutdown,
                    dataplane,
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
        let _ = (config, rib_tx, metrics, daemon_shutdown);
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
pub fn spawn_with_dataplane<D>(
    config: SupervisorConfig,
    evpn_instances: &Arc<EvpnInstanceTable>,
    rib_tx: mpsc::Sender<RibUpdate>,
    daemon_shutdown: CancellationToken,
    dataplane: D,
) -> EvpnDataplaneHandle
where
    D: Dataplane + Send + Sync + 'static,
{
    let (intent_tx, intent_rx) = watch::channel(Arc::new(DataplaneIntent::empty()));
    let (report_tx, report_rx) = mpsc::channel(64);

    // Status logger task: drain reports + log failure summaries.
    // Phase 6 extends this to surface status via gRPC; Phase 5b just
    // logs.
    {
        let mut report_rx: mpsc::Receiver<rustbgpd_evpn::DataplaneReport> = report_rx;
        tokio::spawn(async move {
            while let Some(report) = report_rx.recv().await {
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
            }
        });
    }

    let supervisor_shutdown = daemon_shutdown.clone();
    let supervisor_instances = evpn_instances.clone();
    let supervisor_join = tokio::spawn(supervisor_loop(
        config.poll_interval,
        supervisor_instances,
        rib_tx,
        intent_tx,
        supervisor_shutdown,
    ));

    let actor = ReconcileActor::new(
        config.actor_config,
        dataplane,
        intent_rx,
        report_tx,
        daemon_shutdown.clone(),
    );
    let actor_join = tokio::spawn(actor.run());

    EvpnDataplaneHandle {
        shutdown: daemon_shutdown,
        supervisor_join,
        actor_join,
        local_mac_rx: None,
    }
}

/// Periodic supervisor loop: query the RIB, project, publish.
///
/// Generation only advances when the projected `RemoteMacTable`
/// actually differs from the previously-published one. The
/// reconcile actor uses the generation as the trigger to clear its
/// permanent-failure suppression set (so an EPERM on op N stops
/// retrying); incrementing on every poll regardless of content
/// change would defeat that suppression and cause the actor to
/// hammer the kernel every 5 s. The instance table is pinned at
/// startup (ADR-0052), so equality on `RemoteMacTable` alone is
/// sufficient — if the instance set ever becomes mutable here,
/// extend the comparison.
async fn supervisor_loop(
    poll_interval: Duration,
    instances: Arc<EvpnInstanceTable>,
    rib_tx: mpsc::Sender<RibUpdate>,
    intent_tx: watch::Sender<Arc<DataplaneIntent>>,
    shutdown: CancellationToken,
) {
    let mut generation: u64 = 0;
    let mut last_table = RemoteMacTable::new();
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
                let table = match build_remote_mac_table(&rib_tx, &instances).await {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(error = %e, "EVPN dataplane supervisor: RIB query failed");
                        continue;
                    }
                };
                if table == last_table && generation > 0 {
                    // No semantic change since the last publish.
                    // Skipping the `intent_tx.send` here keeps the
                    // reconcile actor's permanent-suppression set
                    // alive across periodic polls, so an EPERM /
                    // EOPNOTSUPP on op N doesn't get retried every
                    // 5 s tick — it stays suppressed until the
                    // operator's RIB really changes.
                    continue;
                }
                generation = generation.saturating_add(1);
                last_table = table.clone();
                let intent = Arc::new(DataplaneIntent {
                    generation,
                    instances: instances.clone(),
                    remote_macs: Arc::new(table),
                });
                if intent_tx.send(intent).is_err() {
                    debug!("intent receiver gone; supervisor exiting");
                    return;
                }
            }
        }
    }
}

/// Query the RIB for current best-path EVPN routes and project Type 2
/// MAC/IP routes through [`project_evpn_routes`]. Other route types
/// (Type 1 EAD, Type 3 IMET, Type 4 ES, Type 5 IP-Prefix) are ignored
/// for Gate 7b — they're carried by the RR but the L2VNI dataplane
/// boundary only programs Type 2 MACs.
async fn build_remote_mac_table(
    rib_tx: &mpsc::Sender<RibUpdate>,
    instances: &EvpnInstanceTable,
) -> Result<RemoteMacTable, RibQueryError> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    rib_tx
        .send(RibUpdate::QueryEvpnRoutes { reply: reply_tx })
        .await
        .map_err(|_| RibQueryError::SendFailed)?;
    let routes = reply_rx.await.map_err(|_| RibQueryError::ReplyDropped)?;

    let projected: Vec<ProjectedEvpnRoute> = routes.iter().filter_map(project_one).collect();
    Ok(project_evpn_routes(instances, projected))
}

/// Translate a single [`EvpnRibRoute`] into the projection input
/// shape, returning `None` for non-Type-2 routes (Gate 7b L2VNI
/// dataplane only programs MAC/IP entries).
fn project_one(route: &EvpnRibRoute) -> Option<ProjectedEvpnRoute> {
    let EvpnRoute::MacIp(macip) = &route.route else {
        return None;
    };
    let mobility_sequence = extract_mac_mobility_sequence(&route.attributes);
    Some(ProjectedEvpnRoute {
        rd: macip.rd,
        mac: macip.mac,
        host_ip: macip.ip,
        label1: macip.label1,
        next_hop: route.next_hop,
        mobility_sequence,
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
    use std::net::IpAddr;

    use rustbgpd_evpn::{
        EvpnInstance, EvpnInstanceId, EvpnInstanceTable, MacAddress, RouteDistinguisher,
        RouteTarget,
    };
    use rustbgpd_evpn_linux::{InMemoryDataplane, InstanceProbe};
    use rustbgpd_rib::route::EvpnRibRoute;
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, ExtendedCommunity,
        MplsLabel, PathAttribute,
    };

    use super::*;

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).unwrap()
    }
    fn ipa(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn local_instance_table(v: u32, bridge: Option<&str>) -> EvpnInstanceTable {
        let mut bytes = [0u8; 8];
        bytes[2..4].copy_from_slice(&65001u16.to_be_bytes());
        bytes[4..8].copy_from_slice(&v.to_be_bytes());
        let inst = EvpnInstance::new(
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
        .unwrap();
        let mut t = EvpnInstanceTable::new();
        t.insert(inst).unwrap();
        t
    }

    fn evpn_macip_route(v: u32, m: u8, dst: &str, seq: Option<u32>) -> EvpnRibRoute {
        let macip = EvpnMacIp {
            rd: RouteDistinguisher::ZERO,
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            mac: MacAddress::new([m; 6]),
            ip: None,
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

    #[test]
    fn project_one_picks_macip_with_mobility_seq() {
        let route = evpn_macip_route(100, 1, "10.0.0.2", Some(7));
        let projected = project_one(&route).unwrap();
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
        assert!(project_one(&imet).is_none());
    }

    #[test]
    fn extract_seq_returns_none_without_extcomm() {
        let attrs: Vec<PathAttribute> = vec![];
        assert_eq!(extract_mac_mobility_sequence(&attrs), None);
    }

    #[tokio::test]
    async fn spawn_returns_none_for_empty_instance_table() {
        let instances = Arc::new(EvpnInstanceTable::new());
        let (rib_tx, _rib_rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let h = spawn(
            SupervisorConfig::default(),
            &instances,
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
        let h = spawn_with_dataplane(cfg, &instances, rib_tx, shutdown.clone(), dp);

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
        let supervisor_shutdown = shutdown.clone();
        let join = tokio::spawn(super::supervisor_loop(
            Duration::from_millis(15),
            instances,
            rib_tx,
            intent_tx,
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
}
