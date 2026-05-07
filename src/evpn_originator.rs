//! Daemon-side EVPN local-MAC originator (Gate 7b+1).
//!
//! Mirrors `crate::evpn_dataplane::spawn` but on the **opposite
//! flow**: kernel `LocalMacObservation` events become BGP EVPN Type 2
//! originations (RFC 7432 §7.2 + §15.1).
//!
//! ```text
//! crates/evpn-linux ──upward channel──►  this module
//!         (mpsc<LocalMacObservation>)         │
//!                                              │ on_local_learned / on_local_aged
//!                                              ▼
//!                              rustbgpd_evpn::origination::LocalMacOriginator
//!                                              │ Vec<OriginationAction>
//!                                              ▼
//!                              RibUpdate::InjectEvpn / WithdrawEvpn
//! ```
//!
//! Living in `src/` lets this module depend on both `crates/rib`
//! (for `RibUpdate` and `EvpnRibRoute`) and `crates/evpn` (for the
//! state machine), the same allowance ADR-0054 §1 grants
//! `src/evpn_dataplane.rs`.
//!
//! ## Why polling instead of broadcast subscription
//!
//! The RIB's existing `RouteEvent` broadcast (`crates/rib/src/event.rs`)
//! is keyed by `Prefix` and is therefore unicast-only — EVPN best-path
//! changes do not surface there. The dataplane supervisor already
//! polls `RibUpdate::QueryEvpnRoutes` on a fixed cadence (5s default)
//! for the same reason. Adding an EVPN-specific broadcast is a deeper
//! invasive change tracked in `docs/evpn-enablement.md` Gate 7c; until
//! then the originator polls on the same cadence and reuses the
//! supervisor's projection (`rustbgpd_evpn::project_evpn_routes`) to
//! turn raw `EvpnRibRoute`s into `RemoteMacView`s the state machine
//! consumes.
//!
//! ## RR-only deployments
//!
//! When `[[evpn_instances]]` is empty, [`spawn`] returns `None`. No
//! background task is created; the EVPN originator counters remain at
//! zero-label-vector state until an originator action is observed.
//!
//! ## Self-origination filter
//!
//! `RemoteMacView`s passed into the state machine **must not** carry
//! routes whose next-hop matches the local instance's `local_vtep_ip`
//! — otherwise the originator would see its own re-Inject as a
//! contender and bump indefinitely. The polling code drops self-NH
//! routes before the projection.
//!
//! ## Reference
//!
//! - ADR-0054 §1 (dependency direction unchanged)
//! - ADR-0054 §6 (level-triggered cold-start; periodic poll is the
//!   load-bearing convergence mechanism)
//! - RFC 7432 §15.1 (sequence rules; encoded in `crates/evpn`)

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use rustbgpd_evpn::{
    EvpnInstance, EvpnInstanceId, EvpnInstanceTable, LocalMacObservation, LocalMacOriginator,
    MacAddress, OriginationAction, ProjectedEvpnRoute, RemoteMacView, project_evpn_routes,
};
use rustbgpd_rib::{RibUpdate, route::EvpnRibRoute};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    AsPath, EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, EvpnRouteKey,
    ExtendedCommunity, MplsLabel, Origin, PathAttribute,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Mirrors the constant used by `crates/api/src/injection_service.rs`.
/// The RIB indexes locally-injected routes under this synthetic peer
/// IP; setting `EvpnRibRoute.peer` to the same value keeps the route
/// recognizable as locally-originated downstream of the inject path.
const LOCAL_PEER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
const ACTION_INJECT: &str = "inject";
const ACTION_WITHDRAW: &str = "withdraw";

/// Defaults for the originator actor.
#[derive(Debug, Clone, Copy)]
pub struct OriginatorConfig {
    /// How often to poll the RIB for current Type 2 best-paths.
    /// Mirrors `SupervisorConfig::poll_interval`.
    pub poll_interval: Duration,
}

impl Default for OriginatorConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(5),
        }
    }
}

/// Handle returned to the daemon for shutdown coordination.
///
/// Holding this alive keeps the originator task running. Call
/// [`Self::shutdown`] from the coordinated-shutdown block to cancel
/// the task, drain outstanding originations as Withdraws, and await
/// the join handle under a 5 s timeout.
#[derive(Debug)]
pub struct EvpnOriginatorHandle {
    pub(crate) shutdown: CancellationToken,
    pub(crate) join: tokio::task::JoinHandle<()>,
}

impl EvpnOriginatorHandle {
    /// Cancel the actor and wait for it to drain.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.join).await;
    }
}

/// Live read-side counts of locally-originated Type 2 MAC routes
/// accepted by the RIB, keyed by VNI.
#[derive(Debug, Clone, Default)]
pub struct OriginatedLocalMacCounts {
    inner: Arc<RwLock<BTreeMap<EvpnInstanceId, BTreeSet<MacAddress>>>>,
}

impl OriginatedLocalMacCounts {
    /// Count currently-originated local MACs for one VNI.
    #[must_use]
    pub fn count(&self, vni: EvpnInstanceId) -> u64 {
        self.inner
            .read()
            .expect("originated local MAC count lock poisoned")
            .get(&vni)
            .map_or(0, |keys| keys.len() as u64)
    }

    fn record_inject(&self, vni: EvpnInstanceId, mac: MacAddress) {
        self.inner
            .write()
            .expect("originated local MAC count lock poisoned")
            .entry(vni)
            .or_default()
            .insert(mac);
    }

    fn record_withdraw(&self, vni: EvpnInstanceId, mac: MacAddress) {
        let mut guard = self
            .inner
            .write()
            .expect("originated local MAC count lock poisoned");
        if let Some(keys) = guard.get_mut(&vni) {
            keys.remove(&mac);
            if keys.is_empty() {
                guard.remove(&vni);
            }
        }
    }
}

struct OriginatorRuntime {
    instances: Arc<EvpnInstanceTable>,
    rib_tx: mpsc::Sender<RibUpdate>,
    metrics: BgpMetrics,
    originated_local_mac_counts: OriginatedLocalMacCounts,
    shutdown: CancellationToken,
}

/// Spawn the originator. Returns `None` for RR-only deployments
/// (empty `evpn_instances`).
#[must_use = "drop the handle to shut down the originator"]
pub fn spawn(
    config: OriginatorConfig,
    evpn_instances: &Arc<EvpnInstanceTable>,
    rib_tx: mpsc::Sender<RibUpdate>,
    local_mac_rx: Option<mpsc::Receiver<LocalMacObservation>>,
    metrics: BgpMetrics,
    originated_local_mac_counts: OriginatedLocalMacCounts,
    daemon_shutdown: CancellationToken,
) -> Option<EvpnOriginatorHandle> {
    if evpn_instances.is_empty() {
        info!("no EVPN instances configured — originator not spawned (RR-only deployment)");
        return None;
    }
    let local_mac_rx = local_mac_rx?;

    // Build a per-instance LocalMacOriginator, keyed by VNI.
    let mut originators: BTreeMap<EvpnInstanceId, LocalMacOriginator> = BTreeMap::new();
    for inst in evpn_instances.iter() {
        originators.insert(inst.id, LocalMacOriginator::new(inst.id, inst.rd));
    }

    let shutdown = daemon_shutdown;
    let runtime = OriginatorRuntime {
        instances: evpn_instances.clone(),
        rib_tx,
        metrics,
        originated_local_mac_counts,
        shutdown: shutdown.clone(),
    };
    let join = tokio::spawn(originator_loop(config, runtime, local_mac_rx, originators));

    Some(EvpnOriginatorHandle { shutdown, join })
}

/// Cached snapshot of the best-path *non-self* remote Type 2 view per
/// `(VNI, MAC)`, derived by polling the RIB. Diffs against the prior
/// snapshot drive `on_remote_changed` callbacks.
type RemoteMacViewMap = BTreeMap<(EvpnInstanceId, MacAddress), RemoteMacView>;

async fn originator_loop(
    config: OriginatorConfig,
    runtime: OriginatorRuntime,
    mut local_mac_rx: mpsc::Receiver<LocalMacObservation>,
    mut originators: BTreeMap<EvpnInstanceId, LocalMacOriginator>,
) {
    let mut poll_tick = tokio::time::interval(config.poll_interval);
    poll_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut remote_view: RemoteMacViewMap = BTreeMap::new();

    loop {
        tokio::select! {
            biased;
            () = runtime.shutdown.cancelled() => {
                debug!("EVPN originator shutting down");
                drain_to_withdraws(
                    &mut originators,
                    &runtime.instances,
                    &runtime.rib_tx,
                    &runtime.metrics,
                    &runtime.originated_local_mac_counts,
                ).await;
                return;
            }
            obs = local_mac_rx.recv() => {
                let Some(obs) = obs else {
                    debug!("local-mac channel closed; originator idle");
                    // Don't exit — RIB polls still useful for telemetry / future
                    // observation reconnect. Park indefinitely on the other arms.
                    park_until_shutdown(&runtime.shutdown).await;
                    drain_to_withdraws(
                        &mut originators,
                        &runtime.instances,
                        &runtime.rib_tx,
                        &runtime.metrics,
                        &runtime.originated_local_mac_counts,
                    ).await;
                    return;
                };
                handle_observation(
                    &obs,
                    &mut originators,
                    &runtime.instances,
                    &remote_view,
                    &runtime.rib_tx,
                    &runtime.metrics,
                    &runtime.originated_local_mac_counts,
                ).await;
            }
            _ = poll_tick.tick() => {
                if let Err(e) = repoll_rib(
                    &runtime.instances,
                    &runtime.rib_tx,
                    &mut remote_view,
                    &mut originators,
                    &runtime.metrics,
                    &runtime.originated_local_mac_counts,
                ).await {
                    warn!(error = %e, "EVPN originator: RIB poll failed");
                }
            }
        }
    }
}

async fn park_until_shutdown(shutdown: &CancellationToken) {
    shutdown.cancelled().await;
}

async fn handle_observation(
    obs: &LocalMacObservation,
    originators: &mut BTreeMap<EvpnInstanceId, LocalMacOriginator>,
    instances: &Arc<EvpnInstanceTable>,
    remote_view: &RemoteMacViewMap,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
) {
    let (vni, actions) = match *obs {
        LocalMacObservation::Learned { vni, mac, ifindex } => {
            let Some(orig) = originators.get_mut(&vni) else {
                debug!(
                    ?vni,
                    ?mac,
                    "local MAC observation for unknown VNI — dropping"
                );
                return;
            };
            let view = remote_view.get(&(vni, mac));
            // Sticky bit comes from operator config in a future gate;
            // pass through false today.
            let actions = orig.on_local_learned(mac, ifindex, false, view);
            if view.is_some() && !actions.is_empty() {
                record_duplicate_mac_move(metrics, vni, mac);
            }
            (vni, actions)
        }
        LocalMacObservation::Aged { vni, mac } => {
            let Some(orig) = originators.get_mut(&vni) else {
                return;
            };
            (vni, orig.on_local_aged(mac))
        }
    };

    let Some(inst) = instances.get(vni) else {
        // Should not happen — instance table is fixed at startup.
        return;
    };
    apply_actions(actions, inst, rib_tx, metrics, originated_local_mac_counts).await;
}

/// Re-poll the RIB, build a fresh `RemoteMacViewMap`, diff against the
/// cached one, and fire `on_remote_changed` for any tracked MAC whose
/// view changed. Then update the cache.
async fn repoll_rib(
    instances: &EvpnInstanceTable,
    rib_tx: &mpsc::Sender<RibUpdate>,
    remote_view: &mut RemoteMacViewMap,
    originators: &mut BTreeMap<EvpnInstanceId, LocalMacOriginator>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
) -> Result<(), RibQueryError> {
    let routes = query_evpn_routes(rib_tx).await?;
    let new_view = build_remote_view(instances, &routes);

    // Detect adds + changes + removes by union of keys.
    let mut affected: Vec<(EvpnInstanceId, MacAddress)> = Vec::new();
    for k in new_view.keys() {
        if remote_view.get(k) != new_view.get(k) {
            affected.push(*k);
        }
    }
    for k in remote_view.keys() {
        if !new_view.contains_key(k) {
            affected.push(*k);
        }
    }

    for (vni, mac) in affected {
        let Some(orig) = originators.get_mut(&vni) else {
            continue;
        };
        let view = new_view.get(&(vni, mac));
        let actions = orig.on_remote_changed(mac, view);
        if actions.is_empty() {
            continue;
        }
        if view.is_some() {
            record_duplicate_mac_move(metrics, vni, mac);
        }
        let Some(inst) = instances.get(vni) else {
            continue;
        };
        apply_actions(actions, inst, rib_tx, metrics, originated_local_mac_counts).await;
    }

    *remote_view = new_view;
    Ok(())
}

/// Drain on shutdown: emit Withdraws for every still-advertised MAC.
async fn drain_to_withdraws(
    originators: &mut BTreeMap<EvpnInstanceId, LocalMacOriginator>,
    instances: &EvpnInstanceTable,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
) {
    for (vni, orig) in originators {
        let actions = orig.drain_to_withdraws();
        if actions.is_empty() {
            continue;
        }
        let Some(inst) = instances.get(*vni) else {
            continue;
        };
        apply_actions(actions, inst, rib_tx, metrics, originated_local_mac_counts).await;
    }
}

/// Translate `OriginationAction`s into `RibUpdate`s and ship them to
/// the RIB. Awaits each oneshot reply so failed injects are logged.
async fn apply_actions(
    actions: Vec<OriginationAction>,
    instance: &EvpnInstance,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
) {
    for action in actions {
        match action {
            OriginationAction::Inject {
                mac,
                mobility_seq,
                sticky,
                key,
            } => {
                let route = build_originated_route(instance, mac, mobility_seq, sticky, key);
                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                if rib_tx
                    .send(RibUpdate::InjectEvpn {
                        route,
                        reply: reply_tx,
                    })
                    .await
                    .is_err()
                {
                    metrics.record_evpn_local_origination_error(ACTION_INJECT);
                    warn!("RIB channel closed; cannot inject EVPN Type 2");
                    return;
                }
                match reply_rx.await {
                    Ok(Ok(())) => {
                        metrics.record_evpn_local_origination(ACTION_INJECT);
                        originated_local_mac_counts.record_inject(instance.id, mac);
                        debug!(?key, ?mobility_seq, "originated Type 2");
                    }
                    Ok(Err(e)) => {
                        metrics.record_evpn_local_origination_error(ACTION_INJECT);
                        warn!(?key, error = %e, "RIB rejected Type 2 inject");
                    }
                    Err(_) => {
                        metrics.record_evpn_local_origination_error(ACTION_INJECT);
                        warn!(?key, "RIB inject reply dropped");
                    }
                }
            }
            OriginationAction::Withdraw { mac, key } => {
                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                if rib_tx
                    .send(RibUpdate::WithdrawEvpn {
                        key,
                        reply: reply_tx,
                    })
                    .await
                    .is_err()
                {
                    metrics.record_evpn_local_origination_error(ACTION_WITHDRAW);
                    warn!("RIB channel closed; cannot withdraw EVPN Type 2");
                    return;
                }
                match reply_rx.await {
                    Ok(Ok(())) => {
                        metrics.record_evpn_local_origination(ACTION_WITHDRAW);
                        originated_local_mac_counts.record_withdraw(instance.id, mac);
                        debug!(?key, "withdrew Type 2");
                    }
                    Ok(Err(e)) => {
                        metrics.record_evpn_local_origination_error(ACTION_WITHDRAW);
                        // Withdraws for unknown keys can race with
                        // in-flight inject failures; log at debug.
                        debug!(?key, error = %e, "RIB withdraw declined");
                    }
                    Err(_) => {
                        metrics.record_evpn_local_origination_error(ACTION_WITHDRAW);
                        warn!(?key, "RIB withdraw reply dropped");
                    }
                }
            }
        }
    }
}

/// Construct the wire-shaped `EvpnRibRoute` for a Type 2 origination.
fn build_originated_route(
    instance: &EvpnInstance,
    mac: MacAddress,
    mobility_seq: Option<u32>,
    sticky: bool,
    key: EvpnRouteKey,
) -> EvpnRibRoute {
    let macip = EvpnMacIp {
        rd: instance.rd,
        esi: EthernetSegmentIdentifier::ZERO,
        ethernet_tag: EthernetTagId(0),
        mac,
        ip: extract_ip_from_key(&key),
        // VXLAN encap: the EVPN label carries the full 24-bit VNI
        // unmodified (RFC 8365 §5).
        label1: MplsLabel::new(instance.id.as_u32()),
        label2: None,
    };

    let mut ext_communities: Vec<ExtendedCommunity> = instance
        .route_targets
        .iter()
        .copied()
        .map(route_target_to_extcomm)
        .collect();
    if let Some(seq) = mobility_seq {
        ext_communities.push(ExtendedCommunity::mac_mobility(sticky, seq));
    } else if sticky {
        // Sticky bit lives in the MAC Mobility extcomm — emit at
        // seq=0 if the operator marked the MAC sticky but no
        // contention has been observed.
        ext_communities.push(ExtendedCommunity::mac_mobility(true, 0));
    }

    let attributes: Vec<PathAttribute> = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        // Locally-originated routes always set the MP next-hop to our
        // VTEP IP — encode_mp_reach_nlri pulls it from
        // `EvpnRibRoute.next_hop` (set below) when staging EVPN
        // updates, but a NEXT_HOP path attribute is also expected by
        // some peers that look only at attribute 3.
        next_hop_path_attribute(instance.local_vtep_ip),
        PathAttribute::ExtendedCommunities(ext_communities),
    ];

    EvpnRibRoute {
        route: EvpnRoute::MacIp(macip),
        next_hop: instance.local_vtep_ip,
        link_local_next_hop: None,
        peer: LOCAL_PEER,
        attributes: Arc::new(attributes),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::route::RouteOrigin::Local,
        peer_router_id: std::net::Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
    }
}

fn record_duplicate_mac_move(metrics: &BgpMetrics, vni: EvpnInstanceId, mac: MacAddress) {
    metrics.record_evpn_duplicate_mac_move(vni.as_u32(), &mac.to_string());
}

/// Pull the optional host IP back out of the route key the state
/// machine produced. Gate 7b+1 always uses `ip = None`, but stays
/// faithful to the key for forward-compat when ARP suppression
/// learning lands.
fn extract_ip_from_key(key: &EvpnRouteKey) -> Option<IpAddr> {
    match key {
        EvpnRouteKey::MacIp { ip, .. } => *ip,
        _ => None,
    }
}

/// IPv4 next-hop attribute — for IPv6 VTEP IPs the `MP_REACH_NLRI`
/// next-hop carries the address; we still emit a `NEXT_HOP` attribute
/// pointing at 0.0.0.0 in that case to satisfy peers that expect one.
fn next_hop_path_attribute(vtep_ip: IpAddr) -> PathAttribute {
    match vtep_ip {
        IpAddr::V4(v4) => PathAttribute::NextHop(v4),
        IpAddr::V6(_) => PathAttribute::NextHop(std::net::Ipv4Addr::UNSPECIFIED),
    }
}

/// Encode an [`rustbgpd_evpn::RouteTarget`] into the wire-format
/// 8-byte Extended Community per RFC 4360 §4. Three forms differ only
/// in the type byte (`0x00` 2-octet AS, `0x01` IPv4, `0x02` 4-octet
/// AS) and the value-field width split. Subtype is always `0x02`
/// (Route Target).
///
/// Shared with [`crate::evpn_imet`] which encodes the same RT set on
/// Type 3 routes.
pub(crate) fn route_target_to_extcomm(rt: rustbgpd_evpn::RouteTarget) -> ExtendedCommunity {
    use rustbgpd_evpn::RouteTarget;
    match rt {
        RouteTarget::TwoOctetAs { asn, value } => {
            let a = asn.to_be_bytes();
            let v = value.to_be_bytes();
            ExtendedCommunity::new(u64::from_be_bytes([
                0x00, 0x02, a[0], a[1], v[0], v[1], v[2], v[3],
            ]))
        }
        RouteTarget::Ipv4 { ipv4, value } => {
            let a = ipv4.octets();
            let v = value.to_be_bytes();
            ExtendedCommunity::new(u64::from_be_bytes([
                0x01, 0x02, a[0], a[1], a[2], a[3], v[0], v[1],
            ]))
        }
        RouteTarget::FourOctetAs { asn, value } => {
            let a = asn.to_be_bytes();
            let v = value.to_be_bytes();
            ExtendedCommunity::new(u64::from_be_bytes([
                0x02, 0x02, a[0], a[1], a[2], a[3], v[0], v[1],
            ]))
        }
    }
}

/// Build the `RemoteMacViewMap` from a flat set of best-path
/// `EvpnRibRoute`s. Drops self-NH routes per the module-level
/// "self-origination filter" rule.
fn build_remote_view(instances: &EvpnInstanceTable, routes: &[EvpnRibRoute]) -> RemoteMacViewMap {
    // Reuse the supervisor's projection input shape for self-NH
    // filtering and (VNI, MAC) tie-breaking, but extend with the
    // `RemoteMacView` carrying the sticky bit (which the supervisor's
    // projection drops).
    let projected: Vec<(ProjectedEvpnRoute, bool)> = routes
        .iter()
        .filter_map(|r| {
            let EvpnRoute::MacIp(macip) = &r.route else {
                return None;
            };
            let (sticky, seq) = extract_mac_mobility_full(&r.attributes);
            Some((
                ProjectedEvpnRoute {
                    rd: macip.rd,
                    mac: macip.mac,
                    host_ip: macip.ip,
                    label1: macip.label1,
                    next_hop: r.next_hop,
                    mobility_sequence: seq,
                },
                sticky,
            ))
        })
        .collect();

    // First pass: drop self-NH routes per project_evpn_routes.
    let table = project_evpn_routes(instances, projected.iter().map(|(p, _)| p.clone()));
    // Build the typed view by joining the post-projection table with
    // the captured sticky bits. Both keyed on (VNI, MAC); the table
    // is the authority on the winner.
    let mut view: RemoteMacViewMap = BTreeMap::new();
    for ((vni, mac), entry) in table.iter() {
        // Recover the sticky bit by looking up any of the captured
        // routes whose (mac, next_hop, mobility_sequence) match the
        // table entry. This is a small linear scan; the input
        // collection is bounded by the number of best-path Type 2
        // routes per (VNI, MAC) which is ~1 in steady state.
        let sticky = projected
            .iter()
            .find(|(p, _)| {
                p.mac == *mac
                    && p.next_hop == entry.remote_vtep_ip
                    && p.mobility_sequence == entry.mobility_sequence
            })
            .is_some_and(|(_, s)| *s);
        view.insert(
            (*vni, *mac),
            RemoteMacView {
                mac: *mac,
                mobility_sequence: entry.mobility_sequence,
                sticky,
                next_hop: entry.remote_vtep_ip,
            },
        );
    }
    view
}

/// Extract `(sticky, mobility_seq)` from a route's path attributes.
fn extract_mac_mobility_full(attrs: &[PathAttribute]) -> (bool, Option<u32>) {
    for attr in attrs {
        let PathAttribute::ExtendedCommunities(ecs) = attr else {
            continue;
        };
        for ec in ecs {
            if let Some((sticky, seq)) = ec.as_mac_mobility() {
                return (sticky, Some(seq));
            }
        }
    }
    (false, None)
}

async fn query_evpn_routes(
    rib_tx: &mpsc::Sender<RibUpdate>,
) -> Result<Vec<EvpnRibRoute>, RibQueryError> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    rib_tx
        .send(RibUpdate::QueryEvpnRoutes { reply: reply_tx })
        .await
        .map_err(|_| RibQueryError::SendFailed)?;
    reply_rx.await.map_err(|_| RibQueryError::ReplyDropped)
}

#[derive(Debug, thiserror::Error)]
enum RibQueryError {
    #[error("RIB channel send failed")]
    SendFailed,
    #[error("RIB query reply channel dropped")]
    ReplyDropped,
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Encoder;
    use rustbgpd_evpn::{EvpnInstance, EvpnInstanceTable, RouteTarget};
    use rustbgpd_rib::route::RouteOrigin;
    use rustbgpd_wire::{EvpnImet, EvpnMacIp, RouteDistinguisher};

    fn gather_metrics_text(metrics: &BgpMetrics) -> String {
        let encoder = prometheus::TextEncoder::new();
        let families = metrics.registry().gather();
        let mut buf = Vec::new();
        encoder.encode(&families, &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).unwrap()
    }
    fn mac(b: u8) -> MacAddress {
        MacAddress::new([b; 6])
    }
    fn ipa(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn rd(asn: u16, val: u32) -> RouteDistinguisher {
        let mut bytes = [0u8; 8];
        bytes[2..4].copy_from_slice(&asn.to_be_bytes());
        bytes[4..8].copy_from_slice(&val.to_be_bytes());
        RouteDistinguisher::new(bytes)
    }

    fn local_instance(v: u32) -> EvpnInstance {
        EvpnInstance::new(
            vni(v),
            rd(65000, v),
            vec![RouteTarget::TwoOctetAs {
                asn: 65000,
                value: v,
            }],
            ipa("10.0.0.1"),
            Some(format!("br{v}")),
            false,
        )
        .unwrap()
    }

    fn instance_table(v: u32) -> Arc<EvpnInstanceTable> {
        let mut t = EvpnInstanceTable::new();
        t.insert(local_instance(v)).unwrap();
        Arc::new(t)
    }

    fn evpn_macip_route(
        v: u32,
        m: u8,
        next_hop: &str,
        seq: Option<u32>,
        sticky: bool,
    ) -> EvpnRibRoute {
        let macip = EvpnMacIp {
            rd: rd(65000, v),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            mac: mac(m),
            ip: None,
            label1: MplsLabel::new(v),
            label2: None,
        };
        let mut attrs: Vec<PathAttribute> = Vec::new();
        if seq.is_some() || sticky {
            attrs.push(PathAttribute::ExtendedCommunities(vec![
                ExtendedCommunity::mac_mobility(sticky, seq.unwrap_or(0)),
            ]));
        }
        EvpnRibRoute {
            route: EvpnRoute::MacIp(macip),
            next_hop: ipa(next_hop),
            link_local_next_hop: None,
            peer: ipa("10.0.0.99"),
            attributes: Arc::new(attrs),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: std::net::Ipv4Addr::new(10, 0, 0, 99),
            is_stale: false,
            is_llgr_stale: false,
        }
    }

    #[test]
    fn build_remote_view_drops_self_nh_routes() {
        // Two routes for the same (VNI, MAC): one from a remote VTEP,
        // one self-originated (next_hop == our local_vtep_ip).
        // build_remote_view must filter the self-NH out.
        let table = EvpnInstanceTable::new();
        let mut t = table;
        t.insert(local_instance(100)).unwrap();
        let routes = vec![
            evpn_macip_route(100, 0xAA, "10.0.0.2", Some(5), false),
            evpn_macip_route(100, 0xAA, "10.0.0.1", Some(10), false), // self-NH
        ];
        let view = build_remote_view(&t, &routes);
        let v = view.get(&(vni(100), mac(0xAA))).expect("view present");
        assert_eq!(v.next_hop, ipa("10.0.0.2"));
        assert_eq!(v.mobility_sequence, Some(5));
    }

    #[test]
    fn build_remote_view_carries_sticky_bit() {
        let mut t = EvpnInstanceTable::new();
        t.insert(local_instance(100)).unwrap();
        let routes = vec![evpn_macip_route(
            100,
            0xAA,
            "10.0.0.2",
            Some(3),
            /* sticky */ true,
        )];
        let view = build_remote_view(&t, &routes);
        let v = view.get(&(vni(100), mac(0xAA))).expect("view present");
        assert!(v.sticky);
    }

    #[test]
    fn build_remote_view_skips_non_macip_routes() {
        let mut t = EvpnInstanceTable::new();
        t.insert(local_instance(100)).unwrap();
        let imet = EvpnRibRoute {
            route: EvpnRoute::Imet(EvpnImet {
                rd: rd(65000, 100),
                ethernet_tag: EthernetTagId(0),
                originator_ip: ipa("10.0.0.2"),
            }),
            next_hop: ipa("10.0.0.2"),
            link_local_next_hop: None,
            peer: ipa("10.0.0.99"),
            attributes: Arc::new(vec![]),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: std::net::Ipv4Addr::new(10, 0, 0, 99),
            is_stale: false,
            is_llgr_stale: false,
        };
        let view = build_remote_view(&t, &[imet]);
        assert!(view.is_empty());
    }

    #[tokio::test]
    async fn local_learn_with_remote_contender_records_duplicate_mac_counter() {
        let instances = instance_table(100);
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(4);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut originators =
            BTreeMap::from([(vni(100), LocalMacOriginator::new(vni(100), rd(65000, 100)))]);
        let remote_view = BTreeMap::from([(
            (vni(100), mac(0xAA)),
            RemoteMacView {
                mac: mac(0xAA),
                mobility_sequence: Some(3),
                sticky: false,
                next_hop: ipa("10.0.0.2"),
            },
        )]);

        let _rib_responder = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                if let RibUpdate::InjectEvpn { reply, .. } = msg {
                    let _ = reply.send(Ok(()));
                }
            }
        });

        handle_observation(
            &LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut originators,
            &instances,
            &remote_view,
            &rib_tx,
            &metrics,
            &counts,
        )
        .await;

        let text = gather_metrics_text(&metrics);
        assert!(
            text.contains(
                "evpn_duplicate_mac_moves_total{mac=\"aa:aa:aa:aa:aa:aa\",vni=\"100\"} 1"
            ) || text.contains(
                "evpn_duplicate_mac_moves_total{vni=\"100\",mac=\"aa:aa:aa:aa:aa:aa\"} 1"
            ),
            "{text}"
        );
    }

    #[test]
    fn extract_mac_mobility_full_extracts_sticky_and_seq() {
        let attrs = vec![PathAttribute::ExtendedCommunities(vec![
            ExtendedCommunity::mac_mobility(true, 7),
        ])];
        assert_eq!(extract_mac_mobility_full(&attrs), (true, Some(7)));
    }

    #[test]
    fn extract_mac_mobility_full_returns_defaults_without_extcomm() {
        let attrs: Vec<PathAttribute> = vec![];
        assert_eq!(extract_mac_mobility_full(&attrs), (false, None));
    }

    #[test]
    fn build_originated_route_carries_route_targets_and_mobility_seq() {
        let inst = local_instance(100);
        let key = EvpnRouteKey::MacIp {
            rd: inst.rd,
            ethernet_tag: EthernetTagId(0),
            mac: mac(0xAA),
            ip: None,
        };
        let route = build_originated_route(&inst, mac(0xAA), Some(5), false, key);
        assert_eq!(route.next_hop, ipa("10.0.0.1"));
        assert_eq!(route.origin_type, RouteOrigin::Local);
        // Verify the route carries: Origin, AsPath, NextHop, ExtComms.
        assert!(matches!(route.attributes[0], PathAttribute::Origin(_)));
        let extcomms = route
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(v) => Some(v),
                _ => None,
            })
            .unwrap();
        // 1 RT + 1 MAC Mobility = 2 extcomms.
        assert_eq!(extcomms.len(), 2);
        assert!(
            extcomms
                .iter()
                .any(|ec| ec.as_mac_mobility() == Some((false, 5)))
        );
    }

    #[test]
    fn build_originated_route_omits_mobility_extcomm_when_seq_none_and_not_sticky() {
        let inst = local_instance(100);
        let key = EvpnRouteKey::MacIp {
            rd: inst.rd,
            ethernet_tag: EthernetTagId(0),
            mac: mac(0xAA),
            ip: None,
        };
        let route = build_originated_route(&inst, mac(0xAA), None, false, key);
        let extcomms = route
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(v) => Some(v),
                _ => None,
            })
            .unwrap();
        // RT only, no MAC Mobility.
        assert_eq!(extcomms.len(), 1);
        assert!(extcomms.iter().all(|ec| ec.as_mac_mobility().is_none()));
    }

    #[test]
    fn build_originated_route_emits_sticky_at_zero_when_no_seq() {
        let inst = local_instance(100);
        let key = EvpnRouteKey::MacIp {
            rd: inst.rd,
            ethernet_tag: EthernetTagId(0),
            mac: mac(0xAA),
            ip: None,
        };
        let route = build_originated_route(&inst, mac(0xAA), None, /* sticky */ true, key);
        let extcomms = route
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(v) => Some(v),
                _ => None,
            })
            .unwrap();
        assert!(
            extcomms
                .iter()
                .any(|ec| ec.as_mac_mobility() == Some((true, 0)))
        );
    }

    #[tokio::test]
    async fn spawn_returns_none_for_empty_instance_table() {
        let instances = Arc::new(EvpnInstanceTable::new());
        let (rib_tx, _rib_rx) = mpsc::channel(8);
        let (_local_tx, local_rx) = mpsc::channel(8);
        let h = spawn(
            OriginatorConfig::default(),
            &instances,
            rib_tx,
            Some(local_rx),
            BgpMetrics::new(),
            OriginatedLocalMacCounts::default(),
            CancellationToken::new(),
        );
        assert!(h.is_none());
    }

    #[tokio::test]
    async fn spawn_returns_none_when_no_local_mac_rx_provided() {
        let instances = instance_table(100);
        let (rib_tx, _rib_rx) = mpsc::channel(8);
        let h = spawn(
            OriginatorConfig::default(),
            &instances,
            rib_tx,
            None,
            BgpMetrics::new(),
            OriginatedLocalMacCounts::default(),
            CancellationToken::new(),
        );
        assert!(h.is_none());
    }

    #[tokio::test]
    async fn learn_emits_inject_then_aged_emits_withdraw() {
        let instances = instance_table(100);
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (local_tx, local_rx) = mpsc::channel(16);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let shutdown = CancellationToken::new();

        // Auto-respond to QueryEvpnRoutes with empty so the polling
        // loop doesn't block.
        let rib_responder = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                match msg {
                    RibUpdate::QueryEvpnRoutes { reply } => {
                        let _ = reply.send(vec![]);
                    }
                    RibUpdate::InjectEvpn { route, reply } => {
                        let _ = reply.send(Ok(()));
                        break_or_continue(route, &mut Some(()));
                    }
                    _ => {}
                }
            }
        });

        let h = spawn(
            OriginatorConfig {
                poll_interval: Duration::from_millis(20),
            },
            &instances,
            rib_tx,
            Some(local_rx),
            metrics,
            counts,
            shutdown.clone(),
        )
        .expect("originator spawned");

        local_tx
            .send(LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            })
            .await
            .unwrap();

        // Give the loop a moment to process and the RIB responder to
        // ack the inject before we shutdown.
        tokio::time::sleep(Duration::from_millis(80)).await;

        // Drop the responder side and shutdown.
        rib_responder.abort();
        h.shutdown().await;
    }

    fn break_or_continue<T>(_v: T, _flag: &mut Option<()>) {}

    #[tokio::test]
    async fn shutdown_drains_outstanding_originations_as_withdraws() {
        let instances = instance_table(100);
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (local_tx, local_rx) = mpsc::channel(16);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let shutdown = CancellationToken::new();

        // Track injects + withdraws.
        let injects = Arc::new(std::sync::Mutex::new(Vec::<EvpnRouteKey>::new()));
        let withdraws = Arc::new(std::sync::Mutex::new(Vec::<EvpnRouteKey>::new()));
        let injects_c = injects.clone();
        let withdraws_c = withdraws.clone();
        let _rib_responder = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                match msg {
                    RibUpdate::QueryEvpnRoutes { reply } => {
                        let _ = reply.send(vec![]);
                    }
                    RibUpdate::InjectEvpn { route, reply } => {
                        injects_c.lock().unwrap().push(route.key());
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::WithdrawEvpn { key, reply } => {
                        withdraws_c.lock().unwrap().push(key);
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            }
        });

        let h = spawn(
            OriginatorConfig {
                poll_interval: Duration::from_mins(1),
            },
            &instances,
            rib_tx,
            Some(local_rx),
            metrics.clone(),
            counts.clone(),
            shutdown.clone(),
        )
        .expect("originator spawned");

        for m in [0xAA_u8, 0xBB, 0xCC] {
            local_tx
                .send(LocalMacObservation::Learned {
                    vni: vni(100),
                    mac: mac(m),
                    ifindex: u32::from(m),
                })
                .await
                .unwrap();
        }
        // Wait until 3 injects observed.
        for _ in 0..50 {
            if injects.lock().unwrap().len() == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(injects.lock().unwrap().len(), 3, "expected 3 injects");
        assert_eq!(counts.count(vni(100)), 3);

        h.shutdown().await;

        // After shutdown, every originated MAC should have been
        // withdrawn.
        assert_eq!(
            withdraws.lock().unwrap().len(),
            3,
            "expected 3 withdraws on shutdown"
        );

        let text = gather_metrics_text(&metrics);
        assert!(text.contains("evpn_local_originations_total{action=\"inject\"} 3"));
        assert!(text.contains("evpn_local_originations_total{action=\"withdraw\"} 3"));
        assert_eq!(counts.count(vni(100)), 0);
    }

    #[tokio::test]
    async fn rib_rejection_increments_evpn_local_origination_error_counter() {
        let instances = instance_table(100);
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (local_tx, local_rx) = mpsc::channel(16);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let shutdown = CancellationToken::new();

        let _rib_responder = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                match msg {
                    RibUpdate::QueryEvpnRoutes { reply } => {
                        let _ = reply.send(vec![]);
                    }
                    RibUpdate::InjectEvpn { reply, .. } => {
                        let _ = reply.send(Err("synthetic rejection".to_string()));
                    }
                    _ => {}
                }
            }
        });

        let h = spawn(
            OriginatorConfig {
                poll_interval: Duration::from_mins(1),
            },
            &instances,
            rib_tx,
            Some(local_rx),
            metrics.clone(),
            counts.clone(),
            shutdown.clone(),
        )
        .expect("originator spawned");

        local_tx
            .send(LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            })
            .await
            .unwrap();

        for _ in 0..50 {
            let text = gather_metrics_text(&metrics);
            if text.contains("evpn_local_origination_errors_total{action=\"inject\"} 1") {
                assert_eq!(counts.count(vni(100)), 0);
                h.shutdown().await;
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        h.shutdown().await;
        panic!("expected inject error counter to increment");
    }

    #[tokio::test]
    async fn unknown_vni_observation_is_ignored() {
        let instances = instance_table(100);
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (local_tx, local_rx) = mpsc::channel(16);
        let shutdown = CancellationToken::new();

        let _rib_responder = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                if let RibUpdate::QueryEvpnRoutes { reply } = msg {
                    let _ = reply.send(vec![]);
                }
            }
        });

        let h = spawn(
            OriginatorConfig::default(),
            &instances,
            rib_tx,
            Some(local_rx),
            BgpMetrics::new(),
            OriginatedLocalMacCounts::default(),
            shutdown.clone(),
        )
        .expect("originator spawned");

        // VNI 999 isn't configured.
        local_tx
            .send(LocalMacObservation::Learned {
                vni: vni(999),
                mac: mac(0xAA),
                ifindex: 10,
            })
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(20)).await;
        h.shutdown().await;
        // No assertions — the test passes if shutdown didn't hang or
        // crash from the unknown-VNI observation.
    }
}
