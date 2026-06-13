//! Daemon-side EVPN Type 5 originator (Gate 9 slice 6b).
//!
//! Translates the kernel-route observations emitted by Gate 9 slice 6a
//! (`crates/evpn-linux/src/linux/routes.rs`) into `RibUpdate::InjectEvpn`
//! / `RibUpdate::WithdrawEvpn` calls, gated on each IP-VRF's readiness
//! verdict from the slice-5 status broadcast. Mirrors the architectural
//! shape of `src/evpn_originator.rs` (L2 / Type 2) for the L3 / Type 5
//! case.
//!
//! ```text
//! kernel routes ── DataplaneReport.ip_vrf_routes ──► route_observations_rx
//!                                                              │
//!                                                              ▼
//!    ip_vrf_status_rx + effective IpVrfTable watch ─► reconcile (diff want vs have)
//!                                                              │
//!                                                              ▼
//!                          rustbgpd_evpn::ip_vrf::originate_ip_prefix_route
//!                                                              │ EvpnRibRoute
//!                                                              ▼
//!                                          RibUpdate::InjectEvpn / WithdrawEvpn
//! ```
//!
//! Living in `src/` lets this module depend on both `crates/rib` (for
//! `RibUpdate`) and `crates/evpn` (for the pure origination helper),
//! the same allowance ADR-0054 §1 grants `src/evpn_originator.rs`.
//!
//! ## State machine
//!
//! Pure level-triggered diff. No mobility sequencing, no extra
//! contention resolution (Type 5 best-path is decided by the receiving
//! PE per RFC 9136 §4.4.2; we just publish the local kernel state).
//!
//! Per reconcile pass:
//!
//! 1. Snapshot the current observation set and per-VRF readiness.
//! 2. Compute `want = { (vrf, prefix) | vrf.status = Ready AND prefix
//!    is observed }`.
//! 3. Withdraw every `(vrf, prefix)` in `have - want`.
//! 4. Inject every `(vrf, prefix)` in `want - have`.
//!
//! `Ready` → `NotReady` therefore withdraws everything for that VRF;
//! `NotReady` → `Ready` replays the observation set. No transition flags
//! or explicit replay queue.
//!
//! ## Family mismatch
//!
//! The pure origination helper rejects IPv4 prefixes inside an
//! IPv6-VTEP IP-VRF (and vice versa) with
//! [`OriginationError::FamilyMismatch`]. The originator counts the
//! suppression per VRF and drops the candidate; the observation stays
//! in the snapshot so the operator can still see the route.
//!
//! ## RR-only deployments
//!
//! When `[[evpn_ip_vrfs]]` is empty, [`spawn`] returns `None`. No task
//! is created and the Prometheus gauge stays at zero-label-vector
//! state until an originator action is observed.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use rustbgpd_evpn::ip_vrf::{
    IpVrfStatus, LocalIpRoute, OriginationError, originate_ip_prefix_route, select_overlay_gateway,
};
use rustbgpd_evpn::{
    EvpnIpPrefixValue, IpVrf, IpVrfDataplaneStatus, IpVrfId, IpVrfTable, LocalIpRouteObservation,
    RouteSource,
};
use rustbgpd_rib::RibUpdate;
use rustbgpd_rib::route::{EvpnRibRoute, RouteOrigin};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::EvpnRouteKey;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::evpn_originator::LOCAL_PEER;

/// Stable Prometheus-label form for the
/// `evpn_ip_vrf_origination_suppressed_total{reason=…}` counter.
const SUPPRESS_NOT_READY: &str = "not_ready";
const SUPPRESS_FAMILY_MISMATCH: &str = "family_mismatch";

/// Live read-side count of currently-originated Type 5 routes per
/// IP-VRF. Mirrors `OriginatedLocalMacCounts` for the L3 case so the
/// gRPC `originated_routes_count` field on `IpVrfState` can be read
/// without coordinating with the originator task.
#[derive(Debug, Clone, Default)]
pub struct OriginatedIpVrfRouteCounts {
    inner: Arc<RwLock<BTreeMap<IpVrfId, u64>>>,
}

impl OriginatedIpVrfRouteCounts {
    /// Count routes currently originated for one IP-VRF.
    #[must_use]
    pub fn count(&self, vrf_id: IpVrfId) -> u64 {
        self.inner
            .read()
            .expect("originated ip-vrf route count lock poisoned")
            .get(&vrf_id)
            .copied()
            .unwrap_or(0)
    }

    fn inc(&self, vrf_id: IpVrfId) {
        *self
            .inner
            .write()
            .expect("originated ip-vrf route count lock poisoned")
            .entry(vrf_id)
            .or_insert(0) += 1;
    }

    fn dec(&self, vrf_id: IpVrfId) {
        let mut guard = self
            .inner
            .write()
            .expect("originated ip-vrf route count lock poisoned");
        if let Some(c) = guard.get_mut(&vrf_id) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                guard.remove(&vrf_id);
            }
        }
    }
}

/// Cloneable ADR-0063 runtime control surface for daemon apply
/// wiring. The full handle remains owned by coordinated shutdown.
#[derive(Clone)]
pub(crate) struct EvpnL3OriginatorRuntimeControl {
    ip_vrfs_tx: watch::Sender<Arc<IpVrfTable>>,
}

impl EvpnL3OriginatorRuntimeControl {
    /// Whether the Type 5 originator can still receive runtime model
    /// snapshots.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.ip_vrfs_tx.is_closed()
    }

    /// Replace the effective IP-VRF table the originator reconciles
    /// against. Returns `false` if the actor has already exited.
    #[must_use]
    pub fn replace_ip_vrfs(&self, ip_vrfs: Arc<IpVrfTable>) -> bool {
        if self.ip_vrfs_tx.is_closed() {
            return false;
        }
        self.ip_vrfs_tx.send_replace(ip_vrfs);
        true
    }
}

pub struct EvpnL3OriginatorHandle {
    shutdown: CancellationToken,
    ip_vrfs_tx: watch::Sender<Arc<IpVrfTable>>,
    join: tokio::task::JoinHandle<()>,
}

impl EvpnL3OriginatorHandle {
    /// Cloneable ADR-0063 runtime control surface for daemon apply
    /// wiring. The full handle remains owned by coordinated shutdown.
    #[must_use]
    pub(crate) fn runtime_control(&self) -> EvpnL3OriginatorRuntimeControl {
        EvpnL3OriginatorRuntimeControl {
            ip_vrfs_tx: self.ip_vrfs_tx.clone(),
        }
    }

    /// Replace the effective IP-VRF table the originator reconciles
    /// against. Returns `false` if the actor has already exited.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "ADR-0063 coordinator wiring will call this command; this slice adds the actor command surface first"
        )
    )]
    #[must_use]
    pub fn replace_ip_vrfs(&self, ip_vrfs: Arc<IpVrfTable>) -> bool {
        self.runtime_control().replace_ip_vrfs(ip_vrfs)
    }

    /// Cancel the actor and wait for it to drain (mirrors
    /// [`crate::evpn_originator::EvpnOriginatorHandle::shutdown`]).
    /// Bounded to 5 s so a stuck RIB channel doesn't wedge the daemon
    /// shutdown path.
    pub async fn shutdown(self) {
        let Self {
            shutdown,
            ip_vrfs_tx,
            join,
        } = self;
        shutdown.cancel();
        drop(ip_vrfs_tx);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), join).await;
    }
}

/// Spawn parameters. Bundled into a struct because the parameter list
/// would otherwise trip clippy's too-many-arguments lint and the
/// daemon-side spawn is the only caller.
pub struct SpawnConfig {
    /// Configured IP-VRFs. RR-only deployments pass an empty table,
    /// causing [`spawn`] to return `None`.
    pub ip_vrfs: Arc<IpVrfTable>,
    /// Channel into the RIB for `InjectEvpn` / `WithdrawEvpn`.
    pub rib_tx: mpsc::Sender<RibUpdate>,
    /// Watch channel published by `src/main.rs` mirroring
    /// `DataplaneReport.ip_vrf_routes.observations`.
    pub route_observations_rx: watch::Receiver<Arc<HashMap<IpVrfId, Vec<LocalIpRouteObservation>>>>,
    /// Slice-5 watch channel of per-VRF readiness verdicts. Absent
    /// entries are treated as `NotReady` (the originator never sees
    /// the IP-VRF and so never originates for it).
    pub ip_vrf_status_rx: watch::Receiver<Vec<IpVrfDataplaneStatus>>,
    /// Prometheus metrics handle. Used for the
    /// `evpn_ip_vrf_origination_suppressed_total` counter.
    pub metrics: BgpMetrics,
    /// Shared counter the daemon's gRPC handlers read.
    pub originated_counts: OriginatedIpVrfRouteCounts,
    /// Parent shutdown token. Cancelling triggers a drain: every
    /// currently-originated route is withdrawn before the task exits.
    pub shutdown: CancellationToken,
}

struct EffectiveIpVrfModelWatch {
    rx: watch::Receiver<Arc<IpVrfTable>>,
    _tx_keepalive: watch::Sender<Arc<IpVrfTable>>,
}

/// Spawn the Type 5 originator. Returns `None` when no
/// `[[evpn_ip_vrfs]]` are configured (the originator has nothing to
/// do in that case).
#[must_use = "call `EvpnL3OriginatorHandle::shutdown` to stop the originator — \
              dropping the handle leaves the task running because \
              `CancellationToken` does not auto-cancel on drop"]
pub fn spawn(cfg: SpawnConfig) -> Option<EvpnL3OriginatorHandle> {
    if cfg.ip_vrfs.is_empty() {
        info!(
            "no EVPN IP-VRFs configured — Type 5 originator not spawned (L2-only / RR-only \
             deployment)"
        );
        return None;
    }
    let shutdown = cfg.shutdown.clone();
    let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(cfg.ip_vrfs.clone());
    let model_watch = EffectiveIpVrfModelWatch {
        rx: ip_vrfs_rx,
        _tx_keepalive: ip_vrfs_tx.clone(),
    };
    let join = tokio::spawn(originator_loop(cfg, model_watch));
    Some(EvpnL3OriginatorHandle {
        shutdown,
        ip_vrfs_tx,
        join,
    })
}

/// What the originator recorded for one currently-originated
/// `(IpVrfId, prefix)`. The `key` is the RIB withdraw handle; the
/// `gateway` is the Type 5 Gateway Address we last advertised. The
/// gateway is tracked separately because `EvpnRouteKey::IpPrefix` is
/// `{rd, ethernet_tag, prefix}` and deliberately excludes the
/// gateway (RFC 7432/9136 route identity), so a GW-IP via change
/// keeps the same key — the originator must compare the gateway to
/// notice it and re-originate in place (ADR-0087 decision 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OriginatedEntry {
    key: EvpnRouteKey,
    gateway: std::net::IpAddr,
}

async fn originator_loop(mut cfg: SpawnConfig, mut ip_vrf_model: EffectiveIpVrfModelWatch) {
    // (IpVrfId, prefix) -> the route we injected (key + gateway), so a
    // matching withdraw uses the same key and a via change is
    // detectable even though it leaves the key unchanged.
    let mut originated: BTreeMap<(IpVrfId, EvpnIpPrefixValue), OriginatedEntry> = BTreeMap::new();
    let mut ip_vrfs = ip_vrf_model.rx.borrow().clone();
    let mut vrf_names = vrf_name_lookup(ip_vrfs.as_ref());

    // Pre-populate the originated-routes Prometheus gauge at 0 for
    // every configured IP-VRF. Without this, a VRF that has yet to
    // see its first observation never emits a series — Prometheus
    // queries return "no data" for it, which most dashboards conflate
    // with "metric unavailable" rather than "count is zero." The same
    // pattern is used for `evpn_ip_vrf_installed_routes` by the
    // daemon-side report subscriber (see `src/main.rs`).
    publish_all_originated_gauges(&cfg, ip_vrfs.as_ref());

    // Eagerly drive one reconcile so startup state aligns with whatever
    // the dataplane has already reported (the watch channels may already
    // carry a snapshot from the first reconcile pass).
    reconcile(&mut originated, &mut cfg, ip_vrfs.as_ref(), &vrf_names).await;

    loop {
        tokio::select! {
            biased;
            () = cfg.shutdown.cancelled() => {
                debug!("EVPN L3 originator shutting down — draining {} routes", originated.len());
                drain_all(&mut originated, &cfg, &vrf_names).await;
                return;
            }
            res = cfg.route_observations_rx.changed() => {
                if res.is_err() {
                    debug!("L3 originator: observation watch closed; draining");
                    drain_all(&mut originated, &cfg, &vrf_names).await;
                    return;
                }
                reconcile(&mut originated, &mut cfg, ip_vrfs.as_ref(), &vrf_names).await;
            }
            res = cfg.ip_vrf_status_rx.changed() => {
                if res.is_err() {
                    debug!("L3 originator: status watch closed; draining");
                    drain_all(&mut originated, &cfg, &vrf_names).await;
                    return;
                }
                reconcile(&mut originated, &mut cfg, ip_vrfs.as_ref(), &vrf_names).await;
            }
            res = ip_vrf_model.rx.changed() => {
                if res.is_err() {
                    debug!("L3 originator: IP-VRF model watch closed; draining");
                    drain_all(&mut originated, &cfg, &vrf_names).await;
                    return;
                }
                let next_ip_vrfs = ip_vrf_model.rx.borrow().clone();
                drain_changed_ip_vrfs(
                    &mut originated,
                    &cfg,
                    ip_vrfs.as_ref(),
                    next_ip_vrfs.as_ref(),
                    &vrf_names,
                )
                .await;
                ip_vrfs = next_ip_vrfs;
                merge_vrf_names(&mut vrf_names, ip_vrfs.as_ref());
                publish_all_originated_gauges(&cfg, ip_vrfs.as_ref());
                reconcile(&mut originated, &mut cfg, ip_vrfs.as_ref(), &vrf_names).await;
            }
        }
    }
}

/// Per-Ready-VRF connected-subnet set for GW-IP overlay-index gateway
/// selection (ADR-0087 decision 1). Built once per reconcile pass from
/// the same observation snapshot: a via is only a valid gateway if it
/// lands inside a `Connected` (kernel-installed) prefix in the same
/// VRF. Cheap — a handful of prefixes per VRF — and only populated for
/// VRFs in GW-IP mode (Interface-less VRFs never consult it).
fn gateway_mode_connected_subnets(
    ready_vrfs: &HashMap<IpVrfId, &IpVrf>,
    observations: &HashMap<IpVrfId, Vec<LocalIpRouteObservation>>,
) -> HashMap<IpVrfId, Vec<EvpnIpPrefixValue>> {
    let mut connected_subnets: HashMap<IpVrfId, Vec<EvpnIpPrefixValue>> = HashMap::new();
    for (vrf_id, vrf) in ready_vrfs {
        if vrf.overlay_index_mode != rustbgpd_evpn::OverlayIndexMode::GatewayIp {
            continue;
        }
        let Some(obs_vec) = observations.get(vrf_id) else {
            continue;
        };
        let subnets: Vec<EvpnIpPrefixValue> = obs_vec
            .iter()
            .filter(|o| o.source == RouteSource::Connected)
            .map(|o| o.prefix)
            .collect();
        if !subnets.is_empty() {
            connected_subnets.insert(*vrf_id, subnets);
        }
    }
    connected_subnets
}

async fn reconcile(
    originated: &mut BTreeMap<(IpVrfId, EvpnIpPrefixValue), OriginatedEntry>,
    cfg: &mut SpawnConfig,
    ip_vrfs: &IpVrfTable,
    vrf_names: &BTreeMap<IpVrfId, String>,
) {
    // Snapshot the watch values. Both `borrow()` calls are lock-free
    // seqlock reads — the clones release the borrow before any await.
    let observations = cfg.route_observations_rx.borrow().clone();
    let status_rows = cfg.ip_vrf_status_rx.borrow().clone();
    let ready_vrfs: HashMap<IpVrfId, &IpVrf> = ip_vrfs
        .iter()
        .filter(|vrf| {
            status_rows
                .iter()
                .find(|r| r.vrf_id == vrf.id)
                .is_some_and(|r| matches!(r.status, IpVrfStatus::Ready { .. }))
        })
        .map(|vrf| (vrf.id, vrf))
        .collect();

    // Compute `want` — every observation for a Ready VRF.
    let mut want: BTreeMap<(IpVrfId, EvpnIpPrefixValue), LocalIpRouteObservation> = BTreeMap::new();
    for (vrf_id, vrf) in &ready_vrfs {
        let Some(obs_vec) = observations.get(vrf_id) else {
            continue;
        };
        for obs in obs_vec {
            want.insert((*vrf_id, obs.prefix), *obs);
        }
        let _ = vrf; // silence clippy::needless_pass_by_value-style hints
    }

    // For each VRF, suppress `not_ready` counts for observations the
    // operator might be expecting to see. We bump the counter once per
    // observation that *would* have been originated if the VRF were
    // Ready — operators chasing "why isn't my route on the wire?" see
    // the suppression directly.
    for vrf in ip_vrfs.iter() {
        if ready_vrfs.contains_key(&vrf.id) {
            continue;
        }
        let Some(obs_vec) = observations.get(&vrf.id) else {
            continue;
        };
        if obs_vec.is_empty() {
            continue;
        }
        cfg.metrics.add_evpn_ip_vrf_origination_suppressed(
            &vrf.name,
            SUPPRESS_NOT_READY,
            obs_vec.len() as u64,
        );
    }

    // Per-Ready-VRF connected-subnet set for GW-IP overlay-index
    // gateway selection (ADR-0087 decision 1).
    let connected_subnets = gateway_mode_connected_subnets(&ready_vrfs, &observations);

    // Phase 1: withdrawals — `have - want`. Only drop the entry
    // from `originated` once the RIB has acknowledged the withdraw;
    // a transient channel/reply failure leaves the entry in place so
    // the next reconcile pass retries (level-triggered model).
    let to_withdraw: Vec<((IpVrfId, EvpnIpPrefixValue), EvpnRouteKey)> = originated
        .iter()
        .filter(|(k, _)| !want.contains_key(k))
        .map(|(k, v)| (*k, v.key))
        .collect();
    for ((vrf_id, prefix), key) in to_withdraw {
        if withdraw_one(&cfg.rib_tx, vrf_id, key, &cfg.originated_counts).await {
            originated.remove(&(vrf_id, prefix));
            if let Some(name) = vrf_names.get(&vrf_id) {
                publish_originated_gauge(cfg, vrf_id, name);
            }
            // (missing-name case: VRF removed from config mid-flight
            // — the gauge holds its last value; the next config
            // reload won't see this vrf_id anyway.)
        }
    }

    // Phase 2: injections — `want - have`, plus stale-key/gateway repair
    // for same-(VRF,prefix) changes. The per-prefix body lives in
    // `originate_one` so this loop stays small.
    for ((vrf_id, prefix), obs) in &want {
        let Some(vrf) = ready_vrfs.get(vrf_id) else {
            continue; // checked above, but keep the guard for clarity
        };
        let subnets = connected_subnets.get(vrf_id).map_or(&[][..], Vec::as_slice);
        let gateway = select_overlay_gateway(vrf, obs.prefix, obs.via, subnets);
        originate_one(originated, cfg, vrf, *vrf_id, *prefix, obs, gateway).await;
    }
}

/// Originate (or re-originate) one `(VRF, prefix)`. Records the entry
/// in `originated` only after the RIB acks the inject — a failed inject
/// leaves the "want, not yet originated" state so the next pass retries.
/// Handles three sub-cases: fresh inject, in-place gateway repair (same
/// route key, new GW-IP payload — ADR-0087 decision 5, no intermediate
/// withdraw), and key change (withdraw-then-inject).
async fn originate_one(
    originated: &mut BTreeMap<(IpVrfId, EvpnIpPrefixValue), OriginatedEntry>,
    cfg: &SpawnConfig,
    vrf: &IpVrf,
    vrf_id: IpVrfId,
    prefix: EvpnIpPrefixValue,
    obs: &LocalIpRouteObservation,
    gateway: Option<std::net::IpAddr>,
) {
    let route = match try_originate(vrf, obs, gateway) {
        Ok(r) => r,
        // `select_overlay_gateway` never emits a cross-family gateway,
        // so `GatewayFamilyMismatch` is unreachable in practice; both
        // arms suppress + drop the stale entry identically (structural
        // safety net).
        Err(
            OriginationError::FamilyMismatch { .. }
            | OriginationError::GatewayFamilyMismatch { .. },
        ) => {
            cfg.metrics.add_evpn_ip_vrf_origination_suppressed(
                &vrf.name,
                SUPPRESS_FAMILY_MISMATCH,
                1,
            );
            if let Some(stale) = originated.get(&(vrf_id, prefix)).copied()
                && withdraw_one(&cfg.rib_tx, vrf_id, stale.key, &cfg.originated_counts).await
            {
                originated.remove(&(vrf_id, prefix));
                publish_originated_gauge(cfg, vrf_id, &vrf.name);
            }
            return;
        }
    };
    let key = route.key();
    let desired = OriginatedEntry {
        key,
        gateway: route_gateway(&route),
    };
    if let Some(existing) = originated.get(&(vrf_id, prefix)).copied() {
        if existing == desired {
            return; // already originated with this key + gateway
        }
        if existing.key == key {
            // Same route identity, different gateway payload (a GW-IP
            // via change): re-inject in place. `insert_evpn` replaces
            // last-write-wins on the key and re-distributes, so peers
            // see one UPDATE rather than a withdraw/announce pulse.
        } else if withdraw_one(&cfg.rib_tx, vrf_id, existing.key, &cfg.originated_counts).await {
            originated.remove(&(vrf_id, prefix));
            publish_originated_gauge(cfg, vrf_id, &vrf.name);
        } else {
            return;
        }
    }
    if inject_one(&cfg.rib_tx, vrf_id, key, route, &cfg.originated_counts).await {
        // `inject_one` increments the count on every ack. For an
        // in-place gateway change the key was already counted, so step
        // the count back down to avoid double counting the same prefix.
        if originated
            .insert((vrf_id, prefix), desired)
            .is_some_and(|prev| prev.key == key)
        {
            cfg.originated_counts.dec(vrf_id);
        }
        publish_originated_gauge(cfg, vrf_id, &vrf.name);
    }
}

/// Drain Type 5 routes for IP-VRFs that disappeared or changed content in a
/// runtime model update before reconciling the candidate table. Without this,
/// a same-L3VNI redefine that changes RD/RT/NEXT_HOP/Router-MAC attributes
/// would remain in `originated` under the same `(IpVrfId, prefix)` key and the
/// normal `want - have` pass would skip re-injection.
async fn drain_changed_ip_vrfs(
    originated: &mut BTreeMap<(IpVrfId, EvpnIpPrefixValue), OriginatedEntry>,
    cfg: &SpawnConfig,
    current: &IpVrfTable,
    next: &IpVrfTable,
    vrf_names: &BTreeMap<IpVrfId, String>,
) {
    let changed_ids: BTreeSet<IpVrfId> = current
        .iter()
        .filter_map(|old| match next.get(&old.name) {
            Some(new) if new == old => None,
            _ => Some(old.id),
        })
        .collect();
    if changed_ids.is_empty() {
        return;
    }

    let to_withdraw: Vec<((IpVrfId, EvpnIpPrefixValue), EvpnRouteKey)> = originated
        .iter()
        .filter(|((vrf_id, _), _)| changed_ids.contains(vrf_id))
        .map(|(k, v)| (*k, v.key))
        .collect();
    for ((vrf_id, prefix), key) in to_withdraw {
        if withdraw_one(&cfg.rib_tx, vrf_id, key, &cfg.originated_counts).await {
            originated.remove(&(vrf_id, prefix));
            if let Some(name) = vrf_names.get(&vrf_id) {
                publish_originated_gauge(cfg, vrf_id, name);
            }
        }
    }
}

fn try_originate(
    vrf: &IpVrf,
    obs: &LocalIpRouteObservation,
    gateway: Option<std::net::IpAddr>,
) -> Result<EvpnRibRoute, OriginationError> {
    let local = match obs.prefix {
        EvpnIpPrefixValue::V4(p) => LocalIpRoute::v4(p),
        EvpnIpPrefixValue::V6(p) => LocalIpRoute::v6(p),
    }
    .with_gateway(gateway);
    let originated = originate_ip_prefix_route(vrf, &local)?;
    Ok(EvpnRibRoute {
        route: originated.route,
        next_hop: originated.next_hop,
        link_local_next_hop: None,
        peer: LOCAL_PEER,
        attributes: Arc::new(originated.attributes),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Local,
        peer_router_id: std::net::Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
    })
}

/// The Type 5 Gateway Address carried by an originated route. Used to
/// detect a GW-IP via change that leaves the route key unchanged
/// (ADR-0087 decision 5). Non-IpPrefix EVPN routes never flow through
/// this originator; the fallback keeps the helper total.
fn route_gateway(route: &EvpnRibRoute) -> std::net::IpAddr {
    match &route.route {
        rustbgpd_wire::EvpnRoute::IpPrefix(p) => p.gateway,
        _ => std::net::Ipv4Addr::UNSPECIFIED.into(),
    }
}

/// Issue an `InjectEvpn` over the RIB channel and wait for the
/// acknowledgement. Returns `true` only when the RIB replied
/// `Ok(())`; `false` for every failure path (channel closed before
/// send, reply dropped, RIB rejected with a string error). Callers
/// must gate their state updates on the return value — recording an
/// inject as "complete" without an ack would diverge the originator's
/// in-memory state from the RIB and leave the next reconcile pass
/// unable to retry.
async fn inject_one(
    rib_tx: &mpsc::Sender<RibUpdate>,
    vrf_id: IpVrfId,
    _key: EvpnRouteKey,
    route: EvpnRibRoute,
    counts: &OriginatedIpVrfRouteCounts,
) -> bool {
    let (reply_tx, reply_rx) = oneshot::channel();
    if rib_tx
        .send(RibUpdate::InjectEvpn {
            route,
            reply: reply_tx,
        })
        .await
        .is_err()
    {
        warn!("L3 originator: rib channel closed during inject");
        return false;
    }
    match reply_rx.await {
        Ok(Ok(())) => {
            counts.inc(vrf_id);
            true
        }
        Ok(Err(e)) => {
            warn!(error = %e, vrf_id = ?vrf_id, "L3 originator: RIB rejected inject");
            false
        }
        Err(_) => {
            warn!(vrf_id = ?vrf_id, "L3 originator: inject reply dropped");
            false
        }
    }
}

/// Issue a `WithdrawEvpn` over the RIB channel and wait for the
/// acknowledgement. Returns `true` only when the RIB replied
/// `Ok(())`. Callers must keep the entry in their in-memory
/// `originated` map when this returns `false` so the next reconcile
/// pass retries.
async fn withdraw_one(
    rib_tx: &mpsc::Sender<RibUpdate>,
    vrf_id: IpVrfId,
    key: EvpnRouteKey,
    counts: &OriginatedIpVrfRouteCounts,
) -> bool {
    let (reply_tx, reply_rx) = oneshot::channel();
    if rib_tx
        .send(RibUpdate::WithdrawEvpn {
            key,
            reply: reply_tx,
        })
        .await
        .is_err()
    {
        warn!("L3 originator: rib channel closed during withdraw");
        return false;
    }
    match reply_rx.await {
        Ok(Ok(())) => {
            counts.dec(vrf_id);
            true
        }
        Ok(Err(e)) => {
            warn!(error = %e, vrf_id = ?vrf_id, "L3 originator: RIB rejected withdraw");
            false
        }
        Err(_) => {
            warn!(vrf_id = ?vrf_id, "L3 originator: withdraw reply dropped");
            false
        }
    }
}

/// Best-effort drain on shutdown. Walks every currently-originated
/// route, tries to withdraw it, and clears the in-memory map at the
/// end **regardless of withdraw success** — the task is exiting and
/// the map is about to be dropped anyway, so retrying within the
/// shutdown window doesn't earn anything. The bounded
/// `EvpnL3OriginatorHandle::shutdown` timeout caps how long the
/// daemon waits for the withdraw acks; entries whose withdraw failed
/// are not retried here (the next daemon start would re-originate
/// off the kernel observation, then re-issue a normal withdraw).
async fn drain_all(
    originated: &mut BTreeMap<(IpVrfId, EvpnIpPrefixValue), OriginatedEntry>,
    cfg: &SpawnConfig,
    vrf_names: &BTreeMap<IpVrfId, String>,
) {
    let snapshot: Vec<_> = originated.iter().map(|(k, v)| (*k, v.key)).collect();
    for ((vrf_id, _prefix), key) in &snapshot {
        if withdraw_one(&cfg.rib_tx, *vrf_id, *key, &cfg.originated_counts).await
            && let Some(name) = vrf_names.get(vrf_id)
        {
            publish_originated_gauge(cfg, *vrf_id, name);
        }
    }
    originated.clear();
}

/// Republish the `evpn_ip_vrf_originated_routes{vrf}` Prometheus
/// gauge from the authoritative shared counter. Called after every
/// successful `inject_one` / `withdraw_one` so the gauge tracks the
/// gRPC `IpVrfState.originated_routes_count` field exactly. The
/// caller resolves `vrf_name` from a per-pass `IpVrfId -> name`
/// cache (built once at the top of `reconcile` / `drain_all`) so
/// the hot path is O(1) — earlier drafts did
/// `ip_vrfs.iter().find(...)` per inject which was O(VRFs ×
/// routes) and unnecessary.
fn publish_originated_gauge(cfg: &SpawnConfig, vrf_id: IpVrfId, vrf_name: &str) {
    let count = cfg.originated_counts.count(vrf_id);
    cfg.metrics
        .set_evpn_ip_vrf_originated_routes(vrf_name, i64::try_from(count).unwrap_or(i64::MAX));
}

fn publish_all_originated_gauges(cfg: &SpawnConfig, ip_vrfs: &IpVrfTable) {
    for vrf in ip_vrfs.iter() {
        publish_originated_gauge(cfg, vrf.id, &vrf.name);
    }
}

fn merge_vrf_names(names: &mut BTreeMap<IpVrfId, String>, ip_vrfs: &IpVrfTable) {
    for vrf in ip_vrfs.iter() {
        names.insert(vrf.id, vrf.name.clone());
    }
}

/// Build a one-shot `IpVrfId -> name` lookup. Cheap: at most a few
/// dozen entries even in a very large deployment. Allocates one
/// `String` per VRF; the alternative — keeping `&str` borrows —
/// would tie the cache lifetime to `cfg`, which doesn't play with
/// the `await` boundaries inside the reconcile loop.
fn vrf_name_lookup(ip_vrfs: &IpVrfTable) -> BTreeMap<IpVrfId, String> {
    ip_vrfs
        .iter()
        .map(|vrf| (vrf.id, vrf.name.clone()))
        .collect()
}

/// Compute the route key the originator would produce for one
/// observation. Exposed for tests that need to predict the key without
/// running the full origination path.
#[cfg(test)]
fn predicted_key(vrf: &IpVrf, prefix: EvpnIpPrefixValue) -> EvpnRouteKey {
    let local = match prefix {
        EvpnIpPrefixValue::V4(p) => LocalIpRoute::v4(p),
        EvpnIpPrefixValue::V6(p) => LocalIpRoute::v6(p),
    };
    originate_ip_prefix_route(vrf, &local)
        .expect("predicted_key called with matching family")
        .route
        .key()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbgpd_evpn::ip_vrf::IpVrfNotReady;
    use rustbgpd_evpn::{IpVrf, IpVrfId, MacAddress, RouteSource, RouteTarget};
    use rustbgpd_rib::RibCommandError;
    use rustbgpd_telemetry::BgpMetrics;
    use rustbgpd_wire::{Ipv4Prefix, RouteDistinguisher};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tokio::sync::mpsc::error::TryRecvError;

    fn vrf(id: u32, vtep: IpAddr) -> IpVrf {
        IpVrf::new(
            format!("vrf{id}"),
            IpVrfId::new(id).unwrap(),
            format!("65000:{id}").parse::<RouteDistinguisher>().unwrap(),
            vec![format!("65000:{id}").parse::<RouteTarget>().unwrap()],
            vtep,
            MacAddress::new([
                0xaa,
                0xbb,
                0xcc,
                0xdd,
                0xee,
                u8::try_from(id & 0xFF).unwrap(),
            ]),
            format!("vrf{id}"),
            format!("l3vxlan{id}"),
            id,
        )
        .unwrap()
    }

    fn redefined_vrf(id: u32, rd_rt: u32, vtep: IpAddr) -> IpVrf {
        IpVrf::new(
            format!("vrf{id}"),
            IpVrfId::new(id).unwrap(),
            format!("65000:{rd_rt}")
                .parse::<RouteDistinguisher>()
                .unwrap(),
            vec![format!("65000:{rd_rt}").parse::<RouteTarget>().unwrap()],
            vtep,
            MacAddress::new([
                0xaa,
                0xbb,
                0xcc,
                0xdd,
                0xee,
                u8::try_from(id & 0xFF).unwrap(),
            ]),
            format!("vrf{id}"),
            format!("l3vxlan{id}"),
            id,
        )
        .unwrap()
    }

    fn observation(vrf_id: u32, prefix_octets: [u8; 4], len: u8) -> LocalIpRouteObservation {
        LocalIpRouteObservation {
            vrf_id: IpVrfId::new(vrf_id).unwrap(),
            prefix: EvpnIpPrefixValue::V4(Ipv4Prefix::new(Ipv4Addr::from(prefix_octets), len)),
            source: RouteSource::Static,
            via: None,
        }
    }

    /// A `Connected` observation (a tenant connected subnet) so a
    /// GW-IP via can resolve against it in the same pass.
    fn connected(vrf_id: u32, prefix_octets: [u8; 4], len: u8) -> LocalIpRouteObservation {
        LocalIpRouteObservation {
            vrf_id: IpVrfId::new(vrf_id).unwrap(),
            prefix: EvpnIpPrefixValue::V4(Ipv4Prefix::new(Ipv4Addr::from(prefix_octets), len)),
            source: RouteSource::Connected,
            via: None,
        }
    }

    /// A static route with a via, used for GW-IP overlay-index tests.
    fn observation_via(
        vrf_id: u32,
        prefix_octets: [u8; 4],
        len: u8,
        via: &str,
    ) -> LocalIpRouteObservation {
        LocalIpRouteObservation {
            via: Some(via.parse().unwrap()),
            ..observation(vrf_id, prefix_octets, len)
        }
    }

    fn gw_vrf(id: u32, vtep: IpAddr) -> IpVrf {
        vrf(id, vtep).with_overlay_index_mode(rustbgpd_evpn::OverlayIndexMode::GatewayIp)
    }

    fn ready_status(vrf_id: u32) -> IpVrfDataplaneStatus {
        IpVrfDataplaneStatus {
            vrf_id: IpVrfId::new(vrf_id).unwrap(),
            vrf_name: format!("vrf{vrf_id}"),
            status: IpVrfStatus::Ready {
                vrf_ifindex: 10,
                l3vxlan_ifindex: 20,
                table_id: vrf_id,
                router_mac: MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
            },
        }
    }

    fn not_ready_status(vrf_id: u32) -> IpVrfDataplaneStatus {
        IpVrfDataplaneStatus {
            vrf_id: IpVrfId::new(vrf_id).unwrap(),
            vrf_name: format!("vrf{vrf_id}"),
            status: IpVrfStatus::NotReady {
                reasons: vec![IpVrfNotReady::VrfDeviceMissing],
            },
        }
    }

    /// What the test RIB responder does for each request kind.
    /// Defaults to `Ok` for both; tests for the inject-failure and
    /// withdraw-failure regression paths (review finding #2) flip
    /// one or both arms to `Reject` to simulate a RIB that rejects
    /// the request with an error string.
    #[derive(Debug, Clone, Copy)]
    struct RibResponderMode {
        inject: ReplyMode,
        withdraw: ReplyMode,
    }

    impl Default for RibResponderMode {
        fn default() -> Self {
            Self {
                inject: ReplyMode::Ok,
                withdraw: ReplyMode::Ok,
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum ReplyMode {
        Ok,
        Reject,
    }

    /// Spawn a RIB-channel responder that records every Inject /
    /// Withdraw plus the configured reply outcome. Records the
    /// recorded `RibCall` *before* sending the reply so the test
    /// can observe the request shape even when the reply is `Err`.
    fn rib_responder(
        mode: RibResponderMode,
    ) -> (
        mpsc::Sender<RibUpdate>,
        tokio::task::JoinHandle<Vec<RibCall>>,
    ) {
        let (tx, mut rx) = mpsc::channel::<RibUpdate>(32);
        let handle = tokio::spawn(async move {
            let mut calls = Vec::new();
            while let Some(msg) = rx.recv().await {
                match msg {
                    RibUpdate::InjectEvpn { route, reply } => {
                        let key = route.key();
                        calls.push(RibCall::Inject(key));
                        let response = match mode.inject {
                            ReplyMode::Ok => Ok(()),
                            ReplyMode::Reject => Err(RibCommandError::internal("test rejection")),
                        };
                        let _ = reply.send(response);
                    }
                    RibUpdate::WithdrawEvpn { key, reply } => {
                        calls.push(RibCall::Withdraw(key));
                        let response = match mode.withdraw {
                            ReplyMode::Ok => Ok(()),
                            ReplyMode::Reject => Err(RibCommandError::internal("test rejection")),
                        };
                        let _ = reply.send(response);
                    }
                    _other => {
                        calls.push(RibCall::Other);
                    }
                }
            }
            calls
        });
        (tx, handle)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum RibCall {
        Inject(EvpnRouteKey),
        Withdraw(EvpnRouteKey),
        Other,
    }

    async fn next_rib_call(rx: &mut mpsc::Receiver<RibUpdate>) -> RibCall {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timed out waiting for RIB update")
            .expect("RIB channel closed before expected update");
        match msg {
            RibUpdate::InjectEvpn { route, reply } => {
                let key = route.key();
                let _ = reply.send(Ok(()));
                RibCall::Inject(key)
            }
            RibUpdate::WithdrawEvpn { key, reply } => {
                let _ = reply.send(Ok(()));
                RibCall::Withdraw(key)
            }
            _other => RibCall::Other,
        }
    }

    struct Harness {
        cfg: SpawnConfig,
        obs_tx: watch::Sender<Arc<HashMap<IpVrfId, Vec<LocalIpRouteObservation>>>>,
        status_tx: watch::Sender<Vec<IpVrfDataplaneStatus>>,
        rib_handle: tokio::task::JoinHandle<Vec<RibCall>>,
        rib_tx: mpsc::Sender<RibUpdate>,
    }

    impl Harness {
        fn new(vrfs: Vec<IpVrf>) -> Self {
            Self::with_responder_mode(vrfs, RibResponderMode::default())
        }

        fn with_responder_mode(vrfs: Vec<IpVrf>, mode: RibResponderMode) -> Self {
            let mut table = IpVrfTable::new();
            for v in vrfs {
                table.insert(v).unwrap();
            }
            let ip_vrfs = Arc::new(table);
            let (obs_tx, obs_rx) = watch::channel(Arc::new(HashMap::new()));
            let (status_tx, status_rx) = watch::channel(Vec::<IpVrfDataplaneStatus>::new());
            let (rib_tx, rib_handle) = rib_responder(mode);
            let cfg = SpawnConfig {
                ip_vrfs,
                rib_tx: rib_tx.clone(),
                route_observations_rx: obs_rx,
                ip_vrf_status_rx: status_rx,
                metrics: BgpMetrics::new(),
                originated_counts: OriginatedIpVrfRouteCounts::default(),
                shutdown: CancellationToken::new(),
            };
            Self {
                cfg,
                obs_tx,
                status_tx,
                rib_handle,
                rib_tx,
            }
        }

        async fn drive_one(
            mut originated: BTreeMap<(IpVrfId, EvpnIpPrefixValue), OriginatedEntry>,
            cfg: &mut SpawnConfig,
        ) -> BTreeMap<(IpVrfId, EvpnIpPrefixValue), OriginatedEntry> {
            let ip_vrfs = cfg.ip_vrfs.clone();
            let vrf_names = vrf_name_lookup(ip_vrfs.as_ref());
            reconcile(&mut originated, cfg, ip_vrfs.as_ref(), &vrf_names).await;
            originated
        }

        async fn collect_calls(self) -> Vec<RibCall> {
            // Destructure to drop every sender — both the harness's
            // standalone `rib_tx` *and* the one inside `cfg` — before
            // awaiting the responder. With either still alive, the
            // responder's `rx.recv()` stays parked forever.
            let Harness {
                cfg,
                obs_tx,
                status_tx,
                rib_handle,
                rib_tx,
            } = self;
            drop(rib_tx);
            drop(obs_tx);
            drop(status_tx);
            drop(cfg);
            rib_handle.await.unwrap()
        }
    }

    #[tokio::test]
    async fn cold_start_ready_with_one_observation_injects_once() {
        let v = vrf(100, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let predicted = predicted_key(&v, observation(100, [10, 1, 0, 0], 24).prefix);
        let mut h = Harness::new(vec![v]);

        h.status_tx.send_replace(vec![ready_status(100)]);
        let mut obs_map = HashMap::new();
        obs_map.insert(
            IpVrfId::new(100).unwrap(),
            vec![observation(100, [10, 1, 0, 0], 24)],
        );
        h.obs_tx.send_replace(Arc::new(obs_map));

        let originated = Harness::drive_one(BTreeMap::new(), &mut h.cfg).await;
        assert_eq!(originated.len(), 1);
        let prefix = EvpnIpPrefixValue::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24));
        assert_eq!(
            originated
                .get(&(IpVrfId::new(100).unwrap(), prefix))
                .map(|e| e.key),
            Some(predicted),
        );
        let calls = h.collect_calls().await;
        assert_eq!(calls, vec![RibCall::Inject(predicted)]);
    }

    #[tokio::test]
    async fn idempotent_same_observation_does_not_re_inject() {
        let v = vrf(100, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let predicted = predicted_key(&v, observation(100, [10, 1, 0, 0], 24).prefix);
        let mut h = Harness::new(vec![v]);

        h.status_tx.send_replace(vec![ready_status(100)]);
        let mut obs_map = HashMap::new();
        obs_map.insert(
            IpVrfId::new(100).unwrap(),
            vec![observation(100, [10, 1, 0, 0], 24)],
        );
        h.obs_tx.send_replace(Arc::new(obs_map));

        let originated = Harness::drive_one(BTreeMap::new(), &mut h.cfg).await;
        let originated = Harness::drive_one(originated, &mut h.cfg).await;
        assert_eq!(originated.len(), 1);
        let calls = h.collect_calls().await;
        assert_eq!(calls, vec![RibCall::Inject(predicted)]);
    }

    #[tokio::test]
    async fn observation_removed_triggers_withdraw() {
        let v = vrf(100, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let predicted = predicted_key(&v, observation(100, [10, 1, 0, 0], 24).prefix);
        let mut h = Harness::new(vec![v]);

        h.status_tx.send_replace(vec![ready_status(100)]);
        let mut obs_map = HashMap::new();
        obs_map.insert(
            IpVrfId::new(100).unwrap(),
            vec![observation(100, [10, 1, 0, 0], 24)],
        );
        h.obs_tx.send_replace(Arc::new(obs_map));

        let originated = Harness::drive_one(BTreeMap::new(), &mut h.cfg).await;
        assert_eq!(originated.len(), 1);

        // Replace observations with an empty set for the VRF.
        let mut empty_map = HashMap::new();
        empty_map.insert(IpVrfId::new(100).unwrap(), vec![]);
        h.obs_tx.send_replace(Arc::new(empty_map));

        let originated = Harness::drive_one(originated, &mut h.cfg).await;
        assert!(originated.is_empty());
        let calls = h.collect_calls().await;
        assert_eq!(
            calls,
            vec![RibCall::Inject(predicted), RibCall::Withdraw(predicted)],
        );
    }

    #[tokio::test]
    async fn ready_to_not_ready_withdraws_all() {
        let v = vrf(100, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let mut h = Harness::new(vec![v]);

        h.status_tx.send_replace(vec![ready_status(100)]);
        let mut obs_map = HashMap::new();
        obs_map.insert(
            IpVrfId::new(100).unwrap(),
            vec![
                observation(100, [10, 1, 0, 0], 24),
                observation(100, [10, 2, 0, 0], 24),
            ],
        );
        h.obs_tx.send_replace(Arc::new(obs_map));

        let originated = Harness::drive_one(BTreeMap::new(), &mut h.cfg).await;
        assert_eq!(originated.len(), 2);

        // Flip readiness — same observations, but VRF is now NotReady.
        h.status_tx.send_replace(vec![not_ready_status(100)]);

        let originated = Harness::drive_one(originated, &mut h.cfg).await;
        assert!(originated.is_empty());

        let calls = h.collect_calls().await;
        let injects = calls
            .iter()
            .filter(|c| matches!(c, RibCall::Inject(_)))
            .count();
        let withdraws = calls
            .iter()
            .filter(|c| matches!(c, RibCall::Withdraw(_)))
            .count();
        assert_eq!(injects, 2);
        assert_eq!(withdraws, 2);
    }

    #[tokio::test]
    async fn not_ready_to_ready_replays_observations() {
        let v = vrf(100, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let mut h = Harness::new(vec![v]);

        // Start NotReady with observations present — must not inject.
        h.status_tx.send_replace(vec![not_ready_status(100)]);
        let mut obs_map = HashMap::new();
        obs_map.insert(
            IpVrfId::new(100).unwrap(),
            vec![observation(100, [10, 1, 0, 0], 24)],
        );
        h.obs_tx.send_replace(Arc::new(obs_map));

        let originated = Harness::drive_one(BTreeMap::new(), &mut h.cfg).await;
        assert!(originated.is_empty());

        // Transition to Ready — must replay.
        h.status_tx.send_replace(vec![ready_status(100)]);
        let originated = Harness::drive_one(originated, &mut h.cfg).await;
        assert_eq!(originated.len(), 1);

        let calls = h.collect_calls().await;
        let injects = calls
            .iter()
            .filter(|c| matches!(c, RibCall::Inject(_)))
            .count();
        assert_eq!(injects, 1);
        assert_eq!(
            calls
                .iter()
                .filter(|c| matches!(c, RibCall::Withdraw(_)))
                .count(),
            0,
        );
    }

    #[tokio::test]
    async fn family_mismatch_suppresses_origination() {
        // IPv6 VTEP, IPv4 observation.
        let v = vrf(
            100,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        );
        let mut h = Harness::new(vec![v]);

        h.status_tx.send_replace(vec![ready_status(100)]);
        let mut obs_map = HashMap::new();
        obs_map.insert(
            IpVrfId::new(100).unwrap(),
            vec![observation(100, [10, 1, 0, 0], 24)],
        );
        h.obs_tx.send_replace(Arc::new(obs_map));

        let originated = Harness::drive_one(BTreeMap::new(), &mut h.cfg).await;
        assert!(originated.is_empty(), "family mismatch must not originate");

        let calls = h.collect_calls().await;
        assert!(
            calls.iter().all(|c| !matches!(c, RibCall::Inject(_))),
            "no Inject should be sent on family mismatch",
        );
    }

    #[tokio::test]
    async fn spawn_returns_none_for_empty_ip_vrf_table() {
        let (obs_tx, obs_rx) = watch::channel(Arc::new(HashMap::new()));
        let (status_tx, status_rx) = watch::channel(Vec::<IpVrfDataplaneStatus>::new());
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(1);
        let cfg = SpawnConfig {
            ip_vrfs: Arc::new(IpVrfTable::new()),
            rib_tx,
            route_observations_rx: obs_rx,
            ip_vrf_status_rx: status_rx,
            metrics: BgpMetrics::new(),
            originated_counts: OriginatedIpVrfRouteCounts::default(),
            shutdown: CancellationToken::new(),
        };
        assert!(spawn(cfg).is_none());
        drop(obs_tx);
        drop(status_tx);
        // No messages were sent — channel drains immediately.
        assert!(matches!(
            rib_rx.try_recv(),
            Err(TryRecvError::Empty | TryRecvError::Disconnected)
        ));
    }

    #[tokio::test]
    async fn runtime_ip_vrf_model_change_withdraws_originated_routes() {
        let v = vrf(100, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let predicted = predicted_key(&v, observation(100, [10, 1, 0, 0], 24).prefix);
        let mut table = IpVrfTable::new();
        table.insert(v).unwrap();
        let (obs_tx, obs_rx) = watch::channel(Arc::new(HashMap::new()));
        let (status_tx, status_rx) = watch::channel(Vec::<IpVrfDataplaneStatus>::new());
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
        let metrics = BgpMetrics::new();
        let handle = spawn(SpawnConfig {
            ip_vrfs: Arc::new(table),
            rib_tx,
            route_observations_rx: obs_rx,
            ip_vrf_status_rx: status_rx,
            metrics: metrics.clone(),
            originated_counts: OriginatedIpVrfRouteCounts::default(),
            shutdown: CancellationToken::new(),
        })
        .expect("non-empty IP-VRF table should spawn originator");

        status_tx.send_replace(vec![ready_status(100)]);
        let mut obs_map = HashMap::new();
        obs_map.insert(
            IpVrfId::new(100).unwrap(),
            vec![observation(100, [10, 1, 0, 0], 24)],
        );
        obs_tx.send_replace(Arc::new(obs_map));

        assert_eq!(next_rib_call(&mut rib_rx).await, RibCall::Inject(predicted));

        assert!(handle.replace_ip_vrfs(Arc::new(IpVrfTable::new())));

        assert_eq!(
            next_rib_call(&mut rib_rx).await,
            RibCall::Withdraw(predicted),
            "removing a VRF from the effective runtime model must withdraw its Type 5 routes"
        );

        handle.shutdown().await;
        assert_eq!(
            scrape_originated_gauge_from_metrics(&metrics, "vrf100"),
            Some(0)
        );
        drop(obs_tx);
        drop(status_tx);
    }

    #[tokio::test]
    async fn runtime_ip_vrf_redefine_withdraws_and_reinjects_originated_routes() {
        let old = vrf(100, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let new = redefined_vrf(100, 999, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let prefix = observation(100, [10, 1, 0, 0], 24).prefix;
        let old_key = predicted_key(&old, prefix);
        let new_key = predicted_key(&new, prefix);
        assert_ne!(old_key, new_key, "test setup must change the Type 5 key");

        let mut table = IpVrfTable::new();
        table.insert(old).unwrap();
        let (obs_tx, obs_rx) = watch::channel(Arc::new(HashMap::new()));
        let (status_tx, status_rx) = watch::channel(Vec::<IpVrfDataplaneStatus>::new());
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
        let handle = spawn(SpawnConfig {
            ip_vrfs: Arc::new(table),
            rib_tx,
            route_observations_rx: obs_rx,
            ip_vrf_status_rx: status_rx,
            metrics: BgpMetrics::new(),
            originated_counts: OriginatedIpVrfRouteCounts::default(),
            shutdown: CancellationToken::new(),
        })
        .expect("non-empty IP-VRF table should spawn originator");

        status_tx.send_replace(vec![ready_status(100)]);
        let mut obs_map = HashMap::new();
        obs_map.insert(
            IpVrfId::new(100).unwrap(),
            vec![observation(100, [10, 1, 0, 0], 24)],
        );
        obs_tx.send_replace(Arc::new(obs_map));

        assert_eq!(next_rib_call(&mut rib_rx).await, RibCall::Inject(old_key));

        let mut redefined_table = IpVrfTable::new();
        redefined_table.insert(new).unwrap();
        assert!(handle.replace_ip_vrfs(Arc::new(redefined_table)));

        assert_eq!(
            next_rib_call(&mut rib_rx).await,
            RibCall::Withdraw(old_key),
            "redefining an IP-VRF must withdraw the old-RD Type 5 route first"
        );
        assert_eq!(
            next_rib_call(&mut rib_rx).await,
            RibCall::Inject(new_key),
            "redefining an IP-VRF must replay the Type 5 route under the new fields"
        );

        handle.shutdown().await;
        drop(obs_tx);
        drop(status_tx);
    }

    #[tokio::test]
    async fn dropping_handle_does_not_close_runtime_model_watch() {
        let v = vrf(100, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let predicted = predicted_key(&v, observation(100, [10, 1, 0, 0], 24).prefix);
        let mut table = IpVrfTable::new();
        table.insert(v).unwrap();
        let (obs_tx, obs_rx) = watch::channel(Arc::new(HashMap::new()));
        let (status_tx, status_rx) = watch::channel(Vec::<IpVrfDataplaneStatus>::new());
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
        let shutdown = CancellationToken::new();
        let handle = spawn(SpawnConfig {
            ip_vrfs: Arc::new(table),
            rib_tx,
            route_observations_rx: obs_rx,
            ip_vrf_status_rx: status_rx,
            metrics: BgpMetrics::new(),
            originated_counts: OriginatedIpVrfRouteCounts::default(),
            shutdown: shutdown.clone(),
        })
        .expect("non-empty IP-VRF table should spawn originator");

        drop(handle);

        status_tx.send_replace(vec![ready_status(100)]);
        let mut obs_map = HashMap::new();
        obs_map.insert(
            IpVrfId::new(100).unwrap(),
            vec![observation(100, [10, 1, 0, 0], 24)],
        );
        obs_tx.send_replace(Arc::new(obs_map));

        assert_eq!(next_rib_call(&mut rib_rx).await, RibCall::Inject(predicted));

        shutdown.cancel();
        assert_eq!(
            next_rib_call(&mut rib_rx).await,
            RibCall::Withdraw(predicted)
        );
        drop(obs_tx);
        drop(status_tx);
    }

    /// Regression for review finding #1: when the dataplane crate
    /// reports a transient kernel route-dump failure, the daemon's
    /// subscriber preserves the watch channel's last-good value
    /// rather than publishing an empty map. The originator therefore
    /// continues to see the same observation set across the failure
    /// and must NOT withdraw any currently-originated Type 5 routes.
    ///
    /// Driven at the originator layer by holding the observation
    /// watch stable across multiple reconcile passes — the daemon's
    /// `if let Some(dump) = report.ip_vrf_routes` branch enforces
    /// this contract upstream.
    #[tokio::test]
    async fn route_dump_failure_preserves_originated_routes() {
        let v = vrf(100, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let predicted = predicted_key(&v, observation(100, [10, 1, 0, 0], 24).prefix);
        let mut h = Harness::new(vec![v]);

        h.status_tx.send_replace(vec![ready_status(100)]);
        let mut obs_map = HashMap::new();
        obs_map.insert(
            IpVrfId::new(100).unwrap(),
            vec![observation(100, [10, 1, 0, 0], 24)],
        );
        h.obs_tx.send_replace(Arc::new(obs_map));

        let originated = Harness::drive_one(BTreeMap::new(), &mut h.cfg).await;
        assert_eq!(originated.len(), 1);

        // Simulate the dataplane reporting a transient dump failure:
        // the daemon's contract is to NOT update the observation
        // watch. Trigger reconcile via a status re-publish (same
        // value, but `send_replace` always fires `changed()`).
        h.status_tx.send_replace(vec![ready_status(100)]);
        let originated = Harness::drive_one(originated, &mut h.cfg).await;

        assert_eq!(
            originated.len(),
            1,
            "transient route-dump failure must not drop originated entries"
        );
        let calls = h.collect_calls().await;
        assert_eq!(
            calls,
            vec![RibCall::Inject(predicted)],
            "no Withdraw should fire when observations are preserved across a transient failure"
        );
    }

    /// Regression for review finding #2 (inject branch): when the
    /// RIB rejects an `InjectEvpn` with an error reply, the originator
    /// must NOT record the route as originated. The next reconcile
    /// pass observes the same `want` shape and retries the inject.
    #[tokio::test]
    async fn inject_failure_keeps_route_pending_for_retry() {
        let v = vrf(100, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let predicted = predicted_key(&v, observation(100, [10, 1, 0, 0], 24).prefix);
        let mut h = Harness::with_responder_mode(
            vec![v],
            RibResponderMode {
                inject: ReplyMode::Reject,
                withdraw: ReplyMode::Ok,
            },
        );

        h.status_tx.send_replace(vec![ready_status(100)]);
        let mut obs_map = HashMap::new();
        obs_map.insert(
            IpVrfId::new(100).unwrap(),
            vec![observation(100, [10, 1, 0, 0], 24)],
        );
        h.obs_tx.send_replace(Arc::new(obs_map));

        let originated = Harness::drive_one(BTreeMap::new(), &mut h.cfg).await;
        assert!(
            originated.is_empty(),
            "failed inject must not record the entry as originated"
        );

        // Second pass: same `want`, same `have` (empty). The
        // originator should retry the inject. We can't easily flip
        // the responder mode mid-test, so just assert the second
        // pass also emits an Inject (proving retry).
        let originated = Harness::drive_one(originated, &mut h.cfg).await;
        assert!(originated.is_empty());

        let calls = h.collect_calls().await;
        let injects = calls
            .iter()
            .filter(|c| matches!(c, RibCall::Inject(_)))
            .count();
        assert_eq!(
            injects, 2,
            "originator must retry on the next reconcile after a rejected inject"
        );
        assert!(
            calls
                .iter()
                .all(|c| matches!(c, RibCall::Inject(k) if *k == predicted)),
            "every retry uses the same EvpnRouteKey"
        );
    }

    #[tokio::test]
    async fn redefine_withdraw_failure_keeps_stale_key_pending_for_retry() {
        let old = vrf(100, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let new = redefined_vrf(100, 999, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let prefix = observation(100, [10, 1, 0, 0], 24).prefix;
        let old_key = predicted_key(&old, prefix);
        let new_key = predicted_key(&new, prefix);
        let mut h = Harness::with_responder_mode(
            vec![old],
            RibResponderMode {
                inject: ReplyMode::Ok,
                withdraw: ReplyMode::Reject,
            },
        );

        h.status_tx.send_replace(vec![ready_status(100)]);
        let mut obs_map = HashMap::new();
        obs_map.insert(
            IpVrfId::new(100).unwrap(),
            vec![observation(100, [10, 1, 0, 0], 24)],
        );
        h.obs_tx.send_replace(Arc::new(obs_map));
        let originated = Harness::drive_one(BTreeMap::new(), &mut h.cfg).await;

        let mut redefined = IpVrfTable::new();
        redefined.insert(new).unwrap();
        h.cfg.ip_vrfs = Arc::new(redefined);
        let originated = Harness::drive_one(originated, &mut h.cfg).await;
        let originated = Harness::drive_one(originated, &mut h.cfg).await;

        assert_eq!(
            originated
                .get(&(IpVrfId::new(100).unwrap(), prefix))
                .map(|e| e.key),
            Some(old_key),
            "failed withdraw must keep the stale key pending for retry"
        );
        let calls = h.collect_calls().await;
        assert_eq!(
            calls,
            vec![
                RibCall::Inject(old_key),
                RibCall::Withdraw(old_key),
                RibCall::Withdraw(old_key),
            ]
        );
        assert!(
            !calls.contains(&RibCall::Inject(new_key)),
            "new key must not be injected until the stale key withdraw succeeds"
        );
    }

    /// Regression for review finding #2 (withdraw branch): when the
    /// RIB rejects a `WithdrawEvpn`, the originator must KEEP the
    /// entry in its in-memory `originated` map so the next reconcile
    /// pass retries.
    #[tokio::test]
    async fn withdraw_failure_keeps_route_originated() {
        let v = vrf(100, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let predicted = predicted_key(&v, observation(100, [10, 1, 0, 0], 24).prefix);
        let mut h = Harness::with_responder_mode(
            vec![v],
            RibResponderMode {
                inject: ReplyMode::Ok,
                withdraw: ReplyMode::Reject,
            },
        );

        // Inject succeeds.
        h.status_tx.send_replace(vec![ready_status(100)]);
        let mut obs_map = HashMap::new();
        obs_map.insert(
            IpVrfId::new(100).unwrap(),
            vec![observation(100, [10, 1, 0, 0], 24)],
        );
        h.obs_tx.send_replace(Arc::new(obs_map));
        let originated = Harness::drive_one(BTreeMap::new(), &mut h.cfg).await;
        assert_eq!(originated.len(), 1);

        // Observations cleared → next reconcile wants withdraw, but
        // the rejecting responder fails the request. Entry must
        // stay in `originated` so the next pass retries.
        let mut empty_map = HashMap::new();
        empty_map.insert(IpVrfId::new(100).unwrap(), vec![]);
        h.obs_tx.send_replace(Arc::new(empty_map));
        let originated = Harness::drive_one(originated, &mut h.cfg).await;
        assert_eq!(
            originated.len(),
            1,
            "failed withdraw must leave the entry in place for retry"
        );

        // Second pass: same `want`, same `have`. Retry the withdraw.
        let originated = Harness::drive_one(originated, &mut h.cfg).await;
        assert_eq!(originated.len(), 1);

        let calls = h.collect_calls().await;
        let withdraws = calls
            .iter()
            .filter(|c| matches!(c, RibCall::Withdraw(_)))
            .count();
        assert_eq!(
            withdraws, 2,
            "originator must retry on the next reconcile after a rejected withdraw"
        );
        assert!(
            calls
                .iter()
                .filter(|c| matches!(c, RibCall::Withdraw(_)))
                .all(|c| matches!(c, RibCall::Withdraw(k) if *k == predicted)),
        );
    }

    /// Helper: scrape the metrics registry and return one labeled
    /// value from `evpn_ip_vrf_originated_routes` (or `None` if the
    /// series hasn't been emitted yet).
    fn scrape_originated_gauge_from_metrics(metrics: &BgpMetrics, vrf_name: &str) -> Option<i64> {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let families = metrics.registry().gather();
        let mut buf = Vec::new();
        encoder.encode(&families, &mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        let needle = format!("evpn_ip_vrf_originated_routes{{vrf=\"{vrf_name}\"}}");
        for line in text.lines() {
            if line.starts_with(&needle) {
                return line.split_whitespace().last().and_then(|s| s.parse().ok());
            }
        }
        None
    }

    fn scrape_originated_gauge(cfg: &SpawnConfig, vrf_name: &str) -> Option<i64> {
        scrape_originated_gauge_from_metrics(&cfg.metrics, vrf_name)
    }

    #[test]
    fn publish_all_originated_gauges_emits_zero_for_runtime_added_vrf() {
        let (obs_tx, obs_rx) = watch::channel(Arc::new(HashMap::new()));
        let (status_tx, status_rx) = watch::channel(Vec::<IpVrfDataplaneStatus>::new());
        let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(1);
        let cfg = SpawnConfig {
            ip_vrfs: Arc::new(IpVrfTable::new()),
            rib_tx,
            route_observations_rx: obs_rx,
            ip_vrf_status_rx: status_rx,
            metrics: BgpMetrics::new(),
            originated_counts: OriginatedIpVrfRouteCounts::default(),
            shutdown: CancellationToken::new(),
        };
        let mut runtime_table = IpVrfTable::new();
        runtime_table
            .insert(vrf(200, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))))
            .unwrap();

        publish_all_originated_gauges(&cfg, &runtime_table);

        assert_eq!(scrape_originated_gauge(&cfg, "vrf200"), Some(0));
        drop(obs_tx);
        drop(status_tx);
    }

    /// The `evpn_ip_vrf_originated_routes{vrf}` Prometheus gauge
    /// must track the gRPC `IpVrfState.originated_routes_count` field
    /// exactly. Drive a cold start → 1 origination → withdraw cycle
    /// and assert the gauge value follows. This is the test the
    /// soak harness's CSV would lean on if the metric ever regressed.
    #[tokio::test]
    async fn originated_routes_prometheus_gauge_tracks_inject_and_withdraw() {
        let v = vrf(100, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let mut h = Harness::new(vec![v]);

        // Mirror the originator_loop's pre-populate step. The
        // production path calls `publish_originated_gauge` (which
        // reads the live count from `originated_counts`); at this
        // point the count is 0, so the gauge lands at 0 — the
        // intended startup state. Tests drive `reconcile` directly
        // rather than entering `originator_loop`, so we have to
        // call the helper ourselves.
        let ip_vrfs = h.cfg.ip_vrfs.clone();
        publish_all_originated_gauges(&h.cfg, ip_vrfs.as_ref());
        assert_eq!(scrape_originated_gauge(&h.cfg, "vrf100"), Some(0));

        // Drive an inject: gauge → 1.
        h.status_tx.send_replace(vec![ready_status(100)]);
        let mut obs_map = HashMap::new();
        obs_map.insert(
            IpVrfId::new(100).unwrap(),
            vec![observation(100, [10, 1, 0, 0], 24)],
        );
        h.obs_tx.send_replace(Arc::new(obs_map));
        let originated = Harness::drive_one(BTreeMap::new(), &mut h.cfg).await;
        assert_eq!(originated.len(), 1);
        assert_eq!(scrape_originated_gauge(&h.cfg, "vrf100"), Some(1));

        // Drive a withdraw: gauge → 0.
        let mut empty_map = HashMap::new();
        empty_map.insert(IpVrfId::new(100).unwrap(), vec![]);
        h.obs_tx.send_replace(Arc::new(empty_map));
        let originated = Harness::drive_one(originated, &mut h.cfg).await;
        assert!(originated.is_empty());
        assert_eq!(scrape_originated_gauge(&h.cfg, "vrf100"), Some(0));
    }

    // --- ADR-0087 GW-IP overlay-index reconcile behavior ---

    /// Auto-acking RIB responder that records the full injected route
    /// (so a test can read the Gateway Address) and the withdraw keys.
    /// Replaces `cfg.rib_tx` so `reconcile`'s ack-await completes; the
    /// recorded log is read after the responder task is dropped.
    type GwResponderLog = Arc<std::sync::Mutex<Vec<RibUpdate>>>;

    fn recording_rib_responder(
        cfg: &mut SpawnConfig,
    ) -> (GwResponderLog, tokio::task::JoinHandle<()>) {
        let (tx, mut rx) = mpsc::channel::<RibUpdate>(64);
        cfg.rib_tx = tx;
        let log: GwResponderLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log2 = log.clone();
        let handle = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    RibUpdate::InjectEvpn { route, reply } => {
                        log2.lock().unwrap().push(RibUpdate::InjectEvpn {
                            route,
                            reply: oneshot::channel().0,
                        });
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::WithdrawEvpn { key, reply } => {
                        log2.lock().unwrap().push(RibUpdate::WithdrawEvpn {
                            key,
                            reply: oneshot::channel().0,
                        });
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            }
        });
        (log, handle)
    }

    fn inject_gateway_for(log: &GwResponderLog, octets: [u8; 4]) -> Vec<IpAddr> {
        log.lock()
            .unwrap()
            .iter()
            .filter_map(|m| match m {
                RibUpdate::InjectEvpn { route, .. } => match &route.route {
                    rustbgpd_wire::EvpnRoute::IpPrefix(p)
                        if matches!(p.prefix, EvpnIpPrefixValue::V4(pre) if pre.addr == Ipv4Addr::from(octets)) =>
                    {
                        Some(p.gateway)
                    }
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    fn withdraw_count(log: &GwResponderLog) -> usize {
        log.lock()
            .unwrap()
            .iter()
            .filter(|m| matches!(m, RibUpdate::WithdrawEvpn { .. }))
            .count()
    }

    /// A static route via a host on a connected tenant subnet
    /// originates with that via in the Gateway Address; the connected
    /// subnet itself stays interface-less.
    #[tokio::test]
    async fn gateway_mode_via_on_subnet_originates_with_gateway() {
        let v = gw_vrf(100, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let mut h = Harness::new(vec![v]);
        let (log, _resp) = recording_rib_responder(&mut h.cfg);

        h.status_tx.send_replace(vec![ready_status(100)]);
        let mut obs_map = HashMap::new();
        obs_map.insert(
            IpVrfId::new(100).unwrap(),
            vec![
                connected(100, [10, 1, 1, 0], 24),
                observation_via(100, [192, 168, 50, 0], 24, "10.1.1.5"),
            ],
        );
        h.obs_tx.send_replace(Arc::new(obs_map));

        let originated = Harness::drive_one(BTreeMap::new(), &mut h.cfg).await;
        assert_eq!(originated.len(), 2);

        assert_eq!(
            inject_gateway_for(&log, [192, 168, 50, 0]),
            vec!["10.1.1.5".parse::<IpAddr>().unwrap()],
            "the via-on-subnet route must carry the gateway",
        );
        assert_eq!(
            inject_gateway_for(&log, [10, 1, 1, 0]),
            vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)],
            "the connected subnet route must stay interface-less",
        );
    }

    /// A via outside every connected subnet falls back to
    /// interface-less (gateway zero).
    #[tokio::test]
    async fn gateway_mode_via_off_subnet_falls_back_to_interface_less() {
        let v = gw_vrf(100, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let mut h = Harness::new(vec![v]);
        let (log, _resp) = recording_rib_responder(&mut h.cfg);

        h.status_tx.send_replace(vec![ready_status(100)]);
        let mut obs_map = HashMap::new();
        obs_map.insert(
            IpVrfId::new(100).unwrap(),
            vec![
                connected(100, [10, 1, 1, 0], 24),
                observation_via(100, [192, 168, 50, 0], 24, "10.9.9.1"),
            ],
        );
        h.obs_tx.send_replace(Arc::new(obs_map));

        let _ = Harness::drive_one(BTreeMap::new(), &mut h.cfg).await;
        assert_eq!(
            inject_gateway_for(&log, [192, 168, 50, 0]),
            vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)],
            "off-subnet via must fall back to interface-less",
        );
    }

    /// A via change for the same prefix re-originates in place — same
    /// key, new Gateway Address — without an intermediate withdraw
    /// (ADR-0087 decision 5).
    #[tokio::test]
    async fn gateway_mode_via_change_reoriginates_in_place() {
        let v = gw_vrf(100, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let mut h = Harness::new(vec![v]);
        let (log, _resp) = recording_rib_responder(&mut h.cfg);

        h.status_tx.send_replace(vec![ready_status(100)]);
        let mut obs_map = HashMap::new();
        obs_map.insert(
            IpVrfId::new(100).unwrap(),
            vec![
                connected(100, [10, 1, 1, 0], 24),
                observation_via(100, [192, 168, 50, 0], 24, "10.1.1.5"),
            ],
        );
        h.obs_tx.send_replace(Arc::new(obs_map));
        let originated = Harness::drive_one(BTreeMap::new(), &mut h.cfg).await;
        log.lock().unwrap().clear(); // drop the cold-start injects

        let target = (
            IpVrfId::new(100).unwrap(),
            EvpnIpPrefixValue::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 168, 50, 0), 24)),
        );
        let key_before = originated.get(&target).unwrap().key;
        assert_eq!(
            originated.get(&target).unwrap().gateway,
            "10.1.1.5".parse::<IpAddr>().unwrap()
        );

        // The host moves to a new gateway on the same connected subnet.
        let mut moved = HashMap::new();
        moved.insert(
            IpVrfId::new(100).unwrap(),
            vec![
                connected(100, [10, 1, 1, 0], 24),
                observation_via(100, [192, 168, 50, 0], 24, "10.1.1.9"),
            ],
        );
        h.obs_tx.send_replace(Arc::new(moved));
        let originated = Harness::drive_one(originated, &mut h.cfg).await;

        let entry = originated.get(&target).unwrap();
        assert_eq!(
            entry.key, key_before,
            "the route key is gateway-independent and must not change",
        );
        assert_eq!(
            entry.gateway,
            "10.1.1.9".parse::<IpAddr>().unwrap(),
            "the in-place re-origination must carry the new gateway",
        );

        // Exactly one re-inject for the moved prefix, no withdraw.
        assert_eq!(
            inject_gateway_for(&log, [192, 168, 50, 0]),
            vec!["10.1.1.9".parse::<IpAddr>().unwrap()],
            "exactly one in-place re-inject with the new gateway",
        );
        assert_eq!(withdraw_count(&log), 0, "no withdraw on a via change");
        // The shared count stays at 2 (connected + moved prefix), not
        // 3 — the in-place re-inject must not double count.
        assert_eq!(h.cfg.originated_counts.count(IpVrfId::new(100).unwrap()), 2);
    }
}
