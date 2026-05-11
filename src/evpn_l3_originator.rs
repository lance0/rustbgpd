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
//!                          ip_vrf_status_rx ─► reconcile (diff want vs have)
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

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use rustbgpd_evpn::ip_vrf::{
    IpVrfStatus, LocalIpRoute, OriginationError, originate_ip_prefix_route,
};
use rustbgpd_evpn::{
    EvpnIpPrefixValue, IpVrf, IpVrfDataplaneStatus, IpVrfId, IpVrfTable, LocalIpRouteObservation,
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

/// Handle returned by [`spawn`]. Call [`Self::shutdown`] to cancel
/// the actor and wait for the drain to finish.
pub struct EvpnL3OriginatorHandle {
    shutdown: CancellationToken,
    join: tokio::task::JoinHandle<()>,
}

impl EvpnL3OriginatorHandle {
    /// Cancel the actor and wait for it to drain (mirrors
    /// [`crate::evpn_originator::EvpnOriginatorHandle::shutdown`]).
    /// Bounded to 5 s so a stuck RIB channel doesn't wedge the daemon
    /// shutdown path.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), self.join).await;
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
    let join = tokio::spawn(originator_loop(cfg));
    Some(EvpnL3OriginatorHandle { shutdown, join })
}

async fn originator_loop(mut cfg: SpawnConfig) {
    // (IpVrfId, prefix) -> EvpnRouteKey we used for the inject (so the
    // matching withdraw uses the same key).
    let mut originated: BTreeMap<(IpVrfId, EvpnIpPrefixValue), EvpnRouteKey> = BTreeMap::new();

    // Eagerly drive one reconcile so startup state aligns with whatever
    // the dataplane has already reported (the watch channels may already
    // carry a snapshot from the first reconcile pass).
    reconcile(&mut originated, &mut cfg).await;

    loop {
        tokio::select! {
            biased;
            () = cfg.shutdown.cancelled() => {
                debug!("EVPN L3 originator shutting down — draining {} routes", originated.len());
                drain_all(&mut originated, &cfg).await;
                return;
            }
            res = cfg.route_observations_rx.changed() => {
                if res.is_err() {
                    debug!("L3 originator: observation watch closed; draining");
                    drain_all(&mut originated, &cfg).await;
                    return;
                }
                reconcile(&mut originated, &mut cfg).await;
            }
            res = cfg.ip_vrf_status_rx.changed() => {
                if res.is_err() {
                    debug!("L3 originator: status watch closed; draining");
                    drain_all(&mut originated, &cfg).await;
                    return;
                }
                reconcile(&mut originated, &mut cfg).await;
            }
        }
    }
}

async fn reconcile(
    originated: &mut BTreeMap<(IpVrfId, EvpnIpPrefixValue), EvpnRouteKey>,
    cfg: &mut SpawnConfig,
) {
    // Snapshot the watch values. Both `borrow()` calls are lock-free
    // seqlock reads — the clones release the borrow before any await.
    let observations = cfg.route_observations_rx.borrow().clone();
    let status_rows = cfg.ip_vrf_status_rx.borrow().clone();
    let ready_vrfs: HashMap<IpVrfId, &IpVrf> = cfg
        .ip_vrfs
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
    for vrf in cfg.ip_vrfs.iter() {
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

    // Phase 1: withdrawals — `have - want`. Only drop the entry
    // from `originated` once the RIB has acknowledged the withdraw;
    // a transient channel/reply failure leaves the entry in place so
    // the next reconcile pass retries (level-triggered model).
    let to_withdraw: Vec<((IpVrfId, EvpnIpPrefixValue), EvpnRouteKey)> = originated
        .iter()
        .filter(|(k, _)| !want.contains_key(k))
        .map(|(k, v)| (*k, *v))
        .collect();
    for ((vrf_id, prefix), key) in to_withdraw {
        if withdraw_one(&cfg.rib_tx, vrf_id, key, &cfg.originated_counts).await {
            originated.remove(&(vrf_id, prefix));
        }
    }

    // Phase 2: injections — `want - have`. Only record the entry in
    // `originated` once the RIB has acknowledged the inject. A
    // failed inject leaves us in the "want, not yet originated"
    // state so the next pass retries with the same shape.
    for ((vrf_id, prefix), obs) in &want {
        if originated.contains_key(&(*vrf_id, *prefix)) {
            continue; // already originated
        }
        let Some(vrf) = ready_vrfs.get(vrf_id) else {
            continue; // checked above, but keep the guard for clarity
        };
        let route = match try_originate(vrf, obs) {
            Ok(r) => r,
            Err(OriginationError::FamilyMismatch { .. }) => {
                cfg.metrics.add_evpn_ip_vrf_origination_suppressed(
                    &vrf.name,
                    SUPPRESS_FAMILY_MISMATCH,
                    1,
                );
                continue;
            }
        };
        let key = route.key();
        if inject_one(&cfg.rib_tx, *vrf_id, key, route, &cfg.originated_counts).await {
            originated.insert((*vrf_id, *prefix), key);
        }
    }
}

fn try_originate(
    vrf: &IpVrf,
    obs: &LocalIpRouteObservation,
) -> Result<EvpnRibRoute, OriginationError> {
    let local = match obs.prefix {
        EvpnIpPrefixValue::V4(p) => LocalIpRoute::v4(p),
        EvpnIpPrefixValue::V6(p) => LocalIpRoute::v6(p),
    };
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
/// route and tries to withdraw it; entries whose withdraw fails stay
/// in the map but the map is dropped at task exit anyway, so this is
/// strictly observability. The bounded `EvpnL3OriginatorHandle::shutdown`
/// timeout caps how long the daemon waits.
async fn drain_all(
    originated: &mut BTreeMap<(IpVrfId, EvpnIpPrefixValue), EvpnRouteKey>,
    cfg: &SpawnConfig,
) {
    let snapshot: Vec<_> = originated.iter().map(|(k, v)| (*k, *v)).collect();
    for ((vrf_id, _prefix), key) in &snapshot {
        let _ = withdraw_one(&cfg.rib_tx, *vrf_id, *key, &cfg.originated_counts).await;
    }
    originated.clear();
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

    fn observation(vrf_id: u32, prefix_octets: [u8; 4], len: u8) -> LocalIpRouteObservation {
        LocalIpRouteObservation {
            vrf_id: IpVrfId::new(vrf_id).unwrap(),
            prefix: EvpnIpPrefixValue::V4(Ipv4Prefix::new(Ipv4Addr::from(prefix_octets), len)),
            source: RouteSource::Static,
        }
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
                            ReplyMode::Reject => Err("test rejection".to_string()),
                        };
                        let _ = reply.send(response);
                    }
                    RibUpdate::WithdrawEvpn { key, reply } => {
                        calls.push(RibCall::Withdraw(key));
                        let response = match mode.withdraw {
                            ReplyMode::Ok => Ok(()),
                            ReplyMode::Reject => Err("test rejection".to_string()),
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
            mut originated: BTreeMap<(IpVrfId, EvpnIpPrefixValue), EvpnRouteKey>,
            cfg: &mut SpawnConfig,
        ) -> BTreeMap<(IpVrfId, EvpnIpPrefixValue), EvpnRouteKey> {
            reconcile(&mut originated, cfg).await;
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
                .copied(),
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
}
