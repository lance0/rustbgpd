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
//! ## Convergence — push notification + periodic backstop
//!
//! The originator subscribes to the RIB's [`EvpnRouteEvent`] broadcast
//! (added by Gate 7c) and reacts to each best-path change synchronously,
//! driving `on_remote_changed` from the event payload's `best` field
//! directly — no follow-up `QueryEvpnRoutes` round-trip needed. The
//! 5 s `poll_tick` is retained as a backstop for two narrow cases:
//!   1. The broadcast subscriber lagged (capacity 4096 dropped events);
//!      a full repoll re-establishes the cache.
//!   2. The originator started after the RIB had already converged —
//!      the broadcast is edge-triggered and won't replay history, so
//!      the first poll is what populates `remote_view` initially.
//!
//! Self-NH filtering (skip routes whose next-hop matches our local
//! VTEP IP) is applied per-event the same way `repoll_rib` applies it
//! during a full sweep.
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

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use rustbgpd_evpn::{
    DuplicateMacAction, DuplicateMacDecision, DuplicateMacDetector, DuplicateMacKey, EvpnInstance,
    EvpnInstanceId, EvpnInstanceTable, LocalMacIpOriginator, LocalMacObservation,
    LocalMacOriginator, MacAddress, OriginationAction, ProjectedEvpnRoute, RemoteMacIpView,
    RemoteMacView, project_evpn_routes,
};
use rustbgpd_rib::{EvpnRouteEvent, RibUpdate, route::EvpnRibRoute};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    AsPath, EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, EvpnRouteKey,
    ExtendedCommunity, MplsLabel, Origin, PathAttribute,
};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Mirrors the constant used by `crates/api/src/injection_service.rs`.
/// The RIB indexes locally-injected routes under this synthetic peer
/// IP; setting `EvpnRibRoute.peer` to the same value keeps the route
/// recognizable as locally-originated downstream of the inject path.
pub(crate) const LOCAL_PEER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
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

/// Cloneable ADR-0063 runtime control surface for daemon apply
/// wiring. The full handle remains owned by coordinated shutdown.
#[derive(Clone, Debug)]
pub(crate) struct EvpnOriginatorRuntimeControl {
    model_tx: watch::Sender<Arc<OriginatorRuntimeModel>>,
}

impl EvpnOriginatorRuntimeControl {
    /// Whether the originator can still receive runtime model snapshots.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.model_tx.is_closed()
    }

    /// Replace the effective L2VNI model the originator reconciles
    /// against. ADR-0063 runtime commits publish complete snapshots;
    /// this actor drains removed/redefined VNIs before accepting the
    /// new table for future local observations and RIB-event replay.
    #[must_use]
    pub fn replace_runtime_model(
        &self,
        instances: Arc<EvpnInstanceTable>,
        vni_to_esi: Arc<std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>>,
    ) -> bool {
        if self.model_tx.is_closed() {
            return false;
        }
        self.model_tx.send_replace(Arc::new(OriginatorRuntimeModel {
            instances,
            vni_to_esi,
        }));
        true
    }
}

#[derive(Debug)]
pub struct EvpnOriginatorHandle {
    pub(crate) shutdown: CancellationToken,
    pub(crate) join: tokio::task::JoinHandle<()>,
    control: EvpnOriginatorControl,
    model_tx: watch::Sender<Arc<OriginatorRuntimeModel>>,
}

impl EvpnOriginatorHandle {
    /// Cloneable command path for bounded operator control RPCs.
    #[must_use]
    pub fn control(&self) -> EvpnOriginatorControl {
        self.control.clone()
    }

    /// Cloneable ADR-0063 runtime control surface for daemon apply
    /// wiring. The full handle remains owned by coordinated shutdown.
    #[must_use]
    pub(crate) fn runtime_control(&self) -> EvpnOriginatorRuntimeControl {
        EvpnOriginatorRuntimeControl {
            model_tx: self.model_tx.clone(),
        }
    }

    /// Replace the effective L2VNI model the originator reconciles
    /// against. ADR-0063 runtime commits publish complete snapshots;
    /// this actor drains removed/redefined VNIs before accepting the
    /// new table for future local observations and RIB-event replay.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "ADR-0063 coordinator wiring will call this command; this slice adds the actor command surface first"
        )
    )]
    #[must_use]
    pub fn replace_runtime_model(
        &self,
        instances: Arc<EvpnInstanceTable>,
        vni_to_esi: Arc<std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>>,
    ) -> bool {
        self.runtime_control()
            .replace_runtime_model(instances, vni_to_esi)
    }

    /// Cancel the actor and wait for it to drain.
    pub async fn shutdown(self) {
        let Self {
            shutdown,
            join,
            control: _,
            model_tx,
        } = self;
        shutdown.cancel();
        drop(model_tx);
        let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    }
}

/// Cloneable command handle for the EVPN originator actor.
#[derive(Clone)]
pub struct EvpnOriginatorControl {
    command_tx: mpsc::Sender<OriginatorCommand>,
}

impl std::fmt::Debug for EvpnOriginatorControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvpnOriginatorControl")
            .finish_non_exhaustive()
    }
}

impl EvpnOriginatorControl {
    /// Clear one duplicate-MAC quarantine through the actor.
    pub async fn clear_duplicate_mac_quarantine(
        &self,
        key: DuplicateMacKey,
    ) -> Result<ClearDuplicateMacQuarantineResult, EvpnOriginatorControlError> {
        let (reply, rx) = oneshot::channel();
        self.command_tx
            .send(OriginatorCommand::ClearDuplicateMacQuarantine { key, reply })
            .await
            .map_err(|_| EvpnOriginatorControlError::Closed)?;
        rx.await
            .map_err(|_| EvpnOriginatorControlError::ReplyDropped)
    }
}

/// Result of a manual duplicate-MAC quarantine clear request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearDuplicateMacQuarantineResult {
    /// An active quarantine was cleared and live local state replayed.
    Cleared,
    /// No active quarantine existed for the key.
    NotActive,
    /// The originator is running, but this VNI is not configured.
    UnknownVni,
}

/// Error returned when the originator control channel cannot complete a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvpnOriginatorControlError {
    Closed,
    ReplyDropped,
}

enum OriginatorCommand {
    ClearDuplicateMacQuarantine {
        key: DuplicateMacKey,
        reply: oneshot::Sender<ClearDuplicateMacQuarantineResult>,
    },
}

/// Per-MAC set of outstanding `EvpnRouteKey`s — one MAC may be
/// advertising multiple Type 2 NLRIs simultaneously (MAC-only +
/// MAC+IP, or multiple MAC+IP for a dual-stack host).
type MacRouteSet = BTreeMap<MacAddress, HashSet<EvpnRouteKey>>;

/// Live read-side counts of locally-originated Type 2 MAC routes
/// accepted by the RIB, keyed by VNI.
///
/// Tracks **per-`EvpnRouteKey`** rather than per-MAC so a MAC with
/// multiple live MAC+IP routes (e.g., dual-stack host with v4 and
/// v6 bindings, or a future second IP) doesn't get prematurely
/// removed from the count when only one of its `(MAC, IP)` keys
/// withdraws. `count()` returns the number of MACs with at least
/// one live key.
#[derive(Debug, Clone, Default)]
pub struct OriginatedLocalMacCounts {
    inner: Arc<RwLock<BTreeMap<EvpnInstanceId, MacRouteSet>>>,
}

impl OriginatedLocalMacCounts {
    /// Count MACs with at least one outstanding route for one VNI.
    #[must_use]
    pub fn count(&self, vni: EvpnInstanceId) -> u64 {
        self.inner
            .read()
            .expect("originated local MAC count lock poisoned")
            .get(&vni)
            .map_or(0, |per_mac| per_mac.len() as u64)
    }

    pub(crate) fn record_inject(&self, vni: EvpnInstanceId, mac: MacAddress, key: EvpnRouteKey) {
        self.inner
            .write()
            .expect("originated local MAC count lock poisoned")
            .entry(vni)
            .or_default()
            .entry(mac)
            .or_default()
            .insert(key);
    }

    pub(crate) fn record_withdraw(&self, vni: EvpnInstanceId, mac: MacAddress, key: EvpnRouteKey) {
        let mut guard = self
            .inner
            .write()
            .expect("originated local MAC count lock poisoned");
        let Some(per_mac) = guard.get_mut(&vni) else {
            return;
        };
        if let Some(keys) = per_mac.get_mut(&mac) {
            keys.remove(&key);
            if keys.is_empty() {
                per_mac.remove(&mac);
            }
        }
        if per_mac.is_empty() {
            guard.remove(&vni);
        }
    }
}

struct OriginatorRuntime {
    instances: Arc<EvpnInstanceTable>,
    model_rx: watch::Receiver<Arc<OriginatorRuntimeModel>>,
    rib_tx: mpsc::Sender<RibUpdate>,
    metrics: BgpMetrics,
    originated_local_mac_counts: OriginatedLocalMacCounts,
    shutdown: CancellationToken,
    /// Per-VNI ESI override for ESI-aware MAC origination (Gate 8b
    /// remaining slice 5 — DF-role-aware MAC origination). When a
    /// MAC is learned on a VNI that participates in a configured
    /// `[[ethernet_segments]]` block, the Type 2 NLRI's ESI field
    /// carries that segment's ESI so peers can correlate the MAC
    /// with EAD-per-EVI routes via aliasing (RFC 7432 §14). VNIs
    /// not in this map default to `EthernetSegmentIdentifier::ZERO`
    /// (single-homed CE), preserving Gate 7b+1 behavior.
    vni_to_esi: Arc<std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>>,
}

#[derive(Debug)]
struct OriginatorRuntimeModel {
    instances: Arc<EvpnInstanceTable>,
    vni_to_esi: Arc<std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>>,
}

/// Spawn the originator. Returns `None` for RR-only deployments
/// (empty `evpn_instances`).
#[allow(clippy::too_many_arguments)]
// ESI-aware origination nudged the count over the threshold; the daemon-side spawn is the only caller.
#[allow(dead_code)]
#[must_use = "call `EvpnOriginatorHandle::shutdown` to stop the originator — \
              dropping the handle leaves the task running"]
pub fn spawn(
    config: OriginatorConfig,
    evpn_instances: &Arc<EvpnInstanceTable>,
    rib_tx: mpsc::Sender<RibUpdate>,
    local_mac_rx: Option<mpsc::Receiver<LocalMacObservation>>,
    metrics: BgpMetrics,
    originated_local_mac_counts: OriginatedLocalMacCounts,
    daemon_shutdown: CancellationToken,
    vni_to_esi: Arc<std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>>,
) -> Option<EvpnOriginatorHandle> {
    let (duplicate_mac_quarantine_tx, _) = watch::channel(Arc::new(BTreeSet::new()));
    spawn_with_quarantine(
        config,
        evpn_instances,
        rib_tx,
        local_mac_rx,
        metrics,
        originated_local_mac_counts,
        daemon_shutdown,
        vni_to_esi,
        duplicate_mac_quarantine_tx,
    )
}

#[allow(clippy::too_many_arguments)]
#[must_use = "call `EvpnOriginatorHandle::shutdown` to stop the originator — \
              dropping the handle leaves the task running"]
/// Spawn the originator with an external duplicate-MAC quarantine publisher.
///
/// The publisher lets the dataplane supervisor filter remote-FDB intent for
/// active RFC 7432 section 15.1 duplicate-MAC quarantines without changing
/// RIB or route-reflector visibility.
pub fn spawn_with_quarantine(
    config: OriginatorConfig,
    evpn_instances: &Arc<EvpnInstanceTable>,
    rib_tx: mpsc::Sender<RibUpdate>,
    local_mac_rx: Option<mpsc::Receiver<LocalMacObservation>>,
    metrics: BgpMetrics,
    originated_local_mac_counts: OriginatedLocalMacCounts,
    daemon_shutdown: CancellationToken,
    vni_to_esi: Arc<std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>>,
    duplicate_mac_quarantine_tx: watch::Sender<Arc<BTreeSet<DuplicateMacKey>>>,
) -> Option<EvpnOriginatorHandle> {
    if evpn_instances.is_empty() {
        info!("no EVPN instances configured — originator not spawned (RR-only deployment)");
        return None;
    }
    let local_mac_rx = local_mac_rx?;

    let state = OriginatorState::new(evpn_instances, duplicate_mac_quarantine_tx);
    let (command_tx, command_rx) = mpsc::channel(16);
    let control = EvpnOriginatorControl { command_tx };
    let (model_tx, model_rx) = watch::channel(Arc::new(OriginatorRuntimeModel {
        instances: evpn_instances.clone(),
        vni_to_esi: vni_to_esi.clone(),
    }));

    let shutdown = daemon_shutdown;
    let runtime = OriginatorRuntime {
        instances: evpn_instances.clone(),
        model_rx,
        rib_tx,
        metrics,
        originated_local_mac_counts,
        shutdown: shutdown.clone(),
        vni_to_esi,
    };
    let join = tokio::spawn(originator_loop(
        config,
        runtime,
        local_mac_rx,
        command_rx,
        state,
    ));

    Some(EvpnOriginatorHandle {
        shutdown,
        join,
        control,
        model_tx,
    })
}

/// Cached snapshot of the best-path *non-self* remote Type 2 view per
/// `(VNI, MAC)`, derived by polling the RIB. Diffs against the prior
/// snapshot drive `on_remote_changed` callbacks.
type RemoteMacViewMap = BTreeMap<(EvpnInstanceId, MacAddress), RemoteMacView>;

/// Same shape as [`RemoteMacViewMap`] but for MAC+IP Type 2 routes —
/// keyed by `(VNI, MAC, IP)` because RFC 9135 §7.2.3 makes MAC-only
/// and MAC+IP independent advertisements with their own contention
/// resolution. The daemon builds both maps from the same
/// `query_evpn_routes` snapshot during repoll.
type RemoteMacIpViewMap = BTreeMap<(EvpnInstanceId, MacAddress, IpAddr), RemoteMacIpView>;

/// Per-daemon-task bundle of MAC + MAC+IP originator state.
///
/// Slice 3 (Gate 7b+2) added the MAC+IP path. The earlier
/// `originators: BTreeMap<EvpnInstanceId, LocalMacOriginator>` argument
/// got bundled here alongside its MAC+IP sibling, the local-FDB
/// presence cache, the pending-IP-bindings cache, and the live
/// `(MAC, IP)` cache. Bundling avoids threading 7+ params through
/// every handler.
struct OriginatorState {
    /// MAC-only origination state, one per VNI.
    mac_originators: BTreeMap<EvpnInstanceId, LocalMacOriginator>,
    /// MAC+IP origination state, one per VNI. Pairs with
    /// `mac_originators` — the daemon coordinates which originator is
    /// "current" for each MAC under the FRR-style replace model.
    mac_ip_originators: BTreeMap<EvpnInstanceId, LocalMacIpOriginator>,
    /// Per-VNI: MACs currently locally learned, with their last-seen
    /// bridge-port ifindex. The ifindex is retained so a downgrade
    /// from MAC+IP back to MAC-only can replay it into
    /// `LocalMacOriginator::on_local_learned` — without it the
    /// originator's port-move detection would see a synthetic
    /// `0 → real_ifindex` transition the next time a real port
    /// change came in.
    local_macs: BTreeMap<EvpnInstanceId, BTreeMap<MacAddress, u32>>,
    /// Per-`(VNI, MAC)`: IPs observed via ARP/ND on a bridge whose
    /// MAC has not yet appeared in the `AF_BRIDGE` FDB feed. Kernel
    /// can reorder the two edges (e.g., bridge FDB repopulating
    /// while the ARP table already holds entries from before
    /// `neigh_suppress` flipped on). Drained on `Learned`.
    pending_ip_bindings: BTreeMap<(EvpnInstanceId, MacAddress), BTreeSet<IpAddr>>,
    /// Per-VNI live `(MAC, IP)` bindings learned from the kernel. This
    /// survives local-origin suppression so timed recovery can replay
    /// the still-live bindings after quarantine expires.
    live_mac_ip: BTreeMap<EvpnInstanceId, BTreeMap<MacAddress, BTreeSet<IpAddr>>>,
    /// Cached MAC-only contender map.
    remote_mac_view: RemoteMacViewMap,
    /// Cached MAC+IP contender map.
    remote_mac_ip_view: RemoteMacIpViewMap,
    /// RFC 7432 §15.1 duplicate-MAC detector. The pure detector owns
    /// the M/N window and active suppressions; this daemon state owns
    /// the route-withdraw/replay policy.
    duplicate_mac_detector: DuplicateMacDetector,
    /// Keys ever inserted into [`Self::duplicate_mac_detector`] and not
    /// later explicitly cleared. The detector intentionally hides its
    /// window map, so the daemon tracks keys here to purge all stale
    /// per-VNI move history when a runtime model removes/redefines a
    /// VNI.
    known_duplicate_mac_keys: BTreeSet<DuplicateMacKey>,
    /// Active duplicate-MAC quarantine keys published to the EVPN
    /// dataplane supervisor. The supervisor filters these keys out of
    /// remote-FDB intent while leaving Loc-RIB/RR visibility intact.
    active_duplicate_mac_quarantines: BTreeSet<DuplicateMacKey>,
    duplicate_mac_quarantine_tx: watch::Sender<Arc<BTreeSet<DuplicateMacKey>>>,
}

impl OriginatorState {
    /// Build a fresh state bundle for a given instance set.
    fn new(
        instances: &EvpnInstanceTable,
        duplicate_mac_quarantine_tx: watch::Sender<Arc<BTreeSet<DuplicateMacKey>>>,
    ) -> Self {
        let mut mac_originators = BTreeMap::new();
        let mut mac_ip_originators = BTreeMap::new();
        for inst in instances.iter() {
            mac_originators.insert(inst.id, LocalMacOriginator::new(inst.id, inst.rd));
            mac_ip_originators.insert(inst.id, LocalMacIpOriginator::new(inst.id, inst.rd));
        }
        Self {
            mac_originators,
            mac_ip_originators,
            local_macs: BTreeMap::new(),
            pending_ip_bindings: BTreeMap::new(),
            live_mac_ip: BTreeMap::new(),
            remote_mac_view: BTreeMap::new(),
            remote_mac_ip_view: BTreeMap::new(),
            duplicate_mac_detector: DuplicateMacDetector::default(),
            known_duplicate_mac_keys: BTreeSet::new(),
            active_duplicate_mac_quarantines: BTreeSet::new(),
            duplicate_mac_quarantine_tx,
        }
    }

    /// Whether this MAC currently has any MAC+IP route advertising.
    fn is_mac_ip_advertising(&self, vni: EvpnInstanceId, mac: MacAddress) -> bool {
        self.mac_ip_originators
            .get(&vni)
            .is_some_and(|orig| orig.outstanding_keys().any(|(k, _)| k.mac == mac))
    }

    /// Whether the kernel still reports any live `(MAC, IP)` binding
    /// for this MAC. This is intentionally broader than
    /// [`Self::is_mac_ip_advertising`]: quarantine can withdraw the
    /// advertised routes while preserving live bindings for timed
    /// replay, and a re-learned MAC must not emit MAC-only while those
    /// bindings are waiting for recovery.
    fn has_live_mac_ip_bindings(&self, vni: EvpnInstanceId, mac: MacAddress) -> bool {
        self.live_mac_ip
            .get(&vni)
            .and_then(|per_vni| per_vni.get(&mac))
            .is_some_and(|ips| !ips.is_empty())
    }
}

#[allow(clippy::too_many_lines)] // The actor select keeps shutdown, local observations, RIB events, and poll recovery together.
async fn originator_loop(
    config: OriginatorConfig,
    mut runtime: OriginatorRuntime,
    mut local_mac_rx: mpsc::Receiver<LocalMacObservation>,
    mut command_rx: mpsc::Receiver<OriginatorCommand>,
    mut state: OriginatorState,
) {
    let mut poll_tick = tokio::time::interval(config.poll_interval);
    poll_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut local_mac_rx_open = true;
    let mut command_rx_open = true;
    let mut model_rx_open = true;

    // Subscribe to the RIB's EVPN best-path broadcast. A failure here
    // is non-fatal: the 5 s poll fallback is the same convergence
    // mechanism that ran before Gate 7c, so the originator stays
    // correct (just slower) without the broadcast.
    let mut evpn_event_rx = subscribe_evpn_events(&runtime.rib_tx).await;
    if evpn_event_rx.is_none() {
        warn!(
            "EVPN originator: failed to subscribe to RIB event broadcast; running in poll-only mode"
        );
    }

    loop {
        tokio::select! {
            biased;
            () = runtime.shutdown.cancelled() => {
                debug!("EVPN originator shutting down");
                drain_to_withdraws(
                    &mut state,
                    &runtime.instances,
                    &runtime.rib_tx,
                    &runtime.metrics,
                    &runtime.originated_local_mac_counts,
                    &runtime.vni_to_esi,
                ).await;
                return;
            }
            cmd = command_rx.recv(), if command_rx_open => match cmd {
                Some(cmd) => {
                    handle_originator_command(
                        cmd,
                        &mut state,
                        &runtime.instances,
                        &runtime.rib_tx,
                        &runtime.metrics,
                        &runtime.originated_local_mac_counts,
                        &runtime.vni_to_esi,
                    ).await;
                }
                None => {
                    command_rx_open = false;
                }
            },
            changed = runtime.model_rx.changed(), if model_rx_open => {
                if changed.is_err() {
                    debug!("EVPN originator: runtime model watch closed; continuing with current model");
                    model_rx_open = false;
                    continue;
                }
                let model = runtime.model_rx.borrow_and_update().clone();
                apply_runtime_model(model, &mut state, &mut runtime).await;
            }
            obs = local_mac_rx.recv(), if local_mac_rx_open => {
                let Some(obs) = obs else {
                    debug!("local-mac channel closed; originator idle");
                    // Don't exit — RIB polls and operator control still matter
                    // for telemetry and already-learned quarantine state.
                    local_mac_rx_open = false;
                    continue;
                };
                handle_observation(
                    &obs,
                    &mut state,
                    &runtime.instances,
                    &runtime.rib_tx,
                    &runtime.metrics,
                    &runtime.originated_local_mac_counts,
                    &runtime.vni_to_esi,
                ).await;
            }
            event = recv_evpn_event(&mut evpn_event_rx) => match event {
                Ok(ev) => {
                    handle_evpn_event(
                        &ev,
                        &runtime.instances,
                        &mut state,
                        &runtime.rib_tx,
                        &runtime.metrics,
                        &runtime.originated_local_mac_counts,
                        &runtime.vni_to_esi,
                    ).await;
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(
                        skipped,
                        "EVPN originator: event broadcast lagged; falling back to full repoll"
                    );
                    if let Err(e) = repoll_rib(
                        &runtime.instances,
                        &runtime.rib_tx,
                        &mut state,
                        &runtime.metrics,
                        &runtime.originated_local_mac_counts,
                        &runtime.vni_to_esi,
                    ).await {
                        warn!(error = %e, "EVPN originator: lag-recovery repoll failed");
                    }
                }
                Err(broadcast::error::RecvError::Closed) => {
                    warn!("EVPN originator: RIB event broadcast closed; reverting to poll-only");
                    evpn_event_rx = None;
                }
            },
            _ = poll_tick.tick() => {
                recover_duplicate_macs(
                    &mut state,
                    &runtime.instances,
                    &runtime.rib_tx,
                    &runtime.metrics,
                    &runtime.originated_local_mac_counts,
                    &runtime.vni_to_esi,
                ).await;
                if let Err(e) = repoll_rib(
                    &runtime.instances,
                    &runtime.rib_tx,
                    &mut state,
                    &runtime.metrics,
                    &runtime.originated_local_mac_counts,
                    &runtime.vni_to_esi,
                ).await {
                    warn!(error = %e, "EVPN originator: RIB poll failed");
                }
            }
        }
    }
}

/// Subscribe to the RIB's EVPN route-event broadcast. Returns `None`
/// if the RIB channel is full / closed or if the reply was dropped —
/// the originator's 5 s poll backstop covers both cases.
async fn subscribe_evpn_events(
    rib_tx: &mpsc::Sender<RibUpdate>,
) -> Option<broadcast::Receiver<EvpnRouteEvent>> {
    let (reply_tx, reply_rx) = oneshot::channel();
    rib_tx
        .send(RibUpdate::SubscribeEvpnRouteEvents { reply: reply_tx })
        .await
        .ok()?;
    reply_rx.await.ok()
}

/// Receive next event, or park forever if we never got a subscription
/// (poll-only mode). Parking on `pending` lets the surrounding
/// `tokio::select!` continue to service the other arms.
async fn recv_evpn_event(
    rx: &mut Option<broadcast::Receiver<EvpnRouteEvent>>,
) -> Result<EvpnRouteEvent, broadcast::error::RecvError> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// Per-VNI local MACs to replay after an ESI-map-only change.
type LocalMacReplaySet = BTreeMap<EvpnInstanceId, BTreeSet<MacAddress>>;

async fn apply_runtime_model(
    model: Arc<OriginatorRuntimeModel>,
    state: &mut OriginatorState,
    runtime: &mut OriginatorRuntime,
) {
    // Classify currently-known VNIs against the candidate model:
    //  - removed or redefined (instance gone / content changed): full
    //    drain + state clear, the same as a delete.
    //  - ESI-map changed only (instance identical, vni_to_esi differs):
    //    drain the stale routes but preserve and replay the cached local
    //    MAC/IP state so it re-originates under the new ESI instead of
    //    disappearing until the next kernel local-MAC event.
    let mut removed_or_redefined: Vec<EvpnInstanceId> = Vec::new();
    let mut esi_only_changed: Vec<EvpnInstanceId> = Vec::new();
    for old in runtime.instances.iter() {
        match model.instances.get(old.id) {
            Some(next) if next == old => {
                if runtime.vni_to_esi.get(&old.id) != model.vni_to_esi.get(&old.id) {
                    esi_only_changed.push(old.id);
                }
            }
            _ => removed_or_redefined.push(old.id),
        }
    }

    // Snapshot replay keys before the drain clears each advertised route.
    // ESI-only changes intentionally keep the local observation caches,
    // pending IP bindings, remote views, and duplicate-MAC quarantine
    // state. Only delete/redefine may use the full VNI state purge below.
    let mut replay_local_macs: LocalMacReplaySet = BTreeMap::new();
    for &vni in &esi_only_changed {
        let macs = state
            .local_macs
            .get(&vni)
            .map(|per_vni| per_vni.keys().copied().collect())
            .unwrap_or_default();
        replay_local_macs.insert(vni, macs);
    }

    for vni in removed_or_redefined.iter().copied() {
        drain_vni_to_withdraws(
            state,
            runtime.instances.as_ref(),
            vni,
            &runtime.rib_tx,
            &runtime.metrics,
            &runtime.originated_local_mac_counts,
            runtime.vni_to_esi.as_ref(),
        )
        .await;
        remove_vni_state(state, vni, &runtime.metrics);
    }
    for vni in esi_only_changed.iter().copied() {
        drain_vni_to_withdraws(
            state,
            runtime.instances.as_ref(),
            vni,
            &runtime.rib_tx,
            &runtime.metrics,
            &runtime.originated_local_mac_counts,
            runtime.vni_to_esi.as_ref(),
        )
        .await;
    }

    for inst in model.instances.iter() {
        state
            .mac_originators
            .entry(inst.id)
            .or_insert_with(|| LocalMacOriginator::new(inst.id, inst.rd));
        state
            .mac_ip_originators
            .entry(inst.id)
            .or_insert_with(|| LocalMacIpOriginator::new(inst.id, inst.rd));
    }

    runtime.instances = model.instances.clone();
    runtime.vni_to_esi = model.vni_to_esi.clone();

    if let Err(e) = repoll_rib(
        runtime.instances.as_ref(),
        &runtime.rib_tx,
        state,
        &runtime.metrics,
        &runtime.originated_local_mac_counts,
        runtime.vni_to_esi.as_ref(),
    )
    .await
    {
        warn!(error = %e, "EVPN originator: runtime model repoll failed");
    }

    // Replay the preserved local MAC/IP state under the new ESI map. This
    // runs after `repoll_rib` so the remote contender view is current and
    // mobility sequencing is correct. Without this, an ESI-map change would
    // withdraw the member VNI's local Type 2 routes and never re-originate
    // them until the next kernel local-MAC event.
    for (vni, macs) in replay_local_macs {
        for mac in macs {
            if duplicate_mac_is_quarantined(state, vni, mac) {
                debug!(
                    ?vni,
                    ?mac,
                    "EVPN originator: preserving duplicate-MAC suppression across ESI-map change"
                );
                continue;
            }
            replay_local_mac_after_recovery(
                vni,
                mac,
                state,
                runtime.instances.as_ref(),
                &runtime.rib_tx,
                &runtime.metrics,
                &runtime.originated_local_mac_counts,
                runtime.vni_to_esi.as_ref(),
            )
            .await;
        }
    }
}

fn remove_vni_state(state: &mut OriginatorState, vni: EvpnInstanceId, metrics: &BgpMetrics) {
    state.mac_originators.remove(&vni);
    state.mac_ip_originators.remove(&vni);
    state.local_macs.remove(&vni);
    state.live_mac_ip.remove(&vni);
    state
        .pending_ip_bindings
        .retain(|(binding_vni, _), _| *binding_vni != vni);
    state
        .remote_mac_view
        .retain(|(route_vni, _), _| *route_vni != vni);
    state
        .remote_mac_ip_view
        .retain(|(route_vni, _, _), _| *route_vni != vni);

    let removed_duplicate_mac_keys: Vec<DuplicateMacKey> = state
        .known_duplicate_mac_keys
        .iter()
        .copied()
        .filter(|key| key.vni == vni)
        .collect();
    for key in removed_duplicate_mac_keys {
        state.duplicate_mac_detector.clear(key);
        state.known_duplicate_mac_keys.remove(&key);
        if state.active_duplicate_mac_quarantines.remove(&key) {
            metrics.set_evpn_duplicate_mac_quarantine_active(
                key.vni.as_u32(),
                &key.mac.to_string(),
                false,
            );
        }
    }
    publish_duplicate_mac_quarantines(
        &state.duplicate_mac_quarantine_tx,
        &state.active_duplicate_mac_quarantines,
    );
}

#[allow(clippy::too_many_arguments)]
async fn handle_originator_command(
    command: OriginatorCommand,
    state: &mut OriginatorState,
    instances: &EvpnInstanceTable,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    match command {
        OriginatorCommand::ClearDuplicateMacQuarantine { key, reply } => {
            let result = clear_duplicate_mac_quarantine(
                key,
                state,
                instances,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
            let _ = reply.send(result);
        }
    }
}

/// Dispatch a single observation from the kernel observation feed.
///
/// Implements the FRR-style **replace model** for MAC vs MAC+IP
/// (Gate 7b+2): at any time at most one of `(MAC-only, MAC+IP)` is
/// advertising for a given MAC. Receiving an `IpAdded` for a MAC
/// that's currently MAC-only-advertising **withdraws** the MAC-only
/// route and emits a MAC+IP route in its place. Receiving the last
/// `IpRemoved` for a MAC drops it back to MAC-only.
///
/// See `docs/RFC_NOTES.md` for the RFC 9135 §7.2.3 framing and the
/// FRR mailing-list bugs that motivated this model.
async fn handle_observation(
    obs: &LocalMacObservation,
    state: &mut OriginatorState,
    instances: &Arc<EvpnInstanceTable>,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    match *obs {
        LocalMacObservation::Learned { vni, mac, ifindex } => {
            handle_learned(
                vni,
                mac,
                ifindex,
                state,
                instances,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
        }
        LocalMacObservation::Aged { vni, mac } => {
            handle_aged(
                vni,
                mac,
                state,
                instances,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
        }
        LocalMacObservation::IpAdded { vni, mac, ip } => {
            handle_ip_added(
                vni,
                mac,
                ip,
                state,
                instances,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
        }
        LocalMacObservation::IpRemoved { vni, mac, ip } => {
            handle_ip_removed(
                vni,
                mac,
                ip,
                state,
                instances,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
        }
    }
}

/// Resolve the sticky bit for `(vni, mac)` per ADR-0056. Returns
/// `false` if the instance is unknown — caller treats that as the
/// safe default.
fn sticky_for(instances: &EvpnInstanceTable, vni: EvpnInstanceId, mac: MacAddress) -> bool {
    instances
        .get(vni)
        .is_some_and(|inst| inst.sticky_macs.contains(&mac))
}

fn duplicate_action_label(action: DuplicateMacAction) -> &'static str {
    match action {
        DuplicateMacAction::DetectOnly => "detect",
        DuplicateMacAction::SuppressLocal => "suppress_local",
    }
}

fn duplicate_mac_is_quarantined(
    state: &OriginatorState,
    vni: EvpnInstanceId,
    mac: MacAddress,
) -> bool {
    state
        .duplicate_mac_detector
        .is_quarantined(DuplicateMacKey::new(vni, mac), Instant::now())
}

fn remote_route_processing_suppressed(
    state: &OriginatorState,
    vni: EvpnInstanceId,
    mac: MacAddress,
) -> bool {
    if !duplicate_mac_is_quarantined(state, vni, mac) {
        return false;
    }
    debug!(
        ?vni,
        ?mac,
        "EVPN duplicate-MAC quarantine suppresses remote route-processing diff"
    );
    true
}

fn publish_duplicate_mac_quarantines(
    tx: &watch::Sender<Arc<BTreeSet<DuplicateMacKey>>>,
    active: &BTreeSet<DuplicateMacKey>,
) {
    tx.send_replace(Arc::new(active.clone()));
}

fn set_duplicate_mac_quarantine_active(
    state: &mut OriginatorState,
    key: DuplicateMacKey,
    active: bool,
) {
    let changed = if active {
        state.active_duplicate_mac_quarantines.insert(key)
    } else {
        state.active_duplicate_mac_quarantines.remove(&key)
    };
    if changed {
        publish_duplicate_mac_quarantines(
            &state.duplicate_mac_quarantine_tx,
            &state.active_duplicate_mac_quarantines,
        );
    }
}

fn outstanding_route_keys_for_mac(
    state: &OriginatorState,
    vni: EvpnInstanceId,
    mac: MacAddress,
) -> Vec<EvpnRouteKey> {
    let mut keys = Vec::new();
    if let Some(orig) = state.mac_originators.get(&vni) {
        keys.extend(
            orig.outstanding_keys()
                .filter_map(|(m, key)| (m == mac).then_some(key)),
        );
    }
    if let Some(orig) = state.mac_ip_originators.get(&vni) {
        keys.extend(
            orig.outstanding_keys()
                .filter_map(|(k, key)| (k.mac == mac).then_some(key)),
        );
    }
    keys
}

fn record_duplicate_mac_move(
    metrics: &BgpMetrics,
    state: &mut OriginatorState,
    inst: &EvpnInstance,
    vni: EvpnInstanceId,
    mac: MacAddress,
) -> bool {
    metrics.record_evpn_duplicate_mac_move(vni.as_u32(), &mac.to_string());
    let config = inst.duplicate_mac_detection;
    let now = Instant::now();
    let key = DuplicateMacKey::new(vni, mac);
    state.known_duplicate_mac_keys.insert(key);
    if state.duplicate_mac_detector.expire_key(key, now) {
        metrics.set_evpn_duplicate_mac_quarantine_active(vni.as_u32(), &mac.to_string(), false);
        set_duplicate_mac_quarantine_active(state, key, false);
    }
    match state.duplicate_mac_detector.record_move(key, now, config) {
        DuplicateMacDecision::Recorded { .. } => false,
        DuplicateMacDecision::ThresholdExceeded { window_count } => {
            metrics.record_evpn_duplicate_mac_threshold_exceeded(
                vni.as_u32(),
                &mac.to_string(),
                duplicate_action_label(config.action),
            );
            warn!(
                ?vni,
                ?mac,
                window_count,
                threshold = config.threshold,
                window_seconds = config.window.as_secs(),
                "EVPN duplicate-MAC threshold exceeded; action is detect-only"
            );
            false
        }
        DuplicateMacDecision::Quarantined {
            window_count,
            until,
        } => {
            metrics.record_evpn_duplicate_mac_threshold_exceeded(
                vni.as_u32(),
                &mac.to_string(),
                duplicate_action_label(config.action),
            );
            metrics.set_evpn_duplicate_mac_quarantine_active(vni.as_u32(), &mac.to_string(), true);
            set_duplicate_mac_quarantine_active(state, key, true);
            warn!(
                ?vni,
                ?mac,
                window_count,
                threshold = config.threshold,
                window_seconds = config.window.as_secs(),
                recovery_seconds = config.recovery.as_secs(),
                ?until,
                "EVPN duplicate-MAC local-origin suppression active"
            );
            true
        }
        DuplicateMacDecision::AlreadyQuarantined { .. } => true,
    }
}

#[allow(clippy::too_many_arguments)]
async fn apply_actions_with_duplicate_policy(
    actions: Vec<OriginationAction>,
    view_present: bool,
    preexisting_keys: Vec<EvpnRouteKey>,
    vni: EvpnInstanceId,
    mac: MacAddress,
    state: &mut OriginatorState,
    inst: &EvpnInstance,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    if view_present
        && !actions.is_empty()
        && record_duplicate_mac_move(metrics, state, inst, vni, mac)
    {
        suppress_local_originations_for_mac(
            vni,
            mac,
            state,
            inst,
            Some(preexisting_keys),
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
        return;
    }
    apply_actions(
        actions,
        inst,
        rib_tx,
        metrics,
        originated_local_mac_counts,
        vni_to_esi,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn suppress_local_originations_for_mac(
    vni: EvpnInstanceId,
    mac: MacAddress,
    state: &mut OriginatorState,
    inst: &EvpnInstance,
    withdraw_keys: Option<Vec<EvpnRouteKey>>,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    let mut actions = Vec::new();
    if let Some(mac_ip_orig) = state.mac_ip_originators.get_mut(&vni) {
        actions.extend(mac_ip_orig.on_local_mac_aged(mac));
    }
    if let Some(mac_orig) = state.mac_originators.get_mut(&vni) {
        actions.extend(mac_orig.on_local_aged(mac));
    }
    if let Some(keys) = withdraw_keys {
        actions.retain(|action| match action {
            OriginationAction::Withdraw { key, .. } => keys.contains(key),
            OriginationAction::Inject { .. } => false,
        });
    }
    if actions.is_empty() {
        return;
    }
    apply_actions(
        actions,
        inst,
        rib_tx,
        metrics,
        originated_local_mac_counts,
        vni_to_esi,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn recover_duplicate_macs(
    state: &mut OriginatorState,
    instances: &EvpnInstanceTable,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    let recovered = state.duplicate_mac_detector.expire(Instant::now());
    for key in recovered {
        state.known_duplicate_mac_keys.remove(&key);
        metrics.set_evpn_duplicate_mac_quarantine_active(
            key.vni.as_u32(),
            &key.mac.to_string(),
            false,
        );
        set_duplicate_mac_quarantine_active(state, key, false);
        info!(
            vni = ?key.vni,
            mac = ?key.mac,
            "EVPN duplicate-MAC local-origin suppression recovered"
        );
        replay_local_mac_after_recovery(
            key.vni,
            key.mac,
            state,
            instances,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn clear_duplicate_mac_quarantine(
    key: DuplicateMacKey,
    state: &mut OriginatorState,
    instances: &EvpnInstanceTable,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) -> ClearDuplicateMacQuarantineResult {
    if instances.get(key.vni).is_none() {
        return ClearDuplicateMacQuarantineResult::UnknownVni;
    }

    let was_active = state.active_duplicate_mac_quarantines.contains(&key);
    let had_state = state.duplicate_mac_detector.clear(key);
    if had_state {
        state.known_duplicate_mac_keys.remove(&key);
    }
    if !was_active {
        if had_state {
            debug!(
                vni = ?key.vni,
                mac = ?key.mac,
                "EVPN duplicate-MAC manual clear removed inactive move-window state"
            );
        }
        return ClearDuplicateMacQuarantineResult::NotActive;
    }

    metrics.set_evpn_duplicate_mac_quarantine_active(key.vni.as_u32(), &key.mac.to_string(), false);
    set_duplicate_mac_quarantine_active(state, key, false);
    info!(
        vni = ?key.vni,
        mac = ?key.mac,
        "EVPN duplicate-MAC local-origin suppression manually cleared"
    );
    replay_local_mac_after_recovery(
        key.vni,
        key.mac,
        state,
        instances,
        rib_tx,
        metrics,
        originated_local_mac_counts,
        vni_to_esi,
    )
    .await;
    ClearDuplicateMacQuarantineResult::Cleared
}

#[allow(clippy::too_many_arguments)]
async fn replay_local_mac_after_recovery(
    vni: EvpnInstanceId,
    mac: MacAddress,
    state: &mut OriginatorState,
    instances: &EvpnInstanceTable,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    let Some(inst) = instances.get(vni) else {
        return;
    };
    let Some(ifindex) = state
        .local_macs
        .get(&vni)
        .and_then(|m| m.get(&mac).copied())
    else {
        return;
    };
    let sticky = sticky_for(instances, vni, mac);
    let live_ips: Vec<IpAddr> = state
        .live_mac_ip
        .get(&vni)
        .and_then(|m| m.get(&mac))
        .map(|ips| ips.iter().copied().collect())
        .unwrap_or_default();
    if live_ips.is_empty() {
        let Some(orig) = state.mac_originators.get_mut(&vni) else {
            return;
        };
        let view = state.remote_mac_view.get(&(vni, mac));
        let actions = orig.on_local_learned(mac, ifindex, sticky, view);
        apply_actions(
            actions,
            inst,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
        return;
    }
    let Some(orig) = state.mac_ip_originators.get_mut(&vni) else {
        return;
    };
    for ip in live_ips {
        let view = state.remote_mac_ip_view.get(&(vni, mac, ip));
        let actions = orig.on_local_ip_learned(mac, ip, sticky, view);
        apply_actions(
            actions,
            inst,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn handle_learned(
    vni: EvpnInstanceId,
    mac: MacAddress,
    ifindex: u32,
    state: &mut OriginatorState,
    instances: &Arc<EvpnInstanceTable>,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    let Some(inst) = instances.get(vni) else {
        debug!(?vni, ?mac, "Learned for unknown VNI — dropping");
        return;
    };
    state
        .local_macs
        .entry(vni)
        .or_default()
        .insert(mac, ifindex);
    let sticky = sticky_for(instances, vni, mac);

    // Drain any pending IP bindings for this MAC. Their presence
    // bypasses the MAC-only inject — we go straight to MAC+IP per
    // the FRR replace model.
    let pending_ips: Vec<IpAddr> = state
        .pending_ip_bindings
        .remove(&(vni, mac))
        .map(|s| s.into_iter().collect())
        .unwrap_or_default();
    let quarantined = duplicate_mac_is_quarantined(state, vni, mac);

    if pending_ips.is_empty() {
        // No IP bindings yet. Two sub-cases:
        //
        //   1. MAC was previously MAC-only (or never advertised) —
        //      re-emit MAC-only via the originator. `on_local_learned`
        //      is idempotent on identity and handles the port-move
        //      ratchet bump if `ifindex` differs from the prior call.
        //   2. MAC is currently MAC+IP-advertising. The kernel re-emit
        //      is just AF_BRIDGE FDB churn; emitting a MAC-only Inject would
        //      re-introduce the route the IpAdded handler explicitly
        //      withdrew, breaking the replace invariant ("at any time
        //      at most one of {MAC-only, MAC+IP} is advertising").
        //      The `local_macs[vni][mac] = ifindex` update above is
        //      what matters — a future downgrade replays it.
        if state.is_mac_ip_advertising(vni, mac) || state.has_live_mac_ip_bindings(vni, mac) {
            return;
        }
        if quarantined {
            suppress_local_originations_for_mac(
                vni,
                mac,
                state,
                inst,
                None,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
            return;
        }
        let preexisting_keys = outstanding_route_keys_for_mac(state, vni, mac);
        let Some(orig) = state.mac_originators.get_mut(&vni) else {
            return;
        };
        let view = state.remote_mac_view.get(&(vni, mac));
        let actions = orig.on_local_learned(mac, ifindex, sticky, view);
        apply_actions_with_duplicate_policy(
            actions,
            view.is_some(),
            preexisting_keys,
            vni,
            mac,
            state,
            inst,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
    } else {
        if quarantined {
            for ip in pending_ips {
                state
                    .live_mac_ip
                    .entry(vni)
                    .or_default()
                    .entry(mac)
                    .or_default()
                    .insert(ip);
            }
            suppress_local_originations_for_mac(
                vni,
                mac,
                state,
                inst,
                None,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
            return;
        }
        // Pending IPs exist — go straight to MAC+IP. Drop any stale
        // MAC-only from the originator state (idempotent if we never
        // advertised MAC-only).
        let Some(mac_orig) = state.mac_originators.get_mut(&vni) else {
            return;
        };
        let mac_only_actions = mac_orig.on_local_aged(mac);
        apply_actions(
            mac_only_actions,
            inst,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;

        for ip in pending_ips {
            if duplicate_mac_is_quarantined(state, vni, mac) {
                state
                    .live_mac_ip
                    .entry(vni)
                    .or_default()
                    .entry(mac)
                    .or_default()
                    .insert(ip);
                continue;
            }
            let view_present = state.remote_mac_ip_view.contains_key(&(vni, mac, ip));
            let preexisting_keys = outstanding_route_keys_for_mac(state, vni, mac);
            let actions = {
                let view = state.remote_mac_ip_view.get(&(vni, mac, ip));
                let Some(mac_ip_orig) = state.mac_ip_originators.get_mut(&vni) else {
                    return;
                };
                mac_ip_orig.on_local_ip_learned(mac, ip, sticky, view)
            };
            apply_actions_with_duplicate_policy(
                actions,
                view_present,
                preexisting_keys,
                vni,
                mac,
                state,
                inst,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
            state
                .live_mac_ip
                .entry(vni)
                .or_default()
                .entry(mac)
                .or_default()
                .insert(ip);
        }
    }
}

#[allow(clippy::too_many_arguments)] // ESI-aware origination nudged the count over the threshold; refactoring to a context struct is a separate slice.
async fn handle_aged(
    vni: EvpnInstanceId,
    mac: MacAddress,
    state: &mut OriginatorState,
    instances: &Arc<EvpnInstanceTable>,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    let Some(inst) = instances.get(vni) else {
        return;
    };
    if let Some(per_vni) = state.local_macs.get_mut(&vni) {
        per_vni.remove(&mac);
    }
    state.pending_ip_bindings.remove(&(vni, mac));
    if let Some(per_vni) = state.live_mac_ip.get_mut(&vni) {
        per_vni.remove(&mac);
    }

    // Withdraw both MAC-only and any MAC+IP routes for this MAC.
    // At most one set is non-empty under the replace model, but
    // cascading both is safe (each emits empty if not advertising).
    if let Some(mac_orig) = state.mac_originators.get_mut(&vni) {
        let actions = mac_orig.on_local_aged(mac);
        apply_actions(
            actions,
            inst,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
    }
    if let Some(mac_ip_orig) = state.mac_ip_originators.get_mut(&vni) {
        let actions = mac_ip_orig.on_local_mac_aged(mac);
        apply_actions(
            actions,
            inst,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_ip_added(
    vni: EvpnInstanceId,
    mac: MacAddress,
    ip: IpAddr,
    state: &mut OriginatorState,
    instances: &Arc<EvpnInstanceTable>,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    let Some(inst) = instances.get(vni) else {
        return;
    };
    let mac_is_local = state
        .local_macs
        .get(&vni)
        .is_some_and(|m| m.contains_key(&mac));
    if !mac_is_local {
        // Park until the MAC surfaces. AF_INET / AF_INET6 NEIGH
        // can race AF_BRIDGE FDB during cold start.
        debug!(
            ?vni,
            ?mac,
            ?ip,
            "IpAdded for MAC not yet locally learned — parking in pending_ip_bindings"
        );
        state
            .pending_ip_bindings
            .entry((vni, mac))
            .or_default()
            .insert(ip);
        return;
    }

    let sticky = sticky_for(instances, vni, mac);
    let was_mac_only = !state.is_mac_ip_advertising(vni, mac);
    if duplicate_mac_is_quarantined(state, vni, mac) {
        state
            .live_mac_ip
            .entry(vni)
            .or_default()
            .entry(mac)
            .or_default()
            .insert(ip);
        suppress_local_originations_for_mac(
            vni,
            mac,
            state,
            inst,
            None,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
        return;
    }

    // Replace model: if MAC-only is currently advertising, withdraw
    // it before emitting MAC+IP. on_local_aged is idempotent if not
    // advertising.
    if was_mac_only && let Some(mac_orig) = state.mac_originators.get_mut(&vni) {
        let actions = mac_orig.on_local_aged(mac);
        apply_actions(
            actions,
            inst,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
    }

    let view_present = state.remote_mac_ip_view.contains_key(&(vni, mac, ip));
    let preexisting_keys = outstanding_route_keys_for_mac(state, vni, mac);
    let actions = {
        let view = state.remote_mac_ip_view.get(&(vni, mac, ip));
        let Some(mac_ip_orig) = state.mac_ip_originators.get_mut(&vni) else {
            return;
        };
        mac_ip_orig.on_local_ip_learned(mac, ip, sticky, view)
    };
    apply_actions_with_duplicate_policy(
        actions,
        view_present,
        preexisting_keys,
        vni,
        mac,
        state,
        inst,
        rib_tx,
        metrics,
        originated_local_mac_counts,
        vni_to_esi,
    )
    .await;
    state
        .live_mac_ip
        .entry(vni)
        .or_default()
        .entry(mac)
        .or_default()
        .insert(ip);
}

#[allow(clippy::too_many_arguments)]
async fn handle_ip_removed(
    vni: EvpnInstanceId,
    mac: MacAddress,
    ip: IpAddr,
    state: &mut OriginatorState,
    instances: &Arc<EvpnInstanceTable>,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    let Some(inst) = instances.get(vni) else {
        return;
    };

    // Drop pending entry if the MAC never surfaced — there's no
    // route to withdraw.
    if let Some(set) = state.pending_ip_bindings.get_mut(&(vni, mac)) {
        set.remove(&ip);
        if set.is_empty() {
            state.pending_ip_bindings.remove(&(vni, mac));
        }
    }

    // Withdraw the MAC+IP route for this specific (mac, ip).
    let Some(mac_ip_orig) = state.mac_ip_originators.get_mut(&vni) else {
        return;
    };
    let actions = mac_ip_orig.on_local_ip_aged(mac, ip);
    apply_actions(
        actions,
        inst,
        rib_tx,
        metrics,
        originated_local_mac_counts,
        vni_to_esi,
    )
    .await;

    // Update live cache. If this was the last IP for the MAC AND the
    // MAC is still locally learned, downgrade back to MAC-only by
    // re-emitting via the MAC-only originator.
    let mut empty_after = false;
    if let Some(per_vni) = state.live_mac_ip.get_mut(&vni)
        && let Some(ips) = per_vni.get_mut(&mac)
    {
        ips.remove(&ip);
        if ips.is_empty() {
            per_vni.remove(&mac);
            empty_after = true;
        }
    }

    let ifindex_for_mac = state
        .local_macs
        .get(&vni)
        .and_then(|m| m.get(&mac).copied());
    if empty_after && let Some(ifindex) = ifindex_for_mac {
        if duplicate_mac_is_quarantined(state, vni, mac) {
            suppress_local_originations_for_mac(
                vni,
                mac,
                state,
                inst,
                None,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
            return;
        }
        let sticky = sticky_for(instances, vni, mac);
        let view_present = state.remote_mac_view.contains_key(&(vni, mac));
        let preexisting_keys = outstanding_route_keys_for_mac(state, vni, mac);
        let actions = {
            let view = state.remote_mac_view.get(&(vni, mac));
            let Some(mac_orig) = state.mac_originators.get_mut(&vni) else {
                return;
            };
            // Replay the original ifindex so MAC-only's port-move
            // detection stays anchored to the real bridge port —
            // a downgrade isn't a port move and shouldn't ratchet up.
            mac_orig.on_local_learned(mac, ifindex, sticky, view)
        };
        apply_actions_with_duplicate_policy(
            actions,
            view_present,
            preexisting_keys,
            vni,
            mac,
            state,
            inst,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
    }
}

/// Re-poll the RIB, build fresh contender views (both MAC-only and
/// MAC+IP), diff against the cached state, and fire
/// `on_remote_changed` / `on_remote_ip_changed` for any tracked
/// `(MAC)` or `(MAC, IP)` whose view changed.
#[allow(clippy::too_many_lines)] // MAC-only and MAC+IP diffs intentionally stay adjacent for symmetry.
async fn repoll_rib(
    instances: &EvpnInstanceTable,
    rib_tx: &mpsc::Sender<RibUpdate>,
    state: &mut OriginatorState,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) -> Result<(), RibQueryError> {
    let routes = query_evpn_routes(rib_tx).await?;
    let (new_mac_view, new_mac_ip_view) = build_remote_views(instances, &routes);
    let mut suppressed_remote_diffs: BTreeSet<(EvpnInstanceId, MacAddress)> = BTreeSet::new();

    // --- MAC-only contender diff ---
    let mut mac_affected: Vec<(EvpnInstanceId, MacAddress)> = Vec::new();
    for k in new_mac_view.keys() {
        if state.remote_mac_view.get(k) != new_mac_view.get(k) {
            mac_affected.push(*k);
        }
    }
    for k in state.remote_mac_view.keys() {
        if !new_mac_view.contains_key(k) {
            mac_affected.push(*k);
        }
    }
    for (vni, mac) in mac_affected {
        let Some(inst) = instances.get(vni) else {
            continue;
        };
        if remote_route_processing_suppressed(state, vni, mac) {
            suppressed_remote_diffs.insert((vni, mac));
            continue;
        }
        let view_present = new_mac_view.contains_key(&(vni, mac));
        let preexisting_keys = outstanding_route_keys_for_mac(state, vni, mac);
        let actions = {
            let view = new_mac_view.get(&(vni, mac));
            let Some(orig) = state.mac_originators.get_mut(&vni) else {
                continue;
            };
            orig.on_remote_changed(mac, view)
        };
        if actions.is_empty() {
            continue;
        }
        apply_actions_with_duplicate_policy(
            actions,
            view_present,
            preexisting_keys,
            vni,
            mac,
            state,
            inst,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
    }

    // --- MAC+IP contender diff ---
    let mut mac_ip_affected: Vec<(EvpnInstanceId, MacAddress, IpAddr)> = Vec::new();
    for k in new_mac_ip_view.keys() {
        if state.remote_mac_ip_view.get(k) != new_mac_ip_view.get(k) {
            mac_ip_affected.push(*k);
        }
    }
    for k in state.remote_mac_ip_view.keys() {
        if !new_mac_ip_view.contains_key(k) {
            mac_ip_affected.push(*k);
        }
    }
    for (vni, mac, ip) in mac_ip_affected {
        let Some(inst) = instances.get(vni) else {
            continue;
        };
        if remote_route_processing_suppressed(state, vni, mac) {
            suppressed_remote_diffs.insert((vni, mac));
            continue;
        }
        let view_present = new_mac_ip_view.contains_key(&(vni, mac, ip));
        let preexisting_keys = outstanding_route_keys_for_mac(state, vni, mac);
        let actions = {
            let view = new_mac_ip_view.get(&(vni, mac, ip));
            let Some(orig) = state.mac_ip_originators.get_mut(&vni) else {
                continue;
            };
            orig.on_remote_ip_changed(mac, ip, view)
        };
        if actions.is_empty() {
            continue;
        }
        apply_actions_with_duplicate_policy(
            actions,
            view_present,
            preexisting_keys,
            vni,
            mac,
            state,
            inst,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
    }

    for (vni, mac) in suppressed_remote_diffs {
        let Some(inst) = instances.get(vni) else {
            continue;
        };
        suppress_local_originations_for_mac(
            vni,
            mac,
            state,
            inst,
            None,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
    }

    state.remote_mac_view = new_mac_view;
    state.remote_mac_ip_view = new_mac_ip_view;
    Ok(())
}

/// React to a push-notified EVPN best-path change.
///
/// Each [`EvpnRouteEvent`] is keyed by the full [`EvpnRouteKey`]
/// (which includes RD), but the originator's `remote_view` is keyed
/// by `(VNI, MAC)`. The two key spaces are not 1:1 — multiple
/// PEs may advertise the same `(VNI, MAC)` under their own RDs (RFC
/// 7432 §7.9.5), and `crates/evpn::project_evpn_routes` picks the
/// per-`(VNI, MAC)` winner across **all** of them by mobility
/// sequence + next-hop. Applying a single event as a delta would
/// silently get this wrong:
///
///   - PE-A advertises seq=10, PE-B advertises seq=1 under another
///     RD. A PE-B Added event would overwrite the cached view with
///     the worse candidate.
///   - PE-B is the projected winner and PE-A withdraws. A PE-A
///     Withdrawn event would clear the cached view even though
///     PE-B's path still wins.
///
/// The conservative fix is to use the event purely as a wakeup
/// signal: any Type 2 event triggers a full [`repoll_rib`], which
/// re-runs the projection from scratch and converges on the right
/// answer without the originator trying to reimplement projection
/// state. This still meets the Gate 7c sub-second goal — the event
/// fires synchronously off `recompute_and_distribute_evpn`, well
/// inside the previous 5 s `poll_tick` window — at the cost of one
/// `QueryEvpnRoutes` round-trip per Type 2 event.
///
/// A future optimization can cache `BTreeMap<EvpnRouteKey,
/// RemoteMacView>` and recompute the projected `(VNI, MAC)` winner
/// from that cache on each event without a RIB query, but that
/// reimplements projection state and is deferred until measured to
/// matter.
///
/// Non-Type-2 events return early — the originator does not react
/// to Type 1/3/4/5 best-path changes today.
async fn handle_evpn_event(
    event: &EvpnRouteEvent,
    instances: &EvpnInstanceTable,
    state: &mut OriginatorState,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    if !matches!(event.key, EvpnRouteKey::MacIp { .. }) {
        return;
    }
    if let Err(e) = repoll_rib(
        instances,
        rib_tx,
        state,
        metrics,
        originated_local_mac_counts,
        vni_to_esi,
    )
    .await
    {
        warn!(error = %e, "EVPN originator: event-triggered repoll failed");
    }
}

/// Drain on shutdown: emit Withdraws for every still-advertised
/// route across both originators. MAC+IP first so peer state
/// converges from the most-specific NLRIs down — same pattern the
/// daemon's coordinated shutdown uses for SVI then originator then
/// IMET.
async fn drain_to_withdraws(
    state: &mut OriginatorState,
    instances: &EvpnInstanceTable,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    let vnis: BTreeSet<EvpnInstanceId> = state
        .mac_ip_originators
        .keys()
        .chain(state.mac_originators.keys())
        .copied()
        .collect();
    for vni in vnis {
        drain_vni_to_withdraws(
            state,
            instances,
            vni,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            vni_to_esi,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn drain_vni_to_withdraws(
    state: &mut OriginatorState,
    instances: &EvpnInstanceTable,
    vni: EvpnInstanceId,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    originated_local_mac_counts: &OriginatedLocalMacCounts,
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    let Some(inst) = instances.get(vni) else {
        return;
    };
    if let Some(orig) = state.mac_ip_originators.get_mut(&vni) {
        let actions = orig.drain_to_withdraws();
        if !actions.is_empty() {
            apply_actions(
                actions,
                inst,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
        }
    }
    if let Some(orig) = state.mac_originators.get_mut(&vni) {
        let actions = orig.drain_to_withdraws();
        if !actions.is_empty() {
            apply_actions(
                actions,
                inst,
                rib_tx,
                metrics,
                originated_local_mac_counts,
                vni_to_esi,
            )
            .await;
        }
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
    vni_to_esi: &std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
) {
    for action in actions {
        match action {
            OriginationAction::Inject {
                mac,
                mobility_seq,
                sticky,
                key,
            } => {
                // ESI-aware origination: when the VNI is part of a
                // configured Ethernet Segment, attach the segment's
                // ESI so peers can resolve aliasing alternatives.
                // Single-homed VNIs default to ZERO.
                let esi = vni_to_esi
                    .get(&instance.id)
                    .copied()
                    .unwrap_or(EthernetSegmentIdentifier::ZERO);
                let route = build_originated_route(instance, mac, mobility_seq, sticky, key, esi);
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
                        originated_local_mac_counts.record_inject(instance.id, mac, key);
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
                        originated_local_mac_counts.record_withdraw(instance.id, mac, key);
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
///
/// `esi` carries the Ethernet Segment Identifier the local PE attaches
/// to the Type 2 NLRI's ESI field. Single-homed CE = pass
/// [`EthernetSegmentIdentifier::ZERO`]; multi-homed CE on a configured
/// `[[ethernet_segments]]` segment = pass the segment's ESI so peers
/// can correlate this MAC with Type 1 EAD-per-EVI routes for the same
/// segment via aliasing (RFC 7432 §14).
///
/// ## On the route key not including ESI
///
/// Per RFC 7432 §9, the Type 2 NLRI's full wire shape includes the
/// ESI as part of the bytes a BGP receiver hashes to identify the
/// route. `EvpnRouteKey::MacIp` deliberately keys on
/// `(RD, EthTag, MAC, IP)` only — the ESI lives on the route's
/// path-metadata side, not the lookup-key side. Two reasons that's
/// safe in our model:
///
/// 1. **Origination is single-source-per-VNI.**
///    `Config::resolve_ethernet_segments` rejects two segments
///    sharing a member VNI, so the local PE can never originate the
///    same `(RD, EthTag, MAC, IP)` under two different ESIs. The
///    `vni_to_esi` lookup is total and deterministic.
/// 2. **Reception relies on best-path tie-breaking.** When two
///    peers advertise the same `(RD, EthTag, MAC, IP)` under
///    different ESIs (e.g. a CE that accidentally hashes to
///    different segments at different `ToRs`), the existing best-path
///    chain (mobility sequence → `ORIGIN` → `CLUSTER_LIST` →
///    `ORIGINATOR_ID`) picks one winner whose ESI becomes canonical;
///    aliasing on the receive side then surfaces alternative VTEPs
///    via the EAD-per-EVI index without extending the route key.
///
/// Folding ESI into `EvpnRouteKey::MacIp` would be a larger ADR-level
/// change with cascading impact across the RIB index, best-path
/// comparison, and Type 2 withdraw paths — explicitly out of scope
/// for the Gate 8b feature slices.
pub(crate) fn build_originated_route(
    instance: &EvpnInstance,
    mac: MacAddress,
    mobility_seq: Option<u32>,
    sticky: bool,
    key: EvpnRouteKey,
    esi: EthernetSegmentIdentifier,
) -> EvpnRibRoute {
    let macip = EvpnMacIp {
        rd: instance.rd,
        esi,
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

/// Build both contender maps from a flat set of best-path
/// `EvpnRibRoute`s. Drops self-NH routes per the module-level
/// "self-origination filter" rule.
///
/// MAC-only and MAC+IP are independent advertisements per RFC 9135
/// §7.2.3, so the two maps are constructed independently:
///
/// - `RemoteMacViewMap` — the existing per-`(VNI, MAC)` view; reuses
///   `project_evpn_routes` which collapses by `(VNI, MAC)`.
/// - `RemoteMacIpViewMap` — per-`(VNI, MAC, IP)` view for MAC+IP
///   contention; built inline because `project_evpn_routes`
///   intentionally drops the IP. Same self-NH filter, same RFC §15.1
///   tiebreak (higher seq → lower `next_hop` on ties).
fn build_remote_views(
    instances: &EvpnInstanceTable,
    routes: &[EvpnRibRoute],
) -> (RemoteMacViewMap, RemoteMacIpViewMap) {
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
                    esi: macip.esi,
                    ethernet_tag: macip.ethernet_tag,
                },
                sticky,
            ))
        })
        .collect();

    // --- MAC-only map (collapses to per-(VNI, MAC) winner) ---
    let table = project_evpn_routes(instances, projected.iter().map(|(p, _)| p.clone()));
    let mut mac_view: RemoteMacViewMap = BTreeMap::new();
    for ((vni, mac), entry) in table.iter() {
        let sticky = projected
            .iter()
            .find(|(p, _)| {
                p.mac == *mac
                    && p.next_hop == entry.remote_vtep_ip
                    && p.mobility_sequence == entry.mobility_sequence
            })
            .is_some_and(|(_, s)| *s);
        mac_view.insert(
            (*vni, *mac),
            RemoteMacView {
                mac: *mac,
                mobility_sequence: entry.mobility_sequence,
                sticky,
                next_hop: entry.remote_vtep_ip,
            },
        );
    }

    // --- MAC+IP map (per-(VNI, MAC, IP) winner) ---
    //
    // Walk the projected set, drop self-NH and IP-less rows, group
    // by (VNI, MAC, IP), keep the contender with the highest
    // mobility seq (None < Some(0); ties broken by lower next_hop).
    let mut staged: BTreeMap<(EvpnInstanceId, MacAddress, IpAddr), &(ProjectedEvpnRoute, bool)> =
        BTreeMap::new();
    for tup in &projected {
        let p = &tup.0;
        let Some(ip) = p.host_ip else {
            continue;
        };
        let raw_vni = p.label1.as_vni();
        if raw_vni == 0 {
            continue;
        }
        let Ok(vni) = rustbgpd_evpn::EvpnInstanceId::new(raw_vni) else {
            continue;
        };
        let Some(local_inst) = instances.get(vni) else {
            continue;
        };
        if p.next_hop == local_inst.local_vtep_ip {
            continue;
        }
        let key = (vni, p.mac, ip);
        match staged.get(&key) {
            None => {
                staged.insert(key, tup);
            }
            Some(existing) => {
                if prefer_mac_ip_new(p, &existing.0) {
                    staged.insert(key, tup);
                }
            }
        }
    }

    let mut mac_ip_view: RemoteMacIpViewMap = BTreeMap::new();
    for ((vni, mac, ip), tup) in staged {
        let p = &tup.0;
        let sticky = tup.1;
        mac_ip_view.insert(
            (vni, mac, ip),
            RemoteMacIpView {
                mac,
                ip,
                mobility_sequence: p.mobility_sequence,
                sticky,
                next_hop: p.next_hop,
            },
        );
    }

    (mac_view, mac_ip_view)
}

/// MAC+IP contender tiebreak — same shape as
/// `crates/evpn::projection::prefer_new`: higher mobility seq wins,
/// then lower `next_hop`. Inlined here because that function is
/// crate-private to `rustbgpd-evpn`.
fn prefer_mac_ip_new(new: &ProjectedEvpnRoute, existing: &ProjectedEvpnRoute) -> bool {
    match new.mobility_sequence.cmp(&existing.mobility_sequence) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => new.next_hop < existing.next_hop,
    }
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
    use rustbgpd_evpn::{
        DuplicateMacAction, DuplicateMacConfig, EvpnInstance, EvpnInstanceTable, RouteTarget,
    };
    use rustbgpd_rib::route::RouteOrigin;
    use rustbgpd_wire::{EvpnImet, EvpnMacIp, RouteDistinguisher};

    fn gather_metrics_text(metrics: &BgpMetrics) -> String {
        let encoder = prometheus::TextEncoder::new();
        let families = metrics.registry().gather();
        let mut buf = Vec::new();
        encoder.encode(&families, &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn assert_quarantine_metric(metrics: &BgpMetrics, v: u32, m: u8, value: u32) {
        let text = gather_metrics_text(metrics);
        assert!(
            text.contains(&format!(
                "evpn_duplicate_mac_quarantine_active{{mac=\"{}\",vni=\"{v}\"}} {value}",
                mac(m)
            )) || text.contains(&format!(
                "evpn_duplicate_mac_quarantine_active{{vni=\"{v}\",mac=\"{}\"}} {value}",
                mac(m)
            )),
            "{text}"
        );
    }

    fn duplicate_mac_quarantine_tx() -> watch::Sender<Arc<BTreeSet<DuplicateMacKey>>> {
        watch::channel(Arc::new(BTreeSet::new())).0
    }

    fn originator_state(instances: &EvpnInstanceTable) -> OriginatorState {
        OriginatorState::new(instances, duplicate_mac_quarantine_tx())
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

    fn instance_table_many(vnis: &[u32]) -> Arc<EvpnInstanceTable> {
        let mut t = EvpnInstanceTable::new();
        for v in vnis {
            t.insert(local_instance(*v)).unwrap();
        }
        Arc::new(t)
    }

    fn instance_table_with(inst: EvpnInstance) -> Arc<EvpnInstanceTable> {
        let mut t = EvpnInstanceTable::new();
        t.insert(inst).unwrap();
        Arc::new(t)
    }

    fn suppress_local_instance(v: u32) -> EvpnInstance {
        suppress_local_instance_with(v, 1, Duration::from_mins(9))
    }

    fn suppress_local_instance_with(v: u32, threshold: u32, recovery: Duration) -> EvpnInstance {
        local_instance(v).with_duplicate_mac_detection(
            DuplicateMacConfig::new(
                DuplicateMacAction::SuppressLocal,
                Duration::from_mins(3),
                threshold,
                recovery,
            )
            .unwrap(),
        )
    }

    #[test]
    fn duplicate_mac_quarantine_publisher_tracks_active_set() {
        let inst = suppress_local_instance(100);
        let instances = instance_table_with(inst.clone());
        let (tx, rx) = watch::channel(Arc::new(BTreeSet::new()));
        let mut state = OriginatorState::new(&instances, tx);
        let metrics = BgpMetrics::new();
        let key = DuplicateMacKey::new(vni(100), mac(0xAA));

        assert!(record_duplicate_mac_move(
            &metrics, &mut state, &inst, key.vni, key.mac
        ));
        assert!(rx.borrow().contains(&key));

        set_duplicate_mac_quarantine_active(&mut state, key, false);
        assert!(!rx.borrow().contains(&key));
    }

    #[tokio::test]
    async fn originator_control_round_trips_clear_command() {
        let (command_tx, mut command_rx) = mpsc::channel(1);
        let control = EvpnOriginatorControl { command_tx };
        let key = DuplicateMacKey::new(vni(100), mac(0xAA));
        let pending =
            tokio::spawn(async move { control.clear_duplicate_mac_quarantine(key).await });

        let Some(OriginatorCommand::ClearDuplicateMacQuarantine {
            key: received,
            reply,
        }) = command_rx.recv().await
        else {
            panic!("expected clear command");
        };
        assert_eq!(received, key);
        reply
            .send(ClearDuplicateMacQuarantineResult::Cleared)
            .unwrap();

        assert_eq!(
            pending.await.unwrap().unwrap(),
            ClearDuplicateMacQuarantineResult::Cleared
        );
    }

    fn evpn_macip_route(
        v: u32,
        m: u8,
        next_hop: &str,
        seq: Option<u32>,
        sticky: bool,
    ) -> EvpnRibRoute {
        evpn_macip_route_with_ip(v, m, None, next_hop, seq, sticky)
    }

    fn evpn_macip_route_with_ip(
        v: u32,
        m: u8,
        ip: Option<&str>,
        next_hop: &str,
        seq: Option<u32>,
        sticky: bool,
    ) -> EvpnRibRoute {
        let macip = EvpnMacIp {
            rd: rd(65000, v),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            mac: mac(m),
            ip: ip.map(ipa),
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

    fn remote_mac_ip_view(mac_b: u8, ip_str: &str, seq: Option<u32>) -> RemoteMacIpView {
        RemoteMacIpView {
            mac: mac(mac_b),
            ip: ipa(ip_str),
            mobility_sequence: seq,
            sticky: false,
            next_hop: ipa("10.0.0.2"),
        }
    }

    async fn observe_test(
        obs: LocalMacObservation,
        state: &mut OriginatorState,
        instances: &Arc<EvpnInstanceTable>,
        rib_tx: &mpsc::Sender<RibUpdate>,
        metrics: &BgpMetrics,
        counts: &OriginatedLocalMacCounts,
    ) {
        handle_observation(
            &obs,
            state,
            instances,
            rib_tx,
            metrics,
            counts,
            &std::collections::BTreeMap::new(),
        )
        .await;
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
        let (view, _) = build_remote_views(&t, &routes);
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
        let (view, _) = build_remote_views(&t, &routes);
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
        let (view, mac_ip_view) = build_remote_views(&t, &[imet]);
        assert!(view.is_empty());
        assert!(mac_ip_view.is_empty());
    }

    #[tokio::test]
    async fn local_learn_with_remote_contender_records_duplicate_mac_counter() {
        let instances = instance_table(100);
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(4);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);
        state.remote_mac_view.insert(
            (vni(100), mac(0xAA)),
            RemoteMacView {
                mac: mac(0xAA),
                mobility_sequence: Some(3),
                sticky: false,
                next_hop: ipa("10.0.0.2"),
            },
        );

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
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
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

    #[tokio::test]
    async fn duplicate_mac_suppress_local_withdraws_without_reinjecting() {
        let instances = instance_table_with(suppress_local_instance(100));
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (log, _responder) = rib_capture_responder(rib_rx);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);

        handle_observation(
            &LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        state.remote_mac_view.insert(
            (vni(100), mac(0xAA)),
            RemoteMacView {
                mac: mac(0xAA),
                mobility_sequence: Some(3),
                sticky: false,
                next_hop: ipa("10.0.0.2"),
            },
        );
        handle_observation(
            &LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        let actions = log.lock().await.clone();
        assert_eq!(
            actions,
            vec![
                RibAction::Inject(macip_key_with(100, 0xAA, None)),
                RibAction::Withdraw(macip_key_with(100, 0xAA, None)),
            ],
            "threshold crossing should withdraw the local route and suppress the would-be re-inject"
        );

        let text = gather_metrics_text(&metrics);
        assert!(
            text.contains(
                "evpn_duplicate_mac_threshold_exceeded_total{action=\"suppress_local\",mac=\"aa:aa:aa:aa:aa:aa\",vni=\"100\"} 1"
            ) || text.contains(
                "evpn_duplicate_mac_threshold_exceeded_total{vni=\"100\",mac=\"aa:aa:aa:aa:aa:aa\",action=\"suppress_local\"} 1"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "evpn_duplicate_mac_quarantine_active{mac=\"aa:aa:aa:aa:aa:aa\",vni=\"100\"} 1"
            ) || text.contains(
                "evpn_duplicate_mac_quarantine_active{vni=\"100\",mac=\"aa:aa:aa:aa:aa:aa\"} 1"
            ),
            "{text}"
        );
    }

    #[tokio::test]
    async fn duplicate_mac_suppress_local_first_learn_does_not_withdraw_unadvertised_route() {
        let instances = instance_table_with(suppress_local_instance(100));
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (log, _responder) = rib_capture_responder(rib_rx);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);
        state.remote_mac_view.insert(
            (vni(100), mac(0xAA)),
            RemoteMacView {
                mac: mac(0xAA),
                mobility_sequence: Some(3),
                sticky: false,
                next_hop: ipa("10.0.0.2"),
            },
        );

        handle_observation(
            &LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        assert!(
            log.lock().await.is_empty(),
            "first learn with an immediate quarantine has no advertised key to withdraw"
        );
    }

    #[tokio::test]
    async fn duplicate_mac_recovery_replays_local_route_and_resets_metric() {
        let instances = instance_table_with(suppress_local_instance_with(
            100,
            1,
            Duration::from_millis(1),
        ));
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (log, _responder) = rib_capture_responder(rib_rx);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);

        handle_observation(
            &LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;
        state.remote_mac_view.insert(
            (vni(100), mac(0xAA)),
            RemoteMacView {
                mac: mac(0xAA),
                mobility_sequence: Some(3),
                sticky: false,
                next_hop: ipa("10.0.0.2"),
            },
        );
        handle_observation(
            &LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        tokio::time::sleep(Duration::from_millis(5)).await;
        recover_duplicate_macs(
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        let actions = log.lock().await.clone();
        assert_eq!(
            actions,
            vec![
                RibAction::Inject(macip_key_with(100, 0xAA, None)),
                RibAction::Withdraw(macip_key_with(100, 0xAA, None)),
                RibAction::Inject(macip_key_with(100, 0xAA, None)),
            ],
            "recovery should replay the still-local MAC once suppression expires"
        );
        assert_quarantine_metric(&metrics, 100, 0xAA, 0);
    }

    #[tokio::test]
    async fn duplicate_mac_manual_clear_replays_local_route_and_resets_metric() {
        let instances = instance_table_with(suppress_local_instance(100));
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (log, _responder) = rib_capture_responder(rib_rx);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let (quarantine_tx, quarantine_rx) = watch::channel(Arc::new(BTreeSet::new()));
        let mut state = OriginatorState::new(&instances, quarantine_tx);

        observe_test(
            LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
        )
        .await;
        state.remote_mac_view.insert(
            (vni(100), mac(0xAA)),
            RemoteMacView {
                mac: mac(0xAA),
                mobility_sequence: Some(3),
                sticky: false,
                next_hop: ipa("10.0.0.2"),
            },
        );
        observe_test(
            LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
        )
        .await;

        let key = DuplicateMacKey::new(vni(100), mac(0xAA));
        assert!(quarantine_rx.borrow().contains(&key));
        let result = clear_duplicate_mac_quarantine(
            key,
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        assert_eq!(result, ClearDuplicateMacQuarantineResult::Cleared);
        assert!(!quarantine_rx.borrow().contains(&key));
        let actions = log.lock().await.clone();
        assert_eq!(
            actions,
            vec![
                RibAction::Inject(macip_key_with(100, 0xAA, None)),
                RibAction::Withdraw(macip_key_with(100, 0xAA, None)),
                RibAction::Inject(macip_key_with(100, 0xAA, None)),
            ],
            "manual clear should replay the still-local MAC immediately"
        );
        assert_quarantine_metric(&metrics, 100, 0xAA, 0);
    }

    #[tokio::test]
    async fn duplicate_mac_manual_clear_inactive_returns_not_active_and_clears_window() {
        let inst = local_instance(100);
        let instances = instance_table_with(inst.clone());
        let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(16);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);
        let key = DuplicateMacKey::new(vni(100), mac(0xAA));

        assert!(!record_duplicate_mac_move(
            &metrics, &mut state, &inst, key.vni, key.mac
        ));
        let result = clear_duplicate_mac_quarantine(
            key,
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        assert_eq!(result, ClearDuplicateMacQuarantineResult::NotActive);
        assert!(!state.duplicate_mac_detector.clear(key));
    }

    #[tokio::test]
    async fn duplicate_mac_manual_clear_unknown_vni_returns_unknown_vni() {
        let instances = instance_table(100);
        let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(16);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);
        let result = clear_duplicate_mac_quarantine(
            DuplicateMacKey::new(vni(200), mac(0xAA)),
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        assert_eq!(result, ClearDuplicateMacQuarantineResult::UnknownVni);
    }

    #[tokio::test]
    async fn duplicate_mac_mac_ip_quarantine_replays_multiple_live_ips_after_recovery() {
        let instances = instance_table_with(suppress_local_instance_with(
            100,
            1,
            Duration::from_millis(1),
        ));
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (log, _responder) = rib_capture_responder(rib_rx);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);
        state.remote_mac_ip_view.insert(
            (vni(100), mac(0xAA), ipa("192.0.2.10")),
            remote_mac_ip_view(0xAA, "192.0.2.10", Some(3)),
        );

        for ip in ["192.0.2.10", "192.0.2.11"] {
            observe_test(
                LocalMacObservation::IpAdded {
                    vni: vni(100),
                    mac: mac(0xAA),
                    ip: ipa(ip),
                },
                &mut state,
                &instances,
                &rib_tx,
                &metrics,
                &counts,
            )
            .await;
        }

        observe_test(
            LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
        )
        .await;

        assert!(
            log.lock().await.is_empty(),
            "pending MAC+IP quarantine must suppress every live IP, not inject later pending IPs"
        );
        assert_eq!(
            state
                .live_mac_ip
                .get(&vni(100))
                .and_then(|per_vni| per_vni.get(&mac(0xAA)))
                .cloned()
                .unwrap_or_default(),
            BTreeSet::from([ipa("192.0.2.10"), ipa("192.0.2.11")]),
            "suppressed live IPs remain cached for timed replay"
        );

        tokio::time::sleep(Duration::from_millis(5)).await;
        observe_test(
            LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
        )
        .await;
        assert!(
            log.lock().await.is_empty(),
            "expired quarantine must wait for recovery replay instead of emitting MAC-only while live IPs exist"
        );

        recover_duplicate_macs(
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        let actions = log.lock().await.clone();
        assert_eq!(
            actions,
            vec![
                RibAction::Inject(macip_key_with(100, 0xAA, Some("192.0.2.10"))),
                RibAction::Inject(macip_key_with(100, 0xAA, Some("192.0.2.11"))),
            ],
            "recovery should replay every still-live MAC+IP binding without a MAC-only route"
        );
        assert_quarantine_metric(&metrics, 100, 0xAA, 0);
    }

    #[tokio::test]
    async fn duplicate_mac_quarantine_suppresses_remote_mac_repoll_processing() {
        let instances = instance_table_with(suppress_local_instance(100));
        let route_a = evpn_macip_route(100, 0xAA, "10.0.0.2", Some(5), false);
        let route_b = evpn_macip_route(100, 0xAA, "10.0.0.3", Some(9), false);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (log, routes_tx, _responder) =
            rib_capture_dynamic_query_responder(rib_rx, vec![route_a.clone()]);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);

        observe_test(
            LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
        )
        .await;
        let inst = instances.get(vni(100)).unwrap();
        assert!(record_duplicate_mac_move(
            &metrics,
            &mut state,
            inst,
            vni(100),
            mac(0xAA)
        ));
        log.lock().await.clear();

        repoll_rib(
            &instances,
            &rib_tx,
            &mut state,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await
        .unwrap();

        assert_eq!(
            log.lock().await.clone(),
            vec![RibAction::Withdraw(macip_key_with(100, 0xAA, None))],
            "first quarantined remote diff must only enforce local suppression"
        );
        let view = state
            .remote_mac_view
            .get(&(vni(100), mac(0xAA)))
            .expect("remote cache still updates while processing is suppressed");
        assert_eq!(view.next_hop, ipa("10.0.0.2"));

        log.lock().await.clear();
        routes_tx.send_replace(vec![route_b]);
        repoll_rib(
            &instances,
            &rib_tx,
            &mut state,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await
        .unwrap();

        assert!(
            log.lock().await.is_empty(),
            "remote MAC changes during quarantine must not reprocess originator state"
        );
        let view = state
            .remote_mac_view
            .get(&(vni(100), mac(0xAA)))
            .expect("remote cache tracks the latest remote winner");
        assert_eq!(view.next_hop, ipa("10.0.0.3"));
        assert_eq!(view.mobility_sequence, Some(9));

        routes_tx.send_replace(vec![]);
        repoll_rib(
            &instances,
            &rib_tx,
            &mut state,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await
        .unwrap();

        assert!(
            log.lock().await.is_empty(),
            "remote MAC withdrawals during quarantine must not re-inject local routes"
        );
        assert!(
            !state.remote_mac_view.contains_key(&(vni(100), mac(0xAA))),
            "remote cache still reflects the withdrawn route"
        );
    }

    #[tokio::test]
    async fn duplicate_mac_quarantine_suppresses_remote_mac_ip_repoll_processing() {
        let instances = instance_table_with(suppress_local_instance(100));
        let route_a =
            evpn_macip_route_with_ip(100, 0xAA, Some("192.0.2.10"), "10.0.0.2", Some(5), false);
        let route_b =
            evpn_macip_route_with_ip(100, 0xAA, Some("192.0.2.10"), "10.0.0.3", Some(9), false);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (log, routes_tx, _responder) =
            rib_capture_dynamic_query_responder(rib_rx, vec![route_a.clone()]);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);

        observe_test(
            LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
        )
        .await;
        observe_test(
            LocalMacObservation::IpAdded {
                vni: vni(100),
                mac: mac(0xAA),
                ip: ipa("192.0.2.10"),
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
        )
        .await;
        let inst = instances.get(vni(100)).unwrap();
        assert!(record_duplicate_mac_move(
            &metrics,
            &mut state,
            inst,
            vni(100),
            mac(0xAA)
        ));
        log.lock().await.clear();

        repoll_rib(
            &instances,
            &rib_tx,
            &mut state,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await
        .unwrap();

        assert_eq!(
            log.lock().await.clone(),
            vec![RibAction::Withdraw(macip_key_with(
                100,
                0xAA,
                Some("192.0.2.10")
            ))],
            "first quarantined remote MAC+IP diff must only enforce local suppression"
        );
        let view = state
            .remote_mac_ip_view
            .get(&(vni(100), mac(0xAA), ipa("192.0.2.10")))
            .expect("remote MAC+IP cache still updates while processing is suppressed");
        assert_eq!(view.next_hop, ipa("10.0.0.2"));

        log.lock().await.clear();
        routes_tx.send_replace(vec![route_b]);
        repoll_rib(
            &instances,
            &rib_tx,
            &mut state,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await
        .unwrap();

        assert!(
            log.lock().await.is_empty(),
            "remote MAC+IP changes during quarantine must not reprocess originator state"
        );
        let view = state
            .remote_mac_ip_view
            .get(&(vni(100), mac(0xAA), ipa("192.0.2.10")))
            .expect("remote MAC+IP cache tracks the latest remote winner");
        assert_eq!(view.next_hop, ipa("10.0.0.3"));
        assert_eq!(view.mobility_sequence, Some(9));
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
        let route = build_originated_route(
            &inst,
            mac(0xAA),
            Some(5),
            false,
            key,
            EthernetSegmentIdentifier::ZERO,
        );
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
        let route = build_originated_route(
            &inst,
            mac(0xAA),
            None,
            false,
            key,
            EthernetSegmentIdentifier::ZERO,
        );
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
        let route = build_originated_route(
            &inst,
            mac(0xAA),
            None,
            /* sticky */ true,
            key,
            EthernetSegmentIdentifier::ZERO,
        );
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

    #[test]
    fn build_originated_route_carries_segment_esi_when_provided() {
        // Gate 8b ESI-aware MAC origination: when the daemon's
        // `vni_to_esi` lookup returns a non-zero ESI for the VNI a
        // MAC was learned on, the Type 2 NLRI's ESI field carries
        // that segment identifier so peers can resolve aliasing
        // (RFC 7432 §14) against the corresponding EAD-per-EVI
        // routes.
        let inst = local_instance(100);
        let key = EvpnRouteKey::MacIp {
            rd: inst.rd,
            ethernet_tag: EthernetTagId(0),
            mac: mac(0xAA),
            ip: None,
        };
        let segment_esi = EthernetSegmentIdentifier::new([
            0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x01,
        ]);
        let route = build_originated_route(&inst, mac(0xAA), None, false, key, segment_esi);
        let EvpnRoute::MacIp(macip) = &route.route else {
            panic!("expected MacIp route");
        };
        assert_eq!(macip.esi, segment_esi);
        // Single-homed default still works:
        let route_zero = build_originated_route(
            &inst,
            mac(0xAA),
            None,
            false,
            key,
            EthernetSegmentIdentifier::ZERO,
        );
        let EvpnRoute::MacIp(macip_zero) = &route_zero.route else {
            panic!("expected MacIp route");
        };
        assert_eq!(macip_zero.esi, EthernetSegmentIdentifier::ZERO);
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
            std::sync::Arc::new(std::collections::BTreeMap::new()),
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
            std::sync::Arc::new(std::collections::BTreeMap::new()),
        );
        assert!(h.is_none());
    }

    fn runtime_model_rib_responder(
        mut rib_rx: mpsc::Receiver<RibUpdate>,
        injects: Arc<tokio::sync::Mutex<Vec<EvpnRouteKey>>>,
        withdraws: Arc<tokio::sync::Mutex<Vec<EvpnRouteKey>>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let (events_tx, _) = broadcast::channel(16);
            while let Some(msg) = rib_rx.recv().await {
                match msg {
                    RibUpdate::SubscribeEvpnRouteEvents { reply } => {
                        let _ = reply.send(events_tx.subscribe());
                    }
                    RibUpdate::QueryEvpnRoutes { reply } => {
                        let _ = reply.send(vec![]);
                    }
                    RibUpdate::InjectEvpn { route, reply } => {
                        injects.lock().await.push(route.key());
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::WithdrawEvpn { key, reply } => {
                        withdraws.lock().await.push(key);
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            }
        })
    }

    async fn wait_for_key(
        log: &Arc<tokio::sync::Mutex<Vec<EvpnRouteKey>>>,
        expected: EvpnRouteKey,
        context: &str,
    ) {
        for _ in 0..50 {
            if log.lock().await.contains(&expected) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let observed = log.lock().await.clone();
        panic!("{context}: expected {expected:?}, observed {observed:?}");
    }

    // Records full injected routes (not just keys) so tests can inspect
    // route attributes such as the Type 2 ESI.
    fn runtime_model_full_route_responder(
        mut rib_rx: mpsc::Receiver<RibUpdate>,
        injects: Arc<tokio::sync::Mutex<Vec<EvpnRibRoute>>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let (events_tx, _) = broadcast::channel(16);
            while let Some(msg) = rib_rx.recv().await {
                match msg {
                    RibUpdate::SubscribeEvpnRouteEvents { reply } => {
                        let _ = reply.send(events_tx.subscribe());
                    }
                    RibUpdate::QueryEvpnRoutes { reply } => {
                        let _ = reply.send(vec![]);
                    }
                    RibUpdate::InjectEvpn { route, reply } => {
                        injects.lock().await.push(route);
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::WithdrawEvpn { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            }
        })
    }

    async fn wait_for_macip_with_esi(
        routes: &Arc<tokio::sync::Mutex<Vec<EvpnRibRoute>>>,
        esi: EthernetSegmentIdentifier,
        context: &str,
    ) {
        for _ in 0..50 {
            if routes
                .lock()
                .await
                .iter()
                .any(|r| matches!(&r.route, EvpnRoute::MacIp(macip) if macip.esi == esi))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("{context}: no MacIp route observed carrying esi {esi:?}");
    }

    fn originator_runtime_for_test(
        instances: Arc<EvpnInstanceTable>,
        rib_tx: mpsc::Sender<RibUpdate>,
        metrics: BgpMetrics,
        originated_local_mac_counts: OriginatedLocalMacCounts,
        vni_to_esi: Arc<BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>>,
    ) -> OriginatorRuntime {
        let (_, model_rx) = watch::channel(Arc::new(OriginatorRuntimeModel {
            instances: instances.clone(),
            vni_to_esi: vni_to_esi.clone(),
        }));
        OriginatorRuntime {
            instances,
            model_rx,
            rib_tx,
            metrics,
            originated_local_mac_counts,
            shutdown: CancellationToken::new(),
            vni_to_esi,
        }
    }

    #[tokio::test]
    async fn runtime_model_esi_change_restamps_local_mac_with_segment_esi() {
        // Regression: an ESI-map change must not just withdraw the member
        // VNI's ESI=0 local MAC route — it must re-originate it under the
        // new segment ESI without waiting for another kernel local-MAC
        // event.
        let instances = instance_table(100);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(32);
        let (local_tx, local_rx) = mpsc::channel(16);
        let injected = Arc::new(tokio::sync::Mutex::new(Vec::<EvpnRibRoute>::new()));
        let _responder = runtime_model_full_route_responder(rib_rx, injected.clone());

        let h = spawn(
            OriginatorConfig {
                poll_interval: Duration::from_mins(1),
            },
            &instances,
            rib_tx,
            Some(local_rx),
            BgpMetrics::new(),
            OriginatedLocalMacCounts::default(),
            CancellationToken::new(),
            Arc::new(std::collections::BTreeMap::new()),
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
        wait_for_macip_with_esi(
            &injected,
            EthernetSegmentIdentifier::ZERO,
            "initial origination should carry ESI 0",
        )
        .await;

        let segment_esi = EthernetSegmentIdentifier::new([
            0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x01,
        ]);
        let mut vni_to_esi = std::collections::BTreeMap::new();
        vni_to_esi.insert(vni(100), segment_esi);
        assert!(h.replace_runtime_model(instances, Arc::new(vni_to_esi)));

        wait_for_macip_with_esi(
            &injected,
            segment_esi,
            "ESI-map change should re-stamp the local MAC under the segment ESI",
        )
        .await;
        h.shutdown().await;
    }

    #[tokio::test]
    async fn runtime_model_esi_change_preserves_duplicate_mac_quarantine() {
        let instances = instance_table_with(suppress_local_instance(100));
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (log, _responder) = rib_capture_responder(rib_rx);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);
        state.remote_mac_view.insert(
            (vni(100), mac(0xAA)),
            RemoteMacView {
                mac: mac(0xAA),
                mobility_sequence: Some(3),
                sticky: false,
                next_hop: ipa("10.0.0.2"),
            },
        );

        observe_test(
            LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
        )
        .await;

        let duplicate_key = DuplicateMacKey::new(vni(100), mac(0xAA));
        assert!(
            state
                .active_duplicate_mac_quarantines
                .contains(&duplicate_key),
            "remote contender should activate suppress-local quarantine"
        );
        assert!(
            log.lock().await.is_empty(),
            "quarantined local MAC must not advertise before ESI change"
        );
        assert_quarantine_metric(&metrics, 100, 0xAA, 1);

        let segment_esi = EthernetSegmentIdentifier::new([
            0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x01,
        ]);
        let mut next_vni_to_esi = BTreeMap::new();
        next_vni_to_esi.insert(vni(100), segment_esi);
        let mut runtime = originator_runtime_for_test(
            instances.clone(),
            rib_tx,
            metrics.clone(),
            counts,
            Arc::new(BTreeMap::new()),
        );

        apply_runtime_model(
            Arc::new(OriginatorRuntimeModel {
                instances,
                vni_to_esi: Arc::new(next_vni_to_esi),
            }),
            &mut state,
            &mut runtime,
        )
        .await;

        assert!(
            state
                .active_duplicate_mac_quarantines
                .contains(&duplicate_key),
            "ESI-map changes must not clear active duplicate-MAC suppression"
        );
        assert!(
            state
                .duplicate_mac_detector
                .is_quarantined(duplicate_key, Instant::now()),
            "duplicate-MAC detector state must survive ESI-map changes"
        );
        assert!(
            log.lock().await.is_empty(),
            "ESI-map replay must not re-advertise a quarantined local MAC"
        );
        assert_quarantine_metric(&metrics, 100, 0xAA, 1);
    }

    #[tokio::test]
    async fn runtime_model_esi_change_preserves_pending_ip_bindings() {
        let instances = instance_table(100);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (log, _responder) = rib_capture_responder(rib_rx);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);

        observe_test(
            LocalMacObservation::IpAdded {
                vni: vni(100),
                mac: mac(0xAA),
                ip: ipa("192.0.2.10"),
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
        )
        .await;
        assert!(
            state
                .pending_ip_bindings
                .get(&(vni(100), mac(0xAA)))
                .is_some_and(|ips| ips.contains(&ipa("192.0.2.10"))),
            "IP-before-MAC binding should be pending before ESI change"
        );

        let segment_esi = EthernetSegmentIdentifier::new([
            0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x01,
        ]);
        let mut next_vni_to_esi = BTreeMap::new();
        next_vni_to_esi.insert(vni(100), segment_esi);
        let mut runtime = originator_runtime_for_test(
            instances.clone(),
            rib_tx.clone(),
            metrics.clone(),
            counts.clone(),
            Arc::new(BTreeMap::new()),
        );

        apply_runtime_model(
            Arc::new(OriginatorRuntimeModel {
                instances: instances.clone(),
                vni_to_esi: Arc::new(next_vni_to_esi),
            }),
            &mut state,
            &mut runtime,
        )
        .await;
        assert!(
            state
                .pending_ip_bindings
                .get(&(vni(100), mac(0xAA)))
                .is_some_and(|ips| ips.contains(&ipa("192.0.2.10"))),
            "ESI-map changes must preserve pending IP bindings"
        );

        handle_observation(
            &LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            runtime.vni_to_esi.as_ref(),
        )
        .await;

        assert_eq!(
            log.lock().await.clone(),
            vec![RibAction::Inject(macip_key_with(
                100,
                0xAA,
                Some("192.0.2.10")
            ))],
            "Learned after ESI-map change must drain the preserved pending IP and emit MAC+IP"
        );
    }

    #[tokio::test]
    async fn runtime_model_add_allows_future_local_mac_learns() {
        let instances = instance_table(100);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(32);
        let (local_tx, local_rx) = mpsc::channel(16);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _responder = runtime_model_rib_responder(rib_rx, injects.clone(), withdraws.clone());

        let h = spawn(
            OriginatorConfig {
                poll_interval: Duration::from_mins(1),
            },
            &instances,
            rib_tx,
            Some(local_rx),
            BgpMetrics::new(),
            OriginatedLocalMacCounts::default(),
            CancellationToken::new(),
            Arc::new(std::collections::BTreeMap::new()),
        )
        .expect("originator spawned");

        assert!(h.replace_runtime_model(
            instance_table_many(&[100, 200]),
            Arc::new(std::collections::BTreeMap::new()),
        ));
        local_tx
            .send(LocalMacObservation::Learned {
                vni: vni(200),
                mac: mac(0xBB),
                ifindex: 20,
            })
            .await
            .unwrap();

        wait_for_key(
            &injects,
            EvpnRouteKey::MacIp {
                rd: rd(65000, 200),
                ethernet_tag: EthernetTagId(0),
                mac: mac(0xBB),
                ip: None,
            },
            "runtime-added VNI should accept future local learns",
        )
        .await;
        assert!(withdraws.lock().await.is_empty());
        h.shutdown().await;
    }

    #[tokio::test]
    async fn runtime_model_remove_drains_originated_local_mac_routes() {
        let instances = instance_table(100);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(32);
        let (local_tx, local_rx) = mpsc::channel(16);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _responder = runtime_model_rib_responder(rib_rx, injects.clone(), withdraws.clone());

        let h = spawn(
            OriginatorConfig {
                poll_interval: Duration::from_mins(1),
            },
            &instances,
            rib_tx,
            Some(local_rx),
            BgpMetrics::new(),
            OriginatedLocalMacCounts::default(),
            CancellationToken::new(),
            Arc::new(std::collections::BTreeMap::new()),
        )
        .expect("originator spawned");

        let key = EvpnRouteKey::MacIp {
            rd: rd(65000, 100),
            ethernet_tag: EthernetTagId(0),
            mac: mac(0xAA),
            ip: None,
        };
        local_tx
            .send(LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            })
            .await
            .unwrap();
        wait_for_key(&injects, key, "initial VNI should originate").await;

        assert!(h.replace_runtime_model(
            Arc::new(EvpnInstanceTable::new()),
            Arc::new(std::collections::BTreeMap::new()),
        ));
        wait_for_key(
            &withdraws,
            key,
            "runtime-removed VNI should drain local MAC originations",
        )
        .await;
        h.shutdown().await;
    }

    #[tokio::test]
    async fn runtime_model_esi_change_drains_originated_local_mac_routes() {
        let instances = instance_table(100);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(32);
        let (local_tx, local_rx) = mpsc::channel(16);
        let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let _responder = runtime_model_rib_responder(rib_rx, injects.clone(), withdraws.clone());

        let h = spawn(
            OriginatorConfig {
                poll_interval: Duration::from_mins(1),
            },
            &instances,
            rib_tx,
            Some(local_rx),
            BgpMetrics::new(),
            OriginatedLocalMacCounts::default(),
            CancellationToken::new(),
            Arc::new(std::collections::BTreeMap::new()),
        )
        .expect("originator spawned");

        let key = EvpnRouteKey::MacIp {
            rd: rd(65000, 100),
            ethernet_tag: EthernetTagId(0),
            mac: mac(0xAA),
            ip: None,
        };
        local_tx
            .send(LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            })
            .await
            .unwrap();
        wait_for_key(&injects, key, "initial VNI should originate").await;

        let mut vni_to_esi = std::collections::BTreeMap::new();
        vni_to_esi.insert(
            vni(100),
            EthernetSegmentIdentifier::new([
                0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x01,
            ]),
        );
        assert!(h.replace_runtime_model(instances, Arc::new(vni_to_esi)));
        wait_for_key(
            &withdraws,
            key,
            "runtime ESI-map change should drain stale local MAC originations",
        )
        .await;
        h.shutdown().await;
    }

    #[test]
    fn remove_vni_state_clears_inactive_duplicate_mac_detector_windows() {
        let instances = instance_table(100);
        let mut state = originator_state(&instances);
        let metrics = BgpMetrics::new();
        let key = DuplicateMacKey::new(vni(100), mac(0xAA));
        let inst = instances.get(vni(100)).unwrap();

        assert!(!record_duplicate_mac_move(
            &metrics, &mut state, inst, key.vni, key.mac
        ));
        assert!(state.known_duplicate_mac_keys.contains(&key));
        remove_vni_state(&mut state, key.vni, &metrics);

        assert!(!state.known_duplicate_mac_keys.contains(&key));
        assert!(!state.duplicate_mac_detector.clear(key));
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
            std::sync::Arc::new(std::collections::BTreeMap::new()),
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
            std::sync::Arc::new(std::collections::BTreeMap::new()),
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
            std::sync::Arc::new(std::collections::BTreeMap::new()),
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
            std::sync::Arc::new(std::collections::BTreeMap::new()),
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

    /// Build an `EvpnRouteEvent` for a Type 2 best-path with the given
    /// peer / mac / seq, using the same RD shape as `local_instance`.
    fn evpn_event_macip(
        v: u32,
        m: u8,
        peer_addr: &str,
        seq: Option<u32>,
        sticky: bool,
        event_type: rustbgpd_rib::RouteEventType,
        previous_peer: Option<IpAddr>,
    ) -> EvpnRouteEvent {
        let route = evpn_macip_route(v, m, peer_addr, seq, sticky);
        EvpnRouteEvent {
            event_type,
            key: route.key(),
            best: Some(route.clone()),
            previous_best: None,
            peer: Some(ipa(peer_addr)),
            previous_peer,
            timestamp: "0".to_string(),
        }
    }

    /// Build a `QueryEvpnRoutes` responder that replies with `routes`
    /// for every query and forwards `InjectEvpn` / `WithdrawEvpn`
    /// success replies. Returned join handle lives until `rib_rx` is
    /// closed.
    fn rib_query_responder(
        mut rib_rx: mpsc::Receiver<RibUpdate>,
        routes: Vec<EvpnRibRoute>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                match msg {
                    RibUpdate::QueryEvpnRoutes { reply } => {
                        let _ = reply.send(routes.clone());
                    }
                    RibUpdate::InjectEvpn { reply, .. } | RibUpdate::WithdrawEvpn { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            }
        })
    }

    /// Build a mutable `QueryEvpnRoutes` responder that also records
    /// Inject/Withdraw actions. Tests use this to drive consecutive
    /// full-RIB projections without restarting originator state.
    fn rib_capture_dynamic_query_responder(
        mut rib_rx: mpsc::Receiver<RibUpdate>,
        routes: Vec<EvpnRibRoute>,
    ) -> RibDynamicResponder {
        let log = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let log_clone = log.clone();
        let (routes_tx, routes_rx) = watch::channel(routes);
        let join = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                match msg {
                    RibUpdate::QueryEvpnRoutes { reply } => {
                        let _ = reply.send(routes_rx.borrow().clone());
                    }
                    RibUpdate::InjectEvpn { route, reply } => {
                        log_clone.lock().await.push(RibAction::Inject(route.key()));
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::WithdrawEvpn { key, reply } => {
                        log_clone.lock().await.push(RibAction::Withdraw(key));
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            }
        });
        (log, routes_tx, join)
    }

    /// Gate 7c: a Type 2 event triggers a `repoll_rib` round-trip and
    /// the resulting full projection populates `remote_view`. Sub-
    /// second wakeup, full projection — neither half is short-cut.
    #[tokio::test]
    async fn handle_evpn_event_repolls_and_populates_remote_view() {
        let instances = instance_table(100);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(4);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);

        // RIB has one Type 2 from 10.0.0.2; the responder returns it
        // for every QueryEvpnRoutes.
        let route = evpn_macip_route(100, 0xAA, "10.0.0.2", Some(5), false);
        let _responder = rib_query_responder(rib_rx, vec![route.clone()]);

        let event = evpn_event_macip(
            100,
            0xAA,
            "10.0.0.2",
            Some(5),
            false,
            rustbgpd_rib::RouteEventType::Added,
            None,
        );

        handle_evpn_event(
            &event,
            &instances,
            &mut state,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        let view = state
            .remote_mac_view
            .get(&(vni(100), mac(0xAA)))
            .expect("event-triggered repoll must populate remote_view");
        assert_eq!(view.next_hop, ipa("10.0.0.2"));
        assert_eq!(view.mobility_sequence, Some(5));
    }

    /// Regression: a lower-mobility-sequence Added event for a
    /// **different RD** must NOT displace a higher-seq winner.
    /// `crates/evpn::project_evpn_routes` picks per-`(VNI, MAC)`
    /// across all RDs by mobility sequence (RFC 7432 §15.1) — the
    /// per-event delta we tried before would silently overwrite the
    /// cached view with the worse candidate.
    #[tokio::test]
    async fn handle_evpn_event_lower_seq_different_rd_does_not_displace_winner() {
        let instances = instance_table(100);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(4);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);

        // Two routes for the same (VNI, MAC) under different RDs.
        // PE-A wins on mobility seq (10 > 1).
        let mut pe_a = evpn_macip_route(100, 0xAA, "10.0.0.2", Some(10), false);
        if let EvpnRoute::MacIp(ref mut r) = pe_a.route {
            r.rd = rd(65000, 100);
        }
        let mut pe_b = evpn_macip_route(100, 0xAA, "10.0.0.3", Some(1), false);
        if let EvpnRoute::MacIp(ref mut r) = pe_b.route {
            r.rd = rd(65001, 999);
        }
        let _responder = rib_query_responder(rib_rx, vec![pe_a.clone(), pe_b.clone()]);

        // Drive the originator on PE-B's Added event — the worse
        // candidate. The repoll must still pick PE-A.
        let event = EvpnRouteEvent {
            event_type: rustbgpd_rib::RouteEventType::Added,
            key: pe_b.key(),
            best: Some(pe_b),
            previous_best: None,
            peer: Some(ipa("10.0.0.3")),
            previous_peer: None,
            timestamp: "0".to_string(),
        };

        handle_evpn_event(
            &event,
            &instances,
            &mut state,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        let view = state
            .remote_mac_view
            .get(&(vni(100), mac(0xAA)))
            .expect("projection must select PE-A even when PE-B's event triggered the repoll");
        assert_eq!(
            view.next_hop,
            ipa("10.0.0.2"),
            "winner is PE-A (seq=10), not PE-B (seq=1)"
        );
        assert_eq!(view.mobility_sequence, Some(10));
    }

    /// Regression: a Withdrawn event for a **non-winning** RD must
    /// NOT clear the cached view when a winning RD still exists in
    /// the RIB. The repoll model picks PE-A from what remains.
    #[tokio::test]
    async fn handle_evpn_event_non_winning_withdrawn_keeps_winning_view() {
        let instances = instance_table(100);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(4);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);
        state.remote_mac_view.insert(
            (vni(100), mac(0xAA)),
            RemoteMacView {
                mac: mac(0xAA),
                mobility_sequence: Some(10),
                sticky: false,
                next_hop: ipa("10.0.0.2"),
            },
        );

        // The losing PE-B is withdrawn — the RIB still returns PE-A.
        let mut pe_a = evpn_macip_route(100, 0xAA, "10.0.0.2", Some(10), false);
        if let EvpnRoute::MacIp(ref mut r) = pe_a.route {
            r.rd = rd(65000, 100);
        }
        let _responder = rib_query_responder(rib_rx, vec![pe_a.clone()]);

        // Synthesize the loser's prior route + Withdrawn event.
        let mut pe_b_prior = evpn_macip_route(100, 0xAA, "10.0.0.3", Some(1), false);
        if let EvpnRoute::MacIp(ref mut r) = pe_b_prior.route {
            r.rd = rd(65001, 999);
        }
        let event = EvpnRouteEvent {
            event_type: rustbgpd_rib::RouteEventType::Withdrawn,
            key: pe_b_prior.key(),
            best: None,
            previous_best: Some(pe_b_prior),
            peer: None,
            previous_peer: Some(ipa("10.0.0.3")),
            timestamp: "0".to_string(),
        };

        handle_evpn_event(
            &event,
            &instances,
            &mut state,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        let view = state
            .remote_mac_view
            .get(&(vni(100), mac(0xAA)))
            .expect("losing PE's withdrawal must NOT clear the winning view");
        assert_eq!(view.next_hop, ipa("10.0.0.2"));
        assert_eq!(view.mobility_sequence, Some(10));
    }

    /// Non-Type-2 events (Type 1/3/4/5) are out of scope today — they
    /// must not trigger a repoll. Verified by counting
    /// `QueryEvpnRoutes` messages on the RIB channel.
    #[tokio::test]
    async fn handle_evpn_event_non_macip_does_not_repoll() {
        let instances = instance_table(100);
        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(4);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);

        let query_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let qc = query_count.clone();
        let _responder = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                if let RibUpdate::QueryEvpnRoutes { reply } = msg {
                    qc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let _ = reply.send(vec![]);
                }
            }
        });

        // An IMET (Type 3) event — out of scope for the originator.
        let imet_key = EvpnRouteKey::Imet {
            rd: rd(65000, 100),
            ethernet_tag: EthernetTagId(0),
            originator_ip: ipa("10.0.0.2"),
        };
        let event = EvpnRouteEvent {
            event_type: rustbgpd_rib::RouteEventType::Added,
            key: imet_key,
            best: None,
            previous_best: None,
            peer: Some(ipa("10.0.0.2")),
            previous_peer: None,
            timestamp: "0".to_string(),
        };

        handle_evpn_event(
            &event,
            &instances,
            &mut state,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        assert_eq!(
            query_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "non-MacIp events must not trigger a repoll"
        );
    }

    /// ADR-0056: a `Learned` observation for a MAC in the instance's
    /// `sticky_macs` set must produce an `InjectEvpn` whose route
    /// carries the RFC 7432 §15.4 MAC Mobility extended community with
    /// `sticky = true`. Locks the only behavioral effect of the
    /// `sticky_macs` config schema end-to-end.
    #[tokio::test]
    async fn sticky_mac_observation_emits_inject_with_sticky_extcomm() {
        // Instance with one MAC marked sticky.
        let mut t = EvpnInstanceTable::new();
        let inst = local_instance(100).with_sticky_macs(BTreeSet::from([mac(0xAA)]));
        t.insert(inst).unwrap();
        let instances = Arc::new(t);

        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (local_tx, local_rx) = mpsc::channel(16);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let shutdown = CancellationToken::new();

        // Capture the first InjectEvpn so we can inspect its extcomms.
        let (captured_tx, captured_rx) =
            tokio::sync::oneshot::channel::<rustbgpd_rib::route::EvpnRibRoute>();
        let mut captured_tx = Some(captured_tx);
        let _rib_responder = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                match msg {
                    RibUpdate::QueryEvpnRoutes { reply } => {
                        let _ = reply.send(vec![]);
                    }
                    RibUpdate::InjectEvpn { route, reply } => {
                        if let Some(tx) = captured_tx.take() {
                            let _ = tx.send(route);
                        }
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
            metrics,
            counts,
            shutdown.clone(),
            std::sync::Arc::new(std::collections::BTreeMap::new()),
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

        let route = tokio::time::timeout(Duration::from_secs(2), captured_rx)
            .await
            .expect("InjectEvpn must arrive within 2s")
            .expect("captured_tx not dropped");

        let extcomms = route
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(v) => Some(v),
                _ => None,
            })
            .expect("originated route must carry an ExtendedCommunities attribute");
        let mobility = extcomms
            .iter()
            .find_map(|ec| ec.as_mac_mobility())
            .expect("sticky_macs MAC must emit a MAC Mobility extcomm at seq=0");
        assert!(
            mobility.0,
            "MAC Mobility extcomm sticky bit must be set for sticky_macs MAC"
        );

        h.shutdown().await;
    }

    /// A Withdrawn event for the only candidate clears the cached
    /// `RemoteMacView` — the repoll returns an empty route set, and
    /// `build_remote_view` of an empty set yields an empty cache.
    #[tokio::test]
    async fn handle_evpn_event_withdrawn_clears_remote_view_when_rib_empty() {
        let instances = instance_table(100);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(4);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);
        state.remote_mac_view.insert(
            (vni(100), mac(0xCC)),
            RemoteMacView {
                mac: mac(0xCC),
                mobility_sequence: Some(7),
                sticky: false,
                next_hop: ipa("10.0.0.2"),
            },
        );

        // RIB is empty — the route is gone.
        let _responder = rib_query_responder(rib_rx, vec![]);

        let prior = evpn_macip_route(100, 0xCC, "10.0.0.2", Some(7), false);
        let event = EvpnRouteEvent {
            event_type: rustbgpd_rib::RouteEventType::Withdrawn,
            key: prior.key(),
            best: None,
            previous_best: Some(prior),
            peer: None,
            previous_peer: Some(ipa("10.0.0.2")),
            timestamp: "0".to_string(),
        };

        handle_evpn_event(
            &event,
            &instances,
            &mut state,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        assert!(
            !state.remote_mac_view.contains_key(&(vni(100), mac(0xCC))),
            "Withdrawn with empty RIB must clear the cached remote_view entry"
        );
    }

    // -----------------------------------------------------------------
    // Gate 7b+2 slice 3 — MAC+IP correlation tests (replace model)
    // -----------------------------------------------------------------

    /// Capture an ordered log of `(InjectEvpn | WithdrawEvpn)` actions
    /// the daemon emits to the RIB. Returns the captured-actions
    /// handle; the responder ack's every Inject/Withdraw with `Ok(())`.
    fn rib_capture_responder(
        mut rib_rx: mpsc::Receiver<RibUpdate>,
    ) -> (RibActionLog, tokio::task::JoinHandle<()>) {
        let log = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let log_clone = log.clone();
        let join = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                match msg {
                    RibUpdate::InjectEvpn { route, reply } => {
                        log_clone.lock().await.push(RibAction::Inject(route.key()));
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::WithdrawEvpn { key, reply } => {
                        log_clone.lock().await.push(RibAction::Withdraw(key));
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::QueryEvpnRoutes { reply } => {
                        let _ = reply.send(vec![]);
                    }
                    _ => {}
                }
            }
        });
        (log, join)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum RibAction {
        Inject(EvpnRouteKey),
        Withdraw(EvpnRouteKey),
    }

    type RibActionLog = Arc<tokio::sync::Mutex<Vec<RibAction>>>;
    type RibDynamicResponder = (
        RibActionLog,
        watch::Sender<Vec<EvpnRibRoute>>,
        tokio::task::JoinHandle<()>,
    );

    fn macip_key_with(rd_v: u32, mac_b: u8, ip_str: Option<&str>) -> EvpnRouteKey {
        EvpnRouteKey::MacIp {
            rd: rd(65000, rd_v),
            ethernet_tag: EthernetTagId(0),
            mac: mac(mac_b),
            ip: ip_str.map(ipa),
        }
    }

    /// Slice 3 core flow: `Learned` then `IpAdded` produces a
    /// MAC-only Inject, then a MAC-only Withdraw (replacing it),
    /// then a MAC+IP Inject. The replace boundary is the load-bearing
    /// invariant — peers see the upgrade as an explicit handoff.
    #[tokio::test]
    async fn learned_then_ip_added_replaces_mac_only_with_mac_ip() {
        let instances = instance_table(100);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (log, _responder) = rib_capture_responder(rib_rx);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);

        handle_observation(
            &LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        handle_observation(
            &LocalMacObservation::IpAdded {
                vni: vni(100),
                mac: mac(0xAA),
                ip: ipa("192.0.2.10"),
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        let actions = log.lock().await.clone();
        assert_eq!(
            actions,
            vec![
                RibAction::Inject(macip_key_with(100, 0xAA, None)),
                RibAction::Withdraw(macip_key_with(100, 0xAA, None)),
                RibAction::Inject(macip_key_with(100, 0xAA, Some("192.0.2.10"))),
            ],
            "expected MAC-only Inject → MAC-only Withdraw → MAC+IP Inject"
        );
    }

    /// `IpAdded` before `Learned` parks the IP and emits no RIB action.
    /// The kernel can reorder these edges during cold start.
    #[tokio::test]
    async fn ip_added_before_learned_parks_pending_no_rib_action() {
        let instances = instance_table(100);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (log, _responder) = rib_capture_responder(rib_rx);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);

        handle_observation(
            &LocalMacObservation::IpAdded {
                vni: vni(100),
                mac: mac(0xAA),
                ip: ipa("192.0.2.10"),
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        assert!(log.lock().await.is_empty());
        assert!(
            state
                .pending_ip_bindings
                .get(&(vni(100), mac(0xAA)))
                .is_some_and(|s| s.contains(&ipa("192.0.2.10"))),
            "pending IP binding must be parked"
        );
    }

    /// When `Learned` arrives after pending IPs were parked, the
    /// daemon goes straight to MAC+IP — no MAC-only Inject is emitted
    /// at all (no transient L2-only window).
    #[tokio::test]
    async fn learned_after_pending_ip_skips_mac_only_inject() {
        let instances = instance_table(100);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (log, _responder) = rib_capture_responder(rib_rx);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);

        // IpAdded first (parked).
        handle_observation(
            &LocalMacObservation::IpAdded {
                vni: vni(100),
                mac: mac(0xAA),
                ip: ipa("192.0.2.10"),
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        // Then Learned drains the pending IP and emits MAC+IP directly.
        handle_observation(
            &LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        let actions = log.lock().await.clone();
        // Should be exactly one Inject for the MAC+IP route. No
        // MAC-only Inject; the on_local_aged on a never-advertised
        // MAC is a no-op so it doesn't appear either.
        assert_eq!(
            actions,
            vec![RibAction::Inject(macip_key_with(
                100,
                0xAA,
                Some("192.0.2.10")
            ))],
            "Learned after pending IP must skip MAC-only and emit MAC+IP only"
        );
        assert!(
            !state
                .pending_ip_bindings
                .contains_key(&(vni(100), mac(0xAA))),
            "pending bindings drained on Learned"
        );
    }

    /// `IpRemoved` of the **last** IP for a MAC downgrades back to
    /// MAC-only — withdraws the MAC+IP route and re-emits the MAC.
    #[tokio::test]
    async fn last_ip_removed_downgrades_to_mac_only() {
        let instances = instance_table(100);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (log, _responder) = rib_capture_responder(rib_rx);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);

        handle_observation(
            &LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;
        handle_observation(
            &LocalMacObservation::IpAdded {
                vni: vni(100),
                mac: mac(0xAA),
                ip: ipa("192.0.2.10"),
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;
        // Clear the log to focus on the IpRemoved phase.
        log.lock().await.clear();

        handle_observation(
            &LocalMacObservation::IpRemoved {
                vni: vni(100),
                mac: mac(0xAA),
                ip: ipa("192.0.2.10"),
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        let actions = log.lock().await.clone();
        assert_eq!(
            actions,
            vec![
                RibAction::Withdraw(macip_key_with(100, 0xAA, Some("192.0.2.10"))),
                RibAction::Inject(macip_key_with(100, 0xAA, None)),
            ],
            "expected MAC+IP Withdraw → MAC-only re-Inject"
        );
    }

    /// `IpRemoved` of a **non-last** IP withdraws only the MAC+IP for
    /// that key. MAC-only stays absent because other IPs still drive
    /// MAC+IP advertising for the same MAC.
    #[tokio::test]
    async fn non_last_ip_removed_keeps_mac_in_mac_ip_regime() {
        let instances = instance_table(100);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (log, _responder) = rib_capture_responder(rib_rx);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);

        handle_observation(
            &LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;
        for ip in ["192.0.2.10", "192.0.2.11"] {
            handle_observation(
                &LocalMacObservation::IpAdded {
                    vni: vni(100),
                    mac: mac(0xAA),
                    ip: ipa(ip),
                },
                &mut state,
                &instances,
                &rib_tx,
                &metrics,
                &counts,
                &std::collections::BTreeMap::new(),
            )
            .await;
        }
        log.lock().await.clear();

        handle_observation(
            &LocalMacObservation::IpRemoved {
                vni: vni(100),
                mac: mac(0xAA),
                ip: ipa("192.0.2.10"),
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        let actions = log.lock().await.clone();
        assert_eq!(
            actions,
            vec![RibAction::Withdraw(macip_key_with(
                100,
                0xAA,
                Some("192.0.2.10")
            ))],
            "non-last IP removal must NOT downgrade to MAC-only"
        );
    }

    /// `Aged` while multiple IPs are live cascades MAC+IP withdraws
    /// for every IP and clears the live cache. No MAC-only Withdraw
    /// fires because we were in MAC+IP regime.
    #[tokio::test]
    async fn aged_with_live_ips_cascades_mac_ip_withdraws() {
        let instances = instance_table(100);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (log, _responder) = rib_capture_responder(rib_rx);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);

        handle_observation(
            &LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;
        for ip in ["192.0.2.10", "2001:db8::1"] {
            handle_observation(
                &LocalMacObservation::IpAdded {
                    vni: vni(100),
                    mac: mac(0xAA),
                    ip: ipa(ip),
                },
                &mut state,
                &instances,
                &rib_tx,
                &metrics,
                &counts,
                &std::collections::BTreeMap::new(),
            )
            .await;
        }
        log.lock().await.clear();

        handle_observation(
            &LocalMacObservation::Aged {
                vni: vni(100),
                mac: mac(0xAA),
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        let actions = log.lock().await.clone();
        // Two MAC+IP Withdraws (order depends on BTreeMap iteration —
        // both must be present, no MAC-only Inject/Withdraw).
        assert_eq!(
            actions.len(),
            2,
            "expected 2 cascade MAC+IP withdraws: {actions:?}"
        );
        for a in &actions {
            assert!(
                matches!(
                    a,
                    RibAction::Withdraw(EvpnRouteKey::MacIp { ip: Some(_), .. })
                ),
                "every cascade action must be a MAC+IP Withdraw: {a:?}"
            );
        }
        assert!(
            !state
                .live_mac_ip
                .get(&vni(100))
                .is_some_and(|m| m.contains_key(&mac(0xAA))),
            "live cache cleared on Aged"
        );
        assert!(
            !state
                .local_macs
                .get(&vni(100))
                .is_some_and(|m| m.contains_key(&mac(0xAA))),
            "local_macs cleared on Aged"
        );
    }

    /// Counter regression: a non-last `IpRemoved` must NOT decrement
    /// `OriginatedLocalMacCounts` to zero for the MAC. Two MAC+IP
    /// routes for the same MAC each register a distinct
    /// `EvpnRouteKey`; withdrawing one removes only that key, leaving
    /// the MAC's count steady. Operator-visible — the gRPC
    /// `originated_local_macs_count` field would otherwise blink to
    /// zero under dual-stack hosts.
    #[tokio::test]
    async fn non_last_ip_removed_keeps_originated_count_stable() {
        let instances = instance_table(100);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (_log, _responder) = rib_capture_responder(rib_rx);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);

        handle_observation(
            &LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;
        for ip in ["192.0.2.10", "2001:db8::1"] {
            handle_observation(
                &LocalMacObservation::IpAdded {
                    vni: vni(100),
                    mac: mac(0xAA),
                    ip: ipa(ip),
                },
                &mut state,
                &instances,
                &rib_tx,
                &metrics,
                &counts,
                &std::collections::BTreeMap::new(),
            )
            .await;
        }

        assert_eq!(counts.count(vni(100)), 1, "one MAC has two live keys");

        // Withdraw one of the two MAC+IP routes — the MAC still has
        // its second route live, so the count must NOT drop.
        handle_observation(
            &LocalMacObservation::IpRemoved {
                vni: vni(100),
                mac: mac(0xAA),
                ip: ipa("192.0.2.10"),
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;
        assert_eq!(
            counts.count(vni(100)),
            1,
            "non-last IpRemoved must NOT decrement the MAC's count"
        );

        // Withdrawing the last IP downgrades to MAC-only (re-Inject).
        // The MAC retains a single live key — the MAC-only NLRI.
        handle_observation(
            &LocalMacObservation::IpRemoved {
                vni: vni(100),
                mac: mac(0xAA),
                ip: ipa("2001:db8::1"),
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;
        assert_eq!(
            counts.count(vni(100)),
            1,
            "downgrade to MAC-only keeps the MAC counted"
        );

        // Aged drains the last route — count drops.
        handle_observation(
            &LocalMacObservation::Aged {
                vni: vni(100),
                mac: mac(0xAA),
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;
        assert_eq!(counts.count(vni(100)), 0, "Aged clears the count");
    }

    /// Replace-invariant regression: a `Learned` re-emit while MAC+IP
    /// is already advertising must NOT produce another MAC-only
    /// Inject. The kernel can re-emit `RTM_NEWNEIGH AF_BRIDGE` for an
    /// already-known MAC (e.g., after a port flap or a state
    /// transition); emitting a MAC-only Type 2 then would put us in
    /// a "both advertising" state that the replace model forbids.
    #[tokio::test]
    async fn relearn_while_mac_ip_live_does_not_re_emit_mac_only() {
        let instances = instance_table(100);
        let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
        let (log, _responder) = rib_capture_responder(rib_rx);
        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);

        // Drive the MAC into MAC+IP regime: Learned then IpAdded.
        handle_observation(
            &LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;
        handle_observation(
            &LocalMacObservation::IpAdded {
                vni: vni(100),
                mac: mac(0xAA),
                ip: ipa("192.0.2.10"),
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;
        // Snapshot the action log: should be exactly the upgrade
        // sequence (MAC-only Inject, MAC-only Withdraw, MAC+IP Inject).
        let initial = log.lock().await.clone();
        assert_eq!(initial.len(), 3, "expected upgrade sequence: {initial:?}");

        // Now the kernel re-emits a Learned for the same MAC.
        handle_observation(
            &LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        let after = log.lock().await.clone();
        assert_eq!(
            after, initial,
            "Learned while MAC+IP is live must NOT add a MAC-only Inject \
             (replace invariant): {after:?}"
        );
    }

    /// Sticky pass-through to MAC+IP: a MAC listed in
    /// `[[evpn_instances]].sticky_macs` originates the MAC+IP Type 2
    /// with the RFC 7432 §15.4 sticky bit set on its MAC Mobility
    /// extcomm. ADR-0056's promise must hold for both NLRI shapes.
    #[tokio::test]
    async fn sticky_macs_propagates_to_mac_ip_route() {
        // Instance with one sticky MAC.
        let mut t = EvpnInstanceTable::new();
        let inst = local_instance(100).with_sticky_macs(BTreeSet::from([mac(0xAA)]));
        t.insert(inst).unwrap();
        let instances = Arc::new(t);

        let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);

        // Capture the first MAC+IP Inject for inspection.
        let (captured_tx, captured_rx) = tokio::sync::oneshot::channel::<EvpnRibRoute>();
        let mut captured_tx = Some(captured_tx);
        let _responder = tokio::spawn(async move {
            while let Some(msg) = rib_rx.recv().await {
                match msg {
                    RibUpdate::QueryEvpnRoutes { reply } => {
                        let _ = reply.send(vec![]);
                    }
                    RibUpdate::InjectEvpn { route, reply } => {
                        if matches!(route.route, EvpnRoute::MacIp(EvpnMacIp { ip: Some(_), .. }))
                            && let Some(tx) = captured_tx.take()
                        {
                            let _ = tx.send(route.clone());
                        }
                        let _ = reply.send(Ok(()));
                    }
                    RibUpdate::WithdrawEvpn { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            }
        });

        let metrics = BgpMetrics::new();
        let counts = OriginatedLocalMacCounts::default();
        let mut state = originator_state(&instances);

        handle_observation(
            &LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xAA),
                ifindex: 10,
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;
        handle_observation(
            &LocalMacObservation::IpAdded {
                vni: vni(100),
                mac: mac(0xAA),
                ip: ipa("192.0.2.10"),
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
        )
        .await;

        let route = tokio::time::timeout(Duration::from_secs(2), captured_rx)
            .await
            .expect("MAC+IP Inject must arrive within 2s")
            .expect("captured_tx not dropped");

        let extcomms = route
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(v) => Some(v),
                _ => None,
            })
            .expect("originated MAC+IP route must carry ExtendedCommunities");
        let mobility = extcomms
            .iter()
            .find_map(|ec| ec.as_mac_mobility())
            .expect("sticky_macs MAC must emit a MAC Mobility extcomm");
        assert!(
            mobility.0,
            "sticky bit must propagate from sticky_macs to MAC+IP route"
        );
    }
}
