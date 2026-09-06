//! Daemon-side EVPN local-MAC originator (Gate 7b+1).
//!
//! Mirrors `crate::evpn_dataplane::spawn_with_quarantine` but on the **opposite
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
//! (added by Gate 7c) and uses Type 2 best-path changes as wakeups for a
//! full `QueryEvpnRoutes` projection. Ready Type 2 bursts are coalesced
//! into one query so mass route churn does not serialize one full repoll
//! per event. The 5 s `poll_tick` is retained as a backstop for two
//! narrow cases:
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
//! When `[[evpn_instances]]` is empty, [`spawn_with_quarantine`] returns `None`. No
//! background task is created; the EVPN originator counters remain at
//! zero-label-vector state until an originator action is observed.
//!
//! ## Self-origination filter
//!
//! `RemoteMacView`s passed into the state machine **must not** carry
//! routes whose next-hop matches the local instance's `local_vtep_ip`
//! — otherwise the originator would see its own re-Inject as a
//! contender and bump indefinitely. The polling code drops self-NH
//! routes before the projection. Routes advertised by a PE on the
//! VNI's own Ethernet Segment are dropped at the same point: they are
//! peer-sync routes (RFC 7432 §15, RFC 9721 §6.4), and treating them
//! as contenders would make an all-active pair ratchet each other's
//! sequence and count the echo as duplicate-MAC moves. A separate peer-sync
//! view retains eligible sequence floors: locally owned MACs and their local
//! IP bindings adopt higher floors exactly, without creating peer-only local
//! ownership or feeding either duplicate detector.
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

use crate::evpn_ack::PendingRibOps;
use crate::evpn_originator::duplicate_mac::{handle_originator_command, recover_duplicate_macs};
use crate::evpn_originator::lifecycle::{apply_runtime_model, replay_pending_local_macs};
#[cfg(test)]
use crate::evpn_originator::observation::handle_observation;
use crate::evpn_originator::rib_polling::{
    handle_evpn_event_coalesced, recv_evpn_event, repoll_rib, subscribe_evpn_events,
};
use crate::evpn_originator::rib_write::{
    drain_to_withdraws, extract_ip_from_key, next_hop_path_attribute, retry_pending_rib_ops,
};
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
    /// this actor drains removed VNIs, and for a redefined VNI drains the
    /// old-RD routes then re-originates the preserved local MAC/IP state
    /// under the new instance fields, before accepting the new table for
    /// future local observations and RIB-event replay.
    ///
    /// `drained_esis` is the ADR-0084 operator-drained ESI set: a VNI
    /// whose mapped ESI is newly drained withdraws its advertised local
    /// Type 2 routes WITHOUT clearing the local observation caches and
    /// without replay; a newly-undrained VNI replays the cached local
    /// MAC/IP state (quarantine-respecting).
    #[must_use]
    pub fn replace_runtime_model(
        &self,
        instances: Arc<EvpnInstanceTable>,
        vni_to_esi: Arc<std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>>,
        drained_esis: Arc<BTreeSet<EthernetSegmentIdentifier>>,
    ) -> bool {
        if self.model_tx.is_closed() {
            return false;
        }
        self.model_tx.send_replace(Arc::new(OriginatorRuntimeModel {
            instances,
            vni_to_esi,
            drained_esis,
        }));
        true
    }
}

#[cfg(test)]
impl EvpnOriginatorRuntimeControl {
    /// Control whose actor has already exited (the watch receiver is
    /// dropped immediately), so every publish fails. Used by the
    /// cross-actor seam tests to pin the drain primitive's rollback
    /// behavior on an originator publish failure.
    pub(crate) fn closed_for_test() -> Self {
        let (model_tx, _) = watch::channel(Arc::new(OriginatorRuntimeModel {
            instances: Arc::new(EvpnInstanceTable::new()),
            vni_to_esi: Arc::new(std::collections::BTreeMap::new()),
            drained_esis: Arc::new(BTreeSet::new()),
        }));
        Self { model_tx }
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
    /// this actor drains removed VNIs, and for a redefined VNI drains the
    /// old-RD routes then re-originates the preserved local MAC/IP state
    /// under the new instance fields, before accepting the new table for
    /// future local observations and RIB-event replay.
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
        drained_esis: Arc<BTreeSet<EthernetSegmentIdentifier>>,
    ) -> bool {
        self.runtime_control()
            .replace_runtime_model(instances, vni_to_esi, drained_esis)
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
    /// ADR-0084 operator-drained ESIs. A VNI whose mapped ESI is in
    /// this set keeps its local observation caches up to date from
    /// kernel events but originates nothing until undrained.
    drained_esis: Arc<BTreeSet<EthernetSegmentIdentifier>>,
}

#[derive(Debug)]
struct OriginatorRuntimeModel {
    instances: Arc<EvpnInstanceTable>,
    vni_to_esi: Arc<std::collections::BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>>,
    /// ADR-0084 operator-drained ESI set the model was published with.
    drained_esis: Arc<BTreeSet<EthernetSegmentIdentifier>>,
}

/// Whether a VNI's mapped Ethernet Segment is operator-drained
/// (ADR-0084). VNIs without an ESI mapping are never drained.
pub(crate) fn vni_is_drained(
    vni: EvpnInstanceId,
    vni_to_esi: &BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>,
    drained_esis: &BTreeSet<EthernetSegmentIdentifier>,
) -> bool {
    vni_to_esi
        .get(&vni)
        .is_some_and(|esi| drained_esis.contains(esi))
}

/// Test helper that spawns the originator with an empty duplicate-MAC quarantine.
/// Returns `None` for RR-only deployments (empty `evpn_instances`).
#[expect(
    clippy::too_many_arguments,
    reason = "originator spawn keeps each explicit actor dependency visible"
)]
#[cfg(test)]
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

#[expect(
    clippy::too_many_arguments,
    reason = "quarantine-aware spawn keeps each explicit actor dependency visible"
)]
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
    // Drain state is runtime-only and in-memory (ADR-0084): every
    // spawn starts with an empty drained set, so a daemon restart
    // clears any drain and replays configured state.
    let (model_tx, model_rx) = watch::channel(Arc::new(OriginatorRuntimeModel {
        instances: evpn_instances.clone(),
        vni_to_esi: vni_to_esi.clone(),
        drained_esis: Arc::new(BTreeSet::new()),
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
        drained_esis: Arc::new(BTreeSet::new()),
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
    /// Current admitted remote IP owners, carrying each MAC's effective sequence.
    /// Refreshed with the contender snapshot, independently of duplicate diagnostics.
    remote_ip_owners: BTreeMap<(EvpnInstanceId, IpAddr), BTreeMap<MacAddress, u32>>,
    /// Floors computed by real local IP ownership activations. Retained across
    /// withdrawal and suppression; a snapshot or replay cannot raise them.
    local_ip_owner_sequences: BTreeMap<(EvpnInstanceId, MacAddress), u32>,
    /// New local observations must not consume an absent or failed RIB snapshot.
    remote_snapshot_ready: bool,
    /// Runtime-model replay waits for a successful snapshot in the new scope.
    pending_local_replays: LocalMacReplaySet,
    /// Recreated VNI/ESI scopes initialize ownership floors once on that replay.
    pending_ip_owner_scopes: BTreeSet<EvpnInstanceId>,
    /// Same-segment sequence floors, separate from mobility contenders.
    peer_sync_sequences: BTreeMap<(EvpnInstanceId, MacAddress), u32>,
    /// Locally owned MACs that participated in peer sync in this VNI/ESI scope.
    /// Retained local sequences still synchronize children after the peer leaves.
    peer_sync_participants: BTreeSet<(EvpnInstanceId, MacAddress)>,
    /// RFC 7432 §15.1 duplicate-MAC detector. The pure detector owns
    /// the M/N window and active suppressions; this daemon state owns
    /// the route-withdraw/replay policy.
    duplicate_mac_detector: DuplicateMacDetector,
    duplicate_ip: duplicate_ip::DuplicateIpState,
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
    /// ADR-0102 acknowledgement tracker: every inject/withdraw sent to
    /// the RIB stays pending here until the RIB acks it; the actor's
    /// retry arm re-drives unacknowledged operations with bounded
    /// backoff. In-memory only — a restart rebuilds intent from kernel
    /// observation instead of replaying pending operations.
    pending_rib_ops: PendingRibOps,
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
            remote_ip_owners: BTreeMap::new(),
            local_ip_owner_sequences: BTreeMap::new(),
            remote_snapshot_ready: false,
            pending_local_replays: BTreeMap::new(),
            pending_ip_owner_scopes: BTreeSet::new(),
            peer_sync_sequences: BTreeMap::new(),
            peer_sync_participants: BTreeSet::new(),
            duplicate_mac_detector: DuplicateMacDetector::default(),
            duplicate_ip: duplicate_ip::DuplicateIpState::default(),
            known_duplicate_mac_keys: BTreeSet::new(),
            active_duplicate_mac_quarantines: BTreeSet::new(),
            duplicate_mac_quarantine_tx,
            pending_rib_ops: PendingRibOps::new(),
        }
    }

    fn has_live_ip_binding(&self, vni: EvpnInstanceId, mac: MacAddress, ip: IpAddr) -> bool {
        self.live_mac_ip
            .get(&vni)
            .and_then(|macs| macs.get(&mac))
            .is_some_and(|ips| ips.contains(&ip))
    }

    /// Record a new local binding's cross-MAC ownership floor once. Call only
    /// for a newly active binding or a recreated VNI/ESI scope, never for a
    /// kernel refresh or recovery of an already live binding.
    fn record_ip_owner_sequence(&mut self, vni: EvpnInstanceId, mac: MacAddress, ip: IpAddr) {
        let Some(remote_sequence) = self.remote_ip_owners.get(&(vni, ip)).and_then(|owners| {
            owners
                .iter()
                .filter_map(|(owner, sequence)| (*owner != mac).then_some(*sequence))
                .max()
        }) else {
            return;
        };
        let sequence = remote_sequence
            .max(
                self.remote_mac_view
                    .get(&(vni, mac))
                    .and_then(|view| view.mobility_sequence)
                    .unwrap_or(0),
            )
            .saturating_add(1);
        self.local_ip_owner_sequences
            .entry((vni, mac))
            .and_modify(|current| *current = (*current).max(sequence))
            .or_insert(sequence);
    }

    /// Fold exact peer and retained local ownership floors into an action batch.
    /// Replacing an Inject before submission avoids briefly advertising the old
    /// sequence. The RIB acknowledgement tracker remains the sole writer.
    fn prepare_peer_sync_actions(
        &mut self,
        vni: EvpnInstanceId,
        mac: MacAddress,
        mut actions: Vec<OriginationAction>,
    ) -> Vec<OriginationAction> {
        if !self
            .local_macs
            .get(&vni)
            .is_some_and(|macs| macs.contains_key(&mac))
        {
            return actions;
        }
        let peer_sequence = match self.peer_sync_sequences.get(&(vni, mac)).copied() {
            Some(sequence) => {
                self.peer_sync_participants.insert((vni, mac));
                sequence
            }
            None if self.peer_sync_participants.contains(&(vni, mac))
                || self.local_ip_owner_sequences.contains_key(&(vni, mac)) =>
            {
                0
            }
            None => return actions,
        };
        let sequence = peer_sequence
            .max(
                self.local_ip_owner_sequences
                    .get(&(vni, mac))
                    .copied()
                    .unwrap_or(0),
            )
            .max(
                self.mac_originators
                    .get(&vni)
                    .and_then(|orig| orig.sequence_for_mac(mac))
                    .unwrap_or(0),
            )
            .max(
                self.mac_ip_originators
                    .get(&vni)
                    .and_then(|orig| orig.sequence_for_mac(mac))
                    .unwrap_or(0),
            );
        if let Some(retained) = self.local_ip_owner_sequences.get_mut(&(vni, mac)) {
            *retained = (*retained).max(sequence);
        }
        let mut adopted = Vec::new();
        if let Some(orig) = self.mac_originators.get_mut(&vni) {
            adopted.extend(orig.adopt_peer_sequence(mac, sequence));
        }
        if let Some(orig) = self.mac_ip_originators.get_mut(&vni) {
            adopted.extend(orig.adopt_peer_sequence(mac, sequence));
        }
        for action in adopted {
            let OriginationAction::Inject { key, .. } = &action else {
                continue;
            };
            if let Some(existing) = actions.iter_mut().find(|candidate| {
                matches!(candidate, OriginationAction::Inject { key: candidate_key, .. } if candidate_key == key)
            }) {
                *existing = action;
            } else {
                actions.push(action);
            }
        }
        actions
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

#[expect(
    clippy::too_many_lines,
    reason = "the actor select keeps shutdown, observations, RIB events, and recovery ordered"
)]
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

    // A native bounded receive batch shares one current snapshot. In poll-only
    // mode it is collected before the scheduled query and retained if that
    // query fails; no binding can advertise against an unknown ownership view.
    let batch_limit = local_mac_rx.max_capacity();
    let mut observations = Vec::with_capacity(batch_limit);
    loop {
        let mut recovery_due = false;
        let batch_remaining = batch_limit - observations.len();
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
                        &runtime.drained_esis,
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
            // ADR-0102: re-drive RIB operations whose acknowledgement
            // was lost (dropped reply, timeout, backpressure). Parks
            // forever while nothing is pending.
            () = crate::evpn_ack::retry_delay(state.pending_rib_ops.next_deadline()) => {
                retry_pending_rib_ops(
                    &mut state,
                    &runtime.instances,
                    &runtime.rib_tx,
                    &runtime.metrics,
                    &runtime.originated_local_mac_counts,
                    &runtime.vni_to_esi,
                ).await;
            }
            _ = poll_tick.tick() => {
                collect_ready_observations(&mut local_mac_rx, &mut observations);
                if let Err(e) = repoll_rib(
                    &runtime.instances,
                    &runtime.rib_tx,
                    &mut state,
                    &runtime.metrics,
                    &runtime.originated_local_mac_counts,
                    &runtime.vni_to_esi,
                ).await {
                    warn!(error = %e, "EVPN originator: RIB poll failed");
                } else {
                    recovery_due = true;
                }
            }
            event = recv_evpn_event(&mut evpn_event_rx) => {
                collect_ready_observations(&mut local_mac_rx, &mut observations);
                match event {
                Ok(ev) => {
                    handle_evpn_event_coalesced(
                        ev,
                        &mut evpn_event_rx,
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
                    state.remote_snapshot_ready = false;
                }
                }
            },
            count = local_mac_rx.recv_many(&mut observations, batch_remaining),
                if local_mac_rx_open && batch_remaining > 0 => {
                if count == 0 {
                    debug!("local-mac channel closed; originator idle");
                    local_mac_rx_open = false;
                    continue;
                }
                if evpn_event_rx.is_none() {
                    state.remote_snapshot_ready = false;
                }
            }
        }
        observation::process_observation_batch(&mut observations, &mut state, &runtime).await;
        if state.remote_snapshot_ready {
            replay_pending_local_macs(&mut state, &runtime).await;
            if recovery_due {
                state.duplicate_ip.expire(Instant::now());
                recover_duplicate_macs(
                    &mut state,
                    &runtime.instances,
                    &runtime.rib_tx,
                    &runtime.metrics,
                    &runtime.originated_local_mac_counts,
                    &runtime.vni_to_esi,
                    &runtime.drained_esis,
                )
                .await;
            }
        }
    }
}

/// Collect at most one channel capacity, keeping an older failed batch ordered
/// ahead of new observations. A full deferred batch backpressures the channel
/// until a snapshot succeeds; snapshot failure cannot grow an unbounded queue.
fn collect_ready_observations(
    rx: &mut mpsc::Receiver<LocalMacObservation>,
    observations: &mut Vec<LocalMacObservation>,
) {
    for _ in observations.len()..rx.max_capacity() {
        let Ok(obs) = rx.try_recv() else { break };
        observations.push(obs);
    }
}

/// Per-VNI local MACs to replay after an ESI-map-only change.
type LocalMacReplaySet = BTreeMap<EvpnInstanceId, BTreeSet<MacAddress>>;

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

#[derive(Debug, thiserror::Error)]
enum RibQueryError {
    #[error("RIB channel send failed")]
    SendFailed,
    #[error("RIB query reply channel dropped")]
    ReplyDropped,
}

mod duplicate_ip;
mod duplicate_mac;
mod lifecycle;
mod observation;
mod rib_polling;
mod rib_write;
#[cfg(test)]
mod tests;
