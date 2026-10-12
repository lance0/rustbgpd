//! ADR-0140 core-isolation hold for bound Ethernet Segments.
//!
//! A PE that loses every L2VPN/EVPN session, or every configured uplink,
//! takes the CE-facing members of each bound segment administratively
//! down so the CE removes them from its LAG; at startup it holds them
//! down until EVPN has synced. Opt-in through `[evpn_core_isolation]`.
//!
//! ## Shape
//!
//! - [`HoldPlanner`] is the pure decision core: session and uplink
//!   observations plus `Instant`s in, per-binding hold decisions out
//!   (startup hold, isolation with the decision 4 peer check, recovery
//!   with the settle hold and the backstop). Paused-clock unit tests
//!   drive it directly.
//! - [`Controller`] owns the kernel side: it polls the RIB every
//!   [`POLL_INTERVAL`] (Type 4 routes first, then the session counts,
//!   so the last-session-down flush cannot clear the peer latch first),
//!   rediscovers bond members on every `RTNLGRP_LINK` event and poll, and
//!   applies the plan with fresh per-link checks, publishing the
//!   write-ahead [`receipt`] before every admin-down.
//! - [`release_core_isolation`] is the out-of-process
//!   `--release-core-isolation` helper: no config, the lock, the safe
//!   rule, and a loud exit status.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustbgpd_evpn_linux::{AdminLinkState, AdminLinks};
use rustbgpd_rib::{EvpnSessionsSync, RibUpdate, route::EvpnRibRoute};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::EvpnRoute;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::{CoreIsolationBinding, CoreIsolationSnapshot, EvpnCoreIsolationConfig};

pub(crate) mod receipt;

use receipt::{Guard, HostIdentity, LinkIdentity, OpenError, OwnedLink, ReceiptStore};

/// RIB poll cadence for the session signal and the peer latch. The same
/// 1 s cadence as the segment actor's boot-sync poll; uplink carrier is
/// event-driven.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Bound on one RIB query, so a stalled RIB delays a decision instead of
/// wedging the controller.
const RIB_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Published by the daemon on every committed config advance.
pub(crate) type CoreIsolationConfig = Arc<CoreIsolationSnapshot>;

// ─── planner ─────────────────────────────────────────────────────────

/// Global hold phase (ADR-0140 decision 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Armed at daemon start; holds every bound segment.
    Startup { since: Instant, core_seen_up: bool },
    /// The PE is core-isolated.
    Isolated,
    /// The core is back; waiting for sync plus the settle hold, or the
    /// backstop from `since`.
    Recovering { since: Instant },
    /// No hold.
    Released,
}

/// What one RIB poll and link scan observed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Observation {
    pub sessions: EvpnSessionsSync,
    /// Every effective uplink lacks carrier.
    pub uplinks_down: bool,
    /// Remote ES peers per bound interface, from a Type 4 read made
    /// before a session read that still showed an Established session.
    /// Interfaces without a resolved ESI are absent and keep their latch.
    pub peers: Option<BTreeMap<String, BTreeSet<IpAddr>>>,
}

impl Observation {
    fn sessions_isolated(&self) -> bool {
        self.sessions.established == 0 && self.sessions.stale == 0
    }

    fn isolated(&self) -> bool {
        self.sessions_isolated() || self.uplinks_down
    }
}

/// Per-binding hold decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HoldDecision {
    /// Members must be held down; carries the metric state.
    Hold(&'static str),
    /// Members must be up; carries the metric state.
    Release(&'static str),
}

/// Pure decision core.
#[derive(Debug)]
pub(crate) struct HoldPlanner {
    hold_after_sync: Duration,
    backstop: Duration,
    phase: Phase,
    /// Bindings held in the current phase.
    held: BTreeSet<String>,
    /// Bindings an isolation did not hold (decision 4).
    suppressed: BTreeSet<String>,
    /// Remote ES peers latched while the core was up (decision 4).
    peers: BTreeMap<String, BTreeSet<IpAddr>>,
    /// Since when EVPN has been continuously synced and not isolated.
    synced_since: Option<Instant>,
    /// Released by the backstop; cleared once sync is observed.
    backstop_unsynced: bool,
}

impl HoldPlanner {
    /// A planner armed with the startup hold at `start`.
    pub(crate) fn startup(settings: &EvpnCoreIsolationConfig, start: Instant) -> Self {
        let mut planner = Self::released(settings);
        planner.phase = Phase::Startup {
            since: start,
            core_seen_up: false,
        };
        planner
    }

    /// A planner with no hold, for a feature enabled after startup.
    pub(crate) fn released(settings: &EvpnCoreIsolationConfig) -> Self {
        Self {
            hold_after_sync: Duration::from_secs(settings.hold_after_sync_seconds),
            backstop: Duration::from_secs(settings.backstop_seconds),
            phase: Phase::Released,
            held: BTreeSet::new(),
            suppressed: BTreeSet::new(),
            peers: BTreeMap::new(),
            synced_since: None,
            backstop_unsynced: false,
        }
    }

    /// Apply new timers; the phase and its clocks are kept.
    pub(crate) fn retime(&mut self, settings: &EvpnCoreIsolationConfig) {
        self.hold_after_sync = Duration::from_secs(settings.hold_after_sync_seconds);
        self.backstop = Duration::from_secs(settings.backstop_seconds);
    }

    /// Fold one observation for the current binding set at `now`.
    /// Returns a log line for each phase transition.
    pub(crate) fn observe(
        &mut self,
        bindings: &BTreeSet<String>,
        observation: &Observation,
        now: Instant,
    ) -> Vec<(&'static str, String)> {
        let mut events = Vec::new();
        self.held.retain(|b| bindings.contains(b));
        self.suppressed.retain(|b| bindings.contains(b));
        self.peers.retain(|b, _| bindings.contains(b));
        if observation.sessions.established > 0
            && let Some(peers) = &observation.peers
        {
            for (binding, set) in peers {
                if bindings.contains(binding) {
                    self.peers.insert(binding.clone(), set.clone());
                }
            }
        }
        let isolated = observation.isolated();
        if isolated || !observation.sessions.synced {
            self.synced_since = None;
        } else {
            self.synced_since.get_or_insert(now);
        }
        let settled = self
            .synced_since
            .is_some_and(|since| now.saturating_duration_since(since) >= self.hold_after_sync);

        match self.phase {
            Phase::Startup {
                since,
                core_seen_up,
            } => {
                // The startup hold covers every bound segment, including
                // one added while it is armed.
                self.held.clone_from(bindings);
                if isolated && core_seen_up {
                    events.push(self.enter_isolation(bindings));
                } else if settled {
                    events.push(self.release("released", "startup hold released after EVPN sync"));
                } else if now.saturating_duration_since(since) >= self.backstop {
                    events.push(self.release_backstop("startup"));
                } else if !isolated {
                    self.phase = Phase::Startup {
                        since,
                        core_seen_up: true,
                    };
                }
            }
            Phase::Isolated => {
                if !isolated {
                    self.suppressed.clear();
                    self.phase = Phase::Recovering { since: now };
                    events.push((
                        "recovering",
                        "core reachable again; holding until EVPN syncs and settles".to_string(),
                    ));
                }
            }
            Phase::Recovering { since } => {
                if isolated {
                    events.push(self.enter_isolation(bindings));
                } else if settled {
                    events
                        .push(self.release("released", "isolation hold released after EVPN sync"));
                } else if now.saturating_duration_since(since) >= self.backstop {
                    events.push(self.release_backstop("isolation"));
                }
            }
            Phase::Released => {
                if isolated {
                    events.push(self.enter_isolation(bindings));
                } else if self.backstop_unsynced && observation.sessions.synced {
                    self.backstop_unsynced = false;
                    events.push((
                        "released",
                        "EVPN synced after a backstop release".to_string(),
                    ));
                }
            }
        }
        events
    }

    /// No session read yet (or the RIB did not answer): only the
    /// backstop can move a hold, so a stalled RIB never pins links down.
    pub(crate) fn expire(
        &mut self,
        bindings: &BTreeSet<String>,
        now: Instant,
    ) -> Vec<(&'static str, String)> {
        self.held.retain(|b| bindings.contains(b));
        match self.phase {
            Phase::Startup { since, .. } => {
                self.held.clone_from(bindings);
                if now.saturating_duration_since(since) >= self.backstop {
                    return vec![self.release_backstop("startup")];
                }
            }
            Phase::Recovering { since }
                if now.saturating_duration_since(since) >= self.backstop =>
            {
                return vec![self.release_backstop("isolation")];
            }
            _ => {}
        }
        Vec::new()
    }

    fn enter_isolation(&mut self, bindings: &BTreeSet<String>) -> (&'static str, String) {
        self.phase = Phase::Isolated;
        self.backstop_unsynced = false;
        self.synced_since = None;
        self.held = bindings
            .iter()
            .filter(|b| self.peers.get(*b).is_some_and(|p| !p.is_empty()))
            .cloned()
            .collect();
        self.suppressed = bindings.difference(&self.held).cloned().collect();
        (
            "isolated",
            format!(
                "PE is core-isolated; holding {} bound segment(s), {} without a remote ES peer \
                 left up",
                self.held.len(),
                self.suppressed.len()
            ),
        )
    }

    fn release(&mut self, code: &'static str, message: &str) -> (&'static str, String) {
        self.phase = Phase::Released;
        self.held.clear();
        self.suppressed.clear();
        (code, message.to_string())
    }

    fn release_backstop(&mut self, which: &str) -> (&'static str, String) {
        let event = self.release(
            "backstop_unsynced",
            &format!(
                "{which} hold released by the {}s backstop before EVPN synced; the CE may \
                 send traffic this PE has no routes for",
                self.backstop.as_secs()
            ),
        );
        self.backstop_unsynced = true;
        event
    }

    /// The decision for `binding`.
    pub(crate) fn decision(&self, binding: &str) -> HoldDecision {
        if matches!(self.phase, Phase::Startup { .. }) {
            return HoldDecision::Hold("startup_hold");
        }
        if self.held.contains(binding) {
            return HoldDecision::Hold(match self.phase {
                Phase::Startup { .. } => "startup_hold",
                Phase::Isolated => "isolated",
                Phase::Recovering { .. } | Phase::Released => "recovering",
            });
        }
        if self.suppressed.contains(binding) {
            return HoldDecision::Release("suppressed_no_peer");
        }
        if self.backstop_unsynced {
            return HoldDecision::Release("backstop_released");
        }
        HoldDecision::Release("released")
    }
}

// ─── controller ──────────────────────────────────────────────────────

/// Kernel and daemon dependencies.
pub(crate) struct CoreIsolationDeps {
    pub rib_tx: mpsc::Sender<RibUpdate>,
    pub metrics: BgpMetrics,
    /// The pinned runtime-state directory; `None` disables every action.
    pub directory: Option<std::fs::File>,
    /// Daemon start, where the startup hold's backstop clock begins.
    pub start: Instant,
}

/// Handle to the controller task.
pub(crate) struct CoreIsolationHandle {
    stop: CancellationToken,
    task: tokio::task::JoinHandle<Controller>,
}

impl CoreIsolationHandle {
    /// Stop deciding. Held links stay down until [`Self::release`].
    pub(crate) fn freeze(&self) {
        self.stop.cancel();
    }

    /// Clean-shutdown release (ADR-0140 decision 6): wait for the frozen
    /// task, raise every held link through the fresh checks, and remove
    /// the receipt unless ambiguous entries remain.
    pub(crate) async fn release(self) {
        self.stop.cancel();
        match self.task.await {
            Ok(mut controller) => controller.release_all().await,
            Err(error) => error!(%error, "core-isolation controller task failed before release"),
        }
    }
}

/// Spawn the controller.
pub(crate) fn spawn(
    config_rx: watch::Receiver<CoreIsolationConfig>,
    deps: CoreIsolationDeps,
) -> CoreIsolationHandle {
    let stop = CancellationToken::new();
    let controller = Controller::new(deps);
    let task = tokio::spawn(controller.run(config_rx, stop.clone()));
    CoreIsolationHandle { stop, task }
}

/// Owned kernel-side state for one binding.
#[derive(Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent per-binding report flags, each mapped to one metric state"
)]
struct BindingRuntime {
    /// Members seen raised by another writer during this hold.
    overridden: BTreeSet<(u32, String)>,
    action_failed: bool,
    ambiguous: bool,
    ambiguous_logged: bool,
    uplink_overlap: bool,
    reported: Option<&'static str>,
}

pub(crate) struct Controller {
    deps: CoreIsolationDeps,
    snapshot: CoreIsolationConfig,
    planner: Option<HoldPlanner>,
    /// Whether the startup hold may still arm (only for the first
    /// enabled snapshot at daemon start).
    startup: bool,
    store: Option<ReceiptStore>,
    host: Option<HostIdentity>,
    links: Option<AdminLinks>,
    link_events: Option<watch::Receiver<u64>>,
    receipt: Vec<OwnedLink>,
    /// The receipt was read, or never existed, and may be rewritten.
    receipt_loaded: bool,
    reconciled: bool,
    runtime: BTreeMap<String, BindingRuntime>,
    last_sessions: Option<EvpnSessionsSync>,
    store_error: Option<String>,
}

impl Controller {
    fn new(deps: CoreIsolationDeps) -> Self {
        Self {
            deps,
            snapshot: Arc::default(),
            planner: None,
            startup: true,
            store: None,
            host: None,
            links: None,
            link_events: None,
            receipt: Vec::new(),
            receipt_loaded: false,
            reconciled: false,
            runtime: BTreeMap::new(),
            last_sessions: None,
            store_error: None,
        }
    }

    fn enabled(&self) -> Option<&EvpnCoreIsolationConfig> {
        self.snapshot.settings.as_ref().filter(|s| s.enabled)
    }

    async fn run(
        mut self,
        mut config_rx: watch::Receiver<CoreIsolationConfig>,
        stop: CancellationToken,
    ) -> Self {
        let mut tick = tokio::time::interval(POLL_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        self.apply_config(config_rx.borrow_and_update().clone());
        loop {
            let poll = tokio::select! {
                biased;
                () = stop.cancelled() => return self,
                changed = config_rx.changed() => {
                    if changed.is_err() {
                        stop.cancelled().await;
                        return self;
                    }
                    self.apply_config(config_rx.borrow_and_update().clone());
                    false
                }
                _ = tick.tick() => true,
                changed = async {
                    match self.link_events.as_mut() {
                        Some(rx) => rx.changed().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if changed.is_err() {
                        warn!("core-isolation link subscription closed; rediscovering on the 1 s poll");
                        self.link_events = None;
                    }
                    false
                }
            };
            self.step(poll).await;
        }
    }

    fn apply_config(&mut self, snapshot: CoreIsolationConfig) {
        self.snapshot = snapshot;
        match (self.enabled().cloned(), self.planner.as_mut()) {
            (Some(settings), Some(planner)) => planner.retime(&settings),
            (Some(settings), None) => {
                self.planner = Some(if self.startup {
                    HoldPlanner::startup(&settings, self.deps.start)
                } else {
                    HoldPlanner::released(&settings)
                });
            }
            (None, _) => self.planner = None,
        }
        self.startup = false;
        for gone in self
            .runtime
            .keys()
            .filter(|b| !self.snapshot.bindings.contains_key(*b))
            .cloned()
            .collect::<Vec<_>>()
        {
            self.runtime.remove(&gone);
            self.deps.metrics.remove_evpn_es_core_isolation_state(&gone);
        }
    }

    /// Open the store, host identity and netlink handles once there is
    /// anything to own: the feature is enabled or a receipt exists.
    fn ensure_kernel(&mut self) -> bool {
        if self.store.is_some() && self.links.is_some() && self.host.is_some() {
            return true;
        }
        let wanted = self.enabled().is_some()
            || self
                .deps
                .directory
                .as_ref()
                .is_some_and(ReceiptStore::receipt_exists);
        if !wanted {
            return false;
        }
        let result = (|| -> Result<(), String> {
            if self.store.is_none() {
                let directory = self
                    .deps
                    .directory
                    .as_ref()
                    .ok_or("the runtime-state directory is unavailable")?
                    .try_clone()
                    .map_err(|e| e.to_string())?;
                self.store = Some(ReceiptStore::lock(directory).map_err(|e| match e {
                    OpenError::Locked => format!("{e}; retrying"),
                    OpenError::Other(message) => message,
                })?);
            }
            if self.host.is_none() {
                self.host = Some(HostIdentity::current()?);
            }
            if self.links.is_none() {
                let (links, events) = AdminLinks::open_with_events().map_err(|e| e.to_string())?;
                self.links = Some(links);
                self.link_events = Some(events);
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.store_error = None;
                true
            }
            Err(message) => {
                if self.store_error.as_deref() != Some(message.as_str()) {
                    error!(
                        reason = "action_failed",
                        error = %message,
                        "core-isolation hold cannot own link admin state"
                    );
                }
                self.store_error = Some(message);
                false
            }
        }
    }

    async fn step(&mut self, poll: bool) {
        if !self.ensure_kernel() {
            self.publish_states();
            return;
        }
        if !self.receipt_loaded {
            match self.store.as_ref().map(ReceiptStore::read) {
                Some(Ok(entries)) => {
                    self.receipt = entries.unwrap_or_default();
                    self.receipt_loaded = true;
                }
                Some(Err(message)) => {
                    if self.store_error.as_deref() != Some(message.as_str()) {
                        error!(
                            reason = "action_failed",
                            error = %message,
                            "core-isolation receipt unreadable; no link is touched"
                        );
                    }
                    self.store_error = Some(message);
                    self.publish_states();
                    return;
                }
                None => return,
            }
        }
        let peers = if poll && self.enabled().is_some() {
            self.poll_rib().await
        } else {
            None
        };
        let Some(links) = self.dump().await else {
            self.publish_states();
            return;
        };
        if !self.reconciled {
            self.reconcile_at_start(&links);
            self.reconciled = true;
        }
        self.plan(&links, peers);
        self.act(&links).await;
        self.publish_states();
    }

    async fn dump(&mut self) -> Option<Vec<AdminLinkState>> {
        match self.links.as_ref()?.dump().await {
            Ok(links) => Some(links),
            Err(error) => {
                warn!(%error, "core-isolation link scan failed; retrying on the next poll");
                None
            }
        }
    }

    /// Type 4 first, then sessions: the peer set is used only when the
    /// session read that follows it still shows an Established session.
    async fn poll_rib(&mut self) -> Option<BTreeMap<String, BTreeSet<IpAddr>>> {
        let routes = query_type4(&self.deps.rib_tx).await;
        let sessions = query_sessions(&self.deps.rib_tx).await?;
        self.last_sessions = Some(sessions);
        let routes = routes?;
        (sessions.established > 0).then(|| peers_by_binding(&self.snapshot.bindings, &routes))
    }

    /// Run the planner with the latest sessions and the uplink signal
    /// computed from `links`.
    fn plan(
        &mut self,
        links: &[AdminLinkState],
        peers: Option<BTreeMap<String, BTreeSet<IpAddr>>>,
    ) {
        let Some(settings) = self.enabled().cloned() else {
            return;
        };
        let (uplinks_down, overlaps) =
            uplink_signal(&settings.uplinks, &self.snapshot, links, &self.receipt);
        for binding in self.snapshot.bindings.keys() {
            let overlapping: Vec<&String> = overlaps
                .iter()
                .filter(|(_, b)| b == binding)
                .map(|(uplink, _)| uplink)
                .collect();
            let runtime = self.runtime.entry(binding.clone()).or_default();
            if !overlapping.is_empty() && !runtime.uplink_overlap {
                error!(
                    reason = "uplink_overlap",
                    interface = %binding,
                    uplinks = ?overlapping,
                    "core-isolation uplink is, or is enslaved under, a bound interface; it is \
                     excluded from the uplink signal"
                );
            }
            runtime.uplink_overlap = !overlapping.is_empty();
        }
        let bindings: BTreeSet<String> = self.snapshot.bindings.keys().cloned().collect();
        let now = Instant::now();
        let Some(planner) = self.planner.as_mut() else {
            return;
        };
        let mut sessions_isolated = false;
        let events = match self.last_sessions {
            None => planner.expire(&bindings, now),
            Some(sessions) => {
                let observation = Observation {
                    sessions,
                    uplinks_down,
                    peers,
                };
                sessions_isolated = observation.sessions_isolated();
                self.deps
                    .metrics
                    .set_evpn_core_isolated(sessions_isolated, uplinks_down);
                planner.observe(&bindings, &observation, now)
            }
        };
        for (code, message) in events {
            match code {
                "isolated" | "backstop_unsynced" => {
                    warn!(reason = code, sessions_isolated, uplinks_down, "{message}");
                }
                _ => info!(reason = code, "{message}"),
            }
        }
    }

    /// Bindings that must be held right now.
    fn held_bindings(&self) -> BTreeSet<String> {
        let Some(planner) = self.planner.as_ref() else {
            return BTreeSet::new();
        };
        self.snapshot
            .bindings
            .keys()
            .filter(|b| matches!(planner.decision(b), HoldDecision::Hold(_)))
            .cloned()
            .collect()
    }

    /// Receipt entries that still belong to a configured, enabled binding.
    fn entry_is_current(&self, entry: &OwnedLink) -> bool {
        self.enabled().is_some()
            && self
                .snapshot
                .bindings
                .get(&entry.binding)
                .is_some_and(|b| b.esi_text == entry.esi)
    }

    /// Startup reconcile (decision 6, "Next start"): drop entries from
    /// another boot and entries whose link is admin-up (a crash between
    /// publication and the write); raise entries whose binding is gone or
    /// whose feature is off. Matching admin-down entries are adopted into
    /// the startup hold by the first hold pass.
    fn reconcile_at_start(&mut self, links: &[AdminLinkState]) {
        let Some(host) = self.host.clone() else {
            return;
        };
        let before = self.receipt.len();
        self.receipt
            .retain(|entry| match classify_entry(entry, &host, links) {
                Guard::ForeignBoot => {
                    info!(
                        interface = %entry.link.name,
                        "core-isolation receipt entry from an earlier boot discarded"
                    );
                    false
                }
                Guard::Matched { admin_up: true, .. } => false,
                _ => true,
            });
        if self.receipt.len() != before {
            self.persist();
        }
        if !self.receipt.is_empty() {
            info!(
                entries = self.receipt.len(),
                "core-isolation receipt found at startup; reconciling owned links"
            );
        }
    }

    async fn act(&mut self, links: &[AdminLinkState]) {
        let held = self.held_bindings();
        let enabled = self.enabled().is_some();
        let bindings: Vec<(String, CoreIsolationBinding)> = self
            .snapshot
            .bindings
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        if enabled {
            for (interface, binding) in &bindings {
                let runtime = self.runtime.entry(interface.clone()).or_default();
                runtime.action_failed = false;
                if held.contains(interface) {
                    self.hold_pass(interface, binding, links).await;
                } else {
                    self.runtime
                        .entry(interface.clone())
                        .or_default()
                        .overridden
                        .clear();
                }
            }
        }
        // Release every entry that is not held: bindings out of hold, and
        // entries whose binding left the config or whose feature is off.
        let release: Vec<OwnedLink> = self
            .receipt
            .iter()
            .filter(|e| !self.entry_is_current(e) || !held.contains(&e.binding))
            .cloned()
            .collect();
        for entry in release {
            self.release_entry(&entry, links).await;
        }
        // Ambiguity is a property of the receipt against current links.
        let Some(host) = self.host.clone() else {
            return;
        };
        let mut ambiguous: BTreeMap<String, Vec<(String, u32, String)>> = BTreeMap::new();
        for entry in &self.receipt {
            if let Guard::Ambiguous(reason) = classify_entry(entry, &host, links) {
                ambiguous.entry(entry.binding.clone()).or_default().push((
                    entry.link.name.clone(),
                    entry.link.ifindex,
                    reason,
                ));
            }
        }
        for (binding, runtime) in &mut self.runtime {
            runtime.ambiguous = false;
            if !ambiguous.contains_key(binding) {
                runtime.ambiguous_logged = false;
            }
        }
        for (binding, entries) in ambiguous {
            let runtime = self.runtime.entry(binding.clone()).or_default();
            runtime.ambiguous = true;
            if !runtime.ambiguous_logged {
                for (member, ifindex, reason) in entries {
                    error!(
                        reason = "ownership_ambiguous",
                        interface = %binding,
                        member = %member,
                        ifindex,
                        detail = %reason,
                        "core-isolation receipt entry no longer matches its link; it is left \
                         down. Raise the link by hand, then clear the entry"
                    );
                }
                runtime.ambiguous_logged = true;
            }
        }
    }

    /// Level-triggered member discovery for one held binding.
    async fn hold_pass(
        &mut self,
        interface: &str,
        binding: &CoreIsolationBinding,
        links: &[AdminLinkState],
    ) {
        let Some(host) = self.host.clone() else {
            return;
        };
        let overridden = self
            .runtime
            .get(interface)
            .map(|r| r.overridden.clone())
            .unwrap_or_default();
        for action in discover(interface, binding, links, &self.receipt, &overridden, &host) {
            match action {
                MemberAction::Overridden { entry, key } => {
                    // Another writer raised a held member: report it, stop
                    // owning it, and never take it down again this hold.
                    warn!(
                        reason = "overridden",
                        interface,
                        member = %entry.link.name,
                        "a held core-isolation member was raised by another writer; it is no \
                         longer owned for this hold"
                    );
                    self.receipt.retain(|e| *e != entry);
                    self.persist();
                    self.runtime
                        .entry(interface.to_string())
                        .or_default()
                        .overridden
                        .insert(key);
                }
                MemberAction::TakeDown(entry) => self.take_down(entry).await,
            }
        }
    }

    /// Publish the entry, re-read the link, then clear `IFF_UP`.
    async fn take_down(&mut self, entry: OwnedLink) {
        self.receipt.push(entry.clone());
        if !self.persist() {
            self.receipt.pop();
            self.fail(
                &entry.binding,
                &entry.link.name,
                "receipt publication failed",
            );
            return;
        }
        let fresh = self.fresh(&entry.link).await;
        let result = match fresh {
            Ok(Some((identity, true))) if identity == entry.link => self
                .links
                .as_ref()
                .expect("kernel handles are open")
                .set_admin_up(entry.link.ifindex, false)
                .await
                .map_err(|e| e.to_string()),
            Ok(_) => Err("link changed before the write".to_string()),
            Err(error) => Err(error),
        };
        match result {
            Ok(()) => info!(
                reason = "held",
                interface = %entry.binding,
                member = %entry.link.name,
                "core-isolation hold took a CE-facing member administratively down"
            ),
            Err(error) => {
                self.receipt.retain(|e| *e != entry);
                self.persist();
                self.fail(&entry.binding, &entry.link.name, &error);
            }
        }
    }

    /// Raise one entry through the safe rule and the fresh check; drop it
    /// once raised or found already up; keep it when ambiguous.
    async fn release_entry(&mut self, entry: &OwnedLink, links: &[AdminLinkState]) {
        let Some(host) = self.host.clone() else {
            return;
        };
        match classify_entry(entry, &host, links) {
            Guard::ForeignBoot | Guard::Matched { admin_up: true, .. } => {
                self.receipt.retain(|e| e != entry);
                self.persist();
            }
            Guard::Matched {
                admin_up: false,
                ifindex,
            } => {
                let raised = match self.fresh(&entry.link).await {
                    Ok(Some((identity, false))) if identity == entry.link => self
                        .links
                        .as_ref()
                        .expect("kernel handles are open")
                        .set_admin_up(ifindex, true)
                        .await
                        .map_err(|e| e.to_string()),
                    Ok(Some((identity, true))) if identity == entry.link => Ok(()),
                    Ok(_) => Err("link changed before the write".to_string()),
                    Err(error) => Err(error),
                };
                match raised {
                    Ok(()) => {
                        info!(
                            reason = "released",
                            interface = %entry.binding,
                            member = %entry.link.name,
                            "core-isolation hold raised a CE-facing member"
                        );
                        self.receipt.retain(|e| e != entry);
                        self.persist();
                    }
                    Err(error) => self.fail(&entry.binding, &entry.link.name, &error),
                }
            }
            // Kept; `act` reports it.
            Guard::Ambiguous(_) => {}
        }
    }

    /// Re-read `link` (and its master) immediately before a write.
    async fn fresh(&self, link: &LinkIdentity) -> Result<Option<(LinkIdentity, bool)>, String> {
        let handle = self.links.as_ref().ok_or("netlink unavailable")?;
        let Some(state) = handle.get(link.ifindex).await.map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        let master = match state.master {
            Some(index) => handle.get(index).await.map_err(|e| e.to_string())?,
            None => None,
        };
        Ok(Some((
            LinkIdentity::of(&state, master.as_ref()),
            state.admin_up,
        )))
    }

    fn fail(&mut self, binding: &str, member: &str, error: &str) {
        let runtime = self.runtime.entry(binding.to_string()).or_default();
        if !runtime.action_failed {
            error!(
                reason = "action_failed",
                interface = binding,
                member,
                error,
                "core-isolation admin-state action failed; retrying on the next poll"
            );
        }
        runtime.action_failed = true;
    }

    /// Publish the in-memory receipt; `false` on failure.
    fn persist(&mut self) -> bool {
        let Some(store) = self.store.as_ref() else {
            return false;
        };
        match store.publish(&self.receipt) {
            Ok(()) => true,
            Err(error) => {
                error!(reason = "action_failed", %error, "core-isolation receipt publication failed");
                false
            }
        }
    }

    fn publish_states(&mut self) {
        if self.snapshot.settings.is_none() && self.receipt.is_empty() {
            for interface in self.snapshot.bindings.keys() {
                self.deps
                    .metrics
                    .remove_evpn_es_core_isolation_state(interface);
            }
            return;
        }
        let enabled = self.enabled().is_some();
        let store_failed = self.store_error.is_some();
        let interfaces: Vec<String> = self.snapshot.bindings.keys().cloned().collect();
        for interface in interfaces {
            let decision = self.planner.as_ref().map(|p| p.decision(&interface));
            let runtime = self.runtime.entry(interface.clone()).or_default();
            let state = if runtime.ambiguous {
                "ownership_ambiguous"
            } else if !enabled {
                "disabled"
            } else if runtime.action_failed || store_failed {
                "action_failed"
            } else if runtime.uplink_overlap {
                "uplink_overlap"
            } else if !runtime.overridden.is_empty() {
                "overridden"
            } else {
                match decision {
                    Some(HoldDecision::Hold(state) | HoldDecision::Release(state)) => state,
                    None => "disabled",
                }
            };
            if runtime.reported != Some(state) {
                match state {
                    "isolated" | "suppressed_no_peer" | "backstop_released" | "overridden" => {
                        warn!(reason = state, interface = %interface, "core-isolation state changed");
                    }
                    "ownership_ambiguous" | "action_failed" | "uplink_overlap" => {
                        error!(reason = state, interface = %interface, "core-isolation state changed");
                    }
                    _ => {
                        info!(reason = state, interface = %interface, "core-isolation state changed");
                    }
                }
                runtime.reported = Some(state);
            }
            self.deps
                .metrics
                .set_evpn_es_core_isolation_state(&interface, state);
        }
    }

    /// Clean-shutdown release: every entry through the guarded path.
    async fn release_all(&mut self) {
        if self.store.is_none() || !self.receipt_loaded || self.receipt.is_empty() {
            return;
        }
        let Some(links) = self.dump().await else {
            warn!(
                "core-isolation shutdown release could not scan links; the stop hook or next start releases them"
            );
            return;
        };
        info!(
            entries = self.receipt.len(),
            "releasing core-isolation holds for shutdown"
        );
        for entry in self.receipt.clone() {
            self.release_entry(&entry, &links).await;
        }
        if !self.receipt.is_empty() {
            warn!(
                remaining = self.receipt.len(),
                "core-isolation receipt keeps ambiguous entries after shutdown release"
            );
        }
    }
}

/// One member-discovery outcome for a held binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MemberAction {
    /// Admin-up and not owned: publish this entry, then take it down.
    TakeDown(OwnedLink),
    /// Owned but admin-up: another writer raised it.
    Overridden {
        entry: OwnedLink,
        key: (u32, String),
    },
}

/// ADR-0140 decision 3, level-triggered discovery: classify every
/// current member of the bound bond (or the bound link itself) against
/// the receipt. Owned and down: held. Owned and up: overridden. Not owned
/// and up, not overridden this hold: take down. Not owned and down: left
/// alone and not recorded.
pub(crate) fn discover(
    interface: &str,
    binding: &CoreIsolationBinding,
    links: &[AdminLinkState],
    receipt: &[OwnedLink],
    overridden: &BTreeSet<(u32, String)>,
    host: &HostIdentity,
) -> Vec<MemberAction> {
    let members: Vec<&AdminLinkState> = match links.iter().find(|l| l.name == interface) {
        Some(bound) if bound.is_bond => links
            .iter()
            .filter(|l| l.master == Some(bound.ifindex))
            .collect(),
        Some(bound) => vec![bound],
        None => Vec::new(),
    };
    members
        .into_iter()
        .filter(|member| member.admin_up)
        .filter_map(|member| {
            let identity = LinkIdentity::in_dump(member, links);
            let key = (member.ifindex, member.name.clone());
            let owned = receipt.iter().find(|e| {
                e.binding == interface
                    && e.boot_id == host.boot_id
                    && e.netns == host.netns
                    && e.link == identity
            });
            match owned {
                Some(entry) => Some(MemberAction::Overridden {
                    entry: entry.clone(),
                    key,
                }),
                None if overridden.contains(&key) => None,
                None => Some(MemberAction::TakeDown(OwnedLink {
                    boot_id: host.boot_id.clone(),
                    netns: host.netns,
                    esi: binding.esi_text.clone(),
                    binding: interface.to_string(),
                    link: identity,
                })),
            }
        })
        .collect()
}

fn classify_entry(entry: &OwnedLink, host: &HostIdentity, links: &[AdminLinkState]) -> Guard {
    receipt::classify(entry, host, links)
}

/// ADR-0140 decision 2: whether every effective uplink lacks carrier,
/// and the (uplink, binding) pairs excluded because the uplink is a
/// bound link, a member of a bound bond, or an owned member.
fn uplink_signal(
    uplinks: &[String],
    snapshot: &CoreIsolationSnapshot,
    links: &[AdminLinkState],
    receipt: &[OwnedLink],
) -> (bool, Vec<(String, String)>) {
    let mut overlaps = Vec::new();
    let mut effective = Vec::new();
    for uplink in uplinks {
        let link = links.iter().find(|l| &l.name == uplink);
        let bound_master = link
            .and_then(|l| l.master)
            .and_then(|m| links.iter().find(|l| l.ifindex == m))
            .filter(|m| snapshot.bindings.contains_key(&m.name))
            .map(|m| m.name.clone());
        let owner = if snapshot.bindings.contains_key(uplink) {
            Some(uplink.clone())
        } else if let Some(bond) = bound_master {
            Some(bond)
        } else {
            receipt
                .iter()
                .find(|e| &e.link.name == uplink)
                .map(|e| e.binding.clone())
        };
        match owner {
            Some(binding) => overlaps.push((uplink.clone(), binding)),
            None => effective.push(link.is_some_and(|l| l.carrier)),
        }
    }
    let down = !effective.is_empty() && effective.iter().all(|up| !up);
    (down, overlaps)
}

/// Remote ES peers per bound interface: Type 4 routes for the binding's
/// ESI from another originator that carry the matching ES-Import RT.
fn peers_by_binding(
    bindings: &BTreeMap<String, CoreIsolationBinding>,
    routes: &[EvpnRibRoute],
) -> BTreeMap<String, BTreeSet<IpAddr>> {
    bindings
        .iter()
        .filter_map(|(interface, binding)| {
            let esi = binding.esi?;
            let peers = routes
                .iter()
                .filter_map(|r| match &r.route {
                    EvpnRoute::Es(es)
                        if es.esi == esi
                            && Some(es.originator_ip) != binding.originator_ip
                            && crate::evpn_segment::has_matching_es_import_rt(
                                &r.attributes,
                                esi,
                            ) =>
                    {
                        Some(es.originator_ip)
                    }
                    _ => None,
                })
                .collect();
            Some((interface.clone(), peers))
        })
        .collect()
}

async fn query_type4(rib_tx: &mpsc::Sender<RibUpdate>) -> Option<Vec<EvpnRibRoute>> {
    let (reply, rx) = oneshot::channel();
    tokio::time::timeout(RIB_QUERY_TIMEOUT, async {
        rib_tx
            .send(RibUpdate::QueryEvpnRoutes {
                // ponytail: scans the EVPN Loc-RIB once per poll; switch to a
                // Type 4 event-driven re-read if it shows in RIB task profiles.
                filter: Some(Box::new(|route: &EvpnRibRoute| {
                    matches!(route.route, EvpnRoute::Es(_))
                })),
                reply,
            })
            .await
            .ok()?;
        rx.await.ok()
    })
    .await
    .ok()
    .flatten()
}

async fn query_sessions(rib_tx: &mpsc::Sender<RibUpdate>) -> Option<EvpnSessionsSync> {
    let (reply, rx) = oneshot::channel();
    tokio::time::timeout(RIB_QUERY_TIMEOUT, async {
        rib_tx
            .send(RibUpdate::QueryEvpnSessionsSynced { reply })
            .await
            .ok()?;
        rx.await.ok()
    })
    .await
    .ok()
    .flatten()
}

// ─── out-of-process release ──────────────────────────────────────────

/// `rustbgpd --release-core-isolation --runtime-state-dir DIR`. Returns
/// the process exit status: 0 only when nothing owned is left down.
pub(crate) fn release_core_isolation(directory: &Path) -> u8 {
    let store = match ReceiptStore::open_path(directory) {
        Ok(store) => store,
        Err(OpenError::Locked) => {
            eprintln!(
                "error: a running rustbgpd holds {}/{}; it releases its own holds on shutdown",
                directory.display(),
                receipt::LOCK_FILE
            );
            return 1;
        }
        Err(OpenError::Other(message)) => {
            eprintln!("error: {message}");
            return 1;
        }
    };
    let mut entries = match store.read() {
        Ok(None) => {
            println!(
                "no core-isolation receipt in {}; nothing to release",
                directory.display()
            );
            return 0;
        }
        Ok(Some(entries)) => entries,
        Err(message) => {
            eprintln!("error: {message}");
            return 1;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: cannot start the release runtime: {error}");
            return 1;
        }
    };
    let result: Result<(), String> = runtime.block_on(async {
        let host = HostIdentity::current()?;
        let links = AdminLinks::open().map_err(|e| e.to_string())?;
        let dump = links.dump().await.map_err(|e| e.to_string())?;
        let mut kept = Vec::new();
        for entry in entries.drain(..) {
            match receipt::classify(&entry, &host, &dump) {
                Guard::ForeignBoot | Guard::Matched { admin_up: true, .. } => {}
                Guard::Matched { admin_up: false, ifindex } => {
                    let fresh = links.get(ifindex).await.map_err(|e| e.to_string())?;
                    let master = match fresh.as_ref().and_then(|s| s.master) {
                        Some(index) => links.get(index).await.map_err(|e| e.to_string())?,
                        None => None,
                    };
                    let unchanged = fresh.as_ref().is_some_and(|state| {
                        LinkIdentity::of(state, master.as_ref()) == entry.link
                    });
                    if !unchanged {
                        eprintln!(
                            "ownership_ambiguous: {} (ifindex {}) changed before the write; left down",
                            entry.link.name, entry.link.ifindex
                        );
                        kept.push(entry);
                        continue;
                    }
                    if fresh.is_some_and(|s| !s.admin_up)
                        && let Err(error) = links.set_admin_up(ifindex, true).await
                    {
                        eprintln!("error: cannot raise {}: {error}", entry.link.name);
                        kept.push(entry);
                        continue;
                    }
                    println!("raised {} (binding {})", entry.link.name, entry.binding);
                }
                Guard::Ambiguous(reason) => {
                    eprintln!(
                        "ownership_ambiguous: {} (ifindex {}, binding {}): {reason}; left down. \
                         Raise it by hand, then remove the entry",
                        entry.link.name, entry.link.ifindex, entry.binding
                    );
                    kept.push(entry);
                }
            }
        }
        store.publish(&kept)?;
        if kept.is_empty() {
            Ok(())
        } else {
            Err(format!("{} owned link(s) remain down", kept.len()))
        }
    });
    match result {
        Ok(()) => 0,
        Err(message) => {
            eprintln!("error: {message}");
            1
        }
    }
}

#[cfg(test)]
mod tests;
