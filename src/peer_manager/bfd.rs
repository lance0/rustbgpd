//! RFC 5882 BGP/BFD coupling (ADR-0067 step 4).
//!
//! `PeerManager` owns the desired BFD session set and consumes session state
//! changes; the BFD actor is a pure session-runner that reconciles the desired
//! set and never learns BGP internals. This module holds the coupling state and
//! the non-strict teardown / strict withhold logic.
//!
//! The coupling is **level-triggered**, not edge-triggered: a strict peer is
//! always added/enabled withheld (`bfd_should_withhold`), and the actor
//! re-confirms each session's current state on reconcile (an "ack",
//! [`BfdStateChange::resync`]). A withhold is released only when BFD is confirmed
//! to permit BGP (Up, or a remote `AdminDown` per RFC 5882 §4.1) — via either a
//! real transition or an ack. So `PeerManager` never trusts a cached BFD state:
//! a strict re-enable can neither leak BGP across a coalesced disable→enable nor
//! deadlock waiting for an edge that won't come. The active-open lifecycle gates
//! on `bfd_should_withhold`; the passive/inbound path gates on the *current*
//! held state (`bfd_withholding`) so an established strict peer still accepts
//! inbound.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

use tokio::sync::{mpsc, oneshot, watch};
use tracing::{info, warn};

use rustbgpd_bfd::SessionState;
use rustbgpd_transport::PeerCommand;

use crate::bfd_runtime::{
    BfdReloadCommand, BfdRuntimeConfig, BfdSessionParams, BfdStateChange, BfdStateChangeReceiver,
    PreparedRuntime, prepare_reload,
};

use super::{OperatorReadAdmission, PeerManager};

#[derive(Clone, Copy)]
struct BfdCommandRetry {
    session_id: u64,
    revision: Option<u64>,
    start: bool,
}

/// State for RFC 5882 coupling, owned by `PeerManager`.
pub(super) struct BfdCoupling {
    reload_tx: Option<mpsc::Sender<BfdReloadCommand>>,
    /// Socket families stay open after the last member leaves.
    pub(super) opened: BfdRuntimeConfig,
    next_revision: u64,
    /// During a generation, lifecycle mutations must not publish partial BFD membership.
    pub(super) reloading: bool,
    /// The startup registration operation resyncs unchanged membership once at its end.
    pub(super) registering: bool,
    #[cfg(test)]
    pub(super) desired_publications: usize,
    /// The next socket preflight's result, instead of opening real sockets.
    #[cfg(test)]
    pub(super) socket_preflight: Option<Result<Option<PreparedRuntime>, String>>,
    /// Inner compensation must read accepted strict settings without losing
    /// the candidate needed to fence an uncertain rollback.
    rollback_lookup: bool,
    retries: BTreeMap<IpAddr, BfdCommandRetry>,
    retry_at: Option<tokio::time::Instant>,
    retry_cursor: Option<IpAddr>,
    pub(super) prior_held: HashSet<IpAddr>,
    initially_withheld: HashSet<IpAddr>,
    prior_initially_withheld: HashSet<IpAddr>,
    pub(super) pending: Option<HashMap<IpAddr, BfdSessionParams>>,
    /// Publishes the desired session set to the actor (level-triggered).
    desired_tx: watch::Sender<BfdRuntimeConfig>,
    /// Session state changes from the actor (per-peer coalescing, latest state
    /// wins; a real transition is never masked by an ack). Taken into a
    /// `run`-local at loop start so the `select!` arm doesn't borrow `self`.
    state_change_rx: Option<BfdStateChangeReceiver>,
    /// Accepted BFD membership; the published set overlays live admin state.
    pub(super) configured: HashMap<IpAddr, BfdSessionParams>,
    /// Configured peers whose BFD session should NOT run because the neighbor
    /// was administratively disabled or deleted. A configured peer's session is
    /// enabled by default — crucially, this is tracked explicitly rather than
    /// derived from `self.peers` membership, because static peers are added
    /// asynchronously after the run loop starts (deriving from membership would
    /// publish them disabled during that window and churn the actor). Cleared on
    /// enable / (re-)add.
    disabled: HashSet<IpAddr>,
    /// Peers whose BGP session is currently held down by a BFD-down event
    /// (non-strict) or withheld pending BFD permitting BGP (strict). The actor's
    /// reconcile "ack" (a level re-report of the current session state) or a
    /// fresh transition releases the hold once BFD permits BGP — so the strict
    /// withhold is level-triggered without `PeerManager` caching a (possibly
    /// stale) BFD state.
    pub(super) held_down: HashSet<IpAddr>,
    /// Members registered at runtime rather than derived from neighbor
    /// configuration: an interface-only neighbor's binding (ADR-0142) and a
    /// session accepted through a `[[dynamic_neighbors]]` range that runs
    /// BFD. A reload rebuilds them from the candidate; the binding, not the
    /// scope refresh, moves a binding's member.
    pub(super) bound: HashSet<IpAddr>,
    /// The bound members a staged reload settles on, applied with it.
    pending_bound: Option<HashSet<IpAddr>>,
    /// Range placeholders whose socket families a staged change opens,
    /// recorded as opened once the actor acknowledges it.
    pub(super) pending_probes: Vec<BfdSessionParams>,
}

impl PeerManager {
    /// Attach the BFD coupling channels (ADR-0067 step 4). Called once at
    /// startup, including when no neighbor yet configures BFD.
    #[must_use]
    pub fn with_bfd_coupling(
        mut self,
        desired_tx: watch::Sender<BfdRuntimeConfig>,
        state_change_rx: BfdStateChangeReceiver,
        configured: HashMap<IpAddr, BfdSessionParams>,
    ) -> Self {
        // Startup opened the families of the dynamic ranges that run BFD too.
        let probes = crate::bfd_runtime::dynamic_range_socket_probes(&self.current_config)
            .unwrap_or_default();
        let mut opened = BfdRuntimeConfig {
            sessions: configured.values().cloned().chain(probes).collect(),
        };
        opened
            .sessions
            .sort_by_key(|params| (params.peer.is_ipv6(), params.multihop));
        opened
            .sessions
            .dedup_by_key(|params| (params.peer.is_ipv6(), params.multihop));
        self.bfd_coupling = Some(BfdCoupling {
            reload_tx: None,
            opened,
            next_revision: 1,
            reloading: false,
            registering: false,
            #[cfg(test)]
            desired_publications: 0,
            #[cfg(test)]
            socket_preflight: None,
            rollback_lookup: false,
            retries: BTreeMap::new(),
            retry_at: None,
            retry_cursor: None,
            prior_held: HashSet::new(),
            initially_withheld: HashSet::new(),
            prior_initially_withheld: HashSet::new(),
            pending: None,
            desired_tx,
            state_change_rx: Some(state_change_rx),
            configured,
            disabled: HashSet::new(),
            held_down: HashSet::new(),
            bound: HashSet::new(),
            pending_bound: None,
            pending_probes: Vec::new(),
        });
        self
    }

    /// Attach the actor's acknowledged reload channel, including when startup has no BFD.
    #[must_use]
    pub fn with_bfd_reload(mut self, reload_tx: mpsc::Sender<BfdReloadCommand>) -> Self {
        if let Some(coupling) = self.bfd_coupling.as_mut() {
            coupling.reload_tx = Some(reload_tx);
        }
        self
    }

    pub(super) fn prepare_bfd_reload(
        &mut self,
        candidate: &crate::config::Config,
    ) -> Result<Option<PreparedRuntime>, String> {
        let mut bound = self.rebuild_bound_bfd_sessions(candidate)?;
        bound.extend(self.rebuild_dynamic_bfd_sessions(candidate)?);
        let probes = crate::bfd_runtime::dynamic_range_socket_probes(candidate)
            .map_err(|error| error.to_string())?;
        let Some(coupling) = self.bfd_coupling.as_mut() else {
            return Ok(None);
        };
        let pending_bound = bound.iter().map(|params| params.peer).collect();
        let mut desired =
            BfdRuntimeConfig::from_reload(candidate, &self.current_config, &coupling.configured)
                .map_err(|error| error.to_string())?;
        // A binding's session is not in configuration: every live binding's
        // is rebuilt from the candidate, so enabling, disabling or editing
        // its BFD applies, and an unchanged one keeps its revision.
        desired.sessions.extend(bound);
        for params in &mut desired.sessions {
            if let Some(old) = coupling.configured.get(&params.peer) {
                params.revision = old.revision;
                // Strict is admission metadata, not BFD session identity.
                let mut prior = old.clone();
                prior.strict = params.strict;
                if prior == *params {
                    continue;
                }
            }
            params.revision = coupling.next_revision;
            coupling.next_revision = coupling
                .next_revision
                .checked_add(1)
                .ok_or("BFD session revision exhausted")?;
        }
        let sockets = BfdRuntimeConfig {
            sessions: desired
                .sessions
                .iter()
                .cloned()
                .chain(probes.clone())
                .collect(),
        };
        let prepared = coupling.preflight_sockets(&sockets)?;
        coupling.prior_held.clone_from(&coupling.held_down);
        coupling
            .prior_initially_withheld
            .clone_from(&coupling.initially_withheld);
        coupling.pending = Some(
            desired
                .sessions
                .into_iter()
                .map(|params| (params.peer, params))
                .collect(),
        );
        // Staged only once preparation succeeds: a rejected one stages nothing.
        coupling.pending_bound = Some(pending_bound);
        coupling.pending_probes = probes;
        coupling.reloading = true;
        coupling.rollback_lookup = false;
        Ok(prepared)
    }

    /// Every live binding's session as `candidate` configures it, for the
    /// binding's endpoint; a neighbor that runs no BFD there has none.
    fn rebuild_bound_bfd_sessions(
        &self,
        candidate: &crate::config::Config,
    ) -> Result<Vec<BfdSessionParams>, String> {
        let mut sessions = Vec::new();
        for (interface, address, ifindex) in self.unnumbered_bindings() {
            let Some(neighbor) = candidate.neighbors.interface_only_on(&interface) else {
                continue;
            };
            if let Some(params) = crate::bfd_runtime::bound_session_params(
                candidate, neighbor, &interface, address, ifindex,
            )
            .map_err(|error| error.to_string())?
            {
                sessions.push(params);
            }
        }
        Ok(sessions)
    }

    /// Every live dynamic session's BFD session as `candidate`'s range for it
    /// configures it; a session whose range is gone or runs no BFD has none.
    fn rebuild_dynamic_bfd_sessions(
        &self,
        candidate: &crate::config::Config,
    ) -> Result<Vec<BfdSessionParams>, String> {
        let mut sessions = Vec::new();
        for (key, managed) in &self.peers {
            let Some(accepted) = managed
                .accepted_dynamic_range
                .as_ref()
                .filter(|_| managed.is_dynamic)
            else {
                continue;
            };
            let Some(range) = accepted_range(candidate, accepted) else {
                // A removed range's sessions run on until they end, with
                // the BFD session they registered.
                if let Some(member) = self.bfd_coupling.as_ref().and_then(|coupling| {
                    coupling
                        .configured
                        .get(&key.address)
                        .filter(|_| coupling.bound.contains(&key.address))
                }) {
                    sessions.push(member.clone());
                }
                continue;
            };
            if let Some(params) =
                crate::bfd_runtime::dynamic_session_params(candidate, range, key.address)
                    .map_err(|error| error.to_string())?
            {
                sessions.push(params);
            }
        }
        Ok(sessions)
    }

    /// The BFD session a connection from `peer` accepted through `accepted`
    /// registers, or `None` when its range runs no BFD. Refused, before the
    /// session is spawned, when the session could not be registered without
    /// waiting on the BFD actor: a membership change is in progress, or the
    /// range's socket family is not open (startup and reloads open it). The
    /// caller drops the connection; the peer retries.
    pub(super) fn dynamic_bfd_admission(
        &self,
        accepted: &super::dynamic::AcceptedDynamicRange,
        peer: IpAddr,
    ) -> Result<Option<BfdSessionParams>, String> {
        let Some(params) = dynamic_bfd_params(&self.current_config, accepted, peer)? else {
            return Ok(None);
        };
        let coupling = self.bfd_coupling.as_ref().ok_or("BFD is not running")?;
        if coupling.reloading {
            return Err("a BFD membership change is in progress".into());
        }
        if !coupling
            .opened
            .sessions
            .iter()
            .any(|old| old.peer.is_ipv6() == peer.is_ipv6() && !old.multihop)
        {
            return Err("the range's BFD socket family is not open".into());
        }
        Ok(Some(params))
    }

    /// Register an accepted dynamic session's BFD session under a fresh
    /// revision. Published level-triggered, as an admin enable is: the
    /// accept never waits on the BFD actor, and a range runs no strict
    /// sessions whose admission would need its acknowledgement.
    pub(super) fn register_dynamic_bfd(&mut self, mut params: BfdSessionParams) {
        let Some(coupling) = self.bfd_coupling.as_mut() else {
            return;
        };
        let peer = params.peer;
        params.revision = coupling.next_revision;
        coupling.next_revision = coupling.next_revision.saturating_add(1);
        coupling.configured.insert(peer, params);
        coupling.bound.insert(peer);
        coupling.disabled.remove(&peer);
        // A new session starts with no BFD admission state.
        coupling.held_down.remove(&peer);
        coupling.initially_withheld.remove(&peer);
        self.republish_bfd_desired();
    }

    /// Open the BFD socket families of the ranges `candidate` adds, before a
    /// sequential SIGHUP's first effect: the membership is unchanged, and
    /// prepared sockets reach the actor through the acknowledged commit. A
    /// lost acknowledgement fences BFD as an uncertain generation does.
    pub(super) async fn open_dynamic_bfd_sockets(
        &mut self,
        candidate: &crate::config::Config,
    ) -> super::DynamicBfdSocketOutcome {
        use super::DynamicBfdSocketOutcome;
        let probes = match crate::bfd_runtime::dynamic_range_socket_probes(candidate) {
            Ok(probes) => probes,
            Err(error) => return DynamicBfdSocketOutcome::Rejected(error.to_string()),
        };
        let Some(coupling) = self.bfd_coupling.as_mut() else {
            return if probes.is_empty() {
                DynamicBfdSocketOutcome::Ready
            } else {
                DynamicBfdSocketOutcome::Rejected("BFD is not running".into())
            };
        };
        if coupling.reloading {
            return DynamicBfdSocketOutcome::Rejected(
                "a BFD membership change is in progress".into(),
            );
        }
        let prepared = match coupling.preflight_sockets(&BfdRuntimeConfig {
            sessions: probes.clone(),
        }) {
            Ok(Some(prepared)) => prepared,
            Ok(None) => return DynamicBfdSocketOutcome::Ready,
            Err(error) => return DynamicBfdSocketOutcome::Rejected(error),
        };
        coupling.prior_held.clone_from(&coupling.held_down);
        coupling
            .prior_initially_withheld
            .clone_from(&coupling.initially_withheld);
        coupling.pending = Some(coupling.configured.clone());
        coupling.pending_bound = None;
        coupling.pending_probes = probes;
        coupling.reloading = true;
        coupling.rollback_lookup = false;
        match self.commit_bfd_reload(Some(prepared)).await {
            Ok(()) => DynamicBfdSocketOutcome::Ready,
            Err(error) => {
                self.fence_bfd_reload().await;
                DynamicBfdSocketOutcome::Ambiguous(error)
            }
        }
    }

    /// Remove a dynamic session's BFD session once no dynamic peer at `peer`
    /// remains; a dynamic peer kept disabled keeps it, drained. A no-op for
    /// an address that registered none.
    pub(super) fn release_dynamic_bfd(&mut self, peer: IpAddr) {
        let remaining = self
            .peers
            .get(&rustbgpd_api::peer_types::PeerKey::new(peer, None))
            .filter(|managed| managed.is_dynamic)
            .map(|managed| managed.enabled);
        if let Some(enabled) = remaining {
            if !enabled {
                self.set_bfd_peer_disabled(peer, true);
            }
            return;
        }
        self.cancel_bfd_retry(peer, None);
        let Some(coupling) = self.bfd_coupling.as_mut() else {
            return;
        };
        // A generation that first gives the session BFD stages it only in
        // `pending_bound`; its member must not outlive the session either.
        // (`pending_probes` holds range placeholders, not sessions.)
        let staged = coupling
            .pending_bound
            .as_mut()
            .is_some_and(|pending| pending.remove(&peer));
        if !coupling.bound.remove(&peer) && !staged {
            return;
        }
        coupling.configured.remove(&peer);
        coupling.disabled.remove(&peer);
        coupling.held_down.remove(&peer);
        coupling.initially_withheld.remove(&peer);
        // An aborted generation must not restore the ended session's holds.
        coupling.prior_held.remove(&peer);
        coupling.prior_initially_withheld.remove(&peer);
        // A change staged now settles without it too.
        if let Some(pending) = coupling.pending.as_mut() {
            pending.remove(&peer);
        }
        self.republish_bfd_desired();
    }

    /// Restore strict lookup before rollback re-adds peers, but keep publication suspended.
    pub(super) fn restore_bfd_reload_lookup(&mut self) {
        self.set_bfd_rollback_lookup(true);
    }

    /// Select accepted strict settings during compensation and return the
    /// previous lookup mode so an inner rollback can restore its caller's mode.
    pub(super) fn set_bfd_rollback_lookup(&mut self, enabled: bool) -> bool {
        self.bfd_coupling
            .as_mut()
            .is_some_and(|coupling| std::mem::replace(&mut coupling.rollback_lookup, enabled))
    }

    /// An uncertain generation must not let an old notification release a new strict hold.
    pub(super) async fn fence_bfd_reload(&mut self) {
        let strict: Vec<_> = self
            .bfd_coupling
            .as_ref()
            .map(|coupling| {
                coupling
                    .configured
                    .values()
                    .chain(coupling.pending.iter().flat_map(|pending| pending.values()))
                    .filter(|params| params.strict)
                    .map(|params| params.peer)
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect()
            })
            .unwrap_or_default();
        if let Some(coupling) = self.bfd_coupling.as_mut() {
            coupling.reloading = true;
            coupling.held_down.extend(strict.iter().copied());
        }
        for peer in strict {
            if let Err(error) = self.hold_bgp_for_bfd(peer).await {
                warn!(%peer, %error, "failed to stop strict BGP peer after uncertain BFD reload");
            }
        }
    }

    fn cancel_bfd_retry(&mut self, peer: IpAddr, start: Option<bool>) -> bool {
        let Some(coupling) = self.bfd_coupling.as_mut() else {
            return false;
        };
        let matches = coupling
            .retries
            .get(&peer)
            .is_some_and(|retry| start.is_none_or(|start| retry.start == start));
        if matches {
            coupling.retries.remove(&peer);
        }
        if coupling.retries.is_empty() {
            coupling.retry_at = None;
        }
        matches
    }

    pub(super) fn schedule_bfd_retry(&mut self, peer: IpAddr, start: bool) {
        let Some(managed) = self
            .unique_peer_key_for_address(peer)
            .and_then(|key| self.peers.get(&key))
            .filter(|managed| managed.enabled)
        else {
            return;
        };
        if let Some(coupling) = self.bfd_coupling.as_mut() {
            coupling.retries.insert(
                peer,
                BfdCommandRetry {
                    session_id: managed.session_id(),
                    revision: coupling.configured.get(&peer).map(|params| params.revision),
                    start,
                },
            );
            coupling.retry_at.get_or_insert_with(|| {
                tokio::time::Instant::now() + std::time::Duration::from_millis(100)
            });
        }
    }

    pub(super) fn bfd_retry_deadline(&self) -> Option<tokio::time::Instant> {
        self.bfd_coupling
            .as_ref()
            .filter(|coupling| !coupling.reloading)
            .and_then(|coupling| coupling.retry_at)
    }

    /// Retry only failed enqueues, never a full BFD reconcile. Each turn visits
    /// at most 32 peers in address order, resuming after the previous batch.
    pub(super) fn retry_bfd_commands(&mut self, events: Option<&BfdStateChangeReceiver>) {
        let Some(coupling) = self.bfd_coupling.as_ref() else {
            return;
        };
        let cursor = coupling
            .retry_cursor
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let attempts: Vec<_> = coupling
            .retries
            .range((
                std::ops::Bound::Excluded(cursor),
                std::ops::Bound::Unbounded,
            ))
            .chain(coupling.retries.range(..=cursor))
            .take(32)
            .map(|(peer, retry)| (*peer, *retry))
            .collect();
        for (peer, retry) in attempts {
            let commands = self
                .unique_peer_key_for_address(peer)
                .and_then(|key| self.peers.get(&key))
                .filter(|managed| managed.enabled && managed.session_id() == retry.session_id)
                .map(|managed| managed.handle().commands_sender());
            let coupling = self.bfd_coupling.as_mut().expect("BFD retry owns coupling");
            coupling.retry_cursor = Some(peer);
            if events.is_some_and(|events| events.has_pending(peer)) {
                continue;
            }
            if retry.revision != coupling.configured.get(&peer).map(|params| params.revision) {
                coupling.retries.remove(&peer);
                continue;
            }
            let Some(commands) = commands else {
                coupling.retries.remove(&peer);
                continue;
            };
            let command = if retry.start {
                PeerCommand::Start
            } else {
                PeerCommand::BfdDown
            };
            match commands.try_send(command) {
                Ok(()) => {
                    coupling.retries.remove(&peer);
                    if retry.start {
                        coupling.held_down.remove(&peer);
                        coupling.initially_withheld.remove(&peer);
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    coupling.retries.remove(&peer);
                }
                Err(mpsc::error::TrySendError::Full(_)) => {}
            }
        }
        let coupling = self.bfd_coupling.as_mut().expect("BFD retry owns coupling");
        coupling.retry_at = (!coupling.retries.is_empty())
            .then(|| tokio::time::Instant::now() + std::time::Duration::from_millis(100));
    }

    fn enqueue_bfd_command(&mut self, peer: IpAddr, start: bool) -> Result<(), String> {
        let Some(commands) = self
            .unique_peer_key_for_address(peer)
            .and_then(|key| self.peers.get(&key))
            .filter(|managed| managed.enabled)
            .map(|managed| managed.handle().commands_sender())
        else {
            return Ok(());
        };
        let command = if start {
            PeerCommand::Start
        } else {
            PeerCommand::BfdDown
        };
        match commands.try_send(command) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(format!("BFD command for {peer}: session channel closed"))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.schedule_bfd_retry(peer, start);
                Err(format!(
                    "BFD command for {peer}: session queue full; retry scheduled"
                ))
            }
        }
    }

    /// Gate inbound admission and stop both primary and collision sessions.
    async fn hold_bgp_for_bfd(&mut self, peer: IpAddr) -> Result<(), String> {
        self.cancel_bfd_retry(peer, None);
        if let Some(coupling) = self.bfd_coupling.as_mut() {
            coupling.held_down.insert(peer);
            coupling.initially_withheld.remove(&peer);
        }
        let Some(key) = self.unique_peer_key_for_address(peer) else {
            return Ok(());
        };
        let pending = self
            .peers
            .get_mut(&key)
            .and_then(|managed| managed.pending_inbound.take());
        let mut failure = None;
        if let Some(pending) = pending {
            let outcome = self
                .quiesce_retiring_session(
                    &key,
                    pending.session_id,
                    pending.handle,
                    "BFD down pending inbound",
                    false,
                )
                .await;
            if outcome == super::PeerShutdownOutcome::TimedOut {
                failure = Some(format!("BFD pending inbound stop for {peer} timed out"));
            } else {
                info!(%peer, "BFD down — shut down pending inbound collision candidate");
            }
        }
        if let Err(error) = self.enqueue_bfd_command(peer, false) {
            failure = Some(error);
        }
        failure.map_or(Ok(()), Err)
    }

    fn release_bgp_bfd_hold(&mut self, peer: IpAddr) -> Result<(), String> {
        self.cancel_bfd_retry(peer, None);
        if !self.bfd_withholding(&peer) {
            return Ok(());
        }
        self.enqueue_bfd_command(peer, true)?;
        if let Some(coupling) = self.bfd_coupling.as_mut() {
            coupling.held_down.remove(&peer);
            coupling.initially_withheld.remove(&peer);
        }
        Ok(())
    }

    pub(super) fn abort_bfd_reload(&mut self) {
        if let Some(coupling) = self.bfd_coupling.as_mut() {
            coupling.pending = None;
            coupling.pending_bound = None;
            coupling.pending_probes.clear();
            coupling.reloading = false;
            coupling.rollback_lookup = false;
            coupling.held_down.retain(|peer| {
                coupling.prior_held.contains(peer)
                    || coupling
                        .configured
                        .get(peer)
                        .is_some_and(|params| params.strict)
            });
            coupling.initially_withheld.retain(|peer| {
                coupling.held_down.contains(peer)
                    && (!coupling.prior_held.contains(peer)
                        || coupling.prior_initially_withheld.contains(peer))
                    && coupling
                        .configured
                        .get(peer)
                        .is_some_and(|params| params.strict)
            });
            coupling.held_down.extend(coupling.prior_held.drain());
            coupling
                .initially_withheld
                .extend(coupling.prior_initially_withheld.drain());
        }
        self.republish_bfd_desired();
    }

    pub(super) async fn commit_bfd_reload(
        &mut self,
        prepared: Option<PreparedRuntime>,
    ) -> Result<(), String> {
        self.commit_bfd_reload_with_ack(prepared, false).await
    }

    /// A timed-out binding removal already committed its local roster. Re-send
    /// the current roster, including its admin overlay, until the actor confirms it.
    pub(super) async fn confirm_bound_bfd_removal(&mut self) -> Result<(), String> {
        let Some(coupling) = self.bfd_coupling.as_mut() else {
            return Ok(());
        };
        if coupling.reloading {
            return Err("a BFD membership change is in progress".into());
        }
        coupling.prior_held.clone_from(&coupling.held_down);
        coupling
            .prior_initially_withheld
            .clone_from(&coupling.initially_withheld);
        coupling.pending = Some(coupling.configured.clone());
        coupling.reloading = true;
        coupling.rollback_lookup = false;
        self.commit_bfd_reload_with_ack(None, true).await
    }

    #[expect(
        clippy::too_many_lines,
        reason = "commit keeps socket acknowledgement and strict admission settlement in one ordered flow"
    )]
    async fn commit_bfd_reload_with_ack(
        &mut self,
        prepared: Option<PreparedRuntime>,
        require_ack: bool,
    ) -> Result<(), String> {
        let Some(coupling) = self.bfd_coupling.as_mut() else {
            return Ok(());
        };
        let configured = coupling
            .pending
            .take()
            .ok_or("missing staged BFD membership")?;
        let changed = coupling.configured != configured;
        let newly_strict: HashSet<_> = configured
            .values()
            .filter(|params| {
                params.strict
                    && coupling
                        .configured
                        .get(&params.peer)
                        .is_none_or(|old| !old.strict || old.revision != params.revision)
            })
            .map(|params| params.peer)
            .collect();
        let mut released: Vec<_> = coupling
            .held_down
            .iter()
            .copied()
            .filter(|peer| {
                !configured.contains_key(peer)
                    || (coupling.initially_withheld.contains(peer)
                        && configured.get(peer).is_some_and(|params| !params.strict))
            })
            .collect();
        coupling.configured = configured;
        if let Some(bound) = coupling.pending_bound.take() {
            coupling.bound = bound;
        }
        let previously_disabled = std::mem::take(&mut coupling.disabled);
        coupling.disabled = self
            .peers
            .iter()
            .filter(|(_, managed)| !managed.enabled)
            .map(|(key, _)| key.address)
            .collect();
        // A member with no peer keeps its state: a membership change that
        // configuration did not make (a binding, a scope move) must not
        // restart a session that a runtime deletion drained.
        coupling
            .disabled
            .extend(previously_disabled.into_iter().filter(|peer| {
                coupling.configured.contains_key(peer)
                    && !self.peers.keys().any(|key| key.address == *peer)
            }));
        coupling.reloading = false;
        coupling.rollback_lookup = false;
        let desired = BfdRuntimeConfig {
            sessions: coupling
                .configured
                .values()
                .map(|params| BfdSessionParams {
                    enabled: !coupling.disabled.contains(&params.peer),
                    ..params.clone()
                })
                .collect(),
        };
        // Sockets prepared for a range with no session yet must still reach
        // the actor, so their family counts as open.
        if !require_ack
            && !changed
            && prepared.is_none()
            && coupling.configured.is_empty()
            && coupling.held_down.is_empty()
        {
            coupling.pending_probes.clear();
            coupling.prior_held.clear();
            coupling.prior_initially_withheld.clear();
            coupling.desired_tx.send_replace(desired);
            return Ok(());
        }
        let reload_tx = coupling
            .reload_tx
            .clone()
            .ok_or("BFD reload channel unavailable")?;
        let (reply, applied) = oneshot::channel();
        let actor_desired = desired.clone();
        // Acknowledgement observes post-generation state; ordinary mutations
        // remain fenced while readiness and operator reads use the normal lane.
        let apply = async move {
            reload_tx
                .send(BfdReloadCommand {
                    prepared,
                    desired: actor_desired,
                    reply,
                })
                .await
                .map_err(|_| "BFD actor stopped before reload")?;
            applied.await.map_err(|_| "BFD actor stopped during reload")
        };
        let states = self
            .await_with_readiness_budget(
                apply,
                std::time::Duration::from_secs(5),
                OperatorReadAdmission::Served,
            )
            .await
            .ok_or("BFD reload acknowledgement timed out")??;
        let coupling = self
            .bfd_coupling
            .as_mut()
            .expect("BFD coupling remains attached during reload");
        let expected: HashSet<_> = desired
            .sessions
            .iter()
            .filter(|params| params.enabled)
            .map(|params| (params.peer, params.revision))
            .collect();
        let actual: HashSet<_> = states
            .iter()
            .map(|state| (state.peer, state.revision))
            .collect();
        if expected != actual || actual.len() != states.len() {
            return Err(
                "BFD actor acknowledgement did not match the desired session set".to_string(),
            );
        }
        // A real Down may have arrived while this generation owned the manager.
        // Preserve that failure hold before relaxing an initial strict gate.
        for state in &states {
            if !state.resync
                && !state.remote_admin_down
                && matches!(state.state, SessionState::Down | SessionState::AdminDown)
            {
                coupling.initially_withheld.remove(&state.peer);
                if coupling.configured.contains_key(&state.peer) {
                    released.retain(|peer| *peer != state.peer);
                }
            }
        }
        let probes = std::mem::take(&mut coupling.pending_probes);
        for params in desired.sessions.iter().chain(&probes) {
            if !coupling.opened.sessions.iter().any(|old| {
                old.peer.is_ipv6() == params.peer.is_ipv6() && old.multihop == params.multihop
            }) {
                coupling.opened.sessions.push(params.clone());
            }
        }
        coupling.desired_tx.send_replace(desired);
        coupling.prior_held.clear();
        coupling.prior_initially_withheld.clear();
        // The exact actor acknowledgement settles BFD membership. BGP lifecycle
        // commands only acknowledge enqueue, not application; as in ordinary
        // BFD events, a busy peer warns and retains its gate without preventing
        // coupling for the remaining peers or recovery-fencing the daemon.
        for peer in released {
            if let Err(error) = self.release_bgp_bfd_hold(peer) {
                warn!(%peer, %error, "BFD permits BGP: failed to (re)start session");
            }
        }
        for state in states {
            if state.state != SessionState::Up && !state.remote_admin_down {
                let session_id = self
                    .unique_peer_key_for_address(state.peer)
                    .and_then(|key| self.peers.get(&key))
                    .map(super::ManagedPeer::session_id);
                let coupling = self
                    .bfd_coupling
                    .as_mut()
                    .expect("BFD acknowledgement owns coupling");
                if coupling.held_down.contains(&state.peer)
                    && let Some(retry) = coupling.retries.get_mut(&state.peer)
                    && !retry.start
                    && Some(retry.session_id) == session_id
                {
                    // Replacing only BFD must not discard an undelivered Stop
                    // still required by this same BGP session's retained hold.
                    retry.revision = Some(state.revision);
                }
            }
            if newly_strict.contains(&state.peer)
                && state.state != SessionState::Up
                && !state.remote_admin_down
            {
                let superseded_start = self.cancel_bfd_retry(state.peer, Some(true));
                let held = self.bfd_withholding(&state.peer);
                let initially_held = self
                    .bfd_coupling
                    .as_ref()
                    .is_some_and(|coupling| coupling.initially_withheld.contains(&state.peer));
                if !held || superseded_start {
                    if let Err(error) = self.hold_bgp_for_bfd(state.peer).await {
                        let peer = state.peer;
                        warn!(%peer, %error, "BFD down: failed to stop BGP session");
                    }
                    if state.resync && (!held || initially_held) {
                        self.mark_bfd_withheld(state.peer);
                    }
                }
                continue;
            }
            self.handle_bfd_state_change(state).await;
        }
        Ok(())
    }

    /// Mark a configured peer's BFD session enabled (`disabled = false`, e.g.
    /// neighbor enable / (re-)add) or disabled (`true`, e.g. disable / delete)
    /// and republish the desired set. No-op when coupling is off or the peer is
    /// not BFD-configured.
    pub(super) fn set_bfd_peer_disabled(&mut self, peer: IpAddr, disabled: bool) {
        if disabled {
            self.cancel_bfd_retry(peer, None);
        }
        let relevant = self.bfd_coupling.as_mut().is_some_and(|c| {
            if c.reloading || !c.configured.contains_key(&peer) {
                return false;
            }
            let changed = if disabled {
                c.disabled.insert(peer)
            } else {
                c.disabled.remove(&peer)
            };
            // Actual admin transitions must reach the actor immediately, even
            // during registration. Outside that operation an unchanged enable
            // still needs a fresh reconcile ack to release a new strict hold.
            changed || !c.registering
        });
        if relevant {
            self.republish_bfd_desired();
        }
    }

    /// Whether `peer` is a configured **strict**-mode BFD peer (RFC 5882): its
    /// BGP session must be withheld from establishment until BFD reaches Up.
    pub(super) fn is_strict_bfd_peer(&self, peer: &IpAddr) -> bool {
        self.bfd_coupling
            .as_ref()
            .and_then(|c| {
                if c.rollback_lookup {
                    &c.configured
                } else {
                    c.pending.as_ref().unwrap_or(&c.configured)
                }
                .get(peer)
            })
            .is_some_and(|params| params.strict)
    }

    /// Whether starting BGP should be **withheld** when this peer is added or
    /// enabled: true for any strict BFD peer. A strict peer is always added
    /// pre-held; the actor's reconcile **ack** (or a fresh transition) releases
    /// it once BFD permits BGP (Up, or remote `AdminDown` per RFC 5882 §4.1).
    /// `PeerManager` never trusts a cached BFD state for this decision, which is
    /// what keeps a strict re-enable from leaking BGP across a coalesced
    /// disable→enable (and never deadlocks: the ack always re-confirms).
    pub(super) fn bfd_should_withhold(&self, peer: &IpAddr) -> bool {
        self.is_strict_bfd_peer(peer)
    }

    /// Whether this peer's BGP is **currently** withheld/held by BFD (so an
    /// inbound connection must be dropped rather than establishing). Distinct
    /// from [`Self::bfd_should_withhold`] (the add/enable-time decision): an
    /// *established* strict peer is not held and must accept inbound normally.
    pub(super) fn bfd_withholding(&self, peer: &IpAddr) -> bool {
        self.bfd_coupling
            .as_ref()
            .is_some_and(|c| c.held_down.contains(peer))
    }

    /// Mark a strict peer's BGP session as withheld (pre-held) at add time so
    /// the first BFD Up releases it through the normal `handle_bfd_state_change`
    /// up→start path. No-op when coupling is off.
    pub(super) fn mark_bfd_withheld(&mut self, peer: IpAddr) {
        self.cancel_bfd_retry(peer, Some(true));
        if let Some(c) = self.bfd_coupling.as_mut() {
            c.held_down.insert(peer);
            c.initially_withheld.insert(peer);
        }
    }

    /// Follow a recreated interface: re-resolve each scoped link-local BFD
    /// session's interface by name and, when its index changed, replace the
    /// session under a fresh revision. Driven by link-state changes,
    /// independently of TCP dialing, because strict BFD can hold a peer before
    /// any connect attempt. A name that resolves to nothing leaves the session
    /// as it is until it does.
    ///
    /// The replacement is staged as a BFD membership change and settled by
    /// [`Self::commit_bfd_reload`], exactly as a reload that replaces a session:
    /// the actor acknowledges the new set, a strict peer whose replacement is
    /// not yet Up is held again (stopping its BGP session and any pending
    /// inbound candidate), and an undelivered stop retry moves to the new
    /// revision.
    pub(super) async fn refresh_bfd_link_local_scopes(&mut self) {
        let Some(coupling) = self.bfd_coupling.as_ref() else {
            return;
        };
        if coupling.reloading {
            // A generation owns BFD membership now; look again afterwards.
            self.schedule_bfd_scope_retry();
            return;
        }
        let updates: Vec<(IpAddr, u32)> = coupling
            .configured
            .values()
            // A binding's session follows the binding: a recreated interface
            // retires and rebinds it, so this path never moves it as well.
            .filter(|params| !coupling.bound.contains(&params.peer))
            .filter_map(|params| {
                let scope = params.scope_id?;
                let key = self.unique_peer_key_for_address(params.peer)?;
                let interface = key.interface.as_deref()?;
                let current = self
                    .peers
                    .get(&key)?
                    .transport_config
                    .link_state
                    .resolve_interface(interface)?;
                (current != scope).then_some((params.peer, current))
            })
            .collect();
        if updates.is_empty() && self.link_check.bfd_unsettled.is_empty() {
            return;
        }
        let mut moving = std::mem::take(&mut self.link_check.bfd_unsettled);
        moving.extend(updates.iter().map(|(peer, _)| *peer));
        let coupling = self.bfd_coupling.as_mut().expect("checked above");
        coupling.prior_held.clone_from(&coupling.held_down);
        coupling
            .prior_initially_withheld
            .clone_from(&coupling.initially_withheld);
        let strict: Vec<IpAddr> = moving
            .iter()
            .copied()
            .filter(|peer| {
                coupling
                    .configured
                    .get(peer)
                    .is_some_and(|params| params.strict)
            })
            .collect();
        // A strict peer must not admit BGP between staging the replacement
        // and the replacement's confirmed Up: hold it now, before waiting on
        // the actor. The Up acknowledgement at the new revision releases it,
        // on this attempt or a retry.
        for peer in &strict {
            if !self.bfd_withholding(peer)
                && let Err(error) = self.hold_bgp_for_bfd(*peer).await
            {
                warn!(%peer, %error, "failed to stop strict BGP peer for a BFD scope move");
            }
        }
        let coupling = self.bfd_coupling.as_mut().expect("checked above");
        let mut configured = coupling.configured.clone();
        for (peer, ifindex) in updates {
            let Some(params) = configured.get_mut(&peer) else {
                continue;
            };
            let Ok(destination) =
                crate::bfd_runtime::bfd_destination(peer, Some(ifindex), params.multihop)
            else {
                continue;
            };
            info!(
                %peer,
                old_scope = ?params.scope_id,
                new_scope = ifindex,
                "BFD link-local interface has a new index; replacing the session"
            );
            params.scope_id = Some(ifindex);
            params.destination = destination;
            params.revision = coupling.next_revision;
            coupling.next_revision = coupling.next_revision.saturating_add(1);
            // An undelivered stop for this peer's BGP session belongs to the
            // replacement too, whether or not the actor acknowledges it.
            if let Some(retry) = coupling.retries.get_mut(&peer)
                && !retry.start
            {
                retry.revision = Some(params.revision);
            }
        }
        coupling.pending = Some(configured);
        coupling.reloading = true;
        coupling.rollback_lookup = false;
        if let Err(error) = self.commit_bfd_reload(None).await {
            // Fail closed, as an uncertain reload does: the replacement is not
            // confirmed, so the strict peers held above stay held until a
            // later attempt settles it.
            warn!(
                %error,
                "BFD link-local scope move was not acknowledged; strict peers stay held and the \
                 move will be retried"
            );
            if let Some(coupling) = self.bfd_coupling.as_mut() {
                coupling.held_down.extend(strict.iter().copied());
            }
            self.link_check.bfd_unsettled = moving;
            self.schedule_bfd_scope_retry();
        }
    }

    /// Register (`Some`) or remove (`None`) the BFD session of an
    /// interface-only neighbor's binding at `peer`, under a fresh revision,
    /// through the acknowledged replacement path a reload and a scope move
    /// use: the actor confirms the new set, and a strict peer that is not Up
    /// on it is held. Members left by bindings that no longer exist are
    /// pruned on the way. A no-op when nothing is registered or removed.
    pub(super) async fn set_bound_bfd_session(
        &mut self,
        peer: IpAddr,
        params: Option<BfdSessionParams>,
    ) -> Result<(), String> {
        let mut live = self.unnumbered_bound_addresses();
        // A dynamic session's member is runtime-registered too.
        live.extend(
            self.peers
                .iter()
                .filter(|(_, managed)| managed.is_dynamic)
                .map(|(key, _)| key.address),
        );
        let Some(coupling) = self.bfd_coupling.as_mut() else {
            return if params.is_some() {
                Err("BFD is not running".into())
            } else {
                Ok(())
            };
        };
        let mut bound = coupling.bound.clone();
        bound.retain(|member| *member == peer || live.contains(member));
        if params.is_none() && !bound.contains(&peer) && bound.len() == coupling.bound.len() {
            return Ok(());
        }
        if coupling.reloading {
            return Err("a BFD membership change is in progress".into());
        }
        let mut configured = coupling.configured.clone();
        configured.retain(|member, _| !coupling.bound.contains(member) || bound.contains(member));
        if let Some(mut params) = params {
            params.revision = coupling.next_revision;
            configured.insert(peer, params);
            bound.insert(peer);
        } else {
            configured.remove(&peer);
            bound.remove(&peer);
        }
        let desired = BfdRuntimeConfig {
            sessions: configured.values().cloned().collect(),
        };
        let prepared = prepare_reload(&desired, &coupling.opened)
            .map_err(|error| format!("BFD socket preflight: {error}"))?;
        coupling.next_revision = coupling
            .next_revision
            .checked_add(1)
            .ok_or("BFD session revision exhausted")?;
        coupling.bound = bound;
        coupling.pending_bound = None;
        coupling.prior_held.clone_from(&coupling.held_down);
        coupling
            .prior_initially_withheld
            .clone_from(&coupling.initially_withheld);
        coupling.pending = Some(configured);
        coupling.reloading = true;
        coupling.rollback_lookup = false;
        self.commit_bfd_reload(prepared).await
    }

    /// The address of the binding registration owned by the interface-only
    /// neighbor on `interface`, whether or not its peer was ever added.
    pub(super) fn bound_bfd_registration_on(&self, interface: &str) -> Option<IpAddr> {
        let coupling = self.bfd_coupling.as_ref()?;
        coupling.bound.iter().copied().find(|member| {
            coupling
                .configured
                .get(member)
                .is_some_and(|params| params.peer_interface == interface)
        })
    }

    fn schedule_bfd_scope_retry(&mut self) {
        self.link_check.bfd_retry_at.get_or_insert_with(|| {
            tokio::time::Instant::now() + super::link_failover::BFD_SCOPE_RETRY
        });
    }

    /// Take the BFD state-change receiver into a `run`-local (so the `select!`
    /// arm captures the local rather than `self`, mirroring the BMP interval).
    pub(super) fn take_bfd_state_change_rx(&mut self) -> Option<BfdStateChangeReceiver> {
        self.bfd_coupling
            .as_mut()
            .and_then(|c| c.state_change_rx.take())
    }

    /// Overlay live admin state onto the accepted BFD membership. Publication is
    /// suspended during a generation so rollback cannot drain live sessions.
    pub(super) fn republish_bfd_desired(&mut self) {
        let Some(coupling) = self.bfd_coupling.as_mut() else {
            return;
        };
        if coupling.reloading {
            return;
        }
        #[cfg(test)]
        {
            coupling.desired_publications += 1;
        }
        let disabled = coupling.disabled.clone();
        // A disabled peer's session is drained, so it can't be "held down".
        coupling.held_down.retain(|peer| !disabled.contains(peer));
        coupling
            .initially_withheld
            .retain(|peer| !disabled.contains(peer));
        let sessions: Vec<BfdSessionParams> = coupling
            .configured
            .values()
            .map(|params| BfdSessionParams {
                enabled: !disabled.contains(&params.peer),
                ..params.clone()
            })
            .collect();
        // `send` only errors if the actor is gone (daemon shutting down).
        let _ = coupling.desired_tx.send(BfdRuntimeConfig { sessions });
    }

    /// Handle one BFD session state change (ADR-0067 step 4). BFD **permits
    /// BGP** when it is Up *or* the remote signaled `AdminDown` (RFC 5882 §4.1 —
    /// an administratively-down BFD session is disabled, not failing, so the
    /// adjacency MUST be allowed, in both strict and non-strict mode); in that
    /// case any withhold/hold is released and the session started, otherwise an
    /// established session is left alone. A genuine **down** (detection timeout
    /// or a remote-signaled `Down`) tears the BGP session down before the hold
    /// timer and marks it held. The strict/non-strict difference is only the
    /// *initial* withhold (strict peers are added pre-held by `add_peer`).
    pub(super) async fn handle_bfd_state_change(&mut self, change: BfdStateChange) {
        if self
            .bfd_coupling
            .as_ref()
            .is_some_and(|coupling| coupling.reloading)
        {
            return;
        }
        let peer = change.peer;
        // Configured BFD peer? Read whether it is currently held.
        let Some(already_held) = self
            .bfd_coupling
            .as_ref()
            .filter(|c| {
                c.configured
                    .get(&peer)
                    .is_some_and(|params| params.revision == change.revision)
            })
            .map(|c| c.held_down.contains(&peer))
        else {
            return; // not a configured BFD peer (or coupling off)
        };

        // Only act for a peer that is currently managed and admin-enabled. A
        // disabled/deleted peer's session is being drained on purpose (a local
        // operator action; the disable/delete lifecycle path stops BGP), so
        // ignore its changes and clear any stale hold.
        let peer_key = self.unique_peer_key_for_address(peer);
        let active = peer_key
            .as_ref()
            .and_then(|key| self.peers.get(key))
            .is_some_and(|p| p.enabled);
        if !active {
            if let Some(c) = self.bfd_coupling.as_mut() {
                c.held_down.remove(&peer);
                c.initially_withheld.remove(&peer);
            }
            // A *deleted* peer's BFD session drains asynchronously, so
            // its final AdminDown transition re-creates
            // `bfd_session_up{peer}=0` after the delete-path reap. This
            // handler runs after the actor's metric write, so re-reaping
            // here makes removal the last word. A merely disabled peer
            // still exists (`peer_keys_for_address` non-empty) and keeps
            // its series.
            // A binding registers its session before its peer exists; the
            // registration's own acknowledgement is not a deletion.
            let awaiting_binding = self
                .bfd_coupling
                .as_ref()
                .is_some_and(|c| c.bound.contains(&peer));
            if self.peer_keys_for_address(peer).is_empty() && !awaiting_binding {
                // The session's own value: scoped for a link-local neighbor.
                let label = self
                    .bfd_coupling
                    .as_ref()
                    .and_then(|c| c.configured.get(&peer))
                    .map_or_else(|| peer.to_string(), |params| params.peer_label.clone());
                self.metrics.reap_peer_series(&label);
            }
            return;
        }

        // RFC 5882 §4.1/§4.2: BFD permits BGP when Up or when the remote is
        // AdminDown. Release any withhold/hold and (re)start the session; leave
        // an already-established (unheld) one alone. This applies equally to a
        // real transition and to a reconcile ack — an ack that finds BFD
        // permitting BGP is exactly how a coalesced disable→re-enable releases a
        // strict withhold.
        let permits_bgp = change.state == SessionState::Up || change.remote_admin_down;
        if permits_bgp {
            if let Err(error) = self.release_bgp_bfd_hold(peer) {
                warn!(%peer, %error, "BFD permits BGP: failed to (re)start session");
            } else if already_held {
                if change.remote_admin_down {
                    info!(%peer, "BFD remote AdminDown — allowing BGP (RFC 5882 §4.1)");
                } else {
                    info!(%peer, "BFD up — allowing BGP session to (re)establish");
                }
            }
            return;
        }

        // BFD does not permit BGP (a Down/Init). An **ack** (level re-report) is
        // release-only: it must not tear BGP down — a freshly (re)started session
        // is Down, and an established non-strict peer's BGP must only fall to a
        // real Up→Down *transition*, never a level report. So only a genuine
        // transition (resync=false) to Down tears BGP down and holds it.
        // Relaxing strict admission permits the initial Start even while BFD
        // remains initially Down. Its failed enqueue must survive level acks;
        // a genuine failure still revokes that permission and cancels retry.
        let relaxing_initial_hold = change.resync
            && self.bfd_coupling.as_ref().is_some_and(|coupling| {
                coupling.initially_withheld.contains(&peer)
                    && coupling
                        .configured
                        .get(&peer)
                        .is_some_and(|params| !params.strict)
            });
        let superseded_start = !relaxing_initial_hold && self.cancel_bfd_retry(peer, Some(true));
        if change.resync {
            return;
        }
        match change.state {
            SessionState::Down | SessionState::AdminDown => {
                if let Some(coupling) = self.bfd_coupling.as_mut() {
                    coupling.initially_withheld.remove(&peer);
                }
                if already_held && !superseded_start {
                    return;
                }
                if let Err(error) = self.hold_bgp_for_bfd(peer).await {
                    warn!(%peer, %error, "BFD down: failed to stop BGP session");
                } else {
                    info!(%peer, diagnostic = ?change.diagnostic,
                        "BFD down — tearing down BGP session before the hold timer");
                }
            }
            SessionState::Init | SessionState::Up => {}
        }
    }
}

/// The BFD session `config`'s range for an accepted dynamic session runs to
/// `peer`: the range with the session's accepted prefix and peer group.
fn dynamic_bfd_params(
    config: &crate::config::Config,
    accepted: &super::dynamic::AcceptedDynamicRange,
    peer: IpAddr,
) -> Result<Option<BfdSessionParams>, String> {
    let Some(range) = accepted_range(config, accepted) else {
        return Ok(None);
    };
    crate::bfd_runtime::dynamic_session_params(config, range, peer)
        .map_err(|error| error.to_string())
}

/// The range in `config` with a session's accepted prefix and peer group.
fn accepted_range<'a>(
    config: &'a crate::config::Config,
    accepted: &super::dynamic::AcceptedDynamicRange,
) -> Option<&'a crate::config::DynamicNeighborConfig> {
    config.dynamic_neighbors.iter().find(|range| {
        range.peer_group == accepted.peer_group
            && crate::config::effective_prefix_str(&range.prefix)
                == Some((accepted.addr, accepted.prefix_len))
    })
}

impl BfdCoupling {
    /// Reserve the socket families `sockets` needs that the actor does not
    /// own yet; a family that cannot open is an error naming the preflight.
    fn preflight_sockets(
        &mut self,
        sockets: &BfdRuntimeConfig,
    ) -> Result<Option<PreparedRuntime>, String> {
        #[cfg(test)]
        if let Some(result) = self.socket_preflight.take() {
            return result.map_err(|error| format!("BFD socket preflight: {error}"));
        }
        prepare_reload(sockets, &self.opened)
            .map_err(|error| format!("BFD socket preflight: {error}"))
    }
}

/// A config transaction may not change which ranges run BFD or how: those
/// sessions are registered and removed by startup and SIGHUP, which own the
/// socket preflight and the acknowledged membership change.
pub(super) fn dynamic_range_bfd_unchanged(
    current: &crate::config::Config,
    candidate: &crate::config::Config,
) -> Result<(), String> {
    let inventory = |config: &crate::config::Config| {
        let mut ranges: Vec<String> = config
            .dynamic_neighbors
            .iter()
            .filter(|range| range.bfd.as_ref().is_some_and(|bfd| bfd.enabled))
            .map(|range| {
                format!(
                    "{:?} {} {:?}",
                    crate::config::effective_prefix_str(&range.prefix),
                    range.peer_group,
                    range.bfd
                )
            })
            .collect();
        ranges.sort();
        ranges
    };
    if inventory(current) == inventory(candidate) {
        Ok(())
    } else {
        Err(
            "[[dynamic_neighbors]] transaction changes a range's `bfd`; dynamic-range BFD is \
             applied only by startup or SIGHUP reload — apply this change through the config \
             file and SIGHUP"
                .to_string(),
        )
    }
}
