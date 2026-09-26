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
    opened: BfdRuntimeConfig,
    next_revision: u64,
    /// During a generation, lifecycle mutations must not publish partial BFD membership.
    pub(super) reloading: bool,
    /// The startup registration operation resyncs unchanged membership once at its end.
    pub(super) registering: bool,
    #[cfg(test)]
    pub(super) desired_publications: usize,
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
        let mut opened = BfdRuntimeConfig {
            sessions: configured.values().cloned().collect(),
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
        let Some(coupling) = self.bfd_coupling.as_mut() else {
            return Ok(None);
        };
        let mut desired =
            BfdRuntimeConfig::from_reload(candidate, &self.current_config, &coupling.configured)
                .map_err(|error| error.to_string())?;
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
        let prepared = prepare_reload(&desired, &coupling.opened)
            .map_err(|error| format!("BFD socket preflight: {error}"))?;
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
        coupling.reloading = true;
        coupling.rollback_lookup = false;
        Ok(prepared)
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

    #[expect(
        clippy::too_many_lines,
        reason = "commit keeps socket acknowledgement and strict admission settlement in one ordered flow"
    )]
    pub(super) async fn commit_bfd_reload(
        &mut self,
        prepared: Option<PreparedRuntime>,
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
        coupling.disabled = self
            .peers
            .iter()
            .filter(|(_, managed)| !managed.enabled)
            .map(|(key, _)| key.address)
            .collect();
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
        if !changed && coupling.configured.is_empty() && coupling.held_down.is_empty() {
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
        for params in &desired.sessions {
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
            if self.peer_keys_for_address(peer).is_empty() {
                self.metrics.reap_peer_series(&peer.to_string());
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
