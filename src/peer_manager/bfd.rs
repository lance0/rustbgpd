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

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use tokio::sync::watch;
use tracing::{info, warn};

use rustbgpd_bfd::SessionState;

use crate::bfd_runtime::{
    BfdRuntimeConfig, BfdSessionParams, BfdStateChange, BfdStateChangeReceiver,
};

use super::{PEER_LIFECYCLE_COMMAND_TIMEOUT, PeerManager};

/// State for RFC 5882 coupling, owned by `PeerManager`.
pub(super) struct BfdCoupling {
    /// Publishes the desired session set to the actor (level-triggered).
    desired_tx: watch::Sender<BfdRuntimeConfig>,
    /// Session state changes from the actor (per-peer coalescing, latest state
    /// wins; a real transition is never masked by an ack). Taken into a
    /// `run`-local at loop start so the `select!` arm doesn't borrow `self`.
    state_change_rx: Option<BfdStateChangeReceiver>,
    /// Configured BFD params per peer, resolved from config at startup. BFD is
    /// restart-required, so this base set is fixed for the daemon's lifetime;
    /// the published desired set overlays live admin state onto it.
    configured: HashMap<IpAddr, BfdSessionParams>,
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
    held_down: HashSet<IpAddr>,
}

impl PeerManager {
    /// Attach the BFD coupling channels (ADR-0067 step 4). Called once at
    /// startup when any neighbor configures BFD; otherwise coupling stays off.
    #[must_use]
    pub fn with_bfd_coupling(
        mut self,
        desired_tx: watch::Sender<BfdRuntimeConfig>,
        state_change_rx: BfdStateChangeReceiver,
        configured: HashMap<IpAddr, BfdSessionParams>,
    ) -> Self {
        self.bfd_coupling = Some(BfdCoupling {
            desired_tx,
            state_change_rx: Some(state_change_rx),
            configured,
            disabled: HashSet::new(),
            held_down: HashSet::new(),
        });
        self
    }

    /// Mark a configured peer's BFD session enabled (`disabled = false`, e.g.
    /// neighbor enable / (re-)add) or disabled (`true`, e.g. disable / delete)
    /// and republish the desired set. No-op when coupling is off or the peer is
    /// not BFD-configured.
    pub(super) fn set_bfd_peer_disabled(&mut self, peer: IpAddr, disabled: bool) {
        let relevant = self.bfd_coupling.as_mut().is_some_and(|c| {
            if !c.configured.contains_key(&peer) {
                return false;
            }
            if disabled {
                c.disabled.insert(peer);
            } else {
                c.disabled.remove(&peer);
            }
            true
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
            .and_then(|c| c.configured.get(peer))
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
        if let Some(c) = self.bfd_coupling.as_mut() {
            c.held_down.insert(peer);
        }
    }

    /// Take the BFD state-change receiver into a `run`-local (so the `select!`
    /// arm captures the local rather than `self`, mirroring the BMP interval).
    pub(super) fn take_bfd_state_change_rx(&mut self) -> Option<BfdStateChangeReceiver> {
        self.bfd_coupling
            .as_mut()
            .and_then(|c| c.state_change_rx.take())
    }

    /// Recompute and publish the desired BFD session set: every configured BFD
    /// peer, with `enabled = !disabled` (the explicit disabled/deleted set). A
    /// disabled/deleted neighbor is kept in the set as disabled (within the
    /// startup-pinned BFD universe) so the actor drains its session to
    /// `AdminDown`. Timers/strict come only from the fixed startup `configured`
    /// set, so a reload can't leak them into the live set. The `watch` sender is
    /// held for the daemon's life and never recreated — dropping it would signal
    /// the actor to shut down. No-op when coupling is off.
    pub(super) fn republish_bfd_desired(&mut self) {
        let Some(coupling) = self.bfd_coupling.as_mut() else {
            return;
        };
        let disabled = coupling.disabled.clone();
        // A disabled peer's session is drained, so it can't be "held down".
        coupling.held_down.retain(|peer| !disabled.contains(peer));
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
        let peer = change.peer;
        // Configured BFD peer? Read whether it is currently held.
        let Some(already_held) = self
            .bfd_coupling
            .as_ref()
            .filter(|c| c.configured.contains_key(&peer))
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
            if !already_held {
                return;
            }
            if let Some(c) = self.bfd_coupling.as_mut() {
                c.held_down.remove(&peer);
            }
            if let Some(managed) = peer_key.as_ref().and_then(|key| self.peers.get(key)) {
                if let Err(e) = managed
                    .handle
                    .start_timeout(PEER_LIFECYCLE_COMMAND_TIMEOUT)
                    .await
                {
                    warn!(%peer, error = %e, "BFD permits BGP: failed to (re)start session");
                } else if change.remote_admin_down {
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
        if change.resync {
            return;
        }
        match change.state {
            SessionState::Down | SessionState::AdminDown => {
                if already_held {
                    return;
                }
                // Tear down a pending collision candidate too. It is a live,
                // already-started session: stopping only the primary would
                // let the candidate's BackToIdle promotion re-establish BGP
                // over the BFD-down path moments later (the inbound-accept
                // gate only blocks connections accepted AFTER the hold
                // begins, not a candidate spawned before it).
                let pending = peer_key
                    .as_ref()
                    .and_then(|key| self.peers.get_mut(key))
                    .and_then(|managed| managed.pending_inbound.take());
                if let Some(pending) = pending {
                    if let Some(peer_key) = &peer_key {
                        let _ = self
                            .quiesce_retiring_session(
                                peer_key,
                                pending.session_id,
                                pending.handle,
                                "BFD down pending inbound",
                                false,
                            )
                            .await;
                    }
                    info!(%peer, "BFD down — shut down pending inbound collision candidate");
                }
                if let Some(managed) = peer_key.as_ref().and_then(|key| self.peers.get(key)) {
                    let reason = bytes::Bytes::from_static(b"BFD session down");
                    if let Err(e) = managed
                        .handle
                        .stop_timeout(Some(reason), PEER_LIFECYCLE_COMMAND_TIMEOUT)
                        .await
                    {
                        warn!(%peer, error = %e, "BFD down: failed to stop BGP session");
                    } else {
                        info!(%peer, diagnostic = ?change.diagnostic,
                            "BFD down — tearing down BGP session before the hold timer");
                    }
                }
                if let Some(c) = self.bfd_coupling.as_mut() {
                    c.held_down.insert(peer);
                }
            }
            SessionState::Init | SessionState::Up => {}
        }
    }
}
