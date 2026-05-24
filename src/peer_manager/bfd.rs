//! RFC 5882 BGP/BFD coupling (ADR-0067 step 4).
//!
//! `PeerManager` owns the desired BFD session set and consumes session state
//! changes; the BFD actor is a pure session-runner that reconciles the desired
//! set and never learns BGP internals. This module holds the coupling state and
//! the non-strict teardown logic; strict-mode withholding lands in a later
//! slice.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use rustbgpd_bfd::SessionState;

use crate::bfd_runtime::{BfdRuntimeConfig, BfdSessionParams, BfdStateChange};

use super::PeerManager;

/// State for RFC 5882 coupling, owned by `PeerManager`.
pub(super) struct BfdCoupling {
    /// Publishes the desired session set to the actor (level-triggered).
    desired_tx: watch::Sender<BfdRuntimeConfig>,
    /// Lossless session state changes from the actor. Taken into a `run`-local
    /// at loop start so the `select!` arm doesn't borrow `self`.
    state_change_rx: Option<mpsc::UnboundedReceiver<BfdStateChange>>,
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
    /// (non-strict) or withheld pending the first Up (strict). Cleared when BFD
    /// recovers.
    held_down: HashSet<IpAddr>,
    /// Last-known BFD state per configured peer, recorded on every transition
    /// even while the peer is unmanaged. This makes the strict add/enable
    /// decision **level-triggered**: if BFD already reached Up before the peer
    /// was added (the actor starts sessions at spawn, peers are added later),
    /// `start()` happens immediately instead of waiting for a transition that
    /// will never come.
    last_state: HashMap<IpAddr, SessionState>,
}

impl PeerManager {
    /// Attach the BFD coupling channels (ADR-0067 step 4). Called once at
    /// startup when any neighbor configures BFD; otherwise coupling stays off.
    #[must_use]
    pub fn with_bfd_coupling(
        mut self,
        desired_tx: watch::Sender<BfdRuntimeConfig>,
        state_change_rx: mpsc::UnboundedReceiver<BfdStateChange>,
        configured: HashMap<IpAddr, BfdSessionParams>,
    ) -> Self {
        self.bfd_coupling = Some(BfdCoupling {
            desired_tx,
            state_change_rx: Some(state_change_rx),
            configured,
            disabled: HashSet::new(),
            held_down: HashSet::new(),
            last_state: HashMap::new(),
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

    /// Whether the peer's last-known BFD state is Up. Used to make the strict
    /// add/enable decision level-triggered (start now vs. withhold).
    pub(super) fn bfd_is_up(&self, peer: &IpAddr) -> bool {
        self.bfd_coupling
            .as_ref()
            .and_then(|c| c.last_state.get(peer))
            .is_some_and(|state| *state == SessionState::Up)
    }

    /// Whether a strict peer should be withheld from BGP establishment right
    /// now: it is a strict BFD peer **and** BFD is not already Up. (If BFD is
    /// already Up, start immediately — there is no future transition to release
    /// a withhold.)
    pub(super) fn bfd_should_withhold(&self, peer: &IpAddr) -> bool {
        self.is_strict_bfd_peer(peer) && !self.bfd_is_up(peer)
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
    pub(super) fn take_bfd_state_change_rx(
        &mut self,
    ) -> Option<mpsc::UnboundedReceiver<BfdStateChange>> {
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

    /// Handle one BFD session state change (ADR-0067 step 4). Uniform across
    /// strict and non-strict: a BFD **down** tears the BGP session down before
    /// the hold timer (RFC 5882) and marks it held; BFD **up** clears the hold
    /// and (re)starts the session. The strict/non-strict difference is purely
    /// the *initial* state — strict peers are added pre-held (withheld) by
    /// `add_peer`, so their first Up releases the withhold via the same path.
    pub(super) async fn handle_bfd_state_change(&mut self, change: BfdStateChange) {
        let peer = change.peer;
        // Record last-known state for every configured peer (even unmanaged
        // ones), and read whether it is held — then release the borrow before
        // touching `self.peers` / `self.bfd_coupling` mutably.
        let Some(already_held) = self.bfd_coupling.as_mut().and_then(|c| {
            if !c.configured.contains_key(&peer) {
                return None; // not a configured BFD peer
            }
            c.last_state.insert(peer, change.state);
            Some(c.held_down.contains(&peer))
        }) else {
            return; // not a configured BFD peer (or coupling off)
        };

        // Only act for a peer that is currently managed and admin-enabled. A
        // disabled/deleted peer's session is being drained to AdminDown on
        // purpose (PeerManager removed it from the desired set) — that is not a
        // failure, so ignore it and clear any stale hold.
        let active = self.peers.get(&peer).is_some_and(|p| p.enabled);
        if !active {
            if let Some(c) = self.bfd_coupling.as_mut() {
                c.held_down.remove(&peer);
            }
            return;
        }

        match change.state {
            SessionState::Down | SessionState::AdminDown => {
                if already_held {
                    return;
                }
                if let Some(managed) = self.peers.get(&peer) {
                    let reason = bytes::Bytes::from_static(b"BFD session down");
                    if let Err(e) = managed.handle.stop(Some(reason)).await {
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
            SessionState::Up => {
                if !already_held {
                    return;
                }
                if let Some(c) = self.bfd_coupling.as_mut() {
                    c.held_down.remove(&peer);
                }
                if let Some(managed) = self.peers.get(&peer) {
                    if let Err(e) = managed.handle.start().await {
                        warn!(%peer, error = %e, "BFD up: failed to restart BGP session");
                    } else {
                        info!(%peer, "BFD up — allowing BGP session to re-establish");
                    }
                }
            }
            SessionState::Init => {}
        }
    }
}
