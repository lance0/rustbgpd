//! Fast external failover: fan confirmed interface-down events out to the
//! sessions that may be carried by that interface.
//!
//! The manager owns eligibility (operator knob, administratively enabled, not
//! known to be iBGP); each session owns the proof that the interface carries
//! its connection ([`rustbgpd_transport::LinkDownEvent::carries`]), that the
//! event is newer than that connection, and that the negotiated peer is eBGP,
//! because only the session knows its socket and its OPEN. A session the event
//! does not apply to ignores the command.
//!
//! A busy session mailbox does not get a detached waiter per event. Deliveries
//! that find it full wait in a bounded map keyed by (session, interface). A
//! flapping link coalesces into one pending entry per session and interface
//! holding the newest link-level event plus each distinct address removal with
//! its own observation time, and distinct interfaces stay distinct.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rustbgpd_transport::{LinkDownCause, LinkDownEvent, PeerCommand};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::{ManagedPeerState, PeerManager};

/// Pending interface-down deliveries the manager holds for full mailboxes.
/// Past this, a delivery is dropped and logged; that session then relies on
/// its hold timer or BFD, as it would without fast external failover.
pub(super) const LINK_DOWN_PENDING_MAX: usize = 1024;
const LINK_DOWN_RETRY: Duration = Duration::from_millis(100);
/// Distinct address removals kept per pending (session, interface) entry.
/// Past this, a further removal is folded into the oldest one, which keeps
/// the older observation time: a later connection then ignores the folded
/// address rather than being stopped by it, so the overflow can only miss a
/// teardown (the hold timer still applies), never cause a wrong one.
pub(super) const LINK_DOWN_PENDING_ADDRESSES_MAX: usize = 8;

/// Deliveries for one (session, interface) waiting for mailbox capacity.
pub(super) struct PendingLinkDown {
    commands: mpsc::Sender<PeerCommand>,
    /// Newest carrier-loss, admin-down or removal event: it carries every
    /// address the interface had, so it supersedes older link-level events.
    pub(super) link: Option<Arc<LinkDownEvent>>,
    /// Address removals, oldest first, each with its original observation
    /// time; a removal of one address does not supersede another.
    pub(super) addresses: Vec<Arc<LinkDownEvent>>,
}

impl PendingLinkDown {
    fn new(commands: mpsc::Sender<PeerCommand>) -> Self {
        Self {
            commands,
            link: None,
            addresses: Vec::new(),
        }
    }

    fn merge(&mut self, event: &Arc<LinkDownEvent>) {
        if event.cause != LinkDownCause::AddressRemoved {
            self.link = Some(Arc::clone(event));
        } else if self
            .addresses
            .iter()
            .any(|known| known.addresses == event.addresses)
        {
            // Same address again: keep the original observation time.
        } else if self.addresses.len() < LINK_DOWN_PENDING_ADDRESSES_MAX {
            self.addresses.push(Arc::clone(event));
        } else {
            Arc::make_mut(&mut self.addresses[0])
                .addresses
                .extend(event.addresses.iter().copied());
        }
    }

    /// Hand queued events to the session in order. True when nothing is left
    /// to deliver (all sent, or the session exited).
    fn flush(&mut self) -> bool {
        loop {
            let Some(event) = self
                .link
                .clone()
                .or_else(|| self.addresses.first().cloned())
            else {
                return true;
            };
            match self.commands.try_send(PeerCommand::InterfaceDown(event)) {
                Ok(()) => {
                    if self.link.take().is_none() {
                        self.addresses.remove(0);
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return true,
                Err(mpsc::error::TrySendError::Full(_)) => return false,
            }
        }
    }
}

/// The link monitor's event feed (taken into a `run`-local at loop start) and
/// the deliveries waiting for full mailboxes: one entry per (session id,
/// ifindex), at most [`LINK_DOWN_PENDING_MAX`] entries.
#[derive(Default)]
pub(super) struct LinkDownDelivery {
    rx: Option<mpsc::Receiver<Arc<LinkDownEvent>>>,
    pub(super) pending: BTreeMap<(u64, u32), PendingLinkDown>,
    pub(super) retry_at: Option<tokio::time::Instant>,
}

impl PeerManager {
    /// Attach the fast-external-failover event feed. Without it (non-Linux, or
    /// the monitor could not open its netlink socket) sessions keep relying on
    /// the hold timer and BFD.
    #[must_use]
    pub fn with_link_failover(mut self, events: mpsc::Receiver<Arc<LinkDownEvent>>) -> Self {
        self.link_down.rx = Some(events);
        self
    }

    pub(super) fn take_link_down_rx(&mut self) -> Option<mpsc::Receiver<Arc<LinkDownEvent>>> {
        self.link_down.rx.take()
    }

    pub(super) fn handle_link_down(&mut self, event: &Arc<LinkDownEvent>) {
        let targets: Vec<(u64, mpsc::Sender<PeerCommand>)> = self
            .peers
            .values()
            .filter(|managed| fast_external_failover_eligible(managed))
            .flat_map(|managed| {
                let pending = managed
                    .pending_inbound
                    .as_ref()
                    .map(|pending| (pending.session_id, pending.handle.commands_sender()));
                std::iter::once((managed.session_id(), managed.handle().commands_sender()))
                    .chain(pending)
            })
            .collect();
        let mut dropped = 0_usize;
        for (session_id, commands) in &targets {
            let key = (*session_id, event.ifindex);
            if let Some(pending) = self.link_down.pending.get_mut(&key) {
                pending.merge(event);
                continue;
            }
            match commands.try_send(PeerCommand::InterfaceDown(Arc::clone(event))) {
                Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    if self.link_down.pending.len() < LINK_DOWN_PENDING_MAX {
                        let mut pending = PendingLinkDown::new(commands.clone());
                        pending.merge(event);
                        self.link_down.pending.insert(key, pending);
                    } else {
                        dropped += 1;
                    }
                }
            }
        }
        // Keep an armed deadline: events arriving faster than the retry
        // interval must not postpone delivery indefinitely.
        if self.link_down.retry_at.is_none() {
            self.schedule_link_down_retry();
        }
        if dropped > 0 {
            warn!(
                interface = %event.ifname,
                ifindex = event.ifindex,
                dropped,
                "fast external failover: pending deliveries at capacity; affected sessions \
                 fall back to their hold timer or BFD"
            );
        }
        if targets.is_empty() {
            debug!(
                interface = %event.ifname,
                ifindex = event.ifindex,
                reason = event.cause.as_str(),
                "fast external failover: interface down; no eligible sessions"
            );
        } else {
            info!(
                interface = %event.ifname,
                ifindex = event.ifindex,
                reason = event.cause.as_str(),
                candidate_sessions = targets.len(),
                "fast external failover: interface down; checking candidate sessions"
            );
        }
    }

    /// Retry deliveries that found a full mailbox. A session that exited is
    /// forgotten; a still-full one waits for the next retry.
    pub(super) fn retry_link_down(&mut self) {
        self.link_down.pending.retain(|_, pending| !pending.flush());
        self.schedule_link_down_retry();
    }

    fn schedule_link_down_retry(&mut self) {
        self.link_down.retry_at = (!self.link_down.pending.is_empty())
            .then(|| tokio::time::Instant::now() + LINK_DOWN_RETRY);
    }
}

/// Knob on, administratively enabled, and not known to be iBGP. A remote ASN
/// of 0 is an accept-any dynamic child whose ASN the manager has not learned
/// yet; classification is deferred to the session, which checks the
/// negotiated ASN before stopping anything.
fn fast_external_failover_eligible(managed: &ManagedPeerState) -> bool {
    managed.enabled
        && managed.transport_config.fast_external_failover
        && managed.remote_asn != managed.transport_config.peer.local_asn
}
