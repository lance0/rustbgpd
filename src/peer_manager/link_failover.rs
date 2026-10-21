//! Fast external failover: fan confirmed interface-down events out to the
//! sessions that may be carried by that interface.
//!
//! The manager owns eligibility (operator knob, eBGP, administratively enabled);
//! each session owns the proof that the interface carries its connection
//! ([`rustbgpd_transport::LinkDownEvent::carries`]), because only the session
//! knows its socket's local address and scope. A session the interface does not
//! carry ignores the command.

use std::sync::Arc;

use rustbgpd_transport::{LinkDownEvent, PeerCommand};
use tokio::sync::mpsc;
use tracing::{debug, info};

use super::{ManagedPeerState, PeerManager};

impl PeerManager {
    /// Attach the fast-external-failover event feed. Without it (non-Linux, or
    /// the monitor could not open its netlink socket) sessions keep relying on
    /// the hold timer and BFD.
    #[must_use]
    pub fn with_link_failover(mut self, events: mpsc::Receiver<Arc<LinkDownEvent>>) -> Self {
        self.link_down_rx = Some(events);
        self
    }

    pub(super) fn take_link_down_rx(&mut self) -> Option<mpsc::Receiver<Arc<LinkDownEvent>>> {
        self.link_down_rx.take()
    }

    pub(super) fn handle_link_down(&mut self, event: &Arc<LinkDownEvent>) {
        let mut sessions = 0_usize;
        for managed in self.peers.values() {
            if !fast_external_failover_eligible(managed) {
                continue;
            }
            let pending = managed
                .pending_inbound
                .as_ref()
                .map(|pending| pending.handle.commands_sender());
            for commands in std::iter::once(managed.handle().commands_sender()).chain(pending) {
                sessions += 1;
                let command = PeerCommand::InterfaceDown(Arc::clone(event));
                match commands.try_send(command) {
                    Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
                    // A busy session still gets the event: the session checks
                    // its own socket when it runs the command, so a late
                    // delivery cannot stop a connection the interface does not
                    // carry.
                    Err(mpsc::error::TrySendError::Full(command)) => {
                        tokio::spawn(async move {
                            let _ = commands.send(command).await;
                        });
                    }
                }
            }
        }
        if sessions == 0 {
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
                candidate_sessions = sessions,
                "fast external failover: interface down; checking candidate sessions"
            );
        }
    }
}

/// Knob on, administratively enabled, and eBGP. A remote ASN of 0 is an
/// accept-any dynamic child whose ASN is not learned yet; it is not Established,
/// so letting it through can only stop a connection the interface carries.
fn fast_external_failover_eligible(managed: &ManagedPeerState) -> bool {
    managed.enabled
        && managed.transport_config.fast_external_failover
        && managed.remote_asn != managed.transport_config.peer.local_asn
}
