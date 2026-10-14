//! Bounded generation- and connection-fenced EVPN reset admission.

use std::time::Duration;

use rustbgpd_rib::{EvpnRecoveryReset, EvpnRecoveryResetOutcome};
use rustbgpd_transport::PeerCommand;
use tokio::sync::{mpsc, oneshot};

use super::PeerManager;

pub(super) struct SessionRecoveryReset {
    pub(super) request: EvpnRecoveryReset,
    pub(super) queued: bool,
    reply: Option<oneshot::Sender<EvpnRecoveryResetOutcome>>,
    execution: Option<oneshot::Receiver<EvpnRecoveryResetOutcome>>,
}

impl PeerManager {
    pub(super) fn reset_evpn_recovery_session(
        &mut self,
        request: EvpnRecoveryReset,
        reply: oneshot::Sender<EvpnRecoveryResetOutcome>,
    ) {
        if request.outbound.is_closed() {
            let _ = reply.send(EvpnRecoveryResetOutcome::Rejected);
            return;
        }
        let Some(key) = self.peer_key_for_session(request.session_id) else {
            let _ = reply.send(EvpnRecoveryResetOutcome::Rejected);
            return;
        };
        if key.address != request.peer {
            let _ = reply.send(EvpnRecoveryResetOutcome::Rejected);
            return;
        }
        let session_id = request.session_id;
        let Some((_, slot)) = self.peers.recovery_session_mut(&key, session_id) else {
            let _ = reply.send(EvpnRecoveryResetOutcome::Rejected);
            return;
        };
        if let Some(reset) = slot.as_mut()
            && reset.request.outbound.same_channel(&request.outbound)
        {
            if reset.queued && reset.execution.is_none() {
                let _ = reply.send(EvpnRecoveryResetOutcome::Executed);
            } else if reset.reply.as_ref().is_none_or(oneshot::Sender::is_closed) {
                // A retry whose old receipt receiver disappeared can join
                // the one existing command; it never queues another reset.
                reset.reply = Some(reply);
            } else {
                let _ = reply.send(EvpnRecoveryResetOutcome::Rejected);
            }
            return;
        }
        *slot = Some(SessionRecoveryReset {
            request,
            queued: false,
            reply: Some(reply),
            execution: None,
        });
        self.try_evpn_recovery_reset(session_id);
        self.rearm_evpn_recovery_retry();
    }

    fn try_evpn_recovery_reset(&mut self, session_id: u64) {
        let Some(key) = self.peer_key_for_session(session_id) else {
            return;
        };
        let Some((handle, slot)) = self.peers.recovery_session_mut(&key, session_id) else {
            return;
        };
        let Some(reset) = slot.as_mut() else {
            return;
        };
        // Poll execution before checking the token: a successful reset
        // itself closes that outbound connection.
        if let Some(execution) = reset.execution.as_mut() {
            match execution.try_recv() {
                Ok(outcome) => {
                    reset.execution = None;
                    if let Some(reply) = reset.reply.take() {
                        let _ = reply.send(outcome);
                    }
                    if outcome == EvpnRecoveryResetOutcome::Rejected {
                        *slot = None;
                        return;
                    }
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
                Err(oneshot::error::TryRecvError::Closed) => {
                    // Dropping the RIB reply retains the distinction from
                    // a positive execution receipt; the RIB owns its retry.
                    *slot = None;
                    return;
                }
            }
        }
        if reset.request.outbound.is_closed() {
            *slot = None;
            return;
        }
        if reset.queued {
            return;
        }
        let (reply, execution) = oneshot::channel();
        match handle
            .commands_sender()
            .try_send(PeerCommand::ResetEvpnRecoverySession {
                request: reset.request.clone(),
                reply,
            }) {
            Ok(()) => {
                reset.queued = true;
                reset.execution = Some(execution);
            }
            Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => {
                if let Some(reply) = reset.reply.take() {
                    let _ = reply.send(EvpnRecoveryResetOutcome::Rejected);
                }
                *slot = None;
            }
        }
    }

    fn rearm_evpn_recovery_retry(&mut self) {
        if self.peers.recovery_reset_sessions().next().is_some() {
            self.evpn_recovery_retry_at
                .get_or_insert_with(|| tokio::time::Instant::now() + Duration::from_millis(100));
        } else {
            self.evpn_recovery_retry_at = None;
        }
    }

    pub(super) fn retry_evpn_recovery_resets(&mut self) {
        self.evpn_recovery_retry_at = None;
        // Keep only the next 32 circularly ordered actor identities. Inline
        // owner slots bound retained state; a fixed batch also bounds sends
        // and lets full early queues yield to later healthy owners.
        let mut attempts = Vec::with_capacity(32);
        // Also reap an admitted token after its connection closes. Until
        // then its queued marker must suppress duplicate commands.
        for (session_id, _) in self.peers.recovery_reset_sessions() {
            let rank = (session_id <= self.evpn_recovery_retry_cursor, session_id);
            let position = attempts
                .binary_search(&rank)
                .unwrap_or_else(|position| position);
            if position < 32 {
                if attempts.len() == 32 {
                    attempts.pop();
                }
                attempts.insert(position, rank);
            }
        }
        for (_, session_id) in attempts {
            self.evpn_recovery_retry_cursor = session_id;
            self.try_evpn_recovery_reset(session_id);
        }
        self.rearm_evpn_recovery_retry();
    }
}
