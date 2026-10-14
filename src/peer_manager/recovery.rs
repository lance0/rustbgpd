//! Bounded generation- and connection-fenced EVPN reset admission.

use std::time::Duration;

use rustbgpd_rib::EvpnRecoveryReset;
use rustbgpd_transport::PeerCommand;
use tokio::sync::mpsc;

use super::PeerManager;

pub(super) struct SessionRecoveryReset {
    pub(super) request: EvpnRecoveryReset,
    pub(super) queued: bool,
}

impl PeerManager {
    pub(super) fn reset_evpn_recovery_session(&mut self, request: EvpnRecoveryReset) {
        if request.outbound.is_closed() {
            return;
        }
        let Some(key) = self.peer_key_for_session(request.session_id) else {
            return;
        };
        if key.address != request.peer {
            return;
        }
        let session_id = request.session_id;
        let Some((_, slot)) = self.peers.recovery_session_mut(&key, session_id) else {
            return;
        };
        if slot
            .as_ref()
            .is_some_and(|reset| reset.request.outbound.same_channel(&request.outbound))
        {
            return;
        }
        *slot = Some(SessionRecoveryReset {
            request,
            queued: false,
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
        if reset.request.outbound.is_closed() {
            *slot = None;
            return;
        }
        if reset.queued {
            return;
        }
        match handle
            .commands_sender()
            .try_send(PeerCommand::ResetEvpnRecoverySession {
                request: reset.request.clone(),
            }) {
            Ok(()) => reset.queued = true,
            Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => *slot = None,
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
