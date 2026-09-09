//! Explicit one-peer replay completion, with no retained route inventory.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rustbgpd_bmp::{BmpEvent, BmpPeerInfo, BmpReplay};
use rustbgpd_fsm::SessionState;
use rustbgpd_rib::{OutboundRouteUpdate, RibUpdate};
use rustbgpd_wire::{Afi, Message, Safi};
use tokio::sync::{oneshot, watch};

use super::PeerSession;
use crate::PeerCommandError;

/// Same bounded operation window as the daemon's RIB scheduling request.
const REPLAY_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct PendingReplay {
    pub(super) replay: Arc<BmpReplay>,
    pub(super) target: Option<u64>,
    pub(super) deadline: tokio::time::Instant,
    pub(super) peer_info: BmpPeerInfo,
    pub(super) end_of_rib: Vec<Bytes>,
    pub(super) handed_off: bool,
    pub(super) scheduling: Option<oneshot::Receiver<Result<(), rustbgpd_rib::RibCommandError>>>,
    pub(super) reply: Option<oneshot::Sender<Result<(), PeerCommandError>>>,
}

impl Drop for PendingReplay {
    fn drop(&mut self) {
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(Err(PeerCommandError::ReplayUnavailable(
                "replay scheduling canceled".into(),
            )));
        }
        if !self.handed_off {
            self.replay.cancel();
        }
    }
}

/// Only bulk bytes count toward this FIFO fence. Priority traffic cannot
/// certify a replay, and a failed/partial batch never advances the watermark.
pub(super) enum ReplayProgress {
    Scheduled(Result<(), PeerCommandError>),
    Completed(bool),
}

pub(super) async fn poll_completion(
    pending: &mut Option<PendingReplay>,
    completed: &mut Option<watch::Receiver<u64>>,
) -> ReplayProgress {
    let Some(pending) = pending else {
        return std::future::pending().await;
    };
    if let Some(admitted) = pending.scheduling.as_mut() {
        let reply = pending
            .reply
            .as_mut()
            .expect("scheduling owns caller reply");
        let result = tokio::time::timeout_at(pending.deadline, async {
            tokio::select! {
                result = admitted => result.map_err(|_| PeerCommandError::ReplyDropped)?
                    .map_err(|error| PeerCommandError::ReplayUnavailable(error.to_string())),
                () = reply.closed() => Err(PeerCommandError::ReplayUnavailable("replay caller canceled before acknowledgement".into())),
            }
        }).await.unwrap_or(Err(PeerCommandError::TimedOut { operation: "replay_outbound", deadline: REPLAY_TIMEOUT }));
        return ReplayProgress::Scheduled(result);
    }
    let Some(completed) = completed else {
        return ReplayProgress::Completed(false);
    };
    let wait = async {
        loop {
            if !pending.replay.is_valid() {
                return false;
            }
            if pending
                .target
                .is_some_and(|target| *completed.borrow_and_update() >= target)
            {
                return true;
            }
            if completed.changed().await.is_err() {
                return false;
            }
        }
    };
    ReplayProgress::Completed(
        tokio::time::timeout_at(pending.deadline, wait)
            .await
            .unwrap_or(false),
    )
}

impl PeerSession {
    pub(super) fn cancel_outbound_replay(&mut self) {
        self.pending_replay = None;
    }

    #[expect(
        clippy::too_many_lines,
        reason = "enrollment and bounded RIB admission retain one operation and caller reply under the same deadline"
    )]
    pub(super) async fn start_outbound_replay(
        &mut self,
        response: oneshot::Sender<Result<(), PeerCommandError>>,
    ) {
        if response.is_closed() {
            return;
        }
        if self.fsm.state() != SessionState::Established {
            let _ = response.send(Err(PeerCommandError::NotEstablished));
            return;
        }
        if self.pending_replay.is_some() {
            let _ = response.send(Err(PeerCommandError::ReplayUnavailable(
                "an outbound replay is already pending".into(),
            )));
            return;
        }
        let families = self.negotiated_families().to_vec();
        if families.is_empty()
            || families
                .iter()
                .any(|family| !matches!(family, (Afi::Ipv4 | Afi::Ipv6, Safi::Unicast)))
        {
            let _ = response.send(Err(PeerCommandError::ReplayUnavailable(
                "outbound replay requires a nonempty IPv4/IPv6-unicast-only negotiated session"
                    .into(),
            )));
            return;
        }
        let Some(bmp_tx) = self.bmp_tx.clone().filter(|_| self.config.bmp_rib_out) else {
            let _ = response.send(Err(PeerCommandError::ReplayUnavailable(
                "outbound replay requires BMP rib_out_post and negotiated unicast".into(),
            )));
            return;
        };
        let (replay, enrolled) = BmpReplay::new(REPLAY_TIMEOUT);
        let deadline = tokio::time::Instant::now() + REPLAY_TIMEOUT;
        let mut peer_info = self.build_bmp_peer_info();
        peer_info.is_rib_out = true;
        peer_info.is_post_policy = true;
        self.pending_replay = Some(PendingReplay {
            replay: Arc::clone(&replay),
            target: None,
            deadline,
            peer_info: peer_info.clone(),
            end_of_rib: Vec::new(),
            handed_off: false,
            scheduling: None,
            reply: None,
        });
        let result = tokio::time::timeout_at(deadline, async {
            bmp_tx
                .send(BmpEvent::OutboundReplayBegin {
                    peer_info,
                    replay: Arc::clone(&replay),
                })
                .await
                .map_err(|_| {
                    PeerCommandError::ReplayUnavailable("BMP manager is unavailable".into())
                })?;
            if !enrolled.await.unwrap_or(false) {
                return Err(PeerCommandError::ReplayUnavailable(
                    "no eligible connected BMP collector or replay enrollment refused".into(),
                ));
            }
            self.replay_eor_suppressed = true;
            if response.is_closed() || !replay.is_valid() {
                return Err(PeerCommandError::ReplayUnavailable(
                    "replay scheduling canceled".into(),
                ));
            }
            let (rib_reply, admitted) = oneshot::channel();
            self.rib_tx
                .send(RibUpdate::ReplayPeerOutbound {
                    peer: self.peer_ip,
                    session_id: self.session_identity.id,
                    families,
                    replay: Arc::clone(&replay),
                    reply: rib_reply,
                })
                .await
                .map_err(|_| {
                    PeerCommandError::ReplayUnavailable("RIB manager is unavailable".into())
                })?;
            Ok(admitted)
        })
        .await
        .unwrap_or(Err(PeerCommandError::TimedOut {
            operation: "replay_outbound",
            deadline: REPLAY_TIMEOUT,
        }));
        match result {
            Ok(admitted) => {
                if let Some(pending) = &mut self.pending_replay {
                    pending.scheduling = Some(admitted);
                    pending.reply = Some(response);
                }
            }
            Err(error) => {
                let _ = response.send(Err(error));
                self.cancel_outbound_replay();
            }
        }
    }

    pub(super) fn enqueue_replay_terminal(&mut self, update: &OutboundRouteUpdate) {
        let Some(token) = update.replay.as_ref() else {
            return;
        };
        if !token.is_valid()
            || !self
                .pending_replay
                .as_ref()
                .is_some_and(|pending| Arc::ptr_eq(&pending.replay, token))
        {
            return;
        }
        let export = self.export_encoder.snapshot();
        let mut terminal = Vec::with_capacity(update.end_of_rib.len());
        for &(afi, safi) in &update.end_of_rib {
            let pdu = if let Ok(pdu) = export.build_end_of_rib(afi, safi).and_then(|update| {
                rustbgpd_wire::encode_message_with_limit(
                    &Message::Update(update),
                    self.outbound_max_message_len(),
                )
            }) {
                Bytes::from(pdu)
            } else {
                self.cancel_outbound_replay();
                return;
            };
            terminal.push(pdu);
        }
        for pdu in &terminal {
            // The terminal BMP tap is deliberately withheld until all preceding
            // bulk bytes and these exact EoRs have completed local writing.
            if self.enqueue_bulk_encoded(pdu.clone(), false).is_err() {
                self.cancel_outbound_replay();
                return;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
        }
        if let Some(pending) = &mut self.pending_replay {
            pending.target = Some(self.writer_bulk_admitted);
            pending.end_of_rib = terminal;
        }
    }

    pub(super) fn finish_outbound_replay(&mut self, progress: ReplayProgress) {
        let completed = match progress {
            ReplayProgress::Scheduled(mut result) => {
                if let Some(pending) = &mut self.pending_replay {
                    if !pending.replay.is_valid() {
                        result = Err(PeerCommandError::ReplayUnavailable(
                            "replay expired or was canceled before acknowledgement".into(),
                        ));
                    }
                    pending.scheduling = None;
                    let failed = result.is_err();
                    let delivered = pending
                        .reply
                        .take()
                        .is_some_and(|reply| reply.send(result).is_ok());
                    if failed || !delivered {
                        self.cancel_outbound_replay();
                    }
                }
                return;
            }
            ReplayProgress::Completed(completed) => completed,
        };
        let Some(mut pending) = self.pending_replay.take() else {
            return;
        };
        if !completed || !pending.replay.is_valid() || pending.end_of_rib.is_empty() {
            return;
        }
        let Some(tx) = self.bmp_tx.as_ref() else {
            return;
        };
        pending.peer_info.timestamp = std::time::SystemTime::now();
        let event = BmpEvent::OutboundReplayComplete {
            peer_info: pending.peer_info.clone(),
            replay: Arc::clone(&pending.replay),
            end_of_rib: std::mem::take(&mut pending.end_of_rib),
        };
        if tx.try_send(event).is_ok() {
            pending.handed_off = true;
            // Queue admission is not manager acceptance: the token may expire
            // while this event waits. Keep ordinary EoRs suppressed for this
            // writer generation so they cannot certify a rejected completion.
        }
        // On a full/closed source queue there is no successful completion.
        // Dropping the pending operation invalidates even a repaired stream.
    }
}
