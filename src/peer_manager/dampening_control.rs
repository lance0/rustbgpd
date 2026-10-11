//! Manager-owned source-capacity disable and explicit recovery.

use std::sync::Arc;

use rustbgpd_api::peer_types::{
    OwnedDampeningControlOutcome as Outcome, PeerKey, PeerLifecycleError,
};
use rustbgpd_rib::RibUpdate;
use rustbgpd_rib::dampening::{DampeningCapacityNotice, DampeningControlError};
use rustbgpd_rib::update::{PeerSourceContext, ReceivedRouteSource};
use tokio::sync::{mpsc, oneshot};

use super::{PeerManager, RIB_REPLY_TIMEOUT};

async fn rib_control<T>(
    rib_tx: &mpsc::Sender<RibUpdate>,
    command: RibUpdate,
    response: oneshot::Receiver<Result<T, DampeningControlError>>,
) -> Result<Result<T, DampeningControlError>, PeerLifecycleError> {
    let deadline = tokio::time::Instant::now() + RIB_REPLY_TIMEOUT;
    tokio::time::timeout_at(deadline, rib_tx.send(command))
        .await
        .map_err(|_| PeerLifecycleError::internal("dampening RIB control queue timed out"))?
        .map_err(|_| PeerLifecycleError::internal("dampening RIB control queue closed"))?;
    tokio::time::timeout_at(deadline, response)
        .await
        .map_err(|_| {
            PeerLifecycleError::internal("accepted dampening RIB control acknowledgement timed out")
        })?
        .map_err(|_| {
            PeerLifecycleError::internal("accepted dampening RIB control acknowledgement lost")
        })
}

impl PeerManager {
    /// Producers must already be joined. This primary-lane acknowledgement
    /// follows their exact teardown and every previously queued route chunk.
    pub(super) async fn dampening_retirement_barrier(
        &self,
        peer: std::net::IpAddr,
        retired_sessions: &[u64],
    ) -> Result<(), PeerLifecycleError> {
        let deadline = tokio::time::Instant::now() + RIB_REPLY_TIMEOUT;
        let barrier = async {
            for &session_id in retired_sessions {
                self.rib_tx
                    .send(RibUpdate::PeerDown { peer, session_id })
                    .await
                    .map_err(|_| {
                        PeerLifecycleError::internal("RIB source-retirement queue closed")
                    })?;
            }
            let (reply, response) = oneshot::channel();
            self.rib_tx
                .send(RibUpdate::QueryLocRibCount { reply })
                .await
                .map_err(|_| {
                    PeerLifecycleError::internal("RIB source-retirement barrier queue closed")
                })?;
            response.await.map_err(|_| {
                PeerLifecycleError::internal("RIB source-retirement acknowledgement lost")
            })?;
            Ok(())
        };
        tokio::time::timeout_at(deadline, barrier)
            .await
            .map_err(|_| PeerLifecycleError::internal("RIB source-retirement barrier timed out"))?
    }

    pub(super) async fn disable_dampening_capacity(
        &mut self,
        notice: DampeningCapacityNotice,
    ) -> Outcome {
        let Some(context) = &notice.source.context else {
            return Outcome::Applied;
        };
        let Some(original) = &context.dampening_admission else {
            return Outcome::Applied;
        };
        let peer = PeerKey::new(notice.source.peer, context.peer_interface.clone());
        let Some(managed) = self.peers.get(&peer) else {
            return Outcome::Applied;
        };
        let Some(admission) = managed.transport_config.dampening_admission.clone() else {
            return Outcome::Applied;
        };
        // A queued notice cannot disable a newly committed owner at this address,
        // or a source whose explicit recovery has already completed.
        if admission.owner.id() != original.owner.id()
            || admission.capacity_failure().map(|(asn, _)| asn) != notice.source.peer_asn
            || admission.capacity_disable_complete()
        {
            return Outcome::Applied;
        }
        self.invalidate_max_prefix_restart(&peer);
        let pending = {
            let managed = self
                .peers
                .get_mut(&peer)
                .expect("source ownership checked above");
            managed.enabled = false;
            managed.pending_inbound.take()
        };
        self.publish_peer_admin_enabled_metric(&peer, false);
        self.set_bfd_peer_disabled(peer.address, true);
        if let Some(pending) = pending {
            let session_id = pending.session_id;
            pending.handle.abort_for_transport_safety_and_wait().await;
            self.unregister_session(session_id);
            if self
                .rib_tx
                .send(RibUpdate::PeerDown {
                    peer: peer.address,
                    session_id,
                })
                .await
                .is_err()
            {
                return Outcome::Ambiguous(PeerLifecycleError::internal(
                    "RIB unavailable while fencing capacity-blocked collision actor",
                ));
            }
        }
        // This joins the old primary before sending its exact PeerDown and
        // installs a fresh Idle actor with the same pre-owned recovery latch.
        self.replace_unstoppable_primary(&peer).await;
        let (reply, response) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + RIB_REPLY_TIMEOUT;
        let barrier = async {
            self.rib_tx
                .send(RibUpdate::QueryLocRibCount { reply })
                .await
                .map_err(|_| {
                    PeerLifecycleError::internal("RIB capacity-disable barrier queue closed")
                })?;
            response.await.map_err(|_| {
                PeerLifecycleError::internal("RIB capacity-disable barrier acknowledgement lost")
            })?;
            Ok::<_, PeerLifecycleError>(())
        };
        match tokio::time::timeout_at(deadline, barrier).await {
            Ok(Ok(())) => {
                // The primary-lane barrier follows every joined producer's
                // PeerDown, so all old pending chunks/distribution are gone.
                admission.acknowledge_capacity_disable();
                self.publish_peer_lifecycle_event(
                    &peer,
                    rustbgpd_api::peer_types::SessionLifecycleEventType::PeerDisabled,
                    notice.reason.to_string(),
                );
                Outcome::Applied
            }
            Ok(Err(error)) => Outcome::Ambiguous(error),
            Err(_) => Outcome::Ambiguous(PeerLifecycleError::internal(
                "RIB capacity-disable barrier timed out",
            )),
        }
    }

    pub(super) async fn enable_peer_owned(&mut self, peer: PeerKey) -> Outcome {
        let Some(managed) = self.peers.get(&peer) else {
            return Outcome::RejectedNoEffect(PeerLifecycleError::NotFound(peer));
        };
        let admission = managed.transport_config.dampening_admission.clone();
        let failure = admission
            .as_ref()
            .and_then(rustbgpd_rib::dampening::DampeningAdmission::capacity_failure);
        let Some((asn, reason)) = failure else {
            return match self.enable_peer(peer).await {
                Ok(()) => Outcome::Applied,
                Err(error) => Outcome::RejectedNoEffect(error),
            };
        };
        let admission = admission.expect("capacity failure has its admission latch");
        // An operator request may overtake the queued disable while it waits
        // for this coordinator. It must not reopen the still-live old source.
        if managed.enabled || !admission.capacity_disable_complete() {
            return Outcome::RejectedNoEffect(PeerLifecycleError::Invalid(
                "dampening capacity disable is still settling; retry explicit enable after disable completes".into(),
            ));
        }
        let source = ReceivedRouteSource {
            peer: peer.address,
            session_id: managed.session_id(),
            peer_asn: Some(asn),
            context: Some(Arc::new(PeerSourceContext {
                dampening_admission: Some(admission.clone()),
                peer_interface: managed.transport_config.peer_interface.clone(),
                accepted_dynamic_range: managed.transport_config.accepted_dynamic_range.clone(),
                route_server_client: managed.transport_config.route_server_client,
            })),
        };
        let (reply, response) = oneshot::channel();
        let receipt = match rib_control(
            &self.rib_tx,
            RibUpdate::PrepareDampeningEnable {
                source,
                reason,
                reply,
            },
            response,
        )
        .await
        {
            Ok(Ok(receipt)) => receipt,
            Ok(Err(error)) => {
                return Outcome::RejectedNoEffect(PeerLifecycleError::Invalid(error.to_string()));
            }
            Err(error) => return Outcome::Ambiguous(error),
        };
        // Prepare reopens RIB admission with charged headroom before Start.
        // This owner retains the receipt even though the old block is cleared.
        let enabled = self.enable_peer(peer.clone()).await;
        let (reply, response) = oneshot::channel();
        match rib_control(
            &self.rib_tx,
            RibUpdate::CompleteDampeningEnable {
                receipt,
                enabled: enabled.is_ok(),
                reply,
            },
            response,
        )
        .await
        {
            Ok(Ok(())) => match enabled {
                Ok(()) => Outcome::Applied,
                Err(error) => {
                    // Start was not admitted; the fresh Idle actor remains the
                    // joined recovery target. Complete has restored the block.
                    admission.acknowledge_capacity_disable();
                    Outcome::RejectedNoEffect(error)
                }
            },
            Ok(Err(error)) => Outcome::Ambiguous(PeerLifecycleError::internal(error.to_string())),
            Err(error) => Outcome::Ambiguous(error),
        }
    }
}
