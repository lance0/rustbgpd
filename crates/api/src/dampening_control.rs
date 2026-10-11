//! Owned peer recovery controls shared by the API and daemon capacity adapter.

use std::time::Duration;

use rustbgpd_rib::dampening::DampeningCapacityNotice;
use tokio::sync::{mpsc, oneshot};
use tonic::Status;

use crate::health_probe::DaemonGate;
use crate::neighbor_service::peer_lifecycle_error_status;
use crate::peer_types::{OwnedDampeningControlOutcome, PeerKey, PeerManagerCommand};
use crate::runtime_config_settlement::{
    OwnedRuntimeConfigOperation, OwnedRuntimeConfigOutcome, OwnedRuntimeConfigRequestContext,
    RuntimeConfigFenceReason, RuntimeConfigOperationKind, RuntimeConfigSettlementPhase,
    RuntimeConfigSettlementWatchdog,
};
use crate::server::{ConfigMutationGateFn, RuntimeConfigCoordinator, check_config_mutation_gate};

/// Exactly the two manager-owned capacity recovery directions.
pub enum DampeningControl {
    /// Explicit operator enable, including the RIB's capacity check.
    Enable(PeerKey),
    /// Source-local session disable after the RIB has blocked reachable input.
    DisableCapacity(DampeningCapacityNotice),
}

/// Send one owned control, preserving queue admission versus accepted reply loss.
/// The enclosing executor retains its coordinator until this outcome settles.
pub async fn dispatch_owned_dampening_control(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    timeout: Duration,
    pre_effect_deadline: Option<tokio::time::Instant>,
    control: DampeningControl,
) -> OwnedRuntimeConfigOutcome<(), Status> {
    let (reply, reply_rx) = oneshot::channel();
    let command = match control {
        DampeningControl::Enable(peer) => PeerManagerCommand::EnablePeerOwned { peer, reply },
        DampeningControl::DisableCapacity(notice) => {
            PeerManagerCommand::DisableDampeningCapacity { notice, reply }
        }
    };
    let deadline = tokio::time::Instant::now() + timeout;
    let deadline = pre_effect_deadline.map_or(deadline, |cap| cap.min(deadline));
    match tokio::time::timeout_at(deadline, peer_mgr_tx.send(command)).await {
        Err(_) => {
            return OwnedRuntimeConfigOutcome::CleanNoEffect(Err(Status::unavailable(
                "peer manager recovery queue timed out before accepting command",
            )));
        }
        Ok(Err(_)) => {
            return OwnedRuntimeConfigOutcome::CleanNoEffect(Err(Status::unavailable(
                "peer manager unavailable before accepting recovery",
            )));
        }
        Ok(Ok(())) => {}
    }
    match tokio::time::timeout(timeout, reply_rx).await {
        Err(_) => OwnedRuntimeConfigOutcome::Fenced {
            error: Status::deadline_exceeded("peer manager accepted recovery but reply timed out"),
            reason: RuntimeConfigFenceReason::AcknowledgementLost,
        },
        Ok(Err(_)) => OwnedRuntimeConfigOutcome::Fenced {
            error: Status::internal("peer manager accepted recovery but dropped its reply"),
            reason: RuntimeConfigFenceReason::AcknowledgementLost,
        },
        Ok(Ok(OwnedDampeningControlOutcome::RejectedNoEffect(error))) => {
            OwnedRuntimeConfigOutcome::CleanNoEffect(Err(peer_lifecycle_error_status(error)))
        }
        Ok(Ok(OwnedDampeningControlOutcome::Applied)) => {
            OwnedRuntimeConfigOutcome::AcknowledgedAuthority(())
        }
        Ok(Ok(OwnedDampeningControlOutcome::Ambiguous(error))) => {
            OwnedRuntimeConfigOutcome::Fenced {
                error: peer_lifecycle_error_status(error),
                reason: RuntimeConfigFenceReason::KnownDivergence,
            }
        }
    }
}

/// Run explicit neighbor enable under the existing mutation coordinator.
///
/// # Errors
/// Returns determinate admission/actor errors; ambiguous work keeps ownership.
pub async fn enable_peer_owned(
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    peer: PeerKey,
    coordinator: RuntimeConfigCoordinator,
    mutation_gate: Option<ConfigMutationGateFn>,
    settlement: Option<(RuntimeConfigSettlementWatchdog, DaemonGate)>,
    timeout: Duration,
) -> Result<(), Status> {
    let body = move |operation: Option<OwnedRuntimeConfigOperation>| async move {
        if let Err(error) =
            check_config_mutation_gate(&mutation_gate, "NeighborService.EnableNeighbor").await
        {
            return OwnedRuntimeConfigOutcome::CleanNoEffect(Err(error));
        }
        if let Some(operation) = &operation {
            operation.advance_phase(RuntimeConfigSettlementPhase::Mutating);
        }
        dispatch_owned_dampening_control(
            &peer_mgr_tx,
            timeout,
            operation
                .as_ref()
                .map(OwnedRuntimeConfigOperation::pre_effect_deadline),
            DampeningControl::Enable(peer),
        )
        .await
    };
    let (context, attachment) = OwnedRuntimeConfigRequestContext::unary();
    let result = if let Some((watchdog, daemon_gate)) = settlement {
        watchdog
            .execute_owned(
                RuntimeConfigOperationKind::NeighborEnable,
                coordinator,
                daemon_gate,
                context.response_attached(),
                move |operation| body(Some(operation)),
            )
            .await
    } else {
        let join = tokio::spawn(async move {
            let _permit = coordinator.acquire().await?;
            match body(None).await {
                OwnedRuntimeConfigOutcome::CleanNoEffect(result) => result,
                OwnedRuntimeConfigOutcome::PublishedDurable(())
                | OwnedRuntimeConfigOutcome::AcknowledgedAuthority(()) => Ok(()),
                OwnedRuntimeConfigOutcome::Fenced { .. } => std::future::pending().await,
            }
        });
        join.await
            .map_err(|_| Status::internal("owned neighbor enable task did not complete"))?
    };
    drop(attachment);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerKey {
        PeerKey::new("192.0.2.1".parse().unwrap(), None)
    }

    #[tokio::test(start_paused = true)]
    async fn accepted_enable_reply_loss_retains_coordinator() {
        let (tx, mut rx) = mpsc::channel(1);
        let coordinator = RuntimeConfigCoordinator::new();
        let mut call = tokio::spawn(enable_peer_owned(
            tx,
            peer(),
            coordinator.clone(),
            None,
            None,
            Duration::from_secs(10),
        ));
        let Some(PeerManagerCommand::EnablePeerOwned { reply, .. }) = rx.recv().await else {
            panic!("expected owned enable");
        };
        drop(reply);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), &mut call)
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(1), coordinator.acquire())
                .await
                .is_err()
        );
        assert!(
            rx.try_recv().is_err(),
            "accepted enable must not trigger compensation"
        );
        call.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn canceled_enable_caller_keeps_accepted_work_until_acknowledged() {
        let (tx, mut rx) = mpsc::channel(1);
        let coordinator = RuntimeConfigCoordinator::new();
        let call = tokio::spawn(enable_peer_owned(
            tx,
            peer(),
            coordinator.clone(),
            None,
            None,
            Duration::from_secs(10),
        ));
        let Some(PeerManagerCommand::EnablePeerOwned { reply, .. }) = rx.recv().await else {
            panic!("expected owned enable");
        };
        call.abort();
        assert!(call.await.unwrap_err().is_cancelled());
        assert!(
            tokio::time::timeout(Duration::from_secs(1), coordinator.acquire())
                .await
                .is_err()
        );
        reply.send(OwnedDampeningControlOutcome::Applied).unwrap();
        let _released = tokio::time::timeout(Duration::from_secs(1), coordinator.acquire())
            .await
            .unwrap()
            .unwrap();
        assert!(rx.try_recv().is_err(), "one explicit enable is sufficient");
    }

    #[tokio::test(start_paused = true)]
    async fn accepted_enable_reply_budget_survives_admission_deadline() {
        let (tx, mut rx) = mpsc::channel(1);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let call = tokio::spawn(async move {
            dispatch_owned_dampening_control(
                &tx,
                Duration::from_secs(10),
                Some(deadline),
                DampeningControl::Enable(peer()),
            )
            .await
        });
        let Some(PeerManagerCommand::EnablePeerOwned { reply, .. }) = rx.recv().await else {
            panic!("expected owned enable");
        };
        tokio::time::advance(Duration::from_secs(2)).await;
        reply.send(OwnedDampeningControlOutcome::Applied).unwrap();
        assert!(matches!(
            call.await.unwrap(),
            OwnedRuntimeConfigOutcome::AcknowledgedAuthority(())
        ));
    }
}
