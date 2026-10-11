//! Serial capacity-disable adapter under the shared runtime mutation owner.

use rustbgpd_api::dampening_control::{DampeningControl, dispatch_owned_dampening_control};
use rustbgpd_api::health_probe::DaemonGate;
use rustbgpd_api::owner_publication::OWNER_PUBLICATION_TIMEOUT;
use rustbgpd_api::peer_types::PeerManagerCommand;
use rustbgpd_api::runtime_config_settlement::{
    OwnedRuntimeConfigRequestContext, RuntimeConfigOperationKind, RuntimeConfigSettlementPhase,
    RuntimeConfigSettlementWatchdog,
};
use rustbgpd_api::server::RuntimeConfigCoordinator;
use rustbgpd_rib::dampening::DampeningCapacityNotice;
use tokio::sync::{mpsc, watch};

/// Distinguish an intentional stop from loss of the sole RIB-owned sender.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Stopped,
    RibChannelClosed,
}

/// Keep one notice pending while acquiring the coordinator. The RIB coalesces
/// notices with the managed peer's pre-owned latch, including while disabled.
/// Shutdown closes the coordinator before signaling stop; an accepted command
/// must finish owned settlement before this task can return.
pub(crate) async fn run(
    mut notices: mpsc::UnboundedReceiver<DampeningCapacityNotice>,
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    coordinator: RuntimeConfigCoordinator,
    watchdog: RuntimeConfigSettlementWatchdog,
    daemon_gate: DaemonGate,
    mut stop: watch::Receiver<bool>,
) -> Result<Outcome, String> {
    loop {
        if *stop.borrow() || daemon_gate.is_shutting_down() {
            return Ok(Outcome::Stopped);
        }
        let notice = tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return Ok(Outcome::Stopped);
                }
                continue;
            }
            notice = notices.recv() => match notice {
                Some(notice) => notice,
                None => return Ok(Outcome::RibChannelClosed),
            },
        };
        let peer_mgr_tx = peer_mgr_tx.clone();
        let result = watchdog
            .execute_owned(
                RuntimeConfigOperationKind::DampeningCapacityDisable,
                coordinator.clone(),
                daemon_gate.clone(),
                OwnedRuntimeConfigRequestContext::detached().response_attached(),
                move |operation| async move {
                    operation.advance_phase(RuntimeConfigSettlementPhase::Mutating);
                    dispatch_owned_dampening_control(
                        &peer_mgr_tx,
                        OWNER_PUBLICATION_TIMEOUT,
                        Some(operation.pre_effect_deadline()),
                        DampeningControl::DisableCapacity(notice),
                    )
                    .await
                },
            )
            .await;
        if daemon_gate.is_shutting_down() {
            return Ok(Outcome::Stopped);
        }
        result.map_err(|error| format!("owned dampening capacity disable failed: {error}"))?;
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future as _;
    use std::task::Poll;
    use std::time::Duration;

    use rustbgpd_api::peer_types::OwnedDampeningControlOutcome;
    use rustbgpd_rib::dampening::DampeningCapacityReason;
    use rustbgpd_rib::update::ReceivedRouteSource;

    use super::*;

    fn notice() -> DampeningCapacityNotice {
        DampeningCapacityNotice {
            source: ReceivedRouteSource {
                peer: "192.0.2.1".parse().unwrap(),
                session_id: 1,
                peer_asn: Some(65002),
                context: None,
            },
            reason: DampeningCapacityReason::HistoryKeys,
        }
    }

    #[tokio::test]
    async fn shutdown_cancels_queued_coordinator_admission_without_sending_disable() {
        let (notices, rx) = mpsc::unbounded_channel();
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let coordinator = RuntimeConfigCoordinator::new();
        let held = coordinator.acquire().await.unwrap();
        let watchdog = RuntimeConfigSettlementWatchdog::new();
        let gate = DaemonGate::new();
        let (stop, stop_rx) = watch::channel(false);
        notices.send(notice()).unwrap();
        let adapter = run(
            rx,
            peer_tx,
            coordinator.clone(),
            watchdog.clone(),
            gate.clone(),
            stop_rx,
        );
        tokio::pin!(adapter);
        // The ready notice is consumed; the adapter is now waiting for its
        // owned executor, whose coordinator permit is held by this test.
        std::future::poll_fn(|cx| {
            assert!(adapter.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(!watchdog.has_owner());
        assert!(peer_rx.try_recv().is_err());
        gate.begin_shutdown();
        coordinator.close();
        stop.send(true).unwrap();
        assert_eq!(adapter.await.unwrap(), Outcome::Stopped);
        assert!(!watchdog.has_owner());
        assert!(peer_rx.try_recv().is_err());
        drop(held);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_waits_for_accepted_disable_and_never_reenables() {
        let (notices, rx) = mpsc::unbounded_channel();
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let coordinator = RuntimeConfigCoordinator::new();
        let watchdog = RuntimeConfigSettlementWatchdog::new();
        let gate = DaemonGate::new();
        let (stop, stop_rx) = watch::channel(false);
        let mut adapter = tokio::spawn(run(
            rx,
            peer_tx,
            coordinator.clone(),
            watchdog.clone(),
            gate.clone(),
            stop_rx,
        ));
        notices.send(notice()).unwrap();
        let Some(PeerManagerCommand::DisableDampeningCapacity { notice, reply }) =
            peer_rx.recv().await
        else {
            panic!("expected one capacity disable");
        };
        assert_eq!(notice.source.session_id, 1);
        assert!(watchdog.has_owner());
        gate.begin_shutdown();
        coordinator.close();
        stop.send(true).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), &mut adapter)
                .await
                .is_err()
        );
        assert!(watchdog.has_owner(), "stop cannot abandon accepted disable");
        reply.send(OwnedDampeningControlOutcome::Applied).unwrap();
        assert_eq!(adapter.await.unwrap().unwrap(), Outcome::Stopped);
        assert!(!watchdog.has_owner());
        assert!(
            peer_rx.try_recv().is_err(),
            "capacity release never requests enable"
        );
    }

    #[tokio::test]
    async fn sender_owner_panic_is_preserved_when_adapter_observes_closure_first() {
        let (notices, rx) = mpsc::unbounded_channel();
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (_stop, stop_rx) = watch::channel(false);
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let owner = tokio::spawn(async move {
            let _notices = notices;
            released.await.unwrap();
            panic!("capacity notice owner failed");
        });
        let adapter = run(
            rx,
            peer_tx,
            RuntimeConfigCoordinator::new(),
            RuntimeConfigSettlementWatchdog::new(),
            DaemonGate::new(),
            stop_rx,
        );
        tokio::pin!(adapter);
        std::future::poll_fn(|cx| {
            assert!(adapter.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        release.send(()).unwrap();
        // Observe the adapter before joining the sender's owner, as happens
        // when its shutdown-select arm wins. Closure preserves the owner
        // identity so supervision can retrieve the original panic.
        assert_eq!(adapter.await.unwrap(), Outcome::RibChannelClosed);
        let panic = owner.await.unwrap_err().into_panic();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"capacity notice owner failed")
        );
        assert!(peer_rx.try_recv().is_err());
    }
}
