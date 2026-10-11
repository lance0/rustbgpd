//! Internal configured-owner publication under the existing mutation owner.

use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tonic::Status;

use crate::peer_types::{
    ConfiguredOwnerPublicationError, ConfiguredOwnerPublicationOperation,
    ConfiguredOwnerPublicationReceipt, PeerManagerCommand,
};
use crate::runtime_config_settlement::RuntimeConfigFenceReason;

/// The existing owned peer-manager mutation reply budget.
pub const OWNER_PUBLICATION_TIMEOUT: Duration = Duration::from_mins(10);

/// Admission and acknowledgement are separate ownership boundaries.
#[derive(Debug)]
pub enum ConfiguredOwnerPublicationDispatch {
    /// The manager did not accept the command.
    NotAccepted(Status),
    /// The manager returned a determinate protocol result.
    Replied(Result<ConfiguredOwnerPublicationReceipt, ConfiguredOwnerPublicationError>),
    /// The manager accepted the command but its outcome is unknown.
    AcceptedReplyLost(Status),
}

impl ConfiguredOwnerPublicationDispatch {
    /// Classify Begin before any candidate runtime mutation.
    ///
    /// # Errors
    /// A missing fence reason proves that no publication stage remains admitted.
    pub fn begin_result(
        self,
    ) -> Result<ConfiguredOwnerPublicationReceipt, (Status, Option<RuntimeConfigFenceReason>)> {
        match self {
            Self::Replied(Ok(receipt)) => Ok(receipt),
            Self::NotAccepted(error) => Err((error, None)),
            Self::AcceptedReplyLost(error) => {
                Err((error, Some(RuntimeConfigFenceReason::AcknowledgementLost)))
            }
            Self::Replied(Err(error)) => {
                let reason = match error {
                    ConfiguredOwnerPublicationError::RibAcknowledgementLost => {
                        Some(RuntimeConfigFenceReason::AcknowledgementLost)
                    }
                    ConfiguredOwnerPublicationError::StaleAuthority => {
                        Some(RuntimeConfigFenceReason::KnownDivergence)
                    }
                    _ => None,
                };
                Err((publication_error_status(&error), reason))
            }
        }
    }

    /// Classify final Publish or Discard after Begin was acknowledged.
    ///
    /// # Errors
    /// Every failure retains the owner: publication or stage removal is unproved.
    pub fn settlement_result(
        self,
    ) -> Result<ConfiguredOwnerPublicationReceipt, (Status, RuntimeConfigFenceReason)> {
        self.begin_result().map_err(|(error, reason)| {
            (
                error,
                reason.unwrap_or(RuntimeConfigFenceReason::KnownDivergence),
            )
        })
    }
}

fn publication_error_status(error: &ConfiguredOwnerPublicationError) -> Status {
    Status::internal(format!("configured-owner publication failed: {error:?}"))
}

/// Dispatch one publication command while retaining the enclosing owner.
/// Only admission is capped by its pre-effect deadline; accepted work receives
/// the complete reply budget even when that admission deadline has elapsed.
pub async fn dispatch_configured_owner_publication(
    peer_mgr_tx: &mpsc::Sender<PeerManagerCommand>,
    timeout: Duration,
    pre_effect_deadline: Option<tokio::time::Instant>,
    operation: ConfiguredOwnerPublicationOperation,
) -> ConfiguredOwnerPublicationDispatch {
    let (reply, reply_rx) = oneshot::channel();
    let command = PeerManagerCommand::ConfiguredOwnerPublication { operation, reply };
    let send_deadline = tokio::time::Instant::now() + timeout;
    let send_deadline = pre_effect_deadline.map_or(send_deadline, |cap| cap.min(send_deadline));
    match tokio::time::timeout_at(send_deadline, peer_mgr_tx.send(command)).await {
        Err(_) => ConfiguredOwnerPublicationDispatch::NotAccepted(Status::unavailable(
            "peer manager publication queue timed out before accepting command",
        )),
        Ok(Err(_)) => ConfiguredOwnerPublicationDispatch::NotAccepted(Status::unavailable(
            "peer manager unavailable before accepting publication",
        )),
        Ok(Ok(())) => match tokio::time::timeout(timeout, reply_rx).await {
            Err(_) => {
                ConfiguredOwnerPublicationDispatch::AcceptedReplyLost(Status::deadline_exceeded(
                    "peer manager accepted configured-owner publication but reply timed out",
                ))
            }
            Ok(Err(_)) => ConfiguredOwnerPublicationDispatch::AcceptedReplyLost(Status::internal(
                "peer manager accepted configured-owner publication but dropped its reply",
            )),
            Ok(Ok(result)) => ConfiguredOwnerPublicationDispatch::Replied(result),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn accepted_begin_reply_keeps_its_budget_past_admission_deadline() {
        let (tx, mut rx) = mpsc::channel(1);
        let start = tokio::time::Instant::now();
        let dispatch = tokio::spawn(async move {
            dispatch_configured_owner_publication(
                &tx,
                Duration::from_secs(10),
                Some(start + Duration::from_secs(1)),
                ConfiguredOwnerPublicationOperation::Begin,
            )
            .await
        });
        let PeerManagerCommand::ConfiguredOwnerPublication { reply, .. } = rx.recv().await.unwrap()
        else {
            panic!("expected Begin");
        };
        tokio::time::advance(Duration::from_secs(2)).await;
        reply
            .send(Ok(ConfiguredOwnerPublicationReceipt(7)))
            .unwrap();
        assert_eq!(
            dispatch.await.unwrap().begin_result().unwrap(),
            ConfiguredOwnerPublicationReceipt(7)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn begin_queue_timeout_is_clean_but_settlement_queue_timeout_fences() {
        for operation in [
            ConfiguredOwnerPublicationOperation::Begin,
            ConfiguredOwnerPublicationOperation::Discard(ConfiguredOwnerPublicationReceipt(7)),
        ] {
            let (tx, mut rx) = mpsc::channel(1);
            let (reply, _reply_rx) = oneshot::channel();
            tx.send(PeerManagerCommand::ConfiguredOwnerPublication {
                operation: ConfiguredOwnerPublicationOperation::Begin,
                reply,
            })
            .await
            .unwrap();
            let dispatch = dispatch_configured_owner_publication(
                &tx,
                Duration::from_secs(10),
                Some(tokio::time::Instant::now() + Duration::from_secs(1)),
                operation,
            )
            .await;
            match operation {
                ConfiguredOwnerPublicationOperation::Begin => {
                    assert!(matches!(dispatch.begin_result(), Err((_, None))));
                }
                _ => assert!(matches!(
                    dispatch.settlement_result(),
                    Err((_, RuntimeConfigFenceReason::KnownDivergence))
                )),
            }
            assert!(rx.recv().await.is_some());
            assert!(
                rx.try_recv().is_err(),
                "timed out publication must not be queued"
            );
        }
    }

    #[tokio::test]
    async fn accepted_reply_loss_fences_begin_publish_and_discard() {
        for operation in [
            ConfiguredOwnerPublicationOperation::Begin,
            ConfiguredOwnerPublicationOperation::Publish(ConfiguredOwnerPublicationReceipt(7)),
            ConfiguredOwnerPublicationOperation::Discard(ConfiguredOwnerPublicationReceipt(7)),
        ] {
            let (tx, mut rx) = mpsc::channel(1);
            let dispatch = tokio::spawn(async move {
                dispatch_configured_owner_publication(&tx, Duration::from_secs(10), None, operation)
                    .await
            });
            let PeerManagerCommand::ConfiguredOwnerPublication { reply, .. } =
                rx.recv().await.unwrap()
            else {
                panic!("expected publication command");
            };
            drop(reply);
            assert!(matches!(
                dispatch.await.unwrap().begin_result(),
                Err((_, Some(RuntimeConfigFenceReason::AcknowledgementLost)))
            ));
        }
    }

    #[test]
    fn rib_reply_loss_and_stale_authority_keep_ownership() {
        for (error, reason) in [
            (
                ConfiguredOwnerPublicationError::RibAcknowledgementLost,
                RuntimeConfigFenceReason::AcknowledgementLost,
            ),
            (
                ConfiguredOwnerPublicationError::StaleAuthority,
                RuntimeConfigFenceReason::KnownDivergence,
            ),
        ] {
            let Err((_, Some(actual))) =
                ConfiguredOwnerPublicationDispatch::Replied(Err(error)).begin_result()
            else {
                panic!("authority must fence");
            };
            assert_eq!(actual, reason);
        }
    }
}
