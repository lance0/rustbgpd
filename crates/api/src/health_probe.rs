//! Shared control-plane health/readiness probes.

use std::fmt;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::peer_types::{PeerInfo, PeerManagerCommand};
use rustbgpd_rib::RibUpdate;

/// Total deadline for the core actor readiness probe.
pub const CORE_READINESS_DEADLINE: Duration = Duration::from_millis(200);

/// Snapshot returned by a successful core actor probe.
#[derive(Debug)]
pub struct CoreHealthSnapshot {
    /// Peer snapshots returned by the peer manager.
    pub peers: Vec<PeerInfo>,
    /// Current Loc-RIB best-path count.
    pub total_routes: usize,
}

/// A bounded readiness probe for the two core control-plane actors.
#[derive(Clone)]
pub struct CoreReadinessProbe {
    peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
    rib_tx: mpsc::Sender<RibUpdate>,
}

impl CoreReadinessProbe {
    /// Create a new core readiness probe.
    #[must_use]
    pub fn new(
        peer_mgr_tx: mpsc::Sender<PeerManagerCommand>,
        rib_tx: mpsc::Sender<RibUpdate>,
    ) -> Self {
        Self {
            peer_mgr_tx,
            rib_tx,
        }
    }

    /// Probe `PeerManager` and RIB responsiveness.
    ///
    /// This deliberately checks actor responsiveness only. A daemon with zero
    /// configured peers or zero routes can still be ready.
    ///
    /// # Errors
    ///
    /// Returns [`CoreReadinessError`] when either core actor is unavailable,
    /// drops its reply channel, or does not respond before the readiness
    /// deadline.
    pub async fn check(&self) -> Result<(), CoreReadinessError> {
        self.snapshot().await.map(|_| ())
    }

    /// Return the same core actor snapshot used by `GetHealth`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreReadinessError`] when either core actor is unavailable,
    /// drops its reply channel, or does not respond before the readiness
    /// deadline.
    pub async fn snapshot(&self) -> Result<CoreHealthSnapshot, CoreReadinessError> {
        let deadline = Instant::now() + CORE_READINESS_DEADLINE;
        let peers = self.query_peer_manager(deadline).await?;
        let total_routes = self.query_rib(deadline).await?;
        Ok(CoreHealthSnapshot {
            peers,
            total_routes,
        })
    }

    async fn query_peer_manager(
        &self,
        deadline: Instant,
    ) -> Result<Vec<PeerInfo>, CoreReadinessError> {
        timeout_until(deadline, CoreReadinessError::PeerManagerTimedOut, async {
            let (reply_tx, reply_rx) = oneshot::channel();
            self.peer_mgr_tx
                .send(PeerManagerCommand::ListPeers { reply: reply_tx })
                .await
                .map_err(|_| CoreReadinessError::PeerManagerUnavailable)?;
            reply_rx
                .await
                .map_err(|_| CoreReadinessError::PeerManagerDroppedReply)
        })
        .await
    }

    async fn query_rib(&self, deadline: Instant) -> Result<usize, CoreReadinessError> {
        timeout_until(deadline, CoreReadinessError::RibTimedOut, async {
            let (reply_tx, reply_rx) = oneshot::channel();
            self.rib_tx
                .send(RibUpdate::QueryLocRibCount { reply: reply_tx })
                .await
                .map_err(|_| CoreReadinessError::RibUnavailable)?;
            reply_rx
                .await
                .map_err(|_| CoreReadinessError::RibDroppedReply)
        })
        .await
    }
}

async fn timeout_until<T, Fut>(
    deadline: Instant,
    timeout_error: CoreReadinessError,
    future: Fut,
) -> Result<T, CoreReadinessError>
where
    Fut: std::future::Future<Output = Result<T, CoreReadinessError>>,
{
    let now = Instant::now();
    if deadline <= now {
        return Err(timeout_error);
    }
    tokio::time::timeout(deadline - now, future)
        .await
        .map_err(|_| timeout_error)?
}

/// Core readiness failure reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreReadinessError {
    /// `PeerManager` command channel is closed.
    PeerManagerUnavailable,
    /// `PeerManager` did not answer before the readiness deadline.
    PeerManagerTimedOut,
    /// `PeerManager` dropped the reply channel.
    PeerManagerDroppedReply,
    /// RIB command channel is closed.
    RibUnavailable,
    /// RIB did not answer before the readiness deadline.
    RibTimedOut,
    /// RIB dropped the reply channel.
    RibDroppedReply,
}

impl fmt::Display for CoreReadinessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let deadline_ms = CORE_READINESS_DEADLINE.as_millis();
        match self {
            Self::PeerManagerUnavailable => f.write_str("peer manager unavailable"),
            Self::PeerManagerTimedOut => {
                write!(f, "peer manager probe timed out ({deadline_ms}ms deadline)")
            }
            Self::PeerManagerDroppedReply => f.write_str("peer manager dropped reply"),
            Self::RibUnavailable => f.write_str("RIB manager unavailable"),
            Self::RibTimedOut => {
                write!(f, "RIB manager probe timed out ({deadline_ms}ms deadline)")
            }
            Self::RibDroppedReply => f.write_str("RIB manager dropped reply"),
        }
    }
}

impl std::error::Error for CoreReadinessError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe_with_closed_peer_manager() -> CoreReadinessProbe {
        let (peer_tx, peer_rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        drop(peer_rx);
        CoreReadinessProbe::new(peer_tx, rib_tx)
    }

    fn probe_with_closed_rib() -> (CoreReadinessProbe, mpsc::Receiver<PeerManagerCommand>) {
        let (peer_tx, peer_rx) = mpsc::channel(1);
        let (rib_tx, rib_rx) = mpsc::channel(1);
        drop(rib_rx);
        (CoreReadinessProbe::new(peer_tx, rib_tx), peer_rx)
    }

    async fn reply_to_peer_manager(
        peer_rx: &mut mpsc::Receiver<PeerManagerCommand>,
        peers: Vec<PeerInfo>,
    ) {
        let command = peer_rx.recv().await.expect("peer manager command");
        let PeerManagerCommand::ListPeers { reply } = command else {
            panic!("expected ListPeers command");
        };
        reply.send(peers).expect("peer reply receiver is alive");
    }

    async fn reply_to_rib(rib_rx: &mut mpsc::Receiver<RibUpdate>, total_routes: usize) {
        let command = rib_rx.recv().await.expect("RIB command");
        let RibUpdate::QueryLocRibCount { reply } = command else {
            panic!("expected QueryLocRibCount command");
        };
        reply
            .send(total_routes)
            .expect("RIB reply receiver is alive");
    }

    #[test]
    fn display_uses_stable_operator_text() {
        assert_eq!(
            CoreReadinessError::PeerManagerUnavailable.to_string(),
            "peer manager unavailable"
        );
        assert_eq!(
            CoreReadinessError::PeerManagerTimedOut.to_string(),
            "peer manager probe timed out (200ms deadline)"
        );
        assert_eq!(
            CoreReadinessError::PeerManagerDroppedReply.to_string(),
            "peer manager dropped reply"
        );
        assert_eq!(
            CoreReadinessError::RibUnavailable.to_string(),
            "RIB manager unavailable"
        );
        assert_eq!(
            CoreReadinessError::RibTimedOut.to_string(),
            "RIB manager probe timed out (200ms deadline)"
        );
        assert_eq!(
            CoreReadinessError::RibDroppedReply.to_string(),
            "RIB manager dropped reply"
        );
    }

    #[test]
    fn core_readiness_deadline_is_200ms() {
        assert_eq!(CORE_READINESS_DEADLINE, Duration::from_millis(200));
    }

    #[tokio::test]
    async fn snapshot_returns_core_actor_data_when_both_respond() {
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let probe = CoreReadinessProbe::new(peer_tx, rib_tx);

        let snapshot = tokio::join!(probe.snapshot(), async {
            reply_to_peer_manager(&mut peer_rx, Vec::new()).await;
            reply_to_rib(&mut rib_rx, 17).await;
        })
        .0
        .expect("probe should succeed");

        assert!(snapshot.peers.is_empty());
        assert_eq!(snapshot.total_routes, 17);
    }

    #[tokio::test]
    async fn check_succeeds_when_snapshot_succeeds() {
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let probe = CoreReadinessProbe::new(peer_tx, rib_tx);

        let (result, ()) = tokio::join!(probe.check(), async {
            reply_to_peer_manager(&mut peer_rx, Vec::new()).await;
            reply_to_rib(&mut rib_rx, 0).await;
        });

        result.expect("check should succeed");
    }

    #[tokio::test]
    async fn snapshot_fails_when_peer_manager_sender_is_closed() {
        let err = probe_with_closed_peer_manager()
            .snapshot()
            .await
            .expect_err("closed peer manager channel should fail");

        assert_eq!(err, CoreReadinessError::PeerManagerUnavailable);
    }

    #[tokio::test]
    async fn snapshot_fails_when_rib_sender_is_closed() {
        let (probe, mut peer_rx) = probe_with_closed_rib();

        let (result, ()) = tokio::join!(probe.snapshot(), async {
            reply_to_peer_manager(&mut peer_rx, Vec::new()).await;
        });

        assert_eq!(
            result.expect_err("closed RIB channel should fail"),
            CoreReadinessError::RibUnavailable
        );
    }

    #[tokio::test]
    async fn snapshot_fails_when_peer_manager_drops_reply() {
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let probe = CoreReadinessProbe::new(peer_tx, rib_tx);

        let (result, ()) = tokio::join!(probe.snapshot(), async {
            let command = peer_rx.recv().await.expect("peer manager command");
            let PeerManagerCommand::ListPeers { reply } = command else {
                panic!("expected ListPeers command");
            };
            drop(reply);
        });

        assert_eq!(
            result.expect_err("dropped peer reply should fail"),
            CoreReadinessError::PeerManagerDroppedReply
        );
    }

    #[tokio::test]
    async fn snapshot_fails_when_rib_drops_reply() {
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let probe = CoreReadinessProbe::new(peer_tx, rib_tx);

        let (result, ()) = tokio::join!(probe.snapshot(), async {
            reply_to_peer_manager(&mut peer_rx, Vec::new()).await;
            let command = rib_rx.recv().await.expect("RIB command");
            let RibUpdate::QueryLocRibCount { reply } = command else {
                panic!("expected QueryLocRibCount command");
            };
            drop(reply);
        });

        assert_eq!(
            result.expect_err("dropped RIB reply should fail"),
            CoreReadinessError::RibDroppedReply
        );
    }

    #[tokio::test]
    async fn snapshot_fails_when_peer_manager_times_out() {
        let (peer_tx, _peer_rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let probe = CoreReadinessProbe::new(peer_tx, rib_tx);

        let err = probe
            .snapshot()
            .await
            .expect_err("unresponsive peer manager should time out");

        assert_eq!(err, CoreReadinessError::PeerManagerTimedOut);
    }

    #[tokio::test]
    async fn snapshot_fails_when_rib_times_out() {
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let probe = CoreReadinessProbe::new(peer_tx, rib_tx);

        let (result, ()) = tokio::join!(probe.snapshot(), async {
            reply_to_peer_manager(&mut peer_rx, Vec::new()).await;
        });

        assert_eq!(
            result.expect_err("unresponsive RIB should time out"),
            CoreReadinessError::RibTimedOut
        );
    }
}
