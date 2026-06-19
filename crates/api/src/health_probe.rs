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
