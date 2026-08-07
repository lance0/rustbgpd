//! Shared transport boundary for read-only requests to the state-owning actors.

use std::time::Duration;

use rustbgpd_rib::RibUpdate;
use tokio::sync::{mpsc, oneshot};
use tonic::Status;

use crate::peer_types::PeerManagerCommand;

/// Server-side deadline for every peer-manager read. All peer-manager reads
/// are O(peers) state lookups, so this matches the duration class of the
/// neighbor service's `RIB_SNAPSHOT_TIMEOUT`: a wedged actor must surface as
/// `DEADLINE_EXCEEDED` instead of hanging the RPC until client cancel.
const PEER_MANAGER_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Send one read-only request to the peer manager and await its reply.
pub(crate) async fn peer_manager_read<T>(
    tx: &mpsc::Sender<PeerManagerCommand>,
    build: impl FnOnce(oneshot::Sender<T>) -> PeerManagerCommand,
) -> Result<T, Status> {
    tokio::time::timeout(PEER_MANAGER_READ_TIMEOUT, async {
        let (reply, response) = oneshot::channel();
        tx.send(build(reply))
            .await
            .map_err(|_| Status::unavailable("peer manager unavailable"))?;
        response
            .await
            .map_err(|_| Status::unavailable("peer manager dropped reply"))
    })
    .await
    .map_err(|_| Status::deadline_exceeded("peer manager read timed out"))?
}

/// Send one read-only request to the RIB manager and await its reply.
///
/// Unlike [`peer_manager_read`], this is deliberately unbounded here: RIB
/// reads can be legitimately slow at large table sizes, so a single fixed
/// deadline does not fit every caller. Callers that need a bound wrap this
/// in `tokio::time::timeout` (see the neighbor service's
/// `RIB_SNAPSHOT_TIMEOUT`).
pub(crate) async fn rib_manager_read<T>(
    tx: &mpsc::Sender<RibUpdate>,
    build: impl FnOnce(oneshot::Sender<T>) -> RibUpdate,
) -> Result<T, Status> {
    let (reply, response) = oneshot::channel();
    tx.send(build(reply))
        .await
        .map_err(|_| Status::unavailable("RIB manager unavailable"))?;
    response
        .await
        .map_err(|_| Status::unavailable("RIB manager dropped reply"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_types::PeerManagerCommand;
    use std::time::Duration;

    /// Load-bearing: without a server-side deadline inside
    /// `peer_manager_read`, a wedged peer-manager actor leaves the request
    /// pending forever and the outer test guard expires instead of observing
    /// the production `DeadlineExceeded` status.
    #[tokio::test(start_paused = true)]
    async fn stalled_peer_manager_read_returns_deadline_exceeded() {
        let (tx, rx) = mpsc::channel(1);
        let result = tokio::time::timeout(
            Duration::from_secs(30),
            peer_manager_read(&tx, |reply| PeerManagerCommand::ListPeers { reply }),
        )
        .await
        .expect("peer-manager read must be bounded server-side");
        assert_eq!(result.unwrap_err().code(), tonic::Code::DeadlineExceeded);
        // Held so the command is accepted but never answered.
        drop(rx);
    }
}
