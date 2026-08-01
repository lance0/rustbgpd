//! Shared transport boundary for read-only requests to the state-owning actors.

use rustbgpd_rib::RibUpdate;
use tokio::sync::{mpsc, oneshot};
use tonic::Status;

use crate::peer_types::PeerManagerCommand;

/// Send one read-only request to the peer manager and await its reply.
pub(crate) async fn peer_manager_read<T>(
    tx: &mpsc::Sender<PeerManagerCommand>,
    build: impl FnOnce(oneshot::Sender<T>) -> PeerManagerCommand,
) -> Result<T, Status> {
    let (reply, response) = oneshot::channel();
    tx.send(build(reply))
        .await
        .map_err(|_| Status::unavailable("peer manager unavailable"))?;
    response
        .await
        .map_err(|_| Status::unavailable("peer manager dropped reply"))
}

/// Send one read-only request to the RIB manager and await its reply.
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
