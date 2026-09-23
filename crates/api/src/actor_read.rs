//! Shared transport boundary for read-only requests to the state-owning actors.

use std::net::IpAddr;
use std::time::Duration;

use rustbgpd_rib::{RibSummaryQuery, RibUpdate};
use tokio::sync::{mpsc, oneshot};
use tonic::Status;

use crate::peer_types::{EnqueuedOperatorQuery, PeerManagerCommand, PeerManagerOperatorQuery};

/// Server-side deadline for every peer-manager read. All peer-manager reads
/// are O(peers) state lookups, so this matches the duration class of the
/// neighbor service's `RIB_SNAPSHOT_TIMEOUT`: a wedged actor must surface as
/// `DEADLINE_EXCEEDED` instead of hanging the RPC until client cancel.
pub(crate) const PEER_MANAGER_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Send one read-only request to the peer manager and await its reply.
pub(crate) async fn peer_manager_read<T>(
    tx: &mpsc::Sender<PeerManagerCommand>,
    build: impl FnOnce(oneshot::Sender<T>) -> PeerManagerCommand,
) -> Result<T, Status> {
    bounded_peer_manager_read(tx, build).await
}

/// Use the operator lane when configured, retaining the ordinary command path
/// for service constructors without an operator receiver.
pub(crate) async fn peer_manager_operator_read<T>(
    tx: &mpsc::Sender<PeerManagerCommand>,
    operator_tx: Option<&mpsc::Sender<EnqueuedOperatorQuery>>,
    build: impl FnOnce(oneshot::Sender<T>) -> PeerManagerOperatorQuery,
) -> Result<T, Status> {
    match operator_tx {
        Some(operator_tx) => {
            bounded_peer_manager_read(operator_tx, |reply| build(reply).into()).await
        }
        None => peer_manager_read(tx, |reply| build(reply).into()).await,
    }
}

async fn bounded_peer_manager_read<T, C>(
    tx: &mpsc::Sender<C>,
    build: impl FnOnce(oneshot::Sender<T>) -> C,
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

/// Actor lanes that tell an unknown peer address from a known peer with no
/// rows, for peer-scoped reads.
#[derive(Clone)]
pub(crate) struct KnownPeerQueries {
    pub(crate) peer_manager: mpsc::Sender<PeerManagerCommand>,
    pub(crate) operator_lane: Option<mpsc::Sender<EnqueuedOperatorQuery>>,
    pub(crate) rib: mpsc::Sender<RibUpdate>,
}

impl KnownPeerQueries {
    /// Fail with `NOT_FOUND` naming `address` unless it names a known peer.
    ///
    /// Known means a managed peer — a configured neighbor or an accepted
    /// dynamic peer, the same `HasPeerAddress` answer `GetPolicyStats` uses —
    /// or a peer whose Adj-RIB-In still retains GR/LLGR-stale routes after its
    /// session (and, for a dynamic peer, its managed entry) went away. Callers
    /// ask only when a peer-scoped result is empty, so a result with rows is
    /// never delayed. The whole check, both reads together, is bounded by one
    /// [`PEER_MANAGER_READ_TIMEOUT`] deadline taken at entry.
    pub(crate) async fn require_known(&self, address: IpAddr) -> Result<(), Status> {
        let known = tokio::time::timeout(PEER_MANAGER_READ_TIMEOUT, async {
            let managed = peer_manager_operator_read(
                &self.peer_manager,
                self.operator_lane.as_ref(),
                |reply| PeerManagerOperatorQuery::HasPeerAddress { address, reply },
            )
            .await?;
            if managed {
                return Ok(true);
            }
            let retained = rib_manager_read(&self.rib, |reply| RibUpdate::QueryPeerRetainedStale {
                peer: address,
                reply,
            })
            .await?;
            Ok::<_, Status>(retained > 0)
        })
        .await
        .map_err(|_| Status::deadline_exceeded("known-peer check timed out"))??;
        if known {
            Ok(())
        } else {
            Err(Status::not_found(format!("neighbor {address} not found")))
        }
    }
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
    rib_read(tx, build).await
}

/// Use the bounded summary lane when configured. The caller retains its
/// existing deadline across both admission and reply; a closed configured
/// lane never falls back behind the general-query fence.
pub(crate) async fn rib_summary_read<T>(
    tx: &mpsc::Sender<RibUpdate>,
    summary_tx: Option<&mpsc::Sender<RibSummaryQuery>>,
    build: impl FnOnce(oneshot::Sender<T>) -> RibSummaryQuery,
) -> Result<T, Status> {
    match summary_tx {
        Some(summary_tx) => rib_read(summary_tx, build).await,
        None => rib_manager_read(tx, |reply| build(reply).into()).await,
    }
}

async fn rib_read<T, C>(
    tx: &mpsc::Sender<C>,
    build: impl FnOnce(oneshot::Sender<T>) -> C,
) -> Result<T, Status> {
    let (reply, response) = oneshot::channel();
    tx.send(build(reply))
        .await
        .map_err(|_| Status::unavailable("RIB manager unavailable"))?;
    response
        .await
        .map_err(|_| Status::unavailable("RIB manager dropped reply"))
}

/// Known-peer lanes backed by mock actors: `managed` is a managed peer and
/// `retained` holds GR-stale Adj-RIB-In routes; every other address is unknown.
#[cfg(test)]
pub(crate) fn mock_known_peer_queries(managed: IpAddr, retained: IpAddr) -> KnownPeerQueries {
    let (peer_mgr_tx, _) = mpsc::channel(1);
    let (operator_tx, mut operator_rx) = mpsc::channel::<EnqueuedOperatorQuery>(8);
    let (rib_tx, mut rib_rx) = mpsc::channel(8);
    tokio::spawn(async move {
        while let Some(enqueued) = operator_rx.recv().await {
            let PeerManagerOperatorQuery::HasPeerAddress { address, reply } = enqueued.query else {
                panic!("known-peer check sends only HasPeerAddress");
            };
            let _ = reply.send(address == managed);
        }
    });
    tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            let RibUpdate::QueryPeerRetainedStale { peer, reply } = update else {
                panic!("known-peer check sends only QueryPeerRetainedStale");
            };
            let _ = reply.send(if peer == retained { 3 } else { 0 });
        }
    });
    KnownPeerQueries {
        peer_manager: peer_mgr_tx,
        operator_lane: Some(operator_tx),
        rib: rib_tx,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Load-bearing: dropping either clause of the known-peer definition
    /// turns a managed or GR-retained peer into `NOT_FOUND`; dropping the
    /// check turns the unknown row green.
    #[tokio::test]
    async fn known_peer_is_managed_or_retained_and_unknown_is_not_found() {
        let managed: IpAddr = "192.0.2.1".parse().unwrap();
        let retained: IpAddr = "192.0.2.2".parse().unwrap();
        let known = mock_known_peer_queries(managed, retained);
        known.require_known(managed).await.unwrap();
        known.require_known(retained).await.unwrap();
        let error = known
            .require_known("192.0.2.99".parse().unwrap())
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::NotFound);
        assert_eq!(error.message(), "neighbor 192.0.2.99 not found");
    }

    /// Load-bearing: the whole existence check shares one
    /// `PEER_MANAGER_READ_TIMEOUT` deadline. A managed read that spends most
    /// of the budget followed by a wedged RIB read must fail at that single
    /// deadline; bounding each read separately answers at the sum instead,
    /// and an unbounded RIB read leaves the check pending past the guard.
    #[tokio::test(start_paused = true)]
    async fn known_peer_check_is_bounded_by_one_deadline() {
        let managed_delay = PEER_MANAGER_READ_TIMEOUT * 3 / 4;
        let (peer_mgr_tx, mut peer_rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        tokio::spawn(async move {
            while let Some(command) = peer_rx.recv().await {
                if let PeerManagerCommand::HasPeerAddress { reply, .. } = command {
                    tokio::time::sleep(managed_delay).await;
                    let _ = reply.send(false);
                }
            }
        });
        let known = KnownPeerQueries {
            peer_manager: peer_mgr_tx,
            operator_lane: None,
            rib: rib_tx,
        };
        let started = tokio::time::Instant::now();
        let error = tokio::time::timeout(
            Duration::from_secs(30),
            known.require_known("192.0.2.99".parse().unwrap()),
        )
        .await
        .expect("known-peer check must be bounded")
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
        assert_eq!(started.elapsed(), PEER_MANAGER_READ_TIMEOUT);
    }
    use crate::peer_types::PeerManagerCommand;
    use std::time::Duration;

    #[tokio::test]
    async fn closed_rib_summary_lane_does_not_fall_back() {
        let (tx, mut rx) = mpsc::channel(1);
        let (summary_tx, summary_rx) = mpsc::channel(1);
        drop(summary_rx);
        let error = rib_summary_read(&tx, Some(&summary_tx), |reply| {
            RibSummaryQuery::ExportPolicyTermHits { peer: None, reply }
        })
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn operator_read_bounds_admission_and_reply() {
        for full in [false, true] {
            let (tx, _rx) = mpsc::channel(1);
            let (operator_tx, mut operator_rx) = mpsc::channel(1);
            if full {
                let (reply, _response) = oneshot::channel();
                operator_tx
                    .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
                    .await
                    .unwrap();
            }
            let started = tokio::time::Instant::now();
            let error = peer_manager_operator_read(&tx, Some(&operator_tx), |reply| {
                PeerManagerOperatorQuery::ListPeers { reply }
            })
            .await
            .unwrap_err();
            assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
            assert_eq!(started.elapsed(), PEER_MANAGER_READ_TIMEOUT);
            assert!(operator_rx.try_recv().is_ok());
            assert!(operator_rx.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn operator_read_without_lane_retains_command_fallback() {
        let (tx, mut rx) = mpsc::channel(1);
        let actor = tokio::spawn(async move {
            let PeerManagerCommand::ListPeers { reply } = rx.recv().await.unwrap() else {
                panic!("expected ordinary peer read");
            };
            reply.send(Vec::new()).unwrap();
        });
        let peers = peer_manager_operator_read(&tx, None, |reply| {
            PeerManagerOperatorQuery::ListPeers { reply }
        })
        .await
        .unwrap();
        assert!(peers.is_empty());
        actor.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn operator_read_stamp_includes_channel_admission_wait() {
        let (tx, _rx) = mpsc::channel(1);
        let (operator_tx, mut operator_rx) = mpsc::channel(1);
        let (reply, _response) = oneshot::channel();
        operator_tx
            .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
            .await
            .unwrap();
        let task = tokio::spawn(async move {
            peer_manager_operator_read(&tx, Some(&operator_tx), |reply| {
                PeerManagerOperatorQuery::ListPeers { reply }
            })
            .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(500)).await;
        drop(operator_rx.recv().await.unwrap());
        let enqueued = operator_rx.recv().await.unwrap();
        assert_eq!(enqueued.enqueued.elapsed(), Duration::from_millis(500));
        let PeerManagerOperatorQuery::ListPeers { reply } = enqueued.query else {
            panic!("expected operator peer list");
        };
        reply.send(Vec::new()).unwrap();
        assert!(task.await.unwrap().unwrap().is_empty());
    }

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
