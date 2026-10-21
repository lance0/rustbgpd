use super::*;
use crate::PeerId;

pub(super) struct RunningManager {
    pub(super) tx: mpsc::Sender<RibUpdate>,
    pub(super) handle: tokio::task::JoinHandle<()>,
}

pub(super) fn spawn_running_manager(capacity: usize, metrics: BgpMetrics) -> RunningManager {
    spawn_running_manager_with_roster(capacity, metrics).0
}

/// [`spawn_running_manager`] plus a reader of its published export roster.
pub(super) fn spawn_running_manager_with_roster(
    capacity: usize,
    metrics: BgpMetrics,
) -> (RunningManager, crate::export_roster::ExportRosterReader) {
    let (tx, rx) = mpsc::channel(capacity);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics);
    let roster = manager.export_roster();
    let handle = tokio::spawn(manager.run());
    (RunningManager { tx, handle }, roster)
}

/// Return once `peer`'s dirty outbound resync has run, after the caller
/// advanced the paused clock past the resync interval.
///
/// One quiesce is not a barrier here. The run loop can take a query from
/// `select!` before its due-timer check and then yield on its wall-clock
/// flush budget, so whether a quiesce lands ahead of the resync tick depends
/// on host speed. At most two probes precede the tick.
pub(super) async fn await_dirty_resync(tx: &mpsc::Sender<RibUpdate>, peer: PeerId) {
    for _ in 0..4 {
        let (reply, dirty) = oneshot::channel();
        tx.send(RibUpdate::TestQueryPeerOutboundDirty { peer, reply })
            .await
            .unwrap();
        if !dirty.await.unwrap() {
            return;
        }
    }
    panic!("{peer} is still dirty after its resync tick");
}
