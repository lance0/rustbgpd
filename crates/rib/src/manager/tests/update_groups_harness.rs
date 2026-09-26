use super::*;

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
