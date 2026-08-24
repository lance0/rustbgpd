use super::*;

pub(super) struct RunningManager {
    pub(super) tx: mpsc::Sender<RibUpdate>,
    pub(super) handle: tokio::task::JoinHandle<()>,
}

pub(super) fn spawn_running_manager(capacity: usize, metrics: BgpMetrics) -> RunningManager {
    let (tx, rx) = mpsc::channel(capacity);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics);
    let handle = tokio::spawn(manager.run());
    RunningManager { tx, handle }
}
