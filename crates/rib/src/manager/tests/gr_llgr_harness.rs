use super::*;

/// Established GR/LLGR test default.
const UPDATE_CHANNEL_CAPACITY: usize = 64;

/// Tokio clock behavior required by a run-loop test.
#[derive(Clone, Copy)]
pub(super) enum TimeMode {
    Realtime,
    Paused,
}

pub(super) struct RunningManager {
    pub(super) tx: mpsc::Sender<RibUpdate>,
    pub(super) handle: tokio::task::JoinHandle<()>,
}

/// Use a dummy query channel, no global export policy, the requested cluster
/// ID, and fresh metrics alongside the fixed update-channel capacity.
fn manager_with_defaults(cluster_id: Option<Ipv4Addr>) -> (mpsc::Sender<RibUpdate>, RibManager) {
    let (tx, rx) = mpsc::channel(UPDATE_CHANNEL_CAPACITY);
    let manager = RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
    (tx, manager)
}

pub(super) fn spawn_manager(time_mode: TimeMode) -> RunningManager {
    if matches!(time_mode, TimeMode::Paused) {
        tokio::time::pause();
    }
    let (tx, manager) = manager_with_defaults(None);
    let handle = tokio::spawn(manager.run());
    RunningManager { tx, handle }
}

pub(super) fn direct_manager(
    cluster_id: Option<Ipv4Addr>,
) -> (mpsc::Sender<RibUpdate>, RibManager) {
    manager_with_defaults(cluster_id)
}
