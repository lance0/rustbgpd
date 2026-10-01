//! Compact worker-owned progress observations, independent of route outcomes.

use tokio::sync::watch;
use tokio::time::Instant;

/// Latest observation made by the worker itself.
#[derive(Debug, Clone, Copy)]
pub struct WorkerProgressState {
    /// At least one complete attempt has returned, including a retryable failure.
    pub initialized: bool,
    /// Time of the last substantive work checkpoint, not report forwarding.
    pub observed_at: Instant,
}

/// Sole publisher, kept inside the worker so its exit closes all readers.
///
/// A checkpoint records progress without claiming a completed pass or successful
/// forwarding. Callers must not refresh this from a separate heartbeat task.
#[derive(Debug)]
pub struct WorkerProgress {
    tx: watch::Sender<WorkerProgressState>,
}

impl Default for WorkerProgress {
    fn default() -> Self {
        let (tx, _) = watch::channel(WorkerProgressState {
            initialized: false,
            observed_at: Instant::now(),
        });
        Self { tx }
    }
}

impl WorkerProgress {
    /// Subscribe without extending the publisher's lifetime.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<WorkerProgressState> {
        self.tx.subscribe()
    }

    /// Record a concrete work boundary within a possibly long pass.
    pub fn checkpoint(&self) {
        self.tx
            .send_modify(|state| state.observed_at = Instant::now());
    }

    /// Record a returned first or subsequent pass, regardless of route outcomes.
    pub fn complete_pass(&self) {
        self.tx.send_modify(|state| {
            state.initialized = true;
            state.observed_at = Instant::now();
        });
    }
}
