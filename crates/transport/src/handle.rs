use rustbgpd_telemetry::BgpMetrics;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::TransportConfig;
use crate::error::TransportError;
use crate::session::PeerSession;

/// Commands sent to a running peer session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerCommand {
    /// Start the BGP session (`ManualStart`).
    Start,
    /// Gracefully tear down the session (`ManualStop`).
    Stop,
    /// Shut down the task entirely.
    Shutdown,
}

/// Handle for controlling a spawned peer session.
///
/// Dropping the handle does not stop the session — call [`shutdown`](Self::shutdown)
/// for a clean teardown.
pub struct PeerHandle {
    commands: mpsc::Sender<PeerCommand>,
    task: JoinHandle<Result<(), TransportError>>,
}

/// Channel buffer size for peer commands.
const COMMAND_BUFFER: usize = 8;

impl PeerHandle {
    /// Spawn a new peer session task and return a handle to control it.
    ///
    /// The session starts in Idle. Send [`PeerCommand::Start`] to initiate
    /// the BGP handshake.
    #[must_use]
    pub fn spawn(config: TransportConfig, metrics: BgpMetrics) -> Self {
        let (tx, rx) = mpsc::channel(COMMAND_BUFFER);
        let task = tokio::spawn(async move {
            let mut session = PeerSession::new(config, metrics, rx);
            session.run().await
        });
        Self { commands: tx, task }
    }

    /// Send a Start command to begin the BGP handshake.
    ///
    /// # Errors
    ///
    /// Returns an error if the session task has already exited.
    pub async fn start(&self) -> Result<(), mpsc::error::SendError<PeerCommand>> {
        self.commands.send(PeerCommand::Start).await
    }

    /// Send a Stop command for graceful teardown.
    ///
    /// # Errors
    ///
    /// Returns an error if the session task has already exited.
    pub async fn stop(&self) -> Result<(), mpsc::error::SendError<PeerCommand>> {
        self.commands.send(PeerCommand::Stop).await
    }

    /// Send a Shutdown command and wait for the task to finish.
    ///
    /// # Errors
    ///
    /// Returns an error if the session task panicked.
    pub async fn shutdown(self) -> Result<Result<(), TransportError>, tokio::task::JoinError> {
        let _ = self.commands.send(PeerCommand::Shutdown).await;
        self.task.await
    }

    /// Check if the session task has finished.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}
