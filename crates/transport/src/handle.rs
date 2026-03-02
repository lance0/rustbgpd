use std::net::{IpAddr, Ipv4Addr};

use rustbgpd_fsm::SessionState;
use rustbgpd_policy::PrefixList;
use rustbgpd_rib::RibUpdate;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Afi, Safi};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::config::TransportConfig;
use crate::error::TransportError;
use crate::session::PeerSession;

/// Notifications sent from a peer session to the `PeerManager` for
/// collision detection coordination.
#[derive(Debug)]
pub enum SessionNotification {
    /// Session received a valid OPEN and transitioned to `OpenConfirm`.
    OpenReceived {
        peer_addr: IpAddr,
        remote_router_id: Ipv4Addr,
    },
    /// Session fell back to Idle.
    BackToIdle { peer_addr: IpAddr },
}

/// Commands sent to a running peer session.
#[derive(Debug)]
pub enum PeerCommand {
    /// Start the BGP session (`ManualStart`).
    Start,
    /// Gracefully tear down the session (`ManualStop`).
    Stop,
    /// Shut down the task entirely.
    Shutdown,
    /// Query the current session state.
    QueryState {
        reply: oneshot::Sender<PeerSessionState>,
    },
    /// Send a ROUTE-REFRESH message to the peer (RFC 2918).
    SendRouteRefresh {
        afi: Afi,
        safi: Safi,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Collision resolution: send Cease/7 NOTIFICATION and tear down.
    CollisionDump,
}

/// Snapshot of a peer session's runtime state.
#[derive(Debug, Clone)]
pub struct PeerSessionState {
    pub fsm_state: SessionState,
    pub peer_ip: IpAddr,
    pub prefix_count: usize,
    pub negotiated_hold_time: Option<u16>,
    pub four_octet_as: Option<bool>,
    pub remote_router_id: Option<Ipv4Addr>,
    pub updates_received: u64,
    pub updates_sent: u64,
    pub notifications_received: u64,
    pub notifications_sent: u64,
    pub flap_count: u64,
    pub uptime_secs: u64,
    pub last_error: String,
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
    pub fn spawn(
        config: TransportConfig,
        metrics: BgpMetrics,
        rib_tx: mpsc::Sender<RibUpdate>,
        import_policy: Option<PrefixList>,
        export_policy: Option<PrefixList>,
        session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(COMMAND_BUFFER);
        let task = tokio::spawn(async move {
            let mut session = PeerSession::new(
                config,
                metrics,
                rx,
                rib_tx,
                import_policy,
                export_policy,
                session_notify_tx,
            );
            session.run().await
        });
        Self { commands: tx, task }
    }

    /// Spawn a new peer session for an inbound (already-connected) TCP stream.
    ///
    /// The session starts with a connected stream and receives
    /// `TcpConnectionConfirmed` to begin the handshake.
    #[must_use]
    pub fn spawn_inbound(
        config: TransportConfig,
        metrics: BgpMetrics,
        rib_tx: mpsc::Sender<RibUpdate>,
        import_policy: Option<PrefixList>,
        export_policy: Option<PrefixList>,
        stream: TcpStream,
        session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(COMMAND_BUFFER);
        let task = tokio::spawn(async move {
            let mut session = PeerSession::new_inbound(
                config,
                metrics,
                rx,
                rib_tx,
                import_policy,
                export_policy,
                stream,
                session_notify_tx,
            );
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

    /// Send a `CollisionDump` command (Cease/7 and tear down).
    ///
    /// # Errors
    ///
    /// Returns an error if the session task has already exited.
    pub async fn collision_dump(&self) -> Result<(), mpsc::error::SendError<PeerCommand>> {
        self.commands.send(PeerCommand::CollisionDump).await
    }

    /// Send a ROUTE-REFRESH message for the given address family.
    ///
    /// Returns `Ok(())` only if the message was actually sent on the wire.
    /// Returns an error if the session is not Established, the peer lacks
    /// the Route Refresh capability, or the family is not negotiated.
    ///
    /// # Errors
    ///
    /// Returns an error string describing why the message was not sent.
    pub async fn send_route_refresh(&self, afi: Afi, safi: Safi) -> Result<(), String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(PeerCommand::SendRouteRefresh {
                afi,
                safi,
                reply: reply_tx,
            })
            .await
            .map_err(|_| "session task exited".to_string())?;
        reply_rx
            .await
            .map_err(|_| "session task dropped reply".to_string())?
    }

    /// Query the current session state.
    ///
    /// # Errors
    ///
    /// Returns `None` if the session task has exited or the reply was dropped.
    pub async fn query_state(&self) -> Option<PeerSessionState> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(PeerCommand::QueryState { reply: reply_tx })
            .await
            .ok()?;
        reply_rx.await.ok()
    }

    /// Check if the session task has finished.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}
