//! Peer session handle and command types.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use bytes::Bytes;
use rustbgpd_bmp::BmpEvent;
use rustbgpd_fsm::SessionState;
use rustbgpd_policy::PolicyChain;
use rustbgpd_rib::RibUpdate;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Afi, BgpRole, Safi};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use tracing::Instrument;

use crate::config::TransportConfig;
use crate::error::TransportError;
use crate::session::PeerSession;

/// Role of a session relative to the `PeerManager` entry that owns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// The current primary peer session.
    Primary,
    /// A temporary inbound collision candidate.
    InboundCandidate,
}

/// Identity attached to `PeerManager` notifications so stale transitions from
/// a superseded collision candidate cannot mutate the current peer entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionIdentity {
    /// Peer-manager scoped session generation.
    pub id: u64,
    /// Session role when the handle was spawned.
    pub role: SessionRole,
}

/// Direction of a BGP NOTIFICATION observed by a peer session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionNotificationDirection {
    /// rustbgpd sent the NOTIFICATION to the peer.
    Sent,
    /// The peer sent the NOTIFICATION to rustbgpd.
    Received,
}

/// Metadata-only BGP NOTIFICATION event emitted by a peer session for
/// operator-facing observability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionNotificationEvent {
    /// Peer-manager scoped session generation.
    pub session_id: u64,
    /// Role the session had when spawned.
    pub role: SessionRole,
    /// IP address of the remote peer.
    pub peer_addr: IpAddr,
    /// Whether the NOTIFICATION was sent or received.
    pub direction: SessionNotificationDirection,
    /// BGP NOTIFICATION error code.
    pub code: u8,
    /// BGP NOTIFICATION error subcode.
    pub subcode: u8,
    /// Human-readable code/subcode description.
    pub description: String,
    /// RFC 8203 shutdown communication reason, when present.
    pub shutdown_reason: Option<String>,
}

impl SessionIdentity {
    /// Default identity for sessions whose caller does not need collision
    /// generation tracking.
    #[must_use]
    pub const fn primary(id: u64) -> Self {
        Self {
            id,
            role: SessionRole::Primary,
        }
    }

    /// Identity for a live inbound collision candidate.
    #[must_use]
    pub const fn inbound_candidate(id: u64) -> Self {
        Self {
            id,
            role: SessionRole::InboundCandidate,
        }
    }
}

impl Default for SessionIdentity {
    fn default() -> Self {
        Self::primary(0)
    }
}

/// Lossless notifications sent from a peer session to the `PeerManager` for
/// TCP collision coordination.
///
/// This path is intentionally unbounded so collision decisions never block or
/// drop. High-volume operator lifecycle events use
/// [`SessionLifecycleNotification`] instead.
#[derive(Debug)]
pub enum SessionNotification {
    /// BGP FSM state changed.
    ///
    /// Kept for compatibility with tests and external users of the transport
    /// crate. New peer sessions publish state changes over the bounded
    /// [`SessionLifecycleNotification`] channel when one is configured.
    StateChanged {
        /// Peer-manager scoped session generation.
        session_id: u64,
        /// Role the session had when spawned.
        role: SessionRole,
        /// IP address of the remote peer.
        peer_addr: IpAddr,
        /// Previous FSM state.
        old: SessionState,
        /// New FSM state.
        new: SessionState,
    },
    /// Session received a valid OPEN and transitioned to `OpenConfirm`.
    OpenReceived {
        /// Peer-manager scoped session generation.
        session_id: u64,
        /// Role the session had when spawned.
        role: SessionRole,
        /// IP address of the remote peer.
        peer_addr: IpAddr,
        /// Router ID from the peer's OPEN message.
        remote_router_id: Ipv4Addr,
    },
    /// Session fell back to Idle.
    BackToIdle {
        /// Peer-manager scoped session generation.
        session_id: u64,
        /// Role the session had when spawned.
        role: SessionRole,
        /// IP address of the remote peer.
        peer_addr: IpAddr,
    },
}

/// Bounded lifecycle notification sent from a peer session to `PeerManager`.
///
/// These events back operator-facing streams such as
/// `EventService.WatchEvents`. They may be dropped under sustained churn rather
/// than allowing observability traffic to grow the lossless collision channel.
#[derive(Debug)]
pub enum SessionLifecycleNotification {
    /// BGP FSM state changed.
    StateChanged {
        /// Peer-manager scoped session generation.
        session_id: u64,
        /// Role the session had when spawned.
        role: SessionRole,
        /// IP address of the remote peer.
        peer_addr: IpAddr,
        /// Previous FSM state.
        old: SessionState,
        /// New FSM state.
        new: SessionState,
    },
}

/// Commands sent to a running peer session.
#[derive(Debug)]
pub enum PeerCommand {
    /// Start the BGP session (`ManualStart`).
    Start,
    /// Gracefully tear down the session (`ManualStop`).
    /// Optional reason is included in the Cease NOTIFICATION (RFC 8203).
    Stop {
        /// Shutdown communication reason (pre-encoded), or None.
        reason: Option<Bytes>,
    },
    /// Shut down the task entirely.
    Shutdown,
    /// Query the current session state.
    QueryState {
        /// Oneshot channel to receive the session state snapshot.
        reply: oneshot::Sender<PeerSessionState>,
    },
    /// Send a ROUTE-REFRESH message to the peer (RFC 2918).
    SendRouteRefresh {
        /// Address Family Identifier.
        afi: Afi,
        /// Subsequent Address Family Identifier.
        safi: Safi,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Replace the import policy chain for future inbound UPDATE processing.
    UpdateImportPolicy {
        /// New effective import policy chain (`None` = permit-all).
        policy: Option<PolicyChain>,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Replace the export policy chain used on future `PeerUp` registration.
    UpdateExportPolicy {
        /// New effective export policy chain (`None` = permit-all).
        policy: Option<PolicyChain>,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// RFC 8326 graceful-shutdown initiator: toggle attaching the
    /// `GRACEFUL_SHUTDOWN` community to outbound updates from this
    /// session. Receiver behavior on the *other* side of the session
    /// is what makes this useful — they de-prefer paths carrying the
    /// community ahead of planned maintenance.
    UpdateGracefulShutdown {
        /// `true` attaches the community; `false` clears it.
        enabled: bool,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Collision resolution: send Cease/7 NOTIFICATION and tear down.
    CollisionDump,
}

/// Snapshot of a peer session's runtime state.
#[derive(Debug, Clone)]
pub struct PeerSessionState {
    /// Current FSM state.
    pub fsm_state: SessionState,
    /// Remote peer IP address.
    pub peer_ip: IpAddr,
    /// Number of accepted prefixes from this peer.
    pub prefix_count: usize,
    /// Negotiated hold time (seconds), if session reached `OpenConfirm`.
    pub negotiated_hold_time: Option<u16>,
    /// Whether 4-octet AS was negotiated, if session reached `OpenConfirm`.
    pub four_octet_as: Option<bool>,
    /// Remote BGP router ID, if session reached `OpenConfirm`.
    pub remote_router_id: Option<Ipv4Addr>,
    /// Locally configured BGP Role, if advertised.
    pub local_role: Option<BgpRole>,
    /// Remote BGP Role advertised in OPEN, if present.
    pub remote_role: Option<BgpRole>,
    /// True when both sides advertised compatible BGP Roles.
    pub role_negotiated: bool,
    /// Total UPDATE messages received.
    pub updates_received: u64,
    /// Total UPDATE messages sent.
    pub updates_sent: u64,
    /// Total NOTIFICATION messages received.
    pub notifications_received: u64,
    /// Total NOTIFICATION messages sent.
    pub notifications_sent: u64,
    /// Number of times the session went from Established to non-Established.
    pub flap_count: u64,
    /// Seconds since last transition to Established (0 if never established).
    pub uptime_secs: u64,
    /// Human-readable description of the last error (empty if none).
    pub last_error: String,
    /// Number of unicast route announcements blocked by RFC 9234 OTC rules.
    pub otc_routes_blocked: u64,
    /// Import policy evaluations that permitted a route.
    pub import_policy_routes_permitted: u64,
    /// Import policy evaluations that denied a route.
    pub import_policy_routes_denied: u64,
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
    /// Test-only constructor that wraps an already-spawned task plus
    /// its command sender. Lets tests in dependent crates substitute a
    /// fake session task for failure-mode coverage that real session
    /// code can't reach reliably (e.g. "import-policy update times
    /// out *and* QueryState then reports Established"). Production
    /// code MUST go through [`Self::spawn`] / [`Self::spawn_inbound`].
    #[doc(hidden)]
    #[must_use]
    pub fn from_parts(
        commands: mpsc::Sender<PeerCommand>,
        task: JoinHandle<Result<(), TransportError>>,
    ) -> Self {
        Self { commands, task }
    }

    /// Spawn a new peer session task and return a handle to control it.
    ///
    /// The session starts in Idle. Send [`PeerCommand::Start`] to initiate
    /// the BGP handshake.
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn spawn(
        config: TransportConfig,
        metrics: BgpMetrics,
        rib_tx: mpsc::Sender<RibUpdate>,
        import_policy: Option<PolicyChain>,
        export_policy: Option<PolicyChain>,
        session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
        bmp_tx: Option<mpsc::Sender<BmpEvent>>,
        validation_rx: Option<watch::Receiver<rustbgpd_rpki::ValidationSnapshot>>,
        advertise_graceful_shutdown: bool,
    ) -> Self {
        Self::spawn_with_identity(
            config,
            metrics,
            rib_tx,
            import_policy,
            export_policy,
            session_notify_tx,
            None,
            bmp_tx,
            validation_rx,
            advertise_graceful_shutdown,
            SessionIdentity::default(),
        )
    }

    /// Spawn a new primary peer session with an explicit notification identity.
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn spawn_with_identity(
        config: TransportConfig,
        metrics: BgpMetrics,
        rib_tx: mpsc::Sender<RibUpdate>,
        import_policy: Option<PolicyChain>,
        export_policy: Option<PolicyChain>,
        session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
        session_event_tx: Option<mpsc::Sender<SessionNotificationEvent>>,
        bmp_tx: Option<mpsc::Sender<BmpEvent>>,
        validation_rx: Option<watch::Receiver<rustbgpd_rpki::ValidationSnapshot>>,
        advertise_graceful_shutdown: bool,
        session_identity: SessionIdentity,
    ) -> Self {
        Self::spawn_with_identity_and_lifecycle(
            config,
            metrics,
            rib_tx,
            import_policy,
            export_policy,
            session_notify_tx,
            session_event_tx,
            None,
            bmp_tx,
            validation_rx,
            advertise_graceful_shutdown,
            session_identity,
        )
    }

    /// Spawn a new primary peer session with explicit notification identity and
    /// bounded lifecycle event channel.
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn spawn_with_identity_and_lifecycle(
        config: TransportConfig,
        metrics: BgpMetrics,
        rib_tx: mpsc::Sender<RibUpdate>,
        import_policy: Option<PolicyChain>,
        export_policy: Option<PolicyChain>,
        session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
        session_event_tx: Option<mpsc::Sender<SessionNotificationEvent>>,
        session_lifecycle_tx: Option<mpsc::Sender<SessionLifecycleNotification>>,
        bmp_tx: Option<mpsc::Sender<BmpEvent>>,
        validation_rx: Option<watch::Receiver<rustbgpd_rpki::ValidationSnapshot>>,
        advertise_graceful_shutdown: bool,
        session_identity: SessionIdentity,
    ) -> Self {
        let (tx, rx) = mpsc::channel(COMMAND_BUFFER);
        let peer_addr = config.remote_addr.ip();
        let remote_asn = config.peer.remote_asn;
        let peer_group = config.peer_group.clone().unwrap_or_default();
        let span = tracing::info_span!("peer", %peer_addr, remote_asn, %peer_group);
        let task = tokio::spawn(
            async move {
                let mut session = PeerSession::new_with_identity_and_lifecycle(
                    config,
                    metrics,
                    rx,
                    rib_tx,
                    import_policy,
                    export_policy,
                    session_notify_tx,
                    session_event_tx,
                    session_lifecycle_tx,
                    bmp_tx,
                    validation_rx,
                    advertise_graceful_shutdown,
                    session_identity,
                );
                session.run().await
            }
            .instrument(span),
        );
        Self { commands: tx, task }
    }

    /// Spawn a new peer session for an inbound (already-connected) TCP stream.
    ///
    /// The session starts with a connected stream and receives
    /// `TcpConnectionConfirmed` to begin the handshake.
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn spawn_inbound(
        config: TransportConfig,
        metrics: BgpMetrics,
        rib_tx: mpsc::Sender<RibUpdate>,
        import_policy: Option<PolicyChain>,
        export_policy: Option<PolicyChain>,
        stream: TcpStream,
        session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
        bmp_tx: Option<mpsc::Sender<BmpEvent>>,
        validation_rx: Option<watch::Receiver<rustbgpd_rpki::ValidationSnapshot>>,
        advertise_graceful_shutdown: bool,
    ) -> Self {
        Self::spawn_inbound_with_identity(
            config,
            metrics,
            rib_tx,
            import_policy,
            export_policy,
            stream,
            session_notify_tx,
            None,
            bmp_tx,
            validation_rx,
            advertise_graceful_shutdown,
            SessionIdentity::default(),
        )
    }

    /// Spawn a new inbound peer session with an explicit notification identity.
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn spawn_inbound_with_identity(
        config: TransportConfig,
        metrics: BgpMetrics,
        rib_tx: mpsc::Sender<RibUpdate>,
        import_policy: Option<PolicyChain>,
        export_policy: Option<PolicyChain>,
        stream: TcpStream,
        session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
        session_event_tx: Option<mpsc::Sender<SessionNotificationEvent>>,
        bmp_tx: Option<mpsc::Sender<BmpEvent>>,
        validation_rx: Option<watch::Receiver<rustbgpd_rpki::ValidationSnapshot>>,
        advertise_graceful_shutdown: bool,
        session_identity: SessionIdentity,
    ) -> Self {
        Self::spawn_inbound_with_identity_and_lifecycle(
            config,
            metrics,
            rib_tx,
            import_policy,
            export_policy,
            stream,
            session_notify_tx,
            session_event_tx,
            None,
            bmp_tx,
            validation_rx,
            advertise_graceful_shutdown,
            session_identity,
        )
    }

    /// Spawn a new inbound peer session with explicit notification identity and
    /// bounded lifecycle event channel.
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn spawn_inbound_with_identity_and_lifecycle(
        config: TransportConfig,
        metrics: BgpMetrics,
        rib_tx: mpsc::Sender<RibUpdate>,
        import_policy: Option<PolicyChain>,
        export_policy: Option<PolicyChain>,
        stream: TcpStream,
        session_notify_tx: Option<mpsc::UnboundedSender<SessionNotification>>,
        session_event_tx: Option<mpsc::Sender<SessionNotificationEvent>>,
        session_lifecycle_tx: Option<mpsc::Sender<SessionLifecycleNotification>>,
        bmp_tx: Option<mpsc::Sender<BmpEvent>>,
        validation_rx: Option<watch::Receiver<rustbgpd_rpki::ValidationSnapshot>>,
        advertise_graceful_shutdown: bool,
        session_identity: SessionIdentity,
    ) -> Self {
        let (tx, rx) = mpsc::channel(COMMAND_BUFFER);
        let peer_addr = config.remote_addr.ip();
        let remote_asn = config.peer.remote_asn;
        let peer_group = config.peer_group.clone().unwrap_or_default();
        let span = tracing::info_span!("peer", %peer_addr, remote_asn, %peer_group);
        let task = tokio::spawn(
            async move {
                let mut session = PeerSession::new_inbound_with_identity_and_lifecycle(
                    config,
                    metrics,
                    rx,
                    rib_tx,
                    import_policy,
                    export_policy,
                    stream,
                    session_notify_tx,
                    session_event_tx,
                    session_lifecycle_tx,
                    bmp_tx,
                    validation_rx,
                    advertise_graceful_shutdown,
                    session_identity,
                );
                session.run().await
            }
            .instrument(span),
        );
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
    /// The optional `reason` is included in the Cease NOTIFICATION (RFC 8203).
    ///
    /// # Errors
    ///
    /// Returns an error if the session task has already exited.
    pub async fn stop(
        &self,
        reason: Option<Bytes>,
    ) -> Result<(), mpsc::error::SendError<PeerCommand>> {
        self.commands.send(PeerCommand::Stop { reason }).await
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

    /// Query the current session state with a bounded deadline.
    ///
    /// Wraps both the command-channel `send` and the oneshot reply in
    /// `tokio::time::timeout`. Returns `None` on timeout, on a full command
    /// channel that doesn't drain in time, or if the session task has exited.
    ///
    /// Prefer this over [`Self::query_state`] in any RPC or admin path: a session
    /// task parked on TCP write back-pressure cannot service `QueryState`
    /// commands, and the unbounded variant will hang the caller for as long
    /// as the peer's outbound buffer stays full.
    pub async fn query_state_timeout(&self, deadline: Duration) -> Option<PeerSessionState> {
        Self::query_state_with(self.commands.clone(), deadline).await
    }

    /// Driver-side variant of [`Self::query_state_timeout`] that takes an
    /// owned command sender, so it can run inside a `tokio::spawn`-ed
    /// `'static` future. Use [`Self::commands_sender`] to obtain the
    /// sender, then spawn one task per peer for concurrent fan-out.
    pub async fn query_state_with(
        commands: mpsc::Sender<PeerCommand>,
        deadline: Duration,
    ) -> Option<PeerSessionState> {
        // Outer Result is Err on timeout → flatten to None. Inner Option is
        // None when either the send failed (channel closed) or the reply
        // was dropped (session task gone).
        tokio::time::timeout(deadline, async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            commands
                .send(PeerCommand::QueryState { reply: reply_tx })
                .await
                .ok()?;
            reply_rx.await.ok()
        })
        .await
        .ok()
        .flatten()
    }

    /// Clone of the peer command channel sender.
    ///
    /// Use with [`Self::query_state_with`] to drive per-peer queries
    /// from `tokio::spawn`-ed tasks (which require their future to be
    /// `'static`). The command channel is bounded (`COMMAND_BUFFER`),
    /// so callers should still wrap any send in a timeout —
    /// `query_state_with` does this for you.
    #[must_use]
    pub fn commands_sender(&self) -> mpsc::Sender<PeerCommand> {
        self.commands.clone()
    }

    /// Replace the effective import policy chain for this session.
    ///
    /// The new chain applies to future inbound UPDATE processing only.
    ///
    /// # Errors
    ///
    /// Returns an error if the session task has already exited.
    pub async fn update_import_policy(&self, policy: Option<PolicyChain>) -> Result<(), String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(PeerCommand::UpdateImportPolicy {
                policy,
                reply: reply_tx,
            })
            .await
            .map_err(|_| "session task exited".to_string())?;
        reply_rx
            .await
            .map_err(|_| "session task dropped reply".to_string())?
    }

    /// Bounded variant of [`Self::update_import_policy`].
    ///
    /// Wraps both the command-channel send and the reply wait in
    /// `tokio::time::timeout`. Use this from the peer-manager actor —
    /// without a deadline a single back-pressured peer can park the actor
    /// and cascade into a `GetHealth` wedge.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the session is unreachable, replies with one, or
    /// doesn't acknowledge inside `deadline`.
    pub async fn update_import_policy_timeout(
        &self,
        policy: Option<PolicyChain>,
        deadline: Duration,
    ) -> Result<(), String> {
        let commands = self.commands.clone();
        match tokio::time::timeout(deadline, async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            commands
                .send(PeerCommand::UpdateImportPolicy {
                    policy,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| "session task exited".to_string())?;
            reply_rx
                .await
                .map_err(|_| "session task dropped reply".to_string())?
        })
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => Err(format!("update_import_policy timed out after {deadline:?}")),
        }
    }

    /// Replace the effective export policy chain for future `PeerUp` messages.
    ///
    /// The new chain is used when the session next registers with the RIB.
    ///
    /// # Errors
    ///
    /// Returns an error if the session task has already exited.
    pub async fn update_export_policy(&self, policy: Option<PolicyChain>) -> Result<(), String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(PeerCommand::UpdateExportPolicy {
                policy,
                reply: reply_tx,
            })
            .await
            .map_err(|_| "session task exited".to_string())?;
        reply_rx
            .await
            .map_err(|_| "session task dropped reply".to_string())?
    }

    /// Bounded variant of [`Self::update_export_policy`]. See
    /// [`Self::update_import_policy_timeout`] for rationale.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is unreachable, replies with one,
    /// or doesn't acknowledge inside `deadline`.
    pub async fn update_export_policy_timeout(
        &self,
        policy: Option<PolicyChain>,
        deadline: Duration,
    ) -> Result<(), String> {
        let commands = self.commands.clone();
        match tokio::time::timeout(deadline, async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            commands
                .send(PeerCommand::UpdateExportPolicy {
                    policy,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| "session task exited".to_string())?;
            reply_rx
                .await
                .map_err(|_| "session task dropped reply".to_string())?
        })
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => Err(format!("update_export_policy timed out after {deadline:?}")),
        }
    }

    /// Toggle attaching the RFC 8326 `GRACEFUL_SHUTDOWN` community to
    /// outbound updates from this session. Mirrors the
    /// `update_*_policy` shape for consistency.
    ///
    /// # Errors
    ///
    /// Returns an error if the session task isn't reachable or replies
    /// with one.
    pub async fn update_graceful_shutdown(&self, enabled: bool) -> Result<(), String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(PeerCommand::UpdateGracefulShutdown {
                enabled,
                reply: reply_tx,
            })
            .await
            .map_err(|_| "session task exited".to_string())?;
        reply_rx
            .await
            .map_err(|_| "session task dropped reply".to_string())?
    }

    /// Bounded variant of [`Self::update_graceful_shutdown`]. See
    /// [`Self::update_import_policy_timeout`] for rationale — same
    /// wedge class: a session task parked on TCP write back-pressure
    /// would otherwise park the peer-manager actor here, blocking
    /// every other gRPC RPC for as long as the session is wedged.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is unreachable, replies with
    /// one, or doesn't acknowledge inside `deadline`.
    pub async fn update_graceful_shutdown_timeout(
        &self,
        enabled: bool,
        deadline: Duration,
    ) -> Result<(), String> {
        let commands = self.commands.clone();
        match tokio::time::timeout(deadline, async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            commands
                .send(PeerCommand::UpdateGracefulShutdown {
                    enabled,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| "session task exited".to_string())?;
            reply_rx
                .await
                .map_err(|_| "session task dropped reply".to_string())?
        })
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => Err(format!(
                "update_graceful_shutdown timed out after {deadline:?}"
            )),
        }
    }

    /// Check if the session task has finished.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Reproduces the `GetHealth` wedge mode where the session-task's
    /// `select!` is parked on TCP write back-pressure: the command does
    /// reach the receiver, but the reply is never sent. The bounded
    /// variant must surface this as `None` within roughly the deadline,
    /// not hang for as long as the session stays parked.
    #[tokio::test]
    async fn query_state_with_bounds_when_reply_is_never_sent() {
        let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
        // Receiver pulls commands off the channel but holds them so the
        // contained reply_tx is never dropped — `reply_rx.await` blocks.
        let _drain = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Some(cmd) = rx.recv().await {
                held.push(cmd);
            }
        });

        let deadline = Duration::from_millis(50);
        let start = Instant::now();
        let result = PeerHandle::query_state_with(tx, deadline).await;
        let elapsed = start.elapsed();

        assert!(result.is_none(), "stalled reply must surface as None");
        assert!(
            elapsed < Duration::from_millis(250),
            "query_state_with should bound at ~50ms, took {elapsed:?}"
        );
    }

    /// Reproduces the second wedge mode Codex flagged: with a command
    /// channel buffer of `COMMAND_BUFFER = 8`, repeated probes during a
    /// stall can fill the channel itself, so `tx.send().await` parks
    /// indefinitely. The bounded variant must surface that as `None` too,
    /// not hang on send.
    #[tokio::test]
    async fn query_state_with_bounds_when_command_channel_is_full() {
        let (tx, _rx) = mpsc::channel::<PeerCommand>(1);
        // Pre-fill the single-slot buffer; the receiver is never read, so
        // the next send blocks on permit acquisition forever.
        tx.send(PeerCommand::Start).await.unwrap();

        let deadline = Duration::from_millis(50);
        let start = Instant::now();
        let result = PeerHandle::query_state_with(tx, deadline).await;
        let elapsed = start.elapsed();

        assert!(result.is_none(), "blocked send must surface as None");
        assert!(
            elapsed < Duration::from_millis(250),
            "query_state_with should bound at ~50ms, took {elapsed:?}"
        );
    }
}
