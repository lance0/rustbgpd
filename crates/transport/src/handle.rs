//! Peer session handle and command types.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rustbgpd_bmp::BmpEvent;
use rustbgpd_fsm::SessionState;
use rustbgpd_policy::PolicyChain;
use rustbgpd_rib::RibUpdate;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{Afi, BgpRole, Prefix, Safi};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinError, JoinHandle};

use tracing::Instrument;

use crate::config::TransportConfig;
use crate::error::TransportError;
use crate::event_sink::TransportEventSink;
use crate::session::PeerSession;
use crate::session::import_decision_cache::ImportExplainReply;

/// Error returned by a peer-session command round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerCommandError {
    /// The session task exited before accepting the command.
    SessionExited,
    /// The session task accepted the command but dropped the reply channel.
    ReplyDropped,
    /// The command did not complete before the caller's deadline.
    TimedOut {
        /// Stable operation name used in operator-facing error text.
        operation: &'static str,
        /// Deadline that expired.
        deadline: Duration,
    },
    /// The command requires an Established BGP session.
    NotEstablished,
    /// The peer did not negotiate Route Refresh.
    RouteRefreshUnsupported,
    /// The requested AFI/SAFI is not negotiated on this session.
    FamilyNotNegotiated {
        /// Address Family Identifier.
        afi: Afi,
        /// Subsequent Address Family Identifier.
        safi: Safi,
    },
    /// The encoded message could not be queued to the session writer.
    SendFailed(String),
    /// Session-side command rejection that does not have a more specific
    /// transport variant yet.
    CommandFailed(String),
    /// A TCP-AO live mutation may have changed the connected socket before
    /// verification failed. The session has already discarded that stream;
    /// the peer manager must reset every sibling collision candidate too.
    TcpAoMutationFailed(String),
}

impl fmt::Display for PeerCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionExited => f.write_str("session task exited"),
            Self::ReplyDropped => f.write_str("session task dropped reply"),
            Self::TimedOut {
                operation,
                deadline,
            } => write!(f, "{operation} timed out after {deadline:?}"),
            Self::NotEstablished => f.write_str("session not Established"),
            Self::RouteRefreshUnsupported => f.write_str("peer lacks Route Refresh capability"),
            Self::FamilyNotNegotiated { afi, safi } => write!(f, "{afi:?}/{safi:?} not negotiated"),
            Self::SendFailed(error) => write!(f, "send failed: {error}"),
            Self::CommandFailed(error) | Self::TcpAoMutationFailed(error) => f.write_str(error),
        }
    }
}

impl std::error::Error for PeerCommandError {}

/// Error returned by bounded peer-session shutdown.
#[derive(Debug)]
pub enum PeerShutdownError {
    /// Shutdown command delivery or task join did not complete before the
    /// caller's deadline. The session task has been aborted before returning
    /// this error.
    TimedOut {
        /// Stable operation name used in operator-facing error text.
        operation: &'static str,
        /// Deadline that expired.
        deadline: Duration,
    },
    /// The session task joined with an error before the deadline.
    Join(JoinError),
}

impl fmt::Display for PeerShutdownError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut {
                operation,
                deadline,
            } => write!(f, "{operation} timed out after {deadline:?}"),
            Self::Join(error) => write!(f, "session task join error: {error}"),
        }
    }
}

impl std::error::Error for PeerShutdownError {}

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
        /// Peer's ASN learned from OPEN negotiation, if available.
        peer_asn: Option<u32>,
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
    /// Query the negotiated identity needed by a coordinated warm checkpoint.
    /// This is separate from operator state so checkpoint-only fields do not
    /// silently become a public API contract.
    QueryWarmCheckpointState {
        /// Oneshot channel to receive one actor-consistent negotiation view.
        reply: oneshot::Sender<WarmCheckpointSessionState>,
    },
    /// Send a ROUTE-REFRESH message to the peer (RFC 2918).
    SendRouteRefresh {
        /// Address Family Identifier.
        afi: Afi,
        /// Subsequent Address Family Identifier.
        safi: Safi,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), PeerCommandError>>,
    },
    /// Replace the import policy chain for future inbound UPDATE processing.
    UpdateImportPolicy {
        /// New effective import policy chain (`None` = permit-all).
        policy: Option<PolicyChain>,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), PeerCommandError>>,
    },
    /// Replace the export policy chain used on future `PeerUp` registration.
    UpdateExportPolicy {
        /// New effective export policy chain (`None` = permit-all).
        policy: Option<PolicyChain>,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), PeerCommandError>>,
    },
    /// Hot-apply reload-matrix `live` per-session runtime knobs without
    /// tearing the session task down (LAN-341). Every carried field is
    /// re-read from the session config on each evaluation (inbound UPDATE
    /// for `max_prefixes`, outbound emission for `local_ipv6_nexthop` /
    /// `remove_private_as`, GR peer-down for `gr_stale_routes_time`), so
    /// the swap takes effect on the next evaluation.
    UpdateRuntimeConfig {
        /// Maximum prefixes accepted before Cease/1 (None = unlimited).
        max_prefixes: Option<u32>,
        /// Independent IPv4-unicast prefix limit (ADR-0108). Lowering
        /// below the current count enforces immediately on apply.
        max_prefixes_ipv4: Option<u32>,
        /// Independent IPv6-unicast prefix limit (ADR-0108). Lowering
        /// below the current count enforces immediately on apply.
        max_prefixes_ipv6: Option<u32>,
        /// Stale-route retention after peer restart (seconds).
        gr_stale_routes_time: u64,
        /// Explicit IPv6 next-hop for eBGP (None = derive from socket).
        local_ipv6_nexthop: Option<std::net::Ipv6Addr>,
        /// Private AS removal mode for outbound `AS_PATH`.
        remove_private_as: crate::config::RemovePrivateAs,
        /// Reply channel for success/failure.
        reply: oneshot::Sender<Result<(), PeerCommandError>>,
    },
    /// Install the add-only portion of one immutable TCP-AO generation on the
    /// currently owned connected socket, then advance future active-open
    /// configuration. Current/RNext and existing MKTs are untouched.
    ApplyTcpAoAddOnly {
        desired: crate::TcpAoSessionGeneration,
        reply: oneshot::Sender<Result<(), PeerCommandError>>,
    },
    /// Validate a desired add-only generation against this session's current
    /// immutable owner inventory without mutating its socket or configuration.
    PreflightTcpAoAddOnly {
        desired: crate::TcpAoSessionGeneration,
        reply: oneshot::Sender<Result<(), PeerCommandError>>,
    },
    /// Discard this session's connected stream after any sibling may have
    /// partially mutated the immutable TCP-AO generation.
    ResetTcpAoAfterFailedMutation {
        desired_generation: crate::TcpAoRotationGeneration,
        reply: oneshot::Sender<()>,
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
        reply: oneshot::Sender<Result<(), PeerCommandError>>,
    },
    /// Collision resolution: send Cease/7 NOTIFICATION and tear down.
    CollisionDump,
    /// ADR-0073: query this session's import-decision cache. Read-only
    /// — must not mutate session state or counters. `path_id = None`
    /// returns every cached path for the prefix (Add-Path
    /// disambiguation); `Some(id)` resolves the single key.
    ExplainImportPolicy {
        /// Address family of the queried NLRI.
        afi: Afi,
        /// Subsequent address family of the queried NLRI.
        safi: Safi,
        /// Queried prefix.
        prefix: Prefix,
        /// Optional Add-Path identifier. `None` = all paths.
        path_id: Option<u32>,
        /// Reply channel carrying the resolved matches plus this
        /// session's current import-policy generation.
        reply: oneshot::Sender<ImportExplainReply>,
    },
    /// Snapshot this session's live import-chain per-term hit counters
    /// (ADR-0096 Decision 3.3, the import-side read surface). Read-only
    /// — must not mutate session state or counters. `None` when no
    /// import chain is installed (permit-all sessions have nothing to
    /// count).
    QueryImportPolicyTermHits {
        /// Reply channel.
        reply: oneshot::Sender<Option<ImportPolicyTermHits>>,
    },
}

/// Per-term hit-counter snapshot for one session's installed import
/// chain (`PeerCommand::QueryImportPolicyTermHits`).
#[derive(Debug, Clone)]
pub struct ImportPolicyTermHits {
    /// Session-local import-policy generation (ADR-0073): starts at 0
    /// at session-task construction and advances on every chain
    /// install — including a content-equal reinstall — so counters
    /// that reset to zero read as "new chain instance", not continuous
    /// history.
    pub generation: u64,
    /// Routes evaluated through the chain since install.
    pub evals: u64,
    /// Routes denied by an evaluation error since install (ADR-0103
    /// Decision 4 fail-closed rail).
    pub eval_errors: u64,
    /// Most recent evaluation error, rendered (`None` = no evaluation
    /// has errored since install).
    pub last_error: Option<String>,
    /// Per-term labeled hit counts, in chain walk order.
    pub terms: Vec<rustbgpd_policy::TermHitRow>,
}

/// Outcome of a bounded session-state query
/// ([`PeerHandle::query_state_outcome`]) that keeps "the task did not answer
/// in time" separate from "the task is gone". The distinction is load-bearing
/// for collision resolution: a dead task safely yields to a new inbound
/// connection, while a merely unresponsive task may still be an Established
/// session that RFC 4271 §6.8 says must win against the new connection.
#[derive(Debug, Clone)]
#[expect(
    clippy::large_enum_variant,
    reason = "state queries are transient command replies; boxing every successful reply would add allocation to the common path"
)]
pub enum StateQueryOutcome {
    /// The session task answered within the deadline.
    State(PeerSessionState),
    /// The deadline expired before the session task answered (or before the
    /// bounded command channel accepted the query). The task may still be
    /// alive and its session in any state, including Established.
    TimedOut,
    /// The session task has exited: the command channel is closed or the
    /// reply was dropped during task teardown.
    SessionGone,
}

/// Snapshot of a peer session's runtime state.
#[derive(Debug, Clone)]
pub struct PeerSessionState {
    /// Current FSM state.
    pub fsm_state: SessionState,
    /// Remote peer IP address.
    pub peer_ip: IpAddr,
    /// Peer's ASN learned from OPEN negotiation, if available.
    pub peer_asn: Option<u32>,
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
    /// Peer-advertised experimental Paths-Limit values.
    pub peer_paths_limits: Vec<((Afi, Safi), u16)>,
    /// Effective family-local outbound Add-Path caps.
    pub effective_add_path_send_limits: Vec<((Afi, Safi), u32)>,
    /// Total UPDATE messages received.
    pub updates_received: u64,
    /// Total UPDATE messages sent.
    pub updates_sent: u64,
    /// Total NOTIFICATION messages received.
    pub notifications_received: u64,
    /// Total NOTIFICATION messages sent.
    pub notifications_sent: u64,
    /// Total BGP messages received, all types. Read from the per-peer
    /// telemetry counters, so the value is daemon-lifetime (persists
    /// across session flaps) and includes KEEPALIVEs.
    pub messages_received: u64,
    /// Total BGP messages sent, all types (daemon-lifetime; includes
    /// writer-task cadence KEEPALIVEs).
    pub messages_sent: u64,
    /// Number of times the session went from Established to non-Established.
    pub flap_count: u64,
    /// Seconds since last transition to Established (0 if never established).
    pub uptime_secs: u64,
    /// Human-readable description of the last error (empty if none).
    pub last_error: String,
    /// Query-time TCP-AO socket inspection. Refreshed by `QueryState` and
    /// cleared on disconnect or inspection failure.
    pub tcp_ao_info: Option<Box<crate::TcpAoInfoSnapshot>>,
    /// Whether this session is TCP-AO protected, independent of whether the
    /// latest read-only socket inspection succeeded.
    pub tcp_ao_protected: bool,
    /// Number of unicast route announcements blocked by RFC 9234 OTC rules.
    pub otc_routes_blocked: u64,
    /// Import policy evaluations that permitted a route.
    pub import_policy_routes_permitted: u64,
    /// Import policy evaluations that denied a route.
    pub import_policy_routes_denied: u64,
}

/// Actor-consistent negotiated session identity used only while publishing a
/// shutdown warm checkpoint. No route or restore behavior lives here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmCheckpointSessionState {
    /// Current FSM state; only `Established` is checkpoint-eligible.
    pub fsm_state: SessionState,
    /// Peer's ASN learned from the current OPEN exchange.
    pub peer_asn: Option<u32>,
    /// Peer's BGP identifier learned from the current OPEN exchange.
    pub peer_router_id: Option<Ipv4Addr>,
    /// Address families negotiated on the current session.
    pub negotiated_families: Vec<(Afi, Safi)>,
    /// GR families advertised by the current peer OPEN.
    pub peer_gr_families: Vec<(Afi, Safi)>,
    /// Whether the current peer OPEN advertised usable GR capability.
    pub peer_gr_capable: bool,
    /// Restart time advertised in the current peer GR capability.
    pub peer_gr_restart_time: u16,
    /// Families for which this session negotiated Add-Path receive/both.
    pub add_path_receive_families: Vec<(Afi, Safi)>,
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
    /// Immediately abort the owned session task for a fail-closed transport
    /// safety boundary. Normal lifecycle code should use bounded shutdown;
    /// this escape hatch is reserved for cases where the command channel
    /// itself cannot acknowledge discarding a potentially mutated socket.
    #[doc(hidden)]
    pub fn abort_for_transport_safety(&self) {
        self.task.abort();
    }

    async fn send_simple_command_timeout(
        &self,
        command: PeerCommand,
        operation: &'static str,
        deadline: Duration,
    ) -> Result<(), PeerCommandError> {
        match tokio::time::timeout(deadline, self.commands.send(command)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(PeerCommandError::SessionExited),
            Err(_elapsed) => Err(PeerCommandError::TimedOut {
                operation,
                deadline,
            }),
        }
    }

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
    #[expect(
        clippy::too_many_arguments,
        reason = "spawn wrappers mirror session wiring dependencies; replacing them is API churn"
    )]
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
    #[expect(
        clippy::too_many_arguments,
        reason = "spawn wrappers mirror session wiring dependencies; replacing them is API churn"
    )]
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
    #[expect(
        clippy::too_many_arguments,
        reason = "spawn wrappers mirror session wiring dependencies; replacing them is API churn"
    )]
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
        Self::spawn_with_event_sink_and_identity_and_lifecycle(
            config,
            metrics,
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
            None,
        )
    }

    /// Spawn variant that also installs an out-of-crate
    /// [`TransportEventSink`] for ADR-0072 structured event
    /// publishing. `event_sink = None` is equivalent to the legacy
    /// spawn (no-op sink), so the binary's wiring layer can pass
    /// `None` when `[event_history]` is disabled without branching
    /// at every call site.
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "spawn wrappers mirror session wiring dependencies; replacing them is API churn"
    )]
    pub fn spawn_with_event_sink_and_identity_and_lifecycle(
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
        event_sink: Option<Arc<dyn TransportEventSink>>,
    ) -> Self {
        Self::spawn_at_tcp_ao_generation(
            config,
            metrics,
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
            event_sink,
            crate::TcpAoRotationGeneration::STARTUP,
        )
    }

    /// Spawn an active-open session at the peer manager's already-applied
    /// TCP-AO inventory generation. Recreated peers must not fall back to the
    /// startup generation after a successful live rotation.
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "spawn wrappers mirror session wiring dependencies; replacing them is API churn"
    )]
    pub fn spawn_at_tcp_ao_generation(
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
        event_sink: Option<Arc<dyn TransportEventSink>>,
        tcp_ao_generation: crate::TcpAoRotationGeneration,
    ) -> Self {
        let (tx, rx) = mpsc::channel(COMMAND_BUFFER);
        let peer_addr = config.remote_addr.ip();
        let remote_asn = config.peer.remote_asn;
        let peer_group = config.peer_group.clone().unwrap_or_default();
        let span = tracing::info_span!("peer", %peer_addr, remote_asn, %peer_group);
        let task = tokio::spawn(
            async move {
                let mut session = PeerSession::new_at_tcp_ao_generation(
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
                    tcp_ao_generation,
                );
                if let Some(sink) = event_sink {
                    session.set_event_sink(sink);
                }
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
    #[expect(
        clippy::too_many_arguments,
        reason = "spawn wrappers mirror session wiring dependencies; replacing them is API churn"
    )]
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
    #[expect(
        clippy::too_many_arguments,
        reason = "spawn wrappers mirror session wiring dependencies; replacing them is API churn"
    )]
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
    #[expect(
        clippy::too_many_arguments,
        reason = "spawn wrappers mirror session wiring dependencies; replacing them is API churn"
    )]
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
        Self::spawn_inbound_with_event_sink_and_identity_and_lifecycle(
            config,
            metrics,
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
            None,
            None,
        )
    }

    /// Inbound spawn variant that also installs an out-of-crate
    /// [`TransportEventSink`] (ADR-0072). See
    /// [`Self::spawn_with_event_sink_and_identity_and_lifecycle`]
    /// for the lifetime contract.
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "spawn wrappers mirror session wiring dependencies; replacing them is API churn"
    )]
    pub fn spawn_inbound_with_event_sink_and_identity_and_lifecycle(
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
        event_sink: Option<Arc<dyn TransportEventSink>>,
        tcp_ao_info: Option<crate::TcpAoInfoSnapshot>,
    ) -> Self {
        Self::spawn_inbound_at_tcp_ao_generation(
            config,
            metrics,
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
            event_sink,
            tcp_ao_info,
            crate::TcpAoRotationGeneration::STARTUP,
        )
    }

    /// Inbound spawn fenced to the immutable listener generation that
    /// reconciled the accepted child.
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "spawn wrappers mirror session wiring dependencies; replacing them is API churn"
    )]
    pub fn spawn_inbound_at_tcp_ao_generation(
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
        event_sink: Option<Arc<dyn TransportEventSink>>,
        tcp_ao_info: Option<crate::TcpAoInfoSnapshot>,
        tcp_ao_generation: crate::TcpAoRotationGeneration,
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
                    tcp_ao_info,
                    tcp_ao_generation,
                );
                if let Some(sink) = event_sink {
                    session.set_event_sink(sink);
                }
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

    /// Send a Start command with a bounded deadline.
    ///
    /// Use this from actor/RPC/admin paths. A session task parked on TCP write
    /// back-pressure may stop draining its bounded command channel; the
    /// unbounded [`Self::start`] helper is retained for call sites that can
    /// tolerate waiting.
    ///
    /// # Errors
    ///
    /// Returns an error if the session task has exited or the command is not
    /// accepted before `deadline`.
    pub async fn start_timeout(&self, deadline: Duration) -> Result<(), PeerCommandError> {
        self.send_simple_command_timeout(PeerCommand::Start, "start", deadline)
            .await
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

    /// Send a Stop command with a bounded deadline.
    ///
    /// # Errors
    ///
    /// Returns an error if the session task has exited or the command is not
    /// accepted before `deadline`.
    pub async fn stop_timeout(
        &self,
        reason: Option<Bytes>,
        deadline: Duration,
    ) -> Result<(), PeerCommandError> {
        self.send_simple_command_timeout(PeerCommand::Stop { reason }, "stop", deadline)
            .await
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

    /// Send a Shutdown command and wait for the task within a single bounded
    /// deadline.
    ///
    /// The `deadline` is a single budget shared across both the bounded
    /// command-channel send and the task join — it is an absolute instant, not
    /// re-applied per phase — so the total wait never exceeds `deadline`. If the
    /// deadline expires in either phase, the session task is aborted before
    /// returning [`PeerShutdownError::TimedOut`]. This avoids the actor-wedge fix
    /// turning into an unowned live-session leak.
    ///
    /// # Errors
    ///
    /// Returns [`PeerShutdownError::TimedOut`] after aborting the task when the
    /// deadline expires, or [`PeerShutdownError::Join`] if the task joined with
    /// an error before the deadline.
    pub async fn shutdown_timeout(
        mut self,
        deadline: Duration,
    ) -> Result<Result<(), TransportError>, PeerShutdownError> {
        let deadline_at = tokio::time::Instant::now() + deadline;
        if tokio::time::timeout_at(deadline_at, self.commands.send(PeerCommand::Shutdown))
            .await
            .is_err()
        {
            self.task.abort();
            let _ = self.task.await;
            return Err(PeerShutdownError::TimedOut {
                operation: "shutdown",
                deadline,
            });
        }

        match tokio::time::timeout_at(deadline_at, &mut self.task).await {
            Ok(result) => result.map_err(PeerShutdownError::Join),
            Err(_elapsed) => {
                self.task.abort();
                let _ = self.task.await;
                Err(PeerShutdownError::TimedOut {
                    operation: "shutdown",
                    deadline,
                })
            }
        }
    }

    /// Send a `CollisionDump` command (Cease/7 and tear down).
    ///
    /// # Errors
    ///
    /// Returns an error if the session task has already exited.
    pub async fn collision_dump(&self) -> Result<(), mpsc::error::SendError<PeerCommand>> {
        self.commands.send(PeerCommand::CollisionDump).await
    }

    /// Send a `CollisionDump` command with a bounded deadline.
    ///
    /// # Errors
    ///
    /// Returns an error if the session task has exited or the command is not
    /// accepted before `deadline`.
    pub async fn collision_dump_timeout(&self, deadline: Duration) -> Result<(), PeerCommandError> {
        self.send_simple_command_timeout(PeerCommand::CollisionDump, "collision_dump", deadline)
            .await
    }

    /// Send a ROUTE-REFRESH message for the given address family.
    ///
    /// Returns `Ok(())` only if the message was actually sent on the wire.
    /// Returns an error if the session is not Established, the peer lacks
    /// the Route Refresh capability, or the family is not negotiated.
    ///
    /// # Errors
    ///
    /// Returns a typed error describing why the message was not sent.
    pub async fn send_route_refresh(&self, afi: Afi, safi: Safi) -> Result<(), PeerCommandError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(PeerCommand::SendRouteRefresh {
                afi,
                safi,
                reply: reply_tx,
            })
            .await
            .map_err(|_| PeerCommandError::SessionExited)?;
        reply_rx.await.map_err(|_| PeerCommandError::ReplyDropped)?
    }

    /// Send a ROUTE-REFRESH command with a bounded deadline.
    ///
    /// Wraps both the command-channel send and the session-side reply wait so a
    /// single stalled peer cannot park the peer-manager actor during
    /// `soft_reset_in`.
    ///
    /// # Errors
    ///
    /// Returns a typed error describing why the message was not sent, including
    /// [`PeerCommandError::TimedOut`] when the deadline expires.
    pub async fn send_route_refresh_timeout(
        &self,
        afi: Afi,
        safi: Safi,
        deadline: Duration,
    ) -> Result<(), PeerCommandError> {
        let commands = self.commands.clone();
        match tokio::time::timeout(deadline, async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            commands
                .send(PeerCommand::SendRouteRefresh {
                    afi,
                    safi,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| PeerCommandError::SessionExited)?;
            reply_rx.await.map_err(|_| PeerCommandError::ReplyDropped)?
        })
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => Err(PeerCommandError::TimedOut {
                operation: "send_route_refresh",
                deadline,
            }),
        }
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
    ///
    /// `None` conflates "deadline expired" with "session task gone". Callers
    /// whose action on a dead task differs from their action on a slow one
    /// (e.g. collision resolution, where a timed-out task may still be an
    /// Established session) must use [`Self::query_state_outcome`] instead.
    pub async fn query_state_timeout(&self, deadline: Duration) -> Option<PeerSessionState> {
        Self::query_state_with(self.commands.clone(), deadline).await
    }

    /// Bounded state query that distinguishes a deadline expiry from a dead
    /// session task, unlike [`Self::query_state_timeout`] which flattens both
    /// to `None`.
    ///
    /// - [`StateQueryOutcome::TimedOut`]: the deadline expired before the
    ///   session task answered (or before the bounded command channel
    ///   accepted the query). The task may still be alive — e.g. parked on
    ///   TCP write back-pressure — so its session may be in any state,
    ///   including Established.
    /// - [`StateQueryOutcome::SessionGone`]: the session task has exited
    ///   (command channel closed, or the reply was dropped during task
    ///   teardown). There is no live session behind this handle.
    pub async fn query_state_outcome(&self, deadline: Duration) -> StateQueryOutcome {
        let queried = tokio::time::timeout(deadline, async {
            let (reply_tx, reply_rx) = oneshot::channel();
            if self
                .commands
                .send(PeerCommand::QueryState { reply: reply_tx })
                .await
                .is_err()
            {
                return None;
            }
            reply_rx.await.ok()
        })
        .await;
        match queried {
            Err(_elapsed) => StateQueryOutcome::TimedOut,
            Ok(None) => StateQueryOutcome::SessionGone,
            Ok(Some(state)) => StateQueryOutcome::State(state),
        }
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

    /// Bounded checkpoint-only query for current negotiated GR/Add-Path truth.
    ///
    /// Returns `None` on timeout, channel closure, or session exit. Callers
    /// must reject the complete checkpoint rather than publishing a partial
    /// peer inventory when any candidate cannot answer.
    pub async fn query_warm_checkpoint_state_with(
        commands: mpsc::Sender<PeerCommand>,
        deadline: Duration,
    ) -> Option<WarmCheckpointSessionState> {
        tokio::time::timeout(deadline, async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            commands
                .send(PeerCommand::QueryWarmCheckpointState { reply: reply_tx })
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
    /// Returns [`PeerCommandError::SessionExited`] if the session task's
    /// command channel is closed, or [`PeerCommandError::ReplyDropped`] if the
    /// task accepted the command but dropped the reply before responding.
    pub async fn update_import_policy(
        &self,
        policy: Option<PolicyChain>,
    ) -> Result<(), PeerCommandError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(PeerCommand::UpdateImportPolicy {
                policy,
                reply: reply_tx,
            })
            .await
            .map_err(|_| PeerCommandError::SessionExited)?;
        reply_rx.await.map_err(|_| PeerCommandError::ReplyDropped)?
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
    ) -> Result<(), PeerCommandError> {
        Self::update_import_policy_with(self.commands.clone(), policy, deadline).await
    }

    /// Owned-sender variant of [`Self::update_import_policy_timeout`]. See
    /// [`Self::update_export_policy_with`] for rationale.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is unreachable, replies with one, or
    /// does not acknowledge inside `deadline`.
    pub async fn update_import_policy_with(
        commands: mpsc::Sender<PeerCommand>,
        policy: Option<PolicyChain>,
        deadline: Duration,
    ) -> Result<(), PeerCommandError> {
        match tokio::time::timeout(deadline, async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            commands
                .send(PeerCommand::UpdateImportPolicy {
                    policy,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| PeerCommandError::SessionExited)?;
            reply_rx.await.map_err(|_| PeerCommandError::ReplyDropped)?
        })
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => Err(PeerCommandError::TimedOut {
                operation: "update_import_policy",
                deadline,
            }),
        }
    }

    /// Query this session's import-decision cache (ADR-0073).
    ///
    /// Bounded like [`Self::query_state_timeout`]: a session parked on
    /// TCP write back-pressure cannot service the command, so the
    /// caller must not block indefinitely. Returns `None` on timeout,
    /// on a full command channel, or if the session task has exited —
    /// the caller (`PeerManager`) renders that as `NO_SESSION`: the
    /// session-local cache is unreachable, which is honestly distinct
    /// from an evaluated `NOT_SEEN` answer (LAN-320).
    pub async fn explain_import_policy_timeout(
        &self,
        afi: Afi,
        safi: Safi,
        prefix: Prefix,
        path_id: Option<u32>,
        deadline: Duration,
    ) -> Option<ImportExplainReply> {
        let commands = self.commands.clone();
        tokio::time::timeout(deadline, async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            commands
                .send(PeerCommand::ExplainImportPolicy {
                    afi,
                    safi,
                    prefix,
                    path_id,
                    reply: reply_tx,
                })
                .await
                .ok()?;
            reply_rx.await.ok()
        })
        .await
        .ok()
        .flatten()
    }

    /// Bounded snapshot of this session's import-chain per-term hit
    /// counters. `None` folds together "no import chain installed",
    /// "deadline expired", and "session task gone" — the stats surface
    /// simply omits the peer in all three cases.
    pub async fn query_import_policy_term_hits_timeout(
        &self,
        deadline: Duration,
    ) -> Option<ImportPolicyTermHits> {
        let commands = self.commands.clone();
        tokio::time::timeout(deadline, async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            commands
                .send(PeerCommand::QueryImportPolicyTermHits { reply: reply_tx })
                .await
                .ok()?;
            reply_rx.await.ok()
        })
        .await
        .ok()
        .flatten()
        .flatten()
    }

    /// Replace the effective export policy chain for future `PeerUp` messages.
    ///
    /// The new chain is used when the session next registers with the RIB.
    ///
    /// # Errors
    ///
    /// Returns [`PeerCommandError::SessionExited`] if the session task's
    /// command channel is closed, or [`PeerCommandError::ReplyDropped`] if the
    /// task accepted the command but dropped the reply before responding.
    pub async fn update_export_policy(
        &self,
        policy: Option<PolicyChain>,
    ) -> Result<(), PeerCommandError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(PeerCommand::UpdateExportPolicy {
                policy,
                reply: reply_tx,
            })
            .await
            .map_err(|_| PeerCommandError::SessionExited)?;
        reply_rx.await.map_err(|_| PeerCommandError::ReplyDropped)?
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
    ) -> Result<(), PeerCommandError> {
        Self::update_export_policy_with(self.commands.clone(), policy, deadline).await
    }

    /// Owned-sender variant of [`Self::update_export_policy_timeout`]. This
    /// lets an actor select the bounded session step against its own dedicated
    /// read-only query lane without borrowing the managed peer entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is unreachable, replies with one, or
    /// does not acknowledge inside `deadline`.
    pub async fn update_export_policy_with(
        commands: mpsc::Sender<PeerCommand>,
        policy: Option<PolicyChain>,
        deadline: Duration,
    ) -> Result<(), PeerCommandError> {
        match tokio::time::timeout(deadline, async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            commands
                .send(PeerCommand::UpdateExportPolicy {
                    policy,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| PeerCommandError::SessionExited)?;
            reply_rx.await.map_err(|_| PeerCommandError::ReplyDropped)?
        })
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => Err(PeerCommandError::TimedOut {
                operation: "update_export_policy",
                deadline,
            }),
        }
    }

    /// Bounded hot-apply of reload-matrix `live` per-session runtime
    /// knobs ([`PeerCommand::UpdateRuntimeConfig`]). Mirrors
    /// [`Self::update_import_policy_timeout`]'s bounded shape for the
    /// same reason: the peer-manager actor calls this and must not park
    /// behind a wedged session task.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is unreachable, replies with one,
    /// or doesn't acknowledge inside `deadline`.
    #[expect(
        clippy::too_many_arguments,
        reason = "one parameter per hot-appliable runtime knob, mirroring PeerCommand::UpdateRuntimeConfig"
    )]
    pub async fn update_runtime_config_timeout(
        &self,
        max_prefixes: Option<u32>,
        max_prefixes_ipv4: Option<u32>,
        max_prefixes_ipv6: Option<u32>,
        gr_stale_routes_time: u64,
        local_ipv6_nexthop: Option<std::net::Ipv6Addr>,
        remove_private_as: crate::config::RemovePrivateAs,
        deadline: Duration,
    ) -> Result<(), PeerCommandError> {
        let commands = self.commands.clone();
        match tokio::time::timeout(deadline, async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            commands
                .send(PeerCommand::UpdateRuntimeConfig {
                    max_prefixes,
                    max_prefixes_ipv4,
                    max_prefixes_ipv6,
                    gr_stale_routes_time,
                    local_ipv6_nexthop,
                    remove_private_as,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| PeerCommandError::SessionExited)?;
            reply_rx.await.map_err(|_| PeerCommandError::ReplyDropped)?
        })
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => Err(PeerCommandError::TimedOut {
                operation: "update_runtime_config",
                deadline,
            }),
        }
    }

    /// Bounded add-only TCP-AO generation apply.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is unreachable, rejects the candidate
    /// generation, fails to install or verify an MKT, drops its reply, or does
    /// not acknowledge inside `deadline`.
    pub async fn apply_tcp_ao_add_only_timeout(
        &self,
        desired: crate::TcpAoSessionGeneration,
        deadline: Duration,
    ) -> Result<(), PeerCommandError> {
        let commands = self.commands.clone();
        match tokio::time::timeout(deadline, async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            commands
                .send(PeerCommand::ApplyTcpAoAddOnly {
                    desired,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| PeerCommandError::SessionExited)?;
            reply_rx.await.map_err(|_| PeerCommandError::ReplyDropped)?
        })
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => Err(PeerCommandError::TimedOut {
                operation: "apply_tcp_ao_add_only",
                deadline,
            }),
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
    pub async fn update_graceful_shutdown(&self, enabled: bool) -> Result<(), PeerCommandError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(PeerCommand::UpdateGracefulShutdown {
                enabled,
                reply: reply_tx,
            })
            .await
            .map_err(|_| PeerCommandError::SessionExited)?;
        reply_rx.await.map_err(|_| PeerCommandError::ReplyDropped)?
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
    ) -> Result<(), PeerCommandError> {
        let commands = self.commands.clone();
        match tokio::time::timeout(deadline, async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            commands
                .send(PeerCommand::UpdateGracefulShutdown {
                    enabled,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| PeerCommandError::SessionExited)?;
            reply_rx.await.map_err(|_| PeerCommandError::ReplyDropped)?
        })
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => Err(PeerCommandError::TimedOut {
                operation: "update_graceful_shutdown",
                deadline,
            }),
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

    #[test]
    fn peer_command_error_display_preserves_operator_text() {
        assert_eq!(
            PeerCommandError::SessionExited.to_string(),
            "session task exited"
        );
        assert_eq!(
            PeerCommandError::ReplyDropped.to_string(),
            "session task dropped reply"
        );
        assert_eq!(
            PeerCommandError::TimedOut {
                operation: "update_import_policy",
                deadline: Duration::from_secs(2),
            }
            .to_string(),
            "update_import_policy timed out after 2s"
        );
        assert_eq!(
            PeerCommandError::NotEstablished.to_string(),
            "session not Established"
        );
        assert_eq!(
            PeerCommandError::RouteRefreshUnsupported.to_string(),
            "peer lacks Route Refresh capability"
        );
        assert_eq!(
            PeerCommandError::FamilyNotNegotiated {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            }
            .to_string(),
            "Ipv4/Unicast not negotiated"
        );
        assert_eq!(
            PeerCommandError::SendFailed("writer closed".to_string()).to_string(),
            "send failed: writer closed"
        );
        assert_eq!(
            PeerCommandError::CommandFailed("export apply failed once".to_string()).to_string(),
            "export apply failed once"
        );
    }

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

    /// Reproduces the second wedge mode: with a command channel buffer
    /// of `COMMAND_BUFFER = 8`, repeated probes during a
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

    fn handle_with_full_command_channel() -> (PeerHandle, mpsc::Receiver<PeerCommand>) {
        let (tx, rx) = mpsc::channel::<PeerCommand>(1);
        let task = tokio::spawn(async { Ok::<(), TransportError>(()) });
        (PeerHandle { commands: tx, task }, rx)
    }

    async fn fill_command_channel(handle: &PeerHandle) {
        handle
            .commands
            .send(PeerCommand::Start)
            .await
            .expect("receiver is intentionally kept alive");
    }

    fn assert_timed_out(result: &Result<(), PeerCommandError>, operation: &'static str) {
        assert!(
            matches!(
                result,
                Err(PeerCommandError::TimedOut {
                    operation: actual,
                    ..
                }) if *actual == operation
            ),
            "expected {operation} timeout, got {result:?}"
        );
    }

    fn assert_shutdown_timed_out(
        result: &Result<Result<(), TransportError>, PeerShutdownError>,
        operation: &'static str,
    ) {
        assert!(
            matches!(
                result,
                Err(PeerShutdownError::TimedOut {
                    operation: actual,
                    ..
                }) if *actual == operation
            ),
            "expected {operation} timeout, got {result:?}"
        );
    }

    #[tokio::test]
    async fn start_with_bounds_when_command_channel_is_full() {
        let (handle, _rx) = handle_with_full_command_channel();
        fill_command_channel(&handle).await;

        let deadline = Duration::from_millis(50);
        let start = Instant::now();
        let result = handle.start_timeout(deadline).await;
        let elapsed = start.elapsed();

        assert_timed_out(&result, "start");
        assert!(
            elapsed < Duration::from_millis(250),
            "start_timeout should bound at ~50ms, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn stop_with_bounds_when_command_channel_is_full() {
        let (handle, _rx) = handle_with_full_command_channel();
        fill_command_channel(&handle).await;

        let deadline = Duration::from_millis(50);
        let start = Instant::now();
        let result = handle.stop_timeout(None, deadline).await;
        let elapsed = start.elapsed();

        assert_timed_out(&result, "stop");
        assert!(
            elapsed < Duration::from_millis(250),
            "stop_timeout should bound at ~50ms, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn collision_dump_with_bounds_when_command_channel_is_full() {
        let (handle, _rx) = handle_with_full_command_channel();
        fill_command_channel(&handle).await;

        let deadline = Duration::from_millis(50);
        let start = Instant::now();
        let result = handle.collision_dump_timeout(deadline).await;
        let elapsed = start.elapsed();

        assert_timed_out(&result, "collision_dump");
        assert!(
            elapsed < Duration::from_millis(250),
            "collision_dump_timeout should bound at ~50ms, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn send_route_refresh_with_bounds_when_command_channel_is_full() {
        let (handle, _rx) = handle_with_full_command_channel();
        fill_command_channel(&handle).await;

        let deadline = Duration::from_millis(50);
        let start = Instant::now();
        let result = handle
            .send_route_refresh_timeout(Afi::Ipv4, Safi::Unicast, deadline)
            .await;
        let elapsed = start.elapsed();

        assert_timed_out(&result, "send_route_refresh");
        assert!(
            elapsed < Duration::from_millis(250),
            "send_route_refresh_timeout should bound at ~50ms, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn shutdown_with_bounds_aborts_when_command_channel_is_full() {
        let (handle, _rx) = handle_with_full_command_channel();
        fill_command_channel(&handle).await;

        let deadline = Duration::from_millis(50);
        let start = Instant::now();
        let result = handle.shutdown_timeout(deadline).await;
        let elapsed = start.elapsed();

        assert_shutdown_timed_out(&result, "shutdown");
        assert!(
            elapsed < Duration::from_millis(250),
            "shutdown_timeout should bound at ~50ms, took {elapsed:?}"
        );
    }
}
