use bytes::Bytes;
use rustbgpd_wire::{Afi, DecodeError, NotificationMessage, OpenMessage, Safi};

/// Input events that drive FSM transitions.
#[derive(Debug, Clone)]
pub enum Event {
    // ── Admin ──────────────────────────────────────────
    /// Operator requests the session be started.
    ManualStart,
    /// Operator requests the session be torn down.
    /// Optional reason is included in the Cease NOTIFICATION data (RFC 8203).
    ManualStop { reason: Option<Bytes> },

    // ── Timer ─────────────────────────────────────────
    /// The connect-retry timer has expired.
    ConnectRetryTimerExpires,
    /// The hold timer has expired.
    HoldTimerExpires,
    /// The keepalive timer has expired.
    KeepaliveTimerExpires,

    // ── TCP ───────────────────────────────────────────
    /// Outbound TCP connection succeeded (`connect()`).
    TcpConnectionConfirmed,
    /// Inbound TCP connection accepted.
    TcpConnectionAcknowledged,
    /// TCP connection attempt failed or was reset.
    TcpConnectionFails,

    // ── BGP Messages ──────────────────────────────────
    /// A valid OPEN message was decoded from the peer.
    OpenReceived(OpenMessage),
    /// A valid KEEPALIVE was decoded from the peer.
    KeepaliveReceived,
    /// A NOTIFICATION was decoded from the peer.
    NotificationReceived(NotificationMessage),
    /// A valid UPDATE was processed (routes forwarded to RIB by transport).
    UpdateReceived,
    /// A valid ROUTE-REFRESH was decoded from the peer.
    RouteRefreshReceived { afi: Afi, safi: Safi },
    /// UPDATE validation failed — send NOTIFICATION and tear down.
    UpdateValidationError(NotificationMessage),
    /// The wire decoder failed to parse an incoming message.
    DecodeError(DecodeError),
}

impl Event {
    /// Short name for structured logging / metrics labels.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::ManualStart => "ManualStart",
            Self::ManualStop { .. } => "ManualStop",
            Self::ConnectRetryTimerExpires => "ConnectRetryTimerExpires",
            Self::HoldTimerExpires => "HoldTimerExpires",
            Self::KeepaliveTimerExpires => "KeepaliveTimerExpires",
            Self::TcpConnectionConfirmed => "TcpConnectionConfirmed",
            Self::TcpConnectionAcknowledged => "TcpConnectionAcknowledged",
            Self::TcpConnectionFails => "TcpConnectionFails",
            Self::OpenReceived(_) => "OpenReceived",
            Self::KeepaliveReceived => "KeepaliveReceived",
            Self::NotificationReceived(_) => "NotificationReceived",
            Self::UpdateReceived => "UpdateReceived",
            Self::RouteRefreshReceived { .. } => "RouteRefreshReceived",
            Self::UpdateValidationError(_) => "UpdateValidationError",
            Self::DecodeError(_) => "DecodeError",
        }
    }
}
