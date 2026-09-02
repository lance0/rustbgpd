//! rustbgpd-transport — BGP peer TCP connection management
//!
//! Tokio-based read/write loops, session runtime, bounded channels.
//! This is the only crate that owns BGP peer TCP session I/O —
//! `bmp`, `rpki`, `api`, and `mrt` each run their own async tasks
//! for their respective collector / RTR / gRPC / dump-writer I/O.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod config;
pub mod error;
pub mod event_sink;
pub mod framing;
pub mod handle;
pub mod listener;
pub(crate) mod session;
#[allow(
    unsafe_code,
    reason = "Linux BGP socket options require raw libc ABI calls and records"
)]
mod socket_opts;
pub mod timer;

// Authoritative export encoding plus inbound attribute handling exposed ONLY
// for the off-by-default microbenches. Not part of the normal public API.
#[cfg(feature = "bench-internals")]
pub use session::export::{
    FanoutBenchExportSnapshotEvidence, fanout_bench_add_path_export_encoder,
    fanout_bench_export_encoder, fanout_bench_export_snapshot_evidence,
    fanout_bench_route_server_export_encoder,
};
#[cfg(feature = "bench-internals")]
pub use session::inbound::{RouteAttrBundle, materialize_attrs};
#[cfg(feature = "bench-internals")]
pub struct ExplainSnapshotBenchCache(session::import_decision_cache::ImportDecisionCache);

#[cfg(feature = "bench-internals")]
impl ExplainSnapshotBenchCache {
    /// Build the real bounded import-decision cache for the explain benchmark.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(session::import_decision_cache::ImportDecisionCache::with_capacity(capacity))
    }

    /// Exercise the real import-decision insertion seam.
    pub fn insert(&mut self, key: ImportDecisionKey, decision: CachedDecision) {
        self.0.insert(key, decision);
    }
}

pub use config::{
    DEFAULT_MAX_AS_PATH_LENGTH, DEFAULT_SLOW_PEER_DURATION_SECS, DEFAULT_SLOW_PEER_THRESHOLD_PCT,
    RemovePrivateAs, TCP_AO_MAX_INSPECT_KEYS, TcpAoAlgorithm, TcpAoConfig, TcpAoKeyring,
    TcpAoRotationGeneration, TcpAoRotationOperation, TcpAoRotationOwner, TcpAoRotationPhase,
    TcpAoRotationStatus, TcpAoSessionDeletion, TcpAoSessionGeneration, TcpAoSessionSelection,
    TransportAuthSecret, TransportConfig,
};
pub use error::TransportError;
pub use event_sink::{
    NoopTransportEventSink, OtcDirection, OtcRouteBlockedEvent, TransportEventSink,
};
pub use handle::PeerRuntimeConfigUpdate;
pub use handle::{
    ImportPolicyTermHits, NegotiatedGracefulRestartState, NegotiatedSessionState, PeerCommand,
    PeerCommandError, PeerHandle, PeerSessionState, PeerShutdownError, PolicyRejectCounts,
    SessionIdentity, SessionLifecycleNotification, SessionNotification,
    SessionNotificationDirection, SessionNotificationEvent, SessionNotificationReceiver,
    SessionNotificationSender, SessionQueryOutcome, SessionRole, StateQueryOutcome,
    WarmCheckpointSessionState, session_notification_channel,
};
pub use listener::{
    AcceptedConnection, BgpListener, ListenerSocketOptions, Md5ListenerKey,
    TcpAoListenerGeneration, TcpAoListenerHandle, TcpAoListenerKey, TcpAoListenerOwnerKind,
    TtlSecurityListenerPolicy,
};
// ADR-0073: import-decision explain types crossing into the api +
// binary layers (PeerManagerCommand reply, PolicyService mapping).
pub use session::import_decision_cache::{
    CachedDecision, CachedOutcome, CachedPolicyContext, ImportDecisionKey, ImportExplainReply,
    LookupResult, ResolvedMatch,
};
// LAN-472: rejected-route retention types crossing into the api +
// binary layers (PeerManagerCommand reply, PolicyService mapping).
pub use session::rejected_routes::{RejectedRouteEntry, RejectedRoutesReply};
pub use session::{connect_authenticated, preflight_authenticated_dial};
pub use socket_opts::{
    TcpAoInfoSnapshot, TcpAoKeyState, TcpAoSupport, probe_tcp_ao_support, set_gtsm, set_tcp_md5sig,
};
