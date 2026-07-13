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
#[allow(unsafe_code)]
mod socket_opts;
pub mod timer;

// Authoritative export encoding plus inbound attribute handling exposed ONLY
// for the off-by-default microbenches. Not part of the normal public API.
#[cfg(feature = "bench-internals")]
pub use session::export::fanout_bench_export_encoder;
#[cfg(feature = "bench-internals")]
pub use session::inbound::{RouteAttrBundle, materialize_attrs};

pub use config::{
    RemovePrivateAs, TCP_AO_MAX_INSPECT_KEYS, TcpAoAlgorithm, TcpAoConfig, TcpAoKeyring,
    TransportConfig,
};
pub use error::TransportError;
pub use event_sink::{
    NoopTransportEventSink, OtcDirection, OtcRouteBlockedEvent, TransportEventSink,
};
pub use handle::{
    ImportPolicyTermHits, PeerCommand, PeerCommandError, PeerHandle, PeerSessionState,
    PeerShutdownError, SessionIdentity, SessionLifecycleNotification, SessionNotification,
    SessionNotificationDirection, SessionNotificationEvent, SessionRole, StateQueryOutcome,
};
pub use listener::{
    AcceptedConnection, BgpListener, ListenerSocketOptions, TcpAoListenerKey,
    TcpAoListenerOwnerKind,
};
// ADR-0073: import-decision explain types crossing into the api +
// binary layers (PeerManagerCommand reply, PolicyService mapping).
pub use session::import_decision_cache::{
    CachedDecision, CachedOutcome, CachedPolicyContext, ImportExplainReply, LookupResult,
    ResolvedMatch,
};
pub use socket_opts::{TcpAoInfoSnapshot, TcpAoKeyState, TcpAoSupport, probe_tcp_ao_support};
