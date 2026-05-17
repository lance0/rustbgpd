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
pub mod framing;
pub mod handle;
pub mod listener;
pub(crate) mod session;
#[allow(unsafe_code)]
mod socket_opts;
pub mod timer;

pub use config::{RemovePrivateAs, TransportConfig};
pub use error::TransportError;
pub use handle::{
    PeerCommand, PeerHandle, PeerSessionState, SessionIdentity, SessionLifecycleNotification,
    SessionNotification, SessionNotificationDirection, SessionNotificationEvent, SessionRole,
};
pub use listener::{AcceptedConnection, BgpListener};
pub use socket_opts::{TcpAoSupport, probe_tcp_ao_support};
