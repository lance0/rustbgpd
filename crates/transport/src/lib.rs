//! rustbgpd-transport — TCP connection management
//!
//! Tokio-based read/write loops, session runtime, bounded channels.
//! This is the only crate that touches async I/O.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod config;
pub mod error;
pub mod framing;
pub mod handle;
pub(crate) mod session;
pub mod timer;

pub use config::TransportConfig;
pub use error::TransportError;
pub use handle::{PeerCommand, PeerHandle};
