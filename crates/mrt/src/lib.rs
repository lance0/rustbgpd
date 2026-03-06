//! rustbgpd-mrt — MRT dump export (RFC 6396)
//!
//! Periodic `TABLE_DUMP_V2` RIB snapshots to local files.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

/// MRT `TABLE_DUMP_V2` encoding (RFC 6396).
pub mod codec;
/// MRT dump manager: periodic + on-demand RIB snapshots.
pub mod manager;
/// Configuration and re-exported types.
pub mod types;
/// Atomic file writer with optional gzip compression.
pub mod writer;

pub use manager::MrtManager;
pub use types::MrtWriterConfig;
