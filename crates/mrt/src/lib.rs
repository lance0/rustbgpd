//! rustbgpd-mrt — MRT dump export (RFC 6396)
//!
//! Periodic `TABLE_DUMP_V2` RIB snapshots to local files.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod codec;
pub mod manager;
pub mod types;
pub mod writer;

pub use manager::MrtManager;
pub use types::MrtWriterConfig;
