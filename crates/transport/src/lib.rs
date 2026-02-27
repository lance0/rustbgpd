//! rustbgpd-transport — TCP connection management
//!
//! Tokio-based read/write loops, session runtime, bounded channels.
//! This is the only crate that touches async I/O.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
