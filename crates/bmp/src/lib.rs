//! rustbgpd-bmp — BMP exporter (RFC 7854)
//!
//! Unidirectional BGP Monitoring Protocol exporter. Streams BGP
//! session state and raw UPDATE PDUs to configured collectors.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod client;
pub mod codec;
pub mod manager;
pub mod types;

pub use client::BmpClient;
pub use manager::BmpManager;
pub use types::{BmpClientConfig, BmpEvent, BmpPeerInfo, BmpPeerType, PeerDownReason};
