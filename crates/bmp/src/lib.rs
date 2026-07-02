//! rustbgpd-bmp — BMP exporter (RFC 7854, RFC 8671)
//!
//! Unidirectional BGP Monitoring Protocol exporter. Streams BGP
//! session state and raw UPDATE PDUs to configured collectors,
//! including post-policy Adj-RIB-Out monitoring (RFC 8671).

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod client;
pub mod codec;
pub mod manager;
pub mod types;

pub use client::BmpClient;
pub use manager::BmpManager;
pub use types::{
    BmpClientConfig, BmpControlEvent, BmpEvent, BmpMonitorFilter, BmpPeerInfo, BmpPeerType,
    PeerDownReason,
};
