//! rustbgpd-bmp — BMP exporter (RFC 7854, RFC 8671, RFC 9069)
//!
//! Unidirectional BGP Monitoring Protocol exporter. Streams BGP
//! session state and raw UPDATE PDUs to configured collectors,
//! including post-policy Adj-RIB-Out monitoring (RFC 8671) and
//! Loc-RIB instance monitoring with collector-connect table sync
//! (RFC 9069).

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
    BmpClientConfig, BmpControlEvent, BmpDumpChunk, BmpDumpRequest, BmpEvent, BmpLocRibConfig,
    BmpMonitorFilter, BmpPeerInfo, BmpPeerType, LOC_RIB_TABLE_NAME, PeerDownReason,
};
