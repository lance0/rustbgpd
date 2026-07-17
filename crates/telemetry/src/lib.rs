//! rustbgpd-telemetry — Prometheus metrics and structured tracing
//!
//! Observable by default. Metrics counters exist from day one, even
//! if they read zero.
//!
//! This crate has no dependency on any other `rustbgpd-*` crate.
//! Most label values are plain strings — callers pass `state.as_str()`,
//! `"keepalive"`, etc. Reason labels covered by the
//! [`reason_labels`] contract are typed instead, so the canonical
//! vocabulary is enforced at compile time.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod logging;
pub mod metrics;
pub mod reason_labels;

pub use logging::{LoggingError, init_logging, reload_per_peer_directives};
pub use metrics::BgpMetrics;
pub use reason_labels::{NextHopOwnershipBlockReason, OtcBlockReason, RrLoopReason};
