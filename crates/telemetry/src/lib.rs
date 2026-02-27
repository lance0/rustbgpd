//! rustbgpd-telemetry — Prometheus metrics and structured tracing
//!
//! Observable by default. Metrics counters exist from day one, even
//! if they read zero.
//!
//! This crate has no dependency on any other `rustbgpd-*` crate.
//! All label values are plain strings — callers pass `state.as_str()`,
//! `"keepalive"`, etc.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod logging;
pub mod metrics;

pub use logging::{LoggingError, init_logging};
pub use metrics::BgpMetrics;
