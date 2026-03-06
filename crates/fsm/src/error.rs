//! FSM diagnostic error types.

use thiserror::Error;

/// Errors that the FSM can surface to diagnostics.
///
/// Note: `handle_event` itself never returns `Result` — every input produces
/// a well-defined output.  These errors exist for logging / telemetry when
/// the FSM encounters protocol violations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FsmError {
    /// Peer's OPEN message failed validation (bad ASN, hold time, etc.).
    #[error("OPEN validation failed: {reason}")]
    OpenValidationFailed {
        /// Human-readable description of the validation failure.
        reason: String,
    },

    /// An event was received that is invalid for the current FSM state.
    #[error("unexpected event {event} in state {state}")]
    UnexpectedEvent {
        /// Name of the unexpected event.
        event: &'static str,
        /// FSM state when the event arrived.
        state: &'static str,
    },
}
