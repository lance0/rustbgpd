use thiserror::Error;

/// Errors that the FSM can surface to diagnostics.
///
/// Note: `handle_event` itself never returns `Result` — every input produces
/// a well-defined output.  These errors exist for logging / telemetry when
/// the FSM encounters protocol violations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FsmError {
    #[error("OPEN validation failed: {reason}")]
    OpenValidationFailed { reason: String },

    #[error("unexpected event {event} in state {state}")]
    UnexpectedEvent {
        event: &'static str,
        state: &'static str,
    },
}
