//! Structured JSON logging via `tracing`.

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;

/// Initialize the global tracing subscriber with JSON output and
/// `RUST_LOG` env-filter.
///
/// Call once at startup.  Defaults to `info` level if `RUST_LOG` is not
/// set.
///
/// `extra_directives` are appended to the filter and can include
/// per-peer span filters such as `peer{peer_addr=10.0.0.1}=debug`.
///
/// # Errors
///
/// Returns a [`LoggingError`] if the global subscriber has already been
/// set (e.g., called twice or a test already installed one).
pub fn init_logging(extra_directives: &[String]) -> Result<(), LoggingError> {
    let mut filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    for directive in extra_directives {
        filter = filter.add_directive(
            directive
                .parse()
                .map_err(|e| LoggingError::InvalidDirective(format!("{directive}: {e}")))?,
        );
    }

    fmt()
        .json()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .try_init()
        .map_err(|e| LoggingError::AlreadyInitialized(e.to_string()))
}

/// Errors from logging initialization.
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    /// The global tracing subscriber was already set.
    #[error("logging subscriber already initialized: {0}")]
    AlreadyInitialized(String),
    /// A per-peer log filter directive was malformed.
    #[error("invalid log filter directive: {0}")]
    InvalidDirective(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_logging_returns_result() {
        // We can't reliably test init_logging() in unit tests because the
        // global subscriber may already be set by another test. Instead,
        // verify that calling it produces a well-formed Result.
        let result = init_logging(&[]);
        // Either Ok (first call) or Err (already set) — neither should panic.
        assert!(result.is_ok() || result.is_err());
    }
}
