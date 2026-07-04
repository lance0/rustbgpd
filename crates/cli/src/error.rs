use std::fmt;

pub enum CliError {
    Connect(#[expect(dead_code)] tonic::transport::Error),
    ConnectTimeout,
    Rpc(String),
    Argument(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Connect(_) => write!(f, "daemon is not running or unreachable"),
            CliError::ConnectTimeout => write!(f, "daemon is not running or unreachable"),
            CliError::Rpc(msg) => write!(f, "{msg}"),
            CliError::Argument(msg) => write!(f, "{msg}"),
            CliError::Io(e) => write!(f, "{e}"),
            CliError::Json(e) => write!(f, "failed to encode JSON output: {e}"),
        }
    }
}

impl fmt::Debug for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl From<tonic::transport::Error> for CliError {
    fn from(e: tonic::transport::Error) -> Self {
        CliError::Connect(e)
    }
}

impl From<tonic::Status> for CliError {
    fn from(s: tonic::Status) -> Self {
        match s.code() {
            tonic::Code::Unavailable => {
                CliError::Rpc("daemon is not running or unreachable".into())
            }
            tonic::Code::NotFound => CliError::Rpc(format!("not found: {}", s.message())),
            _ => CliError::Rpc(format!("{}: {}", s.code(), s.message())),
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Io(e)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        CliError::Json(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Status;

    // Every gRPC command routes its `Status` errors through
    // `From<Status>` via `?`, so this mapping is the CLI's single
    // operator-facing error contract. These pin the three distinct arms
    // so a regression (reordering the match, dropping a special case, or
    // changing a prefix) is caught centrally rather than per command.

    #[test]
    fn unavailable_is_reported_as_generic_unreachable() {
        // The raw transport detail is intentionally suppressed: an
        // operator seeing UNAVAILABLE almost always just means the daemon
        // is down, so we never leak the noisy inner message.
        let err = CliError::from(Status::unavailable("connection reset by peer"));
        assert!(matches!(err, CliError::Rpc(_)));
        assert_eq!(err.to_string(), "daemon is not running or unreachable");
    }

    #[test]
    fn not_found_gets_friendly_prefix_and_keeps_message() {
        let err = CliError::from(Status::not_found("no IP-VRF named \"blue\""));
        assert!(matches!(err, CliError::Rpc(_)));
        assert_eq!(err.to_string(), "not found: no IP-VRF named \"blue\"");
    }

    #[test]
    fn invalid_argument_falls_through_with_code_and_message() {
        // INVALID_ARGUMENT is not special-cased: it must surface via the
        // generic "{code}: {message}" arm so operators see both.
        let err = CliError::from(Status::invalid_argument("prefix length 33 exceeds 32"));
        assert!(matches!(err, CliError::Rpc(_)));
        assert_eq!(
            err.to_string(),
            "Client specified an invalid argument: prefix length 33 exceeds 32"
        );
    }

    #[test]
    fn already_exists_falls_through_with_code_and_message() {
        let err = CliError::from(Status::already_exists(
            "neighbor 10.0.0.2 already configured",
        ));
        assert!(matches!(err, CliError::Rpc(_)));
        assert_eq!(
            err.to_string(),
            "Some entity that we attempted to create already exists: \
             neighbor 10.0.0.2 already configured"
        );
    }
}
