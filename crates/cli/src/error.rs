use std::fmt;

pub enum CliError {
    /// Failed to reach the daemon at connect time. `addr` is the endpoint the
    /// CLI actually dialed; `detail` is a short human failure class derived
    /// from the transport error chain (never raw transport debris).
    Connect {
        addr: String,
        detail: String,
    },
    Rpc(String),
    Argument(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Connect { addr, detail } => write!(
                f,
                "cannot reach rustbgpd at {addr} ({detail})\n  \
                 hint: is the daemon running? if it uses a different endpoint, pass -s or set RUSTBGPD_ADDR"
            ),
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

impl From<tonic::Status> for CliError {
    fn from(s: tonic::Status) -> Self {
        // tonic's `Code` Display strings are full sentences ("The system is
        // not in a state required for the operation's execution: ..."), so
        // every code maps to a short lowercase prefix and the daemon-side
        // message reads as the sentence.
        let prefix = match s.code() {
            // Connect-time unreachability is handled by `CliError::Connect`
            // (with address + failure class); an UNAVAILABLE that surfaces
            // mid-RPC means the daemon went away, and the raw transport
            // detail is intentionally suppressed.
            tonic::Code::Unavailable => {
                return CliError::Rpc("daemon is not running or unreachable".into());
            }
            tonic::Code::NotFound => "not found",
            tonic::Code::InvalidArgument => "invalid argument",
            tonic::Code::FailedPrecondition => "precondition failed",
            tonic::Code::PermissionDenied => "permission denied",
            tonic::Code::Unauthenticated => "unauthenticated",
            tonic::Code::AlreadyExists => "already exists",
            tonic::Code::ResourceExhausted => "resource exhausted",
            tonic::Code::Unimplemented => "not supported by this daemon",
            tonic::Code::DeadlineExceeded => "deadline exceeded",
            tonic::Code::Aborted => "aborted",
            tonic::Code::OutOfRange => "out of range",
            tonic::Code::Cancelled => "cancelled",
            tonic::Code::DataLoss => "data loss",
            tonic::Code::Internal | tonic::Code::Unknown | tonic::Code::Ok => "daemon error",
        };
        CliError::Rpc(format!("{prefix}: {}", s.message()))
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
    // operator-facing error contract. These pin the distinct arms
    // so a regression (reordering the match, dropping a special case, or
    // changing a prefix) is caught centrally rather than per command.

    #[test]
    fn connect_error_renders_address_class_and_hint() {
        let err = CliError::Connect {
            addr: "unix:///var/lib/rustbgpd/grpc.sock".into(),
            detail: "socket does not exist".into(),
        };
        assert_eq!(
            err.to_string(),
            "cannot reach rustbgpd at unix:///var/lib/rustbgpd/grpc.sock (socket does not exist)\n  \
             hint: is the daemon running? if it uses a different endpoint, pass -s or set RUSTBGPD_ADDR"
        );
    }

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
    fn invalid_argument_gets_short_prefix_not_tonic_sentence() {
        let err = CliError::from(Status::invalid_argument("prefix length 33 exceeds 32"));
        assert!(matches!(err, CliError::Rpc(_)));
        assert_eq!(
            err.to_string(),
            "invalid argument: prefix length 33 exceeds 32"
        );
    }

    #[test]
    fn failed_precondition_gets_short_prefix_not_tonic_sentence() {
        // The live 0.50.0 capture: tonic rendered this code as "The system
        // is not in a state required for the operation's execution: ...".
        let err = CliError::from(Status::failed_precondition(
            "config persistence failed: failed to write /var/lib/rustbgpd/config.toml: No such file or directory (os error 2)",
        ));
        assert!(matches!(err, CliError::Rpc(_)));
        assert_eq!(
            err.to_string(),
            "precondition failed: config persistence failed: failed to write /var/lib/rustbgpd/config.toml: No such file or directory (os error 2)"
        );
    }

    #[test]
    fn permission_denied_gets_short_prefix() {
        let err = CliError::from(Status::permission_denied("token lacks write scope"));
        assert_eq!(
            err.to_string(),
            "permission denied: token lacks write scope"
        );
    }

    #[test]
    fn already_exists_gets_short_prefix_not_tonic_sentence() {
        let err = CliError::from(Status::already_exists(
            "neighbor 10.0.0.2 already configured",
        ));
        assert!(matches!(err, CliError::Rpc(_)));
        assert_eq!(
            err.to_string(),
            "already exists: neighbor 10.0.0.2 already configured"
        );
    }

    #[test]
    fn internal_falls_back_to_daemon_error_prefix() {
        let err = CliError::from(Status::internal("route processor panicked"));
        assert_eq!(err.to_string(), "daemon error: route processor panicked");
    }
}
