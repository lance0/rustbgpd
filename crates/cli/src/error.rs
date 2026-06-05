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
