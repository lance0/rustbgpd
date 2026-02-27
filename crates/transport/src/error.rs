use thiserror::Error;

/// Errors produced by the transport layer.
#[derive(Error, Debug)]
pub enum TransportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("encode error: {0}")]
    Encode(#[from] rustbgpd_wire::EncodeError),

    #[error("clean shutdown")]
    Shutdown,
}
