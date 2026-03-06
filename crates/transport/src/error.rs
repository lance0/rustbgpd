//! Error types for the transport layer.

use thiserror::Error;

/// Errors produced by the transport layer.
#[derive(Error, Debug)]
pub enum TransportError {
    /// Underlying I/O error from TCP operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// BGP message encoding error.
    #[error("encode error: {0}")]
    Encode(#[from] rustbgpd_wire::EncodeError),

    /// Session shut down cleanly (not an error).
    #[error("clean shutdown")]
    Shutdown,
}
