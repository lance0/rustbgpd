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

    /// Bulk outbound channel to the writer task is full (peer hasn't
    /// drained `OUTBOUND_BUFFER` BGP messages). Saturation handler in
    /// the session task converts this into a `Cease/8` (Out of
    /// Resources, RFC 4486 §4 subcode 8) NOTIFICATION + session
    /// teardown.
    #[error("outbound writer channel saturated")]
    OutboundChannelFull,

    /// The writer task is no longer reachable — TCP write half closed
    /// (peer disconnected, write error, etc.). Equivalent in effect to
    /// "not connected"; the session FSM transitions through the
    /// existing TCP-disconnect path.
    #[error("writer task unavailable")]
    WriterClosed,

    /// Session shut down cleanly (not an error).
    #[error("clean shutdown")]
    Shutdown,
}
