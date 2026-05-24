//! Decode errors for BFD control packets.

use thiserror::Error;

/// Errors encountered while decoding a BFD control packet from bytes
/// (RFC 5880 §4.1). No path panics on malformed input.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Fewer bytes than the mandatory 24-byte control section.
    #[error("incomplete BFD packet: need {needed} bytes, have {available}")]
    Incomplete {
        /// Minimum bytes required.
        needed: usize,
        /// Bytes currently available.
        available: usize,
    },

    /// BFD version is not 1 (the only version this implementation supports).
    #[error("unsupported BFD version {version} (expected 1)")]
    UnsupportedVersion {
        /// The version received in the high 3 bits of byte 0.
        version: u8,
    },

    /// The `Length` field disagrees with the buffer.
    #[error("invalid BFD length {length} (have {available} bytes, minimum 24)")]
    InvalidLength {
        /// The `Length` field value from the wire.
        length: u8,
        /// Bytes actually available.
        available: usize,
    },

    /// `Detect Mult` is zero, which RFC 5880 §6.8.6 requires to be discarded.
    #[error("detect multiplier must be non-zero")]
    ZeroDetectMult,

    /// `My Discriminator` is zero, which RFC 5880 §6.8.6 requires to be
    /// discarded.
    #[error("my-discriminator must be non-zero")]
    ZeroMyDiscriminator,

    /// The Multipoint (`M`) bit is set; this implementation is point-to-point
    /// only and RFC 5880 §6.8.6 requires discarding such packets.
    #[error("multipoint bit set (unsupported)")]
    MultipointSet,
}
