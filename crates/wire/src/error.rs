use bytes::{BufMut, Bytes, BytesMut};
use thiserror::Error;

use crate::notification::NotificationCode;

/// Errors encountered while decoding a BGP message from bytes.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Not enough bytes are available to decode the message.
    #[error("incomplete message: need {needed} bytes, have {available}")]
    Incomplete {
        /// Minimum bytes required.
        needed: usize,
        /// Bytes currently available.
        available: usize,
    },

    /// The 16-byte header marker is not all `0xFF`.
    #[error("invalid header marker")]
    InvalidMarker,

    /// Message length field is outside the valid range.
    #[error("invalid message length {length} (must be 19..=4096)")]
    InvalidLength {
        /// The invalid length value from the wire.
        length: u16,
    },

    /// Message type byte is not a known BGP message type.
    #[error("unknown message type {0}")]
    UnknownMessageType(
        /// The unrecognized type byte.
        u8,
    ),

    /// BGP version in OPEN is not 4.
    #[error("unsupported BGP version {version} (expected 4)")]
    UnsupportedVersion {
        /// The version number received.
        version: u8,
    },

    /// KEEPALIVE message has an invalid length (must be exactly 19).
    #[error("invalid keepalive length {length} (expected 19)")]
    InvalidKeepaliveLength {
        /// The invalid length value.
        length: u16,
    },

    /// A field within the message body is structurally invalid.
    #[error("{message_type}: {detail}")]
    MalformedField {
        /// Which message type contained the error.
        message_type: &'static str,
        /// Human-readable description of the malformation.
        detail: String,
    },

    /// An optional parameter in OPEN is malformed.
    #[error("malformed optional parameter at offset {offset}: {detail}")]
    MalformedOptionalParameter {
        /// Byte offset within the optional parameters.
        offset: usize,
        /// Human-readable description of the error.
        detail: String,
    },

    /// UPDATE withdrawn/attribute/NLRI length fields are inconsistent.
    #[error("UPDATE length mismatch: {detail}")]
    UpdateLengthMismatch {
        /// Human-readable description of the mismatch.
        detail: String,
    },

    /// UPDATE attribute fails RFC 4271 §6.3 validation.
    #[error("UPDATE attribute error (subcode {subcode}): {detail}")]
    UpdateAttributeError {
        /// NOTIFICATION subcode for this error.
        subcode: u8,
        /// Raw attribute bytes for the NOTIFICATION data field.
        data: Vec<u8>,
        /// Human-readable description of the error.
        detail: String,
    },

    /// NLRI prefix encoding is invalid (RFC 4271 §4.3).
    #[error("UPDATE invalid network field: {detail}")]
    InvalidNetworkField {
        /// Human-readable description of the error.
        detail: String,
        /// Raw NLRI bytes for the NOTIFICATION data field.
        data: Vec<u8>,
    },
}

/// Errors encountered while encoding a BGP message to bytes.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// Encoded message exceeds the maximum BGP message size.
    #[error("message exceeds maximum size: {size} bytes (max 4096)")]
    MessageTooLong {
        /// Total encoded size in bytes.
        size: usize,
    },

    /// A field value is outside its valid range for encoding.
    #[error("{field}: value {value} out of range")]
    ValueOutOfRange {
        /// Name of the field that is out of range.
        field: &'static str,
        /// String representation of the invalid value.
        value: String,
    },
}

impl DecodeError {
    /// Returns the NOTIFICATION (code, subcode, data) that should be sent
    /// to the peer when this decode error is encountered.
    #[must_use]
    pub fn to_notification(&self) -> (NotificationCode, u8, Bytes) {
        match self {
            Self::InvalidMarker => (
                NotificationCode::MessageHeader,
                1, // Connection Not Synchronized
                Bytes::new(),
            ),
            Self::InvalidLength { length } => {
                let mut data = BytesMut::with_capacity(2);
                data.put_u16(*length);
                (
                    NotificationCode::MessageHeader,
                    2, // Bad Message Length
                    data.freeze(),
                )
            }
            Self::UnknownMessageType(t) => (
                NotificationCode::MessageHeader,
                3, // Bad Message Type
                Bytes::copy_from_slice(&[*t]),
            ),
            Self::UnsupportedVersion { .. } => {
                let mut data = BytesMut::with_capacity(2);
                data.put_u16(4); // supported version
                (
                    NotificationCode::OpenMessage,
                    1, // Unsupported Version Number
                    data.freeze(),
                )
            }
            Self::InvalidKeepaliveLength { .. } | Self::Incomplete { .. } => (
                NotificationCode::MessageHeader,
                2, // Bad Message Length
                Bytes::new(),
            ),
            Self::MalformedField { message_type, .. } if *message_type == "UPDATE" => (
                NotificationCode::UpdateMessage,
                1, // Malformed Attribute List
                Bytes::new(),
            ),
            Self::MalformedField { .. } | Self::MalformedOptionalParameter { .. } => {
                (NotificationCode::OpenMessage, 0, Bytes::new())
            }
            Self::UpdateLengthMismatch { .. } => (
                NotificationCode::UpdateMessage,
                1, // Malformed Attribute List
                Bytes::new(),
            ),
            Self::UpdateAttributeError { subcode, data, .. } => (
                NotificationCode::UpdateMessage,
                *subcode,
                Bytes::from(data.clone()),
            ),
            Self::InvalidNetworkField { data, .. } => (
                NotificationCode::UpdateMessage,
                10, // Invalid Network Field
                Bytes::from(data.clone()),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_marker_maps_to_header_error() {
        let (code, subcode, _) = DecodeError::InvalidMarker.to_notification();
        assert_eq!(code, NotificationCode::MessageHeader);
        assert_eq!(subcode, 1);
    }

    #[test]
    fn invalid_length_maps_to_bad_message_length() {
        let err = DecodeError::InvalidLength { length: 5000 };
        let (code, subcode, data) = err.to_notification();
        assert_eq!(code, NotificationCode::MessageHeader);
        assert_eq!(subcode, 2);
        assert_eq!(data.as_ref(), &5000u16.to_be_bytes());
    }

    #[test]
    fn unknown_type_maps_to_bad_message_type() {
        let err = DecodeError::UnknownMessageType(99);
        let (code, subcode, data) = err.to_notification();
        assert_eq!(code, NotificationCode::MessageHeader);
        assert_eq!(subcode, 3);
        assert_eq!(data.as_ref(), &[99]);
    }

    #[test]
    fn unsupported_version_maps_to_open_error() {
        let err = DecodeError::UnsupportedVersion { version: 3 };
        let (code, subcode, data) = err.to_notification();
        assert_eq!(code, NotificationCode::OpenMessage);
        assert_eq!(subcode, 1);
        assert_eq!(data.as_ref(), &4u16.to_be_bytes());
    }

    #[test]
    fn update_length_mismatch_maps_to_update_error() {
        let err = DecodeError::UpdateLengthMismatch {
            detail: "test".into(),
        };
        let (code, subcode, _) = err.to_notification();
        assert_eq!(code, NotificationCode::UpdateMessage);
        assert_eq!(subcode, 1);
    }

    #[test]
    fn update_malformed_field_maps_to_update_error() {
        let err = DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: "invalid ORIGIN value 5".into(),
        };
        let (code, subcode, _) = err.to_notification();
        assert_eq!(code, NotificationCode::UpdateMessage);
        assert_eq!(subcode, 1);
    }

    #[test]
    fn update_attribute_error_maps_correctly() {
        let err = DecodeError::UpdateAttributeError {
            subcode: 6,
            data: vec![0x40, 0x01, 0x01, 0x05],
            detail: "invalid ORIGIN value 5".into(),
        };
        let (code, subcode, data) = err.to_notification();
        assert_eq!(code, NotificationCode::UpdateMessage);
        assert_eq!(subcode, 6);
        assert_eq!(data.as_ref(), &[0x40, 0x01, 0x01, 0x05]);
    }

    #[test]
    fn invalid_network_field_maps_to_subcode_10() {
        let err = DecodeError::InvalidNetworkField {
            detail: "NLRI prefix length 33 exceeds 32".into(),
            data: vec![33, 10, 0, 0, 0],
        };
        let (code, subcode, data) = err.to_notification();
        assert_eq!(code, NotificationCode::UpdateMessage);
        assert_eq!(subcode, 10);
        // Data includes the offending length byte + address bytes
        assert_eq!(data.as_ref(), &[33, 10, 0, 0, 0]);
    }

    #[test]
    fn open_malformed_field_maps_to_open_error() {
        let err = DecodeError::MalformedField {
            message_type: "OPEN",
            detail: "test".into(),
        };
        let (code, subcode, _) = err.to_notification();
        assert_eq!(code, NotificationCode::OpenMessage);
        assert_eq!(subcode, 0);
    }
}
