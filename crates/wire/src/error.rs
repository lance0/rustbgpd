use bytes::{BufMut, Bytes, BytesMut};
use thiserror::Error;

use crate::notification::NotificationCode;

/// Errors encountered while decoding a BGP message from bytes.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    #[error("incomplete message: need {needed} bytes, have {available}")]
    Incomplete { needed: usize, available: usize },

    #[error("invalid header marker")]
    InvalidMarker,

    #[error("invalid message length {length} (must be 19..=4096)")]
    InvalidLength { length: u16 },

    #[error("unknown message type {0}")]
    UnknownMessageType(u8),

    #[error("unsupported BGP version {version} (expected 4)")]
    UnsupportedVersion { version: u8 },

    #[error("invalid keepalive length {length} (expected 19)")]
    InvalidKeepaliveLength { length: u16 },

    #[error("{message_type}: {detail}")]
    MalformedField {
        message_type: &'static str,
        detail: String,
    },

    #[error("malformed optional parameter at offset {offset}: {detail}")]
    MalformedOptionalParameter { offset: usize, detail: String },

    #[error("UPDATE length mismatch: {detail}")]
    UpdateLengthMismatch { detail: String },

    #[error("UPDATE attribute error (subcode {subcode}): {detail}")]
    UpdateAttributeError {
        subcode: u8,
        data: Vec<u8>,
        detail: String,
    },

    #[error("UPDATE invalid network field: {detail}")]
    InvalidNetworkField { detail: String, data: Vec<u8> },
}

/// Errors encountered while encoding a BGP message to bytes.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    #[error("message exceeds maximum size: {size} bytes (max 4096)")]
    MessageTooLong { size: usize },

    #[error("{field}: value {value} out of range")]
    ValueOutOfRange { field: &'static str, value: String },
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
