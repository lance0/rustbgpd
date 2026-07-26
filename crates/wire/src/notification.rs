/// RFC 4271 §4.5 — NOTIFICATION error codes.
///
/// Known codes (1–6) have named variants. Unknown codes from the wire are
/// preserved via `Unknown(u8)` so the original byte is never lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NotificationCode {
    /// Error in the message header (code 1).
    MessageHeader,
    /// Error in the OPEN message (code 2).
    OpenMessage,
    /// Error in the UPDATE message (code 3).
    UpdateMessage,
    /// Hold timer expired without receiving a KEEPALIVE or UPDATE (code 4).
    HoldTimerExpired,
    /// Finite state machine error (code 5).
    FsmError,
    /// Administrative or resource-related session termination (code 6).
    Cease,
    /// Send Hold Timer expired: the local system could not hand outbound
    /// BGP data to the peer within the `SendHoldTime` (code 8, RFC 9687 §5;
    /// subcode is always 0 per §6).
    SendHoldTimerExpired,
    /// A code value not defined in RFC 4271. The raw byte is preserved
    /// for logging and re-encoding.
    Unknown(u8),
}

impl NotificationCode {
    /// Create from a raw code byte, mapping known values to named variants.
    #[must_use]
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::MessageHeader,
            2 => Self::OpenMessage,
            3 => Self::UpdateMessage,
            4 => Self::HoldTimerExpired,
            5 => Self::FsmError,
            6 => Self::Cease,
            8 => Self::SendHoldTimerExpired,
            other => Self::Unknown(other),
        }
    }

    /// Return the raw byte value for this error code.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::MessageHeader => 1,
            Self::OpenMessage => 2,
            Self::UpdateMessage => 3,
            Self::HoldTimerExpired => 4,
            Self::FsmError => 5,
            Self::Cease => 6,
            Self::SendHoldTimerExpired => 8,
            Self::Unknown(v) => v,
        }
    }
}

impl std::fmt::Display for NotificationCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MessageHeader => write!(f, "Message Header Error"),
            Self::OpenMessage => write!(f, "OPEN Message Error"),
            Self::UpdateMessage => write!(f, "UPDATE Message Error"),
            Self::HoldTimerExpired => write!(f, "Hold Timer Expired"),
            Self::FsmError => write!(f, "Finite State Machine Error"),
            Self::Cease => write!(f, "Cease"),
            Self::SendHoldTimerExpired => write!(f, "Send Hold Timer Expired"),
            Self::Unknown(code) => write!(f, "Unknown({code})"),
        }
    }
}

/// Message Header Error subcodes (code 1).
pub mod header_subcode {
    /// Subcode 1: Connection Not Synchronized.
    pub const CONNECTION_NOT_SYNCHRONIZED: u8 = 1;
    /// Subcode 2: Bad Message Length.
    pub const BAD_MESSAGE_LENGTH: u8 = 2;
    /// Subcode 3: Bad Message Type.
    pub const BAD_MESSAGE_TYPE: u8 = 3;
}

/// OPEN Message Error subcodes (code 2).
pub mod open_subcode {
    /// Subcode 1: Unsupported Version Number.
    pub const UNSUPPORTED_VERSION: u8 = 1;
    /// Subcode 2: Bad Peer AS.
    pub const BAD_PEER_AS: u8 = 2;
    /// Subcode 3: Bad BGP Identifier.
    pub const BAD_BGP_IDENTIFIER: u8 = 3;
    /// Subcode 4: Unsupported Optional Parameter.
    pub const UNSUPPORTED_OPTIONAL_PARAMETER: u8 = 4;
    // subcode 5 deprecated (Authentication Failure)
    /// Subcode 6: Unacceptable Hold Time.
    pub const UNACCEPTABLE_HOLD_TIME: u8 = 6;
    /// Subcode 7: Unsupported Capability (RFC 5492).
    pub const UNSUPPORTED_CAPABILITY: u8 = 7;
    /// Subcode 11: Role Mismatch (RFC 9234 §4.2).
    pub const ROLE_MISMATCH: u8 = 11;
}

/// UPDATE Message Error subcodes (code 3).
pub mod update_subcode {
    /// Subcode 1: Malformed Attribute List.
    pub const MALFORMED_ATTRIBUTE_LIST: u8 = 1;
    /// Subcode 2: Unrecognized Well-known Attribute.
    pub const UNRECOGNIZED_WELLKNOWN: u8 = 2;
    /// Subcode 3: Missing Well-known Attribute.
    pub const MISSING_WELLKNOWN: u8 = 3;
    /// Subcode 4: Attribute Flags Error.
    pub const ATTRIBUTE_FLAGS_ERROR: u8 = 4;
    /// Subcode 5: Attribute Length Error.
    pub const ATTRIBUTE_LENGTH_ERROR: u8 = 5;
    /// Subcode 6: Invalid `ORIGIN` Attribute.
    pub const INVALID_ORIGIN: u8 = 6;
    // subcode 7 deprecated (AS Routing Loop)
    /// Subcode 8: Invalid `NEXT_HOP` Attribute.
    pub const INVALID_NEXT_HOP: u8 = 8;
    /// Subcode 9: Optional Attribute Error.
    pub const OPTIONAL_ATTRIBUTE_ERROR: u8 = 9;
    /// Subcode 10: Invalid Network Field.
    pub const INVALID_NETWORK_FIELD: u8 = 10;
    /// Subcode 11: Malformed `AS_PATH`.
    pub const MALFORMED_AS_PATH: u8 = 11;
}

/// Cease subcodes (code 6, RFC 4486).
pub mod cease_subcode {
    /// Subcode 1: Maximum Number of Prefixes Reached.
    pub const MAX_PREFIXES: u8 = 1;
    /// Subcode 2: Administrative Shutdown (RFC 9003).
    pub const ADMINISTRATIVE_SHUTDOWN: u8 = 2;
    /// Subcode 3: Peer De-configured.
    pub const PEER_DECONFIGURED: u8 = 3;
    /// Subcode 4: Administrative Reset (RFC 9003).
    pub const ADMINISTRATIVE_RESET: u8 = 4;
    /// Subcode 8: Out of Resources.
    pub const OUT_OF_RESOURCES: u8 = 8;
    /// RFC 4271 §6.8
    pub const CONNECTION_COLLISION_RESOLUTION: u8 = 7;
    /// RFC 8538
    pub const HARD_RESET: u8 = 9;
}

/// Encode a shutdown communication reason string (RFC 9003).
///
/// The format is: 1-byte length prefix + UTF-8 string, max 128 bytes.
/// If the reason exceeds 128 bytes, it is truncated at a char boundary.
/// An empty reason encodes as a zero-length field (`[0]`).
#[must_use]
pub fn encode_shutdown_communication(reason: &str) -> bytes::Bytes {
    // Truncate to at most 128 bytes at a char boundary
    let mut end = reason.len().min(128);
    while end > 0 && !reason.is_char_boundary(end) {
        end -= 1;
    }
    let truncated = &reason[..end];
    // Safe: end ≤ 128, which always fits in u8.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "codec bounds or masks the value before narrowing to the protocol field width"
    )]
    let len = truncated.len() as u8;
    let mut buf = Vec::with_capacity(1 + truncated.len());
    buf.push(len);
    buf.extend_from_slice(truncated.as_bytes());
    bytes::Bytes::from(buf)
}

/// A bounded reason why an RFC 9003 shutdown communication was not decoded.
///
/// The variants intentionally classify malformed input without retaining or
/// formatting attacker-controlled bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ShutdownCommunicationError {
    /// The length octet is absent or does not consume the complete data field.
    InvalidLength,
    /// The declared communication is not valid UTF-8.
    InvalidUtf8,
    /// An RFC 8538 Hard Reset does not contain its inner code and subcode.
    MalformedHardResetEnvelope,
}

impl ShutdownCommunicationError {
    /// Return a stable, bounded category suitable for structured logs.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::InvalidLength => "invalid_length",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::MalformedHardResetEnvelope => "malformed_hard_reset_envelope",
        }
    }
}

/// Decode a shutdown communication reason string from NOTIFICATION data (RFC 9003).
///
/// Returns `None` unless the length-prefixed field consumes all of `data` and
/// contains valid UTF-8. RFC 9003 requires malformed data to remain
/// uninterpreted rather than exposing a partial or replacement-character
/// reason.
#[must_use]
pub fn decode_shutdown_communication(data: &[u8]) -> Option<String> {
    decode_shutdown_communication_strict(data)
        .ok()
        .map(str::to_owned)
}

fn decode_shutdown_communication_strict(data: &[u8]) -> Result<&str, ShutdownCommunicationError> {
    let (&declared_len, reason) = data
        .split_first()
        .ok_or(ShutdownCommunicationError::InvalidLength)?;
    if reason.len() != usize::from(declared_len) {
        return Err(ShutdownCommunicationError::InvalidLength);
    }
    std::str::from_utf8(reason).map_err(|_| ShutdownCommunicationError::InvalidUtf8)
}

/// Extract an RFC 9003 shutdown communication from a complete NOTIFICATION.
///
/// Administrative Shutdown and Administrative Reset carry the
/// length-prefixed field directly. RFC 8538 Hard Reset carries exactly one
/// encapsulated NOTIFICATION tuple (`code`, `subcode`, `data`); only an
/// encapsulated Administrative Shutdown or Administrative Reset is eligible.
/// Nested Hard Reset envelopes and malformed shutdown data are not
/// interpreted.
///
/// # Errors
///
/// Returns [`ShutdownCommunicationError`] when an eligible direct or
/// encapsulated communication has inconsistent length, invalid UTF-8, or an
/// incomplete RFC 8538 envelope.
pub fn extract_shutdown_communication(
    notification: &crate::NotificationMessage,
) -> Result<Option<&str>, ShutdownCommunicationError> {
    if notification.code != NotificationCode::Cease {
        return Ok(None);
    }

    let communication_data = match notification.subcode {
        cease_subcode::ADMINISTRATIVE_SHUTDOWN | cease_subcode::ADMINISTRATIVE_RESET => {
            notification.data.as_ref()
        }
        cease_subcode::HARD_RESET => {
            let Some((&inner_code, encapsulated)) = notification.data.split_first() else {
                return Err(ShutdownCommunicationError::MalformedHardResetEnvelope);
            };
            let Some((&inner_subcode, inner_data)) = encapsulated.split_first() else {
                return Err(ShutdownCommunicationError::MalformedHardResetEnvelope);
            };
            if NotificationCode::from_u8(inner_code) != NotificationCode::Cease
                || !matches!(
                    inner_subcode,
                    cease_subcode::ADMINISTRATIVE_SHUTDOWN | cease_subcode::ADMINISTRATIVE_RESET
                )
            {
                return Ok(None);
            }
            inner_data
        }
        _ => return Ok(None),
    };

    // RFC 9003 makes the communication optional. A bare administrative
    // NOTIFICATION has no communication field; an explicit `[0]` remains a
    // present, empty communication for compatibility with the public decoder.
    if communication_data.is_empty() {
        return Ok(None);
    }
    decode_shutdown_communication_strict(communication_data).map(Some)
}

/// Human-readable description for a NOTIFICATION code/subcode pair.
#[must_use]
pub fn description(code: NotificationCode, subcode: u8) -> &'static str {
    match (code, subcode) {
        // Message Header Error
        (NotificationCode::MessageHeader, 1) => "Connection Not Synchronized",
        (NotificationCode::MessageHeader, 2) => "Bad Message Length",
        (NotificationCode::MessageHeader, 3) => "Bad Message Type",
        // OPEN Message Error
        (NotificationCode::OpenMessage, 1) => "Unsupported Version Number",
        (NotificationCode::OpenMessage, 2) => "Bad Peer AS",
        (NotificationCode::OpenMessage, 3) => "Bad BGP Identifier",
        (NotificationCode::OpenMessage, 4) => "Unsupported Optional Parameter",
        (NotificationCode::OpenMessage, 6) => "Unacceptable Hold Time",
        (NotificationCode::OpenMessage, 7) => "Unsupported Capability",
        (NotificationCode::OpenMessage, 11) => "Role Mismatch",
        // UPDATE Message Error
        (NotificationCode::UpdateMessage, 1) => "Malformed Attribute List",
        (NotificationCode::UpdateMessage, 2) => "Unrecognized Well-known Attribute",
        (NotificationCode::UpdateMessage, 3) => "Missing Well-known Attribute",
        (NotificationCode::UpdateMessage, 4) => "Attribute Flags Error",
        (NotificationCode::UpdateMessage, 5) => "Attribute Length Error",
        (NotificationCode::UpdateMessage, 6) => "Invalid ORIGIN Attribute",
        (NotificationCode::UpdateMessage, 8) => "Invalid NEXT_HOP Attribute",
        (NotificationCode::UpdateMessage, 9) => "Optional Attribute Error",
        (NotificationCode::UpdateMessage, 10) => "Invalid Network Field",
        (NotificationCode::UpdateMessage, 11) => "Malformed AS_PATH",
        // Hold Timer Expired
        (NotificationCode::HoldTimerExpired, _) => "Hold Timer Expired",
        // Send Hold Timer Expired (RFC 9687 §5/§6, subcode always 0)
        (NotificationCode::SendHoldTimerExpired, _) => "Send Hold Timer Expired",
        // FSM Error
        (NotificationCode::FsmError, _) => "Finite State Machine Error",
        // Cease
        (NotificationCode::Cease, 1) => "Maximum Number of Prefixes Reached",
        (NotificationCode::Cease, 2) => "Administrative Shutdown",
        (NotificationCode::Cease, 3) => "Peer De-configured",
        (NotificationCode::Cease, 4) => "Administrative Reset",
        (NotificationCode::Cease, 8) => "Out of Resources",
        (NotificationCode::Cease, 7) => "Connection Collision Resolution",
        (NotificationCode::Cease, 9) => "Hard Reset",
        // Unknown code
        (NotificationCode::Unknown(_), _) => "Unknown Error Code",
        // Fallback for known code with unknown subcode
        (_, _) => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u8_roundtrip() {
        for code_val in 1..=6u8 {
            let code = NotificationCode::from_u8(code_val);
            assert_eq!(code.as_u8(), code_val);
            assert!(!matches!(code, NotificationCode::Unknown(_)));
        }
    }

    #[test]
    fn from_u8_unknown_preserved() {
        assert_eq!(NotificationCode::from_u8(0), NotificationCode::Unknown(0));
        assert_eq!(NotificationCode::from_u8(7), NotificationCode::Unknown(7));
        assert_eq!(
            NotificationCode::from_u8(255),
            NotificationCode::Unknown(255)
        );
        // Raw byte survives roundtrip
        assert_eq!(NotificationCode::from_u8(42).as_u8(), 42);
    }

    #[test]
    fn description_returns_nonempty_for_known_pairs() {
        let pairs = [
            (NotificationCode::MessageHeader, 1),
            (NotificationCode::MessageHeader, 2),
            (NotificationCode::MessageHeader, 3),
            (NotificationCode::OpenMessage, 1),
            (NotificationCode::OpenMessage, 6),
            (NotificationCode::UpdateMessage, 1),
            (NotificationCode::UpdateMessage, 11),
            (NotificationCode::Cease, 2),
            (NotificationCode::Cease, 4),
        ];
        for (code, subcode) in pairs {
            let desc = description(code, subcode);
            assert!(
                !desc.is_empty(),
                "empty description for ({code}, {subcode})"
            );
            assert_ne!(desc, "Unknown", "got Unknown for ({code}, {subcode})");
        }
    }

    #[test]
    fn shutdown_communication_roundtrip() {
        let reason = "maintenance window";
        let encoded = encode_shutdown_communication(reason);
        assert_eq!(encoded[0] as usize, reason.len());
        let decoded = decode_shutdown_communication(&encoded).unwrap();
        assert_eq!(decoded, reason);
    }

    #[test]
    fn shutdown_communication_empty() {
        let encoded = encode_shutdown_communication("");
        assert_eq!(encoded.as_ref(), &[0]);
        assert_eq!(decode_shutdown_communication(&encoded).as_deref(), Some(""));
        assert_eq!(decode_shutdown_communication(&[]), None);
    }

    #[test]
    fn shutdown_communication_truncates_at_128() {
        let long = "a".repeat(200);
        let encoded = encode_shutdown_communication(&long);
        assert_eq!(encoded[0], 128);
        assert_eq!(encoded.len(), 129);
        let decoded = decode_shutdown_communication(&encoded).unwrap();
        assert_eq!(decoded.len(), 128);
    }

    /// Load-bearing RFC 9003 compatibility proof: imposing the encoder's
    /// conservative 128-octet interoperability cap on received communications
    /// makes both assertions reject a standards-valid 255-octet field.
    #[test]
    fn shutdown_communication_accepts_255_octets_on_receive() {
        let reason = "a".repeat(255);
        let mut data = Vec::with_capacity(256);
        data.push(255);
        data.extend_from_slice(reason.as_bytes());

        assert_eq!(
            decode_shutdown_communication(&data).as_deref(),
            Some(reason.as_str())
        );
        let notification = crate::NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::ADMINISTRATIVE_SHUTDOWN,
            data.into(),
        );
        assert_eq!(
            extract_shutdown_communication(&notification),
            Ok(Some(reason.as_str()))
        );
    }

    #[test]
    fn shutdown_communication_truncates_at_char_boundary() {
        // 'é' is 2 bytes in UTF-8. Fill 127 bytes + 'é' = 129 bytes total → truncate
        let reason = format!("{}é", "x".repeat(127));
        assert_eq!(reason.len(), 129);
        let encoded = encode_shutdown_communication(&reason);
        // Should truncate to 127 bytes (before the multi-byte char)
        assert_eq!(encoded[0], 127);
        let decoded = decode_shutdown_communication(&encoded).unwrap();
        assert_eq!(decoded, "x".repeat(127));
    }

    #[test]
    fn shutdown_communication_invalid_utf8() {
        // Length 3 + 3 bytes of invalid UTF-8
        let data = [3, 0xff, 0xfe, 0xfd];
        assert_eq!(decode_shutdown_communication(&data), None);
    }

    #[test]
    fn shutdown_communication_rejects_trailing_bytes() {
        let data = [3, b'f', b'o', b'o', b'x'];
        assert_eq!(decode_shutdown_communication(&data), None);
    }

    /// Load-bearing RFC 9003 proof: accepting a prefix instead of the complete
    /// length-delimited field makes the trailing-byte cases return a reason;
    /// lossy UTF-8 decoding makes the invalid-byte cases return invented text.
    #[test]
    fn shutdown_communication_rejects_every_malformed_field_shape() {
        for data in [
            &[][..],
            &[1][..],
            &[2, b'a'][..],
            &[0, b'x'][..],
            &[1, b'x', b'y'][..],
            &[1, 0xff][..],
        ] {
            assert_eq!(
                decode_shutdown_communication(data),
                None,
                "malformed field must remain uninterpreted: {data:?}"
            );
        }
    }

    /// Load-bearing RFC 9003/RFC 8538 proof: removing either direct subcode,
    /// accepting a second Hard Reset envelope, or dropping the single-envelope
    /// branch changes one of these exact results.
    #[test]
    fn shutdown_communication_extractor_accepts_direct_and_one_hard_reset_envelope() {
        for subcode in [
            cease_subcode::ADMINISTRATIVE_SHUTDOWN,
            cease_subcode::ADMINISTRATIVE_RESET,
        ] {
            let direct = crate::NotificationMessage::new(
                NotificationCode::Cease,
                subcode,
                encode_shutdown_communication("planned work"),
            );
            assert_eq!(
                extract_shutdown_communication(&direct),
                Ok(Some("planned work"))
            );

            let mut hard_reset_data = vec![NotificationCode::Cease.as_u8(), subcode];
            hard_reset_data.extend_from_slice(&encode_shutdown_communication("planned work"));
            let hard_reset = crate::NotificationMessage::new(
                NotificationCode::Cease,
                cease_subcode::HARD_RESET,
                hard_reset_data.into(),
            );
            assert_eq!(
                extract_shutdown_communication(&hard_reset),
                Ok(Some("planned work"))
            );
        }

        let empty_direct = crate::NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::ADMINISTRATIVE_SHUTDOWN,
            bytes::Bytes::from_static(&[0]),
        );
        assert_eq!(extract_shutdown_communication(&empty_direct), Ok(Some("")));
        let empty_hard_reset = crate::NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::HARD_RESET,
            bytes::Bytes::from_static(&[6, cease_subcode::ADMINISTRATIVE_RESET, 0]),
        );
        assert_eq!(
            extract_shutdown_communication(&empty_hard_reset),
            Ok(Some(""))
        );

        let nested = crate::NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::HARD_RESET,
            bytes::Bytes::from_static(&[
                6,
                cease_subcode::HARD_RESET,
                6,
                cease_subcode::ADMINISTRATIVE_SHUTDOWN,
                1,
                b'x',
            ]),
        );
        assert_eq!(extract_shutdown_communication(&nested), Ok(None));
    }

    /// Load-bearing eligibility proof: widening either the outer or
    /// encapsulated code/subcode check turns one of these non-administrative
    /// notifications into shutdown communication.
    #[test]
    fn shutdown_communication_extractor_rejects_ineligible_notifications() {
        let reason = encode_shutdown_communication("not administrative");
        for notification in [
            crate::NotificationMessage::new(
                NotificationCode::OpenMessage,
                cease_subcode::ADMINISTRATIVE_SHUTDOWN,
                reason.clone(),
            ),
            crate::NotificationMessage::new(
                NotificationCode::Cease,
                cease_subcode::OUT_OF_RESOURCES,
                reason.clone(),
            ),
            crate::NotificationMessage::new(
                NotificationCode::Cease,
                cease_subcode::HARD_RESET,
                bytes::Bytes::from_static(&[2, cease_subcode::ADMINISTRATIVE_SHUTDOWN, 1, b'x']),
            ),
            crate::NotificationMessage::new(
                NotificationCode::Cease,
                cease_subcode::HARD_RESET,
                bytes::Bytes::from_static(&[6, cease_subcode::OUT_OF_RESOURCES, 1, b'x']),
            ),
        ] {
            assert_eq!(extract_shutdown_communication(&notification), Ok(None));
        }
    }

    /// Load-bearing typed-error proof: collapsing errors into absence, accepting
    /// a prefix, using lossy UTF-8, or treating a short RFC 8538 tuple as a
    /// complete envelope changes the corresponding exact error category.
    #[test]
    fn shutdown_communication_extractor_classifies_malformed_input() {
        for data in [
            bytes::Bytes::from_static(&[2, b'x']),
            bytes::Bytes::from_static(&[1, b'x', b'y']),
        ] {
            let notification = crate::NotificationMessage::new(
                NotificationCode::Cease,
                cease_subcode::ADMINISTRATIVE_SHUTDOWN,
                data,
            );
            assert_eq!(
                extract_shutdown_communication(&notification),
                Err(ShutdownCommunicationError::InvalidLength)
            );
        }

        let invalid_utf8 = crate::NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::ADMINISTRATIVE_RESET,
            bytes::Bytes::from_static(&[1, 0xff]),
        );
        assert_eq!(
            extract_shutdown_communication(&invalid_utf8),
            Err(ShutdownCommunicationError::InvalidUtf8)
        );

        for data in [
            bytes::Bytes::new(),
            bytes::Bytes::from(vec![NotificationCode::Cease.as_u8()]),
        ] {
            let hard_reset = crate::NotificationMessage::new(
                NotificationCode::Cease,
                cease_subcode::HARD_RESET,
                data,
            );
            assert_eq!(
                extract_shutdown_communication(&hard_reset),
                Err(ShutdownCommunicationError::MalformedHardResetEnvelope)
            );
        }

        assert_eq!(
            ShutdownCommunicationError::InvalidLength.category(),
            "invalid_length"
        );
        assert_eq!(
            ShutdownCommunicationError::InvalidUtf8.category(),
            "invalid_utf8"
        );
        assert_eq!(
            ShutdownCommunicationError::MalformedHardResetEnvelope.category(),
            "malformed_hard_reset_envelope"
        );
    }
}
