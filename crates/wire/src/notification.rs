/// RFC 4271 §4.5 — NOTIFICATION error codes.
///
/// Known codes (1–6) have named variants. Unknown codes from the wire are
/// preserved via `Unknown(u8)` so the original byte is never lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotificationCode {
    MessageHeader,
    OpenMessage,
    UpdateMessage,
    HoldTimerExpired,
    FsmError,
    Cease,
    /// A code value not defined in RFC 4271. The raw byte is preserved
    /// for logging and re-encoding.
    Unknown(u8),
}

impl NotificationCode {
    #[must_use]
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::MessageHeader,
            2 => Self::OpenMessage,
            3 => Self::UpdateMessage,
            4 => Self::HoldTimerExpired,
            5 => Self::FsmError,
            6 => Self::Cease,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::MessageHeader => 1,
            Self::OpenMessage => 2,
            Self::UpdateMessage => 3,
            Self::HoldTimerExpired => 4,
            Self::FsmError => 5,
            Self::Cease => 6,
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
            Self::Unknown(code) => write!(f, "Unknown({code})"),
        }
    }
}

/// Message Header Error subcodes (code 1).
pub mod header_subcode {
    pub const CONNECTION_NOT_SYNCHRONIZED: u8 = 1;
    pub const BAD_MESSAGE_LENGTH: u8 = 2;
    pub const BAD_MESSAGE_TYPE: u8 = 3;
}

/// OPEN Message Error subcodes (code 2).
pub mod open_subcode {
    pub const UNSUPPORTED_VERSION: u8 = 1;
    pub const BAD_PEER_AS: u8 = 2;
    pub const BAD_BGP_IDENTIFIER: u8 = 3;
    pub const UNSUPPORTED_OPTIONAL_PARAMETER: u8 = 4;
    // subcode 5 deprecated (Authentication Failure)
    pub const UNACCEPTABLE_HOLD_TIME: u8 = 6;
    /// RFC 5492
    pub const UNSUPPORTED_CAPABILITY: u8 = 7;
}

/// UPDATE Message Error subcodes (code 3).
pub mod update_subcode {
    pub const MALFORMED_ATTRIBUTE_LIST: u8 = 1;
    pub const UNRECOGNIZED_WELLKNOWN: u8 = 2;
    pub const MISSING_WELLKNOWN: u8 = 3;
    pub const ATTRIBUTE_FLAGS_ERROR: u8 = 4;
    pub const ATTRIBUTE_LENGTH_ERROR: u8 = 5;
    pub const INVALID_ORIGIN: u8 = 6;
    // subcode 7 deprecated (AS Routing Loop)
    pub const INVALID_NEXT_HOP: u8 = 8;
    pub const OPTIONAL_ATTRIBUTE_ERROR: u8 = 9;
    pub const INVALID_NETWORK_FIELD: u8 = 10;
    pub const MALFORMED_AS_PATH: u8 = 11;
}

/// Cease subcodes (code 6, RFC 4486).
pub mod cease_subcode {
    pub const MAX_PREFIXES: u8 = 1;
    pub const ADMINISTRATIVE_SHUTDOWN: u8 = 2;
    pub const PEER_DECONFIGURED: u8 = 3;
    /// RFC 8203
    pub const ADMINISTRATIVE_RESET: u8 = 4;
    pub const OUT_OF_RESOURCES: u8 = 8;
    /// RFC 4271 §6.8
    pub const CONNECTION_COLLISION_RESOLUTION: u8 = 7;
    /// RFC 8538
    pub const HARD_RESET: u8 = 9;
}

/// Encode a shutdown communication reason string (RFC 8203).
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
    #[expect(clippy::cast_possible_truncation)]
    let len = truncated.len() as u8;
    let mut buf = Vec::with_capacity(1 + truncated.len());
    buf.push(len);
    buf.extend_from_slice(truncated.as_bytes());
    bytes::Bytes::from(buf)
}

/// Decode a shutdown communication reason string from NOTIFICATION data (RFC 8203).
///
/// Returns `None` if the data is empty or the length prefix is inconsistent.
/// Extra trailing bytes after the declared shutdown-communication string are ignored.
/// Invalid UTF-8 is replaced with the Unicode replacement character.
#[must_use]
pub fn decode_shutdown_communication(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    let len = data[0] as usize;
    if data.len() < 1 + len {
        return None;
    }
    let raw = &data[1..=len];
    Some(String::from_utf8_lossy(raw).into_owned())
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
        let decoded = decode_shutdown_communication(&data).unwrap();
        assert!(decoded.contains('\u{FFFD}')); // replacement char
    }

    #[test]
    fn shutdown_communication_ignores_trailing_bytes() {
        let data = [3, b'f', b'o', b'o', b'x'];
        assert_eq!(decode_shutdown_communication(&data).as_deref(), Some("foo"));
    }
}
