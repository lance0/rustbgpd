/// RFC 4271 §4.5 — NOTIFICATION error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NotificationCode {
    MessageHeader = 1,
    OpenMessage = 2,
    UpdateMessage = 3,
    HoldTimerExpired = 4,
    FsmError = 5,
    Cease = 6,
}

impl NotificationCode {
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::MessageHeader),
            2 => Some(Self::OpenMessage),
            3 => Some(Self::UpdateMessage),
            4 => Some(Self::HoldTimerExpired),
            5 => Some(Self::FsmError),
            6 => Some(Self::Cease),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
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
    pub const OUT_OF_RESOURCES: u8 = 4;
    /// RFC 8538
    pub const HARD_RESET: u8 = 9;
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
        (NotificationCode::Cease, 4) => "Out of Resources",
        (NotificationCode::Cease, 9) => "Hard Reset",
        // Fallback
        (_, _) => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u8_roundtrip() {
        for code_val in 1..=6u8 {
            let code = NotificationCode::from_u8(code_val).unwrap();
            assert_eq!(code.as_u8(), code_val);
        }
    }

    #[test]
    fn from_u8_unknown() {
        assert!(NotificationCode::from_u8(0).is_none());
        assert!(NotificationCode::from_u8(7).is_none());
        assert!(NotificationCode::from_u8(255).is_none());
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
            assert!(!desc.is_empty(), "empty description for ({code}, {subcode})");
            assert_ne!(desc, "Unknown", "got Unknown for ({code}, {subcode})");
        }
    }
}
