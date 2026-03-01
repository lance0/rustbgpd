/// The 16-byte marker field (all 0xFF) that begins every BGP message.
pub const MARKER: [u8; 16] = [0xFF; 16];

/// Length of the BGP message header in bytes.
pub const HEADER_LEN: usize = 19;

/// Minimum valid BGP message length (header only, used by KEEPALIVE).
pub const MIN_MESSAGE_LEN: u16 = 19;

/// Maximum valid BGP message length per RFC 4271 §4.1.
pub const MAX_MESSAGE_LEN: u16 = 4096;

/// Size of the marker field in the header.
pub const MARKER_LEN: usize = 16;

/// BGP protocol version.
pub const BGP_VERSION: u8 = 4;

/// `AS_TRANS` value for 4-byte ASN backward compatibility (RFC 6793).
pub const AS_TRANS: u16 = 23456;

/// Default BGP TCP port.
pub const BGP_PORT: u16 = 179;

/// Minimum non-zero hold time in seconds (RFC 4271 §4.2).
pub const MIN_HOLD_TIME: u16 = 3;

/// Minimum OPEN message length (header + version + AS + hold + ID + opt len).
pub const MIN_OPEN_LEN: u16 = 29;

/// Minimum UPDATE message length (header + withdrawn len + attrs len).
pub const MIN_UPDATE_LEN: u16 = 23;

/// Minimum NOTIFICATION message length (header + code + subcode).
pub const MIN_NOTIFICATION_LEN: u16 = 21;

/// Message type codes.
pub mod message_type {
    pub const OPEN: u8 = 1;
    pub const UPDATE: u8 = 2;
    pub const NOTIFICATION: u8 = 3;
    pub const KEEPALIVE: u8 = 4;
    pub const ROUTE_REFRESH: u8 = 5;
}

/// OPEN optional parameter type codes (RFC 5492).
pub mod param_type {
    pub const CAPABILITIES: u8 = 2;
}

/// Capability codes (IANA BGP Capability Codes registry).
pub mod capability_code {
    /// RFC 4760: Multi-Protocol Extensions.
    pub const MULTI_PROTOCOL: u8 = 1;
    /// RFC 4724: Graceful Restart.
    pub const GRACEFUL_RESTART: u8 = 64;
    /// RFC 6793: 4-Byte AS Number.
    pub const FOUR_OCTET_AS: u8 = 65;
}

/// Path attribute type codes (RFC 4271 §5).
pub mod attr_type {
    pub const ORIGIN: u8 = 1;
    pub const AS_PATH: u8 = 2;
    pub const NEXT_HOP: u8 = 3;
    pub const MULTI_EXIT_DISC: u8 = 4;
    pub const LOCAL_PREF: u8 = 5;
    pub const ATOMIC_AGGREGATE: u8 = 6;
    pub const AGGREGATOR: u8 = 7;
    pub const COMMUNITIES: u8 = 8;
    /// RFC 4360: Extended Communities.
    pub const EXTENDED_COMMUNITIES: u8 = 16;
    /// RFC 4760: `MP_REACH_NLRI`.
    pub const MP_REACH_NLRI: u8 = 14;
    /// RFC 4760: `MP_UNREACH_NLRI`.
    pub const MP_UNREACH_NLRI: u8 = 15;
}

/// Path attribute flag bits (RFC 4271 §4.3).
pub mod attr_flags {
    pub const OPTIONAL: u8 = 0x80;
    pub const TRANSITIVE: u8 = 0x40;
    pub const PARTIAL: u8 = 0x20;
    pub const EXTENDED_LENGTH: u8 = 0x10;
}

/// `AS_PATH` segment types (RFC 4271 §4.3).
pub mod as_path_segment {
    /// `AS_SET` segment type.
    pub const AS_SET: u8 = 1;
    /// `AS_SEQUENCE` segment type.
    pub const AS_SEQUENCE: u8 = 2;
}
