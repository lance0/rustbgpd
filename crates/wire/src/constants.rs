/// The 16-byte marker field (all 0xFF) that begins every BGP message.
pub const MARKER: [u8; 16] = [0xFF; 16];

/// Length of the BGP message header in bytes.
pub const HEADER_LEN: usize = 19;

/// Minimum valid BGP message length (header only, used by KEEPALIVE).
pub const MIN_MESSAGE_LEN: u16 = 19;

/// Maximum valid BGP message length per RFC 4271 §4.1.
pub const MAX_MESSAGE_LEN: u16 = 4096;

/// Maximum BGP message length with Extended Messages (RFC 8654).
pub const EXTENDED_MAX_MESSAGE_LEN: u16 = 65535;

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
    /// OPEN message (type 1).
    pub const OPEN: u8 = 1;
    /// UPDATE message (type 2).
    pub const UPDATE: u8 = 2;
    /// NOTIFICATION message (type 3).
    pub const NOTIFICATION: u8 = 3;
    /// KEEPALIVE message (type 4).
    pub const KEEPALIVE: u8 = 4;
    /// ROUTE-REFRESH message (type 5, RFC 2918).
    pub const ROUTE_REFRESH: u8 = 5;
}

/// OPEN optional parameter type codes (RFC 5492).
pub mod param_type {
    /// Capabilities Optional Parameter (RFC 5492).
    pub const CAPABILITIES: u8 = 2;
}

/// Capability codes (IANA BGP Capability Codes registry).
pub mod capability_code {
    /// RFC 4760: Multi-Protocol Extensions.
    pub const MULTI_PROTOCOL: u8 = 1;
    /// RFC 2918: Route Refresh.
    pub const ROUTE_REFRESH: u8 = 2;
    /// RFC 8950: Extended Next Hop Encoding.
    pub const EXTENDED_NEXT_HOP: u8 = 5;
    /// RFC 4724: Graceful Restart.
    pub const GRACEFUL_RESTART: u8 = 64;
    /// RFC 8654: Extended Messages.
    pub const EXTENDED_MESSAGE: u8 = 6;
    /// RFC 7911: Add-Path.
    pub const ADD_PATH: u8 = 69;
    /// RFC 7313: Enhanced Route Refresh.
    pub const ENHANCED_ROUTE_REFRESH: u8 = 70;
    /// RFC 9494: Long-Lived Graceful Restart.
    pub const LONG_LIVED_GRACEFUL_RESTART: u8 = 71;
    /// RFC 6793: 4-Byte AS Number.
    pub const FOUR_OCTET_AS: u8 = 65;
}

/// Path attribute type codes (RFC 4271 §5).
pub mod attr_type {
    /// `ORIGIN` (type 1).
    pub const ORIGIN: u8 = 1;
    /// `AS_PATH` (type 2).
    pub const AS_PATH: u8 = 2;
    /// `NEXT_HOP` (type 3).
    pub const NEXT_HOP: u8 = 3;
    /// `MULTI_EXIT_DISC` (type 4).
    pub const MULTI_EXIT_DISC: u8 = 4;
    /// `LOCAL_PREF` (type 5).
    pub const LOCAL_PREF: u8 = 5;
    /// `ATOMIC_AGGREGATE` (type 6).
    pub const ATOMIC_AGGREGATE: u8 = 6;
    /// `AGGREGATOR` (type 7).
    pub const AGGREGATOR: u8 = 7;
    /// `COMMUNITIES` (type 8, RFC 1997).
    pub const COMMUNITIES: u8 = 8;
    /// RFC 4456: `ORIGINATOR_ID`.
    pub const ORIGINATOR_ID: u8 = 9;
    /// RFC 4456: `CLUSTER_LIST`.
    pub const CLUSTER_LIST: u8 = 10;
    /// RFC 4360: Extended Communities.
    pub const EXTENDED_COMMUNITIES: u8 = 16;
    /// RFC 8092: Large Communities.
    pub const LARGE_COMMUNITIES: u8 = 32;
    /// RFC 4760: `MP_REACH_NLRI`.
    pub const MP_REACH_NLRI: u8 = 14;
    /// RFC 4760: `MP_UNREACH_NLRI`.
    pub const MP_UNREACH_NLRI: u8 = 15;
}

/// Path attribute flag bits (RFC 4271 §4.3).
pub mod attr_flags {
    /// Bit 7: attribute is optional (vs. well-known).
    pub const OPTIONAL: u8 = 0x80;
    /// Bit 6: attribute is transitive.
    pub const TRANSITIVE: u8 = 0x40;
    /// Bit 5: attribute is partial (incomplete transitive).
    pub const PARTIAL: u8 = 0x20;
    /// Bit 4: attribute length is 2 bytes (vs. 1 byte).
    pub const EXTENDED_LENGTH: u8 = 0x10;
}

/// `AS_PATH` segment types (RFC 4271 §4.3).
pub mod as_path_segment {
    /// `AS_SET` segment type.
    pub const AS_SET: u8 = 1;
    /// `AS_SEQUENCE` segment type.
    pub const AS_SEQUENCE: u8 = 2;
}
