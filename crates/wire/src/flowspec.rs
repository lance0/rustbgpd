//! RFC 8955 / RFC 8956 `FlowSpec` NLRI codec and types.
//!
//! `FlowSpec` rules consist of ordered match components (type-value pairs) that
//! describe traffic to filter. Each component uses either numeric operators
//! (ports, protocol, length, DSCP) or bitmask operators (TCP flags, fragment).
//!
//! The wire format uses a length-prefixed TLV structure with operator bytes
//! that encode comparison semantics and value sizes.

use std::fmt;
use std::net::Ipv4Addr;

use crate::capability::Afi;
use crate::error::DecodeError;
use crate::nlri::{Ipv4Prefix, Ipv6Prefix};

// ---------------------------------------------------------------------------
// Numeric operator — RFC 8955 §3.1 Figure 2
// ---------------------------------------------------------------------------

/// A single numeric comparison term with operator flags and a value.
///
/// Multiple terms are combined with AND/OR logic per the `and_bit` flag;
/// the `end_of_list` flag terminates the operator list for a component.
#[expect(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NumericMatch {
    /// Last term in this operator list.
    pub end_of_list: bool,
    /// If true, AND with the previous term; otherwise OR.
    pub and_bit: bool,
    /// Less-than comparison flag.
    pub lt: bool,
    /// Greater-than comparison flag.
    pub gt: bool,
    /// Equal comparison flag.
    pub eq: bool,
    /// Numeric value to compare against.
    pub value: u64,
}

/// A single bitmask comparison term.
#[expect(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BitmaskMatch {
    /// Last term in this operator list.
    pub end_of_list: bool,
    /// If true, AND with the previous term; otherwise OR.
    pub and_bit: bool,
    /// Negate the match result.
    pub not_bit: bool,
    /// If true, all specified bits must match; otherwise any bit suffices.
    pub match_bit: bool,
    /// Bitmask value to compare against.
    pub value: u16,
}

// ---------------------------------------------------------------------------
// IPv6 prefix with offset — RFC 8956 §3.1
// ---------------------------------------------------------------------------

/// IPv6 prefix with an additional bit offset for `FlowSpec` source/destination.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv6PrefixOffset {
    /// The IPv6 prefix.
    pub prefix: Ipv6Prefix,
    /// Bit offset within the prefix (RFC 8956 §3.1).
    pub offset: u8,
}

// ---------------------------------------------------------------------------
// FlowSpec component — RFC 8955 §4
// ---------------------------------------------------------------------------

/// A single `FlowSpec` match component.
///
/// Components are identified by type code (1–13) and must be stored in
/// ascending type order within a [`FlowSpecRule`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FlowSpecComponent {
    /// Type 1: Destination IP prefix (IPv4 or IPv6 with offset).
    DestinationPrefix(FlowSpecPrefix),
    /// Type 2: Source IP prefix (IPv4 or IPv6 with offset).
    SourcePrefix(FlowSpecPrefix),
    /// Type 3: IP protocol (e.g., TCP=6, UDP=17).
    IpProtocol(Vec<NumericMatch>),
    /// Type 4: Port (source or destination).
    Port(Vec<NumericMatch>),
    /// Type 5: Destination port.
    DestinationPort(Vec<NumericMatch>),
    /// Type 6: Source port.
    SourcePort(Vec<NumericMatch>),
    /// Type 7: ICMP type.
    IcmpType(Vec<NumericMatch>),
    /// Type 8: ICMP code.
    IcmpCode(Vec<NumericMatch>),
    /// Type 9: TCP flags.
    TcpFlags(Vec<BitmaskMatch>),
    /// Type 10: Packet length.
    PacketLength(Vec<NumericMatch>),
    /// Type 11: DSCP value.
    Dscp(Vec<NumericMatch>),
    /// Type 12: Fragment flags.
    Fragment(Vec<BitmaskMatch>),
    /// Type 13: Flow label (IPv6 only, RFC 8956).
    FlowLabel(Vec<NumericMatch>),
}

/// Prefix value for `FlowSpec` destination/source components.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FlowSpecPrefix {
    /// IPv4 prefix.
    V4(Ipv4Prefix),
    /// IPv6 prefix with bit offset.
    V6(Ipv6PrefixOffset),
}

impl FlowSpecComponent {
    /// Return the wire type code for this component.
    #[must_use]
    pub fn type_code(&self) -> u8 {
        match self {
            Self::DestinationPrefix(_) => 1,
            Self::SourcePrefix(_) => 2,
            Self::IpProtocol(_) => 3,
            Self::Port(_) => 4,
            Self::DestinationPort(_) => 5,
            Self::SourcePort(_) => 6,
            Self::IcmpType(_) => 7,
            Self::IcmpCode(_) => 8,
            Self::TcpFlags(_) => 9,
            Self::PacketLength(_) => 10,
            Self::Dscp(_) => 11,
            Self::Fragment(_) => 12,
            Self::FlowLabel(_) => 13,
        }
    }
}

// ---------------------------------------------------------------------------
// FlowSpecRule — ordered set of components
// ---------------------------------------------------------------------------

/// A complete `FlowSpec` NLRI rule — an ordered set of match components.
///
/// Components must be sorted by ascending type code. A rule may contain at
/// most one component of each type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowSpecRule {
    /// Ordered match components (ascending type code).
    pub components: Vec<FlowSpecComponent>,
}

impl FlowSpecRule {
    /// Validate that components are in ascending type-code order.
    ///
    /// # Errors
    ///
    /// Returns `DecodeError` if the rule has no components or if components
    /// are not in strictly ascending type-code order.
    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.components.is_empty() {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: "FlowSpec rule has no components".to_string(),
            });
        }
        for window in self.components.windows(2) {
            if window[0].type_code() >= window[1].type_code() {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: format!(
                        "FlowSpec components out of order: type {} >= {}",
                        window[0].type_code(),
                        window[1].type_code()
                    ),
                });
            }
        }
        Ok(())
    }

    /// Return a human-readable display string for logging / gRPC.
    #[must_use]
    pub fn display_string(&self) -> String {
        let mut parts = Vec::new();
        for c in &self.components {
            parts.push(format_component(c));
        }
        parts.join(" && ")
    }

    /// Extract the destination prefix from the rule, if present.
    #[must_use]
    pub fn destination_prefix(&self) -> Option<crate::nlri::Prefix> {
        self.components.iter().find_map(|c| match c {
            FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(p)) => {
                Some(crate::nlri::Prefix::V4(*p))
            }
            FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V6(p)) => {
                Some(crate::nlri::Prefix::V6(p.prefix))
            }
            _ => None,
        })
    }
}

impl fmt::Display for FlowSpecRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_string())
    }
}

// ---------------------------------------------------------------------------
// FlowSpec actions — RFC 8955 §7, RFC 7674
// ---------------------------------------------------------------------------

/// A traffic action decoded from a `FlowSpec` extended community.
#[derive(Debug, Clone, PartialEq)]
pub enum FlowSpecAction {
    /// Traffic-rate (type 0x8006): rate=0.0 means drop.
    TrafficRateBytes {
        /// Informational ASN.
        asn: u16,
        /// Rate limit in bytes per second.
        rate: f32,
    },
    /// Traffic-rate-packets (type 0x800c, RFC 8955 Appendix A).
    TrafficRatePackets {
        /// Informational ASN.
        asn: u16,
        /// Rate limit in packets per second.
        rate: f32,
    },
    /// Traffic-action (type 0x8007): sample and/or terminal bits.
    TrafficAction {
        /// Sample matching traffic.
        sample: bool,
        /// Terminal action — do not evaluate further `FlowSpec` rules.
        terminal: bool,
    },
    /// Traffic-marking (type 0x8009): set DSCP value.
    TrafficMarking {
        /// DSCP value to mark on matching packets.
        dscp: u8,
    },
    /// Redirect 2-octet AS (type 0x8008).
    Redirect2Octet {
        /// Target 2-octet ASN.
        asn: u16,
        /// Local administrator value.
        value: u32,
    },
    /// Redirect IPv4 (type 0x8108, RFC 7674).
    RedirectIpv4 {
        /// Target IPv4 address.
        addr: Ipv4Addr,
        /// Local administrator value.
        value: u16,
    },
    /// Redirect 4-octet AS (type 0x8208, RFC 7674).
    Redirect4Octet {
        /// Target 4-octet ASN.
        asn: u32,
        /// Local administrator value.
        value: u16,
    },
}

impl crate::attribute::ExtendedCommunity {
    /// Try to decode this extended community as a `FlowSpec` action.
    #[must_use]
    pub fn as_flowspec_action(&self) -> Option<FlowSpecAction> {
        let raw = self.as_u64();
        let bytes = raw.to_be_bytes();
        let type_high = bytes[0];
        let subtype = bytes[1];

        match (type_high, subtype) {
            // Traffic-rate bytes (transitive): 0x80, 0x06
            (0x80, 0x06) => {
                let asn = u16::from_be_bytes([bytes[2], bytes[3]]);
                let rate = f32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
                Some(FlowSpecAction::TrafficRateBytes { asn, rate })
            }
            // Traffic-action: 0x80, 0x07
            (0x80, 0x07) => {
                // bits in byte 7: bit 0 = terminal, bit 1 = sample
                let flags = bytes[7];
                Some(FlowSpecAction::TrafficAction {
                    sample: flags & 0x02 != 0,
                    terminal: flags & 0x01 != 0,
                })
            }
            // Redirect 2-octet AS: 0x80, 0x08
            (0x80, 0x08) => {
                let asn = u16::from_be_bytes([bytes[2], bytes[3]]);
                let value = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
                Some(FlowSpecAction::Redirect2Octet { asn, value })
            }
            // Traffic-marking: 0x80, 0x09
            (0x80, 0x09) => Some(FlowSpecAction::TrafficMarking {
                dscp: bytes[7] & 0x3F,
            }),
            // Traffic-rate packets: 0x80, 0x0c
            (0x80, 0x0c) => {
                let asn = u16::from_be_bytes([bytes[2], bytes[3]]);
                let rate = f32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
                Some(FlowSpecAction::TrafficRatePackets { asn, rate })
            }
            // Redirect IPv4: 0x81, 0x08
            (0x81, 0x08) => {
                let addr = Ipv4Addr::new(bytes[2], bytes[3], bytes[4], bytes[5]);
                let value = u16::from_be_bytes([bytes[6], bytes[7]]);
                Some(FlowSpecAction::RedirectIpv4 { addr, value })
            }
            // Redirect 4-octet AS: 0x82, 0x08
            (0x82, 0x08) => {
                let asn = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
                let value = u16::from_be_bytes([bytes[6], bytes[7]]);
                Some(FlowSpecAction::Redirect4Octet { asn, value })
            }
            _ => None,
        }
    }

    /// Create an extended community from a `FlowSpec` action.
    #[must_use]
    pub fn from_flowspec_action(action: &FlowSpecAction) -> Self {
        let mut bytes = [0u8; 8];
        match action {
            FlowSpecAction::TrafficRateBytes { asn, rate } => {
                bytes[0] = 0x80;
                bytes[1] = 0x06;
                bytes[2..4].copy_from_slice(&asn.to_be_bytes());
                bytes[4..8].copy_from_slice(&rate.to_be_bytes());
            }
            FlowSpecAction::TrafficRatePackets { asn, rate } => {
                bytes[0] = 0x80;
                bytes[1] = 0x0c;
                bytes[2..4].copy_from_slice(&asn.to_be_bytes());
                bytes[4..8].copy_from_slice(&rate.to_be_bytes());
            }
            FlowSpecAction::TrafficAction { sample, terminal } => {
                bytes[0] = 0x80;
                bytes[1] = 0x07;
                let mut flags = 0u8;
                if *sample {
                    flags |= 0x02;
                }
                if *terminal {
                    flags |= 0x01;
                }
                bytes[7] = flags;
            }
            FlowSpecAction::TrafficMarking { dscp } => {
                bytes[0] = 0x80;
                bytes[1] = 0x09;
                bytes[7] = *dscp & 0x3F;
            }
            FlowSpecAction::Redirect2Octet { asn, value } => {
                bytes[0] = 0x80;
                bytes[1] = 0x08;
                bytes[2..4].copy_from_slice(&asn.to_be_bytes());
                bytes[4..8].copy_from_slice(&value.to_be_bytes());
            }
            FlowSpecAction::RedirectIpv4 { addr, value } => {
                bytes[0] = 0x81;
                bytes[1] = 0x08;
                bytes[2..6].copy_from_slice(&addr.octets());
                bytes[6..8].copy_from_slice(&value.to_be_bytes());
            }
            FlowSpecAction::Redirect4Octet { asn, value } => {
                bytes[0] = 0x82;
                bytes[1] = 0x08;
                bytes[2..6].copy_from_slice(&asn.to_be_bytes());
                bytes[6..8].copy_from_slice(&value.to_be_bytes());
            }
        }
        Self::new(u64::from_be_bytes(bytes))
    }
}

// ---------------------------------------------------------------------------
// Wire decode
// ---------------------------------------------------------------------------

/// Decode one or more `FlowSpec` NLRI rules from wire bytes.
///
/// Each rule is length-prefixed: 1-byte length if < 0xF0 (240),
/// otherwise 2-byte big-endian length with first byte ≥ 0xF0.
///
/// # Errors
///
/// Returns `DecodeError` if the wire data is truncated, malformed, or
/// contains components in invalid order.
pub fn decode_flowspec_nlri(mut buf: &[u8], afi: Afi) -> Result<Vec<FlowSpecRule>, DecodeError> {
    let mut rules = Vec::new();
    while !buf.is_empty() {
        // Length prefix
        let (rule_len, consumed) = decode_flowspec_length(buf)?;
        buf = &buf[consumed..];
        if buf.len() < rule_len {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!(
                    "FlowSpec NLRI truncated: need {rule_len} bytes, have {}",
                    buf.len()
                ),
            });
        }
        let rule_bytes = &buf[..rule_len];
        buf = &buf[rule_len..];

        let rule = decode_flowspec_rule(rule_bytes, afi)?;
        rule.validate()?;
        rules.push(rule);
    }
    Ok(rules)
}

/// Encode `FlowSpec` NLRI rules to wire bytes.
pub fn encode_flowspec_nlri(rules: &[FlowSpecRule], buf: &mut Vec<u8>, afi: Afi) {
    for rule in rules {
        let mut rule_bytes = Vec::new();
        encode_flowspec_rule(rule, &mut rule_bytes, afi);
        encode_flowspec_length(rule_bytes.len(), buf);
        buf.extend_from_slice(&rule_bytes);
    }
}

/// Decode `FlowSpec` NLRI length prefix.
fn decode_flowspec_length(buf: &[u8]) -> Result<(usize, usize), DecodeError> {
    if buf.is_empty() {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: "FlowSpec NLRI length: empty buffer".to_string(),
        });
    }
    if buf[0] < 0xF0 {
        Ok((buf[0] as usize, 1))
    } else {
        if buf.len() < 2 {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: "FlowSpec NLRI 2-byte length truncated".to_string(),
            });
        }
        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        // The top 4 bits are 0xF, so subtract 0xF000 to get real length
        let real_len = len & 0x0FFF;
        Ok((real_len, 2))
    }
}

/// Encode `FlowSpec` NLRI length prefix.
fn encode_flowspec_length(len: usize, buf: &mut Vec<u8>) {
    if len < 0xF0 {
        #[expect(clippy::cast_possible_truncation)]
        buf.push(len as u8);
    } else {
        #[expect(clippy::cast_possible_truncation)]
        let val = (0xF000 | (len & 0x0FFF)) as u16;
        buf.extend_from_slice(&val.to_be_bytes());
    }
}

/// Decode a single `FlowSpec` rule from its component bytes (after length prefix).
fn decode_flowspec_rule(mut buf: &[u8], afi: Afi) -> Result<FlowSpecRule, DecodeError> {
    let mut components = Vec::new();
    while !buf.is_empty() {
        let (component, consumed) = decode_component(buf, afi)?;
        components.push(component);
        buf = &buf[consumed..];
    }
    Ok(FlowSpecRule { components })
}

/// Decode a single `FlowSpec` component from the start of `buf`.
/// Returns the component and the number of bytes consumed.
fn decode_component(buf: &[u8], afi: Afi) -> Result<(FlowSpecComponent, usize), DecodeError> {
    if buf.is_empty() {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: "FlowSpec component: empty buffer".to_string(),
        });
    }

    let type_code = buf[0];
    let rest = &buf[1..];

    match type_code {
        1 | 2 => {
            // Prefix component — encoding differs by AFI
            let (prefix, consumed) = decode_prefix_component(rest, afi)?;
            let component = if type_code == 1 {
                FlowSpecComponent::DestinationPrefix(prefix)
            } else {
                FlowSpecComponent::SourcePrefix(prefix)
            };
            Ok((component, 1 + consumed))
        }
        3 => {
            let (ops, consumed) = decode_numeric_ops(rest)?;
            Ok((FlowSpecComponent::IpProtocol(ops), 1 + consumed))
        }
        4 => {
            let (ops, consumed) = decode_numeric_ops(rest)?;
            Ok((FlowSpecComponent::Port(ops), 1 + consumed))
        }
        5 => {
            let (ops, consumed) = decode_numeric_ops(rest)?;
            Ok((FlowSpecComponent::DestinationPort(ops), 1 + consumed))
        }
        6 => {
            let (ops, consumed) = decode_numeric_ops(rest)?;
            Ok((FlowSpecComponent::SourcePort(ops), 1 + consumed))
        }
        7 => {
            let (ops, consumed) = decode_numeric_ops(rest)?;
            Ok((FlowSpecComponent::IcmpType(ops), 1 + consumed))
        }
        8 => {
            let (ops, consumed) = decode_numeric_ops(rest)?;
            Ok((FlowSpecComponent::IcmpCode(ops), 1 + consumed))
        }
        9 => {
            let (ops, consumed) = decode_bitmask_ops(rest)?;
            Ok((FlowSpecComponent::TcpFlags(ops), 1 + consumed))
        }
        10 => {
            let (ops, consumed) = decode_numeric_ops(rest)?;
            Ok((FlowSpecComponent::PacketLength(ops), 1 + consumed))
        }
        11 => {
            let (ops, consumed) = decode_numeric_ops(rest)?;
            Ok((FlowSpecComponent::Dscp(ops), 1 + consumed))
        }
        12 => {
            let (ops, consumed) = decode_bitmask_ops(rest)?;
            Ok((FlowSpecComponent::Fragment(ops), 1 + consumed))
        }
        13 => {
            let (ops, consumed) = decode_numeric_ops(rest)?;
            Ok((FlowSpecComponent::FlowLabel(ops), 1 + consumed))
        }
        _ => Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!("unknown FlowSpec component type {type_code}"),
        }),
    }
}

/// Decode a prefix component (types 1 and 2).
fn decode_prefix_component(buf: &[u8], afi: Afi) -> Result<(FlowSpecPrefix, usize), DecodeError> {
    match afi {
        Afi::Ipv4 => {
            // IPv4: prefix-length (1 byte) + prefix bytes (ceil(len/8))
            if buf.is_empty() {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: "FlowSpec IPv4 prefix: missing length byte".to_string(),
                });
            }
            let prefix_len = buf[0];
            if prefix_len > 32 {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: format!("FlowSpec IPv4 prefix length {prefix_len} > 32"),
                });
            }
            let byte_count = (prefix_len as usize).div_ceil(8);
            if buf.len() < 1 + byte_count {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: "FlowSpec IPv4 prefix truncated".to_string(),
                });
            }
            let mut octets = [0u8; 4];
            octets[..byte_count].copy_from_slice(&buf[1..=byte_count]);
            let addr = Ipv4Addr::from(octets);
            Ok((
                FlowSpecPrefix::V4(Ipv4Prefix::new(addr, prefix_len)),
                1 + byte_count,
            ))
        }
        Afi::Ipv6 => {
            // IPv6: prefix-length (1) + offset (1) + prefix bytes
            if buf.len() < 2 {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: "FlowSpec IPv6 prefix: need length+offset bytes".to_string(),
                });
            }
            let prefix_len = buf[0];
            let offset = buf[1];
            if prefix_len > 128 {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: format!("FlowSpec IPv6 prefix length {prefix_len} > 128"),
                });
            }
            let byte_count = (prefix_len as usize).div_ceil(8);
            if buf.len() < 2 + byte_count {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: "FlowSpec IPv6 prefix truncated".to_string(),
                });
            }
            let mut octets = [0u8; 16];
            octets[..byte_count].copy_from_slice(&buf[2..2 + byte_count]);
            let addr = std::net::Ipv6Addr::from(octets);
            Ok((
                FlowSpecPrefix::V6(Ipv6PrefixOffset {
                    prefix: Ipv6Prefix::new(addr, prefix_len),
                    offset,
                }),
                2 + byte_count,
            ))
        }
    }
}

/// Decode numeric operator+value pairs until end-of-list.
fn decode_numeric_ops(mut buf: &[u8]) -> Result<(Vec<NumericMatch>, usize), DecodeError> {
    let mut ops = Vec::new();
    let start_len = buf.len();
    loop {
        if buf.is_empty() {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: "FlowSpec numeric operators: unexpected end of data".to_string(),
            });
        }
        let op_byte = buf[0];
        buf = &buf[1..];

        let end_of_list = op_byte & 0x80 != 0;
        let and_bit = op_byte & 0x40 != 0;
        let value_len_code = (op_byte >> 4) & 0x03;
        let value_len = 1usize << value_len_code; // 1, 2, 4, or 8
        let lt = op_byte & 0x04 != 0;
        let gt = op_byte & 0x02 != 0;
        let eq = op_byte & 0x01 != 0;

        if buf.len() < value_len {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!(
                    "FlowSpec numeric value truncated: need {value_len}, have {}",
                    buf.len()
                ),
            });
        }

        let value = match value_len {
            1 => u64::from(buf[0]),
            2 => u64::from(u16::from_be_bytes([buf[0], buf[1]])),
            4 => u64::from(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]])),
            8 => u64::from_be_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
            _ => unreachable!(),
        };
        buf = &buf[value_len..];

        ops.push(NumericMatch {
            end_of_list,
            and_bit,
            lt,
            gt,
            eq,
            value,
        });

        if end_of_list {
            break;
        }
    }
    Ok((ops, start_len - buf.len()))
}

/// Decode bitmask operator+value pairs until end-of-list.
fn decode_bitmask_ops(mut buf: &[u8]) -> Result<(Vec<BitmaskMatch>, usize), DecodeError> {
    let mut ops = Vec::new();
    let start_len = buf.len();
    loop {
        if buf.is_empty() {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: "FlowSpec bitmask operators: unexpected end of data".to_string(),
            });
        }
        let op_byte = buf[0];
        buf = &buf[1..];

        let end_of_list = op_byte & 0x80 != 0;
        let and_bit = op_byte & 0x40 != 0;
        let value_len_code = (op_byte >> 4) & 0x03;
        let value_len = 1usize << value_len_code; // 1 or 2 for bitmask
        let not_bit = op_byte & 0x02 != 0;
        let match_bit = op_byte & 0x01 != 0;

        if buf.len() < value_len {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!(
                    "FlowSpec bitmask value truncated: need {value_len}, have {}",
                    buf.len()
                ),
            });
        }

        let value = match value_len {
            1 => u16::from(buf[0]),
            2 => u16::from_be_bytes([buf[0], buf[1]]),
            _ => {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: format!("FlowSpec bitmask value length {value_len} unsupported"),
                });
            }
        };
        buf = &buf[value_len..];

        ops.push(BitmaskMatch {
            end_of_list,
            and_bit,
            not_bit,
            match_bit,
            value,
        });

        if end_of_list {
            break;
        }
    }
    Ok((ops, start_len - buf.len()))
}

// ---------------------------------------------------------------------------
// Wire encode
// ---------------------------------------------------------------------------

/// Encode a single `FlowSpec` rule to wire bytes (without the length prefix).
fn encode_flowspec_rule(rule: &FlowSpecRule, buf: &mut Vec<u8>, afi: Afi) {
    for component in &rule.components {
        buf.push(component.type_code());
        match component {
            FlowSpecComponent::DestinationPrefix(p) | FlowSpecComponent::SourcePrefix(p) => {
                encode_prefix_component(p, buf, afi);
            }
            FlowSpecComponent::IpProtocol(ops)
            | FlowSpecComponent::Port(ops)
            | FlowSpecComponent::DestinationPort(ops)
            | FlowSpecComponent::SourcePort(ops)
            | FlowSpecComponent::IcmpType(ops)
            | FlowSpecComponent::IcmpCode(ops)
            | FlowSpecComponent::PacketLength(ops)
            | FlowSpecComponent::Dscp(ops)
            | FlowSpecComponent::FlowLabel(ops) => {
                encode_numeric_ops(ops, buf);
            }
            FlowSpecComponent::TcpFlags(ops) | FlowSpecComponent::Fragment(ops) => {
                encode_bitmask_ops(ops, buf);
            }
        }
    }
}

/// Encode a prefix component.
fn encode_prefix_component(prefix: &FlowSpecPrefix, buf: &mut Vec<u8>, _afi: Afi) {
    match prefix {
        FlowSpecPrefix::V4(p) => {
            buf.push(p.len);
            let byte_count = (p.len as usize).div_ceil(8);
            buf.extend_from_slice(&p.addr.octets()[..byte_count]);
        }
        FlowSpecPrefix::V6(p) => {
            buf.push(p.prefix.len);
            buf.push(p.offset);
            let byte_count = (p.prefix.len as usize).div_ceil(8);
            buf.extend_from_slice(&p.prefix.addr.octets()[..byte_count]);
        }
    }
}

/// Determine the minimum value-length code for a numeric value.
fn numeric_value_len_code(value: u64) -> u8 {
    if value <= 0xFF {
        0 // 1 byte
    } else if value <= 0xFFFF {
        1 // 2 bytes
    } else if value <= 0xFFFF_FFFF {
        2 // 4 bytes
    } else {
        3 // 8 bytes
    }
}

/// Encode numeric operator+value pairs.
fn encode_numeric_ops(ops: &[NumericMatch], buf: &mut Vec<u8>) {
    for (i, op) in ops.iter().enumerate() {
        let is_last = i == ops.len() - 1;
        let len_code = numeric_value_len_code(op.value);
        let mut op_byte: u8 = 0;
        if is_last {
            op_byte |= 0x80; // end-of-list
        }
        if op.and_bit {
            op_byte |= 0x40;
        }
        op_byte |= len_code << 4;
        if op.lt {
            op_byte |= 0x04;
        }
        if op.gt {
            op_byte |= 0x02;
        }
        if op.eq {
            op_byte |= 0x01;
        }
        buf.push(op_byte);
        let value_len = 1usize << len_code;
        match value_len {
            1 => {
                #[expect(clippy::cast_possible_truncation)]
                buf.push(op.value as u8);
            }
            2 => {
                #[expect(clippy::cast_possible_truncation)]
                buf.extend_from_slice(&(op.value as u16).to_be_bytes());
            }
            4 => {
                #[expect(clippy::cast_possible_truncation)]
                buf.extend_from_slice(&(op.value as u32).to_be_bytes());
            }
            8 => buf.extend_from_slice(&op.value.to_be_bytes()),
            _ => unreachable!(),
        }
    }
}

/// Determine the minimum value-length code for a bitmask value.
fn bitmask_value_len_code(value: u16) -> u8 {
    u8::from(value > 0xFF)
}

/// Encode bitmask operator+value pairs.
fn encode_bitmask_ops(ops: &[BitmaskMatch], buf: &mut Vec<u8>) {
    for (i, op) in ops.iter().enumerate() {
        let is_last = i == ops.len() - 1;
        let len_code = bitmask_value_len_code(op.value);
        let mut op_byte: u8 = 0;
        if is_last {
            op_byte |= 0x80; // end-of-list
        }
        if op.and_bit {
            op_byte |= 0x40;
        }
        op_byte |= len_code << 4;
        if op.not_bit {
            op_byte |= 0x02;
        }
        if op.match_bit {
            op_byte |= 0x01;
        }
        buf.push(op_byte);
        match 1usize << len_code {
            1 => {
                #[expect(clippy::cast_possible_truncation)]
                buf.push(op.value as u8);
            }
            2 => buf.extend_from_slice(&op.value.to_be_bytes()),
            _ => unreachable!(),
        }
    }
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

fn format_component(c: &FlowSpecComponent) -> String {
    match c {
        FlowSpecComponent::DestinationPrefix(p) => format!("dst {}", format_prefix(p)),
        FlowSpecComponent::SourcePrefix(p) => format!("src {}", format_prefix(p)),
        FlowSpecComponent::IpProtocol(ops) => format!("proto {}", format_numeric(ops)),
        FlowSpecComponent::Port(ops) => format!("port {}", format_numeric(ops)),
        FlowSpecComponent::DestinationPort(ops) => format!("dport {}", format_numeric(ops)),
        FlowSpecComponent::SourcePort(ops) => format!("sport {}", format_numeric(ops)),
        FlowSpecComponent::IcmpType(ops) => format!("icmp-type {}", format_numeric(ops)),
        FlowSpecComponent::IcmpCode(ops) => format!("icmp-code {}", format_numeric(ops)),
        FlowSpecComponent::TcpFlags(ops) => format!("tcp-flags {}", format_bitmask(ops)),
        FlowSpecComponent::PacketLength(ops) => format!("pkt-len {}", format_numeric(ops)),
        FlowSpecComponent::Dscp(ops) => format!("dscp {}", format_numeric(ops)),
        FlowSpecComponent::Fragment(ops) => format!("fragment {}", format_bitmask(ops)),
        FlowSpecComponent::FlowLabel(ops) => format!("flow-label {}", format_numeric(ops)),
    }
}

fn format_prefix(p: &FlowSpecPrefix) -> String {
    match p {
        FlowSpecPrefix::V4(v4) => format!("{}/{}", v4.addr, v4.len),
        FlowSpecPrefix::V6(v6) => {
            if v6.offset == 0 {
                format!("{}/{}", v6.prefix.addr, v6.prefix.len)
            } else {
                format!("{}/{} offset {}", v6.prefix.addr, v6.prefix.len, v6.offset)
            }
        }
    }
}

fn format_numeric(ops: &[NumericMatch]) -> String {
    let mut parts = Vec::new();
    for op in ops {
        let cmp = match (op.lt, op.gt, op.eq) {
            (false, false, true) => "==",
            (true, false, false) => "<",
            (false, true, false) => ">",
            (true, false, true) => "<=",
            (false, true, true) => ">=",
            (true, true, false) => "!=",
            _ => "?",
        };
        parts.push(format!("{cmp}{}", op.value));
    }
    parts.join(",")
}

fn format_bitmask(ops: &[BitmaskMatch]) -> String {
    let mut parts = Vec::new();
    for op in ops {
        let prefix = if op.not_bit { "!" } else { "" };
        let suffix = if op.match_bit { "/match" } else { "" };
        parts.push(format!("{prefix}0x{:x}{suffix}", op.value));
    }
    parts.join(",")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn numeric_ops_roundtrip() {
        let ops = vec![
            NumericMatch {
                end_of_list: false,
                and_bit: false,
                lt: false,
                gt: false,
                eq: true,
                value: 6,
            },
            NumericMatch {
                end_of_list: true,
                and_bit: false,
                lt: false,
                gt: false,
                eq: true,
                value: 17,
            },
        ];
        let mut buf = Vec::new();
        encode_numeric_ops(&ops, &mut buf);
        let (decoded, consumed) = decode_numeric_ops(&buf).unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].value, 6);
        assert!(decoded[0].eq);
        assert_eq!(decoded[1].value, 17);
        assert!(decoded[1].end_of_list);
    }

    #[test]
    fn bitmask_ops_roundtrip() {
        let ops = vec![BitmaskMatch {
            end_of_list: true,
            and_bit: false,
            not_bit: false,
            match_bit: true,
            value: 0x02, // SYN
        }];
        let mut buf = Vec::new();
        encode_bitmask_ops(&ops, &mut buf);
        let (decoded, consumed) = decode_bitmask_ops(&buf).unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].value, 0x02);
        assert!(decoded[0].match_bit);
    }

    #[test]
    fn ipv4_prefix_component_roundtrip() {
        let prefix = FlowSpecPrefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8));
        let mut buf = Vec::new();
        encode_prefix_component(&prefix, &mut buf, Afi::Ipv4);
        let (decoded, consumed) = decode_prefix_component(&buf, Afi::Ipv4).unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded, prefix);
    }

    #[test]
    fn ipv6_prefix_component_roundtrip() {
        let prefix = FlowSpecPrefix::V6(Ipv6PrefixOffset {
            prefix: Ipv6Prefix::new(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32),
            offset: 0,
        });
        let mut buf = Vec::new();
        encode_prefix_component(&prefix, &mut buf, Afi::Ipv6);
        let (decoded, consumed) = decode_prefix_component(&buf, Afi::Ipv6).unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded, prefix);
    }

    #[test]
    fn simple_ipv4_rule_roundtrip() {
        let rule = FlowSpecRule {
            components: vec![
                FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(Ipv4Prefix::new(
                    Ipv4Addr::new(10, 0, 0, 0),
                    24,
                ))),
                FlowSpecComponent::IpProtocol(vec![NumericMatch {
                    end_of_list: true,
                    and_bit: false,
                    lt: false,
                    gt: false,
                    eq: true,
                    value: 6, // TCP
                }]),
                FlowSpecComponent::DestinationPort(vec![NumericMatch {
                    end_of_list: true,
                    and_bit: false,
                    lt: false,
                    gt: false,
                    eq: true,
                    value: 80,
                }]),
            ],
        };
        let mut buf = Vec::new();
        encode_flowspec_nlri(std::slice::from_ref(&rule), &mut buf, Afi::Ipv4);
        let decoded = decode_flowspec_nlri(&buf, Afi::Ipv4).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], rule);
    }

    #[test]
    fn multi_rule_roundtrip() {
        let rule1 = FlowSpecRule {
            components: vec![FlowSpecComponent::IpProtocol(vec![NumericMatch {
                end_of_list: true,
                and_bit: false,
                lt: false,
                gt: false,
                eq: true,
                value: 17, // UDP
            }])],
        };
        let rule2 = FlowSpecRule {
            components: vec![FlowSpecComponent::DestinationPort(vec![NumericMatch {
                end_of_list: true,
                and_bit: false,
                lt: false,
                gt: false,
                eq: true,
                value: 53,
            }])],
        };
        let mut buf = Vec::new();
        encode_flowspec_nlri(&[rule1.clone(), rule2.clone()], &mut buf, Afi::Ipv4);
        let decoded = decode_flowspec_nlri(&buf, Afi::Ipv4).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0], rule1);
        assert_eq!(decoded[1], rule2);
    }

    #[test]
    fn component_type_ordering_validated() {
        let rule = FlowSpecRule {
            components: vec![
                FlowSpecComponent::DestinationPort(vec![NumericMatch {
                    end_of_list: true,
                    and_bit: false,
                    lt: false,
                    gt: false,
                    eq: true,
                    value: 80,
                }]),
                FlowSpecComponent::IpProtocol(vec![NumericMatch {
                    end_of_list: true,
                    and_bit: false,
                    lt: false,
                    gt: false,
                    eq: true,
                    value: 6,
                }]),
            ],
        };
        assert!(rule.validate().is_err());
    }

    #[test]
    fn empty_rule_rejected() {
        let rule = FlowSpecRule { components: vec![] };
        assert!(rule.validate().is_err());
    }

    #[test]
    fn two_byte_length_prefix() {
        // Construct a rule large enough to need 2-byte length
        let mut buf = Vec::new();
        let len = 250; // > 0xF0
        encode_flowspec_length(len, &mut buf);
        assert_eq!(buf.len(), 2);
        let (decoded_len, consumed) = decode_flowspec_length(&buf).unwrap();
        assert_eq!(decoded_len, len);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn one_byte_length_prefix() {
        let mut buf = Vec::new();
        let len = 100;
        encode_flowspec_length(len, &mut buf);
        assert_eq!(buf.len(), 1);
        let (decoded_len, consumed) = decode_flowspec_length(&buf).unwrap();
        assert_eq!(decoded_len, len);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn numeric_2byte_value() {
        let ops = vec![NumericMatch {
            end_of_list: true,
            and_bit: false,
            lt: false,
            gt: false,
            eq: true,
            value: 8080,
        }];
        let mut buf = Vec::new();
        encode_numeric_ops(&ops, &mut buf);
        let (decoded, _) = decode_numeric_ops(&buf).unwrap();
        assert_eq!(decoded[0].value, 8080);
    }

    #[test]
    fn numeric_4byte_value() {
        let ops = vec![NumericMatch {
            end_of_list: true,
            and_bit: false,
            lt: false,
            gt: false,
            eq: true,
            value: 100_000,
        }];
        let mut buf = Vec::new();
        encode_numeric_ops(&ops, &mut buf);
        let (decoded, _) = decode_numeric_ops(&buf).unwrap();
        assert_eq!(decoded[0].value, 100_000);
    }

    #[test]
    fn bitmask_2byte_value() {
        let ops = vec![BitmaskMatch {
            end_of_list: true,
            and_bit: false,
            not_bit: false,
            match_bit: true,
            value: 0x0FFF,
        }];
        let mut buf = Vec::new();
        encode_bitmask_ops(&ops, &mut buf);
        let (decoded, _) = decode_bitmask_ops(&buf).unwrap();
        assert_eq!(decoded[0].value, 0x0FFF);
    }

    #[test]
    fn display_string_formatting() {
        let rule = FlowSpecRule {
            components: vec![
                FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(Ipv4Prefix::new(
                    Ipv4Addr::new(192, 168, 1, 0),
                    24,
                ))),
                FlowSpecComponent::IpProtocol(vec![NumericMatch {
                    end_of_list: true,
                    and_bit: false,
                    lt: false,
                    gt: false,
                    eq: true,
                    value: 6,
                }]),
            ],
        };
        let s = rule.display_string();
        assert!(s.contains("dst 192.168.1.0/24"));
        assert!(s.contains("proto ==6"));
    }

    #[test]
    fn traffic_rate_bytes_action_roundtrip() {
        let action = FlowSpecAction::TrafficRateBytes {
            asn: 65000,
            rate: 0.0,
        };
        let ec = crate::attribute::ExtendedCommunity::from_flowspec_action(&action);
        let decoded = ec.as_flowspec_action().unwrap();
        match decoded {
            FlowSpecAction::TrafficRateBytes { asn, rate } => {
                assert_eq!(asn, 65000);
                assert!((rate - 0.0).abs() < f32::EPSILON);
            }
            _ => panic!("wrong action type"),
        }
    }

    #[test]
    fn traffic_action_roundtrip() {
        let action = FlowSpecAction::TrafficAction {
            sample: true,
            terminal: false,
        };
        let ec = crate::attribute::ExtendedCommunity::from_flowspec_action(&action);
        let decoded = ec.as_flowspec_action().unwrap();
        match decoded {
            FlowSpecAction::TrafficAction { sample, terminal } => {
                assert!(sample);
                assert!(!terminal);
            }
            _ => panic!("wrong action type"),
        }
    }

    #[test]
    fn traffic_marking_roundtrip() {
        let action = FlowSpecAction::TrafficMarking { dscp: 46 };
        let ec = crate::attribute::ExtendedCommunity::from_flowspec_action(&action);
        let decoded = ec.as_flowspec_action().unwrap();
        assert!(matches!(
            decoded,
            FlowSpecAction::TrafficMarking { dscp: 46 }
        ));
    }

    #[test]
    fn redirect_2octet_roundtrip() {
        let action = FlowSpecAction::Redirect2Octet {
            asn: 65001,
            value: 100,
        };
        let ec = crate::attribute::ExtendedCommunity::from_flowspec_action(&action);
        let decoded = ec.as_flowspec_action().unwrap();
        assert!(matches!(
            decoded,
            FlowSpecAction::Redirect2Octet {
                asn: 65001,
                value: 100
            }
        ));
    }

    #[test]
    fn redirect_ipv4_roundtrip() {
        let action = FlowSpecAction::RedirectIpv4 {
            addr: Ipv4Addr::new(10, 0, 0, 1),
            value: 200,
        };
        let ec = crate::attribute::ExtendedCommunity::from_flowspec_action(&action);
        let decoded = ec.as_flowspec_action().unwrap();
        match decoded {
            FlowSpecAction::RedirectIpv4 { addr, value } => {
                assert_eq!(addr, Ipv4Addr::new(10, 0, 0, 1));
                assert_eq!(value, 200);
            }
            _ => panic!("wrong action type"),
        }
    }

    #[test]
    fn redirect_4octet_roundtrip() {
        let action = FlowSpecAction::Redirect4Octet {
            asn: 400_000,
            value: 300,
        };
        let ec = crate::attribute::ExtendedCommunity::from_flowspec_action(&action);
        let decoded = ec.as_flowspec_action().unwrap();
        match decoded {
            FlowSpecAction::Redirect4Octet { asn, value } => {
                assert_eq!(asn, 400_000);
                assert_eq!(value, 300);
            }
            _ => panic!("wrong action type"),
        }
    }

    #[test]
    fn traffic_rate_packets_roundtrip() {
        let action = FlowSpecAction::TrafficRatePackets {
            asn: 0,
            rate: 1000.0,
        };
        let ec = crate::attribute::ExtendedCommunity::from_flowspec_action(&action);
        let decoded = ec.as_flowspec_action().unwrap();
        match decoded {
            FlowSpecAction::TrafficRatePackets { asn, rate } => {
                assert_eq!(asn, 0);
                assert!((rate - 1000.0).abs() < f32::EPSILON);
            }
            _ => panic!("wrong action type"),
        }
    }

    #[test]
    fn flow_label_ipv6_roundtrip() {
        let rule = FlowSpecRule {
            components: vec![FlowSpecComponent::FlowLabel(vec![NumericMatch {
                end_of_list: true,
                and_bit: false,
                lt: false,
                gt: false,
                eq: true,
                value: 12345,
            }])],
        };
        let mut buf = Vec::new();
        encode_flowspec_nlri(std::slice::from_ref(&rule), &mut buf, Afi::Ipv6);
        let decoded = decode_flowspec_nlri(&buf, Afi::Ipv6).unwrap();
        assert_eq!(decoded[0], rule);
    }

    #[test]
    fn ipv6_rule_with_prefix_and_flow_label() {
        let rule = FlowSpecRule {
            components: vec![
                FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V6(Ipv6PrefixOffset {
                    prefix: Ipv6Prefix::new(
                        std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                        32,
                    ),
                    offset: 0,
                })),
                FlowSpecComponent::FlowLabel(vec![NumericMatch {
                    end_of_list: true,
                    and_bit: false,
                    lt: false,
                    gt: false,
                    eq: true,
                    value: 42,
                }]),
            ],
        };
        let mut buf = Vec::new();
        encode_flowspec_nlri(std::slice::from_ref(&rule), &mut buf, Afi::Ipv6);
        let decoded = decode_flowspec_nlri(&buf, Afi::Ipv6).unwrap();
        assert_eq!(decoded[0], rule);
    }

    #[test]
    #[expect(clippy::too_many_lines)]
    fn all_13_component_types_in_order() {
        let rule = FlowSpecRule {
            components: vec![
                FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(Ipv4Prefix::new(
                    Ipv4Addr::new(10, 0, 0, 0),
                    8,
                ))),
                FlowSpecComponent::SourcePrefix(FlowSpecPrefix::V4(Ipv4Prefix::new(
                    Ipv4Addr::new(172, 16, 0, 0),
                    12,
                ))),
                FlowSpecComponent::IpProtocol(vec![NumericMatch {
                    end_of_list: true,
                    and_bit: false,
                    lt: false,
                    gt: false,
                    eq: true,
                    value: 6,
                }]),
                FlowSpecComponent::Port(vec![NumericMatch {
                    end_of_list: true,
                    and_bit: false,
                    lt: false,
                    gt: false,
                    eq: true,
                    value: 80,
                }]),
                FlowSpecComponent::DestinationPort(vec![NumericMatch {
                    end_of_list: true,
                    and_bit: false,
                    lt: false,
                    gt: false,
                    eq: true,
                    value: 443,
                }]),
                FlowSpecComponent::SourcePort(vec![NumericMatch {
                    end_of_list: true,
                    and_bit: false,
                    lt: false,
                    gt: true,
                    eq: false,
                    value: 1024,
                }]),
                FlowSpecComponent::IcmpType(vec![NumericMatch {
                    end_of_list: true,
                    and_bit: false,
                    lt: false,
                    gt: false,
                    eq: true,
                    value: 8,
                }]),
                FlowSpecComponent::IcmpCode(vec![NumericMatch {
                    end_of_list: true,
                    and_bit: false,
                    lt: false,
                    gt: false,
                    eq: true,
                    value: 0,
                }]),
                FlowSpecComponent::TcpFlags(vec![BitmaskMatch {
                    end_of_list: true,
                    and_bit: false,
                    not_bit: false,
                    match_bit: true,
                    value: 0x02,
                }]),
                FlowSpecComponent::PacketLength(vec![NumericMatch {
                    end_of_list: true,
                    and_bit: false,
                    lt: true,
                    gt: false,
                    eq: true,
                    value: 1500,
                }]),
                FlowSpecComponent::Dscp(vec![NumericMatch {
                    end_of_list: true,
                    and_bit: false,
                    lt: false,
                    gt: false,
                    eq: true,
                    value: 46,
                }]),
                FlowSpecComponent::Fragment(vec![BitmaskMatch {
                    end_of_list: true,
                    and_bit: false,
                    not_bit: false,
                    match_bit: true,
                    value: 0x01,
                }]),
                FlowSpecComponent::FlowLabel(vec![NumericMatch {
                    end_of_list: true,
                    and_bit: false,
                    lt: false,
                    gt: false,
                    eq: true,
                    value: 99999,
                }]),
            ],
        };
        assert!(rule.validate().is_ok());
        let mut buf = Vec::new();
        encode_flowspec_nlri(std::slice::from_ref(&rule), &mut buf, Afi::Ipv4);
        let decoded = decode_flowspec_nlri(&buf, Afi::Ipv4).unwrap();
        assert_eq!(decoded[0], rule);
    }

    #[test]
    fn destination_prefix_extraction() {
        let rule = FlowSpecRule {
            components: vec![
                FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(Ipv4Prefix::new(
                    Ipv4Addr::new(10, 0, 0, 0),
                    24,
                ))),
                FlowSpecComponent::IpProtocol(vec![NumericMatch {
                    end_of_list: true,
                    and_bit: false,
                    lt: false,
                    gt: false,
                    eq: true,
                    value: 6,
                }]),
            ],
        };
        let prefix = rule.destination_prefix().unwrap();
        match prefix {
            crate::nlri::Prefix::V4(p) => {
                assert_eq!(p.addr, Ipv4Addr::new(10, 0, 0, 0));
                assert_eq!(p.len, 24);
            }
            crate::nlri::Prefix::V6(_) => panic!("expected V4 prefix"),
        }
    }

    #[test]
    fn rule_without_destination_prefix() {
        let rule = FlowSpecRule {
            components: vec![FlowSpecComponent::IpProtocol(vec![NumericMatch {
                end_of_list: true,
                and_bit: false,
                lt: false,
                gt: false,
                eq: true,
                value: 17,
            }])],
        };
        assert!(rule.destination_prefix().is_none());
    }

    #[test]
    fn and_bit_numeric_ops() {
        let ops = vec![
            NumericMatch {
                end_of_list: false,
                and_bit: false,
                lt: false,
                gt: true,
                eq: true,
                value: 100,
            },
            NumericMatch {
                end_of_list: true,
                and_bit: true,
                lt: true,
                gt: false,
                eq: true,
                value: 200,
            },
        ];
        let mut buf = Vec::new();
        encode_numeric_ops(&ops, &mut buf);
        let (decoded, _) = decode_numeric_ops(&buf).unwrap();
        assert_eq!(decoded.len(), 2);
        assert!(!decoded[0].and_bit);
        assert!(decoded[0].gt);
        assert!(decoded[0].eq);
        assert!(decoded[1].and_bit);
        assert!(decoded[1].lt);
        assert!(decoded[1].eq);
    }
}
