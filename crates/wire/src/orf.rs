//! Outbound Route Filtering (ORF) types and codec — RFC 5291 + RFC 5292.
//!
//! ORF is a negotiated capability (code 3) that lets a BGP speaker push a
//! filter to its peer; the peer applies that filter to the routes it
//! advertises back. rustbgpd implements the **receive** side of the
//! Address-Prefix ORF-Type (RFC 5292): it advertises that it is willing to
//! receive ORF entries and applies them to its Adj-RIB-Out for that peer.
//!
//! This module is the pure wire codec. Semantic validation (is the ORF-Type
//! negotiated? is `min_len <= max_len`?) is the caller's responsibility — see
//! the transport/RIB layers. Only genuine BGP-framing errors (truncation, or a
//! group length that overruns the message body) return a `DecodeError`; a
//! malformed Address-Prefix *entry* (undefined Action, or a prefix length
//! beyond the address family) decodes into [`OrfEntries::Malformed`] so the
//! caller can apply the RFC 5291 §5.2 reset instead of tearing the session down.

use bytes::{Buf, BufMut, Bytes};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::capability::{Afi, Safi};
use crate::constants::orf;
use crate::error::DecodeError;
use crate::nlri::{Ipv4Prefix, Ipv6Prefix, Prefix};

/// ORF-Type (RFC 5291 §5 / RFC 5292). Unknown types are preserved so the
/// codec round-trips forward-defined types losslessly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OrfType {
    /// Address-Prefix ORF-Type 64 (RFC 5292) — the standard value.
    AddressPrefix,
    /// Legacy pre-standard Address-Prefix ORF-Type 128 (Cisco).
    AddressPrefixLegacy,
    /// Any other ORF-Type value, preserved verbatim.
    Unknown(u8),
}

impl OrfType {
    /// Create from the raw 8-bit ORF-Type value.
    #[must_use]
    pub fn from_u8(value: u8) -> Self {
        match value {
            orf::TYPE_ADDRESS_PREFIX => Self::AddressPrefix,
            orf::TYPE_ADDRESS_PREFIX_LEGACY => Self::AddressPrefixLegacy,
            other => Self::Unknown(other),
        }
    }

    /// Raw 8-bit ORF-Type value.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::AddressPrefix => orf::TYPE_ADDRESS_PREFIX,
            Self::AddressPrefixLegacy => orf::TYPE_ADDRESS_PREFIX_LEGACY,
            Self::Unknown(value) => value,
        }
    }

    /// Whether this type uses the RFC 5292 Address-Prefix entry encoding.
    #[must_use]
    pub fn is_address_prefix(self) -> bool {
        matches!(self, Self::AddressPrefix | Self::AddressPrefixLegacy)
    }
}

/// Capability Send/Receive field (RFC 5291 §4). Unknown values are preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OrfSendReceive {
    /// The speaker is willing to receive ORF entries from its peer.
    Receive,
    /// The speaker is willing to send ORF entries to its peer.
    Send,
    /// The speaker is willing to both send and receive ORF entries.
    Both,
    /// Any other value, preserved verbatim.
    Unknown(u8),
}

impl OrfSendReceive {
    /// Create from the raw 8-bit Send/Receive value.
    #[must_use]
    pub fn from_u8(value: u8) -> Self {
        match value {
            orf::SEND_RECEIVE_RECEIVE => Self::Receive,
            orf::SEND_RECEIVE_SEND => Self::Send,
            orf::SEND_RECEIVE_BOTH => Self::Both,
            other => Self::Unknown(other),
        }
    }

    /// Raw 8-bit Send/Receive value.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Receive => orf::SEND_RECEIVE_RECEIVE,
            Self::Send => orf::SEND_RECEIVE_SEND,
            Self::Both => orf::SEND_RECEIVE_BOTH,
            Self::Unknown(value) => value,
        }
    }

    /// Whether the advertiser is willing to **send** ORF entries (Send or Both).
    #[must_use]
    pub fn can_send(self) -> bool {
        matches!(self, Self::Send | Self::Both)
    }

    /// Whether the advertiser is willing to **receive** ORF entries (Receive or Both).
    #[must_use]
    pub fn can_receive(self) -> bool {
        matches!(self, Self::Receive | Self::Both)
    }
}

/// One (ORF-Type, Send/Receive) pair inside a capability block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrfCapType {
    /// The ORF-Type.
    pub orf_type: OrfType,
    /// Send/Receive role advertised for this type.
    pub send_receive: OrfSendReceive,
}

/// One per-(AFI,SAFI) block of the ORF capability value (RFC 5291 §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrfCapEntry {
    /// Address family.
    pub afi: Afi,
    /// Sub-address family.
    pub safi: Safi,
    /// The ORF-Types advertised for this family, with their Send/Receive roles.
    pub orf_types: Vec<OrfCapType>,
}

/// ROUTE-REFRESH When-to-refresh octet (RFC 5291 §5.2). Unknown values preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WhenToRefresh {
    /// Re-run the outbound advertisement sweep immediately.
    Immediate,
    /// Install the filter now but defer the sweep to a later ROUTE-REFRESH.
    Defer,
    /// Any other value, preserved verbatim.
    Unknown(u8),
}

impl WhenToRefresh {
    /// Create from the raw 8-bit When-to-refresh value.
    #[must_use]
    pub fn from_u8(value: u8) -> Self {
        match value {
            orf::WHEN_IMMEDIATE => Self::Immediate,
            orf::WHEN_DEFER => Self::Defer,
            other => Self::Unknown(other),
        }
    }

    /// Raw 8-bit When-to-refresh value.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Immediate => orf::WHEN_IMMEDIATE,
            Self::Defer => orf::WHEN_DEFER,
            Self::Unknown(value) => value,
        }
    }
}

/// Action field of a common ORF entry header (RFC 5291 §5.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OrfAction {
    /// Add this entry to the ORF list.
    Add,
    /// Remove the matching entry from the ORF list.
    Remove,
    /// Remove all previously installed entries (entry carries only the header).
    RemoveAll,
}

/// Match field of a common ORF entry header (RFC 5291 §5.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OrfMatch {
    /// Permit routes matching this entry.
    Permit,
    /// Deny routes matching this entry.
    Deny,
}

/// A single Address-Prefix ORF entry (RFC 5291 §5.1.1 header + RFC 5292 §4).
///
/// For [`OrfAction::RemoveAll`], only the action is meaningful — `prefix` is
/// `None` and the length/sequence fields are zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressPrefixOrf {
    /// Add / Remove / Remove-All.
    pub action: OrfAction,
    /// Permit or Deny (ignored for Remove-All).
    pub match_: OrfMatch,
    /// Ordering key within the ORF list.
    pub sequence: u32,
    /// Minimum prefix length (0 = unspecified, RFC 5292 §4).
    pub min_len: u8,
    /// Maximum prefix length (0 = unspecified, RFC 5292 §4).
    pub max_len: u8,
    /// The filtered prefix (`None` for Remove-All).
    pub prefix: Option<Prefix>,
}

/// Decoded entries of one ORF-Type group inside a ROUTE-REFRESH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrfEntries {
    /// Parsed Address-Prefix entries (ORF-Type 64 or 128).
    AddressPrefix(Vec<AddressPrefixOrf>),
    /// Raw bytes for an ORF-Type this codec does not parse, preserved verbatim
    /// for lossless round-trip (the caller ignores un-negotiated types).
    Raw(Bytes),
    /// An Address-Prefix group whose entries could not be parsed (undefined
    /// Action, prefix length beyond the family, etc.). Per RFC 5291 §5.2 the
    /// receiver ignores the malformed entries and removes the previously
    /// installed ORF list of that type — it does not tear the session down,
    /// so this is surfaced as data rather than a `DecodeError`. The raw bytes
    /// are preserved for lossless round-trip.
    Malformed(Bytes),
}

/// One ORF-Type group within a ROUTE-REFRESH ORF payload (RFC 5291 §5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrfEntryGroup {
    /// The ORF-Type of this group.
    pub orf_type: OrfType,
    /// The group's entries.
    pub entries: OrfEntries,
}

/// The ORF section carried in a ROUTE-REFRESH message (RFC 5291 §5.2),
/// following the standard AFI/Reserved/SAFI header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrfPayload {
    /// When-to-refresh directive.
    pub when_to_refresh: WhenToRefresh,
    /// One or more ORF-Type groups.
    pub groups: Vec<OrfEntryGroup>,
}

// ── Capability value codec (RFC 5291 §4) ─────────────────────────────────

/// Encoded length of the ORF capability value (sum over blocks).
#[must_use]
pub fn capability_value_len(entries: &[OrfCapEntry]) -> usize {
    // Per block: AFI(2) + Reserved(1) + SAFI(1) + NumberOfORFs(1) + 2×types.
    entries.iter().map(|e| 5 + 2 * e.orf_types.len()).sum()
}

/// Encode the ORF capability value (without the capability code/length header).
pub fn encode_capability_value(entries: &[OrfCapEntry], buf: &mut impl BufMut) {
    for entry in entries {
        buf.put_u16(entry.afi as u16);
        buf.put_u8(0); // reserved
        buf.put_u8(entry.safi as u8);
        // Number of ORFs — bounded by the 255-byte capability value, so a
        // u8 cast cannot truncate in practice; clamp defensively.
        let count = u8::try_from(entry.orf_types.len()).unwrap_or(u8::MAX);
        buf.put_u8(count);
        for t in &entry.orf_types {
            buf.put_u8(t.orf_type.as_u8());
            buf.put_u8(t.send_receive.as_u8());
        }
    }
}

/// Decode the ORF capability value. Returns `None` on a structural error or an
/// unrecognized AFI/SAFI, so the caller can preserve the capability as
/// `Capability::Unknown` for a lossless round-trip (mirroring Add-Path).
#[must_use]
pub fn decode_capability_value(mut raw: &[u8]) -> Option<Vec<OrfCapEntry>> {
    // RFC 5291 §4: the value carries one or more blocks. An empty value is
    // malformed — return None so the caller preserves it as Unknown.
    if raw.is_empty() {
        return None;
    }
    let mut entries = Vec::new();
    while !raw.is_empty() {
        if raw.len() < 5 {
            return None;
        }
        let afi_raw = u16::from_be_bytes([raw[0], raw[1]]);
        let safi_raw = raw[3];
        let count = usize::from(raw[4]);
        raw = &raw[5..];
        if raw.len() < count * 2 {
            return None;
        }
        let afi = Afi::from_u16(afi_raw)?;
        let safi = Safi::from_u8(safi_raw)?;
        let mut orf_types = Vec::with_capacity(count);
        for _ in 0..count {
            orf_types.push(OrfCapType {
                orf_type: OrfType::from_u8(raw[0]),
                send_receive: OrfSendReceive::from_u8(raw[1]),
            });
            raw = &raw[2..];
        }
        entries.push(OrfCapEntry {
            afi,
            safi,
            orf_types,
        });
    }
    Some(entries)
}

// ── ROUTE-REFRESH ORF payload codec (RFC 5291 §5.2) ──────────────────────

/// Decode the ORF section of a ROUTE-REFRESH body, after the AFI/Reserved/SAFI
/// header. `family` is the resolved AFI of the message (needed to size
/// Address-Prefix entries); if `None`, all groups are kept as raw bytes.
///
/// # Errors
///
/// Returns [`DecodeError`] only on genuine framing problems: truncation, or a
/// group length that overruns the body. A malformed Address-Prefix *entry*
/// (undefined Action, or a prefix length beyond the address family) does not
/// error — that group decodes into [`OrfEntries::Malformed`] for the caller to
/// reset (RFC 5291 §5.2).
pub fn decode_route_refresh_orf(
    buf: &mut impl Buf,
    family: Option<Afi>,
) -> Result<OrfPayload, DecodeError> {
    if buf.remaining() < 1 {
        return Err(DecodeError::Incomplete {
            needed: 1,
            available: buf.remaining(),
        });
    }
    let when_to_refresh = WhenToRefresh::from_u8(buf.get_u8());

    let mut groups = Vec::new();
    while buf.remaining() > 0 {
        if buf.remaining() < 3 {
            return Err(DecodeError::Incomplete {
                needed: 3,
                available: buf.remaining(),
            });
        }
        let orf_type = OrfType::from_u8(buf.get_u8());
        let len = usize::from(buf.get_u16());
        if buf.remaining() < len {
            return Err(DecodeError::Incomplete {
                needed: len,
                available: buf.remaining(),
            });
        }
        let group_bytes = buf.copy_to_bytes(len);
        let entries = if orf_type.is_address_prefix() {
            // A parse failure here is a malformed-but-framed group: surface it
            // as data (RFC 5291 §5.2 reset semantics), not a session error.
            match decode_address_prefix_entries(&group_bytes, family) {
                Ok(parsed) => OrfEntries::AddressPrefix(parsed),
                Err(_) => OrfEntries::Malformed(group_bytes),
            }
        } else {
            OrfEntries::Raw(group_bytes)
        };
        groups.push(OrfEntryGroup { orf_type, entries });
    }

    Ok(OrfPayload {
        when_to_refresh,
        groups,
    })
}

/// Encode an ORF payload after the AFI/Reserved/SAFI header (used for
/// round-trip tests; rustbgpd is receive-side and does not emit ORF in
/// production).
///
/// # Errors
///
/// Returns [`crate::error::EncodeError`] if a group's encoded entries exceed
/// the 16-bit Length field.
pub fn encode_route_refresh_orf(
    payload: &OrfPayload,
    buf: &mut impl BufMut,
) -> Result<(), crate::error::EncodeError> {
    buf.put_u8(payload.when_to_refresh.as_u8());
    for group in &payload.groups {
        let mut group_buf = bytes::BytesMut::new();
        match &group.entries {
            OrfEntries::AddressPrefix(entries) => {
                for entry in entries {
                    encode_address_prefix_entry(entry, &mut group_buf);
                }
            }
            OrfEntries::Raw(raw) | OrfEntries::Malformed(raw) => group_buf.put_slice(raw),
        }
        let len = u16::try_from(group_buf.len()).map_err(|_| {
            crate::error::EncodeError::ValueOutOfRange {
                field: "orf_group_length",
                value: group_buf.len().to_string(),
            }
        })?;
        buf.put_u8(group.orf_type.as_u8());
        buf.put_u16(len);
        buf.put_slice(&group_buf);
    }
    Ok(())
}

/// Encoded length of an ORF payload: When-to-refresh(1) + per group
/// `ORF-Type(1) + Length(2) + entry bytes`.
#[must_use]
pub fn route_refresh_orf_len(payload: &OrfPayload) -> usize {
    let mut len = 1;
    for group in &payload.groups {
        let entry_bytes = match &group.entries {
            OrfEntries::AddressPrefix(entries) => {
                entries.iter().map(address_prefix_entry_len).sum::<usize>()
            }
            OrfEntries::Raw(raw) | OrfEntries::Malformed(raw) => raw.len(),
        };
        len += 3 + entry_bytes;
    }
    len
}

fn address_prefix_entry_len(entry: &AddressPrefixOrf) -> usize {
    match entry.action {
        OrfAction::RemoveAll => 1,
        OrfAction::Add | OrfAction::Remove => {
            // header(1) + sequence(4) + min(1) + max(1) + prefixlen(1) + prefix
            let prefix_bytes = entry
                .prefix
                .map_or(0, |p| usize::from(p.prefix_len().div_ceil(8)));
            8 + prefix_bytes
        }
    }
}

fn decode_address_prefix_entries(
    mut raw: &[u8],
    family: Option<Afi>,
) -> Result<Vec<AddressPrefixOrf>, DecodeError> {
    let mut entries = Vec::new();
    while !raw.is_empty() {
        let header = raw[0];
        raw = &raw[1..];
        let match_ = if header & orf::MATCH_MASK != 0 {
            OrfMatch::Deny
        } else {
            OrfMatch::Permit
        };
        let action = match header & orf::ACTION_MASK {
            orf::ACTION_ADD => OrfAction::Add,
            orf::ACTION_REMOVE => OrfAction::Remove,
            orf::ACTION_REMOVE_ALL => OrfAction::RemoveAll,
            // The 0x40 bit pattern is undefined — a genuine framing error.
            _ => {
                return Err(DecodeError::InvalidNetworkField {
                    detail: format!("ORF entry has undefined Action in header {header:#x}"),
                    data: vec![header],
                });
            }
        };
        if action == OrfAction::RemoveAll {
            entries.push(AddressPrefixOrf {
                action,
                match_,
                sequence: 0,
                min_len: 0,
                max_len: 0,
                prefix: None,
            });
            continue;
        }

        // Add / Remove: sequence(4) + min(1) + max(1) + prefixlen(1) + prefix.
        if raw.len() < 7 {
            return Err(DecodeError::Incomplete {
                needed: 7,
                available: raw.len(),
            });
        }
        let sequence = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let min_len = raw[4];
        let max_len = raw[5];
        let prefix_len = raw[6];
        raw = &raw[7..];

        let prefix = decode_orf_prefix(&mut raw, family, prefix_len)?;
        entries.push(AddressPrefixOrf {
            action,
            match_,
            sequence,
            min_len,
            max_len,
            prefix: Some(prefix),
        });
    }
    Ok(entries)
}

fn decode_orf_prefix(
    raw: &mut &[u8],
    family: Option<Afi>,
    prefix_len: u8,
) -> Result<Prefix, DecodeError> {
    let max_len = match family {
        Some(Afi::Ipv4) => 32,
        Some(Afi::Ipv6) => 128,
        _ => {
            return Err(DecodeError::InvalidNetworkField {
                detail: "ORF Address-Prefix entry on a non-IP address family".into(),
                data: vec![],
            });
        }
    };
    if prefix_len > max_len {
        return Err(DecodeError::InvalidNetworkField {
            detail: format!("ORF prefix length {prefix_len} exceeds {max_len}"),
            data: vec![prefix_len],
        });
    }
    let byte_count = usize::from(prefix_len.div_ceil(8));
    if raw.len() < byte_count {
        return Err(DecodeError::Incomplete {
            needed: byte_count,
            available: raw.len(),
        });
    }
    let prefix = match family {
        Some(Afi::Ipv4) => {
            let mut octets = [0u8; 4];
            octets[..byte_count].copy_from_slice(&raw[..byte_count]);
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(octets), prefix_len))
        }
        Some(Afi::Ipv6) => {
            let mut octets = [0u8; 16];
            octets[..byte_count].copy_from_slice(&raw[..byte_count]);
            Prefix::V6(Ipv6Prefix::new(Ipv6Addr::from(octets), prefix_len))
        }
        _ => unreachable!("family checked above"),
    };
    *raw = &raw[byte_count..];
    Ok(prefix)
}

fn encode_address_prefix_entry(entry: &AddressPrefixOrf, buf: &mut impl BufMut) {
    let action_bits = match entry.action {
        OrfAction::Add => orf::ACTION_ADD,
        OrfAction::Remove => orf::ACTION_REMOVE,
        OrfAction::RemoveAll => orf::ACTION_REMOVE_ALL,
    };
    let match_bits = match entry.match_ {
        OrfMatch::Permit => 0,
        OrfMatch::Deny => orf::MATCH_DENY,
    };
    buf.put_u8(action_bits | match_bits);
    if entry.action == OrfAction::RemoveAll {
        return;
    }
    buf.put_u32(entry.sequence);
    buf.put_u8(entry.min_len);
    buf.put_u8(entry.max_len);
    match entry.prefix {
        Some(Prefix::V4(p)) => {
            buf.put_u8(p.len);
            let n = usize::from(p.len.div_ceil(8));
            buf.put_slice(&p.addr.octets()[..n]);
        }
        Some(Prefix::V6(p)) => {
            buf.put_u8(p.len);
            let n = usize::from(p.len.div_ceil(8));
            buf.put_slice(&p.addr.octets()[..n]);
        }
        None => buf.put_u8(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    fn ap(
        action: OrfAction,
        match_: OrfMatch,
        sequence: u32,
        min_len: u8,
        max_len: u8,
        prefix: Option<Prefix>,
    ) -> AddressPrefixOrf {
        AddressPrefixOrf {
            action,
            match_,
            sequence,
            min_len,
            max_len,
            prefix,
        }
    }

    fn v4(addr: [u8; 4], len: u8) -> Prefix {
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(addr), len))
    }

    #[test]
    fn capability_value_roundtrip_receive() {
        let entries = vec![
            OrfCapEntry {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                orf_types: vec![OrfCapType {
                    orf_type: OrfType::AddressPrefix,
                    send_receive: OrfSendReceive::Receive,
                }],
            },
            OrfCapEntry {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                orf_types: vec![
                    OrfCapType {
                        orf_type: OrfType::AddressPrefix,
                        send_receive: OrfSendReceive::Both,
                    },
                    OrfCapType {
                        orf_type: OrfType::AddressPrefixLegacy,
                        send_receive: OrfSendReceive::Send,
                    },
                ],
            },
        ];
        let mut buf = BytesMut::new();
        encode_capability_value(&entries, &mut buf);
        assert_eq!(buf.len(), capability_value_len(&entries));
        let decoded = decode_capability_value(&buf).unwrap();
        assert_eq!(decoded, entries);
    }

    #[test]
    fn capability_value_unknown_type_preserved() {
        // A future ORF-Type round-trips as Unknown, not a parse failure.
        let entries = vec![OrfCapEntry {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            orf_types: vec![OrfCapType {
                orf_type: OrfType::Unknown(200),
                send_receive: OrfSendReceive::Receive,
            }],
        }];
        let mut buf = BytesMut::new();
        encode_capability_value(&entries, &mut buf);
        let decoded = decode_capability_value(&buf).unwrap();
        assert_eq!(decoded, entries);
    }

    #[test]
    fn capability_value_unknown_afi_rejected() {
        // AFI 99 (unknown) → None so the caller preserves Capability::Unknown.
        let raw = [0u8, 99, 0, 1, 1, 64, 1];
        assert!(decode_capability_value(&raw).is_none());
    }

    #[test]
    fn capability_value_truncated_rejected() {
        let raw = [0u8, 1, 0, 1]; // missing Number-of-ORFs
        assert!(decode_capability_value(&raw).is_none());
    }

    #[test]
    fn rr_orf_roundtrip_add_permit_and_deny() {
        let payload = OrfPayload {
            when_to_refresh: WhenToRefresh::Immediate,
            groups: vec![OrfEntryGroup {
                orf_type: OrfType::AddressPrefix,
                entries: OrfEntries::AddressPrefix(vec![
                    ap(
                        OrfAction::Add,
                        OrfMatch::Permit,
                        10,
                        24,
                        32,
                        Some(v4([10, 0, 0, 0], 8)),
                    ),
                    ap(
                        OrfAction::Add,
                        OrfMatch::Deny,
                        20,
                        0,
                        0,
                        Some(v4([192, 168, 0, 0], 16)),
                    ),
                ]),
            }],
        };
        let mut buf = BytesMut::new();
        encode_route_refresh_orf(&payload, &mut buf).unwrap();
        assert_eq!(buf.len(), route_refresh_orf_len(&payload));
        let mut cursor = buf.freeze();
        let decoded = decode_route_refresh_orf(&mut cursor, Some(Afi::Ipv4)).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn rr_orf_roundtrip_remove_and_remove_all() {
        let payload = OrfPayload {
            when_to_refresh: WhenToRefresh::Defer,
            groups: vec![OrfEntryGroup {
                orf_type: OrfType::AddressPrefix,
                entries: OrfEntries::AddressPrefix(vec![
                    ap(OrfAction::RemoveAll, OrfMatch::Permit, 0, 0, 0, None),
                    ap(
                        OrfAction::Remove,
                        OrfMatch::Permit,
                        5,
                        0,
                        0,
                        Some(v4([172, 16, 0, 0], 12)),
                    ),
                ]),
            }],
        };
        let mut buf = BytesMut::new();
        encode_route_refresh_orf(&payload, &mut buf).unwrap();
        let mut cursor = buf.freeze();
        let decoded = decode_route_refresh_orf(&mut cursor, Some(Afi::Ipv4)).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn rr_orf_roundtrip_default_route_and_host_route() {
        let payload = OrfPayload {
            when_to_refresh: WhenToRefresh::Immediate,
            groups: vec![OrfEntryGroup {
                orf_type: OrfType::AddressPrefix,
                entries: OrfEntries::AddressPrefix(vec![
                    ap(
                        OrfAction::Add,
                        OrfMatch::Permit,
                        1,
                        0,
                        0,
                        Some(v4([0, 0, 0, 0], 0)),
                    ),
                    ap(
                        OrfAction::Add,
                        OrfMatch::Permit,
                        2,
                        0,
                        0,
                        Some(v4([10, 1, 2, 3], 32)),
                    ),
                ]),
            }],
        };
        let mut buf = BytesMut::new();
        encode_route_refresh_orf(&payload, &mut buf).unwrap();
        let mut cursor = buf.freeze();
        let decoded = decode_route_refresh_orf(&mut cursor, Some(Afi::Ipv4)).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn rr_orf_roundtrip_ipv6_host_route() {
        let p = Prefix::V6(Ipv6Prefix::new("2001:db8::1".parse().unwrap(), 128));
        let payload = OrfPayload {
            when_to_refresh: WhenToRefresh::Immediate,
            groups: vec![OrfEntryGroup {
                orf_type: OrfType::AddressPrefix,
                entries: OrfEntries::AddressPrefix(vec![ap(
                    OrfAction::Add,
                    OrfMatch::Deny,
                    7,
                    64,
                    128,
                    Some(p),
                )]),
            }],
        };
        let mut buf = BytesMut::new();
        encode_route_refresh_orf(&payload, &mut buf).unwrap();
        let mut cursor = buf.freeze();
        let decoded = decode_route_refresh_orf(&mut cursor, Some(Afi::Ipv6)).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn rr_orf_legacy_type_128_parsed() {
        let payload = OrfPayload {
            when_to_refresh: WhenToRefresh::Immediate,
            groups: vec![OrfEntryGroup {
                orf_type: OrfType::AddressPrefixLegacy,
                entries: OrfEntries::AddressPrefix(vec![ap(
                    OrfAction::Add,
                    OrfMatch::Permit,
                    1,
                    0,
                    0,
                    Some(v4([10, 0, 0, 0], 8)),
                )]),
            }],
        };
        let mut buf = BytesMut::new();
        encode_route_refresh_orf(&payload, &mut buf).unwrap();
        let mut cursor = buf.freeze();
        let decoded = decode_route_refresh_orf(&mut cursor, Some(Afi::Ipv4)).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn rr_orf_unknown_type_preserved_as_raw() {
        // ORF-Type 9 (unknown): keep the entry bytes verbatim, don't error.
        let mut buf = BytesMut::new();
        buf.put_u8(WhenToRefresh::Immediate.as_u8());
        buf.put_u8(9); // unknown ORF-Type
        buf.put_u16(3);
        buf.put_slice(&[0xAA, 0xBB, 0xCC]);
        let mut cursor = buf.freeze();
        let decoded = decode_route_refresh_orf(&mut cursor, Some(Afi::Ipv4)).unwrap();
        assert_eq!(decoded.groups.len(), 1);
        assert_eq!(decoded.groups[0].orf_type, OrfType::Unknown(9));
        assert_eq!(
            decoded.groups[0].entries,
            OrfEntries::Raw(Bytes::from_static(&[0xAA, 0xBB, 0xCC]))
        );
    }

    #[test]
    fn rr_orf_prefix_len_over_family_max_is_malformed_not_error() {
        // prefixlen 40 for IPv4 is a malformed-but-framed group: it decodes
        // into Malformed (RFC 5291 §5.2 reset semantics), not a session error.
        let mut buf = BytesMut::new();
        buf.put_u8(WhenToRefresh::Immediate.as_u8());
        buf.put_u8(OrfType::AddressPrefix.as_u8());
        buf.put_u16(8);
        buf.put_u8(orf::ACTION_ADD);
        buf.put_u32(1);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(40); // prefixlen > 32
        let mut cursor = buf.freeze();
        let decoded = decode_route_refresh_orf(&mut cursor, Some(Afi::Ipv4)).unwrap();
        assert!(matches!(
            decoded.groups[0].entries,
            OrfEntries::Malformed(_)
        ));
    }

    #[test]
    fn rr_orf_undefined_action_is_malformed_not_error() {
        let mut buf = BytesMut::new();
        buf.put_u8(WhenToRefresh::Immediate.as_u8());
        buf.put_u8(OrfType::AddressPrefix.as_u8());
        buf.put_u16(1);
        buf.put_u8(0x40); // undefined Action bit pattern
        let mut cursor = buf.freeze();
        let decoded = decode_route_refresh_orf(&mut cursor, Some(Afi::Ipv4)).unwrap();
        assert!(matches!(
            decoded.groups[0].entries,
            OrfEntries::Malformed(_)
        ));
    }

    #[test]
    fn rr_orf_truncated_group_rejected() {
        let mut buf = BytesMut::new();
        buf.put_u8(WhenToRefresh::Immediate.as_u8());
        buf.put_u8(OrfType::AddressPrefix.as_u8());
        buf.put_u16(20); // claims 20 bytes but none follow
        let mut cursor = buf.freeze();
        assert!(decode_route_refresh_orf(&mut cursor, Some(Afi::Ipv4)).is_err());
    }
}
