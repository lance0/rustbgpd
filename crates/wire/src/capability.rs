use bytes::{Buf, BufMut, Bytes};

use crate::constants::{capability_code, param_type};
use crate::error::{DecodeError, EncodeError};

/// Address Family Identifier (IANA).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
#[non_exhaustive]
pub enum Afi {
    /// IPv4 (AFI 1).
    Ipv4 = 1,
    /// IPv6 (AFI 2).
    Ipv6 = 2,
    /// Layer-2 VPN (AFI 25) — carrier family for EVPN (RFC 7432).
    L2Vpn = 25,
    /// BGP Link-State (AFI 16388, RFC 9552).
    BgpLs = 16_388,
}

impl Afi {
    /// Create from a raw 16-bit AFI value.
    #[must_use]
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Ipv4),
            2 => Some(Self::Ipv6),
            25 => Some(Self::L2Vpn),
            16_388 => Some(Self::BgpLs),
            _ => None,
        }
    }
}

/// Subsequent Address Family Identifier (IANA).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum Safi {
    /// Unicast forwarding (SAFI 1).
    Unicast = 1,
    /// Multicast forwarding (SAFI 2).
    Multicast = 2,
    /// RFC 8277 labeled-unicast — only valid with [`Afi::Ipv4`] /
    /// [`Afi::Ipv6`].
    LabeledUnicast = 4,
    /// RFC 7432 EVPN — only valid with [`Afi::L2Vpn`].
    Evpn = 70,
    /// RFC 9552 BGP-LS — only valid with [`Afi::BgpLs`].
    BgpLs = 71,
    /// RFC 9552 BGP-LS VPN — only valid with [`Afi::BgpLs`].
    BgpLsVpn = 72,
    /// RFC 4364 / RFC 4659 MPLS L3VPN (VPNv4/VPNv6) — only valid with
    /// [`Afi::Ipv4`] / [`Afi::Ipv6`].
    MplsVpn = 128,
    /// RFC 4684 Route Target Constrain — only valid with [`Afi::Ipv4`].
    RtConstrain = 132,
    /// RFC 8955 `FlowSpec`.
    FlowSpec = 133,
}

impl Safi {
    /// Create from a raw 8-bit SAFI value.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Unicast),
            2 => Some(Self::Multicast),
            4 => Some(Self::LabeledUnicast),
            70 => Some(Self::Evpn),
            71 => Some(Self::BgpLs),
            72 => Some(Self::BgpLsVpn),
            128 => Some(Self::MplsVpn),
            132 => Some(Self::RtConstrain),
            133 => Some(Self::FlowSpec),
            _ => None,
        }
    }
}

/// Per-AFI/SAFI entry in the Graceful Restart capability (RFC 4724 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GracefulRestartFamily {
    /// Address family.
    pub afi: Afi,
    /// Sub-address family.
    pub safi: Safi,
    /// Whether the peer preserved forwarding state for this family.
    pub forwarding_preserved: bool,
}

/// Add-Path send/receive mode per AFI/SAFI (RFC 7911 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AddPathMode {
    /// Peer can receive multiple paths.
    Receive = 1,
    /// Peer can send multiple paths.
    Send = 2,
    /// Peer can both send and receive multiple paths.
    Both = 3,
}

impl AddPathMode {
    /// Create from a raw 8-bit mode value.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Receive),
            2 => Some(Self::Send),
            3 => Some(Self::Both),
            _ => None,
        }
    }
}

/// Per-AFI/SAFI entry in the Add-Path capability (RFC 7911 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddPathFamily {
    /// Address family.
    pub afi: Afi,
    /// Sub-address family.
    pub safi: Safi,
    /// Send/receive mode for this family.
    pub send_receive: AddPathMode,
}

/// Per-family receiver preference carried by the experimental Paths-Limit
/// capability (draft-abraitis-idr-addpath-paths-limit-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathsLimitFamily {
    /// Address family.
    pub afi: Afi,
    /// Sub-address family.
    pub safi: Safi,
    /// Maximum number of paths the sender would like to receive.
    pub receive_limit: u16,
}

/// Per-family entry in the Extended Next Hop Encoding capability (RFC 8950).
///
/// Each tuple advertises that NLRI for `(nlri_afi, nlri_safi)` may use the
/// specified `next_hop_afi` in `MP_REACH_NLRI`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtendedNextHopFamily {
    /// AFI of the NLRI.
    pub nlri_afi: Afi,
    /// SAFI of the NLRI.
    pub nlri_safi: Safi,
    /// AFI of the next-hop encoding.
    pub next_hop_afi: Afi,
}

/// Per-AFI/SAFI entry in the Long-Lived Graceful Restart capability (RFC 9494).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LlgrFamily {
    /// Address family.
    pub afi: Afi,
    /// Sub-address family.
    pub safi: Safi,
    /// Whether the peer preserved forwarding state for this family during LLGR.
    pub forwarding_preserved: bool,
    /// Long-lived stale time in seconds (24-bit, max `16_777_215` ≈ 194 days).
    pub stale_time: u32,
}

/// BGP Role (RFC 9234 §4) — the speaker's role on this eBGP session.
///
/// The numeric encoding is the 1-byte capability value carried in the
/// Role capability (code 9). The compatibility matrix
/// (Provider↔Customer, RS↔RS-Client, Peer↔Peer) is enforced by the FSM
/// negotiator, not by this codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum BgpRole {
    /// Speaker is a transit Provider for the peer.
    Provider = 0,
    /// Speaker is a Route Server (RFC 7947).
    RouteServer = 1,
    /// Speaker is a client of a Route Server.
    RouteServerClient = 2,
    /// Speaker is a Customer of the peer.
    Customer = 3,
    /// Speaker is a lateral Peer of the peer.
    Peer = 4,
}

impl BgpRole {
    /// Create from a raw 8-bit role value. Unknown values yield `None` so
    /// the caller can preserve them via [`Capability::Unknown`].
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Provider),
            1 => Some(Self::RouteServer),
            2 => Some(Self::RouteServerClient),
            3 => Some(Self::Customer),
            4 => Some(Self::Peer),
            _ => None,
        }
    }

    /// Raw 8-bit encoding for the Role capability value field.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// BGP capability as negotiated in OPEN optional parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Capability {
    /// RFC 4760: Multi-Protocol Extensions.
    MultiProtocol {
        /// Address family.
        afi: Afi,
        /// Sub-address family.
        safi: Safi,
    },
    /// RFC 8950: Extended Next Hop Encoding.
    ExtendedNextHop(Vec<ExtendedNextHopFamily>),
    /// RFC 4724: Graceful Restart.
    GracefulRestart {
        /// R-bit: the sender has restarted and its forwarding state
        /// may have been preserved.
        restart_state: bool,
        /// N-bit (RFC 8538): the sender supports Notification GR — NOTIFICATIONs
        /// trigger GR unless Cease/Hard Reset (subcode 9) is used.
        notification: bool,
        /// Time in seconds the sender will retain stale routes (12-bit, max 4095).
        restart_time: u16,
        /// Per-AFI/SAFI forwarding state flags.
        families: Vec<GracefulRestartFamily>,
    },
    /// RFC 2918: Route Refresh.
    RouteRefresh,
    /// RFC 7313: Enhanced Route Refresh.
    EnhancedRouteRefresh,
    /// RFC 8654: Extended Messages (raise max message length to 65535).
    ExtendedMessage,
    /// RFC 9494: Long-Lived Graceful Restart.
    LongLivedGracefulRestart(Vec<LlgrFamily>),
    /// RFC 7911: Add-Path — advertise/receive multiple paths per prefix.
    AddPath(Vec<AddPathFamily>),
    /// Experimental Paths-Limit receiver preferences (capability code 76).
    PathsLimit(Vec<PathsLimitFamily>),
    /// RFC 5291: Outbound Route Filtering — per-family ORF-Type/role blocks.
    OutboundRouteFilter(Vec<crate::orf::OrfCapEntry>),
    /// RFC 6793: 4-Byte AS Number.
    FourOctetAs {
        /// The 4-byte autonomous system number.
        asn: u32,
    },
    /// RFC 9234 §4: BGP Role. The speaker's role on this eBGP session.
    Role {
        /// The role advertised by this speaker.
        role: BgpRole,
    },
    /// Unknown or unrecognized capability, preserved for re-emission.
    Unknown {
        /// Capability code.
        code: u8,
        /// Raw capability value bytes.
        data: Bytes,
    },
}

impl Capability {
    /// Decode a single capability TLV from a buffer.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::MalformedOptionalParameter`] if the TLV is
    /// truncated or the claimed length exceeds the remaining bytes.
    #[expect(
        clippy::too_many_lines,
        reason = "capability decoder keeps TLV length validation and variant decoding together"
    )]
    pub fn decode(buf: &mut impl Buf) -> Result<Self, DecodeError> {
        if buf.remaining() < 2 {
            return Err(DecodeError::MalformedOptionalParameter {
                offset: 0,
                detail: "capability TLV too short".into(),
            });
        }

        let code = buf.get_u8();
        let length = buf.get_u8();

        if buf.remaining() < usize::from(length) {
            return Err(DecodeError::MalformedOptionalParameter {
                offset: 0,
                detail: format!(
                    "capability code {code} claims length {length}, \
                     but only {} bytes remain",
                    buf.remaining()
                ),
            });
        }

        match code {
            capability_code::MULTI_PROTOCOL => {
                if length != 4 {
                    // Store as unknown if length is wrong
                    let data = buf.copy_to_bytes(usize::from(length));
                    return Ok(Capability::Unknown { code, data });
                }
                let afi_raw = buf.get_u16();
                let _reserved = buf.get_u8();
                let safi_raw = buf.get_u8();

                if let (Some(afi), Some(safi)) = (Afi::from_u16(afi_raw), Safi::from_u8(safi_raw)) {
                    Ok(Capability::MultiProtocol { afi, safi })
                } else {
                    // Unrecognized AFI/SAFI — store as unknown
                    let mut data = bytes::BytesMut::with_capacity(4);
                    data.put_u16(afi_raw);
                    data.put_u8(0); // reserved
                    data.put_u8(safi_raw);
                    Ok(Capability::Unknown {
                        code,
                        data: data.freeze(),
                    })
                }
            }
            capability_code::ROUTE_REFRESH => {
                if length != 0 {
                    let data = buf.copy_to_bytes(usize::from(length));
                    return Ok(Capability::Unknown { code, data });
                }
                Ok(Capability::RouteRefresh)
            }
            capability_code::ENHANCED_ROUTE_REFRESH => {
                if length != 0 {
                    let data = buf.copy_to_bytes(usize::from(length));
                    return Ok(Capability::Unknown { code, data });
                }
                Ok(Capability::EnhancedRouteRefresh)
            }
            capability_code::EXTENDED_NEXT_HOP => {
                // RFC 8950: repeated tuples of
                // NLRI AFI (2) | NLRI SAFI (2) | Next Hop AFI (2)
                if !usize::from(length).is_multiple_of(6) {
                    let data = buf.copy_to_bytes(usize::from(length));
                    return Ok(Capability::Unknown { code, data });
                }
                let entry_count = usize::from(length) / 6;
                let raw_data = buf.copy_to_bytes(usize::from(length));
                let mut cursor = raw_data.clone();
                let mut families = Vec::with_capacity(entry_count);
                let mut all_valid = true;
                for _ in 0..entry_count {
                    let nlri_afi_raw = cursor.get_u16();
                    let nlri_safi_field = cursor.get_u16();
                    let next_hop_afi_raw = cursor.get_u16();
                    let nlri_safi = u8::try_from(nlri_safi_field).ok().and_then(Safi::from_u8);
                    if let (Some(nlri_afi), Some(nlri_safi), Some(next_hop_afi)) = (
                        Afi::from_u16(nlri_afi_raw),
                        nlri_safi,
                        Afi::from_u16(next_hop_afi_raw),
                    ) {
                        families.push(ExtendedNextHopFamily {
                            nlri_afi,
                            nlri_safi,
                            next_hop_afi,
                        });
                    } else {
                        all_valid = false;
                    }
                }
                if all_valid {
                    Ok(Capability::ExtendedNextHop(families))
                } else {
                    Ok(Capability::Unknown {
                        code,
                        data: raw_data,
                    })
                }
            }
            capability_code::EXTENDED_MESSAGE => {
                if length != 0 {
                    let data = buf.copy_to_bytes(usize::from(length));
                    return Ok(Capability::Unknown { code, data });
                }
                Ok(Capability::ExtendedMessage)
            }
            capability_code::GRACEFUL_RESTART => {
                // Minimum 2 bytes (restart flags/time). Each family is 4 bytes.
                if length < 2 || !(length - 2).is_multiple_of(4) {
                    let data = buf.copy_to_bytes(usize::from(length));
                    return Ok(Capability::Unknown { code, data });
                }
                let flags_and_time = buf.get_u16();
                let restart_state = (flags_and_time & 0x8000) != 0;
                let notification = (flags_and_time & 0x4000) != 0;
                let restart_time = flags_and_time & 0x0FFF;
                let family_count = (length - 2) / 4;
                let mut families = Vec::with_capacity(usize::from(family_count));
                for _ in 0..family_count {
                    let afi_raw = buf.get_u16();
                    let safi_raw = buf.get_u8();
                    let flags = buf.get_u8();
                    if let (Some(afi), Some(safi)) =
                        (Afi::from_u16(afi_raw), Safi::from_u8(safi_raw))
                    {
                        families.push(GracefulRestartFamily {
                            afi,
                            safi,
                            forwarding_preserved: (flags & 0x80) != 0,
                        });
                    }
                    // Skip unrecognized AFI/SAFI entries silently
                }
                Ok(Capability::GracefulRestart {
                    restart_state,
                    notification,
                    restart_time,
                    families,
                })
            }
            capability_code::LONG_LIVED_GRACEFUL_RESTART => {
                // RFC 9494: repeated entries of AFI(2) + SAFI(1) + flags(1) + stale_time(3) = 7 bytes each
                if !usize::from(length).is_multiple_of(7) {
                    let data = buf.copy_to_bytes(usize::from(length));
                    return Ok(Capability::Unknown { code, data });
                }
                let entry_count = usize::from(length) / 7;
                let raw_data = buf.copy_to_bytes(usize::from(length));
                let mut cursor = raw_data.clone();
                let mut families = Vec::with_capacity(entry_count);
                let mut all_valid = true;
                for _ in 0..entry_count {
                    let afi_raw = cursor.get_u16();
                    let safi_raw = cursor.get_u8();
                    let flags = cursor.get_u8();
                    // stale_time is 24-bit (3 bytes, big-endian)
                    let st_hi = cursor.get_u8();
                    let st_lo = cursor.get_u16();
                    let stale_time = (u32::from(st_hi) << 16) | u32::from(st_lo);
                    if let (Some(afi), Some(safi)) =
                        (Afi::from_u16(afi_raw), Safi::from_u8(safi_raw))
                    {
                        families.push(LlgrFamily {
                            afi,
                            safi,
                            forwarding_preserved: (flags & 0x80) != 0,
                            stale_time,
                        });
                    } else {
                        all_valid = false;
                    }
                }
                if all_valid {
                    Ok(Capability::LongLivedGracefulRestart(families))
                } else {
                    Ok(Capability::Unknown {
                        code,
                        data: raw_data,
                    })
                }
            }
            capability_code::ADD_PATH => {
                // RFC 7911 §4: value is N entries of (AFI:2 + SAFI:1 + mode:1) = 4 bytes each
                if length == 0 || !usize::from(length).is_multiple_of(4) {
                    let data = buf.copy_to_bytes(usize::from(length));
                    return Ok(Capability::Unknown { code, data });
                }
                let entry_count = usize::from(length) / 4;
                // Snapshot the raw bytes before parsing so we can fall back
                // to Unknown if any entry would be discarded (lossless roundtrip).
                let raw_data = buf.copy_to_bytes(usize::from(length));
                let mut cursor = raw_data.clone();
                let mut families = Vec::with_capacity(entry_count);
                let mut all_valid = true;
                for _ in 0..entry_count {
                    let afi_raw = cursor.get_u16();
                    let safi_raw = cursor.get_u8();
                    let mode_raw = cursor.get_u8();
                    if let (Some(afi), Some(safi), Some(mode)) = (
                        Afi::from_u16(afi_raw),
                        Safi::from_u8(safi_raw),
                        AddPathMode::from_u8(mode_raw),
                    ) {
                        families.push(AddPathFamily {
                            afi,
                            safi,
                            send_receive: mode,
                        });
                    } else {
                        all_valid = false;
                    }
                }
                // Preserve as Unknown if any entry was unrecognized, to avoid
                // silently rewriting malformed capability data on re-encode.
                if all_valid {
                    Ok(Capability::AddPath(families))
                } else {
                    Ok(Capability::Unknown {
                        code,
                        data: raw_data,
                    })
                }
            }
            capability_code::PATHS_LIMIT => {
                // draft-04: repeated AFI(2) + SAFI(1) + receive-limit(2) tuples.
                if !usize::from(length).is_multiple_of(5) {
                    let data = buf.copy_to_bytes(usize::from(length));
                    return Ok(Capability::Unknown { code, data });
                }
                let raw_data = buf.copy_to_bytes(usize::from(length));
                let mut cursor = raw_data.clone();
                let mut families = Vec::with_capacity(usize::from(length) / 5);
                let mut all_valid = true;
                while cursor.has_remaining() {
                    let afi_raw = cursor.get_u16();
                    let safi_raw = cursor.get_u8();
                    let receive_limit = cursor.get_u16();
                    if let (Some(afi), Some(safi)) =
                        (Afi::from_u16(afi_raw), Safi::from_u8(safi_raw))
                    {
                        // A zero limit has no meaning and is ignored by draft-04.
                        if receive_limit != 0
                            && !families.iter().any(|entry: &PathsLimitFamily| {
                                entry.afi == afi && entry.safi == safi
                            })
                        {
                            families.push(PathsLimitFamily {
                                afi,
                                safi,
                                receive_limit,
                            });
                        }
                    } else {
                        all_valid = false;
                    }
                }
                if all_valid {
                    Ok(Capability::PathsLimit(families))
                } else {
                    Ok(Capability::Unknown {
                        code,
                        data: raw_data,
                    })
                }
            }
            capability_code::OUTBOUND_ROUTE_FILTERING => {
                // RFC 5291 §4: per-family blocks. Preserve as Unknown on a
                // structural error or unrecognized AFI/SAFI (lossless
                // round-trip, mirroring Add-Path).
                let raw = buf.copy_to_bytes(usize::from(length));
                match crate::orf::decode_capability_value(&raw) {
                    Some(entries) => Ok(Capability::OutboundRouteFilter(entries)),
                    None => Ok(Capability::Unknown { code, data: raw }),
                }
            }
            capability_code::FOUR_OCTET_AS => {
                if length != 4 {
                    let data = buf.copy_to_bytes(usize::from(length));
                    return Ok(Capability::Unknown { code, data });
                }
                let asn = buf.get_u32();
                Ok(Capability::FourOctetAs { asn })
            }
            capability_code::BGP_ROLE => {
                // RFC 9234 §4.1: Length = 1, value ∈ {0..=4}. Anything else
                // is preserved as Unknown so the peer's bytes round-trip and
                // FSM negotiation can decide whether to reject the session.
                if length != 1 {
                    let data = buf.copy_to_bytes(usize::from(length));
                    return Ok(Capability::Unknown { code, data });
                }
                let role_byte = buf.get_u8();
                if let Some(role) = BgpRole::from_u8(role_byte) {
                    Ok(Capability::Role { role })
                } else {
                    let data = Bytes::copy_from_slice(&[role_byte]);
                    Ok(Capability::Unknown { code, data })
                }
            }
            _ => {
                let data = buf.copy_to_bytes(usize::from(length));
                Ok(Capability::Unknown { code, data })
            }
        }
    }

    /// Encode a single capability TLV into a buffer.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::ValueOutOfRange`] if the capability value
    /// exceeds the 255-byte limit of the single-octet length field.
    #[expect(
        clippy::too_many_lines,
        reason = "Capability encode keeps all TLV variants in one exhaustive wire encoder"
    )]
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
        match self {
            Capability::MultiProtocol { afi, safi } => {
                buf.put_u8(capability_code::MULTI_PROTOCOL);
                buf.put_u8(4); // length
                buf.put_u16(*afi as u16);
                buf.put_u8(0); // reserved
                buf.put_u8(*safi as u8);
            }
            Capability::RouteRefresh => {
                buf.put_u8(capability_code::ROUTE_REFRESH);
                buf.put_u8(0); // zero-length value
            }
            Capability::EnhancedRouteRefresh => {
                buf.put_u8(capability_code::ENHANCED_ROUTE_REFRESH);
                buf.put_u8(0); // zero-length value
            }
            Capability::ExtendedNextHop(families) => {
                let value_len = families.len() * 6;
                if value_len > 255 {
                    return Err(EncodeError::ValueOutOfRange {
                        field: "extended_next_hop_capability_length",
                        value: value_len.to_string(),
                    });
                }
                buf.put_u8(capability_code::EXTENDED_NEXT_HOP);
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "codec bounds or masks the value before narrowing to the protocol field width"
                )]
                buf.put_u8(value_len as u8);
                for fam in families {
                    buf.put_u16(fam.nlri_afi as u16);
                    buf.put_u16(u16::from(fam.nlri_safi as u8));
                    buf.put_u16(fam.next_hop_afi as u16);
                }
            }
            Capability::ExtendedMessage => {
                buf.put_u8(capability_code::EXTENDED_MESSAGE);
                buf.put_u8(0); // zero-length value
            }
            Capability::GracefulRestart {
                restart_state,
                notification,
                restart_time,
                families,
            } => {
                let value_len = 2 + families.len() * 4;
                if value_len > 255 {
                    return Err(EncodeError::ValueOutOfRange {
                        field: "graceful_restart_capability_length",
                        value: value_len.to_string(),
                    });
                }
                if *restart_time > 4095 {
                    return Err(EncodeError::ValueOutOfRange {
                        field: "graceful_restart_time",
                        value: restart_time.to_string(),
                    });
                }
                buf.put_u8(capability_code::GRACEFUL_RESTART);
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "codec bounds or masks the value before narrowing to the protocol field width"
                )]
                buf.put_u8(value_len as u8);
                let mut flags_and_time = *restart_time;
                if *restart_state {
                    flags_and_time |= 0x8000;
                }
                if *notification {
                    flags_and_time |= 0x4000;
                }
                buf.put_u16(flags_and_time);
                for fam in families {
                    buf.put_u16(fam.afi as u16);
                    buf.put_u8(fam.safi as u8);
                    buf.put_u8(if fam.forwarding_preserved { 0x80 } else { 0 });
                }
            }
            Capability::LongLivedGracefulRestart(families) => {
                let value_len = families.len() * 7;
                if value_len > 255 {
                    return Err(EncodeError::ValueOutOfRange {
                        field: "llgr_capability_length",
                        value: value_len.to_string(),
                    });
                }
                buf.put_u8(capability_code::LONG_LIVED_GRACEFUL_RESTART);
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "codec bounds or masks the value before narrowing to the protocol field width"
                )]
                buf.put_u8(value_len as u8);
                for fam in families {
                    buf.put_u16(fam.afi as u16);
                    buf.put_u8(fam.safi as u8);
                    buf.put_u8(if fam.forwarding_preserved { 0x80 } else { 0 });
                    // stale_time is 24-bit (3 bytes, big-endian)
                    #[expect(
                        clippy::cast_possible_truncation,
                        reason = "codec bounds or masks the value before narrowing to the protocol field width"
                    )]
                    buf.put_u8((fam.stale_time >> 16) as u8);
                    buf.put_u16((fam.stale_time & 0xFFFF) as u16);
                }
            }
            Capability::AddPath(families) => {
                let value_len = families.len() * 4;
                if value_len > 255 {
                    return Err(EncodeError::ValueOutOfRange {
                        field: "add_path_capability_length",
                        value: value_len.to_string(),
                    });
                }
                buf.put_u8(capability_code::ADD_PATH);
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "codec bounds or masks the value before narrowing to the protocol field width"
                )]
                buf.put_u8(value_len as u8);
                for fam in families {
                    buf.put_u16(fam.afi as u16);
                    buf.put_u8(fam.safi as u8);
                    buf.put_u8(fam.send_receive as u8);
                }
            }
            Capability::PathsLimit(families) => {
                let value_len = families.len() * 5;
                if value_len > 255 {
                    return Err(EncodeError::ValueOutOfRange {
                        field: "paths_limit_capability_length",
                        value: value_len.to_string(),
                    });
                }
                buf.put_u8(capability_code::PATHS_LIMIT);
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "value_len is checked against the u8 maximum above"
                )]
                buf.put_u8(value_len as u8);
                for fam in families {
                    buf.put_u16(fam.afi as u16);
                    buf.put_u8(fam.safi as u8);
                    buf.put_u16(fam.receive_limit);
                }
            }
            Capability::OutboundRouteFilter(entries) => {
                // RFC 5291 §4: the value carries one or more blocks. An empty
                // list would encode to a zero-length value, which the decoder
                // (correctly) treats as malformed and round-trips as Unknown —
                // reject it here so encode/decode stay symmetric.
                if entries.is_empty() {
                    return Err(EncodeError::ValueOutOfRange {
                        field: "outbound_route_filter_capability_blocks",
                        value: "0".to_string(),
                    });
                }
                let value_len = crate::orf::capability_value_len(entries);
                if value_len > 255 {
                    return Err(EncodeError::ValueOutOfRange {
                        field: "outbound_route_filter_capability_length",
                        value: value_len.to_string(),
                    });
                }
                buf.put_u8(capability_code::OUTBOUND_ROUTE_FILTERING);
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "codec bounds or masks the value before narrowing to the protocol field width"
                )]
                buf.put_u8(value_len as u8);
                crate::orf::encode_capability_value(entries, buf);
            }
            Capability::FourOctetAs { asn } => {
                buf.put_u8(capability_code::FOUR_OCTET_AS);
                buf.put_u8(4); // length
                buf.put_u32(*asn);
            }
            Capability::Role { role } => {
                buf.put_u8(capability_code::BGP_ROLE);
                buf.put_u8(1); // length
                buf.put_u8(role.to_u8());
            }
            Capability::Unknown { code, data } => {
                if data.len() > 255 {
                    return Err(EncodeError::ValueOutOfRange {
                        field: "unknown_capability_length",
                        value: data.len().to_string(),
                    });
                }
                buf.put_u8(*code);
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "codec bounds or masks the value before narrowing to the protocol field width"
                )]
                buf.put_u8(data.len() as u8);
                buf.put_slice(data);
            }
        }
        Ok(())
    }

    /// Returns the capability code byte.
    #[must_use]
    pub fn code(&self) -> u8 {
        match self {
            Self::MultiProtocol { .. } => capability_code::MULTI_PROTOCOL,
            Self::RouteRefresh => capability_code::ROUTE_REFRESH,
            Self::EnhancedRouteRefresh => capability_code::ENHANCED_ROUTE_REFRESH,
            Self::ExtendedNextHop(_) => capability_code::EXTENDED_NEXT_HOP,
            Self::ExtendedMessage => capability_code::EXTENDED_MESSAGE,
            Self::LongLivedGracefulRestart(_) => capability_code::LONG_LIVED_GRACEFUL_RESTART,
            Self::AddPath(_) => capability_code::ADD_PATH,
            Self::PathsLimit(_) => capability_code::PATHS_LIMIT,
            Self::OutboundRouteFilter(_) => capability_code::OUTBOUND_ROUTE_FILTERING,
            Self::GracefulRestart { .. } => capability_code::GRACEFUL_RESTART,
            Self::FourOctetAs { .. } => capability_code::FOUR_OCTET_AS,
            Self::Role { .. } => capability_code::BGP_ROLE,
            Self::Unknown { code, .. } => *code,
        }
    }

    /// Encoded size of this capability TLV (code + length + value).
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        2 + match self {
            Self::MultiProtocol { .. } | Self::FourOctetAs { .. } => 4,
            Self::RouteRefresh | Self::EnhancedRouteRefresh | Self::ExtendedMessage => 0,
            Self::Role { .. } => 1,
            Self::ExtendedNextHop(families) => families.len() * 6,
            Self::LongLivedGracefulRestart(families) => families.len() * 7,
            Self::AddPath(families) => families.len() * 4,
            Self::PathsLimit(families) => families.len() * 5,
            Self::OutboundRouteFilter(entries) => crate::orf::capability_value_len(entries),
            Self::GracefulRestart { families, .. } => 2 + families.len() * 4,
            Self::Unknown { data, .. } => data.len(),
        }
    }
}

/// Decode all optional parameters from an OPEN message body.
/// Returns capabilities found in parameter type 2 TLVs.
///
/// # Errors
///
/// Returns [`DecodeError::MalformedOptionalParameter`] if any parameter TLV
/// is truncated or contains an invalid capability.
pub fn decode_optional_parameters(
    buf: &mut impl Buf,
    opt_params_len: u8,
) -> Result<Vec<Capability>, DecodeError> {
    let mut capabilities = Vec::new();
    let mut remaining = usize::from(opt_params_len);

    while remaining > 0 {
        if buf.remaining() < 2 {
            return Err(DecodeError::MalformedOptionalParameter {
                offset: usize::from(opt_params_len) - remaining,
                detail: "optional parameter TLV too short".into(),
            });
        }

        let param_type = buf.get_u8();
        let param_len = buf.get_u8();
        remaining = remaining.saturating_sub(2);

        if usize::from(param_len) > remaining || buf.remaining() < usize::from(param_len) {
            return Err(DecodeError::MalformedOptionalParameter {
                offset: usize::from(opt_params_len) - remaining,
                detail: format!(
                    "parameter type {param_type} claims length {param_len}, \
                     but only {remaining} bytes remain"
                ),
            });
        }

        if param_type == param_type::CAPABILITIES {
            // Parse capabilities from a bounded sub-buffer so a malformed
            // capability length cannot consume into the next parameter or
            // beyond the OPEN body.
            let param_bytes = buf.copy_to_bytes(usize::from(param_len));
            let mut cap_buf = param_bytes;
            while cap_buf.has_remaining() {
                let cap = Capability::decode(&mut cap_buf)?;
                capabilities.push(cap);
            }
        } else {
            // Skip unknown parameter types
            buf.advance(usize::from(param_len));
        }

        remaining = remaining.saturating_sub(usize::from(param_len));
    }

    Ok(capabilities)
}

/// Encode capabilities as OPEN optional parameters (parameter type 2).
///
/// # Errors
///
/// Returns [`EncodeError::ValueOutOfRange`] if the total capabilities size
/// exceeds 255 bytes or any individual capability is too large.
///
/// # Note
///
/// On error, partial bytes may have been written to `buf`. Callers should
/// encode into a staging buffer (as `OpenMessage::encode` does) to ensure
/// atomicity.
pub fn encode_optional_parameters(
    capabilities: &[Capability],
    buf: &mut impl BufMut,
) -> Result<(), EncodeError> {
    if capabilities.is_empty() {
        return Ok(());
    }

    // Calculate total capability TLV size
    let cap_total: usize = capabilities.iter().map(Capability::encoded_len).sum();

    if cap_total > 255 {
        return Err(EncodeError::ValueOutOfRange {
            field: "capabilities_parameter_length",
            value: cap_total.to_string(),
        });
    }

    // Parameter type 2 header
    buf.put_u8(param_type::CAPABILITIES);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "codec bounds or masks the value before narrowing to the protocol field width"
    )]
    buf.put_u8(cap_total as u8);

    for cap in capabilities {
        cap.encode(buf)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_multi_protocol_ipv4_unicast() {
        let data: &[u8] = &[1, 4, 0, 1, 0, 1]; // code=1, len=4, AFI=1, res=0, SAFI=1
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert_eq!(
            cap,
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast
            }
        );
    }

    #[test]
    fn decode_four_octet_as() {
        let data: &[u8] = &[65, 4, 0, 0, 0xFD, 0xE8]; // code=65, len=4, ASN=65000
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert_eq!(cap, Capability::FourOctetAs { asn: 65000 });
    }

    #[test]
    fn decode_unknown_capability_preserved() {
        let data: &[u8] = &[99, 3, 0xAA, 0xBB, 0xCC]; // code=99, len=3
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        match cap {
            Capability::Unknown { code, data } => {
                assert_eq!(code, 99);
                assert_eq!(data.as_ref(), &[0xAA, 0xBB, 0xCC]);
            }
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn unrecognized_afi_safi_stored_as_unknown() {
        let data: &[u8] = &[1, 4, 0, 99, 0, 1]; // code=1, len=4, AFI=99 (unknown)
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert!(matches!(cap, Capability::Unknown { code: 1, .. }));
    }

    #[test]
    fn roundtrip_multi_protocol() {
        let original = Capability::MultiProtocol {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
        };
        let mut encoded = bytes::BytesMut::with_capacity(6);
        original.encode(&mut encoded).unwrap();
        let mut buf = encoded.freeze();
        let decoded = Capability::decode(&mut buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_four_octet_as() {
        let original = Capability::FourOctetAs { asn: 4_200_000_000 };
        let mut encoded = bytes::BytesMut::with_capacity(6);
        original.encode(&mut encoded).unwrap();
        let mut buf = encoded.freeze();
        let decoded = Capability::decode(&mut buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_unknown() {
        let original = Capability::Unknown {
            code: 42,
            data: Bytes::from_static(&[1, 2, 3]),
        };
        let mut encoded = bytes::BytesMut::with_capacity(5);
        original.encode(&mut encoded).unwrap();
        let mut buf = encoded.freeze();
        let decoded = Capability::decode(&mut buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_optional_params_multiple_caps() {
        // Parameter type=2, length=12, containing two capabilities
        let mut data = bytes::BytesMut::new();
        data.put_u8(2); // param type = capabilities
        data.put_u8(12); // param length
        // Cap 1: MultiProtocol IPv4 Unicast
        data.put_u8(1);
        data.put_u8(4);
        data.put_u16(1); // AFI IPv4
        data.put_u8(0);
        data.put_u8(1); // SAFI Unicast
        // Cap 2: FourOctetAs 65001
        data.put_u8(65);
        data.put_u8(4);
        data.put_u32(65001);

        let mut buf = data.freeze();
        let caps = decode_optional_parameters(&mut buf, 14).unwrap();
        assert_eq!(caps.len(), 2);
        assert_eq!(
            caps[0],
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast
            }
        );
        assert_eq!(caps[1], Capability::FourOctetAs { asn: 65001 });
    }

    #[test]
    fn decode_empty_optional_params() {
        let mut buf = Bytes::new();
        let caps = decode_optional_parameters(&mut buf, 0).unwrap();
        assert!(caps.is_empty());
    }

    #[test]
    fn reject_truncated_capability() {
        let data: &[u8] = &[65, 4, 0, 0]; // FourOctetAs but only 2 bytes of value
        let mut buf = Bytes::copy_from_slice(data);
        assert!(Capability::decode(&mut buf).is_err());
    }

    #[test]
    fn decode_graceful_restart_with_families() {
        // code=64, len=10 (2 + 2*4), flags=0x80 (R-bit) | time=120
        // Family 1: IPv4/Unicast, forwarding preserved
        // Family 2: IPv6/Unicast, forwarding not preserved
        let mut data = bytes::BytesMut::new();
        data.put_u8(64); // code
        data.put_u8(10); // length: 2 + 2*4
        data.put_u16(0x8078); // R-bit set, restart_time=120
        data.put_u16(1); // AFI IPv4
        data.put_u8(1); // SAFI Unicast
        data.put_u8(0x80); // forwarding preserved
        data.put_u16(2); // AFI IPv6
        data.put_u8(1); // SAFI Unicast
        data.put_u8(0x00); // forwarding not preserved

        let mut buf = data.freeze();
        let cap = Capability::decode(&mut buf).unwrap();
        assert_eq!(
            cap,
            Capability::GracefulRestart {
                restart_state: true,
                notification: false,
                restart_time: 120,
                families: vec![
                    GracefulRestartFamily {
                        afi: Afi::Ipv4,
                        safi: Safi::Unicast,
                        forwarding_preserved: true,
                    },
                    GracefulRestartFamily {
                        afi: Afi::Ipv6,
                        safi: Safi::Unicast,
                        forwarding_preserved: false,
                    },
                ],
            }
        );
    }

    #[test]
    fn decode_graceful_restart_no_r_bit() {
        let mut data = bytes::BytesMut::new();
        data.put_u8(64);
        data.put_u8(6); // 2 + 1*4
        data.put_u16(0x005A); // R-bit clear, restart_time=90
        data.put_u16(1); // AFI IPv4
        data.put_u8(1); // SAFI Unicast
        data.put_u8(0x00); // forwarding not preserved

        let mut buf = data.freeze();
        let cap = Capability::decode(&mut buf).unwrap();
        assert_eq!(
            cap,
            Capability::GracefulRestart {
                restart_state: false,
                notification: false,
                restart_time: 90,
                families: vec![GracefulRestartFamily {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    forwarding_preserved: false,
                }],
            }
        );
    }

    #[test]
    fn decode_graceful_restart_empty_families() {
        let mut data = bytes::BytesMut::new();
        data.put_u8(64);
        data.put_u8(2); // just the flags/time, no families
        data.put_u16(0x003C); // time=60

        let mut buf = data.freeze();
        let cap = Capability::decode(&mut buf).unwrap();
        assert_eq!(
            cap,
            Capability::GracefulRestart {
                restart_state: false,
                notification: false,
                restart_time: 60,
                families: vec![],
            }
        );
    }

    #[test]
    fn roundtrip_graceful_restart() {
        let original = Capability::GracefulRestart {
            restart_state: true,
            notification: false,
            restart_time: 120,
            families: vec![
                GracefulRestartFamily {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    forwarding_preserved: true,
                },
                GracefulRestartFamily {
                    afi: Afi::Ipv6,
                    safi: Safi::Unicast,
                    forwarding_preserved: false,
                },
            ],
        };
        let mut encoded = bytes::BytesMut::with_capacity(12);
        original.encode(&mut encoded).unwrap();
        let mut buf = encoded.freeze();
        let decoded = Capability::decode(&mut buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn graceful_restart_encoded_len() {
        let cap = Capability::GracefulRestart {
            restart_state: false,
            notification: false,
            restart_time: 120,
            families: vec![GracefulRestartFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                forwarding_preserved: true,
            }],
        };
        // code(1) + length(1) + flags_time(2) + 1 family(4) = 8
        assert_eq!(cap.encoded_len(), 8);
    }

    #[test]
    fn graceful_restart_code() {
        let cap = Capability::GracefulRestart {
            restart_state: false,
            notification: false,
            restart_time: 0,
            families: vec![],
        };
        assert_eq!(cap.code(), 64);
    }

    #[test]
    fn graceful_restart_bad_length_stored_as_unknown() {
        // Length 3 is invalid (not 2 + N*4)
        let data: &[u8] = &[64, 3, 0x00, 0x3C, 0xFF];
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert!(matches!(cap, Capability::Unknown { code: 64, .. }));
    }

    #[test]
    fn encode_rejects_oversized_gr_families() {
        // 64 families → value_len = 2 + 64*4 = 258, exceeds u8
        let families: Vec<GracefulRestartFamily> = (0..64)
            .map(|_| GracefulRestartFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                forwarding_preserved: false,
            })
            .collect();
        let cap = Capability::GracefulRestart {
            restart_state: false,
            notification: false,
            restart_time: 120,
            families,
        };
        let mut buf = bytes::BytesMut::new();
        assert!(cap.encode(&mut buf).is_err());
    }

    #[test]
    fn encode_rejects_oversized_unknown_data() {
        let cap = Capability::Unknown {
            code: 99,
            data: Bytes::from(vec![0u8; 256]),
        };
        let mut buf = bytes::BytesMut::new();
        assert!(cap.encode(&mut buf).is_err());
    }

    #[test]
    fn encode_optional_params_rejects_overflow() {
        // Total capabilities exceeding 255 bytes
        let caps: Vec<Capability> = (0..50)
            .map(|_| Capability::Unknown {
                code: 99,
                data: Bytes::from(vec![0u8; 5]),
            })
            .collect();
        // 50 caps * 7 bytes each = 350 > 255
        let mut buf = bytes::BytesMut::new();
        assert!(encode_optional_parameters(&caps, &mut buf).is_err());
    }

    #[test]
    fn encode_rejects_restart_time_over_4095() {
        let cap = Capability::GracefulRestart {
            restart_state: false,
            notification: false,
            restart_time: 4096,
            families: vec![],
        };
        let mut buf = bytes::BytesMut::new();
        assert!(cap.encode(&mut buf).is_err());
    }

    #[test]
    fn encode_accepts_restart_time_at_4095() {
        let cap = Capability::GracefulRestart {
            restart_state: false,
            notification: false,
            restart_time: 4095,
            families: vec![],
        };
        let mut buf = bytes::BytesMut::new();
        assert!(cap.encode(&mut buf).is_ok());
    }

    #[test]
    fn decode_graceful_restart_n_bit() {
        let mut data = bytes::BytesMut::new();
        data.put_u8(64);
        data.put_u8(6); // 2 + 1*4
        data.put_u16(0xC078); // R-bit + N-bit set, restart_time=120
        data.put_u16(1); // AFI IPv4
        data.put_u8(1); // SAFI Unicast
        data.put_u8(0x80); // forwarding preserved

        let mut buf = data.freeze();
        let cap = Capability::decode(&mut buf).unwrap();
        assert_eq!(
            cap,
            Capability::GracefulRestart {
                restart_state: true,
                notification: true,
                restart_time: 120,
                families: vec![GracefulRestartFamily {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    forwarding_preserved: true,
                }],
            }
        );
    }

    #[test]
    fn roundtrip_graceful_restart_with_n_bit() {
        let original = Capability::GracefulRestart {
            restart_state: true,
            notification: true,
            restart_time: 120,
            families: vec![GracefulRestartFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                forwarding_preserved: true,
            }],
        };
        let mut encoded = bytes::BytesMut::with_capacity(12);
        original.encode(&mut encoded).unwrap();
        let mut buf = encoded.freeze();
        let decoded = Capability::decode(&mut buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_capability_bounded_to_parameter_slice() {
        // Build optional parameters where the capability inside claims a
        // length that would overrun the parameter boundary.
        // Parameter: type=2, len=4 (only 4 bytes of capability data)
        // Capability inside: code=65 (FourOctetAs), len=8 (claims 8 but only 2 available)
        // Followed by: a valid second parameter that should not be consumed.
        let mut data = bytes::BytesMut::new();
        // Parameter 1: capabilities, len=4
        data.put_u8(2); // param type = capabilities
        data.put_u8(4); // param len = 4 bytes
        // Capability: code=65, len=8 (overflows the 4-byte parameter)
        data.put_u8(65);
        data.put_u8(8); // claims 8 bytes but only 2 remain in parameter
        data.put_u16(0xBEEF); // 2 bytes of data
        // Parameter 2: unknown type, should be untouched
        data.put_u8(99); // param type = unknown
        data.put_u8(2); // param len = 2
        data.put_u16(0xCAFE);

        let mut buf = data.freeze();
        // Should fail because the capability overflows the parameter slice
        // Total is 8 bytes: param1(2+4) + param2(2+2) but we pass the full
        // length so the outer parser sees both parameters.
        let result = decode_optional_parameters(&mut buf, 8);
        assert!(result.is_err());
    }

    #[test]
    fn decode_extended_message() {
        let data: &[u8] = &[6, 0]; // code=6, len=0
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert_eq!(cap, Capability::ExtendedMessage);
    }

    #[test]
    fn roundtrip_extended_message() {
        let original = Capability::ExtendedMessage;
        let mut encoded = bytes::BytesMut::with_capacity(2);
        original.encode(&mut encoded).unwrap();
        let mut buf = encoded.freeze();
        let decoded = Capability::decode(&mut buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn extended_message_code_and_len() {
        let cap = Capability::ExtendedMessage;
        assert_eq!(cap.code(), 6);
        assert_eq!(cap.encoded_len(), 2);
    }

    #[test]
    fn extended_message_bad_length_stored_as_unknown() {
        let data: &[u8] = &[6, 1, 0xFF]; // code=6, len=1 (should be 0)
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert!(matches!(cap, Capability::Unknown { code: 6, .. }));
    }

    // --- Extended Next Hop capability tests ---

    #[test]
    fn decode_extended_nexthop_single_family() {
        // code=5, len=6,
        // NLRI AFI=1 (IPv4), NLRI SAFI=1 (Unicast), NH AFI=2 (IPv6)
        let data: &[u8] = &[5, 6, 0, 1, 0, 1, 0, 2];
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert_eq!(
            cap,
            Capability::ExtendedNextHop(vec![ExtendedNextHopFamily {
                nlri_afi: Afi::Ipv4,
                nlri_safi: Safi::Unicast,
                next_hop_afi: Afi::Ipv6,
            }])
        );
    }

    #[test]
    fn roundtrip_extended_nexthop() {
        let original = Capability::ExtendedNextHop(vec![ExtendedNextHopFamily {
            nlri_afi: Afi::Ipv4,
            nlri_safi: Safi::Unicast,
            next_hop_afi: Afi::Ipv6,
        }]);
        let mut encoded = bytes::BytesMut::with_capacity(8);
        original.encode(&mut encoded).unwrap();
        let mut buf = encoded.freeze();
        let decoded = Capability::decode(&mut buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn extended_nexthop_bad_length_stored_as_unknown() {
        // code=5, len=4 (must be multiple of 6)
        let data: &[u8] = &[5, 4, 0, 1, 0, 1];
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert!(matches!(cap, Capability::Unknown { code: 5, .. }));
    }

    // --- Add-Path capability tests ---

    #[test]
    fn decode_add_path_single_family() {
        // code=69, len=4, AFI=1(IPv4), SAFI=1(Unicast), mode=3(Both)
        let data: &[u8] = &[69, 4, 0, 1, 1, 3];
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert_eq!(
            cap,
            Capability::AddPath(vec![AddPathFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                send_receive: AddPathMode::Both,
            }])
        );
    }

    #[test]
    fn decode_add_path_multiple_families() {
        let mut data = bytes::BytesMut::new();
        data.put_u8(69); // code
        data.put_u8(8); // len = 2 * 4
        data.put_u16(1); // AFI IPv4
        data.put_u8(1); // SAFI Unicast
        data.put_u8(1); // Receive
        data.put_u16(2); // AFI IPv6
        data.put_u8(1); // SAFI Unicast
        data.put_u8(2); // Send

        let mut buf = data.freeze();
        let cap = Capability::decode(&mut buf).unwrap();
        assert_eq!(
            cap,
            Capability::AddPath(vec![
                AddPathFamily {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    send_receive: AddPathMode::Receive,
                },
                AddPathFamily {
                    afi: Afi::Ipv6,
                    safi: Safi::Unicast,
                    send_receive: AddPathMode::Send,
                },
            ])
        );
    }

    #[test]
    fn roundtrip_add_path() {
        let original = Capability::AddPath(vec![
            AddPathFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                send_receive: AddPathMode::Both,
            },
            AddPathFamily {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                send_receive: AddPathMode::Receive,
            },
        ]);
        let mut encoded = bytes::BytesMut::with_capacity(10);
        original.encode(&mut encoded).unwrap();
        let mut buf = encoded.freeze();
        let decoded = Capability::decode(&mut buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn add_path_code_and_len() {
        let cap = Capability::AddPath(vec![AddPathFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            send_receive: AddPathMode::Receive,
        }]);
        assert_eq!(cap.code(), 69);
        // code(1) + length(1) + 1 family(4) = 6
        assert_eq!(cap.encoded_len(), 6);
    }

    #[test]
    fn add_path_bad_length_stored_as_unknown() {
        // code=69, len=3 (not multiple of 4)
        let data: &[u8] = &[69, 3, 0, 1, 1];
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert!(matches!(cap, Capability::Unknown { code: 69, .. }));
    }

    #[test]
    fn add_path_zero_length_stored_as_unknown() {
        // code=69, len=0
        let data: &[u8] = &[69, 0];
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert!(matches!(cap, Capability::Unknown { code: 69, .. }));
    }

    #[test]
    fn add_path_unknown_afi_preserved_as_unknown() {
        // code=69, len=4, AFI=99(unknown), SAFI=1, mode=3
        let data: &[u8] = &[69, 4, 0, 99, 1, 3];
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        // Unrecognized entry → preserve as Unknown for lossless roundtrip
        assert!(matches!(cap, Capability::Unknown { code: 69, .. }));
    }

    #[test]
    fn add_path_invalid_mode_preserved_as_unknown() {
        // code=69, len=4, AFI=1, SAFI=1, mode=0 (invalid)
        let data: &[u8] = &[69, 4, 0, 1, 1, 0];
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        // Invalid mode → preserve as Unknown for lossless roundtrip
        assert!(matches!(cap, Capability::Unknown { code: 69, .. }));
    }

    #[test]
    fn add_path_mixed_valid_and_invalid_preserved_as_unknown() {
        // Two entries: valid IPv4/Unicast/Both + invalid AFI=99
        let mut data = bytes::BytesMut::new();
        data.put_u8(69); // code
        data.put_u8(8); // len = 2 * 4
        data.put_u16(1); // AFI IPv4
        data.put_u8(1); // SAFI Unicast
        data.put_u8(3); // Both (valid)
        data.put_u16(99); // AFI unknown
        data.put_u8(1); // SAFI Unicast
        data.put_u8(3); // Both
        let mut buf = data.freeze();
        let cap = Capability::decode(&mut buf).unwrap();
        // One invalid entry → entire capability preserved as Unknown
        assert!(matches!(cap, Capability::Unknown { code: 69, .. }));
    }

    #[test]
    fn llgr_capability_roundtrip() {
        let families = vec![
            LlgrFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                forwarding_preserved: true,
                stale_time: 86400,
            },
            LlgrFamily {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                forwarding_preserved: false,
                stale_time: 3600,
            },
        ];
        let cap = Capability::LongLivedGracefulRestart(families);

        let mut buf = bytes::BytesMut::new();
        cap.encode(&mut buf).unwrap();
        let mut frozen = buf.freeze();
        let decoded = Capability::decode(&mut frozen).unwrap();

        match decoded {
            Capability::LongLivedGracefulRestart(fams) => {
                assert_eq!(fams.len(), 2);
                assert_eq!(fams[0].afi, Afi::Ipv4);
                assert_eq!(fams[0].safi, Safi::Unicast);
                assert!(fams[0].forwarding_preserved);
                assert_eq!(fams[0].stale_time, 86400);
                assert_eq!(fams[1].afi, Afi::Ipv6);
                assert_eq!(fams[1].safi, Safi::Unicast);
                assert!(!fams[1].forwarding_preserved);
                assert_eq!(fams[1].stale_time, 3600);
            }
            other => panic!("expected LongLivedGracefulRestart, got {other:?}"),
        }
    }

    #[test]
    fn llgr_capability_max_stale_time() {
        let cap = Capability::LongLivedGracefulRestart(vec![LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: false,
            stale_time: 0x00FF_FFFF, // 24-bit max
        }]);

        let mut buf = bytes::BytesMut::new();
        cap.encode(&mut buf).unwrap();
        let mut frozen = buf.freeze();
        let decoded = Capability::decode(&mut frozen).unwrap();

        match decoded {
            Capability::LongLivedGracefulRestart(fams) => {
                assert_eq!(fams[0].stale_time, 0x00FF_FFFF);
            }
            other => panic!("expected LongLivedGracefulRestart, got {other:?}"),
        }
    }

    #[test]
    fn llgr_capability_empty() {
        let cap = Capability::LongLivedGracefulRestart(vec![]);
        let mut buf = bytes::BytesMut::new();
        cap.encode(&mut buf).unwrap();
        let mut frozen = buf.freeze();
        let decoded = Capability::decode(&mut frozen).unwrap();
        assert!(matches!(
            decoded,
            Capability::LongLivedGracefulRestart(fams) if fams.is_empty()
        ));
    }

    // --- BGP Role capability (RFC 9234 §4) tests ---

    #[test]
    fn bgp_role_capability_encode_decode_roundtrip() {
        for role in [
            BgpRole::Provider,
            BgpRole::RouteServer,
            BgpRole::RouteServerClient,
            BgpRole::Customer,
            BgpRole::Peer,
        ] {
            let original = Capability::Role { role };
            let mut buf = bytes::BytesMut::new();
            original.encode(&mut buf).unwrap();
            // Wire form: code=9, len=1, value=role
            assert_eq!(buf.as_ref(), &[9, 1, role.to_u8()][..]);
            let mut frozen = buf.freeze();
            let decoded = Capability::decode(&mut frozen).unwrap();
            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn bgp_role_capability_code_returns_nine() {
        assert_eq!(
            Capability::Role {
                role: BgpRole::Provider
            }
            .code(),
            9
        );
    }

    #[test]
    fn bgp_role_capability_encoded_len_is_three() {
        // 1 (code) + 1 (length) + 1 (value) = 3
        assert_eq!(
            Capability::Role {
                role: BgpRole::Customer
            }
            .encoded_len(),
            3
        );
    }

    #[test]
    fn bgp_role_capability_bad_length_stored_as_unknown() {
        // RFC 9234 §4.1: Role length MUST be 1. Anything else round-trips as
        // Unknown so the negotiator can decide (the codec stays non-fatal).
        for (len, payload) in [
            (0u8, &[][..]),
            (2u8, &[0x00, 0x00][..]),
            (3u8, &[0x00, 0x00, 0x03][..]),
        ] {
            let mut wire = vec![9, len];
            wire.extend_from_slice(payload);
            let mut buf = Bytes::copy_from_slice(&wire);
            let cap = Capability::decode(&mut buf).unwrap();
            assert!(
                matches!(cap, Capability::Unknown { code: 9, .. }),
                "len {len}: expected Unknown, got {cap:?}"
            );
        }
    }

    #[test]
    fn bgp_role_capability_invalid_role_byte_stored_as_unknown() {
        // Role bytes 5..=255 are not defined; preserve the offending byte as
        // Unknown so the negotiator can NOTIFICATION 2/11 with the raw value.
        for invalid in [5u8, 99u8, 200u8, 255u8] {
            let wire = [9u8, 1, invalid];
            let mut buf = Bytes::copy_from_slice(&wire);
            let cap = Capability::decode(&mut buf).unwrap();
            match cap {
                Capability::Unknown { code, data } => {
                    assert_eq!(code, 9);
                    assert_eq!(data.as_ref(), &[invalid][..]);
                }
                other => panic!("invalid role byte {invalid}: expected Unknown, got {other:?}"),
            }
        }
    }

    #[test]
    fn bgp_role_from_u8_roundtrip() {
        for role in [
            BgpRole::Provider,
            BgpRole::RouteServer,
            BgpRole::RouteServerClient,
            BgpRole::Customer,
            BgpRole::Peer,
        ] {
            assert_eq!(BgpRole::from_u8(role.to_u8()), Some(role));
        }
        for invalid in [5u8, 9, 99, 255] {
            assert_eq!(BgpRole::from_u8(invalid), None);
        }
    }

    // --- Outbound Route Filtering capability (RFC 5291 §4) tests ---

    #[test]
    fn roundtrip_outbound_route_filter() {
        use crate::orf::{OrfCapEntry, OrfCapType, OrfSendReceive, OrfType};
        let original = Capability::OutboundRouteFilter(vec![OrfCapEntry {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            orf_types: vec![OrfCapType {
                orf_type: OrfType::AddressPrefix,
                send_receive: OrfSendReceive::Receive,
            }],
        }]);
        let mut encoded = bytes::BytesMut::new();
        original.encode(&mut encoded).unwrap();
        // code(1) + len(1) + AFI(2)+res(1)+SAFI(1)+count(1) + type/sr(2) = 9
        assert_eq!(encoded.len(), original.encoded_len());
        assert_eq!(original.code(), 3);
        let mut buf = encoded.freeze();
        let decoded = Capability::decode(&mut buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn outbound_route_filter_rejects_empty_entries() {
        // An empty block list has no valid wire form (RFC 5291 §4 requires one
        // or more), and the decoder treats a zero-length value as Unknown —
        // encode must refuse it so the codec stays symmetric.
        let cap = Capability::OutboundRouteFilter(vec![]);
        let mut buf = bytes::BytesMut::new();
        assert!(cap.encode(&mut buf).is_err());
    }

    #[test]
    fn outbound_route_filter_unknown_afi_preserved_as_unknown() {
        // code=3, len=7, AFI=99(unknown), SAFI=1, count=1, type=64, sr=1
        let data: &[u8] = &[3, 7, 0, 99, 0, 1, 1, 64, 1];
        let mut buf = Bytes::copy_from_slice(data);
        let cap = Capability::decode(&mut buf).unwrap();
        assert!(matches!(cap, Capability::Unknown { code: 3, .. }));
    }

    #[test]
    fn paths_limit_roundtrip_and_first_duplicate_wins() {
        let cap = Capability::PathsLimit(vec![
            PathsLimitFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                receive_limit: 4,
            },
            PathsLimitFamily {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                receive_limit: 8,
            },
        ]);
        let mut encoded = bytes::BytesMut::new();
        cap.encode(&mut encoded).unwrap();
        assert_eq!(encoded[0], 76);
        assert_eq!(encoded[1], 10);
        let mut buf = encoded.freeze();
        assert_eq!(Capability::decode(&mut buf).unwrap(), cap);

        let mut duplicate =
            Bytes::from_static(&[76, 15, 0, 1, 1, 0, 3, 0, 1, 1, 0, 9, 0, 2, 1, 0, 0]);
        assert_eq!(
            Capability::decode(&mut duplicate).unwrap(),
            Capability::PathsLimit(vec![PathsLimitFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                receive_limit: 3,
            }])
        );
    }

    #[test]
    fn paths_limit_malformed_tuple_is_preserved() {
        let mut empty = Bytes::from_static(&[76, 0]);
        assert_eq!(
            Capability::decode(&mut empty).unwrap(),
            Capability::PathsLimit(Vec::new())
        );

        let mut bad_length = Bytes::from_static(&[76, 4, 0, 1, 1, 0]);
        assert!(matches!(
            Capability::decode(&mut bad_length).unwrap(),
            Capability::Unknown { code: 76, .. }
        ));

        let mut unknown_afi = Bytes::from_static(&[76, 5, 0, 99, 1, 0, 4]);
        assert!(matches!(
            Capability::decode(&mut unknown_afi).unwrap(),
            Capability::Unknown { code: 76, .. }
        ));
    }
}
