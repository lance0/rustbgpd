use crate::capability::{Afi, Safi};
use crate::constants::{as_path_segment, attr_flags, attr_type};
use crate::error::{DecodeError, EncodeError};
use crate::nlri::{NlriEntry, Prefix};
use crate::notification::update_subcode;
use crate::validate::{ErrorDisposition, malformed_attr_disposition};
use bytes::Bytes;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Origin attribute values per RFC 4271 §5.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Origin {
    /// Learned via IGP.
    Igp = 0,
    /// Learned via EGP.
    Egp = 1,
    /// Origin undetermined.
    Incomplete = 2,
}
impl Origin {
    /// Create from a raw byte value.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Igp),
            1 => Some(Self::Egp),
            2 => Some(Self::Incomplete),
            _ => None,
        }
    }
}
impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Igp => write!(f, "IGP"),
            Self::Egp => write!(f, "EGP"),
            Self::Incomplete => write!(f, "INCOMPLETE"),
        }
    }
}
/// `AS_PATH` segment types per RFC 4271 §4.3.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AsPathSegment {
    /// `AS_SET` — unordered set of ASNs.
    AsSet(Vec<u32>),
    /// `AS_SEQUENCE` — ordered sequence of ASNs.
    AsSequence(Vec<u32>),
}
/// `AS_PATH` attribute.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AsPath {
    /// Ordered list of path segments.
    pub segments: Vec<AsPathSegment>,
}
/// RFC 4271 / RFC 6793 `AGGREGATOR` attribute in canonical 4-octet form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Aggregator {
    /// AS number of the speaker that formed the aggregate.
    pub asn: u32,
    /// BGP identifier of the speaker that formed the aggregate.
    pub router_id: Ipv4Addr,
    /// Whether the received compatibility attribute carried the Partial bit.
    pub partial: bool,
}
impl AsPath {
    /// Count the total number of ASNs in the path for best-path comparison.
    /// `AS_SET` counts as 1 regardless of size (RFC 4271 §9.1.2.2).
    #[must_use]
    pub fn len(&self) -> usize {
        self.segments
            .iter()
            .map(|seg| match seg {
                AsPathSegment::AsSequence(asns) => asns.len(),
                AsPathSegment::AsSet(_) => 1,
            })
            .sum()
    }
    /// Returns `true` if the path has no segments.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }
    /// Iterate every ASN in the path in wire order: segments in
    /// order, ASNs within each segment in their stored (wire) order,
    /// duplicates from prepends included. `AS_SET` members are yielded
    /// individually — unlike [`len`](Self::len), which counts a set as
    /// 1 per RFC 4271 §9.1.2.2, iteration visits each member (the set
    /// is unordered on the wire but this yields the received byte
    /// order, deterministically per route).
    pub fn asns(&self) -> impl Iterator<Item = u32> + '_ {
        self.segments
            .iter()
            .flat_map(|seg| match seg {
                AsPathSegment::AsSequence(asns) | AsPathSegment::AsSet(asns) => asns,
            })
            .copied()
    }

    /// Returns true if `asn` appears in any segment (`AS_SEQUENCE` or `AS_SET`).
    /// Used for loop detection per RFC 4271 §9.1.2.
    #[must_use]
    pub fn contains_asn(&self, asn: u32) -> bool {
        self.segments.iter().any(|seg| match seg {
            AsPathSegment::AsSequence(asns) | AsPathSegment::AsSet(asns) => asns.contains(&asn),
        })
    }
    /// Extract the origin ASN from the `AS_PATH`.
    ///
    /// The origin AS is the last ASN in the rightmost `AS_SEQUENCE` segment.
    /// Returns `None` if the path has no `AS_SEQUENCE` segments or all
    /// `AS_SEQUENCE` segments are empty.
    #[must_use]
    pub fn origin_asn(&self) -> Option<u32> {
        self.segments.iter().rev().find_map(|seg| match seg {
            AsPathSegment::AsSequence(asns) => asns.last().copied(),
            AsPathSegment::AsSet(_) => None,
        })
    }
    /// Returns `true` if every ASN in the path is a private ASN.
    ///
    /// Returns `false` for empty paths (no ASNs to check).
    #[must_use]
    pub fn all_private(&self) -> bool {
        let mut count = 0;
        for seg in &self.segments {
            match seg {
                AsPathSegment::AsSequence(asns) | AsPathSegment::AsSet(asns) => {
                    for asn in asns {
                        count += 1;
                        if !is_private_asn(*asn) {
                            return false;
                        }
                    }
                }
            }
        }
        count > 0
    }
    /// Convert to a string representation for regex matching.
    ///
    /// `AS_SEQUENCE` segments produce space-separated ASNs.
    /// `AS_SET` segments produce `{ASN1 ASN2}` (curly braces, space-separated).
    /// Multiple segments are space-separated.
    ///
    /// Examples: `"65001 65002"`, `"65001 {65003 65004}"`, `""` (empty path).
    #[must_use]
    pub fn to_aspath_string(&self) -> String {
        let mut parts = Vec::new();
        for seg in &self.segments {
            match seg {
                AsPathSegment::AsSequence(asns) => {
                    for asn in asns {
                        parts.push(asn.to_string());
                    }
                }
                AsPathSegment::AsSet(asns) => {
                    let inner: Vec<String> = asns.iter().map(ToString::to_string).collect();
                    parts.push(format!("{{{}}}", inner.join(" ")));
                }
            }
        }
        parts.join(" ")
    }
}
/// Returns `true` if the given ASN falls in a private-use range.
///
/// Private ranges (RFC 5398 + RFC 6996):
/// - 16-bit: 64512–65534
/// - 32-bit: 4200000000–4294967294
#[must_use]
pub fn is_private_asn(asn: u32) -> bool {
    (64512..=65534).contains(&asn) || (4_200_000_000..=4_294_967_294).contains(&asn)
}
/// RFC 4760 `MP_REACH_NLRI` attribute (type code 14).
///
/// Uses [`NlriEntry`] to carry Add-Path path IDs alongside each prefix.
/// For non-Add-Path peers, `path_id` is always 0.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MpReachNlri {
    /// Address family.
    pub afi: Afi,
    /// Sub-address family.
    pub safi: Safi,
    /// Global next-hop address for the announced prefixes.
    ///
    /// RFC 8950 allows IPv4 unicast NLRI to use an IPv6 next hop in
    /// `MP_REACH_NLRI`, so this field may be IPv6 even when `afi == Ipv4`.
    ///
    /// For `FlowSpec` (SAFI 133), next-hop length is 0 and this field is
    /// unused (defaults to `0.0.0.0`).
    pub next_hop: IpAddr,
    /// Optional IPv6 link-local next-hop carried alongside the global
    /// address per RFC 4760 §3 / RFC 2545 §3. Populated only when the
    /// wire NH-Len is 32 bytes (global + link-local). The decoder
    /// preserves the second 16 bytes here so re-encode round-trips.
    pub link_local_next_hop: Option<Ipv6Addr>,
    /// Announced NLRI entries.
    pub announced: Vec<NlriEntry>,
    /// `FlowSpec` NLRI rules (RFC 8955). Populated only when `safi == FlowSpec`.
    pub flowspec_announced: Vec<crate::flowspec::FlowSpecRule>,
    /// EVPN NLRI routes (RFC 7432). Populated only when `safi == Evpn`.
    pub evpn_announced: Vec<crate::evpn::EvpnRoute>,
    /// BGP-LS NLRI objects (RFC 9552). Populated only for SAFI 71/72.
    pub bgpls_announced: Vec<crate::bgpls::BgpLsNlri>,
    /// VPNv4/VPNv6 NLRI entries (RFC 4364 / RFC 4659). Populated only for
    /// SAFI 128. Carries an RFC 7911 Add-Path path ID per entry; for
    /// non-Add-Path peers, `path_id` is always 0.
    pub vpn_announced: Vec<crate::vpn::VpnNlriEntry>,
    /// IPv4/IPv6 labeled-unicast NLRI entries (RFC 8277). Populated only
    /// for SAFI 4. Carries an RFC 7911 Add-Path path ID per entry; for
    /// non-Add-Path peers, `path_id` is always 0.
    pub labeled_announced: Vec<crate::labeled::LabeledNlriEntry>,
    /// RT-Constrain NLRI entries (RFC 4684). Populated only for SAFI 132.
    pub rtc_announced: Vec<crate::rtc::RtcNlri>,
}
/// RFC 4760 `MP_UNREACH_NLRI` attribute (type 15).
///
/// Uses [`NlriEntry`] to carry Add-Path path IDs alongside each prefix.
/// For non-Add-Path peers, `path_id` is always 0.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MpUnreachNlri {
    /// Address family.
    pub afi: Afi,
    /// Sub-address family.
    pub safi: Safi,
    /// Withdrawn NLRI entries.
    pub withdrawn: Vec<NlriEntry>,
    /// `FlowSpec` NLRI rules withdrawn (RFC 8955). Populated only when `safi == FlowSpec`.
    pub flowspec_withdrawn: Vec<crate::flowspec::FlowSpecRule>,
    /// EVPN NLRI routes withdrawn (RFC 7432). Populated only when `safi == Evpn`.
    pub evpn_withdrawn: Vec<crate::evpn::EvpnRoute>,
    /// BGP-LS NLRI objects withdrawn (RFC 9552). Populated only for SAFI 71/72.
    pub bgpls_withdrawn: Vec<crate::bgpls::BgpLsNlri>,
    /// VPNv4/VPNv6 NLRI entries withdrawn (RFC 4364 / RFC 4659). Populated
    /// only for SAFI 128. Carries an RFC 7911 Add-Path path ID per entry;
    /// for non-Add-Path peers, `path_id` is always 0.
    pub vpn_withdrawn: Vec<crate::vpn::VpnNlriEntry>,
    /// IPv4/IPv6 labeled-unicast NLRI entries withdrawn (RFC 8277).
    /// Populated only for SAFI 4. Carries an RFC 7911 Add-Path path ID per
    /// entry; for non-Add-Path peers, `path_id` is always 0.
    pub labeled_withdrawn: Vec<crate::labeled::LabeledNlriEntry>,
    /// RT-Constrain NLRI entries withdrawn (RFC 4684). Populated only for SAFI 132.
    pub rtc_withdrawn: Vec<crate::rtc::RtcNlri>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MpNlriFamily {
    Unicast,
    FlowSpec,
    Evpn,
    BgpLs,
    Vpn,
    Labeled,
    Rtc,
}
fn classify_mp_nlri_family(
    afi: Afi,
    safi: Safi,
    attribute: &'static str,
) -> Result<MpNlriFamily, DecodeError> {
    match (afi, safi) {
        (Afi::Ipv4 | Afi::Ipv6, Safi::Unicast) => Ok(MpNlriFamily::Unicast),
        (Afi::Ipv4 | Afi::Ipv6, Safi::FlowSpec) => Ok(MpNlriFamily::FlowSpec),
        (Afi::L2Vpn, Safi::Evpn) => Ok(MpNlriFamily::Evpn),
        (Afi::BgpLs, Safi::BgpLs | Safi::BgpLsVpn) => Ok(MpNlriFamily::BgpLs),
        (Afi::Ipv4 | Afi::Ipv6, Safi::MplsVpn) => Ok(MpNlriFamily::Vpn),
        (Afi::Ipv4 | Afi::Ipv6, Safi::LabeledUnicast) => Ok(MpNlriFamily::Labeled),
        // RT-Constrain is AFI 1 only (RFC 4684 §7); (Ipv6, RtConstrain)
        // stays rejected below.
        (Afi::Ipv4, Safi::RtConstrain) => Ok(MpNlriFamily::Rtc),
        (Afi::Ipv4 | Afi::Ipv6 | Afi::L2Vpn, Safi::Multicast | Safi::BgpLs | Safi::BgpLsVpn)
        | (Afi::Ipv4 | Afi::Ipv6, Safi::Evpn)
        | (Afi::L2Vpn, Safi::Unicast | Safi::FlowSpec | Safi::MplsVpn | Safi::LabeledUnicast)
        | (
            Afi::BgpLs,
            Safi::Unicast
            | Safi::Multicast
            | Safi::Evpn
            | Safi::FlowSpec
            | Safi::MplsVpn
            | Safi::LabeledUnicast,
        )
        | (Afi::Ipv6 | Afi::L2Vpn | Afi::BgpLs, Safi::RtConstrain) => {
            Err(unsupported_mp_nlri_family(attribute, afi, safi))
        }
    }
}
fn unsupported_mp_nlri_family(attribute: &'static str, afi: Afi, safi: Safi) -> DecodeError {
    DecodeError::MalformedField {
        message_type: "UPDATE",
        detail: format!(
            "{attribute} unsupported AFI/SAFI {}/{}; supported families are IPv4/IPv6 unicast, IPv4/IPv6 FlowSpec, L2VPN EVPN, BGP-LS/BGP-LS VPN, VPNv4/VPNv6, IPv4/IPv6 labeled-unicast, and IPv4 RT-Constrain",
            afi as u16, safi as u8
        ),
    }
}
/// RFC 4360 Extended Community — 8-byte value stored as `u64`.
///
/// Wire layout: type (1) + sub-type (1) + value (6).
/// Bit 6 of the type byte: 0 = transitive, 1 = non-transitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtendedCommunity(u64);
/// Decoded DF Election Extended Community (RFC 8584 / RFC 9785).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DfElectionExtendedCommunity {
    /// Five-bit DF algorithm ID.
    pub algorithm_id: u8,
    /// Two-octet capability bitmap.
    pub capabilities: u16,
    /// DF Preference. Defined only for RFC 9785 preference algorithms;
    /// `None` for DefaultModulo/HRW where the trailing bytes are reserved.
    pub preference: Option<u16>,
}
impl ExtendedCommunity {
    /// RFC 8097 BGP Origin Validation State Extended Community,
    /// state `valid` (0). Non-transitive opaque: type `0x43`
    /// (opaque `0x03` with the non-transitive bit `0x40` set),
    /// sub-type `0x00`, five reserved zero bytes, and the validation
    /// state in the last octet (RFC 8097 §2).
    pub const ORIGIN_VALIDATION_VALID: Self = Self(0x4300_0000_0000_0000);
    /// RFC 8097 Origin Validation State, state `not found` (1).
    pub const ORIGIN_VALIDATION_NOT_FOUND: Self = Self(0x4300_0000_0000_0001);
    /// RFC 8097 Origin Validation State, state `invalid` (2).
    pub const ORIGIN_VALIDATION_INVALID: Self = Self(0x4300_0000_0000_0002);

    /// Create from a raw 8-byte value.
    #[must_use]
    pub fn new(raw: u64) -> Self {
        Self(raw)
    }
    /// Return the raw 8-byte value.
    #[must_use]
    pub fn as_u64(self) -> u64 {
        self.0
    }
    /// High byte — IANA-assigned type.
    #[must_use]
    pub fn type_byte(self) -> u8 {
        (self.0 >> 56) as u8
    }
    /// Second byte — sub-type within the type.
    #[must_use]
    pub fn subtype(self) -> u8 {
        self.0.to_be_bytes()[1]
    }
    /// Transitive if bit 6 of the type byte is 0.
    #[must_use]
    pub fn is_transitive(self) -> bool {
        self.type_byte() & 0x40 == 0
    }
    /// Bytes 2-7 of the community value.
    #[must_use]
    pub fn value_bytes(self) -> [u8; 6] {
        let b = self.0.to_be_bytes();
        [b[2], b[3], b[4], b[5], b[6], b[7]]
    }
    /// Decode as Route Target (sub-type 0x02).
    ///
    /// Returns `(global_admin, local_admin)` as raw u32 values. The
    /// interpretation of `global_admin` depends on the type byte:
    /// - Type 0x00 (2-octet AS specific): global = ASN (fits u16), local = u32
    /// - Type 0x01 (IPv4 address specific): global = IPv4 addr as u32, local = u16
    /// - Type 0x02 (4-octet AS specific): global = ASN (u32), local = u16
    ///
    /// Callers that need to distinguish these encodings (e.g. for display as
    /// `RT:192.0.2.1:100` vs `RT:65001:100`) must also check [`type_byte()`](Self::type_byte).
    #[must_use]
    pub fn route_target(self) -> Option<(u32, u32)> {
        if self.subtype() != 0x02 {
            return None;
        }
        self.decode_two_part()
    }
    /// Decode as Route Origin (sub-type 0x03).
    ///
    /// Same layout as [`route_target()`](Self::route_target) — returns raw
    /// `(global_admin, local_admin)` with the same type-byte-dependent
    /// interpretation. Check [`type_byte()`](Self::type_byte) to distinguish
    /// 2-octet AS, IPv4-address, and 4-octet AS encodings.
    #[must_use]
    pub fn route_origin(self) -> Option<(u32, u32)> {
        if self.subtype() != 0x03 {
            return None;
        }
        self.decode_two_part()
    }
    // -------------------------------------------------------------------
    // EVPN-specific typed accessors (RFC 7432 / RFC 8365 / RFC 9135)
    // -------------------------------------------------------------------
    /// Decode as BGP Encapsulation Extended Community (RFC 9012 §4.1, encoded
    /// per the widely-deployed RFC 5512 layout: 4-byte reserved + 2-byte
    /// Tunnel Type). Type 0x03, subtype 0x0C.
    ///
    /// Returns the Tunnel Type code. For VXLAN-EVPN (RFC 8365), the value is
    /// 8. Other common values: 7 = NVGRE, 11 = MPLS-over-GRE.
    ///
    /// The reserved bytes are intentionally not validated here: RFC 5512
    /// specifies MUST-zero on send, ignored on receive. FRR, `GoBGP`, Cisco,
    /// and Juniper all emit zeros in practice; rejecting non-zero reserves
    /// would break interop in the rare case an unknown implementation
    /// re-purposes those bytes. Consumers should treat the returned
    /// `tunnel_type` as the semantic signal.
    #[must_use]
    pub fn as_bgp_encapsulation(self) -> Option<u16> {
        if self.type_byte() & 0x3F != 0x03 || self.subtype() != 0x0C {
            return None;
        }
        let v = self.value_bytes();
        Some(u16::from_be_bytes([v[4], v[5]]))
    }
    /// Construct a BGP Encapsulation Extended Community (RFC 9012 §4.1).
    ///
    /// Writes 4 bytes of reserved zero followed by the 16-bit tunnel type.
    #[must_use]
    pub fn bgp_encapsulation(tunnel_type: u16) -> Self {
        let tt = tunnel_type.to_be_bytes();
        let raw = u64::from_be_bytes([0x03, 0x0C, 0, 0, 0, 0, tt[0], tt[1]]);
        Self(raw)
    }
    /// Decode as MAC Mobility Extended Community (RFC 7432 §7.7).
    /// Type 0x06, subtype 0x00.
    ///
    /// Returns `(sticky, sequence_number)`. The sticky bit (bit 0 of the
    /// flags byte) marks the MAC as non-movable; receivers must not displace
    /// a sticky MAC with a higher-sequence non-sticky advertisement.
    #[must_use]
    pub fn as_mac_mobility(self) -> Option<(bool, u32)> {
        if self.type_byte() & 0x3F != 0x06 || self.subtype() != 0x00 {
            return None;
        }
        let v = self.value_bytes();
        let sticky = (v[0] & 0x01) != 0;
        let seq = u32::from_be_bytes([v[2], v[3], v[4], v[5]]);
        Some((sticky, seq))
    }
    /// Construct a MAC Mobility Extended Community (RFC 7432 §7.7).
    #[must_use]
    pub fn mac_mobility(sticky: bool, sequence: u32) -> Self {
        let flags = u8::from(sticky);
        let s = sequence.to_be_bytes();
        let raw = u64::from_be_bytes([0x06, 0x00, flags, 0, s[0], s[1], s[2], s[3]]);
        Self(raw)
    }
    /// Decode as ESI Label Extended Community (RFC 7432 §7.5).
    /// Type 0x06, subtype 0x01.
    ///
    /// Returns `(single_active, label)`. The single-active flag (bit 0 of
    /// the flags byte) signals single-active multi-homing mode.
    #[must_use]
    pub fn as_esi_label(self) -> Option<(bool, u32)> {
        if self.type_byte() & 0x3F != 0x06 || self.subtype() != 0x01 {
            return None;
        }
        let v = self.value_bytes();
        let single_active = (v[0] & 0x01) != 0;
        let label = (u32::from(v[3]) << 16) | (u32::from(v[4]) << 8) | u32::from(v[5]);
        Some((single_active, label))
    }
    /// Construct an ESI Label Extended Community (RFC 7432 §7.5).
    ///
    /// `label` is a 24-bit MPLS label or VXLAN VNI; high 8 bits are masked.
    #[must_use]
    pub fn esi_label(single_active: bool, label: u32) -> Self {
        let flags = u8::from(single_active);
        let l = label & 0x00FF_FFFF;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "codec bounds or masks the value before narrowing to the protocol field width"
        )]
        let raw = u64::from_be_bytes([
            0x06,
            0x01,
            flags,
            0,
            0,
            (l >> 16) as u8,
            (l >> 8) as u8,
            l as u8,
        ]);
        Self(raw)
    }
    /// Decode as ES-Import Route Target Extended Community (RFC 7432 §7.6).
    /// Type 0x06, subtype 0x02.
    ///
    /// Returns the 6-byte MAC address that serves as the import target for
    /// Type 4 ES routes.
    #[must_use]
    pub fn as_es_import_rt(self) -> Option<[u8; 6]> {
        if self.type_byte() & 0x3F != 0x06 || self.subtype() != 0x02 {
            return None;
        }
        Some(self.value_bytes())
    }
    /// Construct an ES-Import Route Target Extended Community.
    #[must_use]
    pub fn es_import_rt(mac: [u8; 6]) -> Self {
        let raw = u64::from_be_bytes([0x06, 0x02, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]]);
        Self(raw)
    }
    /// Decode as DF Election Extended Community (RFC 8584 §2.2,
    /// updated by RFC 9785 §3). Type 0x06, subtype 0x06.
    #[must_use]
    pub fn as_df_election(self) -> Option<DfElectionExtendedCommunity> {
        if self.type_byte() & 0x3F != 0x06 || self.subtype() != 0x06 {
            return None;
        }
        let v = self.value_bytes();
        let algorithm_id = v[0] & 0x1f;
        let capabilities = u16::from_be_bytes([v[1], v[2]]);
        let preference = match algorithm_id {
            2 | 3 => Some(u16::from_be_bytes([v[4], v[5]])),
            _ => None,
        };
        Some(DfElectionExtendedCommunity {
            algorithm_id,
            capabilities,
            preference,
        })
    }
    /// Construct a DF Election Extended Community (RFC 8584 §2.2,
    /// RFC 9785 §3).
    ///
    /// `algorithm_id` is masked to the five-bit DF Alg field. For
    /// `DefaultModulo` and HRW, pass `None` for `preference` so the
    /// reserved trailing bytes are emitted as zero.
    #[must_use]
    pub fn df_election(algorithm_id: u8, capabilities: u16, preference: Option<u16>) -> Self {
        let alg = algorithm_id & 0x1f;
        let cap = capabilities.to_be_bytes();
        let pref = preference.unwrap_or(0).to_be_bytes();
        let raw = u64::from_be_bytes([0x06, 0x06, alg, cap[0], cap[1], 0, pref[0], pref[1]]);
        Self(raw)
    }
    /// Decode as Link Bandwidth Extended Community (RFC 10005 §2): transitive
    /// or non-transitive two-octet-AS-specific, exact type `0x00` or `0x40`,
    /// subtype `0x04`. Returns the raw `(asn, bytes_per_sec)` payload; receiver
    /// policy is applied by the consumer.
    #[must_use]
    pub fn as_link_bandwidth(self) -> Option<(u16, f32)> {
        if !matches!(self.type_byte(), 0x00 | 0x40) || self.subtype() != 0x04 {
            return None;
        }
        let v = self.value_bytes();
        let asn = u16::from_be_bytes([v[0], v[1]]);
        let bytes_per_sec = f32::from_be_bytes([v[2], v[3], v[4], v[5]]);
        Some((asn, bytes_per_sec))
    }
    /// Construct a non-transitive Link Bandwidth Extended Community
    /// (RFC 10005 §2), type `0x40`, subtype `0x04`. `bytes_per_sec` is encoded
    /// as an IEEE-754 single-precision float.
    #[must_use]
    pub fn link_bandwidth(asn: u16, bytes_per_sec: f32) -> Self {
        let a = asn.to_be_bytes();
        let bw = bytes_per_sec.to_be_bytes();
        let raw = u64::from_be_bytes([0x40, 0x04, a[0], a[1], bw[0], bw[1], bw[2], bw[3]]);
        Self(raw)
    }
    /// Decode as Router MAC Extended Community (RFC 9135 §4.1).
    /// Type 0x06, subtype 0x03.
    ///
    /// Returns the 6-byte router MAC used for symmetric IRB.
    #[must_use]
    pub fn as_router_mac(self) -> Option<[u8; 6]> {
        if self.type_byte() & 0x3F != 0x06 || self.subtype() != 0x03 {
            return None;
        }
        Some(self.value_bytes())
    }
    /// Construct a Router MAC Extended Community (RFC 9135 §4.1).
    #[must_use]
    pub fn router_mac(mac: [u8; 6]) -> Self {
        let raw = u64::from_be_bytes([0x06, 0x03, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]]);
        Self(raw)
    }
    /// Decode as Default Gateway Extended Community (RFC 4761 §3.2.5 /
    /// RFC 7432). Type 0x03, subtype 0x0D. This is a flag-only community:
    /// presence is the signal and the 6-byte value field must be all zeros.
    /// Malformed advertisements with non-zero value bytes are treated as
    /// non-matches rather than silently accepted — downstream policy and
    /// validation consumers treat this accessor as semantic truth.
    #[must_use]
    pub fn as_default_gateway(self) -> bool {
        self.type_byte() & 0x3F == 0x03 && self.subtype() == 0x0D && self.value_bytes() == [0u8; 6]
    }
    /// Construct a Default Gateway Extended Community.
    #[must_use]
    pub fn default_gateway() -> Self {
        let raw = u64::from_be_bytes([0x03, 0x0D, 0, 0, 0, 0, 0, 0]);
        Self(raw)
    }
    /// Decode the 6-byte value field as `(global_admin, local_admin)`.
    ///
    /// Handles all three RFC 4360 two-part layouts (2-octet AS, IPv4, 4-octet
    /// AS). Returns raw u32 values — the caller decides how to interpret
    /// `global_admin` (ASN vs IPv4 address) based on `type_byte()`.
    fn decode_two_part(self) -> Option<(u32, u32)> {
        let v = self.value_bytes();
        let t = self.type_byte() & 0x3F; // mask off high two bits
        match t {
            // 2-octet AS specific: AS(2) + value(4)
            0x00 => {
                let global = u32::from(u16::from_be_bytes([v[0], v[1]]));
                let local = u32::from_be_bytes([v[2], v[3], v[4], v[5]]);
                Some((global, local))
            }
            // IPv4 Address specific (0x01) or 4-octet AS specific (0x02): 4 + 2
            0x01 | 0x02 => {
                let global = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
                let local = u32::from(u16::from_be_bytes([v[4], v[5]]));
                Some((global, local))
            }
            _ => None,
        }
    }
}
impl fmt::Display for ExtendedCommunity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // RFC 8097 origin-validation states render by their well-known
        // names (the same aliases the policy frontends parse).
        match *self {
            Self::ORIGIN_VALIDATION_VALID => return write!(f, "OV_VALID"),
            Self::ORIGIN_VALIDATION_NOT_FOUND => return write!(f, "OV_NOT_FOUND"),
            Self::ORIGIN_VALIDATION_INVALID => return write!(f, "OV_INVALID"),
            _ => {}
        }
        let is_ipv4 = self.type_byte() & 0x3F == 0x01;
        if let Some((g, l)) = self.route_target() {
            if is_ipv4 {
                write!(f, "RT:{}:{l}", Ipv4Addr::from(g))
            } else {
                write!(f, "RT:{g}:{l}")
            }
        } else if let Some((g, l)) = self.route_origin() {
            if is_ipv4 {
                write!(f, "RO:{}:{l}", Ipv4Addr::from(g))
            } else {
                write!(f, "RO:{g}:{l}")
            }
        } else {
            write!(f, "0x{:016x}", self.0)
        }
    }
}
/// RFC 8092 Large Community — 12-byte value: `(global_admin, local_data1, local_data2)`.
///
/// Each field is a 32-bit unsigned integer. Display format: `"65001:100:200"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LargeCommunity {
    /// Global administrator (typically ASN).
    pub global_admin: u32,
    /// First local data part.
    pub local_data1: u32,
    /// Second local data part.
    pub local_data2: u32,
}
impl LargeCommunity {
    /// Create a new large community value.
    #[must_use]
    pub fn new(global_admin: u32, local_data1: u32, local_data2: u32) -> Self {
        Self {
            global_admin,
            local_data1,
            local_data2,
        }
    }
}
impl fmt::Display for LargeCommunity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.global_admin, self.local_data1, self.local_data2
        )
    }
}
/// A known path attribute or raw preserved bytes.
///
/// Known attributes are decoded into typed variants. Unknown attributes
/// are preserved as `RawAttribute` for pass-through with the Partial bit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PathAttribute {
    /// `ORIGIN` attribute (type 1).
    Origin(Origin),
    /// `AS_PATH` attribute (type 2).
    AsPath(AsPath),
    /// `AGGREGATOR` attribute (type 7), normalized to a 4-octet ASN.
    Aggregator(Aggregator),
    /// `NEXT_HOP` attribute (type 3).
    NextHop(Ipv4Addr),
    /// `LOCAL_PREF` attribute (type 5).
    LocalPref(u32),
    /// `MULTI_EXIT_DISC` attribute (type 4).
    Med(u32),
    /// RFC 1997 COMMUNITIES — each u32 is high16=ASN, low16=value.
    Communities(Vec<u32>),
    /// RFC 4360 EXTENDED COMMUNITIES.
    ExtendedCommunities(Vec<ExtendedCommunity>),
    /// RFC 8092 LARGE COMMUNITIES. Duplicate values are normalized at
    /// decode and encode boundaries while retaining first-seen order.
    LargeCommunities(Vec<LargeCommunity>),
    /// RFC 4456 `ORIGINATOR_ID` — original router-id of the route.
    OriginatorId(Ipv4Addr),
    /// RFC 4456 `CLUSTER_LIST` — list of cluster-ids traversed.
    ClusterList(Vec<Ipv4Addr>),
    /// RFC 4760 `MP_REACH_NLRI`.
    MpReachNlri(MpReachNlri),
    /// RFC 4760 `MP_UNREACH_NLRI`.
    MpUnreachNlri(MpUnreachNlri),
    /// RFC 6514 §5 `PMSI Tunnel` — used by EVPN Type 3 IMET for
    /// ingress-replication BUM forwarding.
    PmsiTunnel(crate::pmsi::PmsiTunnel),
    /// RFC 9234 §5 `Only-to-Customer` (type 35) — carries the 32-bit ASN
    /// that initially set OTC on the route. Optional + Transitive (`0xC0`).
    OnlyToCustomer(u32),
    /// Unknown or unrecognized attribute, preserved for re-advertisement.
    Unknown(RawAttribute),
}
impl PathAttribute {
    /// Return the type code of this attribute.
    #[must_use]
    pub fn type_code(&self) -> u8 {
        match self {
            Self::Origin(_) => attr_type::ORIGIN,
            Self::AsPath(_) => attr_type::AS_PATH,
            Self::Aggregator(_) => attr_type::AGGREGATOR,
            Self::NextHop(_) => attr_type::NEXT_HOP,
            Self::LocalPref(_) => attr_type::LOCAL_PREF,
            Self::Med(_) => attr_type::MULTI_EXIT_DISC,
            Self::Communities(_) => attr_type::COMMUNITIES,
            Self::OriginatorId(_) => attr_type::ORIGINATOR_ID,
            Self::ClusterList(_) => attr_type::CLUSTER_LIST,
            Self::ExtendedCommunities(_) => attr_type::EXTENDED_COMMUNITIES,
            Self::LargeCommunities(_) => attr_type::LARGE_COMMUNITIES,
            Self::MpReachNlri(_) => attr_type::MP_REACH_NLRI,
            Self::MpUnreachNlri(_) => attr_type::MP_UNREACH_NLRI,
            Self::PmsiTunnel(_) => attr_type::PMSI_TUNNEL,
            Self::OnlyToCustomer(_) => attr_type::ONLY_TO_CUSTOMER,
            Self::Unknown(raw) => raw.type_code,
        }
    }
    /// Return the wire flags for this attribute.
    #[must_use]
    pub fn flags(&self) -> u8 {
        match self {
            Self::Origin(_) | Self::AsPath(_) | Self::NextHop(_) | Self::LocalPref(_) => {
                attr_flags::TRANSITIVE
            }
            Self::Med(_)
            | Self::OriginatorId(_)
            | Self::ClusterList(_)
            | Self::MpReachNlri(_)
            | Self::MpUnreachNlri(_) => attr_flags::OPTIONAL,
            Self::Aggregator(aggregator) => {
                attr_flags::OPTIONAL
                    | attr_flags::TRANSITIVE
                    | if aggregator.partial {
                        attr_flags::PARTIAL
                    } else {
                        0
                    }
            }
            Self::Communities(_)
            | Self::ExtendedCommunities(_)
            | Self::LargeCommunities(_)
            | Self::PmsiTunnel(_)
            | Self::OnlyToCustomer(_) => attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            Self::Unknown(raw) => raw.flags,
        }
    }
}
/// Raw attribute preserved for pass-through (RFC 4271 §5).
///
/// On re-advertisement, the Partial bit (0x20) is OR'd into `flags`.
/// All other flags and bytes are preserved unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawAttribute {
    /// Attribute flags byte (optional, transitive, partial, extended-length).
    pub flags: u8,
    /// Attribute type code.
    pub type_code: u8,
    /// Raw attribute value bytes.
    pub data: Bytes,
}
/// Decode path attributes from wire bytes (RFC 4271 §4.3).
///
/// Each attribute is: flags(1) + type(1) + length(1 or 2) + value.
/// The Extended Length flag determines 1-byte vs 2-byte length.
///
/// `four_octet_as` controls whether AS numbers in `AS_PATH` are 2 or 4 bytes.
///
/// # Errors
///
/// Returns `DecodeError` on truncated data or malformed attribute values.
pub fn decode_path_attributes(
    buf: &[u8],
    four_octet_as: bool,
    add_path_families: &[(Afi, Safi)],
) -> Result<Vec<PathAttribute>, DecodeError> {
    Ok(decode_path_attributes_counted(buf, four_octet_as, add_path_families)?.0)
}

/// Like [`decode_path_attributes`] but also returns the number of BGP-LS NLRIs
/// dropped for out-of-order descriptor TLVs (RFC 9552). The count lets the
/// session layer observe an otherwise-silent recoverable discard; it never
/// includes fatal framing/length errors, which still surface as `Err`.
///
/// # Errors
///
/// Same as [`decode_path_attributes`].
pub fn decode_path_attributes_counted(
    mut buf: &[u8],
    four_octet_as: bool,
    add_path_families: &[(Afi, Safi)],
) -> Result<(Vec<PathAttribute>, u32), DecodeError> {
    let mut attrs = Vec::new();
    let mut bgpls_discarded = 0_u32;
    while !buf.is_empty() {
        let (flags, type_code, value) = split_next_attribute(&mut buf)?;
        let attr = decode_attribute_value(
            flags,
            type_code,
            value,
            four_octet_as,
            add_path_families,
            &mut bgpls_discarded,
        )?;
        attrs.push(attr);
    }
    if let Some(malformed) = normalize_as4_attributes(&mut attrs, four_octet_as, false)
        .into_iter()
        .next()
    {
        return Err(malformed.error);
    }
    Ok((attrs, bgpls_discarded))
}
/// Split the next `flags(1) + type(1) + length(1|2) + value` attribute off
/// the front of `buf`, advancing it past the attribute. On error `buf` is
/// left unchanged.
fn split_next_attribute<'a>(buf: &mut &'a [u8]) -> Result<(u8, u8, &'a [u8]), DecodeError> {
    // Need at least flags(1) + type(1) = 2
    if buf.len() < 2 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: "truncated attribute header".to_string(),
        });
    }
    let flags = buf[0];
    let type_code = buf[1];
    let mut rest = &buf[2..];
    let extended = (flags & attr_flags::EXTENDED_LENGTH) != 0;
    let value_len = if extended {
        if rest.len() < 2 {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: "truncated extended-length attribute".to_string(),
            });
        }
        let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        rest = &rest[2..];
        len
    } else {
        if rest.is_empty() {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: "truncated attribute length".to_string(),
            });
        }
        let len = rest[0] as usize;
        rest = &rest[1..];
        len
    };
    if rest.len() < value_len {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!(
                "attribute type {type_code} value truncated: need {value_len}, have {}",
                rest.len()
            ),
        });
    }
    let value = &rest[..value_len];
    *buf = &rest[value_len..];
    Ok((flags, type_code, value))
}
/// A malformed path attribute recovered during [`decode_path_attributes_revised`].
///
/// Carries enough context for the session layer to log the malformation and
/// apply the RFC 7606 disposition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MalformedAttribute {
    /// Attribute type code of the offending attribute (0 if the attribute
    /// header itself was too truncated to carry one).
    pub type_code: u8,
    /// RFC 7606 disposition for this malformation.
    pub disposition: ErrorDisposition,
    /// The underlying decode error.
    pub error: DecodeError,
}
/// Result of [`decode_path_attributes_revised`]: the attributes that decoded
/// cleanly plus the malformations recovered per RFC 7606.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisedAttributeDecode {
    /// Attributes that decoded cleanly (malformed ones are omitted).
    pub attributes: Vec<PathAttribute>,
    /// BGP-LS NLRIs dropped for out-of-order descriptor TLVs (RFC 9552).
    pub bgpls_nlri_discarded: u32,
    /// Malformed attributes recovered without aborting the decode, each with
    /// its RFC 7606 disposition. Empty means the UPDATE was clean.
    pub malformed: Vec<MalformedAttribute>,
}
/// Decode path attributes with RFC 7606 revised error handling.
///
/// Unlike [`decode_path_attributes`], a malformed attribute does not abort
/// the decode: the offending attribute is isolated (its length field is
/// self-consistent, so the remaining attributes can still be located) and
/// recorded in [`RevisedAttributeDecode::malformed`] with its RFC 7606 §7
/// disposition. The caller applies the strongest recorded disposition
/// (§3 (h)).
///
/// Differences from the legacy decoder, all per RFC 7606:
///
/// - §3 (g): a duplicate attribute type keeps the first occurrence and
///   discards the rest; duplicate `MP_REACH_NLRI`/`MP_UNREACH_NLRI` is fatal.
/// - §4: an attribute whose length overruns the section is treat-as-withdraw
///   (the NLRI field was already located from the UPDATE section lengths),
///   and attribute parsing stops.
/// - §7.6/§7.7: `ATOMIC_AGGREGATE` with a non-zero length and `AGGREGATOR`
///   with a length other than 6/8 (by the 4-octet-AS negotiation) are
///   attribute-discard. The legacy decoder still preserves `ATOMIC_AGGREGATE`
///   opaquely, but now decodes and length-validates typed `AGGREGATOR`.
/// - RFC 9552 §8.2.2: malformed TLV framing inside Attribute 29 is
///   attribute-discard; the attribute is omitted while the NLRI remains
///   available to the caller.
///
/// `is_ibgp` selects the internal-neighbor branch of
/// [`malformed_attr_disposition`] for `LOCAL_PREF` / `ORIGINATOR_ID` /
/// `CLUSTER_LIST`.
///
/// # Errors
///
/// Returns `Err` only for session-reset-class problems: a malformed or
/// duplicated `MP_REACH_NLRI`/`MP_UNREACH_NLRI` (§7.11 — the NLRI cannot be
/// reliably located).
#[expect(
    clippy::too_many_lines,
    reason = "framing inspection, duplicate ordering, and disposition accumulation must stay ordered"
)]
pub fn decode_path_attributes_revised(
    mut buf: &[u8],
    four_octet_as: bool,
    is_ibgp: bool,
    add_path_families: &[(Afi, Safi)],
) -> Result<RevisedAttributeDecode, DecodeError> {
    let mut attrs = Vec::new();
    let mut bgpls_discarded = 0_u32;
    let mut malformed = Vec::new();
    let mut seen = std::collections::HashSet::new();
    while !buf.is_empty() {
        let (flags, type_code, value) = match split_next_attribute(&mut buf) {
            Ok(split) => split,
            Err(error) => {
                // RFC 7606 §4: framing overrun/underrun inside the attribute
                // section is treat-as-withdraw — the section boundaries (and
                // thus the NLRI field) were already fixed by the UPDATE
                // length fields. Nothing after this point can be parsed.
                malformed.push(MalformedAttribute {
                    type_code: if buf.len() >= 2 { buf[1] } else { 0 },
                    disposition: ErrorDisposition::TreatAsWithdraw,
                    error,
                });
                break;
            }
        };
        // RFC 9774 §3 prohibits AS_SET and AS_CONFED_SET in both AS_PATH
        // and AS4_PATH. Inspect the raw segment framing before duplicate
        // handling: a prohibited segment in a later duplicate must retain
        // treat-as-withdraw rather than being reduced to attribute-discard.
        let prohibited_segment = match type_code {
            attr_type::AS_PATH => prohibited_as_set(value, if four_octet_as { 4 } else { 2 }),
            attr_type::AS4_PATH => prohibited_as_set(value, 4),
            _ => None,
        };
        if let Some(segment_type) = prohibited_segment {
            malformed.push(MalformedAttribute {
                type_code,
                disposition: ErrorDisposition::TreatAsWithdraw,
                error: DecodeError::UpdateAttributeError {
                    subcode: update_subcode::MALFORMED_AS_PATH,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!(
                        "RFC 9774 prohibits AS path segment type {segment_type} in attribute type {type_code}"
                    ),
                },
            });
        }
        if !seen.insert(type_code) {
            // RFC 7606 §3 (g): duplicate MP_REACH/MP_UNREACH is fatal; any
            // other duplicate keeps the first occurrence and discards the
            // rest while the UPDATE continues to be processed.
            let error = DecodeError::UpdateAttributeError {
                subcode: update_subcode::MALFORMED_ATTRIBUTE_LIST,
                data: vec![],
                detail: format!("duplicate attribute type {type_code}"),
            };
            if matches!(
                type_code,
                attr_type::MP_REACH_NLRI | attr_type::MP_UNREACH_NLRI
            ) {
                return Err(error);
            }
            malformed.push(MalformedAttribute {
                type_code,
                disposition: ErrorDisposition::AttributeDiscard,
                error,
            });
            continue;
        }
        // RFC 7606 §7.6/§7.7 length checks. The legacy decoder stores both
        // types opaquely as Unknown(RawAttribute) with no length validation,
        // so these checks live only on the revised path. The attribute-discard
        // shortcut applies only when the flags are correct: a flag conflict
        // must fall through to decode_attribute_value, whose flags error is
        // classified treat-as-withdraw below (§3 (c) — the stronger action
        // wins per §3 (h)).
        let flags_ok = expected_flags(type_code).is_none_or(|expected| {
            (flags & (attr_flags::OPTIONAL | attr_flags::TRANSITIVE)) == expected
        });
        let expected_aggregator_len = if four_octet_as { 8 } else { 6 };
        let bad_aggregate_len = flags_ok
            && match type_code {
                attr_type::ATOMIC_AGGREGATE => !value.is_empty(),
                attr_type::AGGREGATOR => value.len() != expected_aggregator_len,
                _ => false,
            };
        if bad_aggregate_len {
            malformed.push(MalformedAttribute {
                type_code,
                disposition: ErrorDisposition::AttributeDiscard,
                error: DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!("attribute type {type_code} length {}", value.len()),
                },
            });
            continue;
        }
        match decode_attribute_value(
            flags,
            type_code,
            value,
            four_octet_as,
            add_path_families,
            &mut bgpls_discarded,
        ) {
            Ok(attr) => attrs.push(attr),
            Err(error) => {
                // RFC 7606 §3 (c): an Optional/Transitive flag conflict is
                // treat-as-withdraw for every attribute — the §7.6/§7.7
                // attribute-discard covers length malformations only. max()
                // keeps MP_REACH/MP_UNREACH at session-reset (§5.3 lists
                // inconsistent flags among what makes the MP attribute
                // itself incorrect).
                let mut disposition = malformed_attr_disposition(type_code, is_ibgp);
                if matches!(
                    &error,
                    DecodeError::UpdateAttributeError { subcode, .. }
                        if *subcode == update_subcode::ATTRIBUTE_FLAGS_ERROR
                ) {
                    disposition = disposition.max(ErrorDisposition::TreatAsWithdraw);
                }
                if disposition == ErrorDisposition::SessionReset {
                    return Err(error);
                }
                malformed.push(MalformedAttribute {
                    type_code,
                    disposition,
                    error,
                });
            }
        }
    }
    malformed.extend(normalize_as4_attributes(&mut attrs, four_octet_as, true));
    Ok(RevisedAttributeDecode {
        attributes: attrs,
        bgpls_nlri_discarded: bgpls_discarded,
        malformed,
    })
}

/// Consume RFC 6793 compatibility attributes and leave one canonical path and
/// aggregator representation. Both decode entry points call this function so
/// BMP/MRT readers and live RFC 7606 processing see identical route semantics.
fn normalize_as4_attributes(
    attrs: &mut Vec<PathAttribute>,
    four_octet_as: bool,
    observe_new_to_new_discard: bool,
) -> Vec<MalformedAttribute> {
    let mut as4_path = None;
    let mut as4_aggregator = None;
    let mut malformed = Vec::new();

    attrs.retain(|attr| {
        let PathAttribute::Unknown(raw) = attr else {
            return true;
        };
        let slot = match raw.type_code {
            attr_type::AS4_PATH => &mut as4_path,
            attr_type::AS4_AGGREGATOR => &mut as4_aggregator,
            _ => return true,
        };
        if slot.is_some() {
            malformed.push(MalformedAttribute {
                type_code: raw.type_code,
                disposition: ErrorDisposition::AttributeDiscard,
                error: DecodeError::UpdateAttributeError {
                    subcode: update_subcode::MALFORMED_ATTRIBUTE_LIST,
                    data: vec![],
                    detail: format!("duplicate attribute type {}", raw.type_code),
                },
            });
        } else {
            *slot = Some(raw.clone());
        }
        false
    });

    let decoded_as4_path = as4_path.and_then(|raw| match decode_as4_path(&raw) {
        Ok((path, confed_sequence_removed)) => {
            if confed_sequence_removed && observe_new_to_new_discard {
                malformed.push(as4_confed_sequence_removed(&raw));
            }
            if four_octet_as && observe_new_to_new_discard {
                malformed.push(new_to_new_discard(&raw));
            }
            Some(path)
        }
        Err(error) => {
            malformed.push(MalformedAttribute {
                type_code: attr_type::AS4_PATH,
                disposition: ErrorDisposition::AttributeDiscard,
                error,
            });
            None
        }
    });
    let decoded_as4_aggregator = as4_aggregator.and_then(|raw| match decode_as4_aggregator(&raw) {
        Ok(aggregator) => {
            if four_octet_as && observe_new_to_new_discard {
                malformed.push(new_to_new_discard(&raw));
            }
            Some(aggregator)
        }
        Err(error) => {
            malformed.push(MalformedAttribute {
                type_code: attr_type::AS4_AGGREGATOR,
                disposition: ErrorDisposition::AttributeDiscard,
                error,
            });
            None
        }
    });

    if !four_octet_as {
        let ordinary_non_trans_aggregator = attrs.iter().any(|attr| {
            matches!(
                attr,
                PathAttribute::Aggregator(aggregator)
                    if aggregator.asn != u32::from(crate::constants::AS_TRANS)
            )
        });
        // RFC 6793 section 4.2.3: when valid AGGREGATOR and AS4_AGGREGATOR
        // are both present but the ordinary ASN is not AS_TRANS, both AS4
        // compatibility attributes are ignored as an inconsistent pair.
        let ignore_as4_pair = ordinary_non_trans_aggregator && decoded_as4_aggregator.is_some();
        if !ignore_as4_pair {
            if let Some(path) = decoded_as4_path {
                reconstruct_as_path(attrs, &path);
            }
            if let Some(aggregator) = decoded_as4_aggregator {
                reconstruct_aggregator(attrs, aggregator);
            }
        }
    }
    malformed
}

fn new_to_new_discard(raw: &RawAttribute) -> MalformedAttribute {
    MalformedAttribute {
        type_code: raw.type_code,
        disposition: ErrorDisposition::AttributeDiscard,
        error: DecodeError::UpdateAttributeError {
            subcode: update_subcode::OPTIONAL_ATTRIBUTE_ERROR,
            data: attr_error_data(raw.flags, raw.type_code, &raw.data),
            detail: format!(
                "attribute type {} received from a four-octet-AS peer and discarded per RFC 6793",
                raw.type_code
            ),
        },
    }
}

fn as4_confed_sequence_removed(raw: &RawAttribute) -> MalformedAttribute {
    MalformedAttribute {
        type_code: attr_type::AS4_PATH,
        disposition: ErrorDisposition::AttributeDiscard,
        error: DecodeError::UpdateAttributeError {
            subcode: update_subcode::OPTIONAL_ATTRIBUTE_ERROR,
            data: attr_error_data(raw.flags, raw.type_code, &raw.data),
            detail: "AS_CONFED_SEQUENCE removed from AS4_PATH per RFC 6793".to_string(),
        },
    }
}

fn decode_as4_path(raw: &RawAttribute) -> Result<(AsPath, bool), DecodeError> {
    let malformed = |detail: String| DecodeError::UpdateAttributeError {
        subcode: update_subcode::MALFORMED_AS_PATH,
        data: attr_error_data(raw.flags, raw.type_code, &raw.data),
        detail,
    };
    if raw.data.len() < 6 || !raw.data.len().is_multiple_of(2) {
        return Err(malformed(format!(
            "AS4_PATH length {} (expected an even value of at least 6)",
            raw.data.len()
        )));
    }
    let mut value = raw.data.as_ref();
    let mut segments = Vec::new();
    let mut confed_sequence_removed = false;
    while !value.is_empty() {
        if value.len() < 2 {
            return Err(malformed("truncated AS4_PATH segment header".to_string()));
        }
        let segment_type = value[0];
        let count = usize::from(value[1]);
        value = &value[2..];
        if count == 0 {
            return Err(malformed("zero-length AS4_PATH segment".to_string()));
        }
        if !matches!(segment_type, 1..=4) {
            return Err(malformed(format!(
                "unknown AS4_PATH segment type {segment_type}"
            )));
        }
        let needed = count
            .checked_mul(4)
            .ok_or_else(|| malformed("AS4_PATH segment length overflow".to_string()))?;
        if value.len() < needed {
            return Err(malformed(format!(
                "AS4_PATH segment truncated: need {needed} bytes, have {}",
                value.len()
            )));
        }
        let asns = value[..needed]
            .chunks_exact(4)
            .map(|asn| u32::from_be_bytes([asn[0], asn[1], asn[2], asn[3]]))
            .collect();
        value = &value[needed..];
        match segment_type {
            1 | 4 => {
                return Err(malformed(format!(
                    "RFC 9774 prohibits AS4_PATH segment type {segment_type}"
                )));
            }
            2 => segments.push(AsPathSegment::AsSequence(asns)),
            // RFC 6793 requires AS_CONFED_SEQUENCE to be removed from the
            // compatibility path before reconstruction.
            3 => confed_sequence_removed = true,
            _ => unreachable!("segment type checked above"),
        }
    }
    Ok((AsPath { segments }, confed_sequence_removed))
}

fn decode_as4_aggregator(raw: &RawAttribute) -> Result<Aggregator, DecodeError> {
    if raw.data.len() != 8 {
        return Err(DecodeError::UpdateAttributeError {
            subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
            data: attr_error_data(raw.flags, raw.type_code, &raw.data),
            detail: format!("AS4_AGGREGATOR length {} (expected 8)", raw.data.len()),
        });
    }
    Ok(Aggregator {
        asn: u32::from_be_bytes([raw.data[0], raw.data[1], raw.data[2], raw.data[3]]),
        router_id: Ipv4Addr::new(raw.data[4], raw.data[5], raw.data[6], raw.data[7]),
        partial: raw.flags & attr_flags::PARTIAL != 0,
    })
}

fn reconstruct_as_path(attrs: &mut [PathAttribute], as4_path: &AsPath) {
    let Some(PathAttribute::AsPath(as_path)) = attrs
        .iter_mut()
        .find(|attr| matches!(attr, PathAttribute::AsPath(_)))
    else {
        return;
    };
    let old_count = as_path.len();
    let as4_count = as4_path.len();
    if old_count < as4_count {
        return;
    }

    let mut keep = old_count - as4_count;
    let mut reconstructed = Vec::new();
    for segment in &as_path.segments {
        if keep == 0 {
            break;
        }
        match segment {
            AsPathSegment::AsSet(asns) => {
                // RFC 4271 path length counts an AS_SET as one regardless of
                // member count. Retaining that one position retains the
                // complete unordered set.
                reconstructed.push(AsPathSegment::AsSet(asns.clone()));
                keep -= 1;
            }
            AsPathSegment::AsSequence(asns) => {
                let take = keep.min(asns.len());
                if take != 0 {
                    reconstructed.push(AsPathSegment::AsSequence(asns[..take].to_vec()));
                }
                keep -= take;
            }
        }
    }
    for segment in &as4_path.segments {
        match (reconstructed.last_mut(), segment) {
            (Some(AsPathSegment::AsSequence(previous)), AsPathSegment::AsSequence(asns)) => {
                previous.extend(asns);
            }
            _ => reconstructed.push(segment.clone()),
        }
    }
    as_path.segments = reconstructed;
}

fn reconstruct_aggregator(attrs: &mut Vec<PathAttribute>, as4_aggregator: Aggregator) {
    let aggregator = attrs
        .iter_mut()
        .find(|attr| matches!(attr, PathAttribute::Aggregator(_)));
    match aggregator {
        Some(PathAttribute::Aggregator(current))
            if current.asn == u32::from(crate::constants::AS_TRANS) =>
        {
            *current = as4_aggregator;
        }
        Some(_) => {}
        None => attrs.push(PathAttribute::Aggregator(as4_aggregator)),
    }
}

/// Return the first RFC 9774-prohibited set segment in a raw AS path.
fn prohibited_as_set(mut value: &[u8], asn_width: usize) -> Option<u8> {
    while value.len() >= 2 {
        let segment_type = value[0];
        let count = usize::from(value[1]);
        if count == 0 || !matches!(segment_type, 1..=4) {
            return None;
        }
        let segment_len = count.checked_mul(asn_width)?;
        let next = value.get(2_usize.checked_add(segment_len)?..)?;
        if matches!(segment_type, 1 | 4) {
            return Some(segment_type);
        }
        value = next;
    }
    None
}
/// Decode a single attribute value given its flags, type code, and raw bytes.
#[expect(
    clippy::too_many_lines,
    reason = "single attribute decoder keeps type-specific validation and error mapping together"
)]
fn decode_attribute_value(
    flags: u8,
    type_code: u8,
    value: &[u8],
    four_octet_as: bool,
    add_path_families: &[(Afi, Safi)],
    bgpls_discarded: &mut u32,
) -> Result<PathAttribute, DecodeError> {
    // Validate the required flags for known attribute types (RFC 4271 §6.3).
    // RFC 4271 §4.3 requires Partial=0 for optional non-transitive
    // attributes. Existing typed attributes predate strict Partial checking;
    // include it for newly recognized Attribute 29 without broadening their
    // error surface in this change.
    let flags_mask = attr_flags::OPTIONAL
        | attr_flags::TRANSITIVE
        | if type_code == attr_type::BGP_LS {
            attr_flags::PARTIAL
        } else {
            0
        };
    if let Some(expected) = expected_flags(type_code)
        && (flags & flags_mask) != expected
    {
        return Err(DecodeError::UpdateAttributeError {
            subcode: update_subcode::ATTRIBUTE_FLAGS_ERROR,
            data: attr_error_data(flags, type_code, value),
            detail: format!(
                "type {} flags {:#04x} (expected {:#04x})",
                type_code,
                flags & flags_mask,
                expected
            ),
        });
    }
    match type_code {
        attr_type::ORIGIN => {
            if value.len() != 1 {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!("ORIGIN length {} (expected 1)", value.len()),
                });
            }
            match Origin::from_u8(value[0]) {
                Some(origin) => Ok(PathAttribute::Origin(origin)),
                None => Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::INVALID_ORIGIN,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!("invalid ORIGIN value {}", value[0]),
                }),
            }
        }
        attr_type::AS_PATH => {
            let segments = decode_as_path(value, four_octet_as).map_err(|e| {
                DecodeError::UpdateAttributeError {
                    subcode: update_subcode::MALFORMED_AS_PATH,
                    data: attr_error_data(flags, type_code, value),
                    detail: e.to_string(),
                }
            })?;
            Ok(PathAttribute::AsPath(AsPath { segments }))
        }
        attr_type::AGGREGATOR => {
            let expected_len = if four_octet_as { 8 } else { 6 };
            if value.len() != expected_len {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!(
                        "AGGREGATOR length {} (expected {expected_len})",
                        value.len()
                    ),
                });
            }
            let (asn, router_id) = if four_octet_as {
                (
                    u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
                    Ipv4Addr::new(value[4], value[5], value[6], value[7]),
                )
            } else {
                (
                    u32::from(u16::from_be_bytes([value[0], value[1]])),
                    Ipv4Addr::new(value[2], value[3], value[4], value[5]),
                )
            };
            Ok(PathAttribute::Aggregator(Aggregator {
                asn,
                router_id,
                partial: flags & attr_flags::PARTIAL != 0,
            }))
        }
        attr_type::NEXT_HOP => {
            if value.len() != 4 {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!("NEXT_HOP length {} (expected 4)", value.len()),
                });
            }
            let addr = Ipv4Addr::new(value[0], value[1], value[2], value[3]);
            Ok(PathAttribute::NextHop(addr))
        }
        attr_type::MULTI_EXIT_DISC => {
            if value.len() != 4 {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!("MED length {} (expected 4)", value.len()),
                });
            }
            let med = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
            Ok(PathAttribute::Med(med))
        }
        attr_type::LOCAL_PREF => {
            if value.len() != 4 {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!("LOCAL_PREF length {} (expected 4)", value.len()),
                });
            }
            let lp = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
            Ok(PathAttribute::LocalPref(lp))
        }
        attr_type::COMMUNITIES => {
            // RFC 7606 §7.8: the length must be a NON-ZERO multiple of 4.
            if value.is_empty() || !value.len().is_multiple_of(4) {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!(
                        "COMMUNITIES length {} not a non-zero multiple of 4",
                        value.len()
                    ),
                });
            }
            let communities = value
                .chunks_exact(4)
                .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                .collect();
            Ok(PathAttribute::Communities(communities))
        }
        attr_type::EXTENDED_COMMUNITIES => {
            // RFC 7606 §7.14: the length must be a NON-ZERO multiple of 8.
            if value.is_empty() || !value.len().is_multiple_of(8) {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!(
                        "EXTENDED_COMMUNITIES length {} not a non-zero multiple of 8",
                        value.len()
                    ),
                });
            }
            let communities = value
                .chunks_exact(8)
                .map(|c| {
                    ExtendedCommunity::new(u64::from_be_bytes([
                        c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7],
                    ]))
                })
                .collect();
            Ok(PathAttribute::ExtendedCommunities(communities))
        }
        attr_type::ORIGINATOR_ID => {
            if value.len() != 4 {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!("ORIGINATOR_ID length {} (expected 4)", value.len()),
                });
            }
            let addr = Ipv4Addr::new(value[0], value[1], value[2], value[3]);
            Ok(PathAttribute::OriginatorId(addr))
        }
        attr_type::CLUSTER_LIST => {
            if !value.len().is_multiple_of(4) {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!("CLUSTER_LIST length {} not a multiple of 4", value.len()),
                });
            }
            let ids = value
                .chunks_exact(4)
                .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                .collect();
            Ok(PathAttribute::ClusterList(ids))
        }
        attr_type::LARGE_COMMUNITIES => {
            if value.is_empty() || !value.len().is_multiple_of(12) {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!(
                        "LARGE_COMMUNITIES length {} invalid (must be non-zero multiple of 12)",
                        value.len()
                    ),
                });
            }
            let mut seen = std::collections::HashSet::with_capacity(value.len() / 12);
            let communities = value
                .chunks_exact(12)
                .filter_map(|c| {
                    let community = LargeCommunity::new(
                        u32::from_be_bytes([c[0], c[1], c[2], c[3]]),
                        u32::from_be_bytes([c[4], c[5], c[6], c[7]]),
                        u32::from_be_bytes([c[8], c[9], c[10], c[11]]),
                    );
                    seen.insert(community).then_some(community)
                })
                .collect();
            Ok(PathAttribute::LargeCommunities(communities))
        }
        attr_type::MP_REACH_NLRI => decode_mp_reach_nlri(value, add_path_families, bgpls_discarded),
        attr_type::MP_UNREACH_NLRI => {
            decode_mp_unreach_nlri(value, add_path_families, bgpls_discarded)
        }
        attr_type::PMSI_TUNNEL => {
            let pmsi = crate::pmsi::PmsiTunnel::decode(value)?;
            Ok(PathAttribute::PmsiTunnel(pmsi))
        }
        attr_type::BGP_LS => {
            // RFC 9552 §8.2.2: an intact path-attribute boundary containing
            // malformed TLV framing discards the whole BGP-LS Attribute. Do
            // not validate fixed/variable value lengths or semantics here;
            // a BGP-LS propagator is explicitly forbidden from doing so.
            crate::bgpls::validate_bgpls_tlv_framing(value).map_err(|error| {
                DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: error.to_string(),
                }
            })?;
            Ok(PathAttribute::Unknown(RawAttribute {
                flags,
                type_code,
                data: Bytes::copy_from_slice(value),
            }))
        }
        attr_type::ONLY_TO_CUSTOMER => {
            // Preserve as Unknown(RawAttribute) in two cases — both keep
            // PR2's transport-side OTC inspection working (it matches
            // typed `OnlyToCustomer(_)` AND `Unknown(raw)` with
            // raw.type_code == 35):
            //
            // (1) **Malformed length (≠ 4 octets).** RFC 9234 §5 / RFC
            //     7606 — must be recoverable, NOT a fatal DecodeError,
            //     because UPDATE parse errors otherwise short-circuit
            //     into the FSM and tear the session down. PR2 detects
            //     malformed type-35 attributes via the Unknown path and
            //     applies treat-as-withdraw.
            //
            // (2) **Partial bit set.** RFC 4271 §5: a recognized
            //     optional-transitive attribute received with Partial=1
            //     MUST have Partial preserved on re-advertisement.
            //     Decoding to canonical `OnlyToCustomer(u32)` would lose
            //     the bit (encode emits 0xC0). Routing it through the
            //     Unknown arm lets the existing Unknown-encode path
            //     keep Partial faithfully (it OR's Partial into
            //     optional-transitive flags on emit). Locally-added OTC
            //     (PR2 E1/I3) constructs `OnlyToCustomer(u32)` directly
            //     and emits canonical 0xC0.
            //
            // Flag-validity ran above (subcode 4), so this arm only
            // sees flags whose (OPTIONAL | TRANSITIVE) bits are 0xC0.
            if value.len() != 4 || (flags & attr_flags::PARTIAL) != 0 {
                return Ok(PathAttribute::Unknown(RawAttribute {
                    flags,
                    type_code,
                    data: Bytes::copy_from_slice(value),
                }));
            }
            let asn = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
            Ok(PathAttribute::OnlyToCustomer(asn))
        }
        // ATOMIC_AGGREGATE and any unknown type -> RawAttribute. AS4_PATH and
        // AS4_AGGREGATOR are kept raw only until the shared post-decode RFC
        // 6793 normalizer consumes them.
        _ => Ok(PathAttribute::Unknown(RawAttribute {
            flags,
            type_code,
            data: Bytes::copy_from_slice(value),
        })),
    }
}
/// Decode `MP_REACH_NLRI` (type 14) attribute value.
///
/// Wire layout (RFC 4760 §3):
///   AFI (2) | SAFI (1) | NH-Len (1) | Next Hop (variable) | Reserved (1) | NLRI (variable)
#[expect(
    clippy::too_many_lines,
    reason = "MP_REACH decoder keeps family dispatch and next-hop validation in one pass"
)]
fn decode_mp_reach_nlri(
    value: &[u8],
    add_path_families: &[(Afi, Safi)],
    bgpls_discarded: &mut u32,
) -> Result<PathAttribute, DecodeError> {
    if value.len() < 5 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!("MP_REACH_NLRI too short: {} bytes", value.len()),
        });
    }
    let afi_raw = u16::from_be_bytes([value[0], value[1]]);
    let safi_raw = value[2];
    let nh_len = value[3] as usize;
    let afi = Afi::from_u16(afi_raw).ok_or_else(|| DecodeError::MalformedField {
        message_type: "UPDATE",
        detail: format!("MP_REACH_NLRI unsupported AFI {afi_raw}"),
    })?;
    let safi = Safi::from_u8(safi_raw).ok_or_else(|| DecodeError::MalformedField {
        message_type: "UPDATE",
        detail: format!("MP_REACH_NLRI unsupported SAFI {safi_raw}"),
    })?;
    let family = classify_mp_nlri_family(afi, safi, "MP_REACH_NLRI")?;
    // 4 bytes for AFI+SAFI+NH-Len, then nh_len bytes, then 1 reserved byte
    if value.len() < 4 + nh_len + 1 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!(
                "MP_REACH_NLRI truncated: NH-Len={nh_len}, have {} bytes total",
                value.len()
            ),
        });
    }
    let nh_bytes = &value[4..4 + nh_len];
    // FlowSpec (SAFI 133): NH length is 0 — no next-hop for filter rules
    let mut link_local_next_hop: Option<Ipv6Addr> = None;
    let next_hop = match family {
        MpNlriFamily::FlowSpec => {
            if nh_len != 0 {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: format!("MP_REACH_NLRI FlowSpec next-hop length {nh_len} (expected 0)"),
                });
            }
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        }
        MpNlriFamily::BgpLs => {
            let (nh, ll) = decode_bgpls_mp_next_hop(safi, nh_bytes, nh_len)?;
            link_local_next_hop = ll;
            nh
        }
        MpNlriFamily::Vpn => {
            let (nh, ll) = decode_vpn_mp_next_hop(nh_bytes, nh_len)?;
            link_local_next_hop = ll;
            nh
        }
        // RTC next-hop is an ordinary host address (RFC 4684 says nothing
        // special): reuse the Unicast 4/16/32-byte forms, no RD prefix.
        MpNlriFamily::Unicast | MpNlriFamily::Evpn | MpNlriFamily::Labeled | MpNlriFamily::Rtc => {
            match afi {
                Afi::Ipv4 => match nh_len {
                    4 => IpAddr::V4(Ipv4Addr::new(
                        nh_bytes[0],
                        nh_bytes[1],
                        nh_bytes[2],
                        nh_bytes[3],
                    )),
                    16 | 32 => {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&nh_bytes[..16]);
                        if nh_len == 32 {
                            let mut ll = [0u8; 16];
                            ll.copy_from_slice(&nh_bytes[16..32]);
                            link_local_next_hop = Some(Ipv6Addr::from(ll));
                        }
                        IpAddr::V6(Ipv6Addr::from(octets))
                    }
                    _ => {
                        return Err(DecodeError::MalformedField {
                            message_type: "UPDATE",
                            detail: format!(
                                "MP_REACH_NLRI IPv4 next-hop length {nh_len} (expected 4, 16, or 32)"
                            ),
                        });
                    }
                },
                Afi::Ipv6 => {
                    if nh_len != 16 && nh_len != 32 {
                        return Err(DecodeError::MalformedField {
                            message_type: "UPDATE",
                            detail: format!(
                                "MP_REACH_NLRI IPv6 next-hop length {nh_len} (expected 16 or 32)"
                            ),
                        });
                    }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&nh_bytes[..16]);
                    if nh_len == 32 {
                        let mut ll = [0u8; 16];
                        ll.copy_from_slice(&nh_bytes[16..32]);
                        link_local_next_hop = Some(Ipv6Addr::from(ll));
                    }
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
                Afi::L2Vpn => match nh_len {
                    4 => IpAddr::V4(Ipv4Addr::new(
                        nh_bytes[0],
                        nh_bytes[1],
                        nh_bytes[2],
                        nh_bytes[3],
                    )),
                    16 => {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&nh_bytes[..16]);
                        IpAddr::V6(Ipv6Addr::from(octets))
                    }
                    _ => {
                        return Err(DecodeError::MalformedField {
                            message_type: "UPDATE",
                            detail: format!(
                                "MP_REACH_NLRI L2VPN next-hop length {nh_len} (expected 4 or 16)"
                            ),
                        });
                    }
                },
                Afi::BgpLs => return Err(unsupported_mp_nlri_family("MP_REACH_NLRI", afi, safi)),
            }
        }
    };
    // Skip reserved byte
    let nlri_start = 4 + nh_len + 1;
    let nlri_bytes = &value[nlri_start..];
    // FlowSpec (SAFI 133): NLRI is FlowSpec rules, not prefixes
    if family == MpNlriFamily::FlowSpec {
        let flowspec_rules = crate::flowspec::decode_flowspec_nlri(nlri_bytes, afi)?;
        return Ok(PathAttribute::MpReachNlri(MpReachNlri {
            afi,
            safi,
            next_hop,
            link_local_next_hop,
            announced: vec![],
            flowspec_announced: flowspec_rules,
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }));
    }
    // EVPN (AFI 25 / SAFI 70): NLRI is typed EVPN routes, not prefixes
    if family == MpNlriFamily::Evpn {
        let routes = crate::evpn::decode_evpn_nlri(nlri_bytes)?;
        return Ok(PathAttribute::MpReachNlri(MpReachNlri {
            afi,
            safi,
            next_hop,
            link_local_next_hop,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: routes,
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }));
    }
    if family == MpNlriFamily::BgpLs {
        // Deliberately kept even though VPN (SAFI 128) grew Add-Path: no
        // demand for multi-path BGP-LS topology feeds, and negotiation never
        // offers Add-Path for these families.
        if add_path_families.contains(&(afi, safi)) {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: "MP_REACH_NLRI BGP-LS Add-Path is not supported".to_string(),
            });
        }
        let (routes, discarded) = if safi == Safi::BgpLsVpn {
            crate::bgpls::decode_bgpls_vpn_nlri_counted(nlri_bytes)?
        } else {
            crate::bgpls::decode_bgpls_nlri_counted(nlri_bytes)?
        };
        *bgpls_discarded = bgpls_discarded.saturating_add(discarded);
        return Ok(PathAttribute::MpReachNlri(MpReachNlri {
            afi,
            safi,
            next_hop,
            link_local_next_hop,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: routes,
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }));
    }
    if family == MpNlriFamily::Vpn {
        let vpn_family = if afi == Afi::Ipv4 {
            crate::vpn::VpnAddressFamily::V4
        } else {
            crate::vpn::VpnAddressFamily::V6
        };
        let routes = if add_path_families.contains(&(afi, safi)) {
            crate::vpn::decode_vpn_nlri_addpath(nlri_bytes, vpn_family)?
        } else {
            crate::vpn::decode_vpn_nlri(nlri_bytes, vpn_family)?
                .into_iter()
                .map(|nlri| crate::vpn::VpnNlriEntry { path_id: 0, nlri })
                .collect()
        };
        return Ok(PathAttribute::MpReachNlri(MpReachNlri {
            afi,
            safi,
            next_hop,
            link_local_next_hop,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: routes,
            rtc_announced: vec![],
        }));
    }
    if family == MpNlriFamily::Labeled {
        let labeled_family = if afi == Afi::Ipv4 {
            crate::labeled::LabeledAddressFamily::V4
        } else {
            crate::labeled::LabeledAddressFamily::V6
        };
        let routes = if add_path_families.contains(&(afi, safi)) {
            crate::labeled::decode_labeled_nlri_addpath(nlri_bytes, labeled_family)?
        } else {
            crate::labeled::decode_labeled_nlri(nlri_bytes, labeled_family)?
                .into_iter()
                .map(|nlri| crate::labeled::LabeledNlriEntry { path_id: 0, nlri })
                .collect()
        };
        return Ok(PathAttribute::MpReachNlri(MpReachNlri {
            afi,
            safi,
            next_hop,
            link_local_next_hop,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            vpn_announced: vec![],
            labeled_announced: routes,
            rtc_announced: vec![],
        }));
    }
    if family == MpNlriFamily::Rtc {
        // Deliberately kept even though VPN (SAFI 128) grew Add-Path:
        // Add-Path semantics for RTC *membership* NLRI are undefined-ish
        // (multiple paths for one RT membership have no useful meaning for
        // the RFC 4684 outbound filter), and negotiation never offers it.
        if add_path_families.contains(&(afi, safi)) {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: "MP_REACH_NLRI RTC Add-Path is not supported".to_string(),
            });
        }
        let routes = crate::rtc::decode_rtc_nlri(nlri_bytes)?;
        return Ok(PathAttribute::MpReachNlri(MpReachNlri {
            afi,
            safi,
            next_hop,
            link_local_next_hop,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: routes,
        }));
    }
    let add_path = add_path_families.contains(&(afi, safi));
    let announced = match (afi, add_path) {
        (Afi::Ipv4, false) => crate::nlri::decode_nlri(nlri_bytes)?
            .into_iter()
            .map(|p| NlriEntry {
                path_id: 0,
                prefix: Prefix::V4(p),
            })
            .collect(),
        (Afi::Ipv4, true) => crate::nlri::decode_nlri_addpath(nlri_bytes)?
            .into_iter()
            .map(|e| NlriEntry {
                path_id: e.path_id,
                prefix: Prefix::V4(e.prefix),
            })
            .collect(),
        (Afi::Ipv6, false) => crate::nlri::decode_ipv6_nlri(nlri_bytes)?
            .into_iter()
            .map(|p| NlriEntry {
                path_id: 0,
                prefix: Prefix::V6(p),
            })
            .collect(),
        (Afi::Ipv6, true) => crate::nlri::decode_ipv6_nlri_addpath(nlri_bytes)?,
        (Afi::L2Vpn | Afi::BgpLs, _) => {
            return Err(unsupported_mp_nlri_family("MP_REACH_NLRI", afi, safi));
        }
    };
    Ok(PathAttribute::MpReachNlri(MpReachNlri {
        afi,
        safi,
        next_hop,
        link_local_next_hop,
        announced,
        flowspec_announced: vec![],
        evpn_announced: vec![],
        bgpls_announced: vec![],
        labeled_announced: vec![],
        vpn_announced: vec![],
        rtc_announced: vec![],
    }))
}
/// Decode `MP_UNREACH_NLRI` (type 15) attribute value.
///
/// Wire layout (RFC 4760 §4):
///   AFI (2) | SAFI (1) | Withdrawn Routes (variable)
#[expect(
    clippy::too_many_lines,
    reason = "MP_UNREACH decoder keeps family dispatch in one pass"
)]
fn decode_mp_unreach_nlri(
    value: &[u8],
    add_path_families: &[(Afi, Safi)],
    bgpls_discarded: &mut u32,
) -> Result<PathAttribute, DecodeError> {
    if value.len() < 3 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!("MP_UNREACH_NLRI too short: {} bytes", value.len()),
        });
    }
    let afi_raw = u16::from_be_bytes([value[0], value[1]]);
    let safi_raw = value[2];
    let afi = Afi::from_u16(afi_raw).ok_or_else(|| DecodeError::MalformedField {
        message_type: "UPDATE",
        detail: format!("MP_UNREACH_NLRI unsupported AFI {afi_raw}"),
    })?;
    let safi = Safi::from_u8(safi_raw).ok_or_else(|| DecodeError::MalformedField {
        message_type: "UPDATE",
        detail: format!("MP_UNREACH_NLRI unsupported SAFI {safi_raw}"),
    })?;
    let family = classify_mp_nlri_family(afi, safi, "MP_UNREACH_NLRI")?;
    let withdrawn_bytes = &value[3..];
    // FlowSpec (SAFI 133): withdrawn is FlowSpec rules
    if family == MpNlriFamily::FlowSpec {
        let flowspec_rules = crate::flowspec::decode_flowspec_nlri(withdrawn_bytes, afi)?;
        return Ok(PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi,
            safi,
            withdrawn: vec![],
            flowspec_withdrawn: flowspec_rules,
            evpn_withdrawn: vec![],
            bgpls_withdrawn: vec![],
            labeled_withdrawn: vec![],
            vpn_withdrawn: vec![],
            rtc_withdrawn: vec![],
        }));
    }
    // EVPN (AFI 25 / SAFI 70): withdrawn is typed EVPN routes, not prefixes
    if family == MpNlriFamily::Evpn {
        let routes = crate::evpn::decode_evpn_nlri(withdrawn_bytes)?;
        return Ok(PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi,
            safi,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: routes,
            bgpls_withdrawn: vec![],
            labeled_withdrawn: vec![],
            vpn_withdrawn: vec![],
            rtc_withdrawn: vec![],
        }));
    }
    if family == MpNlriFamily::BgpLs {
        return decode_bgpls_mp_unreach(
            afi,
            safi,
            withdrawn_bytes,
            add_path_families,
            bgpls_discarded,
        );
    }
    if family == MpNlriFamily::Vpn {
        return decode_vpn_mp_unreach(afi, safi, withdrawn_bytes, add_path_families);
    }
    if family == MpNlriFamily::Labeled {
        return decode_labeled_mp_unreach(afi, safi, withdrawn_bytes, add_path_families);
    }
    if family == MpNlriFamily::Rtc {
        return decode_rtc_mp_unreach(afi, safi, withdrawn_bytes, add_path_families);
    }
    let add_path = add_path_families.contains(&(afi, safi));
    let withdrawn = match (afi, add_path) {
        (Afi::Ipv4, false) => crate::nlri::decode_nlri(withdrawn_bytes)?
            .into_iter()
            .map(|p| NlriEntry {
                path_id: 0,
                prefix: Prefix::V4(p),
            })
            .collect(),
        (Afi::Ipv4, true) => crate::nlri::decode_nlri_addpath(withdrawn_bytes)?
            .into_iter()
            .map(|e| NlriEntry {
                path_id: e.path_id,
                prefix: Prefix::V4(e.prefix),
            })
            .collect(),
        (Afi::Ipv6, false) => crate::nlri::decode_ipv6_nlri(withdrawn_bytes)?
            .into_iter()
            .map(|p| NlriEntry {
                path_id: 0,
                prefix: Prefix::V6(p),
            })
            .collect(),
        (Afi::Ipv6, true) => crate::nlri::decode_ipv6_nlri_addpath(withdrawn_bytes)?,
        (Afi::L2Vpn | Afi::BgpLs, _) => {
            return Err(unsupported_mp_nlri_family("MP_UNREACH_NLRI", afi, safi));
        }
    };
    Ok(PathAttribute::MpUnreachNlri(MpUnreachNlri {
        afi,
        safi,
        withdrawn,
        flowspec_withdrawn: vec![],
        evpn_withdrawn: vec![],
        bgpls_withdrawn: vec![],
        labeled_withdrawn: vec![],
        vpn_withdrawn: vec![],
        rtc_withdrawn: vec![],
    }))
}
/// Decode the BGP-LS / BGP-LS VPN `MP_UNREACH_NLRI` branch (RFC 9552).
fn decode_bgpls_mp_unreach(
    afi: Afi,
    safi: Safi,
    withdrawn_bytes: &[u8],
    add_path_families: &[(Afi, Safi)],
    bgpls_discarded: &mut u32,
) -> Result<PathAttribute, DecodeError> {
    // Kept alongside the VPN Add-Path slice: no demand for multi-path
    // BGP-LS feeds; negotiation never offers Add-Path for these families.
    if add_path_families.contains(&(afi, safi)) {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: "MP_UNREACH_NLRI BGP-LS Add-Path is not supported".to_string(),
        });
    }
    let (routes, discarded) = if safi == Safi::BgpLsVpn {
        crate::bgpls::decode_bgpls_vpn_nlri_counted(withdrawn_bytes)?
    } else {
        crate::bgpls::decode_bgpls_nlri_counted(withdrawn_bytes)?
    };
    *bgpls_discarded = bgpls_discarded.saturating_add(discarded);
    Ok(PathAttribute::MpUnreachNlri(MpUnreachNlri {
        afi,
        safi,
        withdrawn: vec![],
        flowspec_withdrawn: vec![],
        evpn_withdrawn: vec![],
        bgpls_withdrawn: routes,
        labeled_withdrawn: vec![],
        vpn_withdrawn: vec![],
        rtc_withdrawn: vec![],
    }))
}
/// Decode the VPNv4/VPNv6 `MP_UNREACH_NLRI` branch (SAFI 128).
///
/// RFC 8277 §2.4: withdrawn VPN NLRI carry a single ignored 3-octet
/// compatibility field in the label position, not a BOS-terminated label
/// stack — announce-mode parsing would run past the field.
fn decode_vpn_mp_unreach(
    afi: Afi,
    safi: Safi,
    withdrawn_bytes: &[u8],
    add_path_families: &[(Afi, Safi)],
) -> Result<PathAttribute, DecodeError> {
    let vpn_family = if afi == Afi::Ipv4 {
        crate::vpn::VpnAddressFamily::V4
    } else {
        crate::vpn::VpnAddressFamily::V6
    };
    let routes = if add_path_families.contains(&(afi, safi)) {
        crate::vpn::decode_vpn_withdraw_nlri_addpath(withdrawn_bytes, vpn_family)?
    } else {
        crate::vpn::decode_vpn_withdraw_nlri(withdrawn_bytes, vpn_family)?
            .into_iter()
            .map(|nlri| crate::vpn::VpnNlriEntry { path_id: 0, nlri })
            .collect()
    };
    Ok(PathAttribute::MpUnreachNlri(MpUnreachNlri {
        afi,
        safi,
        withdrawn: vec![],
        flowspec_withdrawn: vec![],
        evpn_withdrawn: vec![],
        bgpls_withdrawn: vec![],
        labeled_withdrawn: vec![],
        vpn_withdrawn: routes,
        rtc_withdrawn: vec![],
    }))
}
/// Decode the IPv4/IPv6 labeled-unicast `MP_UNREACH_NLRI` branch (SAFI 4).
///
/// RFC 8277 §2.4: withdrawn labeled NLRI carry a single ignored 3-octet
/// compatibility field in the label position, not a BOS-terminated label
/// stack — announce-mode parsing would run past the field.
fn decode_labeled_mp_unreach(
    afi: Afi,
    safi: Safi,
    withdrawn_bytes: &[u8],
    add_path_families: &[(Afi, Safi)],
) -> Result<PathAttribute, DecodeError> {
    let labeled_family = if afi == Afi::Ipv4 {
        crate::labeled::LabeledAddressFamily::V4
    } else {
        crate::labeled::LabeledAddressFamily::V6
    };
    let routes = if add_path_families.contains(&(afi, safi)) {
        crate::labeled::decode_labeled_withdraw_nlri_addpath(withdrawn_bytes, labeled_family)?
    } else {
        crate::labeled::decode_labeled_withdraw_nlri(withdrawn_bytes, labeled_family)?
            .into_iter()
            .map(|nlri| crate::labeled::LabeledNlriEntry { path_id: 0, nlri })
            .collect()
    };
    Ok(PathAttribute::MpUnreachNlri(MpUnreachNlri {
        afi,
        safi,
        withdrawn: vec![],
        flowspec_withdrawn: vec![],
        evpn_withdrawn: vec![],
        bgpls_withdrawn: vec![],
        vpn_withdrawn: vec![],
        labeled_withdrawn: routes,
        rtc_withdrawn: vec![],
    }))
}
/// Decode the RT-Constrain `MP_UNREACH_NLRI` branch (RFC 4684, SAFI 132).
/// One codec covers both directions — no withdraw-mode split.
fn decode_rtc_mp_unreach(
    afi: Afi,
    safi: Safi,
    withdrawn_bytes: &[u8],
    add_path_families: &[(Afi, Safi)],
) -> Result<PathAttribute, DecodeError> {
    // Kept alongside the VPN Add-Path slice: Add-Path semantics for RTC
    // membership NLRI are undefined-ish; negotiation never offers it.
    if add_path_families.contains(&(afi, safi)) {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: "MP_UNREACH_NLRI RTC Add-Path is not supported".to_string(),
        });
    }
    let routes = crate::rtc::decode_rtc_nlri(withdrawn_bytes)?;
    Ok(PathAttribute::MpUnreachNlri(MpUnreachNlri {
        afi,
        safi,
        withdrawn: vec![],
        flowspec_withdrawn: vec![],
        evpn_withdrawn: vec![],
        bgpls_withdrawn: vec![],
        labeled_withdrawn: vec![],
        vpn_withdrawn: vec![],
        rtc_withdrawn: routes,
    }))
}
/// Decode `AS_PATH` segments from the attribute value bytes.
fn decode_as_path(mut buf: &[u8], four_octet_as: bool) -> Result<Vec<AsPathSegment>, DecodeError> {
    let as_size: usize = if four_octet_as { 4 } else { 2 };
    let mut segments = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 2 {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: "truncated AS_PATH segment header".to_string(),
            });
        }
        let seg_type = buf[0];
        let seg_count = buf[1] as usize;
        buf = &buf[2..];
        let needed = seg_count * as_size;
        if buf.len() < needed {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!(
                    "AS_PATH segment truncated: need {needed} bytes for {seg_count} ASNs, have {}",
                    buf.len()
                ),
            });
        }
        let mut asns = Vec::with_capacity(seg_count);
        for _ in 0..seg_count {
            let asn = if four_octet_as {
                let v = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                buf = &buf[4..];
                v
            } else {
                let v = u32::from(u16::from_be_bytes([buf[0], buf[1]]));
                buf = &buf[2..];
                v
            };
            asns.push(asn);
        }
        match seg_type {
            as_path_segment::AS_SET => segments.push(AsPathSegment::AsSet(asns)),
            as_path_segment::AS_SEQUENCE => segments.push(AsPathSegment::AsSequence(asns)),
            _ => {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: format!("unknown AS_PATH segment type {seg_type}"),
                });
            }
        }
    }
    Ok(segments)
}
/// Build the attribute-triplet (flags + type + length + value) used as
/// NOTIFICATION data in UPDATE error subcodes per RFC 4271 §6.3.
pub(crate) fn attr_error_data(flags: u8, type_code: u8, value: &[u8]) -> Vec<u8> {
    let extended_length = flags & attr_flags::EXTENDED_LENGTH != 0 || value.len() > 255;
    let header_len = if extended_length { 4 } else { 3 };
    let mut buf = Vec::with_capacity(header_len + value.len());
    if extended_length {
        buf.push(flags | attr_flags::EXTENDED_LENGTH);
        buf.push(type_code);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "codec bounds or masks the value before narrowing to the protocol field width"
        )]
        let len = value.len() as u16;
        buf.extend_from_slice(&len.to_be_bytes());
    } else {
        buf.push(flags);
        buf.push(type_code);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "codec bounds or masks the value before narrowing to the protocol field width"
        )]
        buf.push(value.len() as u8);
    }
    buf.extend_from_slice(value);
    buf
}
/// Return the expected Optional + Transitive flags for known attribute types.
/// Returns `None` for unrecognized types (no validation performed).
fn expected_flags(type_code: u8) -> Option<u8> {
    match type_code {
        // Well-known mandatory/discretionary: Optional=0, Transitive=1
        attr_type::ORIGIN
        | attr_type::AS_PATH
        | attr_type::NEXT_HOP
        | attr_type::LOCAL_PREF
        | attr_type::ATOMIC_AGGREGATE => Some(attr_flags::TRANSITIVE),
        // Optional non-transitive (RFC 4760 §3/§4: MP_REACH/UNREACH are non-transitive;
        // RFC 4456: ORIGINATOR_ID and CLUSTER_LIST are optional non-transitive)
        attr_type::MULTI_EXIT_DISC
        | attr_type::ORIGINATOR_ID
        | attr_type::CLUSTER_LIST
        | attr_type::MP_REACH_NLRI
        | attr_type::MP_UNREACH_NLRI
        | attr_type::BGP_LS => Some(attr_flags::OPTIONAL),
        // Optional transitive
        attr_type::AGGREGATOR
        | attr_type::AS4_PATH
        | attr_type::AS4_AGGREGATOR
        | attr_type::COMMUNITIES
        | attr_type::EXTENDED_COMMUNITIES
        | attr_type::LARGE_COMMUNITIES
        | attr_type::PMSI_TUNNEL
        | attr_type::ONLY_TO_CUSTOMER => Some(attr_flags::OPTIONAL | attr_flags::TRANSITIVE),
        _ => None,
    }
}
fn decode_bgpls_mp_next_hop(
    safi: Safi,
    nh_bytes: &[u8],
    nh_len: usize,
) -> Result<(IpAddr, Option<Ipv6Addr>), DecodeError> {
    let (ip_len, ip_bytes) = if safi == Safi::BgpLsVpn {
        if nh_len != 12 && nh_len != 24 && nh_len != 40 {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!(
                    "MP_REACH_NLRI BGP-LS VPN next-hop length {nh_len} (expected 12, 24, or 40)"
                ),
            });
        }
        if nh_bytes[..crate::bgpls::BGP_LS_ROUTE_DISTINGUISHER_LEN]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: "MP_REACH_NLRI BGP-LS VPN next-hop RD must be all zero".to_string(),
            });
        }
        (
            nh_len - crate::bgpls::BGP_LS_ROUTE_DISTINGUISHER_LEN,
            &nh_bytes[crate::bgpls::BGP_LS_ROUTE_DISTINGUISHER_LEN..],
        )
    } else {
        if nh_len != 4 && nh_len != 16 && nh_len != 32 {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!(
                    "MP_REACH_NLRI BGP-LS next-hop length {nh_len} (expected 4, 16, or 32)"
                ),
            });
        }
        (nh_len, nh_bytes)
    };
    let mut link_local_next_hop = None;
    let next_hop = match ip_len {
        4 => IpAddr::V4(Ipv4Addr::new(
            ip_bytes[0],
            ip_bytes[1],
            ip_bytes[2],
            ip_bytes[3],
        )),
        16 | 32 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&ip_bytes[..16]);
            if ip_len == 32 {
                let mut ll = [0_u8; 16];
                ll.copy_from_slice(&ip_bytes[16..32]);
                link_local_next_hop = Some(Ipv6Addr::from(ll));
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => unreachable!("BGP-LS next-hop length validated above"),
    };
    Ok((next_hop, link_local_next_hop))
}
fn encode_bgpls_mp_next_hop(mp: &MpReachNlri, buf: &mut Vec<u8>) {
    let mut next_hop = Vec::new();
    if mp.safi == Safi::BgpLsVpn {
        next_hop.extend_from_slice(&[0_u8; crate::bgpls::BGP_LS_ROUTE_DISTINGUISHER_LEN]);
    }
    match (mp.next_hop, mp.link_local_next_hop) {
        (IpAddr::V4(addr), _) => next_hop.extend_from_slice(&addr.octets()),
        (IpAddr::V6(addr), Some(ll)) => {
            debug_assert!(
                (ll.segments()[0] & 0xffc0) == 0xfe80,
                "MP_REACH BGP-LS NH-Len=32 second segment must be link-local (fe80::/10), got {ll}"
            );
            next_hop.extend_from_slice(&addr.octets());
            next_hop.extend_from_slice(&ll.octets());
        }
        (IpAddr::V6(addr), None) => next_hop.extend_from_slice(&addr.octets()),
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "BGP-LS next-hop encoding is bounded to 4/16/32 bytes plus optional 8-byte RD"
    )]
    let nh_len = next_hop.len() as u8;
    buf.push(nh_len);
    buf.extend_from_slice(&next_hop);
}
/// Decode an RFC 4364 §4.3.2 / RFC 4659 §3.2.1.1 VPN next-hop.
///
/// Every form is prefixed with an 8-octet zero Route Distinguisher:
/// 12 = RD + IPv4, 24 = RD + IPv6 global, 48 = RD + IPv6 global followed by a
/// second RD + IPv6 link-local (RFC 4659 encodes the link-local with its own
/// zero RD, unlike BGP-LS VPN's bare 40-byte form).
fn decode_vpn_mp_next_hop(
    nh_bytes: &[u8],
    nh_len: usize,
) -> Result<(IpAddr, Option<Ipv6Addr>), DecodeError> {
    const RD_LEN: usize = crate::vpn::ROUTE_DISTINGUISHER_LEN;
    if nh_len != 12 && nh_len != 24 && nh_len != 48 {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!("MP_REACH_NLRI VPN next-hop length {nh_len} (expected 12, 24, or 48)"),
        });
    }
    let rd_offsets: &[usize] = if nh_len == 48 { &[0, 24] } else { &[0] };
    for &off in rd_offsets {
        if nh_bytes[off..off + RD_LEN].iter().any(|byte| *byte != 0) {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: "MP_REACH_NLRI VPN next-hop RD must be all zero".to_string(),
            });
        }
    }
    let ip_bytes = &nh_bytes[RD_LEN..];
    match nh_len {
        12 => Ok((
            IpAddr::V4(Ipv4Addr::new(
                ip_bytes[0],
                ip_bytes[1],
                ip_bytes[2],
                ip_bytes[3],
            )),
            None,
        )),
        24 | 48 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&ip_bytes[..16]);
            let link_local = if nh_len == 48 {
                let mut ll = [0_u8; 16];
                ll.copy_from_slice(&nh_bytes[24 + RD_LEN..48]);
                Some(Ipv6Addr::from(ll))
            } else {
                None
            };
            Ok((IpAddr::V6(Ipv6Addr::from(octets)), link_local))
        }
        _ => unreachable!("VPN next-hop length validated above"),
    }
}
fn encode_vpn_mp_next_hop(mp: &MpReachNlri, buf: &mut Vec<u8>) {
    const ZERO_RD: [u8; crate::vpn::ROUTE_DISTINGUISHER_LEN] =
        [0; crate::vpn::ROUTE_DISTINGUISHER_LEN];
    let mut next_hop = Vec::new();
    next_hop.extend_from_slice(&ZERO_RD);
    match (mp.next_hop, mp.link_local_next_hop) {
        (IpAddr::V4(addr), _) => next_hop.extend_from_slice(&addr.octets()),
        (IpAddr::V6(addr), Some(ll)) => {
            debug_assert!(
                (ll.segments()[0] & 0xffc0) == 0xfe80,
                "MP_REACH VPN 48-byte next-hop second address must be link-local (fe80::/10), got {ll}"
            );
            next_hop.extend_from_slice(&addr.octets());
            next_hop.extend_from_slice(&ZERO_RD);
            next_hop.extend_from_slice(&ll.octets());
        }
        (IpAddr::V6(addr), None) => next_hop.extend_from_slice(&addr.octets()),
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "VPN next-hop encoding is bounded to 12/24/48 bytes"
    )]
    let nh_len = next_hop.len() as u8;
    buf.push(nh_len);
    buf.extend_from_slice(&next_hop);
}
/// Encode path attributes to wire bytes.
///
/// `four_octet_as` controls whether AS numbers in `AS_PATH` are 2 or 4 bytes.
///
/// When `add_path_mp` is true, `MP_REACH_NLRI` and `MP_UNREACH_NLRI` NLRI
/// entries include 4-byte path IDs per RFC 7911.
///
/// # Errors
///
/// Returns [`EncodeError`] when a structured MP payload cannot be represented
/// on the wire, such as an oversized `FlowSpec` rule or BGP-LS NLRI/TLV.
#[expect(
    clippy::too_many_lines,
    reason = "dispatch arms are inherently O(variants); each new path attribute adds a small block"
)]
pub fn encode_path_attributes(
    attrs: &[PathAttribute],
    buf: &mut Vec<u8>,
    four_octet_as: bool,
    add_path_mp: bool,
) -> Result<(), EncodeError> {
    for attr in attrs {
        if matches!(
            attr,
            PathAttribute::Unknown(raw)
                if matches!(raw.type_code, attr_type::AS4_PATH | attr_type::AS4_AGGREGATOR)
        ) {
            // Compatibility sidecars are derived from canonical attributes;
            // never reflect stale received copies.
            continue;
        }
        let mut value = Vec::new();
        let mut compatibility = None;
        let flags;
        let type_code;
        match attr {
            PathAttribute::Origin(origin) => {
                flags = attr_flags::TRANSITIVE;
                type_code = attr_type::ORIGIN;
                value.push(*origin as u8);
            }
            PathAttribute::AsPath(as_path) => {
                if as_path
                    .segments
                    .iter()
                    .any(|segment| matches!(segment, AsPathSegment::AsSet(_)))
                {
                    return Err(EncodeError::ValueOutOfRange {
                        field: "AS_PATH",
                        value: "AS_SET cannot be projected under RFC 9774".to_string(),
                    });
                }
                flags = attr_flags::TRANSITIVE;
                type_code = attr_type::AS_PATH;
                encode_as_path(as_path, &mut value, four_octet_as);
                if !four_octet_as && as_path.asns().any(|asn| asn > u32::from(u16::MAX)) {
                    let mut as4_path = Vec::new();
                    encode_as_path(as_path, &mut as4_path, true);
                    compatibility = Some((
                        attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                        attr_type::AS4_PATH,
                        as4_path,
                    ));
                }
            }
            PathAttribute::Aggregator(aggregator) => {
                flags = attr_flags::OPTIONAL
                    | attr_flags::TRANSITIVE
                    | if aggregator.partial {
                        attr_flags::PARTIAL
                    } else {
                        0
                    };
                type_code = attr_type::AGGREGATOR;
                if four_octet_as {
                    value.extend_from_slice(&aggregator.asn.to_be_bytes());
                } else {
                    let asn = u16::try_from(aggregator.asn).unwrap_or(crate::constants::AS_TRANS);
                    value.extend_from_slice(&asn.to_be_bytes());
                    if aggregator.asn > u32::from(u16::MAX) {
                        let mut as4_aggregator = Vec::with_capacity(8);
                        as4_aggregator.extend_from_slice(&aggregator.asn.to_be_bytes());
                        as4_aggregator.extend_from_slice(&aggregator.router_id.octets());
                        compatibility = Some((flags, attr_type::AS4_AGGREGATOR, as4_aggregator));
                    }
                }
                value.extend_from_slice(&aggregator.router_id.octets());
            }
            PathAttribute::NextHop(addr) => {
                flags = attr_flags::TRANSITIVE;
                type_code = attr_type::NEXT_HOP;
                value.extend_from_slice(&addr.octets());
            }
            PathAttribute::Med(med) => {
                flags = attr_flags::OPTIONAL;
                type_code = attr_type::MULTI_EXIT_DISC;
                value.extend_from_slice(&med.to_be_bytes());
            }
            PathAttribute::LocalPref(lp) => {
                flags = attr_flags::TRANSITIVE;
                type_code = attr_type::LOCAL_PREF;
                value.extend_from_slice(&lp.to_be_bytes());
            }
            PathAttribute::Communities(communities) => {
                flags = attr_flags::OPTIONAL | attr_flags::TRANSITIVE;
                type_code = attr_type::COMMUNITIES;
                for &c in communities {
                    value.extend_from_slice(&c.to_be_bytes());
                }
            }
            PathAttribute::ExtendedCommunities(communities) => {
                flags = attr_flags::OPTIONAL | attr_flags::TRANSITIVE;
                type_code = attr_type::EXTENDED_COMMUNITIES;
                for &c in communities {
                    value.extend_from_slice(&c.as_u64().to_be_bytes());
                }
            }
            PathAttribute::LargeCommunities(communities) => {
                flags = attr_flags::OPTIONAL | attr_flags::TRANSITIVE;
                type_code = attr_type::LARGE_COMMUNITIES;
                let mut seen = std::collections::HashSet::with_capacity(communities.len());
                for &c in communities {
                    if !seen.insert(c) {
                        continue;
                    }
                    value.extend_from_slice(&c.global_admin.to_be_bytes());
                    value.extend_from_slice(&c.local_data1.to_be_bytes());
                    value.extend_from_slice(&c.local_data2.to_be_bytes());
                }
            }
            PathAttribute::OriginatorId(addr) => {
                flags = attr_flags::OPTIONAL;
                type_code = attr_type::ORIGINATOR_ID;
                value.extend_from_slice(&addr.octets());
            }
            PathAttribute::ClusterList(ids) => {
                flags = attr_flags::OPTIONAL;
                type_code = attr_type::CLUSTER_LIST;
                for id in ids {
                    value.extend_from_slice(&id.octets());
                }
            }
            PathAttribute::MpReachNlri(mp) => {
                flags = attr_flags::OPTIONAL;
                type_code = attr_type::MP_REACH_NLRI;
                encode_mp_reach_nlri(mp, &mut value, add_path_mp)?;
            }
            PathAttribute::MpUnreachNlri(mp) => {
                flags = attr_flags::OPTIONAL;
                type_code = attr_type::MP_UNREACH_NLRI;
                encode_mp_unreach_nlri(mp, &mut value, add_path_mp)?;
            }
            PathAttribute::PmsiTunnel(pmsi) => {
                // RFC 6514 §5: Optional + Transitive.
                (flags, type_code) = (
                    attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                    attr_type::PMSI_TUNNEL,
                );
                pmsi.encode(&mut value);
            }
            PathAttribute::OnlyToCustomer(asn) => {
                // RFC 9234 §5: Optional + Transitive, length 4, 32-bit ASN.
                // This typed variant is only used for locally constructed
                // canonical OTC. Received Partial-bearing OTC stays in the
                // `Unknown` arm so the original Partial bit is preserved.
                flags = attr_flags::OPTIONAL | attr_flags::TRANSITIVE;
                type_code = attr_type::ONLY_TO_CUSTOMER;
                value.extend_from_slice(&asn.to_be_bytes());
            }
            PathAttribute::Unknown(raw) => {
                // RFC 4271 §5: unrecognized *optional* transitive attributes
                // must be propagated with the Partial bit set. Well-known
                // transitive attributes (OPTIONAL=0) must NOT get PARTIAL.
                let optional_transitive = attr_flags::OPTIONAL | attr_flags::TRANSITIVE;
                flags = if (raw.flags & optional_transitive) == optional_transitive {
                    raw.flags | attr_flags::PARTIAL
                } else {
                    raw.flags
                };
                type_code = raw.type_code;
                value.extend_from_slice(&raw.data);
            }
        }
        encode_attribute_triplet(flags, type_code, &value, buf);
        if let Some((compat_flags, compat_type, compat_value)) = compatibility {
            encode_attribute_triplet(compat_flags, compat_type, &compat_value, buf);
        }
    }
    Ok(())
}

fn encode_attribute_triplet(flags: u8, type_code: u8, value: &[u8], buf: &mut Vec<u8>) {
    // Preserve an explicitly received Extended Length encoding on opaque
    // attributes even when the value would fit in one octet. Otherwise
    // Unknown reflection would retain the flag but emit a one-octet length,
    // corrupting the attribute boundary.
    if value.len() > 255 || (flags & attr_flags::EXTENDED_LENGTH) != 0 {
        buf.push(flags | attr_flags::EXTENDED_LENGTH);
        buf.push(type_code);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "codec bounds or masks the value before narrowing to the protocol field width"
        )]
        let len = value.len() as u16;
        buf.extend_from_slice(&len.to_be_bytes());
    } else {
        buf.push(flags);
        buf.push(type_code);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "codec bounds or masks the value before narrowing to the protocol field width"
        )]
        buf.push(value.len() as u8);
    }
    buf.extend_from_slice(value);
}
/// Encode `MP_REACH_NLRI` value bytes.
///
/// When `add_path` is true, each NLRI entry includes a 4-byte path ID
/// prefix per RFC 7911.
fn encode_mp_reach_nlri(
    mp: &MpReachNlri,
    buf: &mut Vec<u8>,
    add_path: bool,
) -> Result<(), EncodeError> {
    buf.extend_from_slice(&(mp.afi as u16).to_be_bytes());
    buf.push(mp.safi as u8);
    // FlowSpec: NH length = 0, reserved = 0, then FlowSpec NLRI
    if mp.safi == Safi::FlowSpec {
        buf.push(0); // NH-Len = 0
        buf.push(0); // Reserved
        crate::flowspec::try_encode_flowspec_nlri(&mp.flowspec_announced, buf, mp.afi)?;
        return Ok(());
    }
    // EVPN: next-hop is the VTEP loopback IP (4 or 16 bytes), then EVPN NLRI
    if mp.afi == Afi::L2Vpn && mp.safi == Safi::Evpn {
        match mp.next_hop {
            IpAddr::V4(addr) => {
                buf.push(4);
                buf.extend_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                buf.push(16);
                buf.extend_from_slice(&addr.octets());
            }
        }
        buf.push(0); // Reserved
        crate::evpn::encode_evpn_nlri(&mp.evpn_announced, buf);
        return Ok(());
    }
    if mp.afi == Afi::BgpLs && matches!(mp.safi, Safi::BgpLs | Safi::BgpLsVpn) {
        encode_bgpls_mp_next_hop(mp, buf);
        buf.push(0); // Reserved
        crate::bgpls::encode_bgpls_nlri(&mp.bgpls_announced, buf)?;
        return Ok(());
    }
    if mp.safi == Safi::MplsVpn {
        encode_vpn_mp_next_hop(mp, buf);
        buf.push(0); // Reserved
        let family = if mp.afi == Afi::Ipv4 {
            crate::vpn::VpnAddressFamily::V4
        } else {
            crate::vpn::VpnAddressFamily::V6
        };
        if add_path {
            crate::vpn::encode_vpn_nlri_addpath(&mp.vpn_announced, family, buf)?;
        } else {
            for entry in &mp.vpn_announced {
                crate::vpn::encode_vpn_nlri(std::slice::from_ref(&entry.nlri), family, buf)?;
            }
        }
        return Ok(());
    }
    // Labeled-unicast (SAFI 4): ordinary host next-hop (RFC 8277 has no
    // RD-prefixed form), then RFC 8277 announce-mode NLRI.
    if mp.safi == Safi::LabeledUnicast {
        encode_plain_mp_next_hop(mp, buf);
        buf.push(0); // Reserved
        let family = if mp.afi == Afi::Ipv4 {
            crate::labeled::LabeledAddressFamily::V4
        } else {
            crate::labeled::LabeledAddressFamily::V6
        };
        if add_path {
            crate::labeled::encode_labeled_nlri_addpath(&mp.labeled_announced, family, buf)?;
        } else {
            for entry in &mp.labeled_announced {
                crate::labeled::encode_labeled_nlri(
                    std::slice::from_ref(&entry.nlri),
                    family,
                    buf,
                )?;
            }
        }
        return Ok(());
    }
    // RTC (SAFI 132): ordinary host next-hop (same forms as unicast),
    // then RT-Constrain NLRI.
    if mp.safi == Safi::RtConstrain {
        encode_plain_mp_next_hop(mp, buf);
        buf.push(0); // Reserved
        crate::rtc::encode_rtc_nlri(&mp.rtc_announced, buf)?;
        return Ok(());
    }
    encode_plain_mp_next_hop(mp, buf);
    buf.push(0); // Reserved
    if add_path {
        crate::nlri::encode_ipv6_nlri_addpath(&mp.announced, buf);
    } else {
        for entry in &mp.announced {
            match entry.prefix {
                Prefix::V4(p) => crate::nlri::encode_nlri(&[p], buf),
                Prefix::V6(p) => crate::nlri::encode_ipv6_nlri(&[p], buf),
            }
        }
    }
    Ok(())
}
/// Encode the plain (non-RD) 4/16/32-byte MP next-hop shared by unicast
/// and RT-Constrain.
fn encode_plain_mp_next_hop(mp: &MpReachNlri, buf: &mut Vec<u8>) {
    match (mp.next_hop, mp.link_local_next_hop) {
        (IpAddr::V4(addr), _) => {
            buf.push(4); // NH-Len
            buf.extend_from_slice(&addr.octets());
        }
        (IpAddr::V6(addr), Some(ll)) => {
            // Symmetric to inbound validation: a NH-Len=32 form
            // requires the second 16 bytes to be in fe80::/10. No
            // live outbound construction site sets a non-LL value
            // (every `MpReachNlri { link_local_next_hop: ..., .. }`
            // in the daemon either passes `None` or a peer-validated
            // LL), so this is a defense-in-depth catch for future
            // code paths (MRT replay, RR reflection of corrupt
            // upstream input, etc.). Emitting a malformed 32-byte
            // form would tear sessions against any RFC-compliant
            // peer's validator (FRR, GoBGP) — exactly the inverse
            // of the v0.12.1 inbound bug.
            debug_assert!(
                (ll.segments()[0] & 0xffc0) == 0xfe80,
                "MP_REACH NH-Len=32 second segment must be link-local (fe80::/10), got {ll}"
            );
            buf.push(32); // NH-Len: global + link-local
            buf.extend_from_slice(&addr.octets());
            buf.extend_from_slice(&ll.octets());
        }
        (IpAddr::V6(addr), None) => {
            buf.push(16); // NH-Len
            buf.extend_from_slice(&addr.octets());
        }
    }
}
/// Encode `MP_UNREACH_NLRI` value bytes.
///
/// When `add_path` is true, each withdrawn entry includes a 4-byte path ID.
fn encode_mp_unreach_nlri(
    mp: &MpUnreachNlri,
    buf: &mut Vec<u8>,
    add_path: bool,
) -> Result<(), EncodeError> {
    buf.extend_from_slice(&(mp.afi as u16).to_be_bytes());
    buf.push(mp.safi as u8);
    // FlowSpec: encode FlowSpec NLRI rules
    if mp.safi == Safi::FlowSpec {
        crate::flowspec::try_encode_flowspec_nlri(&mp.flowspec_withdrawn, buf, mp.afi)?;
        return Ok(());
    }
    // EVPN: encode EVPN NLRI routes
    if mp.afi == Afi::L2Vpn && mp.safi == Safi::Evpn {
        crate::evpn::encode_evpn_nlri(&mp.evpn_withdrawn, buf);
        return Ok(());
    }
    if mp.afi == Afi::BgpLs && matches!(mp.safi, Safi::BgpLs | Safi::BgpLsVpn) {
        crate::bgpls::encode_bgpls_nlri(&mp.bgpls_withdrawn, buf)?;
        return Ok(());
    }
    if mp.safi == Safi::MplsVpn {
        let family = if mp.afi == Afi::Ipv4 {
            crate::vpn::VpnAddressFamily::V4
        } else {
            crate::vpn::VpnAddressFamily::V6
        };
        // RFC 8277 §2.4: withdraws carry the 3-octet compatibility value
        // 0x800000 in the label position, never a real label stack. Under
        // Add-Path the 4-octet path ID is prepended to each entry.
        if add_path {
            crate::vpn::encode_vpn_withdraw_nlri_addpath(&mp.vpn_withdrawn, family, buf)?;
        } else {
            for entry in &mp.vpn_withdrawn {
                crate::vpn::encode_vpn_withdraw_nlri(
                    std::slice::from_ref(&entry.nlri),
                    family,
                    buf,
                )?;
            }
        }
        return Ok(());
    }
    // Labeled-unicast (SAFI 4): RFC 8277 §2.4 withdraws carry the 3-octet
    // compatibility value 0x800000 in the label position, never a real
    // label stack. Under Add-Path the 4-octet path ID is prepended.
    if mp.safi == Safi::LabeledUnicast {
        let family = if mp.afi == Afi::Ipv4 {
            crate::labeled::LabeledAddressFamily::V4
        } else {
            crate::labeled::LabeledAddressFamily::V6
        };
        if add_path {
            crate::labeled::encode_labeled_withdraw_nlri_addpath(
                &mp.labeled_withdrawn,
                family,
                buf,
            )?;
        } else {
            for entry in &mp.labeled_withdrawn {
                crate::labeled::encode_labeled_withdraw_nlri(
                    std::slice::from_ref(&entry.nlri),
                    family,
                    buf,
                )?;
            }
        }
        return Ok(());
    }
    // RTC (SAFI 132): one codec for both directions (no withdraw split).
    if mp.safi == Safi::RtConstrain {
        crate::rtc::encode_rtc_nlri(&mp.rtc_withdrawn, buf)?;
        return Ok(());
    }
    if add_path {
        crate::nlri::encode_ipv6_nlri_addpath(&mp.withdrawn, buf);
    } else {
        for entry in &mp.withdrawn {
            match entry.prefix {
                Prefix::V4(p) => crate::nlri::encode_nlri(&[p], buf),
                Prefix::V6(p) => crate::nlri::encode_ipv6_nlri(&[p], buf),
            }
        }
    }
    Ok(())
}
/// Encode `AS_PATH` segments into value bytes.
fn encode_as_path(as_path: &AsPath, buf: &mut Vec<u8>, four_octet_as: bool) {
    for segment in &as_path.segments {
        let (seg_type, asns) = match segment {
            AsPathSegment::AsSet(asns) => (as_path_segment::AS_SET, asns),
            AsPathSegment::AsSequence(asns) => (as_path_segment::AS_SEQUENCE, asns),
        };
        for chunk in asns.chunks(u8::MAX as usize) {
            buf.push(seg_type);
            #[expect(
                clippy::cast_possible_truncation,
                reason = "codec bounds or masks the value before narrowing to the protocol field width"
            )]
            buf.push(chunk.len() as u8);
            for &asn in chunk {
                if four_octet_as {
                    buf.extend_from_slice(&asn.to_be_bytes());
                } else {
                    // RFC 6793: ASNs > 65535 are mapped to AS_TRANS (23456)
                    // in 2-octet AS_PATH encoding.
                    let as2 = u16::try_from(asn).unwrap_or(crate::constants::AS_TRANS);
                    buf.extend_from_slice(&as2.to_be_bytes());
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn oversized_flowspec_rule() -> crate::flowspec::FlowSpecRule {
        use crate::flowspec::{FlowSpecComponent, FlowSpecRule, NumericMatch};
        let mut ops: Vec<NumericMatch> = (0..2_200)
            .map(|i| NumericMatch {
                end_of_list: false,
                and_bit: i != 0,
                lt: false,
                gt: false,
                eq: true,
                value: i,
            })
            .collect();
        ops.last_mut().expect("non-empty test rule").end_of_list = true;
        FlowSpecRule {
            components: vec![FlowSpecComponent::Port(ops)],
        }
    }
    #[test]
    fn mp_reach_evpn_attribute_roundtrip() {
        use crate::evpn::{EthernetTagId, EvpnImet, EvpnRoute, RouteDistinguisher};
        let mp = MpReachNlri {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![EvpnRoute::Imet(EvpnImet {
                rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 0x64]),
                ethernet_tag: EthernetTagId(100),
                originator_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)),
            })],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        };
        let attr = PathAttribute::MpReachNlri(mp);
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).expect("decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(attr, decoded[0]);
        let PathAttribute::MpReachNlri(dec) = &decoded[0] else {
            panic!("not MP_REACH after decode");
        };
        assert_eq!(dec.afi, Afi::L2Vpn);
        assert_eq!(dec.safi, Safi::Evpn);
        assert_eq!(dec.evpn_announced.len(), 1);
        assert!(matches!(dec.evpn_announced[0], EvpnRoute::Imet(_)));
    }
    /// EVPN `MP_REACH` with an IPv6 VTEP next-hop. RFC 7432 §7.5
    /// allows the egress PE address to be IPv4 *or* IPv6; the
    /// IPv4 path was covered by `mp_reach_evpn_attribute_roundtrip`,
    /// the IPv6 path was the one validate-side audit gap. EVPN
    /// (AFI 25 / SAFI 70) uses a 16-byte single-address next-hop
    /// for IPv6 — there is no global+link-local 32-byte form here
    /// (that's RFC 2545 / unicast territory). Pinning it as a
    /// roundtrip catches any future regression in the EVPN-specific
    /// branch of `encode_mp_reach_nlri`, which is otherwise only
    /// exercised on the IPv4 path.
    #[test]
    fn mp_reach_evpn_ipv6_next_hop_roundtrip() {
        use crate::evpn::{EthernetTagId, EvpnImet, EvpnRoute, RouteDistinguisher};
        let vtep_v6: Ipv6Addr = "2001:db8:dead::1".parse().unwrap();
        let mp = MpReachNlri {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            next_hop: IpAddr::V6(vtep_v6),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![EvpnRoute::Imet(EvpnImet {
                rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 0x64]),
                ethernet_tag: EthernetTagId(100),
                originator_ip: IpAddr::V6(vtep_v6),
            })],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        };
        let attr = PathAttribute::MpReachNlri(mp.clone());
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false).unwrap();
        // Wire-level shape check: NH-Len byte is 16 (16-byte single
        // IPv6 address; EVPN does NOT use the 32-byte global+LL form),
        // followed by the 16 octets of vtep_v6, then Reserved=0,
        // then EVPN NLRI.
        // Value layout from `encode_mp_reach_nlri`: AFI(2) + SAFI(1)
        // + NH-Len(1) + NH bytes + Reserved(1) + NLRI.
        // Walk past the attribute header (flags(1) + type(1) + len
        // octet(s)) to land on the value. With a single IMET route
        // the value comfortably fits a single-byte length so the
        // header is 3 bytes total.
        let extended = (buf[0] & 0x10) != 0;
        let value_off = if extended { 4 } else { 3 };
        assert_eq!(
            buf[value_off + 3],
            16,
            "EVPN IPv6 NH-Len must be 16, not 32"
        );
        assert_eq!(
            &buf[value_off + 4..value_off + 20],
            &vtep_v6.octets(),
            "encoded VTEP next-hop bytes must match the input"
        );
        let decoded = decode_path_attributes(&buf, true, &[]).expect("decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(PathAttribute::MpReachNlri(mp), decoded[0]);
        let PathAttribute::MpReachNlri(dec) = &decoded[0] else {
            panic!("not MP_REACH after decode");
        };
        assert_eq!(dec.afi, Afi::L2Vpn);
        assert_eq!(dec.safi, Safi::Evpn);
        assert_eq!(dec.next_hop, IpAddr::V6(vtep_v6));
        assert!(
            dec.link_local_next_hop.is_none(),
            "EVPN's 16-byte form must not synthesize a link-local next-hop"
        );
        assert_eq!(dec.evpn_announced.len(), 1);
        match &dec.evpn_announced[0] {
            EvpnRoute::Imet(imet) => {
                assert_eq!(imet.originator_ip, IpAddr::V6(vtep_v6));
                assert_eq!(imet.ethernet_tag, EthernetTagId(100));
            }
            other => panic!("expected IMET, got {other:?}"),
        }
    }
    /// EVPN (AFI 25 / SAFI 70) must reject the 32-byte global+
    /// link-local next-hop form. RFC 7432 §7.5 only permits a
    /// single IPv4 (4 bytes) or IPv6 (16 bytes) next-hop; the
    /// 32-byte form is RFC 2545 unicast-only territory. Pinning
    /// the rejection invariant catches a future regression that
    /// might broaden the L2VPN decoder by mistake.
    #[test]
    fn mp_reach_evpn_rejects_32byte_next_hop() {
        // Hand-crafted MP_REACH attribute: AFI=25 (L2VPN), SAFI=70
        // (EVPN), NH-Len=32 (illegal for EVPN), 32 bytes of
        // next-hop, Reserved=0, then zero bytes of NLRI.
        // Attribute header: flags=0x80 (optional non-transitive),
        // type=14 (MP_REACH), length=u8 = 4 + 32 + 1 = 37.
        let mut attr = vec![0x80u8, 14, 37];
        attr.extend_from_slice(&[
            0x00, 0x19, // AFI = 25 (L2VPN)
            0x46, // SAFI = 70 (EVPN)
            0x20, // NH-Len = 32 (illegal for L2VPN)
        ]);
        attr.extend(std::iter::repeat_n(0u8, 32)); // 32 NH bytes
        attr.push(0); // Reserved
        let err = decode_path_attributes(&attr, true, &[]).unwrap_err();
        match err {
            DecodeError::MalformedField { detail, .. } => {
                assert!(
                    detail.contains("L2VPN next-hop length 32"),
                    "expected L2VPN NH-Len rejection, got: {detail}"
                );
            }
            other => panic!("expected MalformedField, got: {other:?}"),
        }
    }
    #[test]
    fn mp_unreach_evpn_attribute_roundtrip() {
        use crate::evpn::{EthernetSegmentIdentifier, EvpnEs, EvpnRoute, RouteDistinguisher};
        let mp = MpUnreachNlri {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: vec![EvpnRoute::Es(EvpnEs {
                rd: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 0x64]),
                esi: EthernetSegmentIdentifier([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
                originator_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            })],
            bgpls_withdrawn: vec![],
            labeled_withdrawn: vec![],
            vpn_withdrawn: vec![],
            rtc_withdrawn: vec![],
        };
        let attr = PathAttribute::MpUnreachNlri(mp);
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).expect("decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(attr, decoded[0]);
    }
    fn bgpls_test_payload() -> bytes::Bytes {
        bytes::Bytes::from_static(&[
            2, // IS-IS Level 2 protocol-id.
            0, 0, 0, 0, 0, 0, 0, 42, // Identifier.
            0, 1, 0, 1, 0xaa, // One descriptor TLV.
        ])
    }
    fn bgpls_node(route_distinguisher: Option<[u8; 8]>) -> crate::bgpls::BgpLsNlri {
        crate::bgpls::BgpLsNlri::try_new(
            crate::bgpls::BgpLsNlriType::Node,
            route_distinguisher,
            bgpls_test_payload(),
        )
        .expect("test BGP-LS NLRI encodes")
    }
    #[test]
    fn mp_reach_bgpls_attribute_roundtrip() {
        let route = bgpls_node(None);
        let mp = MpReachNlri {
            afi: Afi::BgpLs,
            safi: Safi::BgpLs,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![route.clone()],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        };
        let attr = PathAttribute::MpReachNlri(mp.clone());
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).expect("decode BGP-LS MP_REACH");
        assert_eq!(decoded, vec![PathAttribute::MpReachNlri(mp)]);
        let PathAttribute::MpReachNlri(decoded_mp) = &decoded[0] else {
            panic!("not MP_REACH after decode");
        };
        assert_eq!(decoded_mp.bgpls_announced, vec![route]);
        assert!(decoded_mp.announced.is_empty());
        assert!(decoded_mp.flowspec_announced.is_empty());
        assert!(decoded_mp.evpn_announced.is_empty());
    }
    #[test]
    fn mp_unreach_bgpls_vpn_attribute_roundtrip() {
        let rd = [0, 0, 0xfd, 0xe8, 0, 0, 0, 42];
        let route = bgpls_node(Some(rd));
        let mp = MpUnreachNlri {
            afi: Afi::BgpLs,
            safi: Safi::BgpLsVpn,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: vec![],
            bgpls_withdrawn: vec![route.clone()],
            labeled_withdrawn: vec![],
            vpn_withdrawn: vec![],
            rtc_withdrawn: vec![],
        };
        let attr = PathAttribute::MpUnreachNlri(mp.clone());
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false).unwrap();
        let decoded =
            decode_path_attributes(&buf, true, &[]).expect("decode BGP-LS VPN MP_UNREACH");
        assert_eq!(decoded, vec![PathAttribute::MpUnreachNlri(mp)]);
        let PathAttribute::MpUnreachNlri(decoded_mp) = &decoded[0] else {
            panic!("not MP_UNREACH after decode");
        };
        assert_eq!(decoded_mp.bgpls_withdrawn, vec![route]);
        assert!(decoded_mp.withdrawn.is_empty());
        assert!(decoded_mp.flowspec_withdrawn.is_empty());
        assert!(decoded_mp.evpn_withdrawn.is_empty());
    }
    #[test]
    fn mp_reach_bgpls_addpath_rejected() {
        let route = bgpls_node(None);
        let attr = PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::BgpLs,
            safi: Safi::BgpLs,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![route],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        });
        let mut buf = Vec::new();
        encode_path_attributes(&[attr], &mut buf, true, false).unwrap();
        let err = decode_path_attributes(&buf, true, &[(Afi::BgpLs, Safi::BgpLs)])
            .expect_err("BGP-LS Add-Path must fail closed");
        match err {
            DecodeError::MalformedField { detail, .. } => {
                assert!(
                    detail.contains("BGP-LS Add-Path is not supported"),
                    "unexpected detail: {detail}"
                );
            }
            other => panic!("expected MalformedField, got: {other:?}"),
        }
    }
    #[test]
    fn mp_reach_bgpls_vpn_rejects_nonzero_next_hop_rd() {
        let route = bgpls_node(Some([0, 0, 0xfd, 0xe8, 0, 0, 0, 42]));
        let mut nlri = Vec::new();
        crate::bgpls::encode_bgpls_nlri(&[route], &mut nlri).expect("encode BGP-LS VPN NLRI");
        let mut value = Vec::new();
        value.extend_from_slice(&(Afi::BgpLs as u16).to_be_bytes());
        value.push(Safi::BgpLsVpn as u8);
        value.push(12);
        value.extend_from_slice(&[0, 0, 0xfd, 0xe8, 0, 0, 0, 42]);
        value.extend_from_slice(&[192, 0, 2, 1]);
        value.push(0);
        value.extend_from_slice(&nlri);
        let value_len =
            u8::try_from(value.len()).expect("fixture MP_REACH value length fits in one octet");
        let mut attr = vec![attr_flags::OPTIONAL, 14, value_len];
        attr.extend_from_slice(&value);
        let err = decode_path_attributes(&attr, true, &[])
            .expect_err("BGP-LS VPN next-hop RD must be all zero");
        match err {
            DecodeError::MalformedField { detail, .. } => {
                assert!(
                    detail.contains("next-hop RD must be all zero"),
                    "unexpected detail: {detail}"
                );
            }
            other => panic!("expected MalformedField, got: {other:?}"),
        }
    }
    fn vpn_rd() -> crate::evpn::RouteDistinguisher {
        crate::evpn::RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 1])
    }
    fn vpnv4_nlri(label: u32) -> crate::vpn::VpnNlri {
        crate::vpn::VpnNlri {
            labels: vec![crate::vpn::MplsLabelEntry::try_new(label, 0, true).unwrap()],
            route_distinguisher: vpn_rd(),
            prefix: crate::vpn::VpnPrefix::v4(Ipv4Addr::new(10, 1, 0, 0), 24).unwrap(),
        }
    }
    fn vpnv6_nlri(label: u32) -> crate::vpn::VpnNlri {
        crate::vpn::VpnNlri {
            labels: vec![crate::vpn::MplsLabelEntry::try_new(label, 0, true).unwrap()],
            route_distinguisher: vpn_rd(),
            prefix: crate::vpn::VpnPrefix::v6("2001:db8:100::".parse().unwrap(), 48).unwrap(),
        }
    }
    fn vpn_entry(path_id: u32, nlri: crate::vpn::VpnNlri) -> crate::vpn::VpnNlriEntry {
        crate::vpn::VpnNlriEntry { path_id, nlri }
    }
    fn labeled_nlri(label: u32) -> crate::labeled::LabeledNlri {
        crate::labeled::LabeledNlri {
            labels: vec![crate::vpn::MplsLabelEntry::try_new(label, 0, true).unwrap()],
            prefix: Prefix::V4(crate::nlri::Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24)),
        }
    }
    fn labeled_v6_nlri(label: u32) -> crate::labeled::LabeledNlri {
        crate::labeled::LabeledNlri {
            labels: vec![crate::vpn::MplsLabelEntry::try_new(label, 0, true).unwrap()],
            prefix: Prefix::V6(crate::nlri::Ipv6Prefix::new(
                "2001:db8:100::".parse().unwrap(),
                48,
            )),
        }
    }
    fn labeled_entry(
        path_id: u32,
        nlri: crate::labeled::LabeledNlri,
    ) -> crate::labeled::LabeledNlriEntry {
        crate::labeled::LabeledNlriEntry { path_id, nlri }
    }
    #[test]
    fn mp_reach_vpn_attribute_roundtrip() {
        let route = vpnv4_nlri(24_017);
        let mp = MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::MplsVpn,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![vpn_entry(0, route.clone())],
            rtc_announced: vec![],
        };
        let attr = PathAttribute::MpReachNlri(mp.clone());
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).expect("decode VPN MP_REACH");
        assert_eq!(decoded, vec![PathAttribute::MpReachNlri(mp)]);
        let PathAttribute::MpReachNlri(decoded_mp) = &decoded[0] else {
            panic!("not MP_REACH after decode");
        };
        assert_eq!(decoded_mp.next_hop, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(decoded_mp.vpn_announced, vec![vpn_entry(0, route)]);
        assert_eq!(decoded_mp.vpn_announced[0].nlri.labels[0].label, 24_017);
        assert_eq!(
            decoded_mp.vpn_announced[0].nlri.route_distinguisher,
            vpn_rd()
        );
        assert!(decoded_mp.announced.is_empty());
    }
    /// LAN-217: a `VPNv6` `MP_REACH` carrying an RFC 4659 §3.2.1.1 48-byte
    /// two-address next-hop (RD + global, RD + link-local) must emit the
    /// 48-byte form and round-trip the link-local half, so a route reflector
    /// re-advertising the route preserves `VPNv6` link-local forwarding.
    #[test]
    fn mp_reach_vpnv6_link_local_next_hop_roundtrip() {
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        let route = vpnv6_nlri(100);
        let mp = MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::MplsVpn,
            next_hop: IpAddr::V6(global),
            link_local_next_hop: Some(link_local),
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![vpn_entry(0, route.clone())],
            rtc_announced: vec![],
        };
        let attr = PathAttribute::MpReachNlri(mp.clone());
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false).unwrap();
        // Value layout after the 3-byte attribute header: AFI(2) SAFI(1)
        // NH-Len(1); NH-Len must be 48 (RD + global, RD + link-local), not 24.
        assert_eq!(buf[6], 48, "VPNv6 two-address next-hop must be 48 bytes");
        let decoded = decode_path_attributes(&buf, true, &[]).expect("decode VPNv6 MP_REACH");
        let PathAttribute::MpReachNlri(decoded_mp) = &decoded[0] else {
            panic!("not MP_REACH after decode");
        };
        assert_eq!(decoded_mp.next_hop, IpAddr::V6(global));
        assert_eq!(
            decoded_mp.link_local_next_hop,
            Some(link_local),
            "VPNv6 link-local next-hop must survive encode/decode"
        );
        assert_eq!(decoded, vec![PathAttribute::MpReachNlri(mp)]);
    }
    #[test]
    fn mp_unreach_vpnv6_attribute_roundtrip() {
        // RFC 8277 §2.4: a withdrawn VPN NLRI carries a 3-octet compatibility
        // field (0x800000 on transmission, ignored on receipt), not a label
        // stack. Withdraw entries therefore carry no labels.
        let mut route = vpnv6_nlri(0);
        route.labels = vec![];
        let mp = MpUnreachNlri {
            afi: Afi::Ipv6,
            safi: Safi::MplsVpn,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: vec![],
            bgpls_withdrawn: vec![],
            labeled_withdrawn: vec![],
            vpn_withdrawn: vec![vpn_entry(0, route.clone())],
            rtc_withdrawn: vec![],
        };
        let attr = PathAttribute::MpUnreachNlri(mp.clone());
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false).unwrap();
        // Wire layout: flags, type=15, len, AFI(2), SAFI(1), then the NLRI —
        // whose label position must be the 0x800000 compatibility value.
        assert_eq!(&buf[6], &(24 + 64 + 48), "NLRI bit length");
        assert_eq!(&buf[7..10], &[0x80, 0x00, 0x00], "compatibility field");
        let decoded = decode_path_attributes(&buf, true, &[]).expect("decode VPNv6 MP_UNREACH");
        assert_eq!(decoded, vec![PathAttribute::MpUnreachNlri(mp)]);
        let PathAttribute::MpUnreachNlri(decoded_mp) = &decoded[0] else {
            panic!("not MP_UNREACH after decode");
        };
        assert_eq!(decoded_mp.vpn_withdrawn, vec![vpn_entry(0, route)]);
        assert!(decoded_mp.vpn_withdrawn[0].nlri.labels.is_empty());
    }
    #[test]
    fn mp_unreach_vpn_withdraw_ignores_label_position_value() {
        // Receivers MUST ignore the compatibility field's value entirely
        // (RFC 8277 §2.4) — some implementations echo the announced label
        // (with a real BOS bit) instead of 0x800000. Announce-mode label
        // parsing would mis-parse this; withdraw-mode must accept it.
        let mut value = Vec::new();
        value.extend_from_slice(&(Afi::Ipv4 as u16).to_be_bytes());
        value.push(Safi::MplsVpn as u8);
        value.push(24 + 64 + 24); // NLRI bit length
        // Label 100, TC 0, S=1 — a real label entry, not 0x800000.
        value.extend_from_slice(&[0x00, 0x06, 0x41]);
        value.extend_from_slice(&vpn_rd().0);
        value.extend_from_slice(&[10, 1, 0]); // 10.1.0.0/24
        let value_len = u8::try_from(value.len()).unwrap();
        let mut attr = vec![attr_flags::OPTIONAL, 15, value_len];
        attr.extend_from_slice(&value);
        let decoded =
            decode_path_attributes(&attr, true, &[]).expect("withdraw with echoed label decodes");
        let PathAttribute::MpUnreachNlri(mp) = &decoded[0] else {
            panic!("not MP_UNREACH after decode");
        };
        assert_eq!(mp.vpn_withdrawn.len(), 1);
        assert_eq!(mp.vpn_withdrawn[0].nlri.route_distinguisher, vpn_rd());
        assert_eq!(mp.vpn_withdrawn[0].nlri.prefix.to_string(), "10.1.0.0/24");
        assert!(mp.vpn_withdrawn[0].nlri.labels.is_empty());
    }
    #[test]
    fn mp_reach_vpn_addpath_roundtrip() {
        // RFC 7911 for SAFI 128: each NLRI carries a 4-octet path ID when
        // the family is in the negotiated Add-Path set — both encode and
        // decode dispatch on `add_path_families` / `add_path_mp`.
        let mp = MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::MplsVpn,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![vpn_entry(1, vpnv4_nlri(100)), vpn_entry(2, vpnv4_nlri(200))],
            rtc_announced: vec![],
        };
        let attr = PathAttribute::MpReachNlri(mp.clone());
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, true).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[(Afi::Ipv4, Safi::MplsVpn)])
            .expect("decode VPN Add-Path MP_REACH");
        assert_eq!(decoded, vec![PathAttribute::MpReachNlri(mp)]);
    }
    #[test]
    fn mp_unreach_vpn_addpath_roundtrip() {
        // Withdraw-mode Add-Path: path_id(4) | len | compatibility field |
        // RD | prefix per entry (RFC 7911 + RFC 8277 §2.4).
        let mut route = vpnv6_nlri(0);
        route.labels = vec![];
        let mp = MpUnreachNlri {
            afi: Afi::Ipv6,
            safi: Safi::MplsVpn,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: vec![],
            bgpls_withdrawn: vec![],
            labeled_withdrawn: vec![],
            vpn_withdrawn: vec![vpn_entry(7, route)],
            rtc_withdrawn: vec![],
        };
        let attr = PathAttribute::MpUnreachNlri(mp.clone());
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, true).unwrap();
        // Wire layout: flags, type=15, len, AFI(2), SAFI(1), then path_id(4)
        // and the compatibility field in the label position.
        assert_eq!(&buf[6..10], &7u32.to_be_bytes(), "path_id");
        assert_eq!(&buf[11..14], &[0x80, 0x00, 0x00], "compatibility field");
        let decoded = decode_path_attributes(&buf, true, &[(Afi::Ipv6, Safi::MplsVpn)])
            .expect("decode VPN Add-Path MP_UNREACH");
        assert_eq!(decoded, vec![PathAttribute::MpUnreachNlri(mp)]);
    }
    #[test]
    fn mp_reach_vpn_rejects_nonzero_next_hop_rd() {
        let mut nlri = Vec::new();
        crate::vpn::encode_vpnv4_nlri(&[vpnv4_nlri(100)], &mut nlri).expect("encode VPN NLRI");
        let mut value = Vec::new();
        value.extend_from_slice(&(Afi::Ipv4 as u16).to_be_bytes());
        value.push(Safi::MplsVpn as u8);
        value.push(12); // NH-Len
        value.extend_from_slice(&[0, 0, 0xfd, 0xe8, 0, 0, 0, 1]); // non-zero RD
        value.extend_from_slice(&[192, 0, 2, 1]);
        value.push(0); // Reserved
        value.extend_from_slice(&nlri);
        let value_len = u8::try_from(value.len()).unwrap();
        let mut attr = vec![attr_flags::OPTIONAL, 14, value_len];
        attr.extend_from_slice(&value);
        let err =
            decode_path_attributes(&attr, true, &[]).expect_err("VPN next-hop RD must be all zero");
        match err {
            DecodeError::MalformedField { detail, .. } => {
                assert!(
                    detail.contains("next-hop RD must be all zero"),
                    "unexpected detail: {detail}"
                );
            }
            other => panic!("expected MalformedField, got: {other:?}"),
        }
    }
    #[test]
    fn mp_reach_vpnv6_48_byte_next_hop_roundtrip() {
        let route = vpnv6_nlri(16_000);
        let mp = MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::MplsVpn,
            next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
            link_local_next_hop: Some("fe80::1".parse().unwrap()),
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![vpn_entry(0, route)],
            rtc_announced: vec![],
        };
        let attr = PathAttribute::MpReachNlri(mp.clone());
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false).unwrap();
        // NH-Len must be 48: RD + global, RD + link-local.
        assert_eq!(buf[6], 48, "48-byte RD-prefixed dual next-hop");
        let decoded = decode_path_attributes(&buf, true, &[]).expect("decode 48-byte VPN NH");
        assert_eq!(decoded, vec![PathAttribute::MpReachNlri(mp)]);
    }
    fn rtc_nlri_96() -> crate::rtc::RtcNlri {
        // RT:65001:100 from origin AS 65001, full 96-bit prefix.
        crate::rtc::RtcNlri::new(65001, 0x0002_FDE9_0000_0064, 96).unwrap()
    }
    #[test]
    fn mp_reach_rtc_attribute_roundtrip() {
        // Includes the zero-length default NLRI alongside a /96 to pin the
        // one-codec-for-both behavior through the attribute layer.
        let mp = MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::RtConstrain,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![crate::rtc::RtcNlri::DEFAULT, rtc_nlri_96()],
        };
        let attr = PathAttribute::MpReachNlri(mp.clone());
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false).unwrap();
        // Plain 4-byte next-hop — no RD prefix (unlike SAFI 128).
        assert_eq!(buf[6], 4, "RTC next-hop is an ordinary 4-byte address");
        let decoded = decode_path_attributes(&buf, true, &[]).expect("decode RTC MP_REACH");
        assert_eq!(decoded, vec![PathAttribute::MpReachNlri(mp)]);
        let PathAttribute::MpReachNlri(decoded_mp) = &decoded[0] else {
            panic!("not MP_REACH after decode");
        };
        assert!(decoded_mp.rtc_announced[0].is_default());
        assert_eq!(decoded_mp.rtc_announced[1], rtc_nlri_96());
        assert!(decoded_mp.announced.is_empty());
    }
    #[test]
    fn mp_unreach_rtc_attribute_roundtrip() {
        let mp = MpUnreachNlri {
            afi: Afi::Ipv4,
            safi: Safi::RtConstrain,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: vec![],
            bgpls_withdrawn: vec![],
            labeled_withdrawn: vec![],
            vpn_withdrawn: vec![],
            rtc_withdrawn: vec![rtc_nlri_96()],
        };
        let attr = PathAttribute::MpUnreachNlri(mp.clone());
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).expect("decode RTC MP_UNREACH");
        assert_eq!(decoded, vec![PathAttribute::MpUnreachNlri(mp)]);
    }
    #[test]
    fn mp_reach_rtc_addpath_rejected() {
        let attr = PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::RtConstrain,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![rtc_nlri_96()],
        });
        let mut buf = Vec::new();
        encode_path_attributes(&[attr], &mut buf, true, false).unwrap();
        let err = decode_path_attributes(&buf, true, &[(Afi::Ipv4, Safi::RtConstrain)])
            .expect_err("RTC Add-Path must fail closed");
        match err {
            DecodeError::MalformedField { detail, .. } => {
                assert!(
                    detail.contains("RTC Add-Path is not supported"),
                    "unexpected detail: {detail}"
                );
            }
            other => panic!("expected MalformedField, got: {other:?}"),
        }
    }
    #[test]
    fn mp_reach_ipv6_rtc_stays_rejected() {
        // RFC 4684 defines RT-Constrain for AFI 1 only.
        let mut value = Vec::new();
        value.extend_from_slice(&(Afi::Ipv6 as u16).to_be_bytes());
        value.push(Safi::RtConstrain as u8);
        value.push(4); // NH-Len
        value.extend_from_slice(&[192, 0, 2, 1]);
        value.push(0); // Reserved
        value.push(0); // default NLRI
        let value_len = u8::try_from(value.len()).unwrap();
        let mut attr = vec![attr_flags::OPTIONAL, 14, value_len];
        attr.extend_from_slice(&value);
        let err =
            decode_path_attributes(&attr, true, &[]).expect_err("(IPv6, RTC) must stay rejected");
        assert!(matches!(err, DecodeError::MalformedField { .. }));
    }
    // ---- EVPN extended community typed accessors (RFC 7432 / 8365 / 9135) ---
    #[test]
    fn ext_comm_rfc8097_origin_validation_state_encoding() {
        // RFC 8097 §2: high-order octet 0x43 (non-transitive), low-order
        // 0x00, five reserved zero bytes, state in the last octet
        // (0 = valid, 1 = not found, 2 = invalid).
        for (ec, state) in [
            (ExtendedCommunity::ORIGIN_VALIDATION_VALID, 0u8),
            (ExtendedCommunity::ORIGIN_VALIDATION_NOT_FOUND, 1),
            (ExtendedCommunity::ORIGIN_VALIDATION_INVALID, 2),
        ] {
            assert_eq!(
                ec.as_u64().to_be_bytes(),
                [0x43, 0x00, 0, 0, 0, 0, 0, state]
            );
            assert_eq!(ec.type_byte(), 0x43);
            assert_eq!(ec.subtype(), 0x00);
            assert!(!ec.is_transitive(), "RFC 8097 is non-transitive");
            assert_eq!(
                ExtendedCommunity::new(u64::from_be_bytes([0x43, 0x00, 0, 0, 0, 0, 0, state])),
                ec,
                "decode roundtrip"
            );
            // Not an RT/RO — the two-part decoders must not claim it.
            assert_eq!(ec.route_target(), None);
            assert_eq!(ec.route_origin(), None);
        }
        assert_eq!(
            ExtendedCommunity::ORIGIN_VALIDATION_INVALID.to_string(),
            "OV_INVALID"
        );
        assert_eq!(
            ExtendedCommunity::ORIGIN_VALIDATION_VALID.to_string(),
            "OV_VALID"
        );
        assert_eq!(
            ExtendedCommunity::ORIGIN_VALIDATION_NOT_FOUND.to_string(),
            "OV_NOT_FOUND"
        );
    }

    #[test]
    fn ext_comm_bgp_encapsulation_vxlan() {
        let c = ExtendedCommunity::bgp_encapsulation(8); // VXLAN
        assert_eq!(c.type_byte(), 0x03);
        assert_eq!(c.subtype(), 0x0C);
        assert_eq!(c.as_bgp_encapsulation(), Some(8));
        // Wire layout: 4 bytes reserved + 2-byte tunnel type
        let b = c.as_u64().to_be_bytes();
        assert_eq!(b[2..6], [0, 0, 0, 0]);
        assert_eq!(&b[6..8], &[0, 8]);
        // Negative: other subtypes return None
        assert_eq!(ExtendedCommunity::new(0).as_bgp_encapsulation(), None);
    }
    #[test]
    fn ext_comm_mac_mobility_sticky_and_sequence() {
        let m1 = ExtendedCommunity::mac_mobility(false, 42);
        assert_eq!(m1.as_mac_mobility(), Some((false, 42)));
        let m2 = ExtendedCommunity::mac_mobility(true, 12345);
        assert_eq!(m2.as_mac_mobility(), Some((true, 12345)));
        // Round-trip max sequence
        let m3 = ExtendedCommunity::mac_mobility(true, u32::MAX);
        assert_eq!(m3.as_mac_mobility(), Some((true, u32::MAX)));
        assert_eq!(ExtendedCommunity::new(0).as_mac_mobility(), None);
    }
    #[test]
    fn ext_comm_esi_label_flags_and_label() {
        let e1 = ExtendedCommunity::esi_label(false, 10_000);
        assert_eq!(e1.as_esi_label(), Some((false, 10_000)));
        let e2 = ExtendedCommunity::esi_label(true, 0x00FF_FFFF);
        assert_eq!(e2.as_esi_label(), Some((true, 0x00FF_FFFF)));
    }
    #[test]
    fn ext_comm_es_import_rt_mac() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let e = ExtendedCommunity::es_import_rt(mac);
        assert_eq!(e.as_es_import_rt(), Some(mac));
        assert_eq!(e.type_byte(), 0x06);
        assert_eq!(e.subtype(), 0x02);
    }
    #[test]
    fn ext_comm_df_election_hrw_roundtrips_reserved_bytes_zero() {
        let ec = ExtendedCommunity::df_election(1, 0, None);
        assert_eq!(ec.type_byte(), 0x06);
        assert_eq!(ec.subtype(), 0x06);
        assert_eq!(
            ec.as_df_election(),
            Some(DfElectionExtendedCommunity {
                algorithm_id: 1,
                capabilities: 0,
                preference: None,
            })
        );
        assert_eq!(ec.as_u64().to_be_bytes(), [0x06, 0x06, 0x01, 0, 0, 0, 0, 0]);
    }
    #[test]
    fn ext_comm_df_election_preference_bytes_decode_for_rfc9785_algorithms() {
        let ec = ExtendedCommunity::df_election(3, 0x8000, Some(42));
        assert_eq!(
            ec.as_df_election(),
            Some(DfElectionExtendedCommunity {
                algorithm_id: 3,
                capabilities: 0x8000,
                preference: Some(42),
            })
        );
    }
    #[test]
    fn ext_comm_router_mac() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let e = ExtendedCommunity::router_mac(mac);
        assert_eq!(e.as_router_mac(), Some(mac));
    }
    #[test]
    fn ext_comm_link_bandwidth_roundtrips() {
        let bw = 1.25e9_f32; // 10 Gbps expressed in bytes/second
        let e = ExtendedCommunity::link_bandwidth(65001, bw);
        assert_eq!(e.type_byte(), 0x40, "non-transitive two-octet-AS-specific");
        assert_eq!(e.subtype(), 0x04, "Link Bandwidth subtype");
        let (asn, decoded) = e.as_link_bandwidth().expect("decodes as link bandwidth");
        assert_eq!(asn, 65001);
        // Exact round-trip through IEEE-754 bytes — assert bitwise equality.
        assert_eq!(decoded.to_bits(), bw.to_bits());
    }
    #[test]
    /// Load-bearing proof: dropping exact type `0x00` or `0x40` receiver
    /// support breaks that type's raw ASN/bandwidth assertions.
    fn ext_comm_link_bandwidth_decodes_known_wire_bytes() {
        let one = 1.0_f32.to_be_bytes();
        for type_byte in [0x00, 0x40] {
            let raw =
                u64::from_be_bytes([type_byte, 0x04, 0xFD, 0xE9, one[0], one[1], one[2], one[3]]);
            let (asn, bw) = ExtendedCommunity::new(raw)
                .as_link_bandwidth()
                .expect("decodes as link bandwidth");
            assert_eq!(asn, 65001);
            assert_eq!(bw.to_bits(), 1.0_f32.to_bits());
        }
    }
    #[test]
    /// Load-bearing proof: masking the type byte admits `0x80`/`0xc0`, while
    /// dropping the subtype check admits the wrong-subtype assertion.
    fn ext_comm_link_bandwidth_rejects_wrong_type_or_subtype() {
        for type_byte in [0x80, 0xc0] {
            let wrong_type =
                ExtendedCommunity::new(u64::from_be_bytes([type_byte, 0x04, 0, 0, 0, 0, 0, 0]));
            assert!(wrong_type.as_link_bandwidth().is_none());
        }
        // Right type (0x40) but a different subtype.
        let wrong_sub = ExtendedCommunity::new(u64::from_be_bytes([0x40, 0x02, 0, 0, 0, 0, 0, 0]));
        assert!(wrong_sub.as_link_bandwidth().is_none());
    }
    #[test]
    fn ext_comm_default_gateway_flag_only() {
        let d = ExtendedCommunity::default_gateway();
        assert!(d.as_default_gateway());
        // Not a default gateway
        assert!(!ExtendedCommunity::bgp_encapsulation(8).as_default_gateway());
    }
    /// Regression: Default Gateway is a flag-only community (RFC 7432).
    /// Malformed advertisements that set non-zero bytes in the value
    /// field must NOT be treated as default-gateway matches.
    #[test]
    fn ext_comm_default_gateway_rejects_nonzero_value() {
        // Correct type/subtype (0x03/0x0D) but bogus value.
        let malformed =
            ExtendedCommunity::new(u64::from_be_bytes([0x03, 0x0D, 0, 0, 0, 0, 0, 0x01]));
        assert!(
            !malformed.as_default_gateway(),
            "default-gateway accessor must require all-zero value bytes"
        );
        // Sanity: the clean form still passes.
        assert!(ExtendedCommunity::default_gateway().as_default_gateway());
    }
    #[test]
    fn ext_comm_accessors_return_none_on_unrelated_communities() {
        let rt = ExtendedCommunity::new(u64::from_be_bytes([0x00, 0x02, 0xFD, 0xE8, 0, 0, 0, 100])); // RT:65000:100
        assert_eq!(rt.as_bgp_encapsulation(), None);
        assert_eq!(rt.as_mac_mobility(), None);
        assert_eq!(rt.as_esi_label(), None);
        assert_eq!(rt.as_es_import_rt(), None);
        assert_eq!(rt.as_router_mac(), None);
        assert!(rt.as_link_bandwidth().is_none());
        assert!(!rt.as_default_gateway());
    }
    #[test]
    fn origin_from_u8_roundtrip() {
        assert_eq!(Origin::from_u8(0), Some(Origin::Igp));
        assert_eq!(Origin::from_u8(1), Some(Origin::Egp));
        assert_eq!(Origin::from_u8(2), Some(Origin::Incomplete));
        assert_eq!(Origin::from_u8(3), None);
    }
    #[test]
    fn origin_ordering() {
        assert!(Origin::Igp < Origin::Egp);
        assert!(Origin::Egp < Origin::Incomplete);
    }
    #[test]
    fn as_path_length_calculation() {
        let path = AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![65001, 65002, 65003]),
                AsPathSegment::AsSet(vec![65004, 65005]),
            ],
        };
        // Sequence: 3 ASNs, Set: counts as 1 → total 4
        assert_eq!(path.len(), 4);
    }
    #[test]
    fn as_path_empty() {
        let path = AsPath { segments: vec![] };
        assert!(path.is_empty());
        assert_eq!(path.len(), 0);
    }
    #[test]
    fn contains_asn_in_sequence() {
        let path = AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65001, 65002, 65003])],
        };
        assert!(path.contains_asn(65002));
        assert!(!path.contains_asn(65004));
    }
    #[test]
    fn contains_asn_in_set() {
        let path = AsPath {
            segments: vec![AsPathSegment::AsSet(vec![65004, 65005])],
        };
        assert!(path.contains_asn(65005));
        assert!(!path.contains_asn(65001));
    }
    #[test]
    fn contains_asn_multiple_segments() {
        let path = AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![65001, 65002]),
                AsPathSegment::AsSet(vec![65003]),
            ],
        };
        assert!(path.contains_asn(65001));
        assert!(path.contains_asn(65003));
        assert!(!path.contains_asn(65004));
    }
    #[test]
    fn contains_asn_empty_path() {
        let path = AsPath { segments: vec![] };
        assert!(!path.contains_asn(65001));
    }
    #[test]
    fn is_private_asn_boundaries() {
        // 16-bit private range boundaries
        assert!(!is_private_asn(64_511));
        assert!(is_private_asn(64_512));
        assert!(is_private_asn(65_534));
        assert!(!is_private_asn(65_535));
        // 32-bit private range boundaries
        assert!(!is_private_asn(4_199_999_999));
        assert!(is_private_asn(4_200_000_000));
        assert!(is_private_asn(4_294_967_294));
        assert!(!is_private_asn(4_294_967_295));
    }
    #[test]
    fn all_private_empty_path_is_false() {
        let path = AsPath { segments: vec![] };
        assert!(!path.all_private());
    }
    #[test]
    fn all_private_mixed_segments() {
        let path = AsPath {
            segments: vec![
                AsPathSegment::AsSet(vec![64_512, 65_000]),
                AsPathSegment::AsSequence(vec![4_200_000_000, 65_534]),
            ],
        };
        assert!(path.all_private());
        let non_private = AsPath {
            segments: vec![
                AsPathSegment::AsSet(vec![64_512, 65_000]),
                AsPathSegment::AsSequence(vec![65_535]),
            ],
        };
        assert!(!non_private.all_private());
    }
    #[test]
    fn decode_origin_igp() {
        // flags=0x40 (transitive), type=1, len=1, value=0 (IGP)
        let buf = [0x40, 0x01, 0x01, 0x00];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0], PathAttribute::Origin(Origin::Igp));
    }
    #[test]
    fn decode_origin_egp() {
        let buf = [0x40, 0x01, 0x01, 0x01];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs[0], PathAttribute::Origin(Origin::Egp));
    }
    #[test]
    fn decode_origin_invalid_value() {
        // ORIGIN with value 5 — not a valid Origin (only 0-2 are defined)
        let buf = [0x40, 0x01, 0x01, 0x05];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        match &err {
            DecodeError::UpdateAttributeError { subcode, .. } => {
                assert_eq!(*subcode, update_subcode::INVALID_ORIGIN);
            }
            other => panic!("expected UpdateAttributeError, got: {other:?}"),
        }
    }
    #[test]
    fn decode_next_hop() {
        // flags=0x40, type=3, len=4, value=10.0.0.1
        let buf = [0x40, 0x03, 0x04, 10, 0, 0, 1];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs[0], PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)));
    }
    #[test]
    fn decode_med() {
        // flags=0x80 (optional), type=4, len=4, value=100
        let buf = [0x80, 0x04, 0x04, 0, 0, 0, 100];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs[0], PathAttribute::Med(100));
    }
    #[test]
    fn decode_local_pref() {
        // flags=0x40, type=5, len=4, value=200
        let buf = [0x40, 0x05, 0x04, 0, 0, 0, 200];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs[0], PathAttribute::LocalPref(200));
    }
    #[test]
    fn decode_as_path_4byte() {
        // flags=0x40, type=2, len=10
        // segment: type=2 (AS_SEQUENCE), count=2, ASNs: 65001, 65002 (4 bytes each)
        let buf = [
            0x40, 0x02, 0x0A, // header
            0x02, 0x02, // AS_SEQUENCE, 2 ASNs
            0x00, 0x00, 0xFD, 0xE9, // 65001
            0x00, 0x00, 0xFD, 0xEA, // 65002
        ];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(
            attrs[0],
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001, 65002])]
            })
        );
    }
    #[test]
    fn decode_as_path_2byte() {
        // flags=0x40, type=2, len=6
        // segment: type=2 (AS_SEQUENCE), count=2, ASNs: 100, 200 (2 bytes each)
        let buf = [
            0x40, 0x02, 0x06, // header
            0x02, 0x02, // AS_SEQUENCE, 2 ASNs
            0x00, 0x64, // 100
            0x00, 0xC8, // 200
        ];
        let attrs = decode_path_attributes(&buf, false, &[]).unwrap();
        assert_eq!(
            attrs[0],
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![100, 200])]
            })
        );
    }
    #[test]
    fn decode_unknown_attribute_preserved() {
        // flags=0xC0 (optional+transitive), type=99, len=3, data=[1,2,3]
        let buf = [0xC0, 99, 0x03, 1, 2, 3];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(
            attrs[0],
            PathAttribute::Unknown(RawAttribute {
                flags: 0xC0,
                type_code: 99,
                data: Bytes::from_static(&[1, 2, 3]),
            })
        );
    }
    #[test]
    fn decode_atomic_aggregate_as_unknown() {
        // ATOMIC_AGGREGATE: flags=0x40, type=6, len=0
        let buf = [0x40, 0x06, 0x00];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert!(matches!(attrs[0], PathAttribute::Unknown(_)));
    }
    #[test]
    fn decode_extended_length() {
        // flags=0x50 (transitive+extended), type=2, len=0x000A (10)
        // Same AS_PATH as the 4-byte test
        let buf = [
            0x50, 0x02, 0x00, 0x0A, // header with extended length
            0x02, 0x02, // AS_SEQUENCE, 2 ASNs
            0x00, 0x00, 0xFD, 0xE9, // 65001
            0x00, 0x00, 0xFD, 0xEA, // 65002
        ];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(
            attrs[0],
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001, 65002])]
            })
        );
    }
    #[test]
    fn decode_multiple_attributes() {
        let mut buf = Vec::new();
        // ORIGIN IGP
        buf.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]);
        // NEXT_HOP 10.0.0.1
        buf.extend_from_slice(&[0x40, 0x03, 0x04, 10, 0, 0, 1]);
        // AS_PATH empty
        buf.extend_from_slice(&[0x40, 0x02, 0x00]);
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs[0], PathAttribute::Origin(Origin::Igp));
        assert_eq!(attrs[1], PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(attrs[2], PathAttribute::AsPath(AsPath { segments: vec![] }));
    }
    #[test]
    fn roundtrip_attributes_4byte() {
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001, 65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
            PathAttribute::Med(100),
            PathAttribute::LocalPref(200),
        ];
        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded, attrs);
    }
    #[test]
    fn roundtrip_attributes_2byte() {
        let attrs = vec![
            PathAttribute::Origin(Origin::Egp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![100, 200])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(172, 16, 0, 1)),
        ];
        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, false, false).unwrap();
        let decoded = decode_path_attributes(&buf, false, &[]).unwrap();
        assert_eq!(decoded, attrs);
    }
    #[test]
    fn reject_truncated_attribute_header() {
        let buf = [0x40]; // only 1 byte
        assert!(decode_path_attributes(&buf, true, &[]).is_err());
    }
    #[test]
    fn reject_truncated_attribute_value() {
        // ORIGIN claims 1 byte value but nothing follows
        let buf = [0x40, 0x01, 0x01];
        assert!(decode_path_attributes(&buf, true, &[]).is_err());
    }
    #[test]
    fn reject_bad_origin_length() {
        // ORIGIN with 2-byte value
        let buf = [0x40, 0x01, 0x02, 0x00, 0x00];
        assert!(decode_path_attributes(&buf, true, &[]).is_err());
    }
    /// Origin-AS extraction: the last ASN in the rightmost non-empty
    /// `AS_SEQUENCE`. Absent (`None`) for paths with no usable
    /// sequence — empty paths and `AS_SET`-only paths.
    #[test]
    fn origin_asn_segment_shapes() {
        let seq = AsPathSegment::AsSequence;
        let set = AsPathSegment::AsSet;
        let cases: [(&str, Vec<AsPathSegment>, Option<u32>); 8] = [
            ("empty path", vec![], None),
            ("plain sequence", vec![seq(vec![65001, 65002])], Some(65002)),
            ("AS_SET-only", vec![set(vec![65003, 65004])], None),
            (
                "aggregated: sequence then set",
                vec![seq(vec![65001, 65002]), set(vec![65003, 65004])],
                Some(65002),
            ),
            (
                "set then sequence",
                vec![set(vec![65003]), seq(vec![65001, 65002])],
                Some(65002),
            ),
            (
                "rightmost sequence empty falls back left",
                vec![seq(vec![65001]), seq(vec![])],
                Some(65001),
            ),
            (
                "multiple sequences take the rightmost",
                vec![seq(vec![65001]), seq(vec![65005, 65006])],
                Some(65006),
            ),
            (
                "4-byte ASN, no truncation",
                vec![seq(vec![65001, 4_200_000_001])],
                Some(4_200_000_001),
            ),
        ];
        for (what, segments, expect) in cases {
            assert_eq!(AsPath { segments }.origin_asn(), expect, "{what}");
        }
    }

    /// Load-bearing RFC 9774 ingress proof: removing the raw prohibited-set
    /// scan makes the revised result clean; making the ordinary decoder reject
    /// sets prevents BMP/MRT observation of the received path.
    #[test]
    fn as_path_set_decodes_for_observation_but_revised_treats_as_withdraw() {
        let expected = vec![PathAttribute::AsPath(AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![65_001]),
                AsPathSegment::AsSet(vec![65_002, 65_003]),
            ],
        })];
        let bytes = attr_bytes(
            attr_flags::TRANSITIVE,
            attr_type::AS_PATH,
            &[
                2, 1, 0, 0, 0xFD, 0xE9, 1, 2, 0, 0, 0xFD, 0xEA, 0, 0, 0xFD, 0xEB,
            ],
        );
        assert_eq!(decode_path_attributes(&bytes, true, &[]).unwrap(), expected);
        let revised = decode_path_attributes_revised(&bytes, true, false, &[]).unwrap();
        assert_eq!(revised.attributes, expected);
        assert!(revised.malformed.iter().any(|malformed| {
            malformed.type_code == attr_type::AS_PATH
                && malformed.disposition == ErrorDisposition::TreatAsWithdraw
        }));
    }
    #[test]
    fn decode_communities_single() {
        // flags=0xC0 (optional+transitive), type=8, len=4, community=65001:100
        // 65001 = 0xFDE9, 100 = 0x0064 → u32 = 0xFDE90064
        let community: u32 = (65001 << 16) | 0x0064;
        let bytes = community.to_be_bytes();
        let buf = [0xC0, 0x08, 0x04, bytes[0], bytes[1], bytes[2], bytes[3]];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0], PathAttribute::Communities(vec![community]));
    }
    #[test]
    fn decode_communities_multiple() {
        let c1: u32 = (65001 << 16) | 0x0064;
        let c2: u32 = (65002 << 16) | 0x00C8;
        let b1 = c1.to_be_bytes();
        let b2 = c2.to_be_bytes();
        let buf = [
            0xC0, 0x08, 0x08, b1[0], b1[1], b1[2], b1[3], b2[0], b2[1], b2[2], b2[3],
        ];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs[0], PathAttribute::Communities(vec![c1, c2]));
    }
    #[test]
    fn decode_communities_empty_rejected() {
        // flags=0xC0, type=8, len=0 — RFC 7606 §7.8: the length must be a
        // NON-ZERO multiple of 4, so a vacuous Communities attribute is
        // malformed (treat-as-withdraw on the revised path).
        let buf = [0xC0, 0x08, 0x00];
        assert!(decode_path_attributes(&buf, true, &[]).is_err());
    }
    #[test]
    fn decode_communities_odd_length_rejected() {
        // flags=0xC0, type=8, len=3, only 3 bytes (not multiple of 4)
        let buf = [0xC0, 0x08, 0x03, 0x01, 0x02, 0x03];
        assert!(decode_path_attributes(&buf, true, &[]).is_err());
    }
    #[test]
    fn communities_roundtrip() {
        let c1: u32 = (65001 << 16) | 0x0064;
        let c2: u32 = (65002 << 16) | 0x00C8;
        let attrs = vec![PathAttribute::Communities(vec![c1, c2])];
        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded, attrs);
    }
    #[test]
    fn communities_type_code_and_flags() {
        let attr = PathAttribute::Communities(vec![]);
        assert_eq!(attr.type_code(), 8);
        assert_eq!(attr.flags(), attr_flags::OPTIONAL | attr_flags::TRANSITIVE);
    }
    // --- Extended Communities (RFC 4360) tests ---
    #[test]
    fn decode_extended_communities_single() {
        // Route Target 65001:100 — type 0x00, subtype 0x02, AS 65001 (2-octet), value 100
        let ec = ExtendedCommunity::new(0x0002_FDE9_0000_0064);
        let bytes = ec.as_u64().to_be_bytes();
        let buf = [
            0xC0, 0x10, 0x08, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
            bytes[7],
        ];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0], PathAttribute::ExtendedCommunities(vec![ec]));
    }
    #[test]
    fn decode_extended_communities_multiple() {
        let ec1 = ExtendedCommunity::new(0x0002_FDE9_0000_0064);
        let ec2 = ExtendedCommunity::new(0x0003_FDEA_0000_00C8);
        let b1 = ec1.as_u64().to_be_bytes();
        let b2 = ec2.as_u64().to_be_bytes();
        let mut buf = vec![0xC0, 0x10, 16]; // flags, type=16, len=16
        buf.extend_from_slice(&b1);
        buf.extend_from_slice(&b2);
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs[0], PathAttribute::ExtendedCommunities(vec![ec1, ec2]));
    }
    #[test]
    fn decode_extended_communities_empty_rejected() {
        // RFC 7606 §7.14: the length must be a NON-ZERO multiple of 8.
        let buf = [0xC0, 0x10, 0x00];
        assert!(decode_path_attributes(&buf, true, &[]).is_err());
    }
    #[test]
    fn decode_extended_communities_bad_length() {
        // length 5 is not a multiple of 8
        let buf = [0xC0, 0x10, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(decode_path_attributes(&buf, true, &[]).is_err());
    }
    #[test]
    fn extended_communities_roundtrip() {
        let ec1 = ExtendedCommunity::new(0x0002_FDE9_0000_0064);
        let ec2 = ExtendedCommunity::new(0x0003_FDEA_0000_00C8);
        let attrs = vec![PathAttribute::ExtendedCommunities(vec![ec1, ec2])];
        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded, attrs);
    }
    #[test]
    fn extended_communities_type_code_and_flags() {
        let attr = PathAttribute::ExtendedCommunities(vec![]);
        assert_eq!(attr.type_code(), 16);
        assert_eq!(attr.flags(), attr_flags::OPTIONAL | attr_flags::TRANSITIVE);
    }
    #[test]
    fn extended_community_type_subtype() {
        // Type 0x00, Sub-type 0x02 (Route Target, 2-octet AS)
        let ec = ExtendedCommunity::new(0x0002_FDE9_0000_0064);
        assert_eq!(ec.type_byte(), 0x00);
        assert_eq!(ec.subtype(), 0x02);
        assert!(ec.is_transitive());
    }
    #[test]
    fn extended_community_route_target() {
        // 2-octet AS RT: type=0x00, subtype=0x02, AS=65001, value=100
        let ec = ExtendedCommunity::new(0x0002_FDE9_0000_0064);
        assert_eq!(ec.route_target(), Some((65001, 100)));
        assert_eq!(ec.route_origin(), None);
        // 4-octet AS RT: type=0x02, subtype=0x02, AS=65537, value=200
        let ec4 = ExtendedCommunity::new(0x0202_0001_0001_00C8);
        assert_eq!(ec4.route_target(), Some((65537, 200)));
        // IPv4-specific RT: type=0x01, subtype=0x02, IP=192.0.2.1, value=100
        // 192.0.2.1 = 0xC0000201
        let ec_ipv4 = ExtendedCommunity::new(0x0102_C000_0201_0064);
        let (g, l) = ec_ipv4.route_target().unwrap();
        assert_eq!(g, 0xC000_0201); // 192.0.2.1 as u32
        assert_eq!(l, 100);
        // Callers distinguish via type_byte()
        assert_eq!(ec_ipv4.type_byte() & 0x3F, 0x01);
    }
    #[test]
    fn extended_community_is_transitive() {
        // Type 0x00 → transitive (bit 6 = 0)
        let t = ExtendedCommunity::new(0x0002_0000_0000_0000);
        assert!(t.is_transitive());
        // Type 0x40 → non-transitive (bit 6 = 1)
        let nt = ExtendedCommunity::new(0x4002_0000_0000_0000);
        assert!(!nt.is_transitive());
    }
    #[test]
    fn extended_community_display() {
        let rt = ExtendedCommunity::new(0x0002_FDE9_0000_0064);
        assert_eq!(rt.to_string(), "RT:65001:100");
        let ro = ExtendedCommunity::new(0x0003_FDE9_0000_0064);
        assert_eq!(ro.to_string(), "RO:65001:100");
        // IPv4-specific RT: type=0x01, subtype=0x02, IP=192.0.2.1, value=100
        let target_v4 = ExtendedCommunity::new(0x0102_C000_0201_0064);
        assert_eq!(target_v4.to_string(), "RT:192.0.2.1:100");
        // IPv4-specific RO
        let origin_v4 = ExtendedCommunity::new(0x0103_C000_0201_0064);
        assert_eq!(origin_v4.to_string(), "RO:192.0.2.1:100");
        // 4-octet AS RT
        let rt_as4 = ExtendedCommunity::new(0x0202_0001_0001_00C8);
        assert_eq!(rt_as4.to_string(), "RT:65537:200");
        // Non-transitive opaque → hex fallback
        let opaque = ExtendedCommunity::new(0x4300_1234_5678_9ABC);
        assert_eq!(opaque.to_string(), "0x4300123456789abc");
    }
    #[test]
    fn unknown_attribute_roundtrip() {
        // Input has flags 0xC0 (optional+transitive). After encoding, the
        // Partial bit is OR'd in for transitive unknowns → 0xE0.
        let attrs = vec![PathAttribute::Unknown(RawAttribute {
            flags: 0xC0,
            type_code: 99,
            data: Bytes::from_static(&[1, 2, 3, 4, 5]),
        })];
        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(
            decoded,
            vec![PathAttribute::Unknown(RawAttribute {
                flags: 0xE0, // Partial bit set on re-advertisement
                type_code: 99,
                data: Bytes::from_static(&[1, 2, 3, 4, 5]),
            })]
        );
    }
    #[test]
    fn origin_with_optional_flag_rejected() {
        // ORIGIN with flags 0xC0 (Optional+Transitive) — should be 0x40 (Transitive only)
        let buf = [0xC0, 0x01, 0x01, 0x00];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        match &err {
            DecodeError::UpdateAttributeError { subcode, .. } => {
                assert_eq!(*subcode, update_subcode::ATTRIBUTE_FLAGS_ERROR);
            }
            other => panic!("expected UpdateAttributeError, got: {other:?}"),
        }
    }
    #[test]
    fn med_with_transitive_flag_rejected() {
        // MED with flags 0xC0 (Optional+Transitive) — should be 0x80 (Optional only)
        let buf = [0xC0, 0x04, 0x04, 0, 0, 0, 100];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        match &err {
            DecodeError::UpdateAttributeError { subcode, .. } => {
                assert_eq!(*subcode, update_subcode::ATTRIBUTE_FLAGS_ERROR);
            }
            other => panic!("expected UpdateAttributeError, got: {other:?}"),
        }
    }
    #[test]
    fn communities_without_optional_rejected() {
        // COMMUNITIES with flags 0x40 (Transitive only) — should be 0xC0 (Optional+Transitive)
        let buf = [0x40, 0x08, 0x04, 0, 0, 0, 100];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        match &err {
            DecodeError::UpdateAttributeError { subcode, .. } => {
                assert_eq!(*subcode, update_subcode::ATTRIBUTE_FLAGS_ERROR);
            }
            other => panic!("expected UpdateAttributeError, got: {other:?}"),
        }
    }
    #[test]
    fn next_hop_length_error_subcode() {
        // NEXT_HOP with 3 bytes instead of 4
        let buf = [0x40, 0x03, 0x03, 10, 0, 0];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        match &err {
            DecodeError::UpdateAttributeError { subcode, .. } => {
                assert_eq!(*subcode, update_subcode::ATTRIBUTE_LENGTH_ERROR);
            }
            other => panic!("expected UpdateAttributeError, got: {other:?}"),
        }
    }
    #[test]
    fn invalid_origin_value_subcode() {
        // ORIGIN with value 5 → subcode 6 (INVALID_ORIGIN)
        let buf = [0x40, 0x01, 0x01, 0x05];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        match &err {
            DecodeError::UpdateAttributeError { subcode, .. } => {
                assert_eq!(*subcode, update_subcode::INVALID_ORIGIN);
            }
            other => panic!("expected UpdateAttributeError, got: {other:?}"),
        }
    }
    #[test]
    fn as_path_bad_segment_subcode() {
        // AS_PATH with unknown segment type 5
        let buf = [
            0x40, 0x02, 0x06, // AS_PATH header, length 6
            0x05, 0x01, // unknown segment type 5, count 1
            0x00, 0x00, 0xFD, 0xE9, // ASN 65001
        ];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        match &err {
            DecodeError::UpdateAttributeError { subcode, .. } => {
                assert_eq!(*subcode, update_subcode::MALFORMED_AS_PATH);
            }
            other => panic!("expected UpdateAttributeError, got: {other:?}"),
        }
    }
    #[test]
    fn encode_unknown_transitive_sets_partial() {
        let attr = PathAttribute::Unknown(RawAttribute {
            flags: attr_flags::OPTIONAL | attr_flags::TRANSITIVE, // 0xC0
            type_code: 99,
            data: Bytes::from_static(&[1, 2]),
        });
        let mut buf = Vec::new();
        encode_path_attributes(&[attr], &mut buf, true, false).unwrap();
        // First byte is flags — should have PARTIAL bit set
        assert_eq!(
            buf[0],
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE | attr_flags::PARTIAL
        );
    }
    #[test]
    fn encode_unknown_wellknown_transitive_no_partial() {
        // Well-known transitive (OPTIONAL=0, TRANSITIVE=1) should NOT get PARTIAL
        let attr = PathAttribute::Unknown(RawAttribute {
            flags: attr_flags::TRANSITIVE, // 0x40, well-known transitive
            type_code: 99,
            data: Bytes::from_static(&[1, 2]),
        });
        let mut buf = Vec::new();
        encode_path_attributes(&[attr], &mut buf, true, false).unwrap();
        assert_eq!(buf[0], attr_flags::TRANSITIVE);
    }
    #[test]
    fn encode_unknown_nontransitive_no_partial() {
        let attr = PathAttribute::Unknown(RawAttribute {
            flags: attr_flags::OPTIONAL, // 0x80, no Transitive
            type_code: 99,
            data: Bytes::from_static(&[1, 2]),
        });
        let mut buf = Vec::new();
        encode_path_attributes(&[attr], &mut buf, true, false).unwrap();
        // First byte is flags — should NOT have PARTIAL bit
        assert_eq!(buf[0], attr_flags::OPTIONAL);
    }
    // --- MP_REACH_NLRI / MP_UNREACH_NLRI tests ---
    /// Helper to create a `NlriEntry` with `path_id=0`.
    fn nlri(prefix: Prefix) -> NlriEntry {
        NlriEntry { path_id: 0, prefix }
    }
    #[test]
    fn mp_reach_nlri_ipv6_roundtrip() {
        use crate::capability::{Afi, Safi};
        use crate::nlri::{Ipv6Prefix, Prefix};
        let mp = MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
            link_local_next_hop: None,
            announced: vec![
                nlri(Prefix::V6(Ipv6Prefix::new(
                    "2001:db8:1::".parse().unwrap(),
                    48,
                ))),
                nlri(Prefix::V6(Ipv6Prefix::new(
                    "2001:db8:2::".parse().unwrap(),
                    48,
                ))),
            ],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        };
        let attrs = vec![PathAttribute::MpReachNlri(mp.clone())];
        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], PathAttribute::MpReachNlri(mp));
    }
    #[test]
    fn mp_unreach_nlri_ipv6_roundtrip() {
        use crate::capability::{Afi, Safi};
        use crate::nlri::{Ipv6Prefix, Prefix};
        let mp = MpUnreachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            withdrawn: vec![nlri(Prefix::V6(Ipv6Prefix::new(
                "2001:db8:1::".parse().unwrap(),
                48,
            )))],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: vec![],
            bgpls_withdrawn: vec![],
            labeled_withdrawn: vec![],
            vpn_withdrawn: vec![],
            rtc_withdrawn: vec![],
        };
        let attrs = vec![PathAttribute::MpUnreachNlri(mp.clone())];
        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], PathAttribute::MpUnreachNlri(mp));
    }
    #[test]
    fn mp_reach_flowspec_oversized_rule_returns_encode_error() {
        let attr = PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::FlowSpec,
            next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![oversized_flowspec_rule()],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        });
        let mut buf = vec![0xaa, 0xbb];
        let err =
            encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false).unwrap_err();
        let EncodeError::ValueOutOfRange { field, value } = err else {
            panic!("expected ValueOutOfRange");
        };
        assert_eq!(field, "FlowSpec NLRI rule length");
        assert_eq!(
            value,
            oversized_flowspec_rule().encoded_len(Afi::Ipv4).to_string()
        );
        assert_eq!(buf, vec![0xaa, 0xbb]);
    }
    #[test]
    fn mp_unreach_flowspec_oversized_rule_returns_encode_error() {
        let attr = PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi: Afi::Ipv4,
            safi: Safi::FlowSpec,
            withdrawn: vec![],
            flowspec_withdrawn: vec![oversized_flowspec_rule()],
            evpn_withdrawn: vec![],
            bgpls_withdrawn: vec![],
            labeled_withdrawn: vec![],
            vpn_withdrawn: vec![],
            rtc_withdrawn: vec![],
        });
        let mut buf = vec![0xaa, 0xbb];
        let err =
            encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false).unwrap_err();
        let EncodeError::ValueOutOfRange { field, value } = err else {
            panic!("expected ValueOutOfRange");
        };
        assert_eq!(field, "FlowSpec NLRI rule length");
        assert_eq!(
            value,
            oversized_flowspec_rule().encoded_len(Afi::Ipv4).to_string()
        );
        assert_eq!(buf, vec![0xaa, 0xbb]);
    }
    #[test]
    fn mp_reach_nlri_ipv4_roundtrip() {
        use crate::capability::{Afi, Safi};
        use crate::nlri::Prefix;
        let mp = MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            link_local_next_hop: None,
            announced: vec![nlri(Prefix::V4(crate::nlri::Ipv4Prefix::new(
                Ipv4Addr::new(10, 1, 0, 0),
                16,
            )))],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        };
        let attrs = vec![PathAttribute::MpReachNlri(mp.clone())];
        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded[0], PathAttribute::MpReachNlri(mp));
    }
    #[test]
    fn mp_reach_nlri_ipv4_with_ipv6_nexthop_roundtrip() {
        use crate::capability::{Afi, Safi};
        use crate::nlri::Prefix;
        let mp = MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
            link_local_next_hop: None,
            announced: vec![nlri(Prefix::V4(crate::nlri::Ipv4Prefix::new(
                Ipv4Addr::new(10, 1, 0, 0),
                16,
            )))],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        };
        let attrs = vec![PathAttribute::MpReachNlri(mp.clone())];
        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded[0], PathAttribute::MpReachNlri(mp));
    }
    #[test]
    fn mp_reach_nlri_type_code_and_flags() {
        use crate::capability::{Afi, Safi};
        let attr = PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        });
        assert_eq!(attr.type_code(), 14);
        // RFC 4760 §3: MP_REACH_NLRI is optional non-transitive
        assert_eq!(attr.flags(), attr_flags::OPTIONAL);
    }
    #[test]
    fn mp_unreach_nlri_type_code_and_flags() {
        use crate::capability::{Afi, Safi};
        let attr = PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: vec![],
            bgpls_withdrawn: vec![],
            labeled_withdrawn: vec![],
            vpn_withdrawn: vec![],
            rtc_withdrawn: vec![],
        });
        assert_eq!(attr.type_code(), 15);
        assert_eq!(attr.flags(), attr_flags::OPTIONAL);
    }
    #[test]
    fn mp_reach_nlri_empty_nlri() {
        use crate::capability::{Afi, Safi};
        let mp = MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6("fe80::1".parse().unwrap()),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        };
        let attrs = vec![PathAttribute::MpReachNlri(mp.clone())];
        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded[0], PathAttribute::MpReachNlri(mp));
    }
    #[test]
    fn mp_reach_nlri_bad_flags_rejected() {
        // MP_REACH_NLRI (type 14) with flags 0x40 (Transitive only)
        // — should be 0xC0 (Optional+Transitive)
        // Build minimal valid value: AFI=2, SAFI=1, NH-Len=16, NH=::1, Reserved=0
        let mut value = Vec::new();
        value.extend_from_slice(&2u16.to_be_bytes()); // AFI IPv6
        value.push(1); // SAFI Unicast
        value.push(16); // NH-Len
        value.extend_from_slice(&"::1".parse::<Ipv6Addr>().unwrap().octets()); // NH
        value.push(0); // Reserved
        let mut buf = Vec::new();
        buf.push(0x40); // flags: Transitive only (wrong)
        buf.push(14); // type: MP_REACH_NLRI
        #[expect(
            clippy::cast_possible_truncation,
            reason = "codec bounds or masks the value before narrowing to the protocol field width"
        )]
        buf.push(value.len() as u8);
        buf.extend_from_slice(&value);
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UpdateAttributeError {
                subcode: 4, // ATTRIBUTE_FLAGS_ERROR
                ..
            }
        ));
    }
    // --- MP Add-Path decode tests ---
    #[test]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "codec bounds or masks the value before narrowing to the protocol field width"
    )]
    fn mp_reach_nlri_ipv4_addpath_decode() {
        use crate::capability::{Afi, Safi};
        use crate::nlri::Prefix;
        // Build MP_REACH_NLRI with Add-Path-encoded IPv4 NLRI:
        // path_id(4) + prefix_len(1) + prefix_bytes
        let mut value = Vec::new();
        value.extend_from_slice(&1u16.to_be_bytes()); // AFI IPv4
        value.push(1); // SAFI Unicast
        value.push(4); // NH-Len
        value.extend_from_slice(&[10, 0, 0, 1]); // Next Hop
        value.push(0); // Reserved
        // Add-Path NLRI: path_id=42, 10.1.0.0/16
        value.extend_from_slice(&42u32.to_be_bytes());
        value.push(16);
        value.extend_from_slice(&[10, 1]);
        let mut buf = Vec::new();
        buf.push(0x90); // flags: Optional + Extended Length
        buf.push(14); // type: MP_REACH_NLRI
        buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
        buf.extend_from_slice(&value);
        // With Add-Path for IPv4 unicast → decode path_id
        let decoded = decode_path_attributes(&buf, true, &[(Afi::Ipv4, Safi::Unicast)]).unwrap();
        let PathAttribute::MpReachNlri(mp) = &decoded[0] else {
            panic!("expected MpReachNlri");
        };
        assert_eq!(mp.announced.len(), 1);
        assert_eq!(mp.announced[0].path_id, 42);
        assert!(matches!(mp.announced[0].prefix, Prefix::V4(p) if p.len == 16));
        // Without Add-Path → plain decoder misinterprets the path_id bytes
        // as prefix encoding and rejects the garbled data.
        assert!(decode_path_attributes(&buf, true, &[]).is_err());
    }
    #[test]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "codec bounds or masks the value before narrowing to the protocol field width"
    )]
    fn mp_reach_nlri_ipv6_addpath_decode() {
        use crate::capability::{Afi, Safi};
        use crate::nlri::{Ipv6Prefix, Prefix};
        // Build MP_REACH_NLRI with Add-Path-encoded IPv6 NLRI
        let mut value = Vec::new();
        value.extend_from_slice(&2u16.to_be_bytes()); // AFI IPv6
        value.push(1); // SAFI Unicast
        value.push(16); // NH-Len
        value.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        value.push(0); // Reserved
        // Add-Path NLRI: path_id=99, 2001:db8:1::/48
        value.extend_from_slice(&99u32.to_be_bytes());
        value.push(48);
        value.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);
        let mut buf = Vec::new();
        buf.push(0x90); // flags: Optional + Extended Length
        buf.push(14); // type: MP_REACH_NLRI
        buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
        buf.extend_from_slice(&value);
        let decoded = decode_path_attributes(&buf, true, &[(Afi::Ipv6, Safi::Unicast)]).unwrap();
        let PathAttribute::MpReachNlri(mp) = &decoded[0] else {
            panic!("expected MpReachNlri");
        };
        assert_eq!(mp.announced.len(), 1);
        assert_eq!(mp.announced[0].path_id, 99);
        assert_eq!(
            mp.announced[0].prefix,
            Prefix::V6(Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48))
        );
    }
    #[test]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "codec bounds or masks the value before narrowing to the protocol field width"
    )]
    fn mp_unreach_nlri_ipv6_addpath_decode() {
        use crate::capability::{Afi, Safi};
        use crate::nlri::{Ipv6Prefix, Prefix};
        // Build MP_UNREACH_NLRI with Add-Path-encoded IPv6 NLRI
        let mut value = Vec::new();
        value.extend_from_slice(&2u16.to_be_bytes()); // AFI IPv6
        value.push(1); // SAFI Unicast
        // Add-Path NLRI: path_id=7, 2001:db8:2::/48
        value.extend_from_slice(&7u32.to_be_bytes());
        value.push(48);
        value.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02]);
        let mut buf = Vec::new();
        buf.push(0x90); // flags: Optional + Extended Length
        buf.push(15); // type: MP_UNREACH_NLRI
        buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
        buf.extend_from_slice(&value);
        let decoded = decode_path_attributes(&buf, true, &[(Afi::Ipv6, Safi::Unicast)]).unwrap();
        let PathAttribute::MpUnreachNlri(mp) = &decoded[0] else {
            panic!("expected MpUnreachNlri");
        };
        assert_eq!(mp.withdrawn.len(), 1);
        assert_eq!(mp.withdrawn[0].path_id, 7);
        assert_eq!(
            mp.withdrawn[0].prefix,
            Prefix::V6(Ipv6Prefix::new("2001:db8:2::".parse().unwrap(), 48))
        );
    }
    #[test]
    fn mp_reach_addpath_only_applies_to_matching_family() {
        use crate::capability::{Afi, Safi};
        use crate::nlri::{Ipv6Prefix, Prefix};
        // Build plain (non-Add-Path) MP_REACH_NLRI for IPv6
        let mp = MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
            link_local_next_hop: None,
            announced: vec![NlriEntry {
                path_id: 0,
                prefix: Prefix::V6(Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48)),
            }],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        };
        let attrs = vec![PathAttribute::MpReachNlri(mp.clone())];
        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false).unwrap();
        // Add-Path enabled for IPv4 only — IPv6 should still decode as plain
        let decoded = decode_path_attributes(&buf, true, &[(Afi::Ipv4, Safi::Unicast)]).unwrap();
        assert_eq!(decoded[0], PathAttribute::MpReachNlri(mp));
    }
    // --- ORIGINATOR_ID tests ---
    #[test]
    fn decode_originator_id() {
        // flags=0x80 (optional), type=9, len=4, value=1.2.3.4
        let buf = [0x80, 0x09, 0x04, 1, 2, 3, 4];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(
            attrs[0],
            PathAttribute::OriginatorId(Ipv4Addr::new(1, 2, 3, 4))
        );
    }
    /// 32-byte IPv6 next-hop (global + link-local) round-trips through
    /// decode/encode without dropping the link-local. Regression for the
    /// pre-existing limitation where the decoder kept only the first
    /// 16 bytes and the encoder only emitted 16 bytes.
    #[test]
    fn mp_reach_ipv6_32byte_next_hop_roundtrip() {
        use crate::capability::{Afi, Safi};
        use crate::nlri::{Ipv6Prefix, Prefix};
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        let mp = MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6(global),
            link_local_next_hop: Some(link_local),
            announced: vec![NlriEntry {
                path_id: 0,
                prefix: Prefix::V6(Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48)),
            }],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        };
        let attr = PathAttribute::MpReachNlri(mp.clone());
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false).unwrap();
        // The attribute value should start with NH-Len=32, then the
        // 16-byte global, then the 16-byte link-local.
        // Walk header: flags(1) + type(1) + len(1 or 3) + value.
        let extended = (buf[0] & 0x10) != 0;
        let value_off = if extended { 4 } else { 3 };
        // value layout: AFI(2) + SAFI(1) + NH-Len(1) + NH bytes + Reserved(1) + NLRI
        assert_eq!(buf[value_off + 3], 32, "NH-Len must be 32 for global+LL");
        assert_eq!(&buf[value_off + 4..value_off + 20], &global.octets());
        assert_eq!(
            &buf[value_off + 20..value_off + 36],
            &link_local.octets(),
            "encoded link-local bytes must match the input"
        );
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        let PathAttribute::MpReachNlri(dec) = &decoded[0] else {
            panic!("expected MpReachNlri");
        };
        assert_eq!(dec.next_hop, IpAddr::V6(global));
        assert_eq!(dec.link_local_next_hop, Some(link_local));
    }
    /// Audit follow-up: a peer sending an `MP_REACH` for `FlowSpec`
    /// (SAFI 133) with a non-zero `NH-Len` is malformed per RFC
    /// 8955 §6.1 — the decoder must reject so the rest of the
    /// pipeline never sees a misshapen `FlowSpec` advertisement.
    /// Logic exists at `decode_mp_reach_nlri` but had no direct
    /// regression test; adding one cheaply pins the wire-level
    /// guarantee that complements the validate-time skip.
    #[test]
    fn mp_reach_flowspec_rejects_nonzero_nh_len() {
        // AFI=1 (IPv4), SAFI=133 (FlowSpec), NH-Len=4, NH=10.0.0.1,
        // Reserved=0, then a single component-1 prefix (192.168.1.0/24).
        let value: &[u8] = &[
            0x00, 0x01, // AFI = IPv4
            0x85, // SAFI = 133 (FlowSpec)
            0x04, // NH-Len = 4 (illegal for FlowSpec — must be 0)
            10, 0, 0, 1,    // NH bytes
            0x00, // Reserved
            // FlowSpec NLRI: length(1) + component type 1 + prefix
            0x07, 0x01, 0x18, 192, 168, 1,
        ];
        // attribute header: flags(0x80 = optional) + type(14 =
        // MP_REACH) + len(value.len() as u8) + value
        let mut attr = vec![0x80, 14, u8::try_from(value.len()).unwrap()];
        attr.extend_from_slice(value);
        let err = decode_path_attributes(&attr, true, &[]).unwrap_err();
        match err {
            DecodeError::MalformedField { detail, .. } => {
                assert!(
                    detail.contains("FlowSpec next-hop length"),
                    "expected FlowSpec NH-Len rejection, got: {detail}"
                );
            }
            other => panic!("expected MalformedField, got {other:?}"),
        }
    }
    #[test]
    fn originator_id_roundtrip() {
        let attr = PathAttribute::OriginatorId(Ipv4Addr::new(10, 0, 0, 1));
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded, vec![attr]);
    }
    #[test]
    fn originator_id_wrong_length() {
        // 3 bytes instead of 4
        let buf = [0x80, 0x09, 0x03, 1, 2, 3];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UpdateAttributeError {
                subcode: 5, // ATTRIBUTE_LENGTH_ERROR
                ..
            }
        ));
    }
    #[test]
    fn originator_id_wrong_flags() {
        // flags=0x40 (transitive) — should be 0x80 (optional)
        let buf = [0x40, 0x09, 0x04, 1, 2, 3, 4];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UpdateAttributeError {
                subcode: 4, // ATTRIBUTE_FLAGS_ERROR
                ..
            }
        ));
    }
    // --- CLUSTER_LIST tests ---
    #[test]
    fn decode_cluster_list() {
        // flags=0x80 (optional), type=10, len=8, two cluster IDs
        let buf = [0x80, 0x0A, 0x08, 1, 2, 3, 4, 5, 6, 7, 8];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(
            attrs[0],
            PathAttribute::ClusterList(vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8),])
        );
    }
    #[test]
    fn cluster_list_roundtrip() {
        let attr = PathAttribute::ClusterList(vec![
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
        ]);
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded, vec![attr]);
    }
    #[test]
    fn cluster_list_wrong_length() {
        // 5 bytes — not a multiple of 4
        let buf = [0x80, 0x0A, 0x05, 1, 2, 3, 4, 5];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UpdateAttributeError {
                subcode: 5, // ATTRIBUTE_LENGTH_ERROR
                ..
            }
        ));
    }
    // -----------------------------------------------------------------------
    // Large Communities (RFC 8092)
    // -----------------------------------------------------------------------
    #[test]
    fn large_community_display() {
        let lc = LargeCommunity::new(65001, 100, 200);
        assert_eq!(lc.to_string(), "65001:100:200");
    }
    #[test]
    fn large_community_type_code_and_flags() {
        let attr = PathAttribute::LargeCommunities(vec![LargeCommunity::new(1, 2, 3)]);
        assert_eq!(attr.type_code(), attr_type::LARGE_COMMUNITIES);
        assert_eq!(attr.flags(), attr_flags::OPTIONAL | attr_flags::TRANSITIVE);
    }
    #[test]
    fn decode_large_community_single() {
        // flags=0xC0 (Optional|Transitive), type=32, length=12
        let mut buf = vec![0xC0, 32, 12];
        buf.extend_from_slice(&65001u32.to_be_bytes());
        buf.extend_from_slice(&100u32.to_be_bytes());
        buf.extend_from_slice(&200u32.to_be_bytes());
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(
            attrs[0],
            PathAttribute::LargeCommunities(vec![LargeCommunity::new(65001, 100, 200)])
        );
    }
    #[test]
    fn decode_large_community_multiple() {
        // Two LCs: 24 bytes total
        let mut buf = vec![0xC0, 32, 24];
        for (g, l1, l2) in [(65001u32, 100u32, 200u32), (65002, 300, 400)] {
            buf.extend_from_slice(&g.to_be_bytes());
            buf.extend_from_slice(&l1.to_be_bytes());
            buf.extend_from_slice(&l2.to_be_bytes());
        }
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(
            attrs[0],
            PathAttribute::LargeCommunities(vec![
                LargeCommunity::new(65001, 100, 200),
                LargeCommunity::new(65002, 300, 400),
            ])
        );
    }
    #[test]
    fn decode_large_community_duplicates_preserves_first_seen_order() {
        // RFC 8092 §3: a receiver silently removes redundant values.
        // Load-bearing: removing receive-side dedup returns [b, a, a];
        // reversing/sorting the retained values returns [a, b].
        let a = LargeCommunity::new(65001, 100, 200);
        let b = LargeCommunity::new(65002, 300, 400);
        let mut buf = vec![0xC0, 32, 36];
        for community in [b, a, a] {
            buf.extend_from_slice(&community.global_admin.to_be_bytes());
            buf.extend_from_slice(&community.local_data1.to_be_bytes());
            buf.extend_from_slice(&community.local_data2.to_be_bytes());
        }

        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs, vec![PathAttribute::LargeCommunities(vec![b, a])]);
    }
    #[test]
    fn decode_large_community_bad_length() {
        // 10 bytes — not a multiple of 12
        let buf = [0xC0, 32, 10, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UpdateAttributeError {
                subcode: 5, // ATTRIBUTE_LENGTH_ERROR
                ..
            }
        ));
    }
    #[test]
    fn decode_large_community_empty_rejected() {
        // Zero-length LARGE_COMMUNITIES is rejected (must carry at least one community).
        let buf = [0xC0, 32, 0];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UpdateAttributeError {
                subcode: 5, // ATTRIBUTE_LENGTH_ERROR
                ..
            }
        ));
    }
    #[test]
    fn large_community_roundtrip() {
        let lcs = vec![
            LargeCommunity::new(65001, 100, 200),
            LargeCommunity::new(0, u32::MAX, 42),
        ];
        let attr = PathAttribute::LargeCommunities(lcs.clone());
        let mut buf = Vec::new();
        encode_path_attributes(&[attr], &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], PathAttribute::LargeCommunities(lcs));
    }
    #[test]
    fn encode_large_community_duplicates_preserves_first_seen_order() {
        // RFC 8092 §3: duplicate values must not be transmitted.
        // Load-bearing: removing encode-side dedup changes the raw length to
        // 36 and emits a third value; reversing/sorting emits [a, b].
        let a = LargeCommunity::new(65001, 100, 200);
        let b = LargeCommunity::new(65002, 300, 400);
        let attr = PathAttribute::LargeCommunities(vec![b, a, a]);
        let mut buf = Vec::new();
        encode_path_attributes(&[attr], &mut buf, true, false).unwrap();

        let mut expected = vec![0xC0, 32, 24];
        for community in [b, a] {
            expected.extend_from_slice(&community.global_admin.to_be_bytes());
            expected.extend_from_slice(&community.local_data1.to_be_bytes());
            expected.extend_from_slice(&community.local_data2.to_be_bytes());
        }
        assert_eq!(buf, expected);

        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded, vec![PathAttribute::LargeCommunities(vec![b, a])]);
    }
    #[test]
    fn large_community_expected_flags_validated() {
        // Wrong flags: TRANSITIVE only (0x40) instead of OPTIONAL|TRANSITIVE (0xC0)
        let mut buf = vec![0x40, 32, 12];
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(&3u32.to_be_bytes());
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UpdateAttributeError {
                subcode: 4, // ATTRIBUTE_FLAGS_ERROR
                ..
            }
        ));
    }
    // -----------------------------------------------------------------------
    // AsPath::to_aspath_string()
    // -----------------------------------------------------------------------
    #[test]
    fn aspath_string_sequence() {
        let p = AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65001, 65002, 65003])],
        };
        assert_eq!(p.to_aspath_string(), "65001 65002 65003");
    }
    #[test]
    fn aspath_string_set() {
        let p = AsPath {
            segments: vec![AsPathSegment::AsSet(vec![65003, 65004])],
        };
        assert_eq!(p.to_aspath_string(), "{65003 65004}");
    }
    #[test]
    fn aspath_string_mixed() {
        let p = AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![65001, 65002]),
                AsPathSegment::AsSet(vec![65003, 65004]),
            ],
        };
        assert_eq!(p.to_aspath_string(), "65001 65002 {65003 65004}");
    }
    #[test]
    fn aspath_string_empty() {
        let p = AsPath { segments: vec![] };
        assert_eq!(p.to_aspath_string(), "");
    }
    /// Regression: SAFI 70 (EVPN) is only valid under AFI 25 (L2VPN).
    /// Other AFIs with SAFI=Evpn must be rejected explicitly so the
    /// unicast NLRI fallthrough never tries to parse the typed EVPN
    /// payload as a prefix list.
    #[test]
    fn mp_reach_nlri_rejects_evpn_safi_with_non_l2vpn_afi() {
        // AFI=Ipv4 (1), SAFI=Evpn (70), NH-len=4, NH=192.0.2.1, reserved=0,
        // followed by an arbitrary EVPN-shaped byte (route type 3, len 0).
        let bytes = vec![
            0x00, 0x01, // AFI = Ipv4
            70,   // SAFI = Evpn
            4, 192, 0, 2, 1, // NH len + NH
            0, // reserved
            3, 0, // EVPN-style NLRI (route type 3, length 0)
        ];
        let err = decode_mp_reach_nlri(&bytes, &[], &mut 0).unwrap_err();
        match err {
            DecodeError::MalformedField { detail, .. } => {
                assert!(
                    detail.contains("unsupported AFI/SAFI 1/70"),
                    "unexpected detail: {detail}"
                );
            }
            other => panic!("expected MalformedField, got {other:?}"),
        }
    }
    #[test]
    fn mp_unreach_nlri_rejects_evpn_safi_with_non_l2vpn_afi() {
        let bytes = vec![
            0x00, 0x02, // AFI = Ipv6
            70,   // SAFI = Evpn
            3, 0, // EVPN-style withdrawal (route type 3, length 0)
        ];
        let err = decode_mp_unreach_nlri(&bytes, &[], &mut 0).unwrap_err();
        match err {
            DecodeError::MalformedField { detail, .. } => {
                assert!(
                    detail.contains("unsupported AFI/SAFI 2/70"),
                    "unexpected detail: {detail}"
                );
            }
            other => panic!("expected MalformedField, got {other:?}"),
        }
    }
    #[test]
    fn mp_reach_labeled_attribute_roundtrip() {
        let nlri = labeled_nlri(100);
        let mp = MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::LabeledUnicast,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            vpn_announced: vec![],
            labeled_announced: vec![labeled_entry(0, nlri.clone())],
            rtc_announced: vec![],
        };
        let attr = PathAttribute::MpReachNlri(mp.clone());
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).expect("decode labeled MP_REACH");
        assert_eq!(decoded, vec![PathAttribute::MpReachNlri(mp)]);
        let PathAttribute::MpReachNlri(decoded_mp) = &decoded[0] else {
            panic!("not MP_REACH after decode");
        };
        assert_eq!(decoded_mp.next_hop, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(decoded_mp.labeled_announced, vec![labeled_entry(0, nlri)]);
        assert_eq!(decoded_mp.labeled_announced[0].nlri.labels[0].label, 100);
        assert!(decoded_mp.announced.is_empty());
    }

    /// LAN-190: an IPv6 labeled-unicast `MP_REACH` carrying an RFC 8950 §4 /
    /// RFC 2545 §3 two-address next-hop (global + link-local) must emit the
    /// 32-byte form and round-trip the link-local half, so a route reflector
    /// re-advertising the route preserves labeled IPv6 link-local forwarding.
    #[test]
    fn mp_reach_labeled_v6_link_local_next_hop_roundtrip() {
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        let nlri = labeled_v6_nlri(100);
        let mp = MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::LabeledUnicast,
            next_hop: IpAddr::V6(global),
            link_local_next_hop: Some(link_local),
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            vpn_announced: vec![],
            labeled_announced: vec![labeled_entry(0, nlri.clone())],
            rtc_announced: vec![],
        };
        let attr = PathAttribute::MpReachNlri(mp.clone());
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false).unwrap();
        // Value layout after the 3-byte attribute header: AFI(2) SAFI(1)
        // NH-Len(1); NH-Len must be 32 (global + link-local), not 16.
        assert_eq!(
            buf[6], 32,
            "labeled IPv6 two-address next-hop must be 32 bytes"
        );
        let decoded = decode_path_attributes(&buf, true, &[]).expect("decode labeled v6 MP_REACH");
        let PathAttribute::MpReachNlri(decoded_mp) = &decoded[0] else {
            panic!("not MP_REACH after decode");
        };
        assert_eq!(decoded_mp.next_hop, IpAddr::V6(global));
        assert_eq!(
            decoded_mp.link_local_next_hop,
            Some(link_local),
            "labeled IPv6 link-local next-hop must survive encode/decode"
        );
        assert_eq!(decoded, vec![PathAttribute::MpReachNlri(mp)]);
    }

    /// RFC 8277 §2.4: a labeled-unicast withdraw carries one ignored
    /// 3-octet compatibility field, not a label stack — the decoded entry
    /// has empty `labels` and re-encode emits 0x800000.
    #[test]
    fn mp_unreach_labeled_v6_attribute_roundtrip() {
        let mut nlri = labeled_v6_nlri(0);
        nlri.labels.clear();
        let mp = MpUnreachNlri {
            afi: Afi::Ipv6,
            safi: Safi::LabeledUnicast,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: vec![],
            bgpls_withdrawn: vec![],
            vpn_withdrawn: vec![],
            labeled_withdrawn: vec![labeled_entry(0, nlri.clone())],
            rtc_withdrawn: vec![],
        };
        let attr = PathAttribute::MpUnreachNlri(mp.clone());
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).expect("decode labeled MP_UNREACH");
        assert_eq!(decoded, vec![PathAttribute::MpUnreachNlri(mp)]);
        let PathAttribute::MpUnreachNlri(decoded_mp) = &decoded[0] else {
            panic!("not MP_UNREACH after decode");
        };
        assert_eq!(decoded_mp.labeled_withdrawn, vec![labeled_entry(0, nlri)]);
        assert!(decoded_mp.labeled_withdrawn[0].nlri.labels.is_empty());
    }

    #[test]
    fn mp_reach_labeled_addpath_roundtrip() {
        // RFC 7911 for SAFI 4: each NLRI carries a 4-octet path ID when
        // the family is in the negotiated Add-Path set — both encode and
        // decode dispatch on `add_path_families` / `add_path_mp`.
        let mp = MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::LabeledUnicast,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            vpn_announced: vec![],
            labeled_announced: vec![
                labeled_entry(1, labeled_nlri(100)),
                labeled_entry(2, labeled_nlri(200)),
            ],
            rtc_announced: vec![],
        };
        let attr = PathAttribute::MpReachNlri(mp.clone());
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, true).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[(Afi::Ipv4, Safi::LabeledUnicast)])
            .expect("decode labeled Add-Path MP_REACH");
        assert_eq!(decoded, vec![PathAttribute::MpReachNlri(mp)]);
    }

    #[test]
    fn mp_unreach_labeled_addpath_roundtrip() {
        let mut nlri = labeled_v6_nlri(0);
        nlri.labels.clear();
        let mp = MpUnreachNlri {
            afi: Afi::Ipv6,
            safi: Safi::LabeledUnicast,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: vec![],
            bgpls_withdrawn: vec![],
            vpn_withdrawn: vec![],
            labeled_withdrawn: vec![labeled_entry(7, nlri)],
            rtc_withdrawn: vec![],
        };
        let attr = PathAttribute::MpUnreachNlri(mp.clone());
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, true).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[(Afi::Ipv6, Safi::LabeledUnicast)])
            .expect("decode labeled Add-Path MP_UNREACH");
        assert_eq!(decoded, vec![PathAttribute::MpUnreachNlri(mp)]);
    }
    #[test]
    fn mp_reach_nlri_rejects_multicast_before_prefix_decode() {
        // AFI=Ipv4 (1), SAFI=Multicast (2). The NLRI carries prefix_len=40,
        // which would be an IPv4 prefix-decode error if the unsupported family
        // fell through to unicast `Prefix` parsing. The expected error is the
        // family classifier instead.
        let bytes = vec![
            0x00, 0x01, // AFI = Ipv4
            2,    // SAFI = Multicast
            4, 192, 0, 2, 1,  // NH len + NH
            0,  // reserved
            40, // invalid IPv4 prefix length if parsed as unicast
            10, 0, 0, 0, 0,
        ];
        let err = decode_mp_reach_nlri(&bytes, &[], &mut 0).unwrap_err();
        match err {
            DecodeError::MalformedField { detail, .. } => {
                assert!(
                    detail.contains("unsupported AFI/SAFI 1/2"),
                    "unexpected detail: {detail}"
                );
                assert!(
                    !detail.contains("prefix length"),
                    "unsupported family must reject before prefix decode: {detail}"
                );
            }
            other => panic!("expected MalformedField, got {other:?}"),
        }
    }
    #[test]
    fn mp_unreach_nlri_rejects_multicast_before_prefix_decode() {
        // AFI=Ipv6 (2), SAFI=Multicast (2), followed by prefix_len=129.
        // The family guard must reject before the IPv6 unicast decoder runs.
        let bytes = vec![
            0x00, 0x02, // AFI = Ipv6
            2,    // SAFI = Multicast
            129,  // invalid IPv6 prefix length if parsed as unicast
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let err = decode_mp_unreach_nlri(&bytes, &[], &mut 0).unwrap_err();
        match err {
            DecodeError::MalformedField { detail, .. } => {
                assert!(
                    detail.contains("unsupported AFI/SAFI 2/2"),
                    "unexpected detail: {detail}"
                );
                assert!(
                    !detail.contains("prefix length"),
                    "unsupported family must reject before prefix decode: {detail}"
                );
            }
            other => panic!("expected MalformedField, got {other:?}"),
        }
    }
    #[test]
    fn mp_reach_nlri_rejects_l2vpn_flowspec_at_family_gate() {
        let bytes = vec![
            0x00, 0x19, // AFI = L2VPN
            133,  // SAFI = FlowSpec
            0,    // NH-Len = 0
            0,    // reserved
        ];
        let err = decode_mp_reach_nlri(&bytes, &[], &mut 0).unwrap_err();
        match err {
            DecodeError::MalformedField { detail, .. } => {
                assert!(
                    detail.contains("unsupported AFI/SAFI 25/133"),
                    "unexpected detail: {detail}"
                );
            }
            other => panic!("expected MalformedField, got {other:?}"),
        }
    }
    #[test]
    fn mp_unreach_nlri_rejects_l2vpn_flowspec_at_family_gate() {
        let bytes = vec![
            0x00, 0x19, // AFI = L2VPN
            133,  // SAFI = FlowSpec
        ];
        let err = decode_mp_unreach_nlri(&bytes, &[], &mut 0).unwrap_err();
        match err {
            DecodeError::MalformedField { detail, .. } => {
                assert!(
                    detail.contains("unsupported AFI/SAFI 25/133"),
                    "unexpected detail: {detail}"
                );
            }
            other => panic!("expected MalformedField, got {other:?}"),
        }
    }
    #[test]
    fn pmsi_tunnel_path_attribute_round_trips_through_dispatch() {
        // Encode a multi-attribute payload that includes a PMSI Tunnel
        // alongside the typical path attribute set so the dispatcher
        // (and extended-length / flags / type-code paths) is exercised
        // end-to-end.
        let pmsi =
            crate::pmsi::PmsiTunnel::for_evpn_ingress_replication(100, "10.0.0.1".parse().unwrap());
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
            PathAttribute::LocalPref(100),
            PathAttribute::PmsiTunnel(pmsi.clone()),
        ];
        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false).unwrap();
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded, attrs);
        // Verify the encoded PMSI uses Optional+Transitive flags
        // (RFC 6514 §5) and type code 22.
        let pmsi_decoded = decoded
            .iter()
            .find_map(|a| match a {
                PathAttribute::PmsiTunnel(p) => Some(p),
                _ => None,
            })
            .expect("PMSI present");
        assert_eq!(pmsi_decoded, &pmsi);
        assert_eq!(
            PathAttribute::PmsiTunnel(pmsi).flags(),
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
        );
    }
    #[test]
    fn pmsi_tunnel_decode_attribute_with_truncated_value_is_malformed() {
        // 4 bytes of value (need ≥5: flags+type+3-octet label).
        let buf = [
            0xC0, // optional + transitive
            22,   // PMSI Tunnel type code
            0x04, // length = 4
            0x00, 0x06, 0x00, 0x00,
        ];
        let err = decode_path_attributes(&buf, true, &[]).unwrap_err();
        assert!(matches!(err, DecodeError::MalformedField { .. }));
    }
    // --- Only-to-Customer (RFC 9234 §5) tests ---
    #[test]
    fn only_to_customer_encode_decode_roundtrip() {
        for asn in [0u32, 65000, 65536, 4_200_000_000, u32::MAX] {
            let attrs = vec![PathAttribute::OnlyToCustomer(asn)];
            let mut buf = Vec::new();
            encode_path_attributes(&attrs, &mut buf, true, false).unwrap();
            // Wire shape: flags=0xC0, type=35, len=4, value=asn(be).
            assert_eq!(buf[0], attr_flags::OPTIONAL | attr_flags::TRANSITIVE);
            assert_eq!(buf[1], attr_type::ONLY_TO_CUSTOMER);
            assert_eq!(buf[2], 4);
            assert_eq!(&buf[3..7], &asn.to_be_bytes()[..]);
            let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
            assert_eq!(decoded.len(), 1);
            assert_eq!(decoded[0], PathAttribute::OnlyToCustomer(asn));
        }
    }
    #[test]
    fn only_to_customer_type_code_and_flags() {
        let attr = PathAttribute::OnlyToCustomer(65001);
        assert_eq!(attr.type_code(), 35);
        assert_eq!(attr.flags(), attr_flags::OPTIONAL | attr_flags::TRANSITIVE);
    }
    #[test]
    fn only_to_customer_malformed_length_stored_as_unknown() {
        // RFC 9234 §5 + RFC 7606: malformed-length OTC is recoverable —
        // preserved as Unknown(RawAttribute) with type_code 35 so transport
        // can apply treat-as-withdraw without the session-resetting
        // DecodeError path. Flags are correct (0xC0); only length varies.
        for bad_value in [
            &[0xAA, 0xBB, 0xCC][..],                               // len 3
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE][..],                   // len 5
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11][..], // len 8
        ] {
            let mut buf = vec![
                attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                attr_type::ONLY_TO_CUSTOMER,
                u8::try_from(bad_value.len()).unwrap(),
            ];
            buf.extend_from_slice(bad_value);
            let decoded = decode_path_attributes(&buf, true, &[])
                .expect("malformed-length OTC must NOT be a fatal DecodeError");
            assert_eq!(decoded.len(), 1);
            match &decoded[0] {
                PathAttribute::Unknown(raw) => {
                    assert_eq!(raw.type_code, attr_type::ONLY_TO_CUSTOMER);
                    assert_eq!(raw.data.as_ref(), bad_value);
                    assert_eq!(raw.flags, attr_flags::OPTIONAL | attr_flags::TRANSITIVE);
                }
                other => panic!(
                    "len {}: expected Unknown(type_code=35), got {other:?}",
                    bad_value.len()
                ),
            }
        }
    }
    #[test]
    fn only_to_customer_bad_flags_returns_attribute_flags_error() {
        // Correct length (4), wrong flags — must be subcode 4
        // ATTRIBUTE_FLAGS_ERROR (handled by the shared expected_flags()
        // check before type dispatch).
        for bad_flags in [
            0x00u8,                 // no flags
            attr_flags::TRANSITIVE, // 0x40: missing Optional
            attr_flags::OPTIONAL,   // 0x80: missing Transitive
        ] {
            let buf = [
                bad_flags,
                attr_type::ONLY_TO_CUSTOMER,
                4, // length
                0x00,
                0x00,
                0xFD,
                0xE9, // asn = 65001
            ];
            let err = decode_path_attributes(&buf, true, &[]).expect_err(
                "bad-flags OTC must return ATTRIBUTE_FLAGS_ERROR, not Ok or other variant",
            );
            match err {
                DecodeError::UpdateAttributeError { subcode, .. } => {
                    assert_eq!(
                        subcode,
                        update_subcode::ATTRIBUTE_FLAGS_ERROR,
                        "bad flags {bad_flags:#04x}: expected subcode 4 ATTRIBUTE_FLAGS_ERROR"
                    );
                }
                other => panic!("expected UpdateAttributeError, got {other:?}"),
            }
        }
    }
    #[test]
    fn only_to_customer_partial_bit_preserved_via_unknown() {
        // RFC 4271 §5: a recognized optional-transitive attribute received
        // with Partial set MUST have Partial preserved on re-advertisement.
        // We achieve this by routing Partial-bearing OTC through the
        // `Unknown(RawAttribute)` arm — the typed `OnlyToCustomer(u32)`
        // path emits canonical 0xC0 and is reserved for locally-added or
        // received-with-canonical-flags OTC.
        //
        // Wire-shape sanity: flags = 0xE0 (Optional | Transitive | Partial),
        // length 4, ASN = 65000.
        let buf = [
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE | attr_flags::PARTIAL, // 0xE0
            attr_type::ONLY_TO_CUSTOMER,
            4,
            0x00,
            0x00,
            0xFD,
            0xE8, // asn = 65000
        ];
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded.len(), 1);
        match &decoded[0] {
            PathAttribute::Unknown(raw) => {
                assert_eq!(raw.type_code, attr_type::ONLY_TO_CUSTOMER);
                assert_eq!(
                    raw.flags,
                    attr_flags::OPTIONAL | attr_flags::TRANSITIVE | attr_flags::PARTIAL,
                    "Partial bit must survive decode for round-trip-faithful re-emission"
                );
                assert_eq!(raw.data.as_ref(), &[0x00, 0x00, 0xFD, 0xE8][..]);
            }
            other => panic!(
                "Partial-bearing OTC must decode to Unknown (so encode preserves \
                 Partial via the existing Unknown-encode path); got {other:?}"
            ),
        }
        // Round-trip: encoding the decoded Unknown must emit flags with
        // Partial set (the Unknown-encode arm OR's Partial into optional-
        // transitive flags, so 0xE0 → 0xE0).
        let mut reencoded = Vec::new();
        encode_path_attributes(&decoded, &mut reencoded, true, false).unwrap();
        assert_eq!(
            reencoded[0],
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE | attr_flags::PARTIAL,
            "re-encode must preserve Partial; lost-Partial violates RFC 4271 §5"
        );
        assert_eq!(reencoded[1], attr_type::ONLY_TO_CUSTOMER);
        assert_eq!(reencoded[2], 4);
        assert_eq!(&reencoded[3..7], &[0x00, 0x00, 0xFD, 0xE8][..]);
    }
    #[test]
    fn only_to_customer_locally_constructed_emits_canonical_flags() {
        // Locally-added OTC (PR2 E1/I3 will use this path) is built as
        // `OnlyToCustomer(u32)` and must emit canonical 0xC0 — no Partial.
        let attrs = vec![PathAttribute::OnlyToCustomer(65000)];
        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false).unwrap();
        assert_eq!(
            buf[0],
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            "locally-constructed OTC must emit 0xC0, never 0xE0"
        );
    }

    // -----------------------------------------------------------------
    // RFC 7606 revised error handling — decode_path_attributes_revised
    // -----------------------------------------------------------------
    fn attr_bytes(flags: u8, type_code: u8, value: &[u8]) -> Vec<u8> {
        let mut buf = vec![flags, type_code, u8::try_from(value.len()).unwrap()];
        buf.extend_from_slice(value);
        buf
    }
    fn valid_origin_bytes() -> Vec<u8> {
        attr_bytes(attr_flags::TRANSITIVE, attr_type::ORIGIN, &[0])
    }
    fn valid_as_path_bytes() -> Vec<u8> {
        // One 4-octet AS_SEQUENCE segment holding ASN 65001.
        attr_bytes(
            attr_flags::TRANSITIVE,
            attr_type::AS_PATH,
            &[2, 1, 0, 0, 0xFD, 0xE9],
        )
    }
    fn valid_next_hop_bytes() -> Vec<u8> {
        attr_bytes(attr_flags::TRANSITIVE, attr_type::NEXT_HOP, &[10, 0, 0, 2])
    }
    /// Craft `<valid ORIGIN, AS_PATH, NEXT_HOP> + extra` attribute bytes.
    fn valid_attrs_plus(extra: &[u8]) -> Vec<u8> {
        let mut buf = valid_origin_bytes();
        buf.extend(valid_as_path_bytes());
        buf.extend(valid_next_hop_bytes());
        buf.extend_from_slice(extra);
        buf
    }
    /// Load-bearing flag proof: removing Attribute 29 from `expected_flags`,
    /// or omitting its Partial-bit check, accepts one of these fixtures.
    #[test]
    fn revised_bgpls_attribute_enforces_exact_flags() {
        let value = [0x04, 0x47, 0, 1, 7]; // IGP Metric TLV, 1-byte value
        for bad_flags in [
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_flags::OPTIONAL | attr_flags::PARTIAL,
        ] {
            let decoded = decode_path_attributes_revised(
                &attr_bytes(bad_flags, attr_type::BGP_LS, &value),
                true,
                false,
                &[],
            )
            .unwrap();
            assert!(decoded.attributes.is_empty());
            assert_eq!(decoded.malformed.len(), 1);
            assert_eq!(decoded.malformed[0].type_code, attr_type::BGP_LS);
            assert_eq!(
                decoded.malformed[0].disposition,
                ErrorDisposition::TreatAsWithdraw
            );
            assert!(matches!(
                decoded.malformed[0].error,
                DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_FLAGS_ERROR,
                    ..
                }
            ));
        }
    }
    /// Load-bearing framing and disposition proof: bypassing the Attribute 29
    /// TLV parser accepts this value, while changing its RFC 9552 disposition
    /// to treat-as-withdraw fails the exact verdict below.
    #[test]
    fn revised_bgpls_attribute_truncated_tlv_is_attribute_discard() {
        // Recognized IGP Metric TLV 1095 declares four value octets but only
        // three remain inside the intact Attribute 29 boundary.
        let value = [0x04, 0x47, 0, 4, 0, 0, 7];
        let decoded = decode_path_attributes_revised(
            &attr_bytes(attr_flags::OPTIONAL, attr_type::BGP_LS, &value),
            true,
            false,
            &[],
        )
        .unwrap();
        assert!(decoded.attributes.is_empty());
        assert_eq!(decoded.malformed.len(), 1);
        assert_eq!(decoded.malformed[0].type_code, attr_type::BGP_LS);
        assert_eq!(
            decoded.malformed[0].disposition,
            ErrorDisposition::AttributeDiscard
        );
    }
    /// Load-bearing forward-compatibility proof: rejecting a structurally
    /// complete recognized TLV for a semantically impermissible value length,
    /// rejecting an unknown TLV, or failing to retain the raw Attribute 29
    /// payload makes the byte equality fail. Removing Attribute 29 flag
    /// recognition accepts the mutated-flags copy and fails the final verdict.
    #[test]
    fn bgpls_attribute_unknown_tlv_roundtrips_byte_for_byte() {
        let mut value = Vec::with_capacity(12);
        // Node Flag Bits TLV 1024 has a specified one-octet value. A complete
        // two-octet value is semantically impermissible, but RFC 9552 §8.2.2
        // forbids a propagator from treating that as malformed.
        value.extend_from_slice(&1024_u16.to_be_bytes());
        value.extend_from_slice(&2_u16.to_be_bytes());
        value.extend_from_slice(&[0xff, 0xff]);
        // Unknown TLVs remain opaque and propagatable under RFC 9552 §5.1.
        value.extend_from_slice(&65_000_u16.to_be_bytes());
        value.extend_from_slice(&2_u16.to_be_bytes());
        value.extend_from_slice(&[0xde, 0xad]);

        let mut encoded = vec![
            attr_flags::OPTIONAL | attr_flags::EXTENDED_LENGTH,
            attr_type::BGP_LS,
        ];
        encoded.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        encoded.extend_from_slice(&value);

        let decoded = decode_path_attributes(&encoded, true, &[]).unwrap();
        let [PathAttribute::Unknown(raw)] = decoded.as_slice() else {
            panic!("valid BGP-LS Attribute must remain opaque");
        };
        assert_eq!(raw.type_code, attr_type::BGP_LS);
        assert_eq!(raw.data.as_ref(), value);

        let mut reencoded = Vec::new();
        encode_path_attributes(&decoded, &mut reencoded, true, false).unwrap();
        assert_eq!(reencoded, encoded);

        let mut bad_flags = encoded;
        bad_flags[0] |= attr_flags::TRANSITIVE;
        let rejected = decode_path_attributes_revised(&bad_flags, true, false, &[]).unwrap();
        assert!(rejected.attributes.is_empty());
        assert_eq!(rejected.malformed.len(), 1);
        assert_eq!(
            rejected.malformed[0].disposition,
            ErrorDisposition::TreatAsWithdraw
        );
    }
    #[test]
    fn revised_malformed_med_is_treat_as_withdraw() {
        // RFC 7606 §7.4: MULTI_EXIT_DISC with length != 4 → treat-as-withdraw.
        let buf = valid_attrs_plus(&attr_bytes(
            attr_flags::OPTIONAL,
            attr_type::MULTI_EXIT_DISC,
            &[0, 0, 1],
        ));
        let decoded = decode_path_attributes_revised(&buf, true, false, &[]).unwrap();
        assert_eq!(decoded.attributes.len(), 3, "valid attributes must survive");
        assert_eq!(decoded.malformed.len(), 1);
        assert_eq!(decoded.malformed[0].type_code, attr_type::MULTI_EXIT_DISC);
        assert_eq!(
            decoded.malformed[0].disposition,
            ErrorDisposition::TreatAsWithdraw
        );
        // The legacy decoder still aborts on the same bytes.
        assert!(decode_path_attributes(&buf, true, &[]).is_err());
    }
    #[test]
    fn revised_malformed_communities_is_treat_as_withdraw() {
        // RFC 7606 §7.8: Community length not a non-zero multiple of 4.
        let buf = valid_attrs_plus(&attr_bytes(
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type::COMMUNITIES,
            &[0, 0, 0, 1, 2],
        ));
        let decoded = decode_path_attributes_revised(&buf, true, false, &[]).unwrap();
        assert_eq!(decoded.attributes.len(), 3);
        assert_eq!(decoded.malformed.len(), 1);
        assert_eq!(
            decoded.malformed[0].disposition,
            ErrorDisposition::TreatAsWithdraw
        );
    }
    #[test]
    fn revised_malformed_as_path_is_treat_as_withdraw_not_reset() {
        // RFC 7606 §7.2: a malformed AS_PATH is treat-as-withdraw — 7606
        // moved it OFF the session-reset ladder. Segment claims two ASNs
        // but carries bytes for one.
        let mut buf = valid_origin_bytes();
        buf.extend(attr_bytes(
            attr_flags::TRANSITIVE,
            attr_type::AS_PATH,
            &[2, 2, 0, 0, 0xFD, 0xE9],
        ));
        buf.extend(valid_next_hop_bytes());
        let decoded = decode_path_attributes_revised(&buf, true, false, &[]).unwrap();
        assert_eq!(decoded.attributes.len(), 2);
        assert_eq!(decoded.malformed.len(), 1);
        assert_eq!(decoded.malformed[0].type_code, attr_type::AS_PATH);
        assert_eq!(
            decoded.malformed[0].disposition,
            ErrorDisposition::TreatAsWithdraw
        );
    }
    /// Load-bearing RFC 9774 matrix: deleting the raw segment inspection
    /// makes every prohibited case clean/attribute-discard, while hard-coding
    /// either AS width makes a later set disappear from one matrix row.
    #[test]
    fn revised_rfc9774_prohibits_set_segments_in_as_path_and_as4_path() {
        let cases = [
            (
                "four-octet AS_PATH AS_SET",
                attr_type::AS_PATH,
                1,
                1,
                true,
                &[0, 0, 0xFD, 0xE9][..],
            ),
            (
                "two-octet AS_PATH AS_SET",
                attr_type::AS_PATH,
                1,
                1,
                false,
                &[0xFD, 0xE9],
            ),
            (
                "AS4_PATH AS_SET",
                attr_type::AS4_PATH,
                1,
                1,
                false,
                &[0, 0, 0xFD, 0xE9],
            ),
            (
                "AS4_PATH AS_CONFED_SET",
                attr_type::AS4_PATH,
                4,
                2,
                false,
                &[0, 0, 0xFD, 0xE9],
            ),
        ];
        for (name, type_code, segment_type, preceding_sequences, four_octet_as, asn) in cases {
            let mut value = Vec::new();
            for _ in 0..preceding_sequences {
                value.extend([2, 1]);
                value.extend(asn);
            }
            value.extend([segment_type, 1]);
            value.extend(asn);
            let flags = if type_code == attr_type::AS_PATH {
                attr_flags::TRANSITIVE
            } else {
                attr_flags::OPTIONAL | attr_flags::TRANSITIVE
            };
            let decoded = decode_path_attributes_revised(
                &attr_bytes(flags, type_code, &value),
                four_octet_as,
                false,
                &[],
            )
            .unwrap();
            assert!(
                decoded.malformed.iter().any(|malformed| {
                    malformed.type_code == type_code
                        && malformed.disposition == ErrorDisposition::TreatAsWithdraw
                }),
                "{name} must be treat-as-withdraw"
            );
        }

        let has_rfc9774_taw = |decoded: &RevisedAttributeDecode| {
            decoded.malformed.iter().any(|malformed| {
                malformed.type_code == attr_type::AS4_PATH
                    && malformed.disposition == ErrorDisposition::TreatAsWithdraw
            })
        };
        for (name, value) in [
            ("AS_SEQUENCE", &[2, 1, 0, 0, 0xFD, 0xE9][..]),
            ("truncated AS_SET", &[1, 2, 0, 0, 0xFD, 0xE9][..]),
            ("zero-length AS_SET", &[1, 0][..]),
        ] {
            let bytes = attr_bytes(
                attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                attr_type::AS4_PATH,
                value,
            );
            let decoded = decode_path_attributes_revised(&bytes, false, false, &[]).unwrap();
            assert!(
                !has_rfc9774_taw(&decoded),
                "{name} must not acquire an RFC 9774 verdict"
            );
        }
    }
    /// Load-bearing duplicate proof: moving the RFC 9774 inspection below
    /// duplicate discard leaves only `AttributeDiscard` and fails this test.
    #[test]
    fn revised_rfc9774_prohibited_later_duplicate_keeps_treat_as_withdraw() {
        let mut attrs = valid_as_path_bytes();
        attrs.extend(attr_bytes(
            attr_flags::TRANSITIVE,
            attr_type::AS_PATH,
            &[1, 1, 0, 0, 0xFD, 0xEA],
        ));
        let decoded = decode_path_attributes_revised(&attrs, true, false, &[]).unwrap();
        assert_eq!(decoded.malformed.len(), 2);
        assert!(
            decoded
                .malformed
                .iter()
                .any(|malformed| { malformed.disposition == ErrorDisposition::TreatAsWithdraw })
        );
        assert!(
            decoded
                .malformed
                .iter()
                .any(|malformed| { malformed.disposition == ErrorDisposition::AttributeDiscard })
        );
    }
    #[test]
    fn revised_malformed_aggregator_is_attribute_discard() {
        // RFC 7606 §7.7: AGGREGATOR length must be 8 under 4-octet-AS
        // negotiation; anything else is attribute-discard. The legacy
        // decoder passes AGGREGATOR through opaquely, so this check only
        // exists on the revised path.
        let buf = valid_attrs_plus(&attr_bytes(
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type::AGGREGATOR,
            &[0, 0, 0xFD, 0xE9, 10],
        ));
        let decoded = decode_path_attributes_revised(&buf, true, false, &[]).unwrap();
        assert_eq!(decoded.attributes.len(), 3);
        assert_eq!(decoded.malformed.len(), 1);
        assert_eq!(decoded.malformed[0].type_code, attr_type::AGGREGATOR);
        assert_eq!(
            decoded.malformed[0].disposition,
            ErrorDisposition::AttributeDiscard
        );
        // A correct-length AGGREGATOR still passes through untouched.
        let good = valid_attrs_plus(&attr_bytes(
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type::AGGREGATOR,
            &[0, 0, 0xFD, 0xE9, 10, 0, 0, 1],
        ));
        let decoded = decode_path_attributes_revised(&good, true, false, &[]).unwrap();
        assert_eq!(decoded.attributes.len(), 4);
        assert!(decoded.malformed.is_empty());
    }
    #[test]
    fn revised_malformed_atomic_aggregate_is_attribute_discard() {
        // RFC 7606 §7.6: ATOMIC_AGGREGATE length must be 0.
        let buf = valid_attrs_plus(&attr_bytes(
            attr_flags::TRANSITIVE,
            attr_type::ATOMIC_AGGREGATE,
            &[0xAB],
        ));
        let decoded = decode_path_attributes_revised(&buf, true, false, &[]).unwrap();
        assert_eq!(decoded.attributes.len(), 3);
        assert_eq!(decoded.malformed.len(), 1);
        assert_eq!(
            decoded.malformed[0].disposition,
            ErrorDisposition::AttributeDiscard
        );
    }
    /// Load-bearing error-context proof: reverting `attr_error_data` to choose
    /// width from value length emits `0x50, 2, 6, ...` and fails this equality.
    #[test]
    fn revised_rfc9774_extended_length_preserves_complete_attribute_header() {
        let bytes = vec![
            attr_flags::TRANSITIVE | attr_flags::EXTENDED_LENGTH,
            attr_type::AS_PATH,
            0,
            6,
            1,
            1,
            0,
            0,
            0xFD,
            0xE9,
        ];
        let decoded = decode_path_attributes_revised(&bytes, true, false, &[]).unwrap();
        let DecodeError::UpdateAttributeError { data, .. } = &decoded.malformed[0].error else {
            panic!("expected RFC 9774 attribute error");
        };
        assert_eq!(data, &bytes);
    }
    #[test]
    fn revised_flag_conflict_on_aggregator_is_treat_as_withdraw() {
        // RFC 7606 §3 (c): a flag conflict is treat-as-withdraw for every
        // attribute — §7.6/§7.7 attribute-discard covers length
        // malformations only. AGGREGATOR expects Optional|Transitive; send
        // Transitive only, with a CORRECT length.
        let buf = valid_attrs_plus(&attr_bytes(
            attr_flags::TRANSITIVE,
            attr_type::AGGREGATOR,
            &[0, 0, 0xFD, 0xE9, 10, 0, 0, 1],
        ));
        let decoded = decode_path_attributes_revised(&buf, true, false, &[]).unwrap();
        assert_eq!(decoded.malformed.len(), 1);
        assert_eq!(decoded.malformed[0].type_code, attr_type::AGGREGATOR);
        assert_eq!(
            decoded.malformed[0].disposition,
            ErrorDisposition::TreatAsWithdraw
        );
        // Flag conflict AND bad length: §3 (h) — the stronger action
        // (treat-as-withdraw) still wins over the length discard.
        let buf = valid_attrs_plus(&attr_bytes(
            attr_flags::TRANSITIVE,
            attr_type::AGGREGATOR,
            &[0, 0, 0xFD],
        ));
        let decoded = decode_path_attributes_revised(&buf, true, false, &[]).unwrap();
        assert_eq!(
            decoded.malformed[0].disposition,
            ErrorDisposition::TreatAsWithdraw
        );
    }
    #[test]
    fn revised_zero_length_communities_are_treat_as_withdraw() {
        // RFC 7606 §7.8 / §7.14: the length must be a NON-ZERO multiple of
        // 4 (Communities) / 8 (Extended Communities).
        for type_code in [attr_type::COMMUNITIES, attr_type::EXTENDED_COMMUNITIES] {
            let buf = valid_attrs_plus(&attr_bytes(
                attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                type_code,
                &[],
            ));
            // Legacy decoder now rejects the vacuous attribute outright.
            assert!(decode_path_attributes(&buf, true, &[]).is_err());
            let decoded = decode_path_attributes_revised(&buf, true, false, &[]).unwrap();
            assert_eq!(decoded.attributes.len(), 3);
            assert_eq!(decoded.malformed.len(), 1);
            assert_eq!(decoded.malformed[0].type_code, type_code);
            assert_eq!(
                decoded.malformed[0].disposition,
                ErrorDisposition::TreatAsWithdraw
            );
        }
    }
    #[test]
    fn revised_local_pref_disposition_depends_on_session_type() {
        // RFC 7606 §7.5: malformed LOCAL_PREF is attribute-discard from an
        // external neighbor, treat-as-withdraw from an internal one.
        let buf = valid_attrs_plus(&attr_bytes(
            attr_flags::TRANSITIVE,
            attr_type::LOCAL_PREF,
            &[0, 0, 1],
        ));
        let ibgp = decode_path_attributes_revised(&buf, true, true, &[]).unwrap();
        assert_eq!(
            ibgp.malformed[0].disposition,
            ErrorDisposition::TreatAsWithdraw
        );
        let ebgp = decode_path_attributes_revised(&buf, true, false, &[]).unwrap();
        assert_eq!(
            ebgp.malformed[0].disposition,
            ErrorDisposition::AttributeDiscard
        );
    }
    #[test]
    fn revised_flag_conflict_is_treat_as_withdraw() {
        // RFC 7606 §3 (c): Optional/Transitive bits conflicting with the
        // attribute's specified values → treat-as-withdraw.
        let mut buf = attr_bytes(
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type::ORIGIN,
            &[0],
        );
        buf.extend(valid_as_path_bytes());
        buf.extend(valid_next_hop_bytes());
        let decoded = decode_path_attributes_revised(&buf, true, false, &[]).unwrap();
        assert_eq!(decoded.attributes.len(), 2);
        assert_eq!(decoded.malformed.len(), 1);
        assert_eq!(decoded.malformed[0].type_code, attr_type::ORIGIN);
        assert_eq!(
            decoded.malformed[0].disposition,
            ErrorDisposition::TreatAsWithdraw
        );
    }
    #[test]
    fn revised_malformed_mp_reach_is_session_reset() {
        // RFC 7606 §7.11: a malformed MP_REACH_NLRI means the NLRI cannot
        // be located — session reset stays the only safe approach.
        let buf = valid_attrs_plus(&attr_bytes(
            attr_flags::OPTIONAL,
            attr_type::MP_REACH_NLRI,
            &[0, 1],
        ));
        assert!(decode_path_attributes_revised(&buf, true, false, &[]).is_err());
    }
    #[test]
    fn revised_duplicate_attribute_keeps_first_and_discards_rest() {
        // RFC 7606 §3 (g): occurrences other than the first are discarded
        // and the UPDATE continues to be processed.
        let mut buf = valid_attrs_plus(&attr_bytes(
            attr_flags::OPTIONAL,
            attr_type::MULTI_EXIT_DISC,
            &[0, 0, 0, 5],
        ));
        buf.extend(attr_bytes(
            attr_flags::OPTIONAL,
            attr_type::MULTI_EXIT_DISC,
            &[0, 0, 0, 9],
        ));
        let decoded = decode_path_attributes_revised(&buf, true, false, &[]).unwrap();
        assert!(decoded.attributes.contains(&PathAttribute::Med(5)));
        assert!(!decoded.attributes.contains(&PathAttribute::Med(9)));
        assert_eq!(decoded.malformed.len(), 1);
        assert_eq!(
            decoded.malformed[0].disposition,
            ErrorDisposition::AttributeDiscard
        );
    }
    #[test]
    fn revised_duplicate_mp_unreach_is_session_reset() {
        // RFC 7606 §3 (g): duplicate MP_REACH_NLRI / MP_UNREACH_NLRI is a
        // Malformed Attribute List NOTIFICATION.
        let mp_unreach = attr_bytes(attr_flags::OPTIONAL, attr_type::MP_UNREACH_NLRI, &[0, 2, 1]);
        let mut buf = mp_unreach.clone();
        buf.extend(mp_unreach);
        assert!(decode_path_attributes_revised(&buf, true, false, &[]).is_err());
    }
    #[test]
    fn revised_attribute_overrun_is_treat_as_withdraw_and_stops() {
        // RFC 7606 §4: an attribute length that overruns the section is
        // treat-as-withdraw; nothing beyond it can be parsed.
        let mut buf = valid_origin_bytes();
        buf.extend([attr_flags::OPTIONAL, attr_type::MULTI_EXIT_DISC, 200, 1, 2]);
        let decoded = decode_path_attributes_revised(&buf, true, false, &[]).unwrap();
        assert_eq!(
            decoded.attributes.len(),
            1,
            "attributes before the overrun survive"
        );
        assert_eq!(decoded.malformed.len(), 1);
        assert_eq!(decoded.malformed[0].type_code, attr_type::MULTI_EXIT_DISC);
        assert_eq!(
            decoded.malformed[0].disposition,
            ErrorDisposition::TreatAsWithdraw
        );
    }
    #[test]
    fn revised_clean_update_reports_nothing() {
        let buf = valid_attrs_plus(&[]);
        let decoded = decode_path_attributes_revised(&buf, true, false, &[]).unwrap();
        assert_eq!(decoded.attributes.len(), 3);
        assert!(decoded.malformed.is_empty());
        // Matches the legacy decoder on clean input.
        assert_eq!(
            decoded.attributes,
            decode_path_attributes(&buf, true, &[]).unwrap()
        );
    }

    fn as_path(sequence: &[u32]) -> PathAttribute {
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(sequence.to_vec())],
        })
    }

    fn encoded_attributes(mut bytes: &[u8]) -> Vec<(u8, u8, Vec<u8>)> {
        let mut attributes = Vec::new();
        while !bytes.is_empty() {
            let (flags, type_code, value) = split_next_attribute(&mut bytes).unwrap();
            attributes.push((flags, type_code, value.to_vec()));
        }
        attributes
    }

    /// Load-bearing shared-normalizer proof: deleting the normalizer call
    /// from either decoder leaves `AS_TRANS` or raw type 17 in that result and
    /// fails the equality/no-sidecar assertions.
    #[test]
    fn legacy_as4_path_reconstructs_in_both_decoders() {
        let mut bytes = attr_bytes(
            attr_flags::TRANSITIVE,
            attr_type::AS_PATH,
            &[2, 3, 0xFB, 0xF4, 0xFD, 0xE8, 0x5B, 0xA0],
        );
        bytes.extend(attr_bytes(
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type::AS4_PATH,
            &[2, 2, 0, 0, 0xFD, 0xE8, 0xFA, 0x56, 0xEA, 0x01],
        ));
        let expected = vec![as_path(&[64_500, 65_000, 4_200_000_001])];

        assert_eq!(
            decode_path_attributes(&bytes, false, &[]).unwrap(),
            expected
        );
        let revised = decode_path_attributes_revised(&bytes, false, false, &[]).unwrap();
        assert_eq!(revised.attributes, expected);
        assert!(revised.malformed.is_empty());
        assert!(
            revised
                .attributes
                .iter()
                .all(|attribute| !matches!(attribute, PathAttribute::Unknown(raw) if matches!(raw.type_code, attr_type::AS4_PATH | attr_type::AS4_AGGREGATOR)))
        );
    }

    /// Load-bearing RFC count proof: changing `AS_SET` from one path position
    /// to member-counted/truncated drops the second set member below.
    #[test]
    fn legacy_as4_reconstruction_retains_complete_leading_as_set() {
        let mut bytes = attr_bytes(
            attr_flags::TRANSITIVE,
            attr_type::AS_PATH,
            &[1, 2, 0xFD, 0xE9, 0xFD, 0xEA, 2, 1, 0x5B, 0xA0],
        );
        bytes.extend(attr_bytes(
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type::AS4_PATH,
            &[2, 1, 0xFA, 0x56, 0xEA, 0x01],
        ));
        assert_eq!(
            decode_path_attributes(&bytes, false, &[]).unwrap(),
            vec![PathAttribute::AsPath(AsPath {
                segments: vec![
                    AsPathSegment::AsSet(vec![65_001, 65_002]),
                    AsPathSegment::AsSequence(vec![4_200_000_001]),
                ],
            })]
        );
    }

    /// Load-bearing segment-boundary proof: replacing whole segments instead
    /// of splitting at the RFC count boundary loses ASN 64501; flattening the
    /// result hides the two-segment invariant asserted here.
    #[test]
    fn legacy_as4_reconstruction_splits_sequence_at_count_boundary() {
        let mut bytes = attr_bytes(
            attr_flags::TRANSITIVE,
            attr_type::AS_PATH,
            &[2, 1, 0xFB, 0xF4, 2, 3, 0xFB, 0xF5, 0xFD, 0xE8, 0x5B, 0xA0],
        );
        bytes.extend(attr_bytes(
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type::AS4_PATH,
            &[2, 2, 0, 0, 0xFD, 0xE8, 0xFA, 0x56, 0xEA, 0x01],
        ));
        assert_eq!(
            decode_path_attributes(&bytes, false, &[]).unwrap(),
            vec![PathAttribute::AsPath(AsPath {
                segments: vec![
                    AsPathSegment::AsSequence(vec![64_500]),
                    AsPathSegment::AsSequence(vec![64_501, 65_000, 4_200_000_001]),
                ],
            })]
        );
    }

    /// Load-bearing RFC count guard: deleting `old_count < as4_count` makes
    /// the first row accept a longer compatibility path; changing `<` to `<=`
    /// makes the equal-count row retain `AS_TRANS` instead of replacing it.
    #[test]
    fn legacy_as4_reconstruction_count_guard_matrix() {
        let cases = [
            (
                "shorter ordinary path ignores AS4_PATH",
                &[2, 1, 0x5B, 0xA0][..],
                &[2, 2, 0, 0, 0xFD, 0xE8, 0xFA, 0x56, 0xEA, 0x01][..],
                vec![u32::from(crate::constants::AS_TRANS)],
            ),
            (
                "equal counts replace ordinary path",
                &[2, 2, 0xFD, 0xE8, 0x5B, 0xA0][..],
                &[2, 2, 0, 0, 0xFD, 0xE8, 0xFA, 0x56, 0xEA, 0x01][..],
                vec![65_000, 4_200_000_001],
            ),
        ];
        for (name, ordinary, as4, expected) in cases {
            let mut bytes = attr_bytes(attr_flags::TRANSITIVE, attr_type::AS_PATH, ordinary);
            bytes.extend(attr_bytes(
                attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                attr_type::AS4_PATH,
                as4,
            ));
            assert_eq!(
                decode_path_attributes(&bytes, false, &[]).unwrap(),
                vec![as_path(&expected)],
                "{name}"
            );
        }
    }

    /// Load-bearing NEW-to-NEW proof: retaining compatibility sidecars adds
    /// types 17/18 or overwrites the canonical attributes and fails this
    /// exact two-attribute result.
    #[test]
    fn four_octet_peer_discards_as4_compatibility_attributes() {
        let mut bytes = attr_bytes(
            attr_flags::TRANSITIVE,
            attr_type::AS_PATH,
            &[2, 1, 0xFA, 0x56, 0xEA, 0x01],
        );
        bytes.extend(attr_bytes(
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type::AS4_PATH,
            &[2, 1, 0, 0, 0xFD, 0xE8],
        ));
        bytes.extend(attr_bytes(
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type::AGGREGATOR,
            &[0, 0, 0xFD, 0xE8, 10, 0, 0, 1],
        ));
        bytes.extend(attr_bytes(
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type::AS4_AGGREGATOR,
            &[0xFA, 0x56, 0xEA, 0x01, 10, 0, 0, 2],
        ));
        let expected = vec![
            as_path(&[4_200_000_001]),
            PathAttribute::Aggregator(Aggregator {
                asn: 65_000,
                router_id: Ipv4Addr::new(10, 0, 0, 1),
                partial: false,
            }),
        ];
        assert_eq!(decode_path_attributes(&bytes, true, &[]).unwrap(), expected);
        let revised = decode_path_attributes_revised(&bytes, true, false, &[]).unwrap();
        assert_eq!(revised.attributes, expected);
        assert_eq!(revised.malformed.len(), 2);
        assert!(revised.malformed.iter().all(|malformed| {
            matches!(
                malformed.type_code,
                attr_type::AS4_PATH | attr_type::AS4_AGGREGATOR
            ) && malformed.disposition == ErrorDisposition::AttributeDiscard
        }));
    }

    /// Load-bearing RFC 7606 proof: skipping sidecar value validation makes
    /// these malformed types disappear silently; changing their disposition
    /// away from `AttributeDiscard` fails the exact verdicts.
    #[test]
    fn malformed_as4_compatibility_values_are_attribute_discard() {
        let mut bytes = attr_bytes(
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type::AS4_PATH,
            &[2, 2, 0, 0, 0xFD, 0xE8],
        );
        bytes.extend(attr_bytes(
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type::AS4_AGGREGATOR,
            &[0, 0, 0xFD, 0xE8, 10, 0, 0],
        ));
        assert!(decode_path_attributes(&bytes, false, &[]).is_err());
        for four_octet_as in [false, true] {
            let revised =
                decode_path_attributes_revised(&bytes, four_octet_as, false, &[]).unwrap();
            assert!(revised.attributes.is_empty());
            assert_eq!(revised.malformed.len(), 2);
            assert!(revised.malformed.iter().all(|malformed| {
                matches!(
                    malformed.type_code,
                    attr_type::AS4_PATH | attr_type::AS4_AGGREGATOR
                ) && malformed.disposition == ErrorDisposition::AttributeDiscard
            }));
        }
    }

    /// Load-bearing flags proof: deleting types 17/18 from `expected_flags`
    /// makes these compatibility attributes clean; deleting the flag-error
    /// `max(TreatAsWithdraw)` downgrade leaves only `AttributeDiscard`.
    #[test]
    fn as4_compatibility_flag_conflicts_are_treat_as_withdraw() {
        let cases = [
            (
                attr_type::AS4_PATH,
                attr_flags::TRANSITIVE,
                &[2, 1, 0, 0, 0xFD, 0xE8][..],
            ),
            (
                attr_type::AS4_AGGREGATOR,
                attr_flags::OPTIONAL,
                &[0, 0, 0xFD, 0xE8, 10, 0, 0, 1][..],
            ),
        ];
        for (type_code, flags, value) in cases {
            let decoded = decode_path_attributes_revised(
                &attr_bytes(flags, type_code, value),
                false,
                false,
                &[],
            )
            .unwrap();
            assert!(decoded.attributes.is_empty());
            assert_eq!(decoded.malformed.len(), 1);
            assert_eq!(decoded.malformed[0].type_code, type_code);
            assert_eq!(
                decoded.malformed[0].disposition,
                ErrorDisposition::TreatAsWithdraw
            );
        }
    }

    /// Load-bearing strict-parser matrix: weakening any minimum/even/framing/
    /// count/type check makes the corresponding malformed `AS4_PATH` vanish
    /// instead of producing `AttributeDiscard`.
    #[test]
    fn malformed_as4_path_strict_framing_matrix() {
        let cases = [
            ("short", &[][..], "expected an even value of at least 6"),
            (
                "odd",
                &[2, 1, 0, 0, 0, 1, 0][..],
                "expected an even value of at least 6",
            ),
            (
                "zero count",
                &[2, 0, 0, 0, 0, 0][..],
                "zero-length AS4_PATH segment",
            ),
            (
                "unknown type",
                &[5, 1, 0, 0, 0, 1][..],
                "unknown AS4_PATH segment type",
            ),
            (
                "truncated",
                &[2, 2, 0, 0, 0, 1][..],
                "AS4_PATH segment truncated",
            ),
        ];
        for (name, value, detail) in cases {
            let bytes = attr_bytes(
                attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                attr_type::AS4_PATH,
                value,
            );
            let revised = decode_path_attributes_revised(&bytes, false, false, &[]).unwrap();
            assert!(revised.attributes.is_empty(), "{name}");
            assert_eq!(revised.malformed.len(), 1, "{name}");
            assert_eq!(
                revised.malformed[0].disposition,
                ErrorDisposition::AttributeDiscard,
                "{name}"
            );
            assert!(
                revised.malformed[0].error.to_string().contains(detail),
                "{name}"
            );
        }
    }

    /// Load-bearing confederation sanitation proof: retaining type 3 puts its
    /// ASN into the canonical path; dropping the diagnostic makes the revised
    /// malformed assertion empty; discarding the whole `AS4_PATH` loses 4-byte
    /// ASN 4200000001.
    #[test]
    fn as4_path_confed_sequence_is_removed_and_observed() {
        let mut bytes = attr_bytes(
            attr_flags::TRANSITIVE,
            attr_type::AS_PATH,
            &[2, 2, 0xFD, 0xE8, 0x5B, 0xA0],
        );
        bytes.extend(attr_bytes(
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type::AS4_PATH,
            &[3, 1, 0, 0, 0xFD, 0xEA, 2, 1, 0xFA, 0x56, 0xEA, 0x01],
        ));
        let expected = vec![as_path(&[65_000, 4_200_000_001])];
        assert_eq!(
            decode_path_attributes(&bytes, false, &[]).unwrap(),
            expected
        );
        let revised = decode_path_attributes_revised(&bytes, false, false, &[]).unwrap();
        assert_eq!(revised.attributes, expected);
        assert_eq!(revised.malformed.len(), 1);
        assert_eq!(
            revised.malformed[0].disposition,
            ErrorDisposition::AttributeDiscard
        );
        assert!(
            revised.malformed[0]
                .error
                .to_string()
                .contains("AS_CONFED_SEQUENCE")
        );
    }

    /// Load-bearing legacy projection proof: removing type 17 emission makes
    /// the round-trip retain `AS_TRANS`; changing the legacy placeholder or
    /// leaking type 17 to a modern peer fails the exact wire assertions;
    /// emitting it for an all-mappable path fails the final inventory check.
    #[test]
    fn legacy_encoder_emits_as4_path_only_when_needed() {
        let canonical = as_path(&[65_000, 4_200_000_001]);
        let mut encoded = Vec::new();
        encode_path_attributes(std::slice::from_ref(&canonical), &mut encoded, false, false)
            .unwrap();
        let wire = encoded_attributes(&encoded);
        assert_eq!(
            wire.iter()
                .map(|(_, type_code, _)| *type_code)
                .collect::<Vec<_>>(),
            vec![attr_type::AS_PATH, attr_type::AS4_PATH]
        );
        assert_eq!(wire[0].2, vec![2, 2, 0xFD, 0xE8, 0x5B, 0xA0]);
        assert_eq!(
            wire[1].2,
            vec![2, 2, 0, 0, 0xFD, 0xE8, 0xFA, 0x56, 0xEA, 0x01]
        );
        assert_eq!(
            decode_path_attributes(&encoded, false, &[]).unwrap(),
            vec![canonical.clone()]
        );

        let mut modern = Vec::new();
        encode_path_attributes(std::slice::from_ref(&canonical), &mut modern, true, false).unwrap();
        let modern_wire = encoded_attributes(&modern);
        assert_eq!(modern_wire.len(), 1);
        assert_eq!(modern_wire[0].1, attr_type::AS_PATH);
        assert_eq!(
            modern_wire[0].2,
            vec![2, 2, 0, 0, 0xFD, 0xE8, 0xFA, 0x56, 0xEA, 0x01]
        );
        assert_eq!(
            decode_path_attributes(&modern, true, &[]).unwrap(),
            vec![canonical]
        );

        let mut mapped = Vec::new();
        encode_path_attributes(&[as_path(&[64_500, 65_000])], &mut mapped, false, false).unwrap();
        assert_eq!(
            encoded_attributes(&mapped)
                .iter()
                .map(|(_, type_code, _)| *type_code)
                .collect::<Vec<_>>(),
            vec![attr_type::AS_PATH]
        );
    }

    /// Load-bearing AGGREGATOR projection proof: removing `AS_TRANS`/type18
    /// projection, losing Partial, leaking type18 for a mappable ASN, or
    /// corrupting the modern payload fails an exact canonical/wire assertion.
    #[test]
    fn aggregator_projection_preserves_partial() {
        let canonical = PathAttribute::Aggregator(Aggregator {
            asn: 4_200_000_001,
            router_id: Ipv4Addr::new(10, 0, 0, 1),
            partial: true,
        });
        assert_eq!(
            canonical.flags(),
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE | attr_flags::PARTIAL
        );
        let mut legacy = Vec::new();
        encode_path_attributes(std::slice::from_ref(&canonical), &mut legacy, false, false)
            .unwrap();
        let wire = encoded_attributes(&legacy);
        assert_eq!(wire.len(), 2);
        assert_eq!(wire[0].1, attr_type::AGGREGATOR);
        assert_eq!(&wire[0].2[..2], &crate::constants::AS_TRANS.to_be_bytes());
        assert_eq!(wire[1].1, attr_type::AS4_AGGREGATOR);
        assert!(
            wire.iter()
                .all(|(flags, _, _)| flags & attr_flags::PARTIAL != 0)
        );
        assert_eq!(
            decode_path_attributes(&legacy, false, &[]).unwrap(),
            vec![canonical.clone()]
        );

        let mut new_wire = Vec::new();
        encode_path_attributes(std::slice::from_ref(&canonical), &mut new_wire, true, false)
            .unwrap();
        let encoded_new = encoded_attributes(&new_wire);
        assert_eq!(encoded_new.len(), 1);
        assert_eq!(encoded_new[0].1, attr_type::AGGREGATOR);
        assert_eq!(encoded_new[0].2, vec![0xFA, 0x56, 0xEA, 0x01, 10, 0, 0, 1]);
        assert_eq!(
            decode_path_attributes(&new_wire, true, &[]).unwrap(),
            vec![canonical]
        );

        let mapped = PathAttribute::Aggregator(Aggregator {
            asn: 65_000,
            router_id: Ipv4Addr::new(10, 0, 0, 2),
            partial: false,
        });
        let mut mapped_legacy = Vec::new();
        encode_path_attributes(
            std::slice::from_ref(&mapped),
            &mut mapped_legacy,
            false,
            false,
        )
        .unwrap();
        let mapped_wire = encoded_attributes(&mapped_legacy);
        assert_eq!(mapped_wire.len(), 1);
        assert_eq!(mapped_wire[0].1, attr_type::AGGREGATOR);
        assert_eq!(mapped_wire[0].2, vec![0xFD, 0xE8, 10, 0, 0, 2]);
        assert_eq!(
            decode_path_attributes(&mapped_legacy, false, &[]).unwrap(),
            vec![mapped]
        );
    }

    /// Load-bearing `AGGREGATOR` ingress matrix proof: allowing type18 to
    /// replace a non-`AS_TRANS` type7, ignoring a type18-only attribute, or
    /// coupling type17 to an ordinary-only type7 fails an exact row below.
    #[test]
    fn aggregator_ingress_compatibility_matrix() {
        let mut non_trans = attr_bytes(
            attr_flags::TRANSITIVE,
            attr_type::AS_PATH,
            &[2, 1, 0x5B, 0xA0],
        );
        non_trans.extend(attr_bytes(
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type::AGGREGATOR,
            &[0xFD, 0xE8, 10, 0, 0, 2],
        ));
        non_trans.extend(attr_bytes(
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type::AS4_PATH,
            &[2, 1, 0xFA, 0x56, 0xEA, 0x01],
        ));
        non_trans.extend(attr_bytes(
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE | attr_flags::PARTIAL,
            attr_type::AS4_AGGREGATOR,
            &[0xFA, 0x56, 0xEA, 0x01, 10, 0, 0, 3],
        ));
        assert_eq!(
            decode_path_attributes(&non_trans, false, &[]).unwrap(),
            vec![
                as_path(&[u32::from(crate::constants::AS_TRANS)]),
                PathAttribute::Aggregator(Aggregator {
                    asn: 65_000,
                    router_id: Ipv4Addr::new(10, 0, 0, 2),
                    partial: false,
                }),
            ]
        );

        let only_as4 = attr_bytes(
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE | attr_flags::PARTIAL,
            attr_type::AS4_AGGREGATOR,
            &[0xFA, 0x56, 0xEA, 0x01, 10, 0, 0, 3],
        );
        assert_eq!(
            decode_path_attributes(&only_as4, false, &[]).unwrap(),
            vec![PathAttribute::Aggregator(Aggregator {
                asn: 4_200_000_001,
                router_id: Ipv4Addr::new(10, 0, 0, 3),
                partial: true,
            })]
        );

        let mut ordinary_only = attr_bytes(
            attr_flags::TRANSITIVE,
            attr_type::AS_PATH,
            &[2, 1, 0x5B, 0xA0],
        );
        ordinary_only.extend(attr_bytes(
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type::AGGREGATOR,
            &[0xFD, 0xE8, 10, 0, 0, 4],
        ));
        ordinary_only.extend(attr_bytes(
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type::AS4_PATH,
            &[2, 1, 0xFA, 0x56, 0xEA, 0x01],
        ));
        assert_eq!(
            decode_path_attributes(&ordinary_only, false, &[]).unwrap(),
            vec![
                as_path(&[4_200_000_001]),
                PathAttribute::Aggregator(Aggregator {
                    asn: 65_000,
                    router_id: Ipv4Addr::new(10, 0, 0, 4),
                    partial: false,
                }),
            ]
        );
    }

    /// Load-bearing RFC 9774 egress proof: deleting the guard permits a
    /// generated `AS4_PATH` containing `AS_SET` and makes this encode succeed.
    #[test]
    fn legacy_encoder_rejects_as_set_before_as4_path_generation() {
        for (asn, four_octet_as) in [(4_200_000_001, false), (65_000, false), (65_000, true)] {
            let attribute = PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSet(vec![asn])],
            });
            let error = encode_path_attributes(&[attribute], &mut Vec::new(), four_octet_as, false)
                .unwrap_err();
            assert!(matches!(
                error,
                EncodeError::ValueOutOfRange {
                    field: "AS_PATH",
                    ..
                }
            ));
        }
    }

    /// Load-bearing stale-sidecar proof: removing the suppression branch
    /// emits both raw compatibility attributes and fails the empty result.
    #[test]
    fn encoder_suppresses_stale_raw_as4_sidecars() {
        let attributes = vec![
            PathAttribute::Unknown(RawAttribute {
                flags: attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                type_code: attr_type::AS4_PATH,
                data: Bytes::from_static(&[2, 1, 0, 0, 0xFD, 0xE8]),
            }),
            PathAttribute::Unknown(RawAttribute {
                flags: attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                type_code: attr_type::AS4_AGGREGATOR,
                data: Bytes::from_static(&[0, 0, 0xFD, 0xE8, 10, 0, 0, 1]),
            }),
        ];
        let mut encoded = Vec::new();
        encode_path_attributes(&attributes, &mut encoded, false, false).unwrap();
        assert!(encoded.is_empty());
    }
}
