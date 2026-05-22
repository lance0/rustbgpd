use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use crate::capability::{Afi, Safi};
use crate::constants::{as_path_segment, attr_flags, attr_type};
use crate::error::DecodeError;
use crate::nlri::{NlriEntry, Prefix};
use crate::notification::update_subcode;

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
        #[expect(clippy::cast_possible_truncation)]
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
pub enum PathAttribute {
    /// `ORIGIN` attribute (type 1).
    Origin(Origin),
    /// `AS_PATH` attribute (type 2).
    AsPath(AsPath),
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
    /// RFC 8092 LARGE COMMUNITIES.
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
            Self::Communities(_)
            | Self::ExtendedCommunities(_)
            | Self::LargeCommunities(_)
            | Self::PmsiTunnel(_) => attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
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
    mut buf: &[u8],
    four_octet_as: bool,
    add_path_families: &[(Afi, Safi)],
) -> Result<Vec<PathAttribute>, DecodeError> {
    let mut attrs = Vec::new();

    while !buf.is_empty() {
        // Need at least flags(1) + type(1) = 2
        if buf.len() < 2 {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: "truncated attribute header".to_string(),
            });
        }

        let flags = buf[0];
        let type_code = buf[1];
        buf = &buf[2..];

        let extended = (flags & attr_flags::EXTENDED_LENGTH) != 0;
        let value_len = if extended {
            if buf.len() < 2 {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: "truncated extended-length attribute".to_string(),
                });
            }
            let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            buf = &buf[2..];
            len
        } else {
            if buf.is_empty() {
                return Err(DecodeError::MalformedField {
                    message_type: "UPDATE",
                    detail: "truncated attribute length".to_string(),
                });
            }
            let len = buf[0] as usize;
            buf = &buf[1..];
            len
        };

        if buf.len() < value_len {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!(
                    "attribute type {type_code} value truncated: need {value_len}, have {}",
                    buf.len()
                ),
            });
        }

        let value = &buf[..value_len];
        buf = &buf[value_len..];

        let attr =
            decode_attribute_value(flags, type_code, value, four_octet_as, add_path_families)?;
        attrs.push(attr);
    }

    Ok(attrs)
}

/// Decode a single attribute value given its flags, type code, and raw bytes.
#[expect(clippy::too_many_lines)]
fn decode_attribute_value(
    flags: u8,
    type_code: u8,
    value: &[u8],
    four_octet_as: bool,
    add_path_families: &[(Afi, Safi)],
) -> Result<PathAttribute, DecodeError> {
    // Validate Optional + Transitive flags for known attribute types (RFC 4271 §6.3).
    let flags_mask = attr_flags::OPTIONAL | attr_flags::TRANSITIVE;
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
            if !value.len().is_multiple_of(4) {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!("COMMUNITIES length {} not a multiple of 4", value.len()),
                });
            }
            let communities = value
                .chunks_exact(4)
                .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                .collect();
            Ok(PathAttribute::Communities(communities))
        }

        attr_type::EXTENDED_COMMUNITIES => {
            if !value.len().is_multiple_of(8) {
                return Err(DecodeError::UpdateAttributeError {
                    subcode: update_subcode::ATTRIBUTE_LENGTH_ERROR,
                    data: attr_error_data(flags, type_code, value),
                    detail: format!(
                        "EXTENDED_COMMUNITIES length {} not a multiple of 8",
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
            let communities = value
                .chunks_exact(12)
                .map(|c| {
                    LargeCommunity::new(
                        u32::from_be_bytes([c[0], c[1], c[2], c[3]]),
                        u32::from_be_bytes([c[4], c[5], c[6], c[7]]),
                        u32::from_be_bytes([c[8], c[9], c[10], c[11]]),
                    )
                })
                .collect();
            Ok(PathAttribute::LargeCommunities(communities))
        }

        attr_type::MP_REACH_NLRI => decode_mp_reach_nlri(value, add_path_families),
        attr_type::MP_UNREACH_NLRI => decode_mp_unreach_nlri(value, add_path_families),

        attr_type::PMSI_TUNNEL => {
            let pmsi = crate::pmsi::PmsiTunnel::decode(value)?;
            Ok(PathAttribute::PmsiTunnel(pmsi))
        }

        // ATOMIC_AGGREGATE, AGGREGATOR, and any unknown type → RawAttribute
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
#[expect(clippy::too_many_lines)]
fn decode_mp_reach_nlri(
    value: &[u8],
    add_path_families: &[(Afi, Safi)],
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
    let next_hop = if safi == Safi::FlowSpec {
        if nh_len != 0 {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!("MP_REACH_NLRI FlowSpec next-hop length {nh_len} (expected 0)"),
            });
        }
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
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
        }
    };

    // Skip reserved byte
    let nlri_start = 4 + nh_len + 1;
    let nlri_bytes = &value[nlri_start..];

    // FlowSpec (SAFI 133): NLRI is FlowSpec rules, not prefixes
    if safi == Safi::FlowSpec {
        let flowspec_rules = crate::flowspec::decode_flowspec_nlri(nlri_bytes, afi)?;
        return Ok(PathAttribute::MpReachNlri(MpReachNlri {
            afi,
            safi,
            next_hop,
            link_local_next_hop,
            announced: vec![],
            flowspec_announced: flowspec_rules,
            evpn_announced: vec![],
        }));
    }

    // EVPN (AFI 25 / SAFI 70): NLRI is typed EVPN routes, not prefixes
    if afi == Afi::L2Vpn && safi == Safi::Evpn {
        let routes = crate::evpn::decode_evpn_nlri(nlri_bytes)?;
        return Ok(PathAttribute::MpReachNlri(MpReachNlri {
            afi,
            safi,
            next_hop,
            link_local_next_hop,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: routes,
        }));
    }

    // SAFI 70 (EVPN) is only defined for AFI 25 (L2VPN). Reject any other
    // AFI explicitly so the unicast NLRI fallthrough below cannot
    // misinterpret the typed EVPN payload as a prefix list.
    if safi == Safi::Evpn {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!(
                "MP_REACH_NLRI SAFI EVPN with non-L2VPN AFI {} (only AFI L2VPN supported)",
                afi as u16
            ),
        });
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
        (Afi::L2Vpn, _) => {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!(
                    "MP_REACH_NLRI L2VPN with unsupported SAFI {} (only EVPN supported)",
                    safi as u8
                ),
            });
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
    }))
}

/// Decode `MP_UNREACH_NLRI` (type 15) attribute value.
///
/// Wire layout (RFC 4760 §4):
///   AFI (2) | SAFI (1) | Withdrawn Routes (variable)
fn decode_mp_unreach_nlri(
    value: &[u8],
    add_path_families: &[(Afi, Safi)],
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

    let withdrawn_bytes = &value[3..];

    // FlowSpec (SAFI 133): withdrawn is FlowSpec rules
    if safi == Safi::FlowSpec {
        let flowspec_rules = crate::flowspec::decode_flowspec_nlri(withdrawn_bytes, afi)?;
        return Ok(PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi,
            safi,
            withdrawn: vec![],
            flowspec_withdrawn: flowspec_rules,
            evpn_withdrawn: vec![],
        }));
    }

    // EVPN (AFI 25 / SAFI 70): withdrawn is typed EVPN routes, not prefixes
    if afi == Afi::L2Vpn && safi == Safi::Evpn {
        let routes = crate::evpn::decode_evpn_nlri(withdrawn_bytes)?;
        return Ok(PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi,
            safi,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: routes,
        }));
    }

    // SAFI 70 (EVPN) is only defined for AFI 25 (L2VPN). Reject any other
    // AFI explicitly so the unicast NLRI fallthrough below cannot
    // misinterpret the typed EVPN payload as a prefix list.
    if safi == Safi::Evpn {
        return Err(DecodeError::MalformedField {
            message_type: "UPDATE",
            detail: format!(
                "MP_UNREACH_NLRI SAFI EVPN with non-L2VPN AFI {} (only AFI L2VPN supported)",
                afi as u16
            ),
        });
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
        (Afi::L2Vpn, _) => {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!(
                    "MP_UNREACH_NLRI L2VPN with unsupported SAFI {} (only EVPN supported)",
                    safi as u8
                ),
            });
        }
    };

    Ok(PathAttribute::MpUnreachNlri(MpUnreachNlri {
        afi,
        safi,
        withdrawn,
        flowspec_withdrawn: vec![],
        evpn_withdrawn: vec![],
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
    let mut buf = Vec::with_capacity(3 + value.len());
    if value.len() > 255 {
        buf.push(flags | attr_flags::EXTENDED_LENGTH);
        buf.push(type_code);
        #[expect(clippy::cast_possible_truncation)]
        let len = value.len() as u16;
        buf.extend_from_slice(&len.to_be_bytes());
    } else {
        buf.push(flags);
        buf.push(type_code);
        #[expect(clippy::cast_possible_truncation)]
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
        | attr_type::MP_UNREACH_NLRI => Some(attr_flags::OPTIONAL),
        // Optional transitive
        attr_type::AGGREGATOR
        | attr_type::COMMUNITIES
        | attr_type::EXTENDED_COMMUNITIES
        | attr_type::LARGE_COMMUNITIES
        | attr_type::PMSI_TUNNEL => Some(attr_flags::OPTIONAL | attr_flags::TRANSITIVE),
        _ => None,
    }
}

/// Encode path attributes to wire bytes.
///
/// `four_octet_as` controls whether AS numbers in `AS_PATH` are 2 or 4 bytes.
/// Encode a list of path attributes into wire format.
///
/// When `add_path_mp` is true, `MP_REACH_NLRI` and `MP_UNREACH_NLRI` NLRI
/// entries include 4-byte path IDs per RFC 7911.
#[expect(
    clippy::too_many_lines,
    reason = "dispatch arms are inherently O(variants); each new path attribute adds a small block"
)]
pub fn encode_path_attributes(
    attrs: &[PathAttribute],
    buf: &mut Vec<u8>,
    four_octet_as: bool,
    add_path_mp: bool,
) {
    for attr in attrs {
        let mut value = Vec::new();
        let flags;
        let type_code;

        match attr {
            PathAttribute::Origin(origin) => {
                flags = attr_flags::TRANSITIVE;
                type_code = attr_type::ORIGIN;
                value.push(*origin as u8);
            }
            PathAttribute::AsPath(as_path) => {
                flags = attr_flags::TRANSITIVE;
                type_code = attr_type::AS_PATH;
                encode_as_path(as_path, &mut value, four_octet_as);
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
                for &c in communities {
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
                encode_mp_reach_nlri(mp, &mut value, add_path_mp);
            }
            PathAttribute::MpUnreachNlri(mp) => {
                flags = attr_flags::OPTIONAL;
                type_code = attr_type::MP_UNREACH_NLRI;
                encode_mp_unreach_nlri(mp, &mut value, add_path_mp);
            }
            PathAttribute::PmsiTunnel(pmsi) => {
                // RFC 6514 §5: Optional + Transitive.
                (flags, type_code) = (
                    attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                    attr_type::PMSI_TUNNEL,
                );
                pmsi.encode(&mut value);
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

        // Use extended length if value > 255 bytes
        if value.len() > 255 {
            buf.push(flags | attr_flags::EXTENDED_LENGTH);
            buf.push(type_code);
            #[expect(clippy::cast_possible_truncation)]
            let len = value.len() as u16;
            buf.extend_from_slice(&len.to_be_bytes());
        } else {
            buf.push(flags);
            buf.push(type_code);
            #[expect(clippy::cast_possible_truncation)]
            buf.push(value.len() as u8);
        }
        buf.extend_from_slice(&value);
    }
}

/// Encode `MP_REACH_NLRI` value bytes.
///
/// When `add_path` is true, each NLRI entry includes a 4-byte path ID
/// prefix per RFC 7911.
fn encode_mp_reach_nlri(mp: &MpReachNlri, buf: &mut Vec<u8>, add_path: bool) {
    buf.extend_from_slice(&(mp.afi as u16).to_be_bytes());
    buf.push(mp.safi as u8);

    // FlowSpec: NH length = 0, reserved = 0, then FlowSpec NLRI
    if mp.safi == Safi::FlowSpec {
        buf.push(0); // NH-Len = 0
        buf.push(0); // Reserved
        crate::flowspec::encode_flowspec_nlri(&mp.flowspec_announced, buf, mp.afi);
        return;
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
        return;
    }

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
}

/// Encode `MP_UNREACH_NLRI` value bytes.
///
/// When `add_path` is true, each withdrawn entry includes a 4-byte path ID.
fn encode_mp_unreach_nlri(mp: &MpUnreachNlri, buf: &mut Vec<u8>, add_path: bool) {
    buf.extend_from_slice(&(mp.afi as u16).to_be_bytes());
    buf.push(mp.safi as u8);

    // FlowSpec: encode FlowSpec NLRI rules
    if mp.safi == Safi::FlowSpec {
        crate::flowspec::encode_flowspec_nlri(&mp.flowspec_withdrawn, buf, mp.afi);
        return;
    }

    // EVPN: encode EVPN NLRI routes
    if mp.afi == Afi::L2Vpn && mp.safi == Safi::Evpn {
        crate::evpn::encode_evpn_nlri(&mp.evpn_withdrawn, buf);
        return;
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
            #[expect(clippy::cast_possible_truncation)]
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
        };
        let attr = PathAttribute::MpReachNlri(mp);

        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false);
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
        };
        let attr = PathAttribute::MpReachNlri(mp.clone());

        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false);

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
        };
        let attr = PathAttribute::MpUnreachNlri(mp);
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false);
        let decoded = decode_path_attributes(&buf, true, &[]).expect("decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(attr, decoded[0]);
    }

    // ---- EVPN extended community typed accessors (RFC 7432 / 8365 / 9135) ---

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
        encode_path_attributes(&attrs, &mut buf, true, false);
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
        encode_path_attributes(&attrs, &mut buf, false, false);
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

    #[test]
    fn as_path_with_set_and_sequence() {
        // AS_SEQUENCE [65001], AS_SET [65002, 65003]
        let attrs = vec![PathAttribute::AsPath(AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![65001]),
                AsPathSegment::AsSet(vec![65002, 65003]),
            ],
        })];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false);
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded, attrs);
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
    fn decode_communities_empty() {
        // flags=0xC0, type=8, len=0
        let buf = [0xC0, 0x08, 0x00];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs[0], PathAttribute::Communities(vec![]));
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
        encode_path_attributes(&attrs, &mut buf, true, false);
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
    fn decode_extended_communities_empty() {
        let buf = [0xC0, 0x10, 0x00];
        let attrs = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(attrs[0], PathAttribute::ExtendedCommunities(vec![]));
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
        encode_path_attributes(&attrs, &mut buf, true, false);
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
        encode_path_attributes(&attrs, &mut buf, true, false);
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
        encode_path_attributes(&[attr], &mut buf, true, false);
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
        encode_path_attributes(&[attr], &mut buf, true, false);
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
        encode_path_attributes(&[attr], &mut buf, true, false);
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
        };
        let attrs = vec![PathAttribute::MpReachNlri(mp.clone())];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false);
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
        };
        let attrs = vec![PathAttribute::MpUnreachNlri(mp.clone())];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false);
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], PathAttribute::MpUnreachNlri(mp));
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
        };
        let attrs = vec![PathAttribute::MpReachNlri(mp.clone())];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false);
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
        };
        let attrs = vec![PathAttribute::MpReachNlri(mp.clone())];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false);
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
        };
        let attrs = vec![PathAttribute::MpReachNlri(mp.clone())];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false);
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
        #[expect(clippy::cast_possible_truncation)]
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
    #[expect(clippy::cast_possible_truncation)]
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
    #[expect(clippy::cast_possible_truncation)]
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
    #[expect(clippy::cast_possible_truncation)]
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
        };
        let attrs = vec![PathAttribute::MpReachNlri(mp.clone())];

        let mut buf = Vec::new();
        encode_path_attributes(&attrs, &mut buf, true, false);

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
        };
        let attr = PathAttribute::MpReachNlri(mp.clone());
        let mut buf = Vec::new();
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false);

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
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false);
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
        encode_path_attributes(std::slice::from_ref(&attr), &mut buf, true, false);
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
        encode_path_attributes(&[attr], &mut buf, true, false);
        let decoded = decode_path_attributes(&buf, true, &[]).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], PathAttribute::LargeCommunities(lcs));
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
        let err = decode_mp_reach_nlri(&bytes, &[]).unwrap_err();
        match err {
            DecodeError::MalformedField { detail, .. } => {
                assert!(detail.contains("SAFI EVPN"), "unexpected detail: {detail}");
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
        let err = decode_mp_unreach_nlri(&bytes, &[]).unwrap_err();
        match err {
            DecodeError::MalformedField { detail, .. } => {
                assert!(detail.contains("SAFI EVPN"), "unexpected detail: {detail}");
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
        encode_path_attributes(&attrs, &mut buf, true, false);
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
}
