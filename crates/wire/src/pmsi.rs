//! P-Multicast Service Interface (PMSI) Tunnel attribute — RFC 6514 §5.
//!
//! This is BGP path attribute type 22 (RFC 6514 §11.1, IANA-managed).
//! It tells receivers how to forward BUM (broadcast / unknown unicast /
//! multicast) traffic for the EVI a Type 3 IMET route advertises.
//!
//! # Wire format (RFC 6514 §5)
//!
//! ```text
//! +---------------------------------+
//! |  Flags (1 octet)                |
//! +---------------------------------+
//! |  Tunnel Type (1 octet)          |
//! +---------------------------------+
//! |  MPLS Label (3 octets)          |
//! +---------------------------------+
//! |  Tunnel Identifier (variable)   |
//! +---------------------------------+
//! ```
//!
//! - **Flags** — RFC 6514 §5 defines bit 0 ("Leaf Information Required")
//!   only. EVPN ingress replication does not use it.
//! - **Tunnel Type** — IANA registry, RFC 7385. Values 0–7 are well-
//!   known; unknown values must round-trip without loss for forward
//!   compatibility.
//! - **MPLS Label** — 3 octets. For pure-MPLS deployments the
//!   high-order 20 bits carry the MPLS label value (RFC 6514 §5).
//!   For EVPN-VXLAN deployments **the full 24-bit field is the VNI**,
//!   not `VNI << 4` — RFC 8365 §5.1.3 explicitly redefines the field
//!   semantics to "the VNI" when EVPN routes ride VXLAN encap. This
//!   matches `EvpnMacIp.label1` (also a raw 24-bit VNI per RFC 8365)
//!   and what FRR/Cumulus emit on the wire. A label of 0 still means
//!   "no label present" in either case.
//! - **Tunnel Identifier** — variable-length, semantics depend on
//!   Tunnel Type. For Ingress Replication (type 6) it is the unicast
//!   tunnel endpoint IP — 4 octets for IPv4, 16 octets for IPv6
//!   (RFC 6514 §5; ipv6 form per RFC 8365). Other tunnel types carry
//!   opaque bytes that the codec preserves without interpretation.
//!
//! # Why a typed `PmsiTunnelType`
//!
//! Validating the tunnel type at decode time catches the most common
//! interop bug (operator misconfigures FRR with the wrong tunnel type
//! and the wire becomes nonsensical) without forcing the daemon to
//! reject otherwise-legal future tunnel types — `PmsiTunnelType::Other`
//! preserves any unknown value the IANA registry adds later.
//!
//! # Gate 7b+1 scope
//!
//! Only `PmsiTunnelType::IngressReplication` is exercised by rustbgpd
//! origination today. Decode handles all variants; encode round-trips
//! all variants. Phase F (Type 3 IMET) emits Ingress Replication with
//! the raw 24-bit VNI in the label field (RFC 8365 §5.1.3) and the
//! local VTEP IP as the tunnel identifier.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::DecodeError;

/// PMSI tunnel type (RFC 6514 §11.1, IANA registry RFC 7385).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PmsiTunnelType {
    /// 0 — no tunnel info present (PE listens on a local set).
    NoTunnelInfo,
    /// 1 — RSVP-TE P2MP LSP.
    RsvpTeP2mp,
    /// 2 — mLDP P2MP LSP.
    MldpP2mp,
    /// 3 — PIM-SSM tree.
    PimSsm,
    /// 4 — PIM-SM tree.
    PimSm,
    /// 5 — BIDIR-PIM tree.
    BidirPim,
    /// 6 — Ingress Replication. Tunnel ID is the unicast endpoint IP.
    /// EVPN BUM uses this exclusively over VXLAN.
    IngressReplication,
    /// 7 — mLDP MP2MP LSP.
    MldpMp2mp,
    /// Forward-compat: any value not yet known.
    Other(u8),
}

impl PmsiTunnelType {
    /// Wire encoding (1 octet).
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::NoTunnelInfo => 0,
            Self::RsvpTeP2mp => 1,
            Self::MldpP2mp => 2,
            Self::PimSsm => 3,
            Self::PimSm => 4,
            Self::BidirPim => 5,
            Self::IngressReplication => 6,
            Self::MldpMp2mp => 7,
            Self::Other(v) => v,
        }
    }

    /// Decode from a wire octet.
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::NoTunnelInfo,
            1 => Self::RsvpTeP2mp,
            2 => Self::MldpP2mp,
            3 => Self::PimSsm,
            4 => Self::PimSm,
            5 => Self::BidirPim,
            6 => Self::IngressReplication,
            7 => Self::MldpMp2mp,
            other => Self::Other(other),
        }
    }
}

/// Tunnel Identifier — variable-length, semantics keyed by tunnel type.
///
/// For Ingress Replication, this is the originator's unicast endpoint
/// IP address. Other tunnel types carry opaque bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PmsiTunnelIdentifier {
    /// No identifier (zero-length on the wire).
    Empty,
    /// 4-octet IPv4 unicast endpoint.
    Ipv4(Ipv4Addr),
    /// 16-octet IPv6 unicast endpoint.
    Ipv6(Ipv6Addr),
    /// Anything else — preserved for round-trip without interpretation.
    Raw(Vec<u8>),
}

/// Decoded PMSI Tunnel attribute.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PmsiTunnel {
    /// Wire flags (RFC 6514 §5 bit 0 is Leaf Information Required).
    pub flags: u8,
    /// Tunnel type (RFC 7385 IANA registry).
    pub tunnel_type: PmsiTunnelType,
    /// 24-bit Label field.
    ///
    /// Stored in canonical wire form: low 24 bits hold the value.
    /// **Field semantics depend on encap**:
    /// - Pure MPLS (RFC 6514 §5): high-order 20 bits = label, low 4 = TC+S.
    /// - EVPN-VXLAN (RFC 8365 §5.1.3): all 24 bits = VNI, no shift.
    ///
    /// For EVPN ingress replication, use
    /// [`Self::for_evpn_ingress_replication`] which handles the VNI
    /// width check and emits the field as a raw 24-bit VNI.
    pub mpls_label: u32,
    /// Tunnel Identifier — variable-length.
    pub tunnel_identifier: PmsiTunnelIdentifier,
}

impl PmsiTunnel {
    /// Build a PMSI Tunnel attribute for EVPN ingress replication over
    /// VXLAN (RFC 6514 §5 + RFC 8365 §5.1.3).
    ///
    /// The label field carries the **full 24-bit VNI** unmodified —
    /// RFC 8365 §5.1.3 redefines the field semantics for EVPN-VXLAN
    /// (no MPLS-style high-20-bits shift). This matches
    /// `EvpnMacIp.label1` for Type 2 routes and what FRR/Cumulus emit.
    ///
    /// `vni` is masked to 24 bits to defend against callers that pass
    /// a value outside `EvpnInstanceId`'s valid range; in normal
    /// operation `EvpnInstanceId::new` already rejects VNI > 0xFFFFFF
    /// at config time, so the mask is purely belt-and-braces.
    #[must_use]
    pub fn for_evpn_ingress_replication(vni: u32, originator: IpAddr) -> Self {
        let tunnel_identifier = match originator {
            IpAddr::V4(v4) => PmsiTunnelIdentifier::Ipv4(v4),
            IpAddr::V6(v6) => PmsiTunnelIdentifier::Ipv6(v6),
        };
        Self {
            flags: 0,
            tunnel_type: PmsiTunnelType::IngressReplication,
            mpls_label: vni & 0x00FF_FFFF,
            tunnel_identifier,
        }
    }

    /// Encode into a wire-format byte buffer.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.flags);
        buf.push(self.tunnel_type.as_u8());
        // 3-octet MPLS Label, big-endian (use the low 24 bits).
        let label = self.mpls_label & 0x00FF_FFFF;
        buf.push(((label >> 16) & 0xff) as u8);
        buf.push(((label >> 8) & 0xff) as u8);
        buf.push((label & 0xff) as u8);
        match &self.tunnel_identifier {
            PmsiTunnelIdentifier::Empty => {}
            PmsiTunnelIdentifier::Ipv4(v4) => buf.extend_from_slice(&v4.octets()),
            PmsiTunnelIdentifier::Ipv6(v6) => buf.extend_from_slice(&v6.octets()),
            PmsiTunnelIdentifier::Raw(bytes) => buf.extend_from_slice(bytes),
        }
    }

    /// Decode from a wire-format byte slice.
    ///
    /// The slice is the attribute *value* — caller has already stripped
    /// flags, type code, and length.
    ///
    /// Tunnel Identifier interpretation:
    /// - Tunnel Type 6 (Ingress Replication) with 4-octet rest → IPv4.
    /// - Tunnel Type 6 with 16-octet rest → IPv6.
    /// - Anything else (including type 6 with non-4/16 rest) → `Raw`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::MalformedField`] when the value is shorter
    /// than the 5-octet header (flags + type + 3-octet label).
    pub fn decode(value: &[u8]) -> Result<Self, DecodeError> {
        if value.len() < 5 {
            return Err(DecodeError::MalformedField {
                message_type: "UPDATE",
                detail: format!(
                    "PMSI Tunnel attribute truncated: need ≥5 bytes (flags+type+label), got {}",
                    value.len()
                ),
            });
        }
        let flags = value[0];
        let tunnel_type = PmsiTunnelType::from_u8(value[1]);
        let label = (u32::from(value[2]) << 16) | (u32::from(value[3]) << 8) | u32::from(value[4]);
        let rest = &value[5..];

        let tunnel_identifier = match (tunnel_type, rest.len()) {
            (_, 0) => PmsiTunnelIdentifier::Empty,
            (PmsiTunnelType::IngressReplication, 4) => {
                let mut o = [0u8; 4];
                o.copy_from_slice(rest);
                PmsiTunnelIdentifier::Ipv4(Ipv4Addr::from(o))
            }
            (PmsiTunnelType::IngressReplication, 16) => {
                let mut o = [0u8; 16];
                o.copy_from_slice(rest);
                PmsiTunnelIdentifier::Ipv6(Ipv6Addr::from(o))
            }
            _ => PmsiTunnelIdentifier::Raw(rest.to_vec()),
        };

        Ok(Self {
            flags,
            tunnel_type,
            mpls_label: label,
            tunnel_identifier,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(t: &PmsiTunnel) {
        let mut buf = Vec::new();
        t.encode(&mut buf);
        let decoded = PmsiTunnel::decode(&buf).expect("decode");
        assert_eq!(&decoded, t);
    }

    #[test]
    fn ingress_replication_ipv4_roundtrip() {
        let t = PmsiTunnel::for_evpn_ingress_replication(100, "10.0.0.1".parse().unwrap());
        roundtrip(&t);
        // RFC 8365 §5.1.3: EVPN-VXLAN PMSI label is the raw 24-bit VNI,
        // no MPLS-style high-20-bits shift.
        assert_eq!(t.mpls_label, 100);
        assert_eq!(t.tunnel_type, PmsiTunnelType::IngressReplication);
        assert_eq!(
            t.tunnel_identifier,
            PmsiTunnelIdentifier::Ipv4(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn ingress_replication_ipv6_roundtrip() {
        let t = PmsiTunnel::for_evpn_ingress_replication(50, "2001:db8::1".parse().unwrap());
        roundtrip(&t);
        assert_eq!(t.mpls_label, 50);
    }

    #[test]
    fn ingress_replication_ipv4_wire_bytes_match_rfc_8365() {
        // RFC 6514 §5 wire layout: flags(1) | type(1) | label(3) |
        // tunnel id(variable). For EVPN ingress replication of
        // vni=100, RFC 8365 §5.1.3 says the label field is the raw
        // 24-bit VNI: 100 = 0x000064. This matches FRR/Cumulus on the
        // wire and stays consistent with `EvpnMacIp.label1` (also a
        // raw 24-bit VNI per RFC 8365).
        let t = PmsiTunnel::for_evpn_ingress_replication(100, "10.0.0.1".parse().unwrap());
        let mut buf = Vec::new();
        t.encode(&mut buf);
        assert_eq!(
            buf,
            vec![
                0x00, // flags
                0x06, // tunnel type = Ingress Replication
                0x00, 0x00, 0x64, // label = vni 100 (raw, no shift)
                10, 0, 0, 1, // IPv4 originator
            ]
        );
    }

    #[test]
    fn no_tunnel_info_with_no_identifier_roundtrip() {
        let t = PmsiTunnel {
            flags: 0,
            tunnel_type: PmsiTunnelType::NoTunnelInfo,
            mpls_label: 0,
            tunnel_identifier: PmsiTunnelIdentifier::Empty,
        };
        roundtrip(&t);
    }

    #[test]
    fn rsvp_te_p2mp_with_opaque_id_roundtrip() {
        let t = PmsiTunnel {
            flags: 0,
            tunnel_type: PmsiTunnelType::RsvpTeP2mp,
            mpls_label: 0x1234 << 4,
            tunnel_identifier: PmsiTunnelIdentifier::Raw(vec![1, 2, 3, 4, 5, 6, 7, 8]),
        };
        roundtrip(&t);
    }

    #[test]
    fn mldp_p2mp_roundtrip() {
        let t = PmsiTunnel {
            flags: 0,
            tunnel_type: PmsiTunnelType::MldpP2mp,
            mpls_label: 42 << 4,
            tunnel_identifier: PmsiTunnelIdentifier::Raw(vec![0xaa; 12]),
        };
        roundtrip(&t);
    }

    #[test]
    fn pim_ssm_roundtrip() {
        let t = PmsiTunnel {
            flags: 0,
            tunnel_type: PmsiTunnelType::PimSsm,
            mpls_label: 0,
            tunnel_identifier: PmsiTunnelIdentifier::Raw(vec![10, 0, 0, 1, 224, 0, 0, 1]),
        };
        roundtrip(&t);
    }

    #[test]
    fn pim_sm_roundtrip() {
        let t = PmsiTunnel {
            flags: 0,
            tunnel_type: PmsiTunnelType::PimSm,
            mpls_label: 0,
            tunnel_identifier: PmsiTunnelIdentifier::Raw(vec![0xff; 8]),
        };
        roundtrip(&t);
    }

    #[test]
    fn bidir_pim_roundtrip() {
        let t = PmsiTunnel {
            flags: 0,
            tunnel_type: PmsiTunnelType::BidirPim,
            mpls_label: 0,
            tunnel_identifier: PmsiTunnelIdentifier::Raw(vec![1, 2, 3]),
        };
        roundtrip(&t);
    }

    #[test]
    fn mldp_mp2mp_roundtrip() {
        // Note: zero-length Raw collapses to Empty on decode (the
        // wire byte stream is identical, so we cannot distinguish).
        // Use Empty here to make the round-trip equality precise.
        let t = PmsiTunnel {
            flags: 0,
            tunnel_type: PmsiTunnelType::MldpMp2mp,
            mpls_label: 0,
            tunnel_identifier: PmsiTunnelIdentifier::Empty,
        };
        roundtrip(&t);
    }

    #[test]
    fn unknown_tunnel_type_round_trips_without_loss() {
        let t = PmsiTunnel {
            flags: 0x01, // pretend Leaf Information Required is set
            tunnel_type: PmsiTunnelType::Other(99),
            mpls_label: 0x00ab_cdef,
            tunnel_identifier: PmsiTunnelIdentifier::Raw(vec![0xde, 0xad, 0xbe, 0xef]),
        };
        roundtrip(&t);
    }

    #[test]
    fn decode_rejects_truncated_value() {
        let buf = [0u8, 6u8, 0u8, 0u8]; // 4 bytes — needs ≥5
        let err = PmsiTunnel::decode(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::MalformedField { .. }));
    }

    #[test]
    fn decode_zero_length_tunnel_id_after_label_yields_empty() {
        let buf = [0u8, 1u8, 0u8, 0u8, 0x10]; // RSVP-TE P2MP, label=1, no ID
        let t = PmsiTunnel::decode(&buf).unwrap();
        assert_eq!(t.tunnel_identifier, PmsiTunnelIdentifier::Empty);
    }

    #[test]
    fn ingress_replication_with_8_byte_id_treated_as_raw() {
        // Tunnel type 6 but identifier neither 4 nor 16 octets: keep as Raw
        // for forward-compat (an extension might define a longer form).
        let buf = [
            0u8, 6u8, // type = Ingress Replication
            0u8, 0u8, 0u8, // label = 0
            1, 2, 3, 4, 5, 6, 7, 8, // 8-byte tunnel identifier
        ];
        let t = PmsiTunnel::decode(&buf).unwrap();
        assert!(matches!(t.tunnel_identifier, PmsiTunnelIdentifier::Raw(_)));
    }

    #[test]
    fn for_evpn_ingress_replication_masks_vni_at_24_bits() {
        // `EvpnInstanceId::new` rejects VNI > 0xFFFFFF at config time,
        // so this defensive mask is purely belt-and-braces. RFC 8365
        // §5.1.3 says the field IS the VNI directly (no shift), so a
        // 24-bit-bounded raw value is the correct on-wire form.
        let t = PmsiTunnel::for_evpn_ingress_replication(0xFF00_1234, "10.0.0.1".parse().unwrap());
        assert_eq!(t.mpls_label, 0x0000_1234);
    }
}
