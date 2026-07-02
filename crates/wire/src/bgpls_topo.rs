//! Typed BGP-LS topology accessors (RFC 9552 / RFC 9107 consumers).
//!
//! This is a pure interpretation layer over the opaque [`BgpLsNlri`] codec in
//! [`crate::bgpls`]: code-point constants, canonical node identity, and
//! descriptor/attribute value readers. Nothing here touches encode/decode or
//! route keys, so reflection byte-fidelity is unaffected by construction.
//!
//! The BGP-LS Attribute (path attribute type 29) stays
//! `PathAttribute::Unknown(RawAttribute)` in the daemon; the free functions
//! below interpret its raw value bytes lazily.

use bytes::Bytes;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::bgpls::{BgpLsNlri, BgpLsNlriType, BgpLsTlv, decode_bgpls_tlvs};
use crate::error::DecodeError;
use crate::nlri::{Ipv4Prefix, Ipv6Prefix, Prefix};

/// Local Node Descriptors NLRI TLV (RFC 9552 §5.2.1.2).
pub const BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS: u16 = 256;
/// Remote Node Descriptors NLRI TLV (RFC 9552 §5.2.1.2).
pub const BGP_LS_TLV_REMOTE_NODE_DESCRIPTORS: u16 = 257;
/// Link Local/Remote Identifiers link descriptor TLV (RFC 9552 §5.2.2).
pub const BGP_LS_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS: u16 = 258;
/// IPv4 interface address link descriptor TLV (RFC 9552 §5.2.2).
pub const BGP_LS_TLV_IPV4_INTERFACE_ADDRESS: u16 = 259;
/// IPv4 neighbor address link descriptor TLV (RFC 9552 §5.2.2).
pub const BGP_LS_TLV_IPV4_NEIGHBOR_ADDRESS: u16 = 260;
/// IPv6 interface address link descriptor TLV (RFC 9552 §5.2.2).
pub const BGP_LS_TLV_IPV6_INTERFACE_ADDRESS: u16 = 261;
/// IPv6 neighbor address link descriptor TLV (RFC 9552 §5.2.2).
pub const BGP_LS_TLV_IPV6_NEIGHBOR_ADDRESS: u16 = 262;
/// Multi-Topology Identifier descriptor TLV (RFC 9552 §5.2.2.1).
pub const BGP_LS_TLV_MULTI_TOPOLOGY_ID: u16 = 263;
/// OSPF Route Type prefix descriptor TLV (RFC 9552 §5.2.3.1).
pub const BGP_LS_TLV_OSPF_ROUTE_TYPE: u16 = 264;
/// IP Reachability Information prefix descriptor TLV (RFC 9552 §5.2.3.2).
pub const BGP_LS_TLV_IP_REACHABILITY: u16 = 265;
/// Autonomous System node-descriptor sub-TLV (RFC 9552 §5.2.1.4).
pub const BGP_LS_TLV_AUTONOMOUS_SYSTEM: u16 = 512;
/// BGP-LS Identifier node-descriptor sub-TLV (RFC 9552 §5.2.1.4).
pub const BGP_LS_TLV_BGP_LS_IDENTIFIER: u16 = 513;
/// OSPF Area-ID node-descriptor sub-TLV (RFC 9552 §5.2.1.4).
pub const BGP_LS_TLV_OSPF_AREA_ID: u16 = 514;
/// IGP Router-ID node-descriptor sub-TLV (RFC 9552 §5.2.1.4).
pub const BGP_LS_TLV_IGP_ROUTER_ID: u16 = 515;
/// TE Default Metric link attribute TLV (RFC 9552 §5.3.2.3).
pub const BGP_LS_TLV_TE_DEFAULT_METRIC: u16 = 1092;
/// IGP Metric link attribute TLV (RFC 9552 §5.3.2.4).
pub const BGP_LS_TLV_IGP_METRIC: u16 = 1095;
/// Prefix Metric prefix attribute TLV (RFC 9552 §5.3.3.4).
pub const BGP_LS_TLV_PREFIX_METRIC: u16 = 1155;

/// Opaque, canonical BGP-LS node identity.
///
/// Byte layout: `protocol_id (1) + identifier (8) + raw value bytes of the
/// Local (TLV 256) or Remote (TLV 257) Node Descriptors container`. Byte
/// equality is the identity contract: a Link NLRI's local-node key equals the
/// matching Node NLRI's key because RFC 9552 §5.2.1 mandates canonical
/// ascending TLV order, which the decoder already enforces. No router-ID
/// interpretation happens here.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BgpLsNodeKey(Bytes);

impl BgpLsNodeKey {
    /// Return the canonical key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl BgpLsNlri {
    fn node_key(&self, container: u16) -> Option<BgpLsNodeKey> {
        let protocol_id = self.protocol_id()?;
        let identifier = self.identifier()?;
        let container = self.descriptor_value(container)?;
        let mut bytes = Vec::with_capacity(9 + container.len());
        bytes.push(protocol_id);
        bytes.extend_from_slice(&identifier.to_be_bytes());
        bytes.extend_from_slice(&container);
        Some(BgpLsNodeKey(Bytes::from(bytes)))
    }

    /// Return the first descriptor TLV value with the given type code, or
    /// `None` when the NLRI is opaque/malformed or the TLV is absent.
    fn descriptor_value(&self, type_code: u16) -> Option<Bytes> {
        let tlvs = self.descriptor_tlvs().ok()??;
        tlvs.into_iter()
            .find(|tlv| tlv.type_code == type_code)
            .map(|tlv| tlv.value)
    }

    /// Return a fixed-length link descriptor TLV value; Link NLRIs only.
    fn link_descriptor_value(&self, type_code: u16, len: usize) -> Option<Bytes> {
        if self.nlri_type != BgpLsNlriType::Link {
            return None;
        }
        self.descriptor_value(type_code)
            .filter(|value| value.len() == len)
    }

    /// Return the canonical local-node identity (TLV 256 container).
    ///
    /// Applies to Node, Link, and Prefix NLRIs; `None` when the container is
    /// absent or the NLRI is opaque/malformed.
    #[must_use]
    pub fn local_node_key(&self) -> Option<BgpLsNodeKey> {
        self.node_key(BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS)
    }

    /// Return the canonical remote-node identity (TLV 257 container).
    ///
    /// Link NLRIs only; `None` otherwise or when absent.
    #[must_use]
    pub fn remote_node_key(&self) -> Option<BgpLsNodeKey> {
        if self.nlri_type != BgpLsNlriType::Link {
            return None;
        }
        self.node_key(BGP_LS_TLV_REMOTE_NODE_DESCRIPTORS)
    }

    /// Return the IPv4 interface address link descriptor (TLV 259).
    #[must_use]
    pub fn link_ipv4_interface_address(&self) -> Option<Ipv4Addr> {
        self.link_descriptor_value(BGP_LS_TLV_IPV4_INTERFACE_ADDRESS, 4)
            .map(|value| ipv4_from_bytes(&value))
    }

    /// Return the IPv4 neighbor address link descriptor (TLV 260).
    #[must_use]
    pub fn link_ipv4_neighbor_address(&self) -> Option<Ipv4Addr> {
        self.link_descriptor_value(BGP_LS_TLV_IPV4_NEIGHBOR_ADDRESS, 4)
            .map(|value| ipv4_from_bytes(&value))
    }

    /// Return the IPv6 interface address link descriptor (TLV 261).
    #[must_use]
    pub fn link_ipv6_interface_address(&self) -> Option<Ipv6Addr> {
        self.link_descriptor_value(BGP_LS_TLV_IPV6_INTERFACE_ADDRESS, 16)
            .map(|value| ipv6_from_bytes(&value))
    }

    /// Return the IPv6 neighbor address link descriptor (TLV 262).
    #[must_use]
    pub fn link_ipv6_neighbor_address(&self) -> Option<Ipv6Addr> {
        self.link_descriptor_value(BGP_LS_TLV_IPV6_NEIGHBOR_ADDRESS, 16)
            .map(|value| ipv6_from_bytes(&value))
    }

    /// Return the Link Local/Remote Identifiers descriptor (TLV 258) as a
    /// `(local, remote)` pair.
    #[must_use]
    pub fn link_local_remote_ids(&self) -> Option<(u32, u32)> {
        let value = self.link_descriptor_value(BGP_LS_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS, 8)?;
        Some((
            u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
            u32::from_be_bytes([value[4], value[5], value[6], value[7]]),
        ))
    }

    /// Return the IP Reachability Information prefix descriptor (TLV 265).
    ///
    /// The value is a 1-byte prefix length in bits followed by the minimal
    /// number of prefix bytes (`ceil(len / 8)`, RFC 9552 §5.2.3.2). Returns
    /// `None` on non-prefix NLRIs, absent TLV, out-of-range length, or a
    /// non-minimal/truncated value.
    #[must_use]
    pub fn ip_reachability(&self) -> Option<Prefix> {
        let max_bits: u8 = match self.nlri_type {
            BgpLsNlriType::Ipv4TopologyPrefix => 32,
            BgpLsNlriType::Ipv6TopologyPrefix => 128,
            _ => return None,
        };
        let value = self.descriptor_value(BGP_LS_TLV_IP_REACHABILITY)?;
        let (&len_bits, rest) = value.split_first()?;
        if len_bits > max_bits || rest.len() != usize::from(len_bits.div_ceil(8)) {
            return None;
        }
        Some(if max_bits == 32 {
            let mut octets = [0_u8; 4];
            octets[..rest.len()].copy_from_slice(rest);
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(octets), len_bits))
        } else {
            let mut octets = [0_u8; 16];
            octets[..rest.len()].copy_from_slice(rest);
            Prefix::V6(Ipv6Prefix::new(Ipv6Addr::from(octets), len_bits))
        })
    }
}

fn ipv4_from_bytes(value: &Bytes) -> Ipv4Addr {
    let mut octets = [0_u8; 4];
    octets.copy_from_slice(value);
    Ipv4Addr::from(octets)
}

fn ipv6_from_bytes(value: &Bytes) -> Ipv6Addr {
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(value);
    Ipv6Addr::from(octets)
}

/// Decode the raw value bytes of a BGP-LS Attribute (path attribute type 29)
/// into its TLVs (RFC 9552 §5.3).
///
/// The daemon stores attribute 29 as `PathAttribute::Unknown(RawAttribute)`;
/// pass `RawAttribute::data` here to interpret it lazily.
///
/// # Errors
///
/// Returns `DecodeError` if a TLV header or value is structurally truncated.
pub fn bgp_ls_attribute_tlvs(value: &[u8]) -> Result<Vec<BgpLsTlv>, DecodeError> {
    decode_bgpls_tlvs(value)
}

fn attribute_value(tlvs: &[BgpLsTlv], type_code: u16) -> Option<&Bytes> {
    tlvs.iter()
        .find(|tlv| tlv.type_code == type_code)
        .map(|tlv| &tlv.value)
}

fn metric_u32_be(tlvs: &[BgpLsTlv], type_code: u16) -> Option<u32> {
    let value = attribute_value(tlvs, type_code)?;
    if value.len() != 4 {
        return None;
    }
    Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

/// Return the IGP Metric (TLV 1095, RFC 9552 §5.3.2.4).
///
/// The value is variable-length big-endian: 1 byte (IS-IS small metrics),
/// 2 bytes (OSPF), or 3 bytes (IS-IS wide metrics). Other lengths return
/// `None`.
#[must_use]
pub fn igp_metric(tlvs: &[BgpLsTlv]) -> Option<u32> {
    let value = attribute_value(tlvs, BGP_LS_TLV_IGP_METRIC)?;
    match value.as_ref() {
        [a] => Some(u32::from(*a)),
        [a, b] => Some(u32::from(u16::from_be_bytes([*a, *b]))),
        [a, b, c] => Some(u32::from_be_bytes([0, *a, *b, *c])),
        _ => None,
    }
}

/// Return the Prefix Metric (TLV 1155, RFC 9552 §5.3.3.4), 4-byte big-endian.
#[must_use]
pub fn prefix_metric(tlvs: &[BgpLsTlv]) -> Option<u32> {
    metric_u32_be(tlvs, BGP_LS_TLV_PREFIX_METRIC)
}

/// Return the TE Default Metric (TLV 1092, RFC 9552 §5.3.2.3), 4-byte
/// big-endian.
///
/// Parsed but unused in ORR v1: link cost comes from the IGP Metric only.
#[must_use]
pub fn te_default_metric(tlvs: &[BgpLsTlv]) -> Option<u32> {
    metric_u32_be(tlvs, BGP_LS_TLV_TE_DEFAULT_METRIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgpls::encode_bgpls_tlvs;

    // Fixtures are hand-derived from the RFC 9552 wire layout. GoBGP v4.6.0
    // (`gobgp global rib add -a ls link ...`) produces these same encodings;
    // the M76 interop job cross-checks against a live GoBGP feed.

    fn sub_tlvs(tlvs: &[BgpLsTlv]) -> Bytes {
        let mut bytes = Vec::new();
        encode_bgpls_tlvs(tlvs, &mut bytes).expect("fixture sub-TLVs encode");
        Bytes::from(bytes)
    }

    fn build_nlri(
        nlri_type: BgpLsNlriType,
        protocol_id: u8,
        identifier: u64,
        tlvs: &[BgpLsTlv],
    ) -> BgpLsNlri {
        let mut payload = vec![protocol_id];
        payload.extend_from_slice(&identifier.to_be_bytes());
        encode_bgpls_tlvs(tlvs, &mut payload).expect("fixture TLVs encode");
        BgpLsNlri::try_new(nlri_type, None, Bytes::from(payload)).expect("fixture NLRI fits")
    }

    /// Node descriptors container: AS 64512 + IS-IS system-ID router ID.
    fn node_a_container() -> Bytes {
        sub_tlvs(&[
            BgpLsTlv::new(
                BGP_LS_TLV_AUTONOMOUS_SYSTEM,
                Bytes::from_static(&[0, 0, 0xfc, 0x00]),
            ),
            BgpLsTlv::new(
                BGP_LS_TLV_IGP_ROUTER_ID,
                Bytes::from_static(&[0, 0, 0, 0, 0, 1]),
            ),
        ])
    }

    fn node_b_container() -> Bytes {
        sub_tlvs(&[
            BgpLsTlv::new(
                BGP_LS_TLV_AUTONOMOUS_SYSTEM,
                Bytes::from_static(&[0, 0, 0xfc, 0x00]),
            ),
            BgpLsTlv::new(
                BGP_LS_TLV_IGP_ROUTER_ID,
                Bytes::from_static(&[0, 0, 0, 0, 0, 2]),
            ),
        ])
    }

    fn node_nlri(container: Bytes) -> BgpLsNlri {
        build_nlri(
            BgpLsNlriType::Node,
            2,
            0,
            &[BgpLsTlv::new(BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS, container)],
        )
    }

    fn link_nlri_a_to_b(extra_descriptors: &[BgpLsTlv]) -> BgpLsNlri {
        let mut tlvs = vec![
            BgpLsTlv::new(BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS, node_a_container()),
            BgpLsTlv::new(BGP_LS_TLV_REMOTE_NODE_DESCRIPTORS, node_b_container()),
        ];
        tlvs.extend_from_slice(extra_descriptors);
        build_nlri(BgpLsNlriType::Link, 2, 0, &tlvs)
    }

    #[test]
    fn link_local_node_key_equals_matching_node_nlri_key() {
        let node = node_nlri(node_a_container());
        let link = link_nlri_a_to_b(&[]);
        assert_eq!(
            link.local_node_key().expect("link has local node"),
            node.local_node_key().expect("node has local node")
        );

        // Any differing sub-TLV byte breaks equality.
        let other_node = node_nlri(node_b_container());
        assert_ne!(
            link.local_node_key().expect("link has local node"),
            other_node.local_node_key().expect("node has local node")
        );

        // Differing protocol-id or identifier also breaks equality.
        let mut tlvs = vec![BgpLsTlv::new(
            BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS,
            node_a_container(),
        )];
        let other_proto = build_nlri(BgpLsNlriType::Node, 3, 0, &tlvs);
        assert_ne!(node.local_node_key(), other_proto.local_node_key());
        tlvs.clear();
        tlvs.push(BgpLsTlv::new(
            BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS,
            node_a_container(),
        ));
        let other_ident = build_nlri(BgpLsNlriType::Node, 2, 7, &tlvs);
        assert_ne!(node.local_node_key(), other_ident.local_node_key());
    }

    #[test]
    fn remote_node_key_only_on_link_nlris() {
        let link = link_nlri_a_to_b(&[]);
        assert_eq!(
            link.remote_node_key().expect("link has remote node"),
            node_nlri(node_b_container())
                .local_node_key()
                .expect("node B key")
        );

        assert_eq!(node_nlri(node_a_container()).remote_node_key(), None);
        let prefix = build_nlri(
            BgpLsNlriType::Ipv4TopologyPrefix,
            2,
            0,
            &[
                BgpLsTlv::new(BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS, node_a_container()),
                BgpLsTlv::new(
                    BGP_LS_TLV_IP_REACHABILITY,
                    Bytes::from_static(&[24, 10, 0, 0]),
                ),
            ],
        );
        assert_eq!(prefix.remote_node_key(), None);
        assert!(prefix.local_node_key().is_some());
    }

    #[test]
    fn node_key_none_when_container_missing() {
        let node = build_nlri(BgpLsNlriType::Node, 2, 0, &[]);
        assert_eq!(node.local_node_key(), None);
        // Unknown NLRI types stay opaque.
        let unknown = BgpLsNlri::try_new(
            BgpLsNlriType::Unknown(65_000),
            None,
            Bytes::from_static(&[1, 2, 3]),
        )
        .expect("fixture fits");
        assert_eq!(unknown.local_node_key(), None);
    }

    #[test]
    fn link_descriptor_addresses_extracted() {
        let link = link_nlri_a_to_b(&[
            BgpLsTlv::new(
                BGP_LS_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS,
                Bytes::from_static(&[0, 0, 0, 17, 0, 0, 0, 42]),
            ),
            BgpLsTlv::new(
                BGP_LS_TLV_IPV4_INTERFACE_ADDRESS,
                Bytes::from_static(&[10, 0, 8, 1]),
            ),
            BgpLsTlv::new(
                BGP_LS_TLV_IPV4_NEIGHBOR_ADDRESS,
                Bytes::from_static(&[10, 0, 8, 2]),
            ),
            BgpLsTlv::new(
                BGP_LS_TLV_IPV6_INTERFACE_ADDRESS,
                Bytes::from_static(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            ),
            BgpLsTlv::new(
                BGP_LS_TLV_IPV6_NEIGHBOR_ADDRESS,
                Bytes::from_static(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
            ),
        ]);

        assert_eq!(link.link_local_remote_ids(), Some((17, 42)));
        assert_eq!(
            link.link_ipv4_interface_address(),
            Some(Ipv4Addr::new(10, 0, 8, 1))
        );
        assert_eq!(
            link.link_ipv4_neighbor_address(),
            Some(Ipv4Addr::new(10, 0, 8, 2))
        );
        assert_eq!(
            link.link_ipv6_interface_address(),
            Some("2001:db8::1".parse().expect("fixture address parses"))
        );
        assert_eq!(
            link.link_ipv6_neighbor_address(),
            Some("2001:db8::2".parse().expect("fixture address parses"))
        );

        // Absent on a bare link; never present on non-Link NLRIs.
        let bare = link_nlri_a_to_b(&[]);
        assert_eq!(bare.link_ipv4_interface_address(), None);
        assert_eq!(bare.link_local_remote_ids(), None);
        let node = node_nlri(node_a_container());
        assert_eq!(node.link_ipv4_interface_address(), None);

        // Wrong-length values are rejected.
        let short = link_nlri_a_to_b(&[BgpLsTlv::new(
            BGP_LS_TLV_IPV4_INTERFACE_ADDRESS,
            Bytes::from_static(&[10, 0, 8]),
        )]);
        assert_eq!(short.link_ipv4_interface_address(), None);
    }

    #[test]
    fn ip_reachability_roundtrip_v4_and_v6() {
        let v4 = |value: &'static [u8]| {
            build_nlri(
                BgpLsNlriType::Ipv4TopologyPrefix,
                2,
                0,
                &[
                    BgpLsTlv::new(BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS, node_a_container()),
                    BgpLsTlv::new(BGP_LS_TLV_IP_REACHABILITY, Bytes::from_static(value)),
                ],
            )
        };
        let v6 = |value: &'static [u8]| {
            build_nlri(
                BgpLsNlriType::Ipv6TopologyPrefix,
                2,
                0,
                &[
                    BgpLsTlv::new(BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS, node_a_container()),
                    BgpLsTlv::new(BGP_LS_TLV_IP_REACHABILITY, Bytes::from_static(value)),
                ],
            )
        };

        assert_eq!(
            v4(&[0]).ip_reachability(),
            Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0)))
        );
        assert_eq!(
            v4(&[24, 10, 0, 9]).ip_reachability(),
            Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 9, 0), 24)))
        );
        assert_eq!(
            v4(&[32, 192, 0, 2, 1]).ip_reachability(),
            Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 1), 32)))
        );
        assert_eq!(
            v6(&[0]).ip_reachability(),
            Some(Prefix::V6(Ipv6Prefix::new(Ipv6Addr::UNSPECIFIED, 0)))
        );
        assert_eq!(
            v6(&[64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1]).ip_reachability(),
            Some(Prefix::V6(Ipv6Prefix::new(
                "2001:db8:0:1::".parse().expect("fixture address parses"),
                64
            )))
        );
        assert_eq!(
            v6(&[
                128, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            ])
            .ip_reachability(),
            Some(Prefix::V6(Ipv6Prefix::new(
                "2001:db8::1".parse().expect("fixture address parses"),
                128
            )))
        );

        // Rejections: over-length bits, non-minimal encoding, truncation,
        // empty value, wrong NLRI type.
        assert_eq!(v4(&[33, 10, 0, 0, 0, 0]).ip_reachability(), None);
        assert_eq!(
            v6(&[129, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).ip_reachability(),
            None
        );
        assert_eq!(v4(&[8, 10, 0]).ip_reachability(), None);
        assert_eq!(v4(&[24, 10, 0]).ip_reachability(), None);
        assert_eq!(v4(&[]).ip_reachability(), None);
        assert_eq!(node_nlri(node_a_container()).ip_reachability(), None);
        assert_eq!(link_nlri_a_to_b(&[]).ip_reachability(), None);
    }

    fn attr29(tlvs: &[BgpLsTlv]) -> Vec<BgpLsTlv> {
        let mut bytes = Vec::new();
        encode_bgpls_tlvs(tlvs, &mut bytes).expect("fixture attribute encodes");
        bgp_ls_attribute_tlvs(&bytes).expect("fixture attribute decodes")
    }

    #[test]
    fn igp_metric_parses_1_2_3_byte_forms() {
        // IS-IS small (1 byte), OSPF (2 bytes), IS-IS wide (3 bytes).
        let one = attr29(&[BgpLsTlv::new(
            BGP_LS_TLV_IGP_METRIC,
            Bytes::from_static(&[63]),
        )]);
        assert_eq!(igp_metric(&one), Some(63));

        let two = attr29(&[BgpLsTlv::new(
            BGP_LS_TLV_IGP_METRIC,
            Bytes::from_static(&[0x01, 0x02]),
        )]);
        assert_eq!(igp_metric(&two), Some(0x0102));

        let three = attr29(&[BgpLsTlv::new(
            BGP_LS_TLV_IGP_METRIC,
            Bytes::from_static(&[0x01, 0x02, 0x03]),
        )]);
        assert_eq!(igp_metric(&three), Some(0x0001_0203));
    }

    #[test]
    fn igp_metric_wrong_length_returns_none() {
        for value in [&[][..], &[1, 2, 3, 4][..]] {
            let tlvs = attr29(&[BgpLsTlv::new(
                BGP_LS_TLV_IGP_METRIC,
                Bytes::copy_from_slice(value),
            )]);
            assert_eq!(igp_metric(&tlvs), None, "length {}", value.len());
        }
    }

    #[test]
    fn igp_metric_absent_returns_none() {
        let tlvs = attr29(&[BgpLsTlv::new(
            BGP_LS_TLV_TE_DEFAULT_METRIC,
            Bytes::from_static(&[0, 0, 0, 10]),
        )]);
        assert_eq!(igp_metric(&tlvs), None);
        assert_eq!(igp_metric(&[]), None);
    }

    #[test]
    fn prefix_metric_and_te_metric_parse_4_byte_be() {
        let tlvs = attr29(&[
            BgpLsTlv::new(
                BGP_LS_TLV_TE_DEFAULT_METRIC,
                Bytes::from_static(&[0x00, 0x00, 0x27, 0x10]),
            ),
            BgpLsTlv::new(
                BGP_LS_TLV_PREFIX_METRIC,
                Bytes::from_static(&[0x00, 0x01, 0x00, 0x00]),
            ),
        ]);
        assert_eq!(te_default_metric(&tlvs), Some(10_000));
        assert_eq!(prefix_metric(&tlvs), Some(0x0001_0000));

        // Wrong length and absence both return None.
        let short = attr29(&[BgpLsTlv::new(
            BGP_LS_TLV_PREFIX_METRIC,
            Bytes::from_static(&[0, 1]),
        )]);
        assert_eq!(prefix_metric(&short), None);
        assert_eq!(te_default_metric(&short), None);
    }

    #[test]
    fn attr29_tlv_walk_rejects_malformed() {
        // Truncated TLV header.
        assert!(bgp_ls_attribute_tlvs(&[0x04, 0x47, 0x00]).is_err());
        // Truncated TLV value: claims 4 bytes, has 1.
        assert!(bgp_ls_attribute_tlvs(&[0x04, 0x47, 0x00, 0x04, 0xaa]).is_err());
        // Empty attribute is valid and yields no TLVs.
        assert!(
            bgp_ls_attribute_tlvs(&[])
                .expect("empty attribute decodes")
                .is_empty()
        );
    }
}
