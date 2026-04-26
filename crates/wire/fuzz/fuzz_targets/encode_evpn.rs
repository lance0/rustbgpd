#![no_main]
//! Fuzz the encode → decode → encode round-trip for programmatically
//! constructed EVPN routes. The companion `decode_evpn` target only
//! exercises the input space reachable by the decoder; this target
//! exercises the constructor space.
//!
//! Each fuzzer iteration consumes raw bytes to build a sequence of
//! `EvpnRoute` values (route-type-tagged, fixed-size fields per type),
//! encodes them, decodes the encoded bytes, and asserts the result
//! decodes to the same set after a re-encode (the "encode is a
//! function" property). Decode errors and invariant violations are
//! tolerated — only panics fail the fuzzer.

use libfuzzer_sys::fuzz_target;
use rustbgpd_wire::evpn::{
    EthernetSegmentIdentifier, EthernetTagId, EvpnEadPerEs, EvpnEadPerEvi, EvpnEs,
    EvpnImet, EvpnIpPrefixRoute, EvpnIpPrefixValue, EvpnMacIp, EvpnRoute, MacAddress,
    MplsLabel, RouteDistinguisher, decode_evpn_nlri, encode_evpn_nlri,
};
use rustbgpd_wire::nlri::{Ipv4Prefix, Ipv6Prefix};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

struct ByteCursor<'a> {
    buf: &'a [u8],
}

impl<'a> ByteCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.buf.len() < n {
            return None;
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Some(head)
    }

    fn take_byte(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }

    fn take_u32(&mut self) -> Option<u32> {
        self.take(4).map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
}

fn build_route(c: &mut ByteCursor<'_>) -> Option<EvpnRoute> {
    let kind = c.take_byte()?;
    let rd_bytes: [u8; 8] = c.take(8)?.try_into().ok()?;
    let rd = RouteDistinguisher::new(rd_bytes);
    match kind % 6 {
        0 => {
            // Type 1 EAD per-ES — non-zero ESI, MAX_ET tag forced on encode
            let mut esi: [u8; 10] = c.take(10)?.try_into().ok()?;
            if esi.iter().all(|&b| b == 0) {
                esi[0] = 1;
            }
            let label = MplsLabel::new(c.take_u32()? & 0x00FF_FFFF);
            Some(EvpnRoute::EadPerEs(EvpnEadPerEs {
                rd,
                esi: EthernetSegmentIdentifier::new(esi),
                ethernet_tag: EthernetTagId::MAX_ET,
                label,
            }))
        }
        1 => {
            // Type 1 EAD per-EVI — non-zero ESI, non-MAX_ET tag
            let mut esi: [u8; 10] = c.take(10)?.try_into().ok()?;
            if esi.iter().all(|&b| b == 0) {
                esi[0] = 1;
            }
            let mut tag = c.take_u32()?;
            if tag == EthernetTagId::MAX_ET.0 {
                tag = 0;
            }
            let label = MplsLabel::new(c.take_u32()? & 0x00FF_FFFF);
            Some(EvpnRoute::EadPerEvi(EvpnEadPerEvi {
                rd,
                esi: EthernetSegmentIdentifier::new(esi),
                ethernet_tag: EthernetTagId(tag),
                label,
            }))
        }
        2 => {
            // Type 2 MAC/IP
            let esi: [u8; 10] = c.take(10)?.try_into().ok()?;
            let tag = c.take_u32()?;
            let mac: [u8; 6] = c.take(6)?.try_into().ok()?;
            let ip_kind = c.take_byte()? % 3;
            let ip = match ip_kind {
                0 => None,
                1 => {
                    let o: [u8; 4] = c.take(4)?.try_into().ok()?;
                    Some(IpAddr::V4(Ipv4Addr::from(o)))
                }
                _ => {
                    let o: [u8; 16] = c.take(16)?.try_into().ok()?;
                    Some(IpAddr::V6(Ipv6Addr::from(o)))
                }
            };
            let label1 = MplsLabel::new(c.take_u32()? & 0x00FF_FFFF);
            let label2 = if c.take_byte()? & 1 == 1 {
                Some(MplsLabel::new(c.take_u32()? & 0x00FF_FFFF))
            } else {
                None
            };
            Some(EvpnRoute::MacIp(EvpnMacIp {
                rd,
                esi: EthernetSegmentIdentifier::new(esi),
                ethernet_tag: EthernetTagId(tag),
                mac: MacAddress(mac),
                ip,
                label1,
                label2,
            }))
        }
        3 => {
            // Type 3 IMET
            let tag = c.take_u32()?;
            let ip = if c.take_byte()? & 1 == 1 {
                let o: [u8; 4] = c.take(4)?.try_into().ok()?;
                IpAddr::V4(Ipv4Addr::from(o))
            } else {
                let o: [u8; 16] = c.take(16)?.try_into().ok()?;
                IpAddr::V6(Ipv6Addr::from(o))
            };
            Some(EvpnRoute::Imet(EvpnImet {
                rd,
                ethernet_tag: EthernetTagId(tag),
                originator_ip: ip,
            }))
        }
        4 => {
            // Type 4 ES — non-zero ESI
            let mut esi: [u8; 10] = c.take(10)?.try_into().ok()?;
            if esi.iter().all(|&b| b == 0) {
                esi[0] = 1;
            }
            let ip = if c.take_byte()? & 1 == 1 {
                let o: [u8; 4] = c.take(4)?.try_into().ok()?;
                IpAddr::V4(Ipv4Addr::from(o))
            } else {
                let o: [u8; 16] = c.take(16)?.try_into().ok()?;
                IpAddr::V6(Ipv6Addr::from(o))
            };
            Some(EvpnRoute::Es(EvpnEs {
                rd,
                esi: EthernetSegmentIdentifier::new(esi),
                originator_ip: ip,
            }))
        }
        _ => {
            // Type 5 IP Prefix — gateway family must match prefix family
            let esi: [u8; 10] = c.take(10)?.try_into().ok()?;
            let tag = c.take_u32()?;
            let label = MplsLabel::new(c.take_u32()? & 0x00FF_FFFF);
            if c.take_byte()? & 1 == 1 {
                let o: [u8; 4] = c.take(4)?.try_into().ok()?;
                let len = c.take_byte()?.min(32);
                let prefix = EvpnIpPrefixValue::V4(Ipv4Prefix::new(Ipv4Addr::from(o), len));
                let gw_o: [u8; 4] = c.take(4)?.try_into().ok()?;
                Some(EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
                    rd,
                    esi: EthernetSegmentIdentifier::new(esi),
                    ethernet_tag: EthernetTagId(tag),
                    prefix,
                    gateway: IpAddr::V4(Ipv4Addr::from(gw_o)),
                    label,
                }))
            } else {
                let o: [u8; 16] = c.take(16)?.try_into().ok()?;
                let len = c.take_byte()?.min(128);
                let prefix = EvpnIpPrefixValue::V6(Ipv6Prefix::new(Ipv6Addr::from(o), len));
                let gw_o: [u8; 16] = c.take(16)?.try_into().ok()?;
                Some(EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
                    rd,
                    esi: EthernetSegmentIdentifier::new(esi),
                    ethernet_tag: EthernetTagId(tag),
                    prefix,
                    gateway: IpAddr::V6(Ipv6Addr::from(gw_o)),
                    label,
                }))
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = ByteCursor::new(data);
    let mut routes = Vec::new();
    while let Some(r) = build_route(&mut cursor) {
        routes.push(r);
        if routes.len() >= 32 {
            break;
        }
    }
    if routes.is_empty() {
        return;
    }
    let mut buf = Vec::new();
    encode_evpn_nlri(&routes, &mut buf);
    let decoded = decode_evpn_nlri(&buf).expect("constructed routes must decode");
    let mut buf2 = Vec::new();
    encode_evpn_nlri(&decoded, &mut buf2);
    assert_eq!(buf, buf2, "encode is not a function");
});
