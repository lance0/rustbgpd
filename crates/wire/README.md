# rustbgpd-wire

BGP message codec for Rust. Encode and decode OPEN, UPDATE, KEEPALIVE,
NOTIFICATION, and ROUTE-REFRESH messages per RFC 4271, with extensions for
MP-BGP, EVPN (including PMSI Tunnel for ingress-replication BUM), FlowSpec,
Add-Path, Extended Messages, Outbound Route Filtering (RFC 5291/5292), BGP
Roles + Only-to-Customer (RFC 9234), and more.

This crate is the wire-protocol foundation of
[rustbgpd](https://github.com/lance0/rustbgpd) but is designed for standalone
use in any Rust project that needs to parse or build BGP messages — monitors,
analyzers, test harnesses, MRT readers, etc.

## Supported RFCs

| RFC | Feature |
|-----|---------|
| 1997 | Standard communities (4-byte), including `NO_EXPORT`, `NO_ADVERTISE`, and `NO_EXPORT_SUBCONFED` well-known constants |
| 2545 | IPv6 link-local next-hop in `MP_REACH_NLRI` (32-byte form); second-segment validated as `fe80::/10` on receive (rejects malformed advertisements) |
| 2918 | Route Refresh capability |
| 3032 | MPLS label: 3-byte label field as carried in EVPN NLRI |
| 4271 | BGP-4 core: OPEN, UPDATE, NOTIFICATION, KEEPALIVE |
| 4360 | Extended communities (route target, route origin, 4-byte AS) |
| 4364 §4.2 | Route Distinguisher: 8-byte wire form with all three encodings (2-octet AS, IPv4, 4-octet AS) plus `Display` and `FromStr` for the canonical textual forms |
| 4456 | Route reflector: ORIGINATOR_ID, CLUSTER_LIST |
| 4486 | NOTIFICATION subcodes |
| 4724 | Graceful restart capability |
| 4760 | MP-BGP: `MP_REACH_NLRI` / `MP_UNREACH_NLRI` |
| 4761 §3.2.5 | Default Gateway extended community (decode) |
| 5291 | Outbound Route Filtering (ORF) capability (code 3) + ORF-carrying Route Refresh |
| 5292 | Address-Prefix ORF-Type (64), with the legacy pre-standard type (128) decoded for interoperability |
| 5492 | BGP capabilities |
| 5512 | Tunnel Encapsulation extended-community layout (4-byte reserved + 2-byte value) used by the EVPN VXLAN encap sub-type |
| 6514 §5 | PMSI Tunnel attribute (path attribute type 22): all 8 tunnel types from the IANA registry, with the EVPN-VXLAN ingress-replication form encoding the label field as the raw 24-bit VNI per RFC 8365 §5.1.3 |
| 6793 | 4-octet AS numbers |
| 6811 | RPKI prefix-origin validation state — the `RpkiValidation` routing-domain enum (no extended-community codec) |
| 7313 | Enhanced Route Refresh (BoRR / EoRR markers) |
| 7385 | PMSI Tunnel Type IANA registry — `PmsiTunnelType` preserves unknown values via an `Other(u8)` variant |
| 7432 | EVPN: Types 1–4 (EAD, MAC/IP, IMET, Ethernet Segment) including MAC Mobility extended community (§7.7) |
| 7674 | Clarification of MP_REACH_NLRI next-hop encoding |
| 7999 | `BLACKHOLE` well-known community (`0xFFFF_029A`, rendered as `65535:666`) |
| 7911 | Add-Path: path ID in NLRI encode/decode |
| 8092 | Large communities (3× u32) |
| 8203 | Admin shutdown communication |
| 8326 | `GRACEFUL_SHUTDOWN` well-known community (`0xFFFF_0000`) |
| 8365 | EVPN over VXLAN encapsulation |
| 8538 | Notification GR (N-bit) |
| 8584 §2.2 | DF Election Extended Community (type 0x06, subtype 0x06): decode + construct of the algorithm / capabilities / DF-preference fields |
| 8654 | Extended messages (up to 65535 bytes) |
| 8950 | Extended next hop (IPv4 NLRI over IPv6 NH); optional acceptance of a link-local-primary `MP_REACH_NLRI` next-hop for unnumbered peers via `UpdateValidationOptions` |
| 8955/8956 | FlowSpec: 13 component types, numeric/bitmask operators; §6.1-compliant `NEXT_HOP` validation (the irrelevant-next-hop case is accepted, not rejected); `FlowSpecRule::validate_encoded_len` rejects rules above the 12-bit `MAX_FLOWSPEC_NLRI_RULE_LEN` (4095 bytes) before they reach the wire |
| 9012 | BGP Encapsulation extended community (§4.1) — VXLAN sub-type used by EVPN encap |
| 9135 | EVPN integrated routing for IRB |
| 9136 | EVPN Type 5: IP Prefix advertisement |
| 9234 | BGP Roles (OPEN capability code 9, `BgpRole`) + Only-to-Customer path attribute (type 35, `PathAttribute::OnlyToCustomer`). Codec only; malformed-length OTC is preserved as `Unknown` (not a fatal decode) so transport can apply RFC 7606 treat-as-withdraw. Negotiation + ingress/egress rules live in the daemon (ADR-0071) |
| 9494 | Long-lived graceful restart capability |
| 9785 §3 | DF Election preference algorithms + Don't-Preempt bit, extending the RFC 8584 DF Election Extended Community |
| draft-ietf-idr-link-bandwidth | Link Bandwidth Extended Community (non-transitive two-octet-AS-specific, type 0x40 subtype 0x04): decode + construct of the advertising AS and the IEEE-754 bytes/second bandwidth used to weight unequal-cost multipath |

## Usage

Decode a single BGP message from raw bytes:

```rust
use bytes::Bytes;
use rustbgpd_wire::{decode_message, Message, MAX_MESSAGE_LEN};

# fn handle(raw_bytes: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
let mut buf = Bytes::from(raw_bytes);
let msg = decode_message(&mut buf, MAX_MESSAGE_LEN)?;

match msg {
    Message::Update(update) => {
        let parsed = update.parse(
            true,   // 4-octet AS numbers negotiated
            false,  // Add-Path not negotiated for body NLRI
            &[],    // Add-Path families for MP NLRI (empty = none)
        )?;
        for entry in &parsed.announced {
            println!("announced: {}", entry.prefix);
        }
        for attr in &parsed.attributes {
            println!("attribute: {:?}", attr);
        }
    }
    Message::Open(open) => {
        println!("OPEN: as={} hold={} caps={}", open.my_as, open.hold_time, open.capabilities.len());
    }
    _ => {}
}
# Ok(()) }
```

Build and encode an OPEN message:

```rust
use std::net::Ipv4Addr;
use rustbgpd_wire::{Afi, Capability, encode_message, Message, OpenMessage, Safi};

let open = OpenMessage {
    version: 4,
    my_as: 65000,
    hold_time: 90,
    bgp_identifier: Ipv4Addr::new(10, 0, 0, 1),
    capabilities: vec![
        Capability::FourOctetAs { asn: 65000 },
        Capability::MultiProtocol { afi: Afi::Ipv4, safi: Safi::Unicast },
        Capability::RouteRefresh,
    ],
};
// encode_message returns Result<BytesMut, EncodeError>
let bytes = encode_message(&Message::Open(open)).expect("encode OPEN");
```

## Key types

- **`Message`** — top-level enum: `Open`, `Update`, `Keepalive`, `Notification`, `RouteRefresh`
- **`UpdateMessage`** / **`ParsedUpdate`** — raw wire form and parsed routes + attributes
- **`PathAttribute`** — 14 typed variants plus `Unknown` pass-through, including `AsPath`, `NextHop`, `Communities`, `MpReachNlri`, `LargeCommunities`, `PmsiTunnel` (RFC 6514), and `OnlyToCustomer` (RFC 9234)
- **`Prefix`** — `V4(Ipv4Prefix)` / `V6(Ipv6Prefix)` enum
- **`RpkiValidation` / `AspaValidation` / `AspaValidationContext`** — shared
  routing-domain validation state and ASPA session context used by rustbgpd's
  RIB, policy, transport, and RPKI crates
- **`Capability`** — OPEN capabilities: multi-protocol, 4-octet AS, Add-Path, graceful restart, Outbound Route Filtering, etc.
- **ORF types** (`orf` module, RFC 5291/5292) — `OrfCapEntry` (capability blocks), `OrfPayload` / `OrfEntryGroup` / `OrfEntries` (the Route Refresh ORF section), and `AddressPrefixOrf` (one Address-Prefix entry: action, match, sequence, min/max length, prefix). `RouteRefreshMessage::orf` carries the decoded section; a malformed IPv4/IPv6 unicast Address-Prefix group decodes to `OrfEntries::Malformed` (RFC 5291 §5.2 reset) rather than failing the message, while non-unicast / future-family Address-Prefix groups are preserved as raw bytes until those family encodings are implemented. Adding `orf` to `RouteRefreshMessage` made that struct `Clone` rather than `Copy` (0.11.0)
- **`FlowSpecRule`** / **`FlowSpecComponent`** — FlowSpec NLRI with all 13 match types
- **`EvpnRoute`** / **`EvpnRouteKey`** — typed EVPN routes (Types 1–5) with full payloads (RFC 7432, RFC 9136)
- **`PmsiTunnel`** / **`PmsiTunnelType`** / **`PmsiTunnelIdentifier`** — PMSI Tunnel attribute (RFC 6514 §5) carried on EVPN Type 3 IMET routes for ingress-replication BUM. Constructor `PmsiTunnel::for_evpn_ingress_replication(vni, ip)` emits the RFC 8365 §5.1.3 wire shape (raw 24-bit VNI in the label field, originator IP as the tunnel identifier).
- **`RouteDistinguisher`** — RFC 4364 §4.2 8-byte RD, used by EVPN and VPNv4/v6. Implements `Display` + `FromStr` for the standard `asn:val` / `ipv4:val` textual encodings
- **`DfElectionExtendedCommunity`** (`attribute`) — RFC 8584 §2.2 / RFC 9785 §3 DF Election Extended Community: `ExtendedCommunity::as_df_election()` decodes one, `ExtendedCommunity::df_election(algorithm, capabilities, preference: Option<u16>)` constructs it (EVPN DF election algorithm, capabilities, and the RFC 9785 preference / Don't-Preempt fields)
- **Link Bandwidth** (draft-ietf-idr-link-bandwidth) — `ExtendedCommunity::as_link_bandwidth()` decodes the advertising AS and the IEEE-754 bytes/second bandwidth from a non-transitive two-octet-AS-specific community (type 0x40 subtype 0x04); `ExtendedCommunity::link_bandwidth(asn, bytes_per_sec)` constructs one, for weighting unequal-cost multipath next hops
- **`UpdateValidationOptions`** — opt-in relaxations for
  `validate_update_attributes_with_options`, e.g. accepting a link-local-primary
  IPv4 `MP_REACH_NLRI` next-hop on a scoped unnumbered session (RFC 8950)
- **`DecodeError`** / **`EncodeError`** — structured error types via `thiserror`
- **Well-known community constants** — `u32` values for matching and setting
  standard communities: `COMMUNITY_NO_EXPORT` / `COMMUNITY_NO_ADVERTISE` /
  `COMMUNITY_NO_EXPORT_SUBCONFED` (RFC 1997), `COMMUNITY_BLACKHOLE` (RFC 7999),
  `COMMUNITY_GRACEFUL_SHUTDOWN` (RFC 8326), `COMMUNITY_LLGR_STALE` /
  `COMMUNITY_NO_LLGR` (RFC 9494)

## Fuzz tested

Six fuzz targets exercise the codec continuously in CI:

- `decode_message` — full BGP message framing
- `decode_update` — UPDATE parsing with Add-Path and MP-BGP variants
- `decode_flowspec` — FlowSpec NLRI component decoding
- `decode_evpn` — EVPN NLRI (Types 1–5) decoding
- `encode_evpn` — EVPN NLRI encode round-trip
- `parse_rd` — `RouteDistinguisher` `FromStr` parsing

## License

MIT OR Apache-2.0
