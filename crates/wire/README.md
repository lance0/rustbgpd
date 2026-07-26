# rustbgpd-wire

BGP message codec for Rust. Encode and decode OPEN, UPDATE, KEEPALIVE,
NOTIFICATION, and ROUTE-REFRESH messages per RFC 4271, with extensions for
MP-BGP, EVPN (including PMSI Tunnel for ingress-replication BUM), FlowSpec,
VPNv4/VPNv6 labeled NLRI substrate, BGP-LS/BGP-LS-VPN codec support,
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
| 4364 / 4659 | VPNv4/VPNv6 labeled NLRI substrate: label-stack + RD + IPv4/IPv6 prefix encode/decode. No daemon AFI/SAFI negotiation or RIB support by itself |
| 4456 | Route reflector: ORIGINATOR_ID, CLUSTER_LIST |
| 4486 | NOTIFICATION subcodes |
| 4684 | Route Target Constrain (RTC) NLRI codec (SAFI 132): `RtcNlri` encode/decode with default-route and prefix-bit bounds. Inert codec substrate — negotiation/distribution live in the daemon |
| 4724 | Graceful restart capability |
| 4760 | MP-BGP: `MP_REACH_NLRI` / `MP_UNREACH_NLRI` |
| 4761 §3.2.5 | Default Gateway extended community (decode) |
| 5291 | Outbound Route Filtering (ORF) capability (code 3) + ORF-carrying Route Refresh |
| 5292 | Address-Prefix ORF-Type (64), with the legacy pre-standard type (128) decoded for interoperability |
| 5492 | BGP capabilities |
| 5512 | Tunnel Encapsulation extended-community layout (4-byte reserved + 2-byte value) used by the EVPN VXLAN encap sub-type |
| 6514 §5 | PMSI Tunnel attribute (path attribute type 22): all 8 tunnel types from the IANA registry, with the EVPN-VXLAN ingress-replication form encoding the label field as the raw 24-bit VNI per RFC 8365 §5.1.3 |
| 6793 | 4-octet AS numbers, including canonical type 2/17 and type 7/18 ingress normalization plus capability-specific egress projection |
| 6811 | RPKI prefix-origin validation state — the `RpkiValidation` routing-domain enum (no extended-community codec) |
| 7313 | Enhanced Route Refresh (BoRR / EoRR markers) |
| 7385 | PMSI Tunnel Type IANA registry — `PmsiTunnelType` preserves unknown values via an `Other(u8)` variant |
| 7432 | EVPN: Types 1–4 (EAD, MAC/IP, IMET, Ethernet Segment) including MAC Mobility extended community (§7.7) |
| 7606 | Revised UPDATE error handling: `UpdateMessage::parse_revised` recovers malformed path attributes without aborting the parse, each carrying its §7 per-attribute disposition (treat-as-withdraw / attribute-discard / session-reset) from `malformed_attr_disposition`; malformed or duplicated `MP_REACH_NLRI` / `MP_UNREACH_NLRI` and unparseable NLRI stay session-reset (§5.3, §7.11) |
| 7674 | Clarification of MP_REACH_NLRI next-hop encoding |
| 7999 | `BLACKHOLE` well-known community (`0xFFFF_029A`, rendered as `65535:666`) |
| 7911 | Add-Path: path ID in NLRI encode/decode |
| 8092 | Large communities (3× u32) |
| 8097 | Origin Validation State Extended Community (type 0x43): `ORIGIN_VALIDATION_{VALID,NOT_FOUND,INVALID}` `ExtendedCommunity` constants with `OV_*` textual rendering. Codec only — RPKI-to-community stamping lives in the daemon |
| 8203 | Admin shutdown communication |
| 8277 | IPv4/IPv6 labeled-unicast NLRI codec (SAFI 4): label-stack + prefix encode/decode, Add-Path and withdraw forms. Inert codec substrate |
| 8326 | `GRACEFUL_SHUTDOWN` well-known community (`0xFFFF_0000`) |
| 8365 | EVPN over VXLAN encapsulation |
| 8538 | Notification GR (N-bit) |
| 8584 §2.2 | DF Election Extended Community (type 0x06, subtype 0x06): decode + construct of the algorithm / capabilities / DF-preference fields |
| 8654 | Extended messages (up to 65535 bytes). `encode_message_with_limit()` and the per-message `encode_with_limit()` helpers (on `NotificationMessage` / `RouteRefreshMessage`) encode against a caller-supplied size ceiling; the default `encode()` keeps the 4096-byte base limit |
| 8950 | Extended next hop (IPv4 NLRI over IPv6 NH); optional acceptance of a link-local-primary `MP_REACH_NLRI` next-hop for unnumbered peers via `UpdateValidationOptions` |
| 8955/8956 | FlowSpec: 13 component types, numeric/bitmask operators; §6.1-compliant `NEXT_HOP` validation (the irrelevant-next-hop case is accepted, not rejected); `FlowSpecRule::validate_encoded_len` rejects rules above the 12-bit `MAX_FLOWSPEC_NLRI_RULE_LEN` (4095 bytes) before they reach the wire |
| 9012 | BGP Encapsulation extended community (§4.1) — VXLAN sub-type used by EVPN encap |
| 9072 | Extended Optional Parameters Length for BGP OPEN: classic encoding through 255 optional-parameter octets, extended aggregate and per-parameter lengths above that boundary, and permissive extended-format receive at smaller lengths |
| 9135 | EVPN integrated routing for IRB |
| 9136 | EVPN Type 5: IP Prefix advertisement |
| 9234 | BGP Roles (OPEN capability code 9, `BgpRole`) + Only-to-Customer path attribute (type 35, `PathAttribute::OnlyToCustomer`). Codec only; malformed-length OTC is preserved as `Unknown` (not a fatal decode) so transport can apply RFC 7606 treat-as-withdraw. Negotiation + ingress/egress rules live in the daemon (ADR-0071) |
| 9494 | Long-lived graceful restart capability |
| 9552 | BGP-LS and BGP-LS-VPN NLRI/TLV codec with opaque preservation of unknown NLRI types and TLVs. Attribute 29 enforces optional non-transitive flags and structural TLV framing; malformed contained framing uses RFC 9552 whole-attribute discard while retaining the NLRI. The daemon consumes the codec for the ADR-0077 receive/API tranche. Typed topology read accessors live in `bgpls_topo`; local topology production remains outside the wire crate |
| 9687 | Send Hold Timer: NOTIFICATION code 8 (`NotificationCode::SendHoldTimerExpired`, subcode always 0 per §6). Codec only — the timer itself lives in the daemon |
| 9774 | AS_SET / AS_CONFED_SET deprecation: prohibited segment types in `AS_PATH` / `AS4_PATH` are rejected on decode with RFC 7606 treat-as-withdraw disposition, and an `AS_PATH` containing an AS_SET refuses to encode (`EncodeError::ValueOutOfRange`) |
| 9785 §3 | DF Election preference algorithms + Don't-Preempt bit, extending the RFC 8584 DF Election Extended Community |
| draft-abraitis-idr-addpath-paths-limit-04 | Experimental Paths-Limit capability (`PathsLimitFamily`, IANA-assigned capability code 76). The draft is expired and archived; interoperability and behavior remain experimental |
| 10005 | Link Bandwidth Extended Community receiver subset: decode exact transitive/non-transitive types 0x00/0x40, subtype 0x04, as raw AS + IEEE-754 bytes/second; the constructor remains non-transitive type 0x40 |

### 0.16.0 compatibility note

`rustbgpd-wire` 0.16.0 keeps the public API additive, but **decode acceptance
changed in six places**. Bytes that decoded under 0.15.0 may now be rejected or
typed differently, so diff exactly this list before upgrading a consumer that
asserts on decode outcomes:

- **Unsupported OPEN Optional Parameter types now error** with OPEN Message
  Error / Unsupported Optional Parameter (2/4) instead of being skipped.
  Unknown capabilities *inside* the Capabilities parameter remain accepted.
- **BGP-LS attribute 29 enforces its optional non-transitive flags and
  contained TLV framing.** Malformed contained framing discards the complete
  attribute (RFC 9552 whole-attribute discard) while preserving the BGP-LS NLRI
  and the session; valid unknown TLVs remain byte-stable for reflection.
- **AGGREGATOR decodes as a typed `PathAttribute::Aggregator` value** instead
  of falling through to `PathAttribute::Unknown`. Code matching on `Unknown`
  for type code 7 no longer sees it.
- **OPEN and KEEPALIVE over 4096 bytes are rejected** at header peek, before a
  framing caller buffers the declared body, regardless of a negotiated RFC 8654
  extended message length.
- **AS_SET and AS_CONFED_SET are rejected in a received `AS_PATH` or
  `AS4_PATH`** per RFC 9774, with the RFC 7606 treat-as-withdraw disposition.
  Paths that decoded before now withdraw their routes.
- **`ExtendedCommunity::as_link_bandwidth()` matches exact types only.**
  Communities it previously accepted by a looser match no longer resolve as
  link bandwidth.

### 0.15.0 compatibility note

0.15.0 added `Capability::PathsLimit`: code 76 now decodes to typed
`PathsLimitFamily` entries and is available as
`constants::capability_code::PATHS_LIMIT`. `Capability` is
`#[non_exhaustive]` (see [Enum exhaustiveness](#enum-exhaustiveness)), so
later registry additions land without a breaking release.

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
- **`PathAttribute`** — typed variants plus `Unknown` pass-through, including `AsPath`, `Aggregator`, `NextHop`, `Communities`, `MpReachNlri`, `LargeCommunities`, `PmsiTunnel` (RFC 6514), and `OnlyToCustomer` (RFC 9234)
- **`Prefix`** — `V4(Ipv4Prefix)` / `V6(Ipv6Prefix)` enum
- **`RpkiValidation` / `AspaValidation` / `AspaValidationContext`** — shared
  routing-domain validation state and ASPA session context used by rustbgpd's
  RIB, policy, transport, and RPKI crates
- **`Capability`** — OPEN capabilities: multi-protocol, 4-octet AS, Add-Path,
  experimental Paths-Limit (`Capability::PathsLimit` / `PathsLimitFamily`,
  code 76), graceful restart, Outbound Route Filtering, etc.
- **ORF types** (`orf` module, RFC 5291/5292) — `OrfCapEntry` (capability blocks), `OrfPayload` / `OrfEntryGroup` / `OrfEntries` (the Route Refresh ORF section), and `AddressPrefixOrf` (one Address-Prefix entry: action, match, sequence, min/max length, prefix). `RouteRefreshMessage::orf` carries the decoded section; a malformed IPv4/IPv6 unicast Address-Prefix group decodes to `OrfEntries::Malformed` (RFC 5291 §5.2 reset) rather than failing the message, while non-unicast / future-family Address-Prefix groups are preserved as raw bytes until those family encodings are implemented. Adding `orf` to `RouteRefreshMessage` made that struct `Clone` rather than `Copy` (0.11.0)
- **`FlowSpecRule`** / **`FlowSpecComponent`** — FlowSpec NLRI with all 13 match types
- **`EvpnRoute`** / **`EvpnRouteKey`** — typed EVPN routes (Types 1–5) with
  full payloads (RFC 7432, RFC 9136); `EvpnRouteKey` implements `Ord` for
  deterministic keyed collections
- **`vpn` module** — VPNv4/VPNv6 labeled NLRI substrate, including label-stack
  validation, Route Distinguisher, and IPv4/IPv6 prefix payloads
- **`bgpls` module** — BGP-LS/BGP-LS-VPN NLRI and TLV codec, preserving
  unknown object types and TLVs for the daemon's receive/API surface and
  future reflection support
- **`bgpls_topo` module** — typed read accessors over the opaque BGP-LS codec
  (`bgp_ls_attribute_tlvs`, `igp_metric`, `prefix_metric`, `te_default_metric`,
  `BgpLsNodeKey`, and the `BGP_LS_TLV_*` type constants)
- **`labeled` module** — IPv4/IPv6 labeled-unicast NLRI codec (SAFI 4, RFC 8277):
  `LabeledNlri` / `LabeledNlriEntry` / `LABELED_UNICAST_SAFI`, label-stack +
  prefix encode/decode with Add-Path and withdraw forms
- **`rtc` module** — Route Target Constrain NLRI codec (SAFI 132, RFC 4684):
  `RtcNlri` / `RTC_SAFI` / `RTC_MAX_PREFIX_BITS`, `decode_rtc_nlri` /
  `encode_rtc_nlri` with default-route and prefix-bit bounds
- **`PmsiTunnel`** / **`PmsiTunnelType`** / **`PmsiTunnelIdentifier`** — PMSI Tunnel attribute (RFC 6514 §5) carried on EVPN Type 3 IMET routes for ingress-replication BUM. Constructor `PmsiTunnel::for_evpn_ingress_replication(vni, ip)` emits the RFC 8365 §5.1.3 wire shape (raw 24-bit VNI in the label field, originator IP as the tunnel identifier).
- **`RouteDistinguisher`** — RFC 4364 §4.2 8-byte RD, used by EVPN and VPNv4/v6. Implements `Display` + `FromStr` for the standard `asn:val` / `ipv4:val` textual encodings
- **`DfElectionExtendedCommunity`** (`attribute`) — RFC 8584 §2.2 / RFC 9785 §3 DF Election Extended Community: `ExtendedCommunity::as_df_election()` decodes one, `ExtendedCommunity::df_election(algorithm, capabilities, preference: Option<u16>)` constructs it (EVPN DF election algorithm, capabilities, and the RFC 9785 preference / Don't-Preempt fields)
- **Link Bandwidth** (RFC 10005 §§2, 3.2) — `ExtendedCommunity::as_link_bandwidth()` decodes exact type 0x00/0x40, subtype 0x04, without interpreting the raw AS/float payload; `ExtendedCommunity::link_bandwidth(asn, bytes_per_sec)` continues to construct non-transitive type 0x40
- **Origin Validation State** (RFC 8097) — `ExtendedCommunity::ORIGIN_VALIDATION_VALID` /
  `_NOT_FOUND` / `_INVALID` constants (type 0x43) for the RPKI prefix-origin
  validation-state extended community, rendered `OV_VALID` / `OV_NOT_FOUND` /
  `OV_INVALID` by `Display` (0.14.0)
- **Revised error handling (RFC 7606)** — `UpdateMessage::parse_revised`
  returns `RevisedParsedUpdate`: the cleanly decoded `ParsedUpdate` plus the
  `MalformedAttribute`s recovered without aborting the parse (collected via
  `RevisedAttributeDecode`), each carrying an `ErrorDisposition`
  (`AttributeDiscard` / `TreatAsWithdraw` / `SessionReset`) from
  `malformed_attr_disposition(type_code, is_ibgp)`. `UpdateError` from
  attribute validation also exposes the disposition a revised-error-handling
  caller should apply
- **`UpdateValidationOptions`** — opt-in relaxations for
  `validate_update_attributes_with_options`, e.g. accepting a link-local-primary
  IPv4 `MP_REACH_NLRI` next-hop on a scoped unnumbered session (RFC 8950)
- **`DecodeError`** / **`EncodeError`** — structured error types via `thiserror`
- **`UpdateMessage::build`** / **`UpdateMessage::try_build`** — build a wire
  UPDATE from typed components; `try_build` is the fallible counterpart that
  returns `EncodeError` (e.g. `ValueOutOfRange` for an oversized FlowSpec rule
  vector) instead of panicking, since structured `MP_REACH_NLRI` /
  `MP_UNREACH_NLRI` attribute encoding is now fallible (0.13.0)
- **`Afi`** / **`Safi`** — IANA address-family identifiers; the BGP-LS codec
  adds `Afi::BgpLs` (16388) plus `Safi::BgpLs` (71) and `Safi::BgpLsVpn` (72)
  (0.13.0). Both are `#[non_exhaustive]` as of 0.15.0 (see [Enum
  exhaustiveness](#enum-exhaustiveness)), so downstream matches need a wildcard
  arm and later registry additions are not breaking
- **Well-known community constants** — `u32` values for matching and setting
  standard communities: `COMMUNITY_NO_EXPORT` / `COMMUNITY_NO_ADVERTISE` /
  `COMMUNITY_NO_EXPORT_SUBCONFED` (RFC 1997), `COMMUNITY_BLACKHOLE` (RFC 7999),
  `COMMUNITY_GRACEFUL_SHUTDOWN` (RFC 8326), `COMMUNITY_LLGR_STALE` /
  `COMMUNITY_NO_LLGR` (RFC 9494)

## Enum exhaustiveness

The enums that track IANA/RFC registries — `Capability`, `PathAttribute`,
`Afi`/`Safi`, `Message`/`MessageType`, `NotificationCode`,
`RouteRefreshSubtype`, the EVPN route/key enums, `BgpLsNlriType`, the
FlowSpec component/action enums, the ORF type/entries enums, the PMSI
tunnel enums, `BgpRole`, `AspaValidation`, and the decode/encode error
enums — are `#[non_exhaustive]`. Match them with a wildcard arm:

```rust
use rustbgpd_wire::Capability;

fn negotiate(capability: &Capability) {
    match capability {
        Capability::RouteRefresh => { /* ... */ }
        // New registry variants arrive in minor releases without a
        // semver-major break; ignore what you do not support.
        _ => {}
    }
}
```

Registry growth (a new capability code, path attribute, AFI/SAFI, EVPN
route type, …) is therefore a non-breaking addition from 0.15.0 on.
Closed-by-construction sets — `Origin`, `AsPathSegment`, `Prefix`,
`AddPathMode`, `ErrorDisposition`, `RpkiValidation`, and the fixed V4/V6
family enums — remain exhaustively matchable on purpose.

## Fuzz tested

Twelve fuzz targets exercise the codec continuously in CI:

- `decode_message` — full BGP message framing
- `decode_update` — UPDATE parsing with Add-Path and MP-BGP variants
- `decode_open` — OPEN + capability decode
- `decode_route_refresh` — ROUTE-REFRESH / ORF decode
- `decode_flowspec` — FlowSpec NLRI component decoding
- `decode_evpn` — EVPN NLRI (Types 1–5) decoding
- `encode_evpn` — EVPN NLRI encode round-trip
- `decode_vpn` — VPNv4/VPNv6 labeled NLRI decode + successful decode round-trip
- `decode_labeled` — labeled-unicast NLRI decode (SAFI 4)
- `decode_rtc` — RT-Constrain NLRI decode (SAFI 132)
- `decode_bgpls` — BGP-LS/BGP-LS-VPN NLRI and TLV decode + successful decode round-trip
- `parse_rd` — `RouteDistinguisher` `FromStr` parsing

## License

MIT OR Apache-2.0
