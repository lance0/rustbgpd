# rustbgpd-wire

BGP message codec for Rust. Encode and decode OPEN, UPDATE, KEEPALIVE,
NOTIFICATION, and ROUTE-REFRESH messages per RFC 4271, with extensions for
MP-BGP, FlowSpec, Add-Path, Extended Messages, and more.

This crate is the wire-protocol foundation of
[rustbgpd](https://github.com/lance0/rustbgpd) but is designed for standalone
use in any Rust project that needs to parse or build BGP messages — monitors,
analyzers, test harnesses, MRT readers, etc.

## Supported RFCs

| RFC | Feature |
|-----|---------|
| 4271 | BGP-4 core: OPEN, UPDATE, NOTIFICATION, KEEPALIVE |
| 4760 | MP-BGP: `MP_REACH_NLRI` / `MP_UNREACH_NLRI` (IPv6 unicast) |
| 4360 | Extended communities (route target, route origin, 4-byte AS) |
| 4456 | Route reflector: ORIGINATOR_ID, CLUSTER_LIST |
| 4724 | Graceful restart capability |
| 5492 | BGP capabilities |
| 7911 | Add-Path: path ID in NLRI encode/decode |
| 8092 | Large communities (3x u32) |
| 8203 | Admin shutdown communication |
| 8538 | Notification GR (N-bit) |
| 8654 | Extended messages (up to 65535 bytes) |
| 8950 | Extended next hop (IPv4 NLRI over IPv6 NH) |
| 8955/8956 | FlowSpec: 13 component types, numeric/bitmask operators |
| 9494 | Long-lived graceful restart capability |

## Usage

Parse an UPDATE from raw bytes:

```rust
use bytes::Bytes;
use rustbgpd_wire::{UpdateMessage, Afi, Safi};

let raw = Bytes::from(update_bytes);
let update = UpdateMessage::decode(&mut raw.clone(), raw.len())?;
let parsed = update.parse(
    true,   // 4-octet AS numbers
    false,  // no Add-Path on body NLRI
    &[],    // no Add-Path families for MP NLRI
)?;

for route in &parsed.announced {
    println!("announced: {}", route.prefix);
}
for attr in &parsed.attributes {
    println!("attribute: {:?}", attr);
}
```

Build and encode an OPEN message:

```rust
use rustbgpd_wire::{Message, open::OpenMessage, capability::Capability};

let open = OpenMessage {
    version: 4,
    my_as: 65000,
    hold_time: 90,
    bgp_id: [10, 0, 0, 1],
    capabilities: vec![
        Capability::FourOctetAs(65000),
        Capability::MultiProtocol { afi: 1, safi: 1 },
    ],
};
let msg = Message::Open(open);
let bytes = rustbgpd_wire::encode_message(&msg);
```

## Key types

- **`Message`** — top-level enum: `Open`, `Update`, `Keepalive`, `Notification`, `RouteRefresh`
- **`UpdateMessage`** / **`ParsedUpdate`** — raw wire form and parsed routes + attributes
- **`PathAttribute`** — 18+ attribute types including `AsPath`, `NextHop`, `Communities`, `MpReachNlri`, `LargeCommunities`
- **`Prefix`** — `V4(Ipv4Prefix)` / `V6(Ipv6Prefix)` enum
- **`Capability`** — OPEN capabilities: multi-protocol, 4-octet AS, Add-Path, graceful restart, etc.
- **`FlowSpecRule`** / **`FlowSpecComponent`** — FlowSpec NLRI with all 13 match types
- **`DecodeError`** / **`EncodeError`** — structured error types via `thiserror`

## Fuzz tested

Three fuzz targets exercise the decode paths continuously in CI:

- `decode_message` — full BGP message framing
- `decode_update` — UPDATE parsing with Add-Path and MP-BGP variants
- `decode_flowspec` — FlowSpec NLRI component decoding

## License

MIT OR Apache-2.0
