# ADR-0045: Private AS Removal

- **Status:** Accepted
- **Date:** 2026-03-05

## Context

Private AS numbers (64512–65534 per RFC 5398, 4200000000–4294967294 per RFC 6996) are used internally but should not leak into the global routing table. IX operators and transit providers commonly need to strip these ASNs from AS_PATH before eBGP advertisement. This was a top-5 GoBGP parity gap.

## Decision

### Three Modes (matching FRR)

- **`remove`** — remove all private ASNs only if the entire AS_PATH consists of private ASNs (safe default)
- **`all`** — unconditionally remove all private ASNs from every segment; drop empty segments
- **`replace`** — replace each private ASN with the local ASN

### Integration Point

Private AS removal is applied in `prepare_outbound_attributes()` and `prepare_outbound_attributes_flowspec()` in the transport crate. It operates on the input AS_PATH **before** local ASN prepend — clean first, then prepend.

### Scope

- **eBGP only** — iBGP never modifies AS_PATH.
- **Route server clients skipped** — `route_server_client` peers already skip AS_PATH manipulation.

### Wire Crate Helpers

- `is_private_asn(asn: u32) -> bool` — free function checking both 16-bit and 32-bit private ranges.
- `AsPath::all_private() -> bool` — returns true if every ASN in the path is private (used by `Remove` mode).

### Config

Per-neighbor TOML field:
```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
remove_private_as = "all"
```

Config validation rejects:
- Unknown mode values (must be `"remove"`, `"all"`, or `"replace"`)
- iBGP peers (same as `route_server_client` validation)

### Threading

Follows the `route_server_client` pattern: `Neighbor` → `TransportConfig.remove_private_as` → `PeerManagerNeighborConfig.remove_private_as`.

`RemovePrivateAs` enum defined in transport config, re-exported from crate root.

### `remove_private_asns()` Free Function

Standalone function in `session.rs` that takes `(&AsPath, RemovePrivateAs, u32)` and returns a new `AsPath`. Called from both unicast and FlowSpec outbound attribute preparation.

### gRPC API

- `NeighborConfig.remove_private_as` proto field (string: `""`, `"remove"`, `"all"`, `"replace"`).
- `NeighborService` receives `local_asn` at construction so `AddNeighbor` can reject `remove_private_as` on iBGP peers (same guard as TOML validation).
- `PeerInfo.remove_private_as` exposes the active mode in `ListNeighbors` / `GetNeighborState` responses.
- `parse_remove_private_as_proto()` / `remove_private_as_to_string()` handle proto ↔ enum conversion.
- Dynamic peers default to `Disabled` (empty string).

## Consequences

- Private ASN leakage can now be prevented via simple per-neighbor config.
- Three modes match FRR behavior, familiar to operators.
- No performance impact when `Disabled` (default) — the function returns a clone immediately.
- Config persistence round-trips the string value through `Option<String>`.
- gRPC dynamic peers default to `Disabled` (no private AS removal).
- gRPC query responses include the active mode, enabling monitoring and tooling.
