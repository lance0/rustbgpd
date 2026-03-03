# ADR-0033: Add-Path (RFC 7911)

**Status:** Accepted
**Date:** 2026-03-02

## Context

Add-Path (RFC 7911) allows a BGP speaker to advertise multiple paths
per prefix. This is essential for route servers at IXPs where the route
server must forward all candidate paths, not just the best. GoBGP supports
Add-Path; rustbgpd did not.

## Decision

### Scope: Receive + Single-Best Send

This landing implements Add-Path receive (accept multiple paths per prefix
from peers) and single-best outbound (advertise only the best path, with
path_id encoding when the peer negotiated Add-Path). Multi-path send
(route server mode) is deferred — see Consequences.

### NlriEntry struct

All NLRI throughout the codebase uses a named struct:

```rust
pub struct NlriEntry {
    pub path_id: u32,   // 0 = no Add-Path
    pub prefix: Prefix,
}
```

Non-Add-Path peers always have `path_id = 0`. One code path handles all
NLRI — no parallel variants. For wire-level IPv4 body NLRI,
`Ipv4NlriEntry` carries `path_id + Ipv4Prefix`.

### Wire codec

- Capability code 69: `Capability::AddPath(Vec<AddPathFamily>)` with
  `AddPathMode` enum (Receive=1, Send=2, Both=3)
- `decode_nlri_addpath()` / `encode_nlri_addpath()` for IPv4 body NLRI
- `decode_ipv6_nlri_addpath()` / `encode_ipv6_nlri_addpath()` for IPv6
- Wire format per RFC 7911 §3: `[4-byte path_id][prefix_len][prefix_bytes]`
- `ParsedUpdate` uses `Ipv4NlriEntry` with `path_id=0` for non-Add-Path
- `MpReachNlri` / `MpUnreachNlri` use `NlriEntry` (`Vec<NlriEntry>`)

### Capability negotiation

`negotiate_add_path()` intersects our capabilities with the peer's:
- "We Receive" requires "Peer Send" (or Both)
- "We Send" requires "Peer Receive" (or Both)
- Result stored on `NegotiatedSession.add_path_families`

### RIB composite keying

- `AdjRibIn` and `AdjRibOut` keyed by `(Prefix, u32)` — the path_id
  is part of the composite key
- `Route.path_id: u32` field (0 = no Add-Path, default for all
  non-Add-Path peers and locally-injected routes)
- `AdjRibIn::iter_prefix()` yields all routes for a given prefix across
  path IDs — used by `recompute_best()` for multi-candidate selection
- Loc-RIB unchanged: still `HashMap<Prefix, Route>`, one best per prefix

### Config

```toml
[neighbors.add_path]
receive = true
```

`PeerConfig.add_path_receive: bool` controls whether Add-Path Receive
is advertised in OPEN for the peer's configured families.

### gRPC API

- `Route.path_id`, `RouteEvent.path_id` fields
- `AddPathRequest.path_id` (0 = auto/default)
- `DeletePathRequest.path_id` (0 = delete default path)
- `WithdrawInjected` RIB update carries `path_id`

## Consequences

- Peers that advertise Add-Path can send multiple paths per prefix;
  all are stored in Adj-RIB-In with composite keying
- Best-path selection considers all candidates from all peers
- Outbound: single best path with path_id encoding for Add-Path peers,
  no path_id encoding for non-Add-Path peers
- Non-Add-Path peers: behavior completely unchanged (path_id=0 throughout)
- Route injection via gRPC supports explicit path_id for multiple
  injected paths per prefix

### Deferred: Multi-Path Send (Route Server Mode)

Multi-path send is explicitly deferred. It requires:
- `distribute_changes()` collecting all candidates, not just best
- Per-candidate export policy + split horizon evaluation
- Stable outbound path ID assignment per (target, prefix, source)
- AdjRibOut tracking multiple paths per prefix per peer
- Config: `send = true`, `send_max = N`

The receive + single-best landing validates the hard foundation
(capability negotiation, wire codec, NlriEntry, composite keying,
backward compatibility). Multi-path send builds on it.
