# ADR-0033: Add-Path (RFC 7911)

**Status:** Accepted
**Date:** 2026-03-02

## Context

Add-Path (RFC 7911) allows a BGP speaker to advertise multiple paths
per prefix. This is essential for route servers at IXPs where the route
server must forward all candidate paths, not just the best. GoBGP supports
Add-Path; rustbgpd did not.

## Decision

### Scope: Receive + Family-Aware Multi-Path Send

This implementation supports Add-Path receive (accept multiple paths per
prefix from peers) and family-aware multi-path outbound send (route server
mode). Peers can negotiate Add-Path send independently per family, so one
session can advertise multiple paths for IPv4 unicast while keeping IPv6
unicast single-best, or vice versa.

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
send = true
send_max = 4
```

`PeerConfig.add_path_receive: bool` controls whether Add-Path Receive
is advertised in OPEN. `PeerConfig.add_path_send: bool` controls
Send. `PeerConfig.add_path_send_max: u32` limits outbound paths.

### gRPC API

- `Route.path_id`, `RouteEvent.path_id` fields
- `AddPathRequest.path_id` (0 = auto/default)
- `DeletePathRequest.path_id` (0 = delete default path)
- `WithdrawInjected` RIB update carries `path_id`

## Consequences

- Peers that advertise Add-Path can send multiple paths per prefix;
  all are stored in Adj-RIB-In with composite keying
- Best-path selection considers all candidates from all peers
- Outbound: multi-path send for peers with `add_path_send = true`
  (IPv4 and IPv6). Non-Add-Path peers get no path_id encoding
- Non-Add-Path peers: behavior completely unchanged (path_id=0 throughout)
- Route injection via gRPC supports explicit path_id for multiple
  injected paths per prefix

### Multi-Path Send (Route Server Mode)

Multi-path send allows advertising multiple paths per prefix to peers
that negotiate Add-Path receive. This is the core route server feature
for IXP deployments.

**Config:**

```toml
[neighbors.add_path]
send = true       # advertise multiple paths per prefix
send_max = 4      # limit to top 4 candidates (omit for unlimited)
```

`PeerConfig.add_path_send: bool` controls whether Add-Path Send is
advertised in OPEN. `PeerConfig.add_path_send_max: u32` limits the
number of paths per prefix (0 = unlimited at transport layer, mapped
to `u32::MAX` after negotiation).

**Capability advertisement:** `add_path_capabilities()` now advertises
Send, Receive, or Both based on config. Transport computes the effective
`add_path_send_max` from the intersection of negotiation and config.
The RIB applies that numeric cap per peer, but only to families that
actually negotiated Add-Path Send/Both, so a single session can
simultaneously use multi-path export on one family and single-best
export on another.

**Distribution logic:**

`distribute_multipath_prefix()` is a static method on `RibManager` that:
1. Collects all candidates from all Adj-RIB-In entries for a prefix
2. Filters by split horizon, iBGP/RR suppression, sendable families
3. Sorts by `best_path_cmp` (deterministic ordering)
4. Takes top N candidates (limited by `send_max`)
5. Evaluates export policy per-candidate
6. Assigns rank-based path IDs (1-indexed: best=1, second=2, etc.)
7. Diffs against AdjRibOut to minimize wire churn

**Path ID assignment:** Rank-based (1-indexed). Path ID = candidate's
position in the best_path_cmp sorted order. This is simple and
deterministic; rank shifts on route changes cause re-announcements
for affected path IDs.

**Dual prefix tracking:** `distribute_changes()` takes both
`best_changed` (for single-best peers) and `all_affected` (for
multi-path peers). Any candidate change matters for multi-path peers,
while single-best peers only care about best-path changes.

**Withdrawal type:** `OutboundRouteUpdate.withdraw` changed from
`Vec<Prefix>` to `Vec<(Prefix, u32)>` to support per-path-id
withdrawals.

**Dual-stack:** Both IPv4 and IPv6 unicast support Add-Path send and
receive. IPv4 uses body NLRI path IDs; IPv6 uses path IDs inside
`MP_REACH_NLRI` / `MP_UNREACH_NLRI`. Add-Path send is family-aware:
if Send is negotiated for only a subset of the session's sendable
families, rustbgpd uses multi-path export only for those families and
keeps the others on single-best export.
