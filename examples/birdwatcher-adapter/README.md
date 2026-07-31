# birdwatcher-adapter — external looking glass REST adapter

Standalone HTTP server that exposes a **Birdwatcher-shaped read-only subset**
for [Alice-LG](https://github.com/alice-lg/alice-lg) and similar looking glass
frontends. It serves status, peer, accepted-route, filtered-route, and
noexport views from a running rustbgpd over gRPC. The status/peer/accepted
endpoint paths and response shapes match the removed in-daemon
`[global.telemetry.looking_glass]` server this adapter replaces; the filtered
view is served from the daemon's reject-retention store and the noexport view
from a live-ladder dry run of the export decision. Coverage is honest, not
complete: IPv4/IPv6 unicast single-table only (no VPN/EVPN views, no
`/routes/dump`).

Rationale: the daemon's durable API identity is **gRPC + `rbgp`**.
Partial compatibility with someone else's REST API inside daemon core
is a permanent source of misunderstanding, so the birdwatcher surface
lives here as a maintained adapter instead.

<!-- release-install-contract:birdwatcher-boundary:start -->
The `birdwatcher-adapter` binary is included in release tarballs. It is
excluded from the default `cargo build`, native `.deb`/`.rpm` packages, and
container images; build it from a source checkout with `--workspace` or an
explicit `-p birdwatcher-adapter`.
<!-- release-install-contract:birdwatcher-boundary:end -->

## Build + run

```sh
cargo run --release -p birdwatcher-adapter -- \
    --grpc-addr http://127.0.0.1:50051 \
    --grpc-token-file /run/secrets/rustbgpd-token \
    --listen 0.0.0.0:8080
```

Flags (also settable via env):

| Flag                | Env                                   | Default          | Meaning                                      |
|---------------------|---------------------------------------|------------------|----------------------------------------------|
| `--grpc-addr`       | `BIRDWATCHER_ADAPTER_GRPC_ADDR`       | (required)       | rustbgpd gRPC endpoint (TCP)                 |
| `--grpc-token-file` | `BIRDWATCHER_ADAPTER_GRPC_TOKEN_FILE` | (unset)          | Optional rustbgpd bearer-token file          |
| `--listen`          | `BIRDWATCHER_ADAPTER_LISTEN`          | `127.0.0.1:8080` | REST listen address                          |

The command-line token path takes precedence over the environment variable.
The adapter reads it once at startup, trims trailing whitespace, and rejects
empty token files or values that are not valid ASCII gRPC metadata without
logging the token. Omitting it preserves unauthenticated compatibility for a
daemon listener that permits it.

The daemon needs a gRPC TCP listener the adapter can reach
(`[global.telemetry.grpc_tcp]`); read-only access is sufficient —
every RPC the adapter calls is a read. For a bearer-protected Tier listener,
set its stable `principal` to an `observer` (or stronger) role and pass the
matching token file to the adapter.

## Endpoint → gRPC mapping

| REST endpoint (birdwatcher)  | Backing gRPC RPC(s)                                            |
|------------------------------|----------------------------------------------------------------|
| `GET /status`                | `GlobalService.GetGlobal` + `ControlService.GetHealth`         |
| `GET /protocols/bgp`         | `NeighborService.ListNeighbors` + `PolicyService.ListRejectedRoutes` (per-neighbor `routes.filtered` count) |
| `GET /routes/protocol/{id}`  | `RibService.ListReceivedRoutes` (paged, all unicast families)  |
| `GET /routes/peer/{peer}`    | `RibService.ListReceivedRoutes` (paged, all unicast families)  |
| `GET /routes/filtered/{id}`  | `PolicyService.ListRejectedRoutes` (unpaged — the store is bounded at the `[policy.reject_retention]` capacity, default 1024/peer) |
| `GET /routes/noexport/{id}`  | `RibService.ListBestRoutes` − `RibService.ListAdvertisedRoutes` (both paged), each missing prefix explained by `RibService.ExplainAdvertisedRoute` |

There are no placeholder 501 responses. Route `age` is served from the
`Route.received_at_epoch_seconds` proto field (RIB receive time) on the
accepted view and from the rejection wall-clock time on the filtered view.

## Filtered routes and reject reasons

`/routes/filtered/{id}` (accepts `bgp_<addr>` protocol ids and bare peer IPs)
serves every rejected inbound route the peer's session has retained, with
canonical reason tokens from `PolicyService.ListRejectedRoutes`
(`[policy.reject_retention]` in `docs/CONFIGURATION.md`; unicast only,
LRU-bounded per peer — at the cap the view shows the most recent rejections).
Semantics worth knowing:

- **Retention disabled** (`[policy.reject_retention] enabled = false`): the
  view is empty with a log line — a configuration fact, not an error.
- **No live session**: the session-local store is gone; the view is empty.
- The daemon deliberately does **not** tag reject-reason communities onto
  retained routes; the adapter synthesizes the community representation at
  the serving edge (below), so the daemon surface stays structured.

### Reject-reason → large-community mapping

Alice-LG identifies why a route was filtered by matching a large community
against its rejection config (the BIRD/arouteserver convention). The adapter
appends one synthesized triplet `64496:65520:<id>` per route — global
administrator `64496` (RFC 5398 documentation ASN, can never collide with a
community the route actually carried on the wire), function `65520` (the
arouteserver reject-reason function value), and a stable id per reason token:

| Reason token         | Large community  | Meaning                                        |
|----------------------|------------------|------------------------------------------------|
| `policy_reject`      | `64496:65520:1`  | Denied by import policy (detail = policy name) |
| `otc_route_leak`     | `64496:65520:2`  | RFC 9234 Only-to-Customer role leak            |
| `next_hop_ownership` | `64496:65520:3`  | Route-server strict NEXT_HOP ownership         |
| `as_path_loop`       | `64496:65520:4`  | Own AS in the received AS_PATH                 |
| `rr_loop`            | `64496:65520:5`  | Reflection loop (ORIGINATOR_ID / CLUSTER_LIST) |
| `treat_as_withdraw`  | `64496:65520:6`  | RFC 7606 treat-as-withdraw attribute handling  |
| *(unrecognized)*     | `64496:65520:0`  | Future token this adapter build predates       |

The ids are append-only. Each filtered route also carries human-readable
`reject_reason` / `reject_reason_detail` fields (plus `rpki_validation` /
`aspa_validation`) as extra JSON keys — visible to curl users, ignored by
parsers that don't know them.

Alice-LG config to render the reasons:

```ini
[rejection]
asn = 64496
reject_id = 65520

[rejection_reasons]
0 = Route was filtered
1 = Denied by import policy
2 = Only-to-Customer role leak (RFC 9234)
3 = NEXT_HOP is not the peer's own address
4 = Receiver's AS appears in the AS_PATH
5 = Route reflection loop
6 = Malformed attributes (treat-as-withdraw, RFC 7606)
```

## Noexport routes and reasons

`/routes/noexport/{id}` (accepts `bgp_<addr>` protocol ids and bare peer IPs)
serves every Loc-RIB best route that is **not** in the peer's Adj-RIB-Out,
each explained by `RibService.ExplainAdvertisedRoute` — a dry run of the same
export staging body the live path executes, so the reason cannot drift from
the real decision. Precisely what the view contains:

- **All export-ladder suppressions**, not only NO_EXPORT-community routes:
  split horizon, iBGP/RFC 4456 reflection rules, family negotiation,
  RFC 9494 LLGR-stale handling, RFC 5291 ORF, RFC 4684 RT membership, and
  export-policy denial. Each route names its stopping gate.
- **Prefix-granular**: a prefix with any advertised path is "exported" —
  an Add-Path peer's partially-suppressed extra paths are not reported.
- **IPv4/IPv6 unicast, single-best candidates only** (Loc-RIB best routes
  are the export candidate set), matching the rest of the adapter.
- **No live session ⇒ empty view** with a log line — nothing is being
  exported *or* withheld, same posture as the filtered view.
- If the snapshot diff races an in-flight advertisement (the explain says
  the route *would* be advertised), the route is dropped from the view —
  it never fabricates a "not exported" claim.

**Cost:** each request pages the complete Loc-RIB and peer Adj-RIB-Out, then
makes one `ExplainAdvertisedRoute` call per suppressed prefix. Both paged
snapshots are version-fenced: concurrent table churn can fail the request
rather than return a mixed-generation answer, so clients should retry a 502.
Alice-LG's `[noexport] load_on_demand` (its default) fits this — the view is
only computed when an operator opens it. Do not poll it as a metrics endpoint;
for very large or fast-changing Loc-RIBs, use a caching proxy and expect the
current per-request implementation to be expensive until a bulk RPC exists.

### Noexport-reason → large-community mapping

Same edge-synthesis convention as the reject reasons: one appended triplet
`64496:65521:<id>` per route — function `65521` (adjacent to the
reject-reason function `65520`, distinct so the `[rejection]` and
`[noexport]` matchers never overlap), and a stable id per stopping gate:

| Stopping gate    | Large community  | Meaning                                          |
|------------------|------------------|--------------------------------------------------|
| `split_horizon`  | `64496:65521:1`  | Route originated from the target peer            |
| `rr_reflection`  | `64496:65521:2`  | iBGP split-horizon / RFC 4456 reflection rules   |
| `family`         | `64496:65521:3`  | Peer did not negotiate the route's AFI/SAFI      |
| `llgr`           | `64496:65521:4`  | RFC 9494 LLGR-stale suppression                  |
| `orf`            | `64496:65521:5`  | RFC 5291 outbound route filter                   |
| `rt_membership`  | `64496:65521:6`  | RFC 4684 RT-Constrain membership gate            |
| `export_policy`  | `64496:65521:7`  | Denied by export policy (detail = deciding term) |
| *(unrecognized)* | `64496:65521:0`  | Future gate this adapter build predates          |

The ids are append-only. Each noexport route also carries human-readable
`noexport_reason` (the gate name) / `noexport_reason_detail` extra JSON
keys, ignored by parsers that don't know them.

Alice-LG config to render the reasons:

```ini
[noexport]
asn = 64496
noexport_id = 65521
load_on_demand = true

[noexport_reasons]
0 = Route was not exported
1 = Route originated from this peer (split horizon)
2 = Route reflection rules (RFC 4456)
3 = Address family not negotiated
4 = Long-lived stale route (RFC 9494)
5 = Outbound route filter (RFC 5291)
6 = RT membership (RFC 4684)
7 = Denied by export policy
```

### Field-level gaps

| Field | Adapter value | Limitation |
|---|---|---|
| status `last_reconfig` | `""` | Reconfiguration time is not tracked. |
| protocol `routes.preferred` | omitted | No per-peer Loc-RIB best count exists on the gRPC surface; deriving one would page the whole Loc-RIB on every poll. The field is left out rather than served as a wrong `0` — a client that defaults absent fields still reads zero, but nothing here asserts it. |
| route `interface` | `""` | Interface identity is not exposed for these routes. |
| route `metric` | `0` | Sentinel only; this is not an IGP metric. |
| route `primary` | `false` | Sentinel only; primary-route status is not exposed. |
| filtered route `bgp.origin` | `""` | ORIGIN is not retained for rejected routes. |
| filtered route `bgp.local_pref`, `bgp.med` | `0` | Not retained for rejected routes. |

Error behavior differs only on failure: when the daemon is unreachable
the adapter returns `502 Bad Gateway` (the in-daemon server returned
`500` when its internal channels failed).

## Testing

- Unit tests: `cargo test -p birdwatcher-adapter`
- End-to-end smoke test of the status/peer/accepted/filtered/noexport
  subset: `cargo test --test birdwatcher_adapter_smoke` (root package;
  spawns a real daemon plus this adapter, announces a clean route and a
  loop-poisoned one from one live peer plus an announce-nothing receiver
  peer, and asserts the accepted, filtered, and both sides of the noexport
  views — suppressed route present for the announcer, exported route absent
  for the receiver).
