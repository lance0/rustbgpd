# birdwatcher-adapter — external looking glass REST adapter

Standalone HTTP server that exposes a **Birdwatcher-shaped read-only subset**
for [Alice-LG](https://github.com/alice-lg/alice-lg) and similar looking glass
frontends. It serves status, peer, accepted-route, and filtered-route views
from a running rustbgpd over gRPC. The status/peer/accepted endpoint paths and
response shapes match the removed in-daemon
`[global.telemetry.looking_glass]` server this adapter replaces; the filtered
view is served from the daemon's reject-retention store. This is not a
complete Alice-LG backend (no noexport view).

Rationale: the daemon's durable API identity is **gRPC + `rbgp`**.
Partial compatibility with someone else's REST API inside daemon core
is a permanent source of misunderstanding, so the birdwatcher surface
lives here as a maintained adapter instead. It is a workspace member
but not part of the default `cargo build`, release tarballs, or
container images; it builds with `--workspace` or an explicit
`-p birdwatcher-adapter`.

## Build + run

```sh
cargo run --release -p birdwatcher-adapter -- \
    --grpc-addr http://127.0.0.1:50051 \
    --listen 0.0.0.0:8080
```

Flags (also settable via env):

| Flag          | Env                             | Default          | Meaning                          |
|---------------|---------------------------------|------------------|----------------------------------|
| `--grpc-addr` | `BIRDWATCHER_ADAPTER_GRPC_ADDR` | (required)       | rustbgpd gRPC endpoint (TCP)     |
| `--listen`    | `BIRDWATCHER_ADAPTER_LISTEN`    | `127.0.0.1:8080` | REST listen address              |

The daemon needs a gRPC TCP listener the adapter can reach
(`[global.telemetry.grpc_tcp]`); read-only access is sufficient —
every RPC the adapter calls is a read.

## Endpoint → gRPC mapping

| REST endpoint (birdwatcher)  | Backing gRPC RPC(s)                                            |
|------------------------------|----------------------------------------------------------------|
| `GET /status`                | `GlobalService.GetGlobal` + `ControlService.GetHealth`         |
| `GET /protocols/bgp`         | `NeighborService.ListNeighbors` + `PolicyService.ListRejectedRoutes` (per-neighbor `routes.filtered` count) |
| `GET /routes/protocol/{id}`  | `RibService.ListReceivedRoutes` (paged, all unicast families)  |
| `GET /routes/peer/{peer}`    | `RibService.ListReceivedRoutes` (paged, all unicast families)  |
| `GET /routes/filtered/{id}`  | `PolicyService.ListRejectedRoutes` (unpaged — the store is bounded at the `[policy.reject_retention]` capacity, default 1024/peer) |

There are no placeholder 501 responses. Route `age` is served from the
`Route.received_at_epoch_seconds` proto field (RIB receive time) on the
accepted view and from the rejection wall-clock time on the filtered view.
Alice-LG's noexport view is not implemented (the daemon does not retain a
NO_EXPORT-excluded route set).

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

### Field-level gaps

| Field | Adapter value | Limitation |
|---|---|---|
| status `last_reconfig` | `""` | Reconfiguration time is not tracked. |
| protocol `routes.preferred` | `0` | Sentinel only; preferred-route count is not exposed. |
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
- End-to-end smoke test of the status/peer/accepted/filtered-route subset:
  `cargo test --test birdwatcher_adapter_smoke` (root package; spawns a real
  daemon plus this adapter, announces a clean route and a loop-poisoned one,
  and asserts both the accepted and filtered views).
