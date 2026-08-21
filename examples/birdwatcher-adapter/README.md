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
The `birdwatcher-adapter` binary is included in release tarballs and also in:

- native `.deb`/`.rpm` packages; and
- the production container image.

It remains excluded from the default source-checkout `cargo build`; build it
with `--workspace` or an explicit `-p birdwatcher-adapter`.
<!-- release-install-contract:birdwatcher-boundary:end -->

## Build + run

```sh
cargo run --release -p birdwatcher-adapter -- \
    --grpc-addr unix:///var/lib/rustbgpd/grpc.sock \
    --listen 0.0.0.0:8080
```

Flags (also settable via env):

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--grpc-addr` | `BIRDWATCHER_ADAPTER_GRPC_ADDR` | (required) | rustbgpd gRPC endpoint (`http[s]://` or `unix:///absolute/path`) |
| `--grpc-token-file` | `BIRDWATCHER_ADAPTER_GRPC_TOKEN_FILE` | (unset) | Optional rustbgpd bearer-token file |
| `--listen` | `BIRDWATCHER_ADAPTER_LISTEN` | `127.0.0.1:8080` | REST listen address |
| `--protocol-alias PROTOCOL=PEER_IP@TABLE` | `BIRDWATCHER_ADAPTER_PROTOCOL_ALIASES` (semicolon-delimited) | (unset) | Repeatable startup-only Bird's Eye protocol/table identity |
| `--protocol-alias-file PATH` | `BIRDWATCHER_ADAPTER_PROTOCOL_ALIAS_FILE` | (unset) | File-backed aliases; mutually exclusive with `--protocol-alias` |
| `--max-routes` | `BIRDWATCHER_ADAPTER_MAX_ROUTES` | `1000` | Maximum RIB-derived route-array response size; must be non-zero |

The command-line token path takes precedence over the environment variable.
The adapter reads it once at startup, trims trailing whitespace, and rejects
empty token files or values that are not valid ASCII gRPC metadata without
logging the token. Omitting it preserves unauthenticated compatibility for a
daemon listener that permits it.

The adapter may start before the daemon or Unix socket exists. Its REST
requests return `502 Bad Gateway` while the gRPC endpoint is unavailable and
recover on later requests without an adapter restart.

Every adapter RPC is a read, but the convenient owner-only default socket
authenticates its clients as operator-tier `local-operator`. Run the adapter as
the `rustbgpd` user and use `unix:///var/lib/rustbgpd/grpc.sock` only when that
broader local trust is acceptable. For least privilege, give the adapter a
dedicated loopback listener mapped to `observer`:

```toml
[security.grpc]
enforcement = "tier"
[security.grpc.roles]
"rustbgpd://observer/birdwatcher" = "observer"
[global.telemetry.grpc_tcp]
address = "127.0.0.1:50051"
token_file = "/run/secrets/rustbgpd-birdwatcher-token"
principal = "rustbgpd://observer/birdwatcher"
```

Then pass that address and the same `token_file` to the adapter. Expose the TCP
listener beyond loopback only with the mTLS controls in `docs/SECURITY.md`.

## Endpoint → gRPC mapping

| REST endpoint (birdwatcher)  | Backing gRPC RPC(s)                                            |
|------------------------------|----------------------------------------------------------------|
| `GET /status`                | `GlobalService.GetGlobal` + `ControlService.GetHealth`         |
| `GET /protocols/bgp`         | One `NeighborService.ListNeighbors` request, including actor-authoritative per-neighbor `routes.filtered` counts |
| `GET /protocol/{id}`         | Same live neighbor object exposed by `GET /protocols/bgp`              |
| `GET /symbols`               | Sorted live protocol and routing-table identities from `NeighborService.ListNeighbors` |
| `GET /routes/protocol/{id}`  | `RibService.ListReceivedRoutes` (paged, all unicast families)  |
| `GET /routes/export/{id}`    | `RibService.ListAdvertisedRoutes` (paged, all unicast families) |
| `GET /route/{prefix}/protocol/{id}` | `RibService.ListReceivedRoutes` (paged, exact IPv4/IPv6 unicast prefix) |
| `GET /route/{prefix}/export/{id}` | `RibService.ListAdvertisedRoutes` (paged, exact IPv4/IPv6 unicast prefix) |
| `GET /route/{prefix}/table/{table}` | `RibService.LookupBestPath` (bounded longest-prefix match with one matched-prefix candidate set) |
| `GET /routes/peer/{peer}`    | `RibService.ListReceivedRoutes` (paged, all unicast families)  |
| `GET /routes/filtered/{id}`  | `PolicyService.ListRejectedRoutes` (unpaged — the store is bounded at the `[policy.reject_retention]` capacity, default 1024/peer) |
| `GET /routes/lc-zwild/protocol/{id}/{x}/{y}` | `GlobalService.GetGlobal` + `PolicyService.ListRejectedRoutes` for IXP Manager's `{daemon ASN}:1101:*` filtered-prefix query |
| `GET /routes/noexport/{id}`  | `RibService.ListBestRoutes` − `RibService.ListAdvertisedRoutes` (both paged), each missing prefix explained by `RibService.ExplainAdvertisedRoute` |

There are no placeholder 501 responses. Route `age` is served from the
`Route.received_at_epoch_seconds` proto field (RIB receive time) on the
accepted view and from the rejection wall-clock time on the filtered view.
Status `last_reconfig` is the UTC rendering of the daemon's last successfully
accepted full policy generation (initial load, SIGHUP, or config transaction);
it stays empty only until the daemon reports a positive timestamp.

Protocol inventory never fans out rejected-route queries. It fails HTTP 502
when a stale or older daemon omits the retained count instead of presenting a
false zero. Each row carries `route_limit_at` from the same accepted-prefix
count as `routes.imported`; finite limits add canonical `import_limit` and
`limit_action` fields.

The same one-`ListNeighbors` snapshot supplies protocol-detail transport
state. Established rows expose `source_address` only from the daemon's cached
local IP address and `keepalive` only from its negotiated cadence,
including zero. `connection` is empty for Idle or unknown state and otherwise
uses Bird's Eye's leading-space FSM spelling, such as ` Established`. A
validated route-server client adds `bgp_session` values `external` and
`route-server`, plus `AS4` only when negotiated. Down, stale, and old-daemon
rows do not fabricate the optional transport or session fields. Live
`hold_timer_now` and `keepalive_now` countdowns remain unsupported.

## IXP Manager / Bird's Eye slice

IXP Manager protocol names can be mapped without changing daemon configuration:

```sh
--protocol-alias 'pb_0001_as64496=198.51.100.1@master4'
```

Protocol and table names use letters, digits, and underscores and must start
with a letter or underscore; the `bgp_` prefix is reserved for generated legacy
identities. Duplicate names or peers and malformed mappings fail before the
HTTP listener starts. Aliases apply consistently to inventory,
protocol detail, received/exported/filtered/noexport lookups, and route
`from_protocol`; unmapped peers retain `bgp_<address>` and table `master`, and
bare peer-IP lookup remains accepted.

For live member changes on Unix, put one mapping per line in
`--protocol-alias-file`; blank lines and `#` comments are ignored. The file is
limited to 1 MiB and 4,096 mappings and must be UTF-8. Publish a complete file
with an atomic rename, then send the adapter `SIGHUP`. A valid changed file
replaces the whole resolver in one generation without changing the PID;
unchanged content is a no-op. Unreadable, oversized, malformed, duplicate, or
non-UTF-8 input is rejected with a sanitized log message and the exact prior
generation remains active. Each HTTP request snapshots one generation before
dispatch, so no response can mix old and new identities. Direct
`--protocol-alias` values remain startup-only and do not reload.

IXP Manager v1/v2 candidates generated by `rs-config-render` include this file
at `birdwatcher-protocol-aliases.conf`. After candidate activation, point the
adapter at `<runtime-state-dir>/activation/current/birdwatcher-protocol-aliases.conf`
and send `SIGHUP` explicitly. The `current` link publishes aliases atomically
with daemon configuration; neither renderer nor activation helper signals the
adapter, so there is no cross-process atomicity claim.

Every successful response retains Alice-LG's `api.Version` and
`api.result_from_cache` keys while also exposing Bird's Eye's lowercase
`version`, `from_cache`, and enforced `max_routes`. Both version keys contain
`rustbgpd <package-version>` as product identity; they are not a claim to
implement Bird's Eye API version 2.1.0. A RIB-derived route-array request whose
actual size exceeds that maximum returns HTTP 403 instead of truncating.

IXP Manager's `protocolRoute()`, `exportRoute()`, and `protocolTable()` journeys
use `/route/<prefix>%2F<mask>/protocol/{id}`,
`/route/<prefix>%2F<mask>/export/{id}`, and
`/route/<prefix>%2F<mask>/table/{table}`.
The protocol and export views request an exact prefix on every gRPC page,
retain every Add-Path candidate in daemon order, and apply `--max-routes` only
after exact filtering.
The table view instead performs one bounded longest-prefix lookup and atomically
returns the installed winner first followed by every same-prefix alternative;
it applies `--max-routes` before rendering. Malformed prefixes return HTTP 400,
unknown identities return 404, and daemon failures return a sanitized 502.

This is deliberately partial IXP Manager support: status, live BGP inventory
and detail, protocol symbols, member received routes, and member exported
routes, including exact protocol/export lookup, are available. The exact
filtered-prefix wildcard journey described below and a single-prefix
less-specific table search are also available. The table name validates the
live routing-table identity over rustbgpd's one global Loc-RIB; it is not an
independent table selector. Full table snapshots, counts, other
large-community wildcard queries, and the complete reject-reason inventory are
not implemented; the adapter does not claim full Bird's Eye compatibility.

IXP Manager v7.4 queries member-filtered prefixes through
`/routes/lc-zwild/protocol/{id}/{daemon ASN}/1101`. The adapter answers only
that exact daemon-owned namespace and returns an empty route array for other
`x` or `y` values. It never scans accepted routes: the response comes only from
the selected session's retained rejects and preserves the usual no-session
empty answer. Successful filtered replies use the daemon-reported retention
capacity as `api.max_routes` and are exempt from the generic RIB-derived cap.
Both add `retention.enabled`, `capacity`, `evictions_since_reset`, and
`may_be_incomplete`; the last two are `null` against an older daemon, while a
positive eviction count marks retained loss without hiding retained rows.

Each returned route carries exactly one synthesized `{daemon ASN}:1101:<id>`
reason. Before adding it, the adapter removes every wire-supplied community in
that reserved namespace, preventing a member from forging the displayed
reason while preserving unrelated large communities. Mapping is deliberately
conservative:

| Retained cause | IXP Manager reason id |
|---|---:|
| `.rpol` term `reject-too-specific` | 1 |
| `.rpol` term `reject-non-global` | 3 |
| first-AS mismatch | 7 |
| strict next-hop ownership | 8 |
| `.rpol` term `reject-rpki-invalid` with invalid RPKI state | 13 |
| `.rpol` term `reject-transit-leak` | 14 |
| any other or ambiguous cause | 0 |

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
| `policy_reject`      | `64496:65520:1`  | Denied by import policy (detail = `policy:term` for named `.rpol`, else policy) |
| `otc_route_leak`     | `64496:65520:2`  | RFC 9234 Only-to-Customer role leak            |
| `next_hop_ownership` | `64496:65520:3`  | Route-server strict NEXT_HOP ownership         |
| `as_path_loop`       | `64496:65520:4`  | Own AS in the received AS_PATH                 |
| `rr_loop`            | `64496:65520:5`  | Reflection loop (ORIGINATOR_ID / CLUSTER_LIST) |
| `treat_as_withdraw`  | `64496:65520:6`  | RFC 7606 treat-as-withdraw attribute handling  |
| *(unrecognized)*     | `64496:65520:0`  | Future token this adapter build predates       |

The ids are append-only and term detail does not create new ids. Each filtered
route also carries human-readable `reject_reason` / `reject_reason_detail`
fields (plus `rpki_validation` / `aspa_validation`) as extra JSON keys —
visible to curl users, ignored by parsers that don't know them.

The IXP Manager wildcard uses its separate `{daemon ASN}:1101:<id>` namespace.
For the pinned v7.4 route-server templates the adapter maps the ten active IDs
`1,3,5,6,7,8,9,10,13,14`: prefix length, bogon, AS-path length/first-AS,
NEXT_HOP, IRRDB prefix/origin, RPKI-invalid, and transit-free-AS rejects.
Generated-policy mappings require the exact renderer policy/term identity;
ambiguous, custom, and the five defined-only IDs `2,4,11,12,15` remain `0`.

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
makes one `ExplainAdvertisedRoute` call per suppressed prefix. Each paged
snapshot is version-fenced independently: concurrent churn within either walk
can fail the request rather than mix generations in that snapshot, so clients
should retry the request when it returns a 502. The two snapshots are not fenced
to the same generation, however, so churn between them can make the diff
incomplete. The per-prefix `ExplainAdvertisedRoute` re-check drops candidates
that would be advertised, so the race cannot fabricate a "not exported" claim;
the re-check cannot recover a route omitted by the cross-snapshot diff.
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
- End-to-end smoke test of the status/peer/accepted/filtered/noexport/exact
  subset: `cargo test --test birdwatcher_adapter_smoke` (root package;
  spawns a real daemon plus this adapter, announces a clean route and a
  loop-poisoned one from one live peer plus an announce-nothing receiver
  peer, and asserts the accepted, filtered, and both sides of the noexport
  views — including received/exported Add-Path multiplicity, order, source
  alias direction, exact-filter-before-cap, and stable 400/404/502 errors).
