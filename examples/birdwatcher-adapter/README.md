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
| `--arouteserver-reject-communities-file PATH` | `BIRDWATCHER_ADAPTER_AROUTESERVER_REJECT_COMMUNITIES_FILE` | (unset) | Startup-only artifact emitted by `rs-config-render` for effective `tag_and_reject` peers |
| `--max-routes` | `BIRDWATCHER_ADAPTER_MAX_ROUTES` | `1000` | Maximum RIB-derived route-array response size; must be non-zero |
| `--max-lpm-scan-routes` | `BIRDWATCHER_ADAPTER_MAX_LPM_SCAN_ROUTES` | `10000` | Maximum route rows scanned by a protocol/export longest-match fallback; must be non-zero |

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
listener beyond loopback only with the mTLS controls in `docs/reference/security.md`.

## Endpoint → gRPC mapping

| REST endpoint (birdwatcher)  | Backing gRPC RPC(s)                                            |
|------------------------------|----------------------------------------------------------------|
| `GET /status`                | `GlobalService.GetGlobal` + `ControlService.GetHealth`         |
| `GET /protocols/bgp`         | One `NeighborService.ListNeighbors` request, including actor-authoritative per-neighbor `routes.filtered` counts |
| `GET /protocol/{id}`         | Same live neighbor object exposed by `GET /protocols/bgp`              |
| `GET /symbols`               | Sorted live protocol and routing-table identities from `NeighborService.ListNeighbors` |
| `GET /routes/protocol/{id}`  | `RibService.ListReceivedRoutes` (paged, all unicast families) + `ListBestRoutes` identity join for truthful `primary` |
| `GET /routes/export/{id}`    | `RibService.ListAdvertisedRoutes` (paged, all unicast families) + `ListBestRoutes` identity join for truthful `primary` |
| `GET /routes/table/{table}`  | One `NeighborService.ListNeighbors` snapshot, then global `RibService.ListReceivedRoutes` + `ListBestRoutes` paged under one generation |
| `GET /routes/table/{table}/filtered` | One `NeighborService.ListNeighbors` snapshot, `PolicyService.ListRejectedRoutes` for every peer aliased to the table, then a second `ListNeighbors` snapshot for an inventory-stability retry |
| `GET /route/{prefix}/protocol/{id}` | `RibService.ListReceivedRoutes` (paged; exact prefix, else the view's most-specific covering prefix) + prefix-filtered `ListBestRoutes` for truthful `primary` |
| `GET /route/{prefix}/export/{id}` | `RibService.ListAdvertisedRoutes` (paged; exact prefix, else the view's most-specific covering prefix) + prefix-filtered `ListBestRoutes` for truthful `primary` |
| `GET /route/{prefix}/table/{table}` | `RibService.LookupBestPath` (bounded longest-prefix match with one matched-prefix candidate set) |
| `GET /routes/peer/{peer}`    | `RibService.ListReceivedRoutes` (paged, all unicast families) + `ListBestRoutes` identity join for truthful `primary` |
| `GET /routes/filtered/{id}`  | `PolicyService.ListRejectedRoutes` (unpaged — the store is bounded at the `[policy.reject_retention]` capacity, default 1024/peer) |
| `GET /routes/lc-zwild/protocol/{id}/{x}/{y}` | `GlobalService.GetGlobal` to dispatch: `PolicyService.ListRejectedRoutes` for IXP Manager's `{daemon ASN}:1101:*` filtered-prefix query, or the paged `RibService.ListReceivedRoutes` + `ListBestRoutes` accepted-route scan for any other `(x, y)` wildcard |
| `GET /routes/noexport/{id}`  | `RibService.ListBestRoutes` − `RibService.ListAdvertisedRoutes` (both paged), each missing prefix explained by `RibService.ExplainAdvertisedRoute` |

There are no placeholder 501 responses. Route `age` is served from the
`Route.received_at_epoch_seconds` proto field (RIB receive time) on the
accepted view and from the rejection wall-clock time on the filtered view.
Status `last_reconfig` is the UTC rendering of the daemon's last successfully
accepted full policy generation (initial load, SIGHUP, or config transaction);
it stays empty only until the daemon reports a positive timestamp.

The full-table response unions canonical `(prefix, peer, path_id)` identities,
marks the installed winner `primary`, and sorts each prefix winner-first. It
returns 403 before truncation and sanitized 502 on missing/changing versions,
duplicates, conflicts, or any incomplete walk. Table names and IPv4/IPv6
family are inferred from one live alias snapshot; this is not VRF discovery.

Every received-route view that joins `ListReceivedRoutes` with
`ListBestRoutes` requires one matching `RoutePageVersion` across every page of
both captures. A generation change or upstream `ABORTED` response discards the
entire partial capture and retries at most three times; missing versions and a
third mismatch fail with sanitized HTTP 502. Advertised-route generations are
independent and are not compared with the best-route generation.

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
The protocol and export views are longest-match, like Bird's Eye's
`show route for`: they request an exact prefix on every gRPC page, retain
every Add-Path candidate in daemon order, and when the queried prefix has no
entry they answer with the view's most-specific covering prefix. Exact and
fallback pages are scoped to the queried IPv4 or IPv6 unicast family. The
fallback is a linear scan because there is no covering-prefix RPC filter;
`--max-lpm-scan-routes` bounds that work separately, while `--max-routes`
applies only to the routes returned for the one matched prefix. If the scan
budget is exhausted before the peer view is complete, the request returns a
sanitized HTTP 403 and never evaluates the partial view.
The table view instead performs one bounded longest-prefix lookup and atomically
returns the installed winner first followed by every same-prefix alternative;
it applies `--max-routes` before rendering. Syntactically valid input with
host bits set — which BIRD rejects, so Bird's Eye answers with no routes —
returns HTTP 200 with an empty route array on all three lookups. Genuinely
malformed prefixes return HTTP 400, unknown identities return 404, and daemon
failures return a sanitized 502.

This is verified IXP Manager 7.4 Bird's Eye API compatibility with
documented BIRD-internal divergences: status, live BGP inventory
and detail, protocol symbols, member received routes, and member exported
routes are available, and the boundary is the executable contract in
[`tests/compat/ixp-manager-birdseye/contract.json`](../../tests/compat/ixp-manager-birdseye/contract.json)
(`runtime_supported` / `unsupported` / `runtime_divergences`, with
`runtime_compatibility: true`). The table below is checked against that
contract by `scripts/check_ixp_manager_docs.py`, so the two cannot drift
silently:

| Contract capability | Status | Adapter surface |
|---|---|---|
| `exact-protocol-route` | supported | `/route/{prefix}/protocol/{id}`: exact prefix on every gRPC page, falling back to the view's most-specific covering prefix (`show route for` semantics), every Add-Path candidate in daemon order |
| `exact-export-route` | supported | `/route/{prefix}/export/{id}`: the same discipline over the Adj-RIB-Out |
| `filtered-prefix-wildcard` | supported | `/routes/lc-zwild/protocol/{id}/{daemon ASN}/1101`, answered from the session's retained rejects; ordinary `(x, y)` pairs scan the member's accepted routes instead (Bird's Eye wildcard semantics) |
| `less-specific-longest-prefix-match` | supported | `/route/{prefix}/table/{table}`: one bounded longest-prefix lookup |
| `atomic-full-table-snapshot` | supported | `/routes/table/{table}`: accepted candidates joined with installed winners under one Received/Best generation; refuses rather than truncates |
| `atomic-all-candidate-prefix-snapshot` | supported | the table lookup returns the installed winner first and every same-prefix alternative in one response |
| `file-backed-runtime-protocol-alias-reconfiguration` | supported | `--protocol-alias-file`, replaced as one resolver generation on `SIGHUP` |
| `active-rejected-route-reason-inventory` | supported | the ten template-active `{daemon ASN}:1101:<id>` reasons tabulated below |
| `live-session-transport-detail` | supported | `source_address`, `keepalive`, `connection`, `bgp_session` from one `ListNeighbors` snapshot |
| `full-table-count` | unsupported | no count endpoints; the full-table view does not add counts |
| `direct-runtime-protocol-alias-reconfiguration` | unsupported | `--protocol-alias` values are startup-only and do not reload |
| `live-hold-keepalive-countdowns` | unsupported | `hold_timer_now` / `keepalive_now` are never fabricated |
| `defined-only-rejected-route-reason-emission` | unsupported | the five display-only reason ids are never emitted; such causes fall back to `0` |
| `full-ixp-manager-ui-filter-policy-engine` | unsupported | only the bounded `rs-config-render` manual-export subset exists |

The table
name validates the live routing-table identity over rustbgpd's one global
Loc-RIB; it is not an independent table selector. The claim stops at the
documented divergences: BIRD-internal values stay divergent, the countdown
timers and route-change counters are unsupported, and the product identifies
as rustbgpd. Aliases are read at startup or from the alias file on an
explicit `SIGHUP`, never automatically, so adding a member requires
republishing the file and signaling (or restarting) the adapter.

IXP Manager v7.4 queries member-filtered prefixes through
`/routes/lc-zwild/protocol/{id}/{daemon ASN}/1101`. The daemon-owned
namespace is answered only from the selected session's retained rejects and
preserves the usual no-session empty answer. Any other `(x, y)` pair follows
Bird's Eye's wildcard semantics instead: the member's accepted routes
carrying a large community `(x, y, *)`, served in the accepted-route shape
(no retention envelope) with the generic route cap applied to the matched
rows. Successful filtered replies use the daemon-reported retention
capacity as `api.max_routes` and are exempt from the generic RIB-derived cap.
Both add `retention.enabled`, `capacity`, `evictions_since_reset`, and
`may_be_incomplete`; the last two are `null` against an older daemon, while a
positive eviction count marks retained loss without hiding retained rows.

Each returned route carries exactly one synthesized `{daemon ASN}:1101:<id>`
reason. Before adding it, the adapter removes every wire-supplied community in
that reserved namespace, preventing a member from forging the displayed
reason while preserving unrelated large communities. The emitted ids are
exactly the ten active in the pinned IXP Manager v7.4 route-server templates
(`reject_reasons.active_ids` in the contract); generated-policy causes require
the exact renderer policy/term identity, and mapping is deliberately
conservative:

| Retained cause | IXP Manager reason id | Bird's Eye display |
|---|---:|---|
| `.rpol` term `ixp-manager-hygiene:reject-too-specific` | 1 | PREFIX LENGTH TOO LONG |
| `.rpol` term `reject-special-purpose:reject-non-global` | 3 | BOGON |
| `.rpol` term `ixp-manager-hygiene:reject-as-path-too-long` | 5 | AS PATH TOO LONG |
| `.rpol` term `ixp-manager-hygiene:reject-as-path-too-short`, or first-AS treat-as-withdraw on an empty AS_PATH | 6 | AS PATH TOO SHORT |
| first-AS mismatch: treat-as-withdraw, or generated `client-<id>:reject-first-as-not-peer-as` | 7 | FIRST AS NOT PEER AS |
| strict next-hop ownership | 8 | NEXT HOP NOT PEER IP |
| generated `client-<id>:reject-irrdb-prefix-filtered` | 9 | IRRDB PREFIX FILTERED |
| generated `client-<id>:reject-irrdb-origin-as-filtered` | 10 | IRRDB ORIGIN AS FILTERED |
| `.rpol` term `ixp-manager-hygiene:reject-rpki-invalid` with invalid RPKI state | 13 | RPKI INVALID |
| `.rpol` term `ixp-manager-hygiene:reject-transit-leak` | 14 | TRANSIT FREE ASN |
| any other or ambiguous cause | 0 | (fallback; IXP Manager leaves it untranslated) |

The five ids the pinned templates define but never set
(`reject_reasons.defined_only_ids`) are display-only: the adapter never emits
them, and such causes fall back to `0` rather than gaining invented semantics:

| Defined-only id | Bird's Eye display | Emitted as |
|---:|---|---:|
| 2 | PREFIX LENGTH TOO SHORT | 0 |
| 4 | BOGON ASN | 0 |
| 11 | PREFIX NOT IN ORIGIN AS | 0 |
| 12 | RPKI UNKNOWN | 0 |
| 15 | TOO MANY COMMUNITIES | 0 |

## Filtered routes and reject reasons

`/routes/filtered/{id}` (accepts `bgp_<addr>` protocol ids and bare peer IPs)
serves every rejected inbound route the peer's session has retained, with
canonical reason tokens from `PolicyService.ListRejectedRoutes`
(`[policy.reject_retention]` in `docs/reference/configuration.md`; unicast only,
LRU-bounded per peer — at the cap the view shows the most recent rejections).
Semantics worth knowing:

- **Retention disabled** (`[policy.reject_retention] enabled = false`): the
  view is empty with a log line — a configuration fact, not an error.
- **No live session**: the session-local store is gone; the view is empty.
- The daemon deliberately does **not** tag reject-reason communities onto
  retained routes; the adapter synthesizes the community representation at
  the serving edge (below), so the daemon surface stays structured.

### Table-wide filtered view

`/routes/table/{table}/filtered` is the companion of `/routes/table/{table}`
that Alice-LG's single-table source reads for its routes store: with
`enable_prefix_lookup = true`, Alice fetches both dumps for each configured
main table on every `routes_store_refresh_interval` and answers global
prefix lookups from that store. The view serves every retained reject of
every peer aliased to the table, rendered exactly as the peer's own filtered
view (the alias as `from_protocol`, the ARouteServer presentation when
configured, the synthesized reason community), scoped to the family the
table's peers infer, in peer order. The envelope is the per-peer one
aggregated over the table's live sessions: `retention.capacity` and
`api.max_routes` are the summed capacities (the most rows the view can
hold), `evictions_since_reset` is the summed loss and `may_be_incomplete`
its warning, `enabled` is true when any live session retains, and every
field is `null` when no session in the table is live. A session with
retention disabled contributes no rows, a peer whose session store the
daemon reports as gone (`NOT_FOUND`) contributes nothing, an unknown table
is 404, and the generic `--max-routes` cap does not apply, matching the
peer view. The endpoint adds no truncation beyond each peer's bounded
retention store. A configured peer that is still dialing has a session task
and therefore an empty store whose capacity counts.

The reject stores are session-local and carry no version, so the adapter uses
an inventory-stability retry: it snapshots the table's
members (address, session state, staleness, retained count) with one
`ListNeighbors`, reads each store with one unpaged `ListRejectedRoutes`,
then re-reads the inventory. Any change between the two snapshots discards
the capture and retries, at most three attempts, before answering a sanitized
HTTP 502 after three changed inventories. This detects inventory changes, but
it is not a generation or content fence for the session-local stores. A
member whose inventory changes on every attempt therefore fails the request,
and Alice retries a failed routes-store refresh after ten seconds.

**Cost:** each attempt is `2 + N` RPCs for `N` members aliased to the table.
With stable `N`, three attempts have a ceiling of `3 × (2 + N)` RPCs. One
attempt can carry up to `N × capacity` rows (`[policy.reject_retention]`,
default 1024 per peer). A dual-stack Alice source issues four table dumps
per refresh (accepted and filtered for each main table), so size
`routes_store_refresh_interval` and the retention capacity together. The
pinned compat gate prints the refresh duration Alice logs (which starts at
its refresh lock and so includes Alice's 0-30 s start jitter) next to the
adapter's directly timed four dumps at its five-member, nine-route shape;
those lines are evidence for that shape only, not a production figure.

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

When the renderer artifact is configured, ordinary `/routes/filtered/{id}`
responses for peers named in it use the site's ARouteServer namespaces: the
adapter removes every received value in each configured dynamic namespace and
every exact configured cause-map value, then adds generic cause `0`, a known
cause when the structured daemon reason is unambiguous, and its configured map
value. Unknown reasons remain generic; AS_SET paths and BLACKHOLE requests
cannot receive the guarded late causes. Order is stable and duplicates are
removed. The artifact is parsed once at
startup; changing it requires an adapter restart. A malformed, oversized, or
over-4096-peer artifact refuses startup without echoing its contents.
Only long-AS-path (`1`) and next-hop (`5`) causes are unconditional. Black-list
(`3`) and IRR origin/prefix (`9`/`12`) causes require a valid IPv4 prefix or an
IPv6 prefix provably inside `2000::/3`; malformed or outside-range prefixes stay
generic. Causes `2`, `6`, `7`, `8`, `10`, `13`, `14`, and `15` also stay generic
because the retained rustbgpd reason cannot prove ARouteServer's first cause.

This presentation applies only to the ordinary filtered endpoint. The IXP
Manager `{daemon ASN}:1101:*` wildcard keeps its separate scrub and mapping
rules, so configuring ARouteServer data does not change that consumer surface.
This remains an adapter presentation feature inside the documented
compatibility boundary; it adds no claim of its own.

The IXP Manager wildcard uses its separate `{daemon ASN}:1101:<id>` namespace.
For the pinned v7.4 route-server templates the adapter maps the ten active IDs
`1,3,5,6,7,8,9,10,13,14`: prefix length, bogon, AS-path length/first-AS,
NEXT_HOP, IRRDB prefix/origin, RPKI-invalid, and transit-free-AS rejects.
Generated-policy mappings require the exact renderer policy/term identity;
ambiguous, custom, and the five defined-only IDs `2,4,11,12,15` remain `0`.

Alice-LG config to render the reasons:

```ini
[rejection_reasons]
64496:65520:0 = Route was filtered
64496:65520:1 = Denied by import policy
64496:65520:2 = Only-to-Customer role leak (RFC 9234)
64496:65520:3 = NEXT_HOP is not the peer's own address
64496:65520:4 = Receiver's AS appears in the AS_PATH
64496:65520:5 = Route reflection loop
64496:65520:6 = Malformed attributes (treat-as-withdraw, RFC 7606)
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
makes one `ExplainAdvertisedRoute` call per suppressed prefix. Retained memory
is proportional to the advertised prefix-key set plus at most `--max-routes`
candidate rows: each Loc-RIB page is diffed as it arrives, only suppressed
candidates are kept, and the cap is applied per page. Each paged
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
reject-reason function `65520`, distinct so the `[rejection_reasons]` and
`[noexport_reasons]` matchers never overlap), and a stable id per stopping gate:

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
load_on_demand = true

[noexport_reasons]
64496:65521:0 = Route was not exported
64496:65521:1 = Route originated from this peer (split horizon)
64496:65521:2 = Route reflection rules (RFC 4456)
64496:65521:3 = Address family not negotiated
64496:65521:4 = Long-lived stale route (RFC 9494)
64496:65521:5 = Outbound route filter (RFC 5291)
64496:65521:6 = RT membership (RFC 4684)
64496:65521:7 = Denied by export policy
```

### Field-level gaps

| Field | Adapter value | Limitation |
|---|---|---|
| protocol `routes.preferred` | omitted | No per-peer Loc-RIB best count exists on the gRPC surface; deriving one would page the whole Loc-RIB on every poll. The field is left out rather than served as a wrong `0` — a client that defaults absent fields still reads zero, but nothing here asserts it. |
| route `interface` | `""` | Interface identity is not exposed for these routes. |
| route `metric` | `0` | Sentinel only; this is not an IGP metric. |
| filtered route `bgp.origin` | `""` | ORIGIN is not retained for rejected routes. |
| filtered route `bgp.local_pref`, `bgp.med` | `"100"`, omitted | Not retained for rejected routes: `local_pref` renders the effective default (the same rule the accepted views apply to a route without the attribute) and `med` is omitted. An explicit wire value on the rejected announcement is lost. |
| route `bgp.ext_communities` | rendered | Accepted, exact, and noexport routes carry every extended community as birdwatcher's `[kind, key, value]` string triple parsed from BIRD 2.0.12 text: `rt` / `ro` for the transitive two-octet-AS, IPv4-address, and four-octet-AS families (key and value split per family), `unknown 0x<type>` for other subtypes of those families, and `generic` with the two 32-bit halves in hex for every other type (opaque, EVPN, RFC 8097 origin validation state). Alice-LG converts the two values with `Atoi`, so an IPv4 key or a hex half reads as `0` there, exactly as behind a real birdwatcher. Filtered routes carry none (rejects retain no extended communities). |

Error behavior differs only on failure: when the daemon is unreachable
the adapter returns `502 Bad Gateway` (the in-daemon server returned
`500` when its internal channels failed).

## Testing

- Unit tests: `cargo test -p birdwatcher-adapter`
- End-to-end smoke test of the status/peer/accepted/filtered/noexport/exact
  subset: `cargo test --test birdwatcher_adapter_smoke` (root package;
  spawns a real daemon plus this adapter, announces a clean route and a
  loop-poisoned one from one live peer plus an announce-nothing receiver
  peer, and asserts the accepted, filtered, table-wide filtered, and both
  sides of the noexport views — including received/exported Add-Path
  multiplicity, order, source alias direction, exact-filter-before-cap, the
  summed retention envelope and its loss warning, and stable 400/404/502
  errors).
- Pinned external-consumer proof: the IXP compatibility gate source-builds
  Alice-LG 6.2.0 (with `enable_prefix_lookup = true`, so its routes store
  reads `/routes/table/{table}` and `/routes/table/{table}/filtered`) and the
  MANRS IXP validation tool, then requires Alice to consume this adapter's
  seven populated accepted routes, empty filtered endpoints, one
  split-horizon noexport route, and one accepted prefix-lookup hit before
  MANRS traverses the Alice received-route API. After freezing and hashing
  those captures, the gate runtime-adds a fifth live peer whose import
  policy denies one prefix, atomically reloads its alias, and proves through
  restarted Alice that an AS-path-loop route and a policy-denied route appear
  only in that peer's filtered backend with `64496:65520:4` and
  `64496:65520:1` joined to their exact configured reason labels, and that
  the global prefix lookup finds both as filtered routes. The original seven
  accepted routes, four empty filtered endpoints, and noexport route remain
  unchanged. This is a backend/API proof, not a rendered-browser or
  certification claim.
