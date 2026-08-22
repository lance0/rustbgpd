# Pinned IXP Manager / Bird's Eye contract oracle

This harness captures the external HTTP contract consumed by IXP Manager's
`IXP\Services\LookingGlass\BirdsEye` class. It is an upstream oracle, not a
claim that rustbgpd or its example Birdwatcher adapter is Bird's Eye compatible.

The gate clones and verifies these exact upstream commits, installs both
projects from their committed Composer lockfiles, starts the real Bird's Eye
Lumen server with `APP_DEBUG=false`, and invokes the real IXP Manager consumer.
It then starts a real rustbgpd plus `birdwatcher-adapter` and points that same
pinned consumer's `protocolRoute()`, `exportRoute()`, `protocolTable()`, and
`routesProtocolLargeCommunityWildXYRoutes()` journeys at the live adapter:

- Bird's Eye v2.1.0: `7f8c2375e610578bcf6ea5ceec630a180f945b89`
- IXP Manager v7.4.0: `300b7e0ba9adb0aaac975899e45fc8bcbc0ca37d`

The BIRD side is a deterministic fake `birdc` fed only RFC 5737 documentation
addresses and RFC 5398 documentation ASNs. The capture covers status, BGP
inventory and detail, symbols, protocol/table/export route lists and counts,
exact lookups, the large-community wildcard query, and production error
JSON responses for HTTP 400, 403, 404, and 503 using an explicit
`Accept: application/json`. The IXP Manager leg calls every method on its
concrete Bird's Eye consumer without adding that header and records all four
paths' current behavior of collapsing non-2xx responses to an empty string.

The server uses `CACHE_DRIVER=array` so the oracle needs no external cache and
always captures deterministic, non-cached responses. HTTP status, Content-Type,
and body are all part of the reviewed fixture. Composer validation is strict;
the harness permits only IXP Manager's pinned deprecated `GPL-2.0` identifier
warning and rejects any additional warning.

The live-adapter leg intentionally uses a configured, down peer, so the exact
lookups, table longest-prefix match, and filtered-prefix query return honest
empty route arrays. The pinned protocol-detail consumer also proves its
unconditional `connection` field is the empty string while `source_address`,
`keepalive`, `bgp_session`, `hold_timer_now`, and `keepalive_now` remain absent;
the configured route-server-client flag alone cannot fabricate negotiated
session tags. It drives the same real IXP Manager methods before and
after an atomic alias-file rename plus `SIGHUP`, then repeats them after a
malformed reload is rejected, all against one adapter PID. The live BGP smoke
test separately pins a populated
less-specific lookup with its installed winner first and every same-prefix
Add-Path alternative in the same response, plus retained-reject sourcing,
reserved-community scrubbing, reason fallback, filtering, and source alias
direction. `api.version` remains
`rustbgpd <package-version>` product
identity, not Bird's Eye semantic-version compatibility. No full compatibility
claim is made and `runtime_compatibility` remains false; the exit criterion
that would flip it is in
[What would flip `runtime_compatibility`](#what-would-flip-runtime_compatibility).

The same live adapter also backs the pinned Nagios journey. IXP Manager's
`birdseye-daemons` and `birdseye-bgp-sessions` generators filter routers on
`api_type = Birdseye`, so an excluded route server is absent from generated
monitoring rather than an error. The gate sets fixture router `b2-rs1-lan1-ipv4`
to that API type with the adapter URL, renders both generators through the real
`NagiosController`, and asserts the router's host, service, and hostgroup
membership plus both route-server client session services named
`pb_0001_as1213` and `pb_0004_as112`. It then runs the pinned Bird's Eye
`nagios-check-birdseye.php` plugin against the emitted `_apiurl` and requires
`OK` with a populated `Last Reconfigure` and the one configured, down session
counted. The step writes `nagios-monitoring.json` into the capture directory
and prints one `nagios proof:` line on stderr; `verify_capture.py --nagios`
fails the gate when that artifact is missing or drifted. Alerting content and
thresholds are out of scope.

The real pinned IXP Manager PHP extension also translates every defined
`:1101:<id>` display entry from 1 through 15. The executable contract records
the active route-server-template partition `1,3,5,6,7,8,9,10,13,14`, keeps
`2,4,11,12,15` defined-only, and proves fallback `0` remains untranslated.

The same pinned v7.4 Foil/MySQL journey captures complete ordered UI-filter
rows 31, 33, and 35, then proves unscoped row 32 PREPEND_ONCE overlaps
peer-and-prefix row 33 PREPEND_TWICE before row 35 AS_IS. An in-memory
baseline-delta proves pinned BIRD emits both matching actions sequentially
without retaining raw config. Both strict v2 captures render and pass
`rustbgpd --check --strict`; the oracle executes the disjoint-cell result with
`rbgp policy check`, including target, peer-miss, prefix-miss, path-first, and
unusable-path cases. Exact row
objects, raw repeated-render bytes, v2 completion counts,
receipt-last publication, and v3 refusal are load-bearing. This proves only the
bounded manual export subset; it does not make the adapter runtime-compatible
or claim a generic IXP Manager policy engine.

Both real v2 candidates also contain exact numeric-order Birdwatcher aliases
at `birdwatcher-protocol-aliases.conf`; the v1 candidate pins its own exact
member line. The gate checks newline-terminated bytes, mode 0600, and the
receipt digest. The executable contract records the stable activation-current
path, v4/v6 table names, member-name format, and 4096-alias cap. Adapter SIGHUP
remains an operator action outside this oracle.

The real pinned exporter is also exercised for the stock 15-ASN no-transit
default, selected and complete exclusions, explicit-empty, and deduplicated
explicit-nonempty overrides. Each result is compared with both pinned `bird2`
and `bird2-2025` policy, strict-rendered, and executed through the generated
Rust policy. The legacy implicit token and v1 use of the effective-default token
remain fail-closed.

The strict candidates also append the router-own-AS large-community scrub last
to the global export chain and every v2 client receive override. The manifest
pins its exact removal-only syntax, placement, and foreign-admin preservation.

Run the gate from the repository root:

```console
tests/compat/ixp-manager-birdseye/run.sh
```

To inspect an intentional upstream refresh without overwriting the reviewed
fixtures, capture into a separate directory and diff it:

```console
CAPTURE_FIXTURES=1 CAPTURE_OUTPUT=/tmp/ixp-contract \
  tests/compat/ixp-manager-birdseye/run.sh
diff -u tests/compat/ixp-manager-birdseye/fixtures/birdseye-contract.json \
  /tmp/ixp-contract/birdseye-contract.json
```

`contract.json` deliberately keeps the unsupported runtime matrix executable.
Exact protocol-route, exact export-route, filtered-prefix wildcard, bounded
less-specific lookup, and atomic full-table journeys are runtime-supported. The LPM lookup
returns one matched prefix atomically with its installed winner first and every
same-prefix Add-Path alternative. The full-table view joins Received and Best
under one generation, caps before truncation, and does not add counts. All ten
reject reasons emitted by the pinned route-server templates are
runtime-supported; emitting the five defined-only display reasons and
full-table counts remain blockers. Protocol
aliases supplied directly remain immutable after startup; bounded file-backed
aliases reload as one whole resolver generation on Unix `SIGHUP`. Promoting any
blocker, weakening the explicit alias or product-version
posture, enabling debug mode, skipping a case, or drifting a pin or response
makes the gate fail.

The manual-export matrix separately records the 256-per-client, 4096-total-row,
and 4096 compiled receive-cell caps. Bounded pinned-v7.4 overlap is supported;
the full IXP Manager UI-filter policy engine remains unsupported.

## What would flip `runtime_compatibility`

`contract.json` says `"runtime_compatibility": false` and `verify_capture.py`
fails the gate if that value is anything else. That is the correct claim
today, but a standing `false` with no written definition of `true` cannot be
worked toward, so this section is the exit criterion. Nothing here changes the
flag; the flag flips only when the enforcement below is green. Alice-LG is not
a party to it: its source backends are `birdwatcher`, `gobgp`, and `openbgpd`
(upstream `pkg/sources`, unpinned), it has no Bird's Eye source, and the
adapter's Alice-LG surface is a separate Birdwatcher contract.

### Decisions

| # | Decision | Recommendation | Rejected alternative |
|---|---|---|---|
| 1 | **Divergences** (decides the rest) | `true` means field-for-field equality with the pinned Bird's Eye oracle **after** an explicit, machine-readable divergence allow-list in `contract.json` (per entry: endpoint, JSON path, Bird's Eye shape, adapter shape, reason). `api.version` stays `rustbgpd <version>` product identity and is entry one of that list: the string names the implementation, not the contract, and `verify_capture.py` keeps asserting it. Divergences already encoded stay on the list as-is: product-identity `api.version`, `unsupported_countdowns`, the `filtered_retention_metadata` extras and capacity-as-`max_routes`, defined-only reject IDs on fallback `0`, the five `unsupported` entries. | Byte-identity. It would force `api.version: "2.1.0"` for a surface that has no counts, throttle, or cache, and it would force reproducing the pinned parser's BIRD 2 `via`-line output: `fixtures/birdseye-contract.json` (`protocol_routes`) shows `gateway: "via 198.51.100.1 on eth0"`, `from_protocol: "eth0"`, `learnt_from: "<timestamp>"`, `primary: false`, `metric: 0`, and no `age`. A list can be audited; byte-identity cannot be honest here. |
| 2 | **Scope** | The eleven endpoints IXP Manager v7.4.0's `IXP\Services\LookingGlass\BirdsEye` calls (`status`, `protocols/bgp`, `protocol/{p}`, `symbols`, `routes/protocol|table|export`, `route/{net}/protocol|table|export`, `routes/lc-zwild/...`) — the set the adapter already routes. The six remaining JSON endpoints and the three non-API routes are named out of scope in the inventory below, so a new upstream endpoint is a visible re-decision, not silent drift. | Whole v2.1.0 surface. No pinned consumer drives the other six, so the flag would assert behaviour no oracle exercises; three of them are counts, and table count is the standing `full-table-count` blocker. |
| 3 | **Depth** | Field-for-field JSON equality (decision 1) on a **populated** pinned topology: the same synthetic announcements into BIRD and rustbgpd, both read by the real pinned consumer. Today's live-adapter leg uses a deliberately down peer and `adapter-consumer.php` asserts `routes == []` for every route journey, so it proves empty-shape only. | Route counts plus a sampling rule. The differences found so far are shape and type (`bgp.as_path` integers vs strings, `bgp.local_pref` number vs string, sentinel fields), which counts cannot see; and the harness's own convention is an exact fixture diff (`verify_capture.py`), not a sample. |
| 4 | **Oracle** | Pinned **BIRD 2.0.12 + Bird's Eye 2.1.0** as the reference, fed by the same announcer as the adapter leg, compared through the pinned IXP Manager consumer. BIRD 2.0.12 is what IXP Manager v7.4.0's `bird2`/`bird2-2025` templates target (its `server` template tree is `bird`, `bird2`, `bird2-2025`) and what `tests/interop/Dockerfile.bird` (`bird:2-bookworm`) already pins for the route-server labs. `fake-birdc` stays for the HTTP-contract cases (status codes, error bodies, production-mode keys). | BIRD 3.3.1 (the repo pins it only for TCP-AO, and IXP Manager v7.4.0 has no `bird3` template). The live IXP Manager MySQL oracle alone (`config-consumer.php` proves the configuration export; it never calls Bird's Eye). A real Alice-LG instance (no Bird's Eye source). Bird's Eye's own `USE_BIRD_DUMMY` sample dumps (a parser replay that cannot be correlated with what rustbgpd received). |
| 5 | **Enforcement** | The gate keeps the flag honest in both directions: `verify_capture.py` inverts its flag assertion, diffs oracle against live per scoped endpoint after applying the allow-list, fails on any unlisted difference **and** on any allow-list entry that no longer changes anything (stale entry), and fails if the pinned `routes/web.php` route set differs from scope ∪ out-of-scope. Shape below. | Flipping on green journeys with no oracle diff. That is exactly the rot this section exists to prevent. |

### Endpoint inventory — Bird's Eye v2.1.0 at `birdseye_commit` (`routes/web.php`)

Adapter column cites the handler in
[`examples/birdwatcher-adapter/src/main.rs`](../../../examples/birdwatcher-adapter/src/main.rs);
the adapter serves at `/` where Bird's Eye serves under `/api/` (IXP Manager's
`Router.api` base URL absorbs that; generic clients need a proxy prefix).

| Bird's Eye endpoint | IXP Manager v7.4.0 method | Adapter | Status | Divergence to list |
|---|---|---|---|---|
| `GET /api/status` | `status()` | `status` | served, divergent | `status.version` and `status.message` are product identity (`rustbgpd <version>`, `rustbgpd AS<n>`) where Bird's Eye emits the BIRD version and the last `birdc` line; extra `current_server` key |
| `GET /api/protocols/bgp` | `bgpSummary()` | `protocols_bgp` / `protocol_row` | served, divergent | row lacks `preference`, `input_filter`, `output_filter`, `route_changes.*`, `routes.preferred`, `description_short`, `hold_timer_now`, `keepalive_now`; adds `routes.filtered`; `import_limit`/`limit_action` only with a finite limit |
| `GET /api/protocol/{protocol}` | `bgpNeighbourSummary()` | `protocol_detail` | served, divergent | same row as above (`live_session_detail` in `contract.json`) |
| `GET /api/symbols` | `symbols()` | `symbols` | served, divergent | only `protocol` and `routing table` classes; Bird's Eye emits every `show symbols` class |
| `GET /api/symbols/tables` | — | — | not served | out of scope |
| `GET /api/symbols/protocols` | — | — | not served | out of scope |
| `GET /api/routes/protocol/{protocol}` | `routesForProtocol()` | `routes_protocol` | served, divergent | route shape: `bgp.as_path` integers (strings upstream), `bgp.local_pref` number (string upstream), `gateway` = next hop, `interface` `""`, `metric` `0`, `primary` `false`, `learnt_from` = peer address, `age` from receive time, no `atomic_aggr`/`aggregator` |
| `GET /api/routes/table/{table}` | `routesForTable()` | `routes_table` | served, divergent | route shape as above but `primary` is real; table is a validated alias over one global Loc-RIB, not a BIRD table |
| `GET /api/routes/export/{protocol}` | `routesForExport()` | `routes_export` | served, divergent | route shape as above |
| `GET /api/routes/count/protocol/{protocol}` | — | — | not served | out of scope (`total_count` exists on the first RIB page, so it is a cheap add if scope grows) |
| `GET /api/routes/count/table/{table}` | — | — | not served | out of scope; standing `full-table-count` blocker |
| `GET /api/routes/count/export/{protocol}` | — | — | not served | out of scope (same note as protocol count) |
| `GET /api/routes/lc-zwild/protocol/{protocol}/{x}/{y}` | `routesProtocolLargeCommunityWildXYRoutes()` | `routes_protocol_large_community_wild_xy` | served, divergent | answers only `{daemon ASN}:1101:*` from retained rejects, empty for any other `(x, y)`; adds `retention.*`; `api.max_routes` is the retention capacity |
| `GET /api/route/{net}` (default table `master`) | — | — | not served | out of scope |
| `GET /api/route/{net}/table/{table}` | `protocolTable()` | `route_table` | served, divergent | requires a network-aligned `addr/len` (host or unmasked input is HTTP 400; Bird's Eye accepts `192.0.2.1` and runs `show route for`); returns the installed winner first plus same-prefix Add-Path alternatives; no per-minute throttle |
| `GET /api/route/{net}/protocol/{protocol}` | `protocolRoute()` | `route_protocol` | served, divergent | **exact** prefix match where Bird's Eye's `show route for` is longest-match; network-aligned input only; all Add-Path candidates |
| `GET /api/route/{net}/export/{protocol}` | `exportRoute()` | `route_export` | served, divergent | same as the protocol lookup |
| `GET /test`, `GET /`, `/lg/*` | — | — | not served | out of scope (non-API: hello-world, HTML index, HTML looking glass) |

Counts: **0 exact, 11 served with a divergence, 6 not served, 3 out of scope
(non-API).** Zero is exact because every response carries the product-identity
`api.version`, and each served endpoint also has at least one body-level
difference. The adapter additionally serves `/routes/peer/{peer}`,
`/routes/filtered/{id}`, and `/routes/noexport/{id}`, which are Birdwatcher,
not Bird's Eye, endpoints.

Cross-cutting differences that belong on the allow-list once: the `api` block
adds Birdwatcher's `Version` and `result_from_cache` and never emits
`ttl_mins`; `from_cache` is always `false` because there is no cache to skip
(`use_cache` is ignored); upstream failure is HTTP 502 where Bird's Eye
returns 503 `Error querying bird`; the `/api/route/*` per-minute throttle
(`THROTTLE_PER_MIN`, HTTP 429) has no adapter equivalent; error bodies are
always JSON `{"message": ...}` (Bird's Eye's error body format follows
Lumen's default handler and the request's `Accept` header, which is why the
fixture pins `Accept: application/json`; IXP Manager collapses every non-2xx
to `""`).

### Enforcement shape

Today `verify_capture.py` asserts exactly one thing about the flag:
`manifest.get("runtime_compatibility") is not False` fails with
`contract oracle must not promote a runtime compatibility claim`. No Rust test
reads the flag. After the flip the same file asserts:

```text
runtime_compatibility is not True            -> fail (claim withdrawn without a decision)
for case in SCOPE (11 endpoints):
    oracle = <case>.body from BIRD 2.0.12 + Bird's Eye 2.1.0
    live   = <case>.body from rustbgpd + birdwatcher-adapter, same announcements
    for entry in contract.json runtime divergence list for case:
        apply(entry) to oracle/live      # delete path | coerce type | map value
        if nothing changed               -> fail (stale allow-list entry)
    if oracle != live                    -> fail (undocumented divergence)
route set parsed from pinned routes/web.php != SCOPE | OUT_OF_SCOPE
                                         -> fail (upstream surface changed; re-decide)
```

Each `fail(...)` is the existing fail-closed style; the oracle and live
captures are fixtures under `fixtures/` with the same `CAPTURE_FIXTURES=1`
refresh path as today. This is not a one-assertion addition to an existing
check, because the populated oracle leg does not exist yet, so it is described
here and not implemented.

### Work list

Each line names the gap and the evidence that closes it.

1. Populated oracle leg: pinned BIRD 2.0.12 + Bird's Eye 2.1.0 and rustbgpd + adapter fed identical synthetic announcements, both read by the pinned IXP Manager consumer, captured as an oracle/live fixture pair — evidence: `verify_capture.py` diffs the pair; today's live leg proves empty arrays only.
2. Machine-readable divergence allow-list in `contract.json`, pinned to a constant in `verify_capture.py` like every other block — evidence: the gate fails on an unlisted difference and on a stale entry.
3. `bgp.as_path` element type (integers vs strings) — decide emit-strings or allow-list; evidence: oracle diff clean.
4. `bgp.local_pref` type (number vs string) — same decision; evidence: oracle diff clean.
5. Route sentinels `gateway`, `interface`, `metric`, `primary`, `learnt_from`, `age` — allow-list entries citing the pinned parser's BIRD 2 `via`-line output in `fixtures/birdseye-contract.json`; evidence: entries present and non-stale.
6. `bgp.atomic_aggr` / `bgp.aggregator` absent — emit when the attribute is present or allow-list; evidence: an aggregated announcement in the oracle topology.
7. Protocol row fields `preference`, `input_filter`, `output_filter`, `route_changes.*`, `routes.preferred`, `description_short`, `hold_timer_now`, `keepalive_now` absent and `routes.filtered` extra — decide each (serve or allow-list); `routes.preferred` needs a per-peer best count on `NeighborState` first; evidence: oracle diff on an established peer.
8. `status.version`, `status.message`, extra `current_server` — allow-list as product identity; evidence: entries present.
9. `symbols` classes beyond `protocol` and `routing table` — allow-list (the daemon has no BIRD symbol table); evidence: entry present.
10. `/route/{net}/protocol|export` exact-match versus Bird's Eye longest-match, and HTTP 400 on host or unmasked input on all three lookups — decide allow-list (IXP Manager always passes a listed exact network) or implement longest-match for peer views; evidence: oracle cases with a host address and a covering-only prefix.
11. `lc-zwild` answers only `{daemon ASN}:1101:*` and returns empty for other `(x, y)` without scanning accepted routes — allow-list by design; evidence: an oracle case for a foreign `(x, y)`.
12. Upstream failure HTTP 502 versus Bird's Eye 503 — allow-list or change; evidence: the existing `bird_failure` case mirrored on the live leg.
13. No throttle (429) and no cache (`from_cache`, `ttl_mins`, `use_cache`) — allow-list as deployment concerns; evidence: entries present.
14. `/api` base path — document as reverse-proxy configuration, not adapter behaviour; evidence: README line plus allow-list note.
15. Out-of-scope set (`symbols/tables`, `symbols/protocols`, three counts, untabled `route/{net}`, `/test`, `/`, `/lg/*`) written into the gate so a new pinned upstream route fails it; evidence: route-table parse of `routes/web.php` at `birdseye_commit`.
16. Which route and protocol fields the pinned IXP Manager looking-glass views actually read is unverified; reading `resources/views/services/lg/*.foil.php` at `ixp_manager_commit` would let the allow-list mark consumer-visible versus invisible divergences — evidence: a per-entry `consumer_visible` flag.
17. `tests/birdwatcher_adapter_smoke.rs` pins `adapter-consumer.php` journey counts (`symbols()`, `protocolTable(`, `routesForTable(` exactly once each); a populated leg must keep or update that test — evidence: `cargo test --workspace` green.
18. The flip itself: `runtime_compatibility: true`, the `verify_capture.py` inversion, this README's intro sentence, `docs/INTEROP.md`, and `CHANGELOG.md` — last, only after 1–17.

## Provenance and licensing

Upstream source stays in a temporary directory and is never vendored. IXP
Manager is GPL-2.0; the gate executes its installed consumer while this
repository keeps its original GPL-2.0-only Foil exporter in the segregated
integration subtree. Bird's Eye is MIT-licensed. The two
JSON fixtures are captured outputs from that pinned server using the synthetic
inputs above; they contain no production routing data.
