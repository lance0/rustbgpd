# Pinned IXP Manager / Bird's Eye contract oracle

This harness captures the external HTTP contract consumed by IXP Manager's
`IXP\Services\LookingGlass\BirdsEye` class. It is the gate behind the
project's claim of verified IXP Manager 7.4 Bird's Eye API compatibility with
documented BIRD-internal divergences: the claim covers exactly the Bird's Eye
API surface IXP Manager v7.4.0 consumes, driven by the pinned oracle below,
and the divergence allow-list in `contract.json` is the documented boundary.

The gate clones and verifies these exact upstream commits, installs both
projects from their committed Composer lockfiles, starts the real Bird's Eye
Lumen server with `APP_DEBUG=false`, and invokes the real IXP Manager consumer.
It then starts a real rustbgpd plus `birdwatcher-adapter` and points that same
pinned consumer's `protocolRoute()`, `exportRoute()`, `protocolTable()`, and
`routesProtocolLargeCommunityWildXYRoutes()` journeys at the live adapter:

- Bird's Eye v2.1.0: `7f8c2375e610578bcf6ea5ceec630a180f945b89`
- IXP Manager v7.4.0: `300b7e0ba9adb0aaac975899e45fc8bcbc0ca37d`
- Alice-LG v6.2.0: `e9fa175d00eb192cb09fe1b460bb53a54398fc34`
- MANRS IXP validation tool: `5354e402f65fdbf17711ada30da947cb2670d2ce`

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

The live-adapter leg intentionally uses a configured, down peer, so the route
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
identity, not Bird's Eye semantic-version compatibility. `contract.json` says
`runtime_compatibility: true`: verified IXP Manager 7.4 Bird's Eye API
compatibility with documented BIRD-internal divergences, and nothing more.
The criterion the flip was held to and the enforcement that keeps the claim
honest are in
[What flipped `runtime_compatibility`](#what-flipped-runtime_compatibility).

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
bounded manual export subset; the runtime claim rests on the populated oracle
leg, and no generic IXP Manager policy engine is claimed.

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

The populated oracle leg stands the real reference next to the live leg. A
pinned BIRD 2.0.12 (Debian bookworm `bird2`, `Dockerfile.oracle`) runs next to
the same installed Bird's Eye checkout, and rustbgpd plus `birdwatcher-adapter`
run on the host; both route servers (`oracle-bird.conf` and the rustbgpd
config inside `run-oracle-leg.sh`: same ASN, router ID, descriptions, and
accept-all policy) peer with two pinned ExaBGP announcers
(`oracle-announcer-as64496.conf`, `oracle-announcer-as64497.conf`) over one
harness network with both address families. The announcements are
deterministic: a multi-hop AS path, MED, a received LOCAL_PREF, standard and
large communities, an aggregate carrying ATOMIC_AGGREGATE and AGGREGATOR, and
a more-specific inside a covering prefix. `oracle-consumer.php` drives the pinned IXP Manager `BirdsEye`
consumer through all eleven in-scope endpoints (24 journeys, including a
covering-only prefix, a host address, host-bit input, and a foreign
large-community wildcard) against each leg. The harness then appends a 25th,
deterministic backend-failure journey captured directly with status and body
(the pinned consumer collapses every non-2xx to an empty string): rustbgpd is
stopped under the still-running adapter and BIRD under the still-running
Bird's Eye, and one `api/status` probe per leg records the adapter's HTTP 502
against Bird's Eye's own HTTP 503. `verify_capture.py
--populated` normalizes both captures (timestamps, the rustbgpd version,
countdowns, each leg's own route-server addresses, BIRD's `route_changes`
counters, route and symbol order),
pins them as `fixtures/populated-oracle.json` and
`fixtures/populated-live.json`, diffs oracle against live through the
`runtime_divergences` allow-list in `contract.json`, proves the allow-list
fail-closed on every run (each entry removed in turn surfaces an unlisted
difference; a bogus entry is reported stale), and checks the pinned
`routes/web.php` route set against `birdseye_routes`. It prints one
`populated oracle proof:` line; silent success is a failure.

That populated live leg also source-builds the pinned Alice-LG and MANRS
revisions in ephemeral, digest-pinned Linux/amd64 images. Alice reads the
existing adapter at the harness gateway and must expose exactly one source,
four up neighbors, all seven accepted routes, empty filtered arrays, and the
`192.0.2.0/24` split-horizon noexport route with its full-key reason label.
The pinned MANRS tool then traverses Alice's received-route API with five
synthetic ROAs and must report exactly one deliberate mismatch: the covering
`203.0.113.0/24` originated by AS64520. This is an API consumer proof, not a
browser/UI proof. It does not prove a populated Alice filtered/reject page,
MANRS certification, rustbgpd RPKI enforcement, or route-server policy
conformance; those require their own gates.

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
less-specific lookup, and atomic full-table journeys are runtime-supported;
the protocol and export lookups follow Bird's Eye's `show route for`
longest-match semantics, answering a covering-only prefix or host address
with the view's most-specific covering prefix. The LPM lookup
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

## What flipped `runtime_compatibility`

`contract.json` says `"runtime_compatibility": true`: verified IXP Manager 7.4
Bird's Eye API compatibility with documented BIRD-internal divergences. This
section is the criterion the flip was held to and the enforcement that keeps
the claim honest in both directions; the work list at the end records how
each gap closed. Alice-LG is not
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
| `GET /api/routes/protocol/{protocol}` | `routesForProtocol()` | `routes_protocol` | served, divergent | route shape: `gateway` = next hop, `interface` `""`, `metric` `0`, `learnt_from` = peer address, `age` from receive time |
| `GET /api/routes/table/{table}` | `routesForTable()` | `routes_table` | served, divergent | route shape as above; table is a validated alias over one global Loc-RIB, not a BIRD table |
| `GET /api/routes/export/{protocol}` | `routesForExport()` | `routes_export` | served, divergent | route shape as above |
| `GET /api/routes/count/protocol/{protocol}` | — | — | not served | out of scope (`total_count` exists on the first RIB page, so it is a cheap add if scope grows) |
| `GET /api/routes/count/table/{table}` | — | — | not served | out of scope; standing `full-table-count` blocker |
| `GET /api/routes/count/export/{protocol}` | — | — | not served | out of scope (same note as protocol count) |
| `GET /api/routes/lc-zwild/protocol/{protocol}/{x}/{y}` | `routesProtocolLargeCommunityWildXYRoutes()` | `routes_protocol_large_community_wild_xy` | served, divergent | the daemon's rejection namespace `{daemon ASN}:1101:*` answers from retained rejects (adds `retention.*`; `api.max_routes` is the retention capacity); any other `(x, y)` scans the member's accepted routes for `(x, y, *)` with Bird's Eye's wildcard semantics |
| `GET /api/route/{net}` (default table `master`) | — | — | not served | out of scope |
| `GET /api/route/{net}/table/{table}` | `protocolTable()` | `route_table` | served, divergent | longest-prefix match; host-bit input is HTTP 200 with no routes (BIRD rejects the literal), genuinely malformed or unmasked input is HTTP 400 (Bird's Eye accepts a bare `192.0.2.1`); returns the installed winner first plus same-prefix Add-Path alternatives; no per-minute throttle |
| `GET /api/route/{net}/protocol/{protocol}` | `protocolRoute()` | `route_protocol` | served, divergent | longest-prefix match like Bird's Eye's `show route for`: the exact entry when present, else the view's most-specific covering prefix; host-bit input is HTTP 200 with no routes; all Add-Path candidates |
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
returns 503 `Error querying bird` (captured by the backend-failure journey
and allow-listed `intentional`); the `/api/route/*` per-minute throttle
(`THROTTLE_PER_MIN`, HTTP 429) has no adapter equivalent; error bodies are
always JSON `{"message": ...}` (Bird's Eye's error body format follows
Lumen's default handler and the request's `Accept` header, which is why the
fixture pins `Accept: application/json`; IXP Manager collapses every non-2xx
to `""`).

### Enforcement shape

`verify_capture.py` asserts, on every invocation (no Rust test reads the
flag):

```text
runtime_compatibility not in (true, false)   -> fail (the flag is an explicit decision)
runtime_compatibility is true
  while any must_match entry is open         -> fail (claim refused, naming the entries)
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
refresh path as today. The scope loop and route-set check are implemented in
`verify_capture.py --populated` (see the populated oracle leg paragraph
above); the flag and `must_match` checks run before any mode, so a re-opened
`must_match` entry re-blocks the flag until it converges and is removed.
`false` stays a valid value: the claim can be withdrawn without weakening
the gate.

### Divergence classification

Every `runtime_divergences` entry in `contract.json` carries exactly one
`classification`, mirrored in the `verify_capture.py` constant:

- `must_match` — a real gap the compatibility flip is gated on; the adapter
  or daemon must converge with the oracle, and the entry is then removed
  rather than reclassified.
- `intentional` — a deliberate, permanent, honest divergence (product
  identity; no fabricated BIRD internals).
- `unsupported` — a capability deliberately not provided (the countdown
  timers, the route-change counters).
- `extension` — the live side provides more than the oracle (extra fields),
  harmless to the pinned consumers.

The gate fails on a missing or unknown classification, naming the entry, and
refuses `runtime_compatibility: true` while any entry is classified
`must_match`. The flag therefore flipped only when zero `must_match` entries
remained, and the claim language is "verified IXP Manager 7.4 Bird's Eye API
compatibility with documented BIRD-internal divergences" — a ceiling no
document exceeds. Zero `must_match` entries remain open: the ordinary-`(x, y)`
lc-zwild scope, the route-shape cluster (`bgp.as_path` element type,
`bgp.local_pref`, `bgp.med` emitted when absent, `primary` outside the table
view, the `type` triple), and the two lookup-semantics entries
(exact-versus-longest protocol/export match and the table lookup's HTTP 400
for host-bit input) all converged on the oracle and their entries are
removed.

### Work list

Each line names the gap and the evidence that closes it. Items 1 to 6, 10 to
12, 15, 16, and 18 are done; items 3 to 14 record what the oracle diff showed,
with the observed JSON paths, and carry their decisions: `must_match` entries
stay open and gate the flip, while `intentional`, `unsupported`, and
`extension` entries are closed decisions that stay on the allow-list. Every
observed
divergence is an entry in `contract.json` `runtime_divergences`; the README
predicted eight more that the diff did not show, listed after the table.

1. Done. Populated oracle leg: pinned BIRD 2.0.12 + Bird's Eye 2.1.0 and
   rustbgpd + adapter fed identical synthetic announcements, both read by the
   pinned IXP Manager consumer, captured as the oracle/live fixture pair
   `fixtures/populated-oracle.json` and `fixtures/populated-live.json`;
   `verify_capture.py --populated` diffs the pair.
2. Done. Machine-readable divergence allow-list `runtime_divergences` in
   `contract.json` (per entry: endpoint, JSON path, kind, Bird's Eye shape,
   adapter shape, rationale, `consumer_visible`), pinned to a constant in
   `verify_capture.py`; the gate fails on an unlisted difference and on a stale
   entry, and re-proves both on every run.
3. Done. `bgp.as_path` element type: observed on every route view,
   `routes.*.bgp.as_path.*` strings upstream, integers from the adapter.
   Was `must_match`; the adapter now emits string elements (the split
   `BGP.as_path` text shape) and the entry is removed.
4. Done. `bgp.local_pref`: observed as a type and meaning difference,
   `routes.*.bgp.local_pref` is the string `"100"` upstream (BIRD's default
   local preference assigned at import, also for the route announced with
   LOCAL_PREF 200, which both route servers ignore on the eBGP session) and the
   number `0` from the adapter (the received attribute). Was `must_match`;
   the gRPC projection now serves the effective local preference — the
   attribute when present, otherwise the default 100 best-path selection
   applies, with wire presence on `Route.local_pref_attr` — and the adapter
   prints it as Bird's Eye's string; the entry is removed.
5. Route sentinels: observed `routes.*.interface` (`"eth0"` vs `""`),
   `routes.*.metric` (BIRD preference `100` vs `0`), `routes.*.primary`
   (`true` for the best route in every upstream view, `false` from the adapter
   outside the table view), `routes.*.learnt_from` (`""` upstream because BIRD
   prints `from <address>` only when it differs from the next hop, peer address
   from the adapter), and `routes.*.type` (`["BGP", "univ"]` from BIRD 2 vs the
   BIRD 1 triple). Not observed: `gateway` (the pinned parser takes the BIRD 2
   `via` line, which equals the adapter's next hop), `age` (both carry a
   receive timestamp), `from_protocol`. The sentinel values in
   `fixtures/birdseye-contract.json` come from `fake-birdc`'s BIRD 1 line
   format, not from BIRD 2. Decided: `interface`, `learnt_from`, and `metric`
   are `intentional` (BIRD-internal kernel and preference values a route
   server cannot honestly fabricate); `primary`, the `type` triple, and the
   always-emitted `bgp.med` were `must_match` and are done: `primary` now
   reports the Loc-RIB selection in every view (the received, export, and
   exact-route views join a `ListBestRoutes` identity set; the table views
   already read it), `type` is the BIRD 2 `["BGP", "univ"]` pair, and
   `bgp.med` is emitted only when the route carries the attribute
   (`Route.med_attr` presence). Their entries are removed.
6. Done. `bgp.aggregator` and `bgp.atomic_aggr`: the gRPC route detail
   carries the stored AGGREGATOR and ATOMIC_AGGREGATE path attributes
   (`Route.aggregator`, `Route.atomic_aggregate`) and the adapter renders
   them with the oracle's shapes and presence semantics
   (`"203.0.113.1 AS64496"`; `""`, the key BIRD prints with no value; both
   only when the route carries the attribute). The two allow-list entries
   are removed.
7. Protocol row: observed missing `preference`, `input_filter`,
   `output_filter`, `route_changes.*.*`, `routes.preferred`, `hold_timer_now`,
   `keepalive_now`; observed extra `routes.filtered` and
   `neighbor_capabilities` (BIRD 2 prints a multi-line `Neighbor capabilities`
   block that the pinned `Neighbor caps:` regex never matches, so the oracle
   row has no such field); observed `connection` as a whitespace-only
   difference (`"  Established   "` vs `" Established"`). `routes.preferred`
   upstream is the parser constant `0` (its `Routes:` regex drops BIRD's
   preferred count), so a per-peer best count would not close that entry.
   `description_short` is not observed (Bird's Eye emits it only with
   `PARSER_PROTOCOL_BGP_DESCRIPTION`). `import_limit` and `limit_action` are
   absent on both sides without a configured limit. Decided:
   `preference`, `input_filter`, `output_filter`, `routes.preferred`, and the
   `connection` padding are `intentional` (BIRD filter and preference
   identity, a parser constant, and whitespace); `route_changes.*.*` and the
   countdowns are `unsupported`; `routes.filtered` and
   `neighbor_capabilities` are `extension`.
8. `status.version`, `status.message`, extra `status.current_server`:
   observed, allow-listed as product identity; `status.router_id`,
   `last_reboot`, `last_reconfig`, and `server_time` match after timestamp
   normalization. Decided: `status.version` and `status.message` are
   `intentional`; the extra `status.current_server` is `extension`.
9. `symbols`: observed `symbols.protocol` carrying BIRD's `device1` next to
   the BGP sessions, and a `symbols.undefined` class (BIRD 2.0.12 `show
   symbols` reports configuration keywords there) the adapter never emits.
   Decided: both are `intentional`; the daemon has no BIRD symbol table to
   reproduce.
10. Done. Exact versus longest match: observed on `route/{net}/protocol` and
    `route/{net}/export` (a covering-only prefix and a host address return the
    covering route upstream, `routes: []` from the adapter) and on
    `route/{net}/table` for host-bit input (HTTP 200 `routes: []` upstream
    because BIRD rejects the lookup, HTTP 400 from the adapter, which the
    consumer collapses to `""`). Were `must_match`; the protocol and export
    lookups now fall back to the view's most-specific covering prefix when
    the queried prefix has no entry, and host-bit input answers HTTP 200
    with an empty route array on all three lookups. Both entries are
    removed.
11. Done. `lc-zwild`: observed for a foreign `(x, y)` (the route carrying
    that large community upstream, `routes: []` from the adapter). Was
    `must_match`; the endpoint now dispatches on the pair — the daemon's own
    rejection namespace keeps serving retained rejects, and every other
    `(x, y)` scans the member's accepted routes for `(x, y, *)` with Bird's
    Eye's wildcard semantics — and the entry is removed. The adapter's extra
    `retention.*` and capacity-as-`api.max_routes` on the namespace pair
    stay `extension`; both legs return `routes: []` for the daemon `(x, y)`.
12. Done. 502 versus 503: the populated leg now ends with the deterministic
    backend-failure journey described above (rustbgpd stopped under the
    still-running adapter, BIRD stopped under Bird's Eye, one `api/status`
    probe per leg captured with status and body since the pinned consumer
    collapses every non-2xx to `""`). Observed: HTTP 503
    `Error querying bird` upstream, HTTP 502 `Upstream daemon request
    failed` from the adapter; the difference is one `intentional` allow-list
    entry — a gateway honestly reports 502 where Bird's Eye reports its own
    backend as 503. The existing `bird_failure` case stays on the
    `fake-birdc` oracle.
13. Throttle and cache: not observed as a body difference; `ttl_mins` is
    absent on both sides because `CACHE_DRIVER=array` strips it upstream and
    `from_cache` is `false` on both; the per-minute throttle is not hit by
    the 24 journeys. Settled as documentation: cache and throttle emulation
    are out of scope — there is no cache to emulate (`from_cache` is honestly
    `false`), and per-minute throttling belongs at a reverse proxy in front
    of the adapter, not in it.
14. `/api` base path: not a body difference; IXP Manager's `Router.api` base
    URL absorbs it (`.../api` for Bird's Eye, the adapter root for rustbgpd).
    Settled as documentation: the base path is deployment configuration, not
    a runtime divergence.
15. Done. The in-scope and out-of-scope route sets are `birdseye_routes` in
    `contract.json`; `verify_capture.py --populated` parses `routes/web.php`
    at `birdseye_commit` and fails on any new or removed route.
16. Done. Every allow-list entry carries `consumer_visible`, set from the
    pinned `resources/views/services/lg/*.foil.php` views, the looking-glass
    layout, and the BGP-sessions diagnostics suite at `ixp_manager_commit`.
17. `tests/birdwatcher_adapter_smoke.rs` pins `adapter-consumer.php` journey
    counts (`symbols()`, `protocolTable(`, `routesForTable(` exactly once
    each); the populated leg uses its own `oracle-consumer.php`, so the pin is
    unchanged — evidence: `cargo test --workspace` green.
18. Done. The flip itself: `runtime_compatibility: true`;
    `verify_capture.py` now requires an explicit boolean and keeps the
    `must_match` refusal as the permanent gate; this README, `docs/INTEROP.md`,
    `docs/USE_CASES.md`, `docs/ixp-evaluation.md`, both cookbook recipes, the
    adapter README, `ROADMAP.md`, and `CHANGELOG.md` carry the flipped claim
    language. Landed after 1–17 with zero `must_match` entries open; the gate
    re-blocks the flag if one re-opens.

Normalization applied to both legs before the diff (recorded in each
fixture's `provenance.normalization`): timestamps, the rustbgpd version,
`hold_timer_now`/`keepalive_now`, each leg's own route-server addresses,
route and symbol list order, and BIRD's `route_changes` counters (they follow
announcer arrival order; the block's shape is still compared). The two route
servers cannot share one address
on one segment, so `source_address` is compared as `<route-server>`; BIRD's
default hold time is mirrored in the rustbgpd config so the negotiated timers
match.

## Fixture ownership and consumers

The Rust smoke test pins `adapter-consumer.php`'s journey source and the CI
entry point, but most data and configuration fixtures are owned by the
shell/PHP/Python harness. The renderer fixtures in the last three rows are the
exceptions; they are listed here so every checked-in capture has an explicit
owner and refresh relationship.

| Pinned file | Owner or producer | Executable consumers and checked relationship |
|---|---|---|
| `Dockerfile` | Hand-maintained PHP/Composer environment for the two pinned upstream checkouts | `run.sh` builds the image used by `run-in-container.sh`, `run-adapter-consumer.sh`, and `run-oracle-leg.sh`. |
| `Dockerfile.oracle` | Hand-maintained BIRD 2.0.12 oracle image | `run-oracle-leg.sh` builds it and verifies the installed BIRD version before the populated comparison. |
| `Dockerfile.alice`, `alice.conf`, `alice-consumer.py` | Pinned-source Alice-LG 6.2.0 build and bounded API assertions | `run.sh` builds and label-verifies the image; `run-oracle-leg.sh` proves the populated accepted/noexport and empty filtered views. |
| `Dockerfile.manrs`, `manrs-roas.json` | Pinned-source MANRS build and five synthetic ROAs | `run-oracle-leg.sh` requires one exact Alice-derived invalid stanza and the exact 7-route/5-ROA summary. |
| `birdseye.env` | Hand-maintained production-mode Bird's Eye settings | `run-in-container.sh` copies it unchanged; `run-oracle-leg.sh` changes only `BIRDC` and `MAX_ROUTES` before installing it in the real-BIRD oracle. |
| `fake-birdc` | Hand-maintained deterministic `birdc` transcript oracle selected by `birdseye.env` | Bird's Eye executes it during `run-in-container.sh`; `verify_capture.py` checks the resulting HTTP capture. The populated oracle does not use it. |
| `contract.json` | Reviewed compatibility pins, scope, and divergence decisions | `run.sh`, `verify_capture.py`, `consumer.php`, `adapter-consumer.php`, `oracle-consumer.php`, `nagios-consumer.php`, `scripts/check_ixp_manager_docs.py`, and `tests/interop/scripts/test-m97-ixp-manager-authenticated-lifecycle.sh` read it directly. |
| `fixtures/birdseye-contract.json` | `verify_capture.py` output from pinned Bird's Eye plus `fake-birdc` | `run-in-container.sh` invokes `verify_capture.py`, which byte-compares a fresh HTTP capture with this file. |
| `fixtures/ixp-manager-consumer.json` | `consumer.php` output from the pinned IXP Manager `BirdsEye` client | `run-in-container.sh` byte-compares the fresh consumer output with this file. |
| `fixtures/ixp-manager-v7.4-rustbgpd.json` | `config-consumer.php`'s row-31-disabled, two-client real Foil capture | `run.sh` byte-compares the fresh capture with this file and the renderer-owned v2 supported fixture; `verify_capture.py` checks its schema, filter rows, completion count, and absence of legacy refusal markers. M96 and M97 intentionally use the separate single-client PCH projection below. |
| `fixtures/populated-oracle.json`, `fixtures/populated-live.json` | Normalized `oracle-consumer.php` outputs from BIRD/Bird's Eye and rustbgpd/adapter respectively | `run-oracle-leg.sh` produces the raw pair; `verify_capture.py --populated` normalizes, byte-compares, then applies the divergence audit. |
| `oracle-bird.conf` | Hand-maintained BIRD half of the populated topology | `run-oracle-leg.sh` copies it into the BIRD 2.0.12 container. |
| `oracle-announcer-as64496.conf`, `oracle-announcer-as64497.conf` | Hand-maintained deterministic ExaBGP announcements | `run-oracle-leg.sh` validates each file with ExaBGP, then mounts it into its announcer. |
| `tools/rs-config-render/tests/fixtures/ixp-manager-v1-supported.json` | Pinned legacy single-client PCH contract: VLAN interface 3, customer 3, ASN 42, and `31.135.128.0/19` | `run.sh` renders it directly, projects it into the additive v2 envelope, and compares the transient fresh `config-pch-v2.json` capture before M96 consumes that capture. M97 independently projects the same oracle and compares its authenticated API response. `ixp_manager.rs`, `activation.rs`, and `ixp_manager_lifecycle.rs` also consume it with `include_bytes!`. |
| `tools/rs-config-render/tests/fixtures/ixp-manager-v2-supported.json` | Pinned copy of the row-31-disabled, two-client real capture; intentionally byte-identical to the compatibility fixture above | `run.sh` compares it with the fresh `ixp-manager-v7.4-rustbgpd.json` capture; `ixp_manager.rs`, `recover.rs`, and `ixp_manager_lifecycle.rs` consume it with `include_bytes!`. |
| `tools/rs-config-render/tests/fixtures/ixp-manager-v2-ui-filters.json` | Pinned copy of the distinct real `config-ui-filter.json` capture with rows 31, 33, and 35 enabled | `run.sh` compares it with that fresh capture; `ixp_manager.rs` consumes it with `include_bytes!`. |

Keep the two renderer capture files separate. The supported file pins the
row-31-disabled state (`32, 33, 35`), while the UI-filter file pins the
different full state (`31, 33, 35`). Collapsing them would make one fixture
stand for two real IXP Manager database states, weakening both capture
provenance and the row-selection behavior exercised by the harness. The
byte-identical compatibility and renderer copies of the supported capture are
also intentional: each subtree owns its public contract, and `run.sh` proves
both copies still match the same fresh output.

## Provenance and licensing

Upstream source stays in a temporary directory and is never vendored. Alice-LG
is BSD-3-Clause; the pinned MANRS checkout has no detected license file, so the
harness executes it only transiently and makes no redistribution claim. Both
run only against the synthetic populated leg. IXP
Manager is GPL-2.0; the gate executes its installed consumer while this
repository keeps its original GPL-2.0-only Foil exporter in the segregated
integration subtree. Bird's Eye is MIT-licensed. The two
JSON fixtures are captured outputs from that pinned server using the synthetic
inputs above; they contain no production routing data.
