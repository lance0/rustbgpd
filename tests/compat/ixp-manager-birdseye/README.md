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
claim is made and `runtime_compatibility` remains false.

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

## Provenance and licensing

Upstream source stays in a temporary directory and is never vendored. IXP
Manager is GPL-2.0; the gate executes its installed consumer while this
repository keeps its original GPL-2.0-only Foil exporter in the segregated
integration subtree. Bird's Eye is MIT-licensed. The two
JSON fixtures are captured outputs from that pinned server using the synthetic
inputs above; they contain no production routing data.
