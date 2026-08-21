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
empty route arrays. It drives the same real IXP Manager methods before and
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
Exact protocol-route, exact export-route, filtered-prefix wildcard, and bounded
less-specific table lookup journeys are runtime-supported. The table lookup
returns one matched prefix atomically with its installed winner first and every
same-prefix Add-Path alternative; it is not a full table snapshot. Complete
rejected-route reasons and full-table snapshots remain blockers. Protocol
aliases supplied directly remain immutable after startup; bounded file-backed
aliases reload as one whole resolver generation on Unix `SIGHUP`. Promoting any
blocker, weakening the explicit alias or product-version
posture, enabling debug mode, skipping a case, or drifting a pin or response
makes the gate fail.

## Provenance and licensing

Upstream source stays in a temporary directory and is never vendored. IXP
Manager is GPL-2.0; the gate executes its installed consumer but copies no PHP
source or templates into this repository. Bird's Eye is MIT-licensed. The two
JSON fixtures are captured outputs from that pinned server using the synthetic
inputs above; they contain no production routing data.
