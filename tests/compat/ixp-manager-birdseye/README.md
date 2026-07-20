# Pinned IXP Manager / Bird's Eye contract oracle

This harness captures the external HTTP contract consumed by IXP Manager's
`IXP\Services\LookingGlass\BirdsEye` class. It is an upstream oracle, not a
claim that rustbgpd or its example Birdwatcher adapter is Bird's Eye compatible.

The gate clones and verifies these exact upstream commits, installs both
projects from their committed Composer lockfiles, starts the real Bird's Eye
Lumen server with `APP_DEBUG=false`, and invokes the real IXP Manager consumer:

- Bird's Eye v2.1.0: `7f8c2375e610578bcf6ea5ceec630a180f945b89`
- IXP Manager v7.3.1: `bfbbc23533e56c56a4102178676ec7b3d0d990fa`

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
Complete rejected-route reasons, less-specific lookup, atomic all-candidate
snapshots, and runtime alias configuration remain blockers. Promoting any of
them, weakening the explicit alias, enabling debug mode, skipping a case, or
drifting a pin or response makes the gate fail.

## Provenance and licensing

Upstream source stays in a temporary directory and is never vendored. IXP
Manager is GPL-2.0; the gate executes its installed consumer but copies no PHP
source or templates into this repository. Bird's Eye is MIT-licensed. The two
JSON fixtures are captured outputs from that pinned server using the synthetic
inputs above; they contain no production routing data.
