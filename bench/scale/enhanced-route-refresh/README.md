# Enhanced Route Refresh scale receipt

This directory measures the current RFC 7313 inventory owners before any
representation or ownership change. It drives a real TCP BGP session through
the shipped wire decoder and transport session, announces exactly 100,000 IPv4
prefixes, and exercises both explicit EoRR and the independent five-minute
timeout.

The wire sequence follows
[RFC 7313 section 4](https://www.rfc-editor.org/rfc/rfc7313.html#section-4):
BoRR and EoRR demarcate a complete Adj-RIB-Out re-advertisement, routes not
replayed inside that window are removed, and the locally bounded stale-route
timeout is an allowed completion path. The initial empty IPv4 UPDATE is the
per-family convergence marker defined by
[RFC 4724 section 2](https://www.rfc-editor.org/rfc/rfc4724.html#section-2);
the harness keeps that EoR distinct from EoRR, as RFC 7313 requires. The
duplicate-BoRR cell measures rustbgpd's deliberate fresh-resnapshot behavior;
it is an implementation contract, not a separate normative requirement in
RFC 7313.

The scale boundary matters operationally for this niche:
[RFC 9324 section 5](https://www.rfc-editor.org/rfc/rfc9324.html#section-5)
specifically warns IXP route-server operators about undue Route Refresh load.
This receipt measures one member deterministically before considering any
ownership or representation change.

The runner records a same-process, same-SHA settled baseline and the following
phase boundaries:

| Phase | Required production state |
|---|---|
| baseline | Adj-RIB-In and transport max-prefix usage are 100,000; refresh is inactive |
| first BoRR | refresh active; RIB stale inventory is exactly 100,000 |
| replay one | stale inventory is exactly 99,999 |
| duplicate BoRR | the peer-triggered replacement snapshot is exactly 100,000 again |
| EoRR | unreplayed routes are removed from both Adj-RIB-In and max-prefix accounting |
| restored | the same session re-announces the exact 100,000-prefix table |
| timeout BoRR | a separate refresh window owns exactly 100,000 stale routes |
| timeout complete | the production timer removes all unreplayed routes from both owners |

The exact count is checked from the production Adj-RIB-In and max-prefix
gauges. Three independently queried API sentinels (first, middle, and final
prefix) must exist through each active window and must be absent after both
completion paths, so a zeroed gauge without a real sweep cannot pass.

Each action has an `*-arm` barrier before it. The outer runner uses that
boundary to reset the daemon's kernel high-water mark and capture the
pre-action allocator/RSS state. It continuously samples RSS and jemalloc
gauges, then captures the exact post-action state before acknowledging the
driver. The actor-duration histogram must advance on every accepted begin,
EoRR, and timeout operation.

The fleet shape is deliberately one ERR-capable peer × 100,000 unique IPv4
/24s. It isolates per-peer inventory cost; it does not claim synchronized
multi-peer wall time or extrapolate sampled resident bytes to a larger fleet.

## Run

The durable runner is host-locked and refuses a dirty worktree:

```text
bench/scale/enhanced-route-refresh/run-receipt.sh
```

It builds a real release daemon with jemalloc, the standalone driver, and
`rbgp`; generates the exact daemon configuration; runs the complete
approximately six-minute session; and leaves private raw output under
`target/enhanced-route-refresh/`.

## Load-bearing proofs

- `announcement_plan_encodes_every_receipt_prefix_exactly_once` parses the
  generated wire UPDATEs and checks the complete set. Dropping, duplicating, or
  changing one generated prefix makes it red.
- `receipt_shape_refuses_smaller_nonrepresentative_tables` prevents a quick
  local run from being mislabeled as the durable 100k receipt. Removing the
  fixed-shape guard makes it proceed to connection and changes the asserted
  error.
- `test_validate_phase.py` feeds every exact phase through the same validator
  the runner invokes, then injects an unswept RIB and a missing actor
  observation. Removing either production obligation makes its mutation
  test red.
- The receipt gate itself checks all route, stale, max-prefix, histogram,
  API-sentinel, session-establishment, and flap values at every boundary.
  Removing the RIB BoRR snapshot makes the first-BoRR assertion red; removing
  duplicate resnapshot implementation contract makes duplicate-BoRR stay at
  99,999; removing the EoRR or timeout sweep leaves the route/max-prefix counts
  nonzero and the sampled API routes present; accepting a marker without the
  actor timer makes the corresponding histogram count fail.

No optimization is part of this tranche. A representation change is justified
only if this real-session receipt shows material retained/peak memory or actor
duration without weakening transport-owned max-prefix accounting or
session-identity fencing.
