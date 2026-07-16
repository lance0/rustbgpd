# ADR-0108: Independent per-family maximum-prefix limits

**Status:** Accepted
**Date:** 2026-07-16

## Context

The `max_prefixes` neighbor knob enforces one aggregate ceiling across every
counted family (unicast, FlowSpec, EVPN, BGP-LS, VPN, labeled, RT-Constrain).
Route-server operators provision IPv4 and IPv6 capacity separately —
arouteserver and BIRD deployments express distinct per-family ceilings — and
an aggregate bound lets one family's flood consume the other family's budget
before tripping. RFC 4486 defines Cease subcode 1 (Maximum Number of Prefixes
Reached) and an optional data encoding for the AFI, SAFI, and upper bound.

## Decision

Add `max_prefixes_ipv4` and `max_prefixes_ipv6` (neighbor-level, peer-group
inheritable exactly like `max_prefixes`) bounding unique IPv4-unicast and
IPv6-unicast prefixes respectively.

**Coexistence: independent enforcement, no precedence.** When both a
per-family limit and the aggregate are set, each is enforced on its own
count: the aggregate remains a global backstop across all counted families,
and a per-family limit bounds only its family. Whichever bound is exceeded
first tears the session down. This is the simplest semantics that is
correct: no knob changes meaning when another appears, a legacy config
behaves byte-identically, and the operator can reason about each bound in
isolation. The aggregate is not deprecated.

**Counting.** Per-family limits count what the aggregate counts for unicast:
unique prefixes, with Add-Path multiplicity collapsed. The counts live in the
same compacted accounting (`known_plain_prefixes` / `known_prefix_refcounts`)
as two incrementally maintained per-family totals; withdrawals decrement,
duplicates are free, ERR/EoRR sweeps reconcile, and a session reset clears.

**Teardown.** A per-family violation sends Cease/1 whose data field carries
the RFC 4486 optional encoding — AFI (2 octets), SAFI (1 octet), upper bound
(4 octets) — and logs the AFI, SAFI, and bound. The aggregate keeps its
historical empty data field.

**Runtime lowering.** Hot-applying a per-family limit below the family's
current count enforces immediately on apply. The aggregate keeps its
documented behavior of tripping on the next received UPDATE; changing it was
out of scope and its next-UPDATE semantics are pinned by test.

**Deferred.** Warning thresholds, block/restart (non-teardown) modes,
rejected-route counting, outbound limits, and non-unicast families.

## Consequences

- Legacy configs (aggregate only, or no limit) are unchanged, pinned by a
  regression test asserting identical teardown point and empty Cease data.
- Per-UPDATE enforcement stays O(1); the two per-family counters are
  maintained at the same mutation seams as the existing refcount compaction.
- Operators translating arouteserver/BIRD per-family `import limit` policies
  can map them directly without retiring existing aggregate ceilings.
