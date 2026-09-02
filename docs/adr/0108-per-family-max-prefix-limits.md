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

**Teardown and recovery.** A violation latches the peer administratively down
until explicit enable, fencing active reconnect, passive accept, collision,
dynamic-peer, and config-reconcile paths. Without negotiated Notification GR,
a per-family violation sends Cease/1 whose data carries the RFC 4486 optional
encoding — AFI (2 octets), SAFI (1 octet), upper bound (4 octets); the
aggregate keeps its historical empty data. When the RFC 8538 N-bit was
negotiated, outer Cease/9 (Hard Reset) encapsulates that complete Cease/1 so
the receiver does not retain the over-limit routes as stale.

**Runtime lowering.** Hot-applying a per-family limit below the family's
current count enforces immediately on apply. The aggregate keeps its
documented behavior of tripping on the next received UPDATE; changing it was
out of scope and its next-UPDATE semantics are pinned by test.

**Deferred.** Warning thresholds, block/restart (non-teardown) modes,
rejected-route counting, outbound limits, and non-unicast families.

## Consequences

- Configs with no max-prefix limit remain unchanged. For aggregate-only
  configs, the threshold and empty inner Cease/1 data remain unchanged when
  Notification GR is absent; recovery now uses the explicit-enable latch.
- Per-UPDATE enforcement stays O(1); the two per-family counters are
  maintained at the same mutation seams as the existing refcount compaction.
- Operators translating arouteserver/BIRD per-family `import limit` policies
  can map them directly without retiring existing aggregate ceilings.

## Amendment: pre-policy received-prefix limits

**Date:** 2026-09-01

This amends the deferred "rejected-route counting" item above; the original
decision text is unchanged.

**Decision.** Add `max_prefixes_received_ipv4` and
`max_prefixes_received_ipv6` (neighbor-level, peer-group inheritable exactly
like `max_prefixes_ipv4`). Each bounds the unique unicast prefixes the peer
currently announces in that family **before import policy**: a prefix counts
once whether this daemon accepts it or rejects it (import policy, RFC 9234 OTC,
ADR-0107 next-hop ownership, AS-path and cluster-list loops, and RFC 7606
treat-as-withdraw all count), Add-Path identities share one slot, and an
explicit withdrawal or an RFC 7313 end-of-refresh sweep releases the slot. A
second set of keys rather than a `count_rejected` flag keeps the existing
bounds byte-identical and lets ARouteServer's `count_rejected_routes: true`
(its default) map to the received keys while `false` maps to the accepted
keys; both may be configured at once and are enforced independently, in the
order aggregate, IPv4 accepted, IPv6 accepted, IPv4 received, IPv6 received.

**Counting.** The session actor keeps a rejected sibling of its accepted
accounting — `rejected_plain_prefixes`, `rejected_paths`, and
`rejected_prefix_refcounts` — plus one `rejected_only_*` counter per family
holding the prefixes with a rejected identity and no accepted one. The received
count is `known_unicast_* + rejected_only_*`, maintained in O(1) at every
accept, reject, withdraw, and sweep transition by consulting the other set
before moving a prefix between the two counters. Rejected identities are
tracked only while the family's received bound is configured, so a peer without
one pays no memory; with one, the rejected set is bounded by that limit because
exceeding it tears the session down.

**Exactness.** An enhanced-route-refresh window snapshots the rejected
identities alongside the accepted ones at `BoRR`; a rejected re-announcement
inside the window marks its identity replayed immediately (rejections never
reach the RIB, so no acknowledgement ordering applies), and the `EoRR` or
timeout sweep retires whatever was not replayed through the same
`forget_rejected_path` seam as withdrawals. A withdrawal of a rejected prefix
therefore frees its slot exactly, and an Add-Path prefix counts once until its
last accepted or rejected path leaves.

**Teardown, latch, and recovery** are those of the per-family accepted bounds:
Cease/1 carrying the RFC 4486 AFI, SAFI, and bound, RFC 8538 encapsulation
under Notification GR, the manager's administrative latch, and the optional
`max_prefix_restart_seconds` timed restart. The latch notification and log
line state that the received bound was crossed.

**Runtime edits** are live. Lowering below the announced count enforces
immediately. Enabling a received bound on an Established session starts with
an empty rejected set, so the session requests a plain route refresh for the
family when the peer negotiated it; the replayed table recounts every existing
rejection, and an enhanced-refresh window reconciles the accepted side at
`EoRR`. Without route refresh the count is exact only for announcements after
the change, which is logged; a session reset is always exact. Removing the
bound drops the rejected identities and the metric scope.

**Observability.** `bgp_max_prefix_usage`, `bgp_max_prefix_limit`, and
`bgp_max_prefix_headroom` gain the `ipv4_unicast_received` and
`ipv6_unicast_received` scopes, present only while the bound is configured.

**Warning thresholds and block mode.** `max_prefix_action` (`shutdown`,
`block`, `warning`; neighbor and peer-group inheritable, hot-applied) and
`max_prefix_warning_percent` (1..=100) complete the deferred non-teardown
modes. A warning is evaluated per scope at every accounting boundary: usage at
or above the percentage of the bound (the bound itself under `warning`)
latches the scope, emitting exactly one warn log line, one
`bgp_max_prefix_warning_total` increment, and one `max_prefix_warning` session
event through the lossless coordination lane; the latch re-arms when usage
falls back under, so every crossing reports once and nothing is torn down.

`block` reuses ADR-0113's withhold shape on the inbound side. Withdrawals in an
UPDATE free slots first; then each announced route whose prefix has no accepted
identity is admitted only while its family's bound (and, if the prefix has no
rejected identity either, the received bound) has room, else it is dropped
before accounting and delivery — never installed, never in Adj-RIB-In, and not
remembered, exactly as ADR-0113 refuses a blocked-prefix inventory. A prefix
already accepted always passes (attribute changes, new Add-Path identities). A
prefix blocked by its accepted bound is still a received rejection so the
pre-policy count stays exact; a prefix blocked by the received bound is not
recorded at all. The first drop opens a per-scope episode (one warn line,
`bgp_max_prefix_blocking` = 1, `inbound_prefix_limits[]` row with the stable
`inbound_prefix_limit_reached` reason); usage falling back under the bound ends
it and requests one plain route refresh so the peer replays what was withheld,
the inbound analogue of ADR-0113's coalesced resync. Lowering a bound under
`block` never prunes: the family withholds until usage falls back under.
`block` and `warning` never send `MaxPrefixExceeded`, so the manager latch and
timed restart stay untouched; `block` applies to the per-family unicast bounds
and rejects a configured aggregate `max_prefixes`, whose non-unicast families
have no admission seam; both exclude `max_prefix_restart_seconds`.

**Still deferred.** Outbound limits beyond ADR-0113 and non-unicast families.
