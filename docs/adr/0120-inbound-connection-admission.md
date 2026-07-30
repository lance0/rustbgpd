# ADR-0120: Inbound connection admission rate limiting

**Status:** Accepted
**Date:** 2026-07-30

## Context

The passive accept path admits inbound TCP connections in three classes:
sources matching a configured static neighbor, sources matching a
`[[dynamic_neighbors]]` range, and everything else. Unmatched sources are
dropped immediately after accept, and dynamic admission is capped by the
process-global `dynamic_neighbor_limit`. Neither mechanism bounds the *rate*
at which one source can cycle the accept path: a churny or abusive host
inside a permitted dynamic range can connect, be admitted, drop, and
reconnect as fast as TCP allows, burning session-spawn work (task spawn,
config resolution, OPEN negotiation, teardown) on every cycle. A
route-server front door with wide member ranges is exactly the deployment
shape where one misbehaving member should not be able to monopolize the
accept loop.

SECURITY.md previously claimed per-source inbound TCP rate limiting that did
not exist; the claim was removed. This ADR adds the real mechanism,
deliberately scoped.

## Decision

Add an opt-in per-source token-bucket accept-rate limiter to the passive
accept path, configured by a new top-level `[inbound_admission]` table.

### Identity: aggregated source address

Accounting is per source IP, aggregated to a configurable prefix length:
`/32` for IPv4 and `/64` for IPv6 by default. Per-/128 IPv6 accounting is
trivially evadable — one commodity host holds an entire /64 and can rotate
through 2^64 addresses without ever reusing a bucket — so the v6 default
aggregates at the standard on-link allocation unit. Both lengths are
configurable (`v4_aggregation_len` 8–32, `v6_aggregation_len` 16–128) for
deployments whose members hold larger or smaller allocations. Ports are
ignored: the identity is the remote host (aggregate), not the flow.

### Scope: post-match, pre-spawn; static neighbors exempt

The limiter runs after the existing admission decisions have classified the
source and before any session work is spawned:

- **Unmatched sources** are dropped by the existing unconfigured-source
  check before the limiter is consulted. They never reach session spawn, so
  rate-limiting them would only re-drop an already-dropped connection.
- **Dynamic-range-matched sources** are the protected surface. A matched
  source must pass the token bucket before the dynamic-slot check and
  session spawn; an over-rate source is dropped even though its range
  matches.
- **Statically configured neighbor addresses are exempt.** A static
  neighbor is an explicit, individually provisioned trust decision, and its
  failure mode is the opposite of abuse: a legitimate peer flapping through
  reconnects (link instability, remote restart loop, hold-timer expiry
  cycles) must never lock itself out of re-establishment — BGP's own
  recovery depends on the reconnect succeeding. The static path also
  already bounds its own work (one session per configured peer, collision
  handling per RFC 4271 §6.8), so the spawn-amplification the limiter
  exists to stop does not arise there. Exemption is by admission path, not
  by address comparison: a source that matches a static neighbor takes the
  static path and never consults the limiter, even when a dynamic range
  covers the same aggregate.

### Accounting: bounded LRU table owned by the accept-path actor

Buckets live in a fixed-capacity LRU table (`table_capacity`, default 4096,
bounds 64–65536) keyed by aggregated source address. Inserting into a full
table evicts the least-recently-used entry, so an attacker rotating source
aggregates can at worst cycle the table — daemon memory is bounded at
roughly `table_capacity` × ~100 bytes (≈400 KiB at the default) regardless
of offered load. Eviction forgetting an old bucket refills that source's
burst allowance; that is an accepted trade — the alternative (unbounded
tracking) converts the limiter itself into a memory-exhaustion vector.

The table is a plain field on `PeerManager`, the single-task actor that
already owns the accept path. No locks, no shared state, no new hot-path
synchronization — the check is a hash lookup plus arithmetic on the
already-serialized accept path.

### Behavior on limit: immediate drop

An over-rate connection is dropped immediately after accept (the socket is
closed by drop). No tarpit, no delayed close, no queueing: the accept loop
and the peer-manager actor stay non-blocking, and the remote sees an
ordinary connection close, which well-behaved BGP speakers already handle
with their connect-retry timer.

### Observability

A new label-bounded counter extends the existing drop accounting:

```text
bgp_inbound_connections_dropped_total{reason="unconfigured"|"rate_limited"|"dynamic_limit"}
```

The `reason` vocabulary is closed and low-cardinality; per-source labels are
deliberately excluded (unbounded cardinality under exactly the attack the
limiter exists for). `unconfigured` and `dynamic_limit` count the
pre-existing drop sites — they are recorded even while the limiter is
disabled, giving operators visibility before opting in — and
`bgp_dynamic_neighbor_limit_rejections_total` keeps incrementing at the
slot-saturation site for dashboard compatibility. The rate-limited drop log
line is itself throttled (at most one per second, with a suppressed-count)
so the log stream cannot be flooded by the flood it reports.

### Defaults: off

`enabled = false` by default. An existing deployment's accept behavior is
byte-identical across the upgrade; only the two counters for pre-existing
drop sites appear. This matches the project's upgrade-caution posture:
admission behavior changes only when an operator asks for it.

### Reload: restart-required

Every `[inbound_admission]` field is restart-required, pinned by the SIGHUP
path exactly like `[event_history]`: the reload logs an `ERROR`, the runtime
snapshot keeps the startup table, and the operator's edit survives in the
desired config for the next restart. The limiter's state (bucket table,
sizing, aggregation keying) is built once by the accept-path owner at
startup; hot-applying an aggregation-length or capacity change would
invalidate every live bucket and re-open a fresh burst allowance for every
source mid-attack, and the sibling admission knob
(`dynamic_neighbor_limit`) is already restart-required — one classification
for the whole admission surface is easier to operate than a per-field
split. Live reload is a possible future promotion if operational experience
demands it; the pinning machinery makes the current classification visible
on every reload until restart.

## Consequences

- Configs without `[inbound_admission]` behave exactly as before; the new
  counter reasons for existing drop sites are the only observable change.
- An abusive source inside a permitted dynamic range is bounded to
  `burst` immediate accepts and `rate_per_minute` sustained accepts per
  aggregate, at O(1) cost per inbound connection and bounded memory.
- A flapping static neighbor is never throttled and keeps its existing
  re-establishment behavior.
- Sources sharing an aggregate share a bucket: one abusive host inside a
  shared v6 /64 can exhaust its aggregate's allowance for well-behaved
  cohabitants. That is the standard aggregation trade-off and the reason
  the lengths are configurable.
- SECURITY.md's inbound-handling section now describes a mechanism that
  exists.
