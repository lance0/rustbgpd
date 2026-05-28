# ADR-0073: Import policy explain via per-session decision cache

**Status:** Accepted
**Date:** 2026-05-28

## Context

`rustbgpctl` already explains *export* decisions cleanly: RIB owns
both the candidate route and the export-policy chain
(`crates/rib/src/manager/distribution.rs:75`), and the RPC surface
hangs off the route-explain group at `proto/rustbgpd.proto:608`.

There is no equivalent for **import**. The operator question
"why didn't this route come in?" cannot be answered today, because:

- Import policy is evaluated in the transport layer at
  `crates/transport/src/session/inbound.rs:698`. A denied route
  drops at that point and never reaches RIB. Existing tests pin
  this behaviour.
- Adj-RIB-In holds only **accepted, post-policy** routes; a
  re-evaluation against it can answer "what would current policy
  do to this prefix" but cannot reconstruct what happened to a
  prefix that was *rejected* on arrival.
- `bgp_policy_import_routes_{permitted,denied}_total{peer}`
  counters answer "how many," not "which prefix and why."
- `PolicyEvaluation` (`crates/policy/src/engine.rs:797`) carries
  the terminal-decision policy + action, which is what an explain
  surface should report — but it is consumed and discarded at the
  eval site.

The denied case is the load-bearing one. An import-explain that
only answers for accepted routes is the wrong shape: it ships
something that *looks* like the answer but quietly fails on the
question operators ask most.

### Operator precedent

Adjacent stacks all expose deeper-than-RIB import visibility, all
gated on explicitly retained state:

| Stack | Surface | Default retention |
|---|---|---|
| FRR | `show bgp ... neighbors ...` separates accepted / received-pre-policy / advertised / filtered | filtered visibility opt-in |
| Junos | "hidden routes" retain import-rejected entries by default; `keep none` is the documented memory-saving knob | retained by default |
| Cisco IOS-XR | `received-routes` shows accepted + rejected; `routes` shows accepted-only | retained with soft-reconfiguration |
| OpenBGPD | unfiltered Adj-RIB-In only with `announce ... soft-reconfiguration` enabled | retained when opted in |

The shared theme: useful explain costs memory; make it bounded and
make the retention posture an explicit choice.

## Decision

Add a **per-session import-decision cache** in transport that
records every import-policy evaluation — permit and deny — at the
moment of evaluation, and serve a new `PolicyService.ExplainImportPolicy`
RPC that reads it.

### Framing — this is not durable event history

The cache is **bounded transport-session diagnostic state**, not
durable event history. It is process-local, in-memory, resets on
peer session reset, and resets on daemon restart. It deliberately
sits outside ADR-0072's durable event outbox to avoid re-litigating
SQLite retention, schema versioning, and operator-facing cursor
contracts for a surface whose load-bearing job is "answer the
operator's *current* question about why this prefix isn't here."
Operators who want durable cross-restart policy-decision history
will need a separate surface and a separate ADR — not a config
flag on this one.

### Cache shape

- **Owner:** per-session, in transport. Lives next to the existing
  per-peer state (peer label, metrics, policy handle).
- **Key:** `(AFI, SAFI, prefix, path_id)`. Path-ID is part of the
  key so Add-Path-enabled peers don't collapse multiple paths into
  one entry.
- **Value:** outcome (`PERMIT` / `DENY`), terminal policy label
  and name (from `PolicyEvaluation`), pre-policy path attributes
  as received, modifications applied, RPKI + ASPA validation state
  at eval time, `evaluated_at` timestamp, `policy_generation`.
- **Write triggers:** every return from
  `evaluate_chain_with_attribution` at
  `crates/transport/src/session/inbound.rs:698`. Insert or replace
  under the key.
- **Clear / replace triggers:**
  - newer UPDATE for the same key → replace
  - withdraw for the key → mark as `WITHDRAWN` (not `NOT_SEEN` —
    the distinction is operationally meaningful)
  - peer down / reconnect → flush the per-session table
  - new policy generation → lazy invalidation on read (stamp
    `STALE`); no eager scan
- **Bound:** per-peer cap, **4096 entries**, configurable via
  `[policy.explain] cache_size` (nested under the existing
  `[policy]` section per the convention already established by
  `[policy.definitions.filter]`). The bucket name reads as
  *diagnostic retention*, not policy evaluation behaviour — flipping
  this knob cannot change which routes get accepted. LRU eviction.
  A small secondary structure — a recent-eviction key set, lossy
  with false-positive-only semantics, sized in the low hundreds of
  entries per peer — lets a subsequent lookup return `EVICTED`
  rather than `NOT_SEEN`. The 4096 default mirrors the existing
  4096-entry event ring mental model (`crates/rib/src/manager/mod.rs`
  and the EHM caps): big enough for operational debug, small
  enough to keep total footprint bounded on dense-peer deployments.
  Operators who want full prefix-table retention raise this knob
  and own the memory cost.

### RPC surface

A new method on **`PolicyService`** (not RIB service) because the
source of truth is policy + session state, not the post-policy RIB:

```proto
rpc ExplainImportPolicy(ExplainImportPolicyRequest)
    returns (ExplainImportPolicyResponse);
```

Authorization tier: **`SensitiveRead`**, matching the existing
route-explain surfaces (`crates/api/src/authz.rs`).

Response carries one of five outcomes:

| Outcome | Meaning |
|---|---|
| `PERMIT` | Cached entry, route was permitted |
| `DENY` | Cached entry, route was denied (the load-bearing case) |
| `NOT_SEEN` | Peer has never sent this prefix (or it has been withdrawn — distinguished from `WITHDRAWN` below) |
| `WITHDRAWN` | Was permitted, withdrawn after; entry retained for visibility |
| `EVICTED` | Was in the cache; pushed out by the per-peer bound |
| `STALE` | Cached entry's `policy_generation` is older than current; result no longer represents current policy |

The query is a **read** — it must not increment policy counters,
must not touch RIB, must not log a new policy decision.

### Generation stamping

Policy reload (SIGHUP soft-reset) is an existing surface. Without
generation stamping, a reload silently makes every cached entry
misrepresent current truth. The policy registry exposes a
monotonic `u64` generation, bumped on each reload. The cache copies
the current generation onto each entry at write time; the explain
read compares to the current generation and returns `STALE` on
mismatch.

Lazy invalidation: no scan on reload, no rewrite of cached entries.
`STALE` is decided at read time. Operators who want a fresh decision
can clear-and-replay the peer (existing mechanism) or wait for the
peer to re-advertise.

### CLI

```
rustbgpctl policy explain --neighbor X --prefix Y [--path-id N]
                          [--afi ipv4|ipv6] [--safi unicast]
                          [--json]
```

Text render: outcome line, peer + prefix, terminal policy, pre-eval
summary, modifications, RPKI/ASPA, timestamp, policy generation.
JSON render: every response field, machine-stable.

Add-Path semantics: when the peer negotiated Add-Path and
`--path-id` is omitted, the CLI returns all matching entries (JSON
array; text renderer flags the disambiguation).

### AFI/SAFI scope

IPv4 and IPv6 **unicast** only in this ADR. FlowSpec and EVPN have
different NLRI / route-key shapes (EVPN has per-route-type
discrimination) and need their own ADRs.

## Consequences

### Positive

- The operator question "why didn't this route come in?" gets a
  honest, on-by-default answer.
- Symmetric with the existing export-explain surface: both questions
  are first-class.
- Generation stamping closes a footgun present even in the export
  surface today (an operator running `explain` immediately after a
  policy reload gets an answer that may not reflect current truth);
  the new surface establishes the pattern.
- Bounded, with explicit operator-visible eviction. No silent lies
  under churn.

### Negative

- New persistent state surface in transport. Memory cost scales
  with peer count × cache size, roughly `peers × 4096 × ~256 B ≈
  100 MB` at the proposed defaults with 100 peers. Acceptable on
  the typical deployment shape but not free; the per-peer cap is
  the operator's lever.
- A new contract operators will rely on. Future changes to the
  surface (outcome enum, field set, key shape) carry compatibility
  cost.

### Neutral

- The cache resets on daemon restart and on peer session reset.
  The first UPDATE per `(peer, prefix, path_id)` after the reset
  re-fills the entry. This is by design — see the "not durable
  event history" framing above — but worth restating: an explain
  query during the warm-up window after a restart will see
  `NOT_SEEN` for prefixes the peer has not yet re-advertised.
  Operators triaging restart-window incidents read this surface
  alongside the durable event outbox (ADR-0072), not in place of
  it.

## Decisions baked in

The plan-stage research surfaced six knobs. They are pinned here,
not deferred:

| # | Question | Decision |
|---|---|---|
| 1 | Default per-peer cache size | **4096 entries.** Same mental model as the existing event rings — enough for operational debug, not full-table retention. Operators with eBGP-internet-scale peers raise the knob and own the memory cost. |
| 2 | Default-on retention | **Yes.** Explain should work unless explicitly disabled. The cost is bounded by (1). |
| 3 | EVICTED tracker | **Yes**, kept compact: lossy recent-eviction key set / bloom-ish ring, false-positive-only. A wrong `EVICTED` is operationally better than a wrong `NOT_SEEN`. |
| 4 | Withdraw semantics | **`WITHDRAWN`**, retained as a tombstone until evicted / stale / session reset. Same memory cost as any other entry; preserves the operational distinction between "never seen" and "seen and removed." |
| 5 | Add-Path | Include `path_id` in the cache key and the response. CLI accepts optional `--path-id`. Without it, return all matching entries for the prefix (a clear multi-path response), never an arbitrary first hit. |
| 6 | Statement-level trace | **No in v1.** Terminal `matched_policy` only, aligned with the existing `PolicyEvaluation` shape. Enrichment is a separate ADR if operator feedback says terminal attribution is insufficient. |

## Out of scope

- FlowSpec and EVPN AFI/SAFIs. Separate ADRs.
- Export-explain rework.
- Statement-level policy trace inside `PolicyEvaluation`.
- Bulk "show every denied import for this peer" surface. v1 is
  point-query only.
- Durable cross-restart import-decision history. The cache is
  process-local on purpose; if a durable bridge surfaces a real
  need, it gets its own ADR.

## Implementation sequencing

PR-shaped, after this ADR is Accepted:

1. Transport cache + proto surface. Add the per-session cache,
   wire write and clear sites, add `ExplainImportPolicy` reading
   from the cache, thread `policy_generation` through.
2. CLI + Add-Path semantics. `rustbgpctl policy explain`, text +
   JSON renderers, Add-Path disambiguation.
3. (deferred) Statement-level enrichment of `PolicyEvaluation` and
   the cached entry — only if operator feedback says terminal-only
   attribution is insufficient.

## Anchors

- Eval call site: `crates/transport/src/session/inbound.rs:698`
- `PolicyEvaluation`: `crates/policy/src/engine.rs:797`
- Export-explain reference: `crates/rib/src/manager/distribution.rs:75`,
  RPC at `proto/rustbgpd.proto:608`
- Existing import counters: `record_import_policy_eval` at
  `crates/transport/src/session/inbound.rs:15`
- Authz tier reference: `crates/api/src/authz.rs`
