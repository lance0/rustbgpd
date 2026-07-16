# ADR-0109: Encode-once wire sharing for update-group fanout

**Status:** Accepted
**Date:** 2026-07-16

## Context

A clean grouped export-policy transition (ADR-0105) releases the same
`Arc`-shared announce inventory to every member of an update-group; the
envelopes differ per member only by `announce_source_exclusion` and the
member's exact-export snapshot. Every member's session task then encoded its
own full wire UPDATE stream from that shared inventory. At route-server
scale the encodes are byte-identical work repeated N times: with 700
members × 400,400 routes, the N full encodes fair-share the machine and
every observer's first post-reload UPDATE arrives together after the total
encode time divided by the core count — a measured flat ~1.03 s stall
(p50≈p95), with a ~0.76 s floor attributable to encoding alone.

Update-group membership already guarantees a shared export-policy outcome,
and `SessionExportProfile::has_same_wire_encoding` already proves when two
sessions' profiles produce identical bytes for the same route (it is the
probe-reuse proof for the transition's exact-export preflight). Add-Path
peers are disqualified from update-groups (ADR-0099), so per-member path-id
divergence cannot arise on this seam.

## Decision

**Encode once per fanout, in the first consuming session task; share the
encoded bytes through the envelope.** The `CommitMembers` phase creates one
`SharedGroupEncode` cell (a `tokio::sync::OnceCell`) per transition and
attaches it to every member envelope. The first member to consume its
envelope encodes the whole inventory and publishes the result; concurrent
members await the cell instead of re-encoding. Encoding in a session task —
rather than in the RIB actor — keeps the actor's polls bounded and needs no
new cross-crate encoding surface: the cell payload is opaque to the RIB
(the same `as_any` trust-boundary pattern as the exact-export snapshot).

**Sharing key: the wire-encoding profile.** A member reuses the published
bytes only when its own envelope snapshot proves
`has_same_wire_encoding` with the encoder's profile. That predicate is
derived full-struct equality with only snapshot identity, generation, and
the negotiated message ceiling normalized out, so newly added wire inputs
stay inside the proof by default.

**Exclusion mechanism: per-source chunks.** The shared encode groups routes
exactly like the per-session path (prepared-attribute identity plus next
hops) with the source peer added to the group key, then chunks each group
to the message ceiling. A chunk therefore carries routes of exactly one
source peer and one family, and a member's stream composes as "all chunks
except its own source's, restricted to its negotiated families". Keeping
the source in the key matters because global attribute interning can give
two sources pointer-identical attribute sets; the per-session grouping is
deliberately left unchanged (merging sources there produces fewer
messages).

**Ceiling: chunk to the standard 4096-byte maximum.** `has_same_wire_encoding`
deliberately ignores the RFC 8654 extended-message capability because the
ceiling does not change a route's bytes; a ≤4096-byte message is valid for
extended peers too, so one shared byte stream serves members with mixed
ceilings. A single entry that exceeds 4096 bytes makes the payload
unshareable rather than reproducing the oversize-teardown policy here.

**Fallback: the ordinary per-session encode, on any anomaly.** The encoder
publishes an explicit *unshareable* marker on preparation failure, an OTC
egress hit, a scoped-link-local IPv4 drop, or a single-entry oversize; a
consuming member falls back when the payload is unshareable, when its
profile fails the equality proof, when the envelope carries anything beyond
unicast announcements, or when its snapshot fails the existing owner trust
checks. The fallback is the unmodified existing path and owns all
diagnostics and teardown semantics for those cases. Once a member has begun
enqueueing shared chunks, an enqueue failure aborts the batch exactly like
the per-session chunked senders (the saturation/teardown policy runs inside
the byte-level enqueue seam, which the BMP rib-out tap also shares, keeping
the mirror byte-exact).

## Consequences

- Reload re-advertisement encode cost drops from N× to 1× per update-group;
  at 300 clients × 171,600 routes the observer max-gap p50 drops
  correspondingly (measured in the PR introducing this ADR).
- Members of one group can negotiate different family sets: chunks carry
  their family and are filtered per member, preserving the per-session
  path's negotiated-family semantics.
- The ordinary incremental delta fanout (per-member materialized views) is
  unchanged; extending sharing to it would require the same per-source
  composition at the delta seam and is deliberately out of scope.
- The shared bytes hold one encoded copy of the table for the life of the
  fanout envelopes — bounded by the same inventory the envelopes already
  share.
