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

## Amendment: progressive chunk publication

The original design published the whole encoded payload through one
`OnceCell`, so every consumer awaited the encoder's full-table encode before
sending anything: the single-threaded encode became the per-observer wire-gap
floor (measured 1.2–1.5 s at 700 clients × 400,400 routes, above the 1 s
receipt gate, even though completion and first-UPDATE latency were healthy).

Publication is now progressive. The cell became a synchronous `OnceLock`
whose initializer only *constructs* an empty stream state (encoder profile,
a mutex-guarded chunk vector with a terminal marker, and a `Notify`), so
encoder election commits with no await point between winning and encoding —
an initialized cell always has a live encoder or its guard's terminal. The
encoder prepares, groups, and encodes the inventory in bounded route slices
(2048 routes; single-digit-millisecond encode at reload-stall shapes),
publishing each slice's chunks as they are produced and sending its own
filtered copy along the way; consumers prove wire-equivalence once, then
send chunk *i* as soon as it exists. A member's longest wire silence now
tracks per-slice encode latency instead of the full-table encode.

The encoder walks the inventory through an index sorted by source peer.
The inventory arrives in table order with sources interleaved per prefix,
and per-slice grouping in that order fragments every source across every
slice — measured at 300 clients × 171,600 routes as tens of thousands of
tiny UPDATEs per member and writer-channel saturation teardown. Source
order keeps per-source chunks dense (a source spanning a slice boundary
costs one extra UPDATE) and is safe to reorder because the inventory
carries one route per prefix and announcements of distinct prefixes are
order-independent. Slices keep the announce/next-hop-override index
alignment, and the prepared-attribute cache persists across slices.

The terminal marker is `Complete` or `Failed`. Any encoder anomaly — the
same enumerated cases as before, at any slice — terminates the stream as
`Failed`, published by a drop guard even if the encoder unwinds, and every
member falls back to the ordinary per-session encode. Mid-stream fallback is
safe by construction. The invariant is per-NLRI attribute identity, not
byte-identical chunks: an extended-message member's local re-encode chunks at
its negotiated ceiling rather than 4096, and the shared stream's
source-sorted walk yields different NLRI order and UPDATE boundaries than the
table-order local encode. What the wire-equivalence proof establishes per
route is that every prefix a member already sent maps to exactly the
attributes its local re-encode attaches to it, so the receiver sees
idempotent re-announcements at the BGP semantic level regardless of message
framing, and no route can be skipped: the fallback re-encodes the full
envelope from index 0. An encoder whose own writer
saturates keeps publishing for the group; its own teardown policy has
already run inside the failed enqueue.

## Amendment (2026-09-27): mixed withdrawal and announcement passes keep the shared encode

The Consequences above scoped the incremental delta fanout out, and the
fallback rule sent any envelope carrying more than unicast announcements to
the per-session encode. Live grouped distribution passes later gained the
shared encode cell too, which left one gap: a pass that mixes unicast
withdrawals with announcements. A member failover is the common case. Some of
the failed member's prefixes move to an alternate source, and the rest have no
alternate. The RIB already attached the shared cell to those envelopes and
appended the group's withdrawals, but the session fell back on any withdrawal.
Every member therefore re-prepared and re-encoded the shared announce list
itself.

Such passes now keep the shared encode:

- **Withdrawals stay per member and precede the shared announcements.** A
  member sends its unicast withdrawals through the ordinary encoder first,
  then streams the shared announce chunks. This keeps the per-session path's
  withdrawals-before-announcements order. An elected encoder with withdrawals
  still encodes and publishes the whole inventory at election. It defers only
  its own copy, which it streams from the first chunk once its withdrawals are
  admitted.
- **Fallback resumes at the announcements.** If the stream fails after a
  member's withdrawals went out, the ordinary encode continues from the
  announce phase. Withdrawals are never resent after an announcement, and a
  shared chunk already sent may repeat as before.
- **Other payload kinds are unchanged.** An envelope carrying anything beyond
  unicast withdrawals and announcements still takes the per-session path.
  This covers other families, End-of-RIB and refresh markers, OTC-blocked
  routes, and refresh requests.
- **New winning sources stay per member.** A member whose own route becomes
  the new best path must receive withdrawals for the prefixes it now owns.
  The RIB therefore excludes it from the shared emission and walks the pass's
  deltas for it individually. That RIB-side walk is unchanged and remains
  out of scope here.

Add-Path members remain outside update-groups (ADR-0099), and a member whose
profile fails the wire-equivalence proof still falls back to its full
per-session encode, withdrawals included.

### Follow-up (2026-09-27): new winning sources ride the shared payload

The last bullet above left new winning sources on the RIB-side per-member
walk. That walk cloned every other-sourced announcement into a private
payload, so the member also missed the pass's exact-export probe reuse and the
shared encode cell. A failover with alternates from several members paid that
once per new winner on the RIB actor.

A new winner now rides the group's shared payload:

- **Owed withdrawals are indexed during the shared build.** When the shared
  emission is built from the pass's deltas, each announcement whose source
  changed onto a member records that key as the member's owed withdrawal.
  The member's own routes are hidden by the existing own-source exclusion.
  Its envelope carries those withdrawals ahead of the pass's shared
  withdrawals. The shared announce and next-hop arrays, the probe cache and
  the encode cell are the same ones every other member uses, and the session
  sends all the member's withdrawals before the shared announcements as
  described above.
- **An unchanged source owes nothing.** A member that re-announces its own
  best path differently is hidden by the exclusion alone, so it no longer
  leaves the shared payload either.
- **The remaining exceptions keep the per-member walk.** An old source of a
  withdrawn key would otherwise receive a withdrawal the per-peer path does
  not send. The same applies to an ADR-0126 exception-lane substitution or
  lane target, and to an RS-control member in a tagged pass. Add-Path members
  are still never grouped (ADR-0099), and an incompatible export profile still
  falls back in the session.

Wire output matches the per-peer path: withdrawal keys and per-prefix
announcement attributes are the same, and only the UPDATE frame partition of
the shared announcements differs, as above. The BMP rib-out tap mirrors the
frames that were actually sent. A lost envelope records the same
member-scoped withdrawals for the dirty resync as before.
