# ADR-0133: Installed Import-Counter Reads

**Status:** Accepted
**Date:** 2026-09-13

## Context

`GetPolicyStats` reports live per-term counters for installed policy chains.
Import counters belong to the session that evaluates routes, while the
peer-manager read selects the current session roster and enforces the shared
read deadline. Waiting for a session command can delay an otherwise available
counter read. This record covers the import-counter collection path only; it
does not change readiness, policy explain, rejected-route reads, export
statistics, or dataset semantics.

## Decision

The session publishes a small descriptor for its actual installed import
policy: session identity, policy generation, immutable term labels, and the
existing live counter handle. The handle initially reports Pending, before
the spawned task constructs its session. The constructed session publishes
its initial chain or chainless observation at generation 0. Each later install
or clear advances the generation and publishes before acknowledgement, with no
intervening await. A rollback or lost acknowledgement therefore cannot make
manager desired state look installed. The peer manager chooses the current
session handle; it does not synthesize a publication from configuration.

An import read waits for that session-owned publication under the existing
absolute two-second deadline. Pending, chainless, closed, and unavailable
states remain distinct: a chainless session contributes no row, while an
expired read returns `DEADLINE_EXCEEDED` and unavailable observations return
`UNAVAILABLE`. Cancellation discards the entire collection; the peer-manager
roster and ordinary operator admission path remain in use; only the session command
queue is bypassed for this counter observation.

The collector samples the live atomics and error state while rendering each
row. Rows and ratios are therefore observations gathered during collection,
not an atomic row or fleet transaction, and ratios are not clamped. Error
count and detail are acquired together using the existing cold error lock.
A busy reader yields and retries under the original deadline; poisoned data
returns unavailable without claiming the session exited. The descriptor retains counter
ownership and labels, never a policy or compiled representation. A flap keeps
the session and its generation when the installed chain is retained; a
replacement publishes a new session identity, and a fleet read never swaps a
selected old incarnation for that new one. A short `watch` borrow still uses
its channel lock, and dropping the read releases its publication reference.
Session task destruction closes the publication, including when a join handle
has not yet been reaped. Concurrent readers and selected retired channels can
retain publications across multiple generations. Installation, retention and
reclamation costs scale with the installed policies, terms and labels, and
with the generations readers retain. Neither the latest-value channel nor
the 64-observation per-request limit implies a global memory bound.

Publishing initializes the chain's counter cache, including any required
compiled cache, during session construction or installation instead of
waiting for the first evaluation or statistics request. Labels are copied
into the descriptor. The descriptor does not retain the compiled cache;
the installed chain retains its existing ownership. This deliberately moves
lazy initialization work earlier and needs workload-specific cost evidence.

## Consequences

[ADR-0132](0132-operator-read-path.md) established the broader operator-read
admission and deadline context. This change intentionally narrows the
previous import-read success dependency on a session command response:
counter availability now permits collection from the installed publication,
while deadlines, cancellation, ordering, generation and all-or-error responses
remain. Counter availability alone does not prove session progress or
readiness, and this decision makes no
performance or qualification claim. Existing direct transport reads and
operator wait measurements remain meaningful.

The implementation must test construction, install-before-acknowledgement,
rollback and lost acknowledgement, reconnect and closure, chainless peers,
deadline cancellation, budget exhaustion, busy/poisoned counter state, and
sampled metadata consistency. Those tests establish lifecycle and error
semantics; they do not establish an atomic fleet snapshot or a broad latency
bound.

The counter shape follows the narrow ownership model visible in
[Prometheus' Counter implementation](https://raw.githubusercontent.com/prometheus/client_golang/v1.23.2/prometheus/counter.go):
atomic counter storage and labels do not provide a health or transactional-row
guarantee. Tokio's
[watch receiver contract](https://docs.rs/tokio/1.53.1/tokio/sync/watch/struct.Receiver.html)
likewise documents short borrow locking and distinguishes `has_changed` from
the unread-value behavior of `changed`; it does not make the observation
lock-free or transactional.

## Cost evidence

The [reproducible allocation receipt](../perf/artifacts/installed-import-counters-2026-09-13/README.md)
at `5d0a49cea` exercises 1,000 peers, two term labels per policy, four
independently retained installations and retired channel ownership. Cold
descriptor construction requests 1,248,000 bytes per generation for the
9/12/7-byte label shape, including lazy initialization; the warm case
requests 196,000 bytes. Three 256-byte labels increase those figures to
2,968,000 and 936,000 bytes. Publication and reader captures allocate zero
in these measured windows, which have no waiting tasks or concurrent
reader contention. Final-owner release invalidates the exercised descriptor
and counter Weak references, and all four accounting scopes balance to zero.

These are instrumented `System` requested-size observations, not daemon
jemalloc residency, RSS, a latency distribution or a general leak proof.
The reference reload scenario leaves import policy unchanged; four fresh
import installations are a separate ownership stress shape. Final Weak
disposal includes entire retained Arc backing allocations, not just control
headers. Larger policy shapes and more retained generations need their own
measurement.

## Native evidence and remaining limits

The [retained native diagnostic](../perf/artifacts/installed-import-counters-2026-09-13/native-summary.json)
uses the same revision, 1,000 peers with 400 IPv4 prefixes each, 12 reloads
and 24 scheduled calls. The two-worker daemon and 24-worker generator share
two CPUs. All 12 probe pairs start inside the original -220 to 0 ms
commit-relative band, satisfying its six-pair floor.

The diagnostic fails: 19 calls exceed two seconds, 11 of 12 statistics
requests fail in the import stage, and two neighbor requests fail. The one
successful statistics response contains all 1,000 import and 1,000 export
rows. All ten successful neighbor bodies contain all 1,000 peers, with
370–649 rows explicitly marked stale. Independent routing and live endpoint
records retain all 1,000 sessions; no runtime or parse errors occur.

This observation does not establish the complete operator-read latency
target. The import stage still includes manager admission, collection and
response observation; these records cannot isolate their individual waits.
Neighbor reads retain separate peer-manager and RIB budgets, so a response
can meet those API budgets while missing the diagnostic's stricter external
two-second target. Marked-stale rows are unavailable observations, not lost
sessions or a new zero-stale release gate.

This decision accepts the measured ownership and counter-availability
contract. Complete driven-phase latency and qualifying-soak evidence remain
separate work; neither this diagnostic nor the component regressions supply
a release-qualification pass.
