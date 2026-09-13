# ADR-0133: Installed Import-Counter Reads

**Status:** Proposed
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
reclamation costs still require measurement; the latest-value channel does
not imply a global memory bound.

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

This ADR remains Proposed until implementation review and native evidence are
complete.
