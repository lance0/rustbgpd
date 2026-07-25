# ADR-0064 gRPC authorization threat model

**Status:** Withdrawn — pending rewrite
**Date:** 2026-05-18 (withdrawn 2026-07-25)
**Scope:** gRPC management-plane authentication, authorization, audit
logging, and per-method tier enforcement.

This annex has been withdrawn. It does not describe the shipped system
and must not be cited as security evidence.

## Why it was withdrawn

The draft modeled the management plane as it stood before v0.24.0: tier
enforcement audit-only and off by default, principal mapping
unimplemented, and any accepted credential reaching the whole read-write
surface. None of that holds today. `enforcement = "tier"` is the
default; the runtime resolves each call's tier before the handler runs
and denies it when the listener ceiling or the authenticated principal's
role does not reach that tier; and under tier enforcement startup
validation rejects a listener that can produce no principal at all,
rather than falling back open.

Every risk ranking in the draft was derived from that superseded
assumption, so the rankings cannot be repaired by correcting the prose
around them — they have to be re-derived against the enforced model.
That rewrite is slice 7 of [ADR-0064](0064-grpc-authorization.md), and is
deliberately not improvised here. Until it lands this repository
publishes no gRPC threat model, and the documents below carry the
security surface instead.

## What to read instead

| Question | Source |
|----------|--------|
| How the tier model is designed, and which slices remain open | [ADR-0064](0064-grpc-authorization.md) |
| Which tier each RPC carries, and why | [`docs/grpc-method-inventory.md`](../grpc-method-inventory.md) |
| Deployment hardening, listener posture, credential handling | [`docs/SECURITY.md`](../SECURITY.md) |
| Listener access matrix, audit-record fields, migration steps | [`docs/API.md`](../API.md) |
| How to report a vulnerability | [`SECURITY.md`](../../SECURITY.md) |

Of these, the inventory is the one an auditor can trust mechanically:
`cargo test -p rustbgpd-api authz` fences its per-service tables and
totals against [`grpc-method-inventory.json`](../grpc-method-inventory.json)
in both directions, and fences that export against the `METHODS` matrix
the daemon actually enforces. A tier that drifts from the code fails the
build. The remaining documents are prose and carry no such guarantee.

## What a rewrite has to cover

- The enforced two-check model — listener ceiling then principal role —
  as the baseline, not as future work.
- Where a principal comes from on each listener kind, and what the
  daemon does when one cannot be derived.
- Residual risk that survives tier enforcement: shared-credential blast
  radius within a role, durable audit sink and retention, and
  resource-abuse guardrails on streams and queries.
- Risk rankings derived from that model rather than carried over.
