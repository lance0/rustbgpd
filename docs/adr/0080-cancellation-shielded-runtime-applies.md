# ADR-0080: Cancellation-shielded runtime mutation applies

**Status:** Accepted
**Date:** 2026-06-10

## Context

tonic/hyper drop a request's future when the client disconnects — a
killed `rbgp`, an RPC deadline, a network blip. A dropped future
stops executing at its current await point and never resumes. For
read paths this is free cancellation; for **multi-step runtime mutation
applies** it is a correctness hazard: the mutation stops half-applied,
its rollback ladder (code later in the same dropped future) never runs,
its outcome is never recorded, and its committed baseline never
advances.

The EVPN runtime apply demonstrates every failure mode at once. The
gRPC handler awaits the daemon hook inline, and the hook is a plain
boxed future around `apply_request` — so the entire converge + commit
critical section runs inside the request future. Dropped between an
IMET withdraw and the re-originate of a redefine, it leaves the VNI's
Type 3 withdrawn network-wide while the coordinator still reports the
old generation as Committed/Idle, and — because `set_committed_config`
never ran — the next SIGHUP of an unchanged file diffs against the
stale baseline, computes "no change", and skips repair. The same drop
can come from inside the process: the SIGHUP arm aborts an in-flight
reload task on shutdown, cancelling a converge the same way.

The codebase already contains the cure, applied inconsistently: the
FIB-table CRUD path runs its apply+persist on a **detached task**
precisely so "a cancelled gRPC call can't split apply from persist".
EVPN apply (and any future multi-step apply) never adopted it. A second,
related gap: coordinated shutdown tears down EVPN actors and withdraws
IMET routes *while the gRPC server is still serving* `ApplyEvpnRuntime`,
and none of that teardown takes the apply lock — shutdown can interleave
with an in-flight converge and re-originate routes after the
withdraw-all sweep.

## Decision

**Every multi-step runtime mutation apply runs on a detached task; the
request future only awaits the result.** Concretely:

1. The apply (plan → converge → commit/rollback → baseline advance,
   including failure recording) executes inside `tokio::spawn`. The
   RPC/SIGHUP caller awaits the `JoinHandle` (or a oneshot). Client
   disconnect or reload abort then means the **caller loses the
   response — never the mutation's atomicity**: the apply runs to its
   own completion, records Committed or Degraded in the coordinator,
   and advances the baseline, regardless of who is still listening.
2. The shield lives at the apply layer (e.g. inside
   `EvpnRuntimeReloadApply::apply_request`), not per transport, so the
   gRPC hook, SIGHUP reload, and any future caller inherit it.
3. **Coordinated shutdown serializes with in-flight applies.** The
   shutdown path's actor teardown and IMET `withdraw_all` acquire the
   same apply lock the converge holds (or the daemon stops serving the
   mutating RPC before the teardown begins), so shutdown cannot
   interleave with a converge that already passed its actor-open
   checks. A detached apply also means shutdown must await (with a
   bounded drain deadline) any apply task it cannot fence out.

Inventory at the time of writing:

| Apply path | Status |
|---|---|
| FIB-table CRUD (`SetFibTable`/`DeleteFibTable`) | already shielded (the precedent) |
| Config transactions (`ApplyConfigTransaction` + confirm/abort) | serialized under the coordinator lock; audit found no split-apply window |
| EVPN runtime apply (`ApplyEvpnRuntime` + SIGHUP EVPN section) | **the gap this ADR closes** |

The rule binds future surfaces too: any new RPC whose handler mutates
kernel, RIB, or coordinator-baseline state across more than one await
point must ship shielded, and review should treat an inline multi-step
apply in a request future the way it treats a missing rollback ladder.

### Alternatives considered

- **A dedicated apply actor** (queue of mutation requests owned by one
  task). Strictly stronger — it also serializes applies and shutdown by
  construction — but it is a larger refactor than the hazard requires,
  and the apply lock already provides the serialization; revisit if the
  number of shielded paths grows past comfortable.
- **Accepting cancellation and making every converge step
  cancel-safe** (state-machine checkpointing so a drop at any await
  leaves a recorded, resumable state). Rejected: vastly more invasive
  than detaching, and it still loses the outcome report.

## Consequences

- An operator can no longer wedge EVPN runtime state by Ctrl-C'ing the
  CLI mid-apply: the mutation completes (or rolls back and records
  Degraded), the baseline advances, and SIGHUP repair semantics stay
  truthful. Paired with the IMET `not_found` self-heal, the
  "half-applied and unrepairable" class is closed.
- The caller may now receive `DEADLINE_EXCEEDED`/disconnect while the
  apply succeeds — the same at-least-once ambiguity FIB CRUD already
  has. `GetEvpnRuntime` / transaction status remain the authoritative
  outcome surfaces, and the response-shape docs should say so.
- A detached apply outlives its request, so its tracing span and audit
  log entry — not the RPC context — carry the operator identity for the
  tail of the run.
- Shutdown gains one ordering obligation (fence or drain in-flight
  applies) in exchange for losing an interleaving that could
  re-advertise routes after the shutdown withdraw sweep.
