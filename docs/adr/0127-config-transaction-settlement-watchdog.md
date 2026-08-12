# ADR-0127: Config Transaction Settlement Watchdog

**Status:** Proposed
**Date:** 2026-08-11

## Context

[ADR-0076](0076-config-transaction-model.md) makes a config transaction one
daemon-wide operation under the shared runtime-config coordinator.
[ADR-0080](0080-cancellation-shielded-runtime-applies.md) shields multi-step
mutation from caller cancellation by moving it to a daemon-owned task. The
streamed apply path also hands its sole admission permit and candidate to that
detached operation. An RPC deadline or disconnect can end the response wait but
intentionally cannot cancel the apply or release admission.

That cancellation safety creates a liveness obligation. After the controller
owns the coordinator, an executor can await an actor reply, persistence reply,
or rollback reply without a terminal bound. A lost reply can therefore retain
both the coordinator and the streamed admission permit indefinitely. Later
streamed candidates and other config mutation paths remain fenced until daemon
restart, but the daemon can continue to report process health even though its
config plane cannot settle.

A separate proposed precursor, published in PR #1607 but not yet part of this
ADR's baseline behavior, would give unary and streamed
`ApplyConfigTransaction` ten minutes to acquire the coordinator. It is a
dependency for this design: expiry rejects only those waiting Apply operations
without mutation, while this ADR covers liveness after ownership. It does not
cover rollback, confirm, abort, gNMI, or auto-revert and does not close the
underlying settlement-liveness issue.

This ADR defines the post-ownership contract. It is architecture only. Its
Proposed status does not claim that a watchdog, fail-stop path, observability,
or recovery proof has shipped.

## Decision

### One operation, one owner, one candidate

Every config transaction mutation has exactly one daemon-owned internal
operation record and one owner of the shared runtime-config coordinator. A
streamed apply also has exactly one materialized candidate, one consumed
candidate token, and one held stream-admission permit. The transport transfers
the candidate and permit to the daemon-owned operation; it never retains a
second candidate, starts a replacement operation, or reacquires admission for
the same request.

The exact coordinator-owning roster is unary/streamed `ApplyConfigTransaction`,
`RollbackConfigTransaction`, gRPC `ConfirmConfigTransaction`/
`AbortConfigTransaction`, gNMI Set with ordinary operations or `Commit`,
`Confirm`, `Cancel`, or `SetRollbackDuration`, and timeout auto-revert.
Plan, Status, and History operations are read-only and outside the watchdog.
Other mutators that share the coordinator do not gain a watchdog here; they
remain unable to overlap an owned transaction.

The operation moves monotonically through these phases:

1. `waiting-for-ownership`: validated request, but no coordinator guard and no
   mutation authority.
2. `owned-preflight`: coordinator acquired and watchdog armed, while re-plan,
   token comparison, mutation-family validation, and other side-effect-free
   checks run.
3. `mutating`: the first reversible runtime or journal mutation has begun.
4. `settling/rollback`: persistence, finalization, confirmation-state
   publication, or compensating rollback is in progress.
5. `settled`: a success or clean failure is terminal and all required outcome
   state has been recorded.
6. `ambiguous-fenced`: the watchdog expired without proof of settlement; no
   success or rollback claim is permitted and fail-stop is in progress.

Only `settled` releases the coordinator and streamed admission normally.
`ambiguous-fenced` retains their logical ownership until process death. At
fail-stop or shutdown, every operation still queued in `waiting-for-ownership`
is rejected and no queued waiter may acquire the newly freed physical mutex.
A new process reconstructs authority from durable state.

The ten-minute precursor applies only to unary and streamed Apply operations in
`waiting-for-ownership`. It must not arm, reset, or consume the post-ownership
budget. Acquiring the coordinator changes the phase to `owned-preflight` and
arms the watchdog before any further await or side effect.

### Independent terminal watchdog

The 30-minute budget, five-second grace, and exit status 70 below are Proposed
acceptance choices. None describes current behavior until this ADR is accepted
and its implementation gates pass.

An owned operation gets one 30-minute monotonic settlement budget. The sealed
[IRR transactional-apply receipt](../perf/irr-transactional-apply-2026-08.md)
measured a 295.6 MB candidate with end-to-end completion no higher than 208.55
seconds and auto-revert no slower than 69.5 seconds. Thirty minutes is a
conservative design target, not a latency promise; family limits stay separate.

A dedicated OS thread owns the terminal clock and, after the grace below,
calls `std::process::exit(70)` directly. The choice of this primitive requires
owner acceptance with this ADR. Its hard-exit path cannot await the async
runtime, an actor, logging, filesystem I/O, cleanup, or unwinding. The operation
can update an atomic phase and disarm the thread only with a proved terminal
`settled` transition; it cannot extend or replace the deadline.

At 30 minutes without `settled`, the watchdog atomically marks the operation
`ambiguous-fenced`, marks process readiness unavailable, closes admission for
all new persisted config mutations, and requests supervised shutdown. Existing
read-only diagnostics may remain available during the fail-stop grace. The
shutdown path may finish sooner, but it must not wait on the wedged operation.
If the process is still alive five seconds after watchdog expiry, that OS
thread calls `std::process::exit(70)`. Thus an owned operation either settles
normally or the daemon exits nonzero no later than 30 minutes and five seconds
after ownership.

The five-second grace lets the async side publish its fence and request
shutdown; it is not a rollback window. The OS thread does not depend on that
work completing.

### Response and ownership are separate clocks

The RPC response deadline remains a transport concern. Deadline expiry,
disconnect, dropped response receiver, or caller cancellation may prevent a
client from learning the outcome, but never aborts the transaction task,
releases the coordinator, releases streamed admission, or disarms the terminal
watchdog. The daemon-owned operation continues toward `settled` or fail-stop.

The response therefore remains at-least-once ambiguous to the caller. Existing
transaction status is authoritative only for the confirmed-transaction
lifecycle it already reports. An ordinary Apply caller recovers by issuing a
fresh Plan and comparing effective config and its fresh token; there is no
ordinary-operation status record. This ADR adds no protobuf field, RPC, status
enum, or token format.

Awaiting or dropping a caller-side `JoinHandle` never cancels the detached task;
a dropped handle detaches, and the operation remains owned/running. Executor
`JoinError`, owner-guard drop, panic, unwind, or task abort after coordinator
acquisition fences immediately. Unless already `settled`, the owner guard marks
`ambiguous-fenced` before its coordinator guard or stream permit can drop; the
OS-thread registration outlives the task. Process abort already meets fail-stop.

### Persistence and confirmed transactions

The watchdog covers ordinary applies, confirmed applies, confirm/abort work,
timeout auto-revert, and the gNMI adapter when they mutate under the same
coordinator. The phase record identifies these operation kinds without
creating a second commit model.

For an unconfirmed apply:

- Before atomic persistence publishes the candidate, restart uses the prior
  on-disk config as authority.
- After atomic persistence publishes it, restart uses the candidate on disk as
  authority even if the response or in-process finalization was lost.
- If publication cannot be proven at watchdog expiry, the running process says
  only `ambiguous-fenced`. Startup validates the one atomically published
  config object and fails closed under the existing persistence contract.

V3 authority has three explicit publication windows. Before locator
publication, no v3 boot authority exists and confirmed mutation must not begin.
After locator rename and directory fsync, the config-adjacent locator is the
sole pending boot authority and names fixed owner-private metadata and raw
normalized-prior objects. If locator publication acknowledgement is ambiguous,
the operation treats the locator as potentially authoritative, fences, and
lets boot inspection decide; it never cleans up speculatively.

For confirmed Apply the operation settles after that authority protects the
commit and the pending lifecycle is installed. For confirm, successful abort,
or auto-revert, durable locator unlink plus directory fsync is the terminal
point and disarms the watchdog before warning-only metadata/raw cleanup. That
cleanup cannot retain the coordinator or trigger fail-stop if it stalls.
Locator unlink or directory-fsync failure remains nonterminal, retains the
fence and authority, and proceeds to watchdog fail-stop if it cannot settle.
Restart with a retained locator performs the existing verified boot revert.

Pre-persistence, post-persistence, rollback, and lost-ack windows all obey the
same rule: no in-process success or clean-failure claim without proof. The
watchdog does not guess which side effect completed. It fences, exits, and lets
the established durable authority decide startup behavior.

### Fencing, observability, and shutdown

The internal operation record carries only bounded safe metadata for daemon
logs, metrics, and diagnostics:

- a daemon-generated operation ID;
- operation kind and current phase;
- monotonic elapsed time and configured watchdog budget;
- whether the response waiter is still attached; and
- terminal outcome or fail-stop reason.

Logs must carry the operation ID, phase, and elapsed duration. Metrics expose
the current phase and elapsed duration plus one counter for watchdog fail-stop,
but never use the operation ID as a label. Neither surface may include
candidate TOML, optimistic-concurrency or candidate tokens, confirm IDs,
comments, credentials, filesystem paths, digests, derived candidate fragments,
or free-form actor/error strings. Metric labels come from a closed enum.

The existing process availability gate is the first fencing mechanism at
watchdog expiry: readiness turns red and every entry point for a new persisted
mutation rejects work. Where the process is still schedulable, mutation actors
must also reject newly dequeued persisted work after observing that fence.
Neither step is permission to release the owned coordinator or streamed
admission before death.

Ordinary coordinated shutdown first closes mutation admission. If an owned
transaction exists, shutdown may wait only until the earlier of normal
settlement or its already-armed watchdog deadline. Shutdown cannot abort its
`JoinHandle`, reset the deadline, start a parallel rollback, or tear down a
required actor while the operation is still trying to settle. Watchdog expiry
during shutdown follows the same readiness, fence, and nonzero fail-stop path;
it is not converted to a successful shutdown. All queued coordinator waiters
are rejected before teardown and cannot begin after the owner settles or dies.

### Required proof before acceptance

Implementation is not complete until deterministic tests cover the phase and
recovery contract:

1. Paused-clock unit tests hold each actor and persistence reply used by every
   mutation family. At 29 minutes 59 seconds the owner, coordinator, admission,
   and watchdog remain live; at 30 minutes the state becomes
   `ambiguous-fenced` exactly once.
2. Caller-`JoinHandle` wait/drop tests prove the operation remains owned/running.
   Executor `JoinError`, panic/unwind/task-abort, and owner-guard-drop tests prove
   immediate fencing before coordinator/permit release, OS thread still armed,
   and no new admission.
3. Adversarial tests stall owned preflight, first mutation, persistence before
   and after atomic publication, finalization, rollback, confirm, abort, and
   auto-revert. Each produces either a proved `settled` result or the same
   fail-stop transition.
4. Real-binary subprocess tests prove readiness goes red, queued/new mutations
   reject, exit 70 occurs by the grace, and no second transaction begins.
5. Restart/fault tests cover unconfirmed persistence; v3 before, after, and
   ambiguous locator publication; confirmed Apply/confirm/abort/auto-revert;
   nonterminal locator unlink/fsync failure; and stalled post-terminal cleanup.
   They assert config and authority state, watchdog disarm, and lock release.
6. Fault injection must prove the watchdog still exits when the Tokio runtime,
   transaction task, relevant actor mailbox, persistence acknowledgement, and
   graceful-shutdown path are independently stalled.

The test matrix must exercise every config-transaction entry path and mutation
family. A single synthetic oneshot test is necessary but insufficient.

### Rejected alternatives

- **Timeout around the outer apply future.** Dropping that future can detach or
  cancel the only code capable of rollback and does not prove settlement.
- **Abort or drop the transaction `JoinHandle`.** A dropped Tokio handle
  detaches its task; aborting it reintroduces the split-apply hazard ADR-0080
  forbids.
- **Release admission at the response deadline.** That allows a second
  candidate to overlap a still-owned transaction and breaks the one-candidate
  contract.
- **Add a second semaphore.** Parallel admission hides the stuck owner without
  restoring coordinator liveness or a trustworthy outcome.
- **Put independent timeouts around post-mutation oneshot replies.** Local
  timeout errors cannot distinguish an unprocessed command from a completed
  side effect whose reply was lost. They can trigger rollback races and false
  terminal claims. The aggregate watchdog instead fails stop when settlement
  cannot be proved.

## Consequences

- A permanently stuck owned transaction becomes a bounded daemon restart
  instead of an indefinite config-plane wedge.
- The bound is deliberately fail-stop, so BGP sessions can be interrupted after
  a severe control-plane ambiguity. Supervision and graceful-restart behavior
  mitigate but do not erase that operational cost.
- Healthy applies retain cancellation shielding and one-candidate admission.
  They pay one operation record, one watchdog registration, phase updates, and
  bounded telemetry; the data-plane executor path gains no per-command timer.
- Operators get a precise operation ID and phase for the last 30 minutes before
  fail-stop without exposing candidate or authorization material.
- [ADR-0076](0076-config-transaction-model.md) remains authoritative for
  authorization tiers, optimistic tokens, one-candidate planning,
  mutation-family validation, persistence, rollback, ambiguity fencing, and
  commit-confirm authority.
  [ADR-0080](0080-cancellation-shielded-runtime-applies.md) remains
  authoritative for cancellation shielding. This ADR adds a terminal liveness
  bound; it does not weaken either contract.
- No public API or protobuf change is required. Internal readiness wiring,
  mutation fencing, supervision, metrics, and subprocess recovery tests are
  required before this ADR can be accepted or the underlying issue called
  fixed.
